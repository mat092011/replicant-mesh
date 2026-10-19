"""Bounded consumer adapter over the existing secure C1 coordinator client.

This adapter supplies correlation, deadlines, event backpressure, and local
cancellation intent. C1 remains responsible for TLS peer pinning, signed grants,
credential liveness, authorization, and the secure RPC wire protocol.
"""

from __future__ import annotations

import asyncio
import math
import threading
import time
from collections import deque
from dataclasses import dataclass
from types import MappingProxyType

from steamboat_connector.client import ConsumerSubmission
from steamboat_connector.errors import ConnectorError
from steamboat_security.ids import validate_id
from steamboat_security.outbound import OutboundAuthorizer
from steamboat_runtime.protocol.secure_transport import (
    MAX_CANCELLATION_GRACE_SECONDS,
    SecureCoordinatorClient,
    SecureTaskPending,
    _pending_task_descendants,
    _retain_tasks,
)
from steamboat_runtime.protocol.secure_connector import SecureConnectorPending

MAX_ACTIVE_RUNS = 8
MAX_PENDING_EVENTS = 16
MAX_OUTPUT_STALL_SECONDS = 30.0
MAX_RECENT_REQUEST_IDS = 256
MAX_PROMPT_BYTES = 64 * 1024
MAX_NEW_TOKENS = 1152
MAX_REQUEST_SECONDS = 300
_END = object()
_PENDING_ERRORS = (SecureTaskPending, SecureConnectorPending)


@dataclass(frozen=True)
class ConsumerEvent:
    """Prompt-free event returned by the secure coordinator stream."""

    type: str
    index: int | None = None
    token_id: int | None = None
    status: str | None = None
    generated_tokens: int | None = None


@dataclass(frozen=True)
class ConsumerResult:
    request_id: str
    status: str
    generated_tokens: int


@dataclass(frozen=True)
class _Failure:
    error: ConnectorError


def _validate_submission(submission: ConsumerSubmission) -> int:
    if type(submission) is not ConsumerSubmission:
        raise ConnectorError("INVALID_INPUT", "submission must be a ConsumerSubmission")
    try:
        validate_id(submission.request_id, "req")
    except Exception as error:
        raise ConnectorError("INVALID_INPUT", "request identity is invalid") from error
    if type(submission.prompt) is not str:
        raise ConnectorError("INVALID_INPUT", "prompt must be text")
    try:
        prompt_bytes = submission.prompt.encode("utf-8", errors="strict")
    except UnicodeError as error:
        raise ConnectorError("INVALID_INPUT", "prompt must be valid UTF-8") from error
    if len(prompt_bytes) > MAX_PROMPT_BYTES:
        raise ConnectorError("INVALID_INPUT", "prompt exceeds 64 KiB")
    if (
        type(submission.max_new_tokens) is not int
        or not 1 <= submission.max_new_tokens <= MAX_NEW_TOKENS
    ):
        raise ConnectorError("INVALID_INPUT", "max_new_tokens is outside 1..1152")
    if (
        type(submission.deadline_seconds) is not int
        or not 1 <= submission.deadline_seconds <= MAX_REQUEST_SECONDS
    ):
        raise ConnectorError("INVALID_INPUT", "deadline_seconds is outside 1..300")
    if type(submission.attempt) is not int or submission.attempt != 1:
        raise ConnectorError(
            "INVALID_INPUT", "consumer transport does not retry attempts"
        )
    return len(prompt_bytes)


def _remaining(deadline: float) -> float:
    remaining = deadline - time.monotonic()
    if not math.isfinite(remaining) or remaining <= 0:
        raise ConnectorError("DEADLINE_EXCEEDED", "consumer request deadline elapsed")
    return remaining


def _observe_future(future):
    if not future.cancelled():
        future.exception()


class ConsumerRun:
    """One bounded stream; ``result`` and ``closed`` are awaitable futures."""

    def __init__(self, transport, submission, started_at, loop):
        self.request_id = submission.request_id
        self._transport = transport
        self._submission = submission
        self._started_at = started_at
        self._loop = loop
        self._queue = asyncio.Queue(maxsize=MAX_PENDING_EVENTS + 2)
        self._event_slots = asyncio.Semaphore(MAX_PENDING_EVENTS)
        self._result = loop.create_future()
        self._result.add_done_callback(_observe_future)
        self._closed = loop.create_future()
        self._task = None
        self._iterated = False
        self._cancel_requested = False
        self._cancel_sent = False
        self._context = None

    @property
    def result(self):
        return asyncio.shield(self._result)

    @property
    def closed(self):
        return asyncio.shield(self._closed)

    def __aiter__(self):
        if self._iterated:
            raise RuntimeError("ConsumerRun supports one event iterator")
        self._iterated = True
        return self

    def _task_finished(self, task):
        if not self._closed.done():
            if task.cancelled():
                error = ConnectorError(
                    "CANCELLED",
                    "cancel intent recorded; remote reclamation is unconfirmed",
                )
            else:
                try:
                    task.exception()
                except BaseException:
                    pass
                error = ConnectorError(
                    "EXECUTION_FAILED",
                    "consumer request task ended before cleanup completed",
                )
            if not self._result.done():
                self._result.set_exception(error)
            if self._queue.empty():
                self._queue.put_nowait(_Failure(error))
                self._queue.put_nowait(_END)
            self._closed.set_result(None)
        elif not task.cancelled():
            task.exception()

    async def __anext__(self):
        item = await self._queue.get()
        if isinstance(item, ConsumerEvent):
            self._event_slots.release()
            return item
        if isinstance(item, _Failure):
            self._transport._release(self.request_id, self)
            raise item.error
        if item is _END:
            self._transport._release(self.request_id, self)
            raise StopAsyncIteration
        raise RuntimeError("invalid consumer event queue entry")

    async def aclose(self):
        self._transport.cancel(self.request_id)
        await asyncio.shield(self._closed)
        self._discard_output()
        self._transport._release(self.request_id, self)

    def _discard_output(self):
        while True:
            try:
                item = self._queue.get_nowait()
            except asyncio.QueueEmpty:
                return
            if isinstance(item, ConsumerEvent):
                self._event_slots.release()

    async def _emit(self, event, hard_deadline, context):
        remaining = min(
            MAX_OUTPUT_STALL_SECONDS,
            _remaining(hard_deadline),
            self._transport._context_remaining(context),
        )
        try:
            await asyncio.wait_for(self._event_slots.acquire(), timeout=remaining)
        except asyncio.TimeoutError as error:
            raise ConnectorError(
                "BACKPRESSURE", "consumer stopped draining its bounded event stream"
            ) from error
        try:
            self._queue.put_nowait(event)
        except BaseException:
            self._event_slots.release()
            raise

    async def _drive(self):
        started = self._started_at
        deadline = started + self._submission.deadline_seconds
        context = None
        stream = None
        preserve_context = False
        failure = None
        result = None
        tokens = []
        terminal_seen = False
        try:
            remaining = _remaining(deadline)
            context = self._transport._authorizer.create_consumer_request_context(
                lifetime_seconds=remaining,
                request_id=self.request_id,
            )
            self._context = context
            token_ids = await self._transport._await_before(
                self._transport._client.tokenize(
                    self._submission.prompt,
                    trusted_request_context=context,
                ),
                deadline,
                context=context,
            )
            if (
                type(token_ids) is not list
                or not token_ids
                or len(token_ids) > 16_384
                or any(
                    type(token) is not int or not 0 <= token < 32000
                    for token in token_ids
                )
            ):
                raise ConnectorError(
                    "EXECUTION_FAILED", "coordinator returned invalid tokenization"
                )
            timeout = min(
                _remaining(deadline), self._transport._context_remaining(context)
            )
            stream = self._transport._client.generate(
                token_ids,
                self._submission.max_new_tokens,
                trusted_request_context=context,
                forced_tokens=None,
                capture_logits=False,
                timeout_seconds=timeout,
            )
            if not hasattr(stream, "__aiter__") or not callable(
                getattr(stream, "aclose", None)
            ):
                raise ConnectorError(
                    "EXECUTION_FAILED",
                    "secure Generate did not return a closable stream",
                )
            iterator = stream.__aiter__()
            while True:
                try:
                    raw = await self._transport._await_before(
                        iterator.__anext__(), deadline, context=context
                    )
                except StopAsyncIteration:
                    break
                if type(raw) is not dict or type(raw.get("type")) is not str:
                    raise ConnectorError(
                        "EXECUTION_FAILED", "secure stream event is malformed"
                    )
                if raw["type"] == "token":
                    index = raw.get("index")
                    token = raw.get("token_id")
                    if (
                        terminal_seen
                        or type(index) is not int
                        or index != len(tokens)
                        or type(token) is not int
                        or not 0 <= token < 32000
                        or index >= self._submission.max_new_tokens
                    ):
                        raise ConnectorError(
                            "EXECUTION_FAILED", "secure stream token order is invalid"
                        )
                    tokens.append(token)
                    await self._emit(
                        ConsumerEvent("token", index=index, token_id=token),
                        deadline,
                        context,
                    )
                elif raw["type"] == "result":
                    if terminal_seen or raw.get("status") != "completed":
                        raise ConnectorError(
                            "EXECUTION_FAILED", "secure generation did not complete"
                        )
                    if (
                        raw.get("cleanup_complete") is not True
                        or type(raw.get("token_ids")) is not list
                        or raw["token_ids"] != tokens
                        or len(tokens) != self._submission.max_new_tokens
                    ):
                        raise ConnectorError(
                            "EXECUTION_FAILED", "secure generation result is incomplete"
                        )
                    terminal_seen = True
                    await self._emit(
                        ConsumerEvent(
                            "result", status="completed", generated_tokens=len(tokens)
                        ),
                        deadline,
                        context,
                    )
                    result = ConsumerResult(self.request_id, "completed", len(tokens))
                else:
                    raise ConnectorError(
                        "EXECUTION_FAILED", "secure stream event type is unknown"
                    )
            if not terminal_seen or result is None:
                raise ConnectorError(
                    "EXECUTION_FAILED", "secure stream ended without a result"
                )
        except _PENDING_ERRORS as error:
            self._transport._mark_uncertain(error, context)
            preserve_context = context is not None
            failure = ConnectorError(
                "CLEANUP_UNCERTAIN", "secure request cleanup remains pending"
            )
        except asyncio.CancelledError:
            failure = ConnectorError(
                "CANCELLED", "cancel intent recorded; remote reclamation is unconfirmed"
            )
        except ConnectorError as error:
            failure = error
        except Exception as error:
            failure = ConnectorError(
                "EXECUTION_FAILED", "secure coordinator request failed"
            )
        finally:
            if stream is not None:
                try:
                    await self._transport._await_cleanup(stream.aclose(), context)
                except _PENDING_ERRORS as error:
                    self._transport._mark_uncertain(error, context)
                    preserve_context = context is not None
                    failure = ConnectorError(
                        "CLEANUP_UNCERTAIN", "secure request cleanup remains pending"
                    )
                except BaseException:
                    self._transport._mark_uncertain(None, context)
                    preserve_context = context is not None
                    failure = ConnectorError(
                        "CLEANUP_UNCERTAIN",
                        "secure stream cleanup could not be confirmed",
                    )
            if context is not None and not preserve_context:
                try:
                    context.close()
                except BaseException:
                    self._transport._mark_uncertain(None, context)
                    preserve_context = True
                    failure = ConnectorError(
                        "CLEANUP_UNCERTAIN", "secure request context cleanup failed"
                    )
            if failure is None:
                if not self._result.done():
                    self._result.set_result(result)
                self._queue.put_nowait(_END)
            else:
                self._discard_output()
                if not self._result.done():
                    self._result.set_exception(failure)
                self._queue.put_nowait(_Failure(failure))
                self._queue.put_nowait(_END)
            if not self._closed.done():
                self._closed.set_result(None)


class SecureConsumerTransport:
    """Consumer stream over exact C1 secure-client and outbound-authorizer types."""

    def __init__(self, client: SecureCoordinatorClient, authorizer: OutboundAuthorizer):
        if type(client) is not SecureCoordinatorClient:
            raise TypeError("client must be the exact SecureCoordinatorClient")
        if type(authorizer) is not OutboundAuthorizer:
            raise TypeError("authorizer must be the exact OutboundAuthorizer")
        if client.outbound_authorizer is not authorizer:
            raise TypeError(
                "client and transport must share the same OutboundAuthorizer"
            )
        self._initialize(client, authorizer)

    def _initialize(self, client, authorizer):
        self._client = client
        self._authorizer = authorizer
        self._active = {}
        self._recent_ids = set()
        self._recent_order = deque()
        self._pending_tasks = set()
        self._pending_contexts = set()
        self._pending_context_owners = {}
        self._pending_watchers = set()
        self._unavailable = False
        self._lock = threading.RLock()

    @classmethod
    def _for_tests(cls, client, authorizer):
        """Private seam for portable fake-peer tests; never use in production."""
        instance = cls.__new__(cls)
        instance._initialize(client, authorizer)
        return instance

    async def submit(self, submission: ConsumerSubmission) -> ConsumerRun:
        started = time.monotonic()
        _validate_submission(submission)
        loop = asyncio.get_running_loop()
        with self._lock:
            if self._is_unavailable():
                raise ConnectorError(
                    "UNAVAILABLE", "secure consumer transport is unavailable"
                )
            if (
                submission.request_id in self._active
                or submission.request_id in self._recent_ids
            ):
                raise ConnectorError(
                    "DUPLICATE", "request identity was already submitted"
                )
            if len(self._active) >= MAX_ACTIVE_RUNS:
                raise ConnectorError(
                    "BUSY", "secure consumer transport has eight active runs"
                )
            self._recent_ids.add(submission.request_id)
            self._recent_order.append(submission.request_id)
            while len(self._recent_order) > MAX_RECENT_REQUEST_IDS:
                old = self._recent_order.popleft()
                self._recent_ids.discard(old)
            run = ConsumerRun(self, submission, started, loop)
            self._active[submission.request_id] = run
            run._task = loop.create_task(
                run._drive(), name="secure-consumer-" + submission.request_id
            )
            run._task.add_done_callback(run._task_finished)
        return run

    def cancel(self, request_id: str):
        try:
            validate_id(request_id, "req")
        except Exception as error:
            raise ConnectorError(
                "INVALID_INPUT", "request identity is invalid"
            ) from error
        with self._lock:
            run = self._active.get(request_id)
            if run is None or run._task is None or run._task.done():
                return MappingProxyType(
                    {
                        "request_id": request_id,
                        "accepted": False,
                        "state": "unknown_or_complete",
                        "remote_reclamation_confirmed": False,
                    }
                )
            run._cancel_requested = True
            loop, task = run._loop, run._task
            if run._cancel_sent:
                return MappingProxyType(
                    {
                        "request_id": request_id,
                        "accepted": True,
                        "state": "cancel_intent_recorded",
                        "remote_reclamation_confirmed": False,
                    }
                )
            run._cancel_sent = True
        loop.call_soon_threadsafe(task.cancel)
        return MappingProxyType(
            {
                "request_id": request_id,
                "accepted": True,
                "state": "cancel_intent_recorded",
                "remote_reclamation_confirmed": False,
            }
        )

    def status(self):
        with self._lock:
            return MappingProxyType(
                {
                    "available": not self._is_unavailable(),
                    "active_runs": len(self._active),
                    "max_active_runs": MAX_ACTIVE_RUNS,
                    "pending_secure_tasks": len(self._pending_tasks),
                }
            )

    def _context_remaining(self, context):
        try:
            sample = self._authorizer.clock.sample()
            remaining = float(context.deadline_monotonic) - sample.monotonic
        except Exception as error:
            raise ConnectorError(
                "CLOCK_UNSAFE", "consumer request clock is unavailable"
            ) from error
        if not math.isfinite(remaining) or remaining <= 0:
            raise ConnectorError(
                "DEADLINE_EXCEEDED", "C1 request context deadline elapsed"
            )
        return remaining

    def _is_unavailable(self):
        return bool(
            self._unavailable
            or getattr(self._client, "_closed", False)
            or getattr(self._client, "_unavailable", False)
        )

    async def _await_before(self, awaitable, deadline, *, context=None):
        remaining = max(0.0, deadline - time.monotonic())
        if context is not None:
            remaining = min(remaining, self._context_remaining(context))
        task = asyncio.ensure_future(awaitable)
        try:
            done, pending = await asyncio.wait((task,), timeout=remaining)
        except asyncio.CancelledError:
            await self._cancel_bounded(task, context=context)
            raise
        if pending:
            await self._cancel_bounded(task, context=context)
            raise ConnectorError(
                "DEADLINE_EXCEEDED", "consumer request deadline elapsed"
            )
        return task.result()

    async def _await_cleanup(self, awaitable, context=None):
        task = asyncio.ensure_future(awaitable)
        try:
            done, pending = await asyncio.wait(
                (task,), timeout=MAX_CANCELLATION_GRACE_SECONDS
            )
        except asyncio.CancelledError:
            error = SecureTaskPending(
                (task,),
                "consumer cleanup wait was interrupted; task ownership retained",
            )
            self._mark_uncertain(error, context)
            raise error
        if pending:
            await self._cancel_bounded(task, context=context)
        return task.result()

    async def _cancel_bounded(self, task, *, context=None):
        if not task.done():
            task.cancel()
        try:
            done, pending = await asyncio.wait(
                (task,), timeout=MAX_CANCELLATION_GRACE_SECONDS
            )
        except asyncio.CancelledError:
            tasks = tuple({task, *_pending_task_descendants((task,))})
            error = SecureTaskPending(
                tasks,
                "consumer cancellation wait was interrupted; task ownership retained",
            )
            self._mark_uncertain(error, context)
            raise error
        if pending:
            tasks = tuple({task, *_pending_task_descendants((task,))})
            error = SecureTaskPending(
                tasks, "consumer transport operation remains pending"
            )
            self._mark_uncertain(error, context)
            raise error
        try:
            task.result()
        except asyncio.CancelledError:
            return
        except _PENDING_ERRORS as error:
            self._mark_uncertain(error, context)
            raise error
        except BaseException:
            return

    def _mark_uncertain(self, error, context):
        with self._lock:
            self._unavailable = True
            tasks = tuple(error.tasks) if isinstance(error, _PENDING_ERRORS) else ()
            tasks = tuple(dict.fromkeys((*tasks, *_pending_task_descendants(tasks))))
            for task in tasks:
                if task not in self._pending_tasks:
                    self._pending_tasks.add(task)
                    task.add_done_callback(self._pending_tasks.discard)
                    _retain_tasks((task,))
            if context is not None:
                self._pending_contexts.add(context)
                owner = self._pending_context_owners.setdefault(
                    context, {"roots": set(), "generation": 0, "watcher": None}
                )
                new_roots = set(tasks) - owner["roots"]
                if new_roots:
                    owner["roots"].update(new_roots)
                    owner["generation"] += 1
                if tasks and owner["watcher"] is None:
                    watcher = asyncio.create_task(
                        self._watch_context_tasks(context),
                        name="consumer-cleanup-" + str(id(context)),
                    )
                    owner["watcher"] = watcher
                    self._pending_watchers.add(watcher)
                    watcher.add_done_callback(self._pending_watcher_done)

    def _pending_watcher_done(self, task):
        self._pending_watchers.discard(task)
        _observe_future(task)

    async def _watch_context_tasks(self, context):
        while True:
            with self._lock:
                owner = self._pending_context_owners.get(context)
                if owner is None:
                    return
                roots = tuple(owner["roots"])
                generation = owner["generation"]
            await self._wait_task_graph(roots)
            with self._lock:
                owner = self._pending_context_owners.get(context)
                if owner is None:
                    return
                if owner["generation"] != generation:
                    continue
                context.close()
                self._pending_contexts.discard(context)
                del self._pending_context_owners[context]
                return

    async def _wait_task_graph(self, tasks):
        roots = set(tasks)
        while roots:
            live = tuple(task for task in roots if not task.done())
            if live:
                done, _ = await asyncio.wait(live, return_when=asyncio.FIRST_COMPLETED)
            else:
                done = roots
            descendants = set(_pending_task_descendants(done))
            if descendants:
                with self._lock:
                    for task in descendants:
                        if task not in self._pending_tasks:
                            self._pending_tasks.add(task)
                            task.add_done_callback(self._pending_tasks.discard)
                            _retain_tasks((task,))
            roots = (roots - set(done)) | descendants

    def _release(self, request_id, run):
        with self._lock:
            if self._active.get(request_id) is run:
                del self._active[request_id]
