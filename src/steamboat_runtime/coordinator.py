"""Bounded FIFO scheduling for independent requests on three fixed workers.

This trusted, in-process coordinator owns all leases. It never retries an open
or a step after an ambiguous reply, and never advances two steps of one request
concurrently. Independent requests may occupy different workers concurrently.
"""

import asyncio
from collections import deque
from dataclasses import dataclass, field, fields, replace
import math
import time
import uuid

from .manifest import validate_manifest
from .protocol import PROTOCOL_VERSION
from .protocol.errors import ProtocolError, raise_for_error
from .protocol.secure_connector import SecureConnectorPending
from .protocol.secure_transport import (
    MAX_CANCELLATION_GRACE_SECONDS,
    SecureTaskPending,
    _pending_task_descendants,
    _retain_tasks,
)
from .protocol.worker_pb2 import Request
from .protocol.wire import validate_response
from .participant_context import TrustedRequestContext
from .worker import validate_ready


class CoordinatorError(Exception):
    def __init__(self, code, message):
        self.code, self.message = code, str(message)[:256]
        super().__init__(f"{code}: {self.message}")


@dataclass(frozen=True)
class SchedulerLimits:
    max_sessions: int = 8
    max_stage_queue: int = 8
    max_waiting_admissions: int = 32
    admission_timeout_seconds: float = 30
    request_timeout_seconds: float = 300
    rpc_timeout_seconds: float = 30
    output_queue_tokens: int = 16
    output_stall_timeout_seconds: float = 30
    renew_interval_seconds: float = 30
    cleanup_timeout_seconds: float = 20
    trace_events: int = 8192

    @classmethod
    def from_manifest(cls, manifest):
        values = {item.name: manifest["limits"][item.name] for item in fields(cls)
                  if item.name in manifest["limits"]}
        values["cleanup_timeout_seconds"] = manifest["limits"]["compute_cancel_grace_seconds"] + 5
        return cls(**values)

    def validate(self, manifest):
        maximum = self.from_manifest(manifest)
        integer_fields = {"max_sessions", "max_stage_queue", "max_waiting_admissions",
                          "output_queue_tokens", "trace_events"}
        for item in fields(self):
            value = getattr(self, item.name)
            if (isinstance(value, bool) or not isinstance(value, (int, float))
                    or not math.isfinite(value) or not 0 < value <= getattr(maximum, item.name)
                    or (item.name in integer_fields and type(value) is not int)):
                raise ValueError(f"{item.name} must be positive and within the manifest bound")
        return self


@dataclass(frozen=True)
class TokenEvent:
    session_id: str
    token_id: int
    index: int
    sequence: int
    position: int
    emitted_at: float
    received_at: float | None = None
    logits: object = None


@dataclass(frozen=True)
class RequestResult:
    session_id: str
    status: str
    token_ids: tuple
    cleanup_complete: bool
    error: str | None
    error_code: str | None
    submitted_at: float
    admitted_at: float | None
    finished_at: float


@dataclass(eq=False)
class _RequestState:
    session_id: str
    input_ids: object
    prompt_length: int
    new_tokens: int
    forced_tokens: tuple | None
    capture_logits: bool
    submitted_at: float
    deadline: float
    output: asyncio.Queue
    completion: asyncio.Future
    admission: asyncio.Future
    trusted_request_context: TrustedRequestContext | None = None
    task: asyncio.Task | None = None
    started: bool = False
    admitted: bool = False
    admitted_at: float | None = None
    cleaning: bool = False
    abort_error: CoordinatorError | None = None
    leases: dict = field(default_factory=dict)
    unknown_opens: set = field(default_factory=set)
    token_ids: list = field(default_factory=list)
    renewal_task: asyncio.Task | None = None
    pending_tasks: set = field(default_factory=set)
    cleanup_status_only: set = field(default_factory=set)
    cleanup_deadline: float | None = None
    retirement_task: asyncio.Task | None = None
    retirement_event: asyncio.Event = field(default_factory=asyncio.Event)
    pending_operation_seen: bool = False
    restart_required: bool = False


_PENDING_OPERATION_ERRORS = (SecureTaskPending, SecureConnectorPending)


@dataclass(eq=False)
class _Job:
    request: _RequestState
    sequence: int
    position: int
    count: int
    tensor: object
    future: asyncio.Future
    queued_ns: int
    rpc_task: asyncio.Task | None = None


class _StageQueue:
    def __init__(self, capacity):
        self.capacity = capacity
        self.items = deque()
        self.changed = asyncio.Condition()

    async def put(self, job):
        async with self.changed:
            await self.changed.wait_for(lambda: len(self.items) < self.capacity)
            self.items.append(job)
            self.changed.notify_all()

    async def get(self):
        async with self.changed:
            await self.changed.wait_for(lambda: bool(self.items))
            job = self.items.popleft()
            self.changed.notify_all()
            return job

    async def discard(self, request):
        async with self.changed:
            retained = deque()
            for job in self.items:
                if job.request is request:
                    job.future.cancel()
                else:
                    retained.append(job)
            self.items = retained
            self.changed.notify_all()


class RequestHandle:
    """One consumer should iterate the stream. Result retrieval is independent.

    Cancelling an iterator wait cancels the whole request. On failure/cancellation
    buffered tokens are discarded; previously consumed output remains a valid
    prefix. ``result()`` always returns terminal status, including cleanup status.
    """

    def __init__(self, owner, state):
        self._owner, self._state = owner, state
        self.session_id = state.session_id

    def __aiter__(self):
        return self

    async def __anext__(self):
        state = self._state
        if state.completion.done():
            result = state.completion.result()
            if result.error_code:
                raise CoordinatorError(result.error_code, result.error)
            if state.output.empty():
                raise StopAsyncIteration
        if not state.output.empty():
            return replace(state.output.get_nowait(), received_at=time.monotonic())
        waiting = asyncio.create_task(state.output.get())
        try:
            await asyncio.wait((waiting, state.completion), return_when=asyncio.FIRST_COMPLETED)
            if state.completion.done() and state.completion.result().error_code:
                result = state.completion.result()
                raise CoordinatorError(result.error_code, result.error)
            if waiting.done():
                return replace(waiting.result(), received_at=time.monotonic())
            raise StopAsyncIteration
        except asyncio.CancelledError:
            await asyncio.shield(self.cancel())
            raise
        finally:
            if not waiting.done():
                waiting.cancel()
            await asyncio.gather(waiting, return_exceptions=True)

    async def result(self):
        return await asyncio.shield(self._state.completion)

    async def reclaim_capture_buffers(self):
        """Confirm local capture references are reclaimable after request cleanup.

        This trusted in-process capability is not part of the worker protocol.
        It waits for the request task and supervised CPU work, then drains only
        the completed request's output queue.
        """
        return await self._owner._reclaim_capture_buffers(self._state)

    async def cancel(self):
        self._owner._abort(self._state, CoordinatorError("CANCELLED", "Client cancelled request"))
        return await self.result()


class Coordinator:
    def __init__(self, manifest, clients, model, *, limits=None, trace=None):
        validate_manifest(manifest)
        if len(clients) != 3:
            raise ValueError("Exactly three ordered workers are required")
        if trace is not None and not callable(trace):
            raise ValueError("trace must be a callable")
        self.manifest, self.clients, self.model = manifest, list(clients), model
        self.limits = (limits or SchedulerLimits.from_manifest(manifest)).validate(manifest)
        self.trace = trace
        self.events = deque(maxlen=self.limits.trace_events)
        self.trace_dropped = 0
        self.trace_errors = 0
        self.boot_ids = []
        self.clock_verified = [False] * 3
        self.clock_evidence = []
        self._queues = [_StageQueue(self.limits.max_stage_queue) for _ in range(3)]
        self._active_jobs = [None] * 3
        self._consumers = []
        self._requests = {}
        self._waiting = deque()
        self._slots = 0
        self._ready = self._closed = False
        self._fatal_error = None
        self._close_task = None
        self._start_task = None
        # Keep roots as well as live descendants until shutdown has inspected
        # their completed exceptions. A root may finish with a pending error
        # that names a child created after its first observation.
        self._shutdown_pending_tasks = set()
        self._shutdown_watched_tasks = set()
        self.model_cleanup_complete = None

    def _record(self, event, **values):
        record = {"event": event, "coordinator_ns": time.monotonic_ns(), **values}
        if len(self.events) == self.events.maxlen:
            self.trace_dropped += 1
        self.events.append(record)
        if self.trace is not None:
            try:
                self.trace(dict(record))
            except Exception:
                self.trace_errors += 1

    async def start(self):
        if self._closed or self._fatal_error:
            raise CoordinatorError("CLOSED", "Create a new coordinator after shutdown or worker failure")
        if self._ready:
            return self
        if self._start_task is None:
            self._start_task = asyncio.create_task(self._start())
        return await asyncio.shield(self._start_task)

    async def _start(self):
        await self._preflight()
        if self._closed:
            raise CoordinatorError("CLOSED", "Coordinator closed during startup")
        self._consumers = [asyncio.create_task(self._stage_loop(index)) for index in range(3)]
        self._ready = True
        return self

    def _envelope(self, index, *, timeout=None, state=None, **values):
        milliseconds = max(1, int(1000 * min(timeout or self.limits.rpc_timeout_seconds,
                                           self.limits.rpc_timeout_seconds)))
        fields_ = dict(protocol_version=PROTOCOL_VERSION,
                       manifest_fingerprint=self.manifest["fingerprint"],
                       timeout_ms=milliseconds)
        if self.boot_ids:
            fields_["worker_boot_id"] = self.boot_ids[index]
        if state is not None:
            fields_.update(session_id=state.session_id, lease_token=state.leases.get(index, ""))
        return Request(**fields_, **values)

    async def _execute(self, index, method, request, *, trusted_request_context=None,
                       cleanup=False):
        if trusted_request_context is not None:
            if type(trusted_request_context) is not TrustedRequestContext:
                raise CoordinatorError("INVALID_INPUT", "Invalid trusted request context")
            if not cleanup:
                try:
                    trusted_request_context.assert_data_live()
                except Exception:
                    raise CoordinatorError(
                        "TIMEOUT", "Trusted request authorization is no longer live") from None

        async def execute():
            if trusted_request_context is None:
                return await self.clients[index].execute(method, request)
            return await self.clients[index].execute(
                method, request, trusted_request_context=trusted_request_context)

        response = await asyncio.wait_for(execute(), request.timeout_ms / 1000)
        validate_response(method, request, response)
        return raise_for_error(response)

    async def _execute_for_request(self, index, method, request, *,
                                   trusted_request_context=None, cleanup=False,
                                   state=None):
        """Keep legacy client overrides keyword-free when no capability exists."""
        try:
            if trusted_request_context is None:
                return await self._execute(index, method, request)
            kwargs = {"trusted_request_context": trusted_request_context}
            if cleanup:
                kwargs["cleanup"] = True
            return await self._execute(index, method, request, **kwargs)
        except _PENDING_OPERATION_ERRORS as error:
            self._track_pending(state, error, index=index, method=method)
            raise

    def _track_pending(self, state, error, *, index=None, method=None):
        """Retain the task tree before an ordinary pending error is observed."""
        roots = tuple(getattr(error, "tasks", ()))
        descendants = tuple(_pending_task_descendants(roots))
        if state is not None:
            state.pending_operation_seen = True
            state.pending_tasks.update(roots)
            state.pending_tasks.update(descendants)
            if method in {"CancelSession", "CloseSession"} and index is not None:
                # The mutating cleanup call may already have reached the worker.
                # Once its owner retires, only a read-only status query is safe.
                state.cleanup_status_only.add(index)
        else:
            self._own_shutdown_tasks((*roots, *descendants))
        _retain_tasks((*roots, *descendants))
        self._ready = False
        failure = CoordinatorError(
            "WORKER_PENDING", "Worker transport still owns an unfinished operation")
        if self._fatal_error is None:
            self._fatal_error = failure
        for other in tuple(self._requests.values()):
            if other is not state:
                self._abort(other, failure)
        return descendants

    def _track_pending_task(self, state, task):
        if state is None or task is None:
            return
        state.pending_tasks.add(task)
        _retain_tasks((task,))

    @staticmethod
    def _live_pending_tasks(state):
        live = tuple(_pending_task_descendants(state.pending_tasks))
        state.pending_tasks.update(live)
        return live

    async def _wait_pending_tasks_until(self, state, deadline):
        """Boundedly follow descendants, including errors already observed by gather."""
        while True:
            live = self._live_pending_tasks(state)
            if not live:
                return True
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                _retain_tasks(live)
                return False
            _, pending = await asyncio.wait(live, timeout=remaining)
            # Inspect completed task exceptions before pruning anything. The
            # helper follows nested SecureTaskPending/ConnectorPending trees.
            state.pending_tasks.update(live)
            state.pending_tasks.update(pending)
            nested = tuple(_pending_task_descendants(state.pending_tasks))
            state.pending_tasks.update(nested)
            if pending and time.monotonic() >= deadline:
                _retain_tasks(pending)
                return False

    async def _preflight(self, state=None):
        from .protocol.clock import clock_identity

        evidence, boots = [], []
        trusted_request_context = (state.trusted_request_context if state is not None else None)
        for index in range(3):
            budget = self._remaining(state) if state else self.limits.rpc_timeout_seconds
            request = self._envelope(index, timeout=budget)
            sent = time.monotonic_ns()
            response = await self._execute_for_request(
                index, "Describe", request,
                trusted_request_context=trusted_request_context, state=state)
            received = time.monotonic_ns()
            validate_ready(response, self.manifest, f"worker-{index + 1}")
            boots.append(response.worker_boot_id)
            worker_clock = getattr(response, "clock_id", "")
            worker_now = getattr(response, "monotonic_ns", 0)
            own_clock = clock_identity()
            verified = bool(own_clock and own_clock == worker_clock and sent <= worker_now <= received)
            evidence.append({"worker": index + 1, "clock_id": worker_clock,
                             "coordinator_clock_id": own_clock, "sent_ns": sent,
                             "received_ns": received, "worker_monotonic_ns": worker_now,
                             "verified": verified})
        if len(set(boots)) != 3:
            raise CoordinatorError("INCOMPATIBLE_MODEL", "Worker identities are not distinct")
        self.boot_ids = boots
        if not self.clock_evidence:
            self.clock_evidence = evidence
            self.clock_verified = [record["verified"] for record in evidence]
        return evidence

    def submit(self, input_ids, new_tokens, *, forced_tokens=None,
               timeout_seconds=None, capture_logits=False,
               trusted_request_context=None):
        if not self._ready or self._closed or self._fatal_error:
            raise CoordinatorError("NOT_READY", "Coordinator workers are not ready")
        context_lifetime = None
        if trusted_request_context is not None:
            if type(trusted_request_context) is not TrustedRequestContext:
                raise CoordinatorError("INVALID_INPUT", "Invalid trusted request context")
            try:
                trusted_request_context.assert_data_live()
                context_lifetime = trusted_request_context.remaining_seconds()
            except Exception:
                raise CoordinatorError(
                    "TIMEOUT", "Trusted request authorization is no longer live") from None
        count = self.model.validate_tokens(input_ids)
        if type(new_tokens) is not int or new_tokens < 1:
            raise ValueError("new_tokens must be a positive integer")
        if count + new_tokens > self.manifest["limits"]["max_positions"]:
            raise ValueError("Prompt plus output budget exceeds the context bound")
        if type(capture_logits) is not bool:
            raise ValueError("capture_logits must be boolean")
        if forced_tokens is not None:
            if not isinstance(forced_tokens, (list, tuple)) or len(forced_tokens) != new_tokens - 1:
                raise ValueError("forced_tokens must contain exactly new_tokens-1 feedback token IDs")
            if any(type(token) is not int or not 0 <= token < self.manifest["config"]["vocab_size"]
                   for token in forced_tokens):
                raise ValueError("Forced feedback is outside the vocabulary")
            forced_tokens = tuple(forced_tokens)
        duration = self.limits.request_timeout_seconds if timeout_seconds is None else timeout_seconds
        if (isinstance(duration, bool) or not isinstance(duration, (int, float))
                or not math.isfinite(duration) or not 0 < duration <= self.limits.request_timeout_seconds):
            raise ValueError("Request timeout must be positive and within the configured bound")
        if self._slots >= self.limits.max_sessions and len(self._waiting) >= self.limits.max_waiting_admissions:
            raise CoordinatorError("CAPACITY_EXHAUSTED", "Coordinator admission queue is full")
        loop = asyncio.get_running_loop()
        session_id = (trusted_request_context.session_id if trusted_request_context is not None
                      else uuid.uuid4().hex)
        if trusted_request_context is not None and session_id in self._requests:
            raise CoordinatorError("INVALID_INPUT", "Trusted session is already active")
        cloned_tokens = input_ids.detach().clone()
        context_deadline = None
        if trusted_request_context is not None:
            try:
                context_check_started = time.monotonic()
                trusted_request_context.assert_data_live()
                refreshed_lifetime = trusted_request_context.remaining_seconds()
            except Exception:
                raise CoordinatorError(
                    "TIMEOUT", "Trusted request authorization is no longer live") from None
            context_deadline = context_check_started + min(context_lifetime, refreshed_lifetime)
        now = time.monotonic()
        if context_deadline is not None:
            duration = min(duration, context_deadline - now)
            if duration <= 0:
                raise CoordinatorError("TIMEOUT", "Trusted request context expired before admission")
        state = _RequestState(session_id, cloned_tokens, count, new_tokens,
                              forced_tokens, capture_logits, now, now + duration,
                              asyncio.Queue(self.limits.output_queue_tokens),
                              loop.create_future(), loop.create_future(),
                              trusted_request_context=trusted_request_context)
        if trusted_request_context is not None:
            try:
                trusted_request_context.claim_admission()
            except Exception:
                raise CoordinatorError("INVALID_INPUT", "Trusted request context was already submitted") from None
        try:
            self._requests[state.session_id] = state
            self._waiting.append(state)
            state.task = asyncio.create_task(self._run(state))
        except BaseException:
            self._requests.pop(state.session_id, None)
            try:
                self._waiting.remove(state)
            except ValueError:
                pass
            if trusted_request_context is not None:
                trusted_request_context.complete_admission()
            raise
        self._record("submitted", session_id=state.session_id, prompt_tokens=count, new_tokens=new_tokens)
        self._admit_waiters()
        return RequestHandle(self, state)

    def _admit_waiters(self):
        while self._ready and not self._closed and self._slots < self.limits.max_sessions and self._waiting:
            state = self._waiting.popleft()
            if state.abort_error or state.completion.done():
                continue
            self._slots += 1
            state.admitted = True
            state.admission.set_result(None)

    def _remaining(self, state):
        remaining = state.deadline - time.monotonic()
        if state.trusted_request_context is not None:
            try:
                remaining = min(remaining, state.trusted_request_context.remaining_seconds())
            except Exception:
                raise CoordinatorError("TIMEOUT", "Trusted request context has expired") from None
        if remaining <= 0:
            raise CoordinatorError("TIMEOUT", "Request lifetime expired")
        return remaining

    def _capture_compute_retired(self):
        status = getattr(self.model, "supervision_status", None)
        if not callable(status):
            return False
        try:
            snapshot = status()
        except BaseException:
            return False
        return type(snapshot) is dict and snapshot.get("active_compute") is False

    async def _reclaim_capture_buffers(self, state):
        if not state.capture_logits or not state.completion.done() or state.task is None:
            return False
        try:
            await asyncio.shield(state.task)
        except BaseException:
            return False
        if (not state.task.done() or state.session_id in self._requests
                or not self._capture_compute_retired()):
            while not self._capture_compute_retired():
                await asyncio.sleep(0.01)
        if (not state.task.done() or state.session_id in self._requests
                or not self._capture_compute_retired()):
            return False
        try:
            result = state.completion.result()
        except BaseException:
            return False
        if result.cleanup_complete is not True:
            return False
        for index, job in enumerate(self._active_jobs):
            if job is not None and job.request is state:
                return False
        while not state.output.empty():
            state.output.get_nowait()
        state.input_ids = None
        state.forced_tokens = None
        return state.output.empty()

    def _abort(self, state, error):
        if state.completion.done() or state.cleaning:
            return
        state.abort_error = state.abort_error or error
        if state.started:
            state.task.cancel()

    def _fail_workers(self, error):
        self._ready = False
        self._fatal_error = error
        for state in list(self._requests.values()):
            self._abort(state, error)

    async def _run(self, state):
        state.started = True
        error = None
        try:
            if state.abort_error:
                raise state.abort_error
            async with asyncio.timeout(self._remaining(state)):
                admission_deadline = min(state.deadline, state.submitted_at + self.limits.admission_timeout_seconds)
                async with asyncio.timeout_at(admission_deadline):
                    await asyncio.shield(state.admission)
                    await self._preflight(state)
                    # Renew partially acquired reservations while later opens
                    # await a response, without extending the hard lifetime.
                    state.renewal_task = asyncio.create_task(self._renew(state))
                    for index in range(3):
                        await self._reserve(state, index)
                state.admitted_at = time.monotonic()
                self._record("admitted", session_id=state.session_id,
                             admission_ms=1000 * (state.admitted_at - state.submitted_at))
                await self._generate(state)
        except _PENDING_OPERATION_ERRORS as exc:
            self._track_pending(state, exc)
            error = CoordinatorError(
                "WORKER_PENDING", "Worker transport still owns an unfinished operation")
        except asyncio.CancelledError:
            error = state.abort_error or CoordinatorError("CANCELLED", "Request cancelled")
        except TimeoutError:
            code = "ADMISSION_TIMEOUT" if state.admitted_at is None else "TIMEOUT"
            error = CoordinatorError(code, "Admission or request deadline expired")
        except (ProtocolError, CoordinatorError) as exc:
            error = CoordinatorError(exc.code, exc.message)
        except Exception:
            error = CoordinatorError("EXECUTION_FAILED", "Coordinator operation failed")
        state.cleaning = True
        if state.renewal_task is not None:
            state.renewal_task.cancel()
            done, pending = await asyncio.wait(
                (state.renewal_task,), timeout=MAX_CANCELLATION_GRACE_SECONDS)
            if pending:
                self._track_pending_task(state, state.renewal_task)
                self._ready = False
            for task in done:
                if task.cancelled():
                    continue
                try:
                    failure = task.exception()
                except BaseException as exc:
                    failure = exc
                if isinstance(failure, _PENDING_OPERATION_ERRORS):
                    self._track_pending(state, failure)
        await self._discard(state)
        if error:
            while not state.output.empty():
                state.output.get_nowait()

        now = time.monotonic()
        if state.trusted_request_context is not None:
            cleanup_span = min(self.limits.cleanup_timeout_seconds, 20.0)
            state.cleanup_deadline = now + cleanup_span
            state.cleanup_deadline = min(state.cleanup_deadline, state.deadline + 20.0)
        else:
            state.cleanup_deadline = now + self.limits.cleanup_timeout_seconds
        retirement = asyncio.create_task(self._retire_request(state, error))
        state.retirement_task = retirement
        _retain_tasks((retirement,))
        retirement.add_done_callback(
            lambda task, owner=state, prior_error=error:
            self._retirement_done(owner, task, prior_error))
        wait_budget = min(MAX_CANCELLATION_GRACE_SECONDS,
                          max(0.0, state.cleanup_deadline - time.monotonic()))
        try:
            done, _ = await asyncio.wait((retirement,), timeout=wait_budget)
            if done:
                await asyncio.gather(retirement, return_exceptions=True)
            else:
                self._publish_result(state, error, cleanup_complete=False)
        except asyncio.CancelledError:
            _retain_tasks((retirement,))
            self._publish_result(state, error, cleanup_complete=False)
            raise

    def _retirement_done(self, state, task, error):
        if task.cancelled():
            state.restart_required = True
            self._ready = False
            self._publish_result(state, error, cleanup_complete=False)
            return
        try:
            failure = task.exception()
        except BaseException as exc:
            failure = exc
        if failure is None:
            return
        if isinstance(failure, _PENDING_OPERATION_ERRORS):
            self._track_pending(state, failure)
        state.restart_required = True
        self._ready = False
        if self._fatal_error is None:
            self._fatal_error = CoordinatorError(
                "CLEANUP_UNKNOWN", "Coordinator retirement supervisor failed")
        self._publish_result(state, error or self._fatal_error,
                             cleanup_complete=False)

    async def _retire_request(self, state, error):
        deadline = state.cleanup_deadline or time.monotonic()
        cleanup = False
        while time.monotonic() < deadline:
            if not await self._wait_pending_tasks_until(state, deadline):
                break
            try:
                cleanup = await self._cleanup(state, cancel=error is not None)
            except _PENDING_OPERATION_ERRORS as exc:
                self._track_pending(state, exc)
                if self._live_pending_tasks(state) and time.monotonic() < deadline:
                    continue
                break
            except Exception:
                cleanup = False
            break
        self._complete_request_state(state, error, cleanup)

    def _publish_result(self, state, error, *, cleanup_complete):
        if state.completion.done():
            return
        if error is None and not cleanup_complete:
            error = CoordinatorError("CLEANUP_UNKNOWN", "Worker session cleanup is unconfirmed")
        status = ("completed" if error is None else
                  "cancelled" if error.code == "CANCELLED" else "failed")
        self._record("finished", session_id=state.session_id, status=status,
                     error_code=error.code if error else None,
                     cleanup_complete=cleanup_complete)
        state.completion.set_result(RequestResult(
            state.session_id, status, tuple(state.token_ids), cleanup_complete,
            error.message if error else None, error.code if error else None,
            state.submitted_at, state.admitted_at, time.monotonic()))

    def _complete_request_state(self, state, error, cleanup):
        live_pending = self._live_pending_tasks(state)
        if live_pending:
            cleanup = False
        retain_state = bool(live_pending) or (
            (state.trusted_request_context is not None
             or state.pending_operation_seen) and not cleanup)
        if (not cleanup and state.trusted_request_context is None
                and not live_pending and not state.pending_operation_seen):
            # Keep the isolated legacy lab behavior for ambiguous opens.
            retain_state = False
        if cleanup and state.trusted_request_context is not None:
            try:
                state.trusted_request_context.complete_admission()
            except Exception:
                cleanup = False
                retain_state = True
                self._ready = False
                self._fatal_error = CoordinatorError(
                    "CLEANUP_UNKNOWN", "Trusted request admission could not be completed")
        if cleanup:
            state.input_ids = None
            state.forced_tokens = None
        elif error is None:
            error = CoordinatorError("CLEANUP_UNKNOWN", "Worker session cleanup is unconfirmed")
        self._publish_result(state, error, cleanup_complete=cleanup)
        if retain_state:
            state.restart_required = True
            self._ready = False
            if self._fatal_error is None:
                self._fatal_error = CoordinatorError(
                    "CLEANUP_UNKNOWN", "Coordinator requires restart after unconfirmed cleanup")
            return
        self._requests.pop(state.session_id, None)
        try:
            self._waiting.remove(state)
        except ValueError:
            pass
        if state.admitted:
            self._slots = max(0, self._slots - 1)
            state.admitted = False
        state.retirement_event.set()
        self._admit_waiters()

    async def _reserve(self, state, index):
        state.unknown_opens.add(index)
        lifetime_ms = max(1, int(1000 * self._remaining(state)))
        idle_lease_ms = min(
            self.manifest["limits"]["idle_lease_seconds"] * 1000, lifetime_ms)
        pending = asyncio.create_task(self._execute_for_request(index, "OpenSession", self._envelope(
            index, state=state, timeout=self._remaining(state),
            max_positions=state.prompt_length + state.new_tokens,
            lifetime_ms=lifetime_ms, idle_lease_ms=idle_lease_ms),
            trusted_request_context=state.trusted_request_context, state=state))
        try:
            response = await asyncio.shield(pending)
        except _PENDING_OPERATION_ERRORS as error:
            outcome = (await asyncio.gather(pending, return_exceptions=True))[0]
            if not isinstance(outcome, BaseException):
                state.leases[index] = outcome.lease_token
                state.unknown_opens.discard(index)
            self._track_pending(state, error, index=index, method="OpenSession")
            raise
        except BaseException as error:
            pending.cancel()
            # Preserve a lease if cancellation raced with a completed reply.
            outcome = (await asyncio.gather(pending, return_exceptions=True))[0]
            if isinstance(outcome, _PENDING_OPERATION_ERRORS):
                self._track_pending(state, outcome, index=index, method="OpenSession")
            if not isinstance(outcome, BaseException):
                state.leases[index] = outcome.lease_token
                state.unknown_opens.discard(index)
            elif isinstance(error, ProtocolError) and error.code in {
                    "CAPACITY_EXHAUSTED", "INVALID_INPUT", "INCOMPATIBLE_MODEL",
                    "STALE_WORKER", "CLOSED_SESSION"}:
                state.unknown_opens.discard(index)
            raise
        state.leases[index] = response.lease_token
        state.unknown_opens.discard(index)

    async def _generate(self, state):
        import torch
        from .protocol.codec import decode_tensor, encode_tensor

        tokens, position = state.input_ids, 0
        for sequence in range(state.new_tokens):
            hidden = await self.model.embed(tokens)
            count = tokens.shape[1]
            for index in range(3):
                future = asyncio.get_running_loop().create_future()
                future.add_done_callback(lambda item: None if item.cancelled() else item.exception())
                job = _Job(state, sequence, position, count, encode_tensor(hidden), future,
                           time.monotonic_ns())
                await self._queues[index].put(job)
                response = await asyncio.shield(future)
                hidden = decode_tensor(response.tensor, count)
            logits = await self.model.finish(hidden, all_logits=False)
            if (not isinstance(logits, torch.Tensor) or logits.shape[-1] != self.manifest["config"]["vocab_size"]
                    or logits.numel() != self.manifest["config"]["vocab_size"]
                    or not bool(torch.isfinite(logits).all())):
                raise CoordinatorError("EXECUTION_FAILED", "Invalid final logits")
            last = logits.reshape(1, -1)
            sampled = int(last.argmax(dim=-1).item())
            event = TokenEvent(state.session_id, sampled, sequence, sequence,
                               position + count, time.monotonic(),
                               logits=last.detach().clone() if state.capture_logits else None)
            try:
                await asyncio.wait_for(state.output.put(event),
                                       min(self._remaining(state), self.limits.output_stall_timeout_seconds))
            except TimeoutError as exc:
                raise CoordinatorError("SLOW_CONSUMER", "Output queue did not drain before its deadline") from exc
            state.token_ids.append(sampled)
            self._record("token", session_id=state.session_id, sequence=sequence,
                         position=position + count, token_index=sequence)
            position += count
            feedback = sampled if state.forced_tokens is None or sequence == state.new_tokens - 1 else state.forced_tokens[sequence]
            tokens = torch.tensor([[feedback]], dtype=torch.long)

    async def _stage_loop(self, index):
        while True:
            job = await self._queues[index].get()
            if job.request.abort_error or job.future.cancelled() or job.request.cleaning:
                job.future.cancel()
                continue
            self._active_jobs[index] = job
            dispatched = time.monotonic_ns()
            try:
                request = self._envelope(index, state=job.request, timeout=self._remaining(job.request),
                                         sequence=job.sequence, start_position=job.position,
                                         token_count=job.count, tensor=job.tensor)
                self._record("stage_dispatch", session_id=job.request.session_id, worker=index + 1,
                             sequence=job.sequence, position=job.position, token_count=job.count,
                             dispatch_ns=dispatched, queued_ns=job.queued_ns,
                             request_bytes=request.ByteSize())
                job.rpc_task = asyncio.create_task(self._execute_for_request(
                    index, "Step", request,
                    trusted_request_context=job.request.trusted_request_context,
                    state=job.request))
                response = await job.rpc_task
                self._record("stage_response", session_id=job.request.session_id, worker=index + 1,
                             sequence=job.sequence, position=job.position, token_count=job.count,
                             dispatch_ns=dispatched, response_bytes=response.ByteSize(),
                             queue_ms=response.queue_ms, compute_ms=response.compute_ms,
                             compute_start_ns=getattr(response, "compute_start_ns", 0),
                             compute_end_ns=getattr(response, "compute_end_ns", 0),
                             clock_id=getattr(response, "clock_id", ""),
                             worker_compute_start_ns=getattr(response, "compute_start_ns", 0),
                             worker_compute_end_ns=getattr(response, "compute_end_ns", 0),
                             worker_clock_id=getattr(response, "clock_id", ""))
                if not job.future.done():
                    job.future.set_result(response)
            except asyncio.CancelledError:
                if not job.future.done():
                    job.future.cancel()
                if self._closed and not self._requests:
                    raise
            except _PENDING_OPERATION_ERRORS as exc:
                self._track_pending(job.request, exc, index=index, method="Step")
                if not job.future.done():
                    job.future.set_exception(exc)
            except Exception as exc:
                code = getattr(exc, "code", "TIMEOUT" if isinstance(exc, TimeoutError) else "EXECUTION_FAILED")
                error = CoordinatorError(code, getattr(exc, "message", "Worker step failed"))
                if not job.future.done():
                    job.future.set_exception(error)
                if code in {"STALE_WORKER", "EXECUTION_FAILED", "INCOMPATIBLE_MODEL"}:
                    self._fail_workers(error)
            finally:
                self._active_jobs[index] = None
                # Drop encoded activation and reply references before waiting.
                job.tensor = None
                job.rpc_task = None

    async def _renew(self, state):
        try:
            while True:
                await asyncio.sleep(min(self.limits.renew_interval_seconds, self._remaining(state)))
                for index in list(state.leases):
                    await self._execute_for_request(index, "RenewSession", self._envelope(
                        index, state=state, timeout=self._remaining(state)),
                        trusted_request_context=state.trusted_request_context,
                        state=state)
                self._record("renewed", session_id=state.session_id, workers=len(state.leases))
        except asyncio.CancelledError:
            raise
        except _PENDING_OPERATION_ERRORS as exc:
            self._track_pending(state, exc)
            self._abort(state, CoordinatorError(
                "WORKER_PENDING", "Worker lease renewal did not retire"))
            raise
        except Exception as exc:
            self._abort(state, CoordinatorError(getattr(exc, "code", "EXECUTION_FAILED"),
                                                "Worker lease renewal failed"))

    async def _discard(self, state):
        tasks = set()
        for index, queue in enumerate(self._queues):
            await queue.discard(state)
            job = self._active_jobs[index]
            if job is not None and job.request is state:
                job.future.cancel()
                if job.rpc_task:
                    job.rpc_task.cancel()
                    tasks.add(job.rpc_task)
        if not tasks:
            return
        done, pending = await asyncio.wait(
            tasks, timeout=MAX_CANCELLATION_GRACE_SECONDS)
        for task in pending:
            self._track_pending_task(state, task)
        for task in done:
            if task.cancelled():
                continue
            try:
                error = task.exception()
            except BaseException as exc:
                error = exc
            if isinstance(error, _PENDING_OPERATION_ERRORS):
                self._track_pending(state, error)

    async def _cleanup(self, state, *, cancel):
        deadline = state.cleanup_deadline or time.monotonic()

        async def release(index):
            method = ("SessionStatus" if index in state.cleanup_status_only else
                      "CancelSession" if cancel else "CloseSession")
            while time.monotonic() < deadline:
                try:
                    response = await self._execute_for_request(index, method, self._envelope(
                        index, state=state, timeout=min(5, deadline - time.monotonic())),
                        trusted_request_context=state.trusted_request_context,
                        cleanup=True, state=state)
                    if response.reclaimed:
                        return True
                    if method != "SessionStatus":
                        state.cleanup_status_only.add(index)
                        method = "SessionStatus"
                    await asyncio.sleep(min(0.05, max(0, deadline - time.monotonic())))
                except _PENDING_OPERATION_ERRORS as exc:
                    self._track_pending(state, exc, index=index, method=method)
                    if method in {"CancelSession", "CloseSession"}:
                        state.cleanup_status_only.add(index)
                    if self._live_pending_tasks(state):
                        raise
                    if method != "SessionStatus":
                        method = "SessionStatus"
                        continue
                    return False
                except ProtocolError as exc:
                    # A new process owns no leases from the old boot.
                    if exc.code in {"STALE_WORKER", "UNKNOWN_SESSION"}:
                        return True
                    return False
                except Exception:
                    return False
            return False

        indices = tuple(state.leases)
        operations = [asyncio.create_task(release(index)) for index in indices]
        results = await asyncio.gather(*operations, return_exceptions=True)
        pending_errors = []
        all_released = True
        for index, result in zip(indices, results):
            if isinstance(result, _PENDING_OPERATION_ERRORS):
                pending_errors.append(result)
                self._track_pending(state, result, index=index,
                                    method=("SessionStatus" if index in state.cleanup_status_only
                                            else "CancelSession" if cancel else "CloseSession"))
                all_released = False
            elif isinstance(result, BaseException) or result is not True:
                all_released = False
            else:
                state.leases.pop(index, None)
        live = self._live_pending_tasks(state)
        if pending_errors and live:
            _retain_tasks(live)
            raise SecureTaskPending(live,
                "worker cleanup is waiting for a pending operation to retire")
        return all_released and not state.leases and not state.unknown_opens

    def stats(self):
        return {"ready": self._ready and not self._closed, "active_requests": self._slots,
                "waiting_admissions": len(self._waiting),
                "stage_queue_sizes": [len(queue.items) for queue in self._queues],
                "active_stage_calls": [int(job is not None) for job in self._active_jobs],
                "trace_events": len(self.events), "trace_dropped": self.trace_dropped,
                "trace_errors": self.trace_errors, "model_cleanup_complete": self.model_cleanup_complete}

    async def close(self):
        if self._close_task is None:
            self._close_task = asyncio.create_task(self._close())
        return await asyncio.shield(self._close_task)

    def _own_shutdown_tasks(self, tasks):
        roots = tuple(tasks)
        owned = {task for task in roots if not task.done()}
        owned.update(_pending_task_descendants(roots))
        self._shutdown_pending_tasks.update(owned)
        for task in owned:
            _retain_tasks((task,))
            if not task.done() and task not in self._shutdown_watched_tasks:
                self._shutdown_watched_tasks.add(task)
                task.add_done_callback(self._shutdown_task_finished)
        return tuple(owned)

    def _shutdown_task_finished(self, task):
        # Observe the completed wrapper and attach ownership callbacks to any
        # descendants it reports, including children discovered after close's
        # initial bounded wait has already returned.
        self._own_shutdown_tasks((task,))

    def _live_shutdown_tasks(self):
        roots = tuple(self._shutdown_pending_tasks)
        self._own_shutdown_tasks(roots)
        descendants = tuple(_pending_task_descendants(roots))
        live = {task for task in roots if not task.done()}
        live.update(descendants)
        self._shutdown_pending_tasks.intersection_update(live)
        self._shutdown_pending_tasks.update(live)
        _retain_tasks(live)
        return tuple(live)

    async def _wait_shutdown_tasks_until(self, deadline):
        """Follow globally owned pending work without cancelling its owners."""
        while True:
            live = self._live_shutdown_tasks()
            if not live:
                self._shutdown_pending_tasks.clear()
                self._shutdown_watched_tasks.clear()
                return True
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                _retain_tasks(live)
                return False
            done, pending = await asyncio.wait(live, timeout=remaining)
            # Consume completed wrappers only after recording their descendants
            # through _live_shutdown_tasks on the next iteration.
            if done:
                await asyncio.gather(*done, return_exceptions=True)
            if pending and time.monotonic() >= deadline:
                _retain_tasks(pending)
                return False

    async def _close(self):
        self._closed = True
        self._ready = False
        deadline = time.monotonic() + MAX_CANCELLATION_GRACE_SECONDS
        if self._start_task is not None:
            self._own_shutdown_tasks((self._start_task,))
            if not self._start_task.done():
                self._start_task.cancel()
                _, pending = await asyncio.wait(
                    (self._start_task,),
                    timeout=max(0.0, deadline - time.monotonic()))
                if pending:
                    _retain_tasks(pending)
                    return False
            await asyncio.gather(self._start_task, return_exceptions=True)
            # A completed startup wrapper can still report a live operation
            # child, even if an earlier gather already consumed its exception.
            self._own_shutdown_tasks((self._start_task,))
            if not await self._wait_shutdown_tasks_until(deadline):
                return False
        states = list(self._requests.values())
        for state in states:
            self._abort(state, CoordinatorError("CANCELLED", "Coordinator shut down"))
        request_tasks = tuple(state.task for state in states if state.task is not None)
        if request_tasks:
            _, pending = await asyncio.wait(
                request_tasks, timeout=max(0.0, deadline - time.monotonic()))
            if pending:
                _retain_tasks(pending)
                return False
            await asyncio.gather(*request_tasks, return_exceptions=True)
        for consumer in self._consumers:
            consumer.cancel()
        if self._consumers:
            _, pending = await asyncio.wait(
                self._consumers, timeout=max(0.0, deadline - time.monotonic()))
            if pending:
                _retain_tasks(pending)
                return False
            await asyncio.gather(*self._consumers, return_exceptions=True)
        # A retained request owns worker leases/contexts and may still own a
        # transport task. Closing clients or the model would invalidate that
        # ownership; shutdown remains explicitly fenced until restart.
        if self._requests:
            return False
        close_tasks = tuple(asyncio.create_task(client.close()) for client in self.clients)
        client_close_failed = False
        results = []
        if close_tasks:
            self._own_shutdown_tasks(close_tasks)
            done, pending = await asyncio.wait(
                close_tasks, timeout=max(0.0, deadline - time.monotonic()))
            if done:
                results = await asyncio.gather(*done, return_exceptions=True)
                self._own_shutdown_tasks(done)
            if pending:
                _retain_tasks(pending)
                await self._wait_shutdown_tasks_until(deadline)
                return False
            pending_errors = [result for result in results
                              if isinstance(result, _PENDING_OPERATION_ERRORS)]
            for error in pending_errors:
                self._track_pending(None, error)
            if pending_errors:
                await self._wait_shutdown_tasks_until(deadline)
                return False
            client_close_failed = any(isinstance(result, BaseException) or result is False
                                      for result in results)
            # These are completed wrapper roots; after their error trees have
            # been inspected they no longer need to be held by shutdown.
            self._shutdown_pending_tasks.difference_update(done)
            if not await self._wait_shutdown_tasks_until(deadline):
                return False
        if client_close_failed and self._fatal_error is None:
            self._fatal_error = CoordinatorError(
                "CLOSE_FAILED", "A worker transport did not confirm shutdown")
        closer = getattr(self.model, "close", None)
        if closer is None:
            self.model_cleanup_complete = True
        else:
            async def close_model():
                return await closer()

            model_close = asyncio.create_task(close_model())
            self._own_shutdown_tasks((model_close,))
            done, pending = await asyncio.wait(
                (model_close,), timeout=max(0.0, deadline - time.monotonic()))
            if pending:
                model_close.cancel()
                self._own_shutdown_tasks((model_close,))
                return False
            result = (await asyncio.gather(model_close, return_exceptions=True))[0]
            self._shutdown_pending_tasks.discard(model_close)
            if isinstance(result, _PENDING_OPERATION_ERRORS):
                self._track_pending(None, result)
                await self._wait_shutdown_tasks_until(deadline)
                self.model_cleanup_complete = False
                return False
            if isinstance(result, BaseException):
                if self._fatal_error is None:
                    self._fatal_error = CoordinatorError(
                        "CLOSE_FAILED", "The coordinator model did not confirm shutdown")
                self.model_cleanup_complete = False
            else:
                self.model_cleanup_complete = bool(result)
        return self.model_cleanup_complete and not client_close_failed
