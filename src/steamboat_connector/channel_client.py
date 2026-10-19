"""Coordinator SDK adapter over the owned C2 gateway channel."""
from __future__ import annotations

import asyncio
import inspect
import threading
import time
from typing import Protocol
import weakref

from steamboat_connector import channel_wire as wire
from steamboat_connector.channel_hello import CoordinatorHelloClient
from steamboat_connector.channel_stream import ChannelStream
from steamboat_runtime.protocol import METHODS, MAX_MESSAGE_BYTES
from steamboat_runtime.protocol import MAX_TIMEOUT_MS
from steamboat_runtime.protocol.errors import ProtocolError
from steamboat_runtime.protocol.secure_transport import (
    SecureTaskPending, _maybe_await, _retain_tasks, _run_guarded,
    _wait_owned_tasks,
)
from steamboat_runtime.protocol.wire import (
    Request, Response, parse_message, serialize_message, validate_response,
)
from steamboat_security.codec import WORKER_SERVICE
from steamboat_security.errors import SessionError

_CONTROL = frozenset({"CloseSession", "CancelSession", "SessionStatus"})
_DATA_SLOTS, _CONTROL_SLOTS = 9, 8
_DATA_CAPTURE = (8 * wire.MAX_PROTOBUF_BYTES + wire.MAX_ENVELOPE_BYTES
                 + wire.MAX_BINDING_BYTES + 64 * 1024)
_CONTROL_CAPTURE = (4 * wire.MAX_CONTROL_PROTOBUF_BYTES + wire.MAX_ENVELOPE_BYTES
                    + wire.MAX_BINDING_BYTES + 64 * 1024)
_PUMP_INTERVAL = 0.005
_CLOSE_GRACE = 1.0
_MAX_ABANDONED_IDS = 1024
_STREAM_CLAIM_LOCK = threading.Lock()
_STREAM_CLAIMS = weakref.WeakKeyDictionary()
_CLIENT_TARGET_TOKEN = object()
_CLIENT_TARGET_LOCK = threading.Lock()
_MINTED_CLIENT_TARGETS = weakref.WeakSet()


def _claim_stream(stream):
    # The weak-key tombstone lasts exactly as long as the stream object. Never
    # release a claim: a later client cannot restart IDs or steal replies.
    with _STREAM_CLAIM_LOCK:
        if stream in _STREAM_CLAIMS:
            raise TypeError("coordinator HELLO stream already has a client owner")
        _STREAM_CLAIMS[stream] = True


class SecureWorkerClientProtocol(Protocol):
    async def execute(self, method, request, *, trusted_request_context): ...
    async def close(self): ...


class ChannelClientOwnershipUncertain(RuntimeError):
    """Authorization cleanup failed; its capture remains reserved permanently."""


class CoordinatorChannelClient:
    """Multiplex bounded worker calls over one committed coordinator HELLO stream.

    Per-call capture reservations use the existing relay's conservative
    protobuf/wire/object bound plus 64 KiB temporary headroom. Stream, TLS and
    decoded-queue reservations remain separately owned by ChannelStream.
    C2M1 replies omit a binding, so completion relies on the local immutable
    C1 authorization, exact message ID/method/lane and same live HELLO stream.
    """

    def __init__(self, *, egress, stream: ChannelStream,
                 authorization_watcher, data_capture_reservation_bytes,
                 control_capture_reservation_bytes, runtime_guard=None):
        from steamboat_security.gateway_egress import (
            GatewayCoordinatorEgress, is_owned_gateway_coordinator_egress,
        )
        from steamboat_security.outbound import OutboundAuthorizer
        if (type(egress) is not GatewayCoordinatorEgress
                or not is_owned_gateway_coordinator_egress(egress)
                or type(stream) is not ChannelStream
                or type(stream._hello) is not CoordinatorHelloClient
                or stream._hello.egress is not egress
                or stream._driver._tls is not egress
                or not stream.transport_bootstrap_complete or stream.closed):
            raise TypeError("client requires the exact live coordinator egress HELLO stream")
        if not callable(authorization_watcher):
            raise TypeError("an explicit authorization watcher is required")
        if runtime_guard is not None and (
                not callable(runtime_guard)
                or inspect.iscoroutinefunction(runtime_guard)
                or inspect.isasyncgenfunction(runtime_guard)
                or inspect.iscoroutinefunction(getattr(runtime_guard, "__call__", None))
                or inspect.isasyncgenfunction(getattr(runtime_guard, "__call__", None))):
            raise TypeError("runtime_guard must be a synchronous callback")
        if (type(data_capture_reservation_bytes) is not int
                or data_capture_reservation_bytes < _DATA_SLOTS * _DATA_CAPTURE
                or type(control_capture_reservation_bytes) is not int
                or control_capture_reservation_bytes < _CONTROL_SLOTS * _CONTROL_CAPTURE):
            raise ValueError("separate capture reservations must cover every supported call")
        if (type(egress.authorizer) is not OutboundAuthorizer
                or egress.authorizer.clock is not egress.clock):
            raise TypeError("egress C1 authorizer and Clock owners changed")
        _claim_stream(stream)
        self.egress, self.stream = egress, stream
        self.authorizer = egress.authorizer
        self.authorization_watcher = authorization_watcher
        self._runtime_guard = runtime_guard
        self._runtime_invalidated = threading.Event()
        self._runtime_wake_lock = threading.Lock()
        self._runtime_wake_pending = False
        try:
            self._loop = asyncio.get_running_loop()
        except RuntimeError:
            # Some existing C1 callers construct the client before entering
            # their event loop. The default path never needs a loop handle.
            self._loop = None
        self.data_capture_reservation_bytes = data_capture_reservation_bytes
        self.control_capture_reservation_bytes = control_capture_reservation_bytes
        self._generation = stream._hello.generation
        self._pending = {}
        self._abandoned = {}
        self._owners = {}
        self._next_message_id = 1
        self._data_bytes = self._control_bytes = 0
        self._data_count = self._control_count = 0
        self._lock = asyncio.Lock()
        self._pump_task = None
        self._closed = self._unavailable = self._close_complete = False
        self._unavailable_reason = None
        self._unavailable_cause = None
        self._retained, self._active, self._retirement_tasks = set(), set(), set()
        self._target_proxies = {}

    def request_runtime_invalidation(self, reason):
        """Fence this client from another thread without waiting for its loop.

        The event is the immediate authority fence. Stream closure is coalesced
        onto the owner's loop; callers never close TLS or wait for cleanup.
        """
        if self._runtime_guard is None:
            raise RuntimeError("runtime invalidation requires a configured guard")
        if not isinstance(reason, str) or not reason or len(reason) > 160:
            raise ValueError("runtime invalidation reason must be short text")
        self._runtime_invalidated.set()
        loop = self._loop
        if loop is None:
            try:
                loop = asyncio.get_running_loop()
                self._loop = loop
            except RuntimeError:
                return
        if not self._runtime_wake_lock.acquire(blocking=False):
            return
        try:
            if self._runtime_wake_pending:
                return
            self._runtime_wake_pending = True
            try:
                loop.call_soon_threadsafe(self._apply_runtime_invalidation)
            except RuntimeError:
                # A stopped loop cannot be woken, but the sticky Event still
                # prevents any subsequent operation from admitting work.
                self._runtime_wake_pending = False
        finally:
            self._runtime_wake_lock.release()

    def _apply_runtime_invalidation(self):
        with self._runtime_wake_lock:
            self._runtime_wake_pending = False
        if self._runtime_invalidated.is_set() and not self._unavailable:
            self._fence("C2 coordinator runtime binding was invalidated")

    def _check_runtime_guard(self):
        if self._runtime_invalidated.is_set():
            if not self._unavailable:
                self._fence("C2 coordinator runtime binding was invalidated")
            raise ProtocolError("EXECUTION_FAILED", "coordinator runtime binding is unavailable")
        guard = self._runtime_guard
        if guard is None:
            return
        if self._loop is None:
            try:
                self._loop = asyncio.get_running_loop()
            except RuntimeError:
                pass
        try:
            result = guard()
            if inspect.isawaitable(result):
                close = getattr(result, "close", None)
                if callable(close):
                    close()
                raise TypeError("runtime_guard returned an awaitable")
            if inspect.isasyncgen(result):
                close = result.aclose()
                if inspect.iscoroutine(close):
                    close.close()
                raise TypeError("runtime_guard returned an async generator")
            if result is not None:
                raise TypeError("runtime_guard must return exactly None")
        except BaseException as error:
            self._runtime_invalidated.set()
            self._fence("C2 coordinator runtime guard failed", cause=error)
            raise ProtocolError("EXECUTION_FAILED", "coordinator runtime binding is unavailable") from None
        if self._runtime_invalidated.is_set():
            self._fence("C2 coordinator runtime binding was invalidated")
            raise ProtocolError("EXECUTION_FAILED", "coordinator runtime binding is unavailable")

    def _check_runtime_event(self):
        if self._runtime_invalidated.is_set():
            raise ProtocolError("EXECUTION_FAILED", "coordinator runtime binding is unavailable")

    async def execute(self, method, request, *, trusted_request_context):
        return await self._execute_for(
            self.egress, method, request,
            trusted_request_context=trusted_request_context)

    async def _execute_for(self, route_owner, method, request, *,
                           trusted_request_context):
        from steamboat_security.gateway_egress import (
            GatewayEgressTargetView, is_owned_gateway_target_view,
        )
        if route_owner is not self.egress and (
                type(route_owner) is not GatewayEgressTargetView
                or not is_owned_gateway_target_view(route_owner)
                or route_owner.egress is not self.egress):
            raise ProtocolError("EXECUTION_FAILED", "cohort target view is foreign or stale")
        self._check_runtime_guard()
        if self._closed or self._unavailable or self.stream.closed:
            raise ProtocolError("EXECUTION_FAILED", "coordinator gateway channel is unavailable")
        if method not in METHODS or not isinstance(request, Request):
            raise ProtocolError("INVALID_INPUT", "invalid worker method or protobuf request")
        if trusted_request_context is None:
            raise ValueError("worker calls require explicit trusted request context")
        if (type(request.timeout_ms) is not int
                or not 1 <= request.timeout_ms <= MAX_TIMEOUT_MS
                or request.ByteSize() > MAX_MESSAGE_BYTES):
            raise ProtocolError("INVALID_INPUT", "request timeout or protobuf size exceeds the protocol bound")
        is_control = method in _CONTROL
        if is_control and request.ByteSize() > wire.MAX_CONTROL_PROTOBUF_BYTES:
            raise ProtocolError("INVALID_INPUT", "control request exceeds the control protobuf bound")
        # Shape is the only repeated Request field and the protocol supports
        # at most three dimensions. Check before protobuf CopyFrom can allocate
        # a second native repeated-field container.
        if request.HasField("tensor") and len(request.tensor.shape) > 3:
            raise ProtocolError("INVALID_INPUT", "tensor shape exceeds the protocol structure bound")
        capture = _CONTROL_CAPTURE if is_control else _DATA_CAPTURE
        lane = wire.CONTROL if is_control else wire.DATA
        response_lane = wire.CONTROL_RESPONSE if is_control else wire.RESPONSE
        message_id = None
        auth = None
        transferred = completed = reservation_owned = failed = dispatched = False
        owner = None
        current_task = asyncio.current_task()
        self._active.add(current_task)
        request_deadline = time.monotonic() + request.timeout_ms / 1000
        try:
            self._check_runtime_guard()
            self._assert_live()
            self._check_runtime_guard()
            async with self._lock:
                self._check_runtime_event()
                if self._closed or self._unavailable or self.stream.closed:
                    raise ProtocolError("EXECUTION_FAILED", "coordinator gateway channel is unavailable")
                if self._next_message_id >= (1 << 128):
                    self._fence("generation message ID space is exhausted")
                    raise ProtocolError("EXECUTION_FAILED", "gateway generation message ID space exhausted")
                message_id = self._next_message_id.to_bytes(16, "big")
                self._next_message_id += 1
                owner = {"message_id": message_id, "auth": None,
                         "request": None, "route": None, "capture": capture,
                         "control": is_control, "state": "reserved",
                         "close_attempted": False, "retirement": None}
                self._reserve_capture(is_control, capture)
                reservation_owned = True
                self._owners[message_id] = owner
            # Copy only after the full per-call capture reservation is held.
            source_request = Request()
            source_request.CopyFrom(request)
            owner["request"] = source_request
            self._check_runtime_guard()
            route = route_owner.mint_route_guard(
                method=method, trusted_request_context=trusted_request_context)
            owner["route"] = route
            self._check_runtime_guard()
            auth = route_owner.authorizer.authorize_gateway_outbound(
                service=WORKER_SERVICE, method=method, payload=source_request,
                trusted_request_context=trusted_request_context,
                gateway_route=route)
            owner["auth"], owner["route"], owner["state"] = auth, route, "active"
            self._check_runtime_guard()
            async with self._lock:
                self._check_runtime_event()
                if self._closed or self._unavailable or self.stream.closed:
                    raise ProtocolError("EXECUTION_FAILED", "coordinator gateway channel is unavailable")
                wire_request = Request()
                wire_request.CopyFrom(source_request)
                owner["wire_request"] = wire_request
                remaining = min(await _maybe_await(auth.remaining_seconds()),
                                request_deadline - time.monotonic())
                self._check_runtime_event()
                wire_request.timeout_ms = min(request.timeout_ms, int(remaining * 1000))
                if wire_request.timeout_ms < 1:
                    raise TimeoutError("authorization expires before dispatch")
                raw = serialize_message(wire_request, MAX_MESSAGE_BYTES)
                owner["raw_request"] = raw
                # Apply a fresh authorization/deadline clip after serialization,
                # immediately before the one-way mutation can enter the stream.
                await _maybe_await(auth.assert_live())
                self._check_runtime_event()
                remaining = min(await _maybe_await(auth.remaining_seconds()),
                                request_deadline - time.monotonic())
                self._check_runtime_event()
                wire_request.timeout_ms = min(wire_request.timeout_ms, int(remaining * 1000))
                if wire_request.timeout_ms < 1:
                    raise TimeoutError("authorization expires before dispatch")
                raw = serialize_message(wire_request, MAX_MESSAGE_BYTES)
                owner["raw_request"] = raw
            self._check_runtime_guard()
            self.egress.assert_transport_live()
            route.assert_live()
            self._check_runtime_guard()
            bundle = wire.encode_bundle(
                method, wire.REQUEST, fragment_kind=lane,
                binding=auth.binding_bytes, protobuf=raw)
            owner["bundle"] = bundle
            future = asyncio.get_running_loop().create_future()
            # Everything through enqueue is loop-confined and contains no
            # await, keeping owner callbacks outside the admission lock.
            self._check_runtime_event()
            if self._closed or self._unavailable or self.stream.closed:
                raise ProtocolError("EXECUTION_FAILED", "coordinator gateway channel is unavailable")
            self._pending[message_id] = {
                "future": future, "auth": auth, "method": method,
                "request": wire_request, "binding": auth.binding_bytes,
                "route": route, "control": is_control,
                "capture": capture, "response_lane": response_lane,
            }
            self._check_runtime_event()
            self.stream.enqueue(kind=lane, message_id=message_id, payload=bundle)
            dispatched = True
            owner["dispatched"] = True
            if self._pump_task is None:
                self._pump_task = asyncio.create_task(self._pump())
            try:
                self._check_runtime_guard()
                response, _correlation = await _run_guarded(
                    self._pending[message_id]["future"], auth,
                    self.authorization_watcher,
                    timeout=wire_request.timeout_ms / 1000,
                    absolute_deadline=request_deadline,
                    on_pending=self._retain_pending,
                    close_authorization_on_pending=False)
                self._check_runtime_guard()
            except SecureTaskPending as error:
                transferred = error.authorization_transferred
                pending_entry = self._pending.get(message_id)
                if dispatched and pending_entry is not None:
                    pending_entry["abandon_response"] = True
                if transferred and reservation_owned:
                    owner["state"] = "pending"
                    cleanup_task = asyncio.create_task(
                        self._release_after(error.tasks, owner, failed=True,
                                            cache_may_exist=dispatched and method != "Describe"))
                    self._track_retirement(cleanup_task)
                raise
            if _correlation != (message_id, self._generation, auth.binding_bytes):
                raise ProtocolError("EXECUTION_FAILED", "gateway response correlation changed")
            response = validate_response(method, wire_request, response)
            self._check_runtime_guard()
            await _maybe_await(auth.assert_live())
            self._check_runtime_guard()
            await _maybe_await(auth.complete(response))
            completed = True
            self._check_runtime_guard()
            return response
        except asyncio.CancelledError:
            failed = True
            if dispatched:
                pending_entry = self._pending.get(message_id)
                if pending_entry is not None:
                    pending_entry["abandon_response"] = True
            raise
        except BaseException:
            failed = not completed
            pending_entry = self._pending.get(message_id)
            if (dispatched and not completed and pending_entry is not None
                    and not pending_entry.get("response_received")):
                pending_entry["abandon_response"] = True
            raise
        finally:
            entry = self._pending.pop(message_id, None)
            if (dispatched and entry is not None and entry.get("abandon_response")
                    and not entry.get("response_received")):
                if len(self._abandoned) >= _MAX_ABANDONED_IDS:
                    self._fence("abandoned response-ID bound exhausted")
                else:
                    self._abandoned[message_id] = (
                        method, response_lane, self._generation)
            if entry is not None and not entry["future"].done():
                entry["future"].cancel()
            try:
                if owner is not None and reservation_owned and not transferred:
                    await self._retire_owner(
                        owner, failed=failed,
                        cache_may_exist=dispatched and method != "Describe")
                    if completed:
                        # A result is not delivered until exact C1 retirement
                        # and the final C2 owner check both complete.
                        self._check_runtime_guard()
            finally:
                self._active.discard(current_task)

    def bind_target(self, target_view):
        """Bind one minted target route to this client's shared stream pump."""
        from steamboat_security.gateway_egress import (
            GatewayEgressTargetView, is_owned_gateway_target_view,
        )
        self._check_runtime_guard()
        if (type(target_view) is not GatewayEgressTargetView
                or not is_owned_gateway_target_view(target_view)
                or target_view.egress is not self.egress):
            raise TypeError("target view must belong to this exact egress")
        if self._closed or self._unavailable or self.stream.closed:
            raise ProtocolError("EXECUTION_FAILED", "coordinator gateway client is unavailable")
        self._assert_live()
        target_view.assert_transport_live()
        self._check_runtime_guard()
        key = target_view._key
        existing = self._target_proxies.get(key)
        if existing is not None:
            if existing._target_view is target_view:
                return existing
            raise TypeError("target tuple is already bound to another client proxy")
        proxy = CoordinatorChannelTargetClient(
            _CLIENT_TARGET_TOKEN, self, target_view)
        with _CLIENT_TARGET_LOCK:
            _MINTED_CLIENT_TARGETS.add(proxy)
        self._target_proxies[key] = proxy
        return proxy

    async def _pump(self):
        try:
            while self._pending and not self._closed:
                self._assert_live()
                for entry in tuple(self._pending.values()):
                    try:
                        entry["route"].assert_live()
                        self._check_runtime_guard()
                        await _maybe_await(entry["auth"].assert_live())
                        self._check_runtime_guard()
                    except SessionError:
                        # A request-scoped authorization can expire while
                        # another independent call remains valid on this stream.
                        future = entry["future"]
                        if not future.done():
                            # Never hand another task the caught exception:
                            # its traceback points into this suspended pump
                            # frame, which secure_transport cleanup may clear.
                            future.set_exception(SessionError(
                                "outbound request authorization expired"))
                        entry["abandon_response"] = True
                self._check_runtime_guard()
                self.stream.pump()
                self._check_runtime_guard()
                message = self.stream.pop_message()
                if message is not None:
                    self._check_runtime_guard()
                    self._dispatch_response(message)
                await asyncio.sleep(_PUMP_INTERVAL)
        except asyncio.CancelledError:
            raise
        except BaseException as error:
            self._fence("coordinator gateway stream failed", cause=error)
            for entry in tuple(self._pending.values()):
                future = entry["future"]
                if not future.done():
                    future.set_exception(ProtocolError(
                        "EXECUTION_FAILED", "gateway generation was lost; operation outcome may be unknown"))
        finally:
            if not self._pending:
                self._pump_task = None

    def _dispatch_response(self, message):
        self._check_runtime_guard()
        entry = self._pending.get(message.message_id)
        if entry is None:
            tombstone = self._abandoned.get(message.message_id)
            if (tombstone is None or message.kind != tombstone[1]
                    or message.generation != tombstone[2]):
                raise ProtocolError("EXECUTION_FAILED", "unexpected gateway response ID or lane")
            decoded = wire.decode_bundle(message.payload, fragment_kind=message.kind)
            if (decoded.classification != wire.BUNDLE_RESPONSE
                    or decoded.method != tombstone[0]):
                raise ProtocolError("EXECUTION_FAILED", "late gateway response differs from its abandoned call")
            del self._abandoned[message.message_id]
            return
        if (message.kind != entry["response_lane"]
                or message.generation != self._generation):
            raise ProtocolError("EXECUTION_FAILED", "unexpected gateway response ID or lane")
        decoded = wire.decode_bundle(message.payload, fragment_kind=message.kind)
        if decoded.classification != wire.BUNDLE_RESPONSE or decoded.method != entry["method"]:
            raise ProtocolError("EXECUTION_FAILED", "gateway response method differs from its pending call")
        # The response omits C1 binding by C2M1 design. This immutable local
        # correlation binds the reply to exact message/method/lane and owner generation.
        from steamboat_connector.channel_protobuf import preflight_worker_protobuf
        preflight_worker_protobuf(decoded.protobuf, response=True,
                                  max_bytes=MAX_MESSAGE_BYTES)
        response = parse_message(decoded.protobuf, Response, MAX_MESSAGE_BYTES)
        entry["response_received"] = True
        if not entry["future"].done():
            self._check_runtime_guard()
            entry["future"].set_result((response, (message.message_id,
                self._generation, entry["binding"])))

    def _assert_live(self):
        # This helper is also used inside the capture lock. It only reads the
        # sticky event there; caller-owned guard callbacks run outside locks.
        self._check_runtime_event()
        if self._closed or self._unavailable or self.stream.closed:
            raise ProtocolError("EXECUTION_FAILED", "coordinator gateway generation is unavailable")
        if (self.stream._hello.egress is not self.egress
                or self.stream._hello.generation != self._generation):
            raise ProtocolError("EXECUTION_FAILED", "coordinator HELLO generation changed")
        self.egress.assert_transport_live()

    def _fence(self, reason, *, cause=None):
        self._unavailable = True
        if self._unavailable_reason is None:
            self._unavailable_reason = reason
            self._unavailable_cause = type(cause).__name__ if cause is not None else None
        self.stream.close()
        for entry in tuple(self._pending.values()):
            future = entry["future"]
            if not future.done():
                future.set_exception(ProtocolError("EXECUTION_FAILED", reason))

    def _release(self, control, capture):
        if control:
            self._control_bytes -= capture
            self._control_count -= 1
        else:
            self._data_bytes -= capture
            self._data_count -= 1

    def _reserve_capture(self, control, capture):
        if control:
            if (self._control_count >= _CONTROL_SLOTS
                    or self._control_bytes + capture > self.control_capture_reservation_bytes):
                raise ProtocolError("EXECUTION_FAILED", "control call capacity exhausted")
            self._control_bytes += capture
            self._control_count += 1
        else:
            if (self._data_count >= _DATA_SLOTS
                    or self._data_bytes + capture > self.data_capture_reservation_bytes):
                raise ProtocolError("EXECUTION_FAILED", "data call capacity exhausted")
            self._data_bytes += capture
            self._data_count += 1

    def _retain_pending(self, tasks):
        self._unavailable = True
        if self._unavailable_reason is None:
            self._unavailable_reason = "secure operation transferred pending task ownership"
            self._unavailable_cause = "SecureTaskPending"
        for task in tasks:
            self._retained.add(task)
            task.add_done_callback(self._retained.discard)

    async def _release_after(self, tasks, owner, *, failed, cache_may_exist):
        await _wait_owned_tasks(tuple(tasks))
        await self._retire_owner(owner, failed=failed,
                                  cache_may_exist=cache_may_exist)

    def _track_retirement(self, task):
        self._retirement_tasks.add(task)
        self._retained.add(task)
        def finished(done):
            self._retirement_tasks.discard(done)
            self._retained.discard(done)
            # Consume detached cleanup failures; the operation owner records
            # them permanently and close() reports the sticky uncertainty.
            if not done.cancelled():
                done.exception()
        task.add_done_callback(finished)

    async def _retire_owner(self, owner, *, failed, cache_may_exist):
        task = owner.get("retirement")
        if task is None:
            task = asyncio.create_task(self._finish_owner(
                owner, failed=failed, cache_may_exist=cache_may_exist))
            owner["retirement"] = task
            self._track_retirement(task)
        try:
            await asyncio.shield(task)
        except asyncio.CancelledError:
            _retain_tasks((task,))
            raise

    async def _finish_owner(self, owner, *, failed, cache_may_exist):
        auth = owner.get("auth")
        failure_error = None
        if auth is not None and failed:
            try:
                await _maybe_await(auth.fail(cache_may_exist=cache_may_exist))
            except BaseException as error:
                failure_error = error
        close_error = None
        if auth is not None and not owner["close_attempted"]:
            owner["close_attempted"] = True
            owner["state"] = "closing"
            try:
                await _maybe_await(auth.close())
            except BaseException as error:
                close_error = error
        if failure_error is not None or close_error is not None:
            owner["state"] = "uncertain"
            owner["cleanup_error"] = close_error or failure_error
            self._fence("outbound authorization cleanup is uncertain",
                        cause=close_error or failure_error)
            raise ChannelClientOwnershipUncertain(
                "authorization fail/close did not complete; capture remains owned") from (close_error or failure_error)
        owner["state"] = "closed"
        self._release(owner["control"], owner["capture"])
        self._owners.pop(owner["message_id"], None)

    async def close(self):
        if self._close_complete:
            return
        self._closed = True
        self._fence("coordinator gateway client closed")
        pump = self._pump_task
        if pump is not None and not pump.done():
            pump.cancel()
            try:
                await asyncio.wait_for(asyncio.gather(pump, return_exceptions=True),
                                       timeout=_CLOSE_GRACE)
            except asyncio.TimeoutError:
                self._retained.add(pump)
                pump.add_done_callback(self._retained.discard)
        active = tuple(task for task in self._active if task is not asyncio.current_task())
        if active:
            _done, pending = await asyncio.wait(active, timeout=_CLOSE_GRACE)
            if pending:
                self._retained.update(pending)
                _retain_tasks(pending)
                raise SecureTaskPending(pending,
                    "coordinator calls still own authorization and capture reservations")
        retained = tuple(task for task in self._retained if not task.done())
        if retained:
            _done, pending = await asyncio.wait(retained, timeout=_CLOSE_GRACE)
            if pending:
                _retain_tasks(pending)
                raise SecureTaskPending(pending,
                    "gateway channel still owns pending authorization or captures")
        if self._owners:
            raise ChannelClientOwnershipUncertain(
                "gateway client retains authorization owners with uncertain cleanup")
        self.egress.close()
        self._close_complete = True


class CoordinatorChannelTargetClient:
    """Sealed target-specific SDK surface sharing one coordinator client."""

    __slots__ = ("_client", "_target_view", "_token", "__weakref__")

    def __init__(self, token, client, target_view):
        if token is not _CLIENT_TARGET_TOKEN:
            raise TypeError("target clients are minted by CoordinatorChannelClient")
        object.__setattr__(self, "_client", client)
        object.__setattr__(self, "_target_view", target_view)
        object.__setattr__(self, "_token", token)

    def __setattr__(self, _name, _value):
        raise AttributeError("coordinator target client is immutable")

    @property
    def authorizer(self):
        return self._target_view.authorizer

    @property
    def egress(self):
        return self._client.egress

    async def execute(self, method, request, *, trusted_request_context):
        with _CLIENT_TARGET_LOCK:
            minted = self in _MINTED_CLIENT_TARGETS
        if not minted or self._token is not _CLIENT_TARGET_TOKEN:
            raise ProtocolError("EXECUTION_FAILED", "coordinator target client is forged")
        return await self._client._execute_for(
            self._target_view, method, request,
            trusted_request_context=trusted_request_context)

    async def close(self):
        """Close the shared coordinator channel and every cohort target."""
        with _CLIENT_TARGET_LOCK:
            minted = self in _MINTED_CLIENT_TARGETS
        if not minted or self._token is not _CLIENT_TARGET_TOKEN:
            raise ProtocolError("EXECUTION_FAILED", "coordinator target client is forged")
        await self._client.close()
