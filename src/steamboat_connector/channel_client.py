"""Coordinator SDK adapter over the owned C2 gateway channel."""
from __future__ import annotations

import asyncio
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
                 control_capture_reservation_bytes):
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
        self._retained, self._active, self._retirement_tasks = set(), set(), set()

    async def execute(self, method, request, *, trusted_request_context):
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
            async with self._lock:
                self._assert_live()
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
            route = self.egress.mint_route_guard(
                method=method, trusted_request_context=trusted_request_context)
            auth = self.authorizer.authorize_gateway_outbound(
                service=WORKER_SERVICE, method=method, payload=source_request,
                trusted_request_context=trusted_request_context,
                gateway_route=route)
            owner["auth"], owner["route"], owner["state"] = auth, route, "active"
            async with self._lock:
                self._assert_live()
                wire_request = Request()
                wire_request.CopyFrom(source_request)
                owner["wire_request"] = wire_request
                remaining = min(await _maybe_await(auth.remaining_seconds()),
                                request_deadline - time.monotonic())
                wire_request.timeout_ms = min(request.timeout_ms, int(remaining * 1000))
                if wire_request.timeout_ms < 1:
                    raise TimeoutError("authorization expires before dispatch")
                raw = serialize_message(wire_request, MAX_MESSAGE_BYTES)
                owner["raw_request"] = raw
                # Apply a fresh authorization/deadline clip after serialization,
                # immediately before the one-way mutation can enter the stream.
                await _maybe_await(auth.assert_live())
                remaining = min(await _maybe_await(auth.remaining_seconds()),
                                request_deadline - time.monotonic())
                wire_request.timeout_ms = min(wire_request.timeout_ms, int(remaining * 1000))
                if wire_request.timeout_ms < 1:
                    raise TimeoutError("authorization expires before dispatch")
                raw = serialize_message(wire_request, MAX_MESSAGE_BYTES)
                owner["raw_request"] = raw
                self.egress.assert_transport_live()
                route.assert_live()
                bundle = wire.encode_bundle(
                    method, wire.REQUEST, fragment_kind=lane,
                    binding=auth.binding_bytes, protobuf=raw)
                owner["bundle"] = bundle
                future = asyncio.get_running_loop().create_future()
                self._pending[message_id] = {
                    "future": future, "auth": auth, "method": method,
                    "request": wire_request, "binding": auth.binding_bytes,
                    "route": route, "control": is_control,
                    "capture": capture, "response_lane": response_lane,
                }
                self.stream.enqueue(kind=lane, message_id=message_id, payload=bundle)
                dispatched = True
                owner["dispatched"] = True
                if self._pump_task is None:
                    self._pump_task = asyncio.create_task(self._pump())
            try:
                response, _correlation = await _run_guarded(
                    self._pending[message_id]["future"], auth,
                    self.authorization_watcher,
                    timeout=wire_request.timeout_ms / 1000,
                    absolute_deadline=request_deadline,
                    on_pending=self._retain_pending,
                    close_authorization_on_pending=False)
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
            await _maybe_await(auth.assert_live())
            await _maybe_await(auth.complete(response))
            completed = True
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
            finally:
                self._active.discard(current_task)

    async def _pump(self):
        try:
            while self._pending and not self._closed:
                self._assert_live()
                for entry in tuple(self._pending.values()):
                    try:
                        entry["route"].assert_live()
                        await _maybe_await(entry["auth"].assert_live())
                    except Exception as error:
                        # A request-scoped authorization can expire while
                        # another independent call remains valid on this stream.
                        future = entry["future"]
                        if not future.done():
                            future.set_exception(error)
                        if isinstance(error, SessionError):
                            entry["abandon_response"] = True
                self.stream.pump()
                message = self.stream.pop_message()
                if message is not None:
                    self._dispatch_response(message)
                await asyncio.sleep(_PUMP_INTERVAL)
        except asyncio.CancelledError:
            raise
        except BaseException:
            self._fence("coordinator gateway stream failed")
            for entry in tuple(self._pending.values()):
                future = entry["future"]
                if not future.done():
                    future.set_exception(ProtocolError(
                        "EXECUTION_FAILED", "gateway generation was lost; operation outcome may be unknown"))
        finally:
            if not self._pending:
                self._pump_task = None

    def _dispatch_response(self, message):
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
            entry["future"].set_result((response, (message.message_id,
                self._generation, entry["binding"])))

    def _assert_live(self):
        if self._closed or self._unavailable or self.stream.closed:
            raise ProtocolError("EXECUTION_FAILED", "coordinator gateway generation is unavailable")
        if (self.stream._hello.egress is not self.egress
                or self.stream._hello.generation != self._generation):
            raise ProtocolError("EXECUTION_FAILED", "coordinator HELLO generation changed")
        self.egress.assert_transport_live()

    def _fence(self, reason):
        self._unavailable = True
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
            self._fence("outbound authorization cleanup is uncertain")
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
