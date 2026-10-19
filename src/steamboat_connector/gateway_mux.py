"""Bounded single-pump demultiplexing for one C2 coordinator cohort.

This service owns one coordinator stream and a fixed set of registered worker
streams.  It deliberately calls the existing relay's authenticated message
handlers, never its competing ``run`` loop.
"""
from __future__ import annotations

import asyncio
import threading
import time

from steamboat_connector import channel_wire as wire
from steamboat_connector.channel_hello import (
    CoordinatorHelloServer, RegisteredCoordinator, RegisteredWorker,
)
from steamboat_connector.channel_writer import ChannelFragmentWriter
from steamboat_connector.channel_protobuf import preflight_worker_protobuf
from steamboat_connector.channel_rpc import (
    GatewayChannelRelay, _CONTROL_CAPTURE_BYTES,
    _CONTROL_LIMIT, _DATA_LIMIT, _RELAY_CAPTURE_BYTES,
    _binding, _MONITOR_INTERVAL, _PUMP_INTERVAL,
)
from steamboat_connector.channel_stream import (
    ChannelStream, is_registered_worker_channel_stream,
)
from steamboat_connector.gateway_router import GatewayRouter
from steamboat_runtime.protocol import MAX_MESSAGE_BYTES
from steamboat_runtime.protocol.wire import Request, parse_message, serialize_message

_MAX_WORKERS = 3
_MAX_MESSAGE_IDS = 1024
_CLAIM_LOCK = threading.Lock()
_MAX_LIVE_MUXES = 8
_MAX_CLAIMED_RESOURCES = _MAX_LIVE_MUXES * 2 * (_MAX_WORKERS + 1)
_RESOURCE_CLAIMS = {}
_LIVE_MUXES = set()
_RETAINED_MUXES = set()


class GatewayMuxError(RuntimeError):
    """A mux cohort cannot safely continue."""


class GatewayChannelMultiplexer:
    """One coordinator pump demultiplexing to at most three genuine workers."""

    def __init__(self, *, coordinator_stream, worker_streams, router,
                 data_capture_reservation_bytes,
                 control_capture_reservation_bytes):
        if (type(coordinator_stream) is not ChannelStream
                or type(coordinator_stream._hello) is not CoordinatorHelloServer):
            raise TypeError("mux requires an actual coordinator server HELLO stream")
        if type(router) is not GatewayRouter:
            raise TypeError("mux requires the concrete gateway router")
        coordinator = coordinator_stream.registration
        if type(coordinator) is not RegisteredCoordinator:
            raise TypeError("mux requires the committed coordinator HELLO capability")
        if (coordinator_stream._driver._tls is not coordinator_stream._hello.owner
                or not coordinator_stream.transport_bootstrap_complete
                or coordinator_stream.closed):
            raise GatewayMuxError("coordinator stream is not the live HELLO owner")
        coordinator_writer = coordinator_stream.writer
        if type(coordinator_writer) is not ChannelFragmentWriter:
            raise GatewayMuxError("coordinator stream lacks its actual owned writer")
        if type(worker_streams) is not tuple:
            raise TypeError("worker streams must be a fixed immutable tuple")
        streams = worker_streams
        if not 1 <= len(streams) <= _MAX_WORKERS:
            raise ValueError("mux worker stream tuple must contain one to three streams")
        data_min = _DATA_LIMIT * _RELAY_CAPTURE_BYTES
        control_min = _CONTROL_LIMIT * _CONTROL_CAPTURE_BYTES
        if type(data_capture_reservation_bytes) is not int or data_capture_reservation_bytes < data_min:
            raise ValueError("data reservation must cover the aggregate bounded request captures")
        if (type(control_capture_reservation_bytes) is not int
                or control_capture_reservation_bytes < control_min):
            raise ValueError("control reservation must cover the aggregate bounded request captures")
        workers = {}
        worker_writers = {}
        for stream in streams:
            if not is_registered_worker_channel_stream(stream):
                raise TypeError("mux workers must be live registered server HELLO streams")
            capability = stream.registration
            if (type(capability) is not RegisteredWorker
                    or stream._driver._tls is not stream._hello.owner
                    or not stream.transport_bootstrap_complete):
                raise GatewayMuxError("worker stream is not its actual committed HELLO owner")
            identity = capability.identity
            writer = stream.writer
            if type(writer) is not ChannelFragmentWriter:
                raise GatewayMuxError("worker stream lacks its actual owned writer")
            key = (identity[1], identity[2])
            if key in workers:
                raise GatewayMuxError("worker tuple repeats an exact device/boot slot")
            slot = router._slot(*key)
            if slot.registration is not capability or slot.stream is not stream:
                raise GatewayMuxError("worker is not the exact router-registered stream")
            if slot.writer is not writer:
                raise GatewayMuxError("worker stream writer differs from its router slot")
            workers[key] = (stream, capability, identity)
            worker_writers[key] = writer
        self.coordinator_stream = coordinator_stream
        self.coordinator = coordinator
        self._coordinator_identity = coordinator.identity
        self.router = router
        self._workers = workers
        self._coordinator_writer = coordinator_writer
        self._worker_writers = worker_writers
        self._relays = {
            key: GatewayChannelRelay(
                coordinator_stream=coordinator_stream, worker_stream=entry[0],
                router=router,
                data_capture_reservation_bytes=data_capture_reservation_bytes,
                control_capture_reservation_bytes=control_capture_reservation_bytes)
            for key, entry in workers.items()
        }
        self.data_capture_reservation_bytes = data_capture_reservation_bytes
        self.control_capture_reservation_bytes = control_capture_reservation_bytes
        self._pending = {}  # wire ID -> (worker key, method, lane, generation)
        self._seen = set()
        self._data_bytes = 0
        self._control_bytes = 0
        self._data_count = 0
        self._control_count = 0
        self._capture_by_id = {}
        self._last_monitor = time.monotonic()
        self._accepting = True
        self._pump_lock = threading.Lock()
        self._stop_lock = threading.Lock()
        self._close_once = set()
        self._stuck = []
        self._failure = None
        self._claims_finalized = False
        claim_resources = (coordinator_stream, coordinator_writer,
                           *(item[0] for item in workers.values()),
                           *(worker_writers[key] for key in workers))
        markers = tuple(id(resource) for resource in claim_resources)
        with _CLAIM_LOCK:
            if len(_LIVE_MUXES) + len(_RETAINED_MUXES) >= _MAX_LIVE_MUXES:
                raise GatewayMuxError("global live/uncertain mux cohort bound is exhausted")
            if len(_RESOURCE_CLAIMS) + len(markers) > _MAX_CLAIMED_RESOURCES:
                raise GatewayMuxError("global claimed stream/writer bound is exhausted")
            if any((marker in _RESOURCE_CLAIMS
                    and _RESOURCE_CLAIMS[marker][0] is resource)
                   for marker, resource in zip(markers, claim_resources)):
                raise GatewayMuxError("a captured stream or writer already has a mux owner")
            if len(set(markers)) != len(markers):
                raise GatewayMuxError("mux cohort repeats a captured stream or writer")
            _LIVE_MUXES.add(self)
            for marker, resource in zip(markers, claim_resources):
                _RESOURCE_CLAIMS[marker] = (resource, self)
        self._claim_resources = claim_resources

    @property
    def pending_counts(self):
        return self._data_count, self._control_count

    @property
    def pending_capture_bytes(self):
        return self._data_bytes, self._control_bytes

    def _assert_live(self):
        if not self._accepting:
            raise GatewayMuxError("mux cohort is stopped")
        self.coordinator.assert_live()
        if (self.coordinator_stream.registration is not self.coordinator
                or self.coordinator.identity != self._coordinator_identity
                or self.coordinator_stream.closed
                or self.coordinator_stream.writer is not self._coordinator_writer
                or self.coordinator_stream._driver._tls is not self.coordinator_stream._hello.owner):
            raise GatewayMuxError("captured coordinator stream was replaced or closed")
        for key, (stream, capability, identity) in self._workers.items():
            if (not is_registered_worker_channel_stream(stream)
                    or stream.registration is not capability
                    or capability.identity != identity
                    or stream.writer is not self._worker_writers[key]
                    or stream._driver._tls is not stream._hello.owner):
                raise GatewayMuxError("captured worker cohort member was replaced or closed")
            slot = self.router._slot(*key)
            if slot.stream is not stream or slot.registration is not capability:
                raise GatewayMuxError("captured router worker slot was replaced")

    def _reserve(self, message):
        if type(message.message_id) is not bytes or len(message.message_id) != 16:
            raise GatewayMuxError("wire message ID has an invalid shape")
        if message.message_id in self._seen:
            raise GatewayMuxError("wire message ID was reused in this coordinator generation")
        if len(self._seen) >= _MAX_MESSAGE_IDS:
            raise GatewayMuxError("bounded wire message ID history is exhausted")
        control = message.kind == wire.CONTROL
        if message.kind not in (wire.DATA, wire.CONTROL):
            raise GatewayMuxError("coordinator sent an unsupported request lane")
        if (control and self._control_count >= _CONTROL_LIMIT
                or not control and self._data_count >= _DATA_LIMIT):
            raise GatewayMuxError("aggregate mux pending count is exhausted")
        charge = _CONTROL_CAPTURE_BYTES if control else _RELAY_CAPTURE_BYTES
        if control:
            if self._control_bytes + charge > self.control_capture_reservation_bytes:
                raise GatewayMuxError("aggregate mux control capture reservation is exhausted")
            self._control_bytes += charge
            self._control_count += 1
        else:
            if self._data_bytes + charge > self.data_capture_reservation_bytes:
                raise GatewayMuxError("aggregate mux data capture reservation is exhausted")
            self._data_bytes += charge
            self._data_count += 1
        self._seen.add(message.message_id)
        self._capture_by_id[message.message_id] = (control, charge)
        return control

    def _select(self, message, control):
        decoded = wire.decode_bundle(message.payload, fragment_kind=message.kind)
        if decoded.classification != wire.REQUEST:
            raise GatewayMuxError("coordinator frame is not an RPC request")
        _metadata, binding = _binding(decoded)
        fields = binding.fields
        channel = self.coordinator_stream._hello.channel
        channel.assert_live()
        if (fields["account_id"] != channel.actor_account_id
                or fields["device_id"] != channel.actor_device_id
                or fields["role"] != "personal_coordinator"
                or fields["credential_epoch"] != channel.actor_credential_epoch
                or type(fields.get("target_device_id")) is not str
                or not fields["target_device_id"]):
            raise GatewayMuxError("request C1 actor or target is not authenticated")
        if (message.kind == wire.CONTROL) != (decoded.method in {
                "CloseSession", "CancelSession", "SessionStatus"}):
            raise GatewayMuxError("request method does not match its wire lane")
        preflight_worker_protobuf(decoded.protobuf, response=False,
                                  max_bytes=MAX_MESSAGE_BYTES)
        request = parse_message(decoded.protobuf, Request, MAX_MESSAGE_BYTES)
        if serialize_message(request, MAX_MESSAGE_BYTES) != decoded.protobuf:
            raise GatewayMuxError("request protobuf is not in canonical wire form")
        boot_id = request.worker_boot_id
        if type(boot_id) is not str or not boot_id:
            raise GatewayMuxError("request protobuf lacks an exact worker boot ID")
        key = (fields["target_device_id"], boot_id)
        selected = self._workers.get(key)
        if selected is None:
            raise GatewayMuxError("request target is not an exact captured worker generation")
        _stream, capability, identity = selected
        if "worker_boot_id" in fields and fields["worker_boot_id"] != boot_id:
            raise GatewayMuxError("binding boot ID differs from the request protobuf")
        channel_target = capability._RegisteredWorker__channel
        channel_target.assert_live()
        owner = channel._owner_ref()
        if owner is None:
            raise GatewayMuxError("coordinator TLS policy owner is unavailable")
        policy_worker = owner.policy_store.current().worker(key[0], key[1])
        if policy_worker is None:
            raise GatewayMuxError("selected worker is absent from current channel policy")
        if ("assignment_id" in fields
                and fields["assignment_id"] != policy_worker["assignment_id"]):
            raise GatewayMuxError("binding assignment differs from selected worker policy")
        relay = self._relays[key]
        # Its normal path performs full binding, authorization, route minting,
        # exact writer admission, and per-stream pending registration.
        relay._forward(message)
        entry = relay._pending.get(message.message_id)
        if entry is None:
            raise GatewayMuxError("selected relay did not retain the admitted request")
        self._pending[message.message_id] = (key, decoded.method,
                                             "control" if control else "data", identity[3])

    def _return_from(self, key, message):
        if message.kind == wire.HEARTBEAT:
            self._relays[key]._return(message)
            return
        pending = self._pending.get(message.message_id)
        if pending is None or pending[0] != key:
            raise GatewayMuxError("response came from a worker other than its captured owner")
        decoded = wire.decode_bundle(message.payload, fragment_kind=message.kind)
        if (decoded.method != pending[1]
                or self._workers[key][2][3] != pending[3]):
            raise GatewayMuxError("response method or generation differs from pending request")
        self._assert_live()
        relay = self._relays[key]
        relay._return(message)
        del self._pending[message.message_id]
        control, charge = self._capture_by_id.pop(message.message_id)
        if control:
            self._control_count -= 1
            self._control_bytes -= charge
        else:
            self._data_count -= 1
            self._data_bytes -= charge

    def pump_once(self):
        """Pump/pop each captured stream exactly once and route available frames."""
        if not self._pump_lock.acquire(blocking=False):
            raise GatewayMuxError("mux pump already has an owner")
        try:
            self._assert_live()
            self.coordinator_stream.pump()
            for key, relay in self._relays.items():
                for entry in tuple(relay._pending.values()):
                    self.router.assert_dispatch_live(
                        coordinator=self.coordinator, worker=relay.worker,
                        route_guard=entry[4], method=entry[1])
            for stream, _capability, _identity in self._workers.values():
                stream.pump()
            message = self.coordinator_stream.pop_message()
            if message is not None:
                if message.kind == wire.HEARTBEAT:
                    pass
                else:
                    control = self._reserve(message)
                    self._select(message, control)
            for key, (stream, _capability, _identity) in self._workers.items():
                response = stream.pop_message()
                if response is not None:
                    self._return_from(key, response)
            now = time.monotonic()
            if now - self._last_monitor >= _MONITOR_INTERVAL:
                self._last_monitor = now
                self.router.check_heartbeat_liveness()
                for _key, (_stream, capability, _identity) in self._workers.items():
                    self.router.enqueue_heartbeat(worker=capability)
        except BaseException as error:
            self._failure = type(error).__name__
            self.stop()
            raise
        finally:
            self._pump_lock.release()
            if not self._accepting:
                self._finalize_retirement()

    async def run(self):
        try:
            while self._accepting:
                self.pump_once()
                await asyncio.sleep(_PUMP_INTERVAL)
        finally:
            self.stop()

    def _finalize_retirement(self):
        """Release global claims only after the pump and close outcomes are known."""
        if self._accepting or not self._pump_lock.acquire(blocking=False):
            with _CLAIM_LOCK:
                if not self._claims_finalized:
                    _LIVE_MUXES.discard(self)
                    _RETAINED_MUXES.add(self)
            return
        try:
            clean = (len(self._close_once) == 1 + len(self._workers)
                     and not self._stuck and not self._pending
                     and not self._capture_by_id and self._failure is None)
            with _CLAIM_LOCK:
                if self._claims_finalized:
                    return
                _LIVE_MUXES.discard(self)
                if clean:
                    _RETAINED_MUXES.discard(self)
                    for resource in self._claim_resources:
                        marker = id(resource)
                        claim = _RESOURCE_CLAIMS.get(marker)
                        if claim is not None and claim[0] is resource and claim[1] is self:
                            del _RESOURCE_CLAIMS[marker]
                    self._claims_finalized = True
                else:
                    _RETAINED_MUXES.add(self)
        finally:
            self._pump_lock.release()

    def stop(self):
        """Close each captured stream at most once; retain uncertain pending state."""
        with self._stop_lock:
            self._accepting = False
            cohort = (self.coordinator_stream,
                      *(item[0] for item in self._workers.values()))
            for stream in cohort:
                marker = id(stream)
                if marker in self._close_once:
                    continue
                self._close_once.add(marker)
                try:
                    stream.close()
                except BaseException as error:
                    self._stuck.append((stream, type(error).__name__))
        self._finalize_retirement()

