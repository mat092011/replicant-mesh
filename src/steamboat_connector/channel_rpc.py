"""Bounded RPC execution and relay for authenticated, metered C2 streams.

The worker dispatcher accepts only the actual client-side HELLO stream bound to
its GatewayWorkerIngress. The gateway relay accepts only server-side HELLO
streams and delegates every worker call through GatewayRouter.
"""
from __future__ import annotations

import asyncio
import json
import time

from steamboat_connector import channel_wire as wire
from steamboat_connector.channel_heartbeat import PING, PONG, decode_heartbeat, encode_heartbeat
from steamboat_connector.channel_hello import (
    CoordinatorHelloServer, RegisteredCoordinator, WorkerHelloClient,
    WorkerHelloServer, RegisteredWorker,
)
from steamboat_connector.channel_stream import ChannelStream
from steamboat_runtime.protocol import METHODS, MAX_MESSAGE_BYTES
from steamboat_runtime.protocol.secure_transport import _run_guarded, SecureTaskPending
from steamboat_runtime.protocol.wire import (
    Request, Response, parse_message, serialize_message, validate_response,
)
from steamboat_security.codec import METADATA_KEY, parse_metadata


class ChannelRpcError(RuntimeError):
    """Authenticated C2 message or execution failed closed."""


_CLEANUP = frozenset({"CloseSession", "CancelSession", "SessionStatus"})
_DATA_LIMIT = 9  # one active plus eight pending
_CONTROL_LIMIT = 8
_PUMP_INTERVAL = 0.005
_MONITOR_INTERVAL = 5.0


def _delegation_sequence(envelope):
    if type(envelope) is not bytes or not 1 <= len(envelope) <= wire.MAX_ENVELOPE_BYTES:
        raise ChannelRpcError("delegation envelope is outside its bound")
    try:
        outer = json.loads(envelope.decode("utf-8", "strict"))
        payload = outer["payload"]
        sequence = payload["frame_sequence"]
    except (UnicodeError, ValueError, TypeError, KeyError) as error:
        raise ChannelRpcError("delegation envelope lacks a logical sequence") from error
    if type(sequence) is not int or not 1 <= sequence <= wire.MAX_SEQUENCE:
        raise ChannelRpcError("delegation logical sequence is invalid")
    return sequence


def _binding(decoded):
    metadata = ((METADATA_KEY, decoded.binding),)
    binding = parse_metadata("steamboat.v1.Worker", decoded.method, metadata)
    return metadata, binding


class WorkerChannelRpc:
    """Drive one real worker HELLO stream while dispatching bounded RPC tasks."""

    def __init__(self, *, stream: ChannelStream, bridge):
        if type(stream) is not ChannelStream or type(stream._hello) is not WorkerHelloClient:
            raise TypeError("worker RPC requires a client-side WorkerHelloClient stream")
        hello = stream._hello
        if (stream._driver._tls is not hello.tls_owner or hello.ingress._tls_owner is not hello.tls_owner
                or not stream.transport_bootstrap_complete or stream.closed):
            raise ChannelRpcError("worker RPC stream is not the exact committed ingress owner")
        if (getattr(bridge, "authorizer_core", None) is None
                or bridge.authorizer_core.local_identity.boot_id != hello.ingress.worker_identity[1]):
            raise TypeError("worker bridge and HELLO ingress identify different worker boots")
        self.stream = stream
        self.hello = hello
        self.ingress = hello.ingress
        self.bridge = bridge
        self._accepting = True
        self._active = set()
        self._data_count = 0
        self._control_count = 0
        self._last_monitor = 0.0

    async def run(self):
        """Pump independently of model work; any uncertain fault retires this stream."""
        try:
            await self.bridge.start()
            while self._accepting and not self.stream.closed:
                self.stream.pump()
                message = self.stream.pop_message()
                if message is not None:
                    if message.kind == wire.HEARTBEAT:
                        self._handle_ping(message)
                    elif message.kind in (wire.DATA, wire.CONTROL):
                        self._admit(message)
                    else:
                        raise ChannelRpcError("worker stream received an invalid RPC frame kind")
                now = time.monotonic()
                if now - self._last_monitor >= _MONITOR_INTERVAL:
                    self._last_monitor = now
                    if self.ingress.poll_unavailable():
                        raise ChannelRpcError("worker gateway ingress expired or changed policy")
                await asyncio.sleep(_PUMP_INTERVAL)
        except asyncio.CancelledError:
            self.stop()
            raise
        except BaseException:
            self.stop()
            raise

    def stop(self):
        self._accepting = False
        self.stream.close()

    def _handle_ping(self, message):
        mode, sequence = decode_heartbeat(message.payload)
        if mode != PING:
            raise ChannelRpcError("worker expected a gateway PING")
        self.ingress.heartbeat(self.hello.generation.hex(), sequence)
        self.stream.enqueue(kind=wire.HEARTBEAT, message_id=message.message_id,
                            payload=encode_heartbeat(PONG, sequence))

    def _admit(self, message):
        if not self._accepting:
            raise ChannelRpcError("worker RPC admission is stopped")
        decoded = wire.decode_bundle(message.payload, fragment_kind=message.kind)
        if decoded.classification != wire.REQUEST or decoded.method not in METHODS:
            raise ChannelRpcError("worker received an unsupported request bundle")
        is_control = message.kind == wire.CONTROL
        if is_control != (decoded.method in _CLEANUP):
            raise ChannelRpcError("RPC method arrived on the wrong lane")
        if (is_control and self._control_count >= _CONTROL_LIMIT
                or not is_control and self._data_count >= _DATA_LIMIT):
            raise ChannelRpcError("worker RPC concurrency bound is exhausted")
        if len(decoded.protobuf) > MAX_MESSAGE_BYTES:
            raise ChannelRpcError("worker protobuf exceeds the protocol bound")
        metadata, binding = _binding(decoded)
        request = parse_message(decoded.protobuf, Request, MAX_MESSAGE_BYTES)
        sequence = _delegation_sequence(decoded.envelope)
        lane = "control" if is_control else "data"
        # GatewayWorkerIngress verifies the envelope, exact C1 bytes, parsed Request,
        # authenticated TLS peer and logical lane sequence as one admission.
        authorization = self.bridge.incoming_authorizer.authorize_gateway(
            service="steamboat.v1.Worker", method=decoded.method, payload=request,
            metadata=metadata, ingress=self.ingress, envelope=decoded.envelope,
            request_bytes=decoded.protobuf, frame_sequence=sequence, wire_lane=lane)
        if authorization.binding_bytes != binding.encoded:
            authorization.fail(cache_may_exist=False)
            authorization.close()
            raise ChannelRpcError("bridge captured a different canonical C1 binding")
        if is_control:
            self._control_count += 1
        else:
            self._data_count += 1
        task = asyncio.create_task(self._execute(
            message, decoded, request, authorization, is_control))
        self._active.add(task)
        task.add_done_callback(self._task_finished)

    def _task_finished(self, task):
        self._active.discard(task)
        if not task.cancelled() and task.exception() is not None:
            self.stop()

    async def _execute(self, message, decoded, request, authorization, is_control):
        transferred = False
        completed = False
        try:
            response = await _run_guarded(
                self.bridge.handler.handle(decoded.method, request), authorization,
                self.bridge.authorization_watcher,
                timeout=300,
                failure_cache_may_exist=decoded.method != "Describe")
            if not isinstance(response, Response):
                raise ChannelRpcError("worker handler returned a non-protobuf response")
            authorization.complete(response)
            completed = True
            payload = wire.encode_bundle(
                decoded.method, wire.BUNDLE_RESPONSE,
                fragment_kind=wire.CONTROL_RESPONSE if is_control else wire.RESPONSE,
                protobuf=serialize_message(response, MAX_MESSAGE_BYTES))
            self.stream.enqueue(kind=wire.CONTROL_RESPONSE if is_control else wire.RESPONSE,
                                message_id=message.message_id, payload=payload)
        except SecureTaskPending as error:
            # _run_guarded retained the still-running compute and authorization owner.
            transferred = bool(getattr(error, "authorization_transferred", False))
            self.stop()
            raise
        except BaseException:
            if not completed:
                try:
                    authorization.fail(cache_may_exist=decoded.method != "Describe")
                except BaseException:
                    self.stop()
            self.stop()
            raise
        finally:
            if is_control:
                self._control_count -= 1
            else:
                self._data_count -= 1
            if not transferred:
                try:
                    authorization.close()
                except BaseException:
                    self.stop()


class GatewayChannelRelay:
    """Relay exact worker RPCs between live coordinator and worker HELLO streams."""

    def __init__(self, *, coordinator_stream: ChannelStream, worker_stream: ChannelStream,
                 router):
        if (type(coordinator_stream) is not ChannelStream
                or type(coordinator_stream._hello) is not CoordinatorHelloServer
                or type(worker_stream) is not ChannelStream
                or type(worker_stream._hello) is not WorkerHelloServer):
            raise TypeError("gateway relay requires coordinator/worker server HELLO streams")
        coordinator = coordinator_stream.registration
        worker = worker_stream.registration
        if type(coordinator) is not RegisteredCoordinator or type(worker) is not RegisteredWorker:
            raise ChannelRpcError("gateway relay requires the actual committed HELLO capabilities")
        if (coordinator_stream._driver._tls is not coordinator_stream._hello.owner
                or worker_stream._driver._tls is not worker_stream._hello.owner):
            raise ChannelRpcError("gateway relay stream TLS owners changed")
        self.coordinator_stream = coordinator_stream
        self.worker_stream = worker_stream
        self.coordinator = coordinator
        self.worker = worker
        self.router = router
        self._pending = {}
        self._accepting = True
        self._last_monitor = 0.0

    async def run(self):
        try:
            while self._accepting:
                self.coordinator_stream.pump()
                # A queued writer fragment is dispatched only while every
                # captured coordinator route guard is still live.
                for entry in tuple(self._pending.values()):
                    self.router.assert_dispatch_live(
                        coordinator=self.coordinator, worker=self.worker,
                        route_guard=entry[4], method=entry[1])
                self.worker_stream.pump()
                message = self.coordinator_stream.pop_message()
                if message is not None:
                    self._forward(message)
                response = self.worker_stream.pop_message()
                if response is not None:
                    self._return(response)
                now = time.monotonic()
                if now - self._last_monitor >= _MONITOR_INTERVAL:
                    self._last_monitor = now
                    self.router.check_heartbeat_liveness()
                    self.router.enqueue_heartbeat(worker=self.worker)
                await asyncio.sleep(_PUMP_INTERVAL)
        except BaseException:
            self.stop()
            raise

    def stop(self):
        self._accepting = False
        self.coordinator_stream.close()
        self.worker_stream.close()

    def _forward(self, message):
        if message.kind not in (wire.DATA, wire.CONTROL):
            if message.kind == wire.HEARTBEAT:
                return
            raise ChannelRpcError("gateway coordinator sent an invalid RPC frame kind")
        decoded = wire.decode_bundle(message.payload, fragment_kind=message.kind)
        if decoded.classification != wire.REQUEST:
            raise ChannelRpcError("gateway coordinator sent a non-request bundle")
        if (message.kind == wire.CONTROL) != (decoded.method in _CLEANUP):
            raise ChannelRpcError("gateway coordinator used the wrong RPC lane")
        metadata, binding = _binding(decoded)
        fields = binding.fields
        channel = self.coordinator_stream._hello.channel
        channel.assert_live()
        if (fields["account_id"] != channel.actor_account_id
                or fields["device_id"] != channel.actor_device_id
                or fields["role"] != "personal_coordinator"
                or fields["credential_epoch"] != channel.actor_credential_epoch
                or fields["target_device_id"] != self.worker.identity[1]):
            raise ChannelRpcError("C1 binding differs from the authenticated coordinator route")
        owner = channel._owner_ref()
        if owner is None:
            raise ChannelRpcError("coordinator TLS route owner is unavailable")
        target_policy = owner.policy_store.current().worker(
            self.worker.identity[1], self.worker.identity[2])
        if target_policy is None:
            raise ChannelRpcError("selected worker is absent from current channel policy")
        assignment_id = target_policy["assignment_id"]
        model_id = target_policy["model_id"]
        if fields.get("assignment_id", assignment_id) != assignment_id:
            raise ChannelRpcError("C1 assignment differs from selected policy worker")
        request = parse_message(decoded.protobuf, Request, MAX_MESSAGE_BYTES)
        if serialize_message(request, MAX_MESSAGE_BYTES) != decoded.protobuf:
            raise ChannelRpcError("coordinator protobuf is not in canonical wire form")
        route = channel.authorize_route(
            method=decoded.method, target_device_id=self.worker.identity[1],
            worker_boot_id=self.worker.identity[2],
            assignment_id=assignment_id, model_id=model_id)
        # The C1 binding's worker target and signed C2 policy guard are both checked
        # by GatewayRouter. Existing C1 describes without boot/assignment use route's
        # exact selected worker identity.
        metadata = ((METADATA_KEY, binding.encoded),)
        if message.message_id in self._pending:
            raise ChannelRpcError("coordinator reused a pending wire message ID")
        is_control = decoded.method in _CLEANUP
        lane_limit = 8 if is_control else 9
        lane_pending = sum(item[1] in _CLEANUP for item in self._pending.values())
        if (is_control and lane_pending >= lane_limit
                or not is_control and len(self._pending) - lane_pending >= lane_limit):
            raise ChannelRpcError("gateway relay pending request bound is exhausted")
        accepted = self.router.submit(
            coordinator=self.coordinator, worker=self.worker, route_guard=route,
            method=decoded.method, metadata=metadata, request_bytes=decoded.protobuf,
            message_id=message.message_id)
        if accepted is not True:
            raise ChannelRpcError("gateway worker writer has no bounded admission capacity")
        key = message.message_id
        self._pending[key] = (fields["operation_id"], decoded.method,
                              fields.get("request_id", ""), binding.encoded,
                              route, request)

    def _return(self, message):
        if message.kind not in (wire.RESPONSE, wire.CONTROL_RESPONSE):
            if message.kind == wire.HEARTBEAT:
                self.router.accept_heartbeat_pong(worker=self.worker,
                                                  payload=message.payload)
                return
            raise ChannelRpcError("gateway worker sent an invalid RPC response kind")
        decoded = wire.decode_bundle(message.payload, fragment_kind=message.kind)
        entry = self._pending.get(message.message_id)
        if entry is None or entry[1] != decoded.method:
            raise ChannelRpcError("worker response has no exact pending method/message mapping")
        operation_id, method, request_id, _binding_bytes, route, request = entry
        route.assert_live()
        protobuf = parse_message(decoded.protobuf, Response, MAX_MESSAGE_BYTES)
        validate_response(method, request, protobuf)
        self.router.complete(worker=self.worker, operation_id=operation_id,
                             request_id=request_id, message_id=message.message_id,
                             method=method, payload=message.payload)
        response = wire.encode_bundle(method, wire.BUNDLE_RESPONSE,
                                      fragment_kind=message.kind,
                                      protobuf=serialize_message(protobuf, MAX_MESSAGE_BYTES))
        self.coordinator_stream.enqueue(kind=message.kind, message_id=message.message_id,
                                        payload=response)
        del self._pending[message.message_id]
