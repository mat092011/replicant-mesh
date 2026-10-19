"""C2 RPC dispatch/relay checks over the genuine loopback TLS/HELLO fixtures."""
import asyncio
import secrets
import time
import unittest
from unittest import mock

from steamboat_connector import channel_wire as wire
from steamboat_connector.channel_rpc import (
    ChannelRpcError, GatewayChannelRelay, _delegation_sequence,
    _DATA_LIMIT, _DATA_CAPTURE_BYTES, _CONTROL_LIMIT, _CONTROL_CAPTURE_BYTES,
)
from steamboat_runtime.protocol.wire import Request, Response, serialize_message
from steamboat_security.codec import METADATA_KEY, encode_binding
from steamboat_security.ids import new_id
from tests.connector import test_gateway_router as gateway_router_tests


class ChannelRpcRelayTests(unittest.IsolatedAsyncioTestCase):
    """Fixture establishes two real TLS/HELLO/metered TCP hops."""

    def setUp(self):
        from tests.runtime.test_manifest import sample_manifest

        self.manifest = sample_manifest()
        self._expected_transport_loss = False
        import tests.security.test_identity_core as identity_core
        self._model_patch = mock.patch.object(
            identity_core, "MODEL", self.manifest["fingerprint"])
        self._model_patch.start()
        self.addCleanup(self._model_patch.stop)
        self.fx = gateway_router_tests.GatewayRouterTwoHopTests(
            methodName="test_submit_binds_real_two_hops_hello_generation_and_core_c1")
        self.addCleanup(self.fx.doCleanups)
        self.fx.setUp()
        self.bridge = None

    def _pump_until(self, streams, pop, timeout=1.0):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            for stream in streams:
                stream.pump()
            message = pop()
            if message is not None:
                return message
            time.sleep(0.001)
        return None

    async def asyncTearDown(self):
        if self.bridge is not None and not self.bridge._closed:
            await self.bridge.stop(grace_seconds=1)
            await self.bridge._handler.shutdown(grace_seconds=1)

    def test_gateway_relay_routes_and_returns_exact_protobuf_rpc(self):
        relay = GatewayChannelRelay(
            coordinator_stream=self.fx.coordinator_server_stream,
            worker_stream=self.fx.worker_server_stream, router=self.fx.router,
            data_capture_reservation_bytes=_DATA_LIMIT * _DATA_CAPTURE_BYTES,
            control_capture_reservation_bytes=_CONTROL_LIMIT * _CONTROL_CAPTURE_BYTES)
        fields = {
            "binding_version": 1,
            "operation_id": new_id("op"),
            "account_id": self.fx.actor_record["account_id"],
            "device_id": self.fx.actor_record["device_id"],
            "role": "personal_coordinator",
            "credential_epoch": self.fx.actor_record["credential_epoch"],
            "target_device_id": self.fx.device_id,
        }
        binding = encode_binding("steamboat.v1.Worker", "Describe", fields)
        request = Request(
            protocol_version=1, manifest_fingerprint=self.fx.model_id,
            worker_boot_id=self.fx.worker_boot_id, timeout_ms=5000)
        raw = serialize_message(request)
        message_id = secrets.token_bytes(16)
        inbound = wire.encode_bundle(
            "Describe", wire.REQUEST, fragment_kind=wire.DATA,
            binding=binding, protobuf=raw)
        self.fx.coordinator_client_stream.enqueue(
            kind=wire.DATA, message_id=message_id, payload=inbound)
        # Pump the authenticated coordinator hop until its real server stream has
        # decoded the C2 request, then exercise the relay's route authorization.
        coordinator_message = self._pump_until(
            (self.fx.coordinator_client_stream, self.fx.coordinator_server_stream),
            self.fx.coordinator_server_stream.pop_message)
        self.assertIsNotNone(coordinator_message)
        self.assertEqual(coordinator_message.message_id, message_id)
        relay._forward(coordinator_message)

        worker_message = self.fx._receive_worker_message()
        self.assertEqual(worker_message.message_id, message_id)
        self.assertEqual(worker_message.kind, wire.DATA)
        forwarded = wire.decode_bundle(worker_message.payload,
                                       fragment_kind=worker_message.kind)
        self.assertEqual(forwarded.method, "Describe")
        self.assertEqual(forwarded.binding, binding)
        self.assertEqual(forwarded.protobuf, raw)
        self.assertEqual(_delegation_sequence(forwarded.envelope), 1)

        response_proto = Response(
            protocol_version=1, manifest_fingerprint=self.fx.model_id,
            worker_boot_id=self.fx.worker_boot_id, code="OK")
        response_bundle = wire.encode_bundle(
            "Describe", wire.BUNDLE_RESPONSE, fragment_kind=wire.RESPONSE,
            protobuf=serialize_message(response_proto))
        self.fx.worker_client_stream.enqueue(kind=wire.RESPONSE, message_id=message_id,
                                             payload=response_bundle)
        worker_response = self._pump_until(
            (self.fx.worker_client_stream, self.fx.worker_server_stream),
            self.fx.worker_server_stream.pop_message)
        self.assertIsNotNone(worker_response)
        relay._return(worker_response)
        returned = self._pump_until(
            (self.fx.coordinator_server_stream, self.fx.coordinator_client_stream),
            self.fx.coordinator_client_stream.pop_message)
        self.assertIsNotNone(returned)
        self.assertEqual(returned.message_id, message_id)
        self.assertEqual(returned.kind, wire.RESPONSE)
        self.assertEqual(wire.decode_bundle(returned.payload,
                                            fragment_kind=returned.kind).protobuf,
                         serialize_message(response_proto))
        self.assertEqual(relay._pending, {})

    async def test_bridge_reclamation_checks_notice_fault_and_core_confirmation(self):
        from steamboat_runtime.secure_worker_runtime import (
            RuntimeBridgeUnavailable, SecureWorkerRuntimeBridge,
            _BoundAuthorization, _Operation, _SessionOwner,
        )
        from steamboat_runtime.worker_state import WorkerHandler
        from steamboat_runtime.protocol.worker_pb2 import Request
        from steamboat_security.authorization import Authorizer, LocalIdentity

        authorizer = Authorizer(
            local_identity=LocalIdentity(
                self.fx.host["certificate"], self.fx.worker_boot_id,
                self.manifest["fingerprint"], self.fx.assignment_id),
            snapshot_store=self.fx.base.snapshot_store, clock=self.fx.base.clock,
            session_bindings=self.fx.worker_sessions, worker_request_type=Request)
        handler = WorkerHandler(self.manifest, "worker-1", object(),
                                boot_id=self.fx.worker_boot_id)
        bridge = SecureWorkerRuntimeBridge(authorizer, handler)
        self.bridge = bridge
        await bridge.start()

        def stage_owner(session_id):
            owner = _SessionOwner(
                self.fx.device_id, self.fx.worker_boot_id, self.fx.assignment_id,
                session_id, ("captured-core-owner",), ("captured-core-identity",),
                invalidated=True)
            request = object()
            operation = _Operation(request, "Step", object(), owner, ())
            operation.dispatch_done = True
            authorization = _BoundAuthorization(bridge, operation)
            bridge._owners[owner.key] = owner
            bridge._operations[id(request)] = operation
            return owner, operation, authorization

        owner, operation, authorization = stage_owner(new_id("ses"))
        with mock.patch.object(bridge, "_process_notices",
                               side_effect=lambda: bridge._fence(
                                   "injected notice processing fault")):
            with self.assertRaises(RuntimeBridgeUnavailable):
                await bridge.wait_for_authorized_reclamation(authorization)
        self.assertTrue(bridge.unavailable)
        bridge._owners.pop(owner.key, None)
        bridge._operations.pop(id(operation.request), None)
        bridge._unconfirmed_cleanup = False
        bridge._unavailable = False
        handler.requires_restart = False

        for clock_fault in (False, True):
            with self.subTest(clock_fault=clock_fault):
                owner, operation, authorization = stage_owner(new_id("ses"))
                operation.authorization_closed = True
                # Mirror the operation-table removal performed by the real
                # authorization close path before reconciliation.
                bridge._operations.pop(id(operation.request), None)
                if clock_fault:
                    with mock.patch.object(
                            bridge.session_bindings.clock, "sample",
                            side_effect=RuntimeError("injected core clock failure")):
                        with self.assertRaises(RuntimeBridgeUnavailable):
                            bridge.confirm_authorization_retirement(authorization)
                else:
                    with self.assertRaises(RuntimeBridgeUnavailable):
                        bridge.confirm_authorization_retirement(authorization)
                self.assertTrue(bridge.unavailable)
                self.assertTrue(bridge._unconfirmed_cleanup)
                # Remove only the deliberately fabricated owner before normal
                # fixture shutdown; production cleanup remains fenced above.
                bridge._owners.pop(owner.key, None)
                bridge._operations.pop(id(operation.request), None)
                bridge._unconfirmed_cleanup = False
                bridge._unavailable = False
                handler.requires_restart = False

    def test_worker_dispatcher_rejects_non_client_hello_and_bad_logical_sequence(self):
        from steamboat_connector.channel_rpc import WorkerChannelRpc
        from types import SimpleNamespace

        with self.assertRaises(TypeError):
            WorkerChannelRpc(
                stream=self.fx.worker_server_stream, bridge=object(),
                data_capture_reservation_bytes=_DATA_LIMIT * _DATA_CAPTURE_BYTES,
                control_capture_reservation_bytes=_CONTROL_LIMIT * _CONTROL_CAPTURE_BYTES)
        deeply_nested = b'{"payload":{"frame_sequence":' + b"[" * 400 + b"0" + b"]" * 400 + b"}}"
        for envelope in (b"", b"{}", b'{"payload":{"frame_sequence":true}}',
                         deeply_nested):
            with self.subTest(envelope=envelope), self.assertRaises(ChannelRpcError):
                _delegation_sequence(envelope)

    def test_worker_preflight_rejects_near_limit_shape_before_protobuf_parse(self):
        from types import SimpleNamespace
        from steamboat_connector.channel_protobuf import ChannelProtobufError
        from steamboat_connector.channel_rpc import WorkerChannelRpc

        bridge = SimpleNamespace(authorizer_core=SimpleNamespace(
            local_identity=SimpleNamespace(boot_id=self.fx.worker_boot_id)))
        service = WorkerChannelRpc(
            stream=self.fx.worker_client_stream, bridge=bridge,
            data_capture_reservation_bytes=_DATA_LIMIT * _DATA_CAPTURE_BYTES,
            control_capture_reservation_bytes=_CONTROL_LIMIT * _CONTROL_CAPTURE_BYTES)
        _, _, binding = self.fx._binding_metadata(
            "Step", operation_id=new_id("op"), request_id=new_id("req"),
            session_id=new_id("ses"))
        def encode_varint(value):
            output = bytearray()
            while value > 0x7f:
                output.append((value & 0x7f) | 0x80)
                value >>= 7
            output.append(value)
            return bytes(output)

        packed = b"\x0a" + encode_varint(1_000_000) + b"\x00" * 1_000_000
        # One packed repeated field with a million zero dimensions is under
        # MAX_PROTOBUF_BYTES but must fail before generated protobuf expansion.
        malicious = wire.encode_bundle(
            "Step", wire.REQUEST, fragment_kind=wire.DATA, binding=binding,
            protobuf=b"\x6a" + encode_varint(len(packed)) + packed)
        message = SimpleNamespace(kind=wire.DATA, message_id=b"Q" * 16,
                                  payload=malicious)
        from steamboat_connector import channel_rpc as rpc_module
        with mock.patch.object(rpc_module, "parse_message",
                               side_effect=AssertionError("protobuf parser was reached")) as parser:
            with self.assertRaises(ChannelProtobufError):
                service._admit(message)
            parser.assert_not_called()

    async def test_worker_dispatch_uses_real_c1_bridge_and_worker_handler(self):
        from steamboat_connector.channel_rpc import WorkerChannelRpc
        from steamboat_runtime.secure_worker_runtime import (
            RuntimeBindingError, SecureWorkerRuntimeBridge, _BoundAuthorization,
            _Operation,
        )
        from steamboat_runtime.worker_state import WorkerHandler
        from steamboat_runtime.protocol.worker_pb2 import Request
        from steamboat_security.authorization import Authorizer, LocalIdentity
        from steamboat_security.sessions import SessionBindings

        worker_sessions = self.fx.worker_sessions
        authorizer = Authorizer(
            local_identity=LocalIdentity(
                self.fx.host["certificate"], self.fx.worker_boot_id,
                self.manifest["fingerprint"], self.fx.assignment_id),
            snapshot_store=self.fx.base.snapshot_store, clock=self.fx.base.clock,
            session_bindings=worker_sessions, worker_request_type=Request)
        # Describe exercises the actual WorkerHandler and C1 runtime bridge without
        # claiming model execution; the test executor is intentionally unused here.
        handler = WorkerHandler(self.manifest, "worker-1", object(),
                                 boot_id=self.fx.worker_boot_id)
        self.bridge = SecureWorkerRuntimeBridge(authorizer, handler)
        await self.bridge.start()
        with self.assertRaises(RuntimeBindingError):
            await self.bridge.wait_for_authorized_reclamation(object())
        unrelated_operation = _Operation(None, "Describe", None, None, ())
        unrelated_authorization = _BoundAuthorization(self.bridge, unrelated_operation)
        with self.assertRaises(RuntimeBindingError):
            await self.bridge.wait_for_authorized_reclamation(unrelated_authorization)
        foreign_handler = WorkerHandler(self.manifest, "worker-1", object(),
                                        boot_id=self.fx.worker_boot_id)
        foreign_bridge = SecureWorkerRuntimeBridge(authorizer, foreign_handler)
        foreign_operation = _Operation(None, "Describe", None, None, ())
        foreign_authorization = _BoundAuthorization(foreign_bridge, foreign_operation)
        with self.assertRaises(RuntimeBindingError):
            await self.bridge.wait_for_authorized_reclamation(foreign_authorization)
        service = WorkerChannelRpc(stream=self.fx.worker_client_stream,
                                   bridge=self.bridge,
                                   data_capture_reservation_bytes=_DATA_LIMIT * _DATA_CAPTURE_BYTES,
                                   control_capture_reservation_bytes=_CONTROL_LIMIT * _CONTROL_CAPTURE_BYTES)

        fields = {
            "binding_version": 1, "operation_id": new_id("op"),
            "account_id": self.fx.actor_record["account_id"],
            "device_id": self.fx.actor_record["device_id"],
            "role": "personal_coordinator",
            "credential_epoch": self.fx.actor_record["credential_epoch"],
            "target_device_id": self.fx.device_id,
        }
        binding = encode_binding("steamboat.v1.Worker", "Describe", fields)
        request = Request(protocol_version=1, manifest_fingerprint=self.manifest["fingerprint"],
                          worker_boot_id=self.fx.worker_boot_id, timeout_ms=5000)
        raw = serialize_message(request)
        message_id = secrets.token_bytes(16)
        inbound = wire.encode_bundle("Describe", wire.REQUEST,
                                     fragment_kind=wire.DATA,
                                     binding=binding, protobuf=raw)
        self.fx.coordinator_client_stream.enqueue(kind=wire.DATA,
                                                  message_id=message_id,
                                                  payload=inbound)
        coordinator_message = self._pump_until(
            (self.fx.coordinator_client_stream, self.fx.coordinator_server_stream),
            self.fx.coordinator_server_stream.pop_message)
        self.assertIsNotNone(coordinator_message)
        relay = GatewayChannelRelay(
            coordinator_stream=self.fx.coordinator_server_stream,
            worker_stream=self.fx.worker_server_stream, router=self.fx.router,
            data_capture_reservation_bytes=_DATA_LIMIT * _DATA_CAPTURE_BYTES,
            control_capture_reservation_bytes=_CONTROL_LIMIT * _CONTROL_CAPTURE_BYTES)
        relay._forward(coordinator_message)

        worker_message = self._pump_until(
            (self.fx.worker_server_stream, self.fx.worker_client_stream),
            self.fx.worker_client_stream.pop_message)
        self.assertIsNotNone(worker_message)
        service._admit(worker_message)
        await asyncio.gather(*tuple(service._active))
        self.assertEqual(handler.manifest["fingerprint"], self.manifest["fingerprint"])
        self.assertEqual(self.bridge.status()["active_authorizations"], 0)

        worker_response = self._pump_until(
            (self.fx.worker_client_stream, self.fx.worker_server_stream),
            self.fx.worker_server_stream.pop_message)
        self.assertIsNotNone(worker_response)
        relay._return(worker_response)
        returned = self._pump_until(
            (self.fx.coordinator_server_stream, self.fx.coordinator_client_stream),
            self.fx.coordinator_client_stream.pop_message)
        self.assertIsNotNone(returned)
        result = wire.decode_bundle(returned.payload, fragment_kind=returned.kind)
        self.assertEqual(result.method, "Describe")
        self.assertEqual(result.classification, wire.BUNDLE_RESPONSE)

    async def test_run_keeps_control_responsive_during_real_blocked_step(self):
        import threading
        import torch
        from steamboat_connector.channel_rpc import WorkerChannelRpc
        from steamboat_runtime.secure_worker_runtime import SecureWorkerRuntimeBridge
        from steamboat_runtime.worker_state import WorkerHandler
        from steamboat_runtime.protocol.worker_pb2 import Request
        from steamboat_runtime.protocol.codec import encode_tensor
        from steamboat_security.authorization import Authorizer, LocalIdentity

        class Cache:
            def __init__(self): self.position = 0
            def lengths(self): return [self.position] * 3
            def allocated_bytes(self): return self.position * 1536
            def clear(self): self.position = 0

        class Executor:
            def __init__(self):
                self.caches = []
                self.last_cache = None
                self.started = threading.Event()
                self.release = threading.Event()
                self.exited = threading.Event()
                self.timeline = []
            def new_cache(self):
                cache = Cache()
                self.caches.append(cache)
                return cache
            def execute(self, hidden, cache, position):
                self.last_cache = cache
                cache.position += hidden.shape[1]
                self.timeline.append(("compute-start", time.monotonic()))
                self.started.set()
                try:
                    if not self.release.wait(30):
                        self.timeline.append(("compute-timeout", time.monotonic()))
                        raise RuntimeError("test did not release blocked compute")
                    self.timeline.append(("compute-release-observed", time.monotonic()))
                    return hidden + 1
                finally:
                    self.timeline.append(("compute-exit", time.monotonic()))
                    self.exited.set()

        authorizer = Authorizer(
            local_identity=LocalIdentity(
                self.fx.host["certificate"], self.fx.worker_boot_id,
                self.manifest["fingerprint"], self.fx.assignment_id),
            snapshot_store=self.fx.base.snapshot_store, clock=self.fx.base.clock,
            session_bindings=self.fx.worker_sessions, worker_request_type=Request)
        executor = Executor()
        handler = WorkerHandler(self.manifest, "worker-1", executor,
                                boot_id=self.fx.worker_boot_id)
        self.bridge = SecureWorkerRuntimeBridge(authorizer, handler)
        service = WorkerChannelRpc(
            stream=self.fx.worker_client_stream, bridge=self.bridge,
            data_capture_reservation_bytes=_DATA_LIMIT * _DATA_CAPTURE_BYTES,
            control_capture_reservation_bytes=_CONTROL_LIMIT * _CONTROL_CAPTURE_BYTES)
        relay = GatewayChannelRelay(
            coordinator_stream=self.fx.coordinator_server_stream,
            worker_stream=self.fx.worker_server_stream, router=self.fx.router,
            data_capture_reservation_bytes=_DATA_LIMIT * _DATA_CAPTURE_BYTES,
            control_capture_reservation_bytes=_CONTROL_LIMIT * _CONTROL_CAPTURE_BYTES)
        service_task = asyncio.create_task(service.run())
        relay_task = asyncio.create_task(relay.run())
        self.addAsyncCleanup(self._stop_service_tasks, service, relay,
                             service_task, relay_task, executor)
        pending_responses = {}
        session_contexts = {}

        async def response_demux():
            while not self.fx.coordinator_client_stream.closed:
                self.fx.coordinator_client_stream.pump()
                while True:
                    response = self.fx.coordinator_client_stream.pop_message()
                    if response is None:
                        break
                    waiter = pending_responses.pop(response.message_id, None)
                    if waiter is None:
                        raise AssertionError("response has no exact RPC message-ID waiter")
                    future, expected_method = waiter
                    try:
                        bundle = wire.decode_bundle(response.payload,
                                                    fragment_kind=response.kind)
                        if bundle.method != expected_method:
                            raise AssertionError("response method differs from exact RPC waiter")
                        future.set_result((response.kind, bundle.method, bundle.protobuf))
                    except BaseException as error:
                        future.set_exception(error)
                await asyncio.sleep(0.001)

        demux_task = asyncio.create_task(response_demux())
        self.addAsyncCleanup(self._cancel_task, demux_task)

        async def rpc(method, request, *, lane=wire.DATA, response_timeout=1.0):
            session_id = request.session_id if method != "Describe" else ""
            if method == "OpenSession":
                context = {"request_id": new_id("req"), "route_id": new_id("route")}
                session_contexts[session_id] = context
            else:
                context = session_contexts.get(session_id, {
                    "request_id": new_id("req"), "route_id": new_id("route")})
            fields, metadata, binding = self.fx._binding_metadata(
                method, operation_id=new_id("op"), request_id=context["request_id"],
                route_id=context["route_id"], session_id=session_id)
            raw = serialize_message(request)
            message_id = secrets.token_bytes(16)
            if len(pending_responses) >= 17:
                self.fail("fixture RPC response demultiplexer exceeded its bounded map")
            future = asyncio.get_running_loop().create_future()
            pending_responses[message_id] = (future, method)
            payload = wire.encode_bundle(method, wire.REQUEST, fragment_kind=lane,
                                         binding=binding, protobuf=raw)
            self.fx.coordinator_client_stream.enqueue(kind=lane, message_id=message_id,
                                                       payload=payload)
            try:
                return await asyncio.wait_for(future, timeout=response_timeout)
            finally:
                pending_responses.pop(message_id, None)

        def req(method, **kwargs):
            base = dict(protocol_version=1,
                        manifest_fingerprint=self.manifest["fingerprint"],
                        worker_boot_id=self.fx.worker_boot_id, timeout_ms=5000)
            if method != "Describe": base["session_id"] = kwargs.pop("session_id")
            return Request(**(base | kwargs))

        first_session_id = new_id("ses")
        kind, method, raw = await rpc("OpenSession", req(
            "OpenSession", session_id=first_session_id, lease_token="",
            max_positions=8, lifetime_ms=30000, idle_lease_ms=10000))
        from steamboat_runtime.protocol.worker_pb2 import Response as WorkerResponse
        opened = WorkerResponse.FromString(raw)
        self.assertEqual((kind, method, opened.code), (wire.RESPONSE, "OpenSession", "OK"))
        step_task = asyncio.create_task(rpc("Step", req(
            "Step", session_id=first_session_id, lease_token=opened.lease_token,
            sequence=0, start_position=0, token_count=1,
            tensor=encode_tensor(torch.zeros((1, 1, 64)))), response_timeout=7.0))
        self.assertTrue(await asyncio.to_thread(executor.started.wait, 1),
                        "actual WorkerHandler executor did not enter Step")
        # A second independent session may open while the first session's
        # executor is blocked; control remains independently serviceable.
        other_session_id = new_id("ses")
        _, _, other_open_raw = await rpc("OpenSession", req(
            "OpenSession", session_id=other_session_id, lease_token="",
            max_positions=8, lifetime_ms=30000, idle_lease_ms=10000))
        other_open = WorkerResponse.FromString(other_open_raw)
        self.assertEqual(other_open.code, "OK")
        first_cache = executor.caches[0]
        status_kind, status_method, status_raw = await rpc(
            "SessionStatus", req("SessionStatus", session_id=first_session_id,
                                 lease_token=opened.lease_token), lane=wire.CONTROL)
        status = WorkerResponse.FromString(status_raw)
        self.assertEqual((status_kind, status_method, status.code),
                         (wire.CONTROL_RESPONSE, "SessionStatus", "OK"))
        cancel_kind, cancel_method, cancel_raw = await rpc(
            "CancelSession", req("CancelSession", session_id=first_session_id,
                                  lease_token=opened.lease_token), lane=wire.CONTROL)
        cancelled = WorkerResponse.FromString(cancel_raw)
        self.assertEqual((cancel_kind, cancel_method, cancelled.code),
                         (wire.CONTROL_RESPONSE, "CancelSession", "OK"))
        status_kind, status_method, status_raw = await rpc(
            "SessionStatus", req("SessionStatus", session_id=first_session_id,
                                 lease_token=opened.lease_token), lane=wire.CONTROL)
        status = WorkerResponse.FromString(status_raw)
        self.assertEqual((status_kind, status_method, status.code),
                         (wire.CONTROL_RESPONSE, "SessionStatus", "EXECUTION_FAILED"))
        self.assertFalse(self.fx.worker_client_stream.closed)
        self.assertTrue(executor.started.is_set())
        self.assertEqual(first_cache.position, 1)
        step_kind, step_method, step_raw = await step_task
        executor.timeline.append(("cancelled-step-reply", time.monotonic()))
        step = WorkerResponse.FromString(step_raw)
        self.assertEqual((step_kind, step_method, step.code),
                         (wire.RESPONSE, "Step", "CANCELLED"))
        self.assertFalse(executor.exited.is_set(),
                         f"compute exited before cancellation reply: {executor.timeline!r}")
        self.assertGreater(self.bridge.status()["active_authorizations"], 0)
        self.assertGreaterEqual(service._data_count, 1,
                                 f"capture released before compute exit: {executor.timeline!r}")
        executor.release.set()
        self.assertTrue(await asyncio.to_thread(executor.exited.wait, 1),
                        f"executor did not observe test release: {executor.timeline!r}")
        deadline = time.monotonic() + 1.0
        while self.bridge.status()["active_authorizations"] and time.monotonic() < deadline:
            await asyncio.sleep(0.001)
        self.assertEqual(self.bridge.status()["active_authorizations"], 0)
        # The independent OpenSession above remains valid after the first
        # session is cancelled. Close it explicitly before asserting that the
        # handler has reclaimed every session.
        other_close_kind, other_close_method, other_close_raw = await rpc(
            "CloseSession", req("CloseSession", session_id=other_session_id,
                                lease_token=other_open.lease_token), lane=wire.CONTROL)
        other_closed = WorkerResponse.FromString(other_close_raw)
        self.assertEqual((other_close_kind, other_close_method, other_closed.code),
                         (wire.CONTROL_RESPONSE, "CloseSession", "OK"))
        self.assertNotIn(other_session_id, handler.sessions)
        self.assertEqual(handler.sessions, {})

        # Losing the channel while a native executor owns cache state must not
        # release the bridge authorization or cache capture ahead of the thread.
        executor.started.clear()
        executor.release.clear()
        second_session_id = new_id("ses")
        _, _, second_open_raw = await rpc("OpenSession", req(
            "OpenSession", session_id=second_session_id, lease_token="",
            max_positions=8, lifetime_ms=30000, idle_lease_ms=10000))
        second_open = WorkerResponse.FromString(second_open_raw)
        lost_step_task = asyncio.create_task(rpc("Step", req(
            "Step", session_id=second_session_id, lease_token=second_open.lease_token,
            sequence=0, start_position=0, token_count=1,
            tensor=encode_tensor(torch.zeros((1, 1, 64))))))
        self.assertTrue(await asyncio.to_thread(executor.started.wait, 1))
        # Cleanup may observe a stream-retirement error only after this explicit
        # transport-loss boundary, never for earlier fixture/service faults.
        self._expected_transport_loss = True
        self.fx.worker_client_stream.close()
        self.assertGreater(self.bridge.status()["active_authorizations"], 0)
        self.assertEqual(executor.last_cache.position, 1)
        executor.release.set()
        deadline = time.monotonic() + 1.0
        while self.bridge.status()["active_authorizations"] and time.monotonic() < deadline:
            await asyncio.sleep(0.001)
        self.assertEqual(self.bridge.status()["active_authorizations"], 0)
        # The request's caller may lose its response when the worker stream is
        # closed, but its failure is still observed here rather than discarded.
        lost_result = await asyncio.gather(lost_step_task, return_exceptions=True)
        self.assertIsInstance(lost_result[0], asyncio.TimeoutError)

    async def _stop_service_tasks(self, service, relay, service_task, relay_task, executor):
        executor.release.set()
        service.stop()
        relay.stop()
        for task in (service_task, relay_task):
            if not task.done():
                task.cancel()
        results = await asyncio.gather(service_task, relay_task, return_exceptions=True)
        from steamboat_connector.channel_stream import ChannelStreamError
        expected_retirement = (
            self._expected_transport_loss
            and self.fx.worker_client_stream.closed
            and self.fx.worker_server_stream.closed
            and self.bridge is not None
            and self.bridge.status()["active_authorizations"] == 0
            and not self.bridge._handler.sessions)
        for name, result in zip(("worker service", "gateway relay"), results):
            if isinstance(result, BaseException) and not isinstance(
                    result, asyncio.CancelledError):
                if expected_retirement and isinstance(result, ChannelStreamError):
                    continue
                self.fail(f"{name} task failed during fixture cleanup: {result!r}")

    async def _cancel_task(self, task):
        if not task.done():
            task.cancel()
        result, = await asyncio.gather(task, return_exceptions=True)
        if isinstance(result, BaseException) and not isinstance(
                result, asyncio.CancelledError):
            from steamboat_connector.channel_stream import ChannelStreamError
            expected_retirement = (
                self._expected_transport_loss
                and self.fx.worker_client_stream.closed
                and self.fx.worker_server_stream.closed
                and self.bridge is not None
                and self.bridge.status()["active_authorizations"] == 0
                and not self.bridge._handler.sessions)
            if expected_retirement and isinstance(result, ChannelStreamError):
                return
            self.fail(f"fixture demultiplexer failed: {result!r}")

    def test_capture_reservations_are_mandatory_and_cover_all_admissions(self):
        from steamboat_connector.channel_rpc import WorkerChannelRpc
        minimum_data = _DATA_LIMIT * _DATA_CAPTURE_BYTES
        minimum_control = _CONTROL_LIMIT * _CONTROL_CAPTURE_BYTES
        self.assertGreaterEqual(_DATA_CAPTURE_BYTES, 8 * wire.MAX_PROTOBUF_BYTES)
        with self.assertRaises(ValueError):
            GatewayChannelRelay(
                coordinator_stream=self.fx.coordinator_server_stream,
                worker_stream=self.fx.worker_server_stream, router=self.fx.router,
                data_capture_reservation_bytes=minimum_data - 1,
                control_capture_reservation_bytes=minimum_control)
        with self.assertRaises(ValueError):
            from types import SimpleNamespace
            bridge = SimpleNamespace(authorizer_core=SimpleNamespace(
                local_identity=SimpleNamespace(boot_id=self.fx.worker_boot_id)))
            WorkerChannelRpc(
                stream=self.fx.worker_client_stream, bridge=bridge,
                data_capture_reservation_bytes=minimum_data,
                control_capture_reservation_bytes=minimum_control - 1)

    async def test_retention_follows_pending_descendants_and_sticks_on_close_fault(self):
        from types import SimpleNamespace
        from steamboat_connector.channel_rpc import WorkerChannelRpc
        from steamboat_runtime.protocol.secure_transport import SecureTaskPending

        worker_boot_id = self.fx.worker_boot_id

        class TestBridge:
            def __init__(self):
                self.authorizer_core = SimpleNamespace(
                    local_identity=SimpleNamespace(boot_id=worker_boot_id))
                self.confirm_error = None
            async def wait_for_authorized_reclamation(self, authorization):
                order.append("wait")
            def confirm_authorization_retirement(self, authorization):
                order.append("confirm")
                if self.confirm_error is not None:
                    raise self.confirm_error

        order = []
        bridge = TestBridge()
        service = WorkerChannelRpc(
            stream=self.fx.worker_client_stream, bridge=bridge,
            data_capture_reservation_bytes=_DATA_LIMIT * _DATA_CAPTURE_BYTES,
            control_capture_reservation_bytes=_CONTROL_LIMIT * _CONTROL_CAPTURE_BYTES)
        release = asyncio.Event()

        async def descendant():
            await release.wait()

        child = asyncio.create_task(descendant())

        async def pending_owner():
            raise SecureTaskPending((child,))

        owner = asyncio.create_task(pending_owner())

        class FaultingAuthorization:
            def __init__(self): self.close_called = False
            def close(self):
                self.close_called = True
                order.append("close")
                raise RuntimeError("injected uncertain authorization retirement")

        authorization = FaultingAuthorization()
        service._data_count = 1
        service._data_bytes = _DATA_CAPTURE_BYTES
        from steamboat_connector.channel_rpc import _RpcCaptureOwner
        capture = _RpcCaptureOwner(None, None, None, authorization, False,
                                   _DATA_CAPTURE_BYTES)
        retirement = asyncio.create_task(service._release_after((owner,), capture))
        await asyncio.sleep(0)
        self.assertEqual(service._data_count, 1)
        self.assertFalse(child.done())
        release.set()
        with self.assertRaisesRegex(RuntimeError, "uncertain authorization retirement"):
            await retirement
        self.assertTrue(authorization.close_called)
        self.assertEqual(order, ["wait", "close"])
        self.assertEqual(service._data_count, 1)
        self.assertEqual(service._data_bytes, _DATA_CAPTURE_BYTES)
        self.assertIn(capture, service._stuck_captures)

        # A successful close call does not prove that core session retirement
        # was reconciled. A failed post-close observer must retain the same
        # count and byte reservation, with no second close attempt.
        order.clear()
        bridge.confirm_error = RuntimeError("injected unconfirmed core retirement")

        class ClosedAuthorization:
            def __init__(self): self.close_count = 0
            def close(self):
                self.close_count += 1
                order.append("close")

        closed_authorization = ClosedAuthorization()
        second_capture = _RpcCaptureOwner(None, None, None, closed_authorization,
                                          False, _DATA_CAPTURE_BYTES)
        service._stuck_captures.clear()
        retirement = asyncio.create_task(
            service._release_after((), second_capture))
        with self.assertRaisesRegex(RuntimeError, "unconfirmed core retirement"):
            await retirement
        self.assertEqual(order, ["wait", "close", "confirm"])
        self.assertEqual(closed_authorization.close_count, 1)
        self.assertEqual(service._data_count, 1)
        self.assertEqual(service._data_bytes, _DATA_CAPTURE_BYTES)
        self.assertIn(second_capture, service._stuck_captures)

    async def test_rpc_attempts_single_close_after_reclamation_observer_fault(self):
        from types import SimpleNamespace
        from steamboat_connector.channel_rpc import WorkerChannelRpc, _RpcCaptureOwner

        order = []

        class TestBridge:
            authorizer_core = SimpleNamespace(local_identity=SimpleNamespace(
                boot_id=self.fx.worker_boot_id))

            async def wait_for_authorized_reclamation(self, authorization):
                order.append("wait")
                raise RuntimeError("observer unavailable after C2 fence")

            def confirm_authorization_retirement(self, authorization):
                order.append("confirm")

        class Authorization:
            def __init__(self):
                self.close_count = 0

            def close(self):
                self.close_count += 1
                order.append("close")

        service = WorkerChannelRpc(
            stream=self.fx.worker_client_stream, bridge=TestBridge(),
            data_capture_reservation_bytes=_DATA_LIMIT * _DATA_CAPTURE_BYTES,
            control_capture_reservation_bytes=_CONTROL_LIMIT * _CONTROL_CAPTURE_BYTES)
        authorization = Authorization()
        capture = _RpcCaptureOwner(None, None, None, authorization, False,
                                   _DATA_CAPTURE_BYTES)
        service._data_count = 1
        service._data_bytes = _DATA_CAPTURE_BYTES
        with self.assertRaisesRegex(RuntimeError, "observer unavailable"):
            await service._release_after((), capture)
        self.assertEqual(order, ["wait", "close"])
        self.assertEqual(authorization.close_count, 1)
        self.assertEqual(service._data_count, 1)
        self.assertEqual(service._data_bytes, _DATA_CAPTURE_BYTES)
        self.assertIn(capture, service._stuck_captures)


if __name__ == "__main__":
    unittest.main()
