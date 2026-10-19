"""C2 RPC dispatch/relay checks over the genuine loopback TLS/HELLO fixtures."""
import asyncio
import secrets
import unittest
from unittest import mock

from steamboat_connector import channel_wire as wire
from steamboat_connector.channel_rpc import (
    ChannelRpcError, GatewayChannelRelay, _delegation_sequence,
)
from steamboat_runtime.protocol.wire import Request, Response, serialize_message
from steamboat_security.codec import METADATA_KEY, encode_binding
from steamboat_security.ids import new_id
from tests.connector.test_gateway_router import GatewayRouterTwoHopTests


class ChannelRpcRelayTests(unittest.IsolatedAsyncioTestCase):
    """Fixture establishes two real TLS/HELLO/metered TCP hops."""

    def setUp(self):
        from tests.runtime.test_manifest import sample_manifest

        self.manifest = sample_manifest()
        import tests.security.test_identity_core as identity_core
        self._model_patch = mock.patch.object(
            identity_core, "MODEL", self.manifest["fingerprint"])
        self._model_patch.start()
        self.addCleanup(self._model_patch.stop)
        self.fx = GatewayRouterTwoHopTests(
            methodName="test_submit_binds_real_two_hops_hello_generation_and_core_c1")
        self.fx.setUp()
        self.addCleanup(self.fx.doCleanups)
        self.bridge = None

    async def asyncTearDown(self):
        if self.bridge is not None and not self.bridge._closed:
            await self.bridge.stop(grace_seconds=1)
            await self.bridge._handler.shutdown(grace_seconds=1)

    def test_gateway_relay_routes_and_returns_exact_protobuf_rpc(self):
        relay = GatewayChannelRelay(
            coordinator_stream=self.fx.coordinator_server_stream,
            worker_stream=self.fx.worker_server_stream, router=self.fx.router)
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
        coordinator_message = None
        for _ in range(1000):
            self.fx.coordinator_client_stream.pump()
            self.fx.coordinator_server_stream.pump()
            coordinator_message = self.fx.coordinator_server_stream.pop_message()
            if coordinator_message is not None:
                break
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
        worker_response = None
        for _ in range(1000):
            self.fx.worker_client_stream.pump()
            self.fx.worker_server_stream.pump()
            worker_response = self.fx.worker_server_stream.pop_message()
            if worker_response is not None:
                break
        self.assertIsNotNone(worker_response)
        relay._return(worker_response)
        returned = None
        for _ in range(1000):
            self.fx.coordinator_server_stream.pump()
            self.fx.coordinator_client_stream.pump()
            returned = self.fx.coordinator_client_stream.pop_message()
            if returned is not None:
                break
        self.assertIsNotNone(returned)
        self.assertEqual(returned.message_id, message_id)
        self.assertEqual(returned.kind, wire.RESPONSE)
        self.assertEqual(wire.decode_bundle(returned.payload,
                                            fragment_kind=returned.kind).protobuf,
                         serialize_message(response_proto))
        self.assertEqual(relay._pending, {})

    def test_worker_dispatcher_rejects_non_client_hello_and_bad_logical_sequence(self):
        from steamboat_connector.channel_rpc import WorkerChannelRpc

        with self.assertRaises(TypeError):
            WorkerChannelRpc(stream=self.fx.worker_server_stream, bridge=object())
        for envelope in (b"", b"{}", b'{"payload":{"frame_sequence":true}}'):
            with self.subTest(envelope=envelope), self.assertRaises(ChannelRpcError):
                _delegation_sequence(envelope)

    async def test_worker_dispatch_uses_real_c1_bridge_and_worker_handler(self):
        from steamboat_connector.channel_rpc import WorkerChannelRpc
        from steamboat_runtime.secure_worker_runtime import SecureWorkerRuntimeBridge
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
        service = WorkerChannelRpc(stream=self.fx.worker_client_stream,
                                   bridge=self.bridge)

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
        coordinator_message = None
        for _ in range(1000):
            self.fx.coordinator_client_stream.pump()
            self.fx.coordinator_server_stream.pump()
            coordinator_message = self.fx.coordinator_server_stream.pop_message()
            if coordinator_message is not None:
                break
        self.assertIsNotNone(coordinator_message)
        relay = GatewayChannelRelay(
            coordinator_stream=self.fx.coordinator_server_stream,
            worker_stream=self.fx.worker_server_stream, router=self.fx.router)
        relay._forward(coordinator_message)

        worker_message = None
        for _ in range(1000):
            self.fx.worker_server_stream.pump()
            self.fx.worker_client_stream.pump()
            worker_message = self.fx.worker_client_stream.pop_message()
            if worker_message is not None:
                break
        self.assertIsNotNone(worker_message)
        service._admit(worker_message)
        await asyncio.gather(*tuple(service._active))
        self.assertEqual(handler.manifest["fingerprint"], self.manifest["fingerprint"])
        self.assertEqual(self.bridge.status()["active_authorizations"], 0)

        worker_response = None
        for _ in range(1000):
            self.fx.worker_client_stream.pump()
            self.fx.worker_server_stream.pump()
            worker_response = self.fx.worker_server_stream.pop_message()
            if worker_response is not None:
                break
        self.assertIsNotNone(worker_response)
        relay._return(worker_response)
        returned = None
        for _ in range(1000):
            self.fx.coordinator_server_stream.pump()
            self.fx.coordinator_client_stream.pump()
            returned = self.fx.coordinator_client_stream.pop_message()
            if returned is not None:
                break
        self.assertIsNotNone(returned)
        result = wire.decode_bundle(returned.payload, fragment_kind=returned.kind)
        self.assertEqual(result.method, "Describe")
        self.assertEqual(result.classification, wire.BUNDLE_RESPONSE)


if __name__ == "__main__":
    unittest.main()
