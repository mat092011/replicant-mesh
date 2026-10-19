"""Coordinator SDK checks over the genuine two-hop TLS/HELLO fixture."""
import asyncio
import secrets
import unittest

from steamboat_connector import channel_wire as wire
from steamboat_connector.channel_client import (
    CoordinatorChannelClient, _CONTROL_CAPTURE, _CONTROL_SLOTS,
    _DATA_CAPTURE, _DATA_SLOTS,
)
from steamboat_runtime.protocol.wire import Request, Response, serialize_message
from steamboat_security.outbound import AuthorizationWatcher
from tests.connector import test_gateway_router as gateway_router_tests


class CoordinatorChannelClientTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.fx = gateway_router_tests.GatewayRouterTwoHopTests(
            methodName="test_submit_binds_real_two_hops_hello_generation_and_core_c1")
        # Register nested fixture cleanup before setup so partial setup also cleans.
        self.addCleanup(self.fx.doCleanups)
        self.fx.setUp()
        self.client = None

    async def asyncTearDown(self):
        if self.client is not None:
            await self.client.close()

    def _client(self, *, data_bytes=None, control_bytes=None):
        return CoordinatorChannelClient(
            egress=self.fx.coordinator_egress,
            stream=self.fx.coordinator_client_stream,
            authorization_watcher=AuthorizationWatcher(),
            data_capture_reservation_bytes=(
                _DATA_SLOTS * _DATA_CAPTURE if data_bytes is None else data_bytes),
            control_capture_reservation_bytes=(
                _CONTROL_SLOTS * _CONTROL_CAPTURE if control_bytes is None else control_bytes))

    async def test_describe_authorizes_on_genuine_route_and_correlates_local_c2_response(self):
        self.client = self._client()
        context = self.fx.base.adapter.create_bootstrap_context()
        request = Request(protocol_version=1, manifest_fingerprint=self.fx.model_id,
                          worker_boot_id=self.fx.worker_boot_id, timeout_ms=5000)
        call = asyncio.create_task(self.client.execute(
            "Describe", request, trusted_request_context=context))
        server_request = None
        for _ in range(500):
            self.fx.coordinator_server_stream.pump()
            server_request = self.fx.coordinator_server_stream.pop_message()
            if server_request is not None:
                break
            await asyncio.sleep(0.001)
        self.assertIsNotNone(server_request)
        self.assertEqual(server_request.kind, wire.DATA)
        forwarded = wire.decode_bundle(server_request.payload,
                                       fragment_kind=server_request.kind)
        self.assertEqual(forwarded.method, "Describe")
        self.assertTrue(forwarded.binding)
        echoed_request = Request()
        echoed_request.ParseFromString(forwarded.protobuf)
        self.assertGreaterEqual(echoed_request.timeout_ms, 1)
        response = Response(protocol_version=1, manifest_fingerprint=self.fx.model_id,
                            worker_boot_id=self.fx.worker_boot_id, code="OK")
        self.fx.coordinator_server_stream.enqueue(
            kind=wire.RESPONSE, message_id=server_request.message_id,
            payload=wire.encode_bundle(
                "Describe", wire.BUNDLE_RESPONSE, fragment_kind=wire.RESPONSE,
                protobuf=serialize_message(response)))
        for _ in range(500):
            self.fx.coordinator_server_stream.pump()
            if call.done():
                break
            await asyncio.sleep(0.001)
        result = await asyncio.wait_for(call, timeout=2)
        self.assertEqual(result.worker_boot_id, self.fx.worker_boot_id)
        self.assertEqual(self.client._data_bytes, 0)
        self.assertEqual(len(self.client._pending), 0)

    def test_constructor_requires_full_separate_capture_reservations(self):
        with self.assertRaises(ValueError):
            self._client(data_bytes=_DATA_SLOTS * _DATA_CAPTURE - 1)

    async def test_stream_loss_fails_pending_call_and_releases_local_capture(self):
        self.client = self._client()
        context = self.fx.base.adapter.create_bootstrap_context()
        request = Request(protocol_version=1, manifest_fingerprint=self.fx.model_id,
                          worker_boot_id=self.fx.worker_boot_id, timeout_ms=5000)
        call = asyncio.create_task(self.client.execute(
            "Describe", request, trusted_request_context=context))
        for _ in range(500):
            self.fx.coordinator_server_stream.pump()
            incoming = self.fx.coordinator_server_stream.pop_message()
            if incoming is not None:
                break
            await asyncio.sleep(0.001)
        else:
            self.fail("coordinator did not receive the authorized request")
        self.fx.coordinator_server_stream.close()
        with self.assertRaises(Exception):
            await asyncio.wait_for(call, timeout=2)
        self.assertTrue(self.client._unavailable)
        self.assertEqual(self.client._data_bytes, 0)
        self.assertEqual(self.client._pending, {})

    async def test_unknown_message_id_and_wrong_response_method_are_rejected(self):
        self.client = self._client()
        wrong = type("Message", (), {
            "message_id": secrets.token_bytes(16), "kind": wire.RESPONSE,
            "generation": self.client._generation, "payload": b""})()
        with self.assertRaises(Exception):
            self.client._dispatch_response(wrong)
        self.assertFalse(self.client.stream.closed)
        message_id = secrets.token_bytes(16)
        self.client._pending[message_id] = {
            "future": asyncio.get_running_loop().create_future(),
            "method": "Describe", "response_lane": wire.RESPONSE,
        }
        payload = wire.encode_bundle(
            "OpenSession", wire.BUNDLE_RESPONSE, fragment_kind=wire.RESPONSE,
            protobuf=b"x")
        wrong.message_id = message_id
        wrong.payload = payload
        with self.assertRaises(Exception):
            self.client._dispatch_response(wrong)
        self.client._pending[message_id]["future"].cancel()
        self.client._pending.clear()
        self.assertFalse(self.client.stream.closed)

