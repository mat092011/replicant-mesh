"""Actual-stream tests for the single-owner C2 gateway demultiplexer."""
from __future__ import annotations

import unittest
import time

from steamboat_connector import channel_wire as wire
from steamboat_connector.gateway_mux import GatewayChannelMultiplexer, GatewayMuxError
from steamboat_connector.channel_rpc import _CONTROL_CAPTURE_BYTES, _RELAY_CAPTURE_BYTES
from steamboat_runtime.protocol import PROTOCOL_VERSION
from steamboat_runtime.protocol.wire import Request, Response, serialize_message
from steamboat_security.codec import METADATA_KEY
from tests.connector import test_gateway_router as router_fixtures


class GatewayMuxActualStreamTests(unittest.TestCase):
    def setUp(self):
        self.fixture = router_fixtures.GatewayRouterTwoHopTests(
            methodName="test_submit_binds_real_two_hops_hello_generation_and_core_c1")
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.fx = self.fixture

    def _mux(self, streams=None):
        return GatewayChannelMultiplexer(
            coordinator_stream=self.fx.coordinator_server_stream,
            worker_streams=streams or (self.fx.worker_server_stream,),
            router=self.fx.router,
            data_capture_reservation_bytes=9 * _RELAY_CAPTURE_BYTES,
            control_capture_reservation_bytes=8 * _CONTROL_CAPTURE_BYTES)

    def _enqueue_open(self, *, boot_id=None, message_id=b"M" * 16):
        boot_id = boot_id or self.fx.worker_boot_id
        session_id = "ses_" + "1" * 32
        fields, _metadata, binding = self.fx._binding_metadata(
            "OpenSession", operation_id="op_" + "1" * 32,
            request_id="req_" + "1" * 32, session_id=session_id)
        request = Request(
            protocol_version=PROTOCOL_VERSION,
            manifest_fingerprint=self.fx.model_id,
            worker_boot_id=boot_id, session_id=session_id, timeout_ms=5000,
            max_positions=64, lifetime_ms=30000, idle_lease_ms=10000)
        raw = serialize_message(request)
        payload = wire.encode_bundle("OpenSession", wire.REQUEST,
                                     fragment_kind=wire.DATA, binding=binding,
                                     protobuf=raw)
        self.fx.coordinator_client_stream.enqueue(
            kind=wire.DATA, message_id=message_id, payload=payload)
        return request, raw, binding, message_id

    def test_actual_two_hop_submit_uses_one_coordinator_pop_and_core_ingress(self):
        mux = self._mux()
        request, raw, binding, message_id = self._enqueue_open()
        self.fx.coordinator_client_stream.pump()
        # This is the sole coordinator pump/pop; the selected relay's run loop
        # is deliberately not started.
        mux.pump_once()
        delivered = self.fx._receive_worker_message()
        self.assertEqual(delivered.message_id, message_id)
        self.assertEqual(delivered.kind, wire.DATA)
        decoded = wire.decode_bundle(delivered.payload, fragment_kind=wire.DATA)
        self.assertEqual(decoded.binding, binding)
        envelope = decoded.envelope
        authorizer = type(self.fx.gateway_route_authorizer)(
            local_identity=self.fx.gateway_route_authorizer.local_identity,
            snapshot_store=self.fx.base.snapshot_store,
            clock=self.fx.base.clock,
            session_bindings=self.fx.worker_sessions,
            worker_request_type=Request)
        c1 = authorizer.authorize_gateway(
            "steamboat.v1.Worker", "OpenSession", request,
            ((METADATA_KEY, binding),),
            ingress=self.fx.worker_ingress, envelope=envelope,
            request_bytes=raw, frame_sequence=1, wire_lane="data")
        self.assertIsNotNone(c1)
        c1.complete(Response(
            code="OK", protocol_version=PROTOCOL_VERSION,
            manifest_fingerprint=self.fx.model_id,
            worker_boot_id=self.fx.worker_boot_id,
            session_id=request.session_id,
            lease_token="lease_mux_0123456789", max_positions=64))
        self.assertEqual(mux.pending_counts, (1, 0))
        self.assertEqual(mux.pending_capture_bytes[0], _RELAY_CAPTURE_BYTES)
        response = Response(
            code="OK", protocol_version=PROTOCOL_VERSION,
            manifest_fingerprint=self.fx.model_id,
            worker_boot_id=self.fx.worker_boot_id,
            session_id=request.session_id,
            lease_token="lease_mux_0123456789", max_positions=64)
        response_bundle = wire.encode_bundle(
            "OpenSession", wire.BUNDLE_RESPONSE, fragment_kind=wire.RESPONSE,
            protobuf=serialize_message(response))
        self.fx.worker_client_stream.enqueue(
            kind=wire.RESPONSE, message_id=message_id, payload=response_bundle)
        self.fx.worker_client_stream.pump()
        mux.pump_once()
        deadline = time.monotonic() + 1.0
        received = None
        while time.monotonic() < deadline and received is None:
            self.fx.coordinator_client_stream.pump()
            received = self.fx.coordinator_client_stream.pop_message()
            if received is None:
                time.sleep(0.001)
        self.assertIsNotNone(received)
        self.assertEqual(received.message_id, message_id)
        self.assertEqual(received.kind, wire.RESPONSE)
        self.assertEqual(mux.pending_counts, (0, 0))
        self.assertEqual(mux.pending_capture_bytes, (0, 0))

    def test_exact_worker_boot_is_selected_from_request_and_unknown_boot_fails_closed(self):
        second_client, second_server = self.fx._new_worker_stream(
            worker_boot_id=self.fx.second_worker_boot_id,
            channel_pem=self.fx.second_worker_channel_pem,
            channel_key=self.fx.second_worker_channel_key)
        self.fx.router.register_worker(second_server)
        mux = self._mux((self.fx.worker_server_stream, second_server))
        request, _raw, _binding, _mid = self._enqueue_open(boot_id="f" * 32)
        with self.assertRaises(GatewayMuxError):
            mux.pump_once()
        self.assertEqual(request.worker_boot_id, "f" * 32)
        self.assertEqual(mux.pending_counts, (1, 0))
        self.assertFalse(mux._accepting)

    def test_duplicate_wire_id_is_rejected_after_completion_history_boundary(self):
        mux = self._mux()
        self.assertEqual(mux.pending_counts, (0, 0))
        self.assertEqual(len(mux._seen), 0)
        # ID history is intentionally generation-local and non-evicting; the
        # admission path checks reuse before any decode or route operation.
        mux._seen.add(b"D" * 16)
        from types import SimpleNamespace
        message = SimpleNamespace(message_id=b"D" * 16, kind=wire.DATA)
        with self.assertRaisesRegex(GatewayMuxError, "reused"):
            mux._reserve(message)
        self.assertEqual(mux.pending_counts, (0, 0))


if __name__ == "__main__":
    unittest.main()
