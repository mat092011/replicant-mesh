"""Actual-stream tests for the single-owner C2 gateway demultiplexer."""
from __future__ import annotations

import unittest
import time
import copy
import json

from steamboat_connector import channel_wire as wire
from steamboat_connector.gateway_mux import GatewayChannelMultiplexer, GatewayMuxError
from steamboat_connector.channel_rpc import _CONTROL_CAPTURE_BYTES, _RELAY_CAPTURE_BYTES
from steamboat_connector.channel_heartbeat import PING, PONG, decode_heartbeat, encode_heartbeat
from steamboat_runtime.protocol import PROTOCOL_VERSION
from steamboat_runtime.protocol.wire import Request, Response, serialize_message
from steamboat_security.codec import METADATA_KEY, WORKER_SERVICE, encode_binding
from steamboat_security.ids import new_id
from steamboat_security.snapshot import sign_snapshot
from tests.connector import test_gateway_router as router_fixtures


class GatewayMuxActualStreamTests(unittest.TestCase):
    def setUp(self):
        self.fixture = router_fixtures.GatewayRouterTwoHopTests(
            methodName="test_submit_binds_real_two_hops_hello_generation_and_core_c1")
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.fx = self.fixture
        self._expand_dual_boot_cohort()

    def _expand_dual_boot_cohort(self):
        """Rebuild real C2 endpoints after signing both boot routes/grants."""
        fx = self.fx
        old_worker = fx.worker_registration
        old_coordinator_server = fx.coordinator_server
        old_coordinator_egress = fx.coordinator_egress
        old_coordinator_server_stream = fx.coordinator_server_stream
        old_coordinator_client_stream = fx.coordinator_client_stream
        fx.router.remove_worker(old_worker)
        old_worker_stream = fx.worker_server_stream
        old_worker_client_stream = fx.worker_client_stream
        old_worker_stream.close()
        old_worker_client_stream.close()
        old_coordinator_server_stream.close()
        old_coordinator_client_stream.close()
        old_coordinator_server.close()
        old_coordinator_egress.close()

        snapshot = json.loads(fx.base.snapshot_store.current().canonical_payload)
        snapshot["revision"] += 1
        source_grant = next(
            item for item in snapshot["grants"]
            if item["target_boot_id"] == fx.worker_boot_id
            and item["method"] == "steamboat.v1.Worker/OpenSession")
        for method in ("Describe", "OpenSession", "CancelSession", "SessionStatus"):
            grant = copy.deepcopy(source_grant)
            grant["target_boot_id"] = fx.second_worker_boot_id
            grant["method"] = "steamboat.v1.Worker/" + method
            snapshot["grants"].append(grant)
        fx.base.snapshot_store.install(sign_snapshot(snapshot, fx.fx.signing_key))

        policy = json.loads(fx.base.policy_store.current().canonical_payload)
        policy["revision"] += 1
        second_route = copy.deepcopy(policy["routes"][0])
        second_route["worker_boot_id"] = fx.second_worker_boot_id
        policy["routes"].append(second_route)
        policy["routes"][0]["methods"] = sorted(router_fixtures.WORKER_METHODS)
        policy["routes"][1]["methods"] = sorted(router_fixtures.WORKER_METHODS)
        fx.base.policy_store.install(router_fixtures.sign_channel_policy(
            policy, router_fixtures.egress_tests._private_pem(fx.base.policy_key)))

        target_certificates = {
            (fx.device_id, boot_id, fx.assignment_id, fx.model_id): fx.host["certificate"]
            for boot_id in (fx.worker_boot_id, fx.second_worker_boot_id)
        }
        fx.coordinator_server = router_fixtures.OwnedGatewayCoordinatorTLS.accept(
            gateway_certificate_pem=fx.base.gateway_cert,
            gateway_private_key_pem=fx.base.gateway_key,
            gateway_ca_pem=fx.base.gateway_ca,
            snapshot_store=fx.base.snapshot_store,
            policy_store=fx.base.policy_store, clock=fx.base.clock,
            gateway_id="gw-east", coordinator_boot_id=fx.coordinator_boot_id,
            tenant_account_id=fx.actor_record["account_id"],
            target_certificates=target_certificates)
        fx.addCleanup(fx.coordinator_server.close)
        fx.coordinator_egress = router_fixtures.GatewayCoordinatorEgress.connect(
            authorizer=fx.base.adapter, policy_store=fx.base.policy_store,
            logical_host_certificate_pem=fx.host["certificate"],
            gateway_id="gw-east", gateway_ca_pem=fx.base.gateway_ca,
            coordinator_private_key_pem=fx.actor["key"])
        fx.addCleanup(fx.coordinator_egress.close)
        (fx.coordinator_driver, fx.coordinator_server_driver, sockets) = fx._socket_drivers(
            fx.coordinator_egress, fx.coordinator_server)
        fx._drive_tls_handshake(
            (fx.coordinator_driver, fx.coordinator_server_driver),
            (fx.coordinator_egress, fx.coordinator_server), sockets)
        fx.coordinator_client_hello = router_fixtures.CoordinatorHelloClient(
            fx.coordinator_egress, reassembly_capacity=router_fixtures.MAX_BUNDLE_BYTES)
        fx.coordinator_server_hello = router_fixtures.CoordinatorHelloServer.from_tls(
            fx.coordinator_server, reassembly_capacity=router_fixtures.MAX_BUNDLE_BYTES)
        (fx.coordinator_client_stream, fx.coordinator_server_stream) = fx._start_streams(
            fx.coordinator_driver, fx.coordinator_server_driver,
            fx.coordinator_client_hello, fx.coordinator_server_hello)
        fx.coordinator_registration = fx.coordinator_server_stream.registration

        client_one, server_one = fx._new_worker_stream(
            worker_boot_id=fx.worker_boot_id, channel_pem=fx.worker_channel_pem,
            channel_key=fx.worker_channel_key)
        client_two, server_two = fx._new_worker_stream(
            worker_boot_id=fx.second_worker_boot_id,
            channel_pem=fx.second_worker_channel_pem,
            channel_key=fx.second_worker_channel_key)
        fx.router.register_worker(server_one)
        fx.router.register_worker(server_two)
        fx.worker_client_streams = (client_one, client_two)
        fx.worker_server_streams = (server_one, server_two)
        fx.worker_server_stream = server_one
        fx.worker_client_stream = client_one
        fx.worker_registration = server_one.registration
        fx.second_worker_registration = server_two.registration
        fx.worker_ingresses = (client_one._hello.ingress, client_two._hello.ingress)
        fx.worker_sessions = fx.worker_ingresses[0].sessions
        fx.writer = server_one.writer

    def _mux(self, streams=None):
        mux = GatewayChannelMultiplexer(
            coordinator_stream=self.fx.coordinator_server_stream,
            worker_streams=streams or self.fx.worker_server_streams,
            router=self.fx.router,
            data_capture_reservation_bytes=9 * _RELAY_CAPTURE_BYTES,
            control_capture_reservation_bytes=8 * _CONTROL_CAPTURE_BYTES)
        self.addCleanup(mux.stop)
        self.mux = mux
        self.worker_queues = {index: [] for index in range(len(self.fx.worker_client_streams))}
        self.coordinator_queue = []
        return mux

    def _enqueue_open(self, *, boot_id=None, binding_boot_id=None,
                      message_id=b"M" * 16):
        boot_id = boot_id or self.fx.worker_boot_id
        session_id = new_id("ses")
        fields, _metadata, _binding = self.fx._binding_metadata(
            "OpenSession", operation_id=new_id("op"),
            request_id=new_id("req"), session_id=session_id)
        fields["worker_boot_id"] = binding_boot_id or boot_id
        binding = encode_binding(WORKER_SERVICE, "OpenSession", fields)
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

    def _service_worker_clients(self):
        for index, stream in enumerate(self.fx.worker_client_streams):
            stream.pump()
            message = stream.pop_message()
            if message is None:
                continue
            if message.kind == wire.HEARTBEAT:
                mode, sequence = decode_heartbeat(message.payload)
                if mode != PING:
                    raise AssertionError("gateway sent a non-PING heartbeat")
                stream.enqueue(kind=wire.HEARTBEAT, message_id=message.message_id,
                               payload=encode_heartbeat(PONG, sequence))
                stream.pump()
            else:
                self.worker_queues[index].append(message)

    def _service_coordinator_client(self):
        stream = self.fx.coordinator_client_stream
        stream.pump()
        message = stream.pop_message()
        if message is None:
            return
        if message.kind == wire.HEARTBEAT:
            mode, sequence = decode_heartbeat(message.payload)
            if mode != PING:
                raise AssertionError("gateway sent a non-PING coordinator heartbeat")
            stream.enqueue(kind=wire.HEARTBEAT, message_id=message.message_id,
                           payload=encode_heartbeat(PONG, sequence))
            stream.pump()
        else:
            self.coordinator_queue.append(message)

    def _wait_diagnostic(self, expected_id):
        mux = getattr(self, "mux", None)
        if mux is None:
            return f"message_id={expected_id.hex()} (mux not constructed)"
        streams = (self.fx.coordinator_client_stream, *self.fx.worker_client_streams)
        pending = tuple((stream.decoded_pending_bytes,
                         stream.pending_outgoing_frame_bytes,
                         stream.writer.accounting.queued_and_active_payload_bytes)
                        for stream in streams)
        queues = {index: tuple(item.message_id.hex() for item in queue)
                  for index, queue in self.worker_queues.items()}
        return (f"message_id={expected_id.hex()} pending={mux.pending_counts} "
                f"capture={mux.pending_capture_bytes} stream_bytes={pending} "
                f"worker_message_ids={queues}")

    def _worker_message(self, index, expected_id, timeout=1.0):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            self._service_coordinator_client()
            if self.mux._accepting:
                self.mux.pump_once()
            self._service_worker_clients()
            queue = self.worker_queues[index]
            for offset, message in enumerate(queue):
                if message.message_id == expected_id:
                    return queue.pop(offset)
            time.sleep(0.001)
        self.fail("selected actual worker stream did not receive its request: "
                   + self._wait_diagnostic(expected_id))

    def _another_coordinator_stream(self):
        fx = self.fx
        targets = {
            (fx.device_id, boot, fx.assignment_id, fx.model_id): fx.host["certificate"]
            for boot in (fx.worker_boot_id, fx.second_worker_boot_id)
        }
        server = router_fixtures.OwnedGatewayCoordinatorTLS.accept(
            gateway_certificate_pem=fx.base.gateway_cert,
            gateway_private_key_pem=fx.base.gateway_key,
            gateway_ca_pem=fx.base.gateway_ca,
            snapshot_store=fx.base.snapshot_store,
            policy_store=fx.base.policy_store, clock=fx.base.clock,
            gateway_id="gw-east", coordinator_boot_id=fx.coordinator_boot_id,
            tenant_account_id=fx.actor_record["account_id"],
            target_certificates=targets)
        self.addCleanup(server.close)
        egress = router_fixtures.GatewayCoordinatorEgress.connect(
            authorizer=fx.base.adapter, policy_store=fx.base.policy_store,
            logical_host_certificate_pem=fx.host["certificate"],
            gateway_id="gw-east", gateway_ca_pem=fx.base.gateway_ca,
            coordinator_private_key_pem=fx.actor["key"])
        self.addCleanup(egress.close)
        client_driver, server_driver, sockets = fx._socket_drivers(egress, server)
        fx._drive_tls_handshake((client_driver, server_driver), (egress, server), sockets)
        client_hello = router_fixtures.CoordinatorHelloClient(
            egress, reassembly_capacity=router_fixtures.MAX_BUNDLE_BYTES)
        server_hello = router_fixtures.CoordinatorHelloServer.from_tls(
            server, reassembly_capacity=router_fixtures.MAX_BUNDLE_BYTES)
        _client_stream, server_stream = fx._start_streams(
            client_driver, server_driver, client_hello, server_hello)
        return server_stream

    def _coordinator_message(self, expected_id, timeout=1.0):
        stream = self.fx.coordinator_client_stream
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            self._service_coordinator_client()
            if self.mux._accepting:
                self.mux.pump_once()
            self._service_worker_clients()
            self._service_coordinator_client()
            for offset, queued in enumerate(self.coordinator_queue):
                if queued.message_id == expected_id:
                    return self.coordinator_queue.pop(offset)
            time.sleep(0.001)
        self.fail("actual coordinator stream did not receive its response: "
                   + self._wait_diagnostic(expected_id))

    def _expect_mux_error(self, pattern, timeout=1.0):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                self._service_coordinator_client()
                self.mux.pump_once()
            except GatewayMuxError as error:
                self.assertRegex(str(error), pattern)
                return error
            self._service_worker_clients()
            time.sleep(0.001)
        self.fail("mux did not fail on the expected actual stream input")

    def _verify_ingress(self, index, request, raw, binding, delivered,
                        method="OpenSession"):
        ingress = self.fx.worker_ingresses[index]
        boot_id = request.worker_boot_id
        identity = router_fixtures.LocalIdentity(
            self.fx.host["certificate"], boot_id, self.fx.model_id,
            self.fx.assignment_id)
        authorizer = type(self.fx.gateway_route_authorizer)(
            local_identity=identity, snapshot_store=self.fx.base.snapshot_store,
            clock=self.fx.base.clock, session_bindings=ingress.sessions,
            worker_request_type=Request)
        decoded = wire.decode_bundle(delivered.payload, fragment_kind=wire.DATA)
        self.assertEqual(delivered.kind, wire.DATA)
        self.assertEqual(decoded.binding, binding)
        authorization = authorizer.authorize_gateway(
            WORKER_SERVICE, method, request, ((METADATA_KEY, binding),),
            ingress=ingress, envelope=decoded.envelope,
            request_bytes=raw, frame_sequence=1, wire_lane="data")
        response = Response(code="OK", protocol_version=PROTOCOL_VERSION,
                            manifest_fingerprint=self.fx.model_id,
                            worker_boot_id=boot_id)
        if method == "OpenSession":
            response.session_id = request.session_id
            response.lease_token = "lease_mux_0123456789"
            response.max_positions = request.max_positions
        authorization.complete(response)

    def test_actual_two_hop_submit_uses_one_coordinator_pop_and_core_ingress(self):
        mux = self._mux()
        request, raw, binding, message_id = self._enqueue_open()
        second_request, second_raw, second_binding, second_message_id = self._enqueue_open(
            boot_id=self.fx.second_worker_boot_id, message_id=b"N" * 16)
        self.fx.coordinator_client_stream.pump()
        delivered = self._worker_message(0, message_id)
        self.assertEqual(delivered.message_id, message_id)
        self._verify_ingress(0, request, raw, binding, delivered)
        delivered_second = self._worker_message(1, second_message_id)
        self.assertEqual(delivered_second.message_id, second_message_id)
        self._verify_ingress(1, second_request, second_raw,
                             second_binding, delivered_second)
        self.assertEqual(mux.pending_counts, (2, 0))
        self.assertEqual(mux.pending_capture_bytes[0], 2 * _RELAY_CAPTURE_BYTES)

        second_response = Response(
            code="OK", protocol_version=PROTOCOL_VERSION,
            manifest_fingerprint=self.fx.model_id, worker_boot_id=second_request.worker_boot_id,
            session_id=second_request.session_id,
            lease_token="lease_mux_0123456789", max_positions=64)
        second_response_bundle = wire.encode_bundle(
            "OpenSession", wire.BUNDLE_RESPONSE, fragment_kind=wire.RESPONSE,
            protobuf=serialize_message(second_response))
        self.fx.worker_client_streams[1].enqueue(
            kind=wire.RESPONSE, message_id=second_message_id,
            payload=second_response_bundle)
        self.fx.worker_client_streams[1].pump()
        received_second = self._coordinator_message(second_message_id)
        self.assertEqual((received_second.message_id, received_second.kind),
                         (second_message_id, wire.RESPONSE))

        first_response = Response(
            code="OK", protocol_version=PROTOCOL_VERSION,
            manifest_fingerprint=self.fx.model_id,
            worker_boot_id=request.worker_boot_id, session_id=request.session_id,
            lease_token="lease_mux_0123456789", max_positions=64)
        first_response_bundle = wire.encode_bundle(
            "OpenSession", wire.BUNDLE_RESPONSE, fragment_kind=wire.RESPONSE,
            protobuf=serialize_message(first_response))
        self.fx.worker_client_streams[0].enqueue(
            kind=wire.RESPONSE, message_id=message_id, payload=first_response_bundle)
        self.fx.worker_client_streams[0].pump()
        received_first = self._coordinator_message(message_id)
        self.assertEqual((received_first.message_id, received_first.kind),
                         (message_id, wire.RESPONSE))
        self.assertEqual(mux.pending_counts, (0, 0))
        self.assertEqual(mux.pending_capture_bytes, (0, 0))
        self.assertIn(message_id, mux._seen)
        self._enqueue_open(message_id=message_id)
        self._expect_mux_error("reused in this coordinator generation")
        self.assertEqual(mux.pending_counts, (0, 0))

    def test_exact_worker_boot_is_selected_from_request_and_unknown_boot_fails_closed(self):
        mux = self._mux()
        self.assertNotEqual(
            self.fx.worker_server_streams[0].registration.identity[2],
            self.fx.worker_server_streams[1].registration.identity[2])
        request, _raw, _binding, _mid = self._enqueue_open(
            boot_id="f" * 32, binding_boot_id=self.fx.worker_boot_id)
        self._expect_mux_error("exact captured worker generation")
        self.assertEqual(request.worker_boot_id, "f" * 32)
        self.assertEqual(mux.pending_counts, (1, 0))
        self.assertFalse(mux._accepting)

    def test_legacy_describe_binding_selects_exact_second_boot_from_protobuf(self):
        mux = self._mux()
        fields = {
            "binding_version": 1, "operation_id": new_id("op"),
            "account_id": self.fx.actor_record["account_id"],
            "device_id": self.fx.actor_record["device_id"],
            "role": "personal_coordinator",
            "credential_epoch": self.fx.actor_record["credential_epoch"],
            "target_device_id": self.fx.device_id,
        }
        binding = encode_binding(WORKER_SERVICE, "Describe", fields)
        request = Request(protocol_version=PROTOCOL_VERSION,
                          manifest_fingerprint=self.fx.model_id,
                          worker_boot_id=self.fx.second_worker_boot_id,
                          timeout_ms=5000)
        raw = serialize_message(request)
        message_id = b"D" * 16
        self.fx.coordinator_client_stream.enqueue(
            kind=wire.DATA, message_id=message_id,
            payload=wire.encode_bundle(
                "Describe", wire.REQUEST, fragment_kind=wire.DATA,
                binding=binding, protobuf=raw))
        self.fx.coordinator_client_stream.pump()
        delivered = self._worker_message(1, message_id)
        self.assertEqual(delivered.message_id, message_id)
        self._verify_ingress(1, request, raw, binding, delivered, method="Describe")
        self.assertIn(message_id, mux._pending)

    def test_aggregate_data_full_still_admits_control_on_real_worker_writer(self):
        mux = self._mux()
        for index in range(1, 10):
            message_id = index.to_bytes(16, "big")
            worker_index = index % 2
            worker_boot_id = (self.fx.second_worker_boot_id if worker_index
                              else self.fx.worker_boot_id)
            self._enqueue_open(boot_id=worker_boot_id, message_id=message_id)
            self.fx.coordinator_client_stream.pump()
            delivered = self._worker_message(worker_index, message_id)
            self.assertEqual((delivered.message_id, delivered.kind),
                             (message_id, wire.DATA))
        self.assertEqual(mux.pending_counts, (9, 0))
        self.assertEqual(mux.pending_capture_bytes,
                         (9 * _RELAY_CAPTURE_BYTES, 0))

        fields, _metadata, _binding = self.fx._binding_metadata(
            "SessionStatus", operation_id=new_id("op"),
            request_id=new_id("req"), session_id=new_id("ses"))
        request = Request(
            protocol_version=PROTOCOL_VERSION,
            manifest_fingerprint=self.fx.model_id,
            worker_boot_id=self.fx.worker_boot_id,
            session_id=fields["session_id"], timeout_ms=5000)
        raw = serialize_message(request)
        binding = encode_binding(WORKER_SERVICE, "SessionStatus", fields)
        self.fx.coordinator_client_stream.enqueue(
            kind=wire.CONTROL, message_id=b"C" * 16,
            payload=wire.encode_bundle(
                "SessionStatus", wire.REQUEST, fragment_kind=wire.CONTROL,
                binding=binding, protobuf=raw))
        self.fx.coordinator_client_stream.pump()
        control = self._worker_message(0, b"C" * 16)
        self.assertEqual((control.message_id, control.kind),
                         (b"C" * 16, wire.CONTROL))
        self.assertEqual(mux.pending_counts, (9, 1))
        self.assertEqual(mux.pending_capture_bytes,
                         (9 * _RELAY_CAPTURE_BYTES, _CONTROL_CAPTURE_BYTES))

    def test_wrong_worker_response_and_worker_loss_retire_whole_cohort(self):
        mux = self._mux()
        first, _first_raw, _first_binding, first_id = self._enqueue_open(
            message_id=b"1" * 16)
        second, _second_raw, _second_binding, second_id = self._enqueue_open(
            boot_id=self.fx.second_worker_boot_id, message_id=b"2" * 16)
        self.fx.coordinator_client_stream.pump()
        self._worker_message(0, first_id)
        self._worker_message(1, second_id)
        forged_association_response = Response(
            code="OK", protocol_version=PROTOCOL_VERSION,
            manifest_fingerprint=self.fx.model_id,
            worker_boot_id=second.worker_boot_id, session_id=second.session_id,
            lease_token="lease_mux_0123456789", max_positions=64)
        self.fx.worker_client_streams[0].enqueue(
            kind=wire.RESPONSE, message_id=second_id,
            payload=wire.encode_bundle(
                "OpenSession", wire.BUNDLE_RESPONSE, fragment_kind=wire.RESPONSE,
                protobuf=serialize_message(forged_association_response)))
        self.fx.worker_client_streams[0].pump()
        self._expect_mux_error("other than its captured owner")
        self.assertFalse(mux._accepting)
        self.assertTrue(self.fx.coordinator_server_stream.closed)
        self.assertTrue(all(stream.closed for stream in self.fx.worker_server_streams))
        self.assertEqual(mux.pending_counts, (2, 0))
        self.assertEqual(mux.pending_capture_bytes,
                         (2 * _RELAY_CAPTURE_BYTES, 0))

    def test_worker_generation_loss_closes_cohort_and_retains_pending_capture(self):
        mux2 = self._mux()
        self._enqueue_open(message_id=b"L" * 16)
        self.fx.coordinator_client_stream.pump()
        self._worker_message(0, b"L" * 16)
        self.fx.worker_server_streams[1].close()
        with self.assertRaises(GatewayMuxError):
            mux2.pump_once()
        self.assertFalse(mux2._accepting)
        self.assertTrue(self.fx.coordinator_server_stream.closed)
        self.assertTrue(self.fx.worker_server_streams[0].closed)
        self.assertEqual(mux2.pending_counts, (1, 0))
        self.assertEqual(mux2.pending_capture_bytes, (_RELAY_CAPTURE_BYTES, 0))

    def test_mux_claims_all_captured_streams_globally(self):
        mux = self._mux()
        with self.assertRaisesRegex(GatewayMuxError, "already has a mux owner"):
            GatewayChannelMultiplexer(
                coordinator_stream=self.fx.coordinator_server_stream,
                worker_streams=self.fx.worker_server_streams,
                router=self.fx.router,
                data_capture_reservation_bytes=9 * _RELAY_CAPTURE_BYTES,
                control_capture_reservation_bytes=8 * _CONTROL_CAPTURE_BYTES)
        # A distinct genuine coordinator cannot reuse these genuine worker
        # streams/writers in a competing mux cohort.
        second_coordinator_stream = self._another_coordinator_stream()
        with self.assertRaisesRegex(GatewayMuxError, "already has a mux owner"):
            GatewayChannelMultiplexer(
                coordinator_stream=second_coordinator_stream,
                worker_streams=self.fx.worker_server_streams,
                router=self.fx.router,
                data_capture_reservation_bytes=9 * _RELAY_CAPTURE_BYTES,
                control_capture_reservation_bytes=8 * _CONTROL_CAPTURE_BYTES)
        self.assertEqual(mux.pending_counts, (0, 0))


if __name__ == "__main__":
    unittest.main()
