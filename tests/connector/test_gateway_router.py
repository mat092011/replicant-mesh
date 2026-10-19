"""Focused registration and writer lifecycle tests for the gateway producer."""
import secrets
import unittest
import base64
import hashlib
import json
import ssl
import time
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

from cryptography import x509

from steamboat_security.sessions import SessionBindings
from steamboat_connector.gateway_router import GatewayRouter, GatewayRouterError
from steamboat_connector.channel_writer import ChannelFragmentWriter, writer_reservation_overhead_bytes
from steamboat_connector.channel_heartbeat import (
    HeartbeatError, PING, PONG, decode_heartbeat, encode_heartbeat,
)
from steamboat_connector import channel_wire as wire
from steamboat_connector.channel_hello import WorkerHelloClient, WorkerHelloServer
from steamboat_connector.channel_wire import MAX_BUNDLE_BYTES, MAX_CONTROL_BUNDLE_BYTES
from steamboat_security.gateway_ingress import GatewayWorkerIngress
from tests.security import test_gateway_tls as gateway_tls_tests


class GatewayRouterRegistrationTests(unittest.TestCase):
    def setUp(self):
        self.fixture = gateway_tls_tests.GatewayServerTLSOwnerTests()
        self.fixture.setUp()
        self.ingress = GatewayWorkerIngress.from_tls(
            self.fixture.client, verifier=self.fixture.fixture.fixture.verifier,
            sessions=SessionBindings(clock=self.fixture.fixture.fixture.clock), gateway_id="gw-east")
        self.client = WorkerHelloClient(self.ingress, self.fixture.client,
                                        reassembly_capacity=MAX_BUNDLE_BYTES)
        self.server = WorkerHelloServer.from_tls(
            self.fixture.server, reassembly_capacity=MAX_BUNDLE_BYTES)
        self.server.accept_hello(self.client.hello_frame)
        fx = self.fixture.fixture.fixture
        self.router = GatewayRouter(
            gateway_id="gw-east", gateway_certificate_pem=fx.gateway_pem,
            gateway_private_key_pem=fx.gateway_key, clock=fx.clock,
            communication_reservation_bytes=8_000_000)

    def tearDown(self):
        self.fixture.tearDown()

    def _writer(self, cap):
        return ChannelFragmentWriter(
            bytes.fromhex(cap.identity[3]),
            communication_reservation_bytes=(writer_reservation_overhead_bytes()
                + 256_000 + 8 * MAX_CONTROL_BUNDLE_BYTES), initial_sequence=2)

    def test_registry_accepts_only_owner_minted_live_hello_and_removes_exact_slot(self):
        cap = self.server.registration
        identity = self.router.register_worker(cap, self._writer(cap))
        self.assertEqual(identity, cap.identity)
        with self.assertRaises(GatewayRouterError):
            self.router.register_worker(cap, self._writer(cap))
        self.assertTrue(self.router.remove_worker(cap))
        self.assertFalse(self.router.remove_worker(cap))
        with self.assertRaises(GatewayRouterError):
            self.router.register_worker(object(), self._writer(self.server.registration))

    def test_writer_starts_after_hello_and_is_retired_on_exact_close(self):
        cap = self.server.registration
        self.router.register_worker(cap, self._writer(cap))
        slot = next(iter(self.router._workers.values()))
        self.assertEqual(slot.writer.expected_generation.hex(), cap.identity[3])
        self.assertEqual(slot.writer.accounting.next_fragment_sequence, 2)
        self.assertTrue(self.router.remove_worker(cap))
        self.assertTrue(slot.writer.accounting.retired)

    def test_heartbeat_codec_is_fixed_and_rejects_noncanonical_payloads(self):
        encoded = encode_heartbeat(PING, 7)
        self.assertEqual(len(encoded), 13)
        self.assertEqual(decode_heartbeat(encoded), (PING, 7))
        self.assertEqual(decode_heartbeat(encode_heartbeat(PONG, 7)), (PONG, 7))
        for value in (True, 0, 1 << 63, "7"):
            with self.subTest(sequence=value):
                with self.assertRaises(HeartbeatError):
                    encode_heartbeat(PING, value)
        for payload in (encoded[:-1], encoded + b"x", b"BAD!" + encoded[4:]):
            with self.subTest(payload=payload):
                with self.assertRaises(HeartbeatError):
                    decode_heartbeat(payload)

    def test_ping_shares_control_sequence_and_accepts_one_exact_pong(self):
        cap = self.server.registration
        self.router.register_worker(cap, self._writer(cap))
        slot = next(iter(self.router._workers.values()))
        self.assertTrue(self.router.enqueue_heartbeat(worker=cap))
        self.assertEqual(slot.control_sequence, 2)
        self.assertEqual(slot.heartbeat_outstanding[0], 1)
        self.assertTrue(self.router.accept_heartbeat_pong(
            worker=cap, payload=encode_heartbeat(PONG, 1)))
        self.assertIsNone(slot.heartbeat_outstanding)
        with self.assertRaises(GatewayRouterError):
            self.router.accept_heartbeat_pong(
                worker=cap, payload=encode_heartbeat(PONG, 1))

    def test_full_writer_queue_does_not_consume_heartbeat_control_sequence(self):
        cap = self.server.registration
        self.router.register_worker(cap, self._writer(cap))
        slot = next(iter(self.router._workers.values()))
        bundle = wire.encode_bundle(
            "CancelSession", wire.REQUEST, fragment_kind=wire.CONTROL,
            binding=b"{}", protobuf=b"x")
        for _ in range(8):
            self.assertTrue(slot.writer.enqueue(
                kind=wire.CONTROL, message_id=secrets.token_bytes(16),
                payload=bundle))
        self.assertFalse(self.router.enqueue_heartbeat(worker=cap))
        self.assertEqual(slot.control_sequence, 1)
        self.assertIsNone(slot.heartbeat_outstanding)

    def test_closed_capability_cannot_remove_or_replace_a_new_slot(self):
        cap = self.server.registration
        self.router.register_worker(cap, self._writer(cap))
        self.fixture.server.close()
        self.assertTrue(self.router.remove_worker(cap))
        self.assertEqual(self.router._workers, {})


from steamboat_connector.channel_hello import CoordinatorHelloClient, CoordinatorHelloServer
from steamboat_security.channel_tls import OwnedWorkerTLS
from steamboat_connector.channel_writer import writer_reservation_overhead_bytes
from steamboat_connector.channel_wire import (
    BUNDLE_RESPONSE, CONTROL, CONTROL_RESPONSE, DATA, REQUEST, RESPONSE,
    FragmentDecoder, decode_bundle, encode_bundle,
    MAX_FRAGMENT_BYTES,
)
from steamboat_security.authorization import Authorizer, LocalIdentity
from steamboat_security.certificates import (
    certificate_sha256, generate_private_key_pem, public_key_sha256, serial_hex,
)
from steamboat_security.channel_certificates import (
    issue_channel_certificate, make_channel_csr,
)
from steamboat_security.channel_policy import sign_channel_policy
from steamboat_security.gateway_coordinator_tls import OwnedGatewayCoordinatorTLS
from steamboat_security.gateway_delegation import (
    DOMAIN as DELEGATION_DOMAIN, DelegationError, GatewayDelegationVerifier,
    sign_gateway_delegation,
)
from steamboat_security.gateway_egress import GatewayCoordinatorEgress
from steamboat_security.gateway_ingress import GatewayWorkerIngress
from steamboat_security.gateway_tls import OwnedGatewayWorkerTLS
from steamboat_security.sessions import SessionBindings
from steamboat_security.codec import (
    METADATA_KEY, WORKER_SERVICE, WORKER_METHODS, encode_binding,
)
from steamboat_security.ids import new_id
from tests.security import test_gateway_authorization as core_gateway_tests
from tests.security import test_gateway_egress as egress_tests
from tests.security import test_gateway_ingress as ingress_tests
from tests.security import test_gateway_tls as gateway_tls_tests

class GatewayRouterTwoHopTests(unittest.TestCase):
    """Coherent same-policy, same-gateway actual C1 and channel-TLS fixture."""

    def setUp(self):
        egress_tests.GatewayEgressTests.setUpClass()
        self.base = egress_tests.GatewayEgressTests(
            methodName="test_route_guard_reuses_c1_scope_and_checks_live_gateway_on_completion")
        # LIFO: nested owners close first, base.tearDown restores NOW and the
        # fixture cleans its own resources, then TestCase cleanups close the
        # base's egress and unlink its temporary TLS files. The assertion runs
        # last and only inspects paths created by this fixture.
        self.addCleanup(self._assert_base_tempfiles_removed)
        self.addCleanup(self.base.doCleanups)
        self.base.setUp()
        self._base_temp_paths = tuple(Path(path) for path in self.base.client_temp[2])
        self.addCleanup(self.base.tearDown)
        self.fx = self.base.fx
        self.host = self.fx.credentials["host"]
        self.actor = self.fx.credentials["coordinator"]
        self.actor_record = self.actor["record"]
        self.host_record = self.host["record"]
        self.device_id = self.host_record["device_id"]
        self.worker_boot_id = egress_tests.identity_tests.BOOT_HOST
        self.assignment_id = egress_tests.identity_tests.ASSIGNMENT
        self.model_id = egress_tests.identity_tests.MODEL
        self.coordinator_boot_id = egress_tests.identity_tests.BOOT_COORDINATOR

        # Both C2 endpoints use this one policy-pinned gateway certificate.
        self.base.egress.close()
        channel_key = generate_private_key_pem()
        worker_identity = {
            "account_id": self.host_record["account_id"],
            "device_id": self.host_record["device_id"],
            "host_serial": self.host_record["serial"],
            "credential_epoch": self.host_record["credential_epoch"],
        }
        channel_csr = make_channel_csr(
            channel_key, kind="worker_stream", identity=worker_identity)
        now = int(self.base.time_source.wall)
        self.worker_channel_pem = issue_channel_certificate(
            self.base.gateway_ca, self.base.gateway_ca_key, channel_csr,
            kind="worker_stream", identity=worker_identity,
            now=datetime.fromtimestamp(now, timezone.utc), lifetime_seconds=800)
        worker_channel_cert = x509.load_pem_x509_certificate(self.worker_channel_pem)
        policy = json.loads(json.dumps(self.base.policy_payload))
        policy["revision"] += 1
        policy["workers"][0].update(
            channel_serial=serial_hex(worker_channel_cert.serial_number),
            channel_certificate_sha256=certificate_sha256(worker_channel_cert),
            channel_public_key_sha256=public_key_sha256(worker_channel_cert.public_key()),
        )
        policy["routes"][0]["methods"] = sorted(WORKER_METHODS)
        self.base.policy_store.install(sign_channel_policy(
            policy, egress_tests._private_pem(self.base.policy_key)))

        self.coordinator_server = OwnedGatewayCoordinatorTLS.accept(
            gateway_certificate_pem=self.base.gateway_cert,
            gateway_private_key_pem=self.base.gateway_key,
            gateway_ca_pem=self.base.gateway_ca,
            snapshot_store=self.base.snapshot_store,
            policy_store=self.base.policy_store, clock=self.base.clock,
            gateway_id="gw-east", coordinator_boot_id=self.coordinator_boot_id,
            tenant_account_id=self.actor_record["account_id"],
            target_certificates={(self.device_id, self.worker_boot_id,
                                 self.assignment_id, self.model_id): self.host["certificate"]})
        self.addCleanup(self.coordinator_server.close)
        self.coordinator_egress = GatewayCoordinatorEgress.connect(
            authorizer=self.base.adapter, policy_store=self.base.policy_store,
            logical_host_certificate_pem=self.host["certificate"],
            gateway_id="gw-east", gateway_ca_pem=self.base.gateway_ca,
            coordinator_private_key_pem=self.actor["key"])
        self.addCleanup(self.coordinator_egress.close)
        for _ in range(40):
            outbound = self.coordinator_egress.take_encrypted()
            if outbound:
                self.coordinator_server.feed_encrypted(outbound)
            outbound = self.coordinator_server.take_encrypted()
            if outbound:
                self.coordinator_egress.feed_encrypted(outbound)
            if self.coordinator_egress.handshake_complete and self.coordinator_server.handshake_complete:
                break
        else:
            self.fail("combined coordinator TLS handshake did not complete")
        self.coordinator_client_hello = CoordinatorHelloClient(
            self.coordinator_egress, reassembly_capacity=MAX_BUNDLE_BYTES)
        self.coordinator_server_hello = CoordinatorHelloServer.from_tls(
            self.coordinator_server, reassembly_capacity=MAX_BUNDLE_BYTES)
        self.coordinator_hello_ack = self.coordinator_server_hello.feed_hello(
            self.coordinator_client_hello.hello_frame)
        self.coordinator_server_hello.send_ack(self.coordinator_hello_ack)
        self.coordinator_egress.feed_encrypted(self.coordinator_server.take_encrypted())
        self.assertIsNotNone(self.coordinator_client_hello.read_ack())
        self.coordinator_registration = self.coordinator_server_hello.registration

        self.worker_client_tls = OwnedWorkerTLS.connect(
            worker_certificate_pem=self.worker_channel_pem,
            worker_private_key_pem=channel_key,
            gateway_ca_pem=self.base.gateway_ca,
            endpoint_host="worker.gateway.example", endpoint_port=443,
            clock=self.base.clock)
        self.worker_server_tls = OwnedGatewayWorkerTLS.accept(
            gateway_certificate_pem=self.base.gateway_cert,
            gateway_private_key_pem=self.base.gateway_key,
            cohort_ca_pem=self.base.gateway_ca,
            policy_store=self.base.policy_store, clock=self.base.clock,
            gateway_id="gw-east")
        self.addCleanup(self.worker_client_tls.close)
        self.addCleanup(self.worker_server_tls.close)
        for _ in range(40):
            outbound = self.worker_client_tls.take_encrypted()
            if outbound:
                self.worker_server_tls.feed_encrypted(outbound)
            outbound = self.worker_server_tls.take_encrypted()
            if outbound:
                self.worker_client_tls.feed_encrypted(outbound)
            if self.worker_client_tls.handshake_complete and self.worker_server_tls.handshake_complete:
                break
        else:
            self.fail("combined worker TLS handshake did not complete")

        self.worker_sessions = SessionBindings(clock=self.base.clock)
        self.worker_verifier = GatewayDelegationVerifier(
            self.base.policy_store, clock=self.base.clock,
            gateway_ca_pem=self.base.gateway_ca, participant_ca_pem=self.fx.ca_pem,
            local_identity=LocalIdentity(self.host["certificate"], self.worker_boot_id,
                                         self.model_id, self.assignment_id),
            endpoint_host="worker.gateway.example", endpoint_port=443)
        self.worker_ingress = GatewayWorkerIngress.from_tls(
            self.worker_client_tls, verifier=self.worker_verifier,
            sessions=self.worker_sessions, gateway_id="gw-east")
        self.worker_client_hello = WorkerHelloClient(
            self.worker_ingress, self.worker_client_tls,
            reassembly_capacity=MAX_BUNDLE_BYTES)
        self.worker_server_hello = WorkerHelloServer.from_tls(
            self.worker_server_tls, reassembly_capacity=MAX_BUNDLE_BYTES)
        self.worker_client_hello.send_hello()
        self.worker_server_tls.feed_encrypted(self.worker_client_tls.take_encrypted())
        worker_ack = self.worker_server_hello.read_hello()
        self.worker_server_hello.send_ack(worker_ack)
        self.worker_client_tls.feed_encrypted(self.worker_server_tls.take_encrypted())
        self.assertIsNotNone(self.worker_client_hello.read_ack())
        self.worker_registration = self.worker_server_hello.registration

        self.writer = ChannelFragmentWriter(
            bytes.fromhex(self.worker_registration.identity[3]),
            communication_reservation_bytes=(writer_reservation_overhead_bytes()
                + 256_000 + 8 * MAX_CONTROL_BUNDLE_BYTES), initial_sequence=2,
            fragment_payload_bytes=8192)
        self.router = GatewayRouter(
            gateway_id="gw-east", gateway_certificate_pem=self.base.gateway_cert,
            gateway_private_key_pem=self.base.gateway_key, clock=self.base.clock,
            communication_reservation_bytes=self.writer.communication_reservation_bytes)
        self.router.register_worker(self.worker_registration, self.writer)
        self.gateway_route_authorizer = Authorizer(
            local_identity=LocalIdentity(self.host["certificate"], self.worker_boot_id,
                                         self.model_id, self.assignment_id),
            snapshot_store=self.base.snapshot_store, clock=self.base.clock,
            session_bindings=self.worker_sessions,
            worker_request_type=core_gateway_tests.PortableParsedRequest)

    def _binding_metadata(self, method, *, operation_id, request_id, session_id,
                          route_id="route_" + "9" * 32):
        fields = {
            "binding_version": 1, "operation_id": operation_id,
            "account_id": self.actor_record["account_id"],
            "device_id": self.actor_record["device_id"], "role": "personal_coordinator",
            "credential_epoch": self.actor_record["credential_epoch"],
            "target_device_id": self.device_id,
            "coordinator_boot_id": self.coordinator_boot_id,
            "tenant_account_id": self.actor_record["account_id"],
            "request_id": request_id, "session_id": session_id,
            "route_id": route_id, "route_epoch": 1, "attempt": 1,
            "assignment_id": self.assignment_id, "worker_boot_id": self.worker_boot_id,
        }
        raw = encode_binding(WORKER_SERVICE, method, fields)
        return fields, ((METADATA_KEY, raw),), raw

    def _open_request(self):
        request_id = new_id("req")
        session_id = new_id("ses")
        operation_id = new_id("op")
        fields, metadata, binding = self._binding_metadata(
            "OpenSession", operation_id=operation_id, request_id=request_id,
            session_id=session_id)
        request = core_gateway_tests.PortableParsedRequest(
            protocol_version=1, manifest_fingerprint=self.model_id,
            worker_boot_id=self.worker_boot_id, session_id=session_id,
            timeout_ms=5_000, lease_token="", max_positions=64,
            lifetime_ms=30_000, idle_lease_ms=10_000,
            sequence=0, start_position=0, token_count=0)
        raw_request = request.SerializeToString(deterministic=True)
        guard = self.coordinator_server.authenticated_channel.authorize_route(
            method="OpenSession", target_device_id=self.device_id,
            worker_boot_id=self.worker_boot_id, assignment_id=self.assignment_id,
            model_id=self.model_id)
        message_id = b"O" * 16
        self.assertTrue(self.router.submit(
            coordinator=self.coordinator_registration, worker=self.worker_registration,
            route_guard=guard, method="OpenSession", metadata=metadata,
            request_bytes=raw_request, message_id=message_id))
        envelope = None
        # OpenSession fits one C2 fragment, decoded using the actual HELLO decoder.
        frame = self.writer.next_frame()
        self.assertIsNotNone(frame)
        messages = list(self.worker_server_hello.decoder.feed(frame))
        self.writer.frame_sent(frame)
        self.assertEqual(len(messages), 1)
        bundle = decode_bundle(messages[0].payload, fragment_kind=DATA)
        envelope = bundle.envelope
        self.assertEqual(bundle.binding, binding)
        c1 = self.gateway_route_authorizer.authorize_gateway(
            WORKER_SERVICE, "OpenSession", request, metadata,
            ingress=self.worker_ingress, envelope=envelope,
            request_bytes=raw_request, frame_sequence=1, wire_lane="data")
        response = SimpleNamespace(
            DESCRIPTOR=SimpleNamespace(full_name="steamboat.v1.Response"), code="OK",
            protocol_version=1, manifest_fingerprint=self.model_id,
            worker_boot_id=self.worker_boot_id, session_id=session_id,
            lease_token="lease_router_0123456789", max_positions=64)
        c1.complete(response)
        return (fields, request_id, session_id, operation_id, metadata, binding,
                raw_request, guard, envelope, message_id)

    def _route_guard(self, method):
        return self.coordinator_server.authenticated_channel.authorize_route(
            method=method, target_device_id=self.device_id,
            worker_boot_id=self.worker_boot_id, assignment_id=self.assignment_id,
            model_id=self.model_id)

    def _request_bundle(self, *, method, operation_id, request_id, session_id,
                        protobuf, sequence_expected, message_id):
        fields, metadata, binding = self._binding_metadata(
            method, operation_id=operation_id, request_id=request_id,
            session_id=session_id)
        lane = "control" if method in {"CloseSession", "CancelSession", "SessionStatus"} else "data"
        route_guard = self._route_guard(method)
        kind = CONTROL if lane == "control" else DATA
        self.assertTrue(self.router.submit(
            coordinator=self.coordinator_registration, worker=self.worker_registration,
            route_guard=route_guard, method=method, metadata=metadata,
            request_bytes=protobuf, message_id=message_id))
        return fields, metadata, binding, lane, kind, route_guard

    def test_submit_binds_real_two_hops_hello_generation_and_core_c1(self):
        (fields, request_id, session_id, operation_id, metadata, binding,
         raw_request, guard, envelope, message_id) = self._open_request()
        decoded = json.loads(envelope.decode("utf-8"))["payload"]
        self.assertEqual(decoded["stream_generation"], self.worker_registration.identity[3])
        self.assertNotEqual(decoded["stream_generation"],
                            self.worker_server_tls.authenticated_channel.stream_generation)
        self.assertEqual(decoded["binding_sha256"], hashlib.sha256(binding).hexdigest())
        self.assertEqual(decoded["request_sha256"], hashlib.sha256(raw_request).hexdigest())
        self.assertTrue(self.router.assert_dispatch_live(
            coordinator=self.coordinator_registration, worker=self.worker_registration,
            route_guard=guard, method="OpenSession"))
        response_payload = encode_bundle(
            "OpenSession", BUNDLE_RESPONSE, fragment_kind=RESPONSE, protobuf=b"ok")
        self.assertTrue(self.router.complete(
            worker=self.worker_registration, operation_id=operation_id,
            request_id=request_id, message_id=message_id, method="OpenSession",
            payload=response_payload))
        self.assertNotIn(operation_id, self.router._slot(self.device_id, self.worker_boot_id).pending_data)

    def test_both_genuine_describe_binding_forms_reach_ingress_and_core_c1(self):
        compact_fields = {
            "binding_version": 1, "operation_id": new_id("op"),
            "account_id": self.actor_record["account_id"],
            "device_id": self.actor_record["device_id"],
            "role": "personal_coordinator",
            "credential_epoch": self.actor_record["credential_epoch"],
            "target_device_id": self.device_id,
        }
        forms = (compact_fields, {
            **compact_fields, "operation_id": new_id("op"),
            "worker_boot_id": self.worker_boot_id,
            "assignment_id": self.assignment_id,
        })
        request = core_gateway_tests.PortableParsedRequest(
            protocol_version=1, manifest_fingerprint=self.model_id,
            worker_boot_id=self.worker_boot_id, session_id="", lease_token="",
            timeout_ms=5_000, max_positions=0, lifetime_ms=0,
            idle_lease_ms=0, sequence=0, start_position=0, token_count=0)
        raw = request.SerializeToString(deterministic=True)
        for index, fields in enumerate(forms, start=1):
            with self.subTest(optional_target_fields="worker_boot_id" in fields):
                binding = encode_binding(WORKER_SERVICE, "Describe", fields)
                metadata = ((METADATA_KEY, binding),)
                guard = self._route_guard("Describe")
                message_id = bytes([index]) * 16
                self.assertTrue(self.router.submit(
                    coordinator=self.coordinator_registration,
                    worker=self.worker_registration, route_guard=guard,
                    method="Describe", metadata=metadata, request_bytes=raw,
                    message_id=message_id))
                frame = self.writer.next_frame()
                messages = list(self.worker_server_hello.decoder.feed(frame))
                self.writer.frame_sent(frame)
                self.assertEqual(len(messages), 1)
                bundle = decode_bundle(messages[0].payload, fragment_kind=DATA)
                self.assertEqual(bundle.binding, binding)
                auth = self.gateway_route_authorizer.authorize_gateway(
                    WORKER_SERVICE, "Describe", request, metadata,
                    ingress=self.worker_ingress, envelope=bundle.envelope,
                    request_bytes=raw, frame_sequence=index, wire_lane="data")
                auth.assert_live()
                self.assertTrue(self.router.complete(
                    worker=self.worker_registration, operation_id=fields["operation_id"],
                    request_id=None, message_id=message_id, method="Describe",
                    payload=encode_bundle("Describe", BUNDLE_RESPONSE,
                                          fragment_kind=RESPONSE, protobuf=b"ok")))

    def test_control_preempts_fragmented_step_and_lane_counters_stay_contiguous(self):
        (fields, request_id, session_id, open_op, _metadata, _binding,
         _raw_request, _guard, _envelope, _message_id) = self._open_request()
        step_op, cancel_op = new_id("op"), new_id("op")
        step_raw = json.dumps({"step": "x" * 40_000}, separators=(",", ":")).encode()
        step_id, cancel_id = b"S" * 16, b"C" * 16
        step = self._request_bundle(
            method="Step", operation_id=step_op, request_id=request_id,
            session_id=session_id, protobuf=step_raw, sequence_expected=2,
            message_id=step_id)
        first_step_frame = self.writer.next_frame()
        self.assertEqual(first_step_frame[4], DATA)
        list(self.worker_server_hello.decoder.feed(first_step_frame))
        self.writer.frame_sent(first_step_frame)
        cancel_raw = b"cancel"
        cancel = self._request_bundle(
            method="CancelSession", operation_id=cancel_op,
            request_id=request_id, session_id=session_id, protobuf=cancel_raw,
            sequence_expected=1, message_id=cancel_id)
        first_after_cancel = self.writer.next_frame()
        self.assertEqual(first_after_cancel[4], CONTROL)
        messages = list(self.worker_server_hello.decoder.feed(first_after_cancel))
        self.writer.frame_sent(first_after_cancel)
        while self.writer.pending_bytes:
            frame = self.writer.next_frame()
            messages.extend(self.worker_server_hello.decoder.feed(frame))
            self.writer.frame_sent(frame)
        self.assertEqual([m.kind for m in messages], [CONTROL, DATA])
        decoded = [decode_bundle(m.payload, fragment_kind=m.kind) for m in messages]
        self.assertEqual([b.method for b in decoded], ["CancelSession", "Step"])
        control_seq, data_seq = [], []
        for message, bundle in zip(messages, decoded):
            payload = json.loads(bundle.envelope.decode("utf-8"))["payload"]
            self.assertEqual(payload["stream_generation"], self.worker_registration.identity[3])
            if message.kind == DATA:
                data_seq.append(payload["frame_sequence"])
            else:
                control_seq.append(payload["frame_sequence"])
        self.assertEqual(data_seq, [2])
        self.assertEqual(control_seq, [1])
        # The worker verifier consumes the exact same HELLO generation/counters.
        cancel_bundle = decoded[0]
        cancel_meta = ((METADATA_KEY, cancel_bundle.binding),)
        self.worker_ingress.verify_operation(
            cancel_bundle.envelope, cancel_meta, cancel_raw, 1, "control")
        step_bundle = decoded[1]
        step_meta = ((METADATA_KEY, step_bundle.binding),)
        self.worker_ingress.verify_operation(
            step_bundle.envelope, step_meta, step_raw, 2, "data")
        cancel_response = encode_bundle(
            "CancelSession", BUNDLE_RESPONSE, fragment_kind=CONTROL_RESPONSE,
            protobuf=b"cancelled")
        self.assertFalse(self.router.complete(
            worker=self.worker_registration, operation_id=step_op,
            request_id="req_wrong", message_id=cancel_id,
            method="CancelSession", payload=cancel_response))
        self.assertTrue(self.router.complete(
            worker=self.worker_registration, operation_id=cancel_op,
            request_id=request_id, message_id=cancel_id,
            method="CancelSession", payload=cancel_response))
        step_response = encode_bundle(
            "Step", BUNDLE_RESPONSE, fragment_kind=RESPONSE, protobuf=b"step")
        self.assertTrue(self.router.complete(
            worker=self.worker_registration, operation_id=step_op,
            request_id=request_id, message_id=step_id,
            method="Step", payload=step_response))

    def test_wrong_scope_actor_metadata_and_request_bytes_are_rejected(self):
        (fields, request_id, session_id, operation_id, metadata, binding,
         raw_request, open_guard, envelope, _message_id) = self._open_request()
        # A genuine guard for another method cannot authorize OpenSession.
        with self.assertRaises(GatewayRouterError):
            self.router.submit(
                coordinator=self.coordinator_registration, worker=self.worker_registration,
                route_guard=self._route_guard("Step"), method="OpenSession",
                metadata=metadata, request_bytes=raw_request)
        wrong = dict(fields)
        wrong["device_id"] = egress_tests.identity_tests.DEVICE_ALT_COORDINATOR
        wrong_binding = encode_binding(WORKER_SERVICE, "OpenSession", wrong)
        with self.assertRaises(GatewayRouterError):
            self.router.submit(
                coordinator=self.coordinator_registration, worker=self.worker_registration,
                route_guard=open_guard, method="OpenSession",
                metadata=((METADATA_KEY, wrong_binding),), request_bytes=raw_request)
        with self.assertRaises(GatewayRouterError):
            self.router.submit(
                coordinator=self.coordinator_registration, worker=self.worker_registration,
                route_guard=open_guard, method="OpenSession", metadata=metadata,
                request_bytes=b"x" * (wire.MAX_PROTOBUF_BYTES + 1))
        # A gateway-signed but wrong actual actor leaf cannot verify under current
        # C1 binding and signed route policy.
        outer = json.loads(envelope.decode("utf-8"))
        payload = outer["payload"]
        alt_cert = self.fx.credentials["alt_coordinator"]["certificate"]
        payload["actor_certificate_base64"] = base64.b64encode(alt_cert).decode("ascii")
        forged = sign_gateway_delegation(payload, self.base.gateway_key, self.base.gateway_cert)
        with self.assertRaises(DelegationError):
            self.worker_verifier.verify(
                forged, gateway_peer_certificate_pem=self.base.gateway_cert,
                metadata=metadata, request_bytes=raw_request,
                expected_stream_generation=self.worker_registration.identity[3],
                expected_frame_sequence=1, expected_lane="data")
        slot = self.router._slot(self.device_id, self.worker_boot_id)
        before = (slot.data_sequence, dict(slot.pending_data), self.worker_ingress._state.closed)
        with self.assertRaises(DelegationError):
            self.worker_verifier.verify(
                envelope, gateway_peer_certificate_pem=self.base.gateway_cert,
                metadata=metadata, request_bytes=raw_request + b"changed",
                expected_stream_generation=self.worker_registration.identity[3],
                expected_frame_sequence=1, expected_lane="data")
        self.assertEqual((slot.data_sequence, dict(slot.pending_data),
                          self.worker_ingress._state.closed), before)

    def test_full_control_admission_does_not_create_logical_sequence_gap(self):
        request_id, session_id = new_id("req"), new_id("ses")
        slot = self.router._slot(self.device_id, self.worker_boot_id)
        for _ in range(8):
            self._request_bundle(
                method="CancelSession", operation_id=new_id("op"),
                request_id=request_id, session_id=session_id, protobuf=b"cancel",
                sequence_expected=0, message_id=secrets.token_bytes(16))
        self.assertEqual(slot.control_sequence, 9)
        fields, metadata, _binding = self._binding_metadata(
            "CancelSession", operation_id=new_id("op"), request_id=request_id,
            session_id=session_id)
        accepted = self.router.submit(
            coordinator=self.coordinator_registration, worker=self.worker_registration,
            route_guard=self._route_guard("CancelSession"), method="CancelSession",
            metadata=metadata, request_bytes=b"cancel", message_id=b"Z" * 16)
        self.assertFalse(accepted)
        self.assertEqual(slot.control_sequence, 9)
    def test_policy_or_stream_expiry_rejects_queued_dispatch(self):
        (_fields, _request_id, _session_id, _operation_id, _metadata, _binding,
         _raw_request, guard, _envelope, _message_id) = self._open_request()
        self.base.time_source.advance(301)
        with self.assertRaises(GatewayRouterError):
            self.router.assert_dispatch_live(
                coordinator=self.coordinator_registration, worker=self.worker_registration,
                route_guard=guard, method="OpenSession")

    def _assert_base_tempfiles_removed(self):
        for path in getattr(self, "_base_temp_paths", ()):
            self.assertFalse(path.exists(), f"fixture-owned TLS tempfile leaked: {path}")
