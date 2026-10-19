"""Focused registration and writer lifecycle tests for the gateway producer."""
import secrets
import unittest
import base64
import hashlib
import json
import select
import socket
import time
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from cryptography import x509

from steamboat_security.sessions import SessionBindings
from steamboat_connector.gateway_router import GatewayRouter, GatewayRouterError
from steamboat_connector.channel_writer import writer_reservation_overhead_bytes
from steamboat_connector.channel_heartbeat import (
    HeartbeatError, PING, PONG, decode_heartbeat, encode_heartbeat,
)
from steamboat_connector import channel_wire as wire
from steamboat_connector.channel_hello import WorkerHelloClient, WorkerHelloServer
from steamboat_connector.channel_socket import ChannelSocket
from steamboat_connector.channel_stream import (
    ChannelStream, is_registered_worker_channel_stream,
)
from steamboat_connector.channel_wire import MAX_BUNDLE_BYTES, MAX_CONTROL_BUNDLE_BYTES
from steamboat_security.gateway_ingress import GatewayWorkerIngress
from tests.security import test_gateway_tls as gateway_tls_tests


class GatewayRouterRegistrationTests(unittest.TestCase):
    def setUp(self):
        self.fixture = GatewayRouterTwoHopTests(
            methodName="test_submit_binds_real_two_hops_hello_generation_and_core_c1")
        self.addCleanup(self.fixture.doCleanups)
        self.fixture.setUp()
        self.router = GatewayRouter(
            gateway_id=self.fixture.router.gateway_id,
            gateway_certificate_pem=self.fixture.base.gateway_cert,
            gateway_private_key_pem=self.fixture.base.gateway_key,
            clock=self.fixture.base.clock,
            communication_reservation_bytes=self.fixture.worker_server_stream.reservation_bound_bytes)
        self.stream = self.fixture.worker_server_stream
        self.cap = self.stream.registration

    def test_registry_accepts_only_owner_minted_live_hello_and_removes_exact_slot(self):
        identity = self.router.register_worker(self.stream)
        self.assertEqual(identity, self.cap.identity)
        with self.assertRaises(GatewayRouterError):
            self.router.register_worker(self.cap)
        self.assertTrue(self.router.remove_worker(self.cap))
        self.assertFalse(self.router.remove_worker(self.cap))
        with self.assertRaises(GatewayRouterError):
            self.router.register_worker(object())

    def test_writer_starts_after_hello_and_is_retired_on_exact_close(self):
        cap = self.cap
        self.router.register_worker(self.stream)
        slot = next(iter(self.router._workers.values()))
        self.assertEqual(slot.writer.expected_generation.hex(), cap.identity[3])
        self.assertIs(slot.writer, self.stream.writer)
        self.assertEqual(slot.writer.accounting.next_fragment_sequence, 2)
        self.assertTrue(self.router.remove_worker(cap))
        self.assertTrue(slot.writer.accounting.retired)

    def test_distinct_live_streams_are_admitted_against_aggregate_reservation(self):
        second_client, second_stream = self.fixture._new_worker_stream(
            worker_boot_id=self.fixture.second_worker_boot_id,
            channel_pem=self.fixture.second_worker_channel_pem,
            channel_key=self.fixture.second_worker_channel_key)
        self.addCleanup(second_client.close)
        reservation = self.stream.reservation_bound_bytes
        self.assertEqual(second_stream.reservation_bound_bytes, reservation)
        self.router.register_worker(self.stream)
        first_slot = self.router._workers[(self.cap.identity[1], self.cap.identity[2])]
        first_generation = first_slot.identity[3]
        first_writer = first_slot.writer

        # The router capacity is exactly one stream. A second, distinct live
        # TLS/HELLO capability must be refused without disturbing either owner.
        with self.assertRaisesRegex(GatewayRouterError, "aggregate worker stream"):
            self.router.register_worker(second_stream)
        self.assertEqual(self.router._reserved_bytes, reservation)
        self.assertEqual(first_slot.identity[3], first_generation)
        self.assertIs(self.router._workers[(self.cap.identity[1], self.cap.identity[2])],
                      first_slot)
        self.assertFalse(first_writer.accounting.retired)
        self.assertFalse(self.stream.closed)
        self.assertFalse(second_stream.closed)
        self.assertEqual(second_stream.writer.accounting.next_fragment_sequence, 2)

        exact_fit = GatewayRouter(
            gateway_id=self.fixture.router.gateway_id,
            gateway_certificate_pem=self.fixture.base.gateway_cert,
            gateway_private_key_pem=self.fixture.base.gateway_key,
            clock=self.fixture.base.clock,
            communication_reservation_bytes=2 * reservation)
        exact_fit.register_worker(self.stream)
        exact_fit.register_worker(second_stream)
        self.assertEqual(exact_fit._reserved_bytes, 2 * reservation)
        self.assertEqual(len(exact_fit._workers), 2)
        self.assertTrue(exact_fit.remove_worker(self.cap))
        self.assertEqual(exact_fit._reserved_bytes, reservation)
        self.assertEqual(len(exact_fit._workers), 1)
        self.assertFalse(second_stream.closed)
        self.assertTrue(is_registered_worker_channel_stream(second_stream))
        self.assertFalse(exact_fit.remove_worker(self.cap))

    def test_replacement_releases_only_the_replaced_stream_reservation(self):
        self.router.register_worker(self.stream)
        old_reserved = self.router._reserved_bytes
        replacement_client, replacement_stream = self.fixture._new_worker_stream()
        self.addCleanup(replacement_client.close)
        self.router.register_worker(replacement_stream)
        self.assertEqual(self.router._reserved_bytes, old_reserved)
        self.assertTrue(self.stream.closed)
        self.assertFalse(replacement_stream.closed)
        self.assertIs(self.router._slot(self.fixture.device_id,
                                         self.fixture.worker_boot_id).stream,
                      replacement_stream)

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
        cap = self.cap
        self.router.register_worker(self.stream)
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
        cap = self.cap
        self.router.register_worker(self.stream)
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
        cap = self.cap
        self.router.register_worker(self.stream)
        self.stream.close()
        self.assertTrue(self.router.remove_worker(cap))
        self.assertEqual(self.router._workers, {})


from steamboat_connector.channel_hello import CoordinatorHelloClient, CoordinatorHelloServer
from steamboat_connector.channel_socket import ChannelSocket
from steamboat_connector.channel_stream import (
    TLS_OWNER_MIN_RESERVATION_BYTES, ChannelStream,
    is_registered_worker_channel_stream,
)
from steamboat_security.channel_tls import OwnedWorkerTLS
from steamboat_connector.channel_writer import writer_reservation_overhead_bytes
from steamboat_connector.channel_wire import (
    BUNDLE_RESPONSE, CONTROL, CONTROL_RESPONSE, DATA, REQUEST, RESPONSE,
    decode_bundle, encode_bundle,
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
    DelegationError, GatewayDelegationVerifier, sign_gateway_delegation,
)
from steamboat_security.gateway_egress import GatewayCoordinatorEgress
from steamboat_security.gateway_ingress import GatewayWorkerIngress
from steamboat_security.gateway_tls import OwnedGatewayWorkerTLS
from steamboat_security.sessions import SessionBindings
from tests.connector.test_traffic_budget import _memory_budget, _policy
from steamboat_security.codec import (
    METADATA_KEY, WORKER_SERVICE, WORKER_METHODS, encode_binding,
)
from steamboat_security.ids import new_id
from tests.security import test_gateway_authorization as core_gateway_tests
from tests.security import test_gateway_egress as egress_tests
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
        self.addCleanup(self._restore_base_fixture)
        self.base.setUp()
        self._base_temp_paths = tuple(Path(path) for path in self.base.client_temp[2])
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
        self.meter_budget, self.meter_store, _meter_clock = _memory_budget(
            policy=_policy(global_total=20_000_000, role_total=6_000_000,
                           send_rate=20_000_000, role_send_rate=6_000_000,
                           cleanup_total=4_000_000, cleanup_rate=4_000_000,
                           role_cleanup_rate=1_000_000),
            clock=SimpleNamespace(clock=self.base.clock))
        self.socket_host_boot = "a" * 32
        self.socket_gateway_boot = "b" * 32
        self.meter_budget.bind_role("host", self.socket_host_boot)
        self.meter_budget.bind_role("coordinator", self.socket_gateway_boot)

        # Both C2 endpoints use this one policy-pinned gateway certificate.
        self.base.egress.close()
        channel_key = generate_private_key_pem()
        self.worker_channel_key = channel_key
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
        self.second_worker_boot_id = "e" * 32
        second_channel_key = generate_private_key_pem()
        second_channel_csr = make_channel_csr(
            second_channel_key, kind="worker_stream", identity=worker_identity)
        self.second_worker_channel_pem = issue_channel_certificate(
            self.base.gateway_ca, self.base.gateway_ca_key, second_channel_csr,
            kind="worker_stream", identity=worker_identity,
            now=datetime.fromtimestamp(now, timezone.utc), lifetime_seconds=800)
        self.second_worker_channel_key = second_channel_key
        second_channel_cert = x509.load_pem_x509_certificate(
            self.second_worker_channel_pem)
        policy = json.loads(json.dumps(self.base.policy_payload))
        policy["revision"] += 1
        policy["workers"][0].update(
            channel_serial=serial_hex(worker_channel_cert.serial_number),
            channel_certificate_sha256=certificate_sha256(worker_channel_cert),
            channel_public_key_sha256=public_key_sha256(worker_channel_cert.public_key()),
        )
        second_worker_policy = dict(policy["workers"][0])
        second_worker_policy.update(
            worker_boot_id=self.second_worker_boot_id,
            channel_serial=serial_hex(second_channel_cert.serial_number),
            channel_certificate_sha256=certificate_sha256(second_channel_cert),
            channel_public_key_sha256=public_key_sha256(second_channel_cert.public_key()),
        )
        policy["workers"].append(second_worker_policy)
        policy["workers"].sort(key=lambda item: (item["device_id"],
                                                  item["worker_boot_id"]))
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
        self.coordinator_driver, self.coordinator_server_driver, coordinator_sockets = (
            self._socket_drivers(self.coordinator_egress, self.coordinator_server))
        self._drive_tls_handshake(
            (self.coordinator_driver, self.coordinator_server_driver),
            (self.coordinator_egress, self.coordinator_server), coordinator_sockets)
        self.coordinator_client_hello = CoordinatorHelloClient(
            self.coordinator_egress, reassembly_capacity=MAX_BUNDLE_BYTES)
        self.coordinator_server_hello = CoordinatorHelloServer.from_tls(
            self.coordinator_server, reassembly_capacity=MAX_BUNDLE_BYTES)
        self.coordinator_client_stream, self.coordinator_server_stream = self._start_streams(
            self.coordinator_driver, self.coordinator_server_driver,
            self.coordinator_client_hello, self.coordinator_server_hello)
        self.assertIsNotNone(self.coordinator_server_stream.registration)
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
        self.worker_client_driver, self.worker_server_driver, worker_sockets = (
            self._socket_drivers(self.worker_client_tls, self.worker_server_tls))
        self._drive_tls_handshake(
            (self.worker_client_driver, self.worker_server_driver),
            (self.worker_client_tls, self.worker_server_tls), worker_sockets)

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
        self.worker_client_stream, self.worker_server_stream = self._start_streams(
            self.worker_client_driver, self.worker_server_driver,
            self.worker_client_hello, self.worker_server_hello)
        self.assertTrue(is_registered_worker_channel_stream(self.worker_server_stream))
        self.worker_registration = self.worker_server_hello.registration
        self.writer = self.worker_server_stream.writer
        self.router = GatewayRouter(
            gateway_id="gw-east", gateway_certificate_pem=self.base.gateway_cert,
            gateway_private_key_pem=self.base.gateway_key, clock=self.base.clock,
            communication_reservation_bytes=8 * self.worker_server_stream.reservation_bound_bytes)
        self.router.register_worker(self.worker_server_stream)
        self.gateway_route_authorizer = Authorizer(
            local_identity=LocalIdentity(self.host["certificate"], self.worker_boot_id,
                                         self.model_id, self.assignment_id),
            snapshot_store=self.base.snapshot_store, clock=self.base.clock,
            session_bindings=self.worker_sessions,
            worker_request_type=core_gateway_tests.PortableParsedRequest)

    @staticmethod
    def _connected_pair():
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        client_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_sock.connect(listener.getsockname())
        server_sock, _ = listener.accept()
        listener.close()
        return client_sock, server_sock

    def _socket_drivers(self, client_tls, server_tls):
        client_sock, server_sock = self._connected_pair()
        self.addCleanup(client_sock.close)
        self.addCleanup(server_sock.close)
        client_driver = ChannelSocket(
            client_sock, client_tls, self.meter_budget, role="host",
            boot_id=self.socket_host_boot)
        self.addCleanup(client_driver.close)
        server_driver = ChannelSocket(
            server_sock, server_tls, self.meter_budget, role="coordinator",
            boot_id=self.socket_gateway_boot)
        self.addCleanup(server_driver.close)
        return client_driver, server_driver, (client_sock, server_sock)

    def _drive_tls_handshake(self, drivers, owners, sockets, timeout=5.0):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            for driver in drivers:
                driver.pump()
            if all(owner.handshake_complete for owner in owners) and all(
                    not driver.pending_plaintext_bytes
                    and not driver.pending_ciphertext_bytes
                    and not driver._tls.pending_encrypted_bytes for driver in drivers):
                return
            select.select(list(sockets), list(sockets), [], 0.001)
        self.fail("socket-driven TLS handshake exceeded its bounded deadline")

    def _start_streams(self, client_driver, server_driver, client_hello, server_hello):
        common = dict(
            writer_reservation_bytes=(writer_reservation_overhead_bytes()
                + wire.MAX_BUNDLE_BYTES + 8 * MAX_CONTROL_BUNDLE_BYTES),
            decoded_byte_capacity=MAX_BUNDLE_BYTES,
            tls_owner_reservation_bytes=TLS_OWNER_MIN_RESERVATION_BYTES)
        client_stream = ChannelStream(client_driver, client_hello, **common)
        self.addCleanup(client_stream.close)
        server_stream = ChannelStream(server_driver, server_hello, **common)
        self.addCleanup(server_stream.close)
        deadline = time.monotonic() + 5.0
        while time.monotonic() < deadline:
            client_stream.pump()
            server_stream.pump()
            if (client_stream.transport_bootstrap_complete
                    and server_stream.transport_bootstrap_complete):
                return client_stream, server_stream
            time.sleep(0.001)
        self.fail("socket-driven TLS/HELLO bootstrap exceeded its bounded deadline")

    def _receive_worker_message(self, timeout=1.0):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            self.worker_server_stream.pump()
            self.worker_client_stream.pump()
            message = self.worker_client_stream.pop_message()
            if message is not None:
                return message
            time.sleep(0.001)
        self.fail("worker route message was not delivered within one second")

    def _new_worker_stream(self, *, worker_boot_id=None, channel_pem=None,
                           channel_key=None):
        worker_boot_id = worker_boot_id or self.worker_boot_id
        channel_pem = channel_pem or self.worker_channel_pem
        channel_key = channel_key or self.worker_channel_key
        client_tls = OwnedWorkerTLS.connect(
            worker_certificate_pem=channel_pem,
            worker_private_key_pem=channel_key,
            gateway_ca_pem=self.base.gateway_ca,
            endpoint_host="worker.gateway.example", endpoint_port=443,
            clock=self.base.clock)
        server_tls = OwnedGatewayWorkerTLS.accept(
            gateway_certificate_pem=self.base.gateway_cert,
            gateway_private_key_pem=self.base.gateway_key,
            cohort_ca_pem=self.base.gateway_ca, policy_store=self.base.policy_store,
            clock=self.base.clock, gateway_id="gw-east")
        client_driver, server_driver, sockets = self._socket_drivers(client_tls, server_tls)
        self._drive_tls_handshake((client_driver, server_driver),
                                  (client_tls, server_tls), sockets)
        sessions = SessionBindings(clock=self.base.clock)
        verifier = GatewayDelegationVerifier(
            self.base.policy_store, clock=self.base.clock,
            gateway_ca_pem=self.base.gateway_ca, participant_ca_pem=self.fx.ca_pem,
            local_identity=LocalIdentity(self.host["certificate"], worker_boot_id,
                                         self.model_id, self.assignment_id),
            endpoint_host="worker.gateway.example", endpoint_port=443)
        ingress = GatewayWorkerIngress.from_tls(
            client_tls, verifier=verifier, sessions=sessions, gateway_id="gw-east")
        hello_client = WorkerHelloClient(ingress, client_tls,
                                         reassembly_capacity=MAX_BUNDLE_BYTES)
        hello_server = WorkerHelloServer.from_tls(
            server_tls, reassembly_capacity=MAX_BUNDLE_BYTES)
        client_stream, server_stream = self._start_streams(
            client_driver, server_driver, hello_client, hello_server)
        return client_stream, server_stream

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
        message = self._receive_worker_message()
        self.assertEqual(message.kind, DATA)
        bundle = decode_bundle(message.payload, fragment_kind=DATA)
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
        self.assertEqual((self.coordinator_egress._tls.endpoint_host,
                          self.coordinator_egress._tls.endpoint_port),
                         ("coordinator.gateway.example", 444))
        self.assertEqual((self.worker_client_tls.endpoint_host,
                          self.worker_client_tls.endpoint_port),
                         ("worker.gateway.example", 443))
        self.assertTrue(self.coordinator_client_stream.transport_bootstrap_complete)
        self.assertTrue(self.coordinator_server_stream.transport_bootstrap_complete)
        self.assertIs(self.coordinator_server_stream.registration,
                      self.coordinator_registration)
        self.assertTrue(self.worker_client_stream.transport_bootstrap_complete)
        self.assertTrue(self.worker_server_stream.transport_bootstrap_complete)
        self.assertIs(self.worker_server_stream.registration,
                      self.worker_registration)
        self.assertGreater(sum(self.coordinator_driver.socket_byte_counts), 0)
        self.assertGreater(sum(self.coordinator_server_driver.socket_byte_counts), 0)
        self.assertGreater(sum(self.worker_client_driver.socket_byte_counts), 0)
        self.assertGreater(sum(self.worker_server_driver.socket_byte_counts), 0)
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
                message = self._receive_worker_message()
                self.assertEqual(message.kind, DATA)
                bundle = decode_bundle(message.payload, fragment_kind=DATA)
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
        self._request_bundle(
            method="Step", operation_id=step_op, request_id=request_id,
            session_id=session_id, protobuf=step_raw, sequence_expected=2,
            message_id=step_id)
        first_global_sequence = self.writer.accounting.next_fragment_sequence
        self.worker_server_stream.pump()
        self.assertEqual(self.writer.accounting.next_fragment_sequence,
                         first_global_sequence + 1)
        cancel_raw = b"cancel"
        self._request_bundle(
            method="CancelSession", operation_id=cancel_op,
            request_id=request_id, session_id=session_id, protobuf=cancel_raw,
            sequence_expected=1, message_id=cancel_id)
        messages = [self._receive_worker_message(), self._receive_worker_message()]
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

    def test_stale_stream_close_cannot_remove_its_replacement(self):
        old_registration = self.worker_registration
        old_stream = self.worker_server_stream
        replacement_client, replacement_stream = self._new_worker_stream()
        new_registration = replacement_stream.registration
        self.assertEqual(old_registration.identity[1:3], new_registration.identity[1:3])
        self.assertNotEqual(old_registration.identity[3], new_registration.identity[3])
        self.router.register_worker(replacement_stream)
        replacement_slot = self.router._slot(self.device_id, self.worker_boot_id)
        self.assertIs(replacement_slot.stream, replacement_stream)
        old_stream.close()
        self.assertFalse(self.router.remove_worker(old_registration))
        self.assertIs(self.router._slot(self.device_id, self.worker_boot_id).stream,
                      replacement_stream)
        self.assertTrue(is_registered_worker_channel_stream(replacement_stream))

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

    def test_closed_socket_stream_is_pruned_before_queued_dispatch(self):
        (_fields, _request_id, _session_id, _operation_id, _metadata, _binding,
         _raw_request, guard, _envelope, _message_id) = self._open_request()
        reserved = self.worker_server_stream.reservation_bound_bytes
        self.worker_server_stream.close()
        with self.assertRaises(GatewayRouterError):
            self.router.assert_dispatch_live(
                coordinator=self.coordinator_registration, worker=self.worker_registration,
                route_guard=guard, method="OpenSession")
        self.assertEqual(self.router._workers, {})
        self.assertEqual(self.router._reserved_bytes, 0)
        self.assertGreater(reserved, 0)

    def _assert_base_tempfiles_removed(self):
        paths = getattr(self, "_base_temp_paths", None)
        if paths is None:
            paths = tuple(Path(path) for path in
                          getattr(self.base, "client_temp", (None, None, ()))[2])
        for path in paths:
            self.assertFalse(path.exists(), f"fixture-owned TLS tempfile leaked: {path}")

    def _restore_base_fixture(self):
        prior = getattr(self.base, "_prior_now", None)
        if prior is not None:
            egress_tests.identity_tests.NOW = prior
        fx = getattr(self.base, "fx", None)
        if fx is not None:
            fx.doCleanups()


class GatewayRouterPartialSetupCleanupTests(unittest.TestCase):
    def test_failed_nested_setup_restores_clock_and_removes_its_tempfiles(self):
        egress_tests.GatewayEgressTests.setUpClass()
        previous_now = egress_tests.identity_tests.NOW
        fixture = GatewayRouterTwoHopTests(
            methodName="test_submit_binds_real_two_hops_hello_generation_and_core_c1")
        paths = []

        def fail_after_tempfile(test_case):
            paths.extend(Path(path) for path in test_case.client_temp[2])
            raise RuntimeError("injected handshake setup failure")

        with mock.patch.object(egress_tests.GatewayEgressTests,
                               "_finish_handshake", fail_after_tempfile):
            with self.assertRaisesRegex(RuntimeError, "injected handshake"):
                fixture.setUp()
            fixture.doCleanups()
        self.assertEqual(egress_tests.identity_tests.NOW, previous_now)
        self.assertTrue(paths)
        for path in paths:
            self.assertFalse(path.exists(), f"fixture-owned TLS tempfile leaked: {path}")
