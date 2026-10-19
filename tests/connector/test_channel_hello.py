"""Mutual TLS component tests for the bounded worker HELLO bootstrap."""

import json
import copy
import secrets
import struct
import threading
import unittest
from unittest.mock import patch

import steamboat_connector.channel_hello as _hello_module
from steamboat_connector.channel_hello import (
    ChannelHelloError, CoordinatorHelloClient, CoordinatorHelloServer,
    RegisteredWorker, WorkerHelloClient, WorkerHelloServer,
    _BoundedHelloReader, _parse_hello,
)
from steamboat_security.channel_tls import OwnedWorkerTLS
from steamboat_security.gateway_ingress import GatewayIngressError, GatewayWorkerIngress
from steamboat_security.gateway_tls import OwnedGatewayWorkerTLS
from steamboat_security.gateway_coordinator_tls import OwnedGatewayCoordinatorTLS
from steamboat_security.gateway_tls import GatewayWorkerTLSError
from steamboat_security.sessions import SessionBindings
from steamboat_connector.channel_wire import (HELLO, MAX_BUNDLE_BYTES, DATA,
                                               encode_bundle, iter_fragments)
from tests.security import test_gateway_ingress as ingress_tests
from tests.security import test_gateway_tls as gateway_tls_tests
from tests.security import test_gateway_coordinator_tls as coordinator_tls_tests
from steamboat_security.gateway_egress import GatewayCoordinatorEgress


class ChannelHelloTests(unittest.TestCase):
    def setUp(self):
        # Reuse the repository's actual mutual-TLS MemoryBIO fixture pair.
        self.fixture = gateway_tls_tests.GatewayServerTLSOwnerTests()
        self.fixture.setUp()
        self.ingress = GatewayWorkerIngress.from_tls(
            self.fixture.client,
            verifier=self.fixture.fixture.fixture.verifier,
            sessions=SessionBindings(clock=self.fixture.fixture.fixture.clock),
            gateway_id="gw-east")
        self.capacity = MAX_BUNDLE_BYTES

    def tearDown(self):
        self.fixture.tearDown()

    @staticmethod
    def _deliver_hello_over_tls(server, client, frame):
        client.write_plaintext(frame)
        server.owner.feed_encrypted(client.take_encrypted())
        return server.read_hello()

    def test_hello_ack_binds_real_worker_and_continues_at_sequence_two(self):
        client = WorkerHelloClient(self.ingress, self.fixture.client,
                                   reassembly_capacity=self.capacity)
        server = WorkerHelloServer.from_tls(
            self.fixture.server, self.fixture.server.authenticated_channel,
            reassembly_capacity=self.capacity)
        ack = None
        for byte in client.hello_frame:
            result = server.feed_hello(bytes([byte]))
            if result is not None:
                ack = result
        self.assertIsNotNone(ack)
        self.assertEqual(server.initial_sequence, 2)
        decoder = None
        for byte in ack:
            result = client.feed_ack(bytes([byte]))
            if result is not None:
                decoder = result
        self.assertIsNotNone(decoder)
        self.assertEqual(client.initial_sequence, 2)
        self.assertEqual(server.registration.identity[2], self.fixture.server.authenticated_channel.worker_boot_id)
        self.assertEqual(server.registration.identity[3], self.ingress.stream_generation)
        self.assertEqual(server.registration.server_connection_nonce,
                         self.fixture.server.authenticated_channel.stream_generation)
        self.assertEqual(decoder.expected_generation, client.generation)
        self.assertEqual(server.decoder._next_sequence, 2)
        self.assertEqual(decoder._next_sequence, 2)
        self.assertEqual(server.initial_sequence, 2)
        self.assertEqual(client.initial_sequence, 2)
        # A normal inference bundle larger than the bootstrap limit is accepted
        # after sequence one has been consumed by HELLO/ACK.
        bundle = encode_bundle("Describe", 1, fragment_kind=DATA,
                               binding=b"b", protobuf=b"p" * 5000)
        frame = next(iter_fragments(bundle, kind=DATA, generation=client.generation,
                                    message_id=secrets.token_bytes(16), first_sequence=2))
        self.assertEqual(next(decoder.feed(frame)).payload, bundle)
        server.registration.assert_live()
        with self.assertRaises(AttributeError):
            server.owner = object()
        with self.assertRaises(AttributeError):
            client.tls_owner = object()
        with self.assertRaises(AttributeError):
            server.registration._RegisteredWorker__generation = b"x" * 16
        try:
            copied = copy.copy(server.registration)
        except (AttributeError, TypeError):
            copied = None
        if copied is not None:
            with self.assertRaises(ChannelHelloError):
                copied.assert_live()
        with self.assertRaises(TypeError):
            RegisteredWorker(None, self.fixture.server,
                             self.fixture.server.authenticated_channel,
                             client.generation, b"n" * 16)

    def test_ack_after_ingress_heartbeat_expiry_cannot_commit(self):
        client = WorkerHelloClient(self.ingress, self.fixture.client,
                                   reassembly_capacity=self.capacity)
        server = WorkerHelloServer.from_tls(self.fixture.server,
                                            reassembly_capacity=self.capacity)
        ack = server.accept_hello(client.hello_frame)
        clock = self.fixture.fixture.fixture
        clock.mono += 61
        clock.wall += 61
        with self.assertRaises(GatewayIngressError):
            client.feed_ack(ack)
        self.assertTrue(self.ingress.poll_unavailable())
        self.assertFalse(self.fixture.client.is_live)
        self.assertIsNone(client.decoder)
        with self.assertRaises(ChannelHelloError):
            _ = client.initial_sequence

    def test_hello_and_ack_traverse_the_actual_mutual_tls_plaintext_engines(self):
        client = WorkerHelloClient(self.ingress, self.fixture.client,
                                   reassembly_capacity=self.capacity)
        server = WorkerHelloServer.from_tls(self.fixture.server,
                                            reassembly_capacity=self.capacity)
        self.assertEqual(client.send_hello(), len(client.hello_frame))
        self.fixture.server.feed_encrypted(self.fixture.client.take_encrypted())
        ack = server.read_hello()
        self.assertIsNotNone(ack)
        self.assertEqual(server.send_ack(ack), len(ack))
        self.fixture.client.feed_encrypted(self.fixture.server.take_encrypted())
        decoder = client.read_ack()
        self.assertIsNotNone(decoder)
        self.assertEqual(server.registration.identity[3], client.generation.hex())
        self.assertEqual(client.initial_sequence, 2)
        with self.assertRaises(ChannelHelloError):
            client.send_hello()

    def test_replay_and_duplicate_hello_fault_connection(self):
        client = WorkerHelloClient(self.ingress, self.fixture.client,
                                   reassembly_capacity=self.capacity)
        server = WorkerHelloServer.from_tls(self.fixture.server,
                                            reassembly_capacity=self.capacity)
        self._deliver_hello_over_tls(server, self.fixture.client, client.hello_frame)
        with self.assertRaises(ChannelHelloError):
            self._deliver_hello_over_tls(server, self.fixture.client, client.hello_frame)
        self.assertFalse(self.fixture.server.is_live)

    def test_wrong_boot_is_rejected_against_authenticated_tls_channel(self):
        client = WorkerHelloClient(self.ingress, self.fixture.client,
                                   reassembly_capacity=self.capacity)
        server = WorkerHelloServer.from_tls(self.fixture.server,
                                            reassembly_capacity=self.capacity)
        payload = json.loads(client.hello_frame[56:])
        payload["boot_id"] = "different-boot"
        forged = next(iter_fragments(
            json.dumps(payload, sort_keys=True, separators=(",", ":")).encode(),
            kind=HELLO, generation=client.generation, message_id=secrets.token_bytes(16)))
        with self.assertRaises(ChannelHelloError):
            self._deliver_hello_over_tls(server, self.fixture.client, forged)
        self.assertFalse(self.fixture.server.is_live)

    def test_wrong_account_is_rejected_against_authenticated_tls_channel(self):
        client = WorkerHelloClient(self.ingress, self.fixture.client,
                                   reassembly_capacity=self.capacity)
        value = json.loads(client.hello_frame[56:])
        value["account_id"] = "acct_wrong"
        forged = next(iter_fragments(
            json.dumps(value, sort_keys=True, separators=(",", ":")).encode(),
            kind=HELLO, generation=client.generation, message_id=secrets.token_bytes(16)))
        server = WorkerHelloServer.from_tls(self.fixture.server,
                                            reassembly_capacity=self.capacity)
        with self.assertRaises(ChannelHelloError):
            self._deliver_hello_over_tls(server, self.fixture.client, forged)
        self.assertFalse(self.fixture.server.is_live)

    def test_wrong_policy_revision_is_rejected_against_authenticated_channel(self):
        client = WorkerHelloClient(self.ingress, self.fixture.client,
                                   reassembly_capacity=self.capacity)
        value = json.loads(client.hello_frame[56:])
        value["policy_revision"] += 1
        forged = next(iter_fragments(
            json.dumps(value, sort_keys=True, separators=(",", ":")).encode(),
            kind=HELLO, generation=client.generation, message_id=secrets.token_bytes(16)))
        server = WorkerHelloServer.from_tls(self.fixture.server,
                                            reassembly_capacity=self.capacity)
        with self.assertRaises(ChannelHelloError):
            self._deliver_hello_over_tls(server, self.fixture.client, forged)
        self.assertFalse(self.fixture.server.is_live)

    def test_ack_for_a_different_hello_permanently_faults_worker_ingress(self):
        client = WorkerHelloClient(self.ingress, self.fixture.client,
                                   reassembly_capacity=self.capacity)
        ack = {"version": 1, "role": "gateway",
               "generation": client.generation.hex(),
               "hello_sha256": "0" * 64, "server_nonce": "1" * 32}
        forged = next(iter_fragments(
            json.dumps(ack, sort_keys=True, separators=(",", ":")).encode(),
            kind=HELLO, generation=client.generation, message_id=secrets.token_bytes(16)))
        with self.assertRaises(ChannelHelloError):
            client.accept_ack(forged)
        self.assertFalse(self.fixture.client.is_live)

    def test_policy_replacement_retires_registered_worker_capability(self):
        client = WorkerHelloClient(self.ingress, self.fixture.client,
                                   reassembly_capacity=self.capacity)
        server = WorkerHelloServer.from_tls(self.fixture.server,
                                            reassembly_capacity=self.capacity)
        server.accept_hello(client.hello_frame)
        capability = server.registration
        self.fixture._new_gateway_credential("gateway.example.net")
        with self.assertRaises(GatewayWorkerTLSError):
            capability.assert_live()

    def test_same_worker_tls_owner_cannot_create_second_client_bootstrap(self):
        WorkerHelloClient(self.ingress, self.fixture.client,
                          reassembly_capacity=self.capacity)
        with self.assertRaises(ChannelHelloError):
            WorkerHelloClient(self.ingress, self.fixture.client,
                              reassembly_capacity=self.capacity)
        self.assertFalse(self.fixture.client.is_live)

    def test_same_gateway_tls_owner_cannot_create_second_server_bootstrap(self):
        WorkerHelloServer.from_tls(self.fixture.server,
                                   reassembly_capacity=self.capacity)
        with self.assertRaises(ChannelHelloError):
            WorkerHelloServer.from_tls(self.fixture.server,
                                       reassembly_capacity=self.capacity)
        self.assertFalse(self.fixture.server.is_live)

    def test_duplicate_worker_factory_never_closes_under_registry_lock(self):
        owner = self.fixture.server
        WorkerHelloServer.from_tls(owner, reassembly_capacity=self.capacity)
        _assert_duplicate_factory_lock_order(self, owner, OwnedGatewayWorkerTLS,
            lambda: WorkerHelloServer.from_tls(owner, reassembly_capacity=self.capacity))

    def test_same_worker_generation_cannot_be_replayed_on_another_tls_connection(self):
        client_bootstrap = WorkerHelloClient(
            self.ingress, self.fixture.client, reassembly_capacity=self.capacity)
        first_server = WorkerHelloServer.from_tls(
            self.fixture.server, reassembly_capacity=self.capacity)
        self._deliver_hello_over_tls(first_server, self.fixture.client,
                                     client_bootstrap.hello_frame)

        materials = self.fixture.fixture
        second_client = OwnedWorkerTLS.connect(
            worker_certificate_pem=materials.worker_channel,
            worker_private_key_pem=materials.worker_channel_key,
            gateway_ca_pem=materials.fixture.gateway_ca,
            endpoint_host="gateway.example.net", endpoint_port=443,
            clock=materials.fixture.clock)
        second_server = OwnedGatewayWorkerTLS.accept(
            gateway_certificate_pem=materials.fixture.gateway_pem,
            gateway_private_key_pem=materials.fixture.gateway_key,
            cohort_ca_pem=materials.fixture.gateway_ca,
            policy_store=materials.fixture.policy_store, clock=materials.fixture.clock,
            gateway_id="gw-east")
        try:
            for _ in range(40):
                encrypted = second_client.take_encrypted()
                if encrypted:
                    second_server.feed_encrypted(encrypted)
                encrypted = second_server.take_encrypted()
                if encrypted:
                    second_client.feed_encrypted(encrypted)
                if second_client.handshake_complete and second_server.handshake_complete:
                    break
            else:
                self.fail("second mutual TLS handshake did not complete")
            replay_server = WorkerHelloServer.from_tls(
                second_server, reassembly_capacity=self.capacity)
            with self.assertRaises(ChannelHelloError):
                second_client.write_plaintext(client_bootstrap.hello_frame)
                second_server.feed_encrypted(second_client.take_encrypted())
                replay_server.read_hello()
            self.assertFalse(second_server.is_live)
        finally:
            second_client.close()
            second_server.close()

    def test_bootstrap_header_table_rejects_kind_flags_sequence_and_generation(self):
        generation = b"g" * 16
        cases = (
            (b"BAD!", HELLO, 3, 0, generation, 1, b"m" * 16, 0, 2),
            (b"C2F1", DATA, 3, 0, generation, 1, b"m" * 16, 0, 2),
            (b"C2F1", HELLO, 1, 0, generation, 1, b"m" * 16, 0, 2),
            (b"C2F1", HELLO, 3, 1, generation, 1, b"m" * 16, 0, 2),
            (b"C2F1", HELLO, 3, 0, generation, 2, b"m" * 16, 0, 2),
            (b"C2F1", HELLO, 3, 0, b"z" * 16, 1, b"m" * 16, 0, 2),
            (b"C2F1", HELLO, 3, 0, generation, 1, bytes(16), 0, 2),
            (b"C2F1", HELLO, 3, 0, generation, 1, b"m" * 16, 1, 2),
            (b"C2F1", HELLO, 3, 0, generation, 1, b"m" * 16, 0, 0),
            (b"C2F1", HELLO, 3, 0, generation, 1, b"m" * 16, 0, 4097),
        )
        for values in cases:
            with self.subTest(header=values):
                reader = _BoundedHelloReader(generation)
                header = struct.pack("!4sBBH16sQ16sII", *values)
                with self.assertRaises(ChannelHelloError):
                    reader.feed(header)

    def test_closed_hello_json_rejects_duplicates_unknown_and_nonfinite(self):
        cases = (
            b'{"version":1,"version":1}',
            b'{"unknown":1}',
            b'{"number":NaN}',
            b'{"version":1} trailing',
        )
        for payload in cases:
            with self.subTest(payload=payload):
                with self.assertRaises(ChannelHelloError):
                    _parse_hello(payload)

    def test_partial_eof_permanently_faults_reader(self):
        reader = _BoundedHelloReader()
        reader.feed(b"C2F1")
        with self.assertRaises(ChannelHelloError):
            reader.finish()
        with self.assertRaises(ChannelHelloError):
            reader.feed(b"more")

    def test_oversized_and_non_hello_frames_are_rejected(self):
        client = WorkerHelloClient(self.ingress, self.fixture.client,
                                   reassembly_capacity=self.capacity)
        server = WorkerHelloServer.from_tls(self.fixture.server,
                                            reassembly_capacity=self.capacity)
        with self.assertRaises(ChannelHelloError):
            server.accept_hello(client.hello_frame + b"x")
        self.assertFalse(self.fixture.server.is_live)


class CoordinatorHelloTests(unittest.TestCase):
    def setUp(self):
        self.fixture = coordinator_tls_tests.GatewayCoordinatorTLSOwnerTests()
        self.fixture.setUp()
        fx = self.fixture.fixture
        self.server_owner = self.fixture._new_server()
        self.egress = GatewayCoordinatorEgress.connect(
            authorizer=fx.adapter, policy_store=fx.policy_store,
            logical_host_certificate_pem=fx.fx.credentials["host"]["certificate"],
            gateway_id="gw-east", gateway_ca_pem=fx.gateway_ca,
            coordinator_private_key_pem=fx.fx.credentials["coordinator"]["key"])
        try:
            for _ in range(40):
                encrypted = self.egress.take_encrypted()
                if encrypted:
                    self.server_owner.feed_encrypted(encrypted)
                encrypted = self.server_owner.take_encrypted()
                if encrypted:
                    self.egress.feed_encrypted(encrypted)
                if self.egress.handshake_complete and self.server_owner.handshake_complete:
                    break
            else:
                self.fail("coordinator egress mutual TLS handshake did not complete")
        except BaseException:
            self.egress.close()
            self.server_owner.close()
            self.fixture.tearDown()
            raise
        self.capacity = MAX_BUNDLE_BYTES

    def tearDown(self):
        self.egress.close()
        self.server_owner.close()
        self.fixture.tearDown()

    def test_duplicate_coordinator_factory_never_closes_under_registry_lock(self):
        owner = self.server_owner
        CoordinatorHelloServer.from_tls(owner, reassembly_capacity=self.capacity)
        _assert_duplicate_factory_lock_order(self, owner, OwnedGatewayCoordinatorTLS,
            lambda: CoordinatorHelloServer.from_tls(owner,
                                                    reassembly_capacity=self.capacity))

    def test_coordinator_hello_matches_actual_c1_actor_and_tenant(self):
        client = CoordinatorHelloClient(self.egress,
                                        reassembly_capacity=self.capacity)
        server = CoordinatorHelloServer.from_tls(
            self.server_owner, self.server_owner.authenticated_channel,
            reassembly_capacity=self.capacity)
        ack = None
        for byte in client.hello_frame:
            result = server.feed_hello(bytes([byte]))
            if result is not None:
                ack = result
        self.assertIsNotNone(ack)
        decoder = None
        for byte in ack:
            result = client.feed_ack(bytes([byte]))
            if result is not None:
                decoder = result
        self.assertIsNotNone(decoder)
        channel = self.server_owner.authenticated_channel
        self.assertEqual(server.registration.identity[:4], (
            channel.actor_account_id, channel.actor_device_id,
            channel.coordinator_boot_id, channel.tenant_account_id))
        self.assertEqual(server.registration.server_connection_nonce,
                         channel.stream_generation)
        self.assertEqual(decoder._next_sequence, 2)
        server.registration.assert_live()
        with self.assertRaises(AttributeError):
            server.owner = object()
        with self.assertRaises(AttributeError):
            client.egress = object()
        try:
            copied = copy.copy(server.registration)
        except (AttributeError, TypeError):
            copied = None
        if copied is not None:
            with self.assertRaises(ChannelHelloError):
                copied.assert_live()

    def test_coordinator_hello_and_ack_traverse_actual_egress_and_tls_server(self):
        client = CoordinatorHelloClient(self.egress,
                                        reassembly_capacity=self.capacity)
        server = CoordinatorHelloServer.from_tls(
            self.server_owner, reassembly_capacity=self.capacity)
        self.assertEqual(client.send_hello(), len(client.hello_frame))
        self.server_owner.feed_encrypted(self.egress.take_encrypted())
        ack = server.read_hello()
        self.assertIsNotNone(ack)
        server.send_ack(ack)
        self.egress.feed_encrypted(self.server_owner.take_encrypted())
        self.assertIsNotNone(client.read_ack())
        self.assertEqual(client.initial_sequence, 2)

    def test_coordinator_tls_owner_cannot_be_claimed_twice(self):
        CoordinatorHelloServer.from_tls(
            self.server_owner, reassembly_capacity=self.capacity)
        with self.assertRaises(ChannelHelloError):
            CoordinatorHelloServer.from_tls(
                self.server_owner, reassembly_capacity=self.capacity)
        self.assertFalse(self.server_owner.is_live)


    def test_coordinator_egress_cannot_be_claimed_twice(self):
        CoordinatorHelloClient(self.egress, reassembly_capacity=self.capacity)
        with self.assertRaises(ChannelHelloError):
            CoordinatorHelloClient(self.egress, reassembly_capacity=self.capacity)

    def test_coordinator_hello_cannot_claim_another_tenant(self):
        client = CoordinatorHelloClient(self.egress,
                                        reassembly_capacity=self.capacity)
        value = json.loads(client.hello_frame[56:])
        value["tenant_account_id"] = "acct_wrong"
        payload = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
        forged = next(iter_fragments(payload, kind=HELLO, generation=client.generation,
                                     message_id=secrets.token_bytes(16)))
        server = CoordinatorHelloServer.from_tls(
            self.server_owner, reassembly_capacity=self.capacity)
        with self.assertRaises(ChannelHelloError):
            server.accept_hello(forged)
        self.assertFalse(self.server_owner.is_live)

    def test_coordinator_hello_cannot_claim_another_c1_actor(self):
        client = CoordinatorHelloClient(self.egress,
                                        reassembly_capacity=self.capacity)
        value = json.loads(client.hello_frame[56:])
        value["actor_device_id"] = "dev_" + "f" * 32
        payload = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
        forged = next(iter_fragments(payload, kind=HELLO, generation=client.generation,
                                     message_id=secrets.token_bytes(16)))
        server = CoordinatorHelloServer.from_tls(
            self.server_owner, reassembly_capacity=self.capacity)
        with self.assertRaises(ChannelHelloError):
            server.accept_hello(forged)
        self.assertFalse(self.server_owner.is_live)


def _assert_duplicate_factory_lock_order(testcase, owner, owner_type, factory):
    raw_lock = _hello_module._OWNER_LOCK
    registry_entered = threading.Event()
    allow_registry_entry = threading.Event()
    held = threading.Event()
    release = threading.Event()
    close_started = threading.Event()
    errors = []
    original_close = owner_type.close

    class ObservedRegistryLock:
        def __enter__(self):
            self.acquire()
            return self

        def __exit__(self, *_exc):
            self.release()

        def acquire(self, *args, **kwargs):
            acquired = raw_lock.acquire(*args, **kwargs)
            if acquired and threading.current_thread().name == "duplicate-factory":
                registry_entered.set()
                if not allow_registry_entry.wait(2):
                    errors.append(TimeoutError("registry entry release timed out"))
            return acquired

        def release(self):
            raw_lock.release()

    def hold_owner_lock():
        with owner._lock:
            held.set()
            if not release.wait(2):
                errors.append(TimeoutError("owner lock release timed out"))

    def observed_close(instance):
        if instance is owner:
            close_started.set()
        return original_close(instance)

    def duplicate_factory():
        try:
            factory()
        except ChannelHelloError:
            return
        except Exception as error:
            errors.append(error)
        else:
            errors.append(AssertionError("duplicate owner factory unexpectedly succeeded"))

    locker = threading.Thread(target=hold_owner_lock, daemon=True)
    with patch.object(owner_type, "close", observed_close), \
            patch.object(_hello_module, "_OWNER_LOCK", ObservedRegistryLock()):
        duplicate = threading.Thread(target=duplicate_factory, name="duplicate-factory",
                                     daemon=True)
        duplicate.start()
        try:
            testcase.assertTrue(registry_entered.wait(1), "duplicate path did not enter registry")
            locker.start()
            testcase.assertTrue(held.wait(1), "helper did not acquire owner lock")
            allow_registry_entry.set()
            testcase.assertTrue(close_started.wait(1), "duplicate path did not reach owner close")
            available = _hello_module._OWNER_LOCK.acquire(timeout=0.5)
            testcase.assertTrue(available,
                                "duplicate path held registry lock while waiting for owner close")
            if available:
                _hello_module._OWNER_LOCK.release()
        finally:
            allow_registry_entry.set()
            release.set()
            locker.join(1)
            duplicate.join(1)
    testcase.assertFalse(locker.is_alive())
    testcase.assertFalse(duplicate.is_alive())
    testcase.assertEqual(errors, [])

if __name__ == "__main__":
    unittest.main()
