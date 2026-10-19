"""Mutual TLS component tests for the bounded worker HELLO bootstrap."""

import json
import copy
import secrets
import struct
import unittest

from steamboat_connector.channel_hello import (
    ChannelHelloError, RegisteredWorker, WorkerHelloClient, WorkerHelloServer,
    _BoundedHelloReader, _parse_hello,
)
from steamboat_security.channel_tls import OwnedWorkerTLS
from steamboat_security.gateway_ingress import GatewayWorkerIngress
from steamboat_security.gateway_tls import OwnedGatewayWorkerTLS
from steamboat_security.sessions import SessionBindings
from steamboat_connector.channel_wire import (HELLO, MAX_BUNDLE_BYTES, DATA,
                                               encode_bundle, iter_fragments)
from tests.security import test_gateway_ingress as ingress_tests
from tests.security.test_gateway_tls import GatewayServerTLSOwnerTests


class ChannelHelloTests(unittest.TestCase):
    def setUp(self):
        # Reuse the repository's actual mutual-TLS MemoryBIO fixture pair.
        self.fixture = GatewayServerTLSOwnerTests()
        self.fixture.setUp()
        self.ingress = GatewayWorkerIngress.from_tls(
            self.fixture.client,
            verifier=self.fixture.fixture.fixture.verifier,
            sessions=SessionBindings(clock=self.fixture.fixture.fixture.clock),
            gateway_id="gw-east")
        self.capacity = MAX_BUNDLE_BYTES

    def tearDown(self):
        self.fixture.tearDown()

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
        decoder = None
        for byte in ack:
            result = client.feed_ack(bytes([byte]))
            if result is not None:
                decoder = result
        self.assertIsNotNone(decoder)
        self.assertEqual(server.registration.identity[2], self.fixture.server.authenticated_channel.worker_boot_id)
        self.assertEqual(server.registration.identity[3], self.ingress.stream_generation)
        self.assertEqual(server.registration.server_connection_nonce,
                         self.fixture.server.authenticated_channel.stream_generation)
        self.assertEqual(decoder.expected_generation, client.generation)
        self.assertEqual(server.decoder._next_sequence, 2)
        self.assertEqual(decoder._next_sequence, 2)
        # A normal inference bundle larger than the bootstrap limit is accepted
        # after sequence one has been consumed by HELLO/ACK.
        bundle = encode_bundle("Describe", 1, fragment_kind=DATA,
                               binding=b"b", protobuf=b"p" * 5000)
        frame = next(iter_fragments(bundle, kind=DATA, generation=client.generation,
                                    message_id=secrets.token_bytes(16), first_sequence=2))
        self.assertEqual(next(decoder.feed(frame)).payload, bundle)
        server.registration.assert_live()
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

    def test_replay_and_duplicate_hello_fault_connection(self):
        client = WorkerHelloClient(self.ingress, self.fixture.client,
                                   reassembly_capacity=self.capacity)
        server = WorkerHelloServer.from_tls(self.fixture.server,
                                            reassembly_capacity=self.capacity)
        server.accept_hello(client.hello_frame)
        with self.assertRaises(ChannelHelloError):
            server.accept_hello(client.hello_frame)
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
            server.accept_hello(forged)
        self.assertFalse(self.fixture.server.is_live)

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

    def test_same_worker_generation_cannot_be_replayed_on_another_tls_connection(self):
        client_bootstrap = WorkerHelloClient(
            self.ingress, self.fixture.client, reassembly_capacity=self.capacity)
        first_server = WorkerHelloServer.from_tls(
            self.fixture.server, reassembly_capacity=self.capacity)
        first_server.accept_hello(client_bootstrap.hello_frame)

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
                replay_server.accept_hello(client_bootstrap.hello_frame)
            self.assertFalse(second_server.is_live)
        finally:
            second_client.close()
            second_server.close()

    def test_bootstrap_header_table_rejects_kind_flags_sequence_and_generation(self):
        generation = b"g" * 16
        valid = (b"C2F1", HELLO, 3, 0, generation, 1, b"m" * 16, 0, 2)
        cases = (
            (DATA, 3, 1, generation),
            (HELLO, 1, 1, generation),
            (HELLO, 3, 2, generation),
            (HELLO, 3, 1, b"z" * 16),
        )
        for kind, flags, sequence, wire_generation in cases:
            with self.subTest(kind=kind, flags=flags, sequence=sequence):
                reader = _BoundedHelloReader(generation)
                header = struct.pack(
                    "!4sBBH16sQ16sII", valid[0], kind, flags, valid[3],
                    wire_generation, sequence, valid[6], valid[7], valid[8])
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


if __name__ == "__main__":
    unittest.main()
