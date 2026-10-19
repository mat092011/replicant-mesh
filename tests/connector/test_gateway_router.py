"""Focused registration and writer lifecycle tests for the gateway producer."""
import secrets
import unittest

from steamboat_security.sessions import SessionBindings
from steamboat_connector.gateway_router import GatewayRouter, GatewayRouterError
from steamboat_connector.channel_heartbeat import (
    HeartbeatError, PING, PONG, decode_heartbeat, encode_heartbeat,
)
from steamboat_connector import channel_wire as wire
from steamboat_connector.channel_hello import WorkerHelloClient, WorkerHelloServer
from steamboat_connector.channel_wire import MAX_BUNDLE_BYTES
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

    def test_registry_accepts_only_owner_minted_live_hello_and_removes_exact_slot(self):
        cap = self.server.registration
        identity = self.router.register_worker(cap)
        self.assertEqual(identity, cap.identity)
        with self.assertRaises(GatewayRouterError):
            self.router.register_worker(cap)
        self.assertTrue(self.router.remove_worker(cap))
        self.assertFalse(self.router.remove_worker(cap))
        with self.assertRaises(GatewayRouterError):
            self.router.register_worker(object())

    def test_writer_starts_after_hello_and_is_retired_on_exact_close(self):
        cap = self.server.registration
        self.router.register_worker(cap)
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
        self.router.register_worker(cap)
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
        self.router.register_worker(cap)
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
        self.router.register_worker(cap)
        self.fixture.server.close()
        self.assertTrue(self.router.remove_worker(cap))
        self.assertEqual(self.router._workers, {})


if __name__ == "__main__":
    unittest.main()

