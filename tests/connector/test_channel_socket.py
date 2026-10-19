"""Actual loopback TLS socket and aggregate-budget checks for the C2 pump."""

import socket
import unittest

from steamboat_connector.channel_socket import ChannelSocket, ChannelSocketError
from tests.connector.test_traffic_budget import _memory_budget, _policy
from tests.security import test_gateway_coordinator_tls as gateway_fixture_tests


HOST_BOOT = "a" * 32
COORD_BOOT = "b" * 32


class ChannelSocketTests(unittest.TestCase):
    def setUp(self):
        self.owner_fixture = gateway_fixture_tests.GatewayCoordinatorTLSOwnerTests()
        self.owner_fixture.setUp()
        self.addCleanup(self.owner_fixture.tearDown)
        self.budget, self.store, self.meter_clock = _memory_budget(
            policy=_policy(global_total=2_000_000, role_total=500_000,
                           send_rate=1_000_000, role_send_rate=200_000,
                           cleanup_total=10_000, cleanup_rate=100_000,
                           role_cleanup_rate=30_000))
        self.budget.bind_role("coordinator", COORD_BOOT)
        self.budget.bind_role("host", HOST_BOOT)

    def _connected_pair(self):
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect(listener.getsockname())
        server_socket, _ = listener.accept()
        listener.close()
        return client_socket, server_socket

    def _owners(self):
        return self.owner_fixture._new_client(), self.owner_fixture._new_server()

    class PartialSocket:
        def __init__(self, sock):
            self.sock = sock
            self.first_read = True

        def setblocking(self, value):
            self.sock.setblocking(value)

        def send(self, data):
            return self.sock.send(data[:97])

        def recv(self, size):
            if self.first_read:
                self.first_read = False
                raise BlockingIOError()
            return self.sock.recv(size)

        def close(self):
            self.sock.close()

    def test_real_tls_handshake_and_plaintext_are_fully_metered_at_both_ends(self):
        client_socket, server_socket = self._connected_pair()
        client_tls, server_tls = self._owners()
        client = ChannelSocket(client_socket, client_tls, self.budget,
                              role="coordinator", boot_id=COORD_BOOT)
        server = ChannelSocket(server_socket, server_tls, self.budget,
                              role="host", boot_id=HOST_BOOT)
        self.addCleanup(client.close)
        self.addCleanup(server.close)
        for _ in range(80):
            client.pump()
            server.pump()
            if client.ready_for_plaintext and server.ready_for_plaintext:
                break
        self.assertTrue(client.ready_for_plaintext)
        self.assertTrue(server.ready_for_plaintext)
        client.offer_plaintext(b"bounded TLS socket probe")
        received = None
        for _ in range(20):
            client.pump()
            server.pump()
            received = server.take_plaintext()
            if received is not None:
                break
        self.assertEqual(received, b"bounded TLS socket probe")
        client_sent, client_received = client.socket_byte_counts
        server_sent, server_received = server.socket_byte_counts
        self.assertEqual(client_sent, server_received)
        self.assertEqual(server_sent, client_received)
        self.assertGreater(client_sent + client_received, 0)
        state = self.store.state
        self.assertEqual(state["global"]["observed"]["data"],
                         client_sent + client_received + server_sent + server_received)

    def test_policy_or_socket_failure_retires_owner_stickily(self):
        client_socket, server_socket = self._connected_pair()
        client_tls, _server_tls = self._owners()
        driver = ChannelSocket(client_socket, client_tls, self.budget,
                               role="coordinator", boot_id=COORD_BOOT)
        self.addCleanup(driver.close)
        server_socket.close()
        with self.assertRaises(ChannelSocketError):
            for _ in range(5):
                driver.pump()
        self.assertIsNotNone(driver.failure)
        with self.assertRaises(ChannelSocketError):
            driver.pump()

    def test_policy_revocation_closes_actual_socket_and_tls_owner(self):
        client_socket, server_socket = self._connected_pair()
        client_tls, server_tls = self._owners()
        client = ChannelSocket(client_socket, client_tls, self.budget,
                              role="coordinator", boot_id=COORD_BOOT)
        server = ChannelSocket(server_socket, server_tls, self.budget,
                              role="host", boot_id=HOST_BOOT)
        self.addCleanup(client.close)
        self.addCleanup(server.close)
        for _ in range(80):
            client.pump()
            server.pump()
            if client.ready_for_plaintext and server.ready_for_plaintext:
                break
        payload = dict(self.owner_fixture.fixture.policy_payload)
        payload["revision"] += 1
        encoded = gateway_fixture_tests.egress_tests.sign_channel_policy(
            payload, gateway_fixture_tests.egress_tests._private_pem(
                self.owner_fixture.fixture.policy_key))
        self.owner_fixture.fixture.policy_store.install(encoded)
        with self.assertRaises(ChannelSocketError):
            server.pump()
        self.assertIsNotNone(server.failure)
        self.assertEqual(server_socket.fileno(), -1)

    def test_partial_send_and_eagain_keep_tls_flight_and_refund_zero_io(self):
        client_socket, server_socket = self._connected_pair()
        client_tls, server_tls = self._owners()
        client = ChannelSocket(self.PartialSocket(client_socket), client_tls,
                              self.budget, role="coordinator", boot_id=COORD_BOOT,
                              test_socket=True)
        server = ChannelSocket(self.PartialSocket(server_socket), server_tls,
                              self.budget, role="host", boot_id=HOST_BOOT,
                              test_socket=True)
        self.addCleanup(client.close)
        self.addCleanup(server.close)
        for _ in range(800):
            client.pump()
            server.pump()
            if client.ready_for_plaintext and server.ready_for_plaintext:
                break
        self.assertTrue(client.ready_for_plaintext)
        self.assertTrue(server.ready_for_plaintext)
        for _ in range(20):
            client.pump()
            server.pump()
            if (client.pending_ciphertext_bytes == 0
                    and server.pending_ciphertext_bytes == 0
                    and client.socket_byte_counts[0] == server.socket_byte_counts[1]
                    and server.socket_byte_counts[0] == client.socket_byte_counts[1]):
                break
        self.assertEqual(client.socket_byte_counts[0], server.socket_byte_counts[1])
        self.assertEqual(server.socket_byte_counts[0], client.socket_byte_counts[1])

    def test_quota_denial_is_backpressure_and_retains_ciphertext(self):
        tiny, _store, _clock = _memory_budget(policy=_policy(
            global_total=3, role_total=1, send_rate=1_000_000,
            role_send_rate=200_000, cleanup_total=300, cleanup_rate=100_000,
            role_cleanup_rate=30_000))
        tiny.bind_role("coordinator", COORD_BOOT)
        client_socket, server_socket = self._connected_pair()
        client_tls, server_tls = self._owners()
        client = ChannelSocket(client_socket, client_tls, tiny,
                              role="coordinator", boot_id=COORD_BOOT)
        server = ChannelSocket(server_socket, server_tls, tiny,
                              role="coordinator", boot_id=COORD_BOOT)
        self.addCleanup(client.close)
        self.addCleanup(server.close)
        state = client.pump()
        self.assertIsNotNone(state["backpressure"])
        self.assertIsNone(client.failure)
        self.assertGreater(client.pending_ciphertext_bytes, 0)
        self.assertLessEqual(client.pending_ciphertext_bytes, 16 * 1024)

    def test_exact_tls_owner_required(self):
        left, right = self._connected_pair()
        left.close()
        right.close()
        with self.assertRaises(TypeError):
            ChannelSocket(object(), object(), self.budget,
                          role="coordinator", boot_id=COORD_BOOT)


if __name__ == "__main__":
    unittest.main()
