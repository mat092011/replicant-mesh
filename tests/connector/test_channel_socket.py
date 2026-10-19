"""Actual loopback TLS socket and aggregate-budget checks for the C2 pump."""

import socket
import unittest

from steamboat_connector.channel_socket import ChannelSocket, ChannelSocketError
from tests.connector.test_traffic_budget import (
    _memory_budget, _policy, ALLOC, DOMAIN,
)
from steamboat_connector.traffic_budget import MemoryTrafficStore, TrafficBudget
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
            self.send_calls = 0
            self.recv_calls = 0
            self.send_error = None
            self.recv_error = None
            self.block_next_send = False
            self.eagain_at_send_call = None
            self.eagain_send_hits = 0

        def setblocking(self, value):
            self.sock.setblocking(value)

        def send(self, data):
            self.send_calls += 1
            if self.block_next_send:
                self.block_next_send = False
                raise BlockingIOError()
            if self.send_calls == self.eagain_at_send_call:
                self.eagain_send_hits += 1
                raise BlockingIOError()
            if self.send_error is not None:
                raise self.send_error
            return self.sock.send(data[:97])

        def recv(self, size):
            self.recv_calls += 1
            if self.recv_error is not None:
                raise self.recv_error
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
            if client.tls_handshake_complete and server.tls_handshake_complete:
                break
        self.assertTrue(client.tls_handshake_complete)
        self.assertTrue(server.tls_handshake_complete)
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
            if client.tls_handshake_complete and server.tls_handshake_complete:
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

    def test_policy_revocation_before_flush_retires_queued_ciphertext(self):
        client_socket, server_socket = self._connected_pair()
        client_tls, server_tls = self._owners()
        server_wrapper = self.PartialSocket(server_socket)
        client = ChannelSocket(client_socket, client_tls, self.budget,
                              role="coordinator", boot_id=COORD_BOOT)
        server = ChannelSocket(server_wrapper, server_tls, self.budget,
                              role="host", boot_id=HOST_BOOT, test_socket=True)
        self.addCleanup(client.close)
        self.addCleanup(server.close)
        for _ in range(80):
            client.pump()
            server.pump()
            if client.tls_handshake_complete and server.tls_handshake_complete:
                break
        server_wrapper.block_next_send = True
        server.offer_plaintext(b"must not flush after revocation")
        server.pump()
        self.assertGreater(server.pending_ciphertext_bytes, 0)
        sent_before_revocation = server.socket_byte_counts[0]

        payload = dict(self.owner_fixture.fixture.policy_payload)
        payload["revision"] += 1
        self.owner_fixture.fixture.policy_store.install(
            gateway_fixture_tests.egress_tests.sign_channel_policy(
                payload, gateway_fixture_tests.egress_tests._private_pem(
                    self.owner_fixture.fixture.policy_key)))
        with self.assertRaises(ChannelSocketError):
            server.pump()
        self.assertEqual(server.socket_byte_counts[0], sent_before_revocation)
        self.assertEqual(server_socket.fileno(), -1)

    def test_partial_send_and_eagain_keep_tls_flight_and_refund_zero_io(self):
        client_socket, server_socket = self._connected_pair()
        client_tls, server_tls = self._owners()
        client_wrapper = self.PartialSocket(client_socket)
        server_wrapper = self.PartialSocket(server_socket)
        client = ChannelSocket(client_wrapper, client_tls,
                              self.budget, role="coordinator", boot_id=COORD_BOOT,
                              test_socket=True)
        server = ChannelSocket(server_wrapper, server_tls,
                              self.budget, role="host", boot_id=HOST_BOOT,
                              test_socket=True)
        self.addCleanup(client.close)
        self.addCleanup(server.close)
        for _ in range(800):
            client_sends, client_reads = client_wrapper.send_calls, client_wrapper.recv_calls
            server_sends, server_reads = server_wrapper.send_calls, server_wrapper.recv_calls
            client.pump()
            server.pump()
            self.assertLessEqual(client_wrapper.send_calls - client_sends, 4)
            self.assertLessEqual(client_wrapper.recv_calls - client_reads, 4)
            self.assertLessEqual(server_wrapper.send_calls - server_sends, 4)
            self.assertLessEqual(server_wrapper.recv_calls - server_reads, 4)
            if client.tls_handshake_complete and server.tls_handshake_complete:
                break
        self.assertTrue(client.tls_handshake_complete)
        self.assertTrue(server.tls_handshake_complete)
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

    def test_fourth_partial_send_eagain_counts_toward_pump_attempt_cap(self):
        client_socket, server_socket = self._connected_pair()
        client_tls, server_tls = self._owners()
        client_wrapper = self.PartialSocket(client_socket)
        server_wrapper = self.PartialSocket(server_socket)
        client = ChannelSocket(client_wrapper, client_tls, self.budget,
                              role="coordinator", boot_id=COORD_BOOT,
                              test_socket=True)
        server = ChannelSocket(server_wrapper, server_tls, self.budget,
                              role="host", boot_id=HOST_BOOT,
                              test_socket=True)
        self.addCleanup(client.close)
        self.addCleanup(server.close)
        for _ in range(800):
            client.pump()
            server.pump()
            if client.tls_handshake_complete and server.tls_handshake_complete:
                break
        self.assertTrue(client.tls_handshake_complete)
        self.assertTrue(server.tls_handshake_complete)

        before = server_wrapper.send_calls
        server_wrapper.eagain_at_send_call = before + 4
        server.offer_plaintext(b"x" * 1024)
        server.pump()

        self.assertEqual(server_wrapper.send_calls - before, 4)
        self.assertEqual(server_wrapper.eagain_send_hits, 1)
        self.assertGreater(server.pending_ciphertext_bytes, 0)

    def test_cleanup_ciphertext_keeps_cleanup_kind_after_data_quota_exhaustion(self):
        client_socket, server_socket = self._connected_pair()
        client_tls, server_tls = self._owners()
        budget, store, _clock = _memory_budget(policy=_policy(
            global_total=2_000_000, role_total=500_000,
            send_rate=1_000_000, role_send_rate=200_000,
            cleanup_total=100_000, cleanup_rate=100_000,
            role_cleanup_rate=30_000))
        budget.bind_role("coordinator", COORD_BOOT)
        budget.bind_role("host", HOST_BOOT)
        client = ChannelSocket(client_socket, client_tls, budget,
                              role="coordinator", boot_id=COORD_BOOT)
        server = ChannelSocket(server_socket, server_tls, budget,
                              role="host", boot_id=HOST_BOOT)
        self.addCleanup(client.close)
        self.addCleanup(server.close)
        for _ in range(80):
            client.pump()
            server.pump()
            if client.tls_handshake_complete and server.tls_handshake_complete:
                break

        # Tighten the shared data ceiling to exactly its already charged bytes;
        # cleanup traffic still has its separate bounded allowance.
        status = budget.status()
        current_total = sum(row["charged"]["data"]
                            for row in status["roles"].values())
        policy = _policy(global_total=current_total + 100_000,
                         role_total=max(status["roles"]["coordinator"]["charged"]["data"], 0),
                         send_rate=1_000_000, role_send_rate=200_000,
                         cleanup_total=100_000, cleanup_rate=100_000,
                         role_cleanup_rate=30_000)
        for role, row in status["roles"].items():
            policy["reservations"][role]["total_network_bytes"] = row["charged"]["data"]
        policy["reservations"]["host"]["total_network_bytes"] += 100_000
        budget.refresh_policy(policy)

        before_cleanup_sent = client.socket_byte_counts[0]
        payload = b"c" * (16 * 1024)
        client.offer_plaintext(payload, kind="cleanup")
        for _ in range(6):
            client.pump()
            server.pump()
        self.assertEqual(server.take_plaintext(), payload)
        sent = client.socket_byte_counts[0]
        self.assertEqual(sent - before_cleanup_sent, len(payload) + 22)
        self.assertEqual(client_tls.pending_encrypted_bytes, 0)
        state = store.state
        self.assertEqual(state["roles"]["coordinator"]["observed"]["cleanup"],
                         sent - before_cleanup_sent)
        self.assertEqual(
            state["roles"]["coordinator"]["charged"]["data"],
            policy["reservations"]["coordinator"]["total_network_bytes"])

    def test_unknown_io_outcomes_record_zero_observed_and_full_uncertainty(self):
        for direction in ("send", "receive"):
            with self.subTest(direction=direction):
                store_budget, store, _clock = _memory_budget(policy=_policy(
                    global_total=2_000_000, role_total=500_000,
                    send_rate=1_000_000, role_send_rate=200_000,
                    cleanup_total=10_000, cleanup_rate=100_000,
                    role_cleanup_rate=30_000))
                store_budget.bind_role("coordinator", COORD_BOOT)
                client_socket, server_socket = self._connected_pair()
                client_tls, server_tls = self._owners()
                io_socket = client_socket if direction == "send" else server_socket
                peer_socket = server_socket if direction == "send" else client_socket
                wrapped = self.PartialSocket(io_socket)
                wrapped.first_read = False
                if direction == "send":
                    wrapped.send_error = OSError(5, "outcome unavailable")
                else:
                    wrapped.recv_error = OSError(5, "outcome unavailable")
                tls_owner = client_tls if direction == "send" else server_tls
                unused_tls_owner = server_tls if direction == "send" else client_tls
                driver = ChannelSocket(wrapped, tls_owner, store_budget,
                                       role="coordinator", boot_id=COORD_BOOT,
                                       test_socket=True)
                self.addCleanup(driver.close)
                self.addCleanup(unused_tls_owner.close)
                peer_socket.close()
                with self.assertRaises(ChannelSocketError):
                    driver.pump()
                status = store_budget.status()
                self.assertTrue(driver.io_outcome_uncertain)
                self.assertEqual(driver.socket_byte_counts, (0, 0))
                self.assertEqual(status["global"]["uncertain_observed"]["data"], 0)
                self.assertEqual(status["global"]["observed"]["data"], 0)
                pending = store.state["reservations"]
                self.assertEqual(len(pending), 1)
                self.assertEqual(pending[0]["status"], "uncertain")
                if direction == "receive":
                    self.assertEqual(pending[0]["max_bytes"], 16 * 1024)
                else:
                    self.assertGreater(pending[0]["max_bytes"], 0)
                self.assertEqual(status["global"]["uncertain_bytes"]["data"],
                                 pending[0]["max_bytes"])

    def test_known_positive_io_counter_survives_meter_commit_failure(self):
        class FailOnceStore(MemoryTrafficStore):
            fail_next_commit = False

            def commit(self, state):
                if self.fail_next_commit:
                    self.fail_next_commit = False
                    raise OSError("simulated ledger commit failure")
                super().commit(state)

        class FailAfterSendSocket(self.PartialSocket):
            def __init__(self, sock, store):
                super().__init__(sock)
                self.store = store

            def send(self, data):
                count = self.sock.send(data[:97])
                if count:
                    self.store.fail_next_commit = True
                return count

        store = FailOnceStore()
        clock = self.meter_clock
        budget = TrafficBudget.for_tests(
            store=store, allocation_id=ALLOC, uid=1234, clock=clock.clock,
            clock_domain=DOMAIN, policy=_policy(global_total=2_000_000,
                role_total=500_000, send_rate=1_000_000, role_send_rate=200_000,
                cleanup_total=10_000, cleanup_rate=100_000, role_cleanup_rate=30_000))
        budget.bind_role("coordinator", COORD_BOOT)
        client_socket, server_socket = self._connected_pair()
        client_tls, unused_tls = self._owners()
        wrapper = FailAfterSendSocket(client_socket, store)
        driver = ChannelSocket(wrapper, client_tls, budget,
                               role="coordinator", boot_id=COORD_BOOT,
                               test_socket=True)
        self.addCleanup(driver.close)
        self.addCleanup(unused_tls.close)
        self.addCleanup(server_socket.close)
        with self.assertRaises(ChannelSocketError):
            driver.pump()
        self.assertGreater(driver.socket_byte_counts[0], 0)
        self.assertFalse(driver.io_outcome_uncertain)
        self.assertTrue(driver.metering_uncertain)

    def test_idle_handshake_deadline_retires_socket_before_io(self):
        client_socket, server_socket = self._connected_pair()
        client_tls, _server_tls = self._owners()
        driver = ChannelSocket(client_socket, client_tls, self.budget,
                               role="coordinator", boot_id=COORD_BOOT)
        self.addCleanup(driver.close)
        self.owner_fixture.fixture.time_source.advance(11.0)
        with self.assertRaises(ChannelSocketError):
            driver.pump()
        self.assertEqual(driver.socket_byte_counts, (0, 0))
        self.assertEqual(client_socket.fileno(), -1)
        server_socket.close()

    def test_blocked_writer_still_decodes_six_large_inbound_records(self):
        client_socket, server_socket = self._connected_pair()
        client_socket.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4096)
        client_tls, server_tls = self._owners()
        budget, _store, _clock = _memory_budget(policy=_policy(
            global_total=100_000_000, role_total=30_000_000,
            send_rate=100_000_000, role_send_rate=30_000_000,
            cleanup_total=100_000, cleanup_rate=100_000,
            role_cleanup_rate=30_000))
        budget.bind_role("coordinator", COORD_BOOT)
        budget.bind_role("host", HOST_BOOT)
        client = ChannelSocket(client_socket, client_tls, budget,
                              role="coordinator", boot_id=COORD_BOOT)
        server = ChannelSocket(server_socket, server_tls, budget,
                              role="host", boot_id=HOST_BOOT)
        self.addCleanup(client.close)
        self.addCleanup(server.close)
        for _ in range(80):
            client.pump()
            server.pump()
            if client.tls_handshake_complete and server.tls_handshake_complete:
                break

        # Leave the peer unread until the local TCP writer reaches EAGAIN.
        for index in range(800):
            if client.pending_plaintext_bytes == 0 and client.pending_ciphertext_bytes == 0:
                client.offer_plaintext(bytes((index % 251,)) * (16 * 1024))
            client.pump()
            if client.pending_ciphertext_bytes:
                break
        self.assertGreater(client.pending_ciphertext_bytes, 0,
                           "loopback TCP send buffer did not reach backpressure")

        for index in range(6):
            payload = bytes((200 + index,)) * (16 * 1024)
            server.offer_plaintext(payload)
            for _ in range(8):
                server.pump()
                if (server.pending_plaintext_bytes == 0
                        and server.pending_ciphertext_bytes == 0
                        and server_tls.pending_encrypted_bytes == 0):
                    break
            received = None
            for _ in range(8):
                client.pump()
                received = client.take_plaintext()
                if received is not None:
                    break
            self.assertEqual(received, payload)

        server.offer_plaintext(b"control-readable")
        for _ in range(8):
            server.pump()
            client.pump()
            received = client.take_plaintext()
            if received is not None:
                break
        self.assertEqual(received, b"control-readable")

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
        with self.assertRaises(TypeError):
            ChannelSocket(left, object(), self.budget,
                          role="coordinator", boot_id=COORD_BOOT)
        left.close()
        right.close()
        unconnected = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        with self.assertRaises(TypeError):
            ChannelSocket(unconnected, self.owner_fixture.client,
                          self.budget, role="coordinator", boot_id=COORD_BOOT)
        unconnected.close()


if __name__ == "__main__":
    unittest.main()
