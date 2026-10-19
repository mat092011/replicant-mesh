"""Actual loopback TLS socket and aggregate-budget checks for the C2 pump."""

import socket
import time
import unittest

from steamboat_connector.channel_socket import ChannelSocket, ChannelSocketError
from tests.connector.test_traffic_budget import (
    _memory_budget, _policy, ALLOC, DOMAIN,
)
from steamboat_connector.traffic_budget import (
    MemoryTrafficStore, TrafficBudget, TrafficBudgetDenied, TrafficBudgetError,
)
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

    @staticmethod
    def _progress_state(endpoint, tls_owner):
        return {
            "socket_bytes": endpoint.socket_byte_counts,
            "pending_plaintext": endpoint.pending_plaintext_bytes,
            "pending_ciphertext": endpoint.pending_ciphertext_bytes,
            "pending_tls_output": tls_owner.pending_encrypted_bytes,
        }

    @staticmethod
    def _pump_until(endpoints, ready, *, timeout=1.0):
        """Yield between bounded nonblocking pumps until socket state advances."""
        if not 0 <= timeout <= 1.0:
            raise ValueError("socket test wait must be at most one second")
        deadline = time.monotonic() + timeout
        while True:
            for endpoint in endpoints:
                endpoint.pump()
            if ready():
                return True
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return False
            time.sleep(min(0.001, remaining))

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

        def getblocking(self):
            return self.sock.getblocking()

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

        client.set_incoming_cleanup_mode(True)
        server.set_incoming_cleanup_mode(True)
        before_cleanup_sent = client.socket_byte_counts[0]
        before_client_received = client.socket_byte_counts[1]
        before_server_sent = server.socket_byte_counts[0]
        before_server_received = server.socket_byte_counts[1]
        payload = b"c" * (16 * 1024)
        client.offer_plaintext(payload, kind="cleanup")
        received = None

        def take_cleanup():
            nonlocal received
            received = server.take_plaintext()
            return received is not None

        self.assertTrue(
            self._pump_until((client, server), take_cleanup),
            msg=(f"cleanup record did not arrive; client="
                 f"{self._progress_state(client, client_tls)!r}, server="
                 f"{self._progress_state(server, server_tls)!r}"))
        self.assertEqual(received, payload)
        sent = client.socket_byte_counts[0]
        self.assertEqual(sent - before_cleanup_sent, len(payload) + 22)
        self.assertEqual(client_tls.pending_encrypted_bytes, 0)
        state = store.state
        cleanup_wire_delta = ((sent - before_cleanup_sent)
                              + (client.socket_byte_counts[1] - before_client_received)
                              + (server.socket_byte_counts[0] - before_server_sent)
                              + (server.socket_byte_counts[1] - before_server_received))
        self.assertEqual(state["global"]["observed"]["cleanup"], cleanup_wire_delta)
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

    def test_post_io_clock_failure_preserves_known_send_and_full_reservation(self):
        class RollbackAfterSendSocket(self.PartialSocket):
            def __init__(self, sock, clock):
                super().__init__(sock)
                self.clock = clock

            def send(self, data):
                count = self.sock.send(data[:97])
                self.clock.mono -= 1.0
                self.clock.wall -= 1.0
                return count

        budget, store, clock = _memory_budget(policy=_policy(
            global_total=2_000_000, role_total=500_000,
            send_rate=1_000_000, role_send_rate=200_000,
            cleanup_total=10_000, cleanup_rate=100_000,
            role_cleanup_rate=30_000))
        budget.bind_role("coordinator", COORD_BOOT)
        client_socket, peer_socket = self._connected_pair()
        client_tls, unused_tls = self._owners()
        wrapper = RollbackAfterSendSocket(client_socket, clock)
        driver = ChannelSocket(wrapper, client_tls, budget,
                               role="coordinator", boot_id=COORD_BOOT,
                               test_socket=True)
        self.addCleanup(driver.close)
        self.addCleanup(unused_tls.close)
        self.addCleanup(peer_socket.close)
        with self.assertRaises(ChannelSocketError):
            driver.pump()
        self.assertGreater(driver.socket_byte_counts[0], 0)
        self.assertFalse(driver.io_outcome_uncertain)
        self.assertTrue(driver.metering_uncertain)
        peer_socket.settimeout(1)
        self.assertGreater(len(peer_socket.recv(256)), 0)
        row, = store.state["reservations"]
        self.assertEqual(row["status"], "open")
        self.assertGreater(row["max_bytes"], 0)
        self.assertIsNone(row["actual_bytes"])

    def test_post_io_clock_failure_preserves_known_receive_count(self):
        class RollbackAfterReceiveSocket(self.PartialSocket):
            def __init__(self, sock, clock):
                super().__init__(sock)
                self.clock = clock
                self.first_read = False

            def recv(self, size):
                result = self.sock.recv(size)
                self.clock.mono -= 1.0
                self.clock.wall -= 1.0
                return result

        budget, store, clock = _memory_budget(policy=_policy(
            global_total=2_000_000, role_total=500_000,
            send_rate=1_000_000, role_send_rate=200_000,
            cleanup_total=10_000, cleanup_rate=100_000,
            role_cleanup_rate=30_000))
        budget.bind_role("coordinator", COORD_BOOT)
        client_socket, peer_socket = self._connected_pair()
        client_tls, unused_tls = self._owners()
        peer_socket.sendall(b"known receive payload")
        wrapper = RollbackAfterReceiveSocket(client_socket, clock)
        driver = ChannelSocket(wrapper, client_tls, budget,
                               role="coordinator", boot_id=COORD_BOOT,
                               test_socket=True)
        self.addCleanup(driver.close)
        self.addCleanup(unused_tls.close)
        self.addCleanup(peer_socket.close)
        with self.assertRaises(ChannelSocketError):
            driver.pump()
        self.assertEqual(driver.socket_byte_counts[1], len(b"known receive payload"))
        self.assertFalse(driver.io_outcome_uncertain)
        self.assertTrue(driver.metering_uncertain)
        row, = store.state["reservations"]
        self.assertEqual(row["status"], "open")
        self.assertGreater(row["max_bytes"], 0)
        self.assertIsNone(row["actual_bytes"])

    def test_unknown_io_post_clock_failure_preserves_both_uncertainty_flags(self):
        class SendThenUnknownSocket(self.PartialSocket):
            def __init__(self, sock, clock):
                super().__init__(sock)
                self.clock = clock

            def send(self, data):
                self.sock.send(data[:97])
                self.clock.mono -= 1.0
                self.clock.wall -= 1.0
                raise OSError(5, "outcome unavailable")

        budget, store, clock = _memory_budget(policy=_policy(
            global_total=2_000_000, role_total=500_000,
            send_rate=1_000_000, role_send_rate=200_000,
            cleanup_total=10_000, cleanup_rate=100_000,
            role_cleanup_rate=30_000))
        budget.bind_role("coordinator", COORD_BOOT)
        client_socket, peer_socket = self._connected_pair()
        client_tls, unused_tls = self._owners()
        driver = ChannelSocket(SendThenUnknownSocket(client_socket, clock),
                               client_tls, budget, role="coordinator",
                               boot_id=COORD_BOOT, test_socket=True)
        self.addCleanup(driver.close)
        self.addCleanup(unused_tls.close)
        self.addCleanup(peer_socket.close)
        with self.assertRaises(ChannelSocketError):
            driver.pump()
        self.assertEqual(driver.socket_byte_counts, (0, 0))
        self.assertTrue(driver.io_outcome_uncertain)
        self.assertTrue(driver.metering_uncertain)
        peer_socket.settimeout(1)
        self.assertGreater(len(peer_socket.recv(256)), 0)
        row, = store.state["reservations"]
        self.assertEqual(row["status"], "open")
        self.assertIsNone(row["actual_bytes"])
        self.assertGreater(row["max_bytes"], 0)

    def test_invalid_ledger_state_faults_same_budget_owner(self):
        budget, store, _clock = _memory_budget(policy=_policy(
            global_total=2_000_000, role_total=500_000,
            send_rate=1_000_000, role_send_rate=200_000,
            cleanup_total=10_000, cleanup_rate=100_000,
            role_cleanup_rate=30_000))
        budget.bind_role("coordinator", COORD_BOOT)
        client_socket, peer_socket = self._connected_pair()
        client_tls, unused_tls = self._owners()
        wrapper = self.PartialSocket(client_socket)
        driver = ChannelSocket(wrapper, client_tls, budget,
                               role="coordinator", boot_id=COORD_BOOT,
                               test_socket=True)
        self.addCleanup(driver.close)
        self.addCleanup(unused_tls.close)
        self.addCleanup(peer_socket.close)
        store.state["version"] = 99
        with self.assertRaises(ChannelSocketError):
            driver.pump()
        self.assertTrue(budget._faulted)
        self.assertEqual(wrapper.send_calls, 0)
        self.assertEqual(wrapper.recv_calls, 0)
        store.state["version"] = 2
        with self.assertRaises(TrafficBudgetError):
            budget.run_socket_io(
                wrapper, client_tls, "coordinator", COORD_BOOT,
                "send", "data", b"must-not-send", test_socket=True)
        self.assertEqual(wrapper.send_calls, 0)
        self.assertEqual(wrapper.recv_calls, 0)

    def test_policy_revocation_during_durable_reservation_prevents_send(self):
        class RevokingStore(MemoryTrafficStore):
            callback = None

            def commit(self, state):
                super().commit(state)
                if self.callback is not None and state["reservations"]:
                    callback, self.callback = self.callback, None
                    callback()

        store = RevokingStore()
        budget, _unused, _clock = _memory_budget(store=store, policy=_policy(
            global_total=2_000_000, role_total=500_000,
            send_rate=1_000_000, role_send_rate=200_000,
            cleanup_total=10_000, cleanup_rate=100_000,
            role_cleanup_rate=30_000))
        budget.bind_role("coordinator", COORD_BOOT)
        budget.bind_role("host", HOST_BOOT)
        client_socket, server_socket = self._connected_pair()
        client_tls, server_tls = self._owners()
        server_wrapper = self.PartialSocket(server_socket)
        client = ChannelSocket(client_socket, client_tls, budget,
                              role="coordinator", boot_id=COORD_BOOT)
        server = ChannelSocket(server_wrapper, server_tls, budget,
                              role="host", boot_id=HOST_BOOT, test_socket=True)
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
        store.callback = lambda: self.owner_fixture.fixture.policy_store.install(encoded)
        before = server_wrapper.send_calls
        before_bytes = server.socket_byte_counts[0]
        before_charge = store.state["global"]["charged"]["data"]
        server.offer_plaintext(b"must stay unsent")
        with self.assertRaises(ChannelSocketError):
            server.pump()
        self.assertEqual(server_wrapper.send_calls, before)
        self.assertEqual(server.socket_byte_counts[0], before_bytes)
        self.assertEqual(store.state["global"]["charged"]["data"], before_charge)
        self.assertEqual(store.state["reservations"], [])
        self.assertEqual(store.state["global"]["observed"]["data"],
                         client.socket_byte_counts[0] + client.socket_byte_counts[1]
                         + server.socket_byte_counts[0] + server.socket_byte_counts[1])

    def test_receive_allowance_adapts_to_remaining_one_kibibyte_quota(self):
        policy = _policy(global_total=1024, role_total=0, send_rate=7000,
                         role_send_rate=2000, cleanup_total=300,
                         cleanup_rate=300, role_cleanup_rate=100)
        policy["reservations"]["coordinator"]["total_network_bytes"] = 1024
        budget, store, _clock = _memory_budget(policy=policy)
        budget.bind_role("coordinator", COORD_BOOT)
        client_socket, server_socket = self._connected_pair()
        client_tls, server_tls = self._owners()
        client_socket.setblocking(False)
        server_socket.setblocking(False)
        self.addCleanup(client_socket.close)
        self.addCleanup(server_socket.close)
        self.addCleanup(client_tls.close)
        self.addCleanup(server_tls.close)
        server_socket.send(b"r" * 2048)

        received = budget.run_socket_io(
            client_socket, client_tls, "coordinator", COORD_BOOT,
            "receive", "data", 16 * 1024)

        self.assertEqual(len(received), 1024)
        self.assertEqual(store.state["roles"]["coordinator"]["observed"]["data"], 1024)
        self.assertEqual(client_socket.recv(2048), b"r" * 1024)

    def test_shared_global_socket_quota_cannot_be_overspent_by_two_roles(self):
        policy = _policy(global_total=4, role_total=0, send_rate=7000,
                         role_send_rate=2000, cleanup_total=300,
                         cleanup_rate=300, role_cleanup_rate=100)
        policy["reservations"]["coordinator"]["total_network_bytes"] = 2
        policy["reservations"]["host"]["total_network_bytes"] = 2
        budget, store, _clock = _memory_budget(policy=policy)
        budget.bind_role("coordinator", COORD_BOOT)
        budget.bind_role("host", HOST_BOOT)
        client_socket, peer_socket = self._connected_pair()
        client_socket.setblocking(False)
        peer_socket.setblocking(False)
        self.addCleanup(client_socket.close)
        self.addCleanup(peer_socket.close)

        self.assertEqual(budget.run_socket_io(
            client_socket, self.owner_fixture.client, "coordinator", COORD_BOOT,
            "send", "data", b"AB"), 2)
        self.assertEqual(budget.run_socket_io(
            client_socket, self.owner_fixture.server, "host", HOST_BOOT,
            "send", "data", b"CD"), 2)
        with self.assertRaises(TrafficBudgetDenied) as denied:
            budget.run_socket_io(
                client_socket, self.owner_fixture.client, "coordinator", COORD_BOOT,
                "send", "data", b"E")

        self.assertEqual(denied.exception.reason, "quota")
        self.assertEqual(peer_socket.recv(8), b"ABCD")
        with self.assertRaises(BlockingIOError):
            peer_socket.recv(8)
        self.assertEqual(store.state["global"]["observed"]["data"], 4)
        self.assertEqual(store.state["roles"]["coordinator"]["observed"]["data"], 2)
        self.assertEqual(store.state["roles"]["host"]["observed"]["data"], 2)

    def test_reservation_commit_failure_prevents_any_socket_call(self):
        class FailOnceStore(MemoryTrafficStore):
            fail_next_commit = False

            def commit(self, state):
                if self.fail_next_commit:
                    self.fail_next_commit = False
                    raise OSError("reservation durability unknown")
                super().commit(state)

        store = FailOnceStore()
        budget, _unused, _clock = _memory_budget(store=store, policy=_policy(
            global_total=2_000_000, role_total=500_000,
            send_rate=1_000_000, role_send_rate=200_000,
            cleanup_total=10_000, cleanup_rate=100_000,
            role_cleanup_rate=30_000))
        budget.bind_role("coordinator", COORD_BOOT)
        client_socket, server_socket = self._connected_pair()
        client_tls, server_tls = self._owners()
        wrapper = self.PartialSocket(client_socket)
        driver = ChannelSocket(wrapper, client_tls, budget,
                               role="coordinator", boot_id=COORD_BOOT,
                               test_socket=True)
        peer = ChannelSocket(server_socket, server_tls, budget,
                             role="host", boot_id=HOST_BOOT)
        budget.bind_role("host", HOST_BOOT)
        self.addCleanup(driver.close)
        self.addCleanup(peer.close)
        for _ in range(80):
            driver.pump()
            peer.pump()
            if driver.tls_handshake_complete and peer.tls_handshake_complete:
                break
        before = wrapper.send_calls
        before_bytes = driver.socket_byte_counts[0]
        store.fail_next_commit = True
        driver.offer_plaintext(b"never reaches send")
        with self.assertRaises(ChannelSocketError):
            driver.pump()
        self.assertEqual(wrapper.send_calls, before)
        self.assertEqual(driver.socket_byte_counts[0], before_bytes)
        self.assertTrue(driver.metering_uncertain)
        self.assertFalse(driver.io_outcome_uncertain)

    def test_io_that_outlives_allowance_is_charged_and_retires_stream(self):
        class SlowSocket(self.PartialSocket):
            def __init__(self, sock, clock):
                super().__init__(sock)
                self.clock = clock

            def send(self, data):
                count = self.sock.send(data[:97])
                self.clock.advance(0.101)
                return count

        budget, store, clock = _memory_budget(policy=_policy(
            global_total=2_000_000, role_total=500_000,
            send_rate=1_000_000, role_send_rate=200_000,
            cleanup_total=10_000, cleanup_rate=100_000,
            role_cleanup_rate=30_000))
        budget.bind_role("coordinator", COORD_BOOT)
        client_socket, server_socket = self._connected_pair()
        client_tls, server_tls = self._owners()
        wrapper = SlowSocket(client_socket, clock)
        driver = ChannelSocket(wrapper, client_tls, budget,
                               role="coordinator", boot_id=COORD_BOOT,
                               test_socket=True)
        peer = ChannelSocket(server_socket, server_tls, budget,
                             role="host", boot_id=HOST_BOOT)
        budget.bind_role("host", HOST_BOOT)
        self.addCleanup(driver.close)
        self.addCleanup(peer.close)
        with self.assertRaises(ChannelSocketError):
            driver.pump()
        self.assertGreater(driver.socket_byte_counts[0], 0)
        self.assertTrue(driver.metering_uncertain)
        self.assertFalse(driver.io_outcome_uncertain)
        self.assertGreater(store.state["global"]["uncertain_bytes"]["data"], 0)
        self.assertEqual(store.state["global"]["uncertain_observed"]["data"],
                         driver.socket_byte_counts[0])

    def test_rate_backpressure_expires_after_thirty_monotonic_seconds(self):
        tiny, _store, clock = _memory_budget(policy=_policy(
            global_total=100_000, role_total=30_000, send_rate=3,
            role_send_rate=1, cleanup_total=300, cleanup_rate=300,
            role_cleanup_rate=100))
        tiny.bind_role("coordinator", COORD_BOOT)
        client_socket, server_socket = self._connected_pair()
        client_tls, _server_tls = self._owners()
        driver = ChannelSocket(client_socket, client_tls, tiny,
                               role="coordinator", boot_id=COORD_BOOT)
        self.addCleanup(driver.close)
        first = driver.pump()
        self.assertEqual(first["backpressure"], "rate")
        clock.advance(31)
        with self.assertRaises(ChannelSocketError):
            driver.pump()
        self.assertEqual(client_socket.fileno(), -1)
        server_socket.close()

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
            self.assertTrue(
                self._pump_until(
                    (server,),
                    lambda: (server.pending_plaintext_bytes == 0
                             and server.pending_ciphertext_bytes == 0
                             and server_tls.pending_encrypted_bytes == 0)),
                msg=(f"server could not flush inbound test record {index}; "
                     f"server={self._progress_state(server, server_tls)!r}"))
            received = None

            def take_record():
                nonlocal received
                received = client.take_plaintext()
                return received is not None

            self.assertTrue(
                self._pump_until((client,), take_record),
                msg=(f"client did not decode inbound test record {index}; "
                     f"client={self._progress_state(client, client_tls)!r}, "
                     f"server={self._progress_state(server, server_tls)!r}"))
            self.assertEqual(received, payload)

        server.offer_plaintext(b"control-readable")
        received = None

        def take_control():
            nonlocal received
            received = client.take_plaintext()
            return received is not None

        self.assertTrue(
            self._pump_until((server, client), take_control),
            msg=(f"control record did not arrive; client="
                 f"{self._progress_state(client, client_tls)!r}, server="
                 f"{self._progress_state(server, server_tls)!r}"))
        self.assertEqual(received, b"control-readable")

    def test_quota_denial_with_pending_ciphertext_retires_stream(self):
        tiny, store, _clock = _memory_budget(policy=_policy(
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
        with self.assertRaises(ChannelSocketError):
            client.pump()
        self.assertIsNotNone(client.failure)
        self.assertEqual(client_socket.fileno(), -1)
        self.assertEqual(client.socket_byte_counts[0], 1)
        self.assertEqual(store.state["global"]["observed"]["data"], 1)

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
