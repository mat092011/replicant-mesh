"""Loopback tests for the metered TLS/HELLO/framed stream composition."""

from __future__ import annotations

import secrets
import select
import socket
import struct
import time
import unittest

from steamboat_connector.channel_hello import WorkerHelloClient, WorkerHelloServer
from steamboat_connector import channel_wire as wire
from steamboat_connector.channel_socket import ChannelSocket, ChannelSocketError
from steamboat_connector.channel_stream import (
    ChannelStream, ChannelStreamError, is_registered_worker_channel_stream,
)
from steamboat_connector.channel_wire import (
    CONTROL, DATA, MAX_BUNDLE_BYTES, MAX_CONTROL_BUNDLE_BYTES,
    MAX_FRAGMENT_BYTES, REQUEST, encode_bundle, iter_fragments,
)
from steamboat_connector.channel_writer import writer_reservation_overhead_bytes
from steamboat_security.channel_tls import OwnedWorkerTLS
from steamboat_security.gateway_ingress import GatewayWorkerIngress
from steamboat_security.gateway_tls import OwnedGatewayWorkerTLS
from steamboat_security.sessions import SessionBindings
from tests.connector.test_traffic_budget import _memory_budget, _policy
from tests.security import test_gateway_tls as gateway_tls_tests


WORKER_BOOT = "a" * 32
GATEWAY_BOOT = "b" * 32
DECODED_BYTES = MAX_BUNDLE_BYTES
CONTROL_BYTES = 8 * MAX_CONTROL_BUNDLE_BYTES
WRITER_BYTES = writer_reservation_overhead_bytes() + CONTROL_BYTES + MAX_BUNDLE_BYTES
TLS_BYTES = 4 * 64 * 1024


class LimitedSocket:
    """Explicit test wrapper around a real TCP socket, for partial/EAGAIN IO."""

    def __init__(self, sock, *, max_send=16_384, block_first_send=False):
        self.sock = sock
        self.max_send = max_send
        self.block_first_send = block_first_send
        self.send_calls = 0
        self.recv_calls = 0
        self.sent = bytearray()
        self.received = bytearray()

    def setblocking(self, value):
        self.sock.setblocking(value)

    def getblocking(self):
        return self.sock.getblocking()

    def send(self, data):
        self.send_calls += 1
        if self.block_first_send:
            self.block_first_send = False
            raise BlockingIOError()
        count = self.sock.send(data[:self.max_send])
        self.sent.extend(data[:count])
        return count

    def recv(self, size):
        self.recv_calls += 1
        result = self.sock.recv(size)
        self.received.extend(result)
        return result

    def close(self):
        self.sock.close()


class ChannelStreamTests(unittest.TestCase):
    def setUp(self):
        self.tls_fixture = gateway_tls_tests.GatewayServerTLSOwnerTests()
        self.tls_fixture.setUp()
        self.addCleanup(self.tls_fixture.tearDown)
        self.gateway_fixture = self.tls_fixture.fixture.fixture
        self.budget, self.store, self.meter_clock = _memory_budget(policy=_policy(
            global_total=20_000_000, role_total=5_000_000,
            send_rate=20_000_000, role_send_rate=5_000_000,
            cleanup_total=2_000_000, cleanup_rate=2_000_000,
            role_cleanup_rate=500_000))
        self.budget.bind_role("host", WORKER_BOOT)
        self.budget.bind_role("coordinator", GATEWAY_BOOT)

    def _new_unhandshaken_tls(self):
        # Replace the fixture's already-handshaken in-memory pair with fresh
        # genuine owners so the socket driver carries and meters the handshake.
        old_client, old_server = self.tls_fixture.client, self.tls_fixture.server
        old_client.close()
        old_server.close()
        f = self.tls_fixture.f
        client = OwnedWorkerTLS.connect(
            worker_certificate_pem=self.tls_fixture.fixture.worker_channel,
            worker_private_key_pem=self.tls_fixture.fixture.worker_channel_key,
            gateway_ca_pem=f.gateway_ca, endpoint_host="gateway.example.net",
            endpoint_port=443, clock=f.clock)
        server = OwnedGatewayWorkerTLS.accept(
            gateway_certificate_pem=f.gateway_pem, gateway_private_key_pem=f.gateway_key,
            cohort_ca_pem=f.gateway_ca, policy_store=f.policy_store,
            clock=f.clock, gateway_id="gw-east")
        self.tls_fixture.client = client
        self.tls_fixture.server = server
        return client, server

    @staticmethod
    def _connected_pair():
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        left = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        left.connect(listener.getsockname())
        right, _ = listener.accept()
        listener.close()
        return left, right

    def _bootstrap_pair(self, *, partial_send=False, capture_wire=False):
        client_tls, server_tls = self._new_unhandshaken_tls()
        client_sock, server_sock = self._connected_pair()
        if partial_send:
            client_transport = LimitedSocket(client_sock, max_send=97, block_first_send=True)
            server_transport = LimitedSocket(server_sock, max_send=113)
            test_socket = True
        elif capture_wire:
            client_transport = LimitedSocket(client_sock)
            server_transport = LimitedSocket(server_sock)
            test_socket = True
        else:
            client_transport, server_transport = client_sock, server_sock
            test_socket = False
        client_driver = ChannelSocket(client_transport, client_tls, self.budget,
                                     role="host", boot_id=WORKER_BOOT,
                                     test_socket=test_socket)
        server_driver = ChannelSocket(server_transport, server_tls, self.budget,
                                     role="coordinator", boot_id=GATEWAY_BOOT,
                                     test_socket=test_socket)
        self.addCleanup(client_driver.close)
        self.addCleanup(server_driver.close)
        self.addCleanup(client_sock.close)
        self.addCleanup(server_sock.close)
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            client_driver.pump()
            server_driver.pump()
            if (client_tls.handshake_complete and server_tls.handshake_complete
                    and not client_driver.pending_plaintext_bytes
                    and not client_driver.pending_ciphertext_bytes
                    and not client_tls.pending_encrypted_bytes
                    and not server_driver.pending_plaintext_bytes
                    and not server_driver.pending_ciphertext_bytes
                    and not server_tls.pending_encrypted_bytes):
                break
            select.select([client_sock, server_sock], [client_sock, server_sock], [], 0.001)
        self.assertTrue(client_tls.handshake_complete)
        self.assertTrue(server_tls.handshake_complete)
        ingress = GatewayWorkerIngress.from_tls(
            client_tls, verifier=self.gateway_fixture.verifier,
            sessions=SessionBindings(clock=self.gateway_fixture.clock), gateway_id="gw-east")
        hello_client = WorkerHelloClient(ingress, client_tls,
                                         reassembly_capacity=MAX_BUNDLE_BYTES)
        hello_server = WorkerHelloServer.from_tls(
            server_tls, reassembly_capacity=MAX_BUNDLE_BYTES)
        common = dict(writer_reservation_bytes=WRITER_BYTES,
                      decoded_byte_capacity=DECODED_BYTES,
                      tls_owner_reservation_bytes=TLS_BYTES)
        client = ChannelStream(client_driver, hello_client, **common)
        server = ChannelStream(server_driver, hello_server, **common)
        return client, server, client_sock, server_sock, client_tls, server_tls

    def _progress(self, client, server, predicate, timeout=5):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            client.pump()
            server.pump()
            if predicate():
                return
            # Let the OS deliver loopback packets without assuming a tight
            # fixed number of zero-wait pumps is sufficient on every host.
            time.sleep(0.001)
        self.fail("bounded socket stream did not make progress before its deadline")

    def test_metered_handshake_hello_ack_and_framed_bundle_share_one_stream(self):
        client, server, client_sock, server_sock, client_tls, server_tls = self._bootstrap_pair(
            capture_wire=True)
        self.addCleanup(client.close)
        self.addCleanup(server.close)
        self.addCleanup(client_sock.close)
        self.addCleanup(server_sock.close)
        self._progress(client, server,
                       lambda: client.transport_bootstrap_complete
                       and server.transport_bootstrap_complete)
        self.assertTrue(is_registered_worker_channel_stream(server))
        self.assertEqual(server.registration.identity[2],
                         server_tls.authenticated_channel.worker_boot_id)
        self.assertGreater(sum(client_tls.byte_counts), 0)
        self.assertGreater(sum(client._driver.socket_byte_counts), 0)
        self.assertGreater(sum(server._driver.socket_byte_counts), 0)
        self.assertEqual(client._driver.socket_byte_counts[0],
                         server._driver.socket_byte_counts[1])
        self.assertEqual(server._driver.socket_byte_counts[0],
                         client._driver.socket_byte_counts[1])
        client_wire = client._driver._socket
        server_wire = server._driver._socket
        self.assertEqual(bytes(client_wire.sent), bytes(server_wire.received))
        self.assertEqual(bytes(server_wire.sent), bytes(client_wire.received))
        self.assertEqual(len(client_wire.sent), client._driver.socket_byte_counts[0])
        self.assertEqual(len(server_wire.sent), server._driver.socket_byte_counts[0])
        total_endpoints = sum(client._driver.socket_byte_counts) + sum(server._driver.socket_byte_counts)
        self.assertEqual(self.store.state["global"]["observed"]["data"], total_endpoints)

        payload = encode_bundle("Describe", REQUEST, fragment_kind=DATA,
                                binding=b"b", protobuf=b"hello from worker")
        client.enqueue(kind=DATA, message_id=secrets.token_bytes(16), payload=payload)
        self._progress(client, server, lambda: len(server._incoming) == 1)
        decoded = server.pop_message()
        self.assertEqual(decoded.kind, DATA)
        self.assertEqual(decoded.payload, payload)
        self.assertEqual(client.writer.accounting.next_fragment_sequence, 3)
        self.assertEqual(server.decoder._next_sequence, 3)
        self.assertGreater(len(server.registration.server_connection_nonce), 0)

    def test_partial_send_eagain_and_control_preempts_data_between_fragments(self):
        client, server, client_sock, server_sock, _client_tls, _server_tls = self._bootstrap_pair(
            partial_send=True)
        self.addCleanup(client.close)
        self.addCleanup(server.close)
        self.addCleanup(client_sock.close)
        self.addCleanup(server_sock.close)
        self._progress(client, server,
                       lambda: client.transport_bootstrap_complete
                       and server.transport_bootstrap_complete)
        self.assertFalse(client._driver._socket.block_first_send)
        self.assertGreater(client._driver._socket.send_calls, 0)
        data_payload = encode_bundle("Describe", REQUEST, fragment_kind=DATA,
                                     binding=b"b", protobuf=b"d" * (MAX_FRAGMENT_BYTES * 2))
        control_payload = encode_bundle("CloseSession", REQUEST, fragment_kind=CONTROL,
                                        binding=b"b", protobuf=b"cleanup")
        client.enqueue(kind=DATA, message_id=secrets.token_bytes(16), payload=data_payload)
        client.enqueue(kind=CONTROL, message_id=secrets.token_bytes(16), payload=control_payload)
        start = client.writer.accounting.next_fragment_sequence
        client.pump()  # commits the control-priority fragment to the transport
        self.assertGreater(client.writer.accounting.in_flight_frame_bytes, 0)
        self.assertEqual(client.pending_outgoing_frame_bytes, client.writer.accounting.in_flight_frame_bytes)
        self._progress(client, server, lambda: len(server._incoming) >= 2, timeout=10)
        first, second = server.pop_message(), server.pop_message()
        self.assertEqual((first.kind, first.payload), (CONTROL, control_payload))
        self.assertEqual((second.kind, second.payload), (DATA, data_payload))
        self.assertGreater(client.writer.accounting.next_fragment_sequence, start + 2)
        self.assertGreater(self.store.state["global"]["observed"]["cleanup"], 0)
        self.assertTrue(client._driver.socket_byte_counts[0] > 0)
        self.assertEqual(client.writer.accounting.in_flight_frame_bytes, 0)
        self.assertEqual(client.pending_outgoing_frame_bytes, 0)

    def test_cleanup_mode_rejects_incoming_data_and_retires_capability(self):
        client, server, client_sock, server_sock, _client_tls, _server_tls = self._bootstrap_pair()
        self.addCleanup(client.close)
        self.addCleanup(server.close)
        self.addCleanup(client_sock.close)
        self.addCleanup(server_sock.close)
        self._progress(client, server,
                       lambda: client.transport_bootstrap_complete
                       and server.transport_bootstrap_complete)
        server.enter_incoming_cleanup_mode()
        payload = encode_bundle("Describe", REQUEST, fragment_kind=DATA,
                                binding=b"b", protobuf=b"not cleanup")
        client.enqueue(kind=DATA, message_id=secrets.token_bytes(16), payload=payload)
        with self.assertRaises(ChannelStreamError):
            self._progress(client, server, lambda: server.closed, timeout=5)
        self.assertTrue(server.closed)
        self.assertGreater(self.store.state["global"]["observed"]["cleanup"], 0)
        self.assertFalse(is_registered_worker_channel_stream(server))

    def test_cleanup_header_rejection_retires_before_another_socket_read(self):
        client, server, client_sock, server_sock, _client_tls, _server_tls = self._bootstrap_pair(
            capture_wire=True)
        self.addCleanup(client.close)
        self.addCleanup(server.close)
        self.addCleanup(client_sock.close)
        self.addCleanup(server_sock.close)
        self._progress(client, server,
                       lambda: client.transport_bootstrap_complete
                       and server.transport_bootstrap_complete)
        server.enter_incoming_cleanup_mode()
        client.enqueue(kind=DATA, message_id=secrets.token_bytes(16),
                       payload=encode_bundle("Describe", REQUEST, fragment_kind=DATA,
                                             binding=b"b", protobuf=b"x" * 40_000))
        with self.assertRaises(ChannelStreamError):
            self._progress(client, server, lambda: server.closed, timeout=5)
        recv_calls = server._driver._socket.recv_calls
        with self.assertRaises(ChannelStreamError):
            server.pump()
        self.assertEqual(server._driver._socket.recv_calls, recv_calls)
        self.assertTrue(server.closed)
        self.assertFalse(is_registered_worker_channel_stream(server))

    def test_cleanup_mode_switch_with_partial_non_end_data_retires(self):
        client, server, client_sock, server_sock, _client_tls, _server_tls = self._bootstrap_pair()
        self.addCleanup(client.close)
        self.addCleanup(server.close)
        self.addCleanup(client_sock.close)
        self.addCleanup(server_sock.close)
        self._progress(client, server,
                       lambda: client.transport_bootstrap_complete
                       and server.transport_bootstrap_complete)
        frames = iter_fragments(
            b"x" * 40_000, kind=DATA, generation=client._hello.generation,
            message_id=secrets.token_bytes(16), first_sequence=2)
        first = next(frames)
        self.assertEqual(struct.unpack_from(wire.FRAGMENT_FORMAT, first)[2], wire.START)
        self.assertEqual(list(server._decoder.feed(first)), [])
        with self.assertRaises(ChannelStreamError):
            server.enter_incoming_cleanup_mode()
        self.assertTrue(server.closed)
        self.assertFalse(is_registered_worker_channel_stream(server))

    def test_policy_replacement_before_queue_pop_or_enqueue_retires_stream(self):
        client, server, client_sock, server_sock, _client_tls, _server_tls = self._bootstrap_pair()
        self.addCleanup(client.close)
        self.addCleanup(server.close)
        self.addCleanup(client_sock.close)
        self.addCleanup(server_sock.close)
        self._progress(client, server,
                       lambda: client.transport_bootstrap_complete
                       and server.transport_bootstrap_complete)
        client.enqueue(kind=DATA, message_id=secrets.token_bytes(16),
                       payload=encode_bundle("Describe", REQUEST, fragment_kind=DATA,
                                             binding=b"b", protobuf=b"queued"))
        self._progress(client, server, lambda: server._incoming.pending_bytes > 0)
        payload = dict(self.gateway_fixture.payload)
        payload["revision"] = self.gateway_fixture.policy_store.current().revision + 1
        self.gateway_fixture.policy_store.install(
            gateway_tls_tests.ingress_tests.sign_channel_policy(
                payload, gateway_tls_tests.ingress_tests.delegation_tests.private_pem(
                    self.gateway_fixture.operator_key)))
        counts = server.socket_byte_counts
        with self.assertRaises(ChannelStreamError):
            server.pop_message()
        self.assertTrue(server.closed)
        self.assertEqual(server.socket_byte_counts, counts)
        with self.assertRaises(ChannelStreamError):
            server.enqueue(kind=DATA, message_id=secrets.token_bytes(16), payload=b"x")
        self.assertEqual(server.socket_byte_counts, counts)

    def test_exact_owner_and_post_ack_gating_are_enforced(self):
        client_tls, server_tls = self._new_unhandshaken_tls()
        left, right = self._connected_pair()
        client_driver = ChannelSocket(left, client_tls, self.budget,
                                     role="host", boot_id=WORKER_BOOT)
        server_driver = ChannelSocket(right, server_tls, self.budget,
                                     role="coordinator", boot_id=GATEWAY_BOOT)
        with self.assertRaises(TypeError):
            ChannelStream(client_driver, object(), writer_reservation_bytes=WRITER_BYTES,
                          decoded_byte_capacity=DECODED_BYTES,
                          tls_owner_reservation_bytes=TLS_BYTES)
        self.addCleanup(client_driver.close)
        self.addCleanup(server_driver.close)
        self.addCleanup(left.close)
        self.addCleanup(right.close)
        with self.assertRaises(ChannelSocketError):
            client_driver.offer_plaintext(b"no pre-handshake plaintext")

    def test_wrong_sequence_and_generation_retire_actual_stream(self):
        for fault in ("sequence", "generation"):
            with self.subTest(fault=fault):
                client, server, client_sock, server_sock, _client_tls, _server_tls = self._bootstrap_pair()
                self.addCleanup(client.close)
                self.addCleanup(server.close)
                self.addCleanup(client_sock.close)
                self.addCleanup(server_sock.close)
                self._progress(client, server,
                               lambda: client.transport_bootstrap_complete
                               and server.transport_bootstrap_complete)
                payload = encode_bundle("Describe", REQUEST, fragment_kind=DATA,
                                        binding=b"b", protobuf=b"bad sequence")
                generation = (b"x" * 16 if fault == "generation"
                              else client._hello.generation)
                sequence = 3 if fault == "sequence" else 2
                bad_frame = next(iter_fragments(
                    payload, kind=DATA, generation=generation,
                    message_id=secrets.token_bytes(16), first_sequence=sequence))
                client._driver.offer_plaintext(bad_frame, kind="data")
                with self.assertRaises(ChannelStreamError):
                    self._progress(client, server, lambda: server.closed)
                self.assertTrue(server.closed)
                self.assertFalse(is_registered_worker_channel_stream(server))

    def test_idle_ingress_expiry_retires_stream_without_socket_activity(self):
        client, server, client_sock, server_sock, _client_tls, _server_tls = self._bootstrap_pair()
        self.addCleanup(client.close)
        self.addCleanup(server.close)
        self.addCleanup(client_sock.close)
        self.addCleanup(server_sock.close)
        self._progress(client, server,
                       lambda: client.transport_bootstrap_complete
                       and server.transport_bootstrap_complete)
        counts_before_expiry = client.socket_byte_counts
        self.gateway_fixture.mono += 61.0
        self.gateway_fixture.wall += 61.0
        with self.assertRaises(ChannelStreamError):
            client.pump()
        self.assertTrue(client.closed)
        self.assertEqual(client.cleanup_status, "close_requested")
        self.assertEqual(client.socket_byte_counts, counts_before_expiry)

    def test_peer_eof_retires_socket_and_registered_capability(self):
        client, server, client_sock, server_sock, _client_tls, _server_tls = self._bootstrap_pair()
        self.addCleanup(client.close)
        self.addCleanup(server.close)
        self.addCleanup(client_sock.close)
        self.addCleanup(server_sock.close)
        self._progress(client, server,
                       lambda: client.transport_bootstrap_complete
                       and server.transport_bootstrap_complete)
        self.assertTrue(is_registered_worker_channel_stream(server))
        client_sock.close()
        with self.assertRaises(ChannelStreamError):
            self._progress(server, server, lambda: server.closed)
        self.assertTrue(server.closed)
        self.assertIsNotNone(server.failure)
        self.assertFalse(is_registered_worker_channel_stream(server))
