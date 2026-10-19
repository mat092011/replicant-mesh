"""Stdlib checks for the bounded outbound one-shot CONNECT gate."""

import asyncio
from pathlib import Path
import socket
import sys
import time
import unittest


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from steamboat_runtime.protocol.secure_connector import (
    CONNECT_HEADER_LIMIT_BYTES,
    SecureConnector,
    SecureConnectorError,
    SecureConnectorPending,
)


class _Reservation:
    def __init__(self):
        self.releases = 0

    def release(self):
        self.releases += 1


class SecureConnectorTests(unittest.IsolatedAsyncioTestCase):
    async def _echo_server(self):
        accepted = []

        async def echo(reader, writer):
            accepted.append(True)
            try:
                while data := await reader.read(65536):
                    writer.write(data)
                    await writer.drain()
            finally:
                writer.close()
                await writer.wait_closed()

        server = await asyncio.start_server(echo, "127.0.0.1", 0)
        return server, server.sockets[0].getsockname()[1], accepted

    async def _gate(self, target_port, *, timeout=2.0):
        reservation = _Reservation()
        connector = SecureConnector(
            f"127.0.0.1:{target_port}", ("127.0.0.1",),
            pending_reservation=reservation,
            handshake_deadline=time.monotonic() + timeout,
            lifetime_seconds=30.0,
            on_lifetime_expired=lambda _connector: None)
        await connector.start()
        options = dict(connector.channel_options())
        token = options["grpc.http_connect_headers"].split(":", 1)[1]
        return connector, reservation, token, options

    def _assert_clean_closed_tunnel(self, connector):
        self.assertTrue(connector.closed_confirmed)
        self.assertTrue(connector.listener_closed_confirmed)
        self.assertTrue(connector.owned_sockets_closed)
        self.assertTrue(connector.pump_tasks_done)
        self.assertEqual(len(connector._pump_tasks), 2)
        self.assertEqual(set(connector._pump_results), set(connector._pump_tasks))
        self.assertTrue(set(connector._pump_results.values()).issubset({"eof", "reset"}))
        self.assertTrue(all(sock.fileno() == -1 for sock in connector._owned_sockets))
        self.assertIn(connector.closure_evidence, (
            "bidirectional peer EOF and owned descriptors closed",
            "peer reset and owned descriptors closed",
            "both pumps exited after coordinated shutdown; owned descriptors closed"))

    async def test_constructor_rejects_dns_and_non_allowlisted_addresses(self):
        reservation = _Reservation()
        common = {"pending_reservation": reservation,
                  "handshake_deadline": time.monotonic() + 1,
                  "lifetime_seconds": 30,
                  "on_lifetime_expired": lambda _connector: None}
        with self.assertRaises(ValueError):
            SecureConnector("worker.example:50051", ("127.0.0.1",), **common)
        with self.assertRaises(ValueError):
            SecureConnector("127.0.0.2:50051", ("127.0.0.1",), **common)

    async def test_close_immediately_after_start_releases_empty_gate_reservation(self):
        reservation = _Reservation()
        connector = SecureConnector(
            "127.0.0.1:50051", ("127.0.0.1",),
            pending_reservation=reservation,
            handshake_deadline=time.monotonic() + 2,
            lifetime_seconds=30,
            on_lifetime_expired=lambda _connector: None)
        await connector.start()
        local_port = connector.local_port
        await connector.close(grace=1)
        self.assertTrue(connector.closed_confirmed)
        self.assertEqual(reservation.releases, 1)
        with self.assertRaises(OSError):
            await asyncio.open_connection("127.0.0.1", local_port)

    @unittest.skipUnless(sys.platform.startswith("linux"),
                         "Linux selector EOF wakeup semantics are required")
    async def test_linux_selector_shutdown_wakes_readers_before_descriptor_close(self):
        reservation = _Reservation()
        connector = SecureConnector(
            "127.0.0.1:50051", ("127.0.0.1",),
            pending_reservation=reservation,
            handshake_deadline=time.monotonic() + 2,
            lifetime_seconds=30,
            on_lifetime_expired=lambda _connector: None)
        left, right = socket.socketpair()
        left.setblocking(False)
        right.setblocking(False)
        connector._owned_sockets.extend((left, right))
        loop = asyncio.get_running_loop()
        readers = (asyncio.create_task(loop.sock_recv(left, 32)),
                   asyncio.create_task(loop.sock_recv(right, 32)))
        connector._pump_tasks = readers
        try:
            await asyncio.sleep(0)
            self.assertTrue(all(not task.done() for task in readers),
                            "both recv owners must be registered before shutdown")
            connector._shutdown_owned_sockets()
            self.assertTrue(all(sock.fileno() >= 0 for sock in (left, right)),
                            "shutdown must retain descriptors while selector readers wake")
            result = await asyncio.wait_for(asyncio.gather(*readers), 0.5)
            self.assertEqual(result, [b"", b""],
                             "selector readers must observe EOF from shutdown")
            self.assertTrue(all(sock.fileno() >= 0 for sock in (left, right)),
                            "readers finish before the owned descriptors are closed")
            await connector.close(grace=1)
            self.assertTrue(connector.closed_confirmed)
            self.assertTrue(connector.owned_sockets_closed)
            self.assertEqual(reservation.releases, 1)
        finally:
            connector._shutdown_owned_sockets()
            pending = tuple(task for task in readers if not task.done())
            if pending:
                await asyncio.wait_for(asyncio.gather(*pending, return_exceptions=True), 1)
            for sock in (left, right):
                if sock.fileno() != -1:
                    sock.close()

    @unittest.skipUnless(sys.platform.startswith("linux"),
                         "Linux selector EOF wakeup semantics are required")
    async def test_linux_layered_half_close_then_owned_shutdown_joins_pumps_before_close(self):
        reservation = _Reservation()
        connector = SecureConnector(
            "127.0.0.1:50051", ("127.0.0.1",),
            pending_reservation=reservation,
            handshake_deadline=time.monotonic() + 2,
            lifetime_seconds=30,
            on_lifetime_expired=lambda _connector: None)
        client, gate_client = socket.socketpair()
        gate_upstream, backend = socket.socketpair()
        sockets = (client, gate_client, gate_upstream, backend)
        for sock in sockets:
            sock.setblocking(False)
        connector._owned_sockets.extend((gate_client, gate_upstream))
        pumps = (asyncio.create_task(connector._pump(gate_client, gate_upstream)),
                 asyncio.create_task(connector._pump(gate_upstream, gate_client)))
        connector._pump_tasks = pumps
        loop = asyncio.get_running_loop()
        try:
            await asyncio.sleep(0)
            await loop.sock_sendall(client, b"client-request")
            self.assertEqual(await asyncio.wait_for(loop.sock_recv(backend, 64), 0.5),
                             b"client-request")
            await loop.sock_sendall(backend, b"backend-response")
            self.assertEqual(await asyncio.wait_for(loop.sock_recv(client, 64), 0.5),
                             b"backend-response")

            # The client half-closes first. Its pump forwards EOF to the
            # backend, which keeps its response half open and leaves the
            # opposite-direction gate reader registered.
            client.shutdown(socket.SHUT_WR)
            self.assertEqual(await asyncio.wait_for(loop.sock_recv(backend, 1), 0.5), b"")
            await asyncio.sleep(0)
            self.assertTrue(pumps[0].done())
            self.assertFalse(pumps[1].done())
            self.assertTrue(all(sock.fileno() >= 0
                                for sock in (gate_client, gate_upstream)))

            closing = asyncio.create_task(connector.close(grace=1))
            await asyncio.sleep(0)
            self.assertTrue(all(sock.fileno() >= 0
                                for sock in (gate_client, gate_upstream)),
                            "shutdown must wake the remaining selector reader before close")
            await asyncio.wait_for(closing, 0.8)
            self.assertTrue(all(task.done() for task in pumps))
            self.assertTrue(all(sock.fileno() == -1
                                for sock in (gate_client, gate_upstream)))
            self.assertTrue(connector.closed_confirmed)
            self.assertEqual(reservation.releases, 1)
        finally:
            connector._shutdown_owned_sockets()
            pending = tuple(task for task in pumps if not task.done())
            if pending:
                await asyncio.wait_for(asyncio.gather(*pending, return_exceptions=True), 1)
            for sock in sockets:
                if sock.fileno() != -1:
                    sock.close()

    async def test_fixed_native_proxy_options_and_single_tunnel_forward_bytes(self):
        server, target_port, accepted = await self._echo_server()
        connector, reservation, token, options = await self._gate(target_port)
        reader = writer = None
        try:
            self.assertEqual(options["grpc.enable_retries"], 0)
            self.assertEqual(options["grpc.use_local_subchannel_pool"], 1)
            self.assertEqual(options["grpc.http_proxy"], "")
            self.assertEqual(options["grpc.enable_http_proxy"], 1)
            self.assertEqual(options["grpc.address_http_proxy_enabled_addresses"],
                             "127.0.0.1/32")
            self.assertEqual(options["grpc.max_connections_per_subchannel_cap"], 1)
            self.assertNotIn("grpc.ssl_target_name_override", options)
            reader, writer = await asyncio.open_connection("127.0.0.1", connector.local_port)
            writer.write((f"CONNECT 127.0.0.1:{target_port} HTTP/1.1\r\n"
                          f"Host: 127.0.0.1:{target_port}\r\n"
                          f"Proxy-Connection: Keep-Alive\r\n"
                          f"steamboat-proxy-token: {token}\r\n\r\n").encode("ascii"))
            await writer.drain()
            self.assertTrue((await asyncio.wait_for(
                reader.readuntil(b"\r\n\r\n"), 1)).startswith(b"HTTP/1.0 200"))
            await connector.confirm_ready()
            with self.assertRaises(OSError):
                await asyncio.open_connection("127.0.0.1", connector.local_port)
            self.assertEqual((connector.accepted_count, connector.upstream_dial_count),
                             (1, 1), "the gate must retire its listener after its first accept")
            writer.write(b"opaque-tls-bytes")
            await writer.drain()
            self.assertEqual(await asyncio.wait_for(
                reader.readexactly(len(b"opaque-tls-bytes")), 1), b"opaque-tls-bytes")
            writer.close()
            await writer.wait_closed()
            await connector.close(grace=1)
            self._assert_clean_closed_tunnel(connector)
            self.assertEqual((connector.accepted_count, connector.upstream_dial_count), (1, 1))
            self.assertEqual(reservation.releases, 1,
                "the gate must release its caller's exact pending token once")
            self.assertEqual(len(accepted), 1)
        finally:
            if writer is not None and not writer.is_closing():
                writer.close()
                await writer.wait_closed()
            await connector.close(grace=1)
            server.close()
            await server.wait_closed()

    async def test_channel_close_waits_for_stalled_opposite_pump_before_descriptor_close(self):
        backend_eof = asyncio.Event()
        keep_backend_open = asyncio.Event()

        async def backend(reader, writer):
            try:
                body = await reader.read()
                self.assertEqual(body, b"request-before-half-close")
                backend_eof.set()
                writer.write(b"response-after-half-close")
                await writer.drain()
                await keep_backend_open.wait()
            finally:
                writer.close()
                await writer.wait_closed()

        server = await asyncio.start_server(backend, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        connector, reservation, token, _options = await self._gate(port)
        reader = writer = None
        try:
            reader, writer = await asyncio.open_connection(
                "127.0.0.1", connector.local_port)
            writer.write((f"CONNECT 127.0.0.1:{port} HTTP/1.1\r\n"
                          f"steamboat-proxy-token: {token}\r\n\r\n").encode("ascii"))
            await writer.drain()
            self.assertTrue((await asyncio.wait_for(
                reader.readuntil(b"\r\n\r\n"), 1)).startswith(b"HTTP/1.0 200"))
            await connector.confirm_ready()

            writer.write(b"request-before-half-close")
            await writer.drain()
            writer.write_eof()
            response = await asyncio.wait_for(
                reader.readexactly(len(b"response-after-half-close")), 1)
            self.assertEqual(response, b"response-after-half-close")
            await asyncio.wait_for(backend_eof.wait(), 1)

            # The client has half-closed its write side while the backend
            # deliberately keeps its write half open. One pump must remain
            # owned until connector close shuts the actual descriptors.
            await asyncio.sleep(0)
            self.assertFalse(connector.closed_confirmed)
            self.assertFalse(connector.pump_tasks_done)
            self.assertFalse(connector.owned_sockets_closed)
            self.assertTrue(any(task.done() for task in connector._pump_tasks))
            self.assertTrue(any(not task.done() for task in connector._pump_tasks))
            self.assertEqual(reservation.releases, 1,
                "TLS readiness already released the dynamic pending token")

            if sys.platform.startswith("linux"):
                await connector.close(grace=1)
                self._assert_clean_closed_tunnel(connector)
            else:
                # Windows selector/proactor behavior is not evidence for the
                # LinuxSelector wakeup contract. If local shutdown cannot
                # confirm the reader exit here, the connector must retain its
                # descriptors and report pending cleanup until the peer closes.
                with self.assertRaises(SecureConnectorPending):
                    await connector.close(grace=0.05)
                self.assertFalse(connector.closed_confirmed)
                self.assertFalse(connector.owned_sockets_closed)
                self.assertFalse(connector.pump_tasks_done)
            self.assertEqual(reservation.releases, 1)
        finally:
            keep_backend_open.set()
            if writer is not None and not writer.is_closing():
                writer.close()
                await writer.wait_closed()
            await connector.close(grace=1)
            server.close()
            await server.wait_closed()

    async def test_upstream_first_half_close_still_forwards_later_client_bytes(self):
        received = asyncio.Event()
        received_bytes = []

        async def backend(reader, writer):
            try:
                writer.write(b"server-first-response")
                await writer.drain()
                writer.write_eof()
                received_bytes.append(await reader.read())
                received.set()
            finally:
                writer.close()
                await writer.wait_closed()

        server = await asyncio.start_server(backend, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        connector, reservation, token, _options = await self._gate(port)
        reader = writer = None
        try:
            reader, writer = await asyncio.open_connection(
                "127.0.0.1", connector.local_port)
            writer.write((f"CONNECT 127.0.0.1:{port} HTTP/1.1\r\n"
                          f"steamboat-proxy-token: {token}\r\n\r\n").encode("ascii"))
            await writer.drain()
            self.assertTrue((await asyncio.wait_for(
                reader.readuntil(b"\r\n\r\n"), 1)).startswith(b"HTTP/1.0 200"))
            await connector.confirm_ready()

            self.assertEqual(await asyncio.wait_for(
                reader.readexactly(len(b"server-first-response")), 1),
                b"server-first-response")
            self.assertEqual(await asyncio.wait_for(reader.read(1), 1), b"")
            writer.write(b"client-after-upstream-half-close")
            await writer.drain()
            writer.write_eof()
            await asyncio.wait_for(received.wait(), 1)
            await asyncio.wait_for(connector._closed_event.wait(), 1)
            await connector.close(grace=1)

            self.assertEqual(received_bytes, [b"client-after-upstream-half-close"])
            self.assertTrue(connector.closed_confirmed)
            self.assertTrue(connector.owned_sockets_closed)
            self.assertTrue(connector.pump_tasks_done)
            self.assertTrue(connector.listener_closed_confirmed)
            self.assertEqual(connector.closure_evidence,
                "bidirectional peer EOF and owned descriptors closed")
            self.assertEqual(reservation.releases, 1)
        finally:
            if writer is not None and not writer.is_closing():
                writer.close()
                await writer.wait_closed()
            await connector.close(grace=1)
            server.close()
            await server.wait_closed()

    async def test_readiness_confirmation_rechecks_tunnel_after_await(self):
        server, target_port, _accepted = await self._echo_server()
        connector, reservation, token, _options = await self._gate(target_port)
        reader, writer = await asyncio.open_connection("127.0.0.1", connector.local_port)
        try:
            writer.write((f"CONNECT 127.0.0.1:{target_port} HTTP/1.1\r\n"
                          f"steamboat-proxy-token: {token}\r\n\r\n").encode("ascii"))
            await writer.drain()
            self.assertTrue((await asyncio.wait_for(
                reader.readuntil(b"\r\n\r\n"), 1)).startswith(b"HTTP/1.0 200"))
            stop_timer = connector._stop_timer

            async def stop_timer_then_drop_peer(name, *, grace=None):
                await stop_timer(name, grace=grace)
                writer.close()
                await writer.wait_closed()
                await asyncio.wait_for(connector._closed_event.wait(), 1)

            connector._stop_timer = stop_timer_then_drop_peer
            with self.assertRaisesRegex(SecureConnectorError, "readiness"):
                await connector.confirm_ready()
            self.assertEqual(reservation.releases, 0,
                "a vanished tunnel must retain pending ownership until close confirms EOF")
            connector._stop_timer = stop_timer
            await connector.close(grace=1)
            self.assertEqual(reservation.releases, 1)
        finally:
            if not writer.is_closing():
                writer.close()
                await writer.wait_closed()
            await connector.close(grace=1)
            server.close()
            await server.wait_closed()

    async def test_bad_connect_requests_never_dial_the_fixed_peer(self):
        server, target_port, accepted = await self._echo_server()
        target = f"127.0.0.1:{target_port}"
        cases = (
            (f"GET {target} HTTP/1.1\r\nsteamboat-proxy-token: {{token}}\r\n\r\n", "method"),
            (f"CONNECT 127.0.0.1:1 HTTP/1.1\r\nsteamboat-proxy-token: {{token}}\r\n\r\n", "target"),
            (f"CONNECT {target} HTTP/2\r\nsteamboat-proxy-token: {{token}}\r\n\r\n", "version"),
            (f"CONNECT {target} HTTP/1.1\r\nsteamboat-proxy-token: {{token}}\r\nsteamboat-proxy-token: {{token}}\r\n\r\n", "duplicate"),
            (f"CONNECT {target} HTTP/1.1\r\nContent-Length: 0\r\nsteamboat-proxy-token: {{token}}\r\n\r\n", "body"),
            (f"CONNECT {target} HTTP/1.1\r\nTransfer-Encoding: chunked\r\nsteamboat-proxy-token: {{token}}\r\n\r\n", "body"),
            (f"CONNECT {target} HTTP/1.1\r\nsteamboat-proxy-token: {{token}}\r\n\r\nBODY", "early body"),
            (f"CONNECT {target} HTTP/1.1\r\nsteamboat-proxy-token: invalid\r\n\r\n", "token"),
            (f"CONNECT {target} HTTP/1.1\r\nUser-Agent: \x7f\r\nsteamboat-proxy-token: {{token}}\r\n\r\n", "control byte"),
            (f"CONNECT {target} HTTP/1.1\r\nX-Unknown: no\r\nsteamboat-proxy-token: {{token}}\r\n\r\n", "header"),
        )
        try:
            for template, label in cases:
                with self.subTest(case=label):
                    connector, _reservation, token, _options = await self._gate(target_port)
                    reader = writer = None
                    try:
                        reader, writer = await asyncio.open_connection(
                            "127.0.0.1", connector.local_port)
                        request = template.replace("{token}", token)
                        writer.write(request.encode("ascii"))
                        await writer.drain()
                        response = await asyncio.wait_for(
                            reader.readuntil(b"\r\n\r\n"), 1)
                        self.assertTrue(response.startswith(b"HTTP/1.0 400"))
                        await asyncio.wait_for(connector._closed_event.wait(), 1)
                        self.assertEqual(connector.upstream_dial_count, 0)
                        self.assertEqual(accepted, [])
                        await connector.close(grace=1)
                    finally:
                        if writer is not None and not writer.is_closing():
                            writer.close()
                            await writer.wait_closed()
        finally:
            server.close()
            await server.wait_closed()

    async def test_oversized_and_partial_headers_are_bounded_and_do_not_dial(self):
        server, target_port, accepted = await self._echo_server()
        try:
            connector, _reservation, token, _options = await self._gate(target_port)
            reader, writer = await asyncio.open_connection("127.0.0.1", connector.local_port)
            writer.write((f"CONNECT 127.0.0.1:{target_port} HTTP/1.1\r\n"
                          f"X-Pad: {'x' * (CONNECT_HEADER_LIMIT_BYTES + 32)}\r\n").encode("ascii"))
            await writer.drain()
            response = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 1)
            self.assertTrue(response.startswith(b"HTTP/1.0 400"))
            await asyncio.wait_for(connector._closed_event.wait(), 1)
            self.assertEqual(connector.upstream_dial_count, 0)
            await connector.close(grace=1)
            writer.close()
            try:
                await writer.wait_closed()
            except OSError:
                # The gate rejects the malformed CONNECT and closes the socket;
                # Windows can report that close as a reset when unread input remains.
                pass

            connector, _reservation, _token, _options = await self._gate(target_port,
                timeout=0.08)
            reader, writer = await asyncio.open_connection("127.0.0.1", connector.local_port)
            writer.write(b"CONNECT 127.0.0.1:")
            await writer.drain()
            try:
                response = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 1)
            except (asyncio.IncompleteReadError, ConnectionResetError):
                response = b""
            self.assertTrue(not response or response.startswith(b"HTTP/1.0 400"))
            await asyncio.wait_for(connector._closed_event.wait(), 1)
            self.assertEqual(connector.upstream_dial_count, 0)
            self.assertEqual(accepted, [])
            await connector.close(grace=1)
            writer.close()
            try:
                await writer.wait_closed()
            except OSError:
                pass
        finally:
            server.close()
            await server.wait_closed()

    async def test_channel_lifetime_timer_invokes_owner_close_callback(self):
        server, target_port, _accepted = await self._echo_server()
        reservation = _Reservation()
        state = {}

        async def close_owner(_connector):
            state["expired"] = True
            writer = state["writer"]
            writer.close()
            await writer.wait_closed()

        connector = SecureConnector(
            f"127.0.0.1:{target_port}", ("127.0.0.1",),
            pending_reservation=reservation,
            handshake_deadline=time.monotonic() + 2,
            lifetime_seconds=0.08,
            on_lifetime_expired=close_owner)
        await connector.start()
        token = dict(connector.channel_options())["grpc.http_connect_headers"].split(":", 1)[1]
        reader, writer = await asyncio.open_connection("127.0.0.1", connector.local_port)
        state["writer"] = writer
        try:
            writer.write((f"CONNECT 127.0.0.1:{target_port} HTTP/1.1\r\n"
                          f"steamboat-proxy-token: {token}\r\n\r\n").encode("ascii"))
            await writer.drain()
            self.assertTrue((await asyncio.wait_for(
                reader.readuntil(b"\r\n\r\n"), 1)).startswith(b"HTTP/1.0 200"))
            await connector.confirm_ready()
            await asyncio.wait_for(connector._closed_event.wait(), 1)
            self.assertTrue(state["expired"])
            await connector.close(grace=1)
            self.assertTrue(connector.closed_confirmed)
            self.assertEqual(reservation.releases, 1)
        finally:
            if not writer.is_closing():
                writer.close()
                await writer.wait_closed()
            await connector.close(grace=1)
            server.close()
            await server.wait_closed()

    async def test_readiness_confirmation_rechecks_absolute_deadline_after_timer_await(self):
        server, target_port, _accepted = await self._echo_server()
        connector, reservation, token, _options = await self._gate(
            target_port, timeout=1.2)
        reader, writer = await asyncio.open_connection("127.0.0.1", connector.local_port)
        original_stop_timer = connector._stop_timer
        try:
            writer.write((f"CONNECT 127.0.0.1:{target_port} HTTP/1.1\r\n"
                          f"steamboat-proxy-token: {token}\r\n\r\n").encode("ascii"))
            await writer.drain()
            self.assertTrue((await asyncio.wait_for(
                reader.readuntil(b"\r\n\r\n"), 1)).startswith(b"HTTP/1.0 200"))
            remaining = connector.handshake_deadline - time.monotonic()
            self.assertGreater(remaining, 0.1)

            async def delayed_stop_timer(name, *, grace=None):
                await original_stop_timer(name, grace=grace)
                await asyncio.sleep(max(0.0,
                    connector.handshake_deadline - time.monotonic()) + 0.01)

            connector._stop_timer = delayed_stop_timer
            with self.assertRaisesRegex(SecureConnectorError, "deadline"):
                await connector.confirm_ready()
            self.assertEqual(reservation.releases, 0,
                "late readiness must not release the live pending token")
            self.assertFalse(connector._ready_confirmed)
        finally:
            connector._stop_timer = original_stop_timer
            if not writer.is_closing():
                writer.close()
                await writer.wait_closed()
            await connector.close(grace=1)
            server.close()
            await server.wait_closed()


if __name__ == "__main__":
    unittest.main()
