"""Loopback binary transport checks, not multi-device performance evidence."""

import asyncio
import os
import unittest


@unittest.skipUnless(os.environ.get("STEAMBOAT_PROTOCOL_TESTS") == "1",
                     "Set STEAMBOAT_PROTOCOL_TESTS=1 in the pinned PyTorch image")
class TransportTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        import grpc
        import torch
        from steamboat_runtime.protocol.codec import encode_tensor
        from steamboat_runtime.protocol.errors import ProtocolError
        from steamboat_runtime.protocol.transport import InMemoryTransport, GrpcClient, create_server
        from steamboat_runtime.protocol.worker_pb2 import Request, Response
        self.grpc, self.ProtocolError = grpc, ProtocolError
        self.InMemoryTransport, self.GrpcClient, self.create_server = InMemoryTransport, GrpcClient, create_server
        self.Request, self.Response = Request, Response
        self.payload = encode_tensor(torch.arange(64, dtype=torch.float32).reshape(1, 1, 64))
        self.servers, self.clients = [], []

        class Handler:
            calls = 0
            delay = 0
            change = None

            async def handle(handler, method, request):
                handler.calls += 1
                if handler.delay:
                    await asyncio.sleep(handler.delay)
                response = Response(protocol_version=1, manifest_fingerprint=request.manifest_fingerprint,
                                    worker_boot_id=request.worker_boot_id, session_id=request.session_id,
                                    lease_token=request.lease_token, code="OK", sequence=request.sequence,
                                    start_position=request.start_position, token_count=request.token_count,
                                    end_position=request.start_position + request.token_count,
                                    next_sequence=request.sequence + 1, tensor=request.tensor)
                if handler.change:
                    setattr(response, *handler.change)
                return response
        self.handler = Handler()

    async def asyncTearDown(self):
        for client in self.clients:
            await client.close()
        for server in self.servers:
            await server.stop(0)

    def request(self, **changes):
        values = dict(protocol_version=1, manifest_fingerprint="f" * 64, worker_boot_id="boot-1",
                      session_id="session-1", lease_token="lease-1", timeout_ms=1000,
                      sequence=3, start_position=10, token_count=1, tensor=self.payload)
        values.update(changes)
        return self.Request(**values)

    async def connect(self, max_bytes=1048576):
        server, port = await self.create_server(self.handler, max_message_bytes=max_bytes)
        self.servers.append(server)
        client = self.GrpcClient(f"127.0.0.1:{port}", max_message_bytes=max_bytes)
        self.clients.append(client)
        return client, port

    async def test_in_memory_and_grpc_have_identical_binary_replies(self):
        client, _ = await self.connect()
        local = self.InMemoryTransport(self.handler)
        request = self.request()
        local_result = await local.execute("Step", request)
        remote_result = await client.execute("Step", request)
        self.assertEqual(local_result.SerializeToString(), remote_result.SerializeToString())
        self.assertEqual(remote_result.tensor.data, self.payload.data)
        self.assertEqual(self.handler.calls, 2)

    async def test_successful_reply_identity_and_position_are_checked(self):
        client, _ = await self.connect()
        local = self.InMemoryTransport(self.handler)
        for change in (("session_id", "other"), ("lease_token", "other"),
                       ("manifest_fingerprint", "other"), ("worker_boot_id", "other"),
                       ("sequence", 8), ("start_position", 9), ("token_count", 2),
                       ("end_position", 99), ("next_sequence", 99),
                       ("compute_ms", float("nan")), ("code", "UNKNOWN_ERROR")):
            self.handler.change = change
            for transport in (local, client):
                with self.subTest(change=change, transport=type(transport).__name__):
                    with self.assertRaises(self.ProtocolError):
                        await transport.execute("Step", self.request())

    async def test_invalid_operation_and_timeout_do_not_reach_handler(self):
        client, _ = await self.connect()
        for transport in (self.InMemoryTransport(self.handler), client):
            with self.assertRaises(self.ProtocolError):
                await transport.execute("ArbitraryPython", self.request())
            for timeout in (0, 30001):
                with self.assertRaises(self.ProtocolError):
                    await transport.execute("Step", self.request(timeout_ms=timeout))
        self.assertEqual(self.handler.calls, 0)

    async def test_ambiguous_timeouts_are_not_retried(self):
        client, _ = await self.connect()
        self.handler.delay = 1
        for transport in (self.InMemoryTransport(self.handler), client):
            before = self.handler.calls
            result = await transport.execute("Step", self.request(timeout_ms=30))
            self.assertEqual(result.code, "TIMEOUT")
            self.assertEqual(self.handler.calls, before + 1)

    async def test_malformed_and_unknown_wire_fields_never_reach_handler(self):
        _, port = await self.connect()
        async with self.grpc.aio.insecure_channel(f"127.0.0.1:{port}") as channel:
            method = channel.unary_unary("/steamboat.v1.Worker/Step")
            for payload in (b"\xff", self.request().SerializeToString() + b"\xf8\x3e\x01"):
                raw = await method(payload, timeout=1)
                result = self.Response.FromString(raw)
                self.assertEqual(result.code, "INVALID_INPUT")
        self.assertEqual(self.handler.calls, 0)

    async def test_grpc_core_caps_payload_before_application_parsing(self):
        _, port = await self.connect(max_bytes=512)
        async with self.grpc.aio.insecure_channel(f"127.0.0.1:{port}") as channel:
            method = channel.unary_unary("/steamboat.v1.Worker/Step")
            with self.assertRaises(self.grpc.aio.AioRpcError) as caught:
                await method(b"x" * 513, timeout=1)
            self.assertEqual(caught.exception.code(), self.grpc.StatusCode.RESOURCE_EXHAUSTED)
        self.assertEqual(self.handler.calls, 0)

    async def test_nonloopback_adapter_requires_explicit_opt_in(self):
        with self.assertRaises(ValueError):
            await self.create_server(self.handler, host="0.0.0.0:8080")
        with self.assertRaises(ValueError):
            self.GrpcClient("worker-1:8080")

    async def test_private_listener_preserves_binary_protocol(self):
        server, port = await self.create_server(self.handler, host="0.0.0.0:0",
                                                private_network=True)
        self.servers.append(server)
        client = self.GrpcClient(f"127.0.0.1:{port}")
        self.clients.append(client)
        response = await client.execute("Step", self.request())
        self.assertEqual(response.code, "OK")
        self.assertEqual(response.tensor.data, self.payload.data)

    async def test_private_endpoint_validation_rejects_public_and_malformed_addresses(self):
        from steamboat_runtime.protocol.transport import validate_endpoint
        for endpoint in ("worker-1:50051", "10.0.0.2:50051", "172.16.0.1:1",
                         "192.168.1.2:65535"):
            self.assertEqual(validate_endpoint(endpoint, private_network=True), endpoint)
            with self.assertRaises(ValueError):
                validate_endpoint(endpoint)
        for endpoint in ("8.8.8.8:50051", "169.254.1.1:50051", "0.0.0.0:50051",
                         "worker.example.com:50051", "dns:///worker-1:50051", "[::1]:50051",
                         "worker-1:0", "worker-1:65536", "worker-1:-1", "worker-1:",
                         "worker-1: 80", "worker-1:１２", "", None):
            with self.subTest(endpoint=endpoint), self.assertRaises(ValueError):
                validate_endpoint(endpoint, private_network=True)
        with self.assertRaises(ValueError):
            validate_endpoint("worker-1:50051", private_network=True, listen=True)
