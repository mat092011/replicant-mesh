"""Real loopback mTLS/C-core checks using generated synthetic certificates.

These tests intentionally use independent raw sockets for connection-cap
assertions so HTTP/2 pooling cannot turn several requests into one connection.
They run in the pinned CPU/crypto environment; this host worktree has no gRPC
runtime and these tests are not silently skipped when it is absent.
"""

import asyncio
from datetime import datetime, timedelta
import hashlib
import ipaddress
from pathlib import Path
import socket
import ssl
import sys
import tempfile
import time
import unittest


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from steamboat_runtime.protocol.errors import ProtocolError
from steamboat_runtime.protocol.secure_connector import SecureConnector
from steamboat_runtime.protocol.secure_transport import (
    BINDING_METADATA_KEY,
    CAPACITY_REJECTION_METADATA_KEY,
    ExpectedServerIdentity,
    FixedPeer,
    LocalTlsIdentity,
    MAX_MESSAGE_BYTES,
    NodeConnectionBudget,
    OUTBOUND_STATIC_CONNECTION_SLOTS,
    SecureTaskPending,
    SecureTransportError,
    _SecureSubchannel,
    capacity_rejection_metadata,
    create_secure_worker_client,
    create_secure_worker_server,
    has_capacity_rejection_metadata,
)
from steamboat_runtime.secure_coordinator_service import create_secure_coordinator_server
from steamboat_runtime.protocol.worker_pb2 import Request, Response


class _Authorization:
    binding_bytes = b'{"account_id":"acct_synthetic","binding_version":1}'

    def __init__(self):
        self.completed = []
        self.failed = []
        self.closed = False

    def assert_live(self):
        return None

    def complete(self, response):
        self.completed.append(response)

    def fail(self, *, cache_may_exist=True):
        self.failed.append(cache_may_exist)

    def close(self):
        self.closed = True

    def remaining_seconds(self):
        return 30.0


class _WorkerAuthorizer:
    def __init__(self):
        self.calls = []
        self.authorization = _Authorization()

    def authorize(self, *, service, method, payload, metadata, peer_certificate_pem):
        self.calls.append((service, method, payload, metadata, peer_certificate_pem))
        return self.authorization


class _OutboundAuthorizer:
    def __init__(self):
        self.authorization = _Authorization()
        self.peer_pems = []

    def authorize_outbound(self, *, service, method, payload,
                           trusted_request_context, peer_certificate_pem):
        self.peer_pems.append(peer_certificate_pem)
        return self.authorization


class _CoordinatorAuthorizer:
    def __init__(self):
        self.authorization = _Authorization()
        self.calls = []
        self.error = None

    def authorize(self, *, service, method, payload, metadata, peer_certificate_pem):
        self.calls.append((service, method, payload, metadata, peer_certificate_pem))
        if self.error is not None:
            raise self.error
        return self.authorization


class _Handler:
    def __init__(self):
        self.calls = []

    async def handle(self, method, request):
        self.calls.append((method, request))
        return Response(protocol_version=1, code="OK",
                        worker_boot_id=request.worker_boot_id,
                        manifest_fingerprint=request.manifest_fingerprint)


async def _never_revoked(_authorization):
    await asyncio.Future()


def _certificate_pem(certificate):
    from cryptography.hazmat.primitives import serialization

    return certificate.public_bytes(serialization.Encoding.PEM)


def _private_key_pem(private_key):
    from cryptography.hazmat.primitives import serialization

    return private_key.private_bytes(serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8, serialization.NoEncryption())


def _make_certificate_fixture(directory):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

    now = datetime.utcnow()
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Synthetic C1a Test CA")])
    ca_certificate = (x509.CertificateBuilder()
        .subject_name(ca_name).issuer_name(ca_name).public_key(ca_key.public_key())
        .serial_number(1001).not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(hours=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()),
                       critical=False)
        .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False,
            key_encipherment=False, data_encipherment=False, key_agreement=False,
                key_cert_sign=True, crl_sign=True, encipher_only=None, decipher_only=None),
            critical=True)
        .sign(ca_key, hashes.SHA256()))
    ca_pem = _certificate_pem(ca_certificate)

    def issue(serial, device_id, eku, role="host"):
        key = ec.generate_private_key(ec.SECP256R1())
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,
                                                f"Synthetic {device_id}")])
        identity_uri = ("urn:steamboat:participant:v1:acct_synthetic:"
                        f"{device_id}:{role}")
        certificate = (x509.CertificateBuilder()
            .subject_name(subject).issuer_name(ca_name).public_key(key.public_key())
            .serial_number(serial).not_valid_before(now - timedelta(minutes=1))
            .not_valid_after(now + timedelta(minutes=10))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
                           critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(
                ca_key.public_key()), critical=False)
            .add_extension(x509.SubjectAlternativeName((
                x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
                x509.UniformResourceIdentifier(identity_uri))), critical=False)
            .add_extension(x509.ExtendedKeyUsage(
                eku if isinstance(eku, tuple) else (eku,)), critical=False)
            .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False,
                key_encipherment=False, data_encipherment=False, key_agreement=False,
                key_cert_sign=False, crl_sign=False, encipher_only=None, decipher_only=None),
                critical=True)
            .sign(ca_key, hashes.SHA256()))
        certificate_pem = _certificate_pem(certificate)
        key_pem = _private_key_pem(key)
        return key, certificate, certificate_pem, key_pem

    server = issue(2001, "dev_server", ExtendedKeyUsageOID.SERVER_AUTH)
    wrong_server = issue(2002, "dev_server", ExtendedKeyUsageOID.SERVER_AUTH)
    client = issue(3001, "dev_client", ExtendedKeyUsageOID.CLIENT_AUTH)
    coordinator = issue(2003, "dev_coordinator",
        (ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH),
        role="personal_coordinator")
    for name, data in (("client.pem", client[2]), ("client-key.pem", client[3])):
        (directory / name).write_bytes(data)
    return {"ca_pem": ca_pem, "server": server, "wrong_server": wrong_server,
            "client": client, "coordinator": coordinator, "directory": directory}


def _server_identity(fixture, which="server"):
    _key, _certificate, certificate_pem, key_pem = fixture[which]
    return LocalTlsIdentity(certificate_chain_pem=certificate_pem,
                            private_key_pem=key_pem)


def _fixed_peer(fixture, *, leaf=None, endpoint_ip="127.0.0.1"):
    from cryptography.hazmat.primitives import serialization

    _key, certificate, certificate_pem, _key_pem = fixture["server"]
    if leaf is not None:
        certificate_pem = leaf
    public_key_der = certificate.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    expected = ExpectedServerIdentity(
        account_id="acct_synthetic", device_id="dev_server", role="host",
        serial=certificate.serial_number,
        public_key_hash=hashlib.sha256(public_key_der).digest(),
        certificate_hash=hashlib.sha256(certificate.public_bytes(
            serialization.Encoding.DER)).digest(), expected_ip=endpoint_ip)
    return FixedPeer(endpoint=f"{endpoint_ip}:1", allowed_addresses=(endpoint_ip,),
        device_id="dev_server", server_leaf_pem=certificate_pem,
        cohort_ca_pem=fixture["ca_pem"], expected_server=expected)


def _exact_leaf_verifier(expected_leaf):
    def verify(leaf_pem, _ca_pem, _expected, *, now):
        if leaf_pem != expected_leaf:
            raise SecureTransportError("synthetic exact leaf pin mismatch")
        return leaf_pem
    return verify


def _raw_tcp(address, port, timeout=2):
    sock = socket.create_connection((address, port), timeout=timeout)
    sock.settimeout(0.2)
    return sock


def _free_loopback_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def _wait_for_close(sock, timeout):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            data = sock.recv(4096)
        except socket.timeout:
            continue
        except OSError:
            return True
        if not data:
            return True
    return False


def _tls_without_http2_preface(fixture, port):
    # Each call creates a distinct TCP socket and SSL context. These TLS peers
    # intentionally stop before writing the HTTP/2 connection preface.
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.set_alpn_protocols(["h2"])
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    context.load_verify_locations(cadata=fixture["server"][2].decode("ascii"))
    # The C0 pin is a CA-signed non-CA leaf, used as the exact trust anchor.
    context.verify_flags |= ssl.VERIFY_X509_PARTIAL_CHAIN
    context.load_cert_chain(str(fixture["directory"] / "client.pem"),
                            str(fixture["directory"] / "client-key.pem"))
    raw = _raw_tcp("127.0.0.1", port)
    try:
        return context.wrap_socket(raw, server_hostname="127.0.0.1")
    except BaseException:
        raw.close()
        raise


class RealGrpcMtlsTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        lab_dir = ROOT / ".lab"
        lab_dir.mkdir(exist_ok=True)
        self._temporary = tempfile.TemporaryDirectory(prefix="secure-transport-test-", dir=lab_dir)
        self.fixture = _make_certificate_fixture(Path(self._temporary.name))
        self.servers = []
        self.controller = NodeConnectionBudget()

    async def asyncTearDown(self):
        try:
            for server in reversed(self.servers):
                await server.stop(0)
        finally:
            self._temporary.cleanup()

    async def _start_server(self, *, slots=2, identity="server", port=0,
                            address="127.0.0.1", handler=None):
        authorizer = _WorkerAuthorizer()
        handler = handler or _Handler()
        server = await create_secure_worker_server(
            handler, listen_endpoint=f"{address}:{port}",
            allowed_listen_addresses=(address,),
            server_identity=_server_identity(self.fixture, identity),
            client_ca_pem=self.fixture["ca_pem"], authorizer=authorizer,
            authorization_watcher=_never_revoked,
            connection_controller=self.controller, listener_id=f"listener-{len(self.servers)}",
            listener_slots=slots, acceptor_directory=self._temporary.name)
        server.test_handler = handler
        self.servers.append(server)
        return server, authorizer

    async def _client(self, server, *, expected_leaf=None, peer=None,
                      target_address="127.0.0.1"):
        expected_leaf = expected_leaf or self.fixture["server"][2]
        peer = peer or _fixed_peer(self.fixture)
        peer = FixedPeer(endpoint=f"{target_address}:{server.port}",
            allowed_addresses=(target_address,), device_id=peer.device_id,
            server_leaf_pem=peer.server_leaf_pem, cohort_ca_pem=peer.cohort_ca_pem,
            expected_server=peer.expected_server)
        outbound = _OutboundAuthorizer()
        client = await create_secure_worker_client(peer,
            local_identity=_server_identity(self.fixture, "client"),
            outbound_authorizer=outbound, authorization_watcher=_never_revoked,
            verify_expected_server_leaf=_exact_leaf_verifier(expected_leaf),
            connection_controller=self.controller)
        return client, outbound

    def _assert_connector_shutdown(self, connector):
        self.assertTrue(connector.closed_confirmed)
        self.assertTrue(connector.listener_closed_confirmed)
        self.assertTrue(connector.owned_sockets_closed)
        self.assertIsNotNone(connector._accept_task)
        self.assertTrue(connector._accept_task.done())
        self.assertTrue(connector.pump_tasks_done)
        self.assertEqual(len(connector._pump_tasks), 2,
                         "a ready TLS tunnel must retain both directional pump owners")
        self.assertEqual(set(connector._pump_results), set(connector._pump_tasks),
                         "each pump must finish with an observed terminal result")
        self.assertTrue(set(connector._pump_results.values()).issubset({"eof", "reset"}),
                        "healthy gRPC teardown must be observed through EOF or socket reset")
        self.assertTrue(all(sock.fileno() == -1 for sock in connector._owned_sockets),
                        "all gate-owned descriptors close only after both pump results exist")
        self.assertIn(connector.closure_evidence, (
            "bidirectional peer EOF and owned descriptors closed",
            "peer reset and owned descriptors closed",
            "both pumps exited after coordinated shutdown; owned descriptors closed"))
        self.assertEqual(self.controller.reserved_pending, 0)

    async def test_mtls_worker_call_uses_authenticated_leaf_and_echoes_binding(self):
        server, authorizer = await self._start_server(slots=1)
        client, outbound = await self._client(server)
        connector = None
        try:
            response = await client.execute("Describe", Request(timeout_ms=5000),
                                            trusted_request_context=object())
            self.assertEqual(response.code, "OK")
            connector = client._subchannel.connector
            self.assertIsNotNone(connector, "first RPC must create the lazy outbound connector")
            self.assertEqual(len(authorizer.calls), 1)
            service, method, payload, metadata, peer_pem = authorizer.calls[0]
            self.assertEqual((service, method), ("steamboat.v1.Worker", "Describe"))
            self.assertIsInstance(payload, Request)
            self.assertEqual([value for key, value in metadata if key == BINDING_METADATA_KEY],
                             [_Authorization.binding_bytes])
            self.assertEqual(peer_pem, self.fixture["client"][2])
            self.assertEqual(outbound.peer_pems, [self.fixture["server"][2]])
            self.assertEqual(self.controller.reserved_pending, 0)
            self.assertEqual(authorizer.authorization.completed[0].code, "OK")
        finally:
            await client.close()
        self._assert_connector_shutdown(connector)
        self.assertEqual(self.controller.reserved_connections, 1)

    async def test_healthy_http2_channel_uses_one_accepted_tunnel_for_multiple_rpcs(self):
        server, authorizer = await self._start_server(slots=1)
        client, _outbound = await self._client(server)
        connector = None
        try:
            first = await client.execute("Describe", Request(timeout_ms=5000),
                                         trusted_request_context=object())
            channel = client.channel
            connector = client._subchannel.connector
            self.assertIsNotNone(connector, "first RPC must create the lazy outbound connector")
            second = await client.execute("Describe", Request(timeout_ms=5000),
                                          trusted_request_context=object())
            self.assertEqual((first.code, second.code), ("OK", "OK"))
            self.assertIs(client.channel, channel)
            self.assertIs(client._subchannel.connector, connector)
            self.assertEqual((connector.accepted_count, connector.upstream_dial_count), (1, 1))
            self.assertEqual(len(authorizer.calls), 2)
            self.assertEqual(self.controller.reserved_pending, 0)
        finally:
            await client.close()
        self._assert_connector_shutdown(connector)
        self.assertEqual(self.controller.reserved_connections, 1)

    async def test_client_retains_static_reservation_until_stalled_pump_owner_finishes(self):
        server, _authorizer = await self._start_server(slots=1)
        client, _outbound = await self._client(server)
        self.assertEqual(self.controller.reserved_connections,
            1 + OUTBOUND_STATIC_CONNECTION_SLOTS,
            "client construction reserves its static slots before the first RPC")
        connector = None
        release_finalizer = asyncio.Event()
        finalizer_started = asyncio.Event()
        original_pump = SecureConnector._pump
        held_direction = False
        held_results = []

        async def hold_one_pump_finalizer(owner, source, destination):
            nonlocal held_direction
            hold = not held_direction
            held_direction = True
            try:
                result = await original_pump(owner, source, destination)
                if hold:
                    held_results.append(result)
                return result
            finally:
                if hold:
                    finalizer_started.set()
                    await release_finalizer.wait()

        try:
            from unittest.mock import patch
            with patch.object(SecureConnector, "_pump", hold_one_pump_finalizer):
                response = await client.execute("Describe", Request(timeout_ms=5000),
                                                trusted_request_context=object())
            self.assertEqual(response.code, "OK")
            connector = client._subchannel.connector
            self.assertIsNotNone(connector, "first RPC must create the lazy outbound connector")
            expected_reserved = 1 + OUTBOUND_STATIC_CONNECTION_SLOTS
            self.assertEqual(self.controller.reserved_connections, expected_reserved,
                "the listener and outbound channel profile must be fully reserved")
            self.assertEqual(len(connector._pump_tasks), 2,
                "the gate owns exactly its two directional pumps")

            from steamboat_runtime.protocol import secure_transport

            with patch.object(secure_transport, "MAX_CANCELLATION_GRACE_SECONDS", 0.05):
                with self.assertRaises(SecureTaskPending):
                    await client.close()
                await asyncio.wait_for(finalizer_started.wait(), 0.5)
                self.assertEqual(held_results, ["eof"],
                    "the held finalizer must follow an actual reader EOF")
                self.assertIsNotNone(connector._accept_task)
                self.assertFalse(connector._accept_task.done())
                self.assertTrue(connector.listener_closed_confirmed)
                self.assertFalse(connector.owned_sockets_closed)
                self.assertFalse(connector.pump_tasks_done)
                self.assertFalse(connector.closed_confirmed)
                self.assertEqual(len(connector._pump_tasks), 2)
                self.assertTrue(any(not task.done() for task in connector._pump_tasks),
                    "the actual pump finalizer remains a live owned task")
                self.assertTrue(all(sock.fileno() >= 0
                                    for sock in connector._owned_sockets),
                    "gate descriptors remain open while a directional pump finalizer is live")
                self.assertEqual(self.controller.reserved_connections, expected_reserved,
                    "the static connection reservation stays held until every pump owner exits")

            release_finalizer.set()
            await asyncio.wait_for(asyncio.gather(*connector._pump_tasks), 0.5)
            await asyncio.wait_for(client.close(), 1)
            self._assert_connector_shutdown(connector)
            self.assertEqual(self.controller.reserved_connections, 1,
                "only the configured inbound listener remains reserved")
        finally:
            release_finalizer.set()
            if not client._closed:
                await client.close()

    async def test_simultaneous_rpc_streams_share_one_http2_tunnel(self):
        class ConcurrentHandler(_Handler):
            def __init__(self):
                super().__init__()
                self.active = 0
                self.max_active = 0
                self.both_started = asyncio.Event()
                self.release = asyncio.Event()

            async def handle(self, method, request):
                self.active += 1
                self.max_active = max(self.max_active, self.active)
                self.calls.append((method, request))
                if self.active >= 2:
                    self.both_started.set()
                try:
                    await self.release.wait()
                    return Response(protocol_version=1, code="OK",
                        worker_boot_id=request.worker_boot_id,
                        manifest_fingerprint=request.manifest_fingerprint)
                finally:
                    self.active -= 1

        handler = ConcurrentHandler()
        server, authorizer = await self._start_server(slots=1, handler=handler)
        client, _outbound = await self._client(server)
        connector = None
        calls = [asyncio.create_task(client.execute(
            "Describe", Request(timeout_ms=5000), trusted_request_context=object()))
            for _ in range(2)]
        try:
            await asyncio.wait_for(handler.both_started.wait(), 3)
            connector = client._subchannel.connector
            self.assertIsNotNone(connector, "active RPC streams must have a ready connector")
            self.assertEqual(handler.max_active, 2,
                "both gRPC RPC streams must be active before either is released")
            self.assertEqual(len(authorizer.calls), 2)
            self.assertEqual((connector.accepted_count, connector.upstream_dial_count),
                             (1, 1),
                "multiplexed RPC streams must share the one-shot TLS tunnel")
            self.assertIs(client.channel, client._subchannel.channel)
            handler.release.set()
            responses = await asyncio.gather(*calls)
            self.assertEqual([response.code for response in responses], ["OK", "OK"])
        finally:
            handler.release.set()
            await asyncio.gather(*calls, return_exceptions=True)
            await client.close()
        self._assert_connector_shutdown(connector)
        self.assertEqual(self.controller.reserved_connections, 1)

    async def test_native_proxy_options_keep_original_target_and_exact_peer_address(self):
        server, _authorizer = await self._start_server(slots=1)
        client, _outbound = await self._client(server)
        connector = None
        try:
            await client._ensure_channel(3)
            connector = client._subchannel.connector
            options = dict(connector.channel_options())
            self.assertEqual(options["grpc.address_http_proxy_enabled_addresses"],
                             "127.0.0.1/32")
            self.assertEqual(options["grpc.use_local_subchannel_pool"], 1)
            self.assertEqual(options["grpc.max_connections_per_subchannel_cap"], 1)
            self.assertEqual(options["grpc.http_proxy"], "")
            self.assertEqual(client.peer.endpoint, f"127.0.0.1:{server.port}")
            self.assertNotIn("grpc.ssl_target_name_override", options)
            response = await client.execute("Describe", Request(timeout_ms=5000),
                                            trusted_request_context=object())
            self.assertEqual(response.code, "OK")
            self.assertEqual((connector.accepted_count, connector.upstream_dial_count), (1, 1))
        finally:
            connector = client._subchannel.connector
            await client.close()
        if connector is not None:
            self._assert_connector_shutdown(connector)
            self.assertEqual(self.controller.reserved_connections, 1)

    async def test_wrong_connect_token_is_rejected_before_any_upstream_dial(self):
        import grpc
        from steamboat_runtime.protocol.secure_connector import SecureConnector
        from steamboat_runtime.protocol.secure_transport import MAX_MESSAGE_BYTES, _secure_options

        server, authorizer = await self._start_server(slots=1)
        pending = self.controller.reserve_outbound_pending("dev_server")
        connector = SecureConnector(f"127.0.0.1:{server.port}", ("127.0.0.1",),
            pending_reservation=pending, handshake_deadline=time.monotonic() + 2,
            lifetime_seconds=300,
            on_lifetime_expired=lambda _connector: None)
        await connector.start()
        credentials = grpc.ssl_channel_credentials(
            root_certificates=self.fixture["server"][2],
            private_key=self.fixture["client"][3],
            certificate_chain=self.fixture["client"][2])
        options = list(connector.channel_options())
        options = [(key, "steamboat-proxy-token:invalid-token"
                    if key == "grpc.http_connect_headers" else value)
                   for key, value in options]
        channel = grpc.aio.secure_channel(f"127.0.0.1:{server.port}", credentials,
            options=(*_secure_options(MAX_MESSAGE_BYTES), *options))
        try:
            with self.assertRaises((asyncio.TimeoutError, grpc.aio.AioRpcError)):
                await asyncio.wait_for(channel.channel_ready(), 1)
            self.assertEqual((connector.accepted_count, connector.upstream_dial_count), (1, 0))
            self.assertEqual(authorizer.calls, [])
            self.assertEqual(self.controller.reserved_pending, 1)
        finally:
            await channel.close()
            await connector.close(grace=1)
        self.assertEqual(self.controller.reserved_pending, 0)

    async def test_closed_native_proxy_and_hostile_proxy_environment_do_not_fall_back_direct(self):
        import grpc
        import os
        from unittest.mock import patch
        from steamboat_runtime.protocol.secure_connector import SecureConnector
        from steamboat_runtime.protocol.secure_transport import MAX_MESSAGE_BYTES, _secure_options

        server, authorizer = await self._start_server(slots=1)
        pending = self.controller.reserve_outbound_pending("dev_server")
        connector = SecureConnector(f"127.0.0.1:{server.port}", ("127.0.0.1",),
            pending_reservation=pending, handshake_deadline=time.monotonic() + 2,
            lifetime_seconds=300,
            on_lifetime_expired=lambda _connector: None)
        await connector.start()
        options = (*_secure_options(MAX_MESSAGE_BYTES), *connector.channel_options())
        local_port = connector.local_port
        await connector.close(grace=1)
        credentials = grpc.ssl_channel_credentials(
            root_certificates=self.fixture["server"][2],
            private_key=self.fixture["client"][3],
            certificate_chain=self.fixture["client"][2])
        with patch.dict(os.environ, {"grpc_proxy": f"http://127.0.0.1:{server.port}",
                                     "no_grpc_proxy": "*"}):
            channel = grpc.aio.secure_channel(f"127.0.0.1:{server.port}", credentials,
                options=options)
            try:
                try:
                    await asyncio.wait_for(channel.channel_ready(), 1)
                except (asyncio.TimeoutError, grpc.aio.AioRpcError):
                    pass
                else:
                    self.fail("closed native proxy unexpectedly connected directly")
            finally:
                await channel.close()
        self.assertEqual((connector.accepted_count, connector.upstream_dial_count), (0, 0))
        self.assertEqual(authorizer.calls, [])
        with self.assertRaises(OSError):
            await asyncio.open_connection("127.0.0.1", local_port)

    async def test_coordinator_server_tls_stays_on_gate_backend_uds_and_uses_exact_peer_leaf(self):
        import grpc

        class Coordinator:
            def submit(self, input_ids, new_tokens, *, forced_tokens=None,
                       trusted_request_context=None):
                raise AssertionError("Describe must not submit model work")

        class Service:
            max_streams = 4
            active_streams = 0
            counters = {"rejected_requests": 0, "transport_stalls": 0,
                        "disconnected_streams": 0}
            coordinator = Coordinator()

            async def describe_rpc(self, data, context):
                return b"{}"

            async def tokenize_rpc(self, data, context):
                raise AssertionError("Tokenize was not requested")

        authorizer = _CoordinatorAuthorizer()
        handle, secure_service = await create_secure_coordinator_server(
            Service(), listen_endpoint="127.0.0.1:0",
            allowed_listen_addresses=("127.0.0.1",),
            server_identity=_server_identity(self.fixture, "coordinator"),
            client_ca_pem=self.fixture["ca_pem"], authorizer=authorizer,
            authorization_watcher=_never_revoked,
            request_context_factory=lambda _authorization, _payload: object(),
            connection_controller=self.controller, listener_id="coordinator-listener",
            listener_slots=1, acceptor_directory=self._temporary.name,
            max_generate_streams=4)
        self.servers.append(handle)
        self.assertIs(secure_service.acceptor, handle._acceptor)
        credentials = grpc.ssl_channel_credentials(
            root_certificates=self.fixture["coordinator"][2],
            private_key=self.fixture["client"][3],
            certificate_chain=self.fixture["client"][2])
        channel = grpc.aio.secure_channel(f"127.0.0.1:{handle.port}", credentials,
            options=(("grpc.enable_retries", 0),))
        try:
            call = channel.unary_unary("/steamboat.v1.Coordinator/Describe")(
                b"{}", timeout=3, wait_for_ready=False,
                metadata=((BINDING_METADATA_KEY, _Authorization.binding_bytes),))
            response = await call
            metadata = await call.initial_metadata()
            self.assertEqual(response, b"{}")
            self.assertIn((BINDING_METADATA_KEY, _Authorization.binding_bytes), tuple(metadata))
            self.assertEqual(authorizer.calls[0][0:2],
                             ("steamboat.v1.Coordinator", "Describe"))
            self.assertEqual(authorizer.calls[0][4], self.fixture["client"][2])
            self.assertEqual(self.controller.reserved_pending, 0)
        finally:
            await channel.close()

    async def test_first_coordinator_rpc_returns_native_unauthenticated(self):
        import grpc

        class CredentialError(Exception):
            pass

        class Coordinator:
            class Engine:
                def submit(self, _input_ids, _new_tokens, *, forced_tokens=None,
                           trusted_request_context=None):
                    raise AssertionError("denied coordinator RPC reached model submission")

            def __init__(self):
                self.calls = []
                self.coordinator = self.Engine()
            async def describe_rpc(self, _data, _context):
                self.calls.append("Describe")
                raise AssertionError("denied coordinator RPC reached service dispatch")
            async def tokenize_rpc(self, _data, _context):
                self.calls.append("Tokenize")
                raise AssertionError("denied coordinator RPC reached service dispatch")

            max_streams = 4
            active_streams = 0
            counters = {"rejected_requests": 0, "transport_stalls": 0,
                        "disconnected_streams": 0}

        coordinator = Coordinator()
        authorizer = _CoordinatorAuthorizer()
        authorizer.error = CredentialError("synthetic C0 actor credential denial")
        handle, service = await create_secure_coordinator_server(
            coordinator, listen_endpoint="127.0.0.1:0",
            allowed_listen_addresses=("127.0.0.1",),
            server_identity=_server_identity(self.fixture, "coordinator"),
            client_ca_pem=self.fixture["ca_pem"], authorizer=authorizer,
            authorization_watcher=_never_revoked,
            request_context_factory=lambda _authorization, _payload: object(),
            connection_controller=self.controller, listener_id="coordinator-denied",
            listener_slots=1, acceptor_directory=self._temporary.name,
            max_generate_streams=4)
        self.servers.append(handle)
        self.assertIs(service.acceptor, handle._acceptor)
        credentials = grpc.ssl_channel_credentials(
            root_certificates=self.fixture["coordinator"][2],
            private_key=self.fixture["client"][3],
            certificate_chain=self.fixture["client"][2])
        channel = grpc.aio.secure_channel(
            f"127.0.0.1:{handle.port}", credentials,
            options=(("grpc.enable_retries", 0),))
        try:
            await asyncio.wait_for(channel.channel_ready(), 3)
            rpc = channel.unary_unary("/steamboat.v1.Coordinator/Describe")
            with self.assertRaises(grpc.aio.AioRpcError) as raised:
                await rpc(b"{}", timeout=3, wait_for_ready=False,
                          metadata=((BINDING_METADATA_KEY,
                                     _Authorization.binding_bytes),))
            self.assertEqual(raised.exception.code(), grpc.StatusCode.UNAUTHENTICATED)
            self.assertEqual(len(authorizer.calls), 1)
            self.assertEqual(coordinator.calls, [])
            self.assertEqual(authorizer.authorization.completed, [])
        finally:
            await channel.close()

    async def test_same_ca_same_ip_wrong_server_leaf_fails_during_real_tls(self):
        server, authorizer = await self._start_server(slots=1, identity="wrong_server")
        # The configured peer and leaf verifier still pin the original server
        # leaf. The listening server presents a different leaf from the same CA
        # with the same IP SAN; ordinary verification must reject it.
        client, _outbound = await self._client(server)
        try:
            started = time.monotonic()
            with self.assertRaises(SecureTransportError):
                await client.execute("Describe", Request(timeout_ms=3000),
                                     trusted_request_context=object())
            self.assertLess(time.monotonic() - started, 6.0)
            self.assertEqual(authorizer.calls, [])
            self.assertEqual(server.test_handler.calls, [],
                "a TLS leaf mismatch must not invoke the worker handler")
            self.assertEqual(authorizer.authorization.completed, [],
                "a rejected TLS leaf must not complete or mutate authorization state")
            self.assertTrue(await server._acceptor.wait_for_idle(1.0),
                "the server-side rejected TLS connection must be physically retired")
            self.assertEqual(self.controller.reserved_pending, 0)
            self.assertIsNone(client._subchannel.connector)
        finally:
            await client.close()
        self.assertEqual(self.controller.reserved_connections, 1,
            "failed leaf setup released the server listener or leaked client gate slots")

    async def test_original_target_ip_san_verification_survives_private_proxy(self):
        # The channel target and server bind are 127.0.0.2, while the exact
        # pinned leaf contains only a 127.0.0.1 IP SAN. The test verifier
        # approves the exact leaf so this failure must come from gRPC's normal
        # target-name verification after the local 127.0.0.1 proxy is used.
        server, authorizer = await self._start_server(
            slots=1, address="127.0.0.2")
        peer = _fixed_peer(self.fixture, endpoint_ip="127.0.0.2")
        client, _outbound = await self._client(
            server, peer=peer, target_address="127.0.0.2")
        try:
            started = time.monotonic()
            with self.assertRaises(SecureTransportError):
                await client.execute("Describe", Request(timeout_ms=3000),
                                     trusted_request_context=object())
            self.assertLess(time.monotonic() - started, 6.0)
            self.assertEqual(authorizer.calls, [])
            self.assertEqual(server.test_handler.calls, [])
            self.assertEqual(authorizer.authorization.completed, [])
            self.assertEqual(self.controller.reserved_pending, 0)
            self.assertIsNone(client._subchannel.connector)
            self.assertIsNone(client.channel)
        finally:
            await client.close()
        self.assertEqual(self.controller.reserved_connections, 1,
            "hostname rejection leaked outbound gate slots or released the listener")

    async def test_c_core_rejects_metadata_over_the_8k_absolute_ceiling(self):
        import grpc

        server, authorizer = await self._start_server(slots=1)
        reservation = self.controller.reserve_outbound("dev_server")
        credentials = grpc.ssl_channel_credentials(
            root_certificates=self.fixture["server"][2],
            private_key=self.fixture["client"][3],
            certificate_chain=self.fixture["client"][2])
        channel = grpc.aio.secure_channel(f"127.0.0.1:{server.port}", credentials,
            options=(("grpc.enable_retries", 0),))
        try:
            call = channel.unary_unary(
                "/steamboat.v1.Worker/Describe")(
                    Request(timeout_ms=5000).SerializeToString(), timeout=3,
                    wait_for_ready=False,
                    metadata=((BINDING_METADATA_KEY, _Authorization.binding_bytes),
                              ("x-test-padding", "x" * 9000)))
            with self.assertRaises(grpc.aio.AioRpcError) as raised:
                await call
            self.assertEqual(raised.exception.code(), grpc.StatusCode.RESOURCE_EXHAUSTED)
            self.assertEqual(authorizer.calls, [])
        finally:
            await channel.close()
            reservation.release()

    async def test_real_tls_c_core_oversized_first_response_has_no_capacity_marker(self):
        """Exercise C-core size rejection after valid TLS and binding metadata.

        This raw synthetic endpoint isolates the gRPC receive-size boundary; it
        is not a production authorization or native-gate integration test.
        """
        import grpc

        binding = _Authorization.binding_bytes
        self.assertEqual(capacity_rejection_metadata(binding)[0][0],
                         CAPACITY_REJECTION_METADATA_KEY)

        async def oversize_first_response(_request, context):
            await context.send_initial_metadata(((BINDING_METADATA_KEY, binding),))
            yield b"x" * (MAX_MESSAGE_BYTES + 1)

        handler = grpc.unary_stream_rpc_method_handler(
            oversize_first_response,
            request_deserializer=lambda value: value,
            response_serializer=lambda value: value)
        server = grpc.aio.server(options=(
            ("grpc.max_send_message_length", MAX_MESSAGE_BYTES + 4096),))
        server.add_generic_rpc_handlers((grpc.method_handlers_generic_handler(
            "steamboat.v1.Coordinator", {"Generate": handler}),))
        server_credentials = grpc.ssl_server_credentials(
            ((self.fixture["coordinator"][3], self.fixture["coordinator"][2]),),
            root_certificates=self.fixture["ca_pem"], require_client_auth=True)
        port = server.add_secure_port("127.0.0.1:0", server_credentials)
        self.assertGreater(port, 0)
        await server.start()
        self.servers.append(server)

        client_credentials = grpc.ssl_channel_credentials(
            root_certificates=self.fixture["coordinator"][2],
            private_key=self.fixture["client"][3],
            certificate_chain=self.fixture["client"][2])
        channel = grpc.aio.secure_channel(f"127.0.0.1:{port}", client_credentials,
            options=(("grpc.max_receive_message_length", MAX_MESSAGE_BYTES),
                     ("grpc.enable_retries", 0)))
        call = None
        try:
            call = channel.unary_stream("/steamboat.v1.Coordinator/Generate")(
                b"{}", timeout=5, wait_for_ready=False,
                metadata=((BINDING_METADATA_KEY, binding),))
            initial = await asyncio.wait_for(call.initial_metadata(), timeout=5)
            self.assertIn((BINDING_METADATA_KEY, binding), tuple(initial))
            received = []
            with self.assertRaises(grpc.aio.AioRpcError) as raised:
                async for message in call:
                    received.append(message)
            self.assertEqual(raised.exception.code(), grpc.StatusCode.RESOURCE_EXHAUSTED)
            self.assertEqual(received, [],
                "C-core must reject the oversized first response before yielding it")
            trailers = await asyncio.wait_for(call.trailing_metadata(), timeout=5)
            self.assertNotIn(CAPACITY_REJECTION_METADATA_KEY,
                             tuple(key for key, _value in trailers))
            self.assertFalse(has_capacity_rejection_metadata(trailers, binding))
        finally:
            if call is not None and not call.done():
                call.cancel()
            await channel.close()

    async def test_wrong_offline_leaf_is_rejected_before_grpc_channel_creation(self):
        import grpc
        from unittest.mock import patch

        server_pem = self.fixture["server"][2]
        wrong_pem = self.fixture["wrong_server"][2]
        peer = _fixed_peer(self.fixture, leaf=wrong_pem)
        peer = FixedPeer(endpoint="127.0.0.1:1", allowed_addresses=("127.0.0.1",),
            device_id=peer.device_id, server_leaf_pem=wrong_pem,
            cohort_ca_pem=peer.cohort_ca_pem, expected_server=peer.expected_server)
        outbound = _OutboundAuthorizer()
        with patch.object(grpc.aio, "secure_channel", side_effect=AssertionError(
                "channel must not be constructed after failed offline pin validation")) as channel:
            with self.assertRaises(SecureTransportError):
                await create_secure_worker_client(peer,
                    local_identity=_server_identity(self.fixture, "client"),
                    outbound_authorizer=outbound, authorization_watcher=_never_revoked,
                    verify_expected_server_leaf=_exact_leaf_verifier(server_pem),
                    connection_controller=NodeConnectionBudget())
        channel.assert_not_called()

    async def test_two_incomplete_handshakes_reject_third_timeout_then_allow_reconnect(self):
        server, _authorizer = await self._start_server(slots=2)
        first = await asyncio.to_thread(_raw_tcp, "127.0.0.1", server.port)
        second = await asyncio.to_thread(_raw_tcp, "127.0.0.1", server.port)
        third = None
        try:
            await asyncio.sleep(0.2)
            self.assertEqual(self.controller.reserved_pending, 2)
            third = await asyncio.to_thread(_raw_tcp, "127.0.0.1", server.port)
            rejected = await asyncio.to_thread(_wait_for_close, third, 2.0)
            self.assertTrue(rejected, "third independent incomplete handshake was not rejected")
            first_closed, second_closed = await asyncio.gather(
                asyncio.to_thread(_wait_for_close, first, 7.0),
                asyncio.to_thread(_wait_for_close, second, 7.0))
            self.assertTrue(first_closed, "first handshake did not expire within the configured bound")
            self.assertTrue(second_closed, "second handshake did not expire within the configured bound")
            self.assertTrue(await server._acceptor.wait_for_idle(1.0),
                "gate cleanup did not retire forwarding tasks and sockets within one second")
            self.assertEqual(self.controller.reserved_pending, 0)
            client, _outbound = await self._client(server)
            connector = None
            try:
                response = await client.execute("Describe", Request(timeout_ms=5000),
                                                trusted_request_context=object())
                self.assertEqual(response.code, "OK")
                connector = client._subchannel.connector
                self.assertIsNotNone(connector,
                    "reconnect RPC must create the replacement outbound connector")
            finally:
                await client.close()
            self._assert_connector_shutdown(connector)
        finally:
            first.close()
            second.close()
            if third is not None:
                third.close()

    async def test_real_outbound_channel_failure_is_bounded_and_reconnects_fresh(self):
        port = _free_loopback_port()
        first_server, _authorizer = await self._start_server(slots=1, port=port)
        client, _outbound = await self._client(first_server)
        old_channel = None
        old_connector = None
        try:
            first = await client.execute("Describe", Request(timeout_ms=5000),
                                         trusted_request_context=object())
            self.assertEqual(first.code, "OK")
            old_channel = client.channel
            old_connector = client._subchannel.connector
            await first_server.stop(0)

            failed_at = time.monotonic()
            with self.assertRaises((ProtocolError, SecureTransportError)):
                await client.execute("Describe", Request(timeout_ms=10_000),
                                     trusted_request_context=object())
            self.assertLessEqual(time.monotonic() - failed_at, 6.5)
            self.assertEqual(self.controller.reserved_pending, 0)
            self.assertIsNone(client.channel,
                "failed outbound operation retained a reconnecting channel")
            self.assertEqual((old_connector.accepted_count,
                              old_connector.upstream_dial_count), (1, 1),
                "the retired one-shot gate allowed a hidden physical reconnect")
            self.assertTrue(old_connector.closed_confirmed,
                "fresh channel setup began before the old physical tunnel was confirmed closed")
            self._assert_connector_shutdown(old_connector)

            await self._start_server(slots=1, port=port)
            second = await client.execute("Describe", Request(timeout_ms=5000),
                                          trusted_request_context=object())
            self.assertEqual(second.code, "OK")
            self.assertIsNot(client.channel, old_channel,
                "recovery reused the old channel instead of a fresh connection")
            self.assertIsNot(client._subchannel.connector, old_connector)
            self.assertEqual(self.controller.reserved_pending, 0)
        finally:
            new_connector = client._subchannel.connector
            await client.close()
        if new_connector is not None:
            self._assert_connector_shutdown(new_connector)

    async def test_one_slot_listener_rejects_second_incomplete_handshake(self):
        server, _authorizer = await self._start_server(slots=1)
        first = await asyncio.to_thread(_raw_tcp, "127.0.0.1", server.port)
        second = None
        try:
            await asyncio.sleep(0.2)
            second = await asyncio.to_thread(_raw_tcp, "127.0.0.1", server.port)
            rejected = await asyncio.to_thread(_wait_for_close, second, 2.0)
            self.assertTrue(rejected, "second independent incomplete handshake was not rejected")
        finally:
            first.close()
            if second is not None:
                second.close()

    async def test_two_independent_tls_connections_without_http2_preface_consume_slots(self):
        server, _authorizer = await self._start_server(slots=2)
        first = second = None
        try:
            first, second = await asyncio.gather(
                asyncio.to_thread(_tls_without_http2_preface, self.fixture, server.port),
                asyncio.to_thread(_tls_without_http2_preface, self.fixture, server.port))
            self.assertEqual(self.controller.reserved_pending, 2)
            rejected = False
            try:
                third = await asyncio.to_thread(_tls_without_http2_preface,
                                                self.fixture, server.port)
            except (OSError, ssl.SSLError, TimeoutError):
                rejected = True
            else:
                third.close()
            self.assertTrue(rejected,
                "third independent TLS connection without HTTP/2 preface was accepted")
        finally:
            for sock in (first, second):
                if sock is not None:
                    sock.close()

    async def test_four_one_slot_gates_share_the_node_pending_limit_with_outbound(self):
        servers = [await self._start_server(slots=1) for _ in range(4)]
        sockets = []
        created = []
        subchannel = _SecureSubchannel(endpoint="127.0.0.1:1",
            create_channel=lambda _connector: created.append(True), controller=self.controller,
            peer_id="outbound-peer", allowed_addresses=("127.0.0.1",),
            on_unavailable=lambda: None)
        try:
            for server, _authorizer in servers:
                sockets.append(await asyncio.to_thread(
                    _raw_tcp, "127.0.0.1", server.port))
            deadline = time.monotonic() + 2
            while self.controller.reserved_pending < 4 and time.monotonic() < deadline:
                await asyncio.sleep(0.01)
            self.assertEqual(self.controller.reserved_pending, 4)
            with self.assertRaises(SecureTransportError):
                await subchannel.get_ready(1)
            self.assertEqual(created, [], "fifth shared handshake reached channel construction")
            self.assertEqual(self.controller.reserved_pending, 4)
        finally:
            for sock in sockets:
                sock.close()
            deadline = time.monotonic() + 2
            while self.controller.reserved_pending and time.monotonic() < deadline:
                await asyncio.sleep(0.01)
            await subchannel.close()
        self.assertEqual(self.controller.reserved_pending, 0)

    async def test_gate_deadline_includes_private_uds_setup_and_connect(self):
        from unittest.mock import patch
        from steamboat_runtime.protocol import secure_transport

        server, _authorizer = await self._start_server(slots=1)
        loop = asyncio.get_running_loop()
        original_sock_connect = loop.sock_connect
        backend_setup_started = asyncio.Event()

        async def delayed_backend_connect(sock, address):
            if sock.family == socket.AF_UNIX:
                backend_setup_started.set()
                await asyncio.sleep(0.2)
            return await original_sock_connect(sock, address)

        with patch.object(loop, "sock_connect", delayed_backend_connect), \
                patch.object(secure_transport, "HANDSHAKE_TIMEOUT_SECONDS", 0.05):
            raw = await asyncio.to_thread(_raw_tcp, "127.0.0.1", server.port)
            try:
                await asyncio.wait_for(backend_setup_started.wait(), 1)
                self.assertTrue(await asyncio.to_thread(_wait_for_close, raw, 1))
                deadline = time.monotonic() + 1
                while self.controller.reserved_pending and time.monotonic() < deadline:
                    await asyncio.sleep(0.01)
                self.assertEqual(self.controller.reserved_pending, 0)
            finally:
                raw.close()

    async def test_proxy_pump_error_is_observed_without_waiting_for_stalled_sibling(self):
        from steamboat_runtime.protocol.secure_acceptor import _wait_for_proxy_pumps

        sibling_cancelled = asyncio.Event()

        async def fail_pump():
            await asyncio.sleep(0)
            raise OSError("synthetic forwarding failure")

        async def stalled_pump():
            try:
                await asyncio.Future()
            finally:
                sibling_cancelled.set()

        failed = asyncio.create_task(fail_pump())
        stalled = asyncio.create_task(stalled_pump())
        with self.assertRaisesRegex(OSError, "synthetic forwarding failure"):
            await asyncio.wait_for(_wait_for_proxy_pumps((failed, stalled)), 0.5)
        self.assertFalse(stalled.done(), "pump watcher waited for a stalled sibling")
        stalled.cancel()
        await asyncio.gather(stalled, return_exceptions=True)
        self.assertTrue(sibling_cancelled.is_set())


if __name__ == "__main__":
    unittest.main()
