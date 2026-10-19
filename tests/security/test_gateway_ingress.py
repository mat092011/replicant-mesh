from __future__ import annotations

import ssl
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from cryptography import x509

from steamboat_security.certificates import (certificate_sha256,
    generate_private_key_pem, public_key_sha256, serial_hex)
from steamboat_security.channel_certificates import (issue_channel_certificate,
    make_channel_csr)
from steamboat_security.channel_policy import sign_channel_policy
from steamboat_security.gateway_ingress import (GatewayIngressError,
    GatewayWorkerIngress)
from steamboat_security.sessions import SessionBindings
import test_gateway_delegation as delegation_tests
from test_gateway_delegation import GatewayDelegationTests, private_pem


class GatewayIngressTests(unittest.TestCase):
    def setUp(self):
        delegation_tests.NOW = int(datetime.now(timezone.utc).timestamp()) - 30
        now = delegation_tests.NOW
        self._temp_paths = []
        self.fixture = GatewayDelegationTests()
        self.fixture.setUp()
        self.worker_channel_key = generate_private_key_pem()
        worker_identity = {
            "account_id": self.fixture.payload["workers"][0]["account_id"],
            "device_id": self.fixture.payload["workers"][0]["device_id"],
            "host_serial": self.fixture.payload["workers"][0]["host_serial"],
            "credential_epoch": self.fixture.payload["workers"][0]["host_credential_epoch"],
        }
        csr = make_channel_csr(self.worker_channel_key, kind="worker_stream",
                               identity=worker_identity)
        self.worker_channel = issue_channel_certificate(
            self.fixture.gateway_ca, self.fixture.gateway_ca_key, csr,
            kind="worker_stream", identity=worker_identity,
            now=datetime.fromtimestamp(now, timezone.utc),
            lifetime_seconds=800)
        worker_cert = x509.load_pem_x509_certificate(self.worker_channel)
        payload = dict(self.fixture.payload)
        payload["revision"] = 2
        worker = dict(payload["workers"][0])
        worker.update(channel_serial=serial_hex(worker_cert.serial_number),
                      channel_certificate_sha256=certificate_sha256(worker_cert),
                      channel_public_key_sha256=public_key_sha256(worker_cert.public_key()))
        payload["workers"] = [worker]
        self.fixture.view = self.fixture.policy_store.install(
            sign_channel_policy(payload, private_pem(self.fixture.operator_key)))
        self.gateway_cert_file = None
        self.worker_cert_file = None
        self.worker_key_file = None
        self.ca_file = None
        self.ssl_object = self._make_tls_client()
        self.sessions = SessionBindings(clock=self.fixture.clock)
        self.ingress = GatewayWorkerIngress.from_tls(
            self.ssl_object, verifier=self.fixture.verifier, sessions=self.sessions,
            gateway_id="gw-east", local_worker_channel_certificate_pem=self.worker_channel)

    def tearDown(self):
        self.fixture.tearDown() if hasattr(self.fixture, "tearDown") else None
        for path in self._temp_paths:
            try:
                Path(path).unlink()
            except FileNotFoundError:
                pass

    def _write(self, data):
        file = tempfile.NamedTemporaryFile(delete=False)
        file.write(data)
        file.close()
        self._temp_paths.append(file.name)
        return file.name

    def _make_tls_client(self, hostname="gateway.example.net"):
        f = self.fixture
        self.gateway_cert_file = self._write(f.gateway_pem)
        self.worker_cert_file = self._write(self.worker_channel)
        self.worker_key_file = self._write(self.worker_channel_key)
        self.ca_file = self._write(f.gateway_ca)
        client_context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH,
                                                    cafile=self.ca_file)
        client_context.load_cert_chain(self.worker_cert_file, self.worker_key_file)
        server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server_context.verify_mode = ssl.CERT_REQUIRED
        server_context.load_cert_chain(self.gateway_cert_file,
                                       self._write(f.gateway_key))
        server_context.load_verify_locations(cafile=self.ca_file)
        ci, co, si, so = ssl.MemoryBIO(), ssl.MemoryBIO(), ssl.MemoryBIO(), ssl.MemoryBIO()
        client = client_context.wrap_bio(ci, co, server_side=False,
                                         server_hostname=hostname)
        server = server_context.wrap_bio(si, so, server_side=True)
        client_done = server_done = False
        for _ in range(20):
            if not client_done:
                try:
                    client.do_handshake()
                    client_done = True
                except (ssl.SSLWantReadError, ssl.SSLWantWriteError):
                    pass
            if co.pending:
                si.write(co.read())
            if not server_done:
                try:
                    server.do_handshake()
                    server_done = True
                except (ssl.SSLWantReadError, ssl.SSLWantWriteError):
                    pass
            if so.pending:
                ci.write(so.read())
            if client_done and server_done:
                return client
        raise AssertionError("MemoryBIO TLS handshake did not complete")

    def test_real_mutual_tls_connection_binds_policy_and_unique_generation(self):
        self.assertIs(type(self.ssl_object), ssl.SSLObject)
        self.assertFalse(self.ssl_object.server_side)
        self.assertTrue(self.ssl_object.context.check_hostname)
        self.assertEqual(self.ingress.policy_revision, 2)
        self.assertEqual(len(self.ingress.stream_generation), 32)
        self.assertEqual(self.ingress.ingress_identity[0], "gateway-v1")
        self.assertFalse(self.ingress.poll_unavailable())

    def test_wrong_endpoint_tls_handshake_is_rejected(self):
        with self.assertRaises(ssl.SSLCertVerificationError):
            self._make_tls_client("other.example.net")
            # A TLS client that does not validate the fixed gateway endpoint
            # cannot reach the ingress constructor.
            raise AssertionError("wrong endpoint unexpectedly passed TLS")

    def test_global_sequence_replay_permanently_closes_generation(self):
        with self.assertRaises(GatewayIngressError):
            self.ingress.heartbeat(self.ingress.stream_generation, 2)
        self.assertTrue(self.ingress.poll_unavailable())
        with self.assertRaises(GatewayIngressError):
            self.ingress.heartbeat(self.ingress.stream_generation, 1)

    def test_operation_guard_is_owned_and_tracks_ingress_liveness(self):
        envelope = self.fixture.make_delegation(changes={
            "policy_revision": self.ingress.policy_revision,
            "policy_digest": self.ingress.policy_digest,
            "stream_generation": self.ingress.stream_generation,
            "frame_sequence": 1,
        })
        guard = self.ingress.verify_operation(
            envelope, self.fixture.metadata, self.fixture.request, 1)
        self.assertTrue(guard.assert_live())
        self.assertGreater(guard.deadline_monotonic, self.fixture.mono)
        self.ingress.close()
        with self.assertRaises(GatewayIngressError):
            guard.assert_live()

    def test_clock_fault_permanently_retires_existing_operation_guard(self):
        envelope = self.fixture.make_delegation(changes={
            "policy_revision": self.ingress.policy_revision,
            "policy_digest": self.ingress.policy_digest,
            "stream_generation": self.ingress.stream_generation,
            "frame_sequence": 1,
        })
        guard = self.ingress.verify_operation(
            envelope, self.fixture.metadata, self.fixture.request, 1)
        self.fixture.clock._uncertainty = lambda: (_ for _ in ()).throw(
            RuntimeError("clock source unavailable"))
        with self.assertRaises(GatewayIngressError):
            guard.assert_live()
        self.fixture.clock._uncertainty = lambda: 0.0
        self.fixture.clock.revalidate_after_resume(trusted_clock=True)
        with self.assertRaises(GatewayIngressError):
            guard.assert_live()

    def test_wrong_gateway_id_and_fabricated_ssl_object_are_rejected(self):
        with self.assertRaises(GatewayIngressError):
            GatewayWorkerIngress.from_tls(
                self.ssl_object, verifier=self.fixture.verifier,
                sessions=self.sessions, gateway_id="gw-other",
                local_worker_channel_certificate_pem=self.worker_channel)
        with self.assertRaises(TypeError):
            GatewayWorkerIngress.from_tls(
                object(), verifier=self.fixture.verifier, sessions=self.sessions,
                gateway_id="gw-east",
                local_worker_channel_certificate_pem=self.worker_channel)

    def test_one_tls_object_cannot_mint_multiple_stream_generations(self):
        with self.assertRaises(GatewayIngressError):
            GatewayWorkerIngress.from_tls(
                self.ssl_object, verifier=self.fixture.verifier,
                sessions=self.sessions, gateway_id="gw-east",
                local_worker_channel_certificate_pem=self.worker_channel)

    def test_old_generation_close_does_not_close_replacement_connection(self):
        replacement_tls = self._make_tls_client()
        replacement = GatewayWorkerIngress.from_tls(
            replacement_tls, verifier=self.fixture.verifier,
            sessions=self.sessions, gateway_id="gw-east",
            local_worker_channel_certificate_pem=self.worker_channel)
        self.assertNotEqual(self.ingress.stream_generation,
                            replacement.stream_generation)
        self.ingress.close()
        self.assertFalse(replacement.poll_unavailable())

    def test_policy_refresh_retires_existing_tls_generation(self):
        replacement = dict(self.fixture.payload)
        replacement["revision"] = 3
        self.fixture.policy_store.install(sign_channel_policy(
            replacement, private_pem(self.fixture.operator_key)))
        self.assertTrue(self.ingress.poll_unavailable())
        self.assertTrue(self.ingress._state.closed)


if __name__ == "__main__":
    unittest.main()
