from __future__ import annotations

import ssl
import unittest
import json
import os
import shutil
from datetime import datetime, timezone
from dataclasses import replace
from unittest.mock import patch

from cryptography import x509

from steamboat_security.certificates import (certificate_sha256, generate_ca,
    generate_private_key_pem, public_key_sha256, serial_hex)
from steamboat_security.channel_certificates import make_channel_csr, issue_channel_certificate
from steamboat_security.channel_tls import OwnedWorkerTLS, OwnedWorkerTLSError
from steamboat_security.channel_policy import sign_channel_policy
from steamboat_security.gateway_tls import (AuthenticatedWorkerChannel,
    GatewayWorkerTLSError, OwnedGatewayWorkerTLS, is_authenticated_worker_channel)
from tests.security import test_gateway_ingress as ingress_tests


class GatewayServerTLSOwnerTests(unittest.TestCase):
    def setUp(self):
        self.fixture = ingress_tests.GatewayIngressTests()
        self.fixture.setUp()
        self.f = self.fixture.fixture
        self.client = OwnedWorkerTLS.connect(
            worker_certificate_pem=self.fixture.worker_channel,
            worker_private_key_pem=self.fixture.worker_channel_key,
            gateway_ca_pem=self.f.gateway_ca,
            endpoint_host="gateway.example.net", endpoint_port=443,
            clock=self.f.clock)
        self.server = OwnedGatewayWorkerTLS.accept(
            gateway_certificate_pem=self.f.gateway_pem,
            gateway_private_key_pem=self.f.gateway_key,
            cohort_ca_pem=self.f.gateway_ca, policy_store=self.f.policy_store,
            clock=self.f.clock, gateway_id="gw-east")
        self._handshake()

    def tearDown(self):
        if hasattr(self, "client"):
            self.client.close()
        if hasattr(self, "server"):
            self.server.close()
        self.fixture.tearDown()

    def _handshake(self):
        for _ in range(40):
            outgoing = self.client.take_encrypted()
            if outgoing:
                self.server.feed_encrypted(outgoing)
            outgoing = self.server.take_encrypted()
            if outgoing:
                self.client.feed_encrypted(outgoing)
            if self.client.handshake_complete and self.server.handshake_complete:
                return
        self.fail("MemoryBIO mutual TLS handshake did not complete")

    def _new_gateway_credential(self, host, *, san_dns=(), san_ips=()):
        key = generate_private_key_pem()
        cert_pem = issue_channel_certificate(
            self.f.gateway_ca, self.f.gateway_ca_key,
            make_channel_csr(key, kind="gateway", identity="gw-east",
                             dns_names=san_dns, ip_addresses=san_ips),
            kind="gateway", identity="gw-east",
            now=datetime.fromtimestamp(ingress_tests.delegation_tests.NOW - 20,
                                       timezone.utc),
            lifetime_seconds=600, dns_names=san_dns, ip_addresses=san_ips)
        cert = x509.load_pem_x509_certificate(cert_pem)
        policy = json.loads(self.f.policy_store.current().canonical_payload)
        policy["revision"] += 1
        gateway = policy["gateways"][0]
        gateway.update(
            serial=serial_hex(cert.serial_number),
            certificate_sha256=certificate_sha256(cert),
            public_key_sha256=public_key_sha256(cert.public_key()),
            endpoint_host=host)
        signed = sign_channel_policy(
            policy, ingress_tests.delegation_tests.private_pem(self.f.operator_key))
        self.f.policy_store.install(signed)
        return cert_pem, key

    def _replace_connection_for_gateway(self, host, cert_pem, key_pem):
        self.server.close()
        self.client.close()
        self.server = OwnedGatewayWorkerTLS.accept(
            gateway_certificate_pem=cert_pem, gateway_private_key_pem=key_pem,
            cohort_ca_pem=self.f.gateway_ca, policy_store=self.f.policy_store,
            clock=self.f.clock, gateway_id="gw-east")
        self.client = OwnedWorkerTLS.connect(
            worker_certificate_pem=self.fixture.worker_channel,
            worker_private_key_pem=self.fixture.worker_channel_key,
            gateway_ca_pem=self.f.gateway_ca, endpoint_host=host,
            endpoint_port=443, clock=self.f.clock)
        self._handshake()

    def test_real_cert_required_pair_mints_policy_bound_channel(self):
        channel = self.server.authenticated_channel
        self.assertIs(type(channel), AuthenticatedWorkerChannel)
        self.assertTrue(is_authenticated_worker_channel(channel))
        self.assertEqual(channel.device_id, self.fixture.fixture.payload["workers"][0]["device_id"])
        self.assertEqual(channel.gateway_id, "gw-east")
        self.assertEqual(channel.policy_revision, self.f.policy_store.current().revision)
        self.assertGreater(sum(self.server.byte_counts), 0)
        channel.assert_live()

    def test_handshake_deadline_only_applies_until_handshake_completes(self):
        self.f.mono += 10.001
        self.f.wall += 10.001
        self.client.write_plaintext(b"request")
        self.server.feed_encrypted(self.client.take_encrypted())
        self.assertEqual(self.server.read_plaintext(), b"request")
        self.assertTrue(self.server.is_live)

    def test_ipv4_endpoint_uses_ip_san_validation(self):
        host = "192.0.2.77"
        cert, key = self._new_gateway_credential(host, san_ips=(host,))
        self._replace_connection_for_gateway(host, cert, key)
        self.assertTrue(self.server.handshake_complete)
        self.assertTrue(self.server.is_live)

    def test_ipv6_endpoint_uses_ip_san_validation(self):
        host = "2001:db8::77"
        cert, key = self._new_gateway_credential(host, san_ips=(host,))
        self._replace_connection_for_gateway(host, cert, key)
        self.assertTrue(self.server.handshake_complete)
        self.assertTrue(self.server.is_live)

    def test_ip_endpoint_rejects_wrong_ip_san(self):
        host = "192.0.2.77"
        cert, key = self._new_gateway_credential(
            host, san_ips=("192.0.2.78",))
        self.server.close()
        with self.assertRaises(GatewayWorkerTLSError):
            OwnedGatewayWorkerTLS.accept(
                gateway_certificate_pem=cert, gateway_private_key_pem=key,
                cohort_ca_pem=self.f.gateway_ca, policy_store=self.f.policy_store,
                clock=self.f.clock, gateway_id="gw-east")

    def test_absent_client_certificate_is_rejected_by_server_context(self):
        server = OwnedGatewayWorkerTLS.accept(
            gateway_certificate_pem=self.f.gateway_pem,
            gateway_private_key_pem=self.f.gateway_key,
            cohort_ca_pem=self.f.gateway_ca, policy_store=self.f.policy_store,
            clock=self.f.clock, gateway_id="gw-east")
        client_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        client_context.check_hostname = False
        client_context.verify_mode = ssl.CERT_NONE
        ci, co = ssl.MemoryBIO(), ssl.MemoryBIO()
        client = client_context.wrap_bio(ci, co, server_side=False)
        try:
            self.assertTrue(self.server.handshake_complete)
            rejected = False
            for _ in range(20):
                try:
                    client.do_handshake()
                except (ssl.SSLWantReadError, ssl.SSLWantWriteError):
                    pass
                except ssl.SSLError:
                    rejected = True
                    break
                if co.pending:
                    try:
                        server.feed_encrypted(co.read())
                    except GatewayWorkerTLSError:
                        rejected = True
                        break
                try:
                    server.do_handshake()
                except GatewayWorkerTLSError:
                    rejected = True
                    break
                response = server.take_encrypted()
                if response:
                    ci.write(response)
                if server.handshake_complete:
                    break
            self.assertTrue(rejected, "CERT_REQUIRED server accepted an absent client cert")
            self.assertFalse(server.handshake_complete)
            self.assertFalse(server.is_live)
            with self.assertRaises(GatewayWorkerTLSError):
                _ = server.authenticated_channel
        finally:
            server.close()

    def test_policy_refresh_retires_established_connection(self):
        payload = dict(self.f.payload)
        payload["revision"] = self.f.policy_store.current().revision + 1
        self.f.policy_store.install(ingress_tests.sign_channel_policy(
            payload, ingress_tests.delegation_tests.private_pem(self.f.operator_key)))
        self.assertTrue(self.server.poll_unavailable())
        self.assertFalse(self.server.is_live)
        with self.assertRaises(GatewayWorkerTLSError):
            self.server.authenticated_channel

    def test_unpinned_but_well_formed_worker_certificate_cannot_mint_channel(self):
        identity = {
            "account_id": self.f.payload["workers"][0]["account_id"],
            "device_id": "dev_" + "a" * 32,
            "host_serial": self.f.payload["workers"][0]["host_serial"],
            "credential_epoch": self.f.payload["workers"][0]["host_credential_epoch"],
        }
        key = generate_private_key_pem()
        csr = make_channel_csr(key, kind="worker_stream", identity=identity)
        cert = issue_channel_certificate(
            self.f.gateway_ca, self.f.gateway_ca_key, csr, kind="worker_stream",
            identity=identity, now=datetime.fromtimestamp(
                ingress_tests.delegation_tests.NOW, timezone.utc), lifetime_seconds=700)
        server = OwnedGatewayWorkerTLS.accept(
            gateway_certificate_pem=self.f.gateway_pem,
            gateway_private_key_pem=self.f.gateway_key,
            cohort_ca_pem=self.f.gateway_ca, policy_store=self.f.policy_store,
            clock=self.f.clock, gateway_id="gw-east")
        client = OwnedWorkerTLS.connect(
            worker_certificate_pem=cert, worker_private_key_pem=key,
            gateway_ca_pem=self.f.gateway_ca, endpoint_host="gateway.example.net",
            endpoint_port=443, clock=self.f.clock)
        try:
            rejected = False
            for _ in range(30):
                try:
                    data = client.take_encrypted()
                    if data:
                        server.feed_encrypted(data)
                    data = server.take_encrypted()
                    if data:
                        client.feed_encrypted(data)
                except (GatewayWorkerTLSError, OwnedWorkerTLSError):
                    rejected = True
                    break
                if server.handshake_complete:
                    break
            self.assertTrue(rejected or not server.handshake_complete)
            self.assertFalse(server.is_live)
            with self.assertRaises(GatewayWorkerTLSError):
                _ = server.authenticated_channel
        finally:
            server.close()
            client.close()

    def test_gateway_private_key_must_match_policy_pinned_certificate(self):
        with self.assertRaises(GatewayWorkerTLSError):
            OwnedGatewayWorkerTLS.accept(
                gateway_certificate_pem=self.f.gateway_pem,
                gateway_private_key_pem=generate_private_key_pem(),
                cohort_ca_pem=self.f.gateway_ca, policy_store=self.f.policy_store,
                clock=self.f.clock, gateway_id="gw-east")

    def test_uncertain_credential_cleanup_is_reported_without_retry(self):
        original_rmtree = shutil.rmtree
        with patch("steamboat_security.gateway_tls.shutil.rmtree",
                   side_effect=PermissionError("injected cleanup failure")) as remove:
            with self.assertRaises(GatewayWorkerTLSError) as raised:
                OwnedGatewayWorkerTLS.accept(
                    gateway_certificate_pem=self.f.gateway_pem,
                    gateway_private_key_pem=self.f.gateway_key,
                    cohort_ca_pem=self.f.gateway_ca, policy_store=self.f.policy_store,
                    clock=self.f.clock, gateway_id="gw-east")
        self.assertEqual(remove.call_count, 1)
        self.assertEqual(raised.exception.cleanup_status, "uncertain")
        path = raised.exception.credential_directory
        self.assertTrue(path)
        self.assertTrue(os.path.isdir(path))
        original_rmtree(path)

    def test_worker_certificate_from_another_ca_is_rejected_by_cert_required_server(self):
        identity = {
            "account_id": self.f.payload["workers"][0]["account_id"],
            "device_id": self.f.payload["workers"][0]["device_id"],
            "host_serial": self.f.payload["workers"][0]["host_serial"],
            "credential_epoch": self.f.payload["workers"][0]["host_credential_epoch"],
        }
        foreign_ca, foreign_key = generate_ca(
            common_name="foreign test CA", now=ingress_tests.delegation_tests.NOW)
        key = generate_private_key_pem()
        cert = issue_channel_certificate(
            foreign_ca, foreign_key,
            make_channel_csr(key, kind="worker_stream", identity=identity),
            kind="worker_stream", identity=identity,
            now=datetime.fromtimestamp(ingress_tests.delegation_tests.NOW, timezone.utc),
            lifetime_seconds=700)
        server = OwnedGatewayWorkerTLS.accept(
            gateway_certificate_pem=self.f.gateway_pem,
            gateway_private_key_pem=self.f.gateway_key,
            cohort_ca_pem=self.f.gateway_ca, policy_store=self.f.policy_store,
            clock=self.f.clock, gateway_id="gw-east")
        client = OwnedWorkerTLS.connect(
            worker_certificate_pem=cert, worker_private_key_pem=key,
            gateway_ca_pem=self.f.gateway_ca, endpoint_host="gateway.example.net",
            endpoint_port=443, clock=self.f.clock)
        try:
            with self.assertRaises((GatewayWorkerTLSError, OwnedWorkerTLSError)):
                for _ in range(20):
                    data = client.take_encrypted()
                    if data:
                        server.feed_encrypted(data)
                    data = server.take_encrypted()
                    if data:
                        client.feed_encrypted(data)
            self.assertFalse(server.handshake_complete)
            with self.assertRaises(GatewayWorkerTLSError):
                _ = server.authenticated_channel
        finally:
            server.close()
            client.close()

    def test_clock_fault_after_handshake_is_sticky(self):
        self.f.clock._uncertainty = lambda: (_ for _ in ()).throw(
            RuntimeError("clock source unavailable"))
        self.assertTrue(self.server.poll_unavailable())
        self.f.clock._uncertainty = lambda: 0.0
        self.f.clock.revalidate_after_resume(trusted_clock=True)
        self.assertFalse(self.server.is_live)
        with self.assertRaises(GatewayWorkerTLSError):
            self.server.authenticated_channel

    def test_policy_and_certificate_expiry_retire_established_channel(self):
        self.f.mono += 301
        self.f.wall += 301
        self.assertTrue(self.server.poll_unavailable())
        self.assertFalse(self.server.is_live)
        with self.assertRaises(GatewayWorkerTLSError):
            self.server.authenticated_channel

    def test_worker_certificate_expiry_is_clipped_on_each_uncertain_sample(self):
        identity = {
            "account_id": self.f.payload["workers"][0]["account_id"],
            "device_id": self.f.payload["workers"][0]["device_id"],
            "host_serial": self.f.payload["workers"][0]["host_serial"],
            "credential_epoch": self.f.payload["workers"][0]["host_credential_epoch"],
        }
        key = generate_private_key_pem()
        cert_pem = issue_channel_certificate(
            self.f.gateway_ca, self.f.gateway_ca_key,
            make_channel_csr(key, kind="worker_stream", identity=identity),
            kind="worker_stream", identity=identity,
            now=datetime.fromtimestamp(ingress_tests.delegation_tests.NOW - 20,
                                       timezone.utc), lifetime_seconds=100)
        cert = x509.load_pem_x509_certificate(cert_pem)
        policy = json.loads(self.f.policy_store.current().canonical_payload)
        policy["revision"] += 1
        worker = policy["workers"][0]
        worker.update(channel_serial=serial_hex(cert.serial_number),
                      channel_certificate_sha256=certificate_sha256(cert),
                      channel_public_key_sha256=public_key_sha256(cert.public_key()))
        self.f.policy_store.install(sign_channel_policy(
            policy, ingress_tests.delegation_tests.private_pem(self.f.operator_key)))
        self.server.close()
        self.client.close()
        self.server = OwnedGatewayWorkerTLS.accept(
            gateway_certificate_pem=self.f.gateway_pem,
            gateway_private_key_pem=self.f.gateway_key,
            cohort_ca_pem=self.f.gateway_ca, policy_store=self.f.policy_store,
            clock=self.f.clock, gateway_id="gw-east")
        self.client = OwnedWorkerTLS.connect(
            worker_certificate_pem=cert_pem, worker_private_key_pem=key,
            gateway_ca_pem=self.f.gateway_ca, endpoint_host="gateway.example.net",
            endpoint_port=443, clock=self.f.clock)
        self._handshake()
        channel = self.server.authenticated_channel
        self.assertGreater(channel.deadline_monotonic, self.f.mono)

        self.f.mono += 60
        self.f.wall += 60
        self.f.uncertainty = 30
        self.assertTrue(self.server.poll_unavailable())
        self.f.uncertainty = 0
        self.assertFalse(self.server.is_live)
        with self.assertRaises(GatewayWorkerTLSError):
            channel.assert_live()

    def test_owner_close_invalidates_channel_and_cannot_be_reopened(self):
        channel = self.server.authenticated_channel
        copy = replace(channel)
        self.assertFalse(is_authenticated_worker_channel(copy))
        with self.assertRaises(GatewayWorkerTLSError):
            copy.assert_live()
        self.server.close()
        self.assertFalse(self.server.is_live)
        with self.assertRaises(GatewayWorkerTLSError):
            channel.assert_live()
        with self.assertRaises(GatewayWorkerTLSError):
            self.server.do_handshake()


if __name__ == "__main__":
    unittest.main()
