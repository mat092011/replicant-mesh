"""Two-hop outbound gateway route checks over real MemoryBIO TLS."""

from __future__ import annotations

import ssl
import tempfile
import time
import unittest
from unittest import mock
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from tests.security import test_identity_core as identity_tests
from tests.security import test_outbound_authorization as outbound_tests
from steamboat_runtime.participant_context import TrustedRequestContext
from steamboat_security.authorization import LocalIdentity
from steamboat_security.certificates import (certificate_sha256, generate_ca,
    generate_private_key_pem, issue_leaf, public_key_sha256, serial_hex)
from steamboat_security.channel_certificates import (issue_channel_certificate,
    make_channel_csr)
from steamboat_security.channel_policy import ChannelPolicyStore, sign_channel_policy
from steamboat_security.gateway_egress import (GatewayCoordinatorEgress,
    GatewayEgressError, GatewayRouteGuard)
from steamboat_security.outbound import (BootstrapContext, OutboundAuthorizer,
    OutboundTarget)
from steamboat_security.channel_tls import OwnedWorkerTLSError
from steamboat_security.errors import BindingError, CredentialError, ScopeError, SessionError
from steamboat_security.codec import WORKER_SERVICE


def _private_pem(key):
    return key.private_bytes(serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8, serialization.NoEncryption())


def _public_pem(key):
    return key.public_key().public_bytes(serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo)


class GatewayEgressTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        identity_tests.IdentityFixture.setUpClass()

    def setUp(self):
        self._prior_now = identity_tests.NOW
        now = int(time.time())
        identity_tests.NOW = now
        self.fx = identity_tests.IdentityFixture("runTest")
        self.fx.ca_pem, self.fx.ca_key = generate_ca(now=now - 3600)
        for name, (account, device, role, _boot, ekus, _dns) in self.fx.identities.items():
            entry = self.fx.credentials[name]
            cert = issue_leaf(self.fx.ca_pem, self.fx.ca_key, entry["csr"],
                account_id=account, device_id=device, role=role,
                not_before=now - 60, not_after=now + 700, ekus=ekus)
            entry["certificate"] = cert
            entry["record"] = identity_tests._record_from_leaf(
                cert, account_id=account, device_id=device, role=role,
                credential_epoch=1)
            self.fx.records[name] = entry["record"]
        self.time_source = identity_tests.FakeTime(wall=now, monotonic=time.monotonic())
        self.clock = self.time_source.clock()
        from steamboat_security.snapshot import SnapshotStore
        from steamboat_security.snapshot import sign_snapshot
        self.snapshot_store = SnapshotStore(
            verification_key_pem=self.fx.signing_public,
            ca_certificate_pem=self.fx.ca_pem, clock=self.clock)
        self.snapshot_store.install(sign_snapshot(
            self.fx.payload(now=now, expiry=now + 300,
                            grants=self.fx.grants(expires=now + 300)),
            self.fx.signing_key))
        self.gateway_ca, self.gateway_ca_key = generate_ca(
            now=identity_tests.NOW - 3600)
        self.gateway_key = generate_private_key_pem()
        csr = make_channel_csr(self.gateway_key, kind="gateway",
            identity="gw-east", dns_names=("worker.gateway.example",
                                            "coordinator.gateway.example"))
        self.gateway_cert = issue_channel_certificate(
            self.gateway_ca, self.gateway_ca_key, csr, kind="gateway",
            identity="gw-east", now=datetime.fromtimestamp(
                identity_tests.NOW - 30, timezone.utc), lifetime_seconds=350,
            dns_names=("worker.gateway.example", "coordinator.gateway.example"))
        gateway = x509.load_pem_x509_certificate(self.gateway_cert)
        actor = self.fx.records["coordinator"]
        host = self.fx.records["host"]
        self.policy_key = ec.generate_private_key(ec.SECP256R1())
        self.policy_store = ChannelPolicyStore(
            _public_pem(self.policy_key), clock=self.clock,
            durable_commit=lambda *_: None)
        self.policy_payload = {
            "version": 2, "revision": 1,
            "issued_at": identity_tests.NOW,
            "expires_at": identity_tests.NOW + 300,
            "gateways": [{
                "gateway_id": "gw-east", "serial": serial_hex(gateway.serial_number),
                "certificate_sha256": certificate_sha256(gateway),
                "public_key_sha256": public_key_sha256(gateway.public_key()),
                "not_before": identity_tests.NOW - 30,
                "not_after": identity_tests.NOW + 320,
                "endpoint_host": "worker.gateway.example", "endpoint_port": 443,
                "coordinator_endpoint_host": "coordinator.gateway.example",
                "coordinator_endpoint_port": 444,
            }],
            "workers": [{
                "account_id": host["account_id"], "device_id": host["device_id"],
                "host_serial": host["serial"],
                "host_credential_epoch": host["credential_epoch"],
                "host_certificate_sha256": host["certificate_sha256"],
                "worker_boot_id": identity_tests.BOOT_HOST,
                "assignment_id": identity_tests.ASSIGNMENT,
                "model_id": identity_tests.MODEL,
                "channel_serial": "ab14", "channel_certificate_sha256": "7" * 64,
                "channel_public_key_sha256": "8" * 64,
                "not_before": identity_tests.NOW,
                "not_after": identity_tests.NOW + 300, "gateway_id": "gw-east",
            }],
            "routes": [{
                "gateway_id": "gw-east", "account_id": actor["account_id"],
                "device_id": actor["device_id"], "actor_serial": actor["serial"],
                "actor_credential_epoch": actor["credential_epoch"],
                "actor_certificate_sha256": actor["certificate_sha256"],
                "coordinator_boot_id": identity_tests.BOOT_COORDINATOR,
                "tenant_account_id": actor["account_id"],
                "target_device_id": host["device_id"],
                "worker_boot_id": identity_tests.BOOT_HOST,
                "assignment_id": identity_tests.ASSIGNMENT,
                "model_id": identity_tests.MODEL,
                "methods": ["CloseSession", "Describe", "OpenSession", "Step"],
            }],
        }
        self._install_policy()
        local = LocalIdentity(self.fx.credentials["coordinator"]["certificate"],
                              identity_tests.BOOT_COORDINATOR, identity_tests.MODEL)
        target = OutboundTarget.from_record(
            service=WORKER_SERVICE, record=host,
            boot_id=identity_tests.BOOT_HOST, model_id=identity_tests.MODEL,
            assignment_id=identity_tests.ASSIGNMENT)
        self.adapter = OutboundAuthorizer(
            local_identity=local, snapshot_store=self.snapshot_store,
            clock=self.clock, target=target,
            worker_request_type=outbound_tests.ParsedWorkerRequest,
            trusted_request_context_type=TrustedRequestContext,
            allow_bootstrap_describe=True)
        self.context = self._make_context()
        self.server, self.client_temp = self._make_server()
        self.egress = GatewayCoordinatorEgress.connect(
            authorizer=self.adapter, policy_store=self.policy_store,
            logical_host_certificate_pem=self.fx.credentials["host"]["certificate"],
            gateway_id="gw-east", gateway_ca_pem=self.gateway_ca,
            coordinator_private_key_pem=self.fx.credentials["coordinator"]["key"])
        self.addCleanup(self._cleanup)
        self._finish_handshake()

    def tearDown(self):
        identity_tests.NOW = self._prior_now
        self.fx.doCleanups()

    def _install_policy(self):
        self.policy_store.install(sign_channel_policy(
            self.policy_payload, _private_pem(self.policy_key)))

    def _make_context(self, *, hard_lifetime=3600):
        authorizer, _ = self.fx.coordinator_authorizer(
            time_source=self.time_source, store=self.snapshot_store)
        request_id = "req_" + "1" * 32
        fields = {"binding_version": 1, "operation_id": "op_" + "1" * 32,
                  "account_id": identity_tests.ACCOUNT_A,
                  "device_id": identity_tests.DEVICE_CONSUMER,
                  "role": "consumer", "credential_epoch": 1,
                  "target_device_id": identity_tests.DEVICE_COORDINATOR,
                  "request_id": request_id}
        authorization = authorizer.authorize(
            "steamboat.v1.Coordinator", "Generate",
            {"input_ids": [1], "new_tokens": 1, "timeout_seconds": 20,
             "capture_logits": False}, self.fx.metadata(
                "steamboat.v1.Coordinator", "Generate", fields),
            self.fx.credentials["consumer"]["certificate"])
        return TrustedRequestContext(
            tenant_account_id=identity_tests.ACCOUNT_A, request_id=request_id,
            session_id="ses_" + "2" * 32, route_id="route_" + "3" * 32,
            coordinator_boot_id=identity_tests.BOOT_COORDINATOR,
            route_epoch=1, attempt=1, authorization=authorization,
            hard_monotonic_deadline=time.monotonic() + hard_lifetime)

    def _make_server(self, certificate=None, private_key=None):
        paths = []
        def write(data):
            with tempfile.NamedTemporaryFile(delete=False) as stream:
                stream.write(data)
                paths.append(stream.name)
                return stream.name
        cert_path = write(certificate or self.gateway_cert)
        key_path = write(private_key or self.gateway_key)
        ca_path = write(self.fx.ca_pem)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.verify_mode = ssl.CERT_REQUIRED
        context.load_cert_chain(cert_path, key_path)
        context.load_verify_locations(cafile=ca_path)
        incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
        server = context.wrap_bio(incoming, outgoing, server_side=True)
        return (server, (incoming, outgoing, paths))

    def _finish_handshake(self, egress=None, server=None, client_temp=None):
        egress = egress or self.egress
        server = server or self.server
        client_temp = client_temp or self.client_temp
        incoming, outgoing, _paths = client_temp
        complete = False
        for _ in range(32):
            data = egress.take_encrypted()
            if data:
                incoming.write(data)
            try:
                server.do_handshake()
                complete = True
            except (ssl.SSLWantReadError, ssl.SSLWantWriteError):
                pass
            response = outgoing.read() if outgoing.pending else b""
            if response:
                egress.feed_encrypted(response)
            if complete and egress.handshake_complete:
                break
        self.assertTrue(complete)
        self.assertTrue(egress.handshake_complete)
        self.assertEqual(server.getpeercert(binary_form=True),
            x509.load_pem_x509_certificate(
                self.fx.credentials["coordinator"]["certificate"]).public_bytes(
                    serialization.Encoding.DER))

    def _cleanup(self):
        if hasattr(self, "egress"):
            self.egress.close()
        if hasattr(self, "client_temp"):
            for path in self.client_temp[2]:
                Path(path).unlink(missing_ok=True)

    def _open_payload(self):
        return outbound_tests.ParsedWorkerRequest(
            protocol_version=1, manifest_fingerprint=identity_tests.MODEL,
            worker_boot_id=identity_tests.BOOT_HOST, session_id=self.context.session_id,
            timeout_ms=5_000, sequence=0, start_position=0, token_count=0,
            lease_token="", max_positions=32, lifetime_ms=20_000, idle_lease_ms=10_000)

    def test_route_guard_reuses_c1_scope_and_checks_live_gateway_on_completion(self):
        self.assertEqual(self.egress._tls.endpoint_host,
                         "coordinator.gateway.example")
        self.assertEqual(self.egress._tls.endpoint_port, 444)
        guard = self.egress.mint_route_guard(
            method="OpenSession", trusted_request_context=self.context)
        auth = self.adapter.authorize_gateway_outbound(
            WORKER_SERVICE, "OpenSession", self._open_payload(), self.context,
            gateway_route=guard)
        self.assertIs(type(guard), GatewayRouteGuard)
        self.assertTrue(auth.assert_live())
        fields = outbound_tests.OutboundAuthorizationTests.binding_fields(
            auth.binding_bytes, WORKER_SERVICE, "OpenSession")
        self.assertEqual(fields["assignment_id"], identity_tests.ASSIGNMENT)
        response = outbound_tests.ParsedWorkerResponse(
            protocol_version=1, manifest_fingerprint=identity_tests.MODEL,
            worker_boot_id=identity_tests.BOOT_HOST, session_id=self.context.session_id,
            lease_token="lease_0123456789", code="OK")
        with self.assertRaises(BindingError):
            auth.complete(outbound_tests.ParsedWorkerResponse(
                protocol_version=1, manifest_fingerprint=identity_tests.MODEL,
                worker_boot_id=identity_tests.BOOT_HOST,
                session_id="ses_" + "8" * 32,
                lease_token="lease_0123456789", code="OK"))
        auth.complete(response)
        self.egress.close()
        with self.assertRaises(GatewayEgressError):
            auth.assert_live()

    def test_route_guard_is_single_use_context_method_and_deadline_bound(self):
        with self.assertRaises(GatewayEgressError):
            self.egress.mint_route_guard(
                method="CancelSession", trusted_request_context=self.context)
        guard = self.egress.mint_route_guard(
            method="OpenSession", trusted_request_context=self.context)
        with self.assertRaises(AttributeError):
            guard.deadline_monotonic = float("inf")
        with self.assertRaises(GatewayEgressError):
            self.adapter.authorize_gateway_outbound(
                WORKER_SERVICE, "Step", self._open_payload(), self.context,
                gateway_route=guard)
        auth = self.adapter.authorize_gateway_outbound(
            WORKER_SERVICE, "OpenSession", self._open_payload(), self.context,
            gateway_route=guard)
        with self.assertRaises(GatewayEgressError):
            self.adapter.authorize_gateway_outbound(
                WORKER_SERVICE, "OpenSession", self._open_payload(), self.context,
                gateway_route=guard)
        self.time_source.advance(301)
        with self.assertRaises(GatewayEgressError):
            auth.assert_live()

    def test_wrong_logical_host_and_policy_worker_pin_are_rejected(self):
        wrong_host_egress = GatewayCoordinatorEgress.connect(
            authorizer=self.adapter, policy_store=self.policy_store,
            logical_host_certificate_pem=self.fx.credentials["consumer"]["certificate"],
            gateway_id="gw-east", gateway_ca_pem=self.gateway_ca,
            coordinator_private_key_pem=self.fx.credentials["coordinator"]["key"])
        server, temporary = self._make_server()
        try:
            self._finish_handshake(wrong_host_egress, server, temporary)
            with self.assertRaises(GatewayEgressError):
                wrong_host_egress.mint_route_guard(
                    method="OpenSession", trusted_request_context=self.context)
        finally:
            wrong_host_egress.close()
            for path in temporary[2]:
                Path(path).unlink(missing_ok=True)
        target = replace(self.adapter.target, certificate_sha256="0" * 64)
        wrong = OutboundAuthorizer(
            local_identity=self.adapter.local_identity,
            snapshot_store=self.snapshot_store, clock=self.clock, target=target,
            worker_request_type=outbound_tests.ParsedWorkerRequest,
            trusted_request_context_type=TrustedRequestContext)
        with self.assertRaises(GatewayEgressError):
            GatewayCoordinatorEgress.connect(
                authorizer=wrong, policy_store=self.policy_store,
                logical_host_certificate_pem=self.fx.credentials["host"]["certificate"],
                gateway_id="gw-east", gateway_ca_pem=self.gateway_ca,
                coordinator_private_key_pem=self.fx.credentials["coordinator"]["key"])

    def test_wrong_gateway_leaf_wrong_context_and_clock_fault_fail_closed(self):
        wrong_key = generate_private_key_pem()
        wrong_csr = make_channel_csr(wrong_key, kind="gateway",
            identity="gw-west", dns_names=("worker.gateway.example",
                                            "coordinator.gateway.example"))
        wrong_cert = issue_channel_certificate(
            self.gateway_ca, self.gateway_ca_key, wrong_csr, kind="gateway",
            identity="gw-west", now=datetime.fromtimestamp(
                identity_tests.NOW - 30, timezone.utc), lifetime_seconds=350,
            dns_names=("worker.gateway.example", "coordinator.gateway.example"))
        wrong_egress = GatewayCoordinatorEgress.connect(
            authorizer=self.adapter, policy_store=self.policy_store,
            logical_host_certificate_pem=self.fx.credentials["host"]["certificate"],
            gateway_id="gw-east", gateway_ca_pem=self.gateway_ca,
            coordinator_private_key_pem=self.fx.credentials["coordinator"]["key"])
        server, temporary = self._make_server(wrong_cert, wrong_key)
        try:
            with self.assertRaises(GatewayEgressError):
                self._finish_handshake(wrong_egress, server, temporary)
        finally:
            wrong_egress.close()
            for path in temporary[2]:
                Path(path).unlink(missing_ok=True)

        wrong_context = TrustedRequestContext(
            tenant_account_id=identity_tests.ACCOUNT_B,
            request_id=self.context.request_id, session_id=self.context.session_id,
            route_id=self.context.route_id,
            coordinator_boot_id=identity_tests.BOOT_COORDINATOR,
            route_epoch=1, attempt=1, authorization=self.context.authorization,
            hard_monotonic_deadline=self.context.hard_monotonic_deadline)
        with self.assertRaises(ScopeError):
            self.egress.mint_route_guard(
                method="OpenSession", trusted_request_context=wrong_context)
        guard = self.egress.mint_route_guard(
            method="OpenSession", trusted_request_context=self.context)
        self.time_source.uncertainty = float("inf")
        with self.assertRaises(GatewayEgressError):
            guard.assert_live()
        self.assertTrue(self.egress._faulted)

    def test_c1_snapshot_revocation_invalidates_gateway_authorization(self):
        guard = self.egress.mint_route_guard(
            method="OpenSession", trusted_request_context=self.context)
        auth = self.adapter.authorize_gateway_outbound(
            WORKER_SERVICE, "OpenSession", self._open_payload(), self.context,
            gateway_route=guard)
        revoked = self.fx.records["coordinator"]["serial"]
        records = [record for record in self.fx.records.values()
                   if record["serial"] != revoked]
        grants = [grant for grant in self.fx.grants(expires=identity_tests.NOW + 300)
                  if grant["actor_serial"] != revoked
                  and grant["target_serial"] != revoked]
        self.snapshot_store.install(__import__(
            "steamboat_security.snapshot", fromlist=["sign_snapshot"]).sign_snapshot(
                self.fx.payload(now=identity_tests.NOW, revision=2,
                    records=records, grants=grants, revoked_serials=[revoked],
                    expiry=identity_tests.NOW + 300), self.fx.signing_key))
        with self.assertRaises(CredentialError):
            auth.assert_live()

    def test_fabricated_guard_direct_gateway_peer_and_policy_replacement_reject(self):
        with self.assertRaises(ScopeError):
            self.adapter.authorize_gateway_outbound(
                WORKER_SERVICE, "OpenSession", self._open_payload(), self.context,
                gateway_route=object())
        with self.assertRaises(CredentialError):
            self.adapter.authorize_outbound(
                service=WORKER_SERVICE, method="OpenSession",
                payload=self._open_payload(), trusted_request_context=self.context,
                peer_certificate_pem=self.gateway_cert)
        payload = dict(self.policy_payload)
        payload["revision"] = 2
        payload["expires_at"] = identity_tests.NOW + 290
        self.policy_store.install(sign_channel_policy(payload, _private_pem(self.policy_key)))
        with self.assertRaises(GatewayEgressError):
            self.egress.mint_route_guard(
                method="OpenSession", trusted_request_context=self.context)

    def test_established_cipher_io_rechecks_policy_and_expires_connection(self):
        self.egress.write_plaintext(b"queued authenticated application bytes")
        payload = dict(self.policy_payload)
        payload["revision"] = 2
        payload["expires_at"] = identity_tests.NOW + 290
        self.policy_store.install(sign_channel_policy(payload, _private_pem(self.policy_key)))
        with self.assertRaises(GatewayEgressError):
            self.egress.take_encrypted()
        self.assertTrue(self.egress._faulted)

    def test_coordinator_endpoint_replacement_retires_same_gateway_identity(self):
        original = dict(self.policy_payload["gateways"][0])
        payload = dict(self.policy_payload)
        payload["revision"] += 1
        payload["gateways"] = [dict(original,
            coordinator_endpoint_host="alternate.coordinator.gateway.example")]
        self.policy_store.install(sign_channel_policy(
            payload, _private_pem(self.policy_key)))
        self.assertEqual(payload["gateways"][0]["certificate_sha256"],
                         original["certificate_sha256"])
        with self.assertRaises(GatewayEgressError):
            self.egress.assert_transport_live()
        self.assertTrue(self.egress._faulted)

    def test_coordinator_endpoint_hostname_must_match_gateway_leaf_san(self):
        payload = dict(self.policy_payload)
        payload["revision"] += 1
        payload["gateways"] = [dict(payload["gateways"][0],
            coordinator_endpoint_host="unlisted.coordinator.gateway.example")]
        self.policy_store.install(sign_channel_policy(
            payload, _private_pem(self.policy_key)))
        egress = GatewayCoordinatorEgress.connect(
            authorizer=self.adapter, policy_store=self.policy_store,
            logical_host_certificate_pem=self.fx.credentials["host"]["certificate"],
            gateway_id="gw-east", gateway_ca_pem=self.gateway_ca,
            coordinator_private_key_pem=self.fx.credentials["coordinator"]["key"])
        server, temporary = self._make_server()
        try:
            with self.assertRaises((GatewayEgressError, OwnedWorkerTLSError)):
                self._finish_handshake(egress, server, temporary)
        finally:
            egress.close()
            for path in temporary[2]:
                Path(path).unlink(missing_ok=True)

    def test_terminal_cleanup_grace_is_method_limited_and_bootstrap_is_not_double_spent(self):
        self.context = self._make_context(hard_lifetime=0.05)
        first = self.egress.mint_route_guard(
            method="OpenSession", trusted_request_context=self.context)
        first.assert_live()
        time.sleep(0.06)
        self.time_source.advance(1.1)
        with self.assertRaises(SessionError):
            self.egress.mint_route_guard(
                method="Step", trusted_request_context=self.context)
        terminal = self.egress.mint_route_guard(
            method="CloseSession", trusted_request_context=self.context)
        payload = outbound_tests.ParsedWorkerRequest(
            protocol_version=1, manifest_fingerprint=identity_tests.MODEL,
            worker_boot_id=identity_tests.BOOT_HOST, session_id=self.context.session_id,
            timeout_ms=5_000, lease_token="lease_0123456789")
        auth = self.adapter.authorize_gateway_outbound(
            WORKER_SERVICE, "CloseSession", payload, self.context,
            gateway_route=terminal)
        auth.close()
        unobserved = self._make_context(hard_lifetime=0.05)
        time.sleep(0.06)
        with self.assertRaises(SessionError):
            self.egress.mint_route_guard(
                method="CloseSession", trusted_request_context=unobserved)

        bootstrap = self.adapter.create_bootstrap_context(max_describes=1)
        guard = self.egress.mint_route_guard(
            method="Describe", trusted_request_context=bootstrap)
        self.assertEqual(bootstrap._uses, 1)
        describe = outbound_tests.ParsedWorkerRequest(
            protocol_version=1, timeout_ms=5_000)
        auth = self.adapter.authorize_gateway_outbound(
            WORKER_SERVICE, "Describe", describe, bootstrap, gateway_route=guard)
        auth.close()
        self.assertEqual(bootstrap._uses, 0)
        with self.assertRaises((GatewayEgressError, ScopeError)):
            self.egress.mint_route_guard(
                method="Describe", trusted_request_context=bootstrap)

    def test_coordinator_identity_rotation_retires_old_tls_generation(self):
        self.adapter.local_identity = replace(
            self.adapter.local_identity, boot_id="d" * 32)
        with self.assertRaises(GatewayEgressError):
            self.egress.mint_route_guard(
                method="OpenSession", trusted_request_context=self.context)
        self.assertTrue(self.egress._faulted)

    def test_tls_certificate_pem_normalization_accepts_equivalent_and_fences_replacement(self):
        local = LocalIdentity(
            self.fx.credentials["coordinator"]["certificate"] + b"\n",
            identity_tests.BOOT_COORDINATOR, identity_tests.MODEL)
        adapter = OutboundAuthorizer(
            local_identity=local, snapshot_store=self.snapshot_store,
            clock=self.clock, target=self.adapter.target,
            worker_request_type=outbound_tests.ParsedWorkerRequest,
            trusted_request_context_type=TrustedRequestContext,
            allow_bootstrap_describe=True)
        egress = GatewayCoordinatorEgress.connect(
            authorizer=adapter, policy_store=self.policy_store,
            logical_host_certificate_pem=self.fx.credentials["host"]["certificate"],
            gateway_id="gw-east", gateway_ca_pem=self.gateway_ca,
            coordinator_private_key_pem=self.fx.credentials["coordinator"]["key"])
        server, temporary = self._make_server()
        try:
            self._finish_handshake(egress, server, temporary)
            self.assertTrue(egress.handshake_complete)
            adapter.local_identity = replace(
                local, certificate_pem=self.fx.credentials["host"]["certificate"])
            with self.assertRaises(GatewayEgressError):
                egress.take_encrypted()
            self.assertTrue(egress._faulted)
        finally:
            egress.close()
            for path in temporary[2]:
                Path(path).unlink(missing_ok=True)

    def test_uncertain_tls_credential_cleanup_is_visible_to_caller(self):
        with mock.patch("steamboat_security.gateway_egress.OwnedWorkerTLS.connect",
                        side_effect=OwnedWorkerTLSError(
                            "uncertain", cleanup_status="uncertain",
                            credential_directory="C:/private/tls-owner")):
            with self.assertRaises(GatewayEgressError) as caught:
                GatewayCoordinatorEgress.connect(
                    authorizer=self.adapter, policy_store=self.policy_store,
                    logical_host_certificate_pem=self.fx.credentials["host"]["certificate"],
                    gateway_id="gw-east", gateway_ca_pem=self.gateway_ca,
                    coordinator_private_key_pem=self.fx.credentials["coordinator"]["key"])
        self.assertEqual(caught.exception.cleanup_status, "uncertain")
        self.assertEqual(caught.exception.credential_directory, "C:/private/tls-owner")

        uncertain_owner = mock.Mock(
            cleanup_uncertain=True, cleanup_status="uncertain",
            credential_directory="C:/private/retained-tls-owner")
        with mock.patch("steamboat_security.gateway_egress.OwnedWorkerTLS.connect",
                        return_value=uncertain_owner):
            with self.assertRaises(GatewayEgressError) as caught:
                GatewayCoordinatorEgress.connect(
                    authorizer=self.adapter, policy_store=self.policy_store,
                    logical_host_certificate_pem=self.fx.credentials["host"]["certificate"],
                    gateway_id="gw-east", gateway_ca_pem=self.gateway_ca,
                    coordinator_private_key_pem=self.fx.credentials["coordinator"]["key"])
        self.assertEqual(caught.exception.cleanup_status, "uncertain")
        self.assertEqual(caught.exception.credential_directory,
                         "C:/private/retained-tls-owner")


if __name__ == "__main__":
    unittest.main()
