"""C1 coordinator admission over an owner-created upstream MemoryBIO server."""

from __future__ import annotations

import ssl
import unittest
import os
import shutil
from datetime import datetime, timezone
from unittest.mock import patch

from steamboat_security.certificates import (ROLE_EKUS, generate_ca,
    generate_private_key_pem, issue_leaf, make_csr)
from steamboat_security.channel_certificates import issue_channel_certificate, make_channel_csr
from steamboat_security.channel_tls import (MAX_CHUNK_BYTES, OwnedWorkerTLS,
    OwnedWorkerTLSError)
from steamboat_security.gateway_coordinator_tls import (
    AuthenticatedCoordinatorChannel, GatewayCoordinatorTLSError,
    OwnedGatewayCoordinatorTLS, is_authenticated_coordinator_channel,
    is_coordinator_route_guard)
from tests.security import test_gateway_egress as egress_tests
from steamboat_security.snapshot import sign_snapshot


class GatewayCoordinatorTLSOwnerTests(unittest.TestCase):
    def setUp(self):
        egress_tests.identity_tests.IdentityFixture.setUpClass()
        self.fixture = egress_tests.GatewayEgressTests("test_route_guard_reuses_c1_scope_and_checks_live_gateway_on_completion")
        self.fixture.setUp()
        self.fx = self.fixture.fx
        self.actor = self.fx.credentials["coordinator"]
        self.host = self.fx.credentials["host"]
        self.key = (self.host["record"]["device_id"],
                    egress_tests.identity_tests.BOOT_HOST,
                    egress_tests.identity_tests.ASSIGNMENT,
                    egress_tests.identity_tests.MODEL)
        self.server = self._new_server()
        self.client = self._new_client()
        self._handshake(self.client, self.server)

    def tearDown(self):
        if hasattr(self, "client"):
            self.client.close()
        if hasattr(self, "server"):
            self.server.close()
        self.fixture.tearDown()
        self.fixture.doCleanups()

    def _new_server(self, *, boot=None, tenant=None, targets=None):
        return OwnedGatewayCoordinatorTLS.accept(
            gateway_certificate_pem=self.fixture.gateway_cert,
            gateway_private_key_pem=self.fixture.gateway_key,
            gateway_ca_pem=self.fixture.gateway_ca,
            snapshot_store=self.fixture.snapshot_store,
            policy_store=self.fixture.policy_store, clock=self.fixture.clock,
            gateway_id="gw-east",
            coordinator_boot_id=boot or egress_tests.identity_tests.BOOT_COORDINATOR,
            tenant_account_id=tenant or egress_tests.identity_tests.ACCOUNT_A,
            target_certificates=targets or {self.key: self.host["certificate"]})

    def _new_client(self, credential=None):
        credential = credential or self.actor
        return OwnedWorkerTLS.connect(
            worker_certificate_pem=credential["certificate"],
            worker_private_key_pem=credential["key"],
            gateway_ca_pem=self.fixture.gateway_ca,
            endpoint_host="coordinator.gateway.example", endpoint_port=444,
            clock=self.fixture.clock)

    def _handshake(self, client, server):
        for _ in range(40):
            try:
                outgoing = client.take_encrypted()
                if outgoing:
                    server.feed_encrypted(outgoing)
                outgoing = server.take_encrypted()
                if outgoing:
                    client.feed_encrypted(outgoing)
            except (GatewayCoordinatorTLSError, OwnedWorkerTLSError):
                raise
            if client.handshake_complete and server.handshake_complete:
                return
        self.fail("real C1 coordinator MemoryBIO TLS handshake did not complete")

    def _expect_peer_rejected(self, credential):
        server = self._new_server()
        client = self._new_client(credential)
        rejected = False
        try:
            for _ in range(40):
                try:
                    outgoing = client.take_encrypted()
                    if outgoing:
                        server.feed_encrypted(outgoing)
                    outgoing = server.take_encrypted()
                    if outgoing:
                        client.feed_encrypted(outgoing)
                except (GatewayCoordinatorTLSError, OwnedWorkerTLSError):
                    rejected = True
                    break
                if server.handshake_complete:
                    # TLS may complete before the post-handshake C1 enrollment
                    # check. The authenticated channel must still be absent.
                    try:
                        _ = server.authenticated_channel
                    except GatewayCoordinatorTLSError:
                        rejected = True
                    break
            self.assertTrue(rejected)
            self.assertFalse(server.handshake_complete)
            with self.assertRaises(GatewayCoordinatorTLSError):
                _ = server.authenticated_channel
        finally:
            server.close()
            client.close()

    def _new_personal_coordinator_credential(self, *, device=None, ca=None, ca_key=None):
        identity = egress_tests.identity_tests
        account = identity.ACCOUNT_A
        device = device or ("dev_" + "d" * 32)
        key = generate_private_key_pem()
        ca = ca or self.fx.ca_pem
        ca_key = ca_key or self.fx.ca_key
        csr = make_csr(key, account_id=account, device_id=device,
                       role="personal_coordinator")
        cert = issue_leaf(
            ca, ca_key, csr, account_id=account, device_id=device,
            role="personal_coordinator", not_before=identity.NOW - 30,
            not_after=identity.NOW + 700,
            ekus=ROLE_EKUS["personal_coordinator"])
        return {"certificate": cert, "key": key}

    def test_actual_c1_coordinator_peer_mints_identity_and_route_guard(self):
        self.assertEqual(self.server._gateway_record["coordinator_endpoint_host"],
                         "coordinator.gateway.example")
        self.assertEqual(self.server._gateway_record["coordinator_endpoint_port"], 444)
        channel = self.server.authenticated_channel
        self.assertIs(type(channel), AuthenticatedCoordinatorChannel)
        self.assertTrue(is_authenticated_coordinator_channel(channel))
        self.assertEqual(channel.actor_certificate_pem, self.actor["certificate"])
        self.assertEqual(channel.coordinator_boot_id,
                         egress_tests.identity_tests.BOOT_COORDINATOR)
        guard = channel.authorize_route(
            method="OpenSession", target_device_id=self.key[0],
            worker_boot_id=self.key[1], assignment_id=self.key[2], model_id=self.key[3])
        self.assertTrue(is_coordinator_route_guard(guard))
        self.assertEqual(guard.method, "OpenSession")
        self.assertEqual(guard.target_device_id, self.key[0])
        self.assertGreater(guard.deadline_monotonic,
                           self.fixture.time_source.monotonic)
        self.assertGreater(sum(self.server.byte_counts), 0)

    def test_wrong_method_or_unconfigured_target_cannot_mint_route(self):
        channel = self.server.authenticated_channel
        with self.assertRaises(GatewayCoordinatorTLSError):
            channel.authorize_route(
                method="CancelSession", target_device_id=self.key[0],
                worker_boot_id=self.key[1], assignment_id=self.key[2], model_id=self.key[3])
        with self.assertRaises(GatewayCoordinatorTLSError):
            channel.authorize_route(
                method="OpenSession", target_device_id="dev_" + "f" * 32,
                worker_boot_id=self.key[1], assignment_id=self.key[2], model_id=self.key[3])

    def test_target_map_certificate_must_match_current_c1_host_and_policy(self):
        server = self._new_server(
            targets={self.key: self.fx.credentials["consumer"]["certificate"]})
        client = self._new_client()
        try:
            self._handshake(client, server)
            channel = server.authenticated_channel
            with self.assertRaises(GatewayCoordinatorTLSError):
                channel.authorize_route(
                    method="OpenSession", target_device_id=self.key[0],
                    worker_boot_id=self.key[1], assignment_id=self.key[2],
                    model_id=self.key[3])
            self.assertFalse(server.is_live)
        finally:
            server.close()
            client.close()

    def test_absent_client_certificate_runs_to_cert_required_rejection(self):
        self.assertTrue(self.server.handshake_complete)  # positive pair control
        server = self._new_server()
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
        client = context.wrap_bio(incoming, outgoing, server_side=False)
        rejected = False
        for _ in range(40):
            try:
                client.do_handshake()
            except (ssl.SSLWantReadError, ssl.SSLWantWriteError):
                pass
            except ssl.SSLError:
                rejected = True
                break
            if outgoing.pending:
                try:
                    server.feed_encrypted(outgoing.read())
                except GatewayCoordinatorTLSError:
                    rejected = True
                    break
            try:
                server.do_handshake()
            except GatewayCoordinatorTLSError:
                rejected = True
                break
            data = server.take_encrypted()
            if data:
                incoming.write(data)
            if server.handshake_complete:
                break
        self.assertTrue(rejected, "server did not reject an absent coordinator certificate")
        self.assertFalse(server.handshake_complete)
        server.close()

    def test_c1_host_and_consumer_cannot_register_as_coordinator(self):
        self._expect_peer_rejected(self.host)
        self._expect_peer_rejected(self.fx.credentials["consumer"])
        self._expect_peer_rejected(self.fx.credentials["alt_coordinator"])

    def test_unenrolled_personal_coordinator_is_rejected(self):
        self._expect_peer_rejected(self._new_personal_coordinator_credential())

    def test_wrong_ca_coordinator_is_rejected_by_tls_and_snapshot_trust(self):
        foreign_ca, foreign_key = generate_ca(
            now=egress_tests.identity_tests.NOW - 3600)
        self._expect_peer_rejected(self._new_personal_coordinator_credential(
            ca=foreign_ca, ca_key=foreign_key))

    def test_worker_stream_certificate_cannot_register_as_coordinator(self):
        identity = {
            "account_id": self.host["record"]["account_id"],
            "device_id": self.host["record"]["device_id"],
            "host_serial": self.host["record"]["serial"],
            "credential_epoch": self.host["record"]["credential_epoch"],
        }
        key = generate_private_key_pem()
        cert = issue_channel_certificate(
            self.fixture.gateway_ca, self.fixture.gateway_ca_key,
            make_channel_csr(key, kind="worker_stream", identity=identity),
            kind="worker_stream", identity=identity,
            now=datetime.fromtimestamp(egress_tests.identity_tests.NOW - 20,
                                       timezone.utc), lifetime_seconds=700)
        self._expect_peer_rejected({"certificate": cert, "key": key})

    def test_wrong_configured_boot_or_tenant_fails_operator_route_admission(self):
        bad_boot = "e" * 32
        server = self._new_server(boot=bad_boot)
        client = self._new_client()
        try:
            with self.assertRaises((GatewayCoordinatorTLSError, OwnedWorkerTLSError)):
                self._handshake(client, server)
            self.assertFalse(server.handshake_complete)
        finally:
            server.close()
            client.close()
        server = self._new_server(tenant="acct_" + "f" * 32)
        client = self._new_client()
        try:
            with self.assertRaises((GatewayCoordinatorTLSError, OwnedWorkerTLSError)):
                self._handshake(client, server)
            self.assertFalse(server.handshake_complete)
        finally:
            server.close()
            client.close()

    def test_operator_policy_refresh_permanently_retires_channel_and_guard(self):
        channel = self.server.authenticated_channel
        guard = channel.authorize_route(
            method="OpenSession", target_device_id=self.key[0],
            worker_boot_id=self.key[1], assignment_id=self.key[2], model_id=self.key[3])
        payload = dict(self.fixture.policy_payload)
        payload["revision"] += 1
        self.fixture.policy_store.install(egress_tests.sign_channel_policy(
            payload, egress_tests._private_pem(self.fixture.policy_key)))
        self.assertTrue(self.server.poll_unavailable())
        self.assertFalse(self.server.is_live)
        with self.assertRaises(GatewayCoordinatorTLSError):
            channel.assert_live()
        with self.assertRaises(GatewayCoordinatorTLSError):
            guard.assert_live()

    def test_coordinator_endpoint_replacement_retires_same_gateway_identity(self):
        channel = self.server.authenticated_channel
        payload = dict(self.fixture.policy_payload)
        payload["revision"] += 1
        payload["gateways"] = [dict(payload["gateways"][0],
            coordinator_endpoint_port=445)]
        self.fixture.policy_store.install(egress_tests.sign_channel_policy(
            payload, egress_tests._private_pem(self.fixture.policy_key)))
        self.assertEqual(payload["gateways"][0]["certificate_sha256"],
                         self.fixture.policy_payload["gateways"][0]["certificate_sha256"])
        self.assertTrue(self.server.poll_unavailable())
        with self.assertRaises(GatewayCoordinatorTLSError):
            channel.assert_live()

    def test_coordinator_listener_rejects_worker_only_gateway_certificate_san(self):
        payload = dict(self.fixture.policy_payload)
        payload["revision"] += 1
        payload["gateways"] = [dict(payload["gateways"][0],
            coordinator_endpoint_host="unlisted.coordinator.gateway.example")]
        self.fixture.policy_store.install(egress_tests.sign_channel_policy(
            payload, egress_tests._private_pem(self.fixture.policy_key)))
        with self.assertRaises(GatewayCoordinatorTLSError):
            self._new_server()

    def _assert_policy_change_during_real_tls_flight_rejected(self, *, replace_pin):
        server = self._new_server()
        client = self._new_client()
        try:
            first = client.take_encrypted()
            self.assertTrue(first)
            server.feed_encrypted(first)
            payload = dict(self.fixture.policy_payload)
            payload["revision"] += 1
            if replace_pin:
                # Keep the policy structurally valid while changing the pinned
                # gateway certificate identity under the in-flight handshake.
                payload["gateways"] = [dict(payload["gateways"][0])]
                payload["gateways"][0]["certificate_sha256"] = "a" * 64
                payload["gateways"][0]["public_key_sha256"] = "b" * 64
            self.fixture.policy_store.install(egress_tests.sign_channel_policy(
                payload, egress_tests._private_pem(self.fixture.policy_key)))
            rejected = False
            for _ in range(40):
                try:
                    outgoing = server.take_encrypted()
                    if outgoing:
                        client.feed_encrypted(outgoing)
                    outgoing = client.take_encrypted()
                    if outgoing:
                        server.feed_encrypted(outgoing)
                except (GatewayCoordinatorTLSError, OwnedWorkerTLSError):
                    rejected = True
                    break
                if server.handshake_complete:
                    break
            self.assertTrue(rejected)
            self.assertFalse(server.handshake_complete)
            self.assertTrue(server.poll_unavailable())
        finally:
            server.close()
            client.close()

    def test_policy_revision_change_during_actual_tls_flight_is_rejected(self):
        self._assert_policy_change_during_real_tls_flight_rejected(replace_pin=False)

    def test_replacement_gateway_pin_during_actual_tls_flight_is_rejected(self):
        self._assert_policy_change_during_real_tls_flight_rejected(replace_pin=True)

    def test_snapshot_revocation_retires_channel_and_existing_guard(self):
        channel = self.server.authenticated_channel
        guard = channel.authorize_route(
            method="OpenSession", target_device_id=self.key[0],
            worker_boot_id=self.key[1], assignment_id=self.key[2], model_id=self.key[3])
        now = egress_tests.identity_tests.NOW
        serial = self.actor["record"]["serial"]
        records = [record for record in self.fx.records.values()
                   if record["serial"] != serial]
        grants = [grant for grant in self.fx.grants(expires=now + 300)
                  if grant["actor_serial"] != serial
                  and grant["target_serial"] != serial]
        payload = self.fx.payload(
            now=now, revision=2, records=records, grants=grants,
            revoked_serials=[serial], expiry=now + 300)
        self.fixture.snapshot_store.install(sign_snapshot(payload, self.fx.signing_key))
        self.assertTrue(self.server.poll_unavailable())
        self.assertFalse(self.server.is_live)
        with self.assertRaises(GatewayCoordinatorTLSError):
            guard.assert_live()

    def test_uncertainty_failure_is_sticky_after_clock_revalidation(self):
        channel = self.server.authenticated_channel
        self.fixture.time_source.uncertainty = float("inf")
        self.assertTrue(self.server.poll_unavailable())
        self.fixture.time_source.uncertainty = 0.0
        self.fixture.clock.revalidate_after_resume(trusted_clock=True)
        self.assertFalse(self.server.is_live)
        with self.assertRaises(GatewayCoordinatorTLSError):
            channel.assert_live()

    def test_widened_uncertainty_clips_generation_and_cannot_be_narrowed_back(self):
        channel = self.server.authenticated_channel
        previous_deadline = self.server._deadline
        self.fixture.time_source.advance(0.1)
        self.fixture.time_source.uncertainty = 20.0
        self.assertFalse(self.server.poll_unavailable())
        clipped_deadline = self.server._deadline
        self.assertLess(clipped_deadline, previous_deadline)
        self.fixture.time_source.uncertainty = 0.0
        self.assertTrue(self.server.is_live)
        self.assertEqual(self.server._deadline, clipped_deadline)
        channel.assert_live()

    def test_snapshot_expiry_tightens_existing_generation(self):
        channel = self.server.authenticated_channel
        now = egress_tests.identity_tests.NOW
        short = self.fx.payload(
            now=now, revision=2, records=self.fx.records.values(),
            grants=self.fx.grants(expires=now + 40), expiry=now + 40)
        self.fixture.snapshot_store.install(sign_snapshot(short, self.fx.signing_key))
        self.fixture.time_source.advance(41)
        self.assertTrue(self.server.poll_unavailable())
        self.assertFalse(self.server.is_live)
        with self.assertRaises(GatewayCoordinatorTLSError):
            channel.assert_live()

    def test_actual_coordinator_leaf_expiry_is_a_permanent_monotonic_cap(self):
        identity = egress_tests.identity_tests
        entry = self.actor
        record = self.fx.records["coordinator"]
        short_pem = issue_leaf(
            self.fx.ca_pem, self.fx.ca_key, entry["csr"],
            account_id=record["account_id"], device_id=record["device_id"],
            role="personal_coordinator", not_before=identity.NOW - 20,
            not_after=identity.NOW + 80, ekus=ROLE_EKUS["personal_coordinator"])
        short_record = identity._record_from_leaf(
            short_pem, account_id=record["account_id"],
            device_id=record["device_id"], role="personal_coordinator",
            credential_epoch=record["credential_epoch"])
        entry["certificate"] = short_pem
        entry["record"] = short_record
        self.fx.records["coordinator"] = short_record

        now = identity.NOW
        self.fixture.snapshot_store.install(sign_snapshot(
            self.fx.payload(now=now, revision=2, records=self.fx.records.values(),
                            grants=self.fx.grants(expires=now + 300), expiry=now + 300),
            self.fx.signing_key))
        self.fixture.policy_payload["revision"] = 2
        route = self.fixture.policy_payload["routes"][0]
        route.update(actor_serial=short_record["serial"],
                     actor_credential_epoch=short_record["credential_epoch"],
                     actor_certificate_sha256=short_record["certificate_sha256"])
        self.fixture._install_policy()

        self.server.close()
        self.client.close()
        self.server = self._new_server()
        self.client = self._new_client()
        self._handshake(self.client, self.server)
        channel = self.server.authenticated_channel
        initial_cap = channel._owner_ref()._deadline

        self.fixture.time_source.advance(40)
        self.fixture.time_source.uncertainty = 20
        self.assertFalse(self.server.poll_unavailable())
        clipped_cap = channel._owner_ref()._deadline
        self.assertLess(clipped_cap, initial_cap)
        self.fixture.time_source.uncertainty = 0
        self.assertTrue(self.server.is_live)
        self.assertEqual(channel._owner_ref()._deadline, clipped_cap)

        self.fixture.time_source.advance(21)
        self.assertTrue(self.server.poll_unavailable())
        self.assertFalse(self.server.is_live)
        with self.assertRaises(GatewayCoordinatorTLSError):
            channel.assert_live()

    def test_expiry_after_ttl_retires_channel_and_route_guard(self):
        channel = self.server.authenticated_channel
        guard = channel.authorize_route(
            method="OpenSession", target_device_id=self.key[0],
            worker_boot_id=self.key[1], assignment_id=self.key[2], model_id=self.key[3])
        self.fixture.time_source.advance(301)
        self.assertTrue(self.server.poll_unavailable())
        self.assertFalse(self.server.is_live)
        with self.assertRaises(GatewayCoordinatorTLSError):
            channel.assert_live()
        with self.assertRaises(GatewayCoordinatorTLSError):
            guard.assert_live()

    def test_close_notify_is_terminal_for_channel(self):
        channel = self.server.authenticated_channel
        try:
            self.client._OwnedWorkerTLS__ssl.unwrap()
        except (ssl.SSLWantReadError, ssl.SSLWantWriteError):
            pass
        close_notify = self.client.take_encrypted()
        self.assertTrue(close_notify)
        self.server.feed_encrypted(close_notify)
        self.assertEqual(self.server.read_plaintext(), b"")
        self.assertFalse(self.server.is_live)
        with self.assertRaises(GatewayCoordinatorTLSError):
            channel.assert_live()

    def test_transport_chunk_bound_and_handshake_timeout_are_sticky(self):
        with self.assertRaises(GatewayCoordinatorTLSError):
            self.server.feed_encrypted(b"x" * (MAX_CHUNK_BYTES + 1))
        self.assertFalse(self.server.is_live)
        server = self._new_server()
        self.fixture.time_source.advance(10.001)
        with self.assertRaises(GatewayCoordinatorTLSError):
            server.do_handshake()
        self.assertFalse(server.is_live)
        server.close()

    def test_uncertain_private_credential_cleanup_is_reported_once(self):
        real_rmtree = shutil.rmtree
        with patch("steamboat_security.gateway_coordinator_tls.shutil.rmtree",
                   side_effect=PermissionError("injected cleanup failure")) as remove:
            with self.assertRaises(GatewayCoordinatorTLSError) as raised:
                self._new_server()
        self.assertEqual(remove.call_count, 1)
        self.assertEqual(raised.exception.cleanup_status, "uncertain")
        path = raised.exception.credential_directory
        self.assertTrue(path and os.path.isdir(path))
        real_rmtree(path)

    def test_channel_copy_and_owner_close_are_rejected(self):
        channel = self.server.authenticated_channel
        import copy
        with self.assertRaises(TypeError):
            copy.copy(self.server)
        duplicate = copy.copy(channel)
        self.assertFalse(is_authenticated_coordinator_channel(duplicate))
        with self.assertRaises(GatewayCoordinatorTLSError):
            duplicate.assert_live()
        self.server.close()
        with self.assertRaises(GatewayCoordinatorTLSError):
            channel.assert_live()


if __name__ == "__main__":
    unittest.main()
