from __future__ import annotations

import hashlib
import json
import unittest
from types import SimpleNamespace

from cryptography import x509

from tests.security import test_gateway_ingress as ingress_tests
from tests.security import test_identity_core as c1_tests

from steamboat_security.authorization import Authorizer, LocalIdentity
from steamboat_security.certificates import serial_hex
from steamboat_security.codec import (COORDINATOR_SERVICE, WORKER_METHODS,
    WORKER_SERVICE, encode_binding, parse_metadata)
from steamboat_security.errors import (BindingError, CredentialError, ScopeError,
    SessionError, SnapshotError)
from steamboat_security.gateway_ingress import GatewayIngressError
from steamboat_security.channel_tls import OwnedWorkerTLSError
from steamboat_security.operator import _record_from_leaf
from steamboat_security.snapshot import SnapshotStore


class PortableParsedRequest:
    """Configured exact parsed-request fixture for hosts without native protobuf."""

    DESCRIPTOR = SimpleNamespace(full_name="steamboat.v1.Request")

    def __init__(self, **values):
        self.__dict__.update(values)

    def SerializeToString(self, *, deterministic=False):
        if deterministic is not True:
            raise ValueError("deterministic serialization is required")
        return json.dumps(vars(self), sort_keys=True, separators=(",", ":"),
                          ensure_ascii=False, allow_nan=False).encode("utf-8")

    def ByteSize(self):
        return len(self.SerializeToString(deterministic=True))


class GatewayAuthorizationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        c1_tests.IdentityFixture.setUpClass()

    def setUp(self):
        self.ingress_fixture = ingress_tests.GatewayIngressTests(
            methodName="test_real_mutual_tls_connection_binds_policy_and_unique_generation")
        self.ingress_fixture.setUp()
        self.addCleanup(self.ingress_fixture.tearDown)
        self.fixture = self.ingress_fixture.fixture
        self.clock = self.fixture.clock
        self.now = int(self.clock._wall())
        self.snapshot_key = c1_tests.generate_authorization_signing_key_pem()
        self.snapshot_payload = self._snapshot_payload()
        self.snapshot_store = SnapshotStore(
            verification_key_pem=c1_tests.snapshot_public_key_pem(self.snapshot_key),
            ca_certificate_pem=self.fixture.participant_ca, clock=self.clock)
        self.snapshot_store.install(c1_tests.sign_snapshot(
            self.snapshot_payload, self.snapshot_key))
        self.authorizer = Authorizer(
            local_identity=LocalIdentity(self.fixture.host_pem,
                self.fixture.payload["workers"][0]["worker_boot_id"],
                self.fixture.payload["workers"][0]["model_id"],
                self.fixture.payload["workers"][0]["assignment_id"]),
            snapshot_store=self.snapshot_store, clock=self.clock,
            session_bindings=self.ingress_fixture.sessions,
            worker_request_type=PortableParsedRequest)
        self.next_sequence = 1
        self.lane_sequences = {"data": 1, "control": 1}

    def _snapshot_payload(self, *, revision=1, grants=None, revoked_serials=()):
        f = self.fixture
        actor = _record_from_leaf(f.actor_pem, account_id=f.payload["routes"][0]["account_id"],
            device_id=f.payload["routes"][0]["device_id"], role="personal_coordinator",
            credential_epoch=f.payload["routes"][0]["actor_credential_epoch"])
        worker = f.payload["workers"][0]
        local = _record_from_leaf(f.host_pem, account_id=worker["account_id"],
            device_id=worker["device_id"], role="host",
            credential_epoch=worker["host_credential_epoch"])
        records = sorted((actor, local), key=lambda item: item["serial"])
        actor_revoked = actor["serial"] in revoked_serials
        if actor_revoked:
            records = [local]
        if grants is None:
            grants = []
            for method in (() if actor_revoked else sorted(WORKER_METHODS)):
                grants.append({
                    "account_id": actor["account_id"],
                    "device_id": actor["device_id"], "role": actor["role"],
                    "actor_serial": actor["serial"],
                    "actor_public_key_sha256": actor["public_key_sha256"],
                    "actor_credential_epoch": actor["credential_epoch"],
                    "tenant_account_id": actor["account_id"],
                    "target_account_id": local["account_id"],
                    "target_device_id": local["device_id"],
                    "target_role": local["role"], "target_serial": local["serial"],
                    "target_public_key_sha256": local["public_key_sha256"],
                    "target_credential_epoch": local["credential_epoch"],
                    "target_boot_id": worker["worker_boot_id"],
                    "actor_boot_id": f.payload["routes"][0]["coordinator_boot_id"],
                    "assignment_id": worker["assignment_id"],
                    "model_id": worker["model_id"],
                    "method": f"{WORKER_SERVICE}/{method}",
                    "not_before": self.now - 30, "not_after": self.now + 240,
                })
        return {"version": 1, "revision": revision, "issued_at": self.now - 1,
                "expires_at": self.now + 240,
                "revoked_serials": sorted(revoked_serials), "revoked_devices": [],
                "credentials": records, "grants": grants}

    def _install_snapshot(self, *, grants=None, revoked_serials=(), revision=2):
        self.snapshot_payload = self._snapshot_payload(
            revision=revision, grants=grants, revoked_serials=revoked_serials)
        return self.snapshot_store.install(c1_tests.sign_snapshot(
            self.snapshot_payload, self.snapshot_key))

    def _binding(self, method="OpenSession", *, operation_id=None):
        fields = dict(parse_metadata(WORKER_SERVICE, "OpenSession",
            self.fixture.metadata).fields)
        fields["operation_id"] = operation_id or "op_" + f"{self.next_sequence:032x}"
        if method == "Describe":
            for name in ("coordinator_boot_id", "tenant_account_id", "request_id",
                         "session_id", "route_id", "route_epoch", "attempt",
                         "assignment_id", "worker_boot_id"):
                fields.pop(name, None)
        return encode_binding(WORKER_SERVICE, method, fields)

    def _payload(self, method="OpenSession", *, lease_token="", session_id=None):
        b = parse_metadata(WORKER_SERVICE, "OpenSession", self.fixture.metadata)
        return PortableParsedRequest(
            protocol_version=1,
            manifest_fingerprint=self.fixture.payload["workers"][0]["model_id"],
            worker_boot_id=b["worker_boot_id"], session_id=session_id or b["session_id"],
            lease_token=lease_token, timeout_ms=30_000,
            max_positions=64 if method == "OpenSession" else 0,
            lifetime_ms=120_000 if method == "OpenSession" else 0,
            idle_lease_ms=30_000 if method == "OpenSession" else 0,
            sequence=0 if method == "OpenSession" else 1,
            start_position=0, token_count=1 if method == "Step" else 0)

    def _authorize_gateway(self, method="OpenSession", *, service=WORKER_SERVICE, payload=None,
                           binding_bytes=None, raw_bytes=None, operation_id=None,
                           ingress=None, sequence=None):
        payload = payload or self._payload(method)
        binding_bytes = binding_bytes or self._binding(method, operation_id=operation_id)
        metadata = (("steamboat-binding-bin", binding_bytes),)
        raw_bytes = payload.SerializeToString(deterministic=True) if raw_bytes is None else raw_bytes
        ingress = ingress or self.ingress_fixture.ingress
        if sequence is None:
            lane = ("control" if method in {"CloseSession", "CancelSession", "SessionStatus"}
                    else "data")
            sequence = self.lane_sequences[lane]
            self.lane_sequences[lane] += 1
        else:
            lane = ("control" if method in {"CloseSession", "CancelSession", "SessionStatus"}
                    else "data")
        envelope = self.fixture.make_delegation(changes={
            "policy_revision": ingress.policy_revision,
            "policy_digest": ingress.policy_digest,
            "stream_generation": ingress.stream_generation,
            "frame_sequence": sequence, "service": WORKER_SERVICE,
            "lane": lane,
            "method": method,
            "binding_sha256": hashlib.sha256(binding_bytes).hexdigest(),
            "request_sha256": hashlib.sha256(raw_bytes).hexdigest(),
        })
        return self.authorizer.authorize_gateway(
            service, method, payload, metadata,
            ingress=ingress, envelope=envelope,
            request_bytes=raw_bytes, frame_sequence=sequence, wire_lane=lane)

    @staticmethod
    def _response(auth, *, lease="lease_token_0123456789", reclaimed=False):
        payload = auth.payload
        return SimpleNamespace(
            DESCRIPTOR=SimpleNamespace(full_name="steamboat.v1.Response"), code="OK",
            protocol_version=1, manifest_fingerprint=auth.model_id,
            worker_boot_id=auth._authorizer.local_identity.boot_id,
            session_id=auth.binding.get("session_id", ""), lease_token=lease,
            max_positions=getattr(payload, "max_positions", 0),
            sequence=getattr(payload, "sequence", 0),
            start_position=getattr(payload, "start_position", 0),
            token_count=getattr(payload, "token_count", 0),
            end_position=getattr(payload, "start_position", 0) +
                getattr(payload, "token_count", 0),
            next_sequence=getattr(payload, "sequence", 0) + 1,
            reclaimed=reclaimed)

    def _open_complete(self):
        auth = self._authorize_gateway()
        auth.complete(self._response(auth))
        return auth

    def test_gateway_open_step_close_share_c1_and_ingress_session_ownership(self):
        opened = self._open_complete()
        self.assertEqual(opened._ingress_identity,
                         self.ingress_fixture.ingress.ingress_identity)
        b = parse_metadata(WORKER_SERVICE, "OpenSession", self.fixture.metadata)
        fields = dict(b.fields)
        fields["operation_id"] = "op_" + "f" * 32
        binding = encode_binding(WORKER_SERVICE, "Step", fields)
        step_payload = self._payload("Step", lease_token="lease_token_0123456789")
        step = self._authorize_gateway("Step", payload=step_payload,
                                       binding_bytes=binding)
        step.complete(self._response(step))
        close_fields = dict(fields)
        close_fields["operation_id"] = "op_" + "e" * 32
        close_binding = encode_binding(WORKER_SERVICE, "CloseSession", close_fields)
        close_payload = self._payload("CloseSession", lease_token="lease_token_0123456789")
        closing = self._authorize_gateway("CloseSession", payload=close_payload,
                                          binding_bytes=close_binding)
        closing.complete(self._response(closing, reclaimed=True))
        self.assertTrue(closing.assert_live())

    def test_native_generated_worker_request_bytes_match_deterministic_wire(self):
        from steamboat_runtime.protocol.worker_pb2 import Request
        self.authorizer = Authorizer(
            local_identity=self.authorizer.local_identity,
            snapshot_store=self.snapshot_store, clock=self.clock,
            session_bindings=self.ingress_fixture.sessions,
            worker_request_type=Request)
        b = parse_metadata(WORKER_SERVICE, "OpenSession", self.fixture.metadata)
        request = Request(protocol_version=1,
            manifest_fingerprint=self.fixture.payload["workers"][0]["model_id"],
            worker_boot_id=b["worker_boot_id"], session_id=b["session_id"],
            timeout_ms=30_000, max_positions=64, lifetime_ms=120_000,
            idle_lease_ms=30_000)
        admitted = self._authorize_gateway(payload=request)
        self.assertEqual(admitted.binding.method, "OpenSession")

    def test_c1_grant_rejection_and_revoked_gateway_actor_never_dispatch(self):
        self._install_snapshot(grants=[])
        with self.assertRaises(ScopeError):
            self._authorize_gateway()
        # The same ingress is rejected when its actor enrollment is revoked
        # from the current C1 snapshot.
        actor_serial = serial_hex(
            x509.load_pem_x509_certificate(self.fixture.actor_pem).serial_number)
        self._install_snapshot(grants=None, revoked_serials=(actor_serial,), revision=3)
        with self.assertRaises(CredentialError):
            self._authorize_gateway(operation_id="op_" + "9" * 32)

    def test_c1_denial_consumes_signed_data_lane_attempt(self):
        self._install_snapshot(grants=[])
        ingress = self.ingress_fixture.ingress
        with self.assertRaises(ScopeError):
            self._authorize_gateway()
        self.assertEqual(ingress._state.next_sequence["data"], 2)
        self.assertEqual(ingress._state.next_sequence["control"], 1)

    def test_cross_lane_operation_id_replay_uses_shared_c1_table(self):
        op_id = "op_" + "c" * 32
        opened = self._authorize_gateway("OpenSession", operation_id=op_id)
        with self.assertRaises(ScopeError):
            self._authorize_gateway("CancelSession", operation_id=op_id,
                                    payload=self._payload(
                                        "CancelSession", lease_token="lease_token_0123456789"))
        self.assertEqual(self.ingress_fixture.ingress._state.next_sequence["data"], 2)
        self.assertEqual(self.ingress_fixture.ingress._state.next_sequence["control"], 2)
        opened.fail(cache_may_exist=False)

    def test_preopen_cancel_is_denied_and_late_step_after_cancel_stays_terminal(self):
        with self.assertRaises(SessionError):
            self._authorize_gateway("CancelSession", payload=self._payload(
                "CancelSession", lease_token="lease_token_0123456789"))
        opened = self._authorize_gateway(operation_id="op_" + "a" * 32)
        opened.complete(self._response(opened))
        fields = dict(parse_metadata(WORKER_SERVICE, "OpenSession",
                                     self.fixture.metadata).fields)
        fields["operation_id"] = "op_" + "d" * 32
        cancel = self._authorize_gateway(
            "CancelSession", payload=self._payload(
                "CancelSession", lease_token="lease_token_0123456789"),
            binding_bytes=encode_binding(WORKER_SERVICE, "CancelSession", fields))
        cancel.complete(self._response(cancel, reclaimed=True))
        fields["operation_id"] = "op_" + "e" * 32
        step = self._payload("Step", lease_token="lease_token_0123456789")
        with self.assertRaises(SessionError):
            self._authorize_gateway(
                "Step", payload=step,
                binding_bytes=encode_binding(WORKER_SERVICE, "Step", fields))

    def test_raw_payload_mismatch_rejects_and_closes_the_ingress(self):
        payload = self._payload()
        with self.assertRaises(BindingError):
            self._authorize_gateway(payload=payload, raw_bytes=b"different protobuf bytes")
        self.assertTrue(self.ingress_fixture.ingress._state.closed)

    def test_wrong_entrypoint_is_rejected_and_closes_the_ingress(self):
        with self.assertRaises(ScopeError):
            self._authorize_gateway(service=COORDINATOR_SERVICE,
                                    operation_id="op_" + "8" * 32)
        self.assertTrue(self.ingress_fixture.ingress._state.closed)

    def test_gateway_entry_rejects_nonconcrete_ingress_owner(self):
        with self.assertRaises(GatewayIngressError):
            self.authorizer.authorize_gateway(
                WORKER_SERVICE, "OpenSession", self._payload(), self.fixture.metadata,
                ingress=SimpleNamespace(), envelope=b"x", request_bytes=b"x",
                frame_sequence=1, wire_lane="data")

    def test_replay_uses_shared_c1_replay_table_and_direct_cannot_adopt_gateway_session(self):
        fields = dict(parse_metadata(WORKER_SERVICE, "OpenSession",
                                     self.fixture.metadata).fields)
        fields["operation_id"] = "op_" + "7" * 32
        binding = encode_binding(WORKER_SERVICE, "OpenSession", fields)
        auth = self._authorize_gateway(binding_bytes=binding)
        with self.assertRaises(ScopeError):
            self._authorize_gateway(binding_bytes=binding)
        auth.fail(cache_may_exist=False)
        opened = self._open_complete()
        payload = opened.payload
        direct_fields = dict(parse_metadata(WORKER_SERVICE, "OpenSession",
            (("steamboat-binding-bin", opened.binding_bytes),)).fields)
        direct_fields["operation_id"] = "op_" + "5" * 32
        direct_binding = encode_binding(WORKER_SERVICE, "OpenSession", direct_fields)
        with self.assertRaises(SessionError):
            self.authorizer.authorize(
                WORKER_SERVICE, "OpenSession", payload,
                (("steamboat-binding-bin", direct_binding),),
                self.fixture.actor_pem)

    def test_stream_loss_retires_existing_session(self):
        notices = []
        self.ingress_fixture.sessions.subscribe(notices.append)
        opened = self._open_complete()
        self.ingress_fixture.ingress.close()
        with self.assertRaises(GatewayIngressError):
            opened.assert_live()
        self.assertTrue(notices)
        self.assertEqual(notices[0].reason, "gateway-stream-lost")

    def test_closed_owned_tls_retires_existing_session(self):
        notices = []
        self.ingress_fixture.sessions.subscribe(notices.append)
        opened = self._open_complete()
        self.ingress_fixture.tls_owner.close()
        with self.assertRaises(GatewayIngressError):
            opened.assert_live()
        self.assertTrue(notices)
        self.assertEqual(notices[0].reason, "gateway-clock-fault")

    def test_faulted_owned_tls_invalidates_existing_session_after_revalidation(self):
        notices = []
        self.ingress_fixture.sessions.subscribe(notices.append)
        opened = self._open_complete()
        owner = self.ingress_fixture.tls_owner
        self.fixture.clock._uncertainty = lambda: (_ for _ in ()).throw(
            RuntimeError("clock source unavailable"))
        with self.assertRaises(OwnedWorkerTLSError):
            owner.feed_encrypted(b"x")
        self.fixture.clock._uncertainty = lambda: 0.0
        self.fixture.clock.revalidate_after_resume(trusted_clock=True)
        with self.assertRaises(GatewayIngressError):
            opened.assert_live()
        self.assertTrue(notices)
        self.assertEqual(notices[0].reason, "gateway-clock-fault")

    def test_new_policy_and_tls_generation_cannot_adopt_old_gateway_session(self):
        self._open_complete()
        current = json.loads(self.fixture.policy_store.current().canonical_payload)
        current["revision"] += 1
        self.fixture.policy_store.install(self._sign_channel_policy(current))
        self.ingress_fixture.ingress.poll_unavailable()
        new_tls = self.ingress_fixture._make_tls_client()
        from steamboat_security.gateway_ingress import GatewayWorkerIngress
        new_ingress = GatewayWorkerIngress.from_tls(
            new_tls, verifier=self.fixture.verifier,
            sessions=self.ingress_fixture.sessions, gateway_id="gw-east")
        fields = dict(parse_metadata(WORKER_SERVICE, "OpenSession",
                                     self.fixture.metadata).fields)
        fields["operation_id"] = "op_" + "4" * 32
        with self.assertRaises(SessionError):
            self._authorize_gateway(binding_bytes=encode_binding(
                WORKER_SERVICE, "OpenSession", fields), ingress=new_ingress, sequence=1)

    def _sign_channel_policy(self, payload):
        from steamboat_security.channel_policy import sign_channel_policy
        return sign_channel_policy(payload,
            ingress_tests.delegation_tests.private_pem(self.fixture.operator_key))

    def test_current_c1_snapshot_expiry_caps_gateway_authorization(self):
        short = self._snapshot_payload()
        short["revision"] = 2
        short["expires_at"] = self.now + 20
        self.snapshot_store.install(c1_tests.sign_snapshot(short, self.snapshot_key))
        opened = self._open_complete()
        self.fixture.wall += 21
        self.fixture.mono += 21
        with self.assertRaises(SnapshotError):
            opened.assert_live()

    def test_direct_tls_path_still_admits_only_direct_peer_credentials(self):
        binding = self._binding("Describe", operation_id="op_" + "6" * 32)
        # Describe supports the compact schema; create a matching request.
        payload = self._payload("Describe")
        payload.worker_boot_id = ""
        metadata = (("steamboat-binding-bin", binding),)
        direct = self.authorizer.authorize(
            WORKER_SERVICE, "Describe", payload, metadata, self.fixture.actor_pem)
        self.assertIsNone(direct._gateway_guard)
        self.assertTrue(direct.assert_live())


if __name__ == "__main__":
    unittest.main()
