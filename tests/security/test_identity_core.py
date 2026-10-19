"""Positive and adversarial tests for the transport-neutral C1a identity core."""

from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
import os
import stat
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import unittest
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from steamboat_security import (
    Authorizer, BindingError, Clock, ClockError, CredentialError,
    InvitationRegistry, LocalIdentity, ScopeError, SessionBindings,
    SessionError, SnapshotError, SnapshotStore, StorageError,
    certificate_sha256, create_invitation, enroll_invited,
    encode_binding, generate_authorization_signing_key_pem, generate_ca,
    generate_private_key_pem, identity_uri, issue_leaf, make_csr, make_renewal_proof,
    new_boot_id, new_id, parse_metadata, public_key_sha256, renew_leaf,
    safe_read, safe_write, serial_hex, sign_snapshot, snapshot_public_key_pem,
    verify_expected_server_leaf,
    verify_leaf,
)
from steamboat_security.certificates import _pem_certificate
from steamboat_security.files import _check_path_stat
from steamboat_security.operator import _record_from_leaf
from steamboat_security.snapshot import SNAPSHOT_REFRESH_SECONDS, SNAPSHOT_EXPIRY_CHECK_SECONDS


NOW = 1_800_000_000
MODEL = "a" * 64
ASSIGNMENT = "asg_" + "1" * 32
ACCOUNT_A = "acct_" + "1" * 32
ACCOUNT_B = "acct_" + "2" * 32
DEVICE_CONSUMER = "dev_" + "1" * 32
DEVICE_COORDINATOR = "dev_" + "2" * 32
DEVICE_HOST = "dev_" + "3" * 32
DEVICE_ALT_COORDINATOR = "dev_" + "4" * 32
BOOT_CONSUMER = "b" * 32
BOOT_COORDINATOR = "c" * 32
BOOT_HOST = "d" * 32
BOOT_ALT_COORDINATOR = "e" * 32


class FakeTime:
    def __init__(self, wall=NOW, monotonic=100.0):
        self.wall = float(wall)
        self.monotonic = float(monotonic)
        self.uncertainty = 0.0
        self.resume = 0

    def clock(self):
        return Clock(wall=lambda: self.wall, monotonic=lambda: self.monotonic,
                     uncertainty_seconds=lambda: self.uncertainty,
                     resume_token=lambda: self.resume)

    def advance(self, seconds):
        self.wall += seconds
        self.monotonic += seconds


def _fake_message(full_name, **values):
    return SimpleNamespace(DESCRIPTOR=SimpleNamespace(full_name=full_name), **values)


class ParsedWorkerRequest:
    """Dependency-free exact-type fixture; production injects generated worker_pb2.Request."""

    DESCRIPTOR = SimpleNamespace(full_name="steamboat.v1.Request")

    def __init__(self, **values):
        self.__dict__.update(values)

    def ByteSize(self):
        return sum(len(str(key).encode("utf-8")) + len(str(value).encode("utf-8"))
                   for key, value in vars(self).items())


class IdentityFixture(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ca_pem, cls.ca_key = generate_ca(now=NOW - 3600)
        cls.signing_key = generate_authorization_signing_key_pem()
        cls.signing_public = snapshot_public_key_pem(cls.signing_key)
        cls.identities = {
            "consumer": (ACCOUNT_A, DEVICE_CONSUMER, "consumer", BOOT_CONSUMER, ("client",), ()),
            "coordinator": (ACCOUNT_A, DEVICE_COORDINATOR, "personal_coordinator", BOOT_COORDINATOR,
                            ("client", "server"), ("coordinator.example",)),
            "host": (ACCOUNT_B, DEVICE_HOST, "host", BOOT_HOST, ("server",), ("worker.example",)),
            "alt_coordinator": (ACCOUNT_A, DEVICE_ALT_COORDINATOR, "personal_coordinator",
                                BOOT_ALT_COORDINATOR, ("client", "server"), ("alt.example",)),
        }
        cls.credentials = {}
        cls.records = {}
        for name, (account, device, role, _boot, ekus, dns) in cls.identities.items():
            key = generate_private_key_pem()
            csr = make_csr(key, account_id=account, device_id=device, role=role,
                           dns_sans=dns)
            cert = __import__("steamboat_security").issue_leaf(
                cls.ca_pem, cls.ca_key, csr, account_id=account, device_id=device,
                role=role, not_before=NOW - 60, not_after=NOW + 840, ekus=ekus)
            record = _record_from_leaf(cert, account_id=account, device_id=device,
                                       role=role, credential_epoch=1)
            cls.credentials[name] = {"key": key, "csr": csr, "certificate": cert,
                                     "record": record}
            cls.records[name] = record

    def fresh_time(self):
        return FakeTime()

    def grants(self, *, coordinator_record=None, host_record=None,
               coord_boot=BOOT_COORDINATOR, alt_record=None, expires=NOW + 300):
        coordinator = coordinator_record or self.records["coordinator"]
        host = host_record or self.records["host"]
        alt = alt_record or self.records["alt_coordinator"]
        output = []
        for actor_name, record, actor_boot in (
                ("coordinator", coordinator, coord_boot),
                ("alt_coordinator", alt, BOOT_ALT_COORDINATOR)):
            for method in ("Describe", "OpenSession", "RenewSession", "Step", "CloseSession",
                           "CancelSession", "SessionStatus"):
                output.append(self._grant(
                    actor=record, tenant=record["account_id"], target=host,
                    target_boot=BOOT_HOST, actor_boot=actor_boot,
                    assignment=ASSIGNMENT, model=MODEL,
                    method=f"steamboat.v1.Worker/{method}", not_after=expires))
        consumer = self.records["consumer"]
        for method in ("Describe", "Tokenize", "Generate"):
            output.append(self._grant(
                actor=consumer, tenant=consumer["account_id"],
                target=coordinator, target_boot=BOOT_COORDINATOR,
                actor_boot=None, assignment=None, model=MODEL,
                method=f"steamboat.v1.Coordinator/{method}", not_after=expires))
        return output

    @staticmethod
    def _grant(*, actor, tenant, target, target_boot, actor_boot,
               assignment, model, method, not_after):
        return {
            "account_id": actor["account_id"], "device_id": actor["device_id"],
            "role": actor["role"], "actor_serial": actor["serial"],
            "actor_public_key_sha256": actor["public_key_sha256"],
            "actor_credential_epoch": actor["credential_epoch"],
            "tenant_account_id": tenant,
            "target_account_id": target["account_id"],
            "target_device_id": target["device_id"], "target_role": target["role"],
            "target_serial": target["serial"],
            "target_public_key_sha256": target["public_key_sha256"],
            "target_credential_epoch": target["credential_epoch"],
            "target_boot_id": target_boot, "actor_boot_id": actor_boot,
            "assignment_id": assignment, "model_id": model, "method": method,
            "not_before": NOW, "not_after": not_after,
        }

    def payload(self, *, now=NOW, revision=1, records=None, grants=None,
                revoked_serials=(), revoked_devices=(), expiry=None):
        records = list(records if records is not None else self.records.values())
        grants = list(grants if grants is not None else self.grants())
        return {"version": 1, "revision": revision, "issued_at": now,
                "expires_at": expiry if expiry is not None else now + 300,
                "revoked_serials": sorted(revoked_serials),
                "revoked_devices": sorted(revoked_devices),
                "credentials": records, "grants": grants}

    def store(self, time_source=None, payload=None):
        time_source = time_source or self.fresh_time()
        clock = time_source.clock()
        store = SnapshotStore(verification_key_pem=self.signing_public,
                              ca_certificate_pem=self.ca_pem, clock=clock)
        store.install(sign_snapshot(payload or self.payload(), self.signing_key))
        return store, clock

    def issued_record_with_lifetime(self, name, lifetime_seconds):
        entry = self.credentials[name]
        identity = self.identities[name]
        certificate = issue_leaf(
            self.ca_pem, self.ca_key, entry["csr"], account_id=identity[0],
            device_id=identity[1], role=identity[2], not_before=NOW - 60,
            not_after=NOW + lifetime_seconds, ekus=entry["record"]["ekus"])
        record = _record_from_leaf(certificate, account_id=identity[0],
                                   device_id=identity[1], role=identity[2],
                                   credential_epoch=1)
        return certificate, record

    def worker_authorizer(self, *, time_source=None, store=None, sessions=None,
                          local_certificate=None):
        time_source = time_source or self.fresh_time()
        if store is None:
            store, clock = self.store(time_source)
        else:
            clock = store.clock
        sessions = sessions or SessionBindings(clock=clock)
        authorizer = Authorizer(
            local_identity=LocalIdentity(local_certificate or self.credentials["host"]["certificate"],
                                          BOOT_HOST, MODEL, ASSIGNMENT),
            snapshot_store=store, clock=clock, session_bindings=sessions,
            worker_request_type=ParsedWorkerRequest)
        return authorizer, sessions, time_source

    def coordinator_authorizer(self, *, time_source=None, store=None):
        time_source = time_source or self.fresh_time()
        if store is None:
            store, clock = self.store(time_source)
        else:
            clock = store.clock
        return Authorizer(
            local_identity=LocalIdentity(self.credentials["coordinator"]["certificate"],
                                          BOOT_COORDINATOR, MODEL),
            snapshot_store=store, clock=clock), time_source

    def worker_binding(self, method="OpenSession", *, actor_name="coordinator",
                       operation_id=None, session_id=None, request_id=None,
                       route_id=None, worker_boot=BOOT_HOST, assignment=ASSIGNMENT,
                       target=DEVICE_HOST, account=None, device=None, epoch=None,
                       route_epoch=1, attempt=1):
        actor = self.records[actor_name]
        fields = {"binding_version": 1,
                  "operation_id": operation_id or new_id("op"),
                  "account_id": account or actor["account_id"],
                  "device_id": device or actor["device_id"],
                  "role": actor["role"],
                  "credential_epoch": epoch if epoch is not None else actor["credential_epoch"],
                  "target_device_id": target}
        if method == "Describe":
            return fields
        fields.update({"coordinator_boot_id": self.identities[actor_name][3],
                       "tenant_account_id": actor["account_id"],
                       "request_id": request_id or new_id("req"),
                       "session_id": session_id or new_id("ses"),
                       "route_id": route_id or new_id("route"),
                       "route_epoch": route_epoch, "attempt": attempt,
                       "assignment_id": assignment, "worker_boot_id": worker_boot})
        return fields

    def open_payload(self, binding, *, lease="", max_positions=64,
                     lifetime_ms=120_000, idle_lease_ms=30_000):
        return ParsedWorkerRequest(protocol_version=1, manifest_fingerprint=MODEL,
                                   worker_boot_id=binding["worker_boot_id"],
                                   session_id=binding["session_id"], lease_token=lease,
                                   timeout_ms=30_000, max_positions=max_positions,
                                   lifetime_ms=lifetime_ms, idle_lease_ms=idle_lease_ms,
                                   sequence=0, start_position=0, token_count=0)

    def session_payload(self, binding, method, lease):
        return ParsedWorkerRequest(protocol_version=1, manifest_fingerprint=MODEL,
                                   worker_boot_id=binding["worker_boot_id"],
                                   session_id=binding["session_id"], lease_token=lease,
                                   timeout_ms=30_000, max_positions=0, lifetime_ms=0,
                                   idle_lease_ms=0, sequence=0, start_position=0,
                                   token_count=1)

    @staticmethod
    def response(*, method, payload, lease="", code="OK", reclaimed=False):
        return _fake_message(
            "steamboat.v1.Response", protocol_version=1,
            manifest_fingerprint=MODEL, worker_boot_id=BOOT_HOST,
            session_id=getattr(payload, "session_id", ""), lease_token=lease,
            code=code, message="", max_positions=getattr(payload, "max_positions", 0),
            sequence=getattr(payload, "sequence", 0),
            start_position=getattr(payload, "start_position", 0),
            token_count=getattr(payload, "token_count", 0),
            end_position=getattr(payload, "start_position", 0) + getattr(payload, "token_count", 0),
            next_sequence=getattr(payload, "sequence", 0) + (1 if method == "Step" else 0),
            reclaimed=reclaimed)

    @staticmethod
    def metadata(service, method, fields, extra=()):
        encoded = encode_binding(service, method, fields)
        return (("steamboat-binding-bin", encoded), *extra)


class CertificateTests(IdentityFixture):
    def test_issued_p256_role_certificates_pin_uri_sans_serial_keys_hash_and_eku(self):
        entry = self.credentials["host"]
        record = entry["record"]
        cert = verify_leaf(self.ca_pem, entry["certificate"], now=NOW + 1,
                           account_id=record["account_id"], device_id=record["device_id"],
                           role=record["role"], serial=record["serial"],
                           public_key_hash=record["public_key_sha256"],
                           certificate_hash=record["certificate_sha256"],
                           ekus=record["ekus"], dns_sans=record["dns_sans"])
        self.assertEqual(cert.serial_number, int(record["serial"], 16))
        self.assertEqual(public_key_sha256(cert.public_key()), record["public_key_sha256"])
        self.assertEqual(certificate_sha256(cert), record["certificate_sha256"])
        self.assertEqual(cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca, False)
        self.assertEqual(cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
                         .get_values_for_type(x509.UniformResourceIdentifier),
                         [identity_uri(ACCOUNT_B, DEVICE_HOST, "host")])
        self.assertEqual(verify_expected_server_leaf(
            self.ca_pem, entry["certificate"], now=NOW + 1,
            account_id=ACCOUNT_B, device_id=DEVICE_HOST, role="host",
            serial=record["serial"], public_key_hash=record["public_key_sha256"],
            certificate_hash=record["certificate_sha256"], expected_dns="worker.example",
            ekus=("server",)), entry["certificate"])

    def test_wrong_ca_identity_role_eku_san_hash_key_hash_and_serial_reject(self):
        entry = self.credentials["host"]
        record = entry["record"]
        other_ca, _ = generate_ca(now=NOW)
        wrong_calls = (
            lambda: verify_leaf(other_ca, entry["certificate"], now=NOW + 1,
                                account_id=ACCOUNT_B, device_id=DEVICE_HOST, role="host"),
            lambda: verify_leaf(self.ca_pem, entry["certificate"], now=NOW + 1,
                                account_id=ACCOUNT_A, device_id=DEVICE_HOST, role="host"),
            lambda: verify_leaf(self.ca_pem, entry["certificate"], now=NOW + 1,
                                account_id=ACCOUNT_B, device_id=DEVICE_CONSUMER, role="host"),
            lambda: verify_leaf(self.ca_pem, entry["certificate"], now=NOW + 1,
                                account_id=ACCOUNT_B, device_id=DEVICE_HOST, role="personal_coordinator"),
            lambda: verify_leaf(self.ca_pem, entry["certificate"], now=NOW + 1,
                                account_id=ACCOUNT_B, device_id=DEVICE_HOST, role="host", ekus=("client",)),
            lambda: verify_leaf(self.ca_pem, entry["certificate"], now=NOW + 1,
                                account_id=ACCOUNT_B, device_id=DEVICE_HOST, role="host", dns_sans=("elsewhere.example",)),
            lambda: verify_leaf(self.ca_pem, entry["certificate"], now=NOW + 1,
                                account_id=ACCOUNT_B, device_id=DEVICE_HOST, role="host",
                                certificate_hash="0" * 64),
            lambda: verify_leaf(self.ca_pem, entry["certificate"], now=NOW + 1,
                                account_id=ACCOUNT_B, device_id=DEVICE_HOST, role="host",
                                public_key_hash="0" * 64),
            lambda: verify_leaf(self.ca_pem, entry["certificate"], now=NOW + 1,
                                account_id=ACCOUNT_B, device_id=DEVICE_HOST, role="host",
                                serial="1"),
            lambda: verify_leaf(self.ca_pem, entry["certificate"], now=NOW + 1,
                                account_id=ACCOUNT_B, device_id=DEVICE_HOST, role="host",
                                expected_dns="other.example"),
        )
        for index, call in enumerate(wrong_calls):
            with self.subTest(case=index), self.assertRaises(CredentialError):
                call()

    def _raw_signed_leaf(self, *, key, issuer_cert, issuer_key, account, device,
                         role, not_before, not_after, ca_flag=False, eku="server"):
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "not an identity")])
        san = x509.SubjectAlternativeName([x509.UniformResourceIdentifier(identity_uri(account, device, role))])
        builder = (x509.CertificateBuilder().subject_name(name).issuer_name(issuer_cert.subject)
                   .public_key(key.public_key()).serial_number(int.from_bytes(b"\x01" * 16, "big"))
                   .not_valid_before(datetime.fromtimestamp(not_before, timezone.utc).replace(tzinfo=None))
                   .not_valid_after(datetime.fromtimestamp(not_after, timezone.utc).replace(tzinfo=None))
                   .add_extension(x509.BasicConstraints(ca=ca_flag, path_length=0 if ca_flag else None), critical=True)
                   .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False,
                                                key_encipherment=False, data_encipherment=False,
                                                key_agreement=False, key_cert_sign=False,
                                                crl_sign=False, encipher_only=None, decipher_only=None), critical=True)
                   .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH if eku == "server"
                                                        else ExtendedKeyUsageOID.CLIENT_AUTH]), critical=True)
                   .add_extension(san, critical=False))
        return builder.sign(issuer_key, hashes.SHA256()).public_bytes(serialization.Encoding.PEM)

    def test_expired_future_overlong_and_leaf_signed_leaf_reject(self):
        root = _pem_certificate(self.ca_pem)
        root_key = serialization.load_pem_private_key(self.ca_key, password=None)
        leaf_key = ec.generate_private_key(ec.SECP256R1())
        expired = self._raw_signed_leaf(key=leaf_key, issuer_cert=root, issuer_key=root_key,
                                        account=ACCOUNT_B, device=DEVICE_HOST, role="host",
                                        not_before=NOW - 100, not_after=NOW - 1)
        future = self._raw_signed_leaf(key=leaf_key, issuer_cert=root, issuer_key=root_key,
                                       account=ACCOUNT_B, device=DEVICE_HOST, role="host",
                                       not_before=NOW + 1, not_after=NOW + 100)
        overlong = self._raw_signed_leaf(key=leaf_key, issuer_cert=root, issuer_key=root_key,
                                         account=ACCOUNT_B, device=DEVICE_HOST, role="host",
                                         not_before=NOW - 1, not_after=NOW + 901)
        leaf_cert = _pem_certificate(self.credentials["host"]["certificate"])
        leaf_key = serialization.load_pem_private_key(self.credentials["host"]["key"], password=None)
        leaf_signed_leaf = self._raw_signed_leaf(key=ec.generate_private_key(ec.SECP256R1()),
                                                  issuer_cert=leaf_cert, issuer_key=leaf_key,
                                                  account=ACCOUNT_B, device=DEVICE_HOST, role="host",
                                                  not_before=NOW, not_after=NOW + 100)
        for label, pem in (("expired", expired), ("future", future),
                           ("overlong", overlong), ("leaf-signed-leaf", leaf_signed_leaf)):
            with self.subTest(case=label), self.assertRaises(CredentialError):
                verify_leaf(self.ca_pem, pem, now=NOW,
                            account_id=ACCOUNT_B, device_id=DEVICE_HOST, role="host")
        with self.assertRaises(CredentialError):
            __import__("steamboat_security").issue_leaf(
                self.ca_pem, self.ca_key, self.credentials["host"]["csr"],
                account_id=ACCOUNT_B, device_id=DEVICE_HOST, role="host",
                not_before=NOW, not_after=NOW + 901, ekus=("server",))


class ClockAndSnapshotTests(IdentityFixture):
    def test_callback_retention_is_bounded(self):
        time_source = self.fresh_time()
        store, clock = self.store(time_source)
        for _ in range(16):
            store.subscribe(lambda _view: None)
        with self.assertRaises(SnapshotError):
            store.subscribe(lambda _view: None)

        sessions = SessionBindings(clock=clock)
        for _ in range(16):
            sessions.subscribe(lambda _notice: None)
        with self.assertRaises(SessionError):
            sessions.subscribe(lambda _notice: None)

    def test_snapshot_signature_canonical_schema_bounds_and_rollback(self):
        time_source = self.fresh_time()
        store, _clock = self.store(time_source)
        self.assertEqual(store.current().revision, 1)
        payload2 = self.payload(revision=2, expiry=NOW + 240)
        store.install(sign_snapshot(payload2, self.signing_key))
        with self.assertRaises(SnapshotError):
            store.install(sign_snapshot(self.payload(revision=1), self.signing_key))
        with self.assertRaises(SnapshotError):
            store.install(sign_snapshot(self.payload(revision=2, expiry=NOW + 299), self.signing_key))
        wrong_key = generate_authorization_signing_key_pem()
        with self.assertRaises(SnapshotError):
            store.install(sign_snapshot(self.payload(revision=3), wrong_key))
        overlong = self.payload(revision=3, expiry=NOW + 301)
        with self.assertRaises(SnapshotError):
            sign_snapshot(overlong, self.signing_key)
        duplicate = b'{"payload":{},"payload":{},"signature":"AA=="}'
        with self.assertRaises(SnapshotError):
            store.install(duplicate)
        noncanonical = b'{ "payload": {}, "signature": "AA==" }'
        with self.assertRaises(SnapshotError):
            store.install(noncanonical)
        with self.assertRaises(SnapshotError):
            store.install(b"{" + b" " * (64 * 1024) + b"}")

    def test_snapshot_rejects_actual_device_account_role_and_authority_key_aliases(self):
        alias_account = "acct_" + "9" * 32
        alias_key = generate_private_key_pem()
        alias_csr = make_csr(alias_key, account_id=alias_account,
                             device_id=DEVICE_HOST, role="host",
                             dns_sans=("worker.example",))
        alias_cert = issue_leaf(self.ca_pem, self.ca_key, alias_csr,
                                account_id=alias_account, device_id=DEVICE_HOST,
                                role="host", not_before=NOW, not_after=NOW + 900,
                                ekus=("server",))
        alias_record = _record_from_leaf(alias_cert, account_id=alias_account,
                                         device_id=DEVICE_HOST, role="host",
                                         credential_epoch=1)
        records = list(self.records.values())
        records.append(alias_record)
        with self.assertRaises(SnapshotError):
            sign_snapshot(self.payload(records=records), self.signing_key)

        shared_key = generate_private_key_pem()
        shared_identity = "dev_" + "7" * 32
        shared_host_csr = make_csr(shared_key, account_id=ACCOUNT_A,
                                   device_id=shared_identity, role="host",
                                   dns_sans=("shared-host.example",))
        shared_coord_csr = make_csr(shared_key, account_id=ACCOUNT_A,
                                    device_id=shared_identity,
                                    role="personal_coordinator",
                                    dns_sans=("shared-coordinator.example",))
        shared_host_cert = issue_leaf(self.ca_pem, self.ca_key, shared_host_csr,
                                      account_id=ACCOUNT_A, device_id=shared_identity,
                                      role="host", not_before=NOW, not_after=NOW + 900,
                                      ekus=("server",))
        shared_coord_cert = issue_leaf(
            self.ca_pem, self.ca_key, shared_coord_csr, account_id=ACCOUNT_A,
            device_id=shared_identity, role="personal_coordinator", not_before=NOW,
            not_after=NOW + 900, ekus=("client", "server"))
        shared_records = [*self.records.values(),
                          _record_from_leaf(shared_host_cert, account_id=ACCOUNT_A,
                                            device_id=shared_identity, role="host",
                                            credential_epoch=1),
                          _record_from_leaf(shared_coord_cert, account_id=ACCOUNT_A,
                                            device_id=shared_identity,
                                            role="personal_coordinator",
                                            credential_epoch=1)]
        with self.assertRaises(SnapshotError):
            sign_snapshot(self.payload(records=shared_records), self.signing_key)

        signer_key = serialization.load_pem_private_key(self.signing_key, password=None)
        signer_key_pem = signer_key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption())
        signer_csr = make_csr(signer_key_pem, account_id=ACCOUNT_A,
                              device_id="dev_" + "6" * 32, role="consumer")
        signer_cert = issue_leaf(self.ca_pem, self.ca_key, signer_csr,
                                 account_id=ACCOUNT_A, device_id="dev_" + "6" * 32,
                                 role="consumer", not_before=NOW, not_after=NOW + 900,
                                 ekus=("client",))
        signer_records = [*self.records.values(),
                          _record_from_leaf(signer_cert, account_id=ACCOUNT_A,
                                            device_id="dev_" + "6" * 32,
                                            role="consumer", credential_epoch=1)]
        with self.assertRaises(SnapshotError):
            sign_snapshot(self.payload(records=signer_records), self.signing_key)

        ca_key_csr = make_csr(self.ca_key, account_id=ACCOUNT_A,
                              device_id="dev_" + "5" * 32, role="consumer")
        ca_key_cert = issue_leaf(self.ca_pem, self.ca_key, ca_key_csr,
                                 account_id=ACCOUNT_A, device_id="dev_" + "5" * 32,
                                 role="consumer", not_before=NOW, not_after=NOW + 900,
                                 ekus=("client",))
        ca_key_records = [*self.records.values(),
                          _record_from_leaf(ca_key_cert, account_id=ACCOUNT_A,
                                            device_id="dev_" + "5" * 32,
                                            role="consumer", credential_epoch=1)]
        encoded = sign_snapshot(self.payload(records=ca_key_records), self.signing_key)
        clock = self.fresh_time().clock()
        store = SnapshotStore(verification_key_pem=self.signing_public,
                             ca_certificate_pem=self.ca_pem, clock=clock)
        with self.assertRaises(SnapshotError):
            store.install(encoded)

    def test_snapshot_expiry_revoke_and_clock_anomalies_fail_closed(self):
        time_source = self.fresh_time()
        store, clock = self.store(time_source)
        time_source.advance(301)
        with self.assertRaises(SnapshotError):
            store.current()
        time_source = self.fresh_time()
        clock = time_source.clock()
        clock.sample()
        time_source.wall -= 1
        time_source.monotonic += 1
        with self.assertRaises(ClockError):
            clock.sample()
        time_source.wall += 10
        time_source.monotonic += 10
        with self.assertRaises(ClockError):
            clock.sample()  # anomaly remains latched after values look plausible
        with self.assertRaises(ClockError):
            clock.revalidate_after_resume(trusted_clock=False)
        clock.revalidate_after_resume(trusted_clock=True)
        clock.sample()
        time_source = self.fresh_time()
        clock = time_source.clock()
        clock.sample()
        time_source.wall += 60
        with self.assertRaises(ClockError):
            clock.sample()
        time_source = self.fresh_time()
        clock = time_source.clock()
        clock.sample()
        time_source.resume += 1
        with self.assertRaises(ClockError):
            clock.sample()
        with self.assertRaises(ClockError):
            clock.sample()
        clock.revalidate_after_resume(trusted_clock=True)
        clock.sample()
        time_source = self.fresh_time()
        time_source.uncertainty = 30.1
        with self.assertRaises(ClockError):
            time_source.clock().sample()
        with self.assertRaises(ClockError):
            Clock().sample()
        rollback_time = self.fresh_time()
        rollback_clock = rollback_time.clock()
        rollback_clock.sample()
        rollback_time.monotonic -= 1
        with self.assertRaises(ClockError):
            rollback_clock.sample()
        with self.assertRaises(ClockError):
            rollback_clock.revalidate_after_resume(trusted_clock=True)
        # The restart latch survives even if the monotonic counter catches up.
        rollback_time.monotonic += 2
        rollback_time.wall += 2
        with self.assertRaises(ClockError):
            rollback_clock.revalidate_after_resume(trusted_clock=True)
        with self.assertRaises(ClockError):
            rollback_clock.sample()

    def test_uncertainty_uses_conservative_validity_bounds_without_expiry_grace(self):
        # Snapshot expiry uses the latest plausible wall time.
        late = FakeTime(wall=NOW + 10, monotonic=110.0)
        late.uncertainty = 10.0
        late_store = SnapshotStore(verification_key_pem=self.signing_public,
                                   ca_certificate_pem=self.ca_pem, clock=late.clock())
        with self.assertRaises(SnapshotError):
            late_store.install(sign_snapshot(
                self.payload(now=NOW, expiry=NOW + 15), self.signing_key))

        # Neither a grant that may not have started nor one that may already
        # have expired is active within the uncertainty interval.
        uncertain = FakeTime(wall=NOW + 10, monotonic=110.0)
        uncertain.uncertainty = 10.0
        grants = self.grants(expires=NOW + 15)
        for grant in grants:
            grant["not_before"] = NOW + 5
        payload = self.payload(now=NOW, expiry=NOW + 200, grants=grants)
        store, clock = self.store(uncertain, payload)
        self.assertEqual(store.current().active_grants(clock.sample()), ())
        invite_registry = InvitationRegistry(
            verification_key_pem=self.signing_public, clock=clock)
        future_invite = create_invitation(
            self.signing_key, account_id=ACCOUNT_A, device_id=DEVICE_CONSUMER,
            roles=("consumer",), now=NOW + 5, lifetime_seconds=100)
        expired_invite = create_invitation(
            self.signing_key, account_id=ACCOUNT_A, device_id=DEVICE_CONSUMER,
            roles=("consumer",), now=NOW - 100, lifetime_seconds=115)
        for invite in (future_invite, expired_invite):
            with self.assertRaises(CredentialError):
                invite_registry.consume(invite)

        # Actual certificate notBefore and notAfter are checked against the
        # same conservative interval at admission.
        for not_before, not_after in ((NOW + 5, NOW + 800),
                                      (NOW - 60, NOW + 15)):
            with self.subTest(not_before=not_before, not_after=not_after):
                time_source = FakeTime(wall=NOW + 10, monotonic=110.0)
                time_source.uncertainty = 10.0
                actor = self.credentials["coordinator"]
                cert = issue_leaf(
                    self.ca_pem, self.ca_key, actor["csr"], account_id=ACCOUNT_A,
                    device_id=DEVICE_COORDINATOR, role="personal_coordinator",
                    not_before=not_before, not_after=not_after,
                    ekus=("client", "server"))
                record = _record_from_leaf(cert, account_id=ACCOUNT_A,
                                           device_id=DEVICE_COORDINATOR,
                                           role="personal_coordinator",
                                           credential_epoch=1)
                records = [item for name, item in self.records.items()
                           if name != "coordinator"] + [record]
                grants = self.grants(coordinator_record=record, expires=NOW + 200)
                store, _clock = self.store(
                    time_source,
                    self.payload(now=NOW, expiry=NOW + 200, records=records,
                                 grants=grants))
                authorizer, _sessions, _ = self.worker_authorizer(
                    time_source=time_source, store=store)
                binding = self.worker_binding()
                with self.assertRaises(CredentialError):
                    authorizer.authorize(
                        "steamboat.v1.Worker", "OpenSession", self.open_payload(binding),
                        self.metadata("steamboat.v1.Worker", "OpenSession", binding), cert)

    def test_refresh_never_extends_unchanged_absolute_expiry_caps(self):
        time_source = FakeTime()
        time_source.uncertainty = 10.0
        payload = self.payload(now=NOW - 20, expiry=NOW + 280,
                               grants=self.grants(expires=NOW + 300))
        store, _clock = self.store(time_source, payload)
        first = store.current()
        first_credentials = dict(first.credential_deadlines)
        first_grants = dict(first.grant_deadlines)
        time_source.advance(10)
        time_source.uncertainty = 0.0
        refreshed = self.payload(now=NOW, revision=2, expiry=NOW + 280,
                                 grants=self.grants(expires=NOW + 300))
        second = store.install(sign_snapshot(refreshed, self.signing_key))
        self.assertEqual(second.deadline_monotonic, first.deadline_monotonic)
        self.assertEqual(dict(second.credential_deadlines), first_credentials)
        self.assertEqual(dict(second.grant_deadlines), first_grants)

    def test_trusted_clock_revalidation_does_not_revive_expired_snapshot(self):
        time_source = self.fresh_time()
        store, clock = self.store(
            time_source, self.payload(expiry=NOW + 20))
        first_deadline = store.current().deadline_monotonic
        time_source.advance(10)
        clock.sample()
        # Latch a wall rollback, then revalidate against the explicitly trusted
        # injected clock. Existing monotonic expiry caps must survive the reset.
        time_source.wall -= 5
        with self.assertRaises(ClockError):
            clock.sample()
        clock.revalidate_after_resume(trusted_clock=True)
        self.assertEqual(store.current().deadline_monotonic, first_deadline)
        time_source.advance(11)
        with self.assertRaises(SnapshotError):
            store.current()

    def test_snapshot_cannot_extend_actual_issued_certificate_validity(self):
        for field, delta in (("not_before", 1), ("not_after", 100)):
            with self.subTest(field=field):
                time_source = FakeTime(wall=NOW + 5, monotonic=105.0)
                actor = self.credentials["coordinator"]
                actor_cert = issue_leaf(
                    self.ca_pem, self.ca_key, actor["csr"], account_id=ACCOUNT_A,
                    device_id=DEVICE_COORDINATOR, role="personal_coordinator",
                    not_before=NOW - 60, not_after=NOW + 300,
                    ekus=("client", "server"))
                actor_record = _record_from_leaf(
                    actor_cert, account_id=ACCOUNT_A, device_id=DEVICE_COORDINATOR,
                    role="personal_coordinator", credential_epoch=1)
                records = [record for name, record in self.records.items()
                           if name != "coordinator"] + [actor_record]
                actor_record[field] += delta
                store, _clock = self.store(
                    time_source,
                    self.payload(records=records,
                                 grants=self.grants(coordinator_record=actor_record,
                                                    expires=NOW + 200)))
                authorizer, _sessions, _ = self.worker_authorizer(
                    time_source=time_source, store=store)
                binding = self.worker_binding()
                with self.assertRaises(CredentialError):
                    authorizer.authorize(
                        "steamboat.v1.Worker", "OpenSession", self.open_payload(binding),
                        self.metadata("steamboat.v1.Worker", "OpenSession", binding),
                        actor_cert)

    def test_snapshot_refresh_keeps_unchanged_session_but_rotation_invalidates(self):
        time_source = self.fresh_time()
        initial_grants = self.grants(expires=NOW + 300)
        store, clock = self.store(
            time_source,
            self.payload(expiry=NOW + 120, grants=initial_grants))
        sessions = SessionBindings(clock=clock)
        authorizer = Authorizer(
            local_identity=LocalIdentity(self.credentials["host"]["certificate"],
                                          BOOT_HOST, MODEL, ASSIGNMENT),
            snapshot_store=store, clock=clock, session_bindings=sessions,
            worker_request_type=ParsedWorkerRequest)
        binding = self.worker_binding()
        payload = self.open_payload(binding, lifetime_ms=300_000)
        auth = authorizer.authorize("steamboat.v1.Worker", "OpenSession", payload,
                                    self.metadata("steamboat.v1.Worker", "OpenSession", binding),
                                    self.credentials["coordinator"]["certificate"])
        auth.complete(self.response(method="OpenSession", payload=payload, lease="f" * 32))
        self.assertEqual(auth.deadline_monotonic, 220.0)
        self.assertAlmostEqual(auth.remaining_seconds(), 120.0)
        time_source.advance(30)
        refreshed_grants = self.grants(expires=NOW + 300)
        store.install(sign_snapshot(self.payload(now=NOW + 30, revision=2,
                                                 expiry=NOW + 300,
                                                 grants=refreshed_grants),
                                    self.signing_key))
        self.assertEqual(sessions.records(), ())
        self.assertTrue(auth.assert_live())
        self.assertEqual(auth.deadline_monotonic, 400.0)
        self.assertAlmostEqual(auth.remaining_seconds(), 270.0)
        time_source.advance(130)
        self.assertTrue(auth.assert_live())

        # A new authority snapshot replaces the exact coordinator key/serial and
        # its grants. Existing owner/cache is invalidated and remains retained.
        new_key = generate_private_key_pem()
        new_csr = make_csr(new_key, account_id=ACCOUNT_A, device_id=DEVICE_COORDINATOR,
                           role="personal_coordinator", dns_sans=("coordinator.example",))
        new_cert = __import__("steamboat_security").issue_leaf(
            self.ca_pem, self.ca_key, new_csr, account_id=ACCOUNT_A,
            device_id=DEVICE_COORDINATOR, role="personal_coordinator",
            not_before=NOW, not_after=NOW + 900, ekus=("client", "server"))
        new_record = _record_from_leaf(new_cert, account_id=ACCOUNT_A,
                                       device_id=DEVICE_COORDINATOR,
                                       role="personal_coordinator", credential_epoch=2)
        records = [record for name, record in self.records.items() if name != "coordinator"]
        records.append(new_record)
        grants = self.grants(coordinator_record=new_record)
        rotated = self.payload(now=NOW + 160, revision=3, expiry=NOW + 300,
                               records=records, grants=grants)
        store.install(sign_snapshot(rotated, self.signing_key))
        notices = sessions.records()
        self.assertEqual(len(notices), 1)
        self.assertEqual(notices[0].session_id, binding["session_id"])
        self.assertEqual(sessions.record_count(), 1)
        with self.assertRaises(CredentialError):
            auth.assert_live()
        describe_binding = self.worker_binding("Describe", epoch=2)
        with self.assertRaises(SessionError):
            authorizer.authorize(
                "steamboat.v1.Worker", "Describe",
                ParsedWorkerRequest(protocol_version=1),
                self.metadata("steamboat.v1.Worker", "Describe", describe_binding),
                new_cert)
        blocked_binding = self.worker_binding(epoch=2)
        with self.assertRaises(SessionError):
            authorizer.authorize(
                "steamboat.v1.Worker", "OpenSession", self.open_payload(blocked_binding),
                self.metadata("steamboat.v1.Worker", "OpenSession", blocked_binding), new_cert)
        # Credential rotation cannot admit new work until trusted cleanup has
        # reclaimed every old owner for the affected principal.
        self.assertTrue(sessions.mark_reclaimed(target_device_id=DEVICE_HOST,
                                                worker_boot_id=BOOT_HOST,
                                                session_id=binding["session_id"]))
        for kwargs in (
                {"request_id": binding["request_id"], "route_id": new_id("route")},
                {"request_id": new_id("req"), "route_id": binding["route_id"]}):
            reused = self.worker_binding("OpenSession", epoch=2,
                                         session_id=new_id("ses"), **kwargs)
            with self.subTest(rotation_reuse=kwargs), self.assertRaises(SessionError):
                authorizer.authorize(
                    "steamboat.v1.Worker", "OpenSession", self.open_payload(reused),
                    self.metadata("steamboat.v1.Worker", "OpenSession", reused), new_cert)
        fresh_binding = self.worker_binding(epoch=2)
        self.assertNotEqual(fresh_binding["session_id"], binding["session_id"])
        self.assertNotEqual(fresh_binding["request_id"], binding["request_id"])
        self.assertNotEqual(fresh_binding["route_id"], binding["route_id"])
        fresh_payload = self.open_payload(fresh_binding)
        fresh_auth = authorizer.authorize(
            "steamboat.v1.Worker", "OpenSession", fresh_payload,
            self.metadata("steamboat.v1.Worker", "OpenSession", fresh_binding), new_cert)
        fresh_auth.complete(self.response(method="OpenSession", payload=fresh_payload,
                                          lease="2" * 32))
        self.assertTrue(fresh_auth.assert_live())
        close_binding = dict(fresh_binding, operation_id=new_id("op"))
        close_payload = self.session_payload(close_binding, "CancelSession", "2" * 32)
        close_auth = authorizer.authorize(
            "steamboat.v1.Worker", "CancelSession", close_payload,
            self.metadata("steamboat.v1.Worker", "CancelSession", close_binding), new_cert)
        close_auth.complete(self.response(method="CancelSession", payload=close_payload,
                                          lease="2" * 32, reclaimed=True))
        time_source.advance(31)
        sessions.poll()
        self.assertEqual(sessions.record_count(), 0)

    def test_authorization_deadline_is_earliest_policy_grant_both_credentials_or_session(self):
        cases = (
            (40, 80, 200, 250, 300, 40),   # actor credential
            (80, 40, 200, 250, 300, 40),   # local credential
            (180, 190, 50, 250, 300, 50),  # exact method grant
            (180, 190, 200, 50, 300, 50),  # signed snapshot
            (180, 190, 200, 250, 30, 30),  # opened session lifetime
        )
        for actor_ttl, local_ttl, grant_ttl, snapshot_ttl, session_ttl, expected in cases:
            with self.subTest(actor=actor_ttl, local=local_ttl, grant=grant_ttl,
                              snapshot=snapshot_ttl, session=session_ttl):
                time_source = self.fresh_time()
                actor_cert, actor_record = self.issued_record_with_lifetime(
                    "coordinator", actor_ttl)
                local_cert, local_record = self.issued_record_with_lifetime("host", local_ttl)
                records = [record for record in self.records.values()
                           if record["serial"] not in (self.records["coordinator"]["serial"],
                                                        self.records["host"]["serial"])]
                records.extend((actor_record, local_record))
                grants = self.grants(coordinator_record=actor_record,
                                     host_record=local_record, expires=NOW + grant_ttl)
                store, clock = self.store(
                    time_source,
                    self.payload(records=records, grants=grants,
                                 expiry=NOW + snapshot_ttl))
                sessions = SessionBindings(clock=clock)
                authorizer, _sessions, _ = self.worker_authorizer(
                    time_source=time_source, store=store, sessions=sessions,
                    local_certificate=local_cert)
                binding = self.worker_binding()
                payload = self.open_payload(binding, lifetime_ms=session_ttl * 1000)
                auth = authorizer.authorize(
                    "steamboat.v1.Worker", "OpenSession", payload,
                    self.metadata("steamboat.v1.Worker", "OpenSession", binding),
                    actor_cert)
                auth.complete(self.response(method="OpenSession", payload=payload,
                                            lease="a" * 32))
                self.assertEqual(auth.deadline_monotonic, 100.0 + expected)
                self.assertAlmostEqual(auth.remaining_seconds(), float(expected))
                auth.close()
                self.assertEqual(sessions.record_count(), 1)

    def _open_short_session_for_expiry_order(self, lifetime_ms=10_000):
        time_source = self.fresh_time()
        grants = self.grants(expires=NOW + 300)
        store, clock = self.store(
            time_source,
            self.payload(expiry=NOW + 300, grants=grants))
        sessions = SessionBindings(clock=clock)
        authorizer, _sessions, _ = self.worker_authorizer(
            time_source=time_source, store=store, sessions=sessions)
        binding = self.worker_binding()
        payload = self.open_payload(binding, lifetime_ms=lifetime_ms)
        auth = authorizer.authorize(
            "steamboat.v1.Worker", "OpenSession", payload,
            self.metadata("steamboat.v1.Worker", "OpenSession", binding),
            self.credentials["coordinator"]["certificate"])
        auth.complete(self.response(method="OpenSession", payload=payload,
                                    lease="e" * 32))
        return time_source, store, sessions, authorizer, grants, binding, auth

    def _open_session_with_claim_sample_advance(self, *, lifetime_ms=10_000):
        """Use real signed policy while the claim clock advances after admission."""
        time_source = self.fresh_time()
        grants = self.grants(expires=NOW + 300)
        store, clock = self.store(
            time_source,
            self.payload(expiry=NOW + 300, grants=grants))
        sessions = SessionBindings(clock=clock)
        authorizer, _sessions, _ = self.worker_authorizer(
            time_source=time_source, store=store, sessions=sessions)
        original_claim = sessions.claim

        def claim_after_clock_advance(*args, **kwargs):
            # Authorizer has already calculated the requested absolute bound
            # from its admission sample. Model work between that sample and
            # SessionBindings' own claim-time sample, without wall tolerances.
            time_source.advance(0.001)
            return original_claim(*args, **kwargs)

        sessions.claim = claim_after_clock_advance
        binding = self.worker_binding()
        payload = self.open_payload(binding, lifetime_ms=lifetime_ms)
        auth = authorizer.authorize(
            "steamboat.v1.Worker", "OpenSession", payload,
            self.metadata("steamboat.v1.Worker", "OpenSession", binding),
            self.credentials["coordinator"]["certificate"])
        auth.complete(self.response(method="OpenSession", payload=payload,
                                    lease="f" * 32))
        return time_source, store, sessions, grants, auth

    def test_authorizer_requested_deadline_survives_later_claim_sample_and_refresh(self):
        for first in ("revalidate", "poll"):
            with self.subTest(first=first):
                time_source, store, sessions, grants, auth = (
                    self._open_session_with_claim_sample_advance())
                record = sessions._records[auth._session_key]
                # The Authorizer sampled 100.0; the claim sampled 100.001.
                # Its original requested deadline must remain the exact 110.0
                # bound, rather than being reconstructed from the later sample.
                self.assertEqual(time_source.monotonic, 100.001)
                self.assertEqual(record.requested_expiry_monotonic, 110.0)
                self.assertEqual(record.hard_expiry_monotonic, 110.0)

                time_source.advance(1.0)
                refreshed = self.payload(
                    now=NOW + 1, revision=2, expiry=NOW + 300,
                    grants=grants)
                store.install(sign_snapshot(refreshed, self.signing_key))
                record = sessions._records[auth._session_key]
                self.assertEqual(record.requested_expiry_monotonic, 110.0)
                self.assertEqual(record.hard_expiry_monotonic, 110.0)

                time_source.advance(8.999)
                self.assertEqual(time_source.monotonic, 110.0)
                if first == "poll":
                    notices = sessions.poll()
                    self.assertEqual(len(notices), 1)
                final = self.payload(
                    now=NOW + 10, revision=3, expiry=NOW + 300,
                    grants=grants)
                store.install(sign_snapshot(final, self.signing_key))
                self.assertEqual(sessions.records()[0].reason,
                                 "session-hard-expiry")
                self.assertEqual(record.requested_expiry_monotonic, 110.0)
                self.assertEqual(record.hard_expiry_monotonic, 110.0)

    def test_session_claim_rejects_malformed_original_and_effective_deadlines(self):
        time_source = self.fresh_time()
        store, clock = self.store(time_source)
        view = store.current()
        actor = view.credentials_by_serial[self.records["coordinator"]["serial"]]
        local = view.credentials_by_serial[self.records["host"]["serial"]]
        grant = next(item for item in view.grants
                     if item.method == "steamboat.v1.Worker/OpenSession"
                     and item.assignment_id == ASSIGNMENT)
        fields = self.worker_binding()
        binding = parse_metadata(
            "steamboat.v1.Worker", "OpenSession",
            self.metadata("steamboat.v1.Worker", "OpenSession", fields))
        malformed = (
            ("original bool", {"requested_expiry_monotonic": True,
                                "hard_expiry_monotonic": 110.0}),
            ("original NaN", {"requested_expiry_monotonic": float("nan"),
                               "hard_expiry_monotonic": 110.0}),
            ("original infinity", {"requested_expiry_monotonic": float("inf"),
                                    "hard_expiry_monotonic": 110.0}),
            ("original past", {"requested_expiry_monotonic": 99.0,
                                "hard_expiry_monotonic": 99.0}),
            ("original oversized integer", {
                "requested_expiry_monotonic": 10 ** 1000,
                "hard_expiry_monotonic": 110.0}),
            ("original beyond admission", {"requested_expiry_monotonic": 110.001,
                                            "hard_expiry_monotonic": 110.0}),
            ("original string", {"requested_expiry_monotonic": "110.0",
                                  "hard_expiry_monotonic": 110.0}),
            ("effective bool", {"requested_expiry_monotonic": 110.0,
                                "hard_expiry_monotonic": True}),
            ("effective NaN", {"requested_expiry_monotonic": 110.0,
                               "hard_expiry_monotonic": float("nan")}),
            ("effective infinity", {"requested_expiry_monotonic": 110.0,
                                    "hard_expiry_monotonic": float("inf")}),
            ("effective past", {"requested_expiry_monotonic": 110.0,
                                 "hard_expiry_monotonic": 99.0}),
            ("effective oversized integer", {
                "requested_expiry_monotonic": 110.0,
                "hard_expiry_monotonic": 10 ** 1000}),
            ("effective after original", {"requested_expiry_monotonic": 110.0,
                                           "hard_expiry_monotonic": 110.001}),
        )
        for label, deadlines in malformed:
            with self.subTest(case=label):
                sessions = SessionBindings(clock=clock)
                with self.assertRaises(SessionError):
                    sessions.claim(
                        binding, actor=actor, local=local, grant=grant,
                        model_id=MODEL, lifetime_ms=10_000, max_positions=64,
                        idle_lease_ms=10_000, **deadlines)
                self.assertEqual(sessions.record_count(), 0)

        sessions = SessionBindings(clock=clock)
        claim = sessions.claim(
            binding, actor=actor, local=local, grant=grant, model_id=MODEL,
            lifetime_ms=10_000, max_positions=64, idle_lease_ms=10_000)
        record = sessions._records[claim.key]
        self.assertEqual(record.requested_expiry_monotonic, 110.0)
        self.assertEqual(record.hard_expiry_monotonic, 110.0)

    def test_session_expiry_reason_is_stable_when_revalidation_or_poll_runs_first(self):
        for first in ("revalidate", "poll"):
            with self.subTest(first=first):
                time_source, store, sessions, _authorizer, grants, _binding, auth = (
                    self._open_short_session_for_expiry_order())
                time_source.advance(10)
                if first == "revalidate":
                    refreshed = self.payload(
                        now=NOW + 10, revision=2, expiry=NOW + 300,
                        grants=grants)
                    store.install(sign_snapshot(refreshed, self.signing_key))
                else:
                    notices = sessions.poll()
                    self.assertEqual(len(notices), 1)
                    refreshed = self.payload(
                        now=NOW + 10, revision=2, expiry=NOW + 300,
                        grants=grants)
                    store.install(sign_snapshot(refreshed, self.signing_key))
                self.assertEqual(sessions.records()[0].reason, "session-hard-expiry")
                self.assertEqual(sessions.record_count(), 1)
                with self.assertRaises(SessionError):
                    auth.assert_live()

    def test_changed_policy_at_session_deadline_remains_snapshot_change(self):
        time_source, store, sessions, _authorizer, _grants, _binding, auth = (
            self._open_short_session_for_expiry_order())
        time_source.advance(10)
        actor_serial = self.records["coordinator"]["serial"]
        records = [record for name, record in self.records.items()
                   if name != "coordinator"]
        grants = [grant for grant in self.grants(expires=NOW + 300)
                  if grant["actor_serial"] != actor_serial
                  and grant["target_serial"] != actor_serial]
        changed = self.payload(
            now=NOW + 10, revision=2, expiry=NOW + 300,
            records=records, grants=grants, revoked_serials=(actor_serial,))
        store.install(sign_snapshot(changed, self.signing_key))
        self.assertEqual(sessions.records()[0].reason,
                         "authorization-snapshot-changed")
        self.assertEqual(sessions.record_count(), 1)
        with self.assertRaises(CredentialError):
            auth.assert_live()

    def test_policy_clipped_expiry_keeps_shorter_deadline_and_strict_reason(self):
        time_source, store, sessions, _authorizer, grants, _binding, auth = (
            self._open_short_session_for_expiry_order(lifetime_ms=30_000))
        time_source.advance(1)
        shortened = self.payload(
            now=NOW + 1, revision=2, expiry=NOW + 5,
            grants=grants)
        store.install(sign_snapshot(shortened, self.signing_key))
        self.assertEqual(auth.deadline_monotonic, 105.0)
        self.assertAlmostEqual(auth.remaining_seconds(), 4.0)
        time_source.advance(4)
        sessions.poll()
        self.assertEqual(sessions.records()[0].reason,
                         "authorization-snapshot-changed")
        self.assertEqual(sessions.record_count(), 1)

    def test_authorization_snapshot_revocation_notifies_bounded_cleanup_watcher(self):
        time_source = self.fresh_time()
        store, clock = self.store(time_source)
        sessions = SessionBindings(clock=clock)
        authorizer = Authorizer(
            local_identity=LocalIdentity(self.credentials["host"]["certificate"], BOOT_HOST,
                                          MODEL, ASSIGNMENT),
            snapshot_store=store, clock=clock, session_bindings=sessions,
            worker_request_type=ParsedWorkerRequest)
        notice_calls = []
        sessions.subscribe(notice_calls.append)
        binding = self.worker_binding()
        payload = self.open_payload(binding)
        auth = authorizer.authorize("steamboat.v1.Worker", "OpenSession", payload,
                                    self.metadata("steamboat.v1.Worker", "OpenSession", binding),
                                    self.credentials["coordinator"]["certificate"])
        auth.complete(self.response(method="OpenSession", payload=payload, lease="9" * 32))
        active_records = [record for name, record in self.records.items() if name != "coordinator"]
        coordinator_serial = self.records["coordinator"]["serial"]
        revoked = self.payload(revision=2, records=active_records,
                               grants=[g for g in self.grants()
                                       if g["actor_serial"] != coordinator_serial
                                       and g["target_serial"] != coordinator_serial],
                               revoked_serials=(self.records["coordinator"]["serial"],))
        store.install(sign_snapshot(revoked, self.signing_key))
        self.assertEqual(len(notice_calls), 1)
        self.assertEqual(len(authorizer.sweep()), 1)
        self.assertEqual(sessions.records()[0].reason, "authorization-snapshot-changed")


class CodecAndAuthorizationTests(IdentityFixture):
    def test_binding_codec_rejects_duplicate_unknown_type_scope_id_nesting_and_bounds(self):
        base = self.worker_binding("Describe")
        encoded = encode_binding("steamboat.v1.Worker", "Describe", base)
        binding = parse_metadata("steamboat.v1.Worker", "Describe",
                                 (("steamboat-binding-bin", encoded),))
        self.assertEqual(binding["binding_version"], 1)
        cases = (
            ("steamboat.v1.Worker", "Describe", b'{"binding_version":1,"binding_version":1}'),
            ("steamboat.v1.Worker", "Describe", encode_binding("steamboat.v1.Worker", "Describe", base)[:-1] + b',"unknown":1}'),
            ("steamboat.v1.Worker", "Describe", b'{"binding_version":NaN}'),
            ("steamboat.v1.Worker", "Describe", b'{"binding_version":true}'),
            ("steamboat.v1.Worker", "Describe", b'{"binding_version":{"nested":1}}'),
            ("steamboat.v1.Worker", "Step", encoded),
        )
        for service, method, raw in cases:
            with self.subTest(service=service, method=method, raw=raw[:20]), self.assertRaises(BindingError):
                parse_metadata(service, method, (("steamboat-binding-bin", raw),))
        with self.assertRaises(BindingError):
            parse_metadata("steamboat.v1.Worker", "Describe", (
                ("steamboat-binding-bin", encoded), ("steamboat-binding-bin", encoded)))
        with self.assertRaises(BindingError):
            parse_metadata("steamboat.v1.Worker", "Describe", (
                ("x-extra", b"x" * 8100), ("steamboat-binding-bin", encoded)))
        with self.assertRaises(BindingError):
            parse_metadata("steamboat.v1.Worker", "Describe",
                           (("steamboat-binding-bin", b" " * 4097),))
        wrong_id = dict(base)
        wrong_id["operation_id"] = "op_" + "Z" * 32
        with self.assertRaises(BindingError):
            encode_binding("steamboat.v1.Worker", "Describe", wrong_id)
        with self.assertRaises(BindingError):
            encode_binding("steamboat.v1.Worker", "OpenSession",
                           self.worker_binding("OpenSession", route_epoch=2))
        authorizer, _sessions, _time = self.worker_authorizer()
        describe = self.worker_binding("Describe")
        fake_request = _fake_message("steamboat.v1.Request", protocol_version=1)
        with self.assertRaises(BindingError):
            authorizer.authorize(
                "steamboat.v1.Worker", "Describe", fake_request,
                self.metadata("steamboat.v1.Worker", "Describe", describe),
                self.credentials["coordinator"]["certificate"])
        child_env = os.environ.copy()
        inherited_pythonpath = child_env.get("PYTHONPATH")
        child_env["PYTHONPATH"] = os.pathsep.join(
            path for path in (str(ROOT / "src"), inherited_pythonpath) if path
        )
        isolated_import = subprocess.run(
            [
                sys.executable,
                "-c",
                "import sys\n"
                "import steamboat_security\n"
                "if any(name == 'torch' or name.startswith('torch.') "
                "for name in sys.modules):\n"
                "    raise SystemExit('security core imported Torch')\n",
            ],
            cwd=ROOT,
            env=child_env,
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
        self.assertEqual(
            isolated_import.returncode,
            0,
            msg=(
                "fresh interpreter could not import the security core without Torch: "
                f"{isolated_import.stderr.strip()}"
            ),
        )

    def test_consumer_personal_same_account_and_role_scopes(self):
        authorizer, _time = self.coordinator_authorizer()
        fields = {"binding_version": 1, "operation_id": new_id("op"),
                  "account_id": ACCOUNT_A, "device_id": DEVICE_CONSUMER,
                  "role": "consumer", "credential_epoch": 1,
                  "target_device_id": DEVICE_COORDINATOR}
        auth = authorizer.authorize(
            "steamboat.v1.Coordinator", "Describe", {},
            self.metadata("steamboat.v1.Coordinator", "Describe", fields),
            self.credentials["consumer"]["certificate"])
        self.assertEqual(auth.binding_bytes, encode_binding("steamboat.v1.Coordinator", "Describe", fields))
        auth.complete({"ready": True})

        tokenize_fields = dict(fields, operation_id=new_id("op"))
        tokenize = authorizer.authorize(
            "steamboat.v1.Coordinator", "Tokenize",
            {"text": "synthetic prompt", "add_special_tokens": True},
            self.metadata("steamboat.v1.Coordinator", "Tokenize", tokenize_fields),
            self.credentials["consumer"]["certificate"])
        tokenize.complete({"input_ids": [1, 2]})

        generate_fields = dict(fields, operation_id=new_id("op"), request_id=new_id("req"))
        generate_payload = {"input_ids": [1], "new_tokens": 1,
                            "timeout_seconds": 30, "capture_logits": False}
        generate = authorizer.authorize(
            "steamboat.v1.Coordinator", "Generate", generate_payload,
            self.metadata("steamboat.v1.Coordinator", "Generate", generate_fields),
            self.credentials["consumer"]["certificate"])
        generate.complete({"type": "result"})
        reused_request = dict(generate_fields, operation_id=new_id("op"))
        with self.assertRaises(ScopeError):
            authorizer.authorize(
                "steamboat.v1.Coordinator", "Generate", generate_payload,
                self.metadata("steamboat.v1.Coordinator", "Generate", reused_request),
                self.credentials["consumer"]["certificate"])
        with self.assertRaises(BindingError):
            authorizer.authorize("steamboat.v1.Coordinator", "Open", {}, (),
                                 self.credentials["consumer"]["certificate"])

        wrong_target = dict(fields, operation_id=new_id("op"), target_device_id=DEVICE_HOST)
        with self.assertRaises(ScopeError):
            authorizer.authorize("steamboat.v1.Coordinator", "Describe", {},
                                 self.metadata("steamboat.v1.Coordinator", "Describe", wrong_target),
                                 self.credentials["consumer"]["certificate"])
        wrong_account = dict(fields, operation_id=new_id("op"), account_id=ACCOUNT_B)
        with self.assertRaises(CredentialError):
            authorizer.authorize("steamboat.v1.Coordinator", "Describe", {},
                                 self.metadata("steamboat.v1.Coordinator", "Describe", wrong_account),
                                 self.credentials["consumer"]["certificate"])
        host_actor = dict(fields, operation_id=new_id("op"), account_id=ACCOUNT_B,
                          device_id=DEVICE_HOST, role="host", credential_epoch=1)
        with self.assertRaises(ScopeError):
            authorizer.authorize("steamboat.v1.Coordinator", "Describe", {},
                                 self.metadata("steamboat.v1.Coordinator", "Describe", host_actor),
                                 self.credentials["host"]["certificate"])

        cross_account = dict(fields, operation_id=new_id("op"), device_id=DEVICE_ALT_COORDINATOR)
        with self.assertRaises(CredentialError):
            authorizer.authorize("steamboat.v1.Coordinator", "Describe", {},
                                 self.metadata("steamboat.v1.Coordinator", "Describe", cross_account),
                                 self.credentials["consumer"]["certificate"])

    def test_open_claim_precedes_handler_and_two_phase_lease_sealing(self):
        authorizer, sessions, _time = self.worker_authorizer()
        binding = self.worker_binding()
        payload = self.open_payload(binding)
        auth = authorizer.authorize("steamboat.v1.Worker", "OpenSession", payload,
                                    self.metadata("steamboat.v1.Worker", "OpenSession", binding),
                                    self.credentials["coordinator"]["certificate"])
        # Owner is installed before the hypothetical handler is called.
        self.assertEqual(sessions.record_count(), 1)
        self.assertTrue(auth.assert_live())
        lease = "f" * 32
        response = self.response(method="OpenSession", payload=payload, lease=lease)
        auth.complete(response)
        self.assertTrue(auth.assert_live())

        duplicate = dict(binding, operation_id=new_id("op"))
        duplicate_auth = authorizer.authorize("steamboat.v1.Worker", "OpenSession",
                                              self.open_payload(duplicate),
                                              self.metadata("steamboat.v1.Worker", "OpenSession", duplicate),
                                              self.credentials["coordinator"]["certificate"])
        duplicate_auth.complete(self.response(method="OpenSession",
                                              payload=self.open_payload(duplicate), lease=lease))
        self.assertEqual(sessions.record_count(), 1)
        stolen = self.worker_binding("OpenSession", actor_name="alt_coordinator",
                                     session_id=binding["session_id"], request_id=binding["request_id"],
                                     route_id=binding["route_id"])
        stolen_payload = self.open_payload(stolen)
        with self.assertRaises(SessionError):
            authorizer.authorize("steamboat.v1.Worker", "OpenSession", stolen_payload,
                                 self.metadata("steamboat.v1.Worker", "OpenSession", stolen),
                                 self.credentials["alt_coordinator"]["certificate"])
        self.assertEqual(sessions.record_count(), 1)

        step_binding = dict(binding, operation_id=new_id("op"))
        step_payload = self.session_payload(step_binding, "Step", lease)
        step_auth = authorizer.authorize("steamboat.v1.Worker", "Step", step_payload,
                                         self.metadata("steamboat.v1.Worker", "Step", step_binding),
                                         self.credentials["coordinator"]["certificate"])
        step_response = self.response(method="Step", payload=step_payload, lease=lease)
        step_auth.complete(step_response)
        status_binding = dict(binding, operation_id=new_id("op"))
        status_payload = self.session_payload(status_binding, "SessionStatus", lease)
        status_auth = authorizer.authorize("steamboat.v1.Worker", "SessionStatus", status_payload,
                                           self.metadata("steamboat.v1.Worker", "SessionStatus", status_binding),
                                           self.credentials["coordinator"]["certificate"])
        status_auth.complete(self.response(method="SessionStatus", payload=status_payload, lease=lease))

        bad_duplicate = dict(binding, operation_id=new_id("op"))
        bad_duplicate_auth = authorizer.authorize(
            "steamboat.v1.Worker", "OpenSession", self.open_payload(bad_duplicate),
            self.metadata("steamboat.v1.Worker", "OpenSession", bad_duplicate),
            self.credentials["coordinator"]["certificate"])
        with self.assertRaises(SessionError):
            bad_duplicate_auth.complete(self.response(
                method="OpenSession", payload=self.open_payload(bad_duplicate),
                lease="0" * 32))
        self.assertEqual(sessions.records()[0].reason, "duplicate-open-lease-mismatch")

    def test_stolen_lease_wrong_target_assignment_duplicate_operation_and_cleanup(self):
        authorizer, sessions, time_source = self.worker_authorizer()
        binding = self.worker_binding()
        payload = self.open_payload(binding)
        opened = authorizer.authorize("steamboat.v1.Worker", "OpenSession", payload,
                                      self.metadata("steamboat.v1.Worker", "OpenSession", binding),
                                      self.credentials["coordinator"]["certificate"])
        opened.complete(self.response(method="OpenSession", payload=payload, lease="1" * 32))
        bad_target = dict(binding, operation_id=new_id("op"), target_device_id="dev_" + "9" * 32)
        with self.assertRaises(ScopeError):
            authorizer.authorize("steamboat.v1.Worker", "Step",
                                 self.session_payload(bad_target, "Step", "1" * 32),
                                 self.metadata("steamboat.v1.Worker", "Step", bad_target),
                                 self.credentials["coordinator"]["certificate"])
        bad_assignment = dict(binding, operation_id=new_id("op"), assignment_id="asg_" + "9" * 32)
        with self.assertRaises(ScopeError):
            authorizer.authorize("steamboat.v1.Worker", "Step",
                                 self.session_payload(bad_assignment, "Step", "1" * 32),
                                 self.metadata("steamboat.v1.Worker", "Step", bad_assignment),
                                 self.credentials["coordinator"]["certificate"])
        stolen_binding = dict(binding, operation_id=new_id("op"))
        stolen_lease = self.session_payload(stolen_binding, "Step", "2" * 32)
        with self.assertRaises(SessionError):
            authorizer.authorize("steamboat.v1.Worker", "Step", stolen_lease,
                                 self.metadata("steamboat.v1.Worker", "Step",
                                               stolen_binding),
                                 self.credentials["coordinator"]["certificate"])

        replay_binding = dict(binding, operation_id=new_id("op"))
        replay_payload = self.session_payload(replay_binding, "SessionStatus", "1" * 32)
        replay_metadata = self.metadata("steamboat.v1.Worker", "SessionStatus", replay_binding)
        replay_auth = authorizer.authorize("steamboat.v1.Worker", "SessionStatus", replay_payload,
                                           replay_metadata,
                                           self.credentials["coordinator"]["certificate"])
        replay_auth.complete(self.response(method="SessionStatus", payload=replay_payload,
                                           lease="1" * 32))
        with self.assertRaises(ScopeError):
            authorizer.authorize("steamboat.v1.Worker", "SessionStatus", replay_payload,
                                 replay_metadata,
                                 self.credentials["coordinator"]["certificate"])

        late_step_binding = dict(binding, operation_id=new_id("op"))
        late_step_payload = self.session_payload(late_step_binding, "Step", "1" * 32)
        late_step_auth = authorizer.authorize(
            "steamboat.v1.Worker", "Step", late_step_payload,
            self.metadata("steamboat.v1.Worker", "Step", late_step_binding),
            self.credentials["coordinator"]["certificate"])
        late_status_binding = dict(binding, operation_id=new_id("op"))
        late_status_payload = self.session_payload(late_status_binding, "SessionStatus", "1" * 32)
        late_status_auth = authorizer.authorize(
            "steamboat.v1.Worker", "SessionStatus", late_status_payload,
            self.metadata("steamboat.v1.Worker", "SessionStatus", late_status_binding),
            self.credentials["coordinator"]["certificate"])
        cancel_binding = dict(binding, operation_id=new_id("op"))
        cancel_payload = self.session_payload(cancel_binding, "CancelSession", "1" * 32)
        cancel_auth = authorizer.authorize("steamboat.v1.Worker", "CancelSession", cancel_payload,
                                           self.metadata("steamboat.v1.Worker", "CancelSession", cancel_binding),
                                           self.credentials["coordinator"]["certificate"])
        cancel_auth.complete(self.response(method="CancelSession", payload=cancel_payload,
                                           lease="1" * 32, reclaimed=True))
        self.assertTrue(cancel_auth.assert_live())
        with self.assertRaises(SessionError):
            cancel_auth.complete(self.response(method="CancelSession", payload=cancel_payload,
                                               lease="1" * 32, reclaimed=False))
        with self.assertRaises(SessionError):
            late_step_auth.assert_live()
        with self.assertRaises(SessionError):
            late_step_auth.complete(self.response(method="Step", payload=late_step_payload,
                                                  lease="1" * 32))
        with self.assertRaises(SessionError):
            late_status_auth.assert_live()
        with self.assertRaises(SessionError):
            late_status_auth.complete(self.response(method="SessionStatus",
                                                    payload=late_status_payload,
                                                    lease="1" * 32))
        self.assertEqual(len(sessions.records()), 0)
        sessions.mark_reclaimed(target_device_id=DEVICE_HOST, worker_boot_id=BOOT_HOST,
                                 session_id=binding["session_id"])
        # Reclamation frees the cache owner, not its short-lived request/route
        # replay fences. A new session cannot reuse either retained ID.
        for kwargs in (
                {"request_id": binding["request_id"], "route_id": new_id("route")},
                {"request_id": new_id("req"), "route_id": binding["route_id"]}):
            replay_open = self.worker_binding(
                "OpenSession", session_id=new_id("ses"), **kwargs)
            with self.subTest(reused=kwargs), self.assertRaises(SessionError):
                authorizer.authorize(
                    "steamboat.v1.Worker", "OpenSession", self.open_payload(replay_open),
                    self.metadata("steamboat.v1.Worker", "OpenSession", replay_open),
                    self.credentials["coordinator"]["certificate"])
        time_source.advance(31)
        sessions.poll()
        self.assertEqual(sessions.record_count(), 0)

    def test_reclaimed_request_route_fences_are_worker_assignment_scoped(self):
        time_source = self.fresh_time()
        store, clock = self.store(time_source)
        view = store.current()
        actor = view.credentials_by_serial[self.records["coordinator"]["serial"]]
        local = view.credentials_by_serial[self.records["host"]["serial"]]
        grant = next(item for item in view.grants
                     if item.method == "steamboat.v1.Worker/OpenSession"
                     and item.assignment_id == ASSIGNMENT)
        sessions = SessionBindings(clock=clock)
        first_fields = self.worker_binding()
        first = parse_metadata("steamboat.v1.Worker", "OpenSession",
            self.metadata("steamboat.v1.Worker", "OpenSession", first_fields))
        first_claim = sessions.claim(first, actor=actor, local=local, grant=grant,
                                     model_id=MODEL, lifetime_ms=30_000,
                                     max_positions=64, idle_lease_ms=10_000)
        sessions.seal_open(first_claim, "a" * 32)
        sessions.mark_reclaimed(target_device_id=DEVICE_HOST,
                                worker_boot_id=BOOT_HOST,
                                session_id=first_fields["session_id"])

        # A pipeline may carry the same request/route IDs to another fixed
        # worker boot/assignment; the retained fence is scoped to its target.
        second_fields = self.worker_binding(
            session_id=new_id("ses"), request_id=first_fields["request_id"],
            route_id=first_fields["route_id"], target="dev_" + "9" * 32,
            worker_boot="f" * 32, assignment="asg_" + "9" * 32)
        second = parse_metadata("steamboat.v1.Worker", "OpenSession",
            self.metadata("steamboat.v1.Worker", "OpenSession", second_fields))
        second_claim = sessions.claim(second, actor=actor, local=local, grant=grant,
                                      model_id=MODEL, lifetime_ms=30_000,
                                      max_positions=64, idle_lease_ms=10_000)
        self.assertTrue(second_claim.is_new)

    def test_session_live_and_retained_record_bounds_never_evict_owner_state(self):
        time_source = self.fresh_time()
        store, clock = self.store(time_source)
        sessions = SessionBindings(clock=clock, max_live_sessions=1, max_records=2)
        authorizer, sessions, _ = self.worker_authorizer(
            time_source=time_source, store=store, sessions=sessions)

        first = self.worker_binding()
        first_payload = self.open_payload(first)
        first_auth = authorizer.authorize(
            "steamboat.v1.Worker", "OpenSession", first_payload,
            self.metadata("steamboat.v1.Worker", "OpenSession", first),
            self.credentials["coordinator"]["certificate"])
        first_auth.complete(self.response(method="OpenSession", payload=first_payload,
                                          lease="1" * 32))

        blocked = self.worker_binding()
        with self.assertRaises(SessionError):
            authorizer.authorize(
                "steamboat.v1.Worker", "OpenSession", self.open_payload(blocked),
                self.metadata("steamboat.v1.Worker", "OpenSession", blocked),
                self.credentials["coordinator"]["certificate"])
        self.assertEqual(sessions.record_count(), 1)

        cancel_binding = dict(first, operation_id=new_id("op"))
        cancel_payload = self.session_payload(cancel_binding, "CancelSession", "1" * 32)
        cancel_auth = authorizer.authorize(
            "steamboat.v1.Worker", "CancelSession", cancel_payload,
            self.metadata("steamboat.v1.Worker", "CancelSession", cancel_binding),
            self.credentials["coordinator"]["certificate"])
        cancel_auth.complete(self.response(method="CancelSession", payload=cancel_payload,
                                           lease="1" * 32, reclaimed=False))
        still_blocked = self.worker_binding()
        with self.assertRaises(SessionError):
            authorizer.authorize(
                "steamboat.v1.Worker", "OpenSession", self.open_payload(still_blocked),
                self.metadata("steamboat.v1.Worker", "OpenSession", still_blocked),
                self.credentials["coordinator"]["certificate"])
        self.assertTrue(sessions.mark_reclaimed(target_device_id=DEVICE_HOST,
                                                worker_boot_id=BOOT_HOST,
                                                session_id=first["session_id"]))

        second = self.worker_binding()
        second_payload = self.open_payload(second)
        second_auth = authorizer.authorize(
            "steamboat.v1.Worker", "OpenSession", second_payload,
            self.metadata("steamboat.v1.Worker", "OpenSession", second),
            self.credentials["coordinator"]["certificate"])
        second_auth.complete(self.response(method="OpenSession", payload=second_payload,
                                           lease="2" * 32))
        self.assertEqual(sessions.record_count(), 2)  # one tombstone plus one live owner

        third = self.worker_binding()
        with self.assertRaises(SessionError):
            authorizer.authorize(
                "steamboat.v1.Worker", "OpenSession", self.open_payload(third),
                self.metadata("steamboat.v1.Worker", "OpenSession", third),
                self.credentials["coordinator"]["certificate"])
        self.assertEqual(sessions.record_count(), 2)

    def test_pending_open_failure_is_bounded_and_requires_cleanup_when_ambiguous(self):
        authorizer, sessions, time_source = self.worker_authorizer()
        sessions = authorizer.session_bindings
        binding = self.worker_binding()
        auth = authorizer.authorize("steamboat.v1.Worker", "OpenSession",
                                    self.open_payload(binding),
                                    self.metadata("steamboat.v1.Worker", "OpenSession", binding),
                                    self.credentials["coordinator"]["certificate"])
        auth.fail(cache_may_exist=False)
        self.assertEqual(sessions.record_count(), 0)
        retry_binding = dict(binding, operation_id=new_id("op"))
        auth2 = authorizer.authorize("steamboat.v1.Worker", "OpenSession",
                                     self.open_payload(retry_binding),
                                     self.metadata("steamboat.v1.Worker", "OpenSession", retry_binding),
                                     self.credentials["coordinator"]["certificate"])
        auth2.fail(cache_may_exist=True)
        self.assertEqual(len(sessions.records()), 1)
        time_source.advance(31)
        sessions.poll()
        self.assertEqual(len(sessions.records()), 1)
        sessions.mark_reclaimed(target_device_id=DEVICE_HOST, worker_boot_id=BOOT_HOST,
                                 session_id=binding["session_id"])

    def test_pending_open_deadline_is_clipped_to_requested_session_lifetime(self):
        authorizer, sessions, time_source = self.worker_authorizer()
        binding = self.worker_binding()
        payload = self.open_payload(binding, lifetime_ms=1000)
        auth = authorizer.authorize(
            "steamboat.v1.Worker", "OpenSession", payload,
            self.metadata("steamboat.v1.Worker", "OpenSession", binding),
            self.credentials["coordinator"]["certificate"])
        self.assertAlmostEqual(auth.remaining_seconds(), 1.0)
        time_source.advance(2)
        with self.assertRaises(SessionError):
            auth.complete(self.response(method="OpenSession", payload=payload,
                                        lease="3" * 32))
        self.assertEqual(sessions.records()[0].reason, "open-admission-timeout")

    def test_fresh_ids_and_route_epoch_one_after_rotation_without_retry(self):
        ids = [new_id(prefix) for prefix in ("acct", "dev", "req", "ses", "route", "op", "asg")]
        self.assertEqual(len(set(ids)), len(ids))
        self.assertEqual(len(new_boot_id()), 32)
        binding = self.worker_binding("OpenSession", route_epoch=1, attempt=1)
        self.assertEqual(binding["route_epoch"], 1)
        for kwargs in ({"route_epoch": 2}, {"attempt": 2}):
            with self.subTest(kwargs=kwargs), self.assertRaises(BindingError):
                encode_binding("steamboat.v1.Worker", "OpenSession",
                               self.worker_binding("OpenSession", **kwargs))
        self.assertEqual(SNAPSHOT_REFRESH_SECONDS, 30)
        self.assertEqual(SNAPSHOT_EXPIRY_CHECK_SECONDS, 5)


class EnrollmentAndStorageTests(IdentityFixture):
    def test_enrollment_rejects_one_private_key_for_multiple_roles(self):
        time_source = self.fresh_time()
        signing_key = generate_authorization_signing_key_pem()
        registry = InvitationRegistry(
            verification_key_pem=snapshot_public_key_pem(signing_key),
            clock=time_source.clock())
        account = "acct_" + "8" * 32
        device = "dev_" + "8" * 32
        shared_key = generate_private_key_pem()
        csrs = {
            "host": make_csr(shared_key, account_id=account, device_id=device,
                             role="host", dns_sans=("role-host.example",)),
            "personal_coordinator": make_csr(
                shared_key, account_id=account, device_id=device,
                role="personal_coordinator", dns_sans=("role-coordinator.example",)),
        }
        invitation = create_invitation(
            signing_key, account_id=account, device_id=device,
            roles=("host", "personal_coordinator"), now=NOW, lifetime_seconds=600)
        with self.assertRaises(CredentialError):
            enroll_invited(invitation_registry=registry, invitation=invitation,
                           csr_by_role=csrs, ca_certificate_pem=self.ca_pem,
                           ca_private_key_pem=self.ca_key, now=NOW,
                           leaf_lifetime_seconds=900)

    def test_offline_one_use_invitation_enrollment_and_csr_renewal(self):
        time_source = self.fresh_time()
        clock = time_source.clock()
        signing_key = generate_authorization_signing_key_pem()
        registry = InvitationRegistry(verification_key_pem=snapshot_public_key_pem(signing_key),
                                      clock=clock)
        account, device, role = "acct_" + "8" * 32, "dev_" + "8" * 32, "host"
        key = generate_private_key_pem()
        csr = make_csr(key, account_id=account, device_id=device, role=role,
                       dns_sans=("new-worker.example",))
        invitation = create_invitation(signing_key, account_id=account, device_id=device,
                                       roles=(role,), now=NOW - 60, lifetime_seconds=600)
        leaves, records = enroll_invited(invitation_registry=registry, invitation=invitation,
                                         csr_by_role={role: csr}, ca_certificate_pem=self.ca_pem,
                                         ca_private_key_pem=self.ca_key, now=NOW - 60,
                                         leaf_lifetime_seconds=900,
                                         ekus_by_role={role: ("server",)})
        self.assertEqual(set(leaves), {role})
        self.assertEqual(records[0]["credential_epoch"], 1)
        with self.assertRaises(CredentialError):
            registry.consume(invitation)

        # The issuer verifies current signed authority, rather than trusting a
        # caller-supplied historical record. The device alone holds old_key.
        time_source.advance(700)
        authority_records = list(self.records.values()) + records
        current_grants = self.grants(host_record=records[0], expires=NOW + 900)
        for grant in current_grants:
            grant["not_before"] = NOW + 600
        current_payload = self.payload(now=NOW + 699, records=authority_records,
                                       grants=current_grants, expiry=NOW + 900)
        store, _clock = self.store(time_source, current_payload)
        new_key = generate_private_key_pem()
        new_csr = make_csr(new_key, account_id=account, device_id=device, role=role,
                           dns_sans=("new-worker.example",))
        proof = make_renewal_proof(key, leaves[role], new_csr)
        renewed, new_record = renew_leaf(ca_certificate_pem=self.ca_pem,
                                         ca_private_key_pem=self.ca_key,
                                         snapshot_store=store,
                                         old_certificate_pem=leaves[role],
                                         new_csr_pem=new_csr, renewal_proof=proof,
                                         leaf_lifetime_seconds=900)
        self.assertNotEqual(new_record["serial"], records[0]["serial"])
        self.assertEqual(new_record["credential_epoch"], 2)
        verify_leaf(self.ca_pem, renewed, now=NOW + 701, account_id=account,
                    device_id=device, role=role, serial=new_record["serial"],
                    public_key_hash=new_record["public_key_sha256"],
                    certificate_hash=new_record["certificate_sha256"], ekus=("server",))
        changed_scope_csr = make_csr(new_key, account_id=account, device_id=device,
                                     role=role, dns_sans=("other-worker.example",))
        changed_scope_proof = make_renewal_proof(key, leaves[role], changed_scope_csr)
        with self.assertRaises(CredentialError):
            renew_leaf(ca_certificate_pem=self.ca_pem, ca_private_key_pem=self.ca_key,
                       snapshot_store=store, old_certificate_pem=leaves[role],
                       new_csr_pem=changed_scope_csr, renewal_proof=changed_scope_proof,
                       )
        with self.assertRaises(CredentialError):
            renew_leaf(ca_certificate_pem=self.ca_pem, ca_private_key_pem=self.ca_key,
                       snapshot_store=store, old_certificate_pem=leaves[role],
                       new_csr_pem=new_csr, renewal_proof=b"{}")

        # A fresh but grantless authority view cannot renew a credential.
        no_grant_payload = self.payload(now=NOW + 699, revision=2,
                                        records=authority_records,
                                        grants=self.grants(expires=NOW + 300),
                                        expiry=NOW + 900)
        no_grant_store, _clock = self.store(time_source, no_grant_payload)
        with self.assertRaises(CredentialError):
            renew_leaf(ca_certificate_pem=self.ca_pem, ca_private_key_pem=self.ca_key,
                       snapshot_store=no_grant_store, old_certificate_pem=leaves[role],
                       new_csr_pem=new_csr, renewal_proof=proof)

        # Removed/revoked identity data is not revived by a historical CSR proof.
        removed_records = list(self.records.values())
        removed_payload = self.payload(now=NOW + 699, revision=2,
                                       records=removed_records,
                                       grants=self.grants(expires=NOW + 300),
                                       revoked_serials=(records[0]["serial"],),
                                       expiry=NOW + 900)
        removed_store, _clock = self.store(time_source, removed_payload)
        with self.assertRaises(CredentialError):
            renew_leaf(ca_certificate_pem=self.ca_pem, ca_private_key_pem=self.ca_key,
                       snapshot_store=removed_store, old_certificate_pem=leaves[role],
                       new_csr_pem=new_csr, renewal_proof=proof)

        # Renewal before the 300-second window and after snapshot expiry fail.
        early_time = FakeTime(wall=NOW + 500, monotonic=600.0)
        early_grants = self.grants(host_record=records[0], expires=NOW + 700)
        for grant in early_grants:
            grant["not_before"] = NOW + 400
        early_payload = self.payload(now=NOW + 499, records=authority_records,
                                     grants=early_grants,
                                     expiry=NOW + 700)
        early_store, _clock = self.store(early_time, early_payload)
        with self.assertRaises(CredentialError):
            renew_leaf(ca_certificate_pem=self.ca_pem, ca_private_key_pem=self.ca_key,
                       snapshot_store=early_store, old_certificate_pem=leaves[role],
                       new_csr_pem=new_csr, renewal_proof=proof)
        time_source.advance(201)
        with self.assertRaises(SnapshotError):
            renew_leaf(ca_certificate_pem=self.ca_pem, ca_private_key_pem=self.ca_key,
                       snapshot_store=store, old_certificate_pem=leaves[role],
                       new_csr_pem=new_csr, renewal_proof=proof)

    def test_linux_file_mode_owner_symlink_and_bounded_size_rejection_helpers(self):
        regular_0600 = SimpleNamespace(st_uid=1000, st_mode=0o100600)
        directory_0700 = SimpleNamespace(st_uid=1000, st_mode=0o040700)
        _check_path_stat(regular_0600, expected_uid=1000, mode=0o600,
                         directory=False, label="fixture")
        _check_path_stat(directory_0700, expected_uid=1000, mode=0o700,
                         directory=True, label="fixture")
        bad = (
            (SimpleNamespace(st_uid=1001, st_mode=0o100600), 1000, 0o600, False),
            (SimpleNamespace(st_uid=1000, st_mode=0o120600), 1000, 0o600, False),
            (SimpleNamespace(st_uid=1000, st_mode=0o100644), 1000, 0o600, False),
            (SimpleNamespace(st_uid=1000, st_mode=0o100700), 1000, 0o700, True),
        )
        for info, uid, mode, directory in bad:
            with self.subTest(info=info), self.assertRaises(StorageError):
                _check_path_stat(info, expected_uid=uid, mode=mode,
                                 directory=directory, label="fixture")
        if sys.platform != "linux":
            with self.assertRaises(StorageError):
                safe_read("/tmp/no-key", root="/tmp", expected_uid=1000, max_bytes=4096)

    @unittest.skipUnless(sys.platform == "linux", "requires Linux dirfd and O_NOFOLLOW")
    def test_linux_real_protected_files_symlinks_bounds_exclusive_create_and_fd_cleanup(self):
        uid = os.geteuid()
        with tempfile.TemporaryDirectory(prefix="steamboat-identity-") as temporary:
            base = Path(temporary)
            root = base / "credentials"
            root.mkdir(mode=0o700)
            os.chmod(root, 0o700)
            nested = root / "role"
            nested.mkdir(mode=0o700)
            os.chmod(nested, 0o700)
            key_path = nested / "role.pem"
            safe_write(key_path, b"synthetic-private-key", root=root,
                       expected_uid=uid, max_bytes=128)
            self.assertEqual(safe_read(key_path, root=root, expected_uid=uid,
                                       max_bytes=128), b"synthetic-private-key")
            self.assertEqual(key_path.stat().st_mode & 0o777, 0o600)
            os.chmod(root, 0o755)
            with self.assertRaises(StorageError):
                safe_read(key_path, root=root, expected_uid=uid, max_bytes=128)
            os.chmod(root, 0o700)
            os.chmod(nested, 0o755)
            with self.assertRaises(StorageError):
                safe_read(key_path, root=root, expected_uid=uid, max_bytes=128)
            os.chmod(nested, 0o700)
            with self.assertRaises(StorageError):
                safe_write(key_path, b"replacement", root=root,
                           expected_uid=uid, max_bytes=128)
            self.assertEqual(key_path.read_bytes(), b"synthetic-private-key")

            os.chmod(key_path, 0o640)
            with self.assertRaises(StorageError):
                safe_read(key_path, root=root, expected_uid=uid, max_bytes=128)
            os.chmod(key_path, 0o600)

            oversized = nested / "oversized.pem"
            oversized.write_bytes(b"123456")
            os.chmod(oversized, 0o600)
            with self.assertRaises(StorageError):
                safe_read(oversized, root=root, expected_uid=uid, max_bytes=5)
            with self.assertRaises(StorageError):
                safe_write(nested / "too-large.pem", b"123456", root=root,
                           expected_uid=uid, max_bytes=5)

            final_link = root / "final-link.pem"
            final_link.symlink_to(key_path)
            with self.assertRaises(StorageError):
                safe_read(final_link, root=root, expected_uid=uid, max_bytes=128)
            with self.assertRaises(StorageError):
                safe_write(final_link, b"should-not-follow", root=root,
                           expected_uid=uid, max_bytes=128)
            outside = base / "outside"
            outside.mkdir(mode=0o700)
            os.chmod(outside, 0o700)
            (outside / "role.pem").write_bytes(b"outside")
            os.chmod(outside / "role.pem", 0o600)
            intermediate_link = root / "linked-role"
            intermediate_link.symlink_to(outside, target_is_directory=True)
            with self.assertRaises(StorageError):
                safe_read(intermediate_link / "role.pem", root=root,
                          expected_uid=uid, max_bytes=128)
            with self.assertRaises(StorageError):
                safe_write(intermediate_link / "new.pem", b"no", root=root,
                           expected_uid=uid, max_bytes=128)

            # Repeated failures exercise descriptor cleanup after intermediate
            # and final component opens.
            fd_directory = Path("/proc/self/fd")
            before = len(tuple(fd_directory.iterdir()))
            for _ in range(40):
                with self.assertRaises(StorageError):
                    safe_read(root / "missing" / "no.pem", root=root,
                              expected_uid=uid, max_bytes=128)
            after = len(tuple(fd_directory.iterdir()))
            self.assertLessEqual(after, before + 1)

            # Race a directory rename with an intermediate symlink swap. Reads
            # may fail closed during the race, but may never observe outside data.
            race_dir = root / "race"
            held_dir = root / "race-held"
            race_dir.mkdir(mode=0o700)
            os.chmod(race_dir, 0o700)
            (race_dir / "data").write_bytes(b"inside")
            os.chmod(race_dir / "data", 0o600)
            (outside / "data").write_bytes(b"outside")
            os.chmod(outside / "data", 0o600)
            stop = threading.Event()

            def swap_directory():
                while not stop.is_set():
                    try:
                        os.rename(race_dir, held_dir)
                        os.symlink(outside, race_dir, target_is_directory=True)
                        os.unlink(race_dir)
                        os.rename(held_dir, race_dir)
                    except (FileNotFoundError, FileExistsError):
                        continue

            racer = threading.Thread(target=swap_directory, daemon=True)
            racer.start()
            try:
                for index in range(100):
                    # Exercise write traversal whether or not the concurrent
                    # read happens to succeed on this iteration.
                    try:
                        safe_write(race_dir / f"created-{index}", b"inside-only", root=root,
                                   expected_uid=uid, max_bytes=32)
                    except StorageError:
                        pass
                    try:
                        observed = safe_read(race_dir / "data", root=root,
                                             expected_uid=uid, max_bytes=32)
                    except StorageError:
                        continue
                    self.assertEqual(observed, b"inside")
            finally:
                stop.set()
                racer.join(timeout=2)
                if race_dir.is_symlink():
                    race_dir.unlink()
                if held_dir.exists() and not race_dir.exists():
                    os.rename(held_dir, race_dir)
            self.assertFalse((outside / "created").exists())

    @unittest.skipUnless(sys.platform == "linux", "requires Linux ownership semantics")
    def test_linux_real_foreign_uid_file_is_rejected(self):
        fixture = os.environ.get("STEAMBOAT_IDENTITY_FOREIGN_FIXTURE")
        if fixture:
            path = Path(fixture)
            self.assertNotEqual(path.stat().st_uid, os.geteuid())
            self.assertEqual(path.parent.stat().st_uid, os.geteuid())
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            with self.assertRaises(StorageError):
                safe_read(path, root=path.parent, expected_uid=os.geteuid(), max_bytes=128)
            return
        if os.geteuid() != 0:
            self.fail("provide the Docker ownership fixture for the required Linux UID test")
        with tempfile.TemporaryDirectory(prefix="steamboat-identity-uid-") as temporary:
            root = Path(temporary) / "credentials"
            root.mkdir(mode=0o700)
            os.chmod(root, 0o700)
            path = root / "foreign.pem"
            path.write_bytes(b"synthetic-key")
            os.chmod(path, 0o600)
            os.chown(path, 65534, 65534)
            with self.assertRaises(StorageError):
                safe_read(path, root=root, expected_uid=os.geteuid(), max_bytes=128)
