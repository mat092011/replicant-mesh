"""Whole-cohort root-transition issuance candidate tests with real credentials."""
from __future__ import annotations

from copy import deepcopy
from dataclasses import FrozenInstanceError, replace
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest.mock import patch
from datetime import datetime, timedelta, timezone

from cryptography.hazmat.primitives import serialization
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import NameOID

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from steamboat_security.certificates import (
    ROLE_EKUS, certificate_sha256, generate_ca, generate_private_key_pem,
    issue_leaf, make_csr, public_key_sha256, serial_hex, _pem_certificate,
)
from steamboat_security.clock import Clock
from steamboat_security.codec import canonical_json
from steamboat_security.errors import CredentialError, SnapshotError, StorageError
from steamboat_security.operator import (
    _record_from_leaf, generate_authorization_signing_key_pem, make_renewal_proof,
    snapshot_public_key_pem,
)
from steamboat_security.root_transition import AffectedPrincipal
from steamboat_security.root_transition import parse_root_transition_declaration
from steamboat_security.root_transition_issuance import (
    PrincipalIssuanceInput, prepare_root_transition_issuance,
)
from steamboat_security.root_transition_proof import make_old_role_key_possession_proof
from steamboat_security.root_transition_preparation import (
    LoadedPreparationIntent, PREPARATION_PURPOSE, PreparationIntent, _check_clock,
    load_protected_preparation_intent, parse_preparation_intent,
    make_preparation_possession_proof,
)
from steamboat_security.snapshot import SnapshotStore, canonical_policy_digest, sign_snapshot

NOW = 1_800_000_000
MODEL = "9" * 64


class MutableClock:
    def __init__(self, wall=NOW):
        self.wall = float(wall)
        self.mono = 100.0
        self.clock = Clock(wall=self._wall, monotonic=self._mono,
                           uncertainty_seconds=lambda: 0.0)

    def _wall(self):
        return self.wall

    def _mono(self):
        self.mono += 1.0
        return self.mono

    def advance(self, seconds):
        self.wall += seconds
        self.mono += seconds


class RootTransitionIssuanceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.old_ca, cls.old_ca_key = generate_ca(now=NOW - 3600)
        cls.new_ca, cls.new_ca_key = generate_ca(common_name="new test root", now=NOW - 3600)
        cls.old_snapshot_key = generate_authorization_signing_key_pem()
        cls.new_snapshot_key = generate_authorization_signing_key_pem()
        cls.old_snapshot_public = snapshot_public_key_pem(cls.old_snapshot_key)
        cls.new_snapshot_public = snapshot_public_key_pem(cls.new_snapshot_key)
        cls.clock_source = MutableClock()
        cls.account = "acct_" + "1" * 32
        cls.roles = []
        for index, role, dns, ips, serial in (
                (1, "host", ("worker.example",), ("127.0.0.1",), 0xA111),
                (2, "personal_coordinator", (), (), 0xA112)):
            device = f"dev_{index:032x}"
            boot = f"{index + 10:032x}"
            old_key = generate_private_key_pem()
            old_csr = make_csr(old_key, account_id=cls.account, device_id=device,
                               role=role, dns_sans=dns, ip_sans=ips)
            old_cert = issue_leaf(
                cls.old_ca, cls.old_ca_key, old_csr, account_id=cls.account,
                device_id=device, role=role, not_before=NOW - 500,
                not_after=NOW + 200, serial=serial,
                ekus=tuple(sorted(ROLE_EKUS[role])))
            old_record = _record_from_leaf(
                old_cert, account_id=cls.account, device_id=device,
                role=role, credential_epoch=4)
            new_key = generate_private_key_pem()
            new_csr = make_csr(new_key, account_id=cls.account, device_id=device,
                               role=role, dns_sans=dns, ip_sans=ips)
            cert = _pem_certificate(old_cert)
            principal = AffectedPrincipal(
                cls.account, device, role, boot, old_record["serial"],
                old_record["certificate_sha256"], old_record["public_key_sha256"],
                4, 7, hashlib.sha256(new_csr).hexdigest(), tuple(dns), tuple(ips))
            cls.roles.append({"principal": principal, "old_key": old_key,
                              "old_cert": old_cert, "new_key": new_key,
                              "new_csr": new_csr, "record": old_record,
                              "cert": cert})
        cls.roles.sort(key=lambda item: item["principal"].identity)
        cls.intent_document = {
            "purpose": PREPARATION_PURPOSE, "schema_version": 1,
            "transition_id": "1" * 32,
            "old_ca_sha256": certificate_sha256(_pem_certificate(cls.old_ca)),
            "new_ca_sha256": certificate_sha256(_pem_certificate(cls.new_ca)),
            "old_snapshot_key_sha256": public_key_sha256(
                serialization.load_pem_public_key(cls.old_snapshot_public)),
            "new_snapshot_key_sha256": public_key_sha256(
                serialization.load_pem_public_key(cls.new_snapshot_public)),
            "overlap_not_before": NOW - 10, "overlap_not_after": NOW + 250,
            "old_policy_revision": 4, "old_policy_digest": "0" * 64,
            "next_minimum_revision": 5,
            "affected_principals": [{
                "account_id": p.account_id, "device_id": p.device_id,
                "role": p.role, "old_boot_id": p.old_boot_id,
                "old_serial": p.old_serial,
                "old_certificate_sha256": p.old_certificate_sha256,
                "old_public_key_sha256": p.old_public_key_sha256,
                "old_credential_epoch": p.old_credential_epoch,
                "old_admission_epoch": p.old_admission_epoch,
                "new_csr_sha256": p.new_csr_sha256,
                "dns_sans": list(p.dns_sans), "ip_sans": list(p.ip_sans),
            } for p in (entry["principal"] for entry in cls.roles)],
        }
        cls.payload = cls.snapshot_payload()
        cls.intent_document["old_policy_digest"] = canonical_policy_digest(cls.payload)
        cls.intent = parse_preparation_intent(canonical_json(cls.intent_document))

    @classmethod
    def snapshot_payload(cls, *, revoked_serials=(), grants=None, revision=4):
        host, coordinator = cls.roles[0], cls.roles[1]
        pc = coordinator["record"]
        h = host["record"]
        grant = {
            "account_id": cls.account, "device_id": pc["device_id"],
            "role": "personal_coordinator", "actor_serial": pc["serial"],
            "actor_public_key_sha256": pc["public_key_sha256"],
            "actor_credential_epoch": 4, "tenant_account_id": cls.account,
            "target_account_id": cls.account, "target_device_id": h["device_id"],
            "target_role": "host", "target_serial": h["serial"],
            "target_public_key_sha256": h["public_key_sha256"],
            "target_credential_epoch": 4,
            "target_boot_id": host["principal"].old_boot_id,
            "actor_boot_id": coordinator["principal"].old_boot_id,
            "assignment_id": "asg_" + "3" * 32, "model_id": MODEL,
            "method": "steamboat.v1.Worker/Step",
            "not_before": NOW - 10, "not_after": NOW + 240,
        }
        return {
            "version": 1, "revision": revision, "issued_at": NOW - 10,
            "expires_at": NOW + 240,
            "revoked_serials": sorted(revoked_serials), "revoked_devices": [],
            "credentials": [deepcopy(entry["record"]) for entry in cls.roles],
            "grants": deepcopy(grants if grants is not None else [grant]),
        }

    def setUp(self):
        self.clock_source = MutableClock()
        self.store = SnapshotStore(
            verification_key_pem=self.old_snapshot_public,
            ca_certificate_pem=self.old_ca, clock=self.clock_source.clock)
        self.store.install(sign_snapshot(self.payload, self.old_snapshot_key))
        self.intents = self.intent
        self.inputs = tuple(PrincipalIssuanceInput(
            self.intent.affected_principals[index], entry["old_cert"], entry["new_csr"],
            make_preparation_possession_proof(
                self.intent, self.intent.affected_principals[index],
                old_private_key_pem=entry["old_key"],
                old_certificate_pem=entry["old_cert"], new_csr_pem=entry["new_csr"]))
            for index, entry in enumerate(self.roles))
        self.temp = tempfile.TemporaryDirectory(prefix="root-transition-issuance-")
        self.root = Path(self.temp.name) / "protected"
        self.root.mkdir()
        if os.name == "posix":
            os.chmod(self.root, 0o700)
        self.approval = self.root / "intent.json"
        self.approval.write_bytes(canonical_json(self.intent_document))
        if os.name == "posix":
            os.chmod(self.approval, 0o600)

    def tearDown(self):
        self.temp.cleanup()

    def call(self, **changes):
        real_loader = changes.pop("_real_loader", False)
        fresh_parsed = changes.pop("_fresh_parsed", False)
        intent = changes.pop("_intent", self.intent)
        input_batch = changes.pop("_inputs", self.inputs)
        store = changes.pop("_store", self.store)
        args = dict(
            approval_path=self.approval, approval_root=self.root,
            expected_uid=os.geteuid() if hasattr(os, "geteuid") else 0,
            clock=self.clock_source.clock, old_snapshot_store=store,
            new_ca_certificate_pem=self.new_ca,
            new_ca_private_key_pem=self.new_ca_key,
            new_snapshot_public_key_pem=self.new_snapshot_public,
            principal_inputs=input_batch)
        args.update(changes)
        if real_loader:
            return prepare_root_transition_issuance(**args)
        loaded = LoadedPreparationIntent(intent)
        def checked_loader(_path, *, root, expected_uid, clock):
            _check_clock(intent, clock)
            if fresh_parsed:
                return LoadedPreparationIntent(parse_preparation_intent(self.approval.read_bytes()))
            return loaded
        with patch("steamboat_security.root_transition_issuance.load_protected_preparation_intent",
                   side_effect=checked_loader):
            return prepare_root_transition_issuance(**args)

    def ca_using_key(self, key_pem):
        key = serialization.load_pem_private_key(key_pem, password=None)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test reused role key")])
        now = datetime.fromtimestamp(NOW - 3600, timezone.utc)
        cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
                .public_key(key.public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(now).not_valid_after(now + timedelta(days=10))
                .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
                .add_extension(x509.KeyUsage(digital_signature=False, content_commitment=False,
                    key_encipherment=False, data_encipherment=False, key_agreement=False,
                    key_cert_sign=True, crl_sign=True, encipher_only=None, decipher_only=None),
                    critical=True).sign(key, hashes.SHA256()))
        return cert.public_bytes(serialization.Encoding.PEM)

    def alternate_policy(self, payload, *, principal_edits=None, csr_by_index=None):
        """Create a self-consistent alternate old snapshot/intent for negative tests."""
        doc = deepcopy(self.intent_document)
        doc["old_policy_digest"] = canonical_policy_digest(payload)
        for index, edits in (principal_edits or {}).items():
            doc["affected_principals"][index].update(edits)
        intent = parse_preparation_intent(canonical_json(doc))
        batch = []
        for index, role_entry in enumerate(self.roles):
            principal = intent.affected_principals[index]
            csr = (csr_by_index or {}).get(index, role_entry["new_csr"])
            if index in (csr_by_index or {}):
                doc["affected_principals"][index]["new_csr_sha256"] = hashlib.sha256(csr).hexdigest()
                intent = parse_preparation_intent(canonical_json(doc))
                principal = intent.affected_principals[index]
            proof = make_preparation_possession_proof(
                intent, principal, old_private_key_pem=role_entry["old_key"],
                old_certificate_pem=role_entry["old_cert"], new_csr_pem=csr)
            batch.append(PrincipalIssuanceInput(
                principal, role_entry["old_cert"], csr, proof))
        alternate_store = SnapshotStore(
            verification_key_pem=self.old_snapshot_public,
            ca_certificate_pem=self.old_ca, clock=self.clock_source.clock)
        alternate_store.install(sign_snapshot(payload, self.old_snapshot_key))
        return intent, tuple(batch), alternate_store

    def alternate_intent(self, *, document_edits=None, csr_by_index=None,
                         new_snapshot_public_key_pem=None):
        doc = deepcopy(self.intent_document)
        for field, value in (document_edits or {}).items():
            doc[field] = value
        for index, csr in (csr_by_index or {}).items():
            doc["affected_principals"][index]["new_csr_sha256"] = hashlib.sha256(csr).hexdigest()
        if new_snapshot_public_key_pem is not None:
            doc["new_snapshot_key_sha256"] = public_key_sha256(
                serialization.load_pem_public_key(new_snapshot_public_key_pem))
        intent = parse_preparation_intent(canonical_json(doc))
        batch = []
        for index, role_entry in enumerate(self.roles):
            principal = intent.affected_principals[index]
            csr = (csr_by_index or {}).get(index, role_entry["new_csr"])
            proof = make_preparation_possession_proof(
                intent, principal, old_private_key_pem=role_entry["old_key"],
                old_certificate_pem=role_entry["old_cert"], new_csr_pem=csr)
            batch.append(PrincipalIssuanceInput(principal, role_entry["old_cert"], csr, proof))
        return intent, tuple(batch)

    def test_valid_whole_cohort_returns_immutable_real_certificates_and_manifest(self):
        result = self.call()
        self.assertEqual(len(result.principals), 2)
        manifest = json.loads(result.manifest)
        self.assertEqual(manifest["domain"], "steamboat.root-transition.private-issuance-manifest.v1")
        self.assertEqual(manifest["transition_id"], self.intent.transition_id)
        self.assertEqual(len(manifest["principals"]), 2)
        for issued, entry in zip(result.principals, manifest["principals"]):
            self.assertEqual(issued.record.credential_epoch, 5)
            self.assertEqual(issued.record.serial, entry["new_serial"])
            self.assertEqual(issued.record.public_key_sha256, entry["new_public_key_sha256"])
            self.assertEqual(issued.record.certificate_sha256, entry["new_certificate_sha256"])
            self.assertLessEqual(issued.record.not_after, NOW + 250)
            self.assertEqual(issued.record.ekus, tuple(sorted(ROLE_EKUS[issued.record.role])))
        with self.assertRaises(FrozenInstanceError):
            result.principals[0].record.credential_epoch = 9

        # Either authority may remain unchanged when the corresponding other
        # authority changes; same-role continuity is permitted by intent.
        ca_only_intent, ca_only_inputs = self.alternate_intent(document_edits={
            "new_snapshot_key_sha256": self.intent_document["old_snapshot_key_sha256"]})
        ca_only = self.call(_intent=ca_only_intent, _inputs=ca_only_inputs,
                            new_snapshot_public_key_pem=self.old_snapshot_public)
        self.assertEqual(len(ca_only.principals), 2)

        signer_only_intent, signer_only_inputs = self.alternate_intent(document_edits={
            "new_ca_sha256": self.intent_document["old_ca_sha256"]})
        signer_only = self.call(_intent=signer_only_intent, _inputs=signer_only_inputs,
                                new_ca_certificate_pem=self.old_ca,
                                new_ca_private_key_pem=self.old_ca_key)
        self.assertEqual(len(signer_only.principals), 2)

    def test_freshly_parsed_intent_accepts_value_identical_members_and_rejects_type_alias(self):
        result = self.call(_fresh_parsed=True)
        self.assertEqual(len(result.principals), 2)
        malformed = replace(self.inputs[0].principal, old_credential_epoch=True)
        batch = (replace(self.inputs[0], principal=malformed), self.inputs[1])
        calls = []
        with patch("steamboat_security.root_transition_issuance.issue_leaf",
                   side_effect=lambda *args, **kwargs: calls.append(args)):
            with self.assertRaises(CredentialError):
                self.call(_fresh_parsed=True, principal_inputs=batch)
        self.assertEqual(calls, [])

    def test_missing_extra_duplicate_inputs_and_invalid_batch_sign_zero_leaves(self):
        bad_batches = (self.inputs[:1], self.inputs + (self.inputs[0],),
                       (self.inputs[0], replace(self.inputs[0], principal=self.inputs[0].principal)))
        for batch in bad_batches:
            calls = []
            with self.subTest(batch_size=len(batch)), patch(
                    "steamboat_security.root_transition_issuance.issue_leaf",
                    side_effect=lambda *args, **kwargs: calls.append(args)):
                with self.assertRaises(CredentialError):
                    self.call(principal_inputs=batch)
            self.assertEqual(calls, [])
        bad_proof = replace(self.inputs[0], preparation_proof=b"ordinary renewal")
        calls = []
        with patch("steamboat_security.root_transition_issuance.issue_leaf",
                   side_effect=lambda *args, **kwargs: calls.append(args)):
            with self.assertRaises(CredentialError):
                self.call(principal_inputs=(bad_proof, self.inputs[1]))
        self.assertEqual(calls, [])
        renewal = make_renewal_proof(
            self.roles[0]["old_key"], self.roles[0]["old_cert"],
            self.roles[0]["new_csr"])
        wrong_domain = replace(self.inputs[0], preparation_proof=renewal)
        with self.assertRaises(CredentialError):
            self.call(principal_inputs=(wrong_domain, self.inputs[1]))

        final_doc = deepcopy(self.intent_document)
        final_doc.pop("purpose")
        final_doc["new_policy_digest"] = "f" * 64
        final = parse_root_transition_declaration(canonical_json(final_doc))
        final_proof = make_old_role_key_possession_proof(
            final, final.affected_principals[0],
            old_private_key_pem=self.roles[0]["old_key"],
            old_certificate_pem=self.roles[0]["old_cert"],
            new_csr_pem=self.roles[0]["new_csr"])
        with self.assertRaises(CredentialError):
            self.call(principal_inputs=(replace(self.inputs[0],
                                                preparation_proof=final_proof),
                                        self.inputs[1]))

    def test_invalid_authority_csr_credential_and_grant_reject_before_signing(self):
        invalid_args = (
            {"new_ca_private_key_pem": self.old_ca_key},
            {"new_ca_certificate_pem": self.old_ca},
            {"new_snapshot_public_key_pem": self.old_snapshot_public},
            {"principal_inputs": (replace(self.inputs[0], new_csr_pem=b"bad"), self.inputs[1])},
        )
        for changes in invalid_args:
            calls = []
            with self.subTest(changes=tuple(changes)), patch(
                    "steamboat_security.root_transition_issuance.issue_leaf",
                    side_effect=lambda *args, **kwargs: calls.append(args)):
                with self.assertRaises(CredentialError):
                    self.call(**changes)
            self.assertEqual(calls, [])

        # Neither new authority may reuse any currently live role key.
        for authority_kind in ("ca", "snapshot"):
            role_key = self.roles[0]["old_key"]
            if authority_kind == "ca":
                reused_ca = self.ca_using_key(role_key)
                intent, batch = self.alternate_intent(document_edits={
                    "new_ca_sha256": certificate_sha256(_pem_certificate(reused_ca))})
                changes = {"_intent": intent, "_inputs": batch,
                           "new_ca_certificate_pem": reused_ca,
                           "new_ca_private_key_pem": role_key}
            else:
                reused_snapshot_public = snapshot_public_key_pem(role_key)
                intent, batch = self.alternate_intent(
                    new_snapshot_public_key_pem=reused_snapshot_public)
                changes = {"_intent": intent, "_inputs": batch,
                           "new_snapshot_public_key_pem": reused_snapshot_public}
            calls = []
            with self.subTest(authority_kind=authority_kind), patch(
                    "steamboat_security.root_transition_issuance.issue_leaf",
                    side_effect=lambda *args, **kwargs: calls.append(args)):
                with self.assertRaises(CredentialError):
                    self.call(**changes)
            self.assertEqual(calls, [])

        wrong_epoch, wrong_epoch_inputs = self.alternate_intent(document_edits={
            "affected_principals": [
                {**self.intent_document["affected_principals"][0], "old_credential_epoch": 5},
                self.intent_document["affected_principals"][1]],
        })
        calls = []
        with patch("steamboat_security.root_transition_issuance.issue_leaf",
                   side_effect=lambda *args, **kwargs: calls.append(args)):
            with self.assertRaises(CredentialError):
                self.call(_intent=wrong_epoch, _inputs=wrong_epoch_inputs)
        self.assertEqual(calls, [])

        wrong_old_signer, wrong_signer_inputs = self.alternate_intent(document_edits={
            "old_snapshot_key_sha256": "f" * 64})
        with self.assertRaises(CredentialError):
            self.call(_intent=wrong_old_signer, _inputs=wrong_signer_inputs)

        alias_public = _pem_certificate(self.new_ca).public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        aliased_intent, aliased_inputs = self.alternate_intent(
            new_snapshot_public_key_pem=alias_public)
        with self.assertRaises(CredentialError):
            self.call(_intent=aliased_intent, _inputs=aliased_inputs,
                      new_snapshot_public_key_pem=alias_public)

        host = self.roles[0]
        expanded_csr = make_csr(host["new_key"], account_id=self.account,
                                device_id=host["principal"].device_id,
                                role="host", dns_sans=("worker.example", "extra.example"),
                                ip_sans=("127.0.0.1",))
        scope_intent, scope_inputs = self.alternate_intent(csr_by_index={0: expanded_csr})
        calls = []
        with patch("steamboat_security.root_transition_issuance.issue_leaf",
                   side_effect=lambda *args, **kwargs: calls.append(args)):
            with self.assertRaises(CredentialError):
                self.call(_intent=scope_intent, _inputs=scope_inputs)
        self.assertEqual(calls, [])

        alias_csr = make_csr(self.new_ca_key, account_id=self.account,
                             device_id=host["principal"].device_id, role="host",
                             dns_sans=("worker.example",), ip_sans=("127.0.0.1",))
        key_alias_intent, key_alias_inputs = self.alternate_intent(csr_by_index={0: alias_csr})
        with self.assertRaises(CredentialError):
            self.call(_intent=key_alias_intent, _inputs=key_alias_inputs)

        revoked_grant = self.snapshot_payload()
        revoked_grant["grants"][0]["not_after"] = NOW
        intent, batch, store = self.alternate_policy(revoked_grant)
        calls = []
        with patch("steamboat_security.root_transition_issuance.issue_leaf",
                   side_effect=lambda *args, **kwargs: calls.append(args)):
            with self.assertRaises(CredentialError):
                self.call(_intent=intent, _inputs=batch, _store=store)
        self.assertEqual(calls, [])

        wrong_boot = self.snapshot_payload()
        wrong_boot["grants"][0]["actor_boot_id"] = "f" * 32
        intent, batch, store = self.alternate_policy(wrong_boot)
        with self.assertRaises(CredentialError):
            self.call(_intent=intent, _inputs=batch, _store=store)

    def test_policy_or_live_credential_change_after_signing_discards_candidate(self):
        real_issue = issue_leaf
        calls = []

        def issue_then_expire(*args, **kwargs):
            result = real_issue(*args, **kwargs)
            calls.append(result)
            if len(calls) == 1:
                self.clock_source.advance(251)
            return result

        with patch("steamboat_security.root_transition_issuance.issue_leaf",
                   side_effect=issue_then_expire):
            with self.assertRaises((CredentialError, SnapshotError)):
                self.call()
        self.assertGreaterEqual(len(calls), 1)

    def test_new_leaf_expiry_during_signing_is_rejected_at_final_sample(self):
        real_issue = issue_leaf
        calls = []

        def issue_then_expire_new_leaf(*args, **kwargs):
            result = real_issue(*args, **kwargs)
            calls.append(result)
            self.clock_source.advance(2)
            return result

        with patch("steamboat_security.root_transition_issuance.issue_leaf",
                   side_effect=issue_then_expire_new_leaf):
            with self.assertRaises(CredentialError):
                self.call(leaf_lifetime_seconds=1)
        self.assertEqual(len(calls), 2)

    def test_policy_change_after_signing_discards_candidate(self):
        real_issue = issue_leaf
        calls = []

        def issue_then_update(*args, **kwargs):
            result = real_issue(*args, **kwargs)
            calls.append(result)
            if len(calls) == 1:
                payload = self.snapshot_payload(revision=5)
                self.store.install(sign_snapshot(payload, self.old_snapshot_key))
            return result

        with patch("steamboat_security.root_transition_issuance.issue_leaf",
                   side_effect=issue_then_update):
            with self.assertRaises(CredentialError):
                self.call()
        self.assertGreaterEqual(len(calls), 1)

    @unittest.skipUnless(os.name == "posix", "protected loader requires POSIX no-follow support")
    def test_protected_loader_and_required_baked_foreign_fixture(self):
        # Exercise the issuance path through its real protected-file loader.
        self.call(_real_loader=True)
        fixture = os.environ.get("STEAMBOAT_IDENTITY_FOREIGN_FIXTURE")
        if not fixture:
            self.fail("provide the Docker foreign-UID fixture for the POSIX issuance test")
        foreign = Path(fixture)
        self.assertNotEqual(foreign.stat().st_uid, os.geteuid())
        self.assertEqual(foreign.parent.stat().st_uid, os.geteuid())
        self.assertEqual(stat.S_IMODE(foreign.parent.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(foreign.stat().st_mode), 0o600)
        with self.assertRaises(StorageError):
            load_protected_preparation_intent(
                foreign, root=foreign.parent, expected_uid=os.geteuid(),
                clock=self.clock_source.clock)


if __name__ == "__main__":
    unittest.main()
