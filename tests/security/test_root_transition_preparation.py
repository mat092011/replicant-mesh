"""Preparation-intent parsing, protected loading, and proof domain tests."""
from __future__ import annotations

from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from steamboat_security.certificates import (
    certificate_sha256, generate_ca, generate_private_key_pem, issue_leaf,
    make_csr, public_key_sha256, serial_hex, _pem_certificate,
)
from steamboat_security.clock import Clock
from steamboat_security.codec import canonical_json
from steamboat_security.errors import CredentialError, SnapshotError, StorageError
from steamboat_security.operator import make_renewal_proof
from steamboat_security.root_transition import parse_root_transition_declaration
from steamboat_security.root_transition_preparation import (
    MAX_PREPARATION_PROOF_BYTES, PREPARATION_PURPOSE,
    load_protected_preparation_intent, make_preparation_possession_proof,
    parse_preparation_intent, verify_preparation_possession_proof,
)
from steamboat_security.root_transition_proof import (
    make_old_role_key_possession_proof, verify_old_role_key_possession_proof,
)

NOW = 1_800_000_000


class HealthyClock:
    def __init__(self, wall=NOW, uncertainty=0.0):
        self.wall = wall
        self.mono = 100.0
        self.uncertainty = uncertainty
        self.clock = Clock(wall=self._wall, monotonic=self._mono,
                           uncertainty_seconds=self._uncertainty)

    def _wall(self):
        return self.wall

    def _mono(self):
        self.mono += 1.0
        return self.mono

    def _uncertainty(self):
        return self.uncertainty


class PreparationIntentTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ca, cls.ca_key = generate_ca(now=NOW - 3600)
        cls.old_key = generate_private_key_pem()
        cls.new_key = generate_private_key_pem()
        cls.csr = make_csr(cls.new_key, account_id="acct_" + "1" * 32,
                           device_id="dev_" + "1" * 32, role="host",
                           dns_sans=("worker.example",), ip_sans=("127.0.0.1",))
        old_csr = make_csr(cls.old_key, account_id="acct_" + "1" * 32,
                           device_id="dev_" + "1" * 32, role="host",
                           dns_sans=("worker.example",), ip_sans=("127.0.0.1",))
        cls.old_cert = issue_leaf(
            cls.ca, cls.ca_key, old_csr, account_id="acct_" + "1" * 32,
            device_id="dev_" + "1" * 32, role="host", not_before=NOW - 100,
            not_after=NOW + 200, serial=0xA321, ekus=("server",))
        cert = _pem_certificate(cls.old_cert)
        principal = {
            "account_id": "acct_" + "1" * 32, "device_id": "dev_" + "1" * 32,
            "role": "host", "old_boot_id": "2" * 32,
            "old_serial": serial_hex(cert.serial_number),
            "old_certificate_sha256": certificate_sha256(cert),
            "old_public_key_sha256": public_key_sha256(cert.public_key()),
            "old_credential_epoch": 2, "old_admission_epoch": 3,
            "new_csr_sha256": hashlib.sha256(cls.csr).hexdigest(),
            "dns_sans": ["worker.example"], "ip_sans": ["127.0.0.1"],
        }
        cls.document = {
            "purpose": PREPARATION_PURPOSE, "schema_version": 1,
            "transition_id": "1" * 32, "old_ca_sha256": "a" * 64,
            "new_ca_sha256": "b" * 64, "old_snapshot_key_sha256": "c" * 64,
            "new_snapshot_key_sha256": "d" * 64,
            "overlap_not_before": NOW - 10, "overlap_not_after": NOW + 200,
            "old_policy_revision": 4, "old_policy_digest": "e" * 64,
            "next_minimum_revision": 5, "affected_principals": [principal],
        }
        cls.intent = parse_preparation_intent(canonical_json(cls.document))
        cls.principal = cls.intent.affected_principals[0]

    def prep_proof(self, intent=None, principal=None, **kwargs):
        return make_preparation_possession_proof(
            intent or self.intent, principal or self.principal,
            old_private_key_pem=kwargs.get("key", self.old_key),
            old_certificate_pem=kwargs.get("certificate", self.old_cert),
            new_csr_pem=kwargs.get("csr", self.csr))

    def verify_prep(self, proof, intent=None, principal=None, **kwargs):
        verify_preparation_possession_proof(
            proof, intent or self.intent, principal or self.principal,
            old_certificate_pem=kwargs.get("certificate", self.old_cert),
            new_csr_pem=kwargs.get("csr", self.csr))

    def final_declaration(self, document=None):
        full = dict(document or self.document)
        full.pop("purpose")
        full["new_policy_digest"] = "f" * 64
        return parse_root_transition_declaration(canonical_json(full))

    def test_roundtrip_and_distinct_intent_schema(self):
        proof = self.prep_proof()
        self.assertLessEqual(len(proof), MAX_PREPARATION_PROOF_BYTES)
        self.verify_prep(proof)
        with self.assertRaises(SnapshotError):
            parse_preparation_intent(canonical_json({**self.document, "new_policy_digest": "f" * 64}))
        with self.assertRaises(SnapshotError):
            parse_root_transition_declaration(canonical_json(self.document))

    def test_key_certificate_hash_csr_and_exact_membership_mismatches(self):
        with self.assertRaises(CredentialError):
            self.prep_proof(key=self.new_key)
        with self.assertRaises(CredentialError):
            self.prep_proof(csr=b"different CSR")
        for field in ("old_certificate_sha256", "old_public_key_sha256", "new_csr_sha256"):
            changed = deepcopy(self.document)
            changed["affected_principals"][0][field] = "0" * 64
            intent = parse_preparation_intent(canonical_json(changed))
            with self.subTest(field=field), self.assertRaises(CredentialError):
                self.prep_proof(intent, intent.affected_principals[0])
        with self.assertRaises(CredentialError):
            self.prep_proof(principal=deepcopy(self.principal))

    def test_intent_scope_and_overlap_edits_reject_existing_proof(self):
        proof = self.prep_proof()
        for changes in ({"transition_id": "3" * 32},
                        {"new_ca_sha256": "9" * 64},
                        {"new_snapshot_key_sha256": "8" * 64},
                        {"old_policy_digest": "7" * 64},
                        {"overlap_not_after": NOW + 199}):
            changed = dict(self.document)
            changed.update(changes)
            intent = parse_preparation_intent(canonical_json(changed))
            with self.subTest(changes=changes), self.assertRaises(CredentialError):
                self.verify_prep(proof, intent, intent.affected_principals[0])

    def test_domains_are_not_interchangeable_with_renewal_or_final_proofs(self):
        intent_proof = self.prep_proof()
        with self.assertRaises(CredentialError):
            self.verify_prep(make_renewal_proof(self.old_key, self.old_cert, self.csr))
        final = self.final_declaration()
        final_proof = make_old_role_key_possession_proof(
            final, final.affected_principals[0], old_private_key_pem=self.old_key,
            old_certificate_pem=self.old_cert, new_csr_pem=self.csr)
        with self.assertRaises(CredentialError):
            self.verify_prep(final_proof)
        with self.assertRaises(CredentialError):
            verify_old_role_key_possession_proof(
                intent_proof, final, final.affected_principals[0],
                old_certificate_pem=self.old_cert, new_csr_pem=self.csr)

    def test_proof_closed_canonical_numeric_duplicate_and_size_boundaries(self):
        proof = self.prep_proof()
        raw = json.loads(proof)
        raw["unknown"] = 1
        with self.assertRaises(CredentialError):
            self.verify_prep(canonical_json(raw))
        raw = json.loads(proof)
        raw["payload"]["old_credential_epoch"] = True
        with self.assertRaises(CredentialError):
            self.verify_prep(canonical_json(raw))
        for malformed in (b'{"payload":{},"payload":{},"signature":""}',
                          b'{"payload":{"x":NaN},"signature":""}',
                          b" " * (MAX_PREPARATION_PROOF_BYTES + 1), proof + b" "):
            with self.subTest(malformed=malformed[:24]), self.assertRaises(CredentialError):
                self.verify_prep(malformed)
        raw = json.loads(proof)
        raw["payload"]["old_admission_epoch"] = 3.0
        with self.assertRaises(CredentialError):
            self.verify_prep(json.dumps(raw, separators=(",", ":")).encode())

    @unittest.skipUnless(os.name == "posix", "protected loader requires POSIX no-follow support")
    def test_protected_loader_checks_modes_overlap_and_foreign_uid_before_parse(self):
        with tempfile.TemporaryDirectory(prefix="steamboat-preparation-") as temporary:
            root = Path(temporary) / "root"
            root.mkdir(mode=0o700)
            os.chmod(root, 0o700)
            path = root / "intent.json"
            path.write_bytes(canonical_json(self.document))
            os.chmod(path, 0o600)
            loaded = load_protected_preparation_intent(
                path, root=root, expected_uid=os.geteuid(), clock=HealthyClock().clock)
            self.assertEqual(loaded.intent, self.intent)
            with self.assertRaises(SnapshotError):
                load_protected_preparation_intent(
                    path, root=root, expected_uid=os.geteuid(),
                    clock=HealthyClock(wall=NOW + 300).clock)
            os.chmod(path, 0o640)
            with self.assertRaises(StorageError):
                load_protected_preparation_intent(
                    path, root=root, expected_uid=os.geteuid(), clock=HealthyClock().clock)

        fixture = os.environ.get("STEAMBOAT_IDENTITY_FOREIGN_FIXTURE")
        if not fixture:
            self.fail("provide the Docker foreign-UID fixture for the POSIX loader test")
        foreign = Path(fixture)
        self.assertNotEqual(foreign.stat().st_uid, os.geteuid())
        self.assertEqual(foreign.parent.stat().st_uid, os.geteuid())
        self.assertEqual(stat.S_IMODE(foreign.parent.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(foreign.stat().st_mode), 0o600)
        with self.assertRaises(StorageError):
            load_protected_preparation_intent(
                foreign, root=foreign.parent, expected_uid=os.geteuid(),
                clock=HealthyClock().clock)


if __name__ == "__main__":
    unittest.main()
