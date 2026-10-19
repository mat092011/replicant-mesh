"""Generated-credential tests for cold root-transition key possession proofs."""
from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
import hashlib
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from steamboat_security.certificates import (
    certificate_sha256, generate_ca, generate_private_key_pem, issue_leaf, make_csr,
    public_key_sha256, serial_hex, _key, _pem_certificate,
)
from steamboat_security.codec import canonical_json
from steamboat_security.errors import CredentialError
from steamboat_security.operator import make_renewal_proof
from steamboat_security.root_transition import parse_root_transition_declaration
from steamboat_security.root_transition_proof import (
    MAX_ROOT_TRANSITION_PROOF_BYTES, make_old_role_key_possession_proof,
    verify_old_role_key_possession_proof,
)

NOW = 1_800_000_000


class RootTransitionProofTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ca_pem, cls.ca_key = generate_ca(now=NOW - 3600)
        cls.old_key = generate_private_key_pem()
        cls.new_key = generate_private_key_pem()
        cls.csr = make_csr(cls.new_key, account_id="acct_" + "1" * 32,
                           device_id="dev_" + "1" * 32, role="host",
                           dns_sans=("worker.example",), ip_sans=("127.0.0.1",))
        cls.old_csr = make_csr(cls.old_key, account_id="acct_" + "1" * 32,
                               device_id="dev_" + "1" * 32, role="host",
                               dns_sans=("worker.example",), ip_sans=("127.0.0.1",))
        cls.old_cert = issue_leaf(
            cls.ca_pem, cls.ca_key, cls.old_csr, account_id="acct_" + "1" * 32,
            device_id="dev_" + "1" * 32, role="host", not_before=NOW - 10,
            not_after=NOW + 200, serial=0xA123, ekus=("server",))
        cls.document = {
            "schema_version": 1, "transition_id": "1" * 32,
            "old_ca_sha256": "a" * 64, "new_ca_sha256": "b" * 64,
            "old_snapshot_key_sha256": "c" * 64,
            "new_snapshot_key_sha256": "d" * 64,
            "overlap_not_before": NOW - 10, "overlap_not_after": NOW + 200,
            "old_policy_revision": 4, "old_policy_digest": "e" * 64,
            "next_minimum_revision": 5, "new_policy_digest": "f" * 64,
            "affected_principals": [{
                "account_id": "acct_" + "1" * 32,
                "device_id": "dev_" + "1" * 32, "role": "host",
                "old_boot_id": "2" * 32,
                "old_serial": serial_hex(_pem_certificate(cls.old_cert).serial_number),
                "old_certificate_sha256": certificate_sha256(_pem_certificate(cls.old_cert)),
                "old_public_key_sha256": public_key_sha256(_pem_certificate(cls.old_cert).public_key()),
                "old_credential_epoch": 2, "old_admission_epoch": 3,
                "new_csr_sha256": hashlib.sha256(cls.csr).hexdigest(),
                "dns_sans": ["worker.example"], "ip_sans": ["127.0.0.1"],
            }],
        }
        cls.declaration = parse_root_transition_declaration(canonical_json(cls.document))
        cls.principal = cls.declaration.affected_principals[0]

    def make_proof(self, declaration=None, principal=None, *, key=None, certificate=None, csr=None):
        return make_old_role_key_possession_proof(
            declaration or self.declaration, principal or self.principal,
            old_private_key_pem=key or self.old_key,
            old_certificate_pem=certificate or self.old_cert,
            new_csr_pem=csr or self.csr)

    def verify(self, proof, declaration=None, principal=None, *, certificate=None, csr=None):
        verify_old_role_key_possession_proof(
            proof, declaration or self.declaration, principal or self.principal,
            old_certificate_pem=certificate or self.old_cert,
            new_csr_pem=csr or self.csr)

    def test_roundtrip_with_generated_ca_leaf_and_csr(self):
        proof = self.make_proof()
        self.assertLessEqual(len(proof), MAX_ROOT_TRANSITION_PROOF_BYTES)
        self.verify(proof)

    def test_wrong_key_certificate_csr_and_principal_reject(self):
        with self.assertRaises(CredentialError):
            self.make_proof(key=self.new_key)
        with self.assertRaises(CredentialError):
            self.make_proof(certificate=b"not a certificate")
        with self.assertRaises(CredentialError):
            self.make_proof(csr=self.old_csr)
        for field in ("old_certificate_sha256", "old_public_key_sha256", "new_csr_sha256"):
            altered = deepcopy(self.document)
            altered["affected_principals"][0][field] = "0" * 64
            declaration = parse_root_transition_declaration(canonical_json(altered))
            with self.subTest(field=field), self.assertRaises(CredentialError):
                self.make_proof(declaration=declaration,
                                principal=declaration.affected_principals[0])
        with self.assertRaises(CredentialError):
            self.make_proof(principal=replace(self.principal))
        proof = self.make_proof()
        with self.assertRaises(CredentialError):
            self.verify(proof, certificate=issue_leaf(
                self.ca_pem, self.ca_key, self.old_csr,
                account_id="acct_" + "1" * 32, device_id="dev_" + "1" * 32,
                role="host", not_before=NOW - 10, not_after=NOW + 200, serial=0xA124, ekus=("server",)))

    def test_cross_transition_declaration_scope_and_authority_edits_reject(self):
        proof = self.make_proof()
        edits = (
            {"transition_id": "3" * 32}, {"new_ca_sha256": "9" * 64},
            {"new_snapshot_key_sha256": "8" * 64},
            {"old_policy_digest": "7" * 64}, {"new_policy_digest": "6" * 64},
            {"overlap_not_after": NOW + 199},
        )
        for edit in edits:
            with self.subTest(edit=edit):
                altered = dict(self.document)
                altered.update(edit)
                declaration = parse_root_transition_declaration(canonical_json(altered))
                with self.assertRaises(CredentialError):
                    self.verify(proof, declaration)
        altered = deepcopy(self.document)
        altered["affected_principals"][0]["dns_sans"] = ["other.example"]
        declaration = parse_root_transition_declaration(canonical_json(altered))
        with self.assertRaises(CredentialError):
            self.verify(proof, declaration)

    def test_ordinary_renewal_proof_is_rejected(self):
        renewal = make_renewal_proof(self.old_key, self.old_cert, self.csr)
        with self.assertRaises(CredentialError):
            self.verify(renewal)

    def test_closed_canonical_schema_size_duplicate_and_numeric_boundaries(self):
        proof = self.make_proof()
        parsed = json.loads(proof)
        parsed["extra"] = 1
        with self.assertRaises(CredentialError):
            self.verify(canonical_json(parsed))
        parsed = json.loads(proof)
        parsed["payload"]["version"] = True
        with self.assertRaises(CredentialError):
            self.verify(canonical_json(parsed))
        parsed = json.loads(proof)
        parsed["payload"]["version"] = 1.0
        with self.assertRaises(CredentialError):
            self.verify(json.dumps(parsed, separators=(",", ":")).encode())
        for epoch in (True, 2.0):
            parsed = json.loads(proof)
            parsed["payload"]["old_credential_epoch"] = epoch
            with self.subTest(epoch=epoch), self.assertRaises(CredentialError):
                self.verify(canonical_json(parsed))
        with self.assertRaises(CredentialError):
            self.verify(b'{"payload":{},"payload":{},"signature":""}')
        with self.assertRaises(CredentialError):
            self.verify(b'{"payload":{"x":NaN},"signature":""}')
        with self.assertRaises(CredentialError):
            self.verify(b" " * (MAX_ROOT_TRANSITION_PROOF_BYTES + 1))
        with self.assertRaises(CredentialError):
            self.verify(proof + b" ")


if __name__ == "__main__":
    unittest.main()
