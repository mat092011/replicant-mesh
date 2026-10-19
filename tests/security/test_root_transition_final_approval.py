"""Final approval validation tests using real old and staged credentials."""
from __future__ import annotations

from dataclasses import replace
import os
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

import tests.security.test_root_transition_policy as policy_fixture
from steamboat_security.codec import canonical_json
from steamboat_security.errors import CredentialError, SnapshotError
from steamboat_security.root_transition_final_approval import (
    FINAL_APPROVAL_PURPOSE, FinalActivationApproval, FinalApprovalPrincipalInput,
    final_activation_approval_document, parse_final_activation_approval,
    validate_final_activation_approval,
)
from steamboat_security.root_transition_proof import make_old_role_key_possession_proof


class RootTransitionFinalApprovalTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        policy_fixture.RootTransitionPolicyTests.setUpClass()

    def setUp(self):
        policy = object.__new__(policy_fixture.RootTransitionPolicyTests)
        policy.setUp()
        self.fx = policy.fx
        self.fx.candidate = policy.candidate
        self.fx.csrs = policy.csrs
        approval = FinalActivationApproval(
            1, FINAL_APPROVAL_PURPOSE, self.fx.intent.transition_id,
            self.fx.candidate.preparation_intent_sha256,
            self.fx.candidate.issuance_manifest_sha256,
            self.fx.candidate.activation_manifest_sha256,
            self.fx.candidate.declaration)
        self.encoded = canonical_json(final_activation_approval_document(approval))
        self.root = self.fx.root
        self.path = self.root / "final.json"
        self.path.write_bytes(self.encoded)
        if os.name == "posix":
            os.chmod(self.path, 0o600)
        members = {p.identity: p for p in self.fx.candidate.declaration.affected_principals}
        self.inputs = tuple(FinalApprovalPrincipalInput(
            members[entry["principal"].identity], entry["old_cert"], entry["new_csr"],
            make_old_role_key_possession_proof(
                self.fx.candidate.declaration, members[entry["principal"].identity],
                old_private_key_pem=entry["old_key"],
                old_certificate_pem=entry["old_cert"], new_csr_pem=entry["new_csr"]))
            for entry in self.fx.roles)

    def tearDown(self):
        self.fx.tearDown()

    def call(self, **kwargs):
        args = dict(approval_path=self.path, approval_root=self.root,
            expected_uid=os.geteuid() if hasattr(os, "geteuid") else 0,
            clock=self.fx.clock_source.clock, intent=self.fx.intent,
            candidate=self.fx.candidate, old_snapshot_store=self.fx.store,
            new_ca_certificate_pem=self.fx.new_ca,
            new_snapshot_public_key_pem=self.fx.new_snapshot_public,
            new_csr_by_identity=self.fx.csrs, principal_inputs=self.inputs)
        args.update(kwargs)
        return validate_final_activation_approval(**args)

    def test_protected_final_approval_and_full_proof_cohort(self):
        if os.name != "posix":
            self.skipTest("protected ownership checks require POSIX no-follow semantics")
        self.assertEqual(parse_final_activation_approval(self.encoded).transition_id,
                         self.fx.intent.transition_id)
        result = self.call()
        self.assertEqual(result, parse_final_activation_approval(self.encoded))
        with self.assertRaises(CredentialError):
            self.call(principal_inputs=self.inputs[:-1])
        with self.assertRaises(CredentialError):
            self.call(principal_inputs=(self.inputs[0], self.inputs[0]))
        changed = list(self.inputs)
        changed[0] = replace(changed[0], possession_proof=changed[0].possession_proof + b"x")
        with self.assertRaises(CredentialError):
            self.call(principal_inputs=tuple(changed))

    def test_mutated_candidate_and_missing_or_changed_csr_reject(self):
        from steamboat_security.root_transition_policy import (
            _validate_csr_bindings, validate_prepared_activation_candidate,
        )
        with self.assertRaises(CredentialError):
            validate_prepared_activation_candidate(
                candidate=replace(self.fx.candidate, signed_snapshot=b"altered"),
                intent=self.fx.intent, old_snapshot_store=self.fx.store,
                new_ca_certificate_pem=self.fx.new_ca,
                new_snapshot_public_key_pem=self.fx.new_snapshot_public,
                new_csr_by_identity=self.fx.csrs, clock=self.fx.clock_source.clock)
        csr_map = dict(self.fx.csrs)
        csr_map.pop(next(iter(csr_map)))
        with self.assertRaises(CredentialError):
            _validate_csr_bindings(self.fx.intent, self.fx.candidate.issuance_candidate.principals, csr_map)
        changed = list(self.inputs)
        changed[0] = replace(changed[0], new_csr_pem=changed[0].new_csr_pem + b"x")
        if os.name == "posix":
            with self.assertRaises(CredentialError):
                self.call(principal_inputs=tuple(changed))

    def test_approval_parser_is_closed_and_canonical(self):
        with self.assertRaises(SnapshotError):
            parse_final_activation_approval(self.encoded[:-1] + b",\"extra\":1}")
        with self.assertRaises(SnapshotError):
            parse_final_activation_approval(self.encoded + b" ")
        with self.assertRaises(SnapshotError):
            parse_final_activation_approval(self.encoded + b" " * 65536)


if __name__ == "__main__":
    unittest.main()
