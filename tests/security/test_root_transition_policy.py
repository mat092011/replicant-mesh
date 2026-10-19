"""Real-credential tests for private final policy preparation."""
from __future__ import annotations

from dataclasses import replace
import hashlib
import json
import sys
import unittest
from pathlib import Path

from cryptography.hazmat.primitives import serialization

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

import tests.security.test_root_transition_issuance as issuance_fixture
from steamboat_security.errors import CredentialError
from steamboat_security.codec import canonical_json
from steamboat_security.root_transition_launch import RoleLaunchSpec
from steamboat_security.root_transition_policy import (
    _check_authority_separation, _declaration_document,
    build_final_activation_candidate, expected_transition_generation_sha256,
    validate_prepared_activation_candidate,
)
from steamboat_security.root_transition import parse_root_transition_declaration
from steamboat_security.root_transition_issuance import IssuedPrincipal
from steamboat_security.snapshot import (CredentialRecord, canonical_policy_digest,
                                         sign_snapshot)
from steamboat_security.certificates import (ROLE_EKUS, _pem_certificate,
    certificate_sha256, issue_leaf, make_csr, public_key_sha256, serial_hex)
from steamboat_security.operator import _record_from_leaf


class RootTransitionPolicyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        issuance_fixture.RootTransitionIssuanceTests.setUpClass()

    def setUp(self):
        self.fx = object.__new__(issuance_fixture.RootTransitionIssuanceTests)
        self.fx.setUp()
        self.issued = self.fx.call()
        self.csrs = {entry["principal"].identity: entry["new_csr"]
                     for entry in self.fx.roles}
        old_specs, new_specs = [], []
        gen = "a" * 64
        new_gen = expected_transition_generation_sha256(self.fx.intent)
        for entry, issued in zip(self.fx.roles, self.issued.principals):
            p, old, new = entry["principal"], entry["record"], issued.record
            old_specs.append(RoleLaunchSpec(gen, p.account_id, p.device_id, p.role,
                old["serial"], old["certificate_sha256"], old["public_key_sha256"],
                4, p.old_boot_id, 7, "b" * 64, f"{int(p.old_boot_id,16):032x}"))
            new_specs.append(RoleLaunchSpec(new_gen, p.account_id, p.device_id, p.role,
                new.serial, new.certificate_sha256, new.public_key_sha256,
                5, f"{int(p.old_boot_id,16)+100:032x}", 8, "c" * 64,
                f"{int(p.old_boot_id,16)+200:032x}"))
        self.old_specs, self.new_specs = tuple(old_specs), tuple(new_specs)
        self.candidate = build_final_activation_candidate(
            intent=self.fx.intent, issuance_candidate=self.issued,
            old_snapshot_store=self.fx.store, old_launch_specs=self.old_specs,
            new_launch_specs=self.new_specs, new_ca_certificate_pem=self.fx.new_ca,
            new_snapshot_signing_key_pem=self.fx.new_snapshot_key,
            new_csr_by_identity=self.csrs, requested_expires_at=issuance_fixture.NOW + 100)

    def tearDown(self):
        self.fx.tearDown()

    def test_real_whole_cohort_candidate_revalidates(self):
        self.assertEqual(len(self.candidate.issuance_candidate.principals), 2)
        self.assertEqual(self.candidate.declaration.new_policy_digest,
                         self.candidate.policy_digest)
        validate_prepared_activation_candidate(
            candidate=self.candidate, intent=self.fx.intent,
            old_snapshot_store=self.fx.store,
            new_ca_certificate_pem=self.fx.new_ca,
            new_snapshot_public_key_pem=self.fx.new_snapshot_public,
            new_csr_by_identity=self.csrs, clock=self.fx.clock_source.clock)

    def test_required_public_csr_map_is_exact_and_verified(self):
        wrong = dict(self.csrs)
        wrong.pop(next(iter(wrong)))
        for value in (wrong, {**self.csrs, ("other", "other", "host"): b"x"}):
            with self.assertRaises(CredentialError):
                build_final_activation_candidate(
                    intent=self.fx.intent, issuance_candidate=self.issued,
                    old_snapshot_store=self.fx.store, old_launch_specs=self.old_specs,
                    new_launch_specs=self.new_specs, new_ca_certificate_pem=self.fx.new_ca,
                    new_snapshot_signing_key_pem=self.fx.new_snapshot_key,
                    new_csr_by_identity=value, requested_expires_at=issuance_fixture.NOW + 100)
        changed = dict(self.csrs)
        changed[self.fx.roles[0]["principal"].identity] += b"x"
        with self.assertRaises(CredentialError):
            validate_prepared_activation_candidate(
                candidate=self.candidate, intent=self.fx.intent,
                old_snapshot_store=self.fx.store, new_ca_certificate_pem=self.fx.new_ca,
                new_snapshot_public_key_pem=self.fx.new_snapshot_public,
                new_csr_by_identity=changed, clock=self.fx.clock_source.clock)

    def test_candidate_mutations_are_recomputed_not_trusted(self):
        aliased_manifest = json.loads(self.issued.manifest)
        aliased_manifest["version"] = True
        altered_issuance = replace(self.issued, manifest=json.dumps(
            aliased_manifest, sort_keys=True, separators=(",", ":")).encode())
        for edited in (
            replace(self.candidate, activation_manifest_sha256="0" * 64),
            replace(self.candidate, transition_id="0" * 32),
            replace(self.candidate, preparation_intent_sha256="0" * 64),
            replace(self.candidate, issuance_manifest_sha256="0" * 64),
            replace(self.candidate, policy_payload=self.candidate.policy_payload + b" "),
            replace(self.candidate, policy_payload=b"{}" * 33000),
            replace(self.candidate, signed_snapshot=b"forged"),
            replace(self.candidate, old_launch_digest="0" * 64),
            replace(self.candidate, issuance_candidate=altered_issuance),
        ):
            with self.subTest(candidate=edited):
                with self.assertRaises(CredentialError):
                    validate_prepared_activation_candidate(
                        candidate=edited, intent=self.fx.intent,
                        old_snapshot_store=self.fx.store,
                        new_ca_certificate_pem=self.fx.new_ca,
                        new_snapshot_public_key_pem=self.fx.new_snapshot_public,
                        new_csr_by_identity=self.csrs, clock=self.fx.clock_source.clock)

        aliased = json.loads(self.candidate.activation_manifest)
        aliased["version"] = True
        alias_bytes = json.dumps(aliased, sort_keys=True, separators=(",", ":")).encode()
        with self.assertRaises(CredentialError):
            validate_prepared_activation_candidate(
                candidate=replace(self.candidate, activation_manifest=alias_bytes,
                    activation_manifest_sha256=hashlib.sha256(alias_bytes).hexdigest()),
                intent=self.fx.intent, old_snapshot_store=self.fx.store,
                new_ca_certificate_pem=self.fx.new_ca,
                new_snapshot_public_key_pem=self.fx.new_snapshot_public,
                new_csr_by_identity=self.csrs, clock=self.fx.clock_source.clock)

    def test_signed_candidate_with_future_extra_grant_is_rejected(self):
        payload = json.loads(self.candidate.policy_payload)
        future = dict(payload["grants"][0])
        future.update(not_before=issuance_fixture.NOW + 50,
                      not_after=issuance_fixture.NOW + 90,
                      model_id="8" * 64, assignment_id="asg_" + "5" * 32,
                      method="steamboat.v1.Worker/Describe")
        payload["grants"].append(future)
        payload_bytes = canonical_json(payload)
        digest = canonical_policy_digest(payload)
        declaration = parse_root_transition_declaration(
            canonical_json(_declaration_document(self.fx.intent, digest)))
        manifest = json.loads(self.candidate.activation_manifest)
        manifest.update(policy_digest=digest,
                       policy_payload_sha256=hashlib.sha256(payload_bytes).hexdigest())
        manifest_bytes = canonical_json(manifest)
        forged = replace(self.candidate, declaration=declaration, policy_digest=digest,
            policy_payload=payload_bytes,
            signed_snapshot=sign_snapshot(payload, self.fx.new_snapshot_key),
            activation_manifest=manifest_bytes,
            activation_manifest_sha256=hashlib.sha256(manifest_bytes).hexdigest())
        with self.assertRaises(CredentialError):
            validate_prepared_activation_candidate(
                candidate=forged, intent=self.fx.intent,
                old_snapshot_store=self.fx.store,
                new_ca_certificate_pem=self.fx.new_ca,
                new_snapshot_public_key_pem=self.fx.new_snapshot_public,
                new_csr_by_identity=self.csrs, clock=self.fx.clock_source.clock)

    def test_unrelated_old_boot_permission_is_not_rebound(self):
        payload = self.fx.snapshot_payload()
        other = dict(payload["grants"][0])
        other.update(target_boot_id="f" * 32, model_id="8" * 64,
                     assignment_id="asg_" + "4" * 32,
                     method="steamboat.v1.Worker/Describe")
        payload["grants"].append(other)
        intent, inputs, store = self.fx.alternate_policy(payload)
        issued = self.fx.call(_intent=intent, _inputs=inputs, _store=store)
        csrs = {entry["principal"].identity: entry["new_csr"] for entry in self.fx.roles}
        new_specs = tuple(RoleLaunchSpec(expected_transition_generation_sha256(intent),
            item.identity[0], item.identity[1], item.identity[2], item.record.serial,
            item.record.certificate_sha256, item.record.public_key_sha256, 5,
            f"{int(next(p.old_boot_id for p in intent.affected_principals if p.identity == item.identity),16)+100:032x}",
            8, "c" * 64,
            f"{int(next(p.old_boot_id for p in intent.affected_principals if p.identity == item.identity),16)+200:032x}")
            for item in issued.principals)
        candidate = build_final_activation_candidate(
            intent=intent, issuance_candidate=issued, old_snapshot_store=store,
            old_launch_specs=self.old_specs, new_launch_specs=new_specs,
            new_ca_certificate_pem=self.fx.new_ca,
            new_snapshot_signing_key_pem=self.fx.new_snapshot_key,
            new_csr_by_identity=csrs, requested_expires_at=issuance_fixture.NOW + 100)
        self.assertEqual(len(json.loads(candidate.policy_payload)["grants"]), 1)

    def test_authority_revalidation_rejects_real_leaf_reusing_any_old_role_key(self):
        entry = self.fx.roles[0]
        p = entry["principal"]
        csr = make_csr(entry["old_key"], account_id=p.account_id,
                       device_id=p.device_id, role=p.role,
                       dns_sans=p.dns_sans, ip_sans=p.ip_sans)
        cert_pem = issue_leaf(self.fx.new_ca, self.fx.new_ca_key, csr,
            account_id=p.account_id, device_id=p.device_id, role=p.role,
            not_before=issuance_fixture.NOW - 1,
            not_after=issuance_fixture.NOW + 100,
            serial=0xB111, ekus=ROLE_EKUS[p.role])
        raw = _record_from_leaf(cert_pem, account_id=p.account_id,
            device_id=p.device_id, role=p.role, credential_epoch=p.old_credential_epoch + 1)
        record = CredentialRecord(raw["account_id"], raw["device_id"], raw["role"],
            raw["serial"], raw["public_key_sha256"], raw["certificate_sha256"],
            raw["credential_epoch"], raw["not_before"], raw["not_after"],
            tuple(raw["ekus"]), tuple(raw["dns_sans"]), tuple(raw["ip_sans"]))
        alias = IssuedPrincipal(p.identity, cert_pem, record)
        sample = self.fx.clock_source.clock.sample()
        view = self.fx.store.current(sample=sample)
        new_ca = _pem_certificate(self.fx.new_ca)
        new_public = serialization.load_pem_public_key(self.fx.new_snapshot_public)
        with self.assertRaises(CredentialError):
            _check_authority_separation(self.fx.intent, self.fx.store, new_ca,
                new_public, view, (alias,), sample)
        _check_authority_separation(self.fx.intent, self.fx.store, new_ca,
            new_public, view, self.issued.principals, sample)


if __name__ == "__main__":
    unittest.main()
