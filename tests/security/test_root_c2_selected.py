"""Portable C2 validator tests plus native POSIX selected-store integration."""
from __future__ import annotations

import hashlib
import json
import os
import sys
import tempfile
import unittest
from copy import deepcopy
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

import tests.security.test_root_transition_policy as policy_fixture
from steamboat_security.codec import canonical_json
from steamboat_security.errors import CredentialError
from steamboat_security.root_c2_group_scope import PROFILE
from steamboat_security.root_c2_selected import (
    C2_ACTIVATION_MANIFEST_DOMAIN, make_c2_selected_validation_callback,
    validate_c2_selected_cohort,
)
from steamboat_security.root_transition_launch import (
    canonical_role_launch_digest, parse_role_launch_spec, role_launch_document,
)
from steamboat_security.root_transition_storage import (
    RootGenerationStore, RootGenerationSelector, root_generation_selector_document,
)
from steamboat_security.snapshot import canonical_policy_digest, sign_snapshot


def _sha(data):
    return hashlib.sha256(data).hexdigest()


class C2SelectedCohortTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        policy_fixture.RootTransitionPolicyTests.setUpClass()

    def setUp(self):
        policy = object.__new__(policy_fixture.RootTransitionPolicyTests)
        policy.setUp()
        self.fx = policy.fx
        self.candidate = policy.candidate
        self.temp = tempfile.TemporaryDirectory(prefix="c2-selected-")
        self.root = Path(self.temp.name) / "root"

    def tearDown(self):
        self.temp.cleanup()
        self.fx.tearDown()

    def _scope(self, spec, child_boots=None):
        boots = child_boots or [f"{0xF0000000000000000000000000000000 + n:032x}"
                                for n in range(3)]
        model = json.loads(self.candidate.policy_payload)["grants"][0]["model_id"]
        return {
            "version": 1, "profile": PROFILE, "account_id": spec.account_id,
            "device_id": spec.device_id, "role": "host",
            "credential": {"serial": spec.serial, "credential_epoch": spec.credential_epoch,
                "certificate_sha256": spec.certificate_sha256,
                "public_key_sha256": spec.public_key_sha256},
            "generation_sha256": spec.generation_sha256,
            "admission_epoch": spec.admission_epoch, "parent_boot_id": spec.boot_id,
            "model_id": model, "catalog_sha256": "1" * 64,
            "catalog_public_key_sha256": "2" * 64,
            "operator_public_key_sha256": "3" * 64,
            "components": [{
                "component": f"worker-{index}", "worker_boot_id": boots[index - 1],
                "assignment_id": f"asg_{index:032x}",
                "assignment_sha256": f"{index:064x}",
                "channel_certificate_sha256": f"{index + 10:064x}",
                "channel_public_key_sha256": f"{index + 20:064x}",
            } for index in range(1, 4)],
        }

    def _inputs(self, *, grant_fault=None, reuse_old_child=False,
                payload_hash_fault=False, c1_domain=False, coordinator_only=False,
                launch_fault=None, omit_new_group=False, expired_baseline=False):
        base = json.loads(self.candidate.activation_manifest)
        base["domain"] = ("steamboat.root-transition.activation-manifest.v1"
                           if c1_domain else C2_ACTIVATION_MANIFEST_DOMAIN)
        base["old_host_group_scopes"] = []
        new_specs = list(self.candidate.new_launch_specs)
        host = next(x for x in new_specs if x.role == "host")
        coordinator = next(x for x in new_specs if x.role == "personal_coordinator")
        new_group = self._scope(host)
        base["new_host_group_scopes"] = [] if coordinator_only or omit_new_group else [new_group]
        if coordinator_only:
            new_specs = [coordinator]
            base["new_launch_specs"] = [role_launch_document(coordinator)]
            base["new_launch_digest"] = canonical_role_launch_digest(tuple(new_specs))
            old_coordinator = next(x for x in self.candidate.old_launch_specs
                                   if x.role == "personal_coordinator")
            base["old_launch_specs"] = [role_launch_document(old_coordinator)]
            base["old_launch_digest"] = canonical_role_launch_digest((old_coordinator,))
            base["new_certificates"] = [{"identity": list(coordinator.identity),
                "serial": coordinator.serial, "certificate_sha256": coordinator.certificate_sha256,
                "public_key_sha256": coordinator.public_key_sha256}]
        if reuse_old_child:
            old_host = next(x for x in self.candidate.old_launch_specs if x.role == "host")
            boots = [new_group["components"][0]["worker_boot_id"],
                     f"{0xF1000000000000000000000000000001:032x}",
                     f"{0xF1000000000000000000000000000002:032x}"]
            base["old_host_group_scopes"] = [self._scope(old_host, boots)]
        if launch_fault == "mixed_old_generation":
            base["old_launch_specs"][1]["generation_sha256"] = "e" * 64
            checked = tuple(parse_role_launch_spec(x) for x in base["old_launch_specs"])
            base["old_launch_digest"] = canonical_role_launch_digest(checked)
        elif launch_fault == "old_generation_equals_new":
            for raw in base["old_launch_specs"]:
                raw["generation_sha256"] = new_specs[0].generation_sha256
            checked = tuple(parse_role_launch_spec(x) for x in base["old_launch_specs"])
            base["old_launch_digest"] = canonical_role_launch_digest(checked)
        elif launch_fault == "different_role_sets":
            base["old_launch_specs"] = base["old_launch_specs"][:-1]
            checked = tuple(parse_role_launch_spec(x) for x in base["old_launch_specs"])
            base["old_launch_digest"] = canonical_role_launch_digest(checked)

        baseline_payload = json.loads(self.candidate.policy_payload)
        baseline_policy = self.candidate.signed_snapshot
        if expired_baseline:
            baseline_payload["expires_at"] = int(self.fx.clock_source.wall) + 100
            baseline_policy = sign_snapshot(baseline_payload, self.fx.new_snapshot_key)
            base["policy_revision"] = baseline_payload["revision"]
            base["policy_digest"] = canonical_policy_digest(baseline_payload)
            base["policy_payload_sha256"] = _sha(canonical_json(baseline_payload))
        manifest = canonical_json(base)
        artifacts = {
            "activation_manifest.json": manifest,
            "policy_snapshot.json": baseline_policy,
            "ca_certificate.pem": self.fx.new_ca,
            "snapshot_signer_public.pem": self.fx.new_snapshot_public,
            "old_launch_specs.json": canonical_json(base["old_launch_specs"]),
            "new_launch_specs.json": canonical_json(base["new_launch_specs"]),
        }
        policy_payload = json.loads(self.candidate.policy_payload)
        if coordinator_only:
            policy_payload["grants"] = []
        elif grant_fault:
            source_grant = policy_payload["grants"][0]
            policy_payload["grants"] = []
            for component in new_group["components"]:
                grant = deepcopy(source_grant)
                grant["target_boot_id"] = component["worker_boot_id"]
                grant["assignment_id"] = component["assignment_id"]
                if grant_fault == "targetboot":
                    grant["target_boot_id"] = f"{0xE0000000000000000000000000000001:032x}"
                elif grant_fault == "assignment":
                    grant["assignment_id"] = "asg_" + "e" * 32
                elif grant_fault == "model":
                    grant["model_id"] = "e" * 64
                elif grant_fault == "actorchild":
                    grant["actor_boot_id"] = component["worker_boot_id"]
                elif grant_fault == "futureforeign":
                    grant["target_boot_id"] = f"{0xE0000000000000000000000000000001:032x}"
                    grant["not_before"] += 30
                elif grant_fault == "futurevalid":
                    grant["not_before"] += 30
                policy_payload["grants"].append(grant)
        active_policy = self.candidate.signed_snapshot
        if expired_baseline:
            self.fx.clock_source.advance(120)
            policy_payload["revision"] += 1
            policy_payload["issued_at"] = int(self.fx.clock_source.wall)
            expiry = min(int(self.fx.clock_source.wall) + 100,
                         min(x["not_after"] for x in policy_payload["credentials"]))
            policy_payload["expires_at"] = expiry
            for grant in policy_payload["grants"]:
                grant["not_after"] = expiry
            active_policy = sign_snapshot(policy_payload, self.fx.new_snapshot_key)
        elif coordinator_only or grant_fault:
            policy_payload["revision"] += 1
            active_policy = sign_snapshot(policy_payload, self.fx.new_snapshot_key)
        if payload_hash_fault:
            base["policy_payload_sha256"] = "e" * 64
            manifest = canonical_json(base)
            artifacts["activation_manifest.json"] = manifest
        selector = RootGenerationSelector(
            new_specs[0].generation_sha256, _sha(manifest), policy_payload["revision"],
            canonical_policy_digest(policy_payload), _sha(active_policy),
            {name: _sha(data) for name, data in artifacts.items()})
        return selector, artifacts, active_policy, new_group

    def _assert_rejects(self, *, message=None, **kwargs):
        selector, bundle, active, _group = self._inputs(**kwargs)
        context = (self.assertRaisesRegex(CredentialError, message) if message
                   else self.assertRaises(CredentialError))
        with context:
            validate_c2_selected_cohort(selector, bundle, active,
                                        clock=self.fx.clock_source.clock)

    def test_valid_three_component_scope_and_signed_current_policy(self):
        selector, bundle, active, expected_group = self._inputs(grant_fault="none")
        cohort = validate_c2_selected_cohort(selector, bundle, active,
                                            clock=self.fx.clock_source.clock)
        self.assertEqual(len(cohort.new_groups), 1)
        self.assertEqual(len(cohort.new_groups[0].components), 3)
        self.assertEqual(cohort.new_groups[0].to_document(), expected_group)
        capture = {}
        callback = make_c2_selected_validation_callback(
            clock=self.fx.clock_source.clock, capture=capture)
        self.assertIsNone(callback(selector, bundle, active))
        self.assertEqual(capture["cohort"], cohort)

    def test_coordinator_only_c2_can_have_no_host_groups(self):
        selector, bundle, active, _ = self._inputs(coordinator_only=True)
        cohort = validate_c2_selected_cohort(selector, bundle, active,
                                            clock=self.fx.clock_source.clock)
        self.assertEqual(cohort.new_groups, ())
        self.assertEqual(tuple(x.role for x in cohort.new_specs), ("personal_coordinator",))

    def test_host_role_without_scope_is_rejected(self):
        self._assert_rejects(omit_new_group=True, message="scope every declared host")

    def test_wrong_component_boot_assignment_and_model_reject(self):
        expected = {"targetboot": "component tuple", "assignment": "component tuple",
                    "model": "model differs", "actorchild": "actor differs"}
        for fault, message in expected.items():
            with self.subTest(fault=fault):
                self._assert_rejects(grant_fault=fault, message=message)

    def test_future_grants_are_closed_to_scope_before_they_activate(self):
        self._assert_rejects(grant_fault="futureforeign", message="component tuple")
        selector, bundle, active, _ = self._inputs(grant_fault="futurevalid")
        cohort = validate_c2_selected_cohort(selector, bundle, active,
                                            clock=self.fx.clock_source.clock)
        self.assertEqual(len(cohort.new_groups[0].components), 3)

    def test_new_child_boot_cannot_reuse_previous_child_boot(self):
        self._assert_rejects(reuse_old_child=True, message="reuses parent or child")

    def test_launch_specs_keep_the_c1_normalization_contract(self):
        for fault, message in (("mixed_old_generation", "share a generation"),
                               ("old_generation_equals_new", "distinct from selected"),
                               ("different_role_sets", "identical role identities")):
            with self.subTest(fault=fault):
                self._assert_rejects(launch_fault=fault, message=message)

    def test_baseline_payload_hash_and_active_selector_head_are_bound(self):
        self._assert_rejects(payload_hash_fault=True, message="baseline policy pins")
        selector, bundle, active, _ = self._inputs(grant_fault="none")
        changed_selector = RootGenerationSelector(selector.generation_sha256,
            selector.activation_manifest_sha256, selector.policy_revision,
            "e" * 64, selector.active_policy_snapshot_sha256, selector.artifact_sha256)
        with self.assertRaisesRegex(CredentialError, "selected policy"):
            validate_c2_selected_cohort(changed_selector, bundle, active,
                                        clock=self.fx.clock_source.clock)

    def test_resigned_same_payload_must_match_exact_selector_snapshot_hash(self):
        selector, bundle, active, _ = self._inputs(grant_fault="none")
        same_payload = json.loads(active)["payload"]
        same_payload_resigned = sign_snapshot(same_payload, self.fx.new_snapshot_key)
        self.assertEqual(json.loads(same_payload_resigned)["payload"], same_payload)
        self.assertNotEqual(same_payload_resigned, active)
        corrected_selector = RootGenerationSelector(selector.generation_sha256,
            selector.activation_manifest_sha256, selector.policy_revision,
            selector.policy_digest, _sha(same_payload_resigned), selector.artifact_sha256)
        validate_c2_selected_cohort(corrected_selector, bundle, same_payload_resigned,
                                    clock=self.fx.clock_source.clock)
        with self.assertRaisesRegex(CredentialError, "active policy bytes"):
            validate_c2_selected_cohort(selector, bundle, same_payload_resigned,
                                        clock=self.fx.clock_source.clock)

    def test_expired_immutable_baseline_allows_fresh_selected_policy(self):
        selector, bundle, active, _ = self._inputs(
            grant_fault="none", expired_baseline=True)
        baseline = json.loads(bundle["policy_snapshot.json"])["payload"]
        current = json.loads(active)["payload"]
        sample = self.fx.clock_source.clock.sample()
        self.assertLessEqual(baseline["expires_at"], sample.latest_wall)
        self.assertGreater(current["expires_at"], sample.latest_wall)
        cohort = validate_c2_selected_cohort(selector, bundle, active,
                                            clock=self.fx.clock_source.clock)
        self.assertEqual(cohort.policy_revision, current["revision"])

    def test_c1_domain_and_changed_selected_artifact_bytes_reject(self):
        selector, bundle, active, _ = self._inputs(c1_domain=True)
        with self.assertRaisesRegex(CredentialError, "manifest"):
            validate_c2_selected_cohort(selector, bundle, active,
                                        clock=self.fx.clock_source.clock)
        selector, bundle, active, _ = self._inputs(grant_fault="none")
        changed_bundle = dict(bundle)
        changed_bundle["new_launch_specs.json"] += b" "
        with self.assertRaisesRegex(CredentialError, "artifact"):
            validate_c2_selected_cohort(selector, changed_bundle, active,
                                        clock=self.fx.clock_source.clock)

    @unittest.skipUnless(os.name == "posix", "RootGenerationStore uses native POSIX storage")
    def test_store_callback_adapter_returns_none_and_captures_cohort(self):
        selector, artifacts, active, _ = self._inputs(grant_fault="none")
        self.root.mkdir(mode=0o700)
        os.chmod(self.root, 0o700)
        (self.root / "generations").mkdir(mode=0o700)
        (self.root / "policies").mkdir(mode=0o700)
        (self.root / "transition.lock").touch(mode=0o600)
        generation = self.root / "generations" / selector.generation_sha256
        generation.mkdir(mode=0o700)
        descriptor = {"schema_version": 1, "purpose": "root_generation_descriptor",
            "generation_sha256": selector.generation_sha256,
            "activation_manifest_sha256": selector.activation_manifest_sha256,
            "artifact_sha256": dict(selector.artifact_sha256)}
        for name, data in {"descriptor.json": canonical_json(descriptor), **artifacts}.items():
            (generation / name).write_bytes(data)
            os.chmod(generation / name, 0o600)
        policy_path = self.root / "policies" / f"{_sha(active)}.json"
        policy_path.write_bytes(active)
        os.chmod(policy_path, 0o600)
        (self.root / "selector.json").write_bytes(
            canonical_json(root_generation_selector_document(selector)))
        os.chmod(self.root / "selector.json", 0o600)
        capture = {}
        callback = make_c2_selected_validation_callback(
            clock=self.fx.clock_source.clock, capture=capture)
        with RootGenerationStore(self.root, expected_uid=os.geteuid()) as store:
            selected = store.read_selected(validate=callback)
        self.assertEqual(selected.selector.generation_sha256, selector.generation_sha256)
        self.assertEqual(len(capture["cohort"].new_groups), 1)
