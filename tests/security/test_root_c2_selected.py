"""Focused C2 selected-cohort callback tests using the transition crypto fixture."""
from __future__ import annotations

import hashlib
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

import tests.security.test_root_transition_policy as policy_fixture
from steamboat_security.codec import canonical_json
from steamboat_security.errors import CredentialError
from steamboat_security.root_c2_selected import (
    C2_ACTIVATION_MANIFEST_DOMAIN, validate_c2_selected_cohort,
)
from steamboat_security.root_transition_storage import (
    RootGenerationStore, RootGenerationSelector, root_generation_selector_document,
)


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

    def _install_c2(self, *, domain=C2_ACTIVATION_MANIFEST_DOMAIN,
                    groups=None, active_policy=None):
        source = json.loads(self.candidate.activation_manifest)
        source["domain"] = domain
        source["old_host_group_scopes"] = []
        source["new_host_group_scopes"] = []
        if groups is not None:
            source["new_host_group_scopes"] = groups
        manifest = canonical_json(source)
        artifacts = {
            "activation_manifest.json": manifest,
            "policy_snapshot.json": self.candidate.signed_snapshot,
            "ca_certificate.pem": self.fx.new_ca,
            "snapshot_signer_public.pem": self.fx.new_snapshot_public,
            "old_launch_specs.json": canonical_json(source["old_launch_specs"]),
            "new_launch_specs.json": canonical_json(source["new_launch_specs"]),
        }
        self.root.mkdir(mode=0o700)
        os.chmod(self.root, 0o700)
        (self.root / "generations").mkdir(mode=0o700)
        (self.root / "policies").mkdir(mode=0o700)
        (self.root / "transition.lock").touch(mode=0o600)
        selector = RootGenerationSelector(
            self.candidate.new_launch_specs[0].generation_sha256, _sha(manifest),
            json.loads(self.candidate.policy_payload)["revision"],
            self.candidate.policy_digest,
            _sha(active_policy or self.candidate.signed_snapshot),
            {name: _sha(value) for name, value in artifacts.items()})
        generation = self.root / "generations" / selector.generation_sha256
        generation.mkdir(mode=0o700)
        descriptor = {"schema_version": 1, "purpose": "root_generation_descriptor",
            "generation_sha256": selector.generation_sha256,
            "activation_manifest_sha256": selector.activation_manifest_sha256,
            "artifact_sha256": dict(selector.artifact_sha256)}
        values = {"descriptor.json": canonical_json(descriptor), **artifacts}
        for name, data in values.items():
            (generation / name).write_bytes(data)
            os.chmod(generation / name, 0o600)
        selected_policy = active_policy or self.candidate.signed_snapshot
        (self.root / "policies" / f"{_sha(selected_policy)}.json").write_bytes(selected_policy)
        os.chmod(self.root / "policies" / f"{_sha(selected_policy)}.json", 0o600)
        selector_bytes = canonical_json(root_generation_selector_document(selector))
        (self.root / "selector.json").write_bytes(selector_bytes)
        os.chmod(self.root / "selector.json", 0o600)
        self.selector = selector
        self.artifacts = artifacts

    @unittest.skipUnless(os.name == "posix", "RootGenerationStore uses native POSIX storage")
    def test_selected_empty_host_groups_validate_with_signed_snapshot_and_store(self):
        self._install_c2()
        with RootGenerationStore(self.root, expected_uid=os.geteuid()) as store:
            result = store.read_selected(validate=lambda selector, bundle, active:
                validate_c2_selected_cohort(selector, dict(bundle), active,
                                            clock=self.fx.clock_source.clock))
        self.assertEqual(result.selector.generation_sha256, self.selector.generation_sha256)

    @unittest.skipUnless(os.name == "posix", "RootGenerationStore uses native POSIX storage")
    def test_c1_manifest_domain_is_rejected_by_c2_callback(self):
        self._install_c2(domain="steamboat.root-transition.activation-manifest.v1")
        with RootGenerationStore(self.root, expected_uid=os.geteuid()) as store:
            with self.assertRaises(CredentialError):
                store.read_selected(validate=lambda selector, bundle, active:
                    validate_c2_selected_cohort(selector, dict(bundle), active,
                                                clock=self.fx.clock_source.clock))

    @unittest.skipUnless(os.name == "posix", "RootGenerationStore uses native POSIX storage")
    def test_malformed_groups_and_changed_artifact_hashes_reject(self):
        self._install_c2(groups={"not": "a list"})
        with RootGenerationStore(self.root, expected_uid=os.geteuid()) as store:
            with self.assertRaises(CredentialError):
                store.read_selected(validate=lambda selector, bundle, active:
                    validate_c2_selected_cohort(selector, dict(bundle), active,
                                                clock=self.fx.clock_source.clock))

    @unittest.skipUnless(os.name == "posix", "RootGenerationStore uses native POSIX storage")
    def test_validator_rejects_artifact_bytes_not_matching_selector(self):
        self._install_c2()
        with RootGenerationStore(self.root, expected_uid=os.geteuid()) as store:
            def tamper_inside_callback(selector, bundle, active):
                changed = dict(bundle)
                changed["new_launch_specs.json"] += b" "
                validate_c2_selected_cohort(selector, changed, active,
                                            clock=self.fx.clock_source.clock)
            with self.assertRaises(CredentialError):
                store.read_selected(validate=tamper_inside_callback)

