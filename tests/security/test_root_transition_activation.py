"""Cold activation composition tests; selected bytes are not readiness."""
from __future__ import annotations

import hashlib
import asyncio
import os
import sys
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

import tests.security.test_root_transition_policy as policy_fixture
import tests.security.test_root_transition_retirement as retirement_fixture
from steamboat_security.codec import canonical_json
from steamboat_security.errors import CredentialError, SnapshotError, StorageError
from steamboat_security.root_transition_activation import (
    _old_specs, activate_root_transition,
)
from steamboat_security.root_transition_final_approval import (
    FINAL_APPROVAL_PURPOSE, FinalActivationApproval, FinalApprovalPrincipalInput,
    final_activation_approval_document,
)
from steamboat_security.root_transition_launch import role_launch_document, canonical_role_launch_digest
from steamboat_security.root_transition_policy import build_final_activation_candidate
from steamboat_security.root_transition_policy import _declaration_document
from steamboat_security.root_transition import parse_root_transition_declaration
from steamboat_security.clock import Clock
from steamboat_security.root_transition_proof import make_old_role_key_possession_proof
from steamboat_security.root_transition_retirement import RetirementSupervisor
from steamboat_security.root_transition_storage import (
    RootGenerationStore, RootGenerationSelector, root_generation_selector_document,
)
from steamboat_security.snapshot import SnapshotStore, canonical_policy_digest, sign_snapshot
from steamboat_security.certificates import verify_leaf


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class _StableClockSource:
    def __init__(self, wall: float):
        self.wall = wall
        self.mono = 100.0
        self.clock = Clock(wall=lambda: self.wall, monotonic=lambda: self.mono,
                           uncertainty_seconds=lambda: 0.0)


def _provision_old_root(root: Path, artifacts: dict[str, bytes], *, revision: int,
                        policy_digest: str, generation: str):
    root.mkdir(mode=0o700)
    os.chmod(root, 0o700)
    generations, policies = root / "generations", root / "policies"
    generations.mkdir(mode=0o700)
    policies.mkdir(mode=0o700)
    lock = root / "transition.lock"
    lock.touch(mode=0o600)
    os.chmod(lock, 0o600)
    selector = RootGenerationSelector(
        generation, _sha(artifacts["activation_manifest.json"]), revision,
        policy_digest, _sha(artifacts["policy_snapshot.json"]),
        {name: _sha(data) for name, data in artifacts.items()})
    policy_path = policies / f"{selector.active_policy_snapshot_sha256}.json"
    policy_path.write_bytes(artifacts["policy_snapshot.json"])
    os.chmod(policy_path, 0o600)
    gen_dir = generations / generation
    gen_dir.mkdir(mode=0o700)
    descriptor = {
        "schema_version": 1, "purpose": "root_generation_descriptor",
        "generation_sha256": generation,
        "activation_manifest_sha256": selector.activation_manifest_sha256,
        "artifact_sha256": dict(selector.artifact_sha256),
    }
    for name, data in {"descriptor.json": canonical_json(descriptor), **artifacts}.items():
        path = gen_dir / name
        path.write_bytes(data)
        os.chmod(path, 0o600)
    encoded = canonical_json(root_generation_selector_document(selector))
    (root / "selector.json").write_bytes(encoded)
    os.chmod(root / "selector.json", 0o600)
    return _sha(encoded)


class RootTransitionActivationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        policy_fixture.RootTransitionPolicyTests.setUpClass()

    def setUp(self):
        policy = object.__new__(policy_fixture.RootTransitionPolicyTests)
        policy.setUp()
        self.fx = policy.fx
        self.policy_fixture = policy
        self.csrs = policy.csrs
        self.temp = tempfile.TemporaryDirectory(prefix="root-activation-")
        self.root = Path(self.temp.name) / "root-store"
        self.prep_root = Path(self.temp.name) / "preparation"
        self.approval_root = Path(self.temp.name) / "approval"
        self.launch_mixin = object.__new__(retirement_fixture._ProtectedLaunchFixtureMixin)
        self.launch_mixin.fixtures = []
        self.launch_config = canonical_json({"sleep_seconds": 30})
        if os.name == "posix":
            self.launch_fixture, self.config_hash = self.launch_mixin._make_fixture(self.launch_config)
        else:
            self.launch_fixture = None
            self.config_hash = _sha(self.launch_config)
        self.old_specs = tuple(replace(spec, configuration_sha256=self.config_hash)
                               for spec in policy.old_specs)
        new_specs = tuple(replace(spec, configuration_sha256=self.config_hash)
                          for spec in policy.new_specs)
        self.candidate = build_final_activation_candidate(
            intent=self.fx.intent, issuance_candidate=policy.issued,
            old_snapshot_store=self.fx.store, old_launch_specs=self.old_specs,
            new_launch_specs=new_specs, new_ca_certificate_pem=self.fx.new_ca,
            new_snapshot_signing_key_pem=self.fx.new_snapshot_key,
            new_csr_by_identity=self.csrs, requested_expires_at=policy_fixture.issuance_fixture.NOW + 100)
        for path in (self.prep_root, self.approval_root):
            path.mkdir(mode=0o700)
            if os.name == "posix":
                os.chmod(path, 0o700)
        self.prep_path = self.prep_root / "intent.json"
        self.prep_path.write_bytes(canonical_json(self.fx.intent_document))
        self.approval_path = self.approval_root / "approval.json"
        if os.name == "posix":
            os.chmod(self.prep_path, 0o600)
        self._install_approval_and_proofs(self.candidate)
        old_policy = self.fx.store._encoded
        self.old_artifacts = {name: b"placeholder\n" for name in (
            "activation_manifest.json", "policy_snapshot.json", "ca_certificate.pem",
            "snapshot_signer_public.pem", "credential_bundle.json", "issuance_manifest.json",
            "final_approval.json", "preparation_intent.json", "public_csr_bundle.json",
            "old_possession_proofs.json", "retirement_receipt.json",
            "old_launch_specs.json", "new_launch_specs.json")}
        self.old_artifacts.update({
            "activation_manifest.json": canonical_json({"prior": True}),
            "policy_snapshot.json": old_policy,
            "ca_certificate.pem": self.fx.old_ca,
            "snapshot_signer_public.pem": self.fx.old_snapshot_public,
            "old_launch_specs.json": canonical_json(
                [role_launch_document(replace(x, generation_sha256="f" * 64))
                 for x in self.old_specs]),
            "new_launch_specs.json": canonical_json(
                [role_launch_document(x) for x in self.old_specs]),
        })
        self.old_hash = _provision_old_root(self.root, self.old_artifacts,
            revision=4, policy_digest=canonical_policy_digest(self.fx.payload),
            generation=self.old_specs[0].generation_sha256)

    def _install_approval_and_proofs(self, candidate):
        self.candidate = candidate
        approval = FinalActivationApproval(
            1, FINAL_APPROVAL_PURPOSE, self.fx.intent.transition_id,
            candidate.preparation_intent_sha256,
            candidate.issuance_manifest_sha256,
            candidate.activation_manifest_sha256, candidate.declaration)
        self.approval_bytes = canonical_json(final_activation_approval_document(approval))
        self.approval_path.write_bytes(self.approval_bytes)
        if os.name == "posix":
            os.chmod(self.approval_path, 0o600)
        members = {p.identity: p for p in candidate.declaration.affected_principals}
        self.principal_inputs = tuple(FinalApprovalPrincipalInput(
            members[item["principal"].identity], item["old_cert"], item["new_csr"],
            make_old_role_key_possession_proof(
                candidate.declaration, members[item["principal"].identity],
                old_private_key_pem=item["old_key"], old_certificate_pem=item["old_cert"],
                new_csr_pem=item["new_csr"])) for item in self.fx.roles)

    def tearDown(self):
        if hasattr(self, "supervisor"):
            self.launch_mixin.supervisor = self.supervisor
            self.launch_mixin._cleanup_owned()
        self.launch_mixin._remove_fixtures()
        self.temp.cleanup()
        self.fx.tearDown()

    def _activation_args(self, store, capability, **changes):
        args = dict(
            root_store=store, expected_old_selector_sha256=self.old_hash,
            preparation_path=self.prep_path, preparation_root=self.prep_root,
            approval_path=self.approval_path, approval_root=self.approval_root,
            expected_uid=os.geteuid(), clock=self.fx.clock_source.clock,
            candidate=self.candidate, new_ca_certificate_pem=self.fx.new_ca,
            new_snapshot_public_key_pem=self.fx.new_snapshot_public,
            new_csr_by_identity=self.csrs, principal_inputs=self.principal_inputs,
            retirement_supervisor=self.supervisor,
            retirement_capability=capability)
        args.update(changes)
        return args

    def _start_owned(self):
        self.supervisor = RetirementSupervisor()
        processes = []
        try:
            for spec in self.old_specs:
                pending = self.supervisor.spawn_owned_process(
                    self.launch_fixture.manifest_path,
                    protected_root=self.launch_fixture.root,
                    expected_uid=os.geteuid(), specs=(spec,))
                processes.append(pending._record.process)
                observed = asyncio.run(self.supervisor.observe_ready(
                    pending, ready_timeout_seconds=3))
                self.assertTrue(self.supervisor.validate_observed_launch(observed))
            return processes
        except BaseException:
            for process in processes:
                if process.poll() is None:
                    self.supervisor.terminate_owned_process_group(process)
            raise

    def _retire_owned(self, processes):
        for process in processes:
            if process.poll() is None:
                self.supervisor.terminate_owned_process_group(process)
        capability = asyncio.run(self.supervisor.retire_cohort(
            self.fx.intent.transition_id, self.candidate.old_launch_digest,
            timeout_seconds=5))
        self.assertTrue(self.supervisor.validate_retirement_capability(
            capability, transition_id=self.fx.intent.transition_id,
            expected_old_bindings_digest=self.candidate.old_launch_digest))
        return capability

    def _start_and_retire(self):
        processes = self._start_owned()
        try:
            return processes, self._retire_owned(processes)
        except BaseException:
            for process in processes:
                if process.poll() is None:
                    self.supervisor.terminate_owned_process_group(process)
            raise

    def test_selected_launch_plan_requires_exact_canonical_current_generation(self):
        encoded = self.old_artifacts["new_launch_specs.json"]
        self.assertEqual(_old_specs(encoded, self.old_specs[0].generation_sha256), self.old_specs)
        for bad in (encoded + b" ", b"{}", b"[]", b"null"):
            with self.subTest(bad=bad[:20]):
                with self.assertRaises(CredentialError):
                    _old_specs(bad, self.old_specs[0].generation_sha256)
        self.assertNotEqual(self.old_artifacts["old_launch_specs.json"], encoded)
        with self.assertRaises(CredentialError):
            _old_specs(self.old_artifacts["old_launch_specs.json"],
                       self.old_specs[0].generation_sha256)

    def test_controlled_clock_accepts_sub30s_monotonic_only_advance(self):
        stable = _StableClockSource(float(policy_fixture.issuance_fixture.NOW))
        first = stable.clock.sample()
        stable.mono += 21.0
        second = stable.clock.sample()
        self.assertEqual(first.wall, second.wall)
        self.assertEqual(second.monotonic - first.monotonic, 21.0)

    @unittest.skipUnless(os.name == "posix", "durable activation requires POSIX storage")
    def test_invalid_or_cross_registry_retirement_fails_before_any_write(self):
        supervisor = RetirementSupervisor()
        with RootGenerationStore(self.root, expected_uid=os.geteuid()) as store:
            with self.assertRaises(CredentialError):
                activate_root_transition(
                    root_store=store, expected_old_selector_sha256=self.old_hash,
                    preparation_path=self.prep_path, preparation_root=self.prep_root,
                    approval_path=self.approval_path, approval_root=self.approval_root,
                    expected_uid=os.geteuid(), clock=self.fx.clock_source.clock,
                    candidate=self.candidate,
                    new_ca_certificate_pem=self.fx.new_ca,
                    new_snapshot_public_key_pem=self.fx.new_snapshot_public,
                    new_csr_by_identity=self.csrs,
                    principal_inputs=self.principal_inputs,
                    retirement_supervisor=supervisor,
                    retirement_capability=object())
            selected = store.read_selected(lambda *_: None)
            self.assertEqual(selected.selector_sha256, self.old_hash)
            self.assertNotIn("pending.json", os.listdir(self.root))

    @unittest.skipUnless(os.name == "posix", "durable activation requires POSIX storage")
    def test_changed_selected_old_policy_blocks_before_pending(self):
        current = self.root / "generations" / self.old_specs[0].generation_sha256
        policy_path = current / "policy_snapshot.json"
        policy_path.write_bytes(policy_path.read_bytes() + b" ")
        os.chmod(policy_path, 0o600)
        with RootGenerationStore(self.root, expected_uid=os.geteuid()) as store:
            with self.assertRaises(StorageError):
                activate_root_transition(
                    root_store=store, expected_old_selector_sha256=self.old_hash,
                    preparation_path=self.prep_path, preparation_root=self.prep_root,
                    approval_path=self.approval_path, approval_root=self.approval_root,
                    expected_uid=os.geteuid(), clock=self.fx.clock_source.clock,
                    candidate=self.candidate, new_ca_certificate_pem=self.fx.new_ca,
                    new_snapshot_public_key_pem=self.fx.new_snapshot_public,
                    new_csr_by_identity=self.csrs, principal_inputs=self.principal_inputs,
                    retirement_supervisor=RetirementSupervisor(),
                    retirement_capability=object())
            self.assertEqual(hashlib.sha256((self.root / "selector.json").read_bytes()).hexdigest(),
                             self.old_hash)
            self.assertNotIn("pending.json", os.listdir(self.root))

    @unittest.skipUnless(os.name == "posix" and os.path.isdir("/proc"),
                         "cold activation requires native POSIX process ownership")
    def test_real_owned_old_cohort_retirement_allows_exact_cold_activation(self):
        processes = self._start_owned()
        try:
            with RootGenerationStore(self.root, expected_uid=os.geteuid()) as store:
                before = store.read_selected(lambda *_: None)
                with self.assertRaises(CredentialError):
                    activate_root_transition(**self._activation_args(store, object()))
                self.assertEqual(store.read_selected(lambda *_: None).selector_sha256,
                                 before.selector_sha256)
                self.assertNotIn("pending.json", os.listdir(self.root))

                capability = self._retire_owned(processes)

                bad_csr = dict(self.csrs)
                first_identity = next(iter(bad_csr))
                bad_csr[first_identity] += b"bad"
                with self.assertRaises(CredentialError):
                    activate_root_transition(**self._activation_args(
                        store, capability, new_csr_by_identity=bad_csr))
                bad_inputs = list(self.principal_inputs)
                bad_inputs[0] = replace(bad_inputs[0],
                                        possession_proof=bad_inputs[0].possession_proof + b"x")
                with self.assertRaises(CredentialError):
                    activate_root_transition(**self._activation_args(
                        store, capability, principal_inputs=tuple(bad_inputs)))
                bad_specs = tuple(replace(spec, configuration_sha256="0" * 64)
                                  for spec in self.candidate.old_launch_specs)
                with self.assertRaises(CredentialError):
                    activate_root_transition(**self._activation_args(
                        store, capability,
                        candidate=replace(self.candidate, old_launch_specs=bad_specs)))
                original_approval = self.approval_path.read_bytes()
                try:
                    self.approval_path.write_bytes(b"{}")
                    with self.assertRaises((CredentialError, SnapshotError)):
                        activate_root_transition(**self._activation_args(store, capability))
                finally:
                    self.approval_path.write_bytes(original_approval)
                    os.chmod(self.approval_path, 0o600)
                with self.assertRaises(StorageError):
                    activate_root_transition(**self._activation_args(
                        store, capability, expected_old_selector_sha256="0" * 64))
                self.assertEqual(store.read_selected(lambda *_: None).selector_sha256,
                                 before.selector_sha256)
                self.assertNotIn("pending.json", os.listdir(self.root))

                mutable_inputs = list(self.principal_inputs)
                mutable_csrs = dict(self.csrs)
                def mutate_caller_inputs(label):
                    if label == "validate.before_pending":
                        mutable_inputs.clear()
                        mutable_csrs.clear()
                store._fault_hook = mutate_caller_inputs
                result = activate_root_transition(**self._activation_args(
                    store, capability, principal_inputs=mutable_inputs,
                    new_csr_by_identity=mutable_csrs))
                store._fault_hook = None
                self.assertEqual(mutable_inputs, [])
                self.assertEqual(mutable_csrs, {})
                selected = store.read_selected(lambda *_: None)
                self.assertEqual(result.selector_sha256, selected.selector_sha256)
                self.assertEqual(len(selected.artifacts), 13)
                self.assertNotEqual(selected.artifacts["old_launch_specs.json"],
                                    selected.artifacts["new_launch_specs.json"])
                self.assertEqual(selected.selector.generation_sha256,
                                 result.generation_sha256)
                import base64, json
                persisted_csrs = json.loads(selected.artifacts["public_csr_bundle.json"])
                self.assertEqual([base64.b64decode(item["csr_pem_base64"])
                                  for item in persisted_csrs],
                                 [item.new_csr_pem for item in self.principal_inputs])
                persisted_proofs = json.loads(selected.artifacts["old_possession_proofs.json"])
                self.assertEqual([base64.b64decode(item["proof_base64"])
                                  for item in persisted_proofs],
                                 [item.possession_proof for item in self.principal_inputs])
                new_store = SnapshotStore(
                    verification_key_pem=self.fx.new_snapshot_public,
                    ca_certificate_pem=self.fx.new_ca,
                    clock=self.fx.clock_source.clock,
                    minimum_revision=selected.selector.policy_revision,
                    minimum_policy_digest=selected.selector.policy_digest)
                new_view = new_store.install(selected.active_policy_snapshot)
                self.assertEqual(new_view.policy_digest, self.candidate.policy_digest)
                self.assertEqual(new_view.revision, self.candidate.declaration.next_minimum_revision)
                with self.assertRaises(SnapshotError):
                    new_store.install(self.fx.store._encoded)
                old_entry = self.fx.roles[0]
                old_record = old_entry["record"]
                with self.assertRaises(CredentialError):
                    verify_leaf(self.fx.new_ca, old_entry["old_cert"],
                        now=policy_fixture.issuance_fixture.NOW,
                        account_id=old_record["account_id"],
                        device_id=old_record["device_id"], role=old_record["role"],
                        serial=old_record["serial"],
                        public_key_hash=old_record["public_key_sha256"],
                        certificate_hash=old_record["certificate_sha256"],
                        ekus=old_record["ekus"], dns_sans=old_record["dns_sans"],
                        ip_sans=old_record["ip_sans"])
        finally:
            for process in processes:
                if process.poll() is None:
                    self.supervisor.terminate_owned_process_group(process)

    @unittest.skipUnless(os.name == "posix" and os.path.isdir("/proc"),
                         "cold activation requires native POSIX process ownership")
    def test_overlap_expiry_at_pre_replace_keeps_old_selector_and_pending_fence(self):
        stable = _StableClockSource(float(policy_fixture.issuance_fixture.NOW))
        self.fx.clock_source.clock = stable.clock
        old_store = SnapshotStore(verification_key_pem=self.fx.old_snapshot_public,
            ca_certificate_pem=self.fx.old_ca, clock=stable.clock)
        old_store.install(self.fx.store._encoded)
        short_candidate = build_final_activation_candidate(
            intent=self.fx.intent, issuance_candidate=self.policy_fixture.issued,
            old_snapshot_store=old_store, old_launch_specs=self.old_specs,
            new_launch_specs=self.candidate.new_launch_specs,
            new_ca_certificate_pem=self.fx.new_ca,
            new_snapshot_signing_key_pem=self.fx.new_snapshot_key,
            new_csr_by_identity=self.csrs,
            requested_expires_at=policy_fixture.issuance_fixture.NOW + 120)
        payload = __import__("json").loads(short_candidate.policy_payload)
        payload["grants"][0]["not_after"] = policy_fixture.issuance_fixture.NOW + 20
        self.assertLess(payload["grants"][0]["not_after"], payload["expires_at"])
        self.assertTrue(all(item.record.not_after > payload["grants"][0]["not_after"]
                            for item in short_candidate.issuance_candidate.principals))
        payload_bytes = canonical_json(payload)
        digest = canonical_policy_digest(payload)
        declaration = parse_root_transition_declaration(canonical_json(
            _declaration_document(self.fx.intent, digest)))
        manifest = __import__("json").loads(short_candidate.activation_manifest)
        manifest["policy_digest"] = digest
        manifest["policy_payload_sha256"] = _sha(payload_bytes)
        manifest_bytes = canonical_json(manifest)
        short_candidate = replace(short_candidate, policy_digest=digest,
            policy_payload=payload_bytes,
            signed_snapshot=sign_snapshot(payload, self.fx.new_snapshot_key),
            activation_manifest=manifest_bytes,
            activation_manifest_sha256=_sha(manifest_bytes), declaration=declaration)
        self._install_approval_and_proofs(short_candidate)
        _processes, capability = self._start_and_retire()
        original_selector = (self.root / "selector.json").read_bytes()
        with RootGenerationStore(self.root, expected_uid=os.geteuid()) as store:
            reached_pre_replace = []
            def expire_at_replace(label):
                if label == "selector.replace":
                    reached_pre_replace.append(True)
                    # A sub-30-second monotonic-only advance passes Clock's
                    # discontinuity bound. Wall time is stalled intentionally:
                    # the later snapshot/leaf remain live while this original
                    # short grant's monotonic cap expires.
                    stable.mono += 21.0
            store._fault_hook = expire_at_replace
            with self.assertRaises(CredentialError):
                activate_root_transition(**self._activation_args(store, capability))
        self.assertEqual(reached_pre_replace, [True], "must fail at the final pre-replace gate")
        self.assertEqual((self.root / "selector.json").read_bytes(), original_selector)
        self.assertTrue((self.root / "pending.json").exists(),
                        "pre-replace expiry must retain the fail-closed transaction fence")


if __name__ == "__main__":
    unittest.main()
