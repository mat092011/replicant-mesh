"""Root-bound local identity validation with no model/runtime dependency."""
from __future__ import annotations

import os
import hashlib
import json
import tempfile
import threading
import unittest
from dataclasses import replace
from pathlib import Path

import tests.security.test_root_transition_policy as policy_fixture
import tests.security.test_root_transition_issuance as issuance_fixture
from steamboat_security.authorization import LocalIdentity
from steamboat_security.codec import canonical_json
from steamboat_security.errors import CredentialError, SnapshotError, StorageError
from steamboat_security.root_runtime import (_configuration_header,
    _require_current_role_grants, load_root_runtime_binding)
from steamboat_security.root_transition_launch import RoleLaunchSpec, role_launch_document
from steamboat_security.root_transition_policy import build_final_activation_candidate
from steamboat_security.root_transition_storage import (RootGenerationSelector,
    RootGenerationStore, root_generation_selector_document)
from steamboat_security.snapshot import (SnapshotStore, canonical_policy_digest,
                                         sign_snapshot)
from steamboat_security.certificates import (ROLE_EKUS, generate_private_key_pem,
    issue_leaf, make_csr)
from steamboat_security.operator import _record_from_leaf


class RootRuntimeContractTests(unittest.TestCase):
    def test_legacy_identity_remains_valid_and_root_fields_are_paired(self):
        legacy = LocalIdentity(b"certificate", "a" * 32, "b" * 64)
        self.assertIsNone(legacy.admission_epoch)
        self.assertIsNone(legacy.root_generation_sha256)
        with self.assertRaises(ValueError):
            LocalIdentity(b"certificate", "a" * 32, "b" * 64,
                          admission_epoch=1)
        with self.assertRaises(ValueError):
            LocalIdentity(b"certificate", "a" * 32, "b" * 64,
                          admission_epoch=True, root_generation_sha256="c" * 64)
        with self.assertRaises(ValueError):
            LocalIdentity(b"certificate", "a" * 32, "b" * 64,
                          admission_epoch=1, root_generation_sha256="C" * 64)
        root_bound = LocalIdentity(b"certificate", "a" * 32, "b" * 64,
                                   admission_epoch=3, root_generation_sha256="c" * 64)
        self.assertEqual(root_bound.admission_epoch, 3)

    def test_header_rejects_missing_fields_and_boolean_epochs(self):
        header = {
            "schema_version": 1, "profile": "native_posix_root_role_v1",
            "protected_root": "/protected/root", "selected_root": "a" * 64,
            "account_id": "acct_" + "1" * 32, "device_id": "dev_" + "2" * 32,
            "role": "host", "boot_id": "3" * 32, "credential_epoch": 2,
            "admission_epoch": 4, "generation_sha256": "a" * 64,
            "launch_nonce": "4" * 32, "certificate_path": "/protected/cert.pem",
            "private_key_path": "/protected/key.pem", "model_id": "b" * 64,
            "assignment_id": "asg_" + "5" * 32,
            "runtime_configuration_path": "/protected/runtime.json",
            "runtime_configuration_sha256": "c" * 64,
        }
        self.assertIs(_configuration_header(header), header)
        with self.assertRaises(CredentialError):
            _configuration_header({**header, "credential_epoch": True})
        with self.assertRaises(CredentialError):
            _configuration_header({k: v for k, v in header.items() if k != "launch_nonce"})
        with self.assertRaises(CredentialError):
            _configuration_header({**header, "unexpected": "value"})

    def test_private_key_is_not_exposed_by_binding_repr(self):
        from steamboat_security.root_runtime import TLSMaterials

        materials = TLSMaterials(b"cert bytes", b"secret key bytes")
        self.assertNotIn("secret key bytes", repr(materials))


class RootRuntimeProtectedBindingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        policy_fixture.RootTransitionPolicyTests.setUpClass()

    def setUp(self):
        case = object.__new__(policy_fixture.RootTransitionPolicyTests)
        case.setUp()
        self.fx = case.fx
        self.fx.candidate = case.candidate
        self.fx.csrs = case.csrs
        self.temp = tempfile.TemporaryDirectory()
        self.base = Path(self.temp.name)
        self.root = self.base / "selected-root"
        self.config_root = self.base / "config"
        self.root.mkdir(mode=0o700)
        self.config_root.mkdir(mode=0o700)
        os.chmod(self.root, 0o700)
        os.chmod(self.config_root, 0o700)
        self._prepare_candidate_and_root()
        self.store = (RootGenerationStore(self.root, expected_uid=os.geteuid())
                      if os.name == "posix" and hasattr(os, "O_NOFOLLOW") else None)

    def tearDown(self):
        if getattr(self, "store", None) is not None:
            self.store.close()
        self.fx.tearDown()
        self.temp.cleanup()

    def _prepare_candidate_and_root(self):
        original = self.fx.candidate
        self.principal = next(p for p in self.fx.intent.affected_principals if p.role == "host")
        self.issued = next(x for x in original.issuance_candidate.principals
                           if x.identity == self.principal.identity)
        self.role_entry = next(x for x in self.fx.roles
                               if x["principal"].identity == self.principal.identity)
        self.cert_path = self.config_root / "leaf.pem"
        self.key_path = self.config_root / "role-key.pem"
        self.runtime_path = self.config_root / "runtime.json"
        self.config_path = self.config_root / "role.json"
        self.runtime = canonical_json({"fixed_adapter": "host-v1"})
        grants = json.loads(original.policy_payload)["grants"]
        grant = next(x for x in grants if x["target_serial"] == self.issued.record.serial
                     or x["actor_serial"] == self.issued.record.serial)
        spec = next(x for x in original.new_launch_specs if x.identity == self.principal.identity)
        self.header = {
            "schema_version": 1, "profile": "native_posix_root_role_v1",
            "protected_root": str(self.config_root), "selected_root": str(self.root),
            "account_id": self.principal.account_id, "device_id": self.principal.device_id,
            "role": self.principal.role, "boot_id": spec.boot_id,
            "credential_epoch": spec.credential_epoch,
            "admission_epoch": spec.admission_epoch,
            "generation_sha256": spec.generation_sha256,
            "launch_nonce": spec.launch_nonce,
            "certificate_path": str(self.cert_path), "private_key_path": str(self.key_path),
            "model_id": grant["model_id"], "assignment_id": grant["assignment_id"],
            "runtime_configuration_path": str(self.runtime_path),
            "runtime_configuration_sha256": hashlib.sha256(self.runtime).hexdigest(),
        }
        if self.principal.role == "consumer":
            self.header["assignment_id"] = None
        config_hash = hashlib.sha256(canonical_json(self.header)).hexdigest()
        new_specs = tuple(replace(x, configuration_sha256=config_hash)
                          for x in original.new_launch_specs)
        self.fx.candidate = build_final_activation_candidate(
            intent=self.fx.intent, issuance_candidate=original.issuance_candidate,
            old_snapshot_store=self.fx.store, old_launch_specs=original.old_launch_specs,
            new_launch_specs=new_specs, new_ca_certificate_pem=self.fx.new_ca,
            new_snapshot_signing_key_pem=self.fx.new_snapshot_key,
            new_csr_by_identity=self.fx.csrs,
            requested_expires_at=issuance_fixture.NOW + 100)
        self.spec = next(x for x in self.fx.candidate.new_launch_specs
                         if x.identity == self.principal.identity)
        self.cert_path.write_bytes(self.issued.certificate_pem)
        self.key_path.write_bytes(self.role_entry["new_key"])
        self.runtime_path.write_bytes(self.runtime)
        self.config_path.write_bytes(canonical_json(self.header))
        for path in (self.cert_path, self.key_path, self.runtime_path, self.config_path):
            os.chmod(path, 0o600)

        old_specs = self.fx.candidate.old_launch_specs
        bundle = {
            "activation_manifest.json": self.fx.candidate.activation_manifest,
            "policy_snapshot.json": self.fx.candidate.signed_snapshot,
            "ca_certificate.pem": self.fx.new_ca,
            "snapshot_signer_public.pem": self.fx.new_snapshot_public,
            "credential_bundle.json": b"{}",
            "issuance_manifest.json": self.fx.candidate.issuance_candidate.manifest,
            "final_approval.json": b"{}", "preparation_intent.json": b"{}",
            "public_csr_bundle.json": b"{}", "old_possession_proofs.json": b"{}",
            "retirement_receipt.json": b"{}",
            "old_launch_specs.json": canonical_json([role_launch_document(x) for x in old_specs]),
            "new_launch_specs.json": canonical_json([role_launch_document(x)
                                                       for x in self.fx.candidate.new_launch_specs]),
        }
        sha = lambda value: hashlib.sha256(value).hexdigest()
        digests = {name: sha(value) for name, value in bundle.items()}
        envelope = json.loads(self.fx.candidate.signed_snapshot)
        selector = RootGenerationSelector(
            self.spec.generation_sha256, sha(bundle["activation_manifest.json"]),
            envelope["payload"]["revision"], self.fx.candidate.policy_digest,
            sha(bundle["policy_snapshot.json"]), digests)
        generations, policies = self.root / "generations", self.root / "policies"
        generations.mkdir(mode=0o700)
        policies.mkdir(mode=0o700)
        (self.root / "transition.lock").touch(mode=0o600)
        os.chmod(self.root / "transition.lock", 0o600)
        (policies / f"{selector.active_policy_snapshot_sha256}.json").write_bytes(
            self.fx.candidate.signed_snapshot)
        os.chmod(policies / f"{selector.active_policy_snapshot_sha256}.json", 0o600)
        generation = generations / selector.generation_sha256
        generation.mkdir(mode=0o700)
        descriptor = {"schema_version": 1, "purpose": "root_generation_descriptor",
            "generation_sha256": selector.generation_sha256,
            "activation_manifest_sha256": selector.activation_manifest_sha256,
            "artifact_sha256": dict(selector.artifact_sha256)}
        for name, value in {"descriptor.json": canonical_json(descriptor), **bundle}.items():
            path = generation / name
            path.write_bytes(value)
            os.chmod(path, 0o600)
        selected = self.root / "selector.json"
        selected.write_bytes(canonical_json(root_generation_selector_document(selector)))
        os.chmod(selected, 0o600)

    def call(self, **kwargs):
        values = dict(root_store=self.store, clock=self.fx.clock_source.clock,
            expected_launch_spec=self.spec, configuration_path=self.config_path,
            configuration_root=self.config_root, expected_uid=os.geteuid())
        values.update(kwargs)
        return load_root_runtime_binding(**values)

    def _binding_or_skip(self):
        if self.store is None:
            self.skipTest("durable root runtime binding requires POSIX no-follow support")
        return self.call()

    def _next_policy(self, *, remove_local=False):
        payload = json.loads(self.fx.candidate.policy_payload)
        payload["revision"] += 1
        if remove_local:
            serial = self.issued.record.serial
            payload["credentials"] = [x for x in payload["credentials"]
                                      if x["serial"] != serial]
            payload["grants"] = [x for x in payload["grants"]
                                 if x["actor_serial"] != serial
                                 and x["target_serial"] != serial]
        return sign_snapshot(payload, self.fx.new_snapshot_key)

    def _selected(self):
        return self.store.read_selected(validate=lambda *_args: None)

    def test_initial_install_reconciles_exact_durable_head_and_equal_resign_keeps_bytes(self):
        binding = self._binding_or_skip()
        selected = self._selected()
        self.assertEqual(binding.snapshot_store._encoded, selected.active_policy_snapshot)
        before_files = sorted(p.name for p in (self.root / "policies").iterdir())
        payload = json.loads(selected.active_policy_snapshot)["payload"]
        resigned = sign_snapshot(payload, self.fx.new_snapshot_key)
        binding.snapshot_store.install(resigned)
        after = self._selected()
        self.assertEqual(after.selector_sha256, selected.selector_sha256)
        self.assertEqual(after.active_policy_snapshot, selected.active_policy_snapshot)
        self.assertEqual(sorted(p.name for p in (self.root / "policies").iterdir()), before_files)
        self.assertEqual(binding.snapshot_store._encoded, selected.active_policy_snapshot)

    def test_refresh_persists_before_notify_and_cold_floor_rejects_old_policy(self):
        binding = self._binding_or_skip()
        selected_before = self._selected()
        notifications = []
        callback_heads = []

        def observe_committed(view):
            notifications.append(view)
            selected_now = self._selected()
            callback_heads.append((selected_now.selector.policy_revision,
                                   selected_now.selector.policy_digest))

        binding.snapshot_store.subscribe(observe_committed)
        refreshed = self._next_policy()
        new_view = binding.snapshot_store.install(refreshed)
        selected_after = self._selected()
        self.assertGreater(selected_after.selector.policy_revision,
                           selected_before.selector.policy_revision)
        self.assertEqual(selected_after.active_policy_snapshot, refreshed)
        self.assertEqual(notifications, [new_view])
        self.assertEqual(callback_heads, [(new_view.revision, new_view.policy_digest)])
        cold = SnapshotStore(
            verification_key_pem=selected_after.artifacts["snapshot_signer_public.pem"],
            ca_certificate_pem=selected_after.artifacts["ca_certificate.pem"],
            clock=self.fx.clock_source.clock,
            minimum_revision=selected_after.selector.policy_revision,
            minimum_policy_digest=selected_after.selector.policy_digest)
        with self.assertRaises(SnapshotError):
            cold.install(selected_before.active_policy_snapshot)

    def test_signed_local_role_revocation_persists_and_notifies_then_cold_binding_denies(self):
        binding = self._binding_or_skip()
        notifications = []
        binding.snapshot_store.subscribe(notifications.append)
        revoked = self._next_policy(remove_local=True)
        binding.snapshot_store.install(revoked)
        selected = self._selected()
        self.assertEqual(selected.active_policy_snapshot, revoked)
        self.assertEqual(len(notifications), 1)
        with self.assertRaises(CredentialError):
            self.call()

    def test_two_bindings_reconcile_only_the_same_incoming_head(self):
        first = self._binding_or_skip()
        second = self.call()
        candidate = self._next_policy()
        outcomes = []
        writer_paused = threading.Event()
        release_writer = threading.Event()
        second_attempting = threading.Event()
        second_done = threading.Event()

        def pause_after_temp_fsync(label):
            if label == "selector.replace" and not writer_paused.is_set():
                writer_paused.set()
                if not release_writer.wait(timeout=10):
                    raise TimeoutError("test did not release selector writer")

        self.store._fault_hook = pause_after_temp_fsync

        def install(binding):
            try:
                outcomes.append(("ok", binding.snapshot_store.install(candidate)))
            except BaseException as error:
                outcomes.append(("error", error))

        first_thread = threading.Thread(target=install, args=(first,))
        def install_second():
            second_attempting.set()
            install(second)
            second_done.set()

        second_thread = threading.Thread(target=install_second)
        try:
            first_thread.start()
            self.assertTrue(writer_paused.wait(timeout=5),
                            "first writer did not reach selector replace")
            second_thread.start()
            self.assertTrue(second_attempting.wait(timeout=5))
            # The second operation must be blocked by the root flock while a
            # transaction tempfile exists, not rejected by a pre-lock namespace scan.
            self.assertFalse(second_done.wait(timeout=0.2),
                             "second binding finished while selector writer held the root lock")
        finally:
            release_writer.set()
            for thread in (first_thread, second_thread):
                if thread.ident is not None:
                    thread.join(timeout=10)
        self.assertTrue(all(not thread.is_alive() for thread in (first_thread, second_thread)))
        details = []
        for kind, value in outcomes:
            cause = getattr(value, "__cause__", None)
            details.append(f"{kind}: {type(value).__name__}: {value}; "
                           f"cause={type(cause).__name__ if cause else None}: {cause}")
        self.assertEqual([kind for kind, _value in outcomes], ["ok", "ok"],
                         "; ".join(details))
        selected = self._selected()
        self.assertEqual(selected.active_policy_snapshot, candidate)

    def test_stale_binding_rejects_unrelated_higher_policy_head(self):
        first = self._binding_or_skip()
        second = self.call()
        first.snapshot_store.install(self._next_policy())
        unrelated = self._next_policy()
        payload = json.loads(unrelated)["payload"]
        payload["revision"] += 1
        unrelated_higher = sign_snapshot(payload, self.fx.new_snapshot_key)
        with self.assertRaises(SnapshotError):
            second.snapshot_store.install(unrelated_higher)
        with self.assertRaises(SnapshotError):
            second.snapshot_store.current()
        self.assertEqual(self._selected().active_policy_snapshot,
                         first.snapshot_store._encoded)

    def test_pre_replace_unknown_write_latches_original_store_and_does_not_notify(self):
        binding = self._binding_or_skip()
        selected_before = self._selected()
        notifications = []
        binding.snapshot_store.subscribe(notifications.append)
        selector_before = (self.root / "selector.json").read_bytes()
        self.store._fault_hook = lambda label: (
            (_ for _ in ()).throw(OSError("synthetic unknown write outcome"))
            if label == "selector.replace" else None)
        with self.assertRaises(SnapshotError):
            binding.snapshot_store.install(self._next_policy())
        with self.assertRaises(SnapshotError):
            binding.snapshot_store.current()
        self.assertEqual((self.root / "selector.json").read_bytes(), selector_before)
        self.assertEqual(notifications, [])

    def test_generation_plan_change_and_closed_store_fail_closed(self):
        binding = self._binding_or_skip()
        plan = (self.root / "generations" / self.spec.generation_sha256
                / "new_launch_specs.json")
        plan.write_bytes(b"[]")
        os.chmod(plan, 0o600)
        with self.assertRaises((SnapshotError, StorageError)):
            binding.snapshot_store.install(self._next_policy())

    def test_closed_root_store_faults_live_binding(self):
        binding = self._binding_or_skip()
        self.store.close()
        with self.assertRaises(SnapshotError):
            binding.snapshot_store.install(self._next_policy())

    def test_changed_protected_configuration_faults_live_binding(self):
        binding = self._binding_or_skip()
        self.runtime_path.write_bytes(self.runtime + b" ")
        os.chmod(self.runtime_path, 0o600)
        with self.assertRaises(SnapshotError):
            binding.snapshot_store.install(self._next_policy())
        with self.assertRaises(SnapshotError):
            binding.snapshot_store.current()

    def test_cold_loaded_real_role_binds_selected_policy_and_key(self):
        if self.store is None:
            self.skipTest("protected root binding requires POSIX no-follow support")
        self.store.close()
        self.store = RootGenerationStore(self.root, expected_uid=os.geteuid())
        result = self.call()
        self.assertEqual(result.local_identity.root_generation_sha256, self.spec.generation_sha256)
        self.assertEqual(result.local_identity.admission_epoch, self.spec.admission_epoch)
        self.assertEqual(result.tls_materials.certificate_pem, self.cert_path.read_bytes())
        self.assertEqual(result.runtime_configuration, self.runtime)
        self.assertEqual(result.configuration_header, canonical_json(self.header))
        self.assertIs(result.snapshot_store.clock, self.fx.clock_source.clock)

    def test_tampered_key_or_config_rejects(self):
        if self.store is None:
            self.skipTest("protected root binding requires POSIX no-follow support")
        self.key_path.write_bytes(self.role_entry["old_key"])
        os.chmod(self.key_path, 0o600)
        with self.assertRaises(CredentialError):
            self.call()
        self.key_path.write_bytes(self.role_entry["new_key"])
        os.chmod(self.key_path, 0o600)
        altered = dict(self.header)
        altered["boot_id"] = "f" * 32
        self.config_path.write_bytes(canonical_json(altered))
        os.chmod(self.config_path, 0o600)
        with self.assertRaises(CredentialError):
            self.call()

    def test_wrong_plan_spec_or_runtime_hash_rejects(self):
        if self.store is None:
            self.skipTest("protected root binding requires POSIX no-follow support")
        with self.assertRaises(CredentialError):
            self.call(expected_launch_spec=replace(self.spec, admission_epoch=99))
        self.runtime_path.write_bytes(self.runtime + b" ")
        os.chmod(self.runtime_path, 0o600)
        with self.assertRaises(CredentialError):
            self.call()

    def test_model_assignment_and_old_plan_tampering_reject(self):
        if self.store is None:
            self.skipTest("protected root binding requires POSIX no-follow support")
        for field, value in (("model_id", "e" * 64),
                             ("assignment_id", "asg_" + "f" * 32)):
            altered = dict(self.header)
            altered[field] = value
            self.config_path.write_bytes(canonical_json(altered))
            os.chmod(self.config_path, 0o600)
            with self.assertRaises(CredentialError):
                self.call()
        self.config_path.write_bytes(canonical_json(self.header))
        os.chmod(self.config_path, 0o600)
        old_plan = (self.root / "generations" / self.spec.generation_sha256
                    / "old_launch_specs.json")
        old_plan.write_bytes(b"[]")
        os.chmod(old_plan, 0o600)
        from steamboat_security.errors import StorageError
        with self.assertRaises(StorageError):
            self.call()

    def test_selected_policy_blob_tampering_rejects(self):
        if self.store is None:
            self.skipTest("protected root binding requires POSIX no-follow support")
        selector = json.loads((self.root / "selector.json").read_bytes())
        active_hash = selector["active_policy_snapshot_sha256"]
        active_path = self.root / "policies" / f"{active_hash}.json"
        active_path.write_bytes(active_path.read_bytes() + b" ")
        os.chmod(active_path, 0o600)
        from steamboat_security.errors import StorageError
        with self.assertRaises(StorageError):
            self.call()

    def test_coordinator_checks_consumer_and_multiple_worker_assignment_directions(self):
        payload = json.loads(self.fx.candidate.policy_payload)
        coordinator = next(p for p in self.fx.intent.affected_principals
                          if p.role == "personal_coordinator")
        coordinator_record = next(r for r in json.loads(self.fx.candidate.policy_payload)["credentials"]
                                  if r["account_id"] == coordinator.account_id
                                  and r["device_id"] == coordinator.device_id)
        worker_grant = next(g for g in payload["grants"]
                            if g["actor_serial"] == coordinator_record["serial"])
        extra = dict(worker_grant)
        extra["assignment_id"] = "asg_" + "f" * 32
        payload["grants"].append(extra)
        consumer_key = generate_private_key_pem()
        consumer_device = "dev_" + "e" * 32
        consumer_csr = make_csr(consumer_key, account_id=coordinator.account_id,
                                device_id=consumer_device, role="consumer")
        consumer_cert = issue_leaf(self.fx.new_ca, self.fx.new_ca_key, consumer_csr,
            account_id=coordinator.account_id, device_id=consumer_device, role="consumer",
            not_before=issuance_fixture.NOW - 10,
            not_after=issuance_fixture.NOW + 90,
            ekus=tuple(sorted(ROLE_EKUS["consumer"])))
        consumer_record = _record_from_leaf(consumer_cert,
            account_id=coordinator.account_id, device_id=consumer_device,
            role="consumer", credential_epoch=1)
        payload["credentials"].append(consumer_record)
        model_id = worker_grant["model_id"]
        payload["grants"].append({
            "account_id": coordinator.account_id, "device_id": consumer_device,
            "role": "consumer", "actor_serial": consumer_record["serial"],
            "actor_public_key_sha256": consumer_record["public_key_sha256"],
            "actor_credential_epoch": 1, "tenant_account_id": coordinator.account_id,
            "target_account_id": coordinator.account_id,
            "target_device_id": coordinator.device_id,
            "target_role": "personal_coordinator",
            "target_serial": coordinator_record["serial"],
            "target_public_key_sha256": coordinator_record["public_key_sha256"],
            "target_credential_epoch": coordinator_record["credential_epoch"],
            "target_boot_id": next(x.boot_id for x in self.fx.candidate.new_launch_specs
                                    if x.identity == coordinator.identity),
            "actor_boot_id": None, "assignment_id": None, "model_id": model_id,
            "method": "steamboat.v1.Coordinator/Generate",
            "not_before": issuance_fixture.NOW - 10,
            "not_after": issuance_fixture.NOW + 80,
        })
        encoded = sign_snapshot(payload, self.fx.new_snapshot_key)
        store = SnapshotStore(verification_key_pem=self.fx.new_snapshot_public,
            ca_certificate_pem=self.fx.new_ca, clock=self.fx.clock_source.clock,
            minimum_revision=payload["revision"],
            minimum_policy_digest=canonical_policy_digest(payload))
        view = store.install(encoded)
        sample = self.fx.clock_source.clock.sample()
        spec = next(x for x in self.fx.candidate.new_launch_specs
                    if x.identity == coordinator.identity)
        _require_current_role_grants(view, sample, view.credentials_by_serial[spec.serial],
            spec, {"model_id": worker_grant["model_id"], "assignment_id": None})
        consumer_spec = RoleLaunchSpec(
            spec.generation_sha256, coordinator.account_id, consumer_device, "consumer",
            consumer_record["serial"], consumer_record["certificate_sha256"],
            consumer_record["public_key_sha256"], 1, "e" * 32, 1, "a" * 64, "c" * 32)
        _require_current_role_grants(view, sample,
            view.credentials_by_serial[consumer_record["serial"]], consumer_spec,
            {"model_id": model_id, "assignment_id": None})
        with self.assertRaises(CredentialError):
            _require_current_role_grants(view, sample,
                view.credentials_by_serial[consumer_record["serial"]], consumer_spec,
                {"model_id": model_id, "assignment_id": "asg_" + "f" * 32})

    def test_current_policy_is_rechecked_after_final_selected_head_read(self):
        if self.store is None:
            self.skipTest("protected root binding requires POSIX no-follow support")
        original = self.store.read_selected
        reads = 0

        def advance_after_final_read(*, validate):
            nonlocal reads
            result = original(validate=validate)
            reads += 1
            if reads == 2:
                self.fx.clock_source.advance(101)
            return result

        self.store.read_selected = advance_after_final_read
        with self.assertRaises(CredentialError):
            self.call()

    def test_real_candidate_and_configuration_hash_prepare_on_any_host(self):
        self.assertEqual(self.spec.configuration_sha256,
                         hashlib.sha256(canonical_json(self.header)).hexdigest())
        self.assertEqual(self.spec.generation_sha256,
                         self.fx.candidate.new_launch_specs[0].generation_sha256)
        self.assertEqual(len(self.fx.candidate.issuance_candidate.principals), 2)


if __name__ == "__main__":
    unittest.main()
