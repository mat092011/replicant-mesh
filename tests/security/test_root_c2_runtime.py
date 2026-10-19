"""Portable closed-format and signature checks for the C2 runtime loader."""
from __future__ import annotations

import hashlib
import json
import os
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from cryptography.hazmat.primitives import serialization

from steamboat_security.certificates import (certificate_sha256,
    generate_private_key_pem, public_key_sha256)
from steamboat_security.clock import Clock
from steamboat_security.codec import canonical_json
from steamboat_security.errors import CredentialError, SnapshotError, StorageError
from steamboat_security.channel_certificates import (
    issue_channel_certificate, make_channel_csr, verify_channel_certificate,
)
from steamboat_security.root_c2_group_scope import (
    PROFILE, sign_c2_host_group_policy, verify_c2_host_group_policy,
)
from steamboat_security.root_c2_runtime import (
    _C2PolicyRefreshRequired, _header, load_c2_host_runtime_binding,
)
from steamboat_security.root_runtime import load_root_runtime_binding
from steamboat_security.root_transition_launch import (
    canonical_role_launch_digest, parse_role_launch_spec,
)
from steamboat_security.root_transition_storage import (
    RootGenerationStore, RootGenerationSelector, root_generation_selector_document,
)
from steamboat_security.snapshot import canonical_policy_digest, sign_snapshot
import tests.security.test_root_c2_selected as selected_fixture
import steamboat_security.root_c2_runtime as runtime_module


class _TestClock:
    def __init__(self, wall=2_000_000_000, mono=50.0):
        self.wall, self.mono = wall, mono
        self.clock = Clock(wall=lambda: self.wall, monotonic=lambda: self.mono,
                           uncertainty_seconds=lambda: 0.0)


def _scope(operator_pin):
    components = []
    for index in range(1, 4):
        components.append({"component": f"worker-{index}",
            "worker_boot_id": f"{index:032x}", "assignment_id": f"asg_{index:032x}",
            "assignment_sha256": f"{index:064x}",
            "channel_certificate_sha256": f"{index+10:064x}",
            "channel_public_key_sha256": f"{index+20:064x}"})
    return {"version": 1, "profile": PROFILE, "account_id": "acct_" + "a"*32,
        "device_id": "dev_" + "b"*32, "role": "host",
        "credential": {"serial": "1a", "credential_epoch": 2,
            "certificate_sha256": "c"*64, "public_key_sha256": "d"*64},
        "generation_sha256": "e"*64, "admission_epoch": 3,
        "parent_boot_id": "f"*32, "model_id": "1"*64,
        "catalog_sha256": "2"*64, "catalog_public_key_sha256": "3"*64,
        "operator_public_key_sha256": operator_pin, "components": components}


def _header_value():
    paths = {f"worker-{i}": {"certificate_path": f"/protected/worker-{i}.pem",
              "private_key_path": f"/protected/worker-{i}.key"} for i in range(1, 4)}
    return {"schema_version": 1, "profile": "native_posix_root_c2_host_group_v1",
        "protected_root": "/protected", "selected_root": "/selected",
        "account_id": "acct_" + "a"*32, "device_id": "dev_" + "b"*32,
        "role": "host", "boot_id": "f"*32, "credential_epoch": 2,
        "admission_epoch": 3, "generation_sha256": "e"*64,
        "launch_nonce": "0"*32, "certificate_path": "/protected/host.pem",
        "private_key_path": "/protected/host.key", "model_id": "1"*64,
        "runtime_configuration_path": "/protected/runtime.json",
        "runtime_configuration_sha256": "4"*64, "component_paths": paths,
        "group_policy_path": "/protected/group-policy.json",
        "group_policy_sha256": "5"*64}


class C2RuntimeValidationTests(unittest.TestCase):
    def test_three_component_header_is_closed_and_sorted(self):
        header = _header(_header_value())
        self.assertEqual(len(header["component_paths"]), 3)
        header["unexpected"] = True
        with self.assertRaisesRegex(CredentialError, "unknown or missing"):
            _header(header)

    def test_component_map_must_be_sorted_and_absolute(self):
        header = _header_value()
        header["component_paths"] = dict(reversed(list(header["component_paths"].items())))
        with self.assertRaisesRegex(CredentialError, "sorted"):
            _header(header)
        header = _header_value()
        header["component_paths"]["worker-1"]["certificate_path"] = "relative.pem"
        with self.assertRaisesRegex(CredentialError, "absolute"):
            _header(header)

    def test_real_operator_signature_binds_exact_three_component_scope(self):
        key_pem = generate_private_key_pem()
        key = serialization.load_pem_private_key(key_pem, password=None)
        public_pem = key.public_key().public_bytes(serialization.Encoding.PEM,
                                                    serialization.PublicFormat.SubjectPublicKeyInfo)
        scope = _scope(public_key_sha256(key.public_key()))
        clock = _TestClock()
        payload = {"version": 1, "issued_at": int(clock.wall)-1,
                   "expires_at": int(clock.wall)+120, "scope": scope}
        signed = sign_c2_host_group_policy(payload, key_pem)
        verified = verify_c2_host_group_policy(signed, public_pem, clock=clock.clock)
        self.assertEqual(verified.scope.to_document(), scope)
        self.assertLessEqual(verified.deadline_monotonic, clock.mono+121)
        wrong = serialization.load_pem_private_key(generate_private_key_pem(), password=None)
        wrong_public = wrong.public_key().public_bytes(serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo)
        with self.assertRaisesRegex(SnapshotError, "operator key"):
            verify_c2_host_group_policy(signed, wrong_public, clock=clock.clock)

    def test_group_policy_rejects_expiry_beyond_short_binding_window(self):
        key_pem = generate_private_key_pem()
        key = serialization.load_pem_private_key(key_pem, password=None)
        public_pem = key.public_key().public_bytes(serialization.Encoding.PEM,
                                                    serialization.PublicFormat.SubjectPublicKeyInfo)
        scope = _scope(public_key_sha256(key.public_key()))
        now = _TestClock()
        with self.assertRaisesRegex(SnapshotError, "lifetime"):
            sign_c2_host_group_policy({"version": 1, "issued_at": int(now.wall)-1,
                "expires_at": int(now.wall)+301, "scope": scope}, key_pem)


@unittest.skipUnless(os.name == "posix", "protected root storage requires POSIX")
class C2RuntimeStoreIntegrationTests(unittest.TestCase):
    def setUp(self):
        selected_fixture.C2SelectedCohortTests.setUpClass()
        self.fixture = object.__new__(selected_fixture.C2SelectedCohortTests)
        self.fixture.setUp()
        self.fx = self.fixture.fx
        self.temp = tempfile.TemporaryDirectory(prefix="c2-runtime-binding-")
        base = Path(self.temp.name)
        self.root, self.protected = base / "selected", base / "protected"
        self.root.mkdir(mode=0o700); os.chmod(self.root, 0o700)
        self.protected.mkdir(mode=0o700); os.chmod(self.protected, 0o700)
        self.wall, self.mono = self.fx.clock_source.wall, 500.0
        self.uncertainty = 0.0
        self.clock = Clock(wall=lambda: self.wall, monotonic=lambda: self.mono,
                           uncertainty_seconds=lambda: self.uncertainty)
        group_ttl = 300 if self._testMethodName in {
            "test_channel_wall_expiry_rejects_clock_drift_even_before_monotonic_deadline",
            "test_final_uncertainty_deadline_is_retained_across_clock_drift",
            "test_final_uncertainty_retains_channel_monotonic_deadline",
            "test_initial_uncertainty_retains_channel_monotonic_deadline",
            "test_first_selected_view_uncertainty_deadline_is_retained",
            "test_selected_head_mismatch_retains_deadline_before_refresh"} else 60
        if self._testMethodName in {
            "test_final_uncertainty_retains_group_policy_deadline",
            "test_initial_uncertainty_retains_group_policy_deadline"}:
            group_ttl = 70
        self._build(group_ttl=group_ttl)

    def tearDown(self):
        self.temp.cleanup()
        self.fixture.tearDown()

    @staticmethod
    def _private(path, data):
        path.write_bytes(data)
        os.chmod(path, 0o600)

    def _build(self, *, group_ttl):
        selector, artifacts, active, scope = self.fixture._inputs(grant_fault="none")
        manifest = json.loads(artifacts["activation_manifest.json"])
        host_doc = next(x for x in manifest["new_launch_specs"] if x["role"] == "host")
        host_before = parse_role_launch_spec(host_doc)
        issued = next(x for x in self.fixture.candidate.issuance_candidate.principals
                      if x.identity == host_before.identity)
        role_fx = next(x for x in self.fx.roles
                       if x["principal"].identity == host_before.identity)
        operator_key = generate_private_key_pem()
        operator_private = serialization.load_pem_private_key(operator_key, password=None)
        self.operator_public = operator_private.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        scope["operator_public_key_sha256"] = public_key_sha256(operator_private.public_key())
        self.components = scope["components"]
        self.channel_paths = {}
        channel_identity = {"account_id": host_before.account_id,
            "device_id": host_before.device_id, "host_serial": host_before.serial,
            "credential_epoch": host_before.credential_epoch}
        for component in self.components:
            key_pem = generate_private_key_pem()
            csr = make_channel_csr(key_pem, kind="worker_stream", identity=channel_identity)
            cert_pem = issue_channel_certificate(self.fx.new_ca, self.fx.new_ca_key, csr,
                kind="worker_stream", identity=channel_identity, now=self.wall,
                lifetime_seconds=120)
            checked = verify_channel_certificate(cert_pem, self.fx.new_ca,
                kind="worker_stream", expected_identity=channel_identity, now=self.wall)
            component["channel_certificate_sha256"] = checked.certificate_sha256
            component["channel_public_key_sha256"] = checked.public_key_sha256
            cert_path = self.protected / f"{component['component']}.pem"
            key_path = self.protected / f"{component['component']}.key"
            self._private(cert_path, cert_pem); self._private(key_path, key_pem)
            self.channel_paths[component["component"]] = (cert_path, key_path)
        group_payload = {"version": 1, "issued_at": int(self.wall),
            "expires_at": int(self.wall)+group_ttl, "scope": scope}
        signed_group = sign_c2_host_group_policy(group_payload, operator_key)
        group_path = self.protected / "group-policy.json"
        self._private(group_path, signed_group)
        host_cert_path, host_key_path = self.protected / "host.pem", self.protected / "host.key"
        self._private(host_cert_path, issued.certificate_pem)
        self._private(host_key_path, role_fx["new_key"])
        runtime_path = self.protected / "runtime.json"
        runtime = b'{"opaque":true}'
        self._private(runtime_path, runtime)
        header_path = self.protected / "header.json"
        header = {"schema_version": 1, "profile": "native_posix_root_c2_host_group_v1",
            "protected_root": str(self.protected), "selected_root": str(self.root),
            "account_id": host_before.account_id, "device_id": host_before.device_id,
            "role": "host", "boot_id": host_before.boot_id,
            "credential_epoch": host_before.credential_epoch,
            "admission_epoch": host_before.admission_epoch,
            "generation_sha256": host_before.generation_sha256,
            "launch_nonce": host_before.launch_nonce,
            "certificate_path": str(host_cert_path), "private_key_path": str(host_key_path),
            "model_id": scope["model_id"], "runtime_configuration_path": str(runtime_path),
            "runtime_configuration_sha256": hashlib.sha256(runtime).hexdigest(),
            "component_paths": {name: {"certificate_path": str(paths[0]),
                "private_key_path": str(paths[1])} for name, paths in sorted(self.channel_paths.items())},
            "group_policy_path": str(group_path),
            "group_policy_sha256": hashlib.sha256(signed_group).hexdigest()}
        header_bytes = canonical_json(header)
        self._private(header_path, header_bytes)
        host_doc["configuration_sha256"] = hashlib.sha256(header_bytes).hexdigest()
        manifest["new_host_group_scopes"] = [scope]
        new_specs = tuple(parse_role_launch_spec(x) for x in manifest["new_launch_specs"])
        manifest["new_launch_digest"] = canonical_role_launch_digest(new_specs)
        artifacts["new_launch_specs.json"] = canonical_json(manifest["new_launch_specs"])
        artifacts["activation_manifest.json"] = canonical_json(manifest)
        active_payload = json.loads(active)["payload"]
        # Extend only within the actual selected credential validity so the
        # channel deadline, rather than the test snapshot, is the limiting pin.
        credentials = {x["serial"]: x for x in active_payload["credentials"]}
        expiry = min(x["not_after"] for x in active_payload["credentials"])
        self.assertGreater(expiry, int(self.wall) + 131)
        active_payload["revision"] += 1
        active_payload["issued_at"] = int(self.wall)
        active_payload["expires_at"] = expiry
        for grant in active_payload["grants"]:
            grant["not_after"] = min(expiry,
                credentials[grant["actor_serial"]]["not_after"],
                credentials[grant["target_serial"]]["not_after"])
        active = sign_snapshot(active_payload, self.fx.new_snapshot_key)
        self.selector = RootGenerationSelector(host_before.generation_sha256,
            hashlib.sha256(artifacts["activation_manifest.json"]).hexdigest(),
            active_payload["revision"], canonical_policy_digest(active_payload),
            hashlib.sha256(active).hexdigest(),
            {name: hashlib.sha256(data).hexdigest() for name, data in artifacts.items()})
        self.active, self.artifacts = active, artifacts
        self.host_spec = parse_role_launch_spec(host_doc)
        self.header_path = header_path
        self.root.joinpath("generations").mkdir(mode=0o700)
        self.root.joinpath("policies").mkdir(mode=0o700)
        self._private(self.root / "transition.lock", b"")
        generation = self.root / "generations" / self.selector.generation_sha256
        generation.mkdir(mode=0o700)
        descriptor = {"schema_version": 1, "purpose": "root_generation_descriptor",
            "generation_sha256": self.selector.generation_sha256,
            "activation_manifest_sha256": self.selector.activation_manifest_sha256,
            "artifact_sha256": dict(self.selector.artifact_sha256)}
        for name, data in {"descriptor.json": canonical_json(descriptor), **artifacts}.items():
            self._private(generation / name, data)
        self._private(self.root / "policies" / f"{hashlib.sha256(active).hexdigest()}.json", active)
        self._private(self.root / "selector.json",
            canonical_json(root_generation_selector_document(self.selector)))

    def _load(self):
        store = RootGenerationStore(self.root, expected_uid=os.geteuid())
        binding = load_c2_host_runtime_binding(root_store=store, clock=self.clock,
            expected_launch_spec=self.host_spec, configuration_path=self.header_path,
            configuration_root=self.protected, expected_uid=os.geteuid(),
            operator_verification_key_pem=self.operator_public)
        return store, binding

    def test_real_binding_guards_three_components_and_durably_advances_policy(self):
        store, binding = self._load()
        self.addCleanup(store.close)
        other_store, other_binding = self._load()
        self.addCleanup(other_store.close)
        components = binding.components
        self.assertEqual(tuple(c.component for c in components),
                         ("worker-1", "worker-2", "worker-3"))
        self.assertEqual(tuple(c.identity.boot_id for c in components),
                         tuple(c["worker_boot_id"] for c in self.components))
        self.assertEqual(binding.host_identity.boot_id, self.host_spec.boot_id)
        binding.assert_live()
        payload = json.loads(self.active)["payload"]
        payload["revision"] += 1
        payload["issued_at"] = int(self.wall)
        updated = sign_snapshot(payload, self.fx.new_snapshot_key)
        revision, digest = binding.install_policy(updated)
        self.assertEqual((revision, digest), (payload["revision"], canonical_policy_digest(payload)))
        binding.assert_live()
        # A second binding that observed the same previous head reconciles only
        # the exact same canonical signed bytes after the compare-and-swap race.
        second_revision, second_digest = other_binding.install_policy(updated)
        self.assertEqual((second_revision, second_digest), (revision, digest))
        other_binding.assert_live()

    def test_protected_mutation_invalidates_binding_once(self):
        store, binding = self._load()
        self.addCleanup(store.close)
        calls = []
        binding.subscribe_teardown(calls.append)
        path = self.channel_paths["worker-1"][0]
        original = path.read_bytes()
        self._private(path, original + b"x")
        with self.assertRaises(CredentialError):
            binding.assert_live()
        self.assertEqual(len(calls), 1)
        self._private(path, original)
        with self.assertRaises(CredentialError):
            binding.assert_live()
        self.assertEqual(len(calls), 1)

    def test_original_group_policy_expiry_invalidates_and_cannot_revive(self):
        store, binding = self._load()
        self.addCleanup(store.close)
        calls = []
        binding.subscribe_teardown(calls.append)
        self.wall += 61
        self.mono += 61
        with self.assertRaisesRegex(CredentialError, "policy expired"):
            binding.assert_live()
        self.mono += 1
        with self.assertRaises(CredentialError):
            binding.assert_live()
        self.assertEqual(len(calls), 1)

    def test_channel_wall_expiry_rejects_clock_drift_even_before_monotonic_deadline(self):
        store, binding = self._load()
        self.addCleanup(store.close)
        calls = []
        binding.subscribe_teardown(calls.append)
        self.wall += 131
        self.mono += 110  # 21 seconds of drift is inside Clock's accepted tolerance.
        with self.assertRaisesRegex(CredentialError, "channel certificate expired"):
            binding.assert_live()
        self.assertEqual(len(calls), 1)

    def test_deadline_crossed_during_protected_read_invalidates(self):
        store, binding = self._load()
        self.addCleanup(store.close)
        calls = []
        binding.subscribe_teardown(calls.append)
        original_read = runtime_module.safe_read
        changed = False

        def delayed_read(*args, **kwargs):
            nonlocal changed
            if not changed:
                changed = True
                self.wall += 61
                self.mono += 61
            return original_read(*args, **kwargs)

        with patch.object(runtime_module, "safe_read", side_effect=delayed_read):
            with self.assertRaises(CredentialError):
                binding.assert_live()
        self.assertEqual(len(calls), 1)

    def test_deadline_crossed_while_local_policy_current_waits_invalidates(self):
        store, binding = self._load()
        self.addCleanup(store.close)
        calls = []
        binding.subscribe_teardown(calls.append)
        original_current = binding._snapshot_store.current

        def delayed_current(*args, **kwargs):
            view = original_current(*args, **kwargs)
            # Model a policy lock/durable-I/O wait after returning its view.
            self.wall += 61
            self.mono += 61
            return view

        with patch.object(binding._snapshot_store, "current", side_effect=delayed_current):
            with self.assertRaisesRegex(CredentialError, "policy expired"):
                binding.assert_live()
        self.assertEqual(len(calls), 1)

    def test_deadline_crossed_while_final_binding_lock_waits_invalidates(self):
        store, binding = self._load()
        self.addCleanup(store.close)
        calls = []
        binding.subscribe_teardown(calls.append)
        protected_done = threading.Event()
        continue_after_protected = threading.Event()
        final_lock_attempt = threading.Event()
        finished = threading.Event()
        failures = []
        underlying_lock = binding._lock

        class ObservedLock:
            def __init__(self):
                self.local = threading.local()

            def __enter__(self):
                count = getattr(self.local, "count", 0) + 1
                self.local.count = count
                if count == 2:
                    final_lock_attempt.set()
                underlying_lock.acquire()
                return self

            def __exit__(self, _type, _value, _traceback):
                underlying_lock.release()

        binding._lock = ObservedLock()
        original_protected_check = binding._check_protected_files
        protected_checks = 0

        def pause_after_second_protected_check():
            nonlocal protected_checks
            original_protected_check()
            protected_checks += 1
            if protected_checks == 2:
                protected_done.set()
                if not continue_after_protected.wait(5):
                    raise RuntimeError("test timed out at final protected-read barrier")

        binding._check_protected_files = pause_after_second_protected_check

        def check_live():
            try:
                binding.assert_live()
            except BaseException as exc:
                failures.append(exc)
            finally:
                finished.set()

        worker = threading.Thread(target=check_live)
        worker.start()
        self.assertTrue(protected_done.wait(5))
        underlying_lock.acquire()
        try:
            continue_after_protected.set()
            self.assertTrue(final_lock_attempt.wait(5))
            self.wall += 61
            self.mono += 61
        finally:
            continue_after_protected.set()
            underlying_lock.release()
        self.assertTrue(finished.wait(5))
        worker.join(timeout=2)
        self.assertEqual(len(failures), 1)
        self.assertIsInstance(failures[0], CredentialError)
        self.assertIn("policy expired", str(failures[0]))
        self.assertEqual(len(calls), 1)

    def test_second_selected_read_fault_is_sticky_after_fault_clears(self):
        store, binding = self._load()
        self.addCleanup(store.close)
        calls = []
        binding.subscribe_teardown(calls.append)
        original_read = runtime_module._selected
        count = 0

        def fail_second(*args, **kwargs):
            nonlocal count
            count += 1
            if count == 2:
                raise StorageError("injected second selected read fault")
            return original_read(*args, **kwargs)

        with patch.object(runtime_module, "_selected", side_effect=fail_second):
            with self.assertRaisesRegex(StorageError, "injected"):
                binding.assert_live()
        with self.assertRaises(CredentialError):
            binding.assert_live()
        self.assertEqual(len(calls), 1)

    def test_concurrent_invalidation_during_check_blocks_return(self):
        store, binding = self._load()
        self.addCleanup(store.close)
        calls = []
        binding.subscribe_teardown(calls.append)
        original_check = binding._assert_selected_policy

        def invalidate_after_policy(*args, **kwargs):
            result = original_check(*args, **kwargs)
            binding.invalidate("concurrent invalidation")
            return result

        with patch.object(binding, "_assert_selected_policy", side_effect=invalidate_after_policy):
            with self.assertRaisesRegex(CredentialError, "concurrent invalidation"):
                binding.assert_live()
        self.assertEqual(len(calls), 1)

    def test_final_uncertainty_deadline_is_retained_across_clock_drift(self):
        # Start thirty seconds after issue; then install a short explicit signed
        # snapshot expiry while leaving the selected role credential unchanged.
        self.wall += 30
        self.mono += 30
        store, binding = self._load()
        self.addCleanup(store.close)
        payload = json.loads(self.active)["payload"]
        payload["revision"] += 1
        # Keep the original valid issuance time. The widened uncertainty on
        # the final guard must cross expiry, not fail a not-before check.
        payload["expires_at"] = int(self.wall) + 40
        short_head = sign_snapshot(payload, self.fx.new_snapshot_key)
        binding.install_policy(short_head)
        calls = []
        binding.subscribe_teardown(calls.append)
        original_read = runtime_module.safe_read
        reads = 0
        def widen_on_final_read(*args, **kwargs):
            nonlocal reads
            result = original_read(*args, **kwargs)
            reads += 1
            if reads == 22:
                self.uncertainty = 20.0
            return result
        with patch.object(runtime_module, "safe_read", side_effect=widen_on_final_read):
            binding.assert_live()
        self.assertEqual(reads, 22)
        # Restore clock uncertainty and advance monotonic time past the retained
        # floor while wall time remains 20 seconds behind that advancement.
        self.uncertainty = 0.0
        self.wall += 1
        self.mono += 21
        with self.assertRaisesRegex(SnapshotError, "expired"):
            binding.assert_live()
        self.assertEqual(len(calls), 1)

    def test_initial_uncertainty_retains_group_policy_deadline(self):
        self.wall += 30
        self.mono += 30
        store, binding = self._load()
        self.addCleanup(store.close)
        calls = []
        binding.subscribe_teardown(calls.append)
        self.uncertainty = 20.0
        original_check = binding._check_deadlines
        checks = 0
        def restore_after_initial_sample(sample):
            nonlocal checks
            result = original_check(sample)
            checks += 1
            if checks == 1:
                self.assertEqual(sample.uncertainty, 20.0)
                self.uncertainty = 0.0
            return result
        with patch.object(binding, "_check_deadlines", side_effect=restore_after_initial_sample):
            binding.assert_live()
        self.assertEqual(checks, 3)
        self.uncertainty = 0.0
        self.wall += 1
        self.mono += 21
        with self.assertRaisesRegex(CredentialError, "group policy expired"):
            binding.assert_live()
        self.assertEqual(len(calls), 1)

    def test_final_uncertainty_retains_group_policy_deadline(self):
        self.wall += 30
        self.mono += 30
        store, binding = self._load()
        self.addCleanup(store.close)
        calls = []
        binding.subscribe_teardown(calls.append)
        original_read = runtime_module.safe_read
        reads = 0
        def widen_on_final_read(*args, **kwargs):
            nonlocal reads
            result = original_read(*args, **kwargs)
            reads += 1
            if reads == 22:
                self.uncertainty = 20.0
            return result
        with patch.object(runtime_module, "safe_read", side_effect=widen_on_final_read):
            binding.assert_live()
        self.assertEqual(reads, 22)
        self.uncertainty = 0.0
        self.wall += 1
        self.mono += 21
        with self.assertRaisesRegex(CredentialError, "group policy expired"):
            binding.assert_live()
        self.assertEqual(len(calls), 1)

    def test_initial_uncertainty_retains_channel_monotonic_deadline(self):
        self.wall += 30
        self.mono += 30
        store, binding = self._load()
        self.addCleanup(store.close)
        calls = []
        binding.subscribe_teardown(calls.append)
        self.uncertainty = 20.0
        original_check = binding._check_deadlines
        checks = 0
        def restore_after_initial_sample(sample):
            nonlocal checks
            result = original_check(sample)
            checks += 1
            if checks == 1:
                self.assertEqual(sample.uncertainty, 20.0)
                self.uncertainty = 0.0
            return result
        with patch.object(binding, "_check_deadlines", side_effect=restore_after_initial_sample):
            binding.assert_live()
        self.assertEqual(checks, 3)
        self.wall += 51
        self.mono += 71
        with self.assertRaisesRegex(CredentialError, "channel certificate expired"):
            binding.assert_live()
        self.assertEqual(len(calls), 1)

    def test_final_uncertainty_retains_channel_monotonic_deadline(self):
        self.wall += 30
        self.mono += 30
        store, binding = self._load()
        self.addCleanup(store.close)
        calls = []
        binding.subscribe_teardown(calls.append)
        original_read = runtime_module.safe_read
        reads = 0
        def widen_on_final_read(*args, **kwargs):
            nonlocal reads
            result = original_read(*args, **kwargs)
            reads += 1
            if reads == 22:
                self.uncertainty = 20.0
            return result
        with patch.object(runtime_module, "safe_read", side_effect=widen_on_final_read):
            binding.assert_live()
        self.assertEqual(reads, 22)
        self.uncertainty = 0.0
        self.wall += 51
        self.mono += 71
        with self.assertRaisesRegex(CredentialError, "channel certificate expired"):
            binding.assert_live()
        self.assertEqual(len(calls), 1)

    def test_first_selected_view_uncertainty_deadline_is_retained(self):
        self.wall += 30
        self.mono += 30
        store, binding = self._load()
        self.addCleanup(store.close)
        payload = json.loads(self.active)["payload"]
        payload["revision"] += 1
        payload["expires_at"] = int(self.wall) + 40
        short_head = sign_snapshot(payload, self.fx.new_snapshot_key)
        binding.install_policy(short_head)
        calls = []
        binding.subscribe_teardown(calls.append)
        original = binding._assert_selected_policy
        selected_reads = 0
        def uncertain_first(*args, **kwargs):
            nonlocal selected_reads
            selected_reads += 1
            if selected_reads == 1:
                self.uncertainty = 20.0
            try:
                return original(*args, **kwargs)
            finally:
                self.uncertainty = 0.0
        with patch.object(binding, "_assert_selected_policy", side_effect=uncertain_first):
            binding.assert_live()
        self.assertEqual(selected_reads, 2)
        self.wall += 1
        self.mono += 21
        with self.assertRaisesRegex(SnapshotError, "expired"):
            binding.assert_live()
        self.assertEqual(len(calls), 1)

    def test_selected_head_mismatch_retains_deadline_before_refresh(self):
        self.wall += 30
        self.mono += 30
        root_store, binding = self._load()
        self.addCleanup(root_store.close)
        original_payload = json.loads(self.active)["payload"]
        payload_a = dict(original_payload)
        payload_a["revision"] += 1
        payload_a["expires_at"] = int(self.wall) + 40
        encoded_a = sign_snapshot(payload_a, self.fx.new_snapshot_key)
        binding.install_policy(encoded_a)
        binding.assert_live()  # retain A's wider, uncertainty-zero floor
        payload_b = dict(payload_a)
        payload_b["revision"] += 1
        encoded_b = sign_snapshot(payload_b, self.fx.new_snapshot_key)
        old_head = hashlib.sha256((self.root / "selector.json").read_bytes()).hexdigest()
        root_store.advance_policy(encoded_b, expected_old_selector_sha256=old_head,
                                  clock=self.clock, validate=lambda *_: None)
        calls = []
        binding.subscribe_teardown(calls.append)
        original_read = runtime_module.safe_read
        reads = 0
        def widen_on_final_read(*args, **kwargs):
            nonlocal reads
            result = original_read(*args, **kwargs)
            reads += 1
            if reads == 22:
                self.uncertainty = 20.0
            return result
        with patch.object(runtime_module, "safe_read", side_effect=widen_on_final_read):
            with self.assertRaises(_C2PolicyRefreshRequired):
                binding.assert_live()
        self.assertEqual(reads, 22)
        self.assertFalse(binding._invalid)
        self.assertEqual(calls, [])
        self.uncertainty = 0.0
        self.wall += 1
        self.mono += 21
        install_calls = []
        original_install = binding._snapshot_store.install
        def counted_install(*args, **kwargs):
            install_calls.append(True)
            return original_install(*args, **kwargs)
        with patch.object(binding._snapshot_store, "install", side_effect=counted_install):
            with self.assertRaisesRegex(SnapshotError, "expired"):
                binding.install_policy(encoded_b)
        self.assertEqual(install_calls, [])
        self.assertEqual(binding._snapshot_store.current().revision, payload_a["revision"])
        self.assertEqual(len(calls), 1)

    def test_new_selected_expiry_renews_after_local_snapshot_expiry(self):
        root_store, binding = self._load()
        self.addCleanup(root_store.close)
        credentials = {item["serial"]: item for item in json.loads(self.active)["payload"]["credentials"]}
        payload_a = json.loads(self.active)["payload"]
        payload_a["revision"] += 1
        payload_a["expires_at"] = int(self.wall) + 5
        for grant in payload_a["grants"]:
            grant["not_after"] = min(payload_a["expires_at"],
                credentials[grant["actor_serial"]]["not_after"],
                credentials[grant["target_serial"]]["not_after"])
        encoded_a = sign_snapshot(payload_a, self.fx.new_snapshot_key)
        binding.install_policy(encoded_a)
        binding.assert_live()
        payload_b = dict(payload_a)
        payload_b["revision"] += 1
        payload_b["expires_at"] = int(self.wall) + 60
        payload_b["grants"] = [dict(grant) for grant in payload_a["grants"]]
        for grant in payload_b["grants"]:
            grant["not_after"] = min(payload_b["expires_at"],
                credentials[grant["actor_serial"]]["not_after"],
                credentials[grant["target_serial"]]["not_after"])
        encoded_b = sign_snapshot(payload_b, self.fx.new_snapshot_key)
        old_head = hashlib.sha256((self.root / "selector.json").read_bytes()).hexdigest()
        root_store.advance_policy(encoded_b, expected_old_selector_sha256=old_head,
                                  clock=self.clock, validate=lambda *_: None)
        self.wall += 6
        self.mono += 6
        self.assertEqual(binding.install_policy(encoded_b),
                         (payload_b["revision"], canonical_policy_digest(payload_b)))
        self.assertEqual(binding._snapshot_store.current().revision, payload_b["revision"])
        binding.assert_live()

    def test_teardown_notification_must_be_synchronous(self):
        store, binding = self._load()
        self.addCleanup(store.close)

        async def notification(_reason):
            return None

        with self.assertRaisesRegex(TypeError, "synchronous"):
            binding.subscribe_teardown(notification)

    def test_awaitable_notification_result_is_closed_and_faulted(self):
        store, binding = self._load()
        self.addCleanup(store.close)

        async def work():
            return None

        def bad_notification(_reason):
            return work()

        binding.invalidate("test invalidation")
        binding.subscribe_teardown(bad_notification)
        self.assertTrue(binding._notification_faulted)

    def test_c1_singular_loader_rejects_c2_profile(self):
        store = RootGenerationStore(self.root, expected_uid=os.geteuid())
        self.addCleanup(store.close)
        with self.assertRaisesRegex(CredentialError, "unknown or missing fields"):
            load_root_runtime_binding(root_store=store, clock=self.clock,
                expected_launch_spec=self.host_spec, configuration_path=self.header_path,
                configuration_root=self.protected, expected_uid=os.geteuid())


if __name__ == "__main__":
    unittest.main()
