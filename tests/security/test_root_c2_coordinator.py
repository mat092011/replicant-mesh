"""Focused portable contract checks for the C2 coordinator profile."""
import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from steamboat_security.errors import CredentialError, SnapshotError
from steamboat_security.root_c2_coordinator import (
    C2CoordinatorRuntimeBinding, _FIELDS, _read_header,
    load_c2_personal_coordinator_binding,
)
from steamboat_security.root_transition_launch import (
    canonical_role_launch_digest, parse_role_launch_spec, role_launch_document,
)
from steamboat_security.root_transition_storage import (
    RootGenerationSelector, RootGenerationStore, root_generation_selector_document,
)
from steamboat_security.snapshot import canonical_policy_digest, sign_snapshot
from steamboat_security.codec import canonical_json
import tests.security.test_root_c2_runtime as runtime_fixture


@unittest.skipUnless(os.name == "posix", "RootGenerationStore integration requires POSIX")
class C2CoordinatorStoreIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        runtime_fixture.C2RuntimeStoreIntegrationTests.setUpClass()

    def setUp(self):
        self.fx = object.__new__(runtime_fixture.C2RuntimeStoreIntegrationTests)
        # The inherited fixture selects one of its clock-lifetime profiles by
        # test method name during setup; provide the valid long-lived case.
        self.fx._testMethodName = "test_channel_wall_expiry_rejects_clock_drift_even_before_monotonic_deadline"
        self.fx.setUp()
        self._add_coordinator_header()

    def tearDown(self):
        self.fx.tearDown()

    def _add_coordinator_header(self):
        fx = self.fx
        manifest = json.loads(fx.artifacts["activation_manifest.json"])
        coordinator_doc = next(x for x in manifest["new_launch_specs"]
                              if x["role"] == "personal_coordinator")
        coordinator = parse_role_launch_spec(coordinator_doc)
        issued = next(x for x in fx.fixture.candidate.issuance_candidate.principals
                      if x.identity == coordinator.identity)
        role_fx = next(x for x in fx.fx.roles if x["principal"].identity == coordinator.identity)
        runtime_path = fx.protected / "coordinator-runtime.json"
        runtime_bytes = b'{"opaque_coordinator_adapter":true}'
        fx._private(runtime_path, runtime_bytes)
        cert_path, key_path = fx.protected / "coordinator.pem", fx.protected / "coordinator.key"
        fx._private(cert_path, issued.certificate_pem)
        fx._private(key_path, role_fx["new_key"])
        model_id = json.loads(fx.active)["payload"]["grants"][0]["model_id"]
        header = {
            "schema_version": 1,
            "profile": "native_posix_root_c2_personal_coordinator_v1",
            "protected_root": str(fx.protected), "selected_root": str(fx.root),
            "account_id": coordinator.account_id, "device_id": coordinator.device_id,
            "role": coordinator.role, "boot_id": coordinator.boot_id,
            "credential_epoch": coordinator.credential_epoch,
            "admission_epoch": coordinator.admission_epoch,
            "generation_sha256": coordinator.generation_sha256,
            "launch_nonce": coordinator.launch_nonce,
            "certificate_path": str(cert_path), "private_key_path": str(key_path),
            "model_id": model_id, "runtime_configuration_path": str(runtime_path),
            "runtime_configuration_sha256": hashlib.sha256(runtime_bytes).hexdigest(),
        }
        header_bytes = canonical_json(header)
        header_path = fx.protected / "coordinator-header.json"
        fx._private(header_path, header_bytes)
        coordinator_doc["configuration_sha256"] = hashlib.sha256(header_bytes).hexdigest()
        specs = tuple(parse_role_launch_spec(x) for x in manifest["new_launch_specs"])
        manifest["new_launch_digest"] = canonical_role_launch_digest(specs)
        fx.artifacts["new_launch_specs.json"] = canonical_json(manifest["new_launch_specs"])
        fx.artifacts["activation_manifest.json"] = canonical_json(manifest)
        old = fx.selector
        selector = RootGenerationSelector(old.generation_sha256,
            hashlib.sha256(fx.artifacts["activation_manifest.json"]).hexdigest(),
            old.policy_revision, old.policy_digest, old.active_policy_snapshot_sha256,
            {name: hashlib.sha256(data).hexdigest() for name, data in fx.artifacts.items()})
        generation = fx.root / "generations" / selector.generation_sha256
        descriptor_path = generation / "descriptor.json"
        descriptor = {"schema_version": 1, "purpose": "root_generation_descriptor",
            "generation_sha256": selector.generation_sha256,
            "activation_manifest_sha256": selector.activation_manifest_sha256,
            "artifact_sha256": dict(selector.artifact_sha256)}
        fx._private(descriptor_path, canonical_json(descriptor))
        for name, data in fx.artifacts.items():
            fx._private(generation / name, data)
        fx._private(fx.root / "selector.json", canonical_json(root_generation_selector_document(selector)))
        fx.selector = selector
        fx.coordinator_spec = parse_role_launch_spec(coordinator_doc)
        fx.coordinator_header_path = header_path

    def _load(self):
        store = RootGenerationStore(self.fx.root, expected_uid=os.geteuid())
        try:
            binding = load_c2_personal_coordinator_binding(root_store=store, clock=self.fx.clock,
                expected_launch_spec=self.fx.coordinator_spec,
                configuration_path=self.fx.coordinator_header_path,
                configuration_root=self.fx.protected, expected_uid=os.geteuid())
        except BaseException:
            store.close()
            raise
        return store, binding

    def test_real_selected_coordinator_guard_and_same_head_cas_reconcile(self):
        store, binding = self._load()
        self.addCleanup(store.close)
        other_store, other = self._load()
        self.addCleanup(other_store.close)
        self.assertEqual(binding.local_identity.boot_id, self.fx.coordinator_spec.boot_id)
        self.assertEqual(binding.local_identity.model_id, json.loads(self.fx.active)["payload"]["grants"][0]["model_id"])
        binding.assert_live()
        payload = json.loads(self.fx.active)["payload"]
        payload["revision"] += 1
        payload["issued_at"] = int(self.fx.wall)
        encoded = sign_snapshot(payload, self.fx.fx.new_snapshot_key)
        first = binding.install_policy(encoded)
        self.assertEqual(first, (payload["revision"], canonical_policy_digest(payload)))
        second = other.install_policy(encoded)
        self.assertEqual(second, first)
        other.assert_live()

    def test_config_mutation_invalidates_and_notifies_once(self):
        store, binding = self._load()
        self.addCleanup(store.close)
        events = []
        binding.subscribe_teardown(events.append)
        original = self.fx.coordinator_header_path.read_bytes()
        self.fx._private(self.fx.coordinator_header_path, original + b" ")
        with self.assertRaises(CredentialError):
            binding.assert_live()
        self.fx._private(self.fx.coordinator_header_path, original)
        with self.assertRaises(CredentialError):
            binding.assert_live()
        self.assertEqual(len(events), 1)

    def test_selected_role_key_mutation_invalidates(self):
        store, binding = self._load()
        self.addCleanup(store.close)
        events = []
        binding.subscribe_teardown(events.append)
        key_path = self.fx.coordinator_header_path.parent / "coordinator.key"
        original = key_path.read_bytes()
        self.fx._private(key_path, original + b"\n")
        with self.assertRaises(CredentialError):
            binding.assert_live()
        self.assertEqual(len(events), 1)

    def test_concurrent_invalidation_blocks_guard_return(self):
        store, binding = self._load()
        self.addCleanup(store.close)
        events = []
        binding.subscribe_teardown(events.append)
        original = binding._selected_policy
        def invalidate_during_guard(*args, **kwargs):
            result = original(*args, **kwargs)
            binding.invalidate("concurrent invalidation")
            return result
        with patch.object(binding, "_selected_policy", side_effect=invalidate_during_guard):
            with self.assertRaisesRegex(CredentialError, "concurrent invalidation"):
                binding.assert_live()
        self.assertEqual(len(events), 1)

    def test_final_uncertainty_deadline_is_retained_across_clock_drift(self):
        self.fx.wall += 30
        self.fx.mono += 30
        store, binding = self._load()
        self.addCleanup(store.close)
        payload = json.loads(self.fx.active)["payload"]
        payload["revision"] += 1
        payload["issued_at"] = int(self.fx.wall)
        payload["expires_at"] = int(self.fx.wall) + 40
        short_head = sign_snapshot(payload, self.fx.fx.new_snapshot_key)
        binding.install_policy(short_head)
        events = []
        binding.subscribe_teardown(events.append)

        uncertainty = [0.0]
        self.fx.clock._uncertainty = lambda: uncertainty[0]
        uncertainty[0] = 20.0
        binding.assert_live()
        uncertainty[0] = 0.0
        self.fx.wall += 1
        self.fx.mono += 21
        with self.assertRaisesRegex(SnapshotError, "expired"):
            binding.assert_live()
        self.assertEqual(len(events), 1)

    def test_expiry_during_final_protected_io_invalidates(self):
        store, binding = self._load()
        self.addCleanup(store.close)
        events = []
        binding.subscribe_teardown(events.append)
        original = __import__("steamboat_security.root_c2_coordinator", fromlist=["safe_read"]).safe_read
        calls = 0
        def delayed(*args, **kwargs):
            nonlocal calls
            calls += 1
            if calls == 8:  # final protected-file read, immediately before final clock sample
                delta = int(json.loads(self.fx.active)["payload"]["expires_at"] - self.fx.wall + 1)
                self.fx.wall += delta
                self.fx.mono += delta
            return original(*args, **kwargs)
        with patch("steamboat_security.root_c2_coordinator.safe_read", side_effect=delayed):
            with self.assertRaisesRegex(SnapshotError, "expired"):
                binding.assert_live()
        self.assertEqual(calls, 8)
        self.assertEqual(len(events), 1)


class C2CoordinatorHeaderTests(unittest.TestCase):
    def _header(self):
        return {
            "schema_version": 1,
            "profile": "native_posix_root_c2_personal_coordinator_v1",
            "protected_root": "/protected", "selected_root": "/selected",
            "account_id": "acct_" + "1" * 32,
            "device_id": "dev_" + "2" * 32,
            "role": "personal_coordinator", "boot_id": "boot_" + "3" * 32,
            "credential_epoch": 1, "admission_epoch": 1,
            "generation_sha256": "4" * 64, "launch_nonce": "5" * 32,
            "certificate_path": "/protected/role.pem",
            "private_key_path": "/protected/role.key",
            "model_id": "7" * 64,
            "runtime_configuration_path": "/protected/runtime.bin",
            "runtime_configuration_sha256": "6" * 64,
        }

    def test_accepts_only_closed_coordinator_profile(self):
        header = self._header()
        encoded = canonical_json(header)
        with patch("steamboat_security.root_c2_coordinator.safe_read", return_value=encoded):
            raw, parsed = _read_header("/protected/header.json", "/protected", 1)
        self.assertEqual(raw, encoded)
        self.assertEqual(set(parsed), _FIELDS)

    def test_rejects_host_header_and_extra_command_fields(self):
        for change in (
            {"profile": "native_posix_root_c2_host_group_v1"},
            {"role": "host"}, {"peer_command": ["sh", "-c", "true"]},
        ):
            header = self._header() | change
            with patch("steamboat_security.root_c2_coordinator.safe_read",
                       return_value=canonical_json(header)):
                with self.assertRaises(CredentialError):
                    _read_header("/protected/header.json", "/protected", 1)

    def test_invalidation_notifies_once_and_outside_lock(self):
        binding = object.__new__(C2CoordinatorRuntimeBinding)
        import threading
        binding._lock = threading.RLock()
        binding._invalid = False
        binding._reason = None
        binding._subscribers = []
        binding._notification_faulted = False
        binding._notify = C2CoordinatorRuntimeBinding._notify.__get__(binding)
        calls = []
        binding._subscribers.append(lambda reason: calls.append(reason))
        binding.invalidate("test")
        binding.invalidate("again")
        self.assertEqual(calls, ["test"])
        self.assertTrue(binding._invalid)

    def test_awaitable_teardown_is_rejected(self):
        binding = object.__new__(C2CoordinatorRuntimeBinding)
        import threading
        binding._lock = threading.RLock()
        binding._invalid = False
        binding._subscribers = []
        async def callback(_reason):
            return None
        with self.assertRaisesRegex(TypeError, "synchronous"):
            binding.subscribe_teardown(callback)


if __name__ == "__main__":
    unittest.main()
