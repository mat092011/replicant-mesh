"""Focused portable contract checks for the C2 consumer profile."""
import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from steamboat_security.certificates import (ROLE_EKUS, certificate_sha256,
    generate_private_key_pem, issue_leaf, make_csr, public_key_sha256)
from steamboat_security.errors import CredentialError, SnapshotError
from steamboat_security.operator import _record_from_leaf
from steamboat_security.root_c2_consumer import (
    C2ConsumerRuntimeBinding, _FIELDS, _PolicyRefreshRequired, _read_header,
    load_c2_consumer_binding,
)
from steamboat_security.root_transition_launch import (
    RoleLaunchSpec, canonical_role_launch_digest, parse_role_launch_spec,
    role_launch_document,
)
from steamboat_security.root_transition_storage import (
    RootGenerationSelector, RootGenerationStore, root_generation_selector_document,
)
from steamboat_security.snapshot import canonical_policy_digest, sign_snapshot
from steamboat_security.codec import canonical_json
import tests.security.test_root_c2_runtime as runtime_fixture


@unittest.skipUnless(os.name == "posix", "RootGenerationStore integration requires POSIX")
class C2ConsumerStoreIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        runtime_fixture.C2RuntimeStoreIntegrationTests.setUpClass()

    def setUp(self):
        self.fx = object.__new__(runtime_fixture.C2RuntimeStoreIntegrationTests)
        # The inherited fixture selects one of its clock-lifetime profiles by
        # test method name during setup; provide the valid long-lived case.
        self.fx._testMethodName = "test_channel_wall_expiry_rejects_clock_drift_even_before_monotonic_deadline"
        self.fx.setUp()
        self._add_consumer_header()

    def tearDown(self):
        self.fx.tearDown()

    def _add_consumer_header(self):
        fx = self.fx
        manifest = json.loads(fx.artifacts["activation_manifest.json"])
        # The common selected-root fixture intentionally contains only host
        # and coordinator roles. Add a consumer as a genuine C1 CA-issued
        # principal, then regenerate the signed C2 selection and root store.
        original_new = [parse_role_launch_spec(x) for x in manifest["new_launch_specs"]]
        original_old = [parse_role_launch_spec(x) for x in manifest["old_launch_specs"]]
        host = next(item for item in original_new if item.role == "host")
        coordinator = next(item for item in original_new if item.role == "personal_coordinator")
        device = "dev_" + f"{0xF2000000000000000000000000000001:032x}"
        old_key, new_key = generate_private_key_pem(), generate_private_key_pem()
        old_csr = make_csr(old_key, account_id=coordinator.account_id,
                           device_id=device, role="consumer")
        new_csr = make_csr(new_key, account_id=coordinator.account_id,
                           device_id=device, role="consumer")
        now = int(fx.wall)
        old_cert = issue_leaf(fx.fx.old_ca, fx.fx.old_ca_key, old_csr,
            account_id=coordinator.account_id, device_id=device, role="consumer",
            not_before=now - 500, not_after=now + 240, serial=0xA113,
            ekus=tuple(sorted(ROLE_EKUS["consumer"])))
        new_cert = issue_leaf(fx.fx.new_ca, fx.fx.new_ca_key, new_csr,
            account_id=coordinator.account_id, device_id=device, role="consumer",
            not_before=now - 500, not_after=now + 240, serial=0xA114,
            ekus=tuple(sorted(ROLE_EKUS["consumer"])))
        old_record = _record_from_leaf(old_cert, account_id=coordinator.account_id,
            device_id=device, role="consumer", credential_epoch=4)
        consumer_record = _record_from_leaf(new_cert, account_id=coordinator.account_id,
            device_id=device, role="consumer", credential_epoch=5)
        consumer_boot = f"{0xF3000000000000000000000000000001:032x}"
        old_boot = f"{0xF3000000000000000000000000000002:032x}"
        old_consumer = RoleLaunchSpec(original_old[0].generation_sha256,
            coordinator.account_id, device, "consumer", old_record["serial"],
            old_record["certificate_sha256"], old_record["public_key_sha256"],
            4, old_boot, 7, "0" * 64, f"{0xA113:032x}")
        # Header does not contain its own hash, so the selected configuration
        # pin can be computed after its protected bytes are finalized below.
        consumer = RoleLaunchSpec(fx.selector.generation_sha256,
            coordinator.account_id, device, "consumer", consumer_record["serial"],
            consumer_record["certificate_sha256"], consumer_record["public_key_sha256"],
            5, consumer_boot, 8, "0" * 64, f"{0xA114:032x}")
        runtime_path = fx.protected / "consumer-runtime.json"
        runtime_bytes = b'{"opaque_consumer_adapter":true}'
        fx._private(runtime_path, runtime_bytes)
        cert_path, key_path = fx.protected / "consumer.pem", fx.protected / "consumer.key"
        fx._private(cert_path, new_cert)
        fx._private(key_path, new_key)
        model_id = json.loads(fx.active)["payload"]["grants"][0]["model_id"]
        header = {
            "schema_version": 1,
            "profile": "native_posix_root_c2_consumer_v1",
            "protected_root": str(fx.protected), "selected_root": str(fx.root),
            "account_id": consumer.account_id, "device_id": consumer.device_id,
            "role": consumer.role, "boot_id": consumer.boot_id,
            "credential_epoch": consumer.credential_epoch,
            "admission_epoch": consumer.admission_epoch,
            "generation_sha256": consumer.generation_sha256,
            "launch_nonce": consumer.launch_nonce,
            "certificate_path": str(cert_path), "private_key_path": str(key_path),
            "model_id": model_id, "runtime_configuration_path": str(runtime_path),
            "runtime_configuration_sha256": hashlib.sha256(runtime_bytes).hexdigest(),
        }
        header_bytes = canonical_json(header)
        header_path = fx.protected / "consumer-header.json"
        fx._private(header_path, header_bytes)
        consumer = RoleLaunchSpec(consumer.generation_sha256, consumer.account_id,
            consumer.device_id, consumer.role, consumer.serial,
            consumer.certificate_sha256, consumer.public_key_sha256,
            consumer.credential_epoch, consumer.boot_id, consumer.admission_epoch,
            hashlib.sha256(header_bytes).hexdigest(), consumer.launch_nonce)
        consumer_doc = role_launch_document(consumer)
        new_specs = tuple(sorted((*original_new, consumer), key=lambda item: item.identity))
        old_specs = tuple(sorted((*original_old, old_consumer), key=lambda item: item.identity))
        manifest["old_launch_specs"] = [role_launch_document(item) for item in old_specs]
        manifest["new_launch_specs"] = [role_launch_document(item) for item in new_specs]
        manifest["old_launch_digest"] = canonical_role_launch_digest(old_specs)
        manifest["new_launch_digest"] = canonical_role_launch_digest(new_specs)
        manifest["new_certificates"].append({"identity": list(consumer.identity),
            "serial": consumer.serial, "certificate_sha256": consumer.certificate_sha256,
            "public_key_sha256": consumer.public_key_sha256})
        manifest["new_certificates"].sort(key=lambda item: tuple(item["identity"]))

        def consumer_grant(payload):
            grants = payload["grants"]
            if any(g["actor_serial"] == consumer.serial for g in grants):
                return
            coordinator_record = next(x for x in payload["credentials"]
                                      if x["serial"] == coordinator.serial)
            grants.append({"account_id": consumer.account_id,
                "device_id": consumer.device_id, "role": "consumer",
                "actor_serial": consumer.serial,
                "actor_public_key_sha256": consumer.public_key_sha256,
                "actor_credential_epoch": consumer.credential_epoch,
                "tenant_account_id": consumer.account_id,
                "target_account_id": coordinator.account_id,
                "target_device_id": coordinator.device_id,
                "target_role": "personal_coordinator",
                "target_serial": coordinator.serial,
                "target_public_key_sha256": coordinator.public_key_sha256,
                "target_credential_epoch": coordinator.credential_epoch,
                "target_boot_id": coordinator.boot_id, "actor_boot_id": None,
                "assignment_id": None, "model_id": model_id,
                "method": "steamboat.v1.Coordinator/Generate",
                "not_before": now - 10, "not_after": now + 100})

        baseline = json.loads(fx.artifacts["policy_snapshot.json"])["payload"]
        baseline["credentials"].append(consumer_record)
        consumer_grant(baseline)
        baseline_bytes = sign_snapshot(baseline, fx.fx.new_snapshot_key)
        fx.artifacts["policy_snapshot.json"] = baseline_bytes
        manifest["policy_revision"] = baseline["revision"]
        manifest["policy_digest"] = canonical_policy_digest(baseline)
        manifest["policy_payload_sha256"] = hashlib.sha256(canonical_json(baseline)).hexdigest()
        active_payload = json.loads(fx.active)["payload"]
        active_payload["credentials"].append(consumer_record)
        consumer_grant(active_payload)
        fx.active = sign_snapshot(active_payload, fx.fx.new_snapshot_key)
        fx.artifacts["old_launch_specs.json"] = canonical_json(manifest["old_launch_specs"])
        fx.artifacts["new_launch_specs.json"] = canonical_json(manifest["new_launch_specs"])
        fx.artifacts["activation_manifest.json"] = canonical_json(manifest)
        old_selector = fx.selector
        selector = RootGenerationSelector(old_selector.generation_sha256,
            hashlib.sha256(fx.artifacts["activation_manifest.json"]).hexdigest(),
            active_payload["revision"], canonical_policy_digest(active_payload),
            hashlib.sha256(fx.active).hexdigest(),
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
        fx._private(fx.root / "policies" / f"{hashlib.sha256(fx.active).hexdigest()}.json", fx.active)
        fx._private(fx.root / "selector.json", canonical_json(root_generation_selector_document(selector)))
        fx.selector = selector
        fx.consumer_spec = parse_role_launch_spec(consumer_doc)
        fx.consumer_header_path = header_path

    def _load(self):
        store = RootGenerationStore(self.fx.root, expected_uid=os.geteuid())
        try:
            binding = load_c2_consumer_binding(root_store=store, clock=self.fx.clock,
                expected_launch_spec=self.fx.consumer_spec,
                configuration_path=self.fx.consumer_header_path,
                configuration_root=self.fx.protected, expected_uid=os.geteuid())
        except BaseException:
            store.close()
            raise
        return store, binding

    def test_real_selected_consumer_guard_and_same_head_cas_reconcile(self):
        store, binding = self._load()
        self.addCleanup(store.close)
        other_store, other = self._load()
        self.addCleanup(other_store.close)
        self.assertEqual(binding.local_identity.boot_id, self.fx.consumer_spec.boot_id)
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
        original = self.fx.consumer_header_path.read_bytes()
        self.fx._private(self.fx.consumer_header_path, original + b" ")
        with self.assertRaises(CredentialError):
            binding.assert_live()
        self.fx._private(self.fx.consumer_header_path, original)
        with self.assertRaises(CredentialError):
            binding.assert_live()
        self.assertEqual(len(events), 1)

    def test_selected_role_key_mutation_invalidates(self):
        store, binding = self._load()
        self.addCleanup(store.close)
        events = []
        binding.subscribe_teardown(events.append)
        key_path = self.fx.consumer_header_path.parent / "consumer.key"
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
        # Preserve the original valid issuance time so this tests the expiry
        # floor and the first widened-uncertainty guard remains admissible.
        payload["expires_at"] = int(self.fx.wall) + 40
        short_head = sign_snapshot(payload, self.fx.fx.new_snapshot_key)
        binding.install_policy(short_head)
        events = []
        binding.subscribe_teardown(events.append)

        uncertainty = [0.0]
        self.fx.clock._uncertainty = lambda: uncertainty[0]
        import steamboat_security.root_c2_consumer as consumer_module
        original_read = consumer_module.safe_read
        reads = 0
        def widen_after_final_read(*args, **kwargs):
            nonlocal reads
            result = original_read(*args, **kwargs)
            reads += 1
            if reads == 8:
                uncertainty[0] = 20.0
            return result
        with patch.object(consumer_module, "safe_read", side_effect=widen_after_final_read):
            binding.assert_live()
        self.assertEqual(reads, 8)
        uncertainty[0] = 0.0
        self.fx.wall += 1
        self.fx.mono += 21
        with self.assertRaisesRegex(SnapshotError, "expired"):
            binding.assert_live()
        self.assertEqual(len(events), 1)

    def test_head_mismatch_retains_deadline_before_policy_refresh(self):
        self.fx.wall += 30
        self.fx.mono += 30
        root_store, binding = self._load()
        self.addCleanup(root_store.close)
        payload_a = json.loads(self.fx.active)["payload"]
        payload_a["revision"] += 1
        payload_a["expires_at"] = int(self.fx.wall) + 40
        encoded_a = sign_snapshot(payload_a, self.fx.fx.new_snapshot_key)
        binding.install_policy(encoded_a)
        binding.assert_live()
        payload_b = dict(payload_a)
        payload_b["revision"] += 1
        encoded_b = sign_snapshot(payload_b, self.fx.fx.new_snapshot_key)
        old_head = hashlib.sha256((self.fx.root / "selector.json").read_bytes()).hexdigest()
        root_store.advance_policy(encoded_b, expected_old_selector_sha256=old_head,
                                  clock=self.fx.clock, validate=lambda *_: None)
        events = []
        binding.subscribe_teardown(events.append)
        uncertainty = [0.0]
        self.fx.clock._uncertainty = lambda: uncertainty[0]
        import steamboat_security.root_c2_consumer as consumer_module
        original_read = consumer_module.safe_read
        reads = 0
        def widen_after_final_read(*args, **kwargs):
            nonlocal reads
            result = original_read(*args, **kwargs)
            reads += 1
            if reads == 8:
                uncertainty[0] = 20.0
            return result
        with patch.object(consumer_module, "safe_read", side_effect=widen_after_final_read):
            with self.assertRaises(_PolicyRefreshRequired):
                binding.assert_live()
        self.assertEqual(reads, 8)
        self.assertFalse(binding._invalid)
        self.assertEqual(events, [])
        uncertainty[0] = 0.0
        self.fx.wall += 1
        self.fx.mono += 21
        install_calls = []
        original_install = binding._snapshot_store.install
        def counted_install(*args, **kwargs):
            install_calls.append(True)
            return original_install(*args, **kwargs)
        with patch.object(binding._snapshot_store, "install", side_effect=counted_install):
            with self.assertRaisesRegex(SnapshotError, "expired"):
                binding.refresh_selected_policy()
        self.assertEqual(install_calls, [])
        self.assertEqual(binding._snapshot_store.current().revision, payload_a["revision"])
        self.assertEqual(len(events), 1)

    def test_new_selected_expiry_renews_after_local_snapshot_expiry(self):
        root_store, binding = self._load()
        self.addCleanup(root_store.close)
        original = json.loads(self.fx.active)["payload"]
        credentials = {item["serial"]: item for item in original["credentials"]}
        payload_a = dict(original)
        payload_a["revision"] += 1
        payload_a["expires_at"] = int(self.fx.wall) + 5
        payload_a["grants"] = [dict(grant) for grant in original["grants"]]
        for grant in payload_a["grants"]:
            grant["not_after"] = min(payload_a["expires_at"],
                credentials[grant["actor_serial"]]["not_after"],
                credentials[grant["target_serial"]]["not_after"])
        encoded_a = sign_snapshot(payload_a, self.fx.fx.new_snapshot_key)
        binding.install_policy(encoded_a)
        binding.assert_live()
        payload_b = dict(payload_a)
        payload_b["revision"] += 1
        payload_b["expires_at"] = int(self.fx.wall) + 60
        payload_b["grants"] = [dict(grant) for grant in payload_a["grants"]]
        for grant in payload_b["grants"]:
            grant["not_after"] = min(payload_b["expires_at"],
                credentials[grant["actor_serial"]]["not_after"],
                credentials[grant["target_serial"]]["not_after"])
        encoded_b = sign_snapshot(payload_b, self.fx.fx.new_snapshot_key)
        old_head = hashlib.sha256((self.fx.root / "selector.json").read_bytes()).hexdigest()
        root_store.advance_policy(encoded_b, expected_old_selector_sha256=old_head,
                                  clock=self.fx.clock, validate=lambda *_: None)
        self.fx.wall += 6
        self.fx.mono += 6
        self.assertEqual(binding.refresh_selected_policy(),
            (payload_b["revision"], canonical_policy_digest(payload_b)))
        self.assertEqual(binding._snapshot_store.current().revision, payload_b["revision"])
        binding.assert_live()

    def test_first_selected_view_uncertainty_deadline_is_retained(self):
        self.fx.wall += 30
        self.fx.mono += 30
        store, binding = self._load()
        self.addCleanup(store.close)
        payload = json.loads(self.fx.active)["payload"]
        payload["revision"] += 1
        payload["expires_at"] = int(self.fx.wall) + 40
        short_head = sign_snapshot(payload, self.fx.fx.new_snapshot_key)
        binding.install_policy(short_head)
        events = []
        binding.subscribe_teardown(events.append)
        original = binding._selected_policy
        selected_reads = 0
        uncertainty = [0.0]
        self.fx.clock._uncertainty = lambda: uncertainty[0]
        def uncertain_first(*args, **kwargs):
            nonlocal selected_reads
            selected_reads += 1
            if selected_reads == 1:
                uncertainty[0] = 20.0
            try:
                return original(*args, **kwargs)
            finally:
                uncertainty[0] = 0.0
        with patch.object(binding, "_selected_policy", side_effect=uncertain_first):
            binding.assert_live()
        self.assertEqual(selected_reads, 2)
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
        original = __import__("steamboat_security.root_c2_consumer", fromlist=["safe_read"]).safe_read
        calls = 0
        def delayed(*args, **kwargs):
            nonlocal calls
            calls += 1
            if calls == 8:  # final protected-file read, immediately before final clock sample
                delta = int(json.loads(self.fx.active)["payload"]["expires_at"] - self.fx.wall + 1)
                self.fx.wall += delta
                self.fx.mono += delta
            return original(*args, **kwargs)
        with patch("steamboat_security.root_c2_consumer.safe_read", side_effect=delayed):
            with self.assertRaisesRegex(SnapshotError, "expired"):
                binding.assert_live()
        self.assertEqual(calls, 8)
        self.assertEqual(len(events), 1)


class C2ConsumerHeaderTests(unittest.TestCase):
    def _header(self):
        return {
            "schema_version": 1,
            "profile": "native_posix_root_c2_consumer_v1",
            "protected_root": "/protected", "selected_root": "/selected",
            "account_id": "acct_" + "1" * 32,
            "device_id": "dev_" + "2" * 32,
            "role": "consumer", "boot_id": "boot_" + "3" * 32,
            "credential_epoch": 1, "admission_epoch": 1,
            "generation_sha256": "4" * 64, "launch_nonce": "5" * 32,
            "certificate_path": "/protected/role.pem",
            "private_key_path": "/protected/role.key",
            "model_id": "7" * 64,
            "runtime_configuration_path": "/protected/runtime.bin",
            "runtime_configuration_sha256": "6" * 64,
        }

    def test_accepts_only_closed_consumer_profile(self):
        header = self._header()
        encoded = canonical_json(header)
        with patch("steamboat_security.root_c2_consumer.safe_read", return_value=encoded):
            raw, parsed = _read_header("/protected/header.json", "/protected", 1)
        self.assertEqual(raw, encoded)
        self.assertEqual(set(parsed), _FIELDS)

    def test_rejects_host_header_and_extra_command_fields(self):
        for change in (
            {"profile": "native_posix_root_c2_host_group_v1"},
            {"profile": "native_posix_root_c2_personal_coordinator_v1"},
            {"role": "personal_coordinator"}, {"role": "host"},
            {"peer_command": ["sh", "-c", "true"]},
        ):
            header = self._header() | change
            with patch("steamboat_security.root_c2_consumer.safe_read",
                       return_value=canonical_json(header)):
                with self.assertRaises(CredentialError):
                    _read_header("/protected/header.json", "/protected", 1)

    def test_invalidation_notifies_once_and_outside_lock(self):
        binding = object.__new__(C2ConsumerRuntimeBinding)
        import threading
        binding._lock = threading.RLock()
        binding._invalid = False
        binding._reason = None
        binding._subscribers = []
        binding._notification_faulted = False
        binding._notify = C2ConsumerRuntimeBinding._notify.__get__(binding)
        calls = []
        binding._subscribers.append(lambda reason: calls.append(reason))
        binding.invalidate("test")
        binding.invalidate("again")
        self.assertEqual(calls, ["test"])
        self.assertTrue(binding._invalid)

    def test_awaitable_teardown_is_rejected(self):
        binding = object.__new__(C2ConsumerRuntimeBinding)
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
