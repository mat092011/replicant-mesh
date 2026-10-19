"""C2 coordinator assigned-head assembly and retained-owner checks."""
from __future__ import annotations

import asyncio
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from steamboat_connector.c2_coordinator_runtime import (
    C2CoordinatorRuntimeError, build_c2_coordinator_runtime,
)


class C2CoordinatorRuntimeContractTests(unittest.TestCase):
    def test_import_does_not_load_torch(self):
        code = ("import sys; sys.path.insert(0, " + repr(str(ROOT / "src")) + "); "
                "import steamboat_connector.c2_coordinator_runtime; "
                "assert 'torch' not in sys.modules")
        subprocess.run([sys.executable, "-I", "-c", code], check=True,
                       capture_output=True, text=True, timeout=10)

    def test_builder_rejects_non_owners_before_any_load(self):
        with self.assertRaises(TypeError):
            asyncio.run(build_c2_coordinator_runtime(object(), object(), object(),
                                                      owner_policy=object()))


_ARTIFACTS = Path(os.environ.get("STEAMBOAT_C2_STARTUP_ARTIFACTS", "/artifacts"))
_NATIVE_FIXTURE = (os.name == "posix" and hasattr(os, "geteuid")
                   and _ARTIFACTS.is_dir())


@unittest.skipUnless(_NATIVE_FIXTURE,
    "requires Linux POSIX and the approved offline /artifacts model fixture")
class C2CoordinatorRuntimeNativeTests(unittest.IsolatedAsyncioTestCase):
    @classmethod
    def setUpClass(cls):
        from tests.security.test_root_c2_coordinator import C2CoordinatorStoreIntegrationTests
        C2CoordinatorStoreIntegrationTests.setUpClass()

    def setUp(self):
        from tests.security.test_root_c2_coordinator import C2CoordinatorStoreIntegrationTests
        self.root_fixture = object.__new__(C2CoordinatorStoreIntegrationTests)
        self.root_fixture._testMethodName = (
            "test_channel_wall_expiry_rejects_clock_drift_even_before_monotonic_deadline")
        self.root_fixture.setUp()
        self.fx = self.root_fixture.fx
        self.pin = self.child_pins = self.child_owner = None
        self.runtime = None
        self.installer = None
        self._prepare_assigned_coordinator()

    async def asyncTearDown(self):
        if self.runtime is not None and self.runtime._state not in {"closed", "faulted"}:
            await self.runtime.close()
        if self.child_pins is not None and self.child_pins._state == "open":
            self.child_pins.close()
        if self.pin is not None:
            self.pin.release()
        if self.child_owner is not None:
            self.child_owner.close()
        self.root_fixture.tearDown()

    def _prepare_assigned_coordinator(self):
        from cryptography.hazmat.primitives import serialization
        from steamboat_security.codec import canonical_json
        from steamboat_security.snapshot import sign_snapshot, canonical_policy_digest
        from steamboat_security.root_transition_storage import (
            RootGenerationSelector, root_generation_selector_document,
        )
        from steamboat_security.root_transition_launch import (
            parse_role_launch_spec, canonical_role_launch_digest,
        )
        from steamboat_connector.catalog import (
            ARTIFACT_FILENAMES, CatalogVerifier, RUNTIME_LOCK_SHA256,
        )
        from steamboat_connector.artifacts import ArtifactInstaller
        from steamboat_connector.artifact_pin import RuntimeArtifactPin
        from steamboat_connector.runtime_pin_handoff import validate_child_pin
        from steamboat_connector.c2_child_config import C2ChildBinding
        from steamboat_runtime.manifest import load_manifest, SOURCE_HASHES, MODEL_ID, MODEL_REVISION
        import tests.connector.test_artifacts as artifact_tests
        import tests.connector.test_c2_coordinator_settings as settings_tests

        now = int(self.fx.wall)
        source_manifest = load_manifest(_ARTIFACTS)
        file_bytes = {name: (_ARTIFACTS / name).read_bytes() for name in ARTIFACT_FILENAMES}
        payload = artifact_tests._catalog_payload(now=now, file_bytes=file_bytes)
        payload["manifest"].update(fingerprint=source_manifest["fingerprint"],
            sha256=hashlib.sha256(file_bytes["modelmanifest.json"]).hexdigest(),
            size_bytes=len(file_bytes["modelmanifest.json"]))
        verifier = CatalogVerifier(artifact_tests._PUBLIC, clock=self.fx.clock)
        catalog_bytes = artifact_tests._sign_document(payload, "catalog")
        catalog = verifier.verify_catalog(catalog_bytes, now=now)
        assignment_id = "asg_" + "a" * 32
        assignment_bytes, assignment = artifact_tests._assignment_bundle(
            verifier, catalog, role="coordinator", component="coordinator", now=now,
            assignment_id=assignment_id,
            account_id=self.fx.coordinator_spec.account_id,
            device_id=self.fx.coordinator_spec.device_id)

        class Retriever:
            def iter_chunks(_self, filename, *, deadline, max_chunk_bytes):
                path = _ARTIFACTS / filename
                with path.open("rb") as stream:
                    while True:
                        chunk = stream.read(max_chunk_bytes)
                        if not chunk:
                            return
                        yield chunk

        store_path = self.fx.protected / "coordinator-artifacts"
        store_path.mkdir(mode=0o700)
        installer = ArtifactInstaller(store_path, verifier,
            disk_ceiling_bytes=512 * 1024 * 1024, disk_headroom_bytes=16 * 1024 * 1024,
            wall_clock=lambda: now)
        installer.install(catalog_bytes, assignment_bytes, Retriever(),
            account_id=self.fx.coordinator_spec.account_id,
            device_id=self.fx.coordinator_spec.device_id, role="coordinator")
        self.pin_root = store_path
        self.verifier, self.assignment = verifier, assignment

        # Update the actual signed selected policy's model pin to the source
        # manifest fingerprint, then rebuild the selected immutable generation.
        baseline = json.loads(self.fx.artifacts["policy_snapshot.json"])["payload"]
        active = json.loads(self.fx.active)["payload"]
        for policy in (baseline, active):
            for grant in policy["grants"]:
                grant["model_id"] = source_manifest["fingerprint"]
        baseline_bytes = sign_snapshot(baseline, self.fx.fx.new_snapshot_key)
        active_bytes = sign_snapshot(active, self.fx.fx.new_snapshot_key)
        self.fx.artifacts["policy_snapshot.json"] = baseline_bytes
        self.fx.active = active_bytes
        activation = json.loads(self.fx.artifacts["activation_manifest.json"])
        activation["policy_revision"] = baseline["revision"]
        activation["policy_digest"] = canonical_policy_digest(baseline)
        activation["policy_payload_sha256"] = hashlib.sha256(canonical_json(baseline)).hexdigest()
        self.fx.artifacts["activation_manifest.json"] = canonical_json(activation)

        settings_fixture = object.__new__(settings_tests.C2CoordinatorSettingsTests)
        settings_fixture.setUpClass()
        settings = settings_fixture.document()
        settings["artifact_root"] = str(store_path)
        settings["catalog_public_key_hex"] = verifier.public_key.hex()
        settings["assignment"].update(
            assignment_id=assignment_id,
            catalog_sha256=hashlib.sha256(catalog_bytes).hexdigest(),
            catalog_public_key_sha256=hashlib.sha256(verifier.public_key).hexdigest(),
            assignment_sha256=hashlib.sha256(assignment_bytes).hexdigest())
        if self._testMethodName.endswith("_bad_selected_catalog_key"):
            settings["catalog_public_key_hex"] = "04" + "11" * 64
        elif self._testMethodName.endswith("_bad_valid_selected_catalog_key"):
            from cryptography.hazmat.primitives.asymmetric import ec
            alternate = ec.generate_private_key(ec.SECP256R1()).public_key().public_bytes(
                serialization.Encoding.X962,
                serialization.PublicFormat.UncompressedPoint)
            settings["catalog_public_key_hex"] = alternate.hex()
            settings["assignment"]["catalog_public_key_sha256"] = hashlib.sha256(
                alternate).hexdigest()
        elif self._testMethodName.endswith("_bad_selected_artifact_root"):
            settings["artifact_root"] = str(store_path / "different-root")
        elif self._testMethodName.endswith("_bad_selected_assignment_digest"):
            settings["assignment"]["assignment_sha256"] = "f" * 64
        elif self._testMethodName.endswith("_bad_selected_assignment_id"):
            settings["assignment"]["assignment_id"] = "asg_" + "b" * 32
        settings_bytes = canonical_json(settings)

        header = json.loads(self.fx.coordinator_header_path.read_bytes())
        header["model_id"] = source_manifest["fingerprint"]
        runtime_path = Path(header["runtime_configuration_path"])
        self.fx._private(runtime_path, settings_bytes)
        header["runtime_configuration_sha256"] = hashlib.sha256(settings_bytes).hexdigest()
        header_bytes = canonical_json(header)
        self.fx._private(self.fx.coordinator_header_path, header_bytes)

        launch_specs = self.fx.artifacts["new_launch_specs.json"]
        spec_docs = json.loads(launch_specs)
        for spec_doc in spec_docs:
            if spec_doc["role"] == "personal_coordinator":
                spec_doc["configuration_sha256"] = hashlib.sha256(header_bytes).hexdigest()
        activation["new_launch_specs"] = spec_docs
        activation["new_launch_digest"] = canonical_role_launch_digest(
            tuple(parse_role_launch_spec(item) for item in spec_docs))
        self.fx.artifacts["new_launch_specs.json"] = canonical_json(spec_docs)
        self.fx.artifacts["activation_manifest.json"] = canonical_json(activation)

        old = self.fx.selector
        selector = RootGenerationSelector(old.generation_sha256,
            hashlib.sha256(self.fx.artifacts["activation_manifest.json"]).hexdigest(),
            active["revision"], canonical_policy_digest(active), hashlib.sha256(active_bytes).hexdigest(),
            {name: hashlib.sha256(data).hexdigest() for name, data in self.fx.artifacts.items()})
        generation = self.fx.root / "generations" / selector.generation_sha256
        descriptor = {"schema_version": 1, "purpose": "root_generation_descriptor",
            "generation_sha256": selector.generation_sha256,
            "activation_manifest_sha256": selector.activation_manifest_sha256,
            "artifact_sha256": dict(selector.artifact_sha256)}
        self.fx._private(generation / "descriptor.json", canonical_json(descriptor))
        for name, data in self.fx.artifacts.items():
            self.fx._private(generation / name, data)
        for path in (self.fx.root / "policies").iterdir():
            path.unlink()
        self.fx._private(self.fx.root / "policies" / f"{hashlib.sha256(active_bytes).hexdigest()}.json", active_bytes)
        self.fx._private(self.fx.root / "selector.json",
                         canonical_json(root_generation_selector_document(selector)))
        self.fx.selector = selector
        self.fx.coordinator_spec = parse_role_launch_spec(next(
            item for item in spec_docs if item["role"] == "personal_coordinator"))

        root_store, binding = self.root_fixture._load()
        child_owner = C2ChildBinding(root_store, binding)
        self.child_owner = child_owner
        self.installer = ArtifactInstaller(store_path, verifier,
            disk_ceiling_bytes=512 * 1024 * 1024, disk_headroom_bytes=16 * 1024 * 1024,
            wall_clock=lambda: now, read_only=True)
        view = self.installer.open_view(assignment_id,
            account_id=binding._spec.account_id, device_id=binding._spec.device_id,
            role="coordinator", now=now)
        self.pin = RuntimeArtifactPin.acquire(view, clock=self.fx.clock,
                                              boot_id=binding._spec.boot_id)
        metadata = self.pin.child_launch_metadata()
        metadata.update(version=1, kind="single", role="coordinator",
            root=str(self.pin.root), uid=self.pin.uid,
            public_key=__import__("base64").b64encode(verifier.public_key).decode("ascii"),
            signed_catalog=__import__("base64").b64encode(self.pin.signed_catalog).decode("ascii"),
            signed_assignment=__import__("base64").b64encode(self.pin.signed_assignment).decode("ascii"))
        metadata["global_fd"] = os.dup(metadata["global_fd"])
        metadata["role_fd"] = os.dup(metadata["role_fd"])
        self.child_pins = validate_child_pin(metadata, clock=self.fx.clock, verifier=verifier)

    @staticmethod
    def owner_policy(weights_bytes, *, sessions=2):
        from steamboat_connector.policy import LIMIT_FIELDS, RESERVATION_FIELDS
        limits = {field: 1 for field in LIMIT_FIELDS}
        limits.update(memory_ceiling_bytes=2 << 30, memory_headroom_bytes=16 << 20,
            cpu_quota_millis=2000, disk_ceiling_bytes=2 << 30,
            send_bytes_per_second=1 << 20, receive_bytes_per_second=1 << 20,
            total_network_bytes=1 << 30, cleanup_send_bytes_per_second=1 << 20,
            cleanup_receive_bytes_per_second=1 << 20,
            cleanup_total_network_bytes=1 << 30, max_sessions=8,
            max_queued_calls=8, max_request_seconds=300)
        reservation = {field: 0 for field in RESERVATION_FIELDS}
        reservation.update(weights_bytes=weights_bytes, temporary_bytes=64 << 20,
            runtime_bytes=64 << 20, communication_bytes=1 << 20,
            capture_bytes=1 << 20, cpu_quota_millis=1000, disk_bytes=1 << 30,
            send_bytes_per_second=1 << 20, receive_bytes_per_second=1 << 20,
            total_network_bytes=1 << 30, cleanup_send_bytes_per_second=1 << 20,
            cleanup_receive_bytes_per_second=1 << 20,
            cleanup_total_network_bytes=1 << 30, sessions=sessions,
            queued_calls=0, max_request_seconds=300)
        return {"version": 1, "pool_id": "coordinator-runtime-test",
            "limits": limits, "reservations": {"coordinator": reservation},
            "required_telemetry": []}

    async def test_actual_selected_pin_loads_assigned_head_health_and_confirmed_close(self):
        from steamboat_security.errors import CredentialError
        record = self.installer._load_state()["installations"][self.assignment.payload["assignment_id"]]
        file_path = self.pin_root / record["directory"] / "coordinator.safetensors"
        weight_bytes = file_path.stat().st_size
        bad_policy = self.owner_policy(weight_bytes - 1)
        from steamboat_runtime.assigned_artifacts import AssignedArtifactView
        with mock.patch.object(AssignedArtifactView, "load_coordinator_model",
                side_effect=AssertionError("weights loaded before budget check")) as loader:
            with self.assertRaises(CredentialError):
                await build_c2_coordinator_runtime(self.child_owner, self.child_pins,
                    self.installer, owner_policy=bad_policy)
            loader.assert_not_called()

        self.runtime = await build_c2_coordinator_runtime(self.child_owner, self.child_pins,
            self.installer, owner_policy=self.owner_policy(weight_bytes, sessions=2))
        self.assertEqual(self.runtime.limits["max_sessions"], 2)
        self.assertTrue(await self.runtime.health_check())
        self.assertTrue(await self.runtime.close(grace_seconds=5))
        self.assertEqual(self.runtime._state, "closed")
        with self.assertRaises(C2CoordinatorRuntimeError):
            await self.runtime.tokenize("after close")

    async def test_cancelled_cpu_awaiter_retains_model_and_retry_reclaims_after_drain(self):
        import threading
        import weakref
        import torch
        from steamboat_runtime.coordinator_model import CoordinatorModel

        model = self.runtime = await build_c2_coordinator_runtime(
            self.child_owner, self.child_pins, self.installer,
            owner_policy=self.owner_policy(1 << 30, sessions=2))
        assigned = model._model
        lease = model._lease
        assigned_ref = weakref.ref(assigned)
        original_embed = CoordinatorModel._embed
        entered, release = threading.Event(), threading.Event()
        self.addCleanup(release.set)

        def blocked_embed(actual_model, ids):
            entered.set()
            if not release.wait(5):
                raise RuntimeError("test executor release deadline elapsed")
            return original_embed(actual_model, ids)

        with mock.patch.object(CoordinatorModel, "_embed", blocked_embed):
            call = asyncio.create_task(model.embed(torch.tensor([[1]], dtype=torch.int64)))
            self.assertTrue(await asyncio.to_thread(entered.wait, 2))
            call.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await call
            self.assertGreaterEqual(assigned.diagnostics()["pending_cpu_operations"], 1)
            with self.assertRaises(C2CoordinatorRuntimeError):
                await model.close(grace_seconds=0.05)
            self.assertIs(model._model, assigned)
            self.assertIs(model._lease, lease)
            self.assertIs(model._child_pins, self.child_pins)
            with self.assertRaises(C2CoordinatorRuntimeError):
                await model.embed(torch.tensor([[1]], dtype=torch.int64))
            release.set()
            deadline = asyncio.get_running_loop().time() + 5
            while assigned.diagnostics()["pending_cpu_operations"] and \
                    asyncio.get_running_loop().time() < deadline:
                await asyncio.sleep(0.01)
            self.assertEqual(assigned.diagnostics()["pending_cpu_operations"], 0)
        self.assertTrue(await model.close(grace_seconds=5))
        self.assertIsNone(model._model)
        self.assertIsNone(model._lease)
        self.assertIsNone(model._child_pins)
        del assigned
        self.assertIsNone(assigned_ref())

    async def test_binding_invalidation_fences_but_retains_inflight_cpu_owner(self):
        import threading
        import torch
        from steamboat_runtime.coordinator_model import CoordinatorModel

        runtime = self.runtime = await build_c2_coordinator_runtime(
            self.child_owner, self.child_pins, self.installer,
            owner_policy=self.owner_policy(1 << 30, sessions=2))
        assigned = runtime._model
        original_embed = CoordinatorModel._embed
        entered, release = threading.Event(), threading.Event()
        self.addCleanup(release.set)

        def blocked_embed(actual_model, ids):
            entered.set()
            if not release.wait(5):
                raise RuntimeError("test executor release deadline elapsed")
            return original_embed(actual_model, ids)

        with mock.patch.object(CoordinatorModel, "_embed", blocked_embed):
            call = asyncio.create_task(runtime.embed(torch.tensor([[1]], dtype=torch.int64)))
            self.assertTrue(await asyncio.to_thread(entered.wait, 2))
            runtime._binding.invalidate("test selected-binding invalidation")
            deadline = asyncio.get_running_loop().time() + 1
            while runtime._state != "closing" and asyncio.get_running_loop().time() < deadline:
                await asyncio.sleep(0.005)
            self.assertEqual(runtime._state, "closing")
            self.assertIs(runtime._model, assigned)
            self.assertIs(runtime._child_pins, self.child_pins)
            with self.assertRaises(C2CoordinatorRuntimeError):
                await runtime.embed(torch.tensor([[1]], dtype=torch.int64))
            self.assertFalse(call.done())
            release.set()
            done_deadline = asyncio.get_running_loop().time() + 5
            while runtime._state != "closed" and asyncio.get_running_loop().time() < done_deadline:
                await asyncio.sleep(0.01)
            self.assertEqual(runtime._state, "closed")
            self.assertIsNone(runtime._model)
            self.assertIsNone(runtime._child_pins)
            with self.assertRaises(C2CoordinatorRuntimeError):
                await call

    async def test_lease_exit_failure_keeps_closed_model_and_pin_owners_referenced(self):
        runtime = self.runtime = await build_c2_coordinator_runtime(
            self.child_owner, self.child_pins, self.installer,
            owner_policy=self.owner_policy(1 << 30, sessions=2))
        model, lease, pins = runtime._model, runtime._lease, runtime._child_pins
        original_exit = lease.__exit__
        with mock.patch.object(lease, "__exit__",
                               side_effect=RuntimeError("injected lease cleanup uncertainty")):
            with self.assertRaises(C2CoordinatorRuntimeError):
                await runtime.close(grace_seconds=5)
        self.assertEqual(runtime._state, "faulted")
        self.assertIs(runtime._model, model)
        self.assertIs(runtime._lease, lease)
        self.assertIs(runtime._child_pins, pins)
        # The injected failure happened before invoking the real lease owner;
        # explicitly finish fixture teardown without weakening runtime rules.
        original_exit(None, None, None)

    async def test_close_lock_wait_is_inside_grace_and_retains_owners(self):
        runtime = self.runtime = await build_c2_coordinator_runtime(
            self.child_owner, self.child_pins, self.installer,
            owner_policy=self.owner_policy(1 << 30, sessions=2))
        model, pins = runtime._model, runtime._child_pins
        await runtime._close_lock.acquire()
        try:
            started = asyncio.get_running_loop().time()
            with self.assertRaises(C2CoordinatorRuntimeError):
                await runtime.close(grace_seconds=0.05)
            elapsed = asyncio.get_running_loop().time() - started
            self.assertLess(elapsed, 0.5)
            self.assertIs(runtime._model, model)
            self.assertIs(runtime._child_pins, pins)
        finally:
            runtime._close_lock.release()
        self.assertTrue(await runtime.close(grace_seconds=5))

    async def _assert_anchor_fault_precedes_model_materialization(self, accepted_errors):
        from steamboat_runtime.assigned_artifacts import AssignedArtifactView
        with mock.patch.object(AssignedArtifactView, "load_coordinator_model",
                side_effect=AssertionError("unverified assignment reached weight loading")) as loader:
            with self.assertRaises(accepted_errors):
                await build_c2_coordinator_runtime(self.child_owner, self.child_pins,
                    self.installer, owner_policy=self.owner_policy(1 << 30))
            loader.assert_not_called()

    async def test_bad_selected_catalog_key_fails_before_weight_loading(self):
        from steamboat_connector.c2_coordinator_settings import C2CoordinatorSettingsError
        await self._assert_anchor_fault_precedes_model_materialization(
            (C2CoordinatorSettingsError,))

    async def test_bad_valid_selected_catalog_key(self):
        from steamboat_security.errors import CredentialError
        await self._assert_anchor_fault_precedes_model_materialization((CredentialError,))

    async def test_bad_selected_artifact_root(self):
        from steamboat_security.errors import CredentialError
        await self._assert_anchor_fault_precedes_model_materialization((CredentialError,))

    async def test_bad_selected_assignment_digest_fails_before_weight_loading(self):
        from steamboat_security.errors import CredentialError
        await self._assert_anchor_fault_precedes_model_materialization(
            (CredentialError,))

    async def test_bad_selected_assignment_id_fails_before_weight_loading(self):
        from steamboat_security.errors import CredentialError
        await self._assert_anchor_fault_precedes_model_materialization(
            (CredentialError,))
