"""Closed declaration checks for the cold-start root cohort adapter."""
from __future__ import annotations

import os
import hashlib
import asyncio
import json
import sys
import tempfile
import time
import threading
from pathlib import Path
import unittest
from dataclasses import replace
from unittest import mock

import tests.security.test_root_runtime as binding_fixture
import tests.security.test_root_transition_retirement as retirement_fixture
import steamboat_security.root_transition_startup as startup_module
from steamboat_security.codec import canonical_json
from steamboat_security.errors import BindingError, CredentialError
from steamboat_security.files import safe_write
from steamboat_security.root_transition_launch import (
    canonical_role_launch_digest, parse_role_launch_spec, role_launch_document,
)
from steamboat_security.root_transition_launch_claim import LaunchClaimStore
from steamboat_security.snapshot import canonical_policy_digest, sign_snapshot
from steamboat_security.root_transition_retirement import RetirementSupervisor
from steamboat_security.root_transition_startup import (
    RootCohortStartup, RootRoleLaunch, StartedRootCohort,
)
from steamboat_security.root_transition_storage import (
    RootGenerationStore, root_generation_selector_document,
)


def _spec(**updates):
    raw = {
        "generation_sha256": "a" * 64,
        "account_id": "acct_" + "1" * 32,
        "device_id": "dev_" + "2" * 32,
        "role": "host",
        "serial": "abc123",
        "certificate_sha256": "b" * 64,
        "public_key_sha256": "c" * 64,
        "credential_epoch": 1,
        "boot_id": "3" * 32,
        "admission_epoch": 2,
        "configuration_sha256": "d" * 64,
        "launch_nonce": "4" * 32,
    }
    raw.update(updates)
    return parse_role_launch_spec(raw)


_ROOT = str((Path.cwd() / "startup-test-root").resolve())


def _launch(spec, *, manifest=None, root=_ROOT, config=None):
    manifest = manifest or os.path.join(root, "launcher.json")
    config = config or os.path.join(root, "config.json")
    return RootRoleLaunch(spec, manifest, root, config, root)


class RootCohortStartupDeclarationTests(unittest.TestCase):
    def test_exact_bounded_role_launch_inputs_are_required(self):
        item = _launch(_spec())
        self.assertEqual(RootCohortStartup._validate_launches((item,)), (item,))
        with self.assertRaises(BindingError):
            RootCohortStartup._validate_launches([item])
        with self.assertRaises(BindingError):
            RootCohortStartup._validate_launches((object(),))

    def test_paths_are_absolute_canonical_owner_references(self):
        with self.assertRaises(BindingError):
            RootCohortStartup._validate_launches((
                _launch(_spec(), manifest="../launcher.json"),))
        with self.assertRaises(BindingError):
            RootCohortStartup._validate_launches((
                _launch(_spec(), config="/protected/../outside.json"),))

    def test_shared_process_nonce_fails_closed_for_single_role_headers(self):
        second = _spec(device_id="dev_" + "5" * 32, role="consumer",
                       serial="def456")
        with self.assertRaises(BindingError):
            RootCohortStartup._group_launches((
                _launch(_spec()), _launch(second)))

    def test_distinct_nonces_create_distinct_process_groups(self):
        second = _spec(device_id="dev_" + "5" * 32, role="consumer",
                       serial="def456", launch_nonce="5" * 32,
                       boot_id="6" * 32)
        groups = RootCohortStartup._group_launches(
            (_launch(_spec()), _launch(second, manifest=os.path.join(_ROOT, "other.json"),
                                       config=os.path.join(_ROOT, "other-config.json"))))
        self.assertEqual(len(groups), 2)

    def test_constructor_rejects_non_native_or_untrusted_dependencies(self):
        with self.assertRaises(BindingError):
            RootCohortStartup(root_store=object(), claim_store=object(),
                              retirement_supervisor=object(), clock=object(),
                              expected_uid=os.geteuid() if hasattr(os, "geteuid") else 0)


@unittest.skipUnless(os.name == "posix" and hasattr(os, "geteuid")
                     and os.path.isdir("/proc"),
                     "requires protected native POSIX files and /proc")
class RootCohortStartupProcessTests(unittest.IsolatedAsyncioTestCase):
    @classmethod
    def setUpClass(cls):
        binding_fixture.RootRuntimeProtectedBindingTests.setUpClass()

    def setUp(self):
        case = object.__new__(binding_fixture.RootRuntimeProtectedBindingTests)
        case.setUp()
        self.fixture = case
        self.fx = case.fx
        self.extra = tempfile.TemporaryDirectory(prefix="root-startup-")
        os.chmod(self.extra.name, 0o700)
        self.retirement = RetirementSupervisor()
        self.launch_roots = []
        self.claim_root = Path(self.extra.name) / "claims"
        self.claim_root.mkdir(mode=0o700)
        os.chmod(self.claim_root, 0o700)
        self.claims = LaunchClaimStore(self.claim_root, expected_uid=os.geteuid())
        self._rewrite_selected_cohort()

    def tearDown(self):
        owned = list(self.retirement._owned)
        for generation in {s.generation_sha256 for r in owned for s in r.specs}:
            if any(r.process.poll() is None for r in owned
                   if any(s.generation_sha256 == generation for s in r.specs)):
                self.retirement.terminate_owned_generation(generation, timeout_seconds=5)
        for record in owned:
            if record.process.stdout:
                record.process.stdout.close()
            if record.process.stdin and not record.process.stdin.closed:
                record.process.stdin.close()
        self.claims.close()
        self.fixture.tearDown()
        self.extra.cleanup()

    def _rewrite_selected_cohort(self):
        """Provision one exact selected full-role plan with real protected headers."""
        selected = self.fixture.store.read_selected(validate=lambda *_: None)
        self.fixture.store.close()
        old = self.fx.candidate
        policy_payload = json.loads(old.policy_payload)
        policy_payload["expires_at"] += 200
        for grant in policy_payload["grants"]:
            grant["not_after"] = min(grant["not_after"], policy_payload["issued_at"] + 30)
        selected_policy_bytes = sign_snapshot(policy_payload, self.fx.new_snapshot_key)
        selected_policy_digest = canonical_policy_digest(policy_payload)
        specs = tuple(old.new_launch_specs)
        issued_by_identity = {item.identity: item
                              for item in old.issuance_candidate.principals}
        role_by_identity = {item["principal"].identity: item for item in self.fx.roles}
        grants = json.loads(old.policy_payload)["grants"]
        launch_inputs = []
        updated_specs = []
        for index, spec in enumerate(specs):
            root = Path(self.extra.name) / f"role-{index}"
            root.mkdir(mode=0o700)
            os.chmod(root, 0o700)
            self.launch_roots.append(root)
            cert_path, key_path = root / "leaf.pem", root / "role-key.pem"
            runtime_path, config_path = root / "runtime.json", root / "config.json"
            issued = issued_by_identity[spec.identity]
            role = role_by_identity[spec.identity]
            grant = next(item for item in grants
                         if item["actor_serial"] == spec.serial
                         or item["target_serial"] == spec.serial)
            runtime = canonical_json({"fixed_adapter": "startup-component-v1"})
            header = {
                "schema_version": 1, "profile": "native_posix_root_role_v1",
                "protected_root": str(root), "selected_root": str(self.fixture.root),
                "account_id": spec.account_id, "device_id": spec.device_id,
                "role": spec.role, "boot_id": spec.boot_id,
                "credential_epoch": spec.credential_epoch,
                "admission_epoch": spec.admission_epoch,
                "generation_sha256": spec.generation_sha256,
                "launch_nonce": spec.launch_nonce,
                "certificate_path": str(cert_path), "private_key_path": str(key_path),
                "model_id": grant["model_id"], "assignment_id": grant["assignment_id"],
                "runtime_configuration_path": str(runtime_path),
                "runtime_configuration_sha256": hashlib.sha256(runtime).hexdigest(),
            }
            if spec.role != "host":
                header["assignment_id"] = None
            header_bytes = canonical_json(header)
            bound_spec = replace(
                spec, configuration_sha256=hashlib.sha256(header_bytes).hexdigest())
            updated_specs.append(bound_spec)
            for path, content, limit in (
                    (cert_path, issued.certificate_pem, 64 * 1024),
                    (key_path, role["new_key"], 64 * 1024),
                    (runtime_path, runtime, 16 * 1024),
                    (config_path, header_bytes, 16 * 1024)):
                safe_write(path, content, root=str(root), expected_uid=os.geteuid(),
                           max_bytes=limit)
            script_path = root / "worker.py"
            child_source = retirement_fixture._CHILD_SCRIPT
            ready_marker = 'packet = {"schema_version": 1, "event": "root_role_ready",'
            lock_gate = (
                'import fcntl\n'
                'lock_fd = os.open(os.path.join(config["selected_root"], "transition.lock"), os.O_RDWR)\n'
                'fcntl.flock(lock_fd, fcntl.LOCK_EX)\n'
                'fcntl.flock(lock_fd, fcntl.LOCK_UN)\n'
                'os.close(lock_fd)\n'
            )
            if ready_marker not in child_source:
                raise AssertionError("protected READY fixture insertion point changed")
            script_bytes = child_source.replace(ready_marker, lock_gate + ready_marker).encode("utf-8")
            safe_write(script_path, script_bytes, root=str(root),
                       expected_uid=os.geteuid(), max_bytes=1024 * 1024)
            manifest_path = root / "launcher.json"
            manifest = retirement_fixture._manifest_document(
                sys.executable, str(script_path), str(config_path),
                hashlib.sha256(script_bytes).hexdigest(),
                hashlib.sha256(header_bytes).hexdigest())
            safe_write(manifest_path, canonical_json(manifest), root=str(root),
                       expected_uid=os.geteuid(), max_bytes=16 * 1024)
            launch_inputs.append(RootRoleLaunch(
                bound_spec, str(manifest_path), str(root), str(config_path), str(root)))

        new_specs = tuple(updated_specs)
        activation = json.loads(old.activation_manifest)
        activation["new_launch_specs"] = [role_launch_document(item) for item in new_specs]
        activation["new_launch_digest"] = canonical_role_launch_digest(new_specs)
        activation["policy_digest"] = selected_policy_digest
        activation["policy_payload_sha256"] = hashlib.sha256(
            canonical_json(policy_payload)).hexdigest()
        activation_bytes = canonical_json(activation)
        bundle = dict(selected.artifacts)
        bundle["activation_manifest.json"] = activation_bytes
        bundle["policy_snapshot.json"] = selected_policy_bytes
        bundle["new_launch_specs.json"] = canonical_json(
            [role_launch_document(item) for item in new_specs])
        digest = lambda value: hashlib.sha256(value).hexdigest()
        artifact_sha = {name: digest(value) for name, value in bundle.items()}
        selector = replace(selected.selector,
                           activation_manifest_sha256=digest(activation_bytes),
                           policy_digest=selected_policy_digest,
                           active_policy_snapshot_sha256=digest(selected_policy_bytes),
                           artifact_sha256=artifact_sha)
        generation = self.fixture.root / "generations" / selector.generation_sha256
        for name, content in bundle.items():
            path = generation / name
            path.write_bytes(content)
            os.chmod(path, 0o600)
        descriptor = {
            "schema_version": 1, "purpose": "root_generation_descriptor",
            "generation_sha256": selector.generation_sha256,
            "activation_manifest_sha256": selector.activation_manifest_sha256,
            "artifact_sha256": dict(selector.artifact_sha256),
        }
        descriptor_path = generation / "descriptor.json"
        descriptor_path.write_bytes(canonical_json(descriptor))
        os.chmod(descriptor_path, 0o600)
        policy_path = (self.fixture.root / "policies"
                       / f"{selector.active_policy_snapshot_sha256}.json")
        policy_path.write_bytes(selected_policy_bytes)
        os.chmod(policy_path, 0o600)
        selector_path = self.fixture.root / "selector.json"
        selector_path.write_bytes(canonical_json(root_generation_selector_document(selector)))
        os.chmod(selector_path, 0o600)
        self.fixture.store = RootGenerationStore(
            self.fixture.root, expected_uid=os.geteuid())
        self.launch_inputs = tuple(launch_inputs)

    def _replace_child_script(self, index, transform, *, update_manifest=True):
        root = self.launch_roots[index]
        script_path = root / "worker.py"
        original = script_path.read_bytes()
        changed = transform(original)
        self.assertNotEqual(changed, original)
        script_path.write_bytes(changed)
        os.chmod(script_path, 0o600)
        if update_manifest:
            manifest_path = root / "launcher.json"
            manifest = json.loads(manifest_path.read_bytes())
            manifest["script_sha256"] = hashlib.sha256(changed).hexdigest()
            manifest_path.write_bytes(canonical_json(manifest))
            os.chmod(manifest_path, 0o600)

    def _startup(self, supervisor=None):
        return RootCohortStartup(
            root_store=self.fixture.store, claim_store=self.claims,
            retirement_supervisor=supervisor or self.retirement,
            clock=self.fx.clock_source.clock, expected_uid=os.geteuid())

    async def test_selected_cohort_consumes_claim_spawns_real_ready_children(self):
        startup = self._startup()
        capability = await startup.start(self.launch_inputs, startup_timeout_seconds=20)
        self.assertTrue(startup.validate_started_binding(capability))
        other_supervisor = RetirementSupervisor()
        other_startup = self._startup(other_supervisor)
        self.assertFalse(other_startup.validate_started_binding(capability))
        forged = StartedRootCohort(other_startup, capability._record, other_startup._seal)
        self.assertFalse(other_startup.validate_started_binding(forged),
                         "a copied record is not a supervisor-minted capability")
        expected_groups = len({item.launch_spec.launch_nonce for item in self.launch_inputs})
        self.assertEqual(len(self.retirement._owned), expected_groups)
        self.assertTrue(all(record.process.poll() is None
                            for record in self.retirement._owned))
        self.assertEqual(len(list(self.claim_root.glob("claim-*.json"))), 1)
        same_owner_retry = self._startup(self.retirement)
        with self.assertRaises(BindingError):
            await same_owner_retry.start(self.launch_inputs, startup_timeout_seconds=20)
        self.assertTrue(all(record.process.poll() is None
                            for record in self.retirement._owned),
                        "a rejected retry must not terminate a previously owned cohort")
        retry_supervisor = RetirementSupervisor()
        retry = self._startup(retry_supervisor)
        with self.assertRaises(BindingError):
            await retry.start(self.launch_inputs, startup_timeout_seconds=20)
        self.assertEqual(retry_supervisor._owned, [])
        self.assertTrue(all(record.process.poll() is None
                            for record in self.retirement._owned),
                        "a duplicate claim must not terminate another supervisor's live cohort")
        self.retirement.terminate_owned_generation(
            self.launch_inputs[0].launch_spec.generation_sha256, timeout_seconds=5)
        self.assertFalse(startup.validate_started_binding(capability),
                         "a historical READY capability is invalid after process exit")

    async def test_competing_startup_is_rejected_before_claim_or_fencing_winner(self):
        winner = self._startup()
        entered = threading.Event()
        release = threading.Event()
        outcome = {}
        original = winner._capture_selected

        def pause_after_reservation(store):
            entered.set()
            if not release.wait(5):
                raise TimeoutError("startup race fixture release timed out")
            return original(store)

        winner._capture_selected = pause_after_reservation

        def run_winner():
            try:
                outcome["capability"] = asyncio.run(winner.start(
                    self.launch_inputs, startup_timeout_seconds=20))
            except BaseException as error:
                outcome["error"] = error

        thread = threading.Thread(target=run_winner, daemon=True)
        thread.start()
        try:
            self.assertTrue(entered.wait(5), "first startup did not reserve supervisor")
            loser = self._startup()
            with self.assertRaises(BindingError):
                await loser.start(self.launch_inputs, startup_timeout_seconds=20)
            self.assertEqual(list(self.claim_root.glob("claim-*.json")), [],
                             "losing race must not write a claim or fence winner")
            self.assertEqual(self.retirement._fenced_generations, set())
        finally:
            release.set()
            thread.join(timeout=25)
        self.assertFalse(thread.is_alive(), "winning startup thread did not finish")
        if "error" in outcome:
            raise outcome["error"]
        self.assertTrue(winner.validate_started_binding(outcome["capability"]))

    async def test_invalid_manifest_fails_before_claim_or_popen(self):
        manifest = self.launch_roots[0] / "launcher.json"
        original = json.loads(manifest.read_bytes())
        for malformed in (b"{}", canonical_json({**original, "unexpected": "field"})):
            with self.subTest(manifest=malformed[:2]):
                manifest.write_bytes(malformed)
                os.chmod(manifest, 0o600)
                startup = self._startup()
                with self.assertRaises(BindingError):
                    await startup.start(self.launch_inputs, startup_timeout_seconds=20)
                self.assertEqual(self.retirement._owned, [])
                self.assertEqual(list(self.claim_root.glob("claim-*.json")), [])
                self.assertEqual(startup._started, [])

    async def test_incomplete_or_extra_selected_role_inputs_fail_before_claim(self):
        startup = self._startup()
        for batch in (self.launch_inputs[:-1], self.launch_inputs + (
                _launch(_spec(device_id="dev_" + "9" * 32, role="host",
                              serial="f" * 40, boot_id="9" * 32,
                              launch_nonce="9" * 32),
                        manifest=str(self.launch_roots[0] / "launcher.json"),
                        root=str(self.launch_roots[0]),
                        config=str(self.launch_roots[0] / "config.json")),)):
            with self.subTest(batch_size=len(batch)):
                with self.assertRaises(BindingError):
                    await startup.start(batch, startup_timeout_seconds=20)
                self.assertEqual(self.retirement._owned, [])
                self.assertEqual(list(self.claim_root.glob("claim-*.json")), [])

    async def test_wrong_real_child_ready_nonce_consumes_claim_and_cleans_owner(self):
        def wrong_nonce(source):
            text = source.decode("utf-8")
            text = text.replace('"launch_nonce": roles[0]["launch_nonce"]',
                                '"launch_nonce": "f" * 32')
            return text.encode("utf-8")
        self._replace_child_script(0, wrong_nonce)
        startup = self._startup()
        with self.assertRaises(BindingError):
            await startup.start(self.launch_inputs, startup_timeout_seconds=20)
        self.assertTrue(list(self.claim_root.glob("claim-*.json")))
        self.assertEqual(startup._started, [])
        generation = self.launch_inputs[0].launch_spec.generation_sha256
        self.assertIn(generation, self.retirement._fenced_generations)
        self.assertEqual(len(self.retirement._owned), 2,
                         "both groups are spawned before either READY is awaited")
        self.assertTrue(all(item.process.poll() is not None
                            and self.retirement._group_absent(item.pgid)
                            for item in self.retirement._owned))

    async def test_second_spawn_failure_consumes_whole_claim_and_cleans_first_owner(self):
        groups = RootCohortStartup._group_launches(self.launch_inputs)
        self.assertEqual(len(groups), 2)
        second_root = Path(groups[1].manifest_path).parent
        original_script = (second_root / "worker.py").read_bytes()
        original_manifest = (second_root / "launcher.json").read_bytes()
        def fault(label):
            if label == "claim.root.fsync":
                path = second_root / "worker.py"
                path.write_bytes(original_script + b"\n# changed after preflight\n")
                os.chmod(path, 0o600)
        self.claims._fault_hook = fault
        startup = self._startup()
        with self.assertRaises(BindingError):
            await startup.start(self.launch_inputs, startup_timeout_seconds=20)
        self.assertEqual(len(list(self.claim_root.glob("claim-*.json"))), 1)
        self.assertEqual(len(self.retirement._owned), 1,
                         "first child must be registered before second launch is checked")
        generation = self.launch_inputs[0].launch_spec.generation_sha256
        self.assertIn(generation, self.retirement._fenced_generations)
        self.assertTrue(all(item.process.poll() is not None
                            and self.retirement._group_absent(item.pgid)
                            for item in self.retirement._owned))
        (second_root / "worker.py").write_bytes(original_script)
        os.chmod(second_root / "worker.py", 0o600)
        (second_root / "launcher.json").write_bytes(original_manifest)
        os.chmod(second_root / "launcher.json", 0o600)
        retry_supervisor = RetirementSupervisor()
        with self.assertRaises(BindingError):
            await self._startup(retry_supervisor).start(
                self.launch_inputs, startup_timeout_seconds=20)
        self.assertEqual(retry_supervisor._owned, [],
                         "partial claim must block retry before another Popen")

    async def test_launcher_io_crossing_deadline_cannot_spawn_late_second_child(self):
        groups = RootCohortStartup._group_launches(self.launch_inputs)
        self.assertEqual(len(groups), 2)
        second_manifest = str(Path(groups[1].manifest_path))
        claim_written = False
        def mark_claim(label):
            nonlocal claim_written
            if label == "claim.root.fsync":
                claim_written = True
        self.claims._fault_hook = mark_claim
        original = self.retirement._load_manifest
        advanced = False
        offset = 0.0
        real_monotonic = time.monotonic

        def controlled_monotonic():
            return real_monotonic() + offset

        def slow_second_manifest(path, *args, **kwargs):
            nonlocal advanced, offset
            result = original(path, *args, **kwargs)
            if claim_written and not advanced and str(Path(path)) == second_manifest:
                advanced = True
                offset = 21.0
            return result

        self.retirement._load_manifest = slow_second_manifest
        startup = self._startup()
        with mock.patch.object(startup_module, "_startup_monotonic", controlled_monotonic):
            with self.assertRaises(TimeoutError):
                await startup.start(self.launch_inputs, startup_timeout_seconds=20,
                                    cleanup_timeout_seconds=5)
        self.assertTrue(advanced, "the final protected launcher read must cross deadline")
        self.assertTrue(list(self.claim_root.glob("claim-*.json")))
        self.assertEqual(len(self.retirement._owned), 1,
                         "the second process must not be created after launcher I/O")
        self.assertTrue(all(item.process.poll() is not None
                            and self.retirement._group_absent(item.pgid)
                            for item in self.retirement._owned))
        self.assertIn(self.launch_inputs[0].launch_spec.generation_sha256,
                      self.retirement._fenced_generations)

    async def test_valid_launcher_replacement_after_claim_cannot_mint_capability(self):
        groups = RootCohortStartup._group_launches(self.launch_inputs)
        self.assertEqual(len(groups), 2)
        second_root = Path(groups[1].manifest_path).parent
        original_script = (second_root / "worker.py").read_bytes()
        def fault(label):
            if label == "claim.root.fsync":
                path = second_root / "worker.py"
                changed = original_script + b"\n# owner changed launcher after claim\n"
                path.write_bytes(changed)
                os.chmod(path, 0o600)
                manifest_path = second_root / "launcher.json"
                manifest = json.loads(manifest_path.read_bytes())
                manifest["script_sha256"] = hashlib.sha256(changed).hexdigest()
                manifest_path.write_bytes(canonical_json(manifest))
                os.chmod(manifest_path, 0o600)
        self.claims._fault_hook = fault
        startup = self._startup()
        with self.assertRaises(BindingError):
            await startup.start(self.launch_inputs, startup_timeout_seconds=20)
        self.assertEqual(len(list(self.claim_root.glob("claim-*.json"))), 1)
        self.assertEqual(startup._started, [])
        self.assertEqual(len(self.retirement._owned), 1,
                         "changed second launcher must be rejected before its Popen")
        generation = self.launch_inputs[0].launch_spec.generation_sha256
        self.assertIn(generation, self.retirement._fenced_generations)
        self.assertTrue(all(item.process.poll() is not None
                            and self.retirement._group_absent(item.pgid)
                            for item in self.retirement._owned))

    async def test_cancel_during_real_ready_wait_consumes_and_cleans_cohort(self):
        def wait_before_ready(source):
            return source.replace(
                b'packet = {"schema_version": 1, "event": "root_role_ready",',
                b'time.sleep(30)\npacket = {"schema_version": 1, "event": "root_role_ready",')
        self._replace_child_script(0, wait_before_ready)
        startup = self._startup()
        task = asyncio.create_task(startup.start(
            self.launch_inputs, startup_timeout_seconds=20, cleanup_timeout_seconds=10))
        deadline = asyncio.get_running_loop().time() + 5
        while not self.retirement._owned and asyncio.get_running_loop().time() < deadline:
            await asyncio.sleep(0.01)
        self.assertTrue(self.retirement._owned, "child did not become owned before READY wait")
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await asyncio.wait_for(task, timeout=12)
        self.assertTrue(list(self.claim_root.glob("claim-*.json")))
        self.assertEqual(startup._started, [])
        generation = self.launch_inputs[0].launch_spec.generation_sha256
        self.assertIn(generation, self.retirement._fenced_generations)
        self.assertTrue(all(item.process.poll() is not None
                            and self.retirement._group_absent(item.pgid)
                            for item in self.retirement._owned))

    async def test_missing_real_ready_times_out_then_cleans_owned_cohort(self):
        needle = b'os.write(1, json.dumps(packet, sort_keys=True, separators=(",", ":")).encode() + b"\\n")'
        def suppress_ready(source):
            return source.replace(needle, b"time.sleep(30)")
        self._replace_child_script(0, suppress_ready)
        startup = self._startup()
        with self.assertRaises(TimeoutError):
            await startup.start(self.launch_inputs, startup_timeout_seconds=20,
                                cleanup_timeout_seconds=5)
        self.assertTrue(list(self.claim_root.glob("claim-*.json")))
        self.assertEqual(startup._started, [])
        generation = self.launch_inputs[0].launch_spec.generation_sha256
        self.assertIn(generation, self.retirement._fenced_generations)
        self.assertTrue(all(item.process.poll() is not None
                            and self.retirement._group_absent(item.pgid)
                            for item in self.retirement._owned))

    async def test_late_grant_expiry_after_final_manifest_io_prevents_capability(self):
        startup = self._startup()
        original = self.retirement._load_manifest
        advanced = False
        def late_manifest(*args):
            nonlocal advanced
            result = original(*args)
            if (not advanced and len(self.retirement._owned) == 2
                    and all(item.ready is not None for item in self.retirement._owned)):
                # Snapshot remains valid; only the selected grants have the
                # shorter wall and monotonic validity interval. This advance
                # stays inside the Clock discontinuity bound.
                self.fx.clock_source.advance(21)
                advanced = True
            return result
        self.retirement._load_manifest = late_manifest
        before = self.fixture.store.read_selected(validate=lambda *_: None).selector_sha256
        with self.assertRaises(CredentialError):
            await startup.start(self.launch_inputs, startup_timeout_seconds=20)
        self.assertTrue(advanced, "grant expiry must be injected after READY")
        after = self.fixture.store.read_selected(validate=lambda *_: None).selector_sha256
        self.assertEqual(before, after)
        self.assertTrue(list(self.claim_root.glob("claim-*.json")))
        self.assertEqual(startup._started, [])
        generation = self.launch_inputs[0].launch_spec.generation_sha256
        self.assertIn(generation, self.retirement._fenced_generations)
        self.assertTrue(all(item.process.poll() is not None
                            and self.retirement._group_absent(item.pgid)
                            for item in self.retirement._owned))


if __name__ == "__main__":
    unittest.main()
