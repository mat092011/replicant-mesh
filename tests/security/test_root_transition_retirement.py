"""Protected-launch and real-child tests for POSIX retirement evidence."""

import asyncio
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import threading
import time
import unittest
from dataclasses import replace
from unittest import mock

from steamboat_security.codec import canonical_json
from steamboat_security.errors import BindingError
from steamboat_security.files import safe_write
from steamboat_security.root_transition_launch import (
    canonical_role_launch_digest, parse_role_launch_spec, role_launch_document,
)
from steamboat_security.root_transition_retirement import (
    MAX_LAUNCHER_MANIFEST_BYTES, MAX_READY_BYTES, PendingOwnedLaunch,
    RetirementCapability, RetirementSupervisor, parse_operator_launch_manifest,
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


_CHILD_SCRIPT = r'''import json, os, subprocess, sys, time
roles = json.loads(sys.stdin.buffer.readline().decode("utf-8"))
with open(sys.argv[2], "r", encoding="utf-8") as stream:
    config = json.load(stream)
packet = {"schema_version": 1, "event": "root_role_ready",
          "launch_nonce": roles[0]["launch_nonce"], "roles": roles}
mode = config.get("ready_mode")
if mode == "wrong_nonce":
    packet["launch_nonce"] = "f" * 32
elif mode == "missing_roles":
    packet["roles"] = []
elif mode == "extra_role":
    extra = dict(roles[0]); extra["device_id"] = "dev_" + "5" * 32
    packet["roles"] = sorted(roles + [extra], key=lambda item: (item["account_id"], item["device_id"], item["role"]))
elif mode == "stale_binding":
    packet["roles"][0]["configuration_sha256"] = "e" * 64
if mode != "missing_ready":
    os.write(1, json.dumps(packet, sort_keys=True, separators=(",", ":")).encode() + b"\n")
seconds = config.get("grandchild_seconds")
if seconds:
    code = "import time; time.sleep(" + repr(seconds) + ")"
    subprocess.Popen([sys.executable, "-c", code], stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                    start_new_session=False)
time.sleep(config.get("sleep_seconds", 30))
'''


def _manifest_document(executable, script, config, script_hash, config_hash,
                       executable_hash=None):
    executable = os.path.realpath(executable)
    return {
        "schema_version": 1,
        "containment_profile": "trusted_no_escape_v1",
        "executable_path": executable,
        "executable_sha256": executable_hash or hashlib.sha256(Path(executable).read_bytes()).hexdigest(),
        "script_path": script,
        "script_sha256": script_hash,
        "configuration_path": config,
        "configuration_sha256": config_hash,
        "argv": [executable, "-I", script, "--config", config],
    }


class _Fixture:
    def __init__(self, root, manifest_path, script_path, config_path):
        self.root = root
        self.manifest_path = manifest_path
        self.script_path = script_path
        self.config_path = config_path


class _ProtectedLaunchFixtureMixin:
    def _make_fixture(self, config_bytes, *, executable_hash=None):
        root = tempfile.mkdtemp(prefix="root-launch-")
        os.chmod(root, 0o700)
        script_path = os.path.join(root, "worker.py")
        config_path = os.path.join(root, "config.json")
        manifest_path = os.path.join(root, "launcher.json")
        script_bytes = _CHILD_SCRIPT.encode("utf-8")
        script_hash = hashlib.sha256(script_bytes).hexdigest()
        config_hash = hashlib.sha256(config_bytes).hexdigest()
        safe_write(script_path, script_bytes, root=root, expected_uid=os.geteuid(),
                   max_bytes=1024 * 1024)
        safe_write(config_path, config_bytes, root=root, expected_uid=os.geteuid(),
                   max_bytes=1024 * 1024)
        doc = _manifest_document(sys.executable, script_path, config_path,
                                 script_hash, config_hash, executable_hash)
        safe_write(manifest_path, canonical_json(doc), root=root,
                   expected_uid=os.geteuid(), max_bytes=MAX_LAUNCHER_MANIFEST_BYTES)
        fixture = _Fixture(root, manifest_path, script_path, config_path)
        self.fixtures.append(fixture)
        return fixture, config_hash

    async def _launch(self, *, config=None, base_specs=None, timeout=2):
        config = {"sleep_seconds": 30, **(config or {})}
        config_bytes = canonical_json(config)
        fixture, config_hash = self._make_fixture(config_bytes)
        base_specs = base_specs or (_spec(),)
        specs = tuple(replace(item, configuration_sha256=config_hash)
                      for item in base_specs)
        observed = await self.supervisor.launch_owned_process(
            fixture.manifest_path, protected_root=fixture.root,
            expected_uid=os.geteuid(), specs=specs,
            ready_timeout_seconds=timeout)
        return specs, observed, fixture

    def _spawn(self, *, config=None, base_specs=None):
        config = {"sleep_seconds": 30, **(config or {})}
        config_bytes = canonical_json(config)
        fixture, config_hash = self._make_fixture(config_bytes)
        base_specs = base_specs or (_spec(),)
        specs = tuple(replace(item, configuration_sha256=config_hash)
                      for item in base_specs)
        pending = self.supervisor.spawn_owned_process(
            fixture.manifest_path, protected_root=fixture.root,
            expected_uid=os.geteuid(), specs=specs)
        return specs, pending, fixture

    def _cleanup_owned(self):
        generations = {spec.generation_sha256 for record in self.supervisor._owned
                       for spec in record.specs}
        for generation in generations:
            if any(record.process.poll() is None for record in self.supervisor._owned
                   if any(spec.generation_sha256 == generation for spec in record.specs)):
                self.supervisor.terminate_owned_generation(generation)
        for record in self.supervisor._owned:
            if record.process.stdout:
                record.process.stdout.close()
            if record.process.stdin and not record.process.stdin.closed:
                record.process.stdin.close()

    def _remove_fixtures(self):
        for fixture in self.fixtures:
            for name in ("launcher.json", "worker.py", "config.json"):
                try:
                    os.unlink(os.path.join(fixture.root, name))
                except FileNotFoundError:
                    pass
            os.rmdir(fixture.root)


class OperatorLaunchManifestBoundaryTests(_ProtectedLaunchFixtureMixin, unittest.TestCase):
    @staticmethod
    def _document():
        executable = os.path.abspath(os.path.join(os.sep, "opt", "trusted", "python"))
        script = os.path.abspath(os.path.join(os.sep, "opt", "trusted", "worker.py"))
        config = os.path.abspath(os.path.join(os.sep, "opt", "trusted", "config.json"))
        return _manifest_document(executable, script, config, "a" * 64, "b" * 64,
                                 executable_hash="c" * 64)

    def test_manifest_closed_schema_and_exact_python_isolated_argv(self):
        raw = self._document()
        manifest = parse_operator_launch_manifest(canonical_json(raw))
        self.assertEqual(manifest.argv,
                         (manifest.executable_path, "-I", manifest.script_path,
                          "--config", manifest.configuration_path))
        self.assertEqual(manifest.configuration_sha256, "b" * 64)

    def test_manifest_rejects_duplicate_boolean_alias_and_argv_substitution(self):
        raw = self._document()
        with self.assertRaises(BindingError):
            parse_operator_launch_manifest(b'{"schema_version":1,"schema_version":1}')
        raw["schema_version"] = True
        with self.assertRaises(BindingError):
            parse_operator_launch_manifest(canonical_json(raw))
        raw["schema_version"] = 1
        raw["argv"][1] = "-c"
        with self.assertRaises(BindingError):
            parse_operator_launch_manifest(canonical_json(raw))
        with self.assertRaises(BindingError):
            parse_operator_launch_manifest(b" " * (MAX_LAUNCHER_MANIFEST_BYTES + 1))


@unittest.skipUnless(os.name == "posix" and os.path.isdir("/proc"),
                     "requires native POSIX /proc process-group semantics")
class RootTransitionRetirementProcessTests(
        _ProtectedLaunchFixtureMixin, unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.supervisor = RetirementSupervisor()
        self.fixtures = []

    def tearDown(self):
        self._cleanup_owned()
        self._remove_fixtures()

    async def test_live_group_blocks_then_confirmed_exit_mints_capability(self):
        specs, observed, _ = await self._launch()
        self.assertTrue(self.supervisor.validate_observed_launch(observed))
        digest = canonical_role_launch_digest(specs)
        waiting = asyncio.create_task(self.supervisor.retire_cohort(
            "5" * 32, digest, timeout_seconds=2))
        await asyncio.sleep(0.1)
        self.assertFalse(waiting.done(), "live owned process must block retirement")
        self.assertFalse(self.supervisor.validate_observed_launch(observed),
                         "fenced generation cannot be considered live-ready")
        self.supervisor.terminate_owned_process_group(observed._record.process)
        capability = await waiting
        self.assertTrue(self.supervisor.validate_retirement_capability(
            capability, transition_id="5" * 32,
            expected_old_bindings_digest=digest))
        self.assertFalse(self.supervisor.validate_retirement_capability(
            capability, transition_id="6" * 32,
            expected_old_bindings_digest=digest))

    async def test_pre_spawn_fence_rejects_without_creating_a_child(self):
        old_specs, observed, _ = await self._launch()
        process = observed._record.process
        self.supervisor.terminate_owned_process_group(process)
        digest = canonical_role_launch_digest(old_specs)
        await self.supervisor.retire_cohort("6" * 32, digest, timeout_seconds=2)
        count = len(self.supervisor._owned)
        with self.assertRaises(BindingError):
            await self._launch(base_specs=(_spec(),))
        self.assertEqual(len(self.supervisor._owned), count,
                         "fenced generation must be rejected before Popen")

    async def test_multiple_roles_share_one_verified_process(self):
        second = _spec(device_id="dev_" + "5" * 32, role="consumer",
                       serial="def456", launch_nonce="4" * 32)
        specs, observed, _ = await self._launch(base_specs=(_spec(), second))
        self.assertEqual(len(observed._record.specs), 2)
        self.assertTrue(self.supervisor.validate_observed_launch(observed))
        self.supervisor.terminate_owned_process_group(observed._record.process)
        digest = canonical_role_launch_digest(specs)
        await self.supervisor.retire_cohort("7" * 32, digest, timeout_seconds=2)

    async def test_synchronous_spawns_register_before_ready_observation(self):
        second = _spec(device_id="dev_" + "5" * 32, role="consumer",
                       serial="def456", boot_id="5" * 32, launch_nonce="6" * 32)
        config_bytes = canonical_json({"sleep_seconds": 30})
        fixture, config_hash = self._make_fixture(config_bytes)
        specs1 = (replace(_spec(), configuration_sha256=config_hash),)
        second = replace(second, configuration_sha256=config_hash)
        external_authority_lock = threading.Lock()
        # Model the caller contract: synchronous spawn/owner registration while
        # selected-root serialization is held; no READY await occurs in it.
        external_authority_lock.acquire()
        try:
            pending1 = self.supervisor.spawn_owned_process(
                fixture.manifest_path, protected_root=fixture.root,
                expected_uid=os.geteuid(), specs=specs1)
            pending2 = self.supervisor.spawn_owned_process(
                fixture.manifest_path, protected_root=fixture.root,
                expected_uid=os.geteuid(), specs=(second,))
            records = [item for item in self.supervisor._owned
                       if item.pending in (pending1, pending2)]
            self.assertEqual(len(records), 2)
            self.assertTrue(all(record.ready is None and not record.observation_attempted
                                for record in records))
        finally:
            external_authority_lock.release()
        ready1 = await self.supervisor.observe_ready(pending1, ready_timeout_seconds=2)
        ready2 = await self.supervisor.observe_ready(pending2, ready_timeout_seconds=2)
        self.assertTrue(self.supervisor.validate_observed_launch(ready1))
        self.assertTrue(self.supervisor.validate_observed_launch(ready2))
        with self.assertRaises(BindingError):
            await self.supervisor.observe_ready(pending1, ready_timeout_seconds=2)
        for ready in (ready1, ready2):
            self.supervisor.terminate_owned_process_group(ready._record.process)
        digest = canonical_role_launch_digest(specs1 + (second,))
        await self.supervisor.retire_cohort("b" * 32, digest, timeout_seconds=2)

    async def test_spawn_checks_owned_pipes_but_defers_full_executable_proof_until_ready(self):
        # The first check establishes only that the actual direct child is
        # registered in its own process group with the expected Popen and pipes.
        with mock.patch.object(
                self.supervisor, "_check_process",
                side_effect=AssertionError("full executable proof ran before READY")):
            specs, pending, _ = self._spawn()
        process = pending._record.process
        self.assertIs(pending._supervisor, self.supervisor)
        self.assertIs(pending._record.process, process)
        self.assertEqual(self.supervisor._check_owned_process(
            process, pending._record.manifest), (process.pid, process.pid))

        # READY parsing succeeds, but a failed full pinned-executable check
        # cannot mint an observed capability or discard the owned process.
        with mock.patch.object(
                self.supervisor, "_check_process",
                side_effect=BindingError("simulated full executable mismatch")):
            with self.assertRaisesRegex(BindingError, "full executable mismatch"):
                await self.supervisor.observe_ready(pending, ready_timeout_seconds=2)
        self.assertTrue(pending._record.observation_attempted)
        self.assertIsNone(pending._record.ready)
        self.assertTrue(any(item is pending._record for item in self.supervisor._owned))

    async def test_immediate_owner_check_failure_retains_spawned_child(self):
        config_bytes = canonical_json({"sleep_seconds": 30})
        fixture, config_hash = self._make_fixture(config_bytes)
        specs = (replace(_spec(), configuration_sha256=config_hash),)
        original_check = self.supervisor._check_owned_process

        def fail_after_real_owner_check(process, manifest, **kwargs):
            original_check(process, manifest, **kwargs)
            raise BindingError("immediate ownership check unavailable")

        with mock.patch.object(
                self.supervisor, "_check_owned_process",
                side_effect=fail_after_real_owner_check):
            with self.assertRaisesRegex(BindingError, "immediate ownership check unavailable"):
                self.supervisor.spawn_owned_process(
                    fixture.manifest_path, protected_root=fixture.root,
                    expected_uid=os.geteuid(), specs=specs)
        self.assertEqual(len(self.supervisor._owned), 1)
        record = self.supervisor._owned[0]
        self.assertIsNotNone(record.process)
        self.assertIsNotNone(record.pending)
        self.assertEqual(record.pid, record.process.pid)

    async def test_pending_launch_is_bound_and_observation_is_one_shot(self):
        specs, pending, _ = self._spawn(config={"ready_mode": "missing_ready"})
        forged = PendingOwnedLaunch(self.supervisor, pending._record, object())
        with self.assertRaises(BindingError):
            await self.supervisor.observe_ready(forged, ready_timeout_seconds=1)
        other = RetirementSupervisor()
        with self.assertRaises(BindingError):
            await other.observe_ready(pending, ready_timeout_seconds=1)
        self.assertFalse(pending._record.observation_attempted)
        task = asyncio.create_task(self.supervisor.observe_ready(
            pending, ready_timeout_seconds=2))
        await asyncio.sleep(0.05)
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await task
        self.assertTrue(pending._record.observation_attempted)
        self.assertIsNone(pending._record.ready)
        with self.assertRaises(BindingError):
            await self.supervisor.observe_ready(pending, ready_timeout_seconds=1)
        self.assertTrue(any(record.process is pending._record.process
                            for record in self.supervisor._owned))

    async def test_unobserved_spawn_remains_owned_and_blocks_retirement(self):
        specs, pending, _ = self._spawn()
        digest = canonical_role_launch_digest(specs)
        with self.assertRaises(TimeoutError):
            await self.supervisor.retire_cohort("c" * 32, digest, timeout_seconds=0.1)
        self.assertIn(specs[0].generation_sha256, self.supervisor._fenced_generations)
        self.assertTrue(any(record.process is pending._record.process
                            for record in self.supervisor._owned))
        with self.assertRaises(BindingError):
            await self.supervisor.observe_ready(pending, ready_timeout_seconds=1)

    async def test_protected_script_config_and_executable_substitution_fail_pre_spawn(self):
        for which in ("script", "config", "executable"):
            fixture, _ = self._make_fixture(canonical_json({"sleep_seconds": 1}),
                                            executable_hash=("f" * 64 if which == "executable" else None))
            if which == "script":
                with open(fixture.script_path, "ab") as stream:
                    stream.write(b"# substituted\n")
            elif which == "config":
                with open(fixture.config_path, "ab") as stream:
                    stream.write(b" ")
            specs = (_spec(configuration_sha256=hashlib.sha256(
                canonical_json({"sleep_seconds": 1})).hexdigest()),)
            with self.subTest(which=which), self.assertRaises(BindingError):
                await self.supervisor.launch_owned_process(
                    fixture.manifest_path, protected_root=fixture.root,
                    expected_uid=os.geteuid(), specs=specs, ready_timeout_seconds=1)
            self.assertEqual(len(self.supervisor._owned), 0)

    async def test_frozen_expected_manifest_rejects_valid_replacement_before_spawn(self):
        config_bytes = canonical_json({"sleep_seconds": 30})
        fixture, config_hash = self._make_fixture(config_bytes)
        expected = parse_operator_launch_manifest(Path(fixture.manifest_path).read_bytes())
        script_path = Path(fixture.script_path)
        changed = script_path.read_bytes() + b"\n# changed after frozen preflight\n"
        script_path.write_bytes(changed)
        os.chmod(script_path, 0o600)
        manifest_path = Path(fixture.manifest_path)
        manifest = json.loads(manifest_path.read_bytes())
        manifest["script_sha256"] = hashlib.sha256(changed).hexdigest()
        manifest_path.write_bytes(canonical_json(manifest))
        os.chmod(manifest_path, 0o600)
        specs = (replace(_spec(), configuration_sha256=config_hash),)
        with self.assertRaisesRegex(BindingError, "frozen manifest"):
            self.supervisor.spawn_owned_process(
                fixture.manifest_path, protected_root=fixture.root,
                expected_uid=os.geteuid(), specs=specs,
                expected_manifest=expected)
        self.assertEqual(self.supervisor._owned, [],
                         "changed valid code must be rejected before Popen")

    async def test_pre_popen_check_requires_synchronous_exact_none(self):
        config_bytes = canonical_json({"sleep_seconds": 30})
        fixture, config_hash = self._make_fixture(config_bytes)
        specs = (replace(_spec(), configuration_sha256=config_hash),)

        async def asynchronous_check():
            return None

        for callback in (lambda: False, asynchronous_check):
            with self.subTest(callback=callback), self.assertRaises(BindingError):
                self.supervisor.spawn_owned_process(
                    fixture.manifest_path, protected_root=fixture.root,
                    expected_uid=os.geteuid(), specs=specs,
                    before_popen_check=callback)
        self.assertEqual(self.supervisor._owned, [],
                         "invalid pre-Popen checks cannot create a process")

    async def test_wrong_missing_extra_and_stale_ready_reject_and_retain_owner(self):
        for mode in ("wrong_nonce", "missing_roles", "extra_role", "stale_binding",
                     "missing_ready"):
            before = len(self.supervisor._owned)
            with self.subTest(mode=mode):
                with self.assertRaises((BindingError, TimeoutError)):
                    await self._launch(config={"ready_mode": mode}, timeout=0.15)
            self.assertEqual(len(self.supervisor._owned), before + 1)
            self.assertIsNone(self.supervisor._owned[-1].ready)

    async def test_cancelled_retirement_keeps_fence_and_owner(self):
        specs, observed, _ = await self._launch()
        digest = canonical_role_launch_digest(specs)
        task = asyncio.create_task(self.supervisor.retire_cohort(
            "8" * 32, digest, timeout_seconds=5))
        await asyncio.sleep(0.05)
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await task
        self.assertIn(specs[0].generation_sha256, self.supervisor._fenced_generations)
        self.assertTrue(any(record.process is observed._record.process
                            for record in self.supervisor._owned))
        with self.assertRaises(BindingError):
            await self._launch(base_specs=(_spec(),))

    async def test_exited_leader_with_live_grandchild_does_not_retire(self):
        specs, observed, _ = await self._launch(
            config={"sleep_seconds": 0.25, "grandchild_seconds": 0.8})
        process = observed._record.process
        self.assertEqual(process.wait(timeout=2), 0)
        digest = canonical_role_launch_digest(specs)
        with self.assertRaises(TimeoutError):
            await self.supervisor.retire_cohort("9" * 32, digest, timeout_seconds=0.1)
        self.assertIn(specs[0].generation_sha256, self.supervisor._fenced_generations)
        capability = await self.supervisor.retire_cohort(
            "9" * 32, digest, timeout_seconds=3)
        self.assertTrue(self.supervisor.validate_retirement_capability(
            capability, transition_id="9" * 32,
            expected_old_bindings_digest=digest))

    async def test_forged_cross_registry_and_dead_ready_capabilities_reject(self):
        specs, observed, _ = await self._launch()
        process = observed._record.process
        self.supervisor.terminate_owned_process_group(process)
        self.assertFalse(self.supervisor.validate_observed_launch(observed),
                         "READY is historical after process exit, not current liveness")
        digest = canonical_role_launch_digest(specs)
        capability = await self.supervisor.retire_cohort("a" * 32, digest, timeout_seconds=2)
        self.assertFalse(RetirementSupervisor().validate_retirement_capability(
            capability, transition_id="a" * 32, expected_old_bindings_digest=digest))
        forged = RetirementCapability(object(), object(), object())
        self.assertFalse(self.supervisor.validate_retirement_capability(
            forged, transition_id="a" * 32, expected_old_bindings_digest=digest))


def load_tests(loader, standard_tests, pattern):
    suite = unittest.TestSuite()
    suite.addTests(loader.loadTestsFromTestCase(OperatorLaunchManifestBoundaryTests))
    suite.addTests(loader.loadTestsFromTestCase(RootTransitionRetirementProcessTests))
    return suite


if __name__ == "__main__":
    unittest.main()
