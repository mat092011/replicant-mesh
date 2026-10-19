"""Fixed-profile root-worker CLI framing and protected binding tests."""

from __future__ import annotations

import json
import hashlib
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import tests.security.test_root_runtime as root_runtime_fixture
import tests.security.test_root_transition_policy as policy_fixture
import tests.security.test_root_transition_issuance as issuance_fixture
from lab.root_worker import (
    MAX_ROLE_SPEC_INPUT_BYTES,
    RootWorkerError,
    _parse_arguments,
    _run_root_worker,
    parse_host_launch_spec_input,
    root_role_ready_packet,
)
from lab.secure_worker_config import WorkerConfigError, parse_config_bytes
from steamboat_security.codec import canonical_json
from steamboat_security.errors import SnapshotError
from steamboat_security.root_transition_launch import role_launch_document
from steamboat_security.root_transition_storage import RootGenerationStore
from steamboat_runtime.manifest import MODEL_ID, MODEL_REVISION


def _host_spec():
    return root_runtime_fixture.RoleLaunchSpec(
        "a" * 64, "acct_" + "1" * 32, "dev_" + "2" * 32, "host",
        "abc123", "b" * 64, "c" * 64, 1, "d" * 32, 1, "e" * 64, "f" * 32)


class RootWorkerInputTests(unittest.TestCase):
    def test_one_canonical_host_spec_requires_newline_and_eof(self):
        spec = _host_spec()
        encoded = canonical_json([role_launch_document(spec)]) + b"\n"
        self.assertEqual(parse_host_launch_spec_input(encoded), spec)
        for malformed in (encoded[:-1], encoded + b"\n", b" " + encoded,
                          encoded[:-1] + b" \\n"):
            with self.subTest(malformed=malformed[:20]):
                with self.assertRaises(RootWorkerError):
                    parse_host_launch_spec_input(malformed)

    def test_rejects_renewal_shapes_duplicates_numbers_and_wrong_role(self):
        spec = _host_spec()
        canonical = canonical_json([role_launch_document(spec)])
        cases = (
            canonical.replace(b'"role":"host"', b'"role":"consumer"'),
            canonical.replace(b'"credential_epoch":1', b'"credential_epoch":1.0'),
            canonical.replace(b'"credential_epoch":1', b'"credential_epoch":true'),
            canonical.replace(b'"role":"host"', b'"role":"host","role":"host"'),
            canonical_json({"domain": "ordinary_renewal", "version": 1}),
        )
        for raw in cases:
            with self.subTest(raw=raw[:80]):
                with self.assertRaises(RootWorkerError):
                    parse_host_launch_spec_input(raw + b"\n")

    def test_rejects_input_over_16k_and_extra_cli_arguments(self):
        with self.assertRaises(RootWorkerError):
            parse_host_launch_spec_input(b"[" + b" " * MAX_ROLE_SPEC_INPUT_BYTES + b"]\n")
        valid_path = str(Path.cwd() / "protected" / "role.json")
        self.assertEqual(_parse_arguments(["--config", valid_path]), valid_path)
        for args in ([], ["--config"], ["--config", "relative.json"],
                     ["--config", "/protected/role.json", "--plugin"]):
            with self.subTest(args=args):
                with self.assertRaises(RootWorkerError):
                    _parse_arguments(args)

    def test_actual_isolated_python_invocation_fails_closed_with_fixed_packet(self):
        script = Path(__file__).resolve().parents[2] / "lab" / "root_worker.py"
        config = str(Path.cwd() / "missing-protected-header.json")
        completed = subprocess.run(
            [sys.executable, "-I", str(script), "--config", config],
            input=b"", stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=10, check=False)
        self.assertEqual(completed.returncode, 1)
        self.assertEqual(completed.stdout,
            b'{"category":"startup_rejected","event":"root_role_startup_failed",'
            b'"schema_version":1}\n')
        self.assertEqual(completed.stderr, b"")

    def test_ready_frame_is_canonical_fixed_schema_and_not_a_claim(self):
        spec = _host_spec()
        packet = root_role_ready_packet(spec)
        self.assertTrue(packet.endswith(b"\n"))
        value = json.loads(packet[:-1])
        self.assertEqual(set(value), {"schema_version", "event", "launch_nonce", "roles"})
        self.assertEqual(value["schema_version"], 1)
        self.assertEqual(value["event"], "root_role_ready")
        self.assertEqual(value["launch_nonce"], spec.launch_nonce)
        self.assertEqual(value["roles"], [role_launch_document(spec)])
        self.assertEqual(packet[:-1], canonical_json(value))


class RootWorkerProtectedBindingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # The shared transition fixtures use a historical timestamp. Give this
        # isolated fixture class credentials valid for the real system Clock.
        # Leave margin for Clock.system's conservative uncertainty floor.
        cls.fixture_now = int(time.time()) - 1
        cls.issuance_type = type(
            "CurrentTimeRootTransitionIssuanceTests",
            (issuance_fixture.RootTransitionIssuanceTests,), {})
        with mock.patch.object(issuance_fixture, "NOW", cls.fixture_now):
            with mock.patch.object(issuance_fixture.MutableClock.__init__,
                                   "__defaults__", (cls.fixture_now,)):
                cls.issuance_type.setUpClass()
        cls.fixture_module = SimpleNamespace(
            NOW=cls.fixture_now,
            RootTransitionIssuanceTests=cls.issuance_type,
        )

    def setUp(self):
        self.case = object.__new__(root_runtime_fixture.RootRuntimeProtectedBindingTests)
        with mock.patch.object(policy_fixture, "issuance_fixture", self.fixture_module):
            with mock.patch.object(root_runtime_fixture, "issuance_fixture",
                                   self.fixture_module):
                with mock.patch.object(issuance_fixture, "NOW", self.fixture_now):
                    with mock.patch.object(issuance_fixture.MutableClock.__init__,
                                           "__defaults__", (self.fixture_now,)):
                        root_runtime_fixture.RootRuntimeProtectedBindingTests.setUp(self.case)
        if self.case.store is not None:
            self.case.store.close()
        self.case.temp.cleanup()
        self.case.temp = tempfile.TemporaryDirectory()
        self.case.base = Path(self.case.temp.name)
        self.case.root = self.case.base / "selected-root"
        self.case.config_root = self.case.base / "config"
        self.case.root.mkdir(mode=0o700)
        self.case.config_root.mkdir(mode=0o700)
        os.chmod(self.case.root, 0o700)
        os.chmod(self.case.config_root, 0o700)

        original = self.case.fx.candidate
        principal = next(p for p in self.case.fx.intent.affected_principals
                         if p.role == "host")
        new_spec = next(x for x in original.new_launch_specs
                        if x.identity == principal.identity)
        issued = next(x for x in original.issuance_candidate.principals
                      if x.identity == principal.identity)
        grants = json.loads(original.policy_payload)["grants"]
        grant = next(g for g in grants if g["target_serial"] == issued.record.serial)
        ip = issued.record.ip_sans[0] if issued.record.ip_sans else "192.168.42.22"
        runtime_config = {
            "schema_version": 1,
            "protected_root": str(self.case.config_root),
            "account_id": principal.account_id,
            "device_id": principal.device_id,
            "boot_id": new_spec.boot_id,
            "assignment_id": grant["assignment_id"],
            "worker_name": "worker-1",
            "model_id": MODEL_ID,
            "model_revision": MODEL_REVISION,
            "manifest_fingerprint": grant["model_id"],
            "listen_ip": ip,
            "listen_port": 43127,
            "clock_uncertainty_seconds": 0.25,
            "certificate_path": str(self.case.config_root / "leaf.pem"),
            "private_key_path": str(self.case.config_root / "role-key.pem"),
            "cohort_ca_path": str(self.case.config_root / "ca.pem"),
            "snapshot_verification_key_path": str(self.case.config_root / "snapshot.pub.pem"),
            "signed_snapshot_path": str(self.case.config_root / "snapshot.json"),
            "artifact_directory": str(self.case.base / "artifacts"),
            "acceptor_directory": str(self.case.base / "acceptor"),
            "status_report_path": str(self.case.config_root / "status.json"),
        }
        self.case.runtime = canonical_json(runtime_config)
        self.runtime = self.case.runtime
        self.config = parse_config_bytes(
            self.case.runtime, config_path=self.case.config_root / "runtime.json")
        fixture_canonical = root_runtime_fixture.canonical_json

        def preserve_runtime(value):
            if type(value) is dict and value == {"fixed_adapter": "host-v1"}:
                return self.case.runtime
            return fixture_canonical(value)

        with mock.patch.object(root_runtime_fixture, "canonical_json",
                               side_effect=preserve_runtime):
            with mock.patch.object(policy_fixture, "issuance_fixture", self.fixture_module):
                with mock.patch.object(root_runtime_fixture, "issuance_fixture",
                                       self.fixture_module):
                    with mock.patch.object(issuance_fixture, "NOW", self.fixture_now):
                        with mock.patch.object(issuance_fixture.MutableClock.__init__,
                                               "__defaults__", (self.fixture_now,)):
                            self.case._prepare_candidate_and_root()
        self.assertEqual(self.case.runtime, self.runtime)
        self.spec_input = canonical_json([role_launch_document(self.case.spec)]) + b"\n"
        self.case.store = (RootGenerationStore(self.case.root, expected_uid=os.geteuid())
                           if os.name == "posix" and hasattr(os, "O_NOFOLLOW") else None)

    def tearDown(self):
        self.case.tearDown()

    def test_runtime_configuration_rejects_missing_or_unhealthy_clock_bounds(self):
        for uncertainty in (0, 30.1, True, float("inf")):
            with self.subTest(uncertainty=uncertainty):
                values = json.loads(self.case.runtime)
                values["clock_uncertainty_seconds"] = uncertainty
                raw = json.dumps(values, sort_keys=True, separators=(",", ":")).encode()
                with self.assertRaises(WorkerConfigError):
                    parse_config_bytes(raw,
                        config_path=self.case.config_root / "runtime.json")

    def test_worker_status_path_cannot_replace_the_role_header(self):
        if self.case.store is None:
            self.skipTest("root worker protected binding requires POSIX no-follow support")
        values = json.loads(self.runtime)
        values["status_report_path"] = str(self.case.config_path)
        runtime = canonical_json(values)
        self.case.runtime_path.write_bytes(runtime)
        os.chmod(self.case.runtime_path, 0o600)
        header = dict(self.case.header)
        header["runtime_configuration_sha256"] = hashlib.sha256(runtime).hexdigest()
        self.case.config_path.write_bytes(canonical_json(header))
        os.chmod(self.case.config_path, 0o600)
        with mock.patch("steamboat_security.root_transition_storage.RootGenerationStore") as store:
            with self.assertRaises(RootWorkerError):
                _run_root_worker(str(self.case.config_path), self.spec_input)
        store.assert_not_called()

    def test_real_protected_crypto_binding_reuses_clock_store_and_config(self):
        if self.case.store is None:
            self.skipTest("root worker protected binding requires POSIX no-follow support")
        from steamboat_security.clock import Clock
        from steamboat_security.root_runtime import load_root_runtime_binding
        captured = {}
        clock_args = {}

        def observe_binding(**kwargs):
            clock_args["clock"] = kwargs["clock"]
            return load_root_runtime_binding(**kwargs)

        async def fake_serve(config, *, root_binding, root_ready_callback):
            captured.update(config=config, binding=root_binding, ready=root_ready_callback)
            return 0

        with mock.patch("lab.secure_worker.serve", fake_serve):
            with mock.patch("steamboat_security.root_runtime.load_root_runtime_binding",
                            side_effect=observe_binding):
                result = _run_root_worker(str(self.case.config_path), self.spec_input)
        self.assertEqual(result, 0)
        self.assertIs(type(captured["config"]), type(self.config))
        self.assertEqual(captured["config"], self.config)
        binding = captured["binding"]
        self.assertIs(type(binding.snapshot_store.clock), Clock)
        self.assertIs(binding.snapshot_store.clock, clock_args["clock"])
        self.assertAlmostEqual(binding.snapshot_store.clock.sample().uncertainty, 0.25)
        self.assertEqual(binding.configuration_header, canonical_json(self.case.header))
        self.assertEqual(binding.runtime_configuration, self.case.runtime)
        self.assertTrue(callable(captured["ready"]))
        with self.assertRaises(SnapshotError):
            binding.snapshot_store.install(binding.snapshot_store._encoded)

    def test_failure_from_serve_still_closes_the_caller_owned_root_store(self):
        if self.case.store is None:
            self.skipTest("root worker protected binding requires POSIX no-follow support")
        captured = {}

        async def failing_serve(config, *, root_binding, root_ready_callback):
            captured["binding"] = root_binding
            raise RuntimeError("private simulated failure")

        with mock.patch("lab.secure_worker.serve", failing_serve):
            with self.assertRaises(RuntimeError):
                _run_root_worker(str(self.case.config_path), self.spec_input)
        with self.assertRaises(SnapshotError):
            captured["binding"].snapshot_store.install(
                captured["binding"].snapshot_store._encoded)


if __name__ == "__main__":
    unittest.main()
