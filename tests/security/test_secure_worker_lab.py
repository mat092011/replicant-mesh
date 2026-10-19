"""Local config, binding, and lifecycle checks for the nonproduction worker.

Tests that mutate owner policy use generated credentials and real signed
snapshots. Fixed fake bridge/status adapters check local lifecycle publication;
they do not establish TLS admission or remote inference.
"""

from __future__ import annotations

import ast
import asyncio
import copy
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
from types import SimpleNamespace
import tempfile
import time
import unittest
from unittest import mock

from dataclasses import asdict, replace

from lab.secure_worker import (
    _OwnedRuntime,
    _assert_worker_policy,
    _build_runtime,
    _enable_owner_controls,
    _handler_resource_status,
    _heartbeat_status_report,
    _owner_control_loop,
    _owner_requires_full_revocation,
    _verify_owner_removal_intent,
    _status_payload,
    _sanitize_bridge,
    _shutdown_components,
    _write_status_report,
    _validate_root_worker_binding,
    _same_worker_config_exact,
    _validated_root_launch_spec,
    serve,
    WorkerStatusUnavailable,
)
from lab.secure_worker_config import (
    SecureWorkerConfig,
    WorkerConfigError,
    load_worker_config,
    parse_config_bytes,
    validate_readonly_artifacts,
)
from steamboat_runtime.manifest import MODEL_ID, MODEL_REVISION


class SecureWorkerConfigTests(unittest.TestCase):
    def setUp(self):
        # Parser tests are filesystem-independent and avoid temp roots so they
        # can run in restricted Windows workspaces as well as Linux.
        self.root = Path.cwd().resolve()
        self.config_path = self.root / "worker.json"
        self.values = {
            "schema_version": 1,
            "protected_root": str(self.root),
            "account_id": "acct_" + "1" * 32,
            "device_id": "dev_" + "2" * 32,
            "boot_id": "3" * 32,
            "assignment_id": "asg_" + "4" * 32,
            "worker_name": "worker-1",
            "model_id": MODEL_ID,
            "model_revision": MODEL_REVISION,
            "manifest_fingerprint": "a" * 64,
            "listen_ip": "192.168.42.22",
            "listen_port": 43127,
            "clock_uncertainty_seconds": 0.25,
            "certificate_path": str(self.root / "host.crt.pem"),
            "private_key_path": str(self.root / "host.key.pem"),
            "cohort_ca_path": str(self.root / "cohort-ca.crt.pem"),
            "snapshot_verification_key_path": str(self.root / "snapshot.pub.pem"),
            "signed_snapshot_path": str(self.root / "snapshot.json"),
            "artifact_directory": str(self.root.parent / "artifacts"),
            # The production Unix socket gate limits this path to 70 bytes.
            "acceptor_directory": str(Path(self.root.anchor) / "sw-acceptor"),
            "status_report_path": str(self.root / "worker-status.json"),
        }

    def parse(self, values=None, raw=None):
        if raw is None:
            raw = json.dumps(values or self.values, sort_keys=True,
                             separators=(",", ":")).encode("utf-8")
        return parse_config_bytes(raw, config_path=self.config_path)

    def test_valid_closed_schema_keeps_exact_pins_and_numeric_endpoint(self):
        config = self.parse()
        self.assertIsInstance(config, SecureWorkerConfig)
        self.assertEqual(config.endpoint, "192.168.42.22:43127")
        self.assertEqual(config.device_id, self.values["device_id"])
        self.assertEqual(config.assignment_id, self.values["assignment_id"])
        self.assertEqual(config.model_revision, MODEL_REVISION)
        self.assertEqual(config.clock_uncertainty_seconds, 0.25)

    def test_unknown_missing_duplicate_and_nonfinite_values_are_rejected(self):
        unknown = dict(self.values, extra="not allowed")
        missing = dict(self.values)
        del missing["clock_uncertainty_seconds"]
        self.assertRaises(WorkerConfigError, self.parse, unknown)
        self.assertRaises(WorkerConfigError, self.parse, missing)
        duplicate = json.dumps(self.values).replace(
            '"schema_version": 1', '"schema_version": 1, "schema_version": 1', 1)
        self.assertRaises(WorkerConfigError, self.parse, raw=duplicate.encode("utf-8"))
        nonfinite = json.dumps(self.values).replace("0.25", "NaN")
        self.assertRaises(WorkerConfigError, self.parse, raw=nonfinite.encode("utf-8"))

    def test_ids_worker_model_and_revision_are_exact(self):
        for field, value in (
                ("account_id", "dev_" + "1" * 32),
                ("device_id", "dev_" + "A" * 32),
                ("boot_id", "0" * 31),
                ("assignment_id", "asg_" + "g" * 32),
                ("worker_name", "worker-4"),
                ("model_id", "another/model"),
                ("model_revision", "main"),
                ("manifest_fingerprint", "A" * 64)):
            candidate = dict(self.values, **{field: value})
            with self.subTest(field=field):
                self.assertRaises(WorkerConfigError, self.parse, candidate)

    def test_only_explicit_positive_clock_uncertainty_and_integer_port_are_accepted(self):
        for uncertainty in (0, -0.1, 30.0001, float("inf"), True):
            candidate = dict(self.values, clock_uncertainty_seconds=uncertainty)
            with self.subTest(uncertainty=uncertainty):
                self.assertRaises(WorkerConfigError, self.parse, candidate)
        for port in (0, 65536, True, 43127.0):
            candidate = dict(self.values, listen_port=port)
            with self.subTest(port=port):
                self.assertRaises(WorkerConfigError, self.parse, candidate)

    def test_only_one_private_numeric_ipv4_listener_is_accepted(self):
        for address in ("worker.example", "0.0.0.0", "203.0.113.10", "::1"):
            candidate = dict(self.values, listen_ip=address)
            with self.subTest(address=address):
                self.assertRaises(WorkerConfigError, self.parse, candidate)

    def test_secret_paths_cannot_escape_root_or_alias_and_report_stays_under_root(self):
        outside = dict(self.values, private_key_path=str(self.root.parent / "key.pem"))
        nested_report = dict(self.values,
                             status_report_path=str(self.root / "reports" / "status.json"))
        aliased = dict(self.values, private_key_path=self.values["certificate_path"])
        report_collisions = [
            dict(self.values, status_report_path=self.values[field])
            for field in (
                "certificate_path", "private_key_path", "cohort_ca_path",
                "snapshot_verification_key_path", "signed_snapshot_path",
                "acceptor_directory")
        ]
        report_collisions.append(dict(
            self.values, status_report_path=str(self.config_path)))
        for candidate in (outside, nested_report, aliased, *report_collisions):
            with self.subTest(candidate=candidate):
                self.assertRaises(WorkerConfigError, self.parse, candidate)

    def test_config_reader_requires_linux_owned_modes_and_no_follow_support(self):
        if os.name == "posix":
            with tempfile.TemporaryDirectory(prefix="secure-worker-config-") as directory:
                root = Path(directory).resolve()
                os.chmod(root, 0o700)
                config_path = root / "worker.json"
                values = dict(
                    self.values,
                    protected_root=str(root),
                    certificate_path=str(root / "host.crt.pem"),
                    private_key_path=str(root / "host.key.pem"),
                    cohort_ca_path=str(root / "cohort-ca.crt.pem"),
                    snapshot_verification_key_path=str(root / "snapshot.pub.pem"),
                    signed_snapshot_path=str(root / "snapshot.json"),
                    status_report_path=str(root / "worker-status.json"),
                )
                config_path.write_bytes(json.dumps(values).encode("utf-8"))
                os.chmod(config_path, 0o600)
                config = load_worker_config(config_path)
                self.assertEqual(config.protected_root, str(root))
                os.chmod(config_path, 0o644)
                self.assertRaises(WorkerConfigError, load_worker_config, config_path)
        else:
            self.assertRaises(WorkerConfigError, load_worker_config, self.config_path)

    @unittest.skipUnless(os.name == "posix", "descriptor-chain checks require POSIX no-follow support")
    def test_status_writer_rejects_symlinked_ancestors_and_symlink_targets(self):
        with tempfile.TemporaryDirectory(prefix="secure-worker-status-") as directory:
            root = Path(directory).resolve()
            os.chmod(root, 0o700)
            config = replace(
                self.parse(), protected_root=str(root),
                status_report_path=str(root / "worker-status.json"))
            actual_root = root / "actual-root"
            actual_root.mkdir(mode=0o700)
            os.chmod(actual_root, 0o700)
            alias_root = root / "root-alias"
            alias_root.symlink_to(actual_root, target_is_directory=True)
            aliased_config = replace(
                config, protected_root=str(alias_root),
                status_report_path=str(alias_root / "status.json"))
            from steamboat_security.errors import StorageError

            self.assertRaises(
                StorageError, _write_status_report, aliased_config,
                {"event": "status", "phase": "test"})

            protected_data = root / "protected-data.pem"
            protected_data.write_bytes(b"still protected")
            os.chmod(protected_data, 0o600)
            status_link = root / "worker-status.json"
            status_link.symlink_to(protected_data)
            symlink_config = replace(config, status_report_path=str(status_link))
            self.assertRaises(
                WorkerConfigError, _write_status_report, symlink_config,
                {"event": "status", "phase": "test"})
            self.assertEqual(protected_data.read_bytes(), b"still protected")

    def test_artifact_mount_statvfs_unit_seam_accepts_writable_mode_bits(self):
        """Mode bits alone do not establish or refute a kernel RO mount."""
        artifacts = Path(__file__).resolve().parents[2] / "lab"
        readable_files = [path for path in artifacts.iterdir() if path.is_file()]
        self.assertTrue(readable_files)
        self.assertTrue(any(
            stat.S_IMODE(path.stat().st_mode) & 0o222 for path in readable_files))

        class StatvfsResult:
            f_flag = 1

        with mock.patch.object(os, "ST_RDONLY", 1, create=True), \
                mock.patch("lab.secure_worker_config.os.statvfs",
                           return_value=StatvfsResult(), create=True):
            self.assertEqual(validate_readonly_artifacts(artifacts), artifacts.resolve())

        StatvfsResult.f_flag = 0
        with mock.patch.object(os, "ST_RDONLY", 1, create=True), \
                mock.patch("lab.secure_worker_config.os.statvfs",
                           return_value=StatvfsResult(), create=True):
            self.assertRaises(WorkerConfigError, validate_readonly_artifacts, artifacts)

    def test_artifact_validation_fails_closed_without_statvfs_support(self):
        artifacts = Path(__file__).resolve().parents[2] / "lab"
        with mock.patch.object(os, "ST_RDONLY", 1, create=True), \
                mock.patch("lab.secure_worker_config.os.statvfs", None, create=True):
            self.assertRaises(WorkerConfigError, validate_readonly_artifacts, artifacts)

    @unittest.skipUnless(os.name == "posix", "symlink checks require POSIX link support")
    def test_artifact_mount_check_rejects_symlinks_even_on_reported_ro_mount(self):
        with tempfile.TemporaryDirectory(prefix="secure-worker-artifacts-") as directory:
            artifacts = Path(directory).resolve()
            target = artifacts / "weight.bin"
            target.write_bytes(b"public fixture")
            link = artifacts / "weight-link.bin"
            link.symlink_to(target)

            class StatvfsResult:
                f_flag = 1

            with mock.patch.object(os, "ST_RDONLY", 1, create=True), \
                    mock.patch("lab.secure_worker_config.os.statvfs",
                               return_value=StatvfsResult()):
                self.assertRaises(WorkerConfigError, validate_readonly_artifacts, artifacts)


class SecureWorkerStatusTests(unittest.IsolatedAsyncioTestCase):
    @staticmethod
    def _config():
        return SecureWorkerConfig(
            protected_root="/protected", account_id="acct_" + "1" * 32,
            device_id="dev_" + "2" * 32, boot_id="3" * 32,
            assignment_id="asg_" + "4" * 32, worker_name="worker-1",
            model_id=MODEL_ID, model_revision=MODEL_REVISION,
            manifest_fingerprint="a" * 64, listen_ip="192.168.42.22",
            listen_port=43127, clock_uncertainty_seconds=0.25,
            certificate_path="/protected/host.crt.pem",
            private_key_path="/protected/host.key.pem",
            cohort_ca_path="/protected/cohort-ca.crt.pem",
            snapshot_verification_key_path="/protected/snapshot.pub.pem",
            signed_snapshot_path="/protected/snapshot.json",
            artifact_directory="/artifacts", acceptor_directory="/sw-acceptor",
            status_report_path="/protected/worker-status.json")

    @staticmethod
    def _handler():
        return SimpleNamespace(
            sessions={}, tombstones={}, _active_operation=None, _queue=(),
            requires_restart=False, stopping=False,
            limits={
                "max_sessions": 8, "max_positions": 1024,
                "worker_cache_positions": 8192,
                "worker_cache_bytes": 1_000_000,
                "max_message_bytes": 1_048_576,
            },
            max_tombstones=4096, queue_capacity=8, start=0, end=2,
        )

    @staticmethod
    def _healthy_bridge():
        class Bridge:
            def status(self):
                return {
                    "ready": True, "unavailable": False,
                    "requires_restart": False, "cleanup_confirmed": True,
                    "active_authorizations": 0, "owned_sessions": 0,
                    "pending_notices": 0, "fault": "",
                }
        return Bridge()

    def test_cache_status_counts_sessions_and_tombstones_once_by_entry_identity(self):
        class Cache:
            def __init__(self, allocated):
                self.allocated = allocated

            def allocated_bytes(self):
                return self.allocated

        live = SimpleNamespace(committed_bytes=12, cache=Cache(16), in_flight=False)
        retired = SimpleNamespace(committed_bytes=5, cache=Cache(8), in_flight=False)
        handler = SimpleNamespace(
            sessions={"ses_" + "1" * 32: live, "ses_" + "2" * 32: retired},
            tombstones={"ses_" + "2" * 32: retired},
            _active_operation=None,
            _queue=(),
            requires_restart=False,
            stopping=False,
            limits={
                "max_sessions": 8,
                "max_positions": 1024,
                "worker_cache_positions": 8192,
                "worker_cache_bytes": 1_000_000,
                "max_message_bytes": 1_048_576,
            },
            max_tombstones=4096,
            queue_capacity=8,
        )
        status = _handler_resource_status(handler)
        self.assertEqual(status["committed_cache_bytes"], 17)
        self.assertEqual(status["allocated_cache_bytes"], 24)
        self.assertEqual(status["retained_entries"], 2)
        self.assertEqual(status["tombstones"], 1)
        self.assertTrue(status["cache_bytes_exact"])

    def test_active_tombstone_or_unreadable_cache_cannot_report_exact_zero(self):
        class Cache:
            def allocated_bytes(self):
                return 0

        pending = SimpleNamespace(committed_bytes=6, cache=Cache(), in_flight=True)
        handler = SimpleNamespace(
            sessions={}, tombstones={"pending": pending}, _active_operation=None,
            _queue=(), requires_restart=False, stopping=False,
            limits={
                "max_sessions": 8, "max_positions": 1024,
                "worker_cache_positions": 8192, "worker_cache_bytes": 1_000_000,
                "max_message_bytes": 1_048_576,
            },
            max_tombstones=4096, queue_capacity=8,
        )
        active = _handler_resource_status(handler)
        self.assertTrue(active["active_compute"])
        self.assertFalse(active["cache_bytes_exact"])
        self.assertIsNone(active["committed_cache_bytes"])
        self.assertEqual(active["committed_cache_bytes_lower_bound"], 6)
        self.assertIsNone(active["allocated_cache_bytes"])

        class BrokenCache:
            def allocated_bytes(self):
                raise RuntimeError("not observable")

        pending.in_flight = False
        pending.cache = BrokenCache()
        unknown = _handler_resource_status(handler)
        self.assertEqual(unknown["state"], "unknown")
        self.assertFalse(unknown["cache_bytes_exact"])
        self.assertIsNone(unknown["committed_cache_bytes"])
        self.assertIsNone(unknown["committed_cache_bytes_lower_bound"])
        self.assertIsNone(unknown["allocated_cache_bytes"])

    async def test_heartbeat_reports_explicit_unavailability_then_fails_closed(self):
        config = self._config()
        stop_event = asyncio.Event()
        observed = []

        def record_report(_config, payload):
            observed.append(payload)
            stop_event.set()

        write = mock.patch("lab.secure_worker._write_status_report",
                           side_effect=record_report)
        class UnavailableBridge:
            def status(self):
                return {
                    "ready": False, "unavailable": True,
                    "requires_restart": True, "cleanup_confirmed": False,
                    "active_authorizations": 1, "owned_sessions": 1,
                    "pending_notices": 0, "fault": "redacted",
                }

        with write:
            task = asyncio.create_task(
                _heartbeat_status_report(
                    config, _OwnedRuntime(
                        bridge=UnavailableBridge(), handler=self._handler()),
                    stop_event, interval_seconds=0.01))
            with self.assertRaises(WorkerStatusUnavailable):
                await asyncio.wait_for(task, timeout=0.2)
        self.assertEqual(len(observed), 1)
        self.assertEqual(observed[0]["event"], "heartbeat")
        self.assertEqual(observed[0]["phase"], "unavailable")
        self.assertTrue(observed[0]["bridge"]["unavailable"])
        self.assertEqual(observed[0]["external_supervision"]["startup_watchdog_seconds"], 60)
        self.assertEqual(observed[0]["external_supervision"]["termination_watchdog_seconds"], 15)
        self.assertFalse(observed[0]["external_supervision"]["verified_by_worker"])
        self.assertNotIn("private_key_pem", observed[0])
        self.assertNotIn("redacted", json.dumps(observed[0]))

    async def _assert_unavailable_heartbeat(self, owned):
        observed = []
        config = self._config()
        stop_event = asyncio.Event()
        with mock.patch("lab.secure_worker._write_status_report",
                        side_effect=lambda _config, payload: observed.append(payload)):
            with self.assertRaises(WorkerStatusUnavailable):
                await asyncio.wait_for(
                    _heartbeat_status_report(
                        config, owned, stop_event, interval_seconds=0.001),
                    timeout=0.2)
        self.assertEqual(len(observed), 1)
        self.assertEqual(observed[0]["phase"], "unavailable")
        self.assertEqual(observed[0]["resource_state"], "unknown")
        return observed[0]

    async def test_heartbeat_raising_bridge_is_unknown_not_ready(self):
        class RaisingBridge:
            def status(self):
                raise RuntimeError("unreported implementation detail")

        status = await self._assert_unavailable_heartbeat(_OwnedRuntime(
            bridge=RaisingBridge(), handler=self._handler()))
        self.assertEqual(status["bridge"]["state"], "unknown")
        self.assertIsNone(status["bridge"]["active_authorizations"])
        self.assertIsNone(status["bridge"]["pending_notices"])

    async def test_heartbeat_unreadable_handler_cache_is_unknown_not_zero(self):
        class BrokenCache:
            calls = 0

            def allocated_bytes(self):
                self.calls += 1
                raise RuntimeError("unreadable cache")

        handler = self._handler()
        broken_cache = BrokenCache()
        handler.sessions = {"ses_" + "a" * 32: SimpleNamespace(
            committed_bytes=23, cache=broken_cache, in_flight=False)}
        status = await self._assert_unavailable_heartbeat(_OwnedRuntime(
            bridge=self._healthy_bridge(), handler=handler))
        self.assertGreater(broken_cache.calls, 0)
        self.assertEqual(status["bridge"]["state"], "observed")
        self.assertEqual(status["handler"]["state"], "unknown")
        self.assertIsNone(status["handler"]["active_sessions"])
        self.assertIsNone(status["handler"]["allocated_cache_bytes"])

    def test_bridge_status_missing_counter_stays_unknown_without_zero_default(self):
        class IncompleteBridge:
            def status(self):
                return {
                    "ready": True, "unavailable": False,
                    "requires_restart": False, "cleanup_confirmed": True,
                    "active_authorizations": 0, "owned_sessions": 0,
                    "fault": "",
                }

        status = _sanitize_bridge(IncompleteBridge())
        self.assertEqual(status["state"], "unknown")
        self.assertEqual(status["active_authorizations"], 0)
        self.assertEqual(status["owned_sessions"], 0)
        self.assertIsNone(status["pending_notices"])


class SecureWorkerPolicyGrantTests(unittest.TestCase):
    FINGERPRINT = "a" * 64

    def _fixture_type(self):
        root = Path(__file__).resolve().parents[2]
        src = root / "src"
        security_tests = Path(__file__).resolve().parent
        for path in (src, security_tests):
            if str(path) not in sys.path:
                sys.path.insert(0, str(path))
        from secure_pipeline_fixture import SecurePipelineIdentityFixture
        return SecurePipelineIdentityFixture

    def _worker_config(self, fixture, snapshot_path):
        host = fixture.principals["worker-1"]
        root = fixture.root
        return SecureWorkerConfig(
            protected_root=str(root), account_id=host.account_id,
            device_id=host.device_id, boot_id=host.boot_id,
            assignment_id=host.assignment_id, worker_name="worker-1",
            model_id=MODEL_ID, model_revision=MODEL_REVISION,
            manifest_fingerprint=self.FINGERPRINT,
            listen_ip="127.0.0.1", listen_port=43127,
            clock_uncertainty_seconds=fixture.clock_uncertainty_seconds,
            certificate_path=str(root / "worker-1.role.protected.crt.pem"),
            private_key_path=str(root / "worker-1.role.key.pem"),
            cohort_ca_path=str(root / "worker-cohort-ca.pem"),
            snapshot_verification_key_path=str(root / "worker-snapshot-key.pem"),
            signed_snapshot_path=str(snapshot_path),
            artifact_directory=str(root / "read-only-artifacts"),
            acceptor_directory=str(root / "worker-acceptor"),
            status_report_path=str(root / "worker-status.json"))

    def _matching_open_grant(self, payload, host):
        from steamboat_security.codec import WORKER_SERVICE

        matches = [grant for grant in payload["grants"]
                   if grant["target_account_id"] == host.account_id
                   and grant["target_device_id"] == host.device_id
                   and grant["target_role"] == "host"
                   and grant["target_serial"] == host.record["serial"]
                   and grant["target_public_key_sha256"]
                       == host.record["public_key_sha256"]
                   and grant["target_boot_id"] == host.boot_id
                   and grant["assignment_id"] == host.assignment_id
                   and grant["model_id"] == self.FINGERPRINT
                   and grant["method"] == f"{WORKER_SERVICE}/OpenSession"]
        self.assertEqual(len(matches), 1)
        return matches[0]

    @unittest.skipUnless(
        os.name == "posix",
        "real secure-worker policy construction requires POSIX protected-file semantics")
    def test_signed_expired_and_future_open_grants_reject_before_executor(self):
        SecurePipelineIdentityFixture = self._fixture_type()
        fixture = SecurePipelineIdentityFixture(
            self.FINGERPRINT, clock_uncertainty_seconds=30)
        self.addCleanup(fixture.close)
        from steamboat_runtime.protocol.worker_pb2 import Request
        from steamboat_runtime import worker_state
        from steamboat_runtime.manifest import load_manifest as actual_load_manifest
        from steamboat_security import Authorizer, LocalIdentity, SessionBindings
        from steamboat_security import sign_snapshot

        # Import the real worker module before patching manifest.load_manifest
        # below. worker_state holds its own imported function reference, and
        # importing it inside the patch would permanently capture the mock.
        self.assertIs(worker_state.load_manifest, actual_load_manifest)

        host = fixture.principals["worker-1"]
        # The fixture's public certificate is normally mode 0644. C0 safe_read
        # intentionally accepts only protected 0600 files, so give the worker
        # an owned copy without relaxing that production rule.
        fixture._write_private(
            "worker-1.role.protected.crt.pem", host.certificate_pem)
        fixture._write_private("worker-cohort-ca.pem", fixture.cohort_ca_pem)
        fixture._write_private(
            "worker-snapshot-key.pem", fixture.snapshot_verification_key_pem)
        original_payload = json.loads(fixture.signed_snapshot)["payload"]
        original_payload = copy.deepcopy(original_payload)
        original_grant = self._matching_open_grant(original_payload, host)

        # Verify the real signed view and active-grant boundary before creating
        # the deliberately inactive signed variants below.
        store, clock = fixture.new_store()
        sample = clock.sample()
        view = store.current(sample=sample)
        self.assertEqual(view.expires_at - view.issued_at, 300)
        credential = view.credential(host.record["serial"])
        self.assertEqual(credential.not_after - credential.not_before, 900)
        self.assertLessEqual(original_grant["not_before"], sample.earliest_wall)
        self.assertLess(sample.latest_wall, original_grant["not_after"])
        self.assertTrue(any(
            grant.target_account_id == host.account_id
            and grant.target_device_id == host.device_id
            and grant.target_serial == host.record["serial"]
            and grant.target_public_key_sha256 == host.record["public_key_sha256"]
            and grant.target_boot_id == host.boot_id
            and grant.assignment_id == host.assignment_id
            and grant.model_id == self.FINGERPRINT
            and grant.method.endswith("/OpenSession")
            for grant in view.active_grants(sample)))
        authorizer = Authorizer(
            local_identity=LocalIdentity(
                host.certificate_pem, host.boot_id, self.FINGERPRINT,
                host.assignment_id),
            snapshot_store=store, clock=clock,
            session_bindings=SessionBindings(clock=clock),
            worker_request_type=Request)
        base_snapshot_path = fixture.root / "base-snapshot.json"
        fixture._write_private("base-snapshot.json", fixture.signed_snapshot)
        base_config = self._worker_config(fixture, base_snapshot_path)
        _assert_worker_policy(base_config, authorizer)

        now = int(time.time())
        signing_key = (fixture.root / "snapshot-signing-root.key.pem").read_bytes()
        manifest = {
            "model_id": MODEL_ID,
            "revision": MODEL_REVISION,
            "fingerprint": self.FINGERPRINT,
            "limits": {"max_sessions": 8},
        }

        class StageExecutorReached(RuntimeError):
            pass

        positive_owner = _OwnedRuntime()
        torch_threads = SimpleNamespace(set_num_threads=mock.Mock())
        with mock.patch.dict(os.environ, {"OMP_NUM_THREADS": "2"}), \
                mock.patch.dict(sys.modules, {"torch": torch_threads}), \
                mock.patch("lab.secure_worker.validate_readonly_artifacts") as artifact_check, \
                mock.patch("steamboat_runtime.manifest.load_manifest",
                           return_value=manifest) as manifest_loader, \
                mock.patch("steamboat_runtime.worker_state.StageExecutor",
                           side_effect=StageExecutorReached("construction seam reached")) as executor:
            with self.assertRaisesRegex(StageExecutorReached,
                                        "construction seam reached"):
                _build_runtime(base_config, positive_owner)
            artifact_check.assert_called_once_with(base_config.artifact_directory)
            manifest_loader.assert_called_once_with(base_config.artifact_directory)
            executor.assert_called_once_with(base_config.artifact_directory, "worker-1")
            torch_threads.set_num_threads.assert_called_once_with(2)
        self.assertIs(worker_state.load_manifest, actual_load_manifest)
        self.assertEqual(positive_owner.certificate_pem, host.certificate_pem)
        self.assertEqual(positive_owner.private_key_pem, host.private_key_pem)
        self.assertIsNotNone(positive_owner.authorizer)

        for label, start, stop in (
                ("expired", original_payload["issued_at"], now - 1),
                ("future", now + 60, now + 120)):
            with self.subTest(grant_state=label):
                payload = copy.deepcopy(original_payload)
                target = self._matching_open_grant(payload, host)
                target["not_before"] = start
                target["not_after"] = stop
                # The policy and leaf timestamps are unchanged; the new
                # signed snapshot remains within the actual C0 300 s lifetime.
                self.assertEqual(payload["expires_at"] - payload["issued_at"], 300)
                self.assertEqual(target["not_after"] - target["not_before"],
                                 (now - 1 - original_payload["issued_at"])
                                 if label == "expired" else 60)
                encoded = sign_snapshot(payload, signing_key)
                snapshot_name = f"{label}-snapshot.json"
                fixture._write_private(snapshot_name, encoded)
                config = self._worker_config(
                    fixture, fixture.root / snapshot_name)
                owner = _OwnedRuntime()
                with mock.patch("lab.secure_worker.validate_readonly_artifacts") as artifact_check, \
                        mock.patch("steamboat_runtime.manifest.load_manifest",
                                   return_value=manifest) as manifest_loader, \
                        mock.patch("steamboat_runtime.worker_state.StageExecutor") as executor:
                    with self.assertRaisesRegex(
                            WorkerConfigError,
                            "^signed snapshot has no exact worker boot/assignment grant$"):
                        _build_runtime(config, owner)
                    artifact_check.assert_called_once_with(config.artifact_directory)
                    manifest_loader.assert_called_once_with(config.artifact_directory)
                    executor.assert_not_called()


class SecureWorkerRootBindingTests(unittest.TestCase):
    def test_root_adapter_rejects_bool_integer_aliases_in_config_and_launch_spec(self):
        config = SecureWorkerStatusTests._config()
        self.assertFalse(_same_worker_config_exact(
            replace(config, listen_port=True), config))
        from steamboat_security.root_transition_launch import RoleLaunchSpec
        from steamboat_security.errors import BindingError
        forged = RoleLaunchSpec(
            generation_sha256="a" * 64, account_id="acct_" + "1" * 32,
            device_id="dev_" + "2" * 32, role="host", serial="abc123",
            certificate_sha256="b" * 64, public_key_sha256="c" * 64,
            credential_epoch=True, boot_id="3" * 32, admission_epoch=2,
            configuration_sha256="d" * 64, launch_nonce="4" * 32)
        with self.assertRaises(BindingError):
            _validated_root_launch_spec(forged)

    def test_root_binding_requires_exact_runtime_binding_before_artifact_load(self):
        config = SecureWorkerStatusTests._config()
        with self.assertRaisesRegex(
                WorkerConfigError, "^root mode requires an exact root runtime binding$"):
            _validate_root_worker_binding(config, SimpleNamespace())

    def test_ready_callback_is_rejected_on_legacy_entrypoint(self):
        async def run():
            config = SecureWorkerStatusTests._config()
            with self.assertRaisesRegex(
                    WorkerConfigError,
                    "^root READY callback is available only in root mode$"):
                await serve(config, root_ready_callback=lambda: None)
        asyncio.run(run())

    @unittest.skipUnless(
        os.environ.get("STEAMBOAT_SECURE_PIPELINE_TESTS") == "1"
        and os.environ.get("STEAMBOAT_ARTIFACT_DIR"),
        "requires the opt-in offline worker artifacts and Linux model dependencies")
    def test_root_binding_adopts_real_signed_authority_and_real_stage_executor(self):
        if os.name != "posix" or not hasattr(os, "geteuid"):
            self.skipTest("root worker adoption requires POSIX protected-file semantics")
        try:
            import torch
            import safetensors  # noqa: F401
            import transformers  # noqa: F401
            import grpc  # noqa: F401
            import google.protobuf  # noqa: F401
        except ImportError as error:
            self.skipTest(f"opt-in model dependencies are unavailable: {type(error).__name__}")

        from steamboat_runtime.manifest import load_manifest
        from steamboat_security import Clock, LocalIdentity, SnapshotStore
        from steamboat_security.certificates import (
            _pem_certificate, certificate_sha256, public_key_sha256)
        from steamboat_security.codec import canonical_json
        from steamboat_security.root_runtime import RootRuntimeBinding, TLSMaterials
        from steamboat_security.root_transition_launch import RoleLaunchSpec

        artifact_directory = Path(os.environ["STEAMBOAT_ARTIFACT_DIR"]).resolve(strict=True)
        manifest = load_manifest(artifact_directory)
        fingerprint = manifest["fingerprint"]
        SecurePipelineIdentityFixture = SecureWorkerPolicyGrantTests()._fixture_type()
        fixture = SecurePipelineIdentityFixture(
            fingerprint, clock_uncertainty_seconds=0.25)
        self.addCleanup(fixture.close)
        host = fixture.principals["worker-1"]
        root = fixture.root
        for name, data in (
                ("worker-1.role.protected.crt.pem", host.certificate_pem),
                ("worker-cohort-ca.pem", fixture.cohort_ca_pem),
                ("worker-snapshot-key.pem", fixture.snapshot_verification_key_pem),
                ("snapshot.json", fixture.signed_snapshot)):
            fixture._write_private(name, data)

        store, clock = fixture.new_store()
        config_path = root / "runtime-config.json"
        acceptor_path = f"/tmp/sw-{os.getpid():x}-{id(self):x}"
        config = SecureWorkerConfig(
            protected_root=str(root), account_id=host.account_id,
            device_id=host.device_id, boot_id=host.boot_id,
            assignment_id=host.assignment_id, worker_name="worker-1",
            model_id=manifest["model_id"], model_revision=manifest["revision"],
            manifest_fingerprint=fingerprint, listen_ip="127.0.0.1",
            listen_port=43127, clock_uncertainty_seconds=0.25,
            certificate_path=str(root / "worker-1.role.protected.crt.pem"),
            private_key_path=str(root / "worker-1.role.key.pem"),
            cohort_ca_path=str(root / "worker-cohort-ca.pem"),
            snapshot_verification_key_path=str(root / "worker-snapshot-key.pem"),
            signed_snapshot_path=str(root / "snapshot.json"),
            artifact_directory=str(artifact_directory),
            acceptor_directory=acceptor_path,
            status_report_path=str(root / "worker-status.json"))
        runtime_values = asdict(config)
        runtime_values["schema_version"] = 1
        runtime_bytes = canonical_json(runtime_values)
        fixture._write_private(config_path.name, runtime_bytes)
        header_values = {
            "schema_version": 1, "profile": "native_posix_root_role_v1",
            "protected_root": str(root), "selected_root": str(root / "selected"),
            "account_id": host.account_id, "device_id": host.device_id,
            "role": "host", "boot_id": host.boot_id,
            "credential_epoch": host.record["credential_epoch"],
            "admission_epoch": 7, "generation_sha256": "e" * 64,
            "launch_nonce": "f" * 32,
            "certificate_path": config.certificate_path,
            "private_key_path": config.private_key_path,
            "model_id": fingerprint, "assignment_id": host.assignment_id,
            "runtime_configuration_path": str(config_path),
            "runtime_configuration_sha256": hashlib.sha256(runtime_bytes).hexdigest(),
        }
        header = canonical_json(header_values)
        certificate = _pem_certificate(host.certificate_pem)
        spec = RoleLaunchSpec(
            generation_sha256=header_values["generation_sha256"],
            account_id=host.account_id, device_id=host.device_id, role="host",
            serial=host.record["serial"],
            certificate_sha256=certificate_sha256(certificate),
            public_key_sha256=public_key_sha256(certificate.public_key()),
            credential_epoch=host.record["credential_epoch"], boot_id=host.boot_id,
            admission_epoch=header_values["admission_epoch"],
            configuration_sha256=hashlib.sha256(header).hexdigest(),
            launch_nonce=header_values["launch_nonce"])
        binding = RootRuntimeBinding(
            LocalIdentity(host.certificate_pem, host.boot_id, fingerprint,
                          host.assignment_id, spec.admission_epoch,
                          spec.generation_sha256),
            store, TLSMaterials(host.certificate_pem, host.private_key_pem),
            runtime_bytes, spec, header)

        owner = _OwnedRuntime()
        try:
            _build_runtime(config, owner, root_binding=binding)
            self.assertIs(owner.store, store)
            self.assertIs(owner.clock, clock)
            self.assertIs(owner.authorizer.local_identity, binding.local_identity)
            self.assertIs(owner.authorizer.snapshot_store, store)
            self.assertEqual(owner.authorizer.local_identity.admission_epoch, 7)
            self.assertEqual(owner.authorizer.local_identity.root_generation_sha256, "e" * 64)
            self.assertEqual(owner.certificate_pem, host.certificate_pem)
            self.assertEqual(owner.private_key_pem, host.private_key_pem)
            self.assertEqual(owner.cohort_ca_pem, fixture.cohort_ca_pem)
            self.assertIsNotNone(owner.executor.stage)
            self.assertEqual(owner.executor.manifest["fingerprint"], fingerprint)
            self.assertEqual(owner.handler.boot_id, host.boot_id)
            self.assertEqual(owner.handler.executor, owner.executor)
        finally:
            if owner.handler is not None:
                shutdown = asyncio.run(_shutdown_components(owner))
                self.assertEqual(shutdown["overall"], "confirmed")
                self.assertEqual(shutdown["handler"], "confirmed")
                self.assertEqual(owner.handler.sessions, {})
                self.assertFalse(owner.handler.requires_restart)
            owner.handler = None
            owner.executor = None
            owner.authorizer = None
            owner.bindings = None
            del owner
            import gc
            gc.collect()


class SecureWorkerWiringTests(unittest.TestCase):
    def test_entrypoint_imports_and_constructs_only_real_runtime_types(self):
        source = Path("lab/secure_worker.py").read_text(encoding="utf-8")
        tree = ast.parse(source)
        imported = {
            (node.module, alias.name)
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom)
            for alias in node.names
        }
        required = {
            ("steamboat_security", "Authorizer"),
            ("steamboat_security", "Clock"),
            ("steamboat_security", "LocalIdentity"),
            ("steamboat_security", "SessionBindings"),
            ("steamboat_security", "SnapshotStore"),
            ("steamboat_runtime.protocol.worker_pb2", "Request"),
            ("steamboat_runtime.worker_state", "StageExecutor"),
            ("steamboat_runtime.worker_state", "WorkerHandler"),
            ("steamboat_runtime.secure_worker_runtime", "SecureWorkerRuntimeBridge"),
            ("steamboat_runtime.protocol.secure_transport", "NodeConnectionBudget"),
            ("steamboat_runtime.protocol.secure_transport", "LocalTlsIdentity"),
            ("steamboat_runtime.protocol.secure_transport", "create_secure_worker_server"),
        }
        self.assertTrue(required.issubset(imported))
        manifest_loader = next(
            node for node in ast.walk(tree)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
            and node.func.id == "load_manifest")
        self.assertEqual(len(manifest_loader.args), 1)
        self.assertNotIn("verify_hashes", {keyword.arg for keyword in manifest_loader.keywords})
        calls = {
            node.func.id
            for node in ast.walk(tree)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
        }
        self.assertTrue({
            "Authorizer", "SnapshotStore", "SessionBindings", "StageExecutor",
            "WorkerHandler", "SecureWorkerRuntimeBridge", "NodeConnectionBudget",
            "create_secure_worker_server",
        }.issubset(calls))
        authorizer_call = next(
            node for node in ast.walk(tree)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
            and node.func.id == "Authorizer")
        request_type = next(
            keyword.value for keyword in authorizer_call.keywords
            if keyword.arg == "worker_request_type")
        self.assertIsInstance(request_type, ast.Name)
        self.assertEqual(request_type.id, "Request")
        server_call = next(
            node for node in ast.walk(tree)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
            and node.func.id == "create_secure_worker_server")
        server_keywords = {keyword.arg for keyword in server_call.keywords}
        self.assertTrue({
            "authorizer", "authorization_watcher", "connection_controller",
            "server_identity", "client_ca_pem", "listen_endpoint",
            "allowed_listen_addresses", "listener_slots",
        }.issubset(server_keywords))
        forbidden = {"eval", "exec", "__import__"}
        self.assertFalse(any(
            isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
            and node.func.id in forbidden for node in ast.walk(tree)))


class SecureWorkerShutdownTests(unittest.IsolatedAsyncioTestCase):
    async def test_shutdown_order_and_confirmation_contract(self):
        calls = []

        class Server:
            async def stop(self, *, grace):
                calls.append(("server", grace))

        class Bridge:
            async def stop(self, *, grace_seconds):
                calls.append(("bridge", grace_seconds))
                return True

        class Handler:
            limits = {"compute_cancel_grace_seconds": 15}

            async def shutdown(self, *, grace_seconds):
                calls.append(("handler", grace_seconds))
                return True

        owned = _OwnedRuntime(server=Server(), bridge=Bridge(),
                              bridge_started=True, handler=Handler())
        result = await _shutdown_components(owned)
        self.assertEqual(calls, [("server", 0), ("bridge", 5.0), ("handler", 15)])
        self.assertEqual(result, {
            "server": "confirmed", "bridge": "confirmed",
            "handler": "confirmed", "overall": "confirmed"})

    async def test_ordinary_failure_or_non_true_lifecycle_result_stays_unknown(self):
        calls = []

        class Server:
            async def stop(self, *, grace):
                calls.append("server")
                raise RuntimeError("private details are not reported")

        class Bridge:
            async def stop(self, *, grace_seconds):
                calls.append("bridge")
                return False

        class Handler:
            limits = {"compute_cancel_grace_seconds": 15}

            async def shutdown(self, *, grace_seconds):
                calls.append("handler")
                return 1

        owned = _OwnedRuntime(server=Server(), bridge=Bridge(),
                              bridge_started=True, handler=Handler())
        result = await _shutdown_components(owned)
        self.assertEqual(calls, ["server", "bridge", "handler"])
        self.assertEqual(result["server"], "unknown")
        self.assertEqual(result["bridge"], "unknown")
        self.assertEqual(result["handler"], "unknown")
        self.assertEqual(result["overall"], "unknown")


class SecureWorkerOwnerAdapterTests(unittest.IsolatedAsyncioTestCase):
    def _fixture_type(self):
        root = Path(__file__).resolve().parents[2]
        for path in (root / "src", Path(__file__).resolve().parent):
            if str(path) not in sys.path:
                sys.path.insert(0, str(path))
        from secure_pipeline_fixture import SecurePipelineIdentityFixture
        return SecurePipelineIdentityFixture

    def _config(self, fixture, snapshot_path=None):
        host = fixture.principals["worker-1"]
        root = fixture.root
        return SecureWorkerConfig(
            protected_root=str(root), account_id=host.account_id,
            device_id=host.device_id, boot_id=host.boot_id,
            assignment_id=host.assignment_id, worker_name="worker-1",
            model_id=MODEL_ID, model_revision=MODEL_REVISION,
            manifest_fingerprint="a" * 64, listen_ip="127.0.0.1",
            listen_port=43127, clock_uncertainty_seconds=0.0,
            certificate_path=str(root / "worker-1.role.protected.crt.pem"),
            private_key_path=str(root / "worker-1.role.key.pem"),
            cohort_ca_path=str(root / "worker-cohort-ca.pem"),
            snapshot_verification_key_path=str(root / "worker-snapshot-key.pem"),
            signed_snapshot_path=str(snapshot_path or root / "snapshot.json"),
            artifact_directory=str(root / "read-only-artifacts"),
            acceptor_directory=str(root / "worker-acceptor"),
            status_report_path=str(root / "worker-status.json"))

    async def test_owner_controls_are_opt_in_and_forbidden_with_root_binding(self):
        config = SecureWorkerStatusTests._config()
        payload = _status_payload(
            config, _OwnedRuntime(
                bridge=SecureWorkerStatusTests._healthy_bridge(),
                handler=SecureWorkerStatusTests._handler()),
            event="heartbeat", phase="ready")
        self.assertNotIn("owner_control", payload)
        self.assertNotIn("owner_lifecycle", payload)
        with self.assertRaisesRegex(
                WorkerConfigError,
                "^owner controls are unavailable in root-bound mode$"):
            await serve(config, root_binding=object(),
                        owner_controls_run_id="a" * 32)
        with self.assertRaisesRegex(
                WorkerConfigError,
                "^removal intent root requires owner controls$"):
            await serve(config, owner_removal_intent_root="/outside")

    def test_heartbeat_reports_healthy_owner_drain_without_fake_fault(self):
        config = SecureWorkerStatusTests._config()

        class DrainingBridge:
            _closed = False

            def owner_lifecycle_status(self):
                return {
                    "phase": "draining", "drain_started_monotonic": 10.0,
                    "drain_deadline_monotonic": 40.0, "deadline_reached": False,
                }

            def status(self):
                return {
                    "ready": False, "unavailable": False,
                    "requires_restart": False, "cleanup_confirmed": True,
                    "active_authorizations": 0, "owned_sessions": 0,
                    "pending_notices": 0, "fault": "",
                }

        owned = _OwnedRuntime(
            bridge=DrainingBridge(), bridge_started=True,
            handler=SecureWorkerStatusTests._handler(), owner_controls_enabled=True,
            owner_control_run_id="a" * 32)
        payload = _status_payload(config, owned, event="heartbeat", phase="ready")
        self.assertEqual(payload["phase"], "draining")
        self.assertFalse(payload["bridge"]["ready"])
        self.assertFalse(payload["bridge"]["unavailable"])
        self.assertFalse(payload["bridge"]["requires_restart"])
        self.assertEqual(payload["owner_lifecycle"]["phase"], "draining")
        self.assertEqual(set(payload["owner_control"]), {
            "run_id", "last_sequence", "last_command_sha256", "last_action",
            "received_monotonic_ns", "applied_monotonic_ns",
            "applied_snapshot_sha256", "applied_revision",
            "removal_intent_verified", "revocation_notice_monotonic_ns",
        })

    @unittest.skipUnless(os.name == "posix",
                         "owner command inbox requires POSIX protected-file semantics")
    async def test_drain_command_uses_real_inbox_and_durably_acknowledges(self):
        from lab.secure_worker_owner_control import OwnerControlInbox

        with tempfile.TemporaryDirectory(prefix="worker-owner-inbox-") as directory:
            root = Path(directory)
            os.chmod(root, 0o700)
            run_id, boot_id = "a" * 32, "b" * 32
            command = {
                "schema_version": 1, "event": "owner_command",
                "run_id": run_id, "worker_boot_id": boot_id,
                "sequence": 1, "command_id": "c" * 32,
                "action": "drain", "drain_seconds": 5,
                "snapshot_sha256": "", "snapshot_revision": 0,
            }
            raw = json.dumps(command, sort_keys=True,
                             separators=(",", ":")).encode("ascii")
            command_path = root / "owner-command.json"
            command_path.write_bytes(raw)
            os.chmod(command_path, 0o600)

            class Clock:
                def sample(self):
                    return SimpleNamespace(monotonic=10.0)

            class Store:
                def current(self):
                    return SimpleNamespace(revision=3)

            class Bridge:
                _closed = False

                def __init__(self):
                    self.deadlines = []

                def begin_drain(self, seconds):
                    self.deadlines.append(seconds)
                    return 15.0

                def owner_lifecycle_status(self):
                    return {
                        "phase": "draining", "drain_started_monotonic": 10.0,
                        "drain_deadline_monotonic": 15.0,
                        "deadline_reached": False,
                    }

                def _fence(self, _reason):
                    self._closed = True

            bridge = Bridge()
            inbox = OwnerControlInbox(
                root, run_id=run_id, worker_boot_id=boot_id,
                expected_uid=os.geteuid())
            owned = _OwnedRuntime(
                clock=Clock(), store=Store(), bridge=bridge,
                owner_control_inbox=inbox, owner_control_run_id=run_id,
                installed_snapshot_sha256="d" * 64,
                installed_snapshot_revision=3)
            stop_event = asyncio.Event()
            task = asyncio.create_task(_owner_control_loop(
                SecureWorkerStatusTests._config(), owned, stop_event,
                removal_intent_root=None))
            ack_path = root / "owner-ack.json"
            try:
                deadline = asyncio.get_running_loop().time() + 1.0
                while not ack_path.exists() and asyncio.get_running_loop().time() < deadline:
                    await asyncio.sleep(0.01)
                self.assertTrue(ack_path.exists())
                stop_event.set()
                await asyncio.wait_for(task, 1.0)
            finally:
                stop_event.set()
                if not task.done():
                    task.cancel()
                    await asyncio.gather(task, return_exceptions=True)
            ack = json.loads(ack_path.read_text("ascii"))
            self.assertTrue(ack["accepted"])
            self.assertEqual(ack["phase"], "draining")
            self.assertEqual(ack["applied_snapshot_sha256"], "d" * 64)
            self.assertEqual(ack["applied_revision"], 3)
            self.assertEqual(bridge.deadlines, [5])

    @unittest.skipUnless(os.name == "posix",
                         "owner command inbox requires POSIX protected-file semantics")
    async def test_signed_snapshot_command_installs_on_original_store_and_notifies(self):
        from lab.secure_worker_owner_control import OwnerControlInbox
        from steamboat_security.codec import canonical_json
        from steamboat_security.snapshot import sign_snapshot

        SecurePipelineIdentityFixture = self._fixture_type()
        fixture = SecurePipelineIdentityFixture("a" * 64, clock_uncertainty_seconds=0)
        self.addCleanup(fixture.close)
        store, clock = fixture.new_store()
        before = store.current()
        envelope = json.loads(fixture.signed_snapshot.decode("ascii"))
        payload = envelope["payload"]
        payload["revision"] = before.revision + 1
        signing_key_path = fixture.root / "snapshot-signing-root.key.pem"
        next_snapshot = sign_snapshot(
            payload, signing_key_path.read_bytes())
        snapshot_path = fixture.root / "owner-next-snapshot.json"
        fixture._write_private(snapshot_path.name, next_snapshot)
        digest = hashlib.sha256(next_snapshot).hexdigest()
        config = self._config(fixture, snapshot_path)
        run_id, boot_id = "a" * 32, fixture.principals["worker-1"].boot_id
        command = {
            "schema_version": 1, "event": "owner_command",
            "run_id": run_id, "worker_boot_id": boot_id,
            "sequence": 1, "command_id": "c" * 32,
            "action": "install_snapshot", "drain_seconds": 0,
            "snapshot_sha256": digest, "snapshot_revision": before.revision + 1,
        }
        command_path = fixture.root / "owner-command.json"
        command_path.write_bytes(canonical_json(command))
        os.chmod(command_path, 0o600)
        notifications = []
        store.subscribe(lambda view: notifications.append(view.revision))

        class Bridge:
            _closed = False

            def owner_lifecycle_status(self):
                return {
                    "phase": "ready", "drain_started_monotonic": None,
                    "drain_deadline_monotonic": None, "deadline_reached": False,
                }

            def _fence(self, _reason):
                self._closed = True

        inbox = OwnerControlInbox(
            fixture.root, run_id=run_id, worker_boot_id=boot_id,
            expected_uid=os.geteuid())
        owned = _OwnedRuntime(
            clock=clock, store=store, bridge=Bridge(),
            owner_control_inbox=inbox, owner_control_run_id=run_id,
            snapshot_verification_key_pem=fixture.snapshot_verification_key_pem,
            cohort_ca_pem=fixture.cohort_ca_pem,
            installed_snapshot_sha256=hashlib.sha256(fixture.signed_snapshot).hexdigest(),
            installed_snapshot_revision=before.revision,
            owner_initial_credential_pins={
                serial: record for serial, record in before.credentials_by_serial.items()
                if record.device_id == config.device_id})
        stop_event = asyncio.Event()
        task = asyncio.create_task(_owner_control_loop(
            config, owned, stop_event, removal_intent_root=None))
        ack_path = fixture.root / "owner-ack.json"
        try:
            deadline = asyncio.get_running_loop().time() + 2.0
            while not ack_path.exists() and asyncio.get_running_loop().time() < deadline:
                await asyncio.sleep(0.01)
            self.assertTrue(ack_path.exists())
            stop_event.set()
            await asyncio.wait_for(task, 1.0)
        finally:
            stop_event.set()
            if not task.done():
                task.cancel()
                await asyncio.gather(task, return_exceptions=True)

        ack = json.loads(ack_path.read_text("ascii"))
        self.assertTrue(ack["accepted"])
        self.assertEqual(ack["applied_snapshot_sha256"], digest)
        self.assertEqual(ack["applied_revision"], before.revision + 1)
        self.assertIs(owned.store, store)
        self.assertEqual(store.current().revision, before.revision + 1)
        self.assertEqual(notifications, [before.revision + 1])
        self.assertEqual(owned.installed_snapshot_sha256, digest)

    @unittest.skipUnless(os.name == "posix",
                         "owner command flow requires POSIX protected-file semantics")
    async def test_signed_local_disable_and_remove_keep_separate_intents_and_notice_scope(self):
        await self._run_signed_local_disable_flow()

    @unittest.skipUnless(os.name == "posix",
                         "owner command flow requires POSIX protected-file semantics")
    async def test_second_revocation_must_cover_original_serials(self):
        await self._run_signed_local_disable_flow(
            omit_original_serial_on_second=True)

    async def _run_signed_local_disable_flow(self, *,
                                             omit_original_serial_on_second=False):
        import base64
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        from lab.secure_worker_owner_control import OwnerControlInbox, parse_owner_command
        from steamboat_security import Authorizer, LocalIdentity, SessionBindings
        from steamboat_security.codec import (
            METADATA_KEY, WORKER_SERVICE, canonical_json, parse_metadata)
        from steamboat_security.snapshot import sign_snapshot

        fixture_type = self._fixture_type()
        fixture = fixture_type("a" * 64, clock_uncertainty_seconds=0)
        self.addCleanup(fixture.close)
        store, clock = fixture.new_store()
        initial = store.current()
        host = fixture.principals["worker-1"]
        config = self._config(fixture)
        key_path = fixture.root / "snapshot-signing-root.key.pem"
        signing_key = serialization.load_pem_private_key(
            key_path.read_bytes(), password=None)
        sessions = SessionBindings(clock=clock)
        authorizer = Authorizer(
            local_identity=LocalIdentity(
                host.certificate_pem, host.boot_id, fixture.model_id,
                host.assignment_id), snapshot_store=store, clock=clock,
            session_bindings=sessions)
        owned = _OwnedRuntime(
            clock=clock, store=store, bindings=sessions, authorizer=authorizer,
            bridge=None, bridge_started=True,
            handler=SecureWorkerStatusTests._handler(),
            owner_controls_enabled=False,
            owner_initial_credential_pins={
                serial: record for serial, record in initial.credentials_by_serial.items()
                if record.device_id == config.device_id},
            snapshot_verification_key_pem=fixture.snapshot_verification_key_pem,
            cohort_ca_pem=fixture.cohort_ca_pem,
            installed_snapshot_sha256=hashlib.sha256(fixture.signed_snapshot).hexdigest(),
            installed_snapshot_revision=initial.revision)

        class DrainingBridge:
            _closed = False

            def __init__(self):
                self.phase = "ready"
                self.deadlines = []

            def begin_drain(self, seconds):
                self.deadlines.append(seconds)
                if self.phase == "ready":
                    self.phase = "draining"
                return 120.0

            def owner_lifecycle_status(self):
                return {
                    "phase": self.phase,
                    "drain_started_monotonic": 10.0 if self.phase != "ready" else None,
                    "drain_deadline_monotonic": 40.0 if self.phase != "ready" else None,
                    "deadline_reached": False,
                }

            def status(self):
                return {
                    "ready": self.phase == "ready", "unavailable": False,
                    "requires_restart": False, "cleanup_confirmed": True,
                    "active_authorizations": 0, "owned_sessions": 0,
                    "pending_notices": 0, "fault": "",
                }

            def _fence(self, _reason):
                self._closed = True

        bridge = DrainingBridge()
        owned.bridge = bridge

        def open_real_session(local_name, suffix):
            view = store.current()
            sample = clock.sample()
            actor = authorizer._verify_certificate(
                fixture.principals["coordinator"].certificate_pem, view, sample)
            local = authorizer._verify_certificate(
                fixture.principals[local_name].certificate_pem, view, sample)
            grant = next(grant for grant in view.grants
                         if grant.actor_serial == actor.serial
                         and grant.target_serial == local.serial
                         and grant.method == f"{WORKER_SERVICE}/OpenSession")
            fields = {
                "binding_version": 1,
                "operation_id": "op_" + suffix * 32,
                "account_id": actor.account_id,
                "device_id": actor.device_id,
                "role": actor.role,
                "credential_epoch": actor.credential_epoch,
                "target_device_id": local.device_id,
                "coordinator_boot_id": fixture.principals["coordinator"].boot_id,
                "tenant_account_id": actor.account_id,
                "route_epoch": 1,
                "attempt": 1,
                "worker_boot_id": fixture.principals[local_name].boot_id,
                "assignment_id": fixture.principals[local_name].assignment_id,
                "session_id": "ses_" + suffix * 32,
                "request_id": "req_" + suffix * 32,
                "route_id": "route_" + suffix * 32,
            }
            binding = parse_metadata(
                WORKER_SERVICE, "OpenSession",
                [(METADATA_KEY, canonical_json(fields))])
            claim = sessions.claim(
                binding, actor=actor, local=local, grant=grant,
                model_id=fixture.model_id, lifetime_ms=30_000,
                max_positions=64, idle_lease_ms=20_000)
            sessions.seal_open(claim, lease_token=(suffix * 32))

        # Build actual authorization-owned sessions so signed store installs
        # generate real SessionBindings notices for two different devices.
        open_real_session("worker-1", "1")
        open_real_session("worker-2", "2")

        run_id = "b" * 32
        with tempfile.TemporaryDirectory(prefix="owner-intents-") as intent_dir:
            intent_root = Path(intent_dir).resolve()
            os.chmod(intent_root, 0o700)
            _enable_owner_controls(config, owned, run_id, str(intent_root))

            base_payload = json.loads(fixture.signed_snapshot.decode("ascii"))["payload"]

            def signed_policy(revision, *, remove_device=None, remove_worker2_open=False,
                              omit_original_serial=None):
                payload = copy.deepcopy(base_payload)
                payload["revision"] = revision
                if remove_worker2_open:
                    worker2 = fixture.principals["worker-2"].device_id
                    payload["grants"] = [
                        grant for grant in payload["grants"]
                        if not (grant["target_device_id"] == worker2
                                and grant["method"]
                                    == f"{WORKER_SERVICE}/OpenSession")]
                if remove_device is not None:
                    local_records = [record for record in payload["credentials"]
                                     if record["device_id"] == remove_device]
                    serials = {record["serial"] for record in local_records}
                    payload["credentials"] = [record for record in payload["credentials"]
                                               if record["device_id"] != remove_device]
                    payload["revoked_serials"] = sorted(
                        set(payload["revoked_serials"]) | serials)
                    if omit_original_serial is not None:
                        payload["revoked_serials"] = [
                            serial for serial in payload["revoked_serials"]
                            if serial != omit_original_serial]
                    payload["revoked_devices"] = sorted(
                        set(payload["revoked_devices"]) | {remove_device})
                    payload["grants"] = [grant for grant in payload["grants"]
                                         if grant["device_id"] != remove_device
                                         and grant["target_device_id"] != remove_device]
                return sign_snapshot(payload, key_path.read_bytes())

            # An unrelated actual local authorization notice arrives before a
            # claimed owner update; the unarmed observer must ignore it.
            prior = signed_policy(2, remove_worker2_open=True)
            notifications = []
            store.subscribe(lambda view: notifications.append(view.revision))
            store.install(prior)
            self.assertEqual(owned.owner_control_revocation_notice_monotonic_ns, 0)
            owned.installed_snapshot_sha256 = hashlib.sha256(prior).hexdigest()
            owned.installed_snapshot_revision = 2
            self.assertFalse(_owner_requires_full_revocation(
                config, owned, store.current()),
                "narrowing a different worker grant is not a device removal")
            with self.assertRaisesRegex(
                    WorkerConfigError,
                    "^signed owner removal intent is invalid$"):
                _verify_owner_removal_intent(
                    config, parse_owner_command(
                        canonical_json({
                            "schema_version": 1, "event": "owner_command",
                            "run_id": run_id, "worker_boot_id": host.boot_id,
                            "sequence": 1, "command_id": f"{1:032x}",
                            "action": "install_snapshot", "drain_seconds": 0,
                            "snapshot_sha256": hashlib.sha256(
                                signed_policy(3, remove_device=config.device_id)
                            ).hexdigest(), "snapshot_revision": 3,
                        }), expected_run_id=run_id,
                        expected_worker_boot_id=host.boot_id),
                    str(intent_root),
                    verification_key_pem=fixture.snapshot_verification_key_pem,
                    filename="install-intent.json")
            self.assertEqual(store.current().revision, 2)

            command_path = fixture.root / "owner-command.json"
            ack_path = fixture.root / "owner-ack.json"
            intent_record_bytes = {}
            install_snapshot = signed_policy(
                3, remove_device=config.device_id)
            original_serial = min(owned.owner_initial_credential_pins)
            remove_snapshot = signed_policy(
                4, remove_device=config.device_id,
                omit_original_serial=(original_serial
                                     if omit_original_serial_on_second else None))
            snapshot_path = fixture.root / "owner-next-snapshot.json"
            config = self._config(fixture, str(snapshot_path))

            def write_command(sequence, action, snapshot, intent_filename=None):
                digest = hashlib.sha256(snapshot).hexdigest()
                fields = {
                    "schema_version": 1, "event": "owner_command",
                    "run_id": run_id, "worker_boot_id": host.boot_id,
                    "sequence": sequence, "command_id": f"{sequence:032x}",
                    "action": action, "drain_seconds": 0,
                    "snapshot_sha256": digest,
                    "snapshot_revision": sequence + 2,
                }
                raw = canonical_json(fields)
                command = parse_owner_command(
                    raw, expected_run_id=run_id,
                    expected_worker_boot_id=host.boot_id)
                if intent_filename is not None:
                    intent = {
                        "schema_version": 1, "event": "owner_removal_intent",
                        "run_id": command.run_id,
                        "worker_boot_id": command.worker_boot_id,
                        "command_id": command.command_id,
                        "command_sha256": command.command_sha256,
                        "snapshot_sha256": command.snapshot_sha256,
                        "snapshot_revision": command.snapshot_revision,
                        "roles_off": True,
                    }
                    canonical = canonical_json(intent)
                    signature = signing_key.sign(
                        b"steamboat-owner-removal-intent-v1\x00" + canonical,
                        ec.ECDSA(hashes.SHA256()))
                    envelope = {
                        "schema_version": 1,
                        "event": "signed_owner_removal_intent",
                        "intent": intent,
                        "signature": base64.b64encode(signature).decode("ascii"),
                    }
                    intent_path = intent_root / intent_filename
                    with intent_path.open("xb") as stream:
                        stream.write(canonical_json(envelope))
                        stream.flush()
                        os.fsync(stream.fileno())
                    os.chmod(intent_path, 0o600)
                    intent_record_bytes[intent_filename] = intent_path.read_bytes()
                snapshot_path.write_bytes(snapshot)
                os.chmod(snapshot_path, 0o600)
                temporary = fixture.root / f".command-{sequence}.tmp"
                temporary.write_bytes(raw)
                os.chmod(temporary, 0o600)
                if command_path.exists():
                    os.replace(temporary, command_path)
                else:
                    os.replace(temporary, command_path)

            write_command(1, "install_snapshot", install_snapshot,
                          "install-intent.json")
            inbox = owned.owner_control_inbox
            stop_event = asyncio.Event()
            publications = []
            from lab import secure_worker as worker_module
            write_publication = worker_module._publish

            def record_publication(*args, **kwargs):
                payload = args[1]
                publications.append((dict(payload), stop_event.is_set()))
                return write_publication(*args, **kwargs)

            publication_patch = mock.patch(
                "lab.secure_worker._publish", side_effect=record_publication)
            publication_patch.start()
            task = asyncio.create_task(_owner_control_loop(
                config, owned, stop_event,
                removal_intent_root=str(intent_root)))

            async def wait_ack(sequence):
                deadline = asyncio.get_running_loop().time() + 3.0
                while asyncio.get_running_loop().time() < deadline:
                    if ack_path.exists():
                        try:
                            ack = json.loads(ack_path.read_text("ascii"))
                            if ack.get("sequence") == sequence:
                                return ack
                        except (OSError, ValueError):
                            pass
                    await asyncio.sleep(0.01)
                self.fail(f"owner command {sequence} was not acknowledged")

            try:
                first_ack = await wait_ack(1)
                self.assertTrue(first_ack["accepted"])
                self.assertTrue(owned.owner_control_removal_intent_verified)
                self.assertGreater(owned.owner_control_revocation_notice_monotonic_ns, 0)
                self.assertEqual(owned.owner_control_last_action, "install_snapshot")
                self.assertEqual(bridge.deadlines, [30])
                self.assertEqual(store.current().revision, 3)

                write_command(2, "remove", remove_snapshot,
                              "removal-intent.json")
                second_ack = await wait_ack(2)
                if omit_original_serial_on_second:
                    self.assertFalse(second_ack["accepted"])
                    self.assertEqual(second_ack["failure_code"], "apply_failed")
                    with self.assertRaises(WorkerStatusUnavailable):
                        await asyncio.wait_for(task, 1.0)
                else:
                    self.assertTrue(second_ack["accepted"])
                    await asyncio.wait_for(task, 1.0)
            finally:
                stop_event.set()
                if not task.done():
                    task.cancel()
                    await asyncio.gather(task, return_exceptions=True)
                publication_patch.stop()

            expected_revision = 3 if omit_original_serial_on_second else 4
            self.assertEqual(store.current().revision, expected_revision)
            self.assertEqual(notifications, [2, 3] if omit_original_serial_on_second
                             else [2, 3, 4])
            self.assertTrue((intent_root / "install-intent.json").is_file())
            self.assertTrue((intent_root / "removal-intent.json").is_file())
            self.assertEqual(
                (intent_root / "install-intent.json").read_bytes(),
                intent_record_bytes["install-intent.json"])
            self.assertEqual(
                (intent_root / "removal-intent.json").read_bytes(),
                intent_record_bytes["removal-intent.json"])
            self.assertTrue(stop_event.is_set())
            if omit_original_serial_on_second:
                self.assertEqual(owned.installed_snapshot_revision, 3)
                self.assertEqual(owned.installed_snapshot_sha256,
                                 hashlib.sha256(install_snapshot).hexdigest())
                self.assertEqual(publications, [])
            else:
                status = json.loads(
                    (fixture.root / "worker-status.json").read_text("ascii"))
                self.assertEqual(status["event"], "status")
                self.assertEqual(status["phase"], "draining")
                self.assertEqual(status["owner_lifecycle"]["phase"], "draining")
                self.assertEqual(status["owner_control"]["last_action"], "remove")
                self.assertTrue(status["owner_control"]["removal_intent_verified"])
                self.assertEqual(len(publications), 1)
                self.assertEqual(publications[0][0]["event"], "status")
                self.assertEqual(publications[0][0]["phase"], "draining")
                self.assertFalse(publications[0][1],
                                 "protected final status must publish before stop")

    @unittest.skipUnless(os.name == "posix",
                         "signed owner intent requires POSIX protected-file semantics")
    def test_removal_intent_requires_pinned_ecdsa_signature_and_exact_command(self):
        import base64
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        from lab.secure_worker_owner_control import parse_owner_command

        SecurePipelineIdentityFixture = self._fixture_type()
        fixture = SecurePipelineIdentityFixture("a" * 64, clock_uncertainty_seconds=0)
        self.addCleanup(fixture.close)
        fixture._write_private("worker-snapshot-key.pem",
                               fixture.snapshot_verification_key_pem)
        config = self._config(fixture)
        command_fields = {
            "schema_version": 1, "event": "owner_command",
            "run_id": "a" * 32, "worker_boot_id": fixture.principals["worker-1"].boot_id,
            "sequence": 1, "command_id": "c" * 32, "action": "remove",
            "drain_seconds": 0, "snapshot_sha256": "d" * 64,
            "snapshot_revision": 2,
        }
        command = parse_owner_command(
            json.dumps(command_fields, sort_keys=True, separators=(",", ":")).encode("ascii"),
            expected_run_id=command_fields["run_id"],
            expected_worker_boot_id=command_fields["worker_boot_id"])
        intent = {
            "schema_version": 1, "event": "owner_removal_intent",
            "run_id": command.run_id, "worker_boot_id": command.worker_boot_id,
            "command_id": command.command_id, "command_sha256": command.command_sha256,
            "snapshot_sha256": command.snapshot_sha256,
            "snapshot_revision": command.snapshot_revision, "roles_off": True,
        }
        canonical = json.dumps(intent, sort_keys=True, separators=(",", ":"),
                               ensure_ascii=True, allow_nan=False).encode("ascii")
        signing_key = serialization.load_pem_private_key(
            (fixture.root / "snapshot-signing-root.key.pem").read_bytes(), password=None)
        signature = signing_key.sign(
            b"steamboat-owner-removal-intent-v1\x00" + canonical,
            ec.ECDSA(hashes.SHA256()))
        envelope = {
            "schema_version": 1, "event": "signed_owner_removal_intent",
            "intent": intent, "signature": base64.b64encode(signature).decode("ascii"),
        }
        external_root = Path(tempfile.mkdtemp(prefix="owner-intent-")).resolve()
        self.addCleanup(lambda: __import__("shutil").rmtree(external_root))
        os.chmod(external_root, 0o700)
        path = external_root / "removal-intent.json"

        def write_envelope(document):
            raw = json.dumps(document, sort_keys=True, separators=(",", ":"),
                              ensure_ascii=True, allow_nan=False).encode("ascii")
            path.write_bytes(raw)
            os.chmod(path, 0o600)

        write_envelope(envelope)
        # The protected live runtime key bytes are the authority pin. Replacing
        # the config path after startup cannot change which key verifies intent.
        wrong_ec_key = ec.generate_private_key(ec.SECP256R1())
        wrong_public = wrong_ec_key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo)
        config_key_path = fixture.root / "worker-snapshot-key.pem"
        config_key_path.write_bytes(wrong_public)
        os.chmod(config_key_path, 0o600)
        self.assertEqual(_verify_owner_removal_intent(
            config, command, str(external_root),
            verification_key_pem=fixture.snapshot_verification_key_pem), intent)
        broken = copy.deepcopy(envelope)
        broken["intent"]["roles_off"] = False
        write_envelope(broken)
        with self.assertRaisesRegex(WorkerConfigError,
                                   "^signed owner removal intent is invalid$"):
            _verify_owner_removal_intent(
                config, command, str(external_root),
                verification_key_pem=fixture.snapshot_verification_key_pem)
        write_envelope(envelope)
        broken = copy.deepcopy(envelope)
        signature_bytes = bytearray(base64.b64decode(broken["signature"]))
        signature_bytes[-1] ^= 1
        broken["signature"] = base64.b64encode(signature_bytes).decode("ascii")
        write_envelope(broken)
        with self.assertRaisesRegex(WorkerConfigError,
                                   "^signed owner removal intent is invalid$"):
            _verify_owner_removal_intent(
                config, command, str(external_root),
                verification_key_pem=fixture.snapshot_verification_key_pem)

        # An external protected directory is required. A correctly signed
        # record inside the role-credential root cannot authorize its own removal.
        inside = fixture.root / "inside-intent"
        inside.mkdir(mode=0o700)
        os.chmod(inside, 0o700)
        inside_path = inside / "removal-intent.json"
        inside_path.write_bytes(json.dumps(
            envelope, sort_keys=True, separators=(",", ":"),
            ensure_ascii=True, allow_nan=False).encode("ascii"))
        os.chmod(inside_path, 0o600)
        with self.assertRaisesRegex(
                WorkerConfigError,
                "^owner removal intent must be outside the role root$"):
            _verify_owner_removal_intent(
                config, command, str(inside),
                verification_key_pem=fixture.snapshot_verification_key_pem)

        # A different ECDSA key and a different ECDSA digest algorithm both
        # fail against the configured pinned P-256/SHA-256 verification key.
        from cryptography.hazmat.primitives import hashes
        wrong_signature = wrong_ec_key.sign(
            b"steamboat-owner-removal-intent-v1\x00" + canonical,
            ec.ECDSA(hashes.SHA256()))
        write_envelope({**envelope, "signature": base64.b64encode(
            wrong_signature).decode("ascii")})
        with self.assertRaisesRegex(WorkerConfigError,
                                   "^signed owner removal intent is invalid$"):
            _verify_owner_removal_intent(
                config, command, str(external_root),
                verification_key_pem=fixture.snapshot_verification_key_pem)
        wrong_signature = signing_key.sign(
            b"steamboat-owner-removal-intent-v1\x00" + canonical,
            ec.ECDSA(hashes.SHA384()))
        write_envelope({**envelope, "signature": base64.b64encode(
            wrong_signature).decode("ascii")})
        with self.assertRaisesRegex(WorkerConfigError,
                                   "^signed owner removal intent is invalid$"):
            _verify_owner_removal_intent(
                config, command, str(external_root),
                verification_key_pem=fixture.snapshot_verification_key_pem)


if __name__ == "__main__":
    unittest.main()
