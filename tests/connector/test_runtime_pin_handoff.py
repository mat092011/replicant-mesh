"""Focused supervisor ownership and child handoff tests."""

import os
import base64
import sys
import hashlib
import json
import stat
import subprocess
import time
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from steamboat_connector.aggregate_artifact_pin import RuntimeArtifactGroupPin
from steamboat_connector.artifact_pin import ArtifactPinError
from steamboat_connector.catalog import CatalogVerifier
from steamboat_connector.process_supervisor import ProcessRoleBackend, ROLE_CONFIG_MAX_BYTES
from steamboat_connector.runtime_pin_handoff import (
    MAX_HANDOFF_BYTES, RuntimePinHandoffError, validate_child_pin)
from steamboat_security.clock import Clock

from tests.connector.test_process_supervisor import (
    FakeCgroup, FakeProcess, sample_policy)

REAL_POPEN = subprocess.Popen


def _public_key():
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    key = ec.generate_private_key(ec.SECP256R1()).public_key()
    return key.public_bytes(serialization.Encoding.X962,
                            serialization.PublicFormat.UncompressedPoint)


def _child_group_metadata(root, original, public_key, count=3):
    return {
        "version": 1, "kind": "group", "role": "host",
        "root": str(root), "uid": os.getuid() if hasattr(os, "getuid") else 1,
        "record_path": str(Path(root) / ".runtime-pin-host.json"),
        "record": {"role": "host"}, "global_fd": original[0],
        "role_fd": original[1], "clock_domain": "linux:test",
        "captured_mono": 1.0, "catalog_deadline": 1000.0,
        "signed_catalog": base64.b64encode(b"catalog").decode("ascii"),
        "public_key": base64.b64encode(public_key).decode("ascii"),
        "assignments": [{
            "version": 1, "component": f"worker-{index}",
            "worker_boot_id": f"{index:032x}", "assignment_deadline": 900.0,
            "signed_assignment": base64.b64encode(
                f"assignment-{index}".encode()).decode("ascii"),
        } for index in range(1, count + 1)],
    }


class RuntimePinHandoffTests(unittest.TestCase):
    def setUp(self):
        platform_patch = mock.patch("steamboat_connector.process_supervisor.sys.platform",
                                    "linux")
        platform_patch.start()
        self.addCleanup(platform_patch.stop)
        self.temp = tempfile.TemporaryDirectory()
        os.chmod(self.temp.name, 0o700)
        self.cgroup = FakeCgroup(self.temp.name)
        self.backend = ProcessRoleBackend(self.temp.name, self.cgroup)
        self.pin_fds = (os.open(os.devnull, os.O_RDONLY),
                        os.open(os.devnull, os.O_RDONLY))
        self.addCleanup(self.temp.cleanup)
        self.addCleanup(lambda: [os.close(fd) for fd in self.pin_fds
                                 if fd >= 0])

    def _configured_group_pin(self):
        pin = object.__new__(RuntimeArtifactGroupPin)
        pin.signed_catalog = b"signed-catalog"
        import hashlib
        catalog_digest = hashlib.sha256(pin.signed_catalog).hexdigest()
        pin.record = {
            "version": 2, "pin_id": "c" * 64,
            "account_id": "acct_" + "1" * 32,
            "device_id": "dev_" + "2" * 32, "role": "host",
            "model_id": "test-model", "catalog_sha256": catalog_digest,
            "runtime_boot_id": "d" * 32,
            "assignments": [{"component": "worker-1",
                             "assignment_id": "asg_" + "3" * 32,
                             "assignment_sha256": "a" * 64,
                             "worker_boot_id": "b" * 32}],
        }
        pin.root = Path(self.temp.name)
        pin.uid = os.getuid() if hasattr(os, "getuid") else 1
        pin.record_path = Path(self.temp.name) / ".runtime-pin-host.json"
        pin.global_fd, pin.role_fd = self.pin_fds
        pin.clock_domain = "linux:test"
        pin.captured_mono = 1.0
        pin.catalog_deadline = 1000.0
        pin.clock = Clock(uncertainty_seconds=lambda: 0.0)
        pin.release = mock.Mock()
        metadata = {
            "component": "worker-1", "worker_boot_id": "b" * 32,
            "assignment_deadline": 900.0, "signed_assignment": b"signed-assignment",
        }
        verifier = CatalogVerifier(_public_key(), clock=pin.clock)
        catalog = SimpleNamespace(document_bytes=pin.signed_catalog)
        assignment = SimpleNamespace(
            payload={"assignment_id": pin.record["assignments"][0]["assignment_id"],
                     "component": "worker-1"},
            document_sha256="a" * 64)
        return pin, verifier, metadata, catalog, assignment

    def test_supervisor_holds_pin_until_empty_group_is_removed(self):
        pin, verifier, metadata, catalog, assignment = self._configured_group_pin()
        holder = {}

        def spawn(args, **kwargs):
            process = FakeProcess(args, kwargs, self.cgroup)
            holder["process"] = process
            return process

        with (mock.patch.object(RuntimeArtifactGroupPin, "assert_open_descriptors",
                                return_value=True),
              mock.patch.object(RuntimeArtifactGroupPin, "child_launch_metadata",
                                return_value=metadata),
              mock.patch.object(CatalogVerifier, "verify_catalog", return_value=catalog),
              mock.patch.object(CatalogVerifier, "verify_assignment",
                                return_value=assignment),
              mock.patch("steamboat_connector.process_supervisor.atomic_write_private",
                         side_effect=lambda path, data: Path(path).write_bytes(data)),
              mock.patch("steamboat_connector.process_supervisor.read_private_json",
                         side_effect=lambda path, **kwargs: __import__("json").loads(
                             Path(path).read_text(encoding="utf-8"))),
              mock.patch.object(ProcessRoleBackend, "_read_ready", return_value=True),
              mock.patch("steamboat_connector.process_supervisor.signal",
                         SimpleNamespace(SIGTERM=15, SIGKILL=9)),
              mock.patch("steamboat_connector.process_supervisor.os.write",
                         side_effect=lambda fd, data: len(data) if data == b"R" else 0),
              mock.patch("steamboat_connector.process_supervisor.subprocess.Popen",
                         side_effect=spawn),
              mock.patch("steamboat_connector.process_supervisor.os.killpg",
                         side_effect=lambda pid, sig: holder["process"].on_signal(
                             sig, kill_descendants=False), create=True)):
            self.assertTrue(self.backend.configure_pinned_role(
                "host", {"test_mode": True}, pin, catalog_verifier=verifier))
            self.assertTrue(self.backend.start("host", sample_policy()))
            self.assertEqual(set(holder["process"].kwargs["pass_fds"]),
                             {holder["process"].kwargs["pass_fds"][0], *self.pin_fds})
            self.assertIs(self.backend._owned["host"].artifact_pin, pin)
            self.assertFalse(self.backend.stop(["host"], 0.2)["host"])
            pin.release.assert_not_called()
            self.assertIn("host", self.backend._pinned_roles)
            self.cgroup.set_empty()
            result = self.backend.stop(["host"], 0.2)["host"]
            self.assertTrue(result)
            pin.release.assert_called_once_with()
            self.assertNotIn("host", self.backend._pinned_roles)

    def test_pinned_metadata_keeps_original_config_limit(self):
        too_large = {"kind": "single", "payload": "x" * ROLE_CONFIG_MAX_BYTES}
        with self.assertRaises(ValueError):
            ProcessRoleBackend._encode_config("host", {}, pin_metadata=too_large)

    def test_ambiguous_popen_failure_keeps_pin_fenced_and_blocks_restart(self):
        pin, verifier, metadata, catalog, assignment = self._configured_group_pin()
        popen = mock.Mock(side_effect=OSError("injected ambiguous Popen failure"))
        with (mock.patch.object(RuntimeArtifactGroupPin, "assert_open_descriptors",
                                return_value=True),
              mock.patch.object(RuntimeArtifactGroupPin, "child_launch_metadata",
                                return_value=metadata),
              mock.patch.object(CatalogVerifier, "verify_catalog", return_value=catalog),
              mock.patch.object(CatalogVerifier, "verify_assignment",
                                return_value=assignment),
              mock.patch("steamboat_connector.process_supervisor.atomic_write_private",
                         side_effect=lambda path, data: Path(path).write_bytes(data)),
              mock.patch("steamboat_connector.process_supervisor.read_private_json",
                         side_effect=lambda path, **kwargs: __import__("json").loads(
                             Path(path).read_text(encoding="utf-8"))),
              mock.patch("steamboat_connector.process_supervisor.subprocess.Popen",
                         popen)):
            self.assertTrue(self.backend.configure_pinned_role(
                "host", {"test_mode": True}, pin, catalog_verifier=verifier))
            self.assertFalse(self.backend.start("host", sample_policy()))
            self.assertFalse(self.backend.stop(["host"], 0.2)["host"])
            self.assertFalse(self.backend.start("host", sample_policy()))
            self.assertEqual(popen.call_count, 1)
            pin.release.assert_not_called()
            self.assertIn("host", self.backend._pinned_roles)

    def test_slow_pin_release_runs_outside_stop_locks_and_remains_observable(self):
        pin, verifier, metadata, catalog, assignment = self._configured_group_pin()
        release_entered = __import__("threading").Event()
        allow_release = __import__("threading").Event()
        pin.release.side_effect = lambda: (release_entered.set(), allow_release.wait(2))
        holder = {}

        def spawn(args, **kwargs):
            process = FakeProcess(args, kwargs, self.cgroup)
            holder["process"] = process
            return process

        def wait_for_empty(owned, deadline):
            while time.monotonic() < deadline:
                if owned.process.poll() is not None:
                    self.cgroup.set_empty(owned.group)
                    return True
                time.sleep(0.002)
            return False

        self.backend._wait_empty = wait_for_empty
        with (mock.patch.object(RuntimeArtifactGroupPin, "assert_open_descriptors",
                                return_value=True),
              mock.patch.object(RuntimeArtifactGroupPin, "child_launch_metadata",
                                return_value=metadata),
              mock.patch.object(CatalogVerifier, "verify_catalog", return_value=catalog),
              mock.patch.object(CatalogVerifier, "verify_assignment",
                                return_value=assignment),
              mock.patch("steamboat_connector.process_supervisor.atomic_write_private",
                         side_effect=lambda path, data: Path(path).write_bytes(data)),
              mock.patch("steamboat_connector.process_supervisor.read_private_json",
                         side_effect=lambda path, **kwargs: __import__("json").loads(
                             Path(path).read_text(encoding="utf-8"))),
              mock.patch.object(ProcessRoleBackend, "_read_ready", return_value=True),
              mock.patch("steamboat_connector.process_supervisor.signal",
                         SimpleNamespace(SIGTERM=15, SIGKILL=9)),
              mock.patch("steamboat_connector.process_supervisor.os.write",
                         side_effect=lambda fd, data: len(data) if data == b"R" else 0),
              mock.patch("steamboat_connector.process_supervisor.subprocess.Popen",
                         side_effect=spawn),
              mock.patch("steamboat_connector.process_supervisor.os.killpg",
                         side_effect=lambda pid, sig: holder["process"].on_signal(
                             sig, kill_descendants=False), create=True)):
            self.assertTrue(self.backend.configure_pinned_role(
                "host", {"test_mode": True}, pin, catalog_verifier=verifier))
            self.assertTrue(self.backend.start("host", sample_policy()))
            started = time.monotonic()
            self.assertFalse(self.backend.stop(["host"], 0.05)["host"])
            self.assertTrue(release_entered.wait(0.2))
            self.assertLess(time.monotonic() - started, 0.15)
            self.assertTrue(self.backend._lock.acquire(timeout=0.05))
            self.backend._lock.release()
            started = time.monotonic()
            self.assertTrue(self.backend.request_stop(["host"])["host"])
            self.assertLess(time.monotonic() - started, 0.05)
            self.assertIn("host", self.backend._pinned_roles)
            allow_release.set()
            self.assertTrue(self.backend.stop(["host"], 0.5)["host"])
            pin.release.assert_called_once_with()

    def test_failed_pin_release_is_sticky_and_never_retried(self):
        pin, verifier, metadata, catalog, assignment = self._configured_group_pin()
        pin.release.side_effect = OSError("injected uncertain pin release")
        with (mock.patch.object(RuntimeArtifactGroupPin, "assert_open_descriptors",
                                return_value=True),
              mock.patch.object(RuntimeArtifactGroupPin, "child_launch_metadata",
                                return_value=metadata),
              mock.patch.object(CatalogVerifier, "verify_catalog", return_value=catalog),
              mock.patch.object(CatalogVerifier, "verify_assignment",
                                return_value=assignment),
              mock.patch("steamboat_connector.process_supervisor.atomic_write_private",
                         side_effect=lambda path, data: Path(path).write_bytes(data))):
            self.assertTrue(self.backend.configure_pinned_role(
                "host", {"test_mode": True}, pin, catalog_verifier=verifier))
            self.assertFalse(self.backend.release_configured_pin("host"))
            self.assertFalse(self.backend.release_configured_pin("host"))
            self.assertTrue(self.backend._lock.acquire(timeout=0.05))
            self.backend._lock.release()
            pin.release.assert_called_once_with()
            self.assertIn("host", self.backend._pinned_roles)
            self.assertIn("host", self.backend._pin_release_blocked)

    def test_successful_configured_pin_release_allows_reconfiguration(self):
        first = self._configured_group_pin()
        second = self._configured_group_pin()
        first_pin, first_verifier, first_metadata, first_catalog, first_assignment = first
        second_pin, second_verifier, second_metadata, second_catalog, second_assignment = second
        release_entered = __import__("threading").Event()
        allow_release = __import__("threading").Event()
        first_pin.release.side_effect = lambda: (release_entered.set(), allow_release.wait(2))
        with (mock.patch.object(RuntimeArtifactGroupPin, "assert_open_descriptors",
                                return_value=True),
              mock.patch.object(RuntimeArtifactGroupPin, "child_launch_metadata",
                                side_effect=[first_metadata, second_metadata]),
              mock.patch.object(CatalogVerifier, "verify_catalog",
                                side_effect=[first_catalog, second_catalog]),
              mock.patch.object(CatalogVerifier, "verify_assignment",
                                side_effect=[first_assignment, second_assignment]),
              mock.patch("steamboat_connector.process_supervisor.atomic_write_private",
                         side_effect=lambda path, data: Path(path).write_bytes(data))):
            self.assertTrue(self.backend.configure_pinned_role(
                "host", {"test_mode": True}, first_pin,
                catalog_verifier=first_verifier))
            with mock.patch("steamboat_connector.process_supervisor.STOP_GRACE_MAX_SECONDS",
                            0.05):
                self.assertFalse(self.backend.release_configured_pin("host"))
            self.assertTrue(release_entered.wait(0.2))
            self.assertIn("host", self.backend._pin_release_blocked)
            allow_release.set()
            self.assertTrue(self.backend._pin_cleanups["host"].completed.wait(0.2))
            self.assertTrue(self.backend.release_configured_pin("host"))
            self.assertNotIn("host", self.backend._pin_release_blocked)
            self.assertTrue(self.backend.configure_pinned_role(
                "host", {"test_mode": True}, second_pin,
                catalog_verifier=second_verifier))
            self.assertTrue(self.backend.release_configured_pin("host"))
            first_pin.release.assert_called_once_with()
            second_pin.release.assert_called_once_with()

    def test_stop_never_reports_success_for_blocked_unowned_generation(self):
        from steamboat_connector.process_supervisor import _StartIntent

        self.backend._pin_release_blocked.add("host")
        self.assertFalse(self.backend.stop(["host"], 0.1)["host"])

        completed = _StartIntent(finished=True)
        self.backend._start_intents["host"] = completed
        self.assertFalse(self.backend.stop(["host"], 0.1)["host"])
        self.assertNotIn("host", self.backend._start_intents)

        group = Path(self.temp.name) / "finished-empty-group"
        group.mkdir()
        (group / "cgroup.events").write_text("populated 0\n", encoding="ascii")
        (group / "cgroup.procs").write_text("", encoding="ascii")
        cleanup = _StartIntent(finished=True, group=group)
        self.backend._start_intents["host"] = cleanup
        self.assertFalse(self.backend.stop(["host"], 0.1)["host"])
        self.assertFalse(group.exists())
        self.assertNotIn("host", self.backend._start_intents)
        self.assertIn("host", self.backend._pin_release_blocked)

    def test_child_helper_requires_exact_trusted_clock_and_verifier(self):
        with self.assertRaises(RuntimePinHandoffError):
            validate_child_pin({}, clock=object(), verifier=object())

    def test_single_handoff_retains_guard_pin_owner(self):
        clock = Clock(uncertainty_seconds=lambda: 0.0)
        public_key = _public_key()
        verifier = CatalogVerifier(public_key, clock=clock)
        original = (os.open(os.devnull, os.O_RDONLY),
                    os.open(os.devnull, os.O_RDONLY))
        record = {"version": 1, "pin_id": "a" * 64,
                  "account_id": "acct_" + "1" * 32,
                  "device_id": "dev_" + "2" * 32,
                  "role": "coordinator", "assignment_id": "asg_" + "3" * 32,
                  "catalog_sha256": "b" * 64, "assignment_sha256": "c" * 64,
                  "boot_id": "d" * 32}
        metadata = {"version": 1, "kind": "single", "role": "coordinator",
                    "root": self.temp.name, "uid": os.getuid() if hasattr(os, "getuid") else 1,
                    "record_path": str(Path(self.temp.name) / ".runtime-pin-coordinator.json"),
                    "record": record, "global_fd": original[0], "role_fd": original[1],
                    "clock_domain": "linux:test", "captured_mono": 1.0,
                    "catalog_deadline": 1000.0, "assignment_deadline": 900.0,
                    "signed_catalog": base64.b64encode(b"catalog").decode("ascii"),
                    "signed_assignment": base64.b64encode(b"assignment").decode("ascii"),
                    "public_key": base64.b64encode(public_key).decode("ascii")}

        class Owner:
            def __init__(self):
                self.close = mock.Mock()

        owner = Owner()
        guard = SimpleNamespace(pin=owner)
        with mock.patch("steamboat_connector.artifact_pin.validate_inherited_pin",
                        return_value=guard):
            pins = validate_child_pin(metadata, clock=clock, verifier=verifier)
        self.assertEqual(pins.owners, (owner,))
        self.assertEqual(pins.guards, (guard,))
        pins.close()
        owner.close.assert_called_once_with()
        for fd in original:
            os.close(fd)

    def test_group_handoff_duplicates_one_pair_per_assignment(self):
        clock = Clock(uncertainty_seconds=lambda: 0.0)
        public_key = _public_key()
        verifier = CatalogVerifier(public_key, clock=clock)
        original = (os.open(os.devnull, os.O_RDONLY),
                    os.open(os.devnull, os.O_RDONLY))
        metadata = _child_group_metadata(self.temp.name, original, public_key)
        created = []

        class Owner:
            def __init__(self, fds):
                self.fds = fds

            def close(self):
                for fd in self.fds:
                    os.close(fd)

        def validate(global_fd, role_fd, **kwargs):
            created.append((global_fd, role_fd))
            return Owner((global_fd, role_fd)), object()

        with mock.patch("steamboat_connector.aggregate_artifact_pin.validate_inherited_group_pin",
                        side_effect=validate):
            handoff = validate_child_pin(metadata, clock=clock, verifier=verifier)
        self.assertEqual(len(created), 3)
        self.assertEqual(len({fd for pair in created for fd in pair}), 6)
        for fd in original:
            os.fstat(fd)
        self.assertEqual(len(handoff.guards), 3)
        handoff.close()
        for fd in original:
            with self.assertRaises(OSError):
                os.fstat(fd)

    def test_group_handoff_rejects_bad_entry_before_descriptor_duplication(self):
        clock = Clock(uncertainty_seconds=lambda: 0.0)
        public_key = _public_key()
        original = (os.open(os.devnull, os.O_RDONLY),
                    os.open(os.devnull, os.O_RDONLY))
        metadata = _child_group_metadata(self.temp.name, original, public_key, count=1)
        metadata["assignments"][0]["version"] = True
        verifier = CatalogVerifier(public_key, clock=clock)
        with mock.patch("steamboat_connector.runtime_pin_handoff.os.dup",
                        side_effect=AssertionError("metadata validation must run first")):
            with self.assertRaises(RuntimePinHandoffError):
                validate_child_pin(metadata, clock=clock, verifier=verifier)
        for fd in original:
            os.fstat(fd)
            os.close(fd)

    def test_child_handoff_enforces_size_bound_before_base64_decode(self):
        import steamboat_connector.runtime_pin_handoff as handoff_module
        clock = Clock(uncertainty_seconds=lambda: 0.0)
        public_key = _public_key()
        original = (os.open(os.devnull, os.O_RDONLY),
                    os.open(os.devnull, os.O_RDONLY))
        metadata = _child_group_metadata(self.temp.name, original, public_key, count=1)
        metadata["signed_catalog"] = "A" * MAX_HANDOFF_BYTES
        verifier = CatalogVerifier(public_key, clock=clock)
        with mock.patch.object(handoff_module, "_decode",
                               side_effect=AssertionError("decode ran before size check")):
            with self.assertRaises(RuntimePinHandoffError):
                validate_child_pin(metadata, clock=clock, verifier=verifier)
        for fd in original:
            os.fstat(fd)
            os.close(fd)

    def test_second_dup_failure_closes_only_the_acquired_copy(self):
        import steamboat_connector.runtime_pin_handoff as handoff_module
        clock = Clock(uncertainty_seconds=lambda: 0.0)
        public_key = _public_key()
        original = (os.open(os.devnull, os.O_RDONLY),
                    os.open(os.devnull, os.O_RDONLY))
        metadata = _child_group_metadata(self.temp.name, original, public_key, count=2)
        verifier = CatalogVerifier(public_key, clock=clock)
        real_dup = os.dup
        copied = []

        class Owner:
            def __init__(self, fds):
                self.fds = fds

            def close(self):
                for fd in self.fds:
                    os.close(fd)

        def fail_second_duplicate(fd):
            if not copied:
                copied.append(real_dup(fd))
                return copied[-1]
            raise OSError("injected second dup failure")

        with (mock.patch.object(handoff_module.os, "dup", side_effect=fail_second_duplicate),
              mock.patch("steamboat_connector.aggregate_artifact_pin.validate_inherited_group_pin",
                         return_value=(Owner(original), object()))):
            with self.assertRaises(OSError) as caught:
                validate_child_pin(metadata, clock=clock, verifier=verifier)
        caught.exception.pin_owner.close()
        with self.assertRaises(OSError):
            os.fstat(copied[0])
        for fd in original:
            with self.assertRaises(OSError):
                os.fstat(fd)

    def test_partial_owner_is_allocated_before_descriptor_duplication(self):
        import steamboat_connector.runtime_pin_handoff as handoff_module
        clock = Clock(uncertainty_seconds=lambda: 0.0)
        public_key = _public_key()
        original = (os.open(os.devnull, os.O_RDONLY),
                    os.open(os.devnull, os.O_RDONLY))
        metadata = _child_group_metadata(self.temp.name, original, public_key, count=2)
        verifier = CatalogVerifier(public_key, clock=clock)
        class Owner:
            def __init__(self, fds):
                self.fds = fds

            def close(self):
                for fd in self.fds:
                    os.close(fd)

        with (mock.patch("steamboat_connector.aggregate_artifact_pin.validate_inherited_group_pin",
                         return_value=(Owner(original), object())),
              mock.patch.object(handoff_module, "_owner_for_partial_pair",
                                side_effect=MemoryError("injected owner allocation failure")),
              mock.patch.object(handoff_module.os, "dup",
                                side_effect=AssertionError("dup must follow owner allocation"))):
            with self.assertRaises(MemoryError):
                validate_child_pin(metadata, clock=clock, verifier=verifier)
        for fd in original:
            os.fstat(fd)
            os.close(fd)

    @unittest.skipUnless(sys.platform.startswith("linux"),
                         "descriptor close ambiguity follows Linux fd reuse semantics")
    def test_ambiguous_partial_close_is_sticky_across_fd_reuse(self):
        import steamboat_connector.runtime_pin_handoff as handoff_module
        clock = Clock(uncertainty_seconds=lambda: 0.0)
        public_key = _public_key()
        original = (os.open(os.devnull, os.O_RDONLY),
                    os.open(os.devnull, os.O_RDONLY))
        metadata = _child_group_metadata(self.temp.name, original, public_key, count=2)
        verifier = CatalogVerifier(public_key, clock=clock)
        real_dup, real_close = os.dup, os.close
        copied = []

        class Owner:
            def __init__(self, fds):
                self.fds = fds

            def close(self):
                for fd in self.fds:
                    os.close(fd)

        def fail_second_duplicate(fd):
            if not copied:
                copied.append(real_dup(fd))
                return copied[-1]
            raise OSError("injected second dup failure")

        def close_then_report_unknown(fd):
            real_close(fd)
            if fd == copied[0]:
                raise OSError("injected ambiguous close result")

        with (mock.patch.object(handoff_module.os, "dup", side_effect=fail_second_duplicate),
              mock.patch.object(handoff_module.os, "close",
                                side_effect=close_then_report_unknown),
              mock.patch("steamboat_connector.aggregate_artifact_pin.validate_inherited_group_pin",
                         return_value=(Owner(original), object()))):
            with self.assertRaises(ArtifactPinError) as caught:
                validate_child_pin(metadata, clock=clock, verifier=verifier)
        composite = caught.exception.pin_owner
        # Retain both the already validated first assignment and the current
        # pair whose close result is ambiguous.
        self.assertEqual(len(composite.owners), 2)
        self.assertEqual(composite.owners[1]._uncertain_descriptors["global_fd"],
                         copied[0])
        replacement = os.open(os.devnull, os.O_RDONLY)
        if replacement != copied[0]:
            os.dup2(replacement, copied[0])
            os.close(replacement)
            replacement = copied[0]
        self.assertEqual(replacement, copied[0])
        with self.assertRaises(RuntimePinHandoffError):
            composite.close()
        os.fstat(replacement)
        os.close(replacement)

    def test_validator_unknown_owner_is_combined_with_prior_owner_once(self):
        clock = Clock(uncertainty_seconds=lambda: 0.0)
        public_key = _public_key()
        original = (os.open(os.devnull, os.O_RDONLY),
                    os.open(os.devnull, os.O_RDONLY))
        metadata = _child_group_metadata(self.temp.name, original, public_key, count=2)
        verifier = CatalogVerifier(public_key, clock=clock)
        calls = []

        class Owner:
            def __init__(self, fds=(), fail=False):
                self.fds = fds
                self.fail = fail
                self.calls = 0

            def close(self):
                self.calls += 1
                if self.fail:
                    raise OSError("uncertain child close")
                for fd in self.fds:
                    os.close(fd)

        def validate(global_fd, role_fd, **kwargs):
            if not calls:
                owner = Owner((global_fd, role_fd))
                calls.append(owner)
                return owner, object()
            owner = Owner((global_fd, role_fd), fail=True)
            error = RuntimeError("validator cleanup is uncertain")
            error.pin_owner = owner
            calls.append(owner)
            raise error

        with mock.patch("steamboat_connector.aggregate_artifact_pin.validate_inherited_group_pin",
                        side_effect=validate):
            with self.assertRaises(RuntimeError) as caught:
                validate_child_pin(metadata, clock=clock, verifier=verifier)
        composite = caught.exception.pin_owner
        self.assertEqual(composite.owners, tuple(calls))
        with self.assertRaises(RuntimePinHandoffError):
            composite.close()
        with self.assertRaises(RuntimePinHandoffError):
            composite.close()
        self.assertEqual([owner.calls for owner in calls], [1, 1])
        for fd in calls[1].fds:
            try:
                os.close(fd)
            except OSError:
                pass


@unittest.skipUnless(sys.platform.startswith("linux")
                     and os.environ.get("STEAMBOAT_ASSIGNED_TEST_SOURCE")
                     and os.environ.get("STEAMBOAT_ASSIGNED_TEST_SCRATCH"),
                     "parent Linux gate supplies genuine signed artifacts and bounded scratch")
class RuntimePinNativeHandoffTests(unittest.TestCase):
    def test_supervised_exec_validates_inherited_pin_and_keeps_store_locked(self):
        from steamboat_connector.aggregate_artifact_pin import (
            AggregateArtifactPinError, RuntimeArtifactGroupPin)
        from steamboat_connector.artifact_pin import RuntimeArtifactPin
        from steamboat_connector.artifacts import (ArtifactInstallBusy,
                                                    ArtifactInstaller)
        from steamboat_connector.catalog import (ARTIFACT_FILENAMES,
                                                  RUNTIME_LOCK_SHA256,
                                                  CatalogVerifier)
        from steamboat_runtime.manifest import (MODEL_ID, MODEL_REVISION,
                                                 SOURCE_HASHES, load_manifest)
        from steamboat_security.clock import Clock
        from tests.connector.test_artifacts import (
            _ACCOUNT, _PUBLIC, _assignment_bundle, _sign_document)

        source = Path(os.environ["STEAMBOAT_ASSIGNED_TEST_SOURCE"])
        scratch = Path(os.environ["STEAMBOAT_ASSIGNED_TEST_SCRATCH"])
        manifest = load_manifest(source)
        now = int(time.time())
        file_entries = {}
        for filename, digest in manifest["files"].items():
            info = (source / filename).lstat()
            self.assertTrue(stat.S_ISREG(info.st_mode))
            file_entries[filename] = {"sha256": digest,
                                      "size_bytes": info.st_size}
        manifest_bytes = (source / "modelmanifest.json").read_bytes()
        file_entries["modelmanifest.json"] = {
            "sha256": hashlib.sha256(manifest_bytes).hexdigest(),
            "size_bytes": len(manifest_bytes)}
        components = {
            name: {"file": item["file"], "layer_range": item["layer_range"],
                   "sha256": item["sha256"],
                   "size_bytes": file_entries[item["file"]]["size_bytes"]}
            for name, item in manifest["components"].items()}
        catalog_payload = {
            "schema_version": 1, "catalog_revision": 1,
            "issued_at": now - 10, "expires_at": now + 3600,
            "model": {"model_id": MODEL_ID, "model_revision": MODEL_REVISION,
                      "tokenizer_revision": MODEL_REVISION, "source_hashes": SOURCE_HASHES,
                      "device": "cpu", "dtype": "float32", "attention": "eager",
                      "compression": "none", "layout": "batch_sequence_hidden",
                      "batch_size": 1, "hidden_size": 64, "vocabulary_size": 32000,
                      "layers": 8, "model_context": 2048, "runtime_context": 1152,
                      "tied_input_output_weights": False},
            "runtime": {"os": "linux", "architecture": "amd64", "python": "3.12.15",
                        "torch": "2.14.1+cpu", "transformers": "5.19.0",
                        "grpcio": "1.84.0", "protobuf": "7.36.2",
                        "lock_sha256": RUNTIME_LOCK_SHA256},
            "manifest": {"filename": "modelmanifest.json",
                         "fingerprint": manifest["fingerprint"],
                         **file_entries["modelmanifest.json"]},
            "components": components, "files": file_entries}
        catalog_bytes = _sign_document(catalog_payload, "catalog")
        clock = Clock(uncertainty_seconds=lambda: 0.0)
        verifier = CatalogVerifier(_PUBLIC, clock=clock)

        class SourceRetriever:
            def iter_chunks(self, filename, *, deadline, max_chunk_bytes):
                if filename not in ARTIFACT_FILENAMES:
                    raise ValueError("unapproved source artifact")
                path = source / filename
                if not stat.S_ISREG(path.lstat().st_mode):
                    raise ValueError("source artifact is not regular")
                with path.open("rb") as stream:
                    while True:
                        chunk = stream.read(max_chunk_bytes)
                        if not chunk:
                            return
                        yield chunk

        device_id = "dev_" + "2" * 32
        assignment_id = "asg_" + "3" * 32
        signed_catalog = verifier.verify_catalog(catalog_bytes, now=now)
        assignment_bytes, _ = _assignment_bundle(
            verifier, signed_catalog, role="host", component="worker-1", now=now,
            assignment_id=assignment_id, device_id=device_id)
        with tempfile.TemporaryDirectory(dir=scratch) as temporary:
            installer = ArtifactInstaller(Path(temporary) / "store", verifier,
                disk_ceiling_bytes=256 * 1024 * 1024,
                disk_headroom_bytes=16 * 1024 * 1024, wall_clock=lambda: now)
            installer.install(catalog_bytes, assignment_bytes, SourceRetriever(),
                              account_id=_ACCOUNT, device_id=device_id, role="host")
            view = installer.open_view(assignment_id, account_id=_ACCOUNT,
                                       device_id=device_id, role="host", now=now)
            pin = RuntimeArtifactGroupPin.acquire(
                [view], clock=clock, runtime_boot_id="d" * 32,
                worker_boot_ids={"worker-1": "e" * 32})
            backend_root = Path(temporary) / "supervisor"
            backend_root.mkdir()
            cgroup_root = backend_root / "cgroups"
            cgroup_root.mkdir()
            cgroup = FakeCgroup(cgroup_root)
            backend = ProcessRoleBackend(backend_root / "state", cgroup)
            state_root = backend_root / "state"
            state_root.mkdir(mode=0o700)
            self.assertEqual(stat.S_IMODE(state_root.lstat().st_mode), 0o700)
            self.assertTrue(backend.configure_pinned_role(
                "host", {"test_mode": True}, pin, catalog_verifier=verifier))
            metadata = backend._pinned_roles["host"][2]
            repo_root = Path(__file__).resolve().parents[2]
            child_script = "\n".join((
                "import base64, json, os, site, sys, time",
                "gate = int(sys.argv[2]); release = os.read(gate, 1); os.close(gate)",
                "if release != b'R': raise SystemExit(65)",
                "for path in site.getsitepackages(): site.addsitedir(path)",
                "sys.path.insert(0, os.path.join(sys.argv[3], 'src'))",
                "from steamboat_connector.runtime_pin_handoff import validate_child_pin",
                "from steamboat_connector.catalog import CatalogVerifier",
                "from steamboat_security.clock import Clock",
                "p = json.loads(sys.argv[1]); c = Clock(uncertainty_seconds=lambda: 0.0)",
                "v = CatalogVerifier(base64.b64decode(p['public_key']), clock=c)",
                "owner = validate_child_pin(p, clock=c, verifier=v)",
                "print('READY', flush=True)",
                "while True: time.sleep(0.05)"))

            def spawn(_command, **kwargs):
                gate_fd = kwargs["pass_fds"][0]
                return REAL_POPEN(
                    [sys.executable, "-I", "-S", "-c", child_script,
                     json.dumps(metadata), str(gate_fd), str(repo_root)],
                    **kwargs)

            def wait_for_empty(owned, deadline):
                while time.monotonic() < deadline:
                    if owned.process.poll() is not None:
                        cgroup.set_empty(owned.group)
                        return True
                    time.sleep(0.005)
                return False

            backend._wait_empty = wait_for_empty
            try:
                with mock.patch("steamboat_connector.process_supervisor.subprocess.Popen",
                                side_effect=spawn):
                    self.assertTrue(backend.start("host", sample_policy()))
                owned = backend._owned["host"]
                # The child has validated the inherited pair and is blocked in
                # its loop. Closing the parent's pin now tests the child's own
                # real flock ownership across exec.
                pin.release()
                with self.assertRaises(ArtifactInstallBusy):
                    installer.deactivate("host", compute_stopped=True)
                self.assertTrue(backend.stop(["host"], 3.0)["host"])
                reacquired = RuntimeArtifactGroupPin.acquire(
                    [view], clock=clock, runtime_boot_id="f" * 32,
                    worker_boot_ids={"worker-1": "e" * 32})
                reacquired.release()

                # Exercise the coordinator's distinct single-pin validator
                # through the same actual exec/pass_fds/startup-gate path.
                coordinator_id = "asg_" + "4" * 32
                coordinator_bytes, _ = _assignment_bundle(
                    verifier, signed_catalog, role="coordinator",
                    component="coordinator", now=now,
                    assignment_id=coordinator_id, device_id=device_id)
                installer.install(catalog_bytes, coordinator_bytes, SourceRetriever(),
                                  account_id=_ACCOUNT, device_id=device_id,
                                  role="coordinator")
                coordinator_view = installer.open_view(
                    coordinator_id, account_id=_ACCOUNT, device_id=device_id,
                    role="coordinator", now=now)
                coordinator_pin = RuntimeArtifactPin.acquire(
                    coordinator_view, clock=clock, boot_id="7" * 32)
                self.assertTrue(backend.configure_pinned_role(
                    "coordinator", {"test_mode": True}, coordinator_pin,
                    catalog_verifier=verifier))
                metadata = backend._pinned_roles["coordinator"][2]
                with mock.patch("steamboat_connector.process_supervisor.subprocess.Popen",
                                side_effect=spawn):
                    self.assertTrue(backend.start("coordinator", sample_policy()))
                coordinator_pin.release()
                with self.assertRaises(ArtifactInstallBusy):
                    installer.deactivate("coordinator", compute_stopped=True)
                self.assertTrue(backend.stop(["coordinator"], 3.0)["coordinator"])
                single_reacquired = RuntimeArtifactPin.acquire(
                    coordinator_view, clock=clock, boot_id="8" * 32)
                single_reacquired.release()
            finally:
                if "host" in backend._owned:
                    backend.stop(["host"], 3.0)
                if getattr(pin, "_state", None) == "open":
                    pin.release()
                if "coordinator" in backend._owned:
                    backend.stop(["coordinator"], 3.0)
                if "coordinator_pin" in locals() and not coordinator_pin._released:
                    coordinator_pin.release()


if __name__ == "__main__":
    unittest.main()
