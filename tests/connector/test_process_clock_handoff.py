"""C2 supervised-process Clock handoff; lifecycle fixtures are not a role runtime."""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

from steamboat_connector.c2_child_config import build_c2_child_config
from steamboat_connector.process_supervisor import ProcessRoleBackend
from steamboat_connector.resources import ResourceError
from steamboat_security.clock import Clock
from steamboat_security.root_transition_launch import RoleLaunchSpec
import tests.connector.test_process_supervisor as supervisor_fixtures


def _coordinator_config():
    spec = RoleLaunchSpec("a" * 64, "acct_" + "1" * 32, "dev_" + "2" * 32,
        "personal_coordinator", "1a", "b" * 64, "c" * 64, 1,
        "d" * 32, 1, "e" * 64, "f" * 32)
    return build_c2_child_config(role="coordinator", selected_root="/protected/selected",
        protected_root="/protected", configuration_path="/protected/role.json",
        launch_spec=spec)


class _LifecycleCgroup:
    """Filesystem stand-in for cgroup lifecycle only; it does not emulate limits."""
    def __init__(self, root):
        self.root = Path(root)
        self.group = None

    def create_group(self, name, _policy, _role):
        self.group = self.root / name
        self.group.mkdir()
        (self.group / "cgroup.events").write_text("populated 0\n", encoding="ascii")
        (self.group / "cgroup.procs").write_text("", encoding="ascii")
        return self.group

    def attach_child(self, group, process):
        Path(group, "cgroup.events").write_text("populated 1\n", encoding="ascii")
        Path(group, "cgroup.procs").write_text(str(process.pid), encoding="ascii")

    def mark_empty(self):
        Path(self.group, "cgroup.events").write_text("populated 0\n", encoding="ascii")
        Path(self.group, "cgroup.procs").write_text("", encoding="ascii")

    def remove_empty_group(self, group):
        group = Path(group)
        if not ProcessRoleBackend._events_populated(group):
            return False
        (group / "cgroup.events").unlink()
        (group / "cgroup.procs").unlink()
        group.rmdir()
        return True


def _policy():
    return supervisor_fixtures.sample_policy()


class ProcessClockHandoffTests(unittest.TestCase):
    @unittest.skipUnless(sys.platform.startswith("linux"), "clock handoff is Linux-only")
    def test_pre_popen_cancel_releases_lease_but_ambiguous_popen_retains_owner(self):
        class BridgeDouble:
            instances = []
            def __init__(self, _clock):
                self.read_fd, self.write_fd = os.pipe()
                self.cancelled = False
                self.stop_calls = 0
                type(self).instances.append(self)
            def begin_spawn(self):
                return self.read_fd
            def cancel_spawn_without_child(self):
                self.cancelled = True
                for fd_name in ("read_fd", "write_fd"):
                    fd = getattr(self, fd_name)
                    setattr(self, fd_name, -1)
                    if fd >= 0:
                        os.close(fd)
                return True
            def stop(self):
                self.stop_calls += 1
                return True

        with tempfile.TemporaryDirectory() as temporary:
            os.chmod(temporary, 0o700)
            cgroup = _LifecycleCgroup(temporary)
            with mock.patch("steamboat_connector.process_supervisor.sys.platform", "linux"):
                backend = ProcessRoleBackend(temporary, cgroup)
            backend.bind_authority_clock(Clock.system(uncertainty_seconds=lambda: 0.01))
            def write_private(path, data):
                Path(path).write_bytes(data)
                os.chmod(path, 0o600)
            reader = lambda path, **_kw: json.loads(Path(path).read_text(encoding="utf-8"))
            with mock.patch("steamboat_connector.process_supervisor.atomic_write_private",
                            side_effect=write_private), \
                 mock.patch("steamboat_connector.process_supervisor.read_private_json",
                            side_effect=reader), \
                 mock.patch("steamboat_connector.clock_bridge.OwnedClockBridge", BridgeDouble):
                self.assertTrue(backend.configure_role("coordinator", _coordinator_config()))
                cancelled = threading.Event()
                popen = mock.Mock()
                popen.side_effect = AssertionError("Popen must not be entered")
                with mock.patch("steamboat_connector.process_supervisor.subprocess.Popen", popen):
                    self.assertIsNone(backend.spawn_owned_start("coordinator", _policy(),
                        cancel_event=cancelled,
                        before_popen_check=lambda: cancelled.set()))
                self.assertTrue(BridgeDouble.instances[-1].cancelled)
                popen.assert_not_called()

                failing_popen = mock.Mock(side_effect=OSError("ambiguous spawn result"))
                with mock.patch("steamboat_connector.process_supervisor.subprocess.Popen",
                                failing_popen):
                    self.assertIsNone(backend.spawn_owned_start("coordinator", _policy()))
                owner = backend._owned["coordinator"]
                self.assertTrue(owner.clock_bridge_unknown_spawn)
                self.assertIsNotNone(owner.clock_bridge)
                self.assertGreaterEqual(owner.clock_bridge.stop_calls, 1)
                self.assertFalse(owner.clock_bridge.cancelled)
                self.assertIn("coordinator", backend._pin_release_blocked)
                self.assertFalse(backend.stop(("coordinator",), 0.05)["coordinator"])
                # Unknown outcome retains the leased FD and its strong owner;
                # close only the test double's descriptors during fixture cleanup.
                owner.clock_bridge.cancel_spawn_without_child()

    @unittest.skipUnless(sys.platform.startswith("linux") and
                         sys.implementation.name == "cpython" and
                         sys.version_info[:2] == (3, 12),
                         "requires pinned Linux CPython 3.12 process ownership")
    def test_actual_child_samples_captured_clock_only_after_handoff_document(self):
        from steamboat_connector.clock_bridge import active_clock_bridge_generations

        with tempfile.TemporaryDirectory() as temporary:
            os.chmod(temporary, 0o700)
            cgroup = _LifecycleCgroup(temporary)
            backend = ProcessRoleBackend(temporary, cgroup)
            clock = Clock.system(uncertainty_seconds=lambda: 0.01)
            backend.bind_authority_clock(clock)
            config = _coordinator_config()
            self.assertTrue(backend.configure_role("coordinator", config))
            self.assertIsNone(backend.bind_authority_clock(clock))

            source = Path(__file__).resolve().parents[2] / "src"
            child_code = (
                "import json,os,sys; gate=int(sys.argv[2]); os.read(gate,1); os.close(gate); "
                "sys.path.insert(0,sys.argv[3]); "
                "from steamboat_connector.clock_bridge import ChildClockBridge; "
                "doc=json.load(open(sys.argv[1],encoding='utf-8')); "
                "bridge=ChildClockBridge(doc['clock_handoff']); "
                "sample=bridge.clock.sample(); print(json.dumps({'wall':sample.wall,"
                "'monotonic':sample.monotonic,'uncertainty':sample.uncertainty})); "
                "bridge.stop()")
            launched = {}

            def popen(_command, **kwargs):
                passed = tuple(kwargs["pass_fds"])
                self.assertGreaterEqual(len(passed), 2)
                self.assertEqual(len(set(passed)), len(passed))
                child_command = [sys.executable, "-c", child_code,
                    os.fspath(backend._config_path("coordinator")),
                    str(passed[0]), os.fspath(source)]
                process = subprocess.Popen(child_command, **kwargs)
                launched["process"] = process
                launched["passed"] = passed
                return process

            with mock.patch("steamboat_connector.process_supervisor.subprocess.Popen",
                            side_effect=popen), \
                 mock.patch.object(ProcessRoleBackend, "_attach_child_safely",
                                   autospec=True,
                                   side_effect=lambda self, group, process:
                                       self.cgroup.attach_child(group, process)):
                handle = backend.spawn_owned_start("coordinator", _policy())
            self.assertIsNotNone(handle)
            owned = handle._owned
            self.assertIs(owned.clock_bridge._clock, clock)
            document = json.loads(backend._config_path("coordinator").read_text(encoding="utf-8"))
            self.assertEqual(set(document), {"version", "role", "config", "policy", "clock_handoff"})
            self.assertEqual(document["config"], config)
            self.assertEqual(document["clock_handoff"]["child_pid"], launched["process"].pid)
            self.assertIn(document["clock_handoff"]["fd"], launched["passed"])
            stdout, _stderr = launched["process"].communicate(timeout=5)
            sample = json.loads(stdout.decode("utf-8"))
            self.assertGreater(sample["wall"], 0)
            self.assertGreater(sample["monotonic"], 0)
            self.assertLessEqual(sample["uncertainty"], 30)

            # The helper process has exited; this fixture proves only process
            # ownership and bridge retirement, never role READY or model load.
            cgroup.mark_empty()
            deadline = time.monotonic() + 2
            reclaimed = False
            while time.monotonic() < deadline and not reclaimed:
                reclaimed = backend.stop(("coordinator",), 1).get("coordinator") is True
                if not reclaimed:
                    time.sleep(0.02)
            self.assertTrue(reclaimed)
            self.assertEqual(active_clock_bridge_generations(), 0)

    @unittest.skipUnless(sys.platform.startswith("linux") and
                         sys.implementation.name == "cpython" and
                         sys.version_info[:2] == (3, 12),
                         "requires pinned Linux CPython 3.12 process ownership")
    def test_stop_is_fast_during_clock_provider_and_retains_until_bridge_quiesces(self):
        from steamboat_connector.clock_bridge import active_clock_bridge_generations

        entered, release = threading.Event(), threading.Event()
        def wall_provider():
            entered.set()
            release.wait(5)
            return time.time()

        with tempfile.TemporaryDirectory() as temporary:
            os.chmod(temporary, 0o700)
            cgroup = _LifecycleCgroup(temporary)
            backend = ProcessRoleBackend(temporary, cgroup)
            clock = Clock(wall=wall_provider, uncertainty_seconds=lambda: 0.01)
            backend.bind_authority_clock(clock)
            self.assertTrue(backend.configure_role("coordinator", _coordinator_config()))
            source = Path(__file__).resolve().parents[2] / "src"
            child_code = (
                "import json,os,sys; gate=int(sys.argv[2]); os.read(gate,1); os.close(gate); "
                "sys.path.insert(0,sys.argv[3]); "
                "from steamboat_connector.clock_bridge import ChildClockBridge; "
                "doc=json.load(open(sys.argv[1],encoding='utf-8')); "
                "bridge=ChildClockBridge(doc['clock_handoff']); bridge.clock.sample()")

            def popen(_command, **kwargs):
                passed = tuple(kwargs["pass_fds"])
                child_command = [sys.executable, "-c", child_code,
                    os.fspath(backend._config_path("coordinator")), str(passed[0]),
                    os.fspath(source)]
                return subprocess.Popen(child_command, **kwargs)

            with mock.patch("steamboat_connector.process_supervisor.subprocess.Popen",
                            side_effect=popen), \
                 mock.patch.object(ProcessRoleBackend, "_attach_child_safely",
                                   autospec=True,
                                   side_effect=lambda self, group, process:
                                       self.cgroup.attach_child(group, process)):
                handle = backend.spawn_owned_start("coordinator", _policy())
            self.assertIsNotNone(handle)
            owned = handle._owned
            process = owned.process
            self.assertTrue(entered.wait(3), "child did not reach the blocked authority Clock")

            before = time.monotonic()
            self.assertFalse(backend.stop(("coordinator",), 0.2)["coordinator"])
            self.assertLess(time.monotonic() - before, 1.0)
            process.wait(timeout=3)
            cgroup.mark_empty()
            self.assertFalse(backend.stop(("coordinator",), 0.1)["coordinator"])
            self.assertIs(backend._owned["coordinator"], owned)
            self.assertFalse(owned.clock_bridge.quiescent)
            self.assertGreaterEqual(active_clock_bridge_generations(), 1)

            release.set()
            deadline = time.monotonic() + 3
            reclaimed = False
            while time.monotonic() < deadline and not reclaimed:
                reclaimed = backend.stop(("coordinator",), 0.5)["coordinator"]
                if not reclaimed:
                    time.sleep(0.02)
            self.assertTrue(reclaimed)
            self.assertEqual(active_clock_bridge_generations(), 0)

    def test_c2_profile_without_bound_clock_fails_before_popen_but_legacy_is_unchanged(self):
        with tempfile.TemporaryDirectory() as temporary:
            os.chmod(temporary, 0o700)
            with mock.patch("steamboat_connector.process_supervisor.sys.platform", "linux"):
                backend = ProcessRoleBackend(temporary, _LifecycleCgroup(temporary))
                def write_private(path, data):
                    Path(path).write_bytes(data)
                    os.chmod(path, 0o600)
                with mock.patch("steamboat_connector.process_supervisor.atomic_write_private",
                                side_effect=write_private), \
                     mock.patch("steamboat_connector.process_supervisor.read_private_json",
                                side_effect=lambda path, **_kw: json.loads(
                                    Path(path).read_text(encoding="utf-8"))):
                    self.assertTrue(backend.configure_role("coordinator", _coordinator_config()))
                    with mock.patch("steamboat_connector.process_supervisor.subprocess.Popen") as popen:
                        self.assertIsNone(backend.spawn_owned_start("coordinator", _policy()))
                        popen.assert_not_called()

            legacy_dir = Path(temporary) / "legacy"
            legacy_dir.mkdir()
            with mock.patch("steamboat_connector.process_supervisor.sys.platform", "linux"):
                legacy = ProcessRoleBackend(legacy_dir, _LifecycleCgroup(legacy_dir))
            self.assertIsNone(legacy._authority_clock)
            self.assertIs(legacy.clock, time.monotonic)

    def test_authority_clock_is_exact_idempotent_and_separate_from_deadline_callable(self):
        with tempfile.TemporaryDirectory() as temporary:
            with mock.patch("steamboat_connector.process_supervisor.sys.platform", "linux"):
                backend = ProcessRoleBackend(temporary, _LifecycleCgroup(temporary), clock=lambda: 9.0)
            authority = Clock.system(uncertainty_seconds=lambda: 0.01)
            deadline_callable = backend.clock
            self.assertIsNone(backend.bind_authority_clock(authority))
            self.assertIsNone(backend.bind_authority_clock(authority))
            self.assertIs(backend.clock, deadline_callable)
            with self.assertRaises(TypeError):
                backend.bind_authority_clock(lambda: 1.0)
            with self.assertRaises(ResourceError):
                backend.bind_authority_clock(Clock.system(uncertainty_seconds=lambda: 0.01))


if __name__ == "__main__":
    unittest.main()
