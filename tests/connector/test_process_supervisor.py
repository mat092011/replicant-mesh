import os
from pathlib import Path
import signal
import tempfile
from types import SimpleNamespace
import time
import unittest
from unittest import mock

from steamboat_connector.process_supervisor import ProcessRoleBackend


def sample_policy():
    reservation = {
        "weights_bytes": 10, "kv_bytes": 10, "temporary_bytes": 10,
        "runtime_bytes": 10, "communication_bytes": 10, "capture_bytes": 10,
        "cpu_quota_millis": 100, "disk_bytes": 1,
        "send_bytes_per_second": 1, "receive_bytes_per_second": 1,
        "total_network_bytes": 1, "cleanup_send_bytes_per_second": 1,
        "cleanup_receive_bytes_per_second": 1, "cleanup_total_network_bytes": 1,
        "sessions": 1, "queued_calls": 1, "max_request_seconds": 30,
    }
    limits = {
        "memory_ceiling_bytes": 1000, "memory_headroom_bytes": 100,
        "cpu_quota_millis": 1000, "disk_ceiling_bytes": 1000,
        "send_bytes_per_second": 100, "receive_bytes_per_second": 100,
        "total_network_bytes": 1000, "cleanup_send_bytes_per_second": 10,
        "cleanup_receive_bytes_per_second": 10, "cleanup_total_network_bytes": 100,
        "max_sessions": 1, "max_queued_calls": 1, "max_request_seconds": 30,
    }
    return {"version": 1, "pool_id": "test-pool", "limits": limits,
            "reservations": {"host": dict(reservation),
                             "coordinator": dict(reservation)},
            "required_telemetry": []}


class FakeCgroup:
    def __init__(self, root):
        self.root = Path(root)
        self.group = None
        self.attached = False
        self.fail_attach = False

    def create_group(self, name, policy, role):
        self.group = self.root / name
        self.group.mkdir()
        (self.group / "cgroup.events").write_text("populated 1\n", encoding="ascii")
        (self.group / "cgroup.procs").write_text("", encoding="ascii")
        return self.group

    def attach_child(self, group, process):
        if self.fail_attach:
            raise OSError("attach refused")
        self.attached = True
        (Path(group) / "cgroup.procs").write_text(str(process.pid), encoding="ascii")

    def set_empty(self):
        (self.group / "cgroup.events").write_text("populated 0\n", encoding="ascii")


class FakeProcess:
    pid = 43121

    def __init__(self, args, kwargs, cgroup):
        self.args = args
        self.kwargs = kwargs
        self.cgroup = cgroup
        self.returncode = None
        self.stdout = object()

    def poll(self):
        return self.returncode

    def wait(self, timeout=None):
        if self.returncode is None:
            import subprocess
            raise subprocess.TimeoutExpired(self.args, timeout)
        return self.returncode

    def on_signal(self, sig, *, kill_descendants=True):
        if sig in (signal.SIGTERM, 9):
            self.returncode = 0
        if sig == 9:
            if kill_descendants:
                self.cgroup.set_empty()


class ProcessSupervisorTests(unittest.TestCase):
    def setUp(self):
        platform_patch = mock.patch("steamboat_connector.process_supervisor.sys.platform", "linux")
        platform_patch.start()
        self.addCleanup(platform_patch.stop)
        storage_patch = mock.patch("steamboat_connector.process_supervisor.atomic_write_private",
                                   side_effect=lambda path, data: Path(path).write_bytes(data))
        storage_patch.start()
        self.addCleanup(storage_patch.stop)
        self.readiness_patch = mock.patch.object(
            ProcessRoleBackend, "_read_ready",
            return_value=True)
        self.readiness_patch.start()
        self.addCleanup(self.readiness_patch.stop)
        signal_patch = mock.patch("steamboat_connector.process_supervisor.signal",
                                  SimpleNamespace(SIGTERM=15, SIGKILL=9))
        signal_patch.start()
        self.addCleanup(signal_patch.stop)
        write_patch = mock.patch(
            "steamboat_connector.process_supervisor.os.write",
            side_effect=lambda fd, data: len(data) if data == b"R" else 0)
        write_patch.start()
        self.addCleanup(write_patch.stop)
        self.temp = tempfile.TemporaryDirectory()
        os.chmod(self.temp.name, 0o700)
        self.cgroup = FakeCgroup(self.temp.name)
        self.backend = ProcessRoleBackend(self.temp.name, self.cgroup)

    def tearDown(self):
        self.temp.cleanup()

    def _spawn_patch(self, *, fail_attach=False, kill_descendants=True):
        self.cgroup.fail_attach = fail_attach
        holder = {}

        def spawn(*args, **kwargs):
            process = FakeProcess(args[0], kwargs, self.cgroup)
            holder["process"] = process
            return process

        def killpg(pid, sig):
            holder["process"].on_signal(sig, kill_descendants=kill_descendants)

        return holder, mock.patch("steamboat_connector.process_supervisor.subprocess.Popen",
                                  side_effect=spawn), mock.patch(
            "steamboat_connector.process_supervisor.os.killpg", side_effect=killpg,
            create=True)

    def test_child_is_owned_and_attached_before_start_gate_opens(self):
        holder, popen, killpg = self._spawn_patch()
        def checked_write(fd, data):
            if data == b"R":
                self.assertTrue(self.cgroup.attached)
                return len(data)
            return 0

        with popen, killpg, mock.patch("steamboat_connector.process_supervisor.os.write",
                                      side_effect=checked_write):
            self.assertTrue(self.backend.start("host", sample_policy()))
        process = holder["process"]
        self.assertTrue(self.cgroup.attached)
        self.assertEqual(process.args[1:5], ["-I", "-S", "-m",
                                             "steamboat_connector.process_bootstrap"])
        self.assertEqual(process.args[5], "host")
        self.assertEqual(self.backend.status()["host"]["ready"], True)
        self.assertEqual(process.kwargs["stderr"], -3)  # subprocess.DEVNULL

    def test_attach_failure_never_releases_child_or_reports_ready(self):
        holder, popen, killpg = self._spawn_patch(fail_attach=True)
        with popen, killpg:
            self.assertFalse(self.backend.start("host", sample_policy()))
        self.assertNotIn("host", self.backend.status())
        self.assertIsNotNone(holder["process"].poll())

    def test_stop_escalates_ignored_term_and_waits_for_empty_cgroup(self):
        holder, popen, _ = self._spawn_patch()
        with popen:
            self.assertTrue(self.backend.start("host", sample_policy()))
        signals = []

        def ignore_term(pid, sig):
            signals.append(sig)
            if sig == 9:
                holder["process"].on_signal(sig)

        with mock.patch("steamboat_connector.process_supervisor.os.killpg",
                        side_effect=ignore_term, create=True):
            self.assertTrue(self.backend.stop(["host"], grace_seconds=0.2)["host"])
        self.assertEqual(signals, [signal.SIGTERM, 9])
        self.assertEqual(self.backend.status(), {})

    def test_exited_leader_with_live_descendant_keeps_ownership(self):
        holder, popen, _ = self._spawn_patch(kill_descendants=False)
        with popen:
            self.assertTrue(self.backend.start("host", sample_policy()))
        with mock.patch("steamboat_connector.process_supervisor.os.killpg",
                        side_effect=lambda pid, sig: holder["process"].on_signal(
                            sig, kill_descendants=False), create=True):
            self.assertFalse(self.backend.stop(["host"], grace_seconds=0.05)["host"])
        self.assertIn("host", self.backend.status())
        self.assertTrue(self.backend.status()["host"]["cgroup_populated"])

    def test_unknown_role_does_not_spawn(self):
        with mock.patch("steamboat_connector.process_supervisor.subprocess.Popen") as spawn:
            self.assertFalse(self.backend.start("consumer", sample_policy()))
        spawn.assert_not_called()

    def test_ready_protocol_reader_rejects_oversized_stdout_line(self):
        self.readiness_patch.stop()
        class Selector:
            def register(self, stream, events):
                pass

            def select(self, timeout):
                return [(None, None)]

            def close(self):
                pass

        class Stream:
            def fileno(self):
                return 99

            def close(self):
                pass

        process = type("Process", (), {"stdout": Stream()})()
        with mock.patch("steamboat_connector.process_supervisor.selectors.DefaultSelector",
                        return_value=Selector()), mock.patch(
                "steamboat_connector.process_supervisor.os.read",
                return_value=b"X" * 65) as read:
            self.assertFalse(ProcessRoleBackend._read_ready(process, 1))
        read.assert_called_once_with(99, 65)


if __name__ == "__main__":
    unittest.main()
