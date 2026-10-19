import os
import json
from pathlib import Path
import shutil
import select
import signal
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import threading
import time
import unittest
from unittest import mock

from steamboat_connector.process_supervisor import (ProcessRoleBackend,
                                                     ROLE_CONFIG_MAX_BYTES,
                                                     READY_LINE_MAX)


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
        self.groups = []
        self.attached = False
        self.fail_attach = False
        self.create_entered = None
        self.create_release = None
        self.attach_entered = None
        self.attach_release = None

    def create_group(self, name, policy, role):
        if self.create_entered is not None:
            self.create_entered.set()
            self.create_release.wait(2)
        self.group = self.root / name
        self.group.mkdir()
        (self.group / "cgroup.events").write_text("populated 0\n", encoding="ascii")
        (self.group / "cgroup.procs").write_text("", encoding="ascii")
        self.groups.append(self.group)
        return self.group

    def attach_child(self, group, process):
        if self.attach_entered is not None:
            self.attach_entered.set()
            self.attach_release.wait(2)
        if self.fail_attach:
            raise OSError("attach refused")
        self.attached = True
        (Path(group) / "cgroup.events").write_text("populated 1\n", encoding="ascii")
        (Path(group) / "cgroup.procs").write_text(str(process.pid), encoding="ascii")

    def set_empty(self, group=None):
        (Path(group or self.group) / "cgroup.events").write_text(
            "populated 0\n", encoding="ascii")


class FakeProcess:
    pid = 43121

    def __init__(self, args, kwargs, cgroup):
        self.args = args
        self.pid = 43121 + (1 if args[4] == "coordinator" else 0)
        self.kwargs = kwargs
        self.cgroup = cgroup
        self.group = cgroup.group
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
                self.cgroup.set_empty(self.group)


class ProcessSupervisorTests(unittest.TestCase):
    def setUp(self):
        platform_patch = mock.patch("steamboat_connector.process_supervisor.sys.platform", "linux")
        platform_patch.start()
        self.addCleanup(platform_patch.stop)
        def write_private(path, data):
            Path(path).write_bytes(data)
            os.chmod(path, 0o600)
        storage_patch = mock.patch("steamboat_connector.process_supervisor.atomic_write_private",
                                   side_effect=write_private)
        storage_patch.start()
        self.addCleanup(storage_patch.stop)
        reader_patch = mock.patch(
            "steamboat_connector.process_supervisor.read_private_json",
            side_effect=lambda path, **kwargs: json.loads(Path(path).read_text(
                encoding="utf-8")))
        reader_patch.start()
        self.addCleanup(reader_patch.stop)
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
        self.assertTrue(self.backend.configure_role("host", {"test_mode": True}))
        self.assertTrue(self.backend.configure_role("coordinator", {"test_mode": True}))

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
        self.assertEqual(process.args[1:3], ["-I", "-S"])
        self.assertEqual(Path(process.args[3]).name, "process_bootstrap.py")
        self.assertEqual(process.args[4], "host")
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

    def test_multi_role_stop_signals_all_first_and_shares_one_deadline(self):
        holder = {}

        def spawn(*args, **kwargs):
            process = FakeProcess(args[0], kwargs, self.cgroup)
            holder[args[0][4]] = process
            return process

        with mock.patch("steamboat_connector.process_supervisor.subprocess.Popen",
                        side_effect=spawn):
            self.assertTrue(self.backend.start("host", sample_policy()))
            self.assertTrue(self.backend.start("coordinator", sample_policy()))
        events = []
        for process in holder.values():
            original_wait = process.wait

            def delayed_wait(timeout=None, *, _process=process, _original=original_wait):
                events.append(("wait", _process.args[4]))
                if _process.returncode is None and timeout and timeout > 0:
                    time.sleep(timeout)
                return _original(0)

            process.wait = delayed_wait

        def killpg(pid, sig):
            process = next(item for item in holder.values() if item.pid == pid)
            events.append(("signal", sig, process.args[4]))
            if sig == 9:
                process.on_signal(sig)

        started = time.monotonic()
        with mock.patch("steamboat_connector.process_supervisor.os.killpg",
                        side_effect=killpg, create=True):
            result = self.backend.stop(["host", "coordinator"], 0.2)
        elapsed = time.monotonic() - started
        self.assertEqual(result, {"host": True, "coordinator": True}, f"events={events}")
        self.assertLess(elapsed, 0.35)
        first_wait = next(index for index, event in enumerate(events) if event[0] == "wait")
        self.assertEqual([event[1] for event in events[:first_wait]],
                         [signal.SIGTERM, signal.SIGTERM])

    def test_duplicate_start_does_not_mutate_config_or_create_second_group(self):
        holder, popen, killpg = self._spawn_patch()
        original = (Path(self.temp.name) / "host-runtime.json").read_bytes()
        with popen, killpg:
            self.assertTrue(self.backend.start("host", sample_policy()))
            configured = (Path(self.temp.name) / "host-runtime.json").read_bytes()
            self.assertFalse(self.backend.start("host", sample_policy()))
            self.assertEqual((Path(self.temp.name) / "host-runtime.json").read_bytes(),
                             configured)
        self.assertEqual(len(self.cgroup.groups), 1)
        self.assertEqual(len(holder), 1)
        self.assertNotEqual((Path(self.temp.name) / "host-runtime.json").read_bytes(), original)

    def test_stop_cancels_queued_start_before_any_spawn(self):
        entered = threading.Event()
        release = threading.Event()
        self.cgroup.create_entered = entered
        self.cgroup.create_release = release
        spawned = mock.Mock()
        result = {}
        with mock.patch("steamboat_connector.process_supervisor.subprocess.Popen", spawned):
            thread = threading.Thread(target=lambda: result.setdefault(
                "started", self.backend.start("host", sample_policy())))
            thread.start()
            self.assertTrue(entered.wait(1))
            self.assertFalse(self.backend.start("host", sample_policy()))
            self.assertFalse(self.backend.stop(["host"], 1)["host"])
            release.set()
            thread.join(2)
        self.assertFalse(thread.is_alive())
        self.assertFalse(result["started"])
        spawned.assert_not_called()

    def test_controller_cancel_event_cancels_before_and_during_queued_start(self):
        cancelled = threading.Event()
        cancelled.set()
        with mock.patch("steamboat_connector.process_supervisor.subprocess.Popen") as spawn:
            self.assertFalse(self.backend.start("host", sample_policy(),
                                                cancel_event=cancelled))
        spawn.assert_not_called()

        cancelled.clear()
        entered = threading.Event()
        release = threading.Event()
        self.cgroup.create_entered = entered
        self.cgroup.create_release = release
        outcome = {}
        with mock.patch("steamboat_connector.process_supervisor.subprocess.Popen") as spawn:
            thread = threading.Thread(target=lambda: outcome.setdefault(
                "started", self.backend.start("host", sample_policy(),
                                              cancel_event=cancelled)))
            thread.start()
            self.assertTrue(entered.wait(1))
            cancelled.set()
            release.set()
            thread.join(2)
        self.assertFalse(thread.is_alive())
        self.assertFalse(outcome["started"])
        spawn.assert_not_called()

    def test_request_stop_interrupts_attach_and_final_stop_reclaims(self):
        holder, popen, _ = self._spawn_patch()
        attach_entered = threading.Event()
        attach_release = threading.Event()
        self.cgroup.attach_entered = attach_entered
        self.cgroup.attach_release = attach_release
        outcome = {}
        signals = []

        def killpg(pid, sig):
            signals.append(sig)
            holder["process"].on_signal(sig)

        with popen, mock.patch("steamboat_connector.process_supervisor.os.killpg",
                              side_effect=killpg, create=True), mock.patch(
                "steamboat_connector.process_supervisor.os.write",
                return_value=1) as gate_write:
            thread = threading.Thread(target=lambda: outcome.setdefault(
                "started", self.backend.start("host", sample_policy())))
            thread.start()
            self.assertTrue(attach_entered.wait(1))
            self.assertEqual(self.backend.request_stop(["host"]), {"host": True})
            attach_release.set()
            thread.join(2)
            self.assertFalse(thread.is_alive())
            self.assertFalse(outcome["started"])
            gate_write.assert_not_called()
            self.assertTrue(self.backend.stop(["host"], 0.2)["host"])
        self.assertIn(9, signals)

    def test_failed_startup_gate_write_reclaims_published_child(self):
        holder, popen, killpg = self._spawn_patch()
        with popen, killpg, mock.patch(
                "steamboat_connector.process_supervisor.os.write",
                side_effect=OSError("pipe write failed")):
            self.assertFalse(self.backend.start("host", sample_policy()))
        self.assertEqual(self.backend.status(), {})
        self.assertTrue(ProcessRoleBackend._events_populated(self.cgroup.group))

    def test_cancel_during_ready_wait_never_marks_role_ready(self):
        holder, popen, _ = self._spawn_patch()
        entered = threading.Event()
        release = threading.Event()
        caller_cancel = threading.Event()
        signals = []

        def wait_ready(process, timeout):
            entered.set()
            return release.wait(timeout)

        def killpg(pid, sig):
            signals.append(sig)
            holder["process"].on_signal(sig)

        outcome = {}
        with popen, mock.patch.object(ProcessRoleBackend, "_read_ready",
                                      side_effect=wait_ready), mock.patch(
                "steamboat_connector.process_supervisor.os.killpg",
                side_effect=killpg, create=True):
            thread = threading.Thread(target=lambda: outcome.setdefault(
                "started", self.backend.start("host", sample_policy(),
                                              cancel_event=caller_cancel)))
            thread.start()
            self.assertTrue(entered.wait(1))
            caller_cancel.set()
            release.set()
            thread.join(2)
        self.assertFalse(thread.is_alive())
        self.assertFalse(outcome["started"])
        self.assertNotIn("host", self.backend.status())
        self.assertIn(9, signals)

    def test_configuration_is_bounded_role_scoped_and_required(self):
        fresh = ProcessRoleBackend(self.temp.name, FakeCgroup(self.temp.name))
        self.assertFalse(fresh.start("host", sample_policy()))
        self.assertFalse(fresh.configure_role("consumer", {}))
        self.assertFalse(fresh.configure_role("host", {"large": "x" * ROLE_CONFIG_MAX_BYTES}))
        self.assertTrue(fresh.configure_role("host", {"manifest": "fixed"}))
        self.assertFalse(fresh.configure_role("host", {"invalid": float("nan")}))

    def test_invalid_stop_grace_fails_closed(self):
        for value in (float("nan"), float("inf"), -1, True, "1"):
            self.assertFalse(self.backend.stop(["host"], value)["host"])

    def test_cgroup_population_parser_rejects_duplicate_unknown_and_bad_values(self):
        path = Path(self.temp.name) / "probe"
        path.mkdir()
        events = path / "cgroup.events"
        for value in ("populated 0\npopulated 1\n", "populated 0\nother 1\n",
                      "populated maybe\n", "frozen 0\n"):
            events.write_text(value, encoding="ascii")
            self.assertFalse(ProcessRoleBackend._events_populated(path))
        events.write_text("populated 0\nfrozen 0\n", encoding="ascii")
        self.assertTrue(ProcessRoleBackend._events_populated(path))

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

    @unittest.skipUnless(sys.platform.startswith("linux"), "requires Linux fd inheritance")
    def test_actual_source_layout_bootstrap_waits_for_gate_without_torch(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "source"
            package = root / "steamboat_connector"
            package.mkdir(parents=True)
            source_bootstrap = (Path(__file__).resolve().parents[2] / "src" /
                                "steamboat_connector" / "process_bootstrap.py")
            shutil.copyfile(source_bootstrap, package / "process_bootstrap.py")
            (package / "__init__.py").write_text("", encoding="utf-8")
            marker = Path(temporary) / "role-imported"
            module_source = (
                "import pathlib, sys, time\n"
                "class Service:\n"
                "    def run(self):\n"
                "        while True:\n"
                "            print('x' * 4096, flush=True)\n"
                "            time.sleep(0.002)\n"
                "def start(config_path):\n"
                f"    pathlib.Path({str(marker)!r}).write_text(str('torch' in sys.modules))\n"
                "    return Service()\n")
            (package / "role_worker.py").write_text(module_source, encoding="utf-8")
            config = Path(temporary) / "role-config.json"
            config.write_text("{}", encoding="utf-8")
            read_fd, write_fd = os.pipe()
            child = None
            try:
                child = subprocess.Popen(
                    [sys.executable, "-I", "-S", str(package / "process_bootstrap.py"),
                     "host", str(config), str(read_fd)],
                    stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL, pass_fds=(read_fd,),
                    start_new_session=True, close_fds=True)
                os.close(read_fd)
                read_fd = -1
                time.sleep(0.1)
                self.assertIsNone(child.poll())
                self.assertFalse(marker.exists())
                os.write(write_fd, b"R")
                os.close(write_fd)
                write_fd = -1
                self.assertTrue(select.select([child.stdout], [], [], 5)[0])
                self.assertEqual(child.stdout.readline(READY_LINE_MAX + 1), b"READY\n")
                self.assertTrue(select.select([child.stdout], [], [], 2)[0])
                self.assertEqual(child.stdout.read(1), b"")
                deadline = time.monotonic() + 5
                while not marker.exists() and time.monotonic() < deadline:
                    time.sleep(0.01)
                self.assertEqual(marker.read_text(encoding="utf-8"), "False")
            finally:
                if read_fd >= 0:
                    os.close(read_fd)
                if write_fd >= 0:
                    os.close(write_fd)
                if child is not None:
                    try:
                        os.killpg(child.pid, signal.SIGTERM)
                        child.wait(timeout=2)
                    except (OSError, subprocess.TimeoutExpired):
                        os.killpg(child.pid, 9)
                        child.wait(timeout=2)

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
