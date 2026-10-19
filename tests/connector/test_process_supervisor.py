import os
import json
import hashlib
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
import uuid
from unittest import mock

from steamboat_connector.process_supervisor import (ProcessRoleBackend,
                                                     ROLE_CONFIG_MAX_BYTES,
                                                     READY_LINE_MAX, _StartIntent)
from steamboat_connector.resources import CgroupV2Controller, ResourceError
from steamboat_connector.validation import json_bytes


# setUp patches the supervisor's os.write attribute. Since os is a module
# singleton, preserve a real writer for tests that exercise inherited pipes.
REAL_OS_WRITE = os.write


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
        self.attach_checked_entered = None
        self.attach_checked_release = None
        self.state_lock = threading.RLock()

    def _write_atomic(self, path, contents):
        path = Path(path)
        temporary = path.with_name(
            f".{path.name}.{threading.get_ident()}.{uuid.uuid4().hex}.tmp")
        try:
            temporary.write_text(contents, encoding="ascii")
            deadline = time.monotonic() + 0.1
            while True:
                try:
                    temporary.replace(path)
                    break
                except PermissionError:
                    # Windows readers can briefly deny replacement while their
                    # regular-file handle is open; cgroupfs does not have this
                    # behavior, but the fixture still needs complete snapshots.
                    if time.monotonic() >= deadline:
                        raise
                    time.sleep(0.001)
        finally:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass

    def create_group(self, name, policy, role):
        if self.create_entered is not None:
            self.create_entered.set()
            self.create_release.wait(2)
        self.group = self.root / name
        self.group.mkdir()
        self._write_atomic(self.group / "cgroup.events", "populated 0\n")
        (self.group / "cgroup.procs").write_text("", encoding="ascii")
        self.groups.append(self.group)
        return self.group

    def attach_child(self, group, process):
        if self.attach_entered is not None:
            self.attach_entered.set()
            self.attach_release.wait(2)
        if self.fail_attach:
            raise OSError("attach refused")
        with self.state_lock:
            # Popen.poll() mirrors CPython: it returns None without reaping
            # while _waitpid_lock is held by the supervisor across placement.
            eligible = process.returncode is None
        if self.attach_checked_entered is not None:
            self.attach_checked_entered.set()
            self.attach_checked_release.wait(2)
        with self.state_lock:
            # Revalidate the observation at the publication point. A TERM
            # between eligibility and placement must not resurrect an exited
            # fake child in cgroup.events.
            if not eligible or process.returncode is not None:
                self._write_atomic(Path(group) / "cgroup.events", "populated 0\n")
                (Path(group) / "cgroup.procs").write_text("", encoding="ascii")
                return
            self.attached = True
            self._write_atomic(Path(group) / "cgroup.events", "populated 1\n")
            (Path(group) / "cgroup.procs").write_text(str(process.pid), encoding="ascii")

    def set_empty(self, group=None):
        with self.state_lock:
            self._write_atomic(Path(group or self.group) / "cgroup.events",
                               "populated 0\n")

    def remove_empty_group(self, group):
        group = Path(group)
        with self.state_lock:
            if not ProcessRoleBackend._events_populated(group):
                return False
            for name in ("cgroup.events", "cgroup.procs"):
                try:
                    (group / name).unlink()
                except FileNotFoundError:
                    pass
            group.rmdir()
            return not group.exists()


class FakeProcess:
    pid = 43121

    def __init__(self, args, kwargs, cgroup, *, ignore_term=False):
        self.args = args
        self.pid = 43121 + (1 if args[4] == "coordinator" else 0)
        self.kwargs = kwargs
        self.cgroup = cgroup
        self.group = cgroup.group
        self.returncode = None
        self.stdout = object()
        self.ignore_term = ignore_term
        self._waitpid_lock = threading.Lock()

    def poll(self):
        if not self._waitpid_lock.acquire(blocking=False):
            return None
        try:
            return self.returncode
        finally:
            self._waitpid_lock.release()

    def wait(self, timeout=None):
        with self._waitpid_lock:
            if self.returncode is None:
                import subprocess
                raise subprocess.TimeoutExpired(self.args, timeout)
            return self.returncode

    def on_signal(self, sig, *, kill_descendants=True):
        with self.cgroup.state_lock:
            if sig == signal.SIGTERM and self.ignore_term:
                return
            if sig in (signal.SIGTERM, 9):
                self.returncode = 0
            if sig in (signal.SIGTERM, 9) and kill_descendants:
                self.cgroup._write_atomic(
                    Path(self.group) / "cgroup.events", "populated 0\n")


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

    def _spawn_patch(self, *, fail_attach=False, kill_descendants=True,
                     ignore_term=False):
        self.cgroup.fail_attach = fail_attach
        holder = {}

        def spawn(*args, **kwargs):
            process = FakeProcess(args[0], kwargs, self.cgroup, ignore_term=ignore_term)
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

    def test_overlapping_stop_does_not_extend_first_absolute_deadline(self):
        holder, popen, _ = self._spawn_patch(kill_descendants=False, ignore_term=True)
        with popen:
            self.assertTrue(self.backend.start("host", sample_policy()))
        with mock.patch("steamboat_connector.process_supervisor.os.killpg",
                        side_effect=lambda pid, sig: holder["process"].on_signal(
                            sig, kill_descendants=False), create=True):
            self.assertFalse(self.backend.stop(["host"], 0.05)["host"])
            owned = self.backend._owned["host"]
            first_deadline = owned.stop_deadline
            started = time.monotonic()
            self.assertFalse(self.backend.stop(["host"], 1.0)["host"])
        self.assertEqual(owned.stop_deadline, first_deadline)
        self.assertLess(time.monotonic() - started, 0.2)
        self.assertIn("host", self.backend.status())

    def test_request_stop_deadline_survives_delayed_final_stop(self):
        holder, popen, _ = self._spawn_patch(kill_descendants=False, ignore_term=True)
        signals = []

        def killpg(pid, sig):
            if sig == 9:
                holder["process"].on_signal(sig)
            signals.append(sig)

        with popen, mock.patch(
                "steamboat_connector.process_supervisor.os.killpg",
                side_effect=killpg, create=True), mock.patch(
                "steamboat_connector.process_supervisor.STOP_GRACE_MAX_SECONDS", 0.3):
            self.assertTrue(self.backend.start("host", sample_policy()))
            self.assertTrue(self.backend.request_stop(["host"])["host"])
            owned = self.backend._owned["host"]
            first_deadline = owned.stop_deadline
            self.assertIsNotNone(first_deadline)
            time.sleep(0.32)
            self.assertIn(9, signals)
            self.assertIsNotNone(holder["process"].poll())
            self.assertTrue(self.backend._events_populated(owned.group))
            started = time.monotonic()
            self.assertTrue(self.backend.stop(["host"], 1.0)["host"])
        self.assertEqual(owned.stop_deadline, first_deadline)
        self.assertLess(time.monotonic() - started, 0.15)

    def test_request_stop_tightens_watchdog_deadline_without_extension(self):
        holder, popen, _ = self._spawn_patch(kill_descendants=False, ignore_term=True)
        signals = []

        def killpg(pid, sig):
            if sig == 9:
                holder["process"].on_signal(sig)
            signals.append(sig)

        with popen, mock.patch(
                "steamboat_connector.process_supervisor.os.killpg",
                side_effect=killpg, create=True), mock.patch(
                "steamboat_connector.process_supervisor.STOP_GRACE_MAX_SECONDS", 0.5):
            self.assertTrue(self.backend.start("host", sample_policy()))
            self.assertTrue(self.backend.request_stop(["host"])["host"])
            owned = self.backend._owned["host"]
            first = owned.stop_deadline
            time.sleep(0.03)
            with mock.patch("steamboat_connector.process_supervisor.STOP_GRACE_MAX_SECONDS", 0.12):
                self.assertTrue(self.backend.request_stop(["host"])["host"])
            self.assertLess(owned.stop_deadline, first)
            self.assertLessEqual(owned.term_deadline, owned.stop_deadline)
            deadline = owned.term_deadline + 0.1
            while 9 not in signals and time.monotonic() < deadline:
                time.sleep(0.005)
            self.assertIn(9, signals)
            self.assertTrue(self.backend._events_populated(owned.group))
            self.assertTrue(self.backend.stop(["host"], 0.4)["host"])

    def test_request_stop_ack_does_not_wait_for_owned_or_global_locks(self):
        holder, popen, killpg = self._spawn_patch(ignore_term=True)
        with popen, killpg:
            self.assertTrue(self.backend.start("host", sample_policy()))
        owned = self.backend._owned["host"]
        watchdog = self.backend._stop_watchdogs["host"]
        signal_event = threading.Event()

        class ObservedEvent:
            def set(self):
                signal_event.set()
                watchdog_event.set()

            def wait(self, timeout=None):
                return watchdog_event.wait(timeout)

            def clear(self):
                watchdog_event.clear()

        watchdog_event = watchdog.wake
        watchdog.wake = ObservedEvent()
        locks = (self.backend._lock, self.backend._watchdog_lock,
                 owned.escalation_lock, owned.deadline_lock)
        for lock in locks:
            lock.acquire()
        try:
            started = time.monotonic()
            self.assertTrue(self.backend.request_stop(["host"])["host"])
            elapsed = time.monotonic() - started
            self.assertLess(elapsed, 0.5)
            self.assertTrue(signal_event.is_set())
            self.assertTrue(owned.stopping)
            self.assertTrue(owned.force_cleanup.is_set())
        finally:
            for lock in reversed(locks):
                lock.release()
        with mock.patch("steamboat_connector.process_supervisor.os.killpg",
                        side_effect=lambda pid, sig: holder["process"].on_signal(sig),
                        create=True):
            self.assertTrue(self.backend.stop(["host"], 0.5)["host"])

    def test_reclaimed_generation_watchdog_retirement_skips_contended_lifecycle_lock(self):
        from types import SimpleNamespace

        acquired, release = threading.Event(), threading.Event()
        new_owned = SimpleNamespace(stopping=False)
        new_intent = _StartIntent()
        watchdog = SimpleNamespace(armed=threading.Event(), wake=threading.Event())
        self.backend._owned["host"] = new_owned
        self.backend._start_intents["host"] = new_intent
        self.backend._stop_watchdogs["host"] = watchdog

        def hold_lifecycle_lock():
            with self.backend._lock:
                acquired.set()
                release.wait(5)

        holder = threading.Thread(target=hold_lifecycle_lock)
        holder.start()
        try:
            self.assertTrue(acquired.wait(2))
            old_reclaimed_generation = SimpleNamespace(reclaimed=True)
            started = time.monotonic()
            self.backend._retire_stop_watchdog("host", old_reclaimed_generation)
            self.assertLess(time.monotonic() - started, 0.5)
            self.assertIs(self.backend._owned["host"], new_owned)
            self.assertIs(self.backend._start_intents["host"], new_intent)
            self.assertIs(self.backend._stop_watchdogs["host"], watchdog)
            self.assertFalse(watchdog.armed.is_set())
            self.assertFalse(watchdog.wake.is_set())
        finally:
            release.set()
            holder.join(2)
            self.assertFalse(holder.is_alive())

    def test_reclaimed_owned_stop_reaches_nonblocking_watchdog_retirement(self):
        holder, popen, killpg = self._spawn_patch()
        lock_acquired, release_lock = threading.Event(), threading.Event()
        original_retire = self.backend._retire_stop_watchdog
        retired = []

        def hold_lifecycle_lock(role, generation):
            def hold():
                with self.backend._lock:
                    lock_acquired.set()
                    release_lock.wait(5)

            thread = threading.Thread(target=hold)
            thread.start()
            try:
                self.assertTrue(lock_acquired.wait(2))
                started = time.monotonic()
                original_retire(role, generation)
                self.assertLess(time.monotonic() - started, 0.5)
                retired.append(generation)
            finally:
                release_lock.set()
                thread.join(2)
                self.assertFalse(thread.is_alive())

        with popen, killpg, mock.patch.object(
                self.backend, "_retire_stop_watchdog",
                side_effect=hold_lifecycle_lock):
            self.assertTrue(self.backend.start("host", sample_policy()))
            old_owned = self.backend._owned["host"]
            self.assertTrue(self.backend.stop(["host"], 1.0)["host"])
            self.assertTrue(old_owned.reclaimed)
        self.assertEqual(retired, [old_owned.start_intent])
        self.assertNotIn("host", self.backend._owned)

    def test_deadline_force_flag_cannot_be_overwritten_by_late_writer(self):
        intent = _StartIntent()
        intent.deadline_lock.acquire()
        outcome = {}

        def tighten_while_writer_holds_lock():
            started = time.monotonic()
            self.backend._cancel_intent(intent, started + 10, started + 5)
            outcome["elapsed"] = time.monotonic() - started

        thread = threading.Thread(target=tighten_while_writer_holds_lock)
        thread.start()
        thread.join(0.5)
        self.assertFalse(thread.is_alive())
        self.assertLess(outcome["elapsed"], 0.5)
        self.assertTrue(intent.force_cleanup.is_set())
        intent.deadline_lock.release()

        later = time.monotonic() + 100
        self.backend._cancel_intent(intent, later, later)
        self.assertTrue(intent.force_cleanup.is_set())
        effective_deadline, effective_term = self.backend._effective_deadlines(
            intent, intent=True)
        self.assertLess(effective_deadline, later)
        self.assertLess(effective_term, later)

    def test_reaped_leader_uses_owned_cgroup_kill_without_reused_pgid(self):
        holder, popen, _ = self._spawn_patch()
        with popen:
            self.assertTrue(self.backend.start("host", sample_policy()))
        owned = self.backend._owned["host"]
        kill_file = owned.group / "cgroup.kill"
        kill_file.write_text("", encoding="ascii")
        holder["process"].returncode = 0
        owned.leader_reaped = True
        owned.reaped_event.set()
        writes = []
        original_write_text = Path.write_text

        def record_owned_kill(path, data, *args, **kwargs):
            if path == kill_file:
                writes.append(data)
            return original_write_text(path, data, *args, **kwargs)

        with mock.patch.object(Path, "write_text", record_owned_kill), mock.patch(
                "steamboat_connector.process_supervisor.os.killpg", create=True) as killpg:
            self.backend._watchdog_kill(owned)
        self.assertEqual(writes, ["1"])
        killpg.assert_not_called()

    def test_drain_cutoff_is_not_process_cleanup_deadline(self):
        holder, popen, _ = self._spawn_patch()
        with popen:
            self.assertTrue(self.backend.start("host", sample_policy()))
        owned = self.backend._owned["host"]
        outcome = self.backend.drain(["host"], time.monotonic() + 300,
                                     threading.Event())
        self.assertEqual(outcome, {"drained": False, "reclaimed": False})
        self.assertIsNone(owned.stop_deadline)
        self.assertIsNone(owned.term_deadline)
        with mock.patch("steamboat_connector.process_supervisor.os.killpg",
                        side_effect=lambda pid, sig: holder["process"].on_signal(
                            sig), create=True):
            started = time.monotonic()
            self.assertTrue(self.backend.stop(["host"], 0.05)["host"])
        self.assertLess(time.monotonic() - started, 0.2)

    def test_request_drain_disables_admission_without_signalling_healthy_role(self):
        holder, popen, killpg = self._spawn_patch()
        signals = []
        with popen, mock.patch(
                "steamboat_connector.process_supervisor.os.killpg",
                side_effect=lambda pid, sig: signals.append(sig), create=True):
            self.assertTrue(self.backend.start("host", sample_policy()))
            owned = self.backend._owned["host"]
            self.assertTrue(owned.ready)
            self.assertEqual(self.backend.request_drain(["host"]), {"host": True})
            self.assertFalse(owned.ready)
            self.assertTrue(owned.stopping)
            self.assertEqual(signals, [])
        with killpg:
            self.assertTrue(self.backend.stop(["host"], 0.1)["host"])

    def test_request_drain_is_nonblocking_and_fences_start_during_attach(self):
        attach_entered = threading.Event()
        attach_release = threading.Event()
        self.cgroup.attach_entered = attach_entered
        self.cgroup.attach_release = attach_release
        holder, popen, killpg = self._spawn_patch()
        outcome = {}
        with popen, killpg:
            thread = threading.Thread(target=lambda: outcome.setdefault(
                "started", self.backend.start("host", sample_policy())))
            thread.start()
            try:
                self.assertTrue(attach_entered.wait(1))
                began = time.monotonic()
                self.assertEqual(self.backend.request_drain(["host"]), {"host": True})
                self.assertLess(time.monotonic() - began, 0.1)
            finally:
                attach_release.set()
                thread.join(2)
        self.assertFalse(thread.is_alive())
        self.assertFalse(outcome["started"])
        self.assertEqual(self.backend.status(), {})

    def test_drain_during_start_sets_only_bounded_cleanup_cap(self):
        attach_entered = threading.Event()
        attach_release = threading.Event()
        self.cgroup.attach_entered = attach_entered
        self.cgroup.attach_release = attach_release
        holder, popen, killpg = self._spawn_patch()
        outcome = {}
        with popen, killpg:
            thread = threading.Thread(target=lambda: outcome.setdefault(
                "started", self.backend.start("host", sample_policy())))
            thread.start()
            self.assertTrue(attach_entered.wait(1))
            drain_cutoff = time.monotonic() + 300
            self.backend.drain(["host"], drain_cutoff, threading.Event())
            intent = self.backend._start_intents["host"]
            self.assertLessEqual(intent.cancel_deadline, time.monotonic() + 15)
            self.assertNotEqual(intent.cancel_deadline, drain_cutoff)
            attach_release.set()
            thread.join(2)
        self.assertFalse(thread.is_alive())
        self.assertFalse(outcome["started"])
        self.assertEqual(self.backend.status(), {})

    def test_stop_finalizes_finished_intent_after_prior_group_cleanup(self):
        intent = _StartIntent()
        intent.finished = True
        intent.group = None
        self.backend._start_intents["host"] = intent
        self.assertEqual(self.backend.stop(["host"], 0.1), {"host": True})
        self.assertNotIn("host", self.backend._start_intents)

    def test_forget_start_intent_is_bounded_and_stop_can_recover(self):
        intent = _StartIntent()
        intent.finished = True
        intent.group = None
        self.backend._start_intents["host"] = intent
        with mock.patch.object(ProcessRoleBackend, "_acquire_until", return_value=False):
            self.assertFalse(self.backend._forget_start_intent("host", intent))
        self.assertIs(self.backend._start_intents["host"], intent)
        self.assertEqual(self.backend.stop(["host"], 0.1), {"host": True})

    def test_multi_role_stop_signals_all_first_and_shares_one_deadline(self):
        holder = {}

        def spawn(*args, **kwargs):
            process = FakeProcess(args[0], kwargs, self.cgroup, ignore_term=True)
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
        term_signals = [event for event in events if event[0] == "signal"
                        and event[1] == signal.SIGTERM]
        self.assertEqual(len(term_signals), 2)
        self.assertEqual({event[2] for event in term_signals},
                         {"host", "coordinator"})

    def test_request_stop_uses_one_watchdog_per_role_for_both_roles(self):
        holder = {}

        def spawn(*args, **kwargs):
            process = FakeProcess(args[0], kwargs, self.cgroup)
            holder[args[0][4]] = process
            return process

        signals = []

        def killpg(pid, sig):
            process = next(item for item in holder.values() if item.pid == pid)
            if sig == 9:
                process.on_signal(sig)
            signals.append((process.args[0][4], sig))

        with mock.patch("steamboat_connector.process_supervisor.subprocess.Popen",
                        side_effect=spawn), mock.patch(
                "steamboat_connector.process_supervisor.os.killpg",
                side_effect=killpg, create=True), mock.patch(
                "steamboat_connector.process_supervisor.STOP_GRACE_MAX_SECONDS", 0.2):
            self.assertTrue(self.backend.start("host", sample_policy()))
            self.assertTrue(self.backend.start("coordinator", sample_policy()))
            self.assertEqual(self.backend.request_stop(["host", "coordinator"]),
                             {"host": True, "coordinator": True})
            self.assertEqual(len(self.backend._stop_watchdogs), 2)
            deadline = time.monotonic() + 0.2
            while len(signals) < 2 and time.monotonic() < deadline:
                time.sleep(0.005)
            self.assertEqual([sig for _, sig in signals], [signal.SIGTERM, signal.SIGTERM])
            deadline = time.monotonic() + 0.3
            while (sum(sig == 9 for _, sig in signals) < 2
                   and time.monotonic() < deadline):
                time.sleep(0.005)
            self.assertEqual(sum(sig == 9 for _, sig in signals), 2)
            self.assertTrue(all(self.backend._events_populated(
                self.backend._owned[role].group) for role in ("host", "coordinator")))
            self.assertEqual(self.backend.stop(["host", "coordinator"], 0.4),
                             {"host": True, "coordinator": True})

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

    def test_owned_start_rejects_changed_captured_role_config_before_popen(self):
        expected = hashlib.sha256(
            json_bytes(self.backend._configured_role("host"))).hexdigest()
        self.assertTrue(self.backend.configure_role("host", {"changed": True}))
        with mock.patch("steamboat_connector.process_supervisor.subprocess.Popen") as spawn:
            self.assertIsNone(self.backend.spawn_owned_start(
                "host", sample_policy(), expected_role_config_sha256=expected))
            spawn.assert_not_called()
        self.assertEqual(self.cgroup.groups, [])

    def test_owned_start_rejects_malformed_expected_role_config_digest(self):
        with mock.patch("steamboat_connector.process_supervisor.subprocess.Popen") as spawn:
            self.assertIsNone(self.backend.spawn_owned_start(
                "host", sample_policy(), expected_role_config_sha256="bad"))
            spawn.assert_not_called()
        self.assertEqual(self.cgroup.groups, [])

    def test_owned_start_rejects_two_read_role_config_replacement_before_popen(self):
        import steamboat_connector.process_supervisor as supervisor
        original = supervisor.read_private_json
        calls = 0

        def replaced(path, **kwargs):
            nonlocal calls
            calls += 1
            document = original(path, **kwargs)
            if calls == 2:
                document = dict(document)
                document["config"] = {"test_mode": False}
            return document

        expected = hashlib.sha256(
            json_bytes(self.backend._configured_role("host"))).hexdigest()
        with mock.patch.object(supervisor, "read_private_json", side_effect=replaced), \
                mock.patch.object(supervisor.subprocess, "Popen") as spawn:
            self.assertIsNone(self.backend.spawn_owned_start(
                "host", sample_policy(), expected_role_config_sha256=expected))
            spawn.assert_not_called()
        self.assertGreaterEqual(calls, 2)
        self.assertEqual(self.cgroup.groups, [])

    def test_owned_start_rejects_replaced_artifact_pin_before_popen(self):
        expected = object()
        with mock.patch.object(self.backend, "_pinned_roles", {
                "host": (object(), object(), None)}):
            # Pin identity is checked after start intent acquisition under the
            # backend lock and before configuration/cgroup/Popen work.
            with mock.patch("steamboat_connector.process_supervisor.subprocess.Popen") as spawn:
                self.assertIsNone(self.backend.spawn_owned_start(
                    "host", sample_policy(), expected_artifact_pin=expected))
                spawn.assert_not_called()
        self.assertEqual(self.cgroup.groups, [])

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

    def test_drain_cancels_and_reports_unresolved_start_intent(self):
        entered = threading.Event()
        release = threading.Event()
        self.cgroup.create_entered = entered
        self.cgroup.create_release = release
        result = {}
        with mock.patch("steamboat_connector.process_supervisor.subprocess.Popen") as spawn:
            thread = threading.Thread(target=lambda: result.setdefault(
                "started", self.backend.start("host", sample_policy())))
            thread.start()
            self.assertTrue(entered.wait(1))
            drain = self.backend.drain(["host"], time.monotonic() + 0.5,
                                       threading.Event())
            self.assertEqual(drain, {"drained": False, "reclaimed": False})
            release.set()
            thread.join(2)
        self.assertFalse(thread.is_alive())
        self.assertFalse(result["started"])
        spawn.assert_not_called()

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
        attach_checked_entered = threading.Event()
        attach_checked_release = threading.Event()
        self.cgroup.attach_checked_entered = attach_checked_entered
        self.cgroup.attach_checked_release = attach_checked_release
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
            self.assertTrue(attach_checked_entered.wait(1))
            self.assertEqual(self.backend.request_stop(["host"]), {"host": True})
            attach_checked_release.set()
            thread.join(2)
            self.assertFalse(thread.is_alive())
            self.assertFalse(outcome["started"])
            gate_write.assert_not_called()
            owned = self.backend._owned.get("host")
            stopped = self.backend.stop(["host"], 0.2)["host"]
            if not stopped:
                intent = self.backend._start_intents.get("host")
                process = None if owned is None else owned.process
                try:
                    events = (None if owned is None else
                              (owned.group / "cgroup.events").read_text(
                                  encoding="ascii"))
                except OSError as error:
                    events = f"read failed: {error!r}"
                intent_state = (None if intent is None else {
                    "finished": intent.finished,
                    "cancelled": intent.cancelled.is_set(),
                    "final_stop_requested": intent.final_stop_requested,
                    "group": intent.group,
                })
                self.fail(
                    "final stop did not reclaim: "
                    f"status={self.backend.status()!r}, "
                    f"owned_is_current={self.backend._owned.get('host') is owned}, "
                    f"process_returncode={None if process is None else process.returncode!r}, "
                    f"leader_reaped={None if owned is None else owned.leader_reaped!r}, "
                    f"reaped_event={None if owned is None else owned.reaped_event.is_set()!r}, "
                    f"term_sent={None if owned is None else owned.term_sent!r}, "
                    f"events={events!r}, "
                    f"intent={intent_state!r}")
        self.assertIn(signal.SIGTERM, signals)
        self.assertNotIn(9, signals)

    def test_failed_startup_gate_write_reclaims_published_child(self):
        holder, popen, killpg = self._spawn_patch()
        with popen, killpg, mock.patch(
                "steamboat_connector.process_supervisor.os.write",
                side_effect=OSError("pipe write failed")):
            self.assertFalse(self.backend.start("host", sample_policy()))
        self.assertEqual(self.backend.status(), {})
        self.assertFalse(self.cgroup.group.exists())

    def test_cancel_during_ready_wait_never_marks_role_ready(self):
        holder, popen, _ = self._spawn_patch()
        entered = threading.Event()
        release = threading.Event()
        caller_cancel = threading.Event()
        signals = []

        def wait_ready(process, timeout, cancelled=None):
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
        self.assertIn(signal.SIGTERM, signals)
        self.assertNotIn(9, signals)

    @unittest.skipUnless(sys.platform.startswith("linux"), "requires selectable Linux pipes")
    def test_real_stdout_pipe_cancellation_interrupts_ready_wait_and_kills(self):
        self.readiness_patch.stop()
        read_fd, write_fd = os.pipe()
        holder = {}
        readiness_entered = threading.Event()
        original_read_ready = ProcessRoleBackend._read_ready

        def spawn(*args, **kwargs):
            process = FakeProcess(args[0], kwargs, self.cgroup)
            process.stdout = os.fdopen(read_fd, "rb", buffering=0)
            holder["process"] = process
            return process

        cancelled = threading.Event()

        def killpg(pid, sig):
            holder["process"].on_signal(sig)

        def read_ready(process, timeout, cancelled=None):
            readiness_entered.set()
            return original_read_ready(process, timeout, cancelled)

        outcome = {}
        started = time.monotonic()
        with mock.patch("steamboat_connector.process_supervisor.subprocess.Popen",
                        side_effect=spawn), mock.patch(
                "steamboat_connector.process_supervisor.os.killpg",
                side_effect=killpg, create=True), mock.patch(
                "steamboat_connector.process_supervisor.STOP_GRACE_MAX_SECONDS", 0.3), \
                mock.patch.object(ProcessRoleBackend, "_read_ready",
                                  side_effect=read_ready):
            thread = threading.Thread(target=lambda: outcome.setdefault(
                "started", self.backend.start("host", sample_policy(),
                                              cancel_event=cancelled)))
            try:
                thread.start()
                self.assertTrue(readiness_entered.wait(1))
                cancelled.set()
                thread.join(1)
                self.assertFalse(thread.is_alive())
                self.assertFalse(outcome["started"])
                self.assertLess(time.monotonic() - started, 1)
                self.assertNotIn("host", self.backend.status())
                self.assertFalse(self.cgroup.group.exists())
            finally:
                os.close(write_fd)
                if thread.is_alive():
                    thread.join(2)

    @unittest.skipUnless(sys.platform.startswith("linux"), "requires Linux process groups")
    def test_linux_ignored_term_child_is_reaped_after_pipe_readiness_cancel(self):
        import subprocess
        real_popen = subprocess.Popen
        self.readiness_patch.stop()
        readiness_entered = threading.Event()
        original_read_ready = ProcessRoleBackend._read_ready
        real_killpg = os.killpg
        holder = {}
        outcome = {}
        signals = []

        program = (
            "import os,signal,sys,time\n"
            "signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
            "os.write(1,b'TERM_IGNORED\\n')\n"
            "fd=int(sys.argv[1]); os.read(fd,1); os.close(fd)\n"
            "while True: time.sleep(10)\n")

        def spawn(command, **kwargs):
            process = real_popen([sys.executable, "-I", "-S", "-c", program,
                                  command[6]], **kwargs)
            holder["process"] = process
            return process

        def read_ready(process, timeout, cancelled=None):
            # Observe the real child's installed signal handler before sending
            # TERM; reaching the parent's reader alone is insufficient proof.
            if not select.select([process.stdout], [], [], 2)[0]:
                raise RuntimeError("native child did not install TERM handler")
            if process.stdout.readline(32) != b"TERM_IGNORED\n":
                raise RuntimeError("native child readiness control is invalid")
            readiness_entered.set()
            return original_read_ready(process, timeout, cancelled)

        def killpg(pid, sig):
            signals.append(sig)
            real_killpg(pid, sig)
            if sig == signal.SIGKILL:
                self.cgroup.set_empty()

        started = time.monotonic()
        with mock.patch("steamboat_connector.process_supervisor.subprocess.Popen",
                        side_effect=spawn), mock.patch(
                "steamboat_connector.process_supervisor.os.write",
                side_effect=REAL_OS_WRITE), mock.patch(
                "steamboat_connector.process_supervisor.os.killpg",
                side_effect=killpg), mock.patch(
                "steamboat_connector.process_supervisor.STOP_GRACE_MAX_SECONDS", 0.4), \
                mock.patch.object(ProcessRoleBackend, "_read_ready",
                                  side_effect=read_ready):
            thread = threading.Thread(target=lambda: outcome.setdefault(
                "started", self.backend.start("host", sample_policy())))
            thread.start()
            owned = None
            try:
                self.assertTrue(readiness_entered.wait(2))
                self.assertTrue(self.backend.request_stop(["host"])["host"])
                owned = self.backend._owned["host"]
                original_deadline = owned.stop_deadline
                thread.join(2)
                self.assertFalse(thread.is_alive())
                self.assertFalse(outcome["started"])
                time.sleep(0.45)
                # Prove the independent watchdog killed the TERM-ignoring
                # child before final lifecycle stop had a chance to do so.
                self.assertIn(9, signals)
                self.assertIsNotNone(holder["process"].poll())
                self.assertTrue(self.backend._events_populated(owned.group))
                final_started = time.monotonic()
                self.assertTrue(self.backend.stop(["host"], 1.0)["host"])
                self.assertEqual(owned.stop_deadline, original_deadline)
                self.assertLess(time.monotonic() - final_started, 0.2)
            finally:
                child = holder.get("process")
                if child is not None and child.poll() is None:
                    try:
                        real_killpg(child.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    child.wait(timeout=2)
                    if owned is not None:
                        self.cgroup.set_empty(owned.group)
                if owned is not None and self.backend._owned.get("host") is owned:
                    self.backend.stop(["host"], 1.0)
                thread.join(2)
                if thread.is_alive():
                    self.fail("readiness thread did not terminate during test cleanup")
        self.assertFalse(thread.is_alive())
        self.assertFalse(outcome["started"])
        self.assertIsNotNone(holder["process"].poll())
        self.assertLess(time.monotonic() - started, 2)
        self.assertEqual(self.backend.status(), {})

    def test_stop_during_blocked_popen_is_bounded_and_never_opens_gate(self):
        entered = threading.Event()
        release = threading.Event()
        holder = {}
        outcome = {}

        def spawn(*args, **kwargs):
            entered.set()
            release.wait(2)
            process = FakeProcess(args[0], kwargs, self.cgroup)
            holder["process"] = process
            return process

        def killpg(pid, sig):
            holder["process"].on_signal(sig)

        with mock.patch("steamboat_connector.process_supervisor.subprocess.Popen",
                        side_effect=spawn), mock.patch(
                "steamboat_connector.process_supervisor.os.write",
                side_effect=REAL_OS_WRITE), mock.patch(
                "steamboat_connector.process_supervisor.os.killpg",
                side_effect=killpg, create=True), mock.patch(
                "steamboat_connector.process_supervisor.os.write",
                return_value=1) as gate_write:
            thread = threading.Thread(target=lambda: outcome.setdefault(
                "started", self.backend.start("host", sample_policy())))
            thread.start()
            self.assertTrue(entered.wait(1))
            started = time.monotonic()
            self.assertEqual(self.backend.stop(["host"], 0.05), {"host": False})
            self.assertLess(time.monotonic() - started, 0.3)
            release.set()
            thread.join(2)
        self.assertFalse(thread.is_alive())
        self.assertFalse(outcome["started"])
        gate_write.assert_not_called()
        self.assertEqual(self.backend.status(), {})

    def test_request_stop_watchdog_covers_process_publication_race(self):
        entered = threading.Event()
        release = threading.Event()
        holder = {}
        outcome = {}
        signals = []

        def spawn(*args, **kwargs):
            process = FakeProcess(args[0], kwargs, self.cgroup)
            holder["process"] = process
            entered.set()
            release.wait(2)
            return process

        original_attach = self.cgroup.attach_child

        def attach_after_spawn(group, process):
            if process.poll() is not None:
                self.cgroup.attached = True
                self.cgroup.set_empty(group)
                (Path(group) / "cgroup.procs").write_text("", encoding="ascii")
                return
            original_attach(group, process)

        def killpg(pid, sig):
            signals.append(sig)
            holder["process"].on_signal(sig)

        with mock.patch("steamboat_connector.process_supervisor.subprocess.Popen",
                        side_effect=spawn), mock.patch.object(
                self.cgroup, "attach_child", side_effect=attach_after_spawn), mock.patch(
                "steamboat_connector.process_supervisor.os.killpg",
                side_effect=killpg, create=True), mock.patch(
                "steamboat_connector.process_supervisor.os.write",
                side_effect=REAL_OS_WRITE), mock.patch(
                "steamboat_connector.process_supervisor.STOP_GRACE_MAX_SECONDS", 0.2):
            thread = threading.Thread(target=lambda: outcome.setdefault(
                "started", self.backend.start("host", sample_policy())))
            thread.start()
            try:
                self.assertTrue(entered.wait(1))
                self.assertTrue(self.backend.request_stop(["host"])["host"])
                time.sleep(0.12)  # The watchdog reaches its TERM-to-KILL deadline while Popen is unpublished.
                self.assertNotIn(9, signals)
                release.set()
                thread.join(2)
                self.assertFalse(thread.is_alive())
                self.assertFalse(outcome["started"])
                deadline = time.monotonic() + 0.2
                while 9 not in signals and time.monotonic() < deadline:
                    time.sleep(0.005)
                self.assertIn(9, signals)
                self.assertIsNotNone(holder["process"].poll())
                self.assertTrue(self.backend._events_populated(holder["process"].group))
                self.assertTrue(self.backend.stop(["host"], 0.3)["host"])
            finally:
                release.set()
                thread.join(2)
                if "host" in self.backend._owned:
                    self.backend.stop(["host"], 0.4)
        self.assertFalse(thread.is_alive())

    def test_stop_kills_during_pid_locked_attach_without_reaping_early(self):
        attach_entered = threading.Event()
        attach_release = threading.Event()
        self.cgroup.attach_entered = attach_entered
        self.cgroup.attach_release = attach_release
        holder, popen, _ = self._spawn_patch(ignore_term=True)
        signals = []
        outcome = {}

        def killpg(pid, sig):
            signals.append(sig)
            holder["process"].on_signal(sig)

        with popen, mock.patch(
                "steamboat_connector.process_supervisor.os.killpg",
                side_effect=killpg, create=True), mock.patch(
                "steamboat_connector.process_supervisor.STOP_GRACE_MAX_SECONDS", 0.2):
            thread = threading.Thread(target=lambda: outcome.setdefault(
                "started", self.backend.start("host", sample_policy())))
            thread.start()
            try:
                self.assertTrue(attach_entered.wait(1))
                process = holder["process"]
                self.assertFalse(process._waitpid_lock.acquire(blocking=False))
                self.assertTrue(self.backend.request_stop(["host"])["host"])
                deadline = time.monotonic() + 0.18
                while 9 not in signals and time.monotonic() < deadline:
                    time.sleep(0.005)
                self.assertIn(9, signals)
                self.assertEqual(process.returncode, 0)
                self.assertIsNone(process.poll())
                owned = self.backend._owned["host"]
                self.assertFalse(owned.reaped_event.is_set())
                attach_release.set()
                thread.join(1)
                self.assertFalse(thread.is_alive())
                self.assertFalse(outcome["started"])
                self.assertTrue(owned.reaped_event.wait(0.2))
                self.assertEqual(process.poll(), 0)
                self.assertTrue(self.backend.stop(["host"], 0.3)["host"])
            finally:
                attach_release.set()
                thread.join(1)

    @unittest.skipUnless(sys.platform.startswith("linux"), "requires native Linux Popen ownership")
    def test_native_child_pid_remains_reserved_through_blocked_attachment(self):
        real_popen, real_killpg = subprocess.Popen, os.killpg
        entered, release = threading.Event(), threading.Event()
        holder, outcome, signals = {}, {}, []
        program = (
            "import os,signal,time\n"
            "signal.signal(signal.SIGTERM,signal.SIG_IGN)\n"
            "os.write(1,b'TERM_IGNORED\\n')\n"
            "while True: time.sleep(10)\n")

        def spawn(command, **kwargs):
            child = real_popen([sys.executable, "-I", "-S", "-c", program], **kwargs)
            holder["child"] = child
            if (not select.select([child.stdout], [], [], 2)[0]
                    or child.stdout.readline(32) != b"TERM_IGNORED\n"):
                raise RuntimeError("native child did not install its signal handler")
            return child

        def attach(group, child):
            entered.set()
            if not release.wait(3):
                raise RuntimeError("test attachment barrier timed out")
            # CPython's real poll cannot reap while the placement owner holds
            # _waitpid_lock. This fixture does not claim kernel cgroup placement.
            self.assertIsNone(child.poll())
            self.cgroup.attached = True
            self.cgroup.set_empty(group)

        def killpg(pid, sig):
            signals.append(sig)
            real_killpg(pid, sig)

        with mock.patch("steamboat_connector.process_supervisor.subprocess.Popen",
                        side_effect=spawn), mock.patch.object(
                self.cgroup, "attach_child", side_effect=attach), mock.patch(
                "steamboat_connector.process_supervisor.os.killpg", side_effect=killpg), \
                mock.patch("steamboat_connector.process_supervisor.STOP_GRACE_MAX_SECONDS", 0.3):
            thread = threading.Thread(target=lambda: outcome.setdefault(
                "started", self.backend.start("host", sample_policy())))
            thread.start()
            try:
                self.assertTrue(entered.wait(2))
                child = holder["child"]
                owned = self.backend._owned["host"]
                self.assertTrue(self.backend.request_stop(["host"])["host"])
                deadline = time.monotonic() + 1
                state = None
                while time.monotonic() < deadline:
                    state = Path(f"/proc/{child.pid}/stat").read_text().rsplit(") ", 1)[1].split()[0]
                    if state == "Z":
                        break
                    time.sleep(0.005)
                self.assertIn(signal.SIGKILL, signals)
                self.assertEqual(state, "Z")
                self.assertIsNone(child.poll())
                self.assertIsNone(child.returncode)
                self.assertFalse(owned.reaped_event.is_set())
                release.set()
                thread.join(2)
                self.assertFalse(thread.is_alive())
                self.assertFalse(outcome["started"])
                self.assertTrue(self.backend.stop(["host"], 0.3)["host"])
                self.assertEqual(child.returncode, -signal.SIGKILL)
                self.assertFalse(Path(f"/proc/{child.pid}").exists())
            finally:
                release.set()
                thread.join(2)
                child = holder.get("child")
                if child is not None and child.poll() is None:
                    try:
                        real_killpg(child.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    child.wait(timeout=2)
                if "host" in self.backend._owned:
                    self.cgroup.set_empty()
                    self.backend.stop(["host"], 0.3)
                self.assertFalse(thread.is_alive())

    def test_old_monitor_retirement_rechecks_new_published_generation(self):
        processes = []
        signals = []

        def spawn(*args, **kwargs):
            process = FakeProcess(args[0], kwargs, self.cgroup, ignore_term=True)
            process.pid = 44000 + len(processes)
            processes.append(process)
            return process

        def killpg(pid, sig):
            process = next(item for item in processes if item.pid == pid)
            signals.append((pid, sig))
            process.on_signal(sig)

        original_owner = self.backend._stop_watchdog_owner
        decision_seen = threading.Event()
        allow_retirement = threading.Event()
        paused = threading.Event()

        def pause_after_finished_decision(watchdog):
            result = original_owner(watchdog)
            if result[1] and not paused.is_set():
                paused.set()
                decision_seen.set()
                allow_retirement.wait(1)
            return result

        with mock.patch("steamboat_connector.process_supervisor.subprocess.Popen",
                        side_effect=spawn), mock.patch(
                "steamboat_connector.process_supervisor.os.killpg",
                side_effect=killpg, create=True), mock.patch.object(
                self.backend, "_stop_watchdog_owner",
                side_effect=pause_after_finished_decision), mock.patch(
                "steamboat_connector.process_supervisor.STOP_GRACE_MAX_SECONDS", 0.2):
            self.assertTrue(self.backend.start("host", sample_policy()))
            first_watchdog = self.backend._stop_watchdogs["host"]
            self.assertTrue(self.backend.stop(["host"], 0.4)["host"])
            self.assertTrue(decision_seen.wait(0.5))
            self.assertTrue(self.backend.start("host", sample_policy()))
            second_owned = self.backend._owned["host"]
            self.assertIsNotNone(self.backend._stop_watchdogs.get("host"))
            allow_retirement.set()
            time.sleep(0.02)
            self.assertIs(self.backend._stop_watchdogs.get("host"), first_watchdog)
            self.assertTrue(self.backend.request_stop(["host"])["host"])
            deadline = time.monotonic() + 0.3
            while (second_owned.process.returncode is None
                   and time.monotonic() < deadline):
                time.sleep(0.005)
            self.assertEqual(second_owned.process.returncode, 0)
            self.assertTrue(self.backend.stop(["host"], 0.3)["host"])

    def test_empty_cgroup_disposal_uses_real_rmdir_and_unknown_state_is_retained(self):
        empty = Path(self.temp.name) / "empty-group"
        empty.mkdir()
        (empty / "cgroup.events").write_text("populated 0\n", encoding="ascii")
        (empty / "cgroup.procs").write_text("", encoding="ascii")
        self.assertTrue(self.backend._remove_empty_group(empty))
        self.assertFalse(empty.exists())

        unknown = Path(self.temp.name) / "unknown-group"
        unknown.mkdir()
        self.assertFalse(self.backend._remove_empty_group(unknown))
        self.assertTrue(unknown.exists())

    def test_uncertain_empty_group_removal_remains_visible_and_stop_fails_closed(self):
        cancelled = threading.Event()

        class RefuseRemoveCgroup(FakeCgroup):
            def create_group(inner, name, policy, role):
                path = super(RefuseRemoveCgroup, inner).create_group(name, policy, role)
                cancelled.set()
                return path

            def remove_empty_group(inner, group):
                return False

        cgroup = RefuseRemoveCgroup(self.temp.name)
        backend = ProcessRoleBackend(self.temp.name, cgroup)
        self.assertTrue(backend.configure_role("host", {"test_mode": True}))
        with mock.patch("steamboat_connector.process_supervisor.subprocess.Popen") as spawn:
            self.assertFalse(backend.start("host", sample_policy(),
                                           cancel_event=cancelled))
        spawn.assert_not_called()
        status = backend.status()["host"]
        self.assertTrue(status["cleanup_pending"])
        self.assertFalse(status["cgroup_populated"])
        self.assertFalse(backend.stop(["host"], 0.01)["host"])

    def test_partial_cgroup_error_path_is_retained_by_supervisor(self):
        retained = Path(self.temp.name) / "partial-group"
        retained.mkdir()

        class PartialCreateCgroup:
            def create_group(inner, name, policy, role):
                raise ResourceError("partial group retained", retained_group=retained)

        backend = ProcessRoleBackend(self.temp.name, PartialCreateCgroup())
        self.assertTrue(backend.configure_role("host", {"test_mode": True}))
        with mock.patch("steamboat_connector.process_supervisor.subprocess.Popen") as spawn:
            self.assertFalse(backend.start("host", sample_policy()))
        spawn.assert_not_called()
        self.assertTrue(backend.status()["host"]["cleanup_pending"])
        self.assertFalse(backend.stop(["host"], 0.01)["host"])
        self.assertTrue(retained.exists())

    def test_cgroup_create_validates_reservation_and_tracks_partial_group_failure(self):
        parent = Path(self.temp.name) / "delegated"
        parent.mkdir()
        (parent / "cgroup.controllers").write_text("cpu memory\n", encoding="ascii")
        (parent / "cgroup.subtree_control").write_text("cpu memory\n", encoding="ascii")
        controller = CgroupV2Controller(cgroup_root=parent)
        no_reservation = sample_policy()
        del no_reservation["reservations"]["host"]
        with self.assertRaises(ResourceError):
            controller.create_group("participant-no-reservation", no_reservation, "host")
        self.assertFalse((parent / "participant-no-reservation").exists())
        collision = parent / "participant-collision"
        collision.mkdir()
        with self.assertRaises(ResourceError):
            controller.create_group("participant-collision", sample_policy(), "host")
        self.assertTrue(collision.is_dir())

        empty_failure = parent / "participant-empty-failure"
        original_write = Path.write_text

        def fail_first_control_write(path, data, *args, **kwargs):
            if path == empty_failure / "memory.max":
                raise OSError("simulated first control write failure")
            return original_write(path, data, *args, **kwargs)

        with mock.patch.object(Path, "write_text", fail_first_control_write):
            with self.assertRaises(ResourceError) as error:
                controller.create_group("participant-empty-failure", sample_policy(), "host")
        self.assertIsNone(error.exception.retained_group)
        self.assertFalse(empty_failure.exists())

        partial_failure = parent / "participant-partial-failure"

        def fail_second_control_write(path, data, *args, **kwargs):
            if path == partial_failure / "cpu.max":
                raise OSError("simulated second control write failure")
            return original_write(path, data, *args, **kwargs)

        with mock.patch.object(Path, "write_text", fail_second_control_write):
            with self.assertRaises(ResourceError) as error:
                controller.create_group("participant-partial-failure", sample_policy(), "host")
        self.assertEqual(error.exception.retained_group, partial_failure)
        self.assertTrue(partial_failure.exists())

    def test_configuration_is_bounded_role_scoped_and_required(self):
        fresh_state = Path(self.temp.name) / "fresh-state"
        fresh_state.mkdir(mode=0o700)
        fresh = ProcessRoleBackend(str(fresh_state), FakeCgroup(fresh_state))
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
                REAL_OS_WRITE(write_fd, b"R")
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
