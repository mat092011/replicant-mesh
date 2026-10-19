import json
import os
import signal
import tempfile
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from steamboat_connector.process_supervisor import (
    PendingRoleStart, ProcessRoleBackend)
from steamboat_connector import process_supervisor
from tests.connector.test_process_supervisor import FakeCgroup, FakeProcess, sample_policy


class ProcessStartSeamTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        platform_patch = mock.patch.object(process_supervisor.sys, "platform", "linux")
        platform_patch.start()
        self.addCleanup(platform_patch.stop)
        self.cgroup = FakeCgroup(self.temp.name)
        self.backend = ProcessRoleBackend(self.temp.name, self.cgroup)
        self.owner = {}

        def write_private(path, data):
            Path(path).write_bytes(data)
            os.chmod(path, 0o600)

        def spawn(*args, **kwargs):
            child = FakeProcess(args[0], kwargs, self.cgroup)
            self.owner["process"] = child
            return child

        def killpg(pid, sig):
            self.owner["process"].on_signal(sig)

        patches = [
            mock.patch.object(process_supervisor, "atomic_write_private",
                               side_effect=write_private),
            mock.patch.object(process_supervisor, "read_private_json",
                               side_effect=lambda path, **kwargs: json.loads(
                                   Path(path).read_text(encoding="utf-8"))),
            mock.patch.object(ProcessRoleBackend, "_read_ready", return_value=True),
            mock.patch.object(ProcessRoleBackend, "_attach_child_safely",
                               side_effect=lambda group, child:
                               self.cgroup.attach_child(group, child)),
            mock.patch.object(process_supervisor, "signal",
                               SimpleNamespace(SIGTERM=15, SIGKILL=9)),
            mock.patch.object(process_supervisor.os, "write",
                               side_effect=lambda fd, data: len(data)
                               if data == b"R" else 0),
            mock.patch.object(process_supervisor.subprocess, "Popen", side_effect=spawn),
            mock.patch.object(process_supervisor.os, "killpg", side_effect=killpg,
                               create=True),
        ]
        self.patchers = patches
        for patcher in patches:
            patcher.start()
            self.addCleanup(patcher.stop)
        self.assertTrue(self.backend.configure_role("host", {"test_mode": True}))

    def test_spawn_and_ready_are_separate_and_handle_is_one_shot(self):
        with mock.patch.object(ProcessRoleBackend, "_read_ready", return_value=True) as ready:
            handle = self.backend.spawn_owned_start("host", sample_policy())
            self.assertIs(type(handle), PendingRoleStart)
            ready.assert_not_called()
            self.assertTrue(self.cgroup.attached)
            self.assertTrue(self.backend.status()["host"]["owned"])
            self.assertFalse(self.backend.status()["host"]["ready"])
            self.assertIn("host", self.backend._start_intents)
            self.assertIsNone(self.backend.spawn_owned_start("host", sample_policy()))

            self.assertTrue(self.backend.observe_owned_ready(handle, timeout_seconds=1))
            self.assertEqual(ready.call_count, 1)
            self.assertTrue(self.backend.status()["host"]["ready"])
            self.assertNotIn("host", self.backend._start_intents)
            with self.assertRaisesRegex(ValueError, "already observed"):
                self.backend.observe_owned_ready(handle)

    def test_foreign_and_forged_handles_are_rejected(self):
        handle = self.backend.spawn_owned_start("host", sample_policy())
        other = ProcessRoleBackend(self.temp.name, self.cgroup)
        with self.assertRaisesRegex(ValueError, "foreign or forged"):
            other.observe_owned_ready(handle)
        forged = PendingRoleStart.__new__(PendingRoleStart)
        with self.assertRaisesRegex(ValueError, "foreign or forged"):
            self.backend.observe_owned_ready(forged)
        self.assertTrue(self.backend.stop(["host"], 0.5)["host"])

    def test_stop_reclaims_unobserved_spawn_and_invalidates_handle(self):
        handle = self.backend.spawn_owned_start("host", sample_policy())
        process = self.owner["process"]
        self.assertIn("host", self.backend._pending_starts)
        self.assertTrue(self.backend.stop(["host"], 0.5)["host"])
        self.assertIsNotNone(process.poll())
        self.assertEqual(self.backend.status(), {})
        self.assertNotIn("host", self.backend._pending_starts)
        self.assertNotIn("host", self.backend._start_intents)
        with self.assertRaisesRegex(ValueError, "no longer current"):
            self.backend.observe_owned_ready(handle)

    def test_stop_during_ready_observation_prevents_readiness(self):
        entered, release = threading.Event(), threading.Event()

        def wait_ready(process, timeout, cancelled=None):
            entered.set()
            release.wait(1)
            return True

        handle = self.backend.spawn_owned_start("host", sample_policy())
        outcome = {}
        with mock.patch.object(ProcessRoleBackend, "_read_ready", side_effect=wait_ready):
            observer = threading.Thread(target=lambda: outcome.setdefault(
                "ready", self.backend.observe_owned_ready(handle, timeout_seconds=1)))
            observer.start()
            self.assertTrue(entered.wait(1))
            self.backend.request_stop(["host"])
            self.assertTrue(self.backend.stop(["host"], 0.5)["host"])
            release.set()
            observer.join(1)
        self.assertFalse(observer.is_alive())
        self.assertFalse(outcome["ready"])
        self.assertEqual(self.backend.status(), {})

    def test_concurrent_observation_is_rejected_without_a_second_read(self):
        entered, release = threading.Event(), threading.Event()

        def wait_ready(process, timeout, cancelled=None):
            entered.set()
            release.wait(1)
            return True

        handle = self.backend.spawn_owned_start("host", sample_policy())
        result = {}
        with mock.patch.object(ProcessRoleBackend, "_read_ready", side_effect=wait_ready) as ready:
            observer = threading.Thread(target=lambda: result.setdefault(
                "ready", self.backend.observe_owned_ready(handle)))
            observer.start()
            self.assertTrue(entered.wait(1))
            with self.assertRaisesRegex(RuntimeError, "already in progress"):
                self.backend.observe_owned_ready(handle)
            release.set()
            observer.join(1)
        self.assertFalse(observer.is_alive())
        self.assertTrue(result["ready"])
        self.assertEqual(ready.call_count, 1)

    def test_ready_reader_exception_consumes_handle_and_stops_child(self):
        handle = self.backend.spawn_owned_start("host", sample_policy())
        with mock.patch.object(ProcessRoleBackend, "_read_ready",
                               side_effect=OSError("read failed")) as ready:
            self.assertFalse(self.backend.observe_owned_ready(handle))
            self.assertEqual(ready.call_count, 1)
            with self.assertRaisesRegex(ValueError, "already observed"):
                self.backend.observe_owned_ready(handle)
        self.assertIsNotNone(self.owner["process"].poll())

    def test_pre_popen_check_must_return_exact_none_and_precedes_spawn(self):
        calls = []

        def accepted():
            calls.append(("check", self.cgroup.group.exists()))
            return None

        handle = self.backend.spawn_owned_start(
            "host", sample_policy(), before_popen_check=accepted)
        self.assertIsNotNone(handle)
        self.assertEqual(calls, [("check", True)])
        self.assertTrue(self.backend.observe_owned_ready(handle))

    def test_pre_popen_check_rejects_value_and_awaitable_without_popen(self):
        self.assertIsNone(self.backend.spawn_owned_start(
            "host", sample_policy(), before_popen_check=lambda: False))
        self.assertNotIn("host", self.backend._owned)
        self.assertNotIn("host", self.backend._start_intents)

        async def async_check():
            return None

        self.assertIsNone(self.backend.spawn_owned_start(
            "host", sample_policy(), before_popen_check=async_check))
        self.assertNotIn("host", self.backend._owned)
        self.assertNotIn("host", self.backend._start_intents)
        self.assertNotIn("process", self.owner)
        self.assertTrue(all(not group.exists() for group in self.cgroup.groups))

    def test_invalid_ready_timeouts_are_rejected_before_consuming_handle(self):
        handle = self.backend.spawn_owned_start("host", sample_policy())
        for invalid in (True, -1, 30.01, float("inf"), float("nan"), "1", 10 ** 1000):
            with self.subTest(invalid=invalid):
                with self.assertRaises(ValueError):
                    self.backend.observe_owned_ready(handle, timeout_seconds=invalid)
        self.assertTrue(self.backend.observe_owned_ready(handle, timeout_seconds=0))


if __name__ == "__main__":
    unittest.main()
