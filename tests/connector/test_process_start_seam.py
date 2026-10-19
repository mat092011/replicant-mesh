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

    def test_final_process_poll_exception_consumes_handle_and_returns_false(self):
        def spawn_with_one_poll_error(*args, **kwargs):
            child = FakeProcess(args[0], kwargs, self.cgroup)
            original_poll = child.poll
            calls = []

            def poll_once_fails():
                if not calls:
                    calls.append(True)
                    raise OSError("poll failed")
                return original_poll()

            child.poll = poll_once_fails
            self.owner["process"] = child
            return child

        with mock.patch.object(process_supervisor.subprocess, "Popen",
                               side_effect=spawn_with_one_poll_error):
            handle = self.backend.spawn_owned_start("host", sample_policy())
            self.assertIsNotNone(handle)
            self.assertFalse(self.backend.observe_owned_ready(handle))
            with self.assertRaisesRegex(ValueError, "already observed"):
                self.backend.observe_owned_ready(handle)
        self.assertNotIn("host", self.backend.status())
        self.assertIsNotNone(self.owner["process"].poll())

        # The compatibility wrapper retains its boolean failure contract when
        # its final process observation fails as well.
        with mock.patch.object(process_supervisor.subprocess, "Popen",
                               side_effect=spawn_with_one_poll_error):
            self.assertFalse(self.backend.start("host", sample_policy()))
        self.assertNotIn("host", self.backend.status())

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

    def test_pre_popen_callback_cancellation_prevents_process_creation(self):
        cancelled = threading.Event()
        calls = []

        def check():
            calls.append(True)
            cancelled.set()
            return None

        with mock.patch.object(process_supervisor.subprocess, "Popen") as popen:
            self.assertIsNone(self.backend.spawn_owned_start(
                "host", sample_policy(), cancel_event=cancelled,
                before_popen_check=check))
        self.assertEqual(calls, [True])
        popen.assert_not_called()
        self.assertNotIn("host", self.backend._owned)
        self.assertNotIn("host", self.backend._start_intents)

    def test_cancel_published_during_owner_publication_prevents_popen(self):
        cancelled = threading.Event()
        real_owned = self.backend._owned

        class CancelOnPublish(dict):
            def __setitem__(self, key, value):
                super().__setitem__(key, value)
                cancelled.set()

        self.backend._owned = CancelOnPublish()
        try:
            with mock.patch.object(process_supervisor.subprocess, "Popen") as popen:
                self.assertIsNone(self.backend.spawn_owned_start(
                    "host", sample_policy(), cancel_event=cancelled))
            popen.assert_not_called()
            self.assertNotIn("host", self.backend._owned)
            self.assertNotIn("host", self.backend._start_intents)
        finally:
            self.backend._owned = real_owned

    def test_gate_close_consumes_descriptor_before_close_attempt(self):
        real_close = os.close
        real_open = os.open

        for gate in ("read", "write"):
            with self.subTest(gate=gate):
                self.owner.clear()
                captured_write = []

                def capture_write(fd, data):
                    if data == b"R":
                        captured_write.append(fd)
                        if gate == "write":
                            target["fd"] = fd
                    return len(data) if data == b"R" else 0

                replacement = []
                target = {"fd": None, "raised": False}

                def close_then_reuse(fd):
                    if fd == target["fd"] and not target["raised"]:
                        target["raised"] = True
                        real_close(fd)
                        reused = real_open(os.devnull, os.O_RDONLY)
                        replacement.append(reused)
                        self.assertEqual(reused, fd)
                        raise OSError("close reported failure after closing")
                    real_close(fd)

                def spawn_capture(*args, **kwargs):
                    child = FakeProcess(args[0], kwargs, self.cgroup)
                    self.owner["process"] = child
                    if gate == "read":
                        target["fd"] = int(args[0][-1])
                    return child

                with mock.patch.object(process_supervisor.os, "write",
                                       side_effect=capture_write), mock.patch.object(
                        process_supervisor.os, "close", side_effect=close_then_reuse), \
                        mock.patch.object(process_supervisor.subprocess, "Popen",
                                          side_effect=spawn_capture):
                    pending = self.backend.spawn_owned_start("host", sample_policy())
                self.assertIsNone(pending)
                self.assertEqual(len(replacement), 1)
                os.fstat(replacement[0])
                real_close(replacement[0])

    def _assert_fence_during_final_poll(self, fence):
        handle = self.backend.spawn_owned_start("host", sample_policy())
        process = self.owner["process"]
        original_poll = process.poll
        entered, release = threading.Event(), threading.Event()

        def blocked_poll():
            if not entered.is_set():
                entered.set()
                release.wait(1)
            return original_poll()

        process.poll = blocked_poll
        result = {}
        observer = threading.Thread(target=lambda: result.setdefault(
            "ready", self.backend.observe_owned_ready(handle, timeout_seconds=1)))
        observer.start()
        self.assertTrue(entered.wait(1))
        if fence == "stop":
            self.assertTrue(self.backend.request_stop(["host"])["host"])
        else:
            self.assertTrue(self.backend.request_drain(["host"])["host"])
        release.set()
        observer.join(1)
        self.assertFalse(observer.is_alive())
        self.assertFalse(result["ready"])
        self.assertFalse(self.backend.status().get("host", {}).get("ready", False))
        self.assertTrue(self.backend.stop(["host"], 0.5)["host"])

    def test_stop_fence_during_final_poll_cannot_publish_ready(self):
        self._assert_fence_during_final_poll("stop")

    def test_drain_fence_during_final_poll_cannot_publish_ready(self):
        self._assert_fence_during_final_poll("drain")

    def test_old_observer_cannot_remove_replacement_generation_handle(self):
        old_handle = self.backend.spawn_owned_start("host", sample_policy())
        old_process = self.owner["process"]
        entered, release = threading.Event(), threading.Event()

        def delay_old_ready(process, timeout, cancelled=None):
            if process is old_process:
                entered.set()
                release.wait(1)
            return True

        outcome = {}
        with mock.patch.object(ProcessRoleBackend, "_read_ready",
                               side_effect=delay_old_ready):
            observer = threading.Thread(target=lambda: outcome.setdefault(
                "ready", self.backend.observe_owned_ready(old_handle)))
            observer.start()
            self.assertTrue(entered.wait(1))
            self.assertTrue(self.backend.stop(["host"], 0.5)["host"])
            new_handle = self.backend.spawn_owned_start("host", sample_policy())
            self.assertIsNotNone(new_handle)
            new_process = self.owner["process"]
            self.assertIsNot(new_process, old_process)
            self.assertIs(self.backend._pending_starts["host"], new_handle)
            release.set()
            observer.join(1)
            self.assertFalse(observer.is_alive())
            self.assertFalse(outcome["ready"])
            self.assertIs(self.backend._owned["host"].process, new_process)
            self.assertIs(self.backend._pending_starts["host"], new_handle)
            self.assertTrue(self.backend.observe_owned_ready(new_handle))
        self.assertTrue(self.backend.stop(["host"], 0.5)["host"])

    def test_invalid_ready_timeouts_are_rejected_before_consuming_handle(self):
        handle = self.backend.spawn_owned_start("host", sample_policy())
        for invalid in (True, -1, 30.01, float("inf"), float("nan"), "1", 10 ** 1000):
            with self.subTest(invalid=invalid):
                with self.assertRaises(ValueError):
                    self.backend.observe_owned_ready(handle, timeout_seconds=invalid)
        self.assertTrue(self.backend.observe_owned_ready(handle, timeout_seconds=0))


if __name__ == "__main__":
    unittest.main()
