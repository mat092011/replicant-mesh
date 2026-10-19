from __future__ import annotations

import json
import os
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from lab import secure_cohort_supervisor as supervisor


class _Channel:
    def __init__(self, *, subsystem_error=None, recv_error=None):
        self.timeouts = []
        self.subsystem_error = subsystem_error
        self.recv_error = recv_error
        self.closed = False
        self.close_calls = []
        self.closed_event = threading.Event()
        self.events = []

    def settimeout(self, value):
        self.timeouts.append(value)

    def invoke_subsystem(self, name):
        self.events.append(("subsystem", name))
        if self.subsystem_error is not None:
            raise self.subsystem_error

    def exec_command(self, command):
        self.events.append(("exec", command))

    def makefile_stdin(self, *_args):
        return SimpleNamespace(write=lambda _value: None, flush=lambda: None)

    def makefile(self, *_args):
        return SimpleNamespace(channel=self)

    def makefile_stderr(self, *_args):
        return SimpleNamespace(channel=self)

    def recv_ready(self):
        return self.recv_error is not None

    def recv(self, _count):
        raise self.recv_error

    def recv_stderr_ready(self):
        return False

    def exit_status_ready(self):
        return False

    def recv_exit_status(self):
        return 0

    def shutdown_write(self):
        self.events.append(("shutdown_write",))

    def close(self):
        self.close_calls.append(time.monotonic())
        self.closed = True
        self.closed_event.set()


class _Transport:
    def __init__(self, channel):
        self.channel = channel
        self.open_timeouts = []

    def open_session(self, *, timeout):
        self.open_timeouts.append(timeout)
        return self.channel


class _Sftp:
    def __init__(self, channel):
        self.channel = channel
        self.events = []
        self.payload_size = 0
        self.file_mode = 0o644
        self.open_modes = []
        self.apply_file_chmod = True
        self.block_write = False
        self.write_started = threading.Event()
        self.release_write = threading.Event()
        self.write_finished = threading.Event()
        self.fail_at = None

    def get_channel(self):
        return self.channel

    def _event(self, name):
        self.events.append(name)
        if self.fail_at == name:
            raise socket.timeout("synthetic SFTP timeout")

    def open(self, _path, mode):
        self._event("open")
        self.open_modes.append(mode)
        return _SftpStream(self)

    def chmod(self, _path, _mode):
        self._event("chmod")

    def stat(self, _path):
        self._event("stat")
        return SimpleNamespace(st_uid=1000, st_gid=1000,
                               st_mode=stat.S_IFREG | self.file_mode,
                               st_size=self.payload_size)

    def normalize(self, _path):
        self._event("normalize")
        return "/home/worker"

    def close(self):
        self._event("sftp_close")


class _SftpStream:
    def __init__(self, sftp):
        self.sftp = sftp

    def set_pipelined(self, _enabled):
        self.sftp._event("pipelined")

    def chmod(self, mode):
        self.sftp._event("file_chmod")
        if self.sftp.apply_file_chmod:
            self.sftp.file_mode = mode

    def stat(self):
        self.sftp._event("file_stat")
        return SimpleNamespace(st_uid=1000, st_gid=1000,
                               st_mode=stat.S_IFREG | self.sftp.file_mode,
                               st_size=self.sftp.payload_size)

    def write(self, payload):
        self.sftp.payload_size = len(payload)
        self.sftp._event("write")
        self.sftp.write_started.set()
        try:
            if self.sftp.block_write:
                self.sftp.release_write.wait()
        finally:
            self.sftp.write_finished.set()

    def flush(self):
        self.sftp._event("flush")

    def close(self):
        self.sftp._event("file_close")


class DeadlineHelperTests(unittest.TestCase):
    def test_deadline_rejects_expired_and_nonfinite_values(self):
        for deadline in (True, float("nan"), float("inf"), time.monotonic() - 1):
            with self.subTest(deadline=deadline):
                with self.assertRaises(supervisor.SupervisorError) as caught:
                    supervisor._deadline_remaining(deadline, "test")
                self.assertEqual(caught.exception.code, "deadline")

    def test_connect_requires_caller_deadline(self):
        with self.assertRaises(supervisor.SupervisorError) as caught:
            supervisor._connect_ssh(SimpleNamespace())
        self.assertEqual(caught.exception.code, "deadline")


class SshConnectionDeadlineTests(unittest.TestCase):
    def _paramiko(self, client):
        return SimpleNamespace(SSHClient=lambda: client,
                               RejectPolicy=lambda: "strict-reject")

    def _args(self):
        return SimpleNamespace(known_hosts="known-hosts", ssh_password_file="password",
                               ssh_key_file=None, ssh_host="worker.example",
                               ssh_user="operator")

    def test_connection_timeout_uses_absolute_deadline_and_strict_host_policy(self):
        key = SimpleNamespace(asbytes=lambda: b"pinned-host-key")
        transport = SimpleNamespace(get_remote_server_key=lambda: key)

        class Client:
            policy = None
            kwargs = None

            def load_host_keys(self, path):
                self.host_file = path

            def set_missing_host_key_policy(self, policy):
                self.policy = policy

            def connect(self, *_args, **kwargs):
                self.kwargs = kwargs

            def get_transport(self):
                return transport

            def close(self):
                self.was_closed = True

        client = Client()
        deadline = time.monotonic() + 1.0
        with mock.patch.dict(sys.modules, {"paramiko": self._paramiko(client)}), \
                mock.patch.object(supervisor, "_read_secret_file", return_value="secret"):
            returned, fingerprint, password = supervisor._connect_ssh(
                self._args(), deadline)
        self.assertIs(returned, client)
        self.assertEqual(password, "secret")
        self.assertEqual(fingerprint, supervisor.hashlib.sha256(b"pinned-host-key").hexdigest())
        self.assertEqual(client.policy, "strict-reject")
        self.assertLessEqual(client.kwargs["timeout"], 1.0)
        self.assertLessEqual(client.kwargs["banner_timeout"], 1.0)
        self.assertLessEqual(client.kwargs["auth_timeout"], 1.0)
        self.assertLessEqual(client.kwargs["channel_timeout"], 1.0)

    def test_blocked_connection_returns_at_deadline_and_closes_client(self):
        started = threading.Event()
        release = threading.Event()
        finished = threading.Event()

        class Client:
            def load_host_keys(self, _path):
                pass

            def set_missing_host_key_policy(self, _policy):
                pass

            def connect(self, *_args, **_kwargs):
                started.set()
                release.wait(2.0)
                finished.set()

            def close(self):
                self.was_closed = True

            def get_transport(self):
                return None

        client = Client()
        deadline = time.monotonic() + 0.08
        try:
            with mock.patch.dict(sys.modules, {"paramiko": self._paramiko(client)}), \
                    mock.patch.object(supervisor, "_read_secret_file", return_value="secret"):
                started_at = time.monotonic()
                with self.assertRaises(supervisor.SupervisorError) as caught:
                    supervisor._connect_ssh(self._args(), deadline)
                elapsed = time.monotonic() - started_at
            self.assertTrue(started.wait(0.2))
            self.assertEqual(caught.exception.code, "deadline")
            self.assertLess(elapsed, 0.5)
            self.assertTrue(client.was_closed)
        finally:
            release.set()
            self.assertTrue(finished.wait(0.5))

    def test_expired_deadline_does_not_construct_client(self):
        factory = mock.Mock()
        with mock.patch.dict(sys.modules, {
                "paramiko": SimpleNamespace(SSHClient=factory)}):
            with self.assertRaises(supervisor.SupervisorError):
                supervisor._connect_ssh(self._args(), time.monotonic() - 1)
        factory.assert_not_called()


class SshCommandDeadlineTests(unittest.TestCase):
    def test_channel_timeout_uses_remaining_absolute_budget_after_open(self):
        channel = _Channel()
        channel.exit_status_ready = lambda: True
        now = [100.0]
        transport = _Transport(channel)
        client = SimpleNamespace(get_transport=lambda: transport)
        with mock.patch.object(supervisor.time, "monotonic", side_effect=lambda: now[0]):
            code, output = supervisor._ssh_exec(
                client, ["true"], password=None, deadline=105.0, sudo=False)
        self.assertEqual((code, output), (0, b""))
        self.assertEqual(transport.open_timeouts[0], 5.0)
        self.assertLessEqual(channel.timeouts[-1], 5.0)
        self.assertGreater(channel.timeouts[-1], 0)

    def test_blocked_ssh_read_gets_socket_timeout_and_closes_channel(self):
        channel = _Channel(recv_error=socket.timeout("blocked read"))
        transport = _Transport(channel)
        client = SimpleNamespace(get_transport=lambda: transport)
        with self.assertRaises(supervisor.SupervisorError) as caught:
            supervisor._ssh_exec(client, ["true"], password=None,
                                 deadline=time.monotonic() + 1.0, sudo=False)
        self.assertEqual(caught.exception.code, "timeout")
        self.assertGreater(transport.open_timeouts[0], 0)
        self.assertTrue(channel.timeouts)
        self.assertTrue(channel.closed)

    def test_request_timeout_closes_channel_and_retains_then_retires_operation(self):
        channel = _Channel()
        started = threading.Event()
        channel.exec_command = lambda _command: (started.set(), channel.closed_event.wait())
        deadline = time.monotonic() + 0.05
        with self.assertRaises(supervisor.SupervisorError) as caught:
            supervisor._channel_operation(
                channel, lambda: channel.exec_command("true"), deadline=deadline,
                stage="ssh_command", failure_code="transport_error")
        self.assertEqual(caught.exception.code, "ack_timeout_unknown")
        self.assertTrue(started.wait(0.2))
        self.assertTrue(channel.closed_event.wait(0.2))
        limit = time.monotonic() + 1.0
        while supervisor._pending_channel_operation_count() and time.monotonic() < limit:
            time.sleep(0.005)
        self.assertEqual(supervisor._pending_channel_operation_count(), 0)

    def test_successful_request_has_retired_before_success_returns(self):
        channel = _Channel()
        calls = []
        result = supervisor._channel_operation(
            channel, lambda: calls.append("acknowledged") or 7,
            deadline=time.monotonic() + 1.0, stage="ssh_command",
            failure_code="transport_error")
        self.assertEqual(result, 7)
        self.assertEqual(calls, ["acknowledged"])
        self.assertEqual(supervisor._pending_channel_operation_count(), 0)


class SftpDeadlineTests(unittest.TestCase):
    def _wait_for_owner_count(self, expected, timeout=1.0):
        limit = time.monotonic() + timeout
        while time.monotonic() < limit:
            if supervisor._pending_channel_operation_count() == expected:
                return True
            time.sleep(0.005)
        return supervisor._pending_channel_operation_count() == expected

    def test_open_sftp_bounds_channel_open_and_subsystem_handshake(self):
        channel = _Channel()
        transport = _Transport(channel)
        client = SimpleNamespace(get_transport=lambda: transport,
                                  open_sftp=lambda: self.fail("unbounded open_sftp used"))
        paramiko = SimpleNamespace(SFTPClient=lambda actual: _Sftp(actual))
        deadline = time.monotonic() + 1.0
        with mock.patch.dict(sys.modules, {"paramiko": paramiko}):
            result = supervisor._open_sftp(client, deadline)
        self.assertIsInstance(result, _Sftp)
        self.assertEqual(channel.events, [("subsystem", "sftp")])
        self.assertGreater(transport.open_timeouts[0], 0)
        self.assertLessEqual(transport.open_timeouts[0], 1.0)
        self.assertTrue(channel.timeouts)
        self.assertTrue(all(0 < value <= 1.0 for value in channel.timeouts))

    def test_open_sftp_closes_channel_on_handshake_failure(self):
        channel = _Channel(subsystem_error=socket.timeout("blocked handshake"))
        transport = _Transport(channel)
        with mock.patch.dict(sys.modules, {
                "paramiko": SimpleNamespace(SFTPClient=lambda actual: _Sftp(actual))}):
            with self.assertRaises(supervisor.SupervisorError) as caught:
                supervisor._open_sftp(SimpleNamespace(get_transport=lambda: transport),
                                      time.monotonic() + 1.0)
        self.assertEqual(caught.exception.code, "timeout")
        self.assertTrue(channel.closed)
        self.assertGreater(channel.timeouts[0], 0)

    def test_subsystem_ack_timeout_closes_channel_and_retires_waiter(self):
        channel = _Channel()
        started = threading.Event()

        def blocked_subsystem(_name):
            started.set()
            channel.closed_event.wait()

        channel.invoke_subsystem = blocked_subsystem
        transport = _Transport(channel)
        with mock.patch.dict(sys.modules, {
                "paramiko": SimpleNamespace(SFTPClient=lambda actual: _Sftp(actual))}):
            with self.assertRaises(supervisor.SupervisorError) as caught:
                supervisor._open_sftp(
                    SimpleNamespace(get_transport=lambda: transport),
                    time.monotonic() + 0.05)
        self.assertEqual(caught.exception.code, "ack_timeout_unknown")
        self.assertTrue(started.wait(0.2))
        self.assertTrue(channel.closed_event.wait(0.2))
        limit = time.monotonic() + 1.0
        while supervisor._pending_channel_operation_count() and time.monotonic() < limit:
            time.sleep(0.005)
        self.assertEqual(supervisor._pending_channel_operation_count(), 0)

    def test_sftp_constructor_handshake_is_bounded_by_same_deadline(self):
        channel = _Channel()
        transport = _Transport(channel)
        started = threading.Event()

        def blocked_constructor(actual):
            self.assertIs(actual, channel)
            started.set()
            channel.closed_event.wait()
            raise EOFError("closed by deadline")

        with mock.patch.dict(sys.modules, {
                "paramiko": SimpleNamespace(SFTPClient=blocked_constructor)}):
            with self.assertRaises(supervisor.SupervisorError) as caught:
                supervisor._open_sftp(
                    SimpleNamespace(get_transport=lambda: transport),
                    time.monotonic() + 0.05)
        self.assertEqual(caught.exception.code, "ack_timeout_unknown")
        self.assertTrue(started.wait(0.2))
        self.assertTrue(channel.closed_event.wait(0.2))
        limit = time.monotonic() + 1.0
        while supervisor._pending_channel_operation_count() and time.monotonic() < limit:
            time.sleep(0.005)
        self.assertEqual(supervisor._pending_channel_operation_count(), 0)

    def test_expired_open_sftp_never_opens_channel(self):
        channel = _Channel()
        transport = _Transport(channel)
        with mock.patch.dict(sys.modules, {
                "paramiko": SimpleNamespace(SFTPClient=lambda actual: _Sftp(actual))}):
            with self.assertRaises(supervisor.SupervisorError) as caught:
                supervisor._open_sftp(SimpleNamespace(get_transport=lambda: transport),
                                      time.monotonic() - 1)
        self.assertEqual(caught.exception.code, "deadline")
        self.assertEqual(transport.open_timeouts, [])

    def test_bundle_upload_times_each_sftp_operation_and_closes(self):
        channel = _Channel()
        sftp = _Sftp(channel)
        deadline = time.monotonic() + 2.0
        with mock.patch.object(supervisor, "_open_sftp", return_value=sftp):
            supervisor._sftp_upload_bundle(
                SimpleNamespace(), b"bundle", "/srv/jobs/job-1", 1000, deadline)
        self.assertEqual(sftp.open_modes, ["wx"])
        self.assertEqual(sftp.events, ["open", "file_chmod", "file_stat",
                                       "pipelined", "write", "flush",
                                       "file_close", "stat", "sftp_close"])
        self.assertLess(sftp.events.index("file_chmod"), sftp.events.index("write"))
        self.assertLess(sftp.events.index("file_stat"), sftp.events.index("write"))
        self.assertTrue(channel.timeouts)
        self.assertTrue(all(value > 0 for value in channel.timeouts))
        self.assertTrue(all(left >= right for left, right in
                            zip(channel.timeouts, channel.timeouts[1:])))

    def test_bundle_upload_fails_closed_before_payload_if_handle_mode_is_not_private(self):
        channel = _Channel()
        sftp = _Sftp(channel)
        sftp.apply_file_chmod = False
        with mock.patch.object(supervisor, "_open_sftp", return_value=sftp):
            with self.assertRaises(supervisor.SupervisorError) as caught:
                supervisor._sftp_upload_bundle(
                    SimpleNamespace(), b"bundle", "/srv/jobs/job-1", 1000,
                    time.monotonic() + 1.0)
        self.assertEqual(caught.exception.code, "remote_metadata")
        self.assertEqual(sftp.open_modes, ["wx"])
        self.assertNotIn("write", sftp.events)
        self.assertIn("file_chmod", sftp.events)
        self.assertIn("file_stat", sftp.events)
        self.assertIn("file_close", sftp.events)
        self.assertIn("sftp_close", sftp.events)

    def test_timeout_close_failure_is_not_confirmed_when_operation_retires(self):
        channel = _Channel()
        sftp = _Sftp(channel)
        sftp.block_write = True
        close_attempts = []

        def failed_close():
            close_attempts.append(True)
            raise OSError("synthetic channel close failure")

        channel.close = failed_close
        with mock.patch.object(supervisor, "_open_sftp", return_value=sftp):
            with self.assertRaises(supervisor.SupervisorError) as caught:
                supervisor._sftp_upload_bundle(
                    SimpleNamespace(), b"bundle", "/srv/jobs/job-1", 1000,
                    time.monotonic() + 0.04)
        self.assertEqual(caught.exception.code, "ack_timeout_unknown")
        self.assertTrue(sftp.write_started.is_set())
        with supervisor._CHANNEL_OPERATION_LOCK:
            owner = supervisor._CHANNEL_OPERATION_BY_CHANNEL[id(channel)]
            reaper = owner["reaper"]
        try:
            sftp.release_write.set()
            reaper.join(1)
            self.assertFalse(reaper.is_alive())
            self.assertTrue(supervisor._channel_operation_owned(channel))
            self.assertEqual(len(close_attempts), 1)
            self.assertNotIn("file_close", sftp.events)
            self.assertNotIn("sftp_close", sftp.events)
            self.assertIn({
                "stage": "bundle_upload", "state": "close_failed_unconfirmed",
                "failure_code": "abort_close_failed", "close_started": True,
            }, supervisor._pending_channel_operation_evidence())
            forbidden = mock.Mock()
            with self.assertRaises(supervisor.SupervisorError) as fenced:
                supervisor._sftp_call(sftp, time.monotonic() + 1, "next_call", forbidden)
            self.assertEqual(fenced.exception.code, "operation_ownership_pending")
            forbidden.assert_not_called()
        finally:
            sftp.release_write.set()
            reaper.join(1)
            # Only synthetic fixtures are disposed after actual threads exit.
            with supervisor._CHANNEL_OPERATION_LOCK:
                supervisor._CHANNEL_OPERATION_OWNERS.pop(id(owner), None)
                supervisor._CHANNEL_OPERATION_BY_CHANNEL.pop(id(channel), None)

    def test_failed_abort_retains_unconfirmed_channel_after_threads_exit(self):
        channel = _Channel()
        release = threading.Event()
        entered = threading.Event()

        def failed_close():
            entered.set()
            release.wait()
            raise OSError("synthetic close failure")

        channel.close = failed_close
        supervisor._abort_channel(channel)
        self.assertTrue(entered.wait(0.5))
        with supervisor._CHANNEL_OPERATION_LOCK:
            owner = supervisor._CHANNEL_OPERATION_BY_CHANNEL[id(channel)]
            reaper = owner["closer"]
        try:
            release.set()
            reaper.join(1)
            self.assertFalse(reaper.is_alive())
            self.assertTrue(supervisor._channel_operation_owned(channel))
            self.assertIn({
                "stage": "transport_abort", "state": "close_failed_unconfirmed",
                "failure_code": "abort_close_failed", "close_started": True,
            }, supervisor._pending_channel_operation_evidence())
        finally:
            release.set()
            reaper.join(1)
            # Dispose only this synthetic channel after its actual test threads
            # exited. Production cannot erase an unconfirmed close this way.
            with supervisor._CHANNEL_OPERATION_LOCK:
                supervisor._CHANNEL_OPERATION_OWNERS.pop(id(owner), None)
                supervisor._CHANNEL_OPERATION_BY_CHANNEL.pop(id(channel), None)

    def test_deadline_between_upload_calls_never_waits_for_stalled_abort(self):
        channel = _Channel()
        sftp = _Sftp(channel)
        release_close = threading.Event()
        close_started = threading.Event()
        close_attempts = []
        original_close = channel.close
        original_call = supervisor._sftp_call
        baseline = supervisor._pending_channel_operation_count()
        deadline = time.monotonic() + 0.06

        def stalled_close():
            close_attempts.append(True)
            close_started.set()
            release_close.wait()
            original_close()

        def expire_after_metadata(actual, cutoff, stage, call):
            result = original_call(actual, cutoff, stage, call)
            if getattr(call, "__name__", None) == "stat" and isinstance(
                    getattr(call, "__self__", None), _SftpStream):
                time.sleep(max(0, cutoff - time.monotonic()) + 0.01)
            return result

        channel.close = stalled_close
        started = time.monotonic()
        try:
            with mock.patch.object(supervisor, "_open_sftp", return_value=sftp), \
                    mock.patch.object(supervisor, "_sftp_call", side_effect=expire_after_metadata):
                with self.assertRaises(supervisor.SupervisorError) as caught:
                    supervisor._sftp_upload_bundle(
                        SimpleNamespace(), b"bundle", "/srv/jobs/job-1", 1000,
                        deadline)
            self.assertEqual(caught.exception.code, "deadline")
            self.assertLess(time.monotonic() - started, 0.5)
            self.assertTrue(close_started.wait(0.2))
            self.assertEqual(supervisor._pending_channel_operation_count(), baseline + 1)
            self.assertNotIn("write", sftp.events)
            self.assertNotIn("file_close", sftp.events)
            self.assertNotIn("sftp_close", sftp.events)
            supervisor._abort_sftp(sftp)
            self.assertEqual(len(close_attempts), 1)
        finally:
            release_close.set()
            limit = time.monotonic() + 1
            while supervisor._pending_channel_operation_count() != baseline and time.monotonic() < limit:
                time.sleep(0.005)
        self.assertEqual(supervisor._pending_channel_operation_count(), baseline)

    def test_upload_timeout_keeps_owned_abort_and_blocks_finally_sftp_calls(self):
        channel = _Channel()
        sftp = _Sftp(channel)
        sftp.block_write = True
        baseline_owners = supervisor._pending_channel_operation_count()
        deadline = time.monotonic() + 0.08
        started = time.monotonic()
        try:
            with mock.patch.object(supervisor, "_open_sftp", return_value=sftp):
                with self.assertRaises(supervisor.SupervisorError) as caught:
                    supervisor._sftp_upload_bundle(
                        SimpleNamespace(), b"bundle", "/srv/jobs/job-1", 1000,
                        deadline)
            elapsed = time.monotonic() - started
            self.assertEqual(caught.exception.code, "ack_timeout_unknown")
            self.assertLess(elapsed, 0.5)
            self.assertTrue(sftp.write_started.is_set())
            self.assertTrue(channel.closed_event.wait(0.5))
            self.assertEqual(supervisor._pending_channel_operation_count(),
                             baseline_owners + 1)
            evidence = supervisor._pending_channel_operation_evidence()
            self.assertIn({
                "stage": "bundle_upload",
                "state": "unknown_pending_retirement",
                "failure_code": "ack_timeout_unknown",
                "close_started": True,
            }, evidence)
            self.assertNotIn("file_close", sftp.events)
            self.assertNotIn("sftp_close", sftp.events)

            next_call = mock.Mock()
            with self.assertRaises(supervisor.SupervisorError) as pending:
                supervisor._sftp_call(
                    sftp, time.monotonic() + 1.0, "second_sftp_operation", next_call)
            self.assertEqual(pending.exception.code, "operation_ownership_pending")
            next_call.assert_not_called()
            self.assertEqual(len(channel.close_calls), 1)
            supervisor._abort_sftp(sftp)
            self.assertEqual(len(channel.close_calls), 1)
            self.assertEqual(supervisor._pending_channel_operation_count(),
                             baseline_owners + 1)
        finally:
            sftp.release_write.set()
        self.assertTrue(sftp.write_finished.wait(1.0))
        self.assertTrue(self._wait_for_owner_count(baseline_owners))

    def test_blocked_flush_is_bounded_and_file_and_channel_are_closed(self):
        channel = _Channel()
        sftp = _Sftp(channel)
        sftp.fail_at = "flush"
        with mock.patch.object(supervisor, "_open_sftp", return_value=sftp):
            with self.assertRaises(supervisor.SupervisorError) as caught:
                supervisor._sftp_upload_bundle(
                    SimpleNamespace(), b"bundle", "/srv/jobs/job-1", 1000,
                    time.monotonic() + 1.0)
        self.assertEqual(caught.exception.code, "timeout")
        self.assertIn("file_close", sftp.events)
        self.assertIn("sftp_close", sftp.events)
        self.assertTrue(channel.timeouts)

    def test_blocked_sftp_close_is_timed_and_channel_is_aborted(self):
        channel = _Channel()
        sftp = _Sftp(channel)
        sftp.fail_at = "sftp_close"
        with mock.patch.object(supervisor, "_open_sftp", return_value=sftp):
            with self.assertRaises(supervisor.SupervisorError) as caught:
                supervisor._sftp_upload_bundle(
                    SimpleNamespace(), b"bundle", "/srv/jobs/job-1", 1000,
                    time.monotonic() + 1.0)
        self.assertEqual(caught.exception.code, "timeout")
        self.assertTrue(channel.timeouts)
        self.assertTrue(channel.closed)

    def test_expired_sftp_call_does_not_invoke_remote_operation(self):
        sftp = _Sftp(_Channel())
        operation = mock.Mock()
        with self.assertRaises(supervisor.SupervisorError) as caught:
            supervisor._sftp_call(sftp, time.monotonic() - 1, "sftp_test", operation)
        self.assertEqual(caught.exception.code, "deadline")
        operation.assert_not_called()

    def test_remote_user_identity_reads_are_deadline_bounded(self):
        sftp = _Sftp(_Channel())
        self.assertEqual(supervisor._remote_user_ids(
            sftp, time.monotonic() + 1.0), (1000, 1000))
        self.assertEqual(sftp.events, ["normalize", "stat"])
        self.assertEqual(len(sftp.channel.timeouts), 2)


class RemoteRemovalTests(unittest.TestCase):
    def _evidence(self, **overrides):
        value = {
            "schema_version": 1,
            "event": "remote_job_removal",
            "job_root": "/srv/steamboat/job-1",
            "uid": 1000,
            "gid": 1000,
            "confirmed": True,
            "removed": ["worker.tar", "host.key", "sockets/", "."],
            "residuals": [],
            "residuals_known": True,
            "residuals_truncated": False,
            "reason": None,
        }
        value.update(overrides)
        return supervisor._json_bytes(value)

    def test_script_is_bounded_descriptor_based_and_compiles(self):
        script = supervisor._remote_remove_job_script()
        compile(script, "remote_remove_job.py", "exec")
        self.assertIn("os.O_NOFOLLOW", script)
        self.assertIn("os.scandir(fd)", script)
        self.assertIn("os.unlink(n,dir_fd=root_fd)", script)
        self.assertIn("os.rmdir(parts[-1],dir_fd=parent_fd)", script)
        self.assertIn("worker.tar", script)
        self.assertIn("backend-[0-9a-f]{12}\\.sock", script)
        self.assertNotIn("shutil.rmtree", script)
        self.assertNotIn("os.walk(", script)

    @unittest.skipUnless(os.name == "posix", "requires POSIX dir_fd and Unix sockets")
    def test_script_removes_only_allowlisted_private_job_entries(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "job"
            root.mkdir(mode=0o700)
            os.chmod(root, 0o700)
            payload = root / "worker.tar"
            payload.write_bytes(b"partial-bundle")
            os.chmod(payload, 0o600)
            sockets = root / "sockets"
            sockets.mkdir(mode=0o700)
            os.chmod(sockets, 0o700)
            socket_path = sockets / "backend-012345abcdef.sock"
            unix_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            try:
                unix_socket.bind(str(socket_path))
            finally:
                unix_socket.close()
            completed = subprocess.run(
                [sys.executable, "-c", supervisor._remote_remove_job_script(),
                 str(root), str(os.getuid()), str(os.getgid())],
                capture_output=True, timeout=3.0, check=False)
            evidence = json.loads(completed.stdout.decode("utf-8"))
            self.assertEqual(completed.returncode, 0)
            self.assertTrue(evidence["confirmed"])
            self.assertFalse(root.exists())

    @unittest.skipUnless(os.name == "posix", "requires POSIX dir_fd support")
    def test_script_refuses_unexpected_entry_without_removing_anything(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "job"
            root.mkdir(mode=0o700)
            os.chmod(root, 0o700)
            unexpected = root / "unexpected.log"
            unexpected.write_text("retain", encoding="utf-8")
            completed = subprocess.run(
                [sys.executable, "-c", supervisor._remote_remove_job_script(),
                 str(root), str(os.getuid()), str(os.getgid())],
                capture_output=True, timeout=3.0, check=False)
            evidence = json.loads(completed.stdout.decode("utf-8"))
            self.assertEqual(completed.returncode, 1)
            self.assertFalse(evidence["confirmed"])
            self.assertEqual(evidence["residuals"], ["unexpected.log"])
            self.assertTrue(unexpected.exists())
            self.assertTrue(root.exists())

    @unittest.skipUnless(os.name == "posix", "requires POSIX no-follow file opens")
    def test_script_refuses_symlinked_role_key_without_following_it(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "job"
            root.mkdir(mode=0o700)
            os.chmod(root, 0o700)
            marker = Path(temporary) / "outside-key"
            marker.write_bytes(b"keep")
            (root / "host.key").symlink_to(marker)
            completed = subprocess.run(
                [sys.executable, "-c", supervisor._remote_remove_job_script(),
                 str(root), str(os.getuid()), str(os.getgid())],
                capture_output=True, timeout=3.0, check=False)
            evidence = json.loads(completed.stdout.decode("utf-8"))
            self.assertEqual(completed.returncode, 1)
            self.assertFalse(evidence["confirmed"])
            self.assertTrue((root / "host.key").is_symlink())
            self.assertEqual(marker.read_bytes(), b"keep")

    def test_remove_helper_returns_explicit_confirmed_evidence(self):
        client = object()
        with mock.patch.object(supervisor, "_ssh_exec",
                               return_value=(0, self._evidence())) as remote:
            evidence = supervisor._remove_remote_job(
                client, job_root="/srv/steamboat/job-1", uid=1000, gid=1000,
                password=None, deadline=time.monotonic() + 3.0)
        self.assertTrue(evidence["confirmed"])
        self.assertEqual(evidence["residuals"], [])
        self.assertEqual(remote.call_args.args[0], client)
        self.assertEqual(remote.call_args.args[1][-3:],
                         ["/srv/steamboat/job-1", "1000", "1000"])

    def test_remove_helper_returns_unconfirmed_residuals_without_claiming_success(self):
        evidence_bytes = self._evidence(
            confirmed=False, removed=["worker.tar"],
            residuals=["unexpected.log"], residuals_known=True,
            reason="unexpected_entries")
        with mock.patch.object(supervisor, "_ssh_exec", return_value=(1, evidence_bytes)):
            evidence = supervisor._remove_remote_job(
                object(), job_root="/srv/steamboat/job-1", uid=1000, gid=1000,
                password=None, deadline=time.monotonic() + 3.0)
        self.assertFalse(evidence["confirmed"])
        self.assertEqual(evidence["residuals"], ["unexpected.log"])

    def test_remove_helper_rejects_noncanonical_root_before_remote_call(self):
        remote = mock.Mock()
        with mock.patch.object(supervisor, "_ssh_exec", remote):
            with self.assertRaises(supervisor.SupervisorError):
                supervisor._remove_remote_job(
                    object(), job_root="/srv/steamboat/../job-1", uid=1000,
                    gid=1000, password=None, deadline=time.monotonic() + 3.0)
        remote.assert_not_called()

    def test_remove_helper_rejects_unexpected_owner_before_remote_call(self):
        remote = mock.Mock()
        with mock.patch.object(supervisor, "_ssh_exec", remote):
            with self.assertRaises(supervisor.SupervisorError):
                supervisor._remove_remote_job(
                    object(), job_root="/srv/steamboat/job-1", uid=0,
                    gid=0, password=None, deadline=time.monotonic() + 3.0)
        remote.assert_not_called()

    def test_remove_helper_rejects_false_confirmation_with_residuals(self):
        evidence_bytes = self._evidence(residuals=["host.key"])
        with mock.patch.object(supervisor, "_ssh_exec", return_value=(0, evidence_bytes)):
            with self.assertRaises(supervisor.SupervisorError) as caught:
                supervisor._remove_remote_job(
                    object(), job_root="/srv/steamboat/job-1", uid=1000, gid=1000,
                    password=None, deadline=time.monotonic() + 3.0)
        self.assertEqual(caught.exception.code, "incomplete_confirmation")


if __name__ == "__main__":
    unittest.main()
