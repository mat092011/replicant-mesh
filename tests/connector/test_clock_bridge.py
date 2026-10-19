"""Native Linux tests for the inherited, parent-owned clock bridge."""
from __future__ import annotations

import json
import array
import os
import select
import socket
import struct
import sys
import signal
import threading
import time
import unittest
from unittest import mock

from steamboat_connector import clock_bridge as bridge_module
from steamboat_connector.clock_bridge import (
    ChildClockBridge, ClockBridgeError, MAX_GENERATIONS, OwnedClockBridge,
    active_clock_bridge_generations,
)
from steamboat_security.clock import Clock


_RESULT = struct.Struct("!cdd")
_LINUX = sys.platform.startswith("linux") and hasattr(os, "fork")


def _fork_clock_sample(owner, *, alter_metadata=None, stop_while_blocked=False,
                       stop_after_cached_wall=False, send_rights_count=0):
    """Fork before the server thread starts; transfer closed handoff metadata."""
    owner.begin_spawn()
    metadata_read, metadata_write = os.pipe()
    result_read, result_write = os.pipe()
    pid = os.fork()
    if pid == 0:
        try:
            os.close(metadata_write)
            os.close(result_read)
            owner.close_inherited_parent_copy()
            raw = bytearray()
            while True:
                part = os.read(metadata_read, 4096)
                if not part:
                    break
                raw.extend(part)
                if b"\n" in raw:
                    break
            metadata = json.loads(bytes(raw).split(b"\n", 1)[0].decode("ascii"))
            if owner.detach_inherited_child_copy() != metadata["fd"]:
                raise AssertionError("child descriptor changed across fork")
            if alter_metadata is not None:
                alter_metadata(metadata)
            try:
                if send_rights_count:
                    client = socket.socket(fileno=metadata["fd"])
                    descriptors = [os.open(os.devnull, os.O_RDONLY)
                                   for _ in range(send_rights_count)]
                    try:
                        request = bridge_module._REQUEST.pack(
                            bridge_module._REQUEST_MAGIC,
                            bytes.fromhex(metadata["server_nonce"]),
                            bytes.fromhex(metadata["generation"]), 1)
                        rights = array.array("i", descriptors).tobytes()
                        client.sendmsg([request], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, rights)])
                    finally:
                        for fd in descriptors:
                            os.close(fd)
                        client.close()
                    result = _RESULT.pack(b"E", 0.0, 0.0)
                    os.write(result_write, result)
                    os._exit(0)
                child = ChildClockBridge(metadata)
                if stop_after_cached_wall:
                    child._wall()
                    child.stop()
                    try:
                        child._monotonic()
                    except ClockBridgeError:
                        result = _RESULT.pack(b"E", 0.0, 0.0)
                    else:
                        result = _RESULT.pack(b"O", 0.0, 0.0)
                else:
                    sample = child.clock.sample()
                    result = _RESULT.pack(b"O", sample.wall, sample.uncertainty)
            except BaseException as error:
                result = _RESULT.pack(b"E", 0.0, 0.0)
            os.write(result_write, result)
            try:
                if "child" in locals():
                    child.stop()
            finally:
                os._exit(0)
        except BaseException:
            os._exit(71)

    os.close(metadata_read)
    os.close(result_write)
    metadata = owner.bind_child(pid, os.getuid())
    os.write(metadata_write, json.dumps(metadata, separators=(",", ":")).encode("ascii") + b"\n")
    os.close(metadata_write)
    owner.close_parent_child_copy()
    if stop_while_blocked:
        if not owner._request_seen.wait(1.0):
            raise AssertionError("child clock request did not reach the parent")
        started = time.monotonic()
        owner.stop()
        if time.monotonic() - started > 0.25:
            raise AssertionError("bridge stop waited for the parent Clock")
    ready, _, _ = select.select([result_read], [], [], 4.0)
    payload = os.read(result_read, _RESULT.size) if ready else b""
    os.close(result_read)
    _pid, status = os.waitpid(pid, 0)
    owner.confirm_child_reaped(pid)
    return payload, status


def _open_fd_count():
    return len(os.listdir("/proc/self/fd"))


class ClockBridgeMetadataTests(unittest.TestCase):
    def test_handoff_metadata_is_closed_and_rejects_boolean_process_ids(self):
        valid = {
            "fd": 3, "server_nonce": "01" * 16, "generation": "02" * 16,
            "child_uid": 1000, "child_pid": 22, "parent_uid": 1000,
            "parent_pid": 11, "boot_domain": "00000000-0000-0000-0000-000000000001",
        }
        self.assertEqual(bridge_module._metadata(valid), valid)
        with self.assertRaises(ClockBridgeError):
            bridge_module._metadata({**valid, "module": "arbitrary.import"})
        with self.assertRaises(ClockBridgeError):
            bridge_module._metadata({**valid, "child_pid": True})

    def test_child_stop_pending_and_uncertain_close_states_are_sticky(self):
        entered, release = threading.Event(), threading.Event()

        class SlowSocket:
            def __init__(self):
                self.close_calls = 0

            def shutdown(self, _how):
                entered.set()
                release.wait(1.0)

            def close(self):
                self.close_calls += 1

        child = object.__new__(ChildClockBridge)
        child._state_lock = threading.Lock()
        child._closed = False
        child._close_uncertain = False
        child._stop_state = "open"
        child._snapshot = object()
        child._sock = SlowSocket()
        result = []
        stopping = threading.Thread(target=lambda: result.append(child.stop()))
        stopping.start()
        self.assertTrue(entered.wait(1.0))
        self.assertFalse(child.stop())
        release.set()
        stopping.join(1.0)
        self.assertEqual(result, [True])
        self.assertTrue(child.stop())
        self.assertEqual(child._sock, None)

        class AmbiguousSocket:
            def __init__(self):
                self.close_calls = 0

            def shutdown(self, _how):
                pass

            def close(self):
                self.close_calls += 1
                raise OSError("ambiguous close")

        child._closed = False
        child._close_uncertain = False
        child._stop_state = "open"
        ambiguous = AmbiguousSocket()
        child._sock = ambiguous
        self.assertFalse(child.stop())
        self.assertFalse(child.stop())
        self.assertEqual(child._sock, None)
        self.assertEqual(ambiguous.close_calls, 1)


@unittest.skipUnless(_LINUX, "requires native Linux AF_UNIX credentials and fork")
class ClockBridgeTests(unittest.TestCase):
    def setUp(self):
        self.owners = []

    def tearDown(self):
        for owner in self.owners:
            owner.stop()
            if owner._child_pid is not None and not owner._child_reaped:
                owner.confirm_child_reaped(owner._child_pid)
            thread = owner._server_thread
            if thread is not None:
                thread.join(1.0)
            _ = owner.quiescent

    def _owner(self, clock=None):
        clock = clock or Clock.system(uncertainty_seconds=lambda: 0.01)
        owner = OwnedClockBridge(clock)
        self.owners.append(owner)
        return owner

    def test_native_system_clock_round_trip_is_bracketed_and_uncertainty_grows(self):
        owner = self._owner()
        before = time.time()
        payload, status = _fork_clock_sample(owner)
        tag, wall, uncertainty = _RESULT.unpack(payload)
        self.assertEqual(status, 0)
        self.assertEqual(tag, b"O")
        self.assertGreaterEqual(wall, before)
        self.assertGreater(uncertainty, 0.01)
        owner.stop()
        owner._server_thread.join(1.0)
        self.assertTrue(owner.quiescent)

    def test_different_parent_monotonic_domain_fails_closed(self):
        clock = Clock(wall=time.time, monotonic=lambda: time.monotonic() + 10.0,
                      uncertainty_seconds=lambda: 0.01)
        owner = self._owner(clock)
        payload, status = _fork_clock_sample(owner)
        tag, _, _ = _RESULT.unpack(payload)
        self.assertEqual(status, 0)
        self.assertEqual(tag, b"E")

    def test_foreign_nonce_request_fails_closed(self):
        owner = self._owner()
        def alter(metadata):
            metadata["server_nonce"] = ("0" if metadata["server_nonce"][0] != "0" else "1") + metadata["server_nonce"][1:]
        payload, status = _fork_clock_sample(owner, alter_metadata=alter)
        tag, _, _ = _RESULT.unpack(payload)
        self.assertEqual(status, 0)
        self.assertEqual(tag, b"E")

    def test_cached_child_callbacks_fail_after_child_stop(self):
        owner = self._owner()
        payload, status = _fork_clock_sample(owner, stop_after_cached_wall=True)
        tag, _, _ = _RESULT.unpack(payload)
        self.assertEqual(status, 0)
        self.assertEqual(tag, b"E")

    def test_unexpected_rights_are_closed_before_server_rejects_request(self):
        before = _open_fd_count()
        owner = self._owner()
        payload, status = _fork_clock_sample(owner, send_rights_count=40)
        tag, _, _ = _RESULT.unpack(payload)
        owner._server_thread.join(1.0)
        owner.stop()
        self.assertEqual(status, 0)
        self.assertEqual(tag, b"E")
        self.assertEqual(_open_fd_count(), before)

    def test_stop_during_spawn_retains_descriptor_and_late_pid_until_reaped(self):
        owner = self._owner()
        child_fd = owner.begin_spawn()
        owner.stop()
        self.assertEqual(active_clock_bridge_generations(), 1)
        self.assertEqual(os.fstat(child_fd).st_mode & 0o170000, 0o140000)
        pid = os.fork()
        if pid == 0:
            owner.close_inherited_parent_copy()
            signal.pause()
            os._exit(0)
        self.assertIsNone(owner.bind_child(pid, os.getuid()))
        self.assertEqual(owner._child_pid, pid)
        self.assertTrue(owner.close_parent_child_copy())
        self.assertFalse(owner.quiescent)
        os.kill(pid, signal.SIGTERM)
        os.waitpid(pid, 0)
        self.assertTrue(owner.confirm_child_reaped(pid))
        owner.finalize_stop()
        self.assertTrue(owner.quiescent)
        self.assertEqual(active_clock_bridge_generations(), 0)

    def test_stop_after_fork_before_bind_publishes_late_pid(self):
        owner = self._owner()
        child_fd = owner.begin_spawn()
        pid = os.fork()
        if pid == 0:
            owner.close_inherited_parent_copy()
            signal.pause()
            os._exit(0)
        owner.stop()
        self.assertEqual(os.fstat(child_fd).st_mode & 0o170000, 0o140000)
        self.assertIsNone(owner.bind_child(pid, os.getuid()))
        self.assertTrue(owner.close_parent_child_copy())
        self.assertFalse(owner.quiescent)
        os.kill(pid, signal.SIGTERM)
        os.waitpid(pid, 0)
        owner.confirm_child_reaped(pid)
        owner.finalize_stop()
        self.assertTrue(owner.quiescent)

    def test_pending_spawn_retains_slot_and_fd_number_until_no_child_is_proven(self):
        owner = self._owner()
        child_fd = owner.begin_spawn()
        owner.stop()
        replacement = os.open(os.devnull, os.O_RDONLY)
        try:
            self.assertNotEqual(replacement, child_fd)
            self.assertEqual(active_clock_bridge_generations(), 1)
        finally:
            os.close(replacement)
        self.assertTrue(owner.cancel_spawn_without_child())
        self.assertTrue(owner.quiescent)
        self.assertEqual(active_clock_bridge_generations(), 0)

    def test_stop_does_not_wait_for_global_slot_lock(self):
        owner = self._owner()
        bridge_module._SLOT_LOCK.acquire()
        try:
            started = time.monotonic()
            owner.stop()
            self.assertLess(time.monotonic() - started, 0.1)
            self.assertIn(owner, bridge_module._SLOTS)
        finally:
            bridge_module._SLOT_LOCK.release()
        owner.finalize_stop()
        self.assertNotIn(owner, bridge_module._SLOTS)

    def test_received_descriptor_close_uncertainty_is_typed(self):
        left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        source = os.open(os.devnull, os.O_RDONLY)
        original_close = os.close
        try:
            left.sendmsg([b"x"], [(socket.SOL_SOCKET, socket.SCM_RIGHTS,
                                  array.array("i", [source]).tobytes())])
            def close_then_report(fd):
                original_close(fd)
                raise OSError("ambiguous close")

            with mock.patch.object(bridge_module.os, "close", side_effect=close_then_report):
                with self.assertRaises(bridge_module._DescriptorCleanupUncertain):
                    bridge_module._recvmsg_checked(right, 1)
        finally:
            left.close()
            right.close()
            original_close(source)

    def test_received_descriptor_close_failure_sticks_owner_in_isolated_process(self):
        read_fd, write_fd = os.pipe()
        pid = os.fork()
        if pid == 0:
            os.close(read_fd)
            owner = OwnedClockBridge(Clock.system(uncertainty_seconds=lambda: 0.01))
            original_close = os.close
            server_pid = os.getpid()
            def fail_after_closing_devnull(fd):
                info = os.fstat(fd)
                target = os.stat(os.devnull)
                original_close(fd)
                if (os.getpid() == server_pid
                        and (info.st_dev, info.st_ino) == (target.st_dev, target.st_ino)):
                    raise OSError("ambiguous received-FD close")

            try:
                with mock.patch.object(bridge_module.os, "close", side_effect=fail_after_closing_devnull):
                    _fork_clock_sample(owner, send_rights_count=1)
                result = owner.close_uncertain and not owner.quiescent
                owner.stop()
                result = result and owner in bridge_module._SLOTS
            except BaseException:
                result = False
            os.write(write_fd, b"1" if result else b"0")
            os._exit(0)
        os.close(write_fd)
        result = os.read(read_fd, 1)
        os.close(read_fd)
        _pid, status = os.waitpid(pid, 0)
        self.assertEqual(status, 0)
        self.assertEqual(result, b"1")

    def test_parent_without_known_uncertainty_fails_closed(self):
        owner = self._owner(Clock())
        payload, status = _fork_clock_sample(owner)
        tag, _, _ = _RESULT.unpack(payload)
        self.assertEqual(status, 0)
        self.assertEqual(tag, b"E")

    def test_stop_does_not_wait_for_clock_lock_and_slot_retains_until_reaped_and_quiet(self):
        clock = Clock.system(uncertainty_seconds=lambda: 0.01)
        owner = self._owner(clock)
        clock._lock.acquire()
        try:
            payload, status = _fork_clock_sample(owner, stop_while_blocked=True)
            self.assertEqual(status, 0)
            self.assertTrue(owner._child_reaped)
            self.assertFalse(owner.quiescent)
            self.assertIn(owner, bridge_module._SLOTS)
        finally:
            clock._lock.release()
        owner._server_thread.join(1.0)
        self.assertTrue(owner.quiescent)
        self.assertNotIn(owner, bridge_module._SLOTS)

    def test_clock_lock_stall_times_out_using_boottime_and_latches_child(self):
        clock = Clock.system(uncertainty_seconds=lambda: 0.01)
        owner = self._owner(clock)
        clock._lock.acquire()
        started = time.monotonic()
        try:
            payload, status = _fork_clock_sample(owner)
            elapsed = time.monotonic() - started
            tag, _, _ = _RESULT.unpack(payload)
            self.assertEqual(status, 0)
            self.assertEqual(tag, b"E")
            self.assertGreaterEqual(elapsed, 1.8)
            self.assertTrue(owner._server_thread.is_alive())
            self.assertIn(owner, bridge_module._SLOTS)
        finally:
            clock._lock.release()
        owner.stop()
        owner._server_thread.join(1.0)
        self.assertTrue(owner.quiescent)

    def test_global_generation_ceiling_includes_unbound_owners(self):
        self.assertEqual(active_clock_bridge_generations(), 0)
        owners = [self._owner() for _ in range(MAX_GENERATIONS)]
        self.assertTrue(all(not owner.quiescent for owner in owners))
        self.assertEqual(active_clock_bridge_generations(), MAX_GENERATIONS)
        with self.assertRaises(ClockBridgeError):
            OwnedClockBridge(Clock.system(uncertainty_seconds=lambda: 0.01))
        for owner in owners:
            self.assertTrue(owner.stop())
        self.assertEqual(active_clock_bridge_generations(), 0)

    def test_unbound_quiescent_query_cannot_release_live_socket_owner(self):
        owner = self._owner()
        self.assertFalse(owner.quiescent)
        self.assertFalse(owner.close_complete)
        self.assertEqual(active_clock_bridge_generations(), 1)
        owner.stop()
        self.assertTrue(owner.close_complete)
        self.assertTrue(owner.quiescent)
        self.assertEqual(active_clock_bridge_generations(), 0)

    def test_stop_ack_does_not_wait_for_owner_lock_and_defers_endpoint_close(self):
        owner = self._owner()
        owner._lock.acquire()
        try:
            started = time.monotonic()
            self.assertTrue(owner.stop())
            self.assertLess(time.monotonic() - started, 0.1)
            self.assertFalse(owner.close_complete)
            self.assertFalse(owner.quiescent)
            self.assertEqual(active_clock_bridge_generations(), 1)
        finally:
            owner._lock.release()
        owner.finalize_stop()
        self.assertTrue(owner.close_complete)
        self.assertTrue(owner.quiescent)
        self.assertEqual(active_clock_bridge_generations(), 0)

    def test_thread_start_failure_retains_actual_child_identity_until_reap(self):
        owner = self._owner()
        owner.begin_spawn()
        pid = os.fork()
        if pid == 0:
            owner.close_inherited_parent_copy()
            signal.pause()
            os._exit(0)
        with mock.patch.object(threading.Thread, "start", side_effect=RuntimeError("blocked")):
            with self.assertRaises(ClockBridgeError):
                owner.bind_child(pid, os.getuid())
        self.assertEqual(owner._child_pid, pid)
        self.assertFalse(owner.quiescent)
        owner.stop()
        os.kill(pid, signal.SIGTERM)
        os.waitpid(pid, 0)
        self.assertTrue(owner.confirm_child_reaped(pid))
        self.assertTrue(owner.quiescent)

    def test_close_uncertainty_is_sticky_and_keeps_slot_reserved(self):
        read_fd, write_fd = os.pipe()
        pid = os.fork()
        if pid == 0:
            os.close(read_fd)
            owner = OwnedClockBridge(Clock.system(uncertainty_seconds=lambda: 0.01))
            original_close = socket.socket.close
            calls = []

            def close_then_report_uncertain(sock):
                calls.append(sock.fileno())
                original_close(sock)
                raise OSError("ambiguous close result")

            with mock.patch.object(socket.socket, "close", close_then_report_uncertain):
                owner.stop()
                result = (owner.close_uncertain and not owner.close_complete
                          and not owner.quiescent and active_clock_bridge_generations() == 1)
                owner.stop()
                result = result and len(calls) == 2
            os.write(write_fd, b"1" if result else b"0")
            os._exit(0)
        os.close(write_fd)
        result = os.read(read_fd, 1)
        os.close(read_fd)
        os.waitpid(pid, 0)
        self.assertEqual(result, b"1")

    def test_recvmsg_closes_delivered_rights_even_when_control_is_truncated(self):
        left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        descriptors = [os.open(os.devnull, os.O_RDONLY) for _ in range(40)]
        baseline = _open_fd_count()
        try:
            packed = array.array("i", descriptors).tobytes()
            left.sendmsg([b"x"], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, packed)])
            with self.assertRaises(ClockBridgeError):
                bridge_module._recvmsg_checked(right, 1)
            self.assertEqual(_open_fd_count(), baseline)
        finally:
            left.close()
            right.close()
            for fd in descriptors:
                os.close(fd)

    def test_offset_interval_rejects_suspend_discontinuity_and_boottime_exists(self):
        self.assertTrue(hasattr(time, "CLOCK_BOOTTIME"))
        baseline = bridge_module._offset_interval()
        shifted = baseline[0] + 1_000_000, baseline[1] + 1_000_000
        with self.assertRaises(ClockBridgeError):
            bridge_module._intersect(baseline, shifted)

    def test_reply_decoder_rejects_foreign_identity_and_duplicate_sequence(self):
        metadata = {
            "fd": 0, "server_nonce": "01" * 16, "generation": "02" * 16,
            "child_uid": os.getuid(), "child_pid": os.getpid(),
            "parent_uid": os.getuid(), "parent_pid": os.getpid(),
            "boot_domain": bridge_module._boot_domain(),
        }
        packet = bridge_module._REPLY.pack(bridge_module._REPLY_MAGIC,
            bytes.fromhex(metadata["server_nonce"]), bytes.fromhex(metadata["generation"]),
            1, 0, time.time(), time.monotonic(), 0.01, 1, 2)
        credentials = bridge_module._CREDENTIALS.pack(os.getpid(), os.getuid(), os.getgid())
        self.assertEqual(bridge_module._decode_reply(packet, credentials, 0, metadata,
            bytes.fromhex(metadata["server_nonce"]), bytes.fromhex(metadata["generation"]), 1)[2], 0.01)
        with self.assertRaises(ClockBridgeError):
            bridge_module._decode_reply(packet, credentials, 0, metadata,
                b"\xff" * 16, bytes.fromhex(metadata["generation"]), 1)
        with self.assertRaises(ClockBridgeError):
            bridge_module._decode_reply(packet, credentials, 0, metadata,
                bytes.fromhex(metadata["server_nonce"]), bytes.fromhex(metadata["generation"]), 2)


if __name__ == "__main__":
    unittest.main()
