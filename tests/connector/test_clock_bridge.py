"""Native Linux tests for the inherited, parent-owned clock bridge."""
from __future__ import annotations

import json
import os
import select
import socket
import struct
import sys
import time
import unittest

from steamboat_connector import clock_bridge as bridge_module
from steamboat_connector.clock_bridge import (
    ChildClockBridge, ClockBridgeError, MAX_GENERATIONS, OwnedClockBridge,
    active_clock_bridge_generations,
)
from steamboat_security.clock import Clock


_RESULT = struct.Struct("!cdd")
_LINUX = sys.platform.startswith("linux") and hasattr(os, "fork")


def _fork_clock_sample(owner, *, alter_metadata=None, stop_while_blocked=False):
    """Fork before the server thread starts; transfer closed handoff metadata."""
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
                child = ChildClockBridge(metadata)
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
        with self.assertRaises(ClockBridgeError):
            OwnedClockBridge(Clock.system(uncertainty_seconds=lambda: 0.01))
        for owner in owners:
            self.assertTrue(owner.stop())
        self.assertEqual(active_clock_bridge_generations(), 0)

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
        credentials = [(socket.SOL_SOCKET, socket.SCM_CREDENTIALS,
                        bridge_module._CREDENTIALS.pack(os.getpid(), os.getuid(), os.getgid()))]
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
