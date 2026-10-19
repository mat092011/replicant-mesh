"""Bounded same-host clock handoff for a fixed supervised child.

The parent remains the only clock authority. This module transports one
validated sample over an inherited private Unix socket; it is not a time
service for remote hosts and does not itself make the parent's Clock trusted.
"""
from __future__ import annotations

import math
import os
import secrets
import select
import socket
import struct
import sys
import threading
import time
import uuid
from dataclasses import dataclass

from steamboat_security.clock import Clock, ClockError


MAX_GENERATIONS = 8
IO_TIMEOUT_SECONDS = 2.0
_POLL_SECONDS = 0.05
_REQUEST = struct.Struct("!4s16s16sQ")
_REPLY = struct.Struct("!4s16s16sQB7xdddqq")
_REQUEST_MAGIC = b"SBCR"
_REPLY_MAGIC = b"SBCL"
_CREDENTIALS = struct.Struct("3i")
_METADATA_FIELDS = frozenset({
    "fd", "server_nonce", "generation", "child_uid", "child_pid",
    "parent_uid", "parent_pid", "boot_domain",
})
_SLOT_LOCK = threading.Lock()
_SLOTS: set["OwnedClockBridge"] = set()


class ClockBridgeError(ClockError):
    """The trusted clock handoff failed or was fenced."""


def _require_linux():
    if (not sys.platform.startswith("linux") or not hasattr(socket, "SOCK_SEQPACKET")
            or not hasattr(socket, "SO_PASSCRED") or not hasattr(time, "CLOCK_BOOTTIME")):
        raise ClockBridgeError("clock bridge requires Linux Unix seqpacket and CLOCK_BOOTTIME")


def _boot_domain():
    try:
        value = open("/proc/sys/kernel/random/boot_id", "rt", encoding="ascii").read().strip()
        return str(uuid.UUID(value))
    except (OSError, UnicodeError, ValueError) as error:
        raise ClockBridgeError("kernel boot domain is unavailable") from error


def _offset_interval():
    """Return a bracketed interval for CLOCK_BOOTTIME minus CLOCK_MONOTONIC."""
    before = time.monotonic_ns()
    boot = time.clock_gettime_ns(time.CLOCK_BOOTTIME)
    after = time.monotonic_ns()
    if after < before:
        raise ClockBridgeError("monotonic clock rolled back")
    return boot - after, boot - before


def _intersect(left, right):
    low, high = max(left[0], right[0]), min(left[1], right[1])
    if low > high:
        raise ClockBridgeError("CLOCK_BOOTTIME offset changed within the bridge generation")
    return low, high


def _decode_reply(packet, ancillary, flags, metadata, nonce, generation, sequence):
    """Validate one reply packet and its kernel-attested peer identity."""
    if flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC) or len(packet) != _REPLY.size:
        raise ClockBridgeError("clock bridge reply length or flags are invalid")
    credentials = [data for level, kind, data in ancillary
                   if level == socket.SOL_SOCKET and kind == socket.SCM_CREDENTIALS]
    if len(credentials) != 1 or len(credentials[0]) < _CREDENTIALS.size:
        raise ClockBridgeError("clock bridge reply lacks peer credentials")
    peer_pid, peer_uid, _gid = _CREDENTIALS.unpack(credentials[0][:_CREDENTIALS.size])
    if peer_pid != metadata["parent_pid"] or peer_uid != metadata["parent_uid"]:
        raise ClockBridgeError("clock bridge reply came from a foreign process")
    magic, got_nonce, got_generation, got_sequence, status, wall, mono, uncertainty, low, high = _REPLY.unpack(packet)
    if (magic != _REPLY_MAGIC or got_nonce != nonce or got_generation != generation
            or got_sequence != sequence):
        raise ClockBridgeError("clock bridge reply identity or sequence is invalid")
    if status != 0:
        raise ClockBridgeError("parent clock provider failed")
    if (not math.isfinite(wall) or not math.isfinite(mono)
            or not math.isfinite(uncertainty) or uncertainty < 0 or uncertainty > 30
            or low > high):
        raise ClockBridgeError("parent clock sample is outside its accepted bounds")
    return wall, mono, uncertainty, (low, high)


def _exact_identity(value, *, positive):
    return type(value) is int and (value > 0 if positive else value >= 0)


def _metadata(value):
    if type(value) is not dict or set(value) != _METADATA_FIELDS:
        raise ClockBridgeError("clock handoff metadata is not the closed schema")
    if (type(value["fd"]) is not int or value["fd"] < 0
            or not _exact_identity(value["child_uid"], positive=False)
            or not _exact_identity(value["child_pid"], positive=True)
            or not _exact_identity(value["parent_uid"], positive=False)
            or not _exact_identity(value["parent_pid"], positive=True)):
        raise ClockBridgeError("clock handoff process identity is invalid")
    for name in ("server_nonce", "generation"):
        text = value[name]
        if (type(text) is not str or len(text) != 32
                or any(char not in "0123456789abcdef" for char in text)):
            raise ClockBridgeError(f"clock handoff {name} is invalid")
    if type(value["boot_domain"]) is not str:
        raise ClockBridgeError("clock handoff boot domain is invalid")
    try:
        if str(uuid.UUID(value["boot_domain"])) != value["boot_domain"]:
            raise ValueError
    except ValueError as error:
        raise ClockBridgeError("clock handoff boot domain is invalid") from error
    return dict(value)


def active_clock_bridge_generations():
    """Return the number of reserved bridge generations, including retained ones."""
    with _SLOT_LOCK:
        return len(_SLOTS)


class OwnedClockBridge:
    """Parent-side owner of one trusted Clock and one inherited child endpoint.

    Construct before process creation, pass ``child_fd`` to the fixed child,
    then call ``bind_child`` with the PID actually returned by Popen. The
    caller must close its child-end copy after Popen and retain this owner until
    both its service thread has exited and the child has been confirmed reaped.
    """

    def __init__(self, clock: Clock, *, expected_child_uid=None):
        _require_linux()
        if type(clock) is not Clock:
            raise TypeError("clock bridge requires the exact trusted Clock owner")
        if expected_child_uid is None:
            expected_child_uid = os.getuid()
        if not _exact_identity(expected_child_uid, positive=False):
            raise TypeError("expected child UID must be an exact non-negative integer")
        self._clock = clock
        self._expected_child_uid = expected_child_uid
        self._boot_domain = _boot_domain()
        self._nonce = secrets.token_bytes(16)
        self._generation = secrets.token_bytes(16)
        self._parent_pid, self._parent_uid = os.getpid(), os.getuid()
        self._child_pid = self._child_uid = None
        self._child_reaped = False
        self._stopping = threading.Event()
        self._request_seen = threading.Event()
        self._lock = threading.Lock()
        self._server_thread = None
        self._parent_sock, self._child_sock = socket.socketpair(
            socket.AF_UNIX, socket.SOCK_SEQPACKET)
        try:
            self._parent_sock.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
            self._child_sock.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
            self._parent_sock.setblocking(False)
            self._child_sock.setblocking(False)
        except BaseException:
            self._child_sock.close()
            self._parent_sock.close()
            self._child_sock = self._parent_sock = None
            raise
        self._slot_reserved = False
        with _SLOT_LOCK:
            if len(_SLOTS) >= MAX_GENERATIONS:
                self._close_socket_attribute("_child_sock")
                self._close_socket_attribute("_parent_sock")
                raise ClockBridgeError("global clock bridge generation ceiling is full")
            _SLOTS.add(self)
            self._slot_reserved = True

    @property
    def child_fd(self):
        sock = self._child_sock
        if sock is None or self._stopping.is_set():
            raise ClockBridgeError("inherited child endpoint is no longer available")
        return sock.fileno()

    def bind_child(self, pid: int, uid: int):
        if not _exact_identity(pid, positive=True) or not _exact_identity(uid, positive=False):
            raise ClockBridgeError("child process identity is invalid")
        if uid != self._expected_child_uid:
            raise ClockBridgeError("clock bridge child UID differs from the configured UID")
        with self._lock:
            if self._child_pid is not None or self._stopping.is_set():
                raise ClockBridgeError("clock bridge child was already bound or stopped")
            self._child_pid, self._child_uid = pid, uid
            thread = threading.Thread(target=self._serve, name="owned-clock-bridge", daemon=True)
            self._server_thread = thread
            try:
                thread.start()
            except BaseException:
                self._server_thread = None
                self._child_pid = self._child_uid = None
                raise
        return self.child_metadata

    @property
    def child_metadata(self):
        if self._child_pid is None:
            raise ClockBridgeError("clock bridge has no bound child")
        return {
            "fd": self.child_fd,
            "server_nonce": self._nonce.hex(),
            "generation": self._generation.hex(),
            "child_uid": self._child_uid,
            "child_pid": self._child_pid,
            "parent_uid": self._parent_uid,
            "parent_pid": self._parent_pid,
            "boot_domain": self._boot_domain,
        }

    def close_parent_child_copy(self):
        """Consume and close the parent's inherited-end copy exactly once."""
        # The child inherited a duplicate descriptor. shutdown() would fence
        # the shared socket endpoint in the child as well as in this process.
        with self._lock:
            sock = self._child_sock
            self._child_sock = None
        if sock is None:
            return True
        try:
            sock.close()
            return True
        except OSError:
            return False

    def close_inherited_parent_copy(self):
        """In a forked child, close its accidental copy of the parent endpoint."""
        # The descriptor is a duplicate of the parent's endpoint. shutdown()
        # would affect the shared socket object in both processes.
        with self._lock:
            sock = self._parent_sock
            self._parent_sock = None
        if sock is None:
            return True
        try:
            sock.close()
            return True
        except OSError:
            return False

    def detach_inherited_child_copy(self):
        """Transfer the child FD out of an inherited owner after fork, without close."""
        with self._lock:
            sock = self._child_sock
            self._child_sock = None
        if sock is None:
            raise ClockBridgeError("inherited child endpoint is unavailable")
        return sock.detach()

    def _close_socket_attribute(self, name):
        with self._lock:
            sock = getattr(self, name)
            if sock is None:
                return True
            setattr(self, name, None)
        error = None
        try:
            sock.shutdown(socket.SHUT_RDWR)
        except OSError as caught:
            error = caught
        try:
            sock.close()
        except OSError as caught:
            error = error or caught
        return error is None

    def _serve(self):
        previous_offset = None
        try:
            previous_offset = _offset_interval()
            expected_sequence = 1
            while not self._stopping.is_set():
                sock = self._parent_sock
                if sock is None:
                    return
                poller = select.poll()
                poller.register(sock, select.POLLIN | select.POLLHUP | select.POLLERR)
                events = poller.poll(int(_POLL_SECONDS * 1000))
                if self._stopping.is_set():
                    return
                if not events:
                    current = _offset_interval()
                    previous_offset = _intersect(previous_offset, current)
                    continue
                packet, ancillary, flags, _address = sock.recvmsg(
                    _REQUEST.size, socket.CMSG_SPACE(_CREDENTIALS.size))
                if flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC):
                    return
                credentials = [data for level, kind, data in ancillary
                               if level == socket.SOL_SOCKET and kind == socket.SCM_CREDENTIALS]
                if len(credentials) != 1 or len(credentials[0]) < _CREDENTIALS.size:
                    return
                peer_pid, peer_uid, _peer_gid = _CREDENTIALS.unpack(credentials[0][:_CREDENTIALS.size])
                if (peer_pid != self._child_pid or peer_uid != self._child_uid
                        or len(packet) != _REQUEST.size):
                    return
                magic, nonce, generation, sequence = _REQUEST.unpack(packet)
                if (magic != _REQUEST_MAGIC or nonce != self._nonce
                        or generation != self._generation or sequence != expected_sequence
                        or sequence > (1 << 64) - 1):
                    return
                self._request_seen.set()
                before = time.monotonic_ns()
                offset_before = _offset_interval()
                try:
                    sample = self._clock.sample()
                    after = time.monotonic_ns()
                    offset_after = _offset_interval()
                    if not (before / 1e9 <= sample.monotonic <= after / 1e9):
                        return
                    parent_offset = _intersect(previous_offset, _intersect(offset_before, offset_after))
                    previous_offset = parent_offset
                    if (not math.isfinite(sample.wall) or not math.isfinite(sample.uncertainty)
                            or sample.uncertainty < 0 or sample.uncertainty > 30):
                        return
                    reply = _REPLY.pack(_REPLY_MAGIC, nonce, generation, sequence, 0,
                        sample.wall, sample.monotonic, sample.uncertainty,
                        parent_offset[0], parent_offset[1])
                except BaseException:
                    reply = _REPLY.pack(_REPLY_MAGIC, nonce, generation, sequence, 1,
                        0.0, 0.0, 0.0, 0, 0)
                if self._stopping.is_set():
                    return
                if sock.send(reply) != len(reply):
                    return
                expected_sequence += 1
        except (OSError, ClockBridgeError, ValueError, OverflowError):
            return
        finally:
            self._close_socket_attribute("_parent_sock")
            self._maybe_release_slot()

    def stop(self):
        """Fence the bridge without joining or waiting for the parent Clock."""
        self._stopping.set()
        child_ok = self._close_socket_attribute("_child_sock")
        parent_ok = self._close_socket_attribute("_parent_sock")
        self._maybe_release_slot()
        return child_ok and parent_ok

    def confirm_child_reaped(self, pid):
        if self._child_pid is None or pid != self._child_pid:
            return False
        self._child_reaped = True
        self._maybe_release_slot()
        return True

    @property
    def quiescent(self):
        thread = self._server_thread
        result = ((thread is None or not thread.is_alive())
                  and (self._child_pid is None or self._child_reaped))
        if result:
            self._maybe_release_slot()
        return result

    def _maybe_release_slot(self):
        thread = self._server_thread
        thread_done = thread is None or not thread.is_alive()
        child_done = self._child_pid is None or self._child_reaped
        if thread_done and child_done and self._slot_reserved:
            with _SLOT_LOCK:
                if self._slot_reserved:
                    _SLOTS.discard(self)
                    self._slot_reserved = False


@dataclass(frozen=True)
class _ValidatedReply:
    wall: float
    monotonic: float
    uncertainty: float
    offset: tuple[int, int]


class ChildClockBridge:
    """Child-side adapter exposing an exact Clock backed by one parent Clock."""

    def __init__(self, metadata):
        _require_linux()
        info = _metadata(metadata)
        if (info["child_pid"] != os.getpid() or info["child_uid"] != os.getuid()
                or info["parent_pid"] != os.getppid()
                or info["boot_domain"] != _boot_domain()):
            raise ClockBridgeError("clock handoff process or kernel boot domain changed")
        self._metadata = info
        self._nonce, self._generation = bytes.fromhex(info["server_nonce"]), bytes.fromhex(info["generation"])
        try:
            self._sock = socket.socket(fileno=info["fd"])
            self._sock.setblocking(False)
            if (self._sock.family != socket.AF_UNIX
                    or self._sock.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) != socket.SOCK_SEQPACKET
                    or self._sock.getsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED) != 1):
                raise OSError("inherited descriptor is not the configured credentialed seqpacket")
        except OSError as error:
            sock = getattr(self, "_sock", None)
            if sock is not None:
                sock.close()
            raise ClockBridgeError("inherited clock endpoint is unavailable") from error
        self._sequence = 1
        self._faulted = False
        self._closed = False
        self._generation_token = object()
        try:
            self._offset = _offset_interval()
        except BaseException:
            sock, self._sock = self._sock, None
            sock.close()
            raise
        self._snapshot: _ValidatedReply | None = None
        self._snapshot_fields = set()
        self._clock = Clock(wall=self._wall, monotonic=self._monotonic,
                            uncertainty_seconds=self._uncertainty,
                            resume_token=self._resume_token)

    def _wait(self, event, deadline):
        while True:
            remaining = deadline - time.clock_gettime(time.CLOCK_BOOTTIME)
            if remaining <= 0:
                raise ClockBridgeError("clock bridge I/O deadline elapsed")
            poller = select.poll()
            poller.register(self._sock, event | select.POLLHUP | select.POLLERR)
            result = poller.poll(max(1, min(50, int(remaining * 1000))))
            if result:
                if result[0][1] & (select.POLLHUP | select.POLLERR):
                    raise ClockBridgeError("clock bridge peer closed")
                if result[0][1] & event:
                    return

    def _exchange(self):
        if self._faulted or self._closed:
            raise ClockBridgeError("clock bridge failure is latched")
        before_offset = _offset_interval()
        self._offset = _intersect(self._offset, before_offset)
        send_mono_ns = time.monotonic_ns()
        send_boot = time.clock_gettime(time.CLOCK_BOOTTIME)
        deadline = send_boot + IO_TIMEOUT_SECONDS
        packet = _REQUEST.pack(_REQUEST_MAGIC, self._nonce, self._generation, self._sequence)
        try:
            while True:
                try:
                    if self._sock.send(packet) != len(packet):
                        raise ClockBridgeError("clock bridge request was incomplete")
                    break
                except BlockingIOError:
                    self._wait(select.POLLOUT, deadline)
            while True:
                self._wait(select.POLLIN, deadline)
                try:
                    reply, ancillary, flags, _address = self._sock.recvmsg(
                        _REPLY.size, socket.CMSG_SPACE(_CREDENTIALS.size))
                    break
                except BlockingIOError:
                    continue
            receive_mono_ns = time.monotonic_ns()
            receive_boot = time.clock_gettime(time.CLOCK_BOOTTIME)
            after_offset = _offset_interval()
            self._offset = _intersect(self._offset, _intersect(before_offset, after_offset))
            if receive_boot > deadline:
                raise ClockBridgeError("clock bridge I/O deadline elapsed")
            wall, parent_mono, uncertainty, remote_offset = _decode_reply(
                reply, ancillary, flags, self._metadata, self._nonce,
                self._generation, self._sequence)
            send_mono, receive_mono = send_mono_ns / 1e9, receive_mono_ns / 1e9
            if not send_mono <= parent_mono <= receive_mono:
                raise ClockBridgeError("parent clock monotonic sample is outside the IPC bracket")
            self._offset = _intersect(self._offset, remote_offset)
            rtt = (receive_mono_ns - send_mono_ns) / 1e9
            adjusted_wall = wall + (receive_mono - parent_mono)
            adjusted_uncertainty = uncertainty + rtt
            if (not math.isfinite(adjusted_wall) or not math.isfinite(adjusted_uncertainty)
                    or adjusted_uncertainty > 30):
                raise ClockBridgeError("clock bridge uncertainty exceeds 30 seconds")
            self._sequence += 1
            return _ValidatedReply(adjusted_wall, receive_mono, adjusted_uncertainty,
                                   self._offset)
        except BaseException:
            self._faulted = True
            raise

    def _wall(self):
        if self._snapshot is None:
            self._snapshot = self._exchange()
            self._snapshot_fields.clear()
        return self._snapshot.wall

    def _field(self, name):
        if self._snapshot is None:
            raise ClockBridgeError("clock callback order changed")
        value = getattr(self._snapshot, name)
        self._snapshot_fields.add(name)
        if self._snapshot_fields == {"monotonic", "uncertainty", "resume_token"}:
            self._snapshot = None
            self._snapshot_fields.clear()
        return value

    def _monotonic(self):
        return self._field("monotonic")

    def _uncertainty(self):
        return self._field("uncertainty")

    def _resume_token(self):
        if self._snapshot is None:
            raise ClockBridgeError("clock callback order changed")
        self._snapshot_fields.add("resume_token")
        token = self._generation_token
        if self._snapshot_fields == {"monotonic", "uncertainty", "resume_token"}:
            self._snapshot = None
            self._snapshot_fields.clear()
        return token

    @property
    def clock(self):
        return self._clock

    def stop(self):
        self._closed = True
        sock, self._sock = self._sock, None
        if sock is None:
            return True
        error = None
        try:
            sock.shutdown(socket.SHUT_RDWR)
        except OSError as caught:
            error = caught
        try:
            sock.close()
        except OSError as caught:
            error = error or caught
        return error is None
