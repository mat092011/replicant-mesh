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
_MAX_RECEIVED_RIGHTS = 16
_METADATA_FIELDS = frozenset({
    "fd", "server_nonce", "generation", "child_uid", "child_pid",
    "parent_uid", "parent_pid", "boot_domain",
})
_SLOT_LOCK = threading.Lock()
_SLOTS: set["OwnedClockBridge"] = set()


class ClockBridgeError(ClockError):
    """The trusted clock handoff failed or was fenced."""


class _DescriptorCleanupUncertain(ClockBridgeError):
    """A consumed descriptor could not be confirmed closed."""


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


def _decode_reply(packet, credential_data, flags, metadata, nonce, generation, sequence):
    """Validate one reply packet and its kernel-attested peer identity."""
    if flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC) or len(packet) != _REPLY.size:
        raise ClockBridgeError("clock bridge reply length or flags are invalid")
    try:
        peer_pid, peer_uid, _gid = _decode_peer_credentials(credential_data)
    except ClockBridgeError as error:
        raise ClockBridgeError("clock bridge reply lacks valid peer credentials") from error
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


def _decode_peer_credentials(data):
    if type(data) is not bytes or len(data) != _CREDENTIALS.size:
        raise ClockBridgeError("clock bridge peer credentials are invalid")
    return _CREDENTIALS.unpack(data)


def _recvmsg_checked(sock, payload_bytes):
    """Receive one frame, close all delivered rights, and accept credentials only."""
    ancillary_bytes = (socket.CMSG_SPACE(_CREDENTIALS.size)
                       + socket.CMSG_SPACE(_MAX_RECEIVED_RIGHTS * struct.calcsize("i")))
    packet, ancillary, flags, address = sock.recvmsg(
        payload_bytes, ancillary_bytes, getattr(socket, "MSG_CMSG_CLOEXEC", 0))
    credentials = []
    rights = set()
    invalid_control = False
    for level, kind, data in ancillary:
        if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
            usable = len(data) - (len(data) % struct.calcsize("i"))
            rights.update(item[0] for item in struct.iter_unpack("@i", data[:usable]))
            invalid_control = invalid_control or usable != len(data)
        elif level == socket.SOL_SOCKET and kind == socket.SCM_CREDENTIALS:
            credentials.append(data)
        else:
            invalid_control = True
    close_error = None
    for fd in rights:
        try:
            os.close(fd)
        except OSError as error:
            close_error = close_error or error
    if close_error is not None:
        raise _DescriptorCleanupUncertain("received descriptor cleanup is uncertain") from close_error
    if (flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC) or invalid_control or rights
            or len(credentials) != 1):
        raise ClockBridgeError("clock bridge ancillary data or frame is invalid")
    _decode_peer_credentials(credentials[0])
    return packet, credentials[0], flags, address


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

    Construct before process creation, call ``begin_spawn`` to acquire a
    handoff lease, pass its descriptor to the fixed child, then call
    ``bind_child`` with the PID actually returned by Popen. The
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
        self._slot_reserved = False
        self._endpoint_state = {"parent": "open", "child": "open"}
        self._terminal = False
        self._close_uncertain = False
        self._spawn_pending = False
        self._spawn_issued = False
        self._handoff_pending = False
        self._child_may_exist = False
        # Reserve before opening descriptors, and never perform socket I/O
        # while holding the process-wide generation lock.
        with _SLOT_LOCK:
            if len(_SLOTS) >= MAX_GENERATIONS:
                raise ClockBridgeError("global clock bridge generation ceiling is full")
            _SLOTS.add(self)
            self._slot_reserved = True
        try:
            self._parent_sock, self._child_sock = socket.socketpair(
                socket.AF_UNIX, socket.SOCK_SEQPACKET)
        except BaseException:
            with _SLOT_LOCK:
                _SLOTS.discard(self)
                self._slot_reserved = False
            raise
        try:
            self._parent_sock.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
            self._child_sock.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
            self._parent_sock.setblocking(False)
            self._child_sock.setblocking(False)
        except BaseException:
            child_sock, parent_sock = self._child_sock, self._parent_sock
            self._child_sock = self._parent_sock = None
            for endpoint, sock in (("child", child_sock), ("parent", parent_sock)):
                try:
                    sock.close()
                except OSError:
                    self._endpoint_state[endpoint] = "uncertain"
                    self._close_uncertain = True
                else:
                    self._endpoint_state[endpoint] = "closed"
            self._terminal = True
            if not self._close_uncertain:
                with _SLOT_LOCK:
                    _SLOTS.discard(self)
                    self._slot_reserved = False
            raise

    @property
    def child_fd(self):
        sock = self._child_sock
        if (sock is None or self._endpoint_state["child"] != "open"
                or not self._handoff_pending or self._stopping.is_set()):
            raise ClockBridgeError("inherited child endpoint is no longer available")
        return sock.fileno()

    def begin_spawn(self):
        """Acquire a generation lease before calling Popen/fork.

        Keep the lease until bind_child publishes the returned PID, or
        cancel_spawn_without_child records a trusted definite no-child result.
        If spawn outcome is unknown, retain this owner indefinitely.
        """
        with self._lock:
            if (self._terminal or self._stopping.is_set() or self._spawn_pending
                    or self._spawn_issued):
                raise ClockBridgeError("clock bridge spawn lease is unavailable")
            self._spawn_issued = True
            self._spawn_pending = True
            self._handoff_pending = True
            self._child_may_exist = True
            return self.child_fd

    def cancel_spawn_without_child(self):
        """Release a pending spawn lease only when the caller knows no child exists."""
        with self._lock:
            if not self._spawn_pending or self._child_pid is not None:
                return False
            self._spawn_pending = False
            self._handoff_pending = False
            self._child_may_exist = False
            self._child_reaped = True
        self.stop()
        return True

    def bind_child(self, pid: int, uid: int):
        if not _exact_identity(pid, positive=True) or not _exact_identity(uid, positive=False):
            raise ClockBridgeError("child process identity is invalid")
        if uid != self._expected_child_uid:
            raise ClockBridgeError("clock bridge child UID differs from the configured UID")
        start_error = None
        with self._lock:
            if self._child_pid is not None or not self._spawn_pending:
                raise ClockBridgeError("clock bridge child was not pending or was already bound")
            self._child_pid, self._child_uid = pid, uid
            self._spawn_pending = False
            if self._stopping.is_set():
                # The Popen result arrived after stop. Record the actual PID;
                # do not start a service thread for a fenced child.
                self._terminal = True
                return None
            thread = threading.Thread(target=self._serve, name="owned-clock-bridge", daemon=True)
            self._server_thread = thread
            try:
                thread.start()
            except BaseException as error:
                # Popen already created this child. Keep its identity and the
                # generation slot until the caller proves that child reaped.
                self._terminal = True
                self._stopping.set()
                start_error = error
        if start_error is not None:
            self._close_socket_attribute("_child_sock", nonblocking=True)
            self._close_socket_attribute("_parent_sock", nonblocking=True)
            with self._lock:
                self._handoff_pending = False
            raise ClockBridgeError("clock bridge server thread could not start") from start_error
        return self._bound_child_metadata()

    def _bound_child_metadata(self):
        sock = self._child_sock
        if sock is None or not self._handoff_pending or self._child_pid is None:
            raise ClockBridgeError("inherited child endpoint is no longer available")
        return {
            "fd": sock.fileno(),
            "server_nonce": self._nonce.hex(),
            "generation": self._generation.hex(),
            "child_uid": self._child_uid,
            "child_pid": self._child_pid,
            "parent_uid": self._parent_uid,
            "parent_pid": self._parent_pid,
            "boot_domain": self._boot_domain,
        }

    @property
    def child_metadata(self):
        return self._bound_child_metadata()

    def close_parent_child_copy(self):
        """Consume and close the parent's inherited-end copy exactly once."""
        # The child inherited a duplicate descriptor. shutdown() would fence
        # the shared socket endpoint in the child as well as in this process.
        result = self._close_socket_attribute("_child_sock", shutdown=False)
        if result is True:
            with self._lock:
                self._handoff_pending = False
            self._maybe_release_slot()
        return result

    def close_inherited_parent_copy(self):
        """In a forked child, close its accidental copy of the parent endpoint."""
        # The descriptor is a duplicate of the parent's endpoint. shutdown()
        # would affect the shared socket object in both processes.
        return self._close_socket_attribute("_parent_sock", shutdown=False)

    def detach_inherited_child_copy(self):
        """Transfer the child FD out of an inherited owner after fork, without close."""
        with self._lock:
            sock = self._child_sock
            self._child_sock = None
        if sock is None:
            raise ClockBridgeError("inherited child endpoint is unavailable")
        return sock.detach()

    def _close_socket_attribute(self, name, *, shutdown=True, nonblocking=False):
        acquired = self._lock.acquire(blocking=not nonblocking)
        if not acquired:
            return None
        endpoint = "parent" if name == "_parent_sock" else "child"
        try:
            sock = getattr(self, name)
            state = self._endpoint_state[endpoint]
            if sock is None:
                return state == "closed"
            if state != "open":
                return None if state == "closing" else False
            setattr(self, name, None)
            self._endpoint_state[endpoint] = "closing"
            error = None
            if shutdown:
                try:
                    sock.shutdown(socket.SHUT_RDWR)
                except OSError as caught:
                    error = caught
            try:
                sock.close()
            except OSError as caught:
                error = error or caught
            self._endpoint_state[endpoint] = "closed" if error is None else "uncertain"
            if error is not None:
                self._close_uncertain = True
            return error is None
        finally:
            self._lock.release()

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
                packet, credentials, _flags, _address = _recvmsg_checked(sock, _REQUEST.size)
                peer_pid, peer_uid, _peer_gid = _decode_peer_credentials(credentials)
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
        except _DescriptorCleanupUncertain:
            self._close_uncertain = True
            return
        except (OSError, ClockBridgeError, ValueError, OverflowError):
            return
        finally:
            self._stopping.set()
            self._terminal = True
            self._close_socket_attribute("_parent_sock")
            self._maybe_release_slot()

    def stop(self):
        """Request stop without waiting for the owner lock or parent Clock."""
        self._stopping.set()
        self._terminal = True
        # During Popen/fork, keep the borrowed child descriptor owned until
        # the caller publishes the PID and closes its copy, or proves no child.
        if not self._handoff_pending:
            self._close_socket_attribute("_child_sock", nonblocking=True)
        self._close_socket_attribute("_parent_sock", nonblocking=True)
        self._maybe_release_slot()
        # True acknowledges the stop request only. Callers use close_complete
        # and quiescent as the physical cleanup evidence.
        return True

    def finalize_stop(self):
        """Retry deferred endpoint cleanup without retrying any closed FD."""
        return self.stop()

    def confirm_child_reaped(self, pid):
        if not _exact_identity(pid, positive=True):
            return False
        with self._lock:
            if self._child_pid is None or pid != self._child_pid:
                return False
            self._child_reaped = True
            self._child_may_exist = False
        self._maybe_release_slot()
        return True

    def try_confirm_child_reaped(self, pid):
        """Nonblocking reap confirmation for bounded lifecycle callers.

        A busy bridge owner lock means the caller has not confirmed this
        transition; it must retain its process owner and retry later.
        """
        if not _exact_identity(pid, positive=True):
            return False
        if not self._lock.acquire(blocking=False):
            return False
        try:
            if self._child_pid is None or pid != self._child_pid:
                return False
            self._child_reaped = True
            self._child_may_exist = False
        finally:
            self._lock.release()
        self._maybe_release_slot()
        return True

    @property
    def quiescent(self):
        if not self._lock.acquire(blocking=False):
            return False
        try:
            thread = self._server_thread
            result = (self._terminal and not self._close_uncertain
                      and all(state == "closed" for state in self._endpoint_state.values())
                      and (thread is None or not thread.is_alive())
                      and (self._child_pid is None or self._child_reaped)
                      and not self._spawn_pending and not self._handoff_pending
                      and not self._child_may_exist)
        finally:
            self._lock.release()
        if result:
            self._maybe_release_slot()
        return result

    @property
    def close_complete(self):
        if not self._lock.acquire(blocking=False):
            return False
        try:
            return (not self._close_uncertain
                    and all(state == "closed" for state in self._endpoint_state.values()))
        finally:
            self._lock.release()

    @property
    def close_uncertain(self):
        return self._close_uncertain

    def _maybe_release_slot(self):
        if not self._lock.acquire(blocking=False):
            return False
        try:
            thread = self._server_thread
            ready = (self._terminal and not self._close_uncertain
                     and all(state == "closed" for state in self._endpoint_state.values())
                     and (thread is None or not thread.is_alive())
                     and (self._child_pid is None or self._child_reaped)
                     and not self._spawn_pending and not self._handoff_pending
                     and not self._child_may_exist)
        finally:
            self._lock.release()
        if ready and self._slot_reserved and _SLOT_LOCK.acquire(blocking=False):
            try:
                if self._slot_reserved:
                    _SLOTS.discard(self)
                    self._slot_reserved = False
            finally:
                _SLOT_LOCK.release()
        return ready


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
        self._close_uncertain = False
        self._stop_state = "open"
        self._state_lock = threading.Lock()
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

    def _wait(self, sock, event, deadline):
        while True:
            remaining = deadline - time.clock_gettime(time.CLOCK_BOOTTIME)
            if remaining <= 0:
                raise ClockBridgeError("clock bridge I/O deadline elapsed")
            poller = select.poll()
            poller.register(sock, event | select.POLLHUP | select.POLLERR)
            result = poller.poll(max(1, min(50, int(remaining * 1000))))
            if result:
                if result[0][1] & (select.POLLHUP | select.POLLERR):
                    raise ClockBridgeError("clock bridge peer closed")
                if result[0][1] & event:
                    return

    def _exchange(self):
        with self._state_lock:
            if self._faulted or self._closed or self._sock is None:
                raise ClockBridgeError("clock bridge failure is latched")
            sock = self._sock
        before_offset = _offset_interval()
        self._offset = _intersect(self._offset, before_offset)
        send_mono_ns = time.monotonic_ns()
        send_boot = time.clock_gettime(time.CLOCK_BOOTTIME)
        deadline = send_boot + IO_TIMEOUT_SECONDS
        packet = _REQUEST.pack(_REQUEST_MAGIC, self._nonce, self._generation, self._sequence)
        try:
            while True:
                try:
                    if sock.send(packet) != len(packet):
                        raise ClockBridgeError("clock bridge request was incomplete")
                    break
                except BlockingIOError:
                    self._wait(sock, select.POLLOUT, deadline)
            while True:
                self._wait(sock, select.POLLIN, deadline)
                try:
                    reply, credentials, flags, _address = _recvmsg_checked(sock, _REPLY.size)
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
                reply, credentials, flags,
                self._metadata, self._nonce,
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
            with self._state_lock:
                if self._closed:
                    raise ClockBridgeError("clock bridge was stopped during sample")
                self._sequence += 1
                return _ValidatedReply(adjusted_wall, receive_mono, adjusted_uncertainty,
                                       self._offset)
        except BaseException as error:
            with self._state_lock:
                self._faulted = True
                if isinstance(error, _DescriptorCleanupUncertain):
                    self._close_uncertain = True
            raise

    def _wall(self):
        with self._state_lock:
            if self._closed:
                raise ClockBridgeError("clock bridge is stopped")
            snapshot = self._snapshot
        if snapshot is None:
            snapshot = self._exchange()
            with self._state_lock:
                if self._closed:
                    raise ClockBridgeError("clock bridge was stopped during sample")
                if self._snapshot is None:
                    self._snapshot = snapshot
                    self._snapshot_fields.clear()
                snapshot = self._snapshot
        return snapshot.wall

    def _field(self, name):
        with self._state_lock:
            if self._closed:
                raise ClockBridgeError("clock bridge is stopped")
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
        with self._state_lock:
            if self._closed:
                raise ClockBridgeError("clock bridge is stopped")
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
        with self._state_lock:
            if self._stop_state != "open":
                return self._stop_state == "closed"
            self._stop_state = "closing"
            self._closed = True
            self._snapshot = None
            sock, self._sock = self._sock, None
            prior_uncertainty = self._close_uncertain
        if sock is None:
            with self._state_lock:
                self._stop_state = "uncertain" if prior_uncertainty else "closed"
            return not prior_uncertainty
        error = None
        try:
            sock.shutdown(socket.SHUT_RDWR)
        except OSError as caught:
            error = caught
        try:
            sock.close()
        except OSError as caught:
            error = error or caught
        if error is not None or prior_uncertainty:
            with self._state_lock:
                self._close_uncertain = True
                self._stop_state = "uncertain"
        else:
            with self._state_lock:
                self._stop_state = "closed"
        return error is None and not prior_uncertainty
