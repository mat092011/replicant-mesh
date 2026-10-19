"""Bounded nonblocking TCP pump for fixed owner-minted C2 TLS engines.

This component owns one already-connected socket and one fixed TLS owner. It
does not frame plaintext, authenticate application messages, or claim route
readiness. Its accounting boundary is TCP payload handed to/from the socket.
"""

from __future__ import annotations

import errno
import socket
import threading

from steamboat_connector.traffic_budget import (
    TrafficBudget, TrafficBudgetDenied, TrafficBudgetError,
)
from steamboat_security.channel_tls import is_owned_worker_tls
from steamboat_security.gateway_tls import is_owned_gateway_worker_tls
from steamboat_security.gateway_coordinator_tls import (
    is_owned_gateway_coordinator_tls,
)
from steamboat_security.gateway_egress import (
    GatewayCoordinatorEgress, is_owned_gateway_coordinator_egress,
)


MAX_SOCKET_CHUNK = 16 * 1024
MAX_PENDING_CIPHERTEXT = 16 * 1024
MAX_PENDING_PLAINTEXT = 16 * 1024
MAX_IO_CALLS_PER_PUMP = 4


class ChannelSocketError(RuntimeError):
    """The owned socket/TLS generation was retired or is unavailable."""


class ChannelBackpressure(ChannelSocketError):
    """Traffic quota/rate denied this bounded pump operation."""


def _tls_engine(owner):
    if is_owned_worker_tls(owner) or is_owned_gateway_worker_tls(owner):
        return owner
    if is_owned_gateway_coordinator_tls(owner):
        return owner
    if is_owned_gateway_coordinator_egress(owner):
        return owner
    raise TypeError("TLS owner must be an internally minted fixed-profile owner")


class ChannelSocket:
    """Drive a connected nonblocking TCP socket and genuine owned TLS engine.

    ``test_socket=True`` is an explicit test-only escape hatch for a controlled
    wrapper around a real socket. Production accepts only the exact socket type.
    TrafficBudget role binding/allocation must already exist; construction never
    creates or refreshes an allowance.
    """

    def __init__(self, connected_socket, tls_owner, traffic_budget, *, role,
                 boot_id, test_socket=False):
        if (type(traffic_budget) is not TrafficBudget
                or type(role) is not str or type(boot_id) is not str):
            raise TypeError("socket driver requires a bound TrafficBudget role")
        if type(connected_socket) is not socket.socket and not (
                test_socket is True and callable(getattr(connected_socket, "send", None))
                and callable(getattr(connected_socket, "recv", None))
                and callable(getattr(connected_socket, "close", None))):
            raise TypeError("socket must be an exact connected socket")
        if type(test_socket) is not bool:
            raise TypeError("test_socket flag must be boolean")
        self._socket = connected_socket
        self._tls = _tls_engine(tls_owner)
        self._budget = traffic_budget
        self._role = role
        self._boot_id = boot_id
        self._lock = threading.RLock()
        self._pending_ciphertext = bytearray()
        self._pending_ciphertext_kind = "data"
        self._pending_plaintext = None
        self._pending_plaintext_kind = None
        self._received_plaintext = None
        self._incoming_cleanup_mode = False
        self._closed = False
        self._failure = None
        self._socket_sent = 0
        self._socket_received = 0
        self._backpressure = None
        self._socket.setblocking(False)

    @property
    def failure(self):
        return self._failure

    @property
    def socket_byte_counts(self):
        return self._socket_sent, self._socket_received

    @property
    def pending_ciphertext_bytes(self):
        return len(self._pending_ciphertext)

    @property
    def pending_plaintext_bytes(self):
        return len(self._pending_plaintext or b"")

    @property
    def incoming_cleanup_mode(self):
        return self._incoming_cleanup_mode

    @property
    def ready_for_plaintext(self):
        with self._lock:
            self._require_live()
            try:
                return bool(self._tls.handshake_complete)
            except Exception as error:
                self._retire("TLS handshake/liveness check failed", error)

    def set_incoming_cleanup_mode(self, enabled):
        if type(enabled) is not bool:
            raise TypeError("cleanup mode must be boolean")
        with self._lock:
            self._require_live()
            if self._incoming_cleanup_mode and not enabled:
                raise ChannelSocketError("incoming cleanup mode is irreversible")
            if enabled and (self._pending_ciphertext or self._pending_plaintext is not None):
                raise ChannelBackpressure("drain pending data before cleanup-only mode")
            self._incoming_cleanup_mode = enabled

    def offer_plaintext(self, data, *, kind="data"):
        if type(data) is not bytes or not data or len(data) > MAX_PENDING_PLAINTEXT:
            raise ValueError("plaintext chunk is empty or exceeds 16 KiB")
        if kind not in ("data", "cleanup"):
            raise ValueError("plaintext kind is invalid")
        with self._lock:
            self._require_live()
            if not self.ready_for_plaintext:
                raise ChannelSocketError("TLS handshake is incomplete")
            if self._pending_plaintext is not None:
                raise ChannelBackpressure("one plaintext chunk is already pending")
            self._pending_plaintext = data
            self._pending_plaintext_kind = kind

    def take_plaintext(self):
        with self._lock:
            self._require_live()
            value = self._received_plaintext
            self._received_plaintext = None
            return value

    def pump(self):
        """Perform one bounded readiness/deadline and socket-I/O iteration."""
        with self._lock:
            self._require_live()
            self._backpressure = None
            try:
                # Owner checks drive the TLS deadline even when the socket is idle.
                _ = self._tls.handshake_complete
                self._collect_ciphertext()
                calls = 0
                while self._pending_ciphertext and calls < MAX_IO_CALLS_PER_PUMP:
                    if not self._send_once():
                        break
                    calls += 1
                if self._backpressure is None and not self._pending_ciphertext:
                    self._drive_plaintext()
                calls = 0
                while (calls < MAX_IO_CALLS_PER_PUMP
                       and self._received_plaintext is None):
                    if not self._receive_once():
                        break
                    calls += 1
                    if self._received_plaintext is not None:
                        break
                self._collect_ciphertext()
                while (self._pending_ciphertext and calls < MAX_IO_CALLS_PER_PUMP
                       and self._backpressure is None):
                    if not self._send_once():
                        break
                    calls += 1
            except ChannelBackpressure:
                pass
            except ChannelSocketError:
                raise
            except BaseException as error:
                self._retire("TLS/socket pump failed", error)
            return {"handshake_complete": self._safe_handshake(),
                    "backpressure": self._backpressure,
                    "socket_byte_counts": self.socket_byte_counts,
                    "pending_ciphertext_bytes": len(self._pending_ciphertext),
                    "pending_plaintext_bytes": len(self._pending_plaintext or b"")}

    tick = pump

    def close(self):
        with self._lock:
            if self._closed:
                return
            self._retire("socket driver closed", raise_error=False)

    def _safe_handshake(self):
        if self._closed:
            return False
        try:
            return bool(self._tls.handshake_complete)
        except Exception as error:
            self._retire("TLS deadline or policy check failed", error)
            return False

    def _collect_ciphertext(self, *, kind="data"):
        if self._pending_ciphertext:
            return
        try:
            chunk = self._tls.take_encrypted(MAX_PENDING_CIPHERTEXT)
        except Exception as error:
            self._retire("TLS encrypted output failed", error)
        if type(chunk) is not bytes or len(chunk) > MAX_PENDING_CIPHERTEXT:
            self._retire("TLS owner returned malformed encrypted output")
        if chunk:
            self._pending_ciphertext.extend(chunk)
            self._pending_ciphertext_kind = kind

    def _drive_plaintext(self):
        if not self._tls.handshake_complete:
            return
        if self._pending_plaintext is not None:
            kind = self._pending_plaintext_kind
            try:
                written = self._tls.write_plaintext(self._pending_plaintext)
            except Exception as error:
                self._retire("TLS plaintext write failed", error)
            if type(written) is not int or not 0 <= written <= len(self._pending_plaintext):
                self._retire("TLS owner returned an invalid plaintext write count")
            if written:
                self._pending_plaintext = self._pending_plaintext[written:] or None
                if self._pending_plaintext is None:
                    self._pending_plaintext_kind = None
                self._collect_ciphertext(kind=kind)
        if self._received_plaintext is None:
            try:
                plaintext = self._tls.read_plaintext(MAX_PENDING_PLAINTEXT)
            except Exception as error:
                self._retire("TLS plaintext read failed", error)
            if plaintext not in (None, b""):
                if type(plaintext) is not bytes or len(plaintext) > MAX_PENDING_PLAINTEXT:
                    self._retire("TLS owner returned malformed plaintext")
                self._received_plaintext = plaintext

    def _allowance(self, direction, max_bytes=MAX_SOCKET_CHUNK):
        kind = (self._pending_ciphertext_kind if direction == "send"
                else ("cleanup" if self._incoming_cleanup_mode else "data"))
        try:
            allowance = self._budget.reserve(
                self._role, self._boot_id, direction, kind, max_bytes)
            try:
                allowance.assert_live()
            except Exception:
                try:
                    allowance.settle(0, outcome_known=True)
                except Exception:
                    pass
                raise
            return allowance
        except TrafficBudgetDenied as error:
            self._backpressure = str(error)
            raise ChannelBackpressure(str(error)) from error
        except Exception as error:
            self._retire("traffic allowance or liveness check failed", error)

    def _send_once(self):
        payload = bytes(self._pending_ciphertext[:MAX_SOCKET_CHUNK])
        allowance = self._allowance("send", len(payload))
        try:
            count = self._socket.send(payload)
        except (BlockingIOError, InterruptedError) as error:
            try:
                allowance.settle(0, outcome_known=True)
            except Exception as settle_error:
                self._retire("known-zero send settlement failed", settle_error)
            return False
        except OSError as error:
            if error.errno in (errno.EAGAIN, errno.EWOULDBLOCK, errno.EINTR):
                try:
                    allowance.settle(0, outcome_known=True)
                except Exception as settle_error:
                    self._retire("known-zero send settlement failed", settle_error)
                return False
            try:
                allowance.settle(len(payload), outcome_known=False)
            except Exception:
                pass
            self._retire("socket send outcome is uncertain", error)
        except BaseException as error:
            try:
                allowance.settle(len(payload), outcome_known=False)
            except Exception:
                pass
            self._retire("socket send outcome is uncertain", error)
        if type(count) is not int or not 0 <= count <= len(payload):
            try:
                allowance.settle(len(payload), outcome_known=False)
            except Exception:
                pass
            self._retire("socket returned an invalid send count")
        try:
            allowance.settle(count, outcome_known=True)
        except Exception as error:
            self._retire("send settlement failed", error)
        if count:
            del self._pending_ciphertext[:count]
            self._socket_sent += count
        return count > 0

    def _receive_once(self):
        allowance = self._allowance("receive")
        try:
            data = self._socket.recv(MAX_SOCKET_CHUNK)
        except (BlockingIOError, InterruptedError):
            try:
                allowance.settle(0, outcome_known=True)
            except Exception as error:
                self._retire("known-zero receive settlement failed", error)
            return False
        except OSError as error:
            if error.errno in (errno.EAGAIN, errno.EWOULDBLOCK, errno.EINTR):
                try:
                    allowance.settle(0, outcome_known=True)
                except Exception as settle_error:
                    self._retire("known-zero receive settlement failed", settle_error)
                return False
            try:
                allowance.settle(MAX_SOCKET_CHUNK, outcome_known=False)
            except Exception:
                pass
            self._retire("socket receive outcome is uncertain", error)
        except BaseException as error:
            try:
                allowance.settle(MAX_SOCKET_CHUNK, outcome_known=False)
            except Exception:
                pass
            self._retire("socket receive outcome is uncertain", error)
        if type(data) is not bytes or len(data) > MAX_SOCKET_CHUNK:
            try:
                allowance.settle(MAX_SOCKET_CHUNK, outcome_known=False)
            except Exception:
                pass
            self._retire("socket returned malformed receive data")
        try:
            allowance.settle(len(data), outcome_known=True)
        except Exception as error:
            self._retire("receive settlement failed", error)
        if not data:
            self._retire("TCP peer closed the stream")
        self._socket_received += len(data)
        try:
            self._tls.feed_encrypted(data)
        except Exception as error:
            self._retire("TLS encrypted input failed", error)
        self._collect_ciphertext()
        return True

    def _require_live(self):
        if self._closed:
            raise ChannelSocketError(self._failure or "socket driver is closed")

    def _retire(self, reason, cause=None, *, raise_error=True):
        if self._closed:
            if raise_error:
                raise ChannelSocketError(self._failure or reason) from cause
            return
        self._closed = True
        self._failure = reason
        self._pending_ciphertext.clear()
        self._pending_plaintext = None
        self._pending_plaintext_kind = None
        self._received_plaintext = None
        for obj, method in ((self._socket, "close"), (self._tls, "close")):
            try:
                getattr(obj, method)()
            except Exception:
                pass
        if raise_error:
            raise ChannelSocketError(reason) from cause
