"""Bounded nonblocking TCP pump for fixed owner-minted C2 TLS engines."""

from __future__ import annotations

import errno
import socket
import threading

from steamboat_connector.traffic_budget import (
    TrafficBudget, TrafficBudgetDenied,
)
from steamboat_security.channel_tls import is_owned_worker_tls
from steamboat_security.gateway_tls import is_owned_gateway_worker_tls
from steamboat_security.gateway_coordinator_tls import (
    is_owned_gateway_coordinator_tls,
)
from steamboat_security.gateway_egress import is_owned_gateway_coordinator_egress


MAX_SOCKET_CHUNK = 16 * 1024
MAX_PENDING_CIPHERTEXT = 16 * 1024
MAX_PENDING_PLAINTEXT = 16 * 1024
MAX_IO_CALLS_PER_PUMP = 4


class ChannelSocketError(RuntimeError):
    """The owned socket/TLS generation was retired or is unavailable."""


class ChannelBackpressure(ChannelSocketError):
    """Traffic quota/rate denied this bounded pump operation."""


def _tls_engine(owner):
    if (is_owned_worker_tls(owner) or is_owned_gateway_worker_tls(owner)
            or is_owned_gateway_coordinator_tls(owner)
            or is_owned_gateway_coordinator_egress(owner)):
        return owner
    raise TypeError("TLS owner must be an internally minted fixed-profile owner")


class ChannelSocket:
    """Drive one connected TCP socket and one genuine owner-minted TLS engine.

    `test_socket=True` is an explicit test-only escape hatch for wrappers around
    real sockets. Production accepts only a connected IPv4/IPv6 TCP socket.
    The caller must bind the TrafficBudget role before constructing the driver.
    """

    def __init__(self, connected_socket, tls_owner, traffic_budget, *, role,
                 boot_id, test_socket=False):
        if (type(traffic_budget) is not TrafficBudget
                or type(role) is not str or type(boot_id) is not str):
            raise TypeError("socket driver requires a bound TrafficBudget role")
        if type(test_socket) is not bool:
            raise TypeError("test_socket flag must be boolean")
        if type(connected_socket) is socket.socket:
            self._validate_connected_tcp(connected_socket)
        elif (test_socket and all(callable(getattr(connected_socket, name, None))
                                  for name in ("setblocking", "send", "recv", "close"))):
            pass
        else:
            raise TypeError("socket must be an exact connected TCP socket")
        self._socket = connected_socket
        self._tls = _tls_engine(tls_owner)
        self._budget = traffic_budget
        self._role = role
        self._boot_id = boot_id
        self._lock = threading.RLock()
        self._pending_ciphertext = bytearray()
        self._pending_ciphertext_kind = "data"
        self._tls_output_kind = "data"
        self._pending_plaintext = None
        self._pending_plaintext_kind = None
        self._received_plaintext = None
        self._incoming_cleanup_mode = False
        self._closed = False
        self._failure = None
        self._socket_sent = 0
        self._socket_received = 0
        self._io_outcome_uncertain = False
        self._metering_uncertain = False
        self._backpressure = None
        self._socket.setblocking(False)

    @staticmethod
    def _validate_connected_tcp(sock):
        if sock.family not in (socket.AF_INET, socket.AF_INET6):
            raise TypeError("production socket must use IPv4 or IPv6")
        if (sock.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) & 0xF) != socket.SOCK_STREAM:
            raise TypeError("production socket must be TCP stream")
        try:
            peer = sock.getpeername()
        except OSError as error:
            raise TypeError("production socket must already be connected") from error
        if (type(peer) is not tuple or len(peer) < 2
                or type(peer[1]) is not int or not 1 <= peer[1] <= 65535):
            raise TypeError("production socket peer address is malformed")

    @property
    def failure(self):
        return self._failure

    @property
    def socket_byte_counts(self):
        return self._socket_sent, self._socket_received

    @property
    def io_outcome_uncertain(self):
        return self._io_outcome_uncertain

    @property
    def metering_uncertain(self):
        return self._metering_uncertain

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
    def tls_handshake_complete(self):
        with self._lock:
            self._require_live()
            try:
                self._assert_owner_live()
                return bool(self._tls.handshake_complete)
            except Exception as error:
                self._retire("TLS handshake/liveness check failed", error)

    def set_incoming_cleanup_mode(self, enabled):
        if type(enabled) is not bool:
            raise TypeError("cleanup mode must be boolean")
        with self._lock:
            self._require_live()
            try:
                self._assert_owner_live()
            except Exception as error:
                self._retire("TLS liveness check failed", error)
            if self._incoming_cleanup_mode and not enabled:
                raise ChannelSocketError("incoming cleanup mode is irreversible")
            if enabled and (self._pending_ciphertext or self._pending_plaintext is not None
                            or self._tls.pending_encrypted_bytes):
                raise ChannelBackpressure("drain pending data before cleanup-only mode")
            self._incoming_cleanup_mode = enabled

    def offer_plaintext(self, data, *, kind="data"):
        if type(data) is not bytes or not data or len(data) > MAX_PENDING_PLAINTEXT:
            raise ValueError("plaintext chunk is empty or exceeds 16 KiB")
        if kind not in ("data", "cleanup"):
            raise ValueError("plaintext kind is invalid")
        with self._lock:
            self._require_live()
            try:
                self._assert_owner_live()
                if not self._tls.handshake_complete:
                    raise ChannelSocketError("TLS handshake is incomplete")
            except ChannelSocketError:
                raise
            except Exception as error:
                self._retire("TLS liveness check failed", error)
            if self._pending_plaintext is not None:
                raise ChannelBackpressure("one plaintext chunk is already pending")
            self._pending_plaintext = data
            self._pending_plaintext_kind = kind

    def take_plaintext(self):
        with self._lock:
            self._require_live()
            try:
                self._assert_owner_live()
            except Exception as error:
                self._retire("TLS liveness check failed", error)
            value = self._received_plaintext
            self._received_plaintext = None
            return value

    def pump(self):
        """Perform one deadline check and bounded nonblocking socket iteration."""
        with self._lock:
            self._require_live()
            self._backpressure = None
            send_calls = 0
            receive_calls = 0
            try:
                self._assert_owner_live()
                self._collect_ciphertext()
                self._drive_tls_read_and_write()
                while self._pending_ciphertext and send_calls < MAX_IO_CALLS_PER_PUMP:
                    send_calls += 1
                    if not self._send_once():
                        break
                # TLS decoding does not wait for writer readiness. Every input
                # chunk is decoded before another bounded receive can accumulate.
                self._drive_tls_read_and_write(write_allowed=False)
                while (self._backpressure is None
                       and self._received_plaintext is None
                       and receive_calls < MAX_IO_CALLS_PER_PUMP):
                    receive_calls += 1
                    if not self._receive_once():
                        break
                    self._drive_tls_read_and_write(write_allowed=False)
                self._collect_ciphertext()
                while (self._pending_ciphertext
                       and send_calls < MAX_IO_CALLS_PER_PUMP
                       and self._backpressure is None):
                    send_calls += 1
                    if not self._send_once():
                        break
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
                    "pending_plaintext_bytes": len(self._pending_plaintext or b""),
                    "io_outcome_uncertain": self._io_outcome_uncertain,
                    "metering_uncertain": self._metering_uncertain}

    tick = pump

    def close(self):
        with self._lock:
            if self._closed:
                return
            self._retire("socket driver closed", raise_error=False)

    def _assert_owner_live(self):
        self._tls.assert_transport_live()

    def _safe_handshake(self):
        if self._closed:
            return False
        try:
            self._assert_owner_live()
            return bool(self._tls.handshake_complete)
        except Exception as error:
            self._retire("TLS deadline or policy check failed", error)

    def _collect_ciphertext(self):
        self._assert_owner_live()
        if self._pending_ciphertext:
            return
        pending = self._tls.pending_encrypted_bytes
        if not pending:
            self._tls_output_kind = "data"
            return
        chunk = self._tls.take_encrypted(min(MAX_PENDING_CIPHERTEXT, pending))
        if type(chunk) is not bytes or not chunk or len(chunk) > MAX_PENDING_CIPHERTEXT:
            self._retire("TLS owner returned malformed encrypted output")
        self._pending_ciphertext.extend(chunk)
        self._pending_ciphertext_kind = self._tls_output_kind
        if self._tls.pending_encrypted_bytes == 0:
            self._tls_output_kind = "data"

    def _drive_tls_read_and_write(self, *, write_allowed=True):
        self._assert_owner_live()
        if not self._tls.handshake_complete:
            return
        if (write_allowed and self._pending_plaintext is not None
                and not self._pending_ciphertext
                and self._tls.pending_encrypted_bytes == 0):
            kind = self._pending_plaintext_kind
            self._tls_output_kind = kind
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
                self._collect_ciphertext()
        if self._received_plaintext is None:
            self._assert_owner_live()
            try:
                plaintext = self._tls.read_plaintext(MAX_PENDING_PLAINTEXT)
            except Exception as error:
                self._retire("TLS plaintext read failed", error)
            if plaintext not in (None, b""):
                if type(plaintext) is not bytes or len(plaintext) > MAX_PENDING_PLAINTEXT:
                    self._retire("TLS owner returned malformed plaintext")
                self._received_plaintext = plaintext
                self._collect_ciphertext()

    def _allowance(self, direction, max_bytes=MAX_SOCKET_CHUNK):
        kind = (self._pending_ciphertext_kind if direction == "send"
                else ("cleanup" if self._incoming_cleanup_mode else "data"))
        try:
            allowance = self._budget.reserve(
                self._role, self._boot_id, direction, kind, max_bytes)
        except TrafficBudgetDenied as error:
            self._backpressure = str(error)
            raise ChannelBackpressure(str(error)) from error
        try:
            allowance.assert_live()
        except Exception as error:
            try:
                allowance.settle(0, outcome_known=True)
            except Exception:
                self._metering_uncertain = True
            self._retire("traffic allowance or liveness check failed", error)
        return allowance

    def _send_once(self):
        self._assert_owner_live()
        payload = bytes(self._pending_ciphertext[:MAX_SOCKET_CHUNK])
        allowance = self._allowance("send", len(payload))
        self._assert_owner_live()
        try:
            count = self._socket.send(payload)
        except (BlockingIOError, InterruptedError):
            self._settle(allowance, 0, outcome_known=True)
            return False
        except OSError as error:
            if error.errno in (errno.EAGAIN, errno.EWOULDBLOCK, errno.EINTR):
                self._settle(allowance, 0, outcome_known=True)
                return False
            self._io_outcome_uncertain = True
            self._settle_uncertain_io(allowance)
            self._retire("socket send outcome is uncertain", error)
        except BaseException as error:
            self._io_outcome_uncertain = True
            self._settle_uncertain_io(allowance)
            self._retire("socket send outcome is uncertain", error)
        if type(count) is not int or not 0 <= count <= len(payload):
            self._io_outcome_uncertain = True
            self._settle_uncertain_io(allowance)
            self._retire("socket returned an invalid send count")
        if count:
            self._socket_sent += count
        self._settle(allowance, count, outcome_known=True)
        if count == 0:
            self._retire("socket send made no progress")
        if count:
            del self._pending_ciphertext[:count]
        return count > 0

    def _receive_once(self):
        self._assert_owner_live()
        allowance = self._allowance("receive")
        self._assert_owner_live()
        try:
            data = self._socket.recv(MAX_SOCKET_CHUNK)
        except (BlockingIOError, InterruptedError):
            self._settle(allowance, 0, outcome_known=True)
            return False
        except OSError as error:
            if error.errno in (errno.EAGAIN, errno.EWOULDBLOCK, errno.EINTR):
                self._settle(allowance, 0, outcome_known=True)
                return False
            self._io_outcome_uncertain = True
            self._settle_uncertain_io(allowance)
            self._retire("socket receive outcome is uncertain", error)
        except BaseException as error:
            self._io_outcome_uncertain = True
            self._settle_uncertain_io(allowance)
            self._retire("socket receive outcome is uncertain", error)
        if type(data) is not bytes or len(data) > MAX_SOCKET_CHUNK:
            self._io_outcome_uncertain = True
            self._settle_uncertain_io(allowance)
            self._retire("socket returned malformed receive data")
        if data:
            self._socket_received += len(data)
        self._settle(allowance, len(data), outcome_known=True)
        if not data:
            self._retire("TCP peer closed the stream")
        self._assert_owner_live()
        try:
            self._tls.feed_encrypted(data)
        except Exception as error:
            self._retire("TLS encrypted input failed", error)
        self._collect_ciphertext()
        return True

    def _settle(self, allowance, actual, *, outcome_known):
        try:
            result = allowance.settle(actual, outcome_known=outcome_known)
            if result.get("uncertain"):
                self._metering_uncertain = True
        except Exception as error:
            self._metering_uncertain = True
            self._retire("traffic settlement failed after socket I/O", error)

    def _settle_uncertain_io(self, allowance):
        # The syscall may have transferred bytes, but its lower bound is zero.
        # The ledger retains the full reservation and records zero observed bytes.
        try:
            result = allowance.settle(0, outcome_known=False)
            if not result.get("uncertain"):
                self._metering_uncertain = True
        except Exception:
            self._metering_uncertain = True

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
        for obj, method in ((self._socket, "close"), (self._tls, "close")):
            try:
                getattr(obj, method)()
            except Exception:
                pass
        # Unsent ciphertext is discarded only after retiring the entire TLS stream.
        self._pending_ciphertext.clear()
        self._pending_plaintext = None
        self._pending_plaintext_kind = None
        self._received_plaintext = None
        if raise_error:
            raise ChannelSocketError(reason) from cause
