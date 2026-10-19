"""Owned, bounded outbound mTLS channel for a C2 worker stream.

The owner creates the TLS context and SSLObject from one verified client
credential. It exposes only bounded encrypted/plaintext I/O, never the context
or SSLObject. This is a MemoryBIO transport primitive, not socket framing,
aggregate traffic metering, or channel readiness.
"""

from __future__ import annotations

import ipaddress
import os
import re
import shutil
import ssl
import tempfile
import threading
import weakref

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from .clock import Clock
from .errors import SecurityError


MAX_CHUNK_BYTES = 16 * 1024
MAX_PENDING_BIO_BYTES = 64 * 1024
MAX_HANDSHAKE_BYTES = 128 * 1024
MAX_HANDSHAKE_SECONDS = 10.0


class OwnedWorkerTLSError(SecurityError):
    """The owned worker TLS channel is malformed, stale, or faulted."""

    def __init__(self, message, *, cleanup_status=None, credential_directory=None):
        super().__init__(message)
        self.cleanup_status = cleanup_status
        self.credential_directory = credential_directory


_OWNER_TOKEN = object()
_MINT_LOCK = threading.Lock()
_MINTED_OWNERS = weakref.WeakSet()


def is_owned_worker_tls(value):
    if type(value) is not OwnedWorkerTLS:
        return False
    with _MINT_LOCK:
        return value in _MINTED_OWNERS and getattr(value, "_token", None) is _OWNER_TOKEN


def _strict_bytes(value, name, limit):
    if type(value) is not bytes or not value or len(value) > limit:
        raise OwnedWorkerTLSError(f"{name} is empty or exceeds its bound")
    return value


def _valid_endpoint_host(host):
    if (type(host) is not str or not host or host != host.lower()
            or len(host) > 253 or any(c in host for c in "*/@?#[]%\\")):
        return False
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        labels = host.split(".")
        return all(1 <= len(label) <= 63
                   and re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", label)
                   for label in labels)


class OwnedWorkerTLS:
    """Owns a private TLS client context, MemoryBIO pair, and credential files."""

    def __init__(self, token, *, context, incoming, outgoing, ssl_object,
                 local_certificate_pem, clock, started):
        if token is not _OWNER_TOKEN:
            raise TypeError("use OwnedWorkerTLS.connect()")
        self.__context = context
        self.__incoming = incoming
        self.__outgoing = outgoing
        self.__ssl = ssl_object
        self._local_certificate_pem = local_certificate_pem
        self.clock = clock
        self._started = started
        self._lock = threading.RLock()
        self._closed = False
        self._faulted = False
        self._handshake_done = False
        self._sent_bytes = 0
        self._received_bytes = 0
        self._token = _OWNER_TOKEN
        self._private_directory = None
        self._cleanup_status = "not_created"

    @classmethod
    def connect(cls, *, worker_certificate_pem: bytes,
                worker_private_key_pem: bytes, gateway_ca_pem: bytes,
                endpoint_host: str, endpoint_port: int, clock: Clock):
        """Create a TLS 1.2/1.3 client pinned to a fixed endpoint and CA."""
        if type(clock) is not Clock:
            raise TypeError("owned TLS requires the exact core Clock")
        worker_certificate_pem = _strict_bytes(
            worker_certificate_pem, "worker certificate", 64 * 1024)
        worker_private_key_pem = _strict_bytes(
            worker_private_key_pem, "worker private key", 64 * 1024)
        gateway_ca_pem = _strict_bytes(gateway_ca_pem, "gateway CA", 64 * 1024)
        if (not _valid_endpoint_host(endpoint_host)
                or type(endpoint_port) is not int or not 1 <= endpoint_port <= 65535):
            raise OwnedWorkerTLSError("fixed gateway endpoint is malformed")
        try:
            cert = x509.load_pem_x509_certificate(worker_certificate_pem)
            key = serialization.load_pem_private_key(worker_private_key_pem, password=None)
            cert_public = cert.public_key().public_bytes(
                serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
            selected_local_leaf_pem = cert.public_bytes(serialization.Encoding.PEM)
            key_public = key.public_key().public_bytes(
                serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
            if cert_public != key_public:
                raise OwnedWorkerTLSError("worker private key does not match its leaf")
        except OwnedWorkerTLSError:
            raise
        except Exception as error:
            raise OwnedWorkerTLSError("worker TLS credential is malformed") from error

        temporary = tempfile.mkdtemp(prefix="steamboat-channel-")
        context = None
        owner = None
        try:
            if os.name == "posix":
                os.chmod(temporary, 0o700)
                if os.stat(temporary).st_mode & 0o777 != 0o700:
                    raise OwnedWorkerTLSError("private TLS directory mode could not be enforced")
            cert_path = os.path.join(temporary, "worker.pem")
            key_path = os.path.join(temporary, "worker-key.pem")
            ca_path = os.path.join(temporary, "gateway-ca.pem")
            for path, data in ((cert_path, worker_certificate_pem),
                               (key_path, worker_private_key_pem),
                               (ca_path, gateway_ca_pem)):
                flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
                fd = os.open(path, flags, 0o600)
                try:
                    stream = os.fdopen(fd, "wb", closefd=True)
                    fd = None  # fdopen owns it from this point, even on write errors.
                    with stream:
                        stream.write(data)
                        stream.flush()
                        os.fsync(stream.fileno())
                finally:
                    if fd is not None:
                        os.close(fd)
            if os.name == "posix" and any(
                    os.stat(path).st_mode & 0o777 != 0o600
                    for path in (cert_path, key_path, ca_path)):
                raise OwnedWorkerTLSError("private TLS file mode could not be enforced")

            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            context.maximum_version = ssl.TLSVersion.TLSv1_3
            context.verify_mode = ssl.CERT_REQUIRED
            context.check_hostname = True
            if not hasattr(ssl, "OP_NO_RENEGOTIATION"):
                raise OwnedWorkerTLSError("TLS backend cannot disable renegotiation")
            context.options |= ssl.OP_NO_RENEGOTIATION
            context.post_handshake_auth = False
            context.load_verify_locations(cafile=ca_path)
            context.load_cert_chain(certfile=cert_path, keyfile=key_path)
            incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
            ssl_object = context.wrap_bio(incoming, outgoing, server_side=False,
                                          server_hostname=endpoint_host)
            clock_sample = clock.sample()
            owner = cls(_OWNER_TOKEN, context=context, incoming=incoming,
                        outgoing=outgoing, ssl_object=ssl_object,
                        local_certificate_pem=selected_local_leaf_pem,
                        clock=clock, started=clock_sample.monotonic)
            owner._endpoint_host = endpoint_host
            owner._endpoint_port = endpoint_port
            owner._private_directory = temporary
            owner._cleanup_status = "pending"
            temporary = None
            # OpenSSL has loaded the key. A cleanup failure leaves a visible,
            # unusable owner with an explicit uncertain path status.
            if not owner._remove_credentials_locked():
                owner._faulted = True
                owner._cleanup_failed_locked()
                return owner
            owner._drive_handshake_locked()
            with _MINT_LOCK:
                _MINTED_OWNERS.add(owner)
            return owner
        except BaseException:
            if owner is not None:
                owner.close()
                if owner.cleanup_uncertain:
                    raise OwnedWorkerTLSError(
                        "TLS credential cleanup is uncertain",
                        cleanup_status="uncertain",
                        credential_directory=owner._private_directory)
            if context is not None:
                context = None
            if temporary is not None:
                try:
                    shutil.rmtree(temporary)
                except OSError as cleanup_error:
                    raise OwnedWorkerTLSError(
                        "TLS credential cleanup is uncertain",
                        cleanup_status="uncertain",
                        credential_directory=temporary) from cleanup_error
            raise

    @property
    def handshake_complete(self):
        with self._lock:
            return self._handshake_done and not self._closed and not self._faulted

    @property
    def endpoint_host(self):
        return self._endpoint_host

    @property
    def endpoint_port(self):
        return self._endpoint_port

    @property
    def peer_certificate_der(self):
        with self._lock:
            self._require_live_locked()
            if not self._handshake_done:
                raise OwnedWorkerTLSError("TLS handshake is incomplete")
            try:
                return self.__ssl.getpeercert(binary_form=True)
            except Exception as error:
                self._fail_locked()
                raise OwnedWorkerTLSError("TLS peer certificate is unavailable") from error

    @property
    def configured_local_certificate_pem(self):
        with self._lock:
            self._require_live_locked()
            if not self._handshake_done:
                raise OwnedWorkerTLSError("TLS handshake is incomplete")
            return self._local_certificate_pem

    @property
    def byte_counts(self):
        with self._lock:
            return self._sent_bytes, self._received_bytes

    @property
    def cleanup_status(self):
        with self._lock:
            return self._cleanup_status

    @property
    def cleanup_uncertain(self):
        with self._lock:
            return self._cleanup_status == "uncertain"

    @property
    def credential_directory(self):
        """Retained path when cleanup is uncertain; None only after confirmed removal."""
        with self._lock:
            return self._private_directory

    @property
    def is_live(self):
        with self._lock:
            return self._handshake_done and not self._closed and not self._faulted

    def assert_transport_live(self):
        """Check Clock, owner state and startup deadline without consuming bytes."""
        with self._lock:
            self._require_live_locked()
            sample = self._sample_clock_locked()
            if (not self._handshake_done
                    and sample.monotonic >= self._started + MAX_HANDSHAKE_SECONDS):
                self._fail_locked()
                raise OwnedWorkerTLSError("TLS handshake deadline exceeded")
            return self._handshake_done

    @property
    def pending_encrypted_bytes(self):
        with self._lock:
            self._require_live_locked()
            return self.__outgoing.pending

    def take_encrypted(self, maximum=MAX_CHUNK_BYTES):
        with self._lock:
            self._require_live_locked()
            if type(maximum) is not int or not 1 <= maximum <= MAX_CHUNK_BYTES:
                raise ValueError("encrypted output chunk exceeds the bound")
            if not self._handshake_done:
                sample = self._sample_clock_locked()
                if sample.monotonic >= self._started + MAX_HANDSHAKE_SECONDS:
                    self._fail_locked()
                    raise OwnedWorkerTLSError("TLS handshake deadline exceeded")
            if self.__outgoing.pending > MAX_PENDING_BIO_BYTES:
                self._fail_locked()
                raise OwnedWorkerTLSError("TLS output BIO exceeds its bound")
            data = self.__outgoing.read(maximum)
            self._sent_bytes += len(data)
            return data

    def feed_encrypted(self, data):
        with self._lock:
            self._require_live_locked()
            if type(data) is not bytes or not data or len(data) > MAX_CHUNK_BYTES:
                self._fail_locked()
                raise OwnedWorkerTLSError("encrypted input chunk is empty or exceeds its bound")
            if self.__incoming.pending + len(data) > MAX_PENDING_BIO_BYTES:
                self._fail_locked()
                raise OwnedWorkerTLSError("TLS input BIO exceeds its bound")
            if not self._handshake_done and (
                    self._sent_bytes + self._received_bytes + len(data)
                    > MAX_HANDSHAKE_BYTES):
                self._fail_locked()
                raise OwnedWorkerTLSError("TLS handshake byte budget exceeded")
            try:
                self._received_bytes += len(data)
                self.__incoming.write(data)
                self._drive_handshake_locked()
            except BaseException:
                self._fail_locked()
                raise

    def do_handshake(self):
        with self._lock:
            self._require_live_locked()
            self._drive_handshake_locked()
            return self._handshake_done

    def write_plaintext(self, data):
        with self._lock:
            self._require_live_locked()
            if type(data) is not bytes or not data or len(data) > MAX_CHUNK_BYTES:
                self._fail_locked()
                raise OwnedWorkerTLSError("TLS plaintext is empty or exceeds its bound")
            if not self._handshake_done:
                raise OwnedWorkerTLSError("TLS handshake is incomplete")
            try:
                written = self.__ssl.write(data)
                if self.__outgoing.pending > MAX_PENDING_BIO_BYTES:
                    raise OwnedWorkerTLSError("TLS output BIO exceeds its bound")
                return written
            except BaseException:
                self._fail_locked()
                raise

    def read_plaintext(self, maximum=MAX_CHUNK_BYTES):
        with self._lock:
            self._require_live_locked()
            if not self._handshake_done:
                raise OwnedWorkerTLSError("TLS handshake is incomplete")
            if type(maximum) is not int or not 1 <= maximum <= MAX_CHUNK_BYTES:
                raise ValueError("TLS plaintext read exceeds the bound")
            try:
                plaintext = self.__ssl.read(maximum)
            except ssl.SSLWantReadError:
                plaintext = None
            except ssl.SSLWantWriteError:
                plaintext = None
            except ssl.SSLZeroReturnError:
                self._fail_locked()
                return b""
            except BaseException:
                self._fail_locked()
                raise
            if self.__outgoing.pending > MAX_PENDING_BIO_BYTES:
                self._fail_locked()
                raise OwnedWorkerTLSError("TLS output BIO exceeds its bound")
            if plaintext == b"":
                # Empty application data is not emitted by SSLObject.read; an
                # empty result means the peer sent close_notify.
                self._fail_locked()
            return plaintext

    def _drive_handshake_locked(self):
        self._require_live_locked()
        sample = self._sample_clock_locked()
        if (not self._handshake_done
                and sample.monotonic >= self._started + MAX_HANDSHAKE_SECONDS):
            self._fail_locked()
            raise OwnedWorkerTLSError("TLS handshake deadline exceeded")
        if self._handshake_done:
            return
        try:
            self.__ssl.do_handshake()
            self._handshake_done = True
        except (ssl.SSLWantReadError, ssl.SSLWantWriteError):
            pass
        except BaseException as error:
            self._fail_locked()
            raise OwnedWorkerTLSError("TLS handshake failed") from error
        if (self.__outgoing.pending > MAX_PENDING_BIO_BYTES
                or self._sent_bytes + self._received_bytes + self.__outgoing.pending
                > MAX_HANDSHAKE_BYTES):
            self._fail_locked()
            raise OwnedWorkerTLSError("TLS handshake exceeded its bounded byte budget")

    def _require_live_locked(self):
        if self._closed or self._faulted:
            raise OwnedWorkerTLSError("owned TLS connection is closed or faulted")

    def _sample_clock_locked(self):
        try:
            return self.clock.sample()
        except Exception as error:
            self._faulted = True
            self._cleanup_locked()
            raise OwnedWorkerTLSError("TLS clock is unavailable") from error

    def _fail_locked(self):
        self._faulted = True
        self._cleanup_locked()

    def _cleanup_locked(self):
        if not self._closed:
            self._closed = True
            self.__ssl = None
            self.__context = None
            self.__incoming = None
            self.__outgoing = None
            self._remove_credentials_locked()

    def _remove_credentials_locked(self):
        path = self._private_directory
        if path is None:
            if self._cleanup_status == "not_created":
                self._cleanup_status = "removed"
            return self._cleanup_status == "removed"
        try:
            shutil.rmtree(path)
        except Exception:
            self._cleanup_status = "uncertain"
            return False
        self._private_directory = None
        self._cleanup_status = "removed"
        return True

    def _cleanup_failed_locked(self):
        self._closed = True
        self.__ssl = None
        self.__context = None
        self.__incoming = None
        self.__outgoing = None

    def close(self):
        with self._lock:
            self._cleanup_locked()

    def __del__(self):
        try:
            self.close()
        except Exception:
            pass

    def __copy__(self):
        raise TypeError("owned TLS connections cannot be copied")

    def __deepcopy__(self, _memo):
        raise TypeError("owned TLS connections cannot be copied")
