"""Owned server-side TLS for a policy-pinned C2 worker stream.

This module owns a private server SSLContext and MemoryBIO connection. It mints
an authenticated worker record only after CERT_REQUIRED completes and the
actual TLS peer certificate matches the current operator-signed channel policy.
It does not provide sockets, framing, enrollment, readiness, or aggregate quota.
"""

from __future__ import annotations

import hashlib
import os
import re
import shutil
import ssl
import tempfile
import threading
import weakref
from dataclasses import dataclass, field

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from .certificates import certificate_sha256, public_key_sha256, serial_hex
from .channel_certificates import verify_channel_certificate
from .channel_policy import ChannelPolicyStore
from .channel_tls import (MAX_CHUNK_BYTES, MAX_HANDSHAKE_BYTES,
                          MAX_HANDSHAKE_SECONDS, MAX_PENDING_BIO_BYTES)
from .clock import Clock
from .errors import SecurityError


class GatewayWorkerTLSError(SecurityError):
    """TLS peer, policy, clock, bound, or credential cleanup failure."""

    def __init__(self, message, *, cleanup_status=None, credential_directory=None):
        super().__init__(message)
        self.cleanup_status = cleanup_status
        self.credential_directory = credential_directory


_TOKEN = object()
_MINT_LOCK = threading.Lock()
_OWNERS = weakref.WeakSet()
_CHANNELS = weakref.WeakSet()
_URI = re.compile(
    r"^urn:steamboat:channel:v1:worker_stream:(acct_[a-z0-9_-]{1,48}):"
    r"(dev_[a-z0-9_-]{1,48}):([1-9a-f][0-9a-f]{0,39}):([1-9][0-9]{0,9})$"
)


def is_owned_gateway_worker_tls(value):
    if type(value) is not OwnedGatewayWorkerTLS:
        return False
    with _MINT_LOCK:
        return value in _OWNERS and getattr(value, "_token", None) is _TOKEN


def is_authenticated_worker_channel(value):
    if type(value) is not AuthenticatedWorkerChannel:
        return False
    with _MINT_LOCK:
        return value in _CHANNELS and getattr(value, "_token", None) is _TOKEN


def _bounded_pem(value, label):
    if type(value) is not bytes or not 1 <= len(value) <= 64 * 1024:
        raise GatewayWorkerTLSError(f"{label} input exceeds its bound")
    return value


def _worker_uri_identity(cert):
    try:
        names = cert.extensions.get_extension_for_class(
            x509.SubjectAlternativeName).value.get_values_for_type(
                x509.UniformResourceIdentifier)
    except x509.ExtensionNotFound as error:
        raise GatewayWorkerTLSError("worker peer has no identity URI") from error
    if len(names) != 1:
        raise GatewayWorkerTLSError("worker peer identity URI is ambiguous")
    match = _URI.fullmatch(names[0])
    if match is None:
        raise GatewayWorkerTLSError("TLS peer is not a worker_stream certificate")
    account_id, device_id, host_serial, epoch = match.groups()
    if int(epoch) > 2**31 - 1 or str(int(epoch)) != epoch:
        raise GatewayWorkerTLSError("worker peer epoch is not canonical")
    return {
        "account_id": account_id,
        "device_id": device_id,
        "host_serial": host_serial,
        "credential_epoch": int(epoch),
    }


def _write_private_files(entries):
    """Write PEM inputs with private modes; return path and cleanup status."""
    directory = tempfile.mkdtemp(prefix="steamboat-gateway-tls-")
    try:
        if os.name == "posix":
            os.chmod(directory, 0o700)
            if os.stat(directory).st_mode & 0o777 != 0o700:
                raise GatewayWorkerTLSError("private TLS directory mode could not be enforced")
        paths = {}
        for name, data in entries.items():
            path = os.path.join(directory, name)
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            try:
                stream = os.fdopen(fd, "wb", closefd=True)
                fd = None
                with stream:
                    stream.write(data)
                    stream.flush()
                    os.fsync(stream.fileno())
            finally:
                if fd is not None:
                    os.close(fd)
            if os.name == "posix" and os.stat(path).st_mode & 0o777 != 0o600:
                raise GatewayWorkerTLSError("private TLS file mode could not be enforced")
            paths[name] = path
        return directory, paths
    except BaseException as error:
        try:
            shutil.rmtree(directory)
        except OSError as cleanup_error:
            raise GatewayWorkerTLSError(
                "private TLS credential cleanup is uncertain",
                cleanup_status="uncertain", credential_directory=directory) from cleanup_error
        raise error


@dataclass(frozen=True)
class AuthenticatedWorkerChannel:
    gateway_id: str
    gateway_certificate_sha256: str
    account_id: str
    device_id: str
    host_serial: str
    host_credential_epoch: int
    host_certificate_sha256: str
    worker_boot_id: str
    assignment_id: str
    model_id: str
    channel_serial: str
    channel_certificate_sha256: str
    channel_public_key_sha256: str
    policy_revision: int
    policy_digest: str
    stream_generation: str
    _deadline_at_mint: float = field(repr=False)
    _owner_ref: object = field(repr=False, compare=False)
    _token: object = field(repr=False, compare=False)

    def assert_live(self):
        if self._token is not _TOKEN:
            raise GatewayWorkerTLSError("worker channel record is not owner-minted")
        owner = self._owner_ref()
        if owner is None:
            raise GatewayWorkerTLSError("worker TLS owner is unavailable")
        owner.assert_channel_live(self)

    @property
    def deadline_monotonic(self):
        owner = self._owner_ref()
        if owner is None:
            raise GatewayWorkerTLSError("worker TLS owner is unavailable")
        return owner._channel_deadline(self)


class OwnedGatewayWorkerTLS:
    """Own a server TLS endpoint and authenticate its actual worker peer."""

    def __init__(self, token, *, context, incoming, outgoing, ssl_object,
                 policy_store, clock, gateway_id, gateway_record, gateway_cert,
                 ca_pem, started, directory):
        if token is not _TOKEN:
            raise TypeError("use OwnedGatewayWorkerTLS.accept()")
        self.__context = context
        self.__incoming = incoming
        self.__outgoing = outgoing
        self.__ssl = ssl_object
        self.policy_store = policy_store
        self.clock = clock
        self.gateway_id = gateway_id
        self._gateway_record = gateway_record
        self._gateway_cert = gateway_cert
        self._peer_cert = None
        self._ca_pem = ca_pem
        self._started = started
        self._deadline = float("inf")
        self._view = None
        self._sample = None
        self._directory = directory
        self._cleanup_status = "pending"
        self._lock = threading.RLock()
        self._token = _TOKEN
        self._handshake_done = False
        self._closed = False
        self._faulted = False
        self._sent_bytes = 0
        self._received_bytes = 0
        self._channel = None
        self._generation = os.urandom(16).hex()

    @classmethod
    def accept(cls, *, gateway_certificate_pem: bytes,
               gateway_private_key_pem: bytes, cohort_ca_pem: bytes,
               policy_store: ChannelPolicyStore, clock: Clock, gateway_id: str):
        """Create a private CERT_REQUIRED server owner for one gateway identity."""
        if type(policy_store) is not ChannelPolicyStore or type(clock) is not Clock:
            raise TypeError("gateway TLS requires exact channel policy and core Clock owners")
        if policy_store.clock is not clock:
            raise TypeError("gateway TLS and policy store must share the exact Clock")
        gateway_certificate_pem = _bounded_pem(gateway_certificate_pem, "gateway certificate")
        gateway_private_key_pem = _bounded_pem(gateway_private_key_pem, "gateway private key")
        cohort_ca_pem = _bounded_pem(cohort_ca_pem, "cohort CA")
        try:
            local_cert = x509.load_pem_x509_certificate(gateway_certificate_pem)
            local_key = serialization.load_pem_private_key(gateway_private_key_pem, password=None)
            if local_cert.public_key().public_bytes(
                    serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
            ) != local_key.public_key().public_bytes(
                    serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo):
                raise GatewayWorkerTLSError("gateway private key does not match its leaf")
            view, sample = policy_store.current_with_sample()
            gateway = view.gateway(gateway_id)
            if gateway is None:
                raise GatewayWorkerTLSError("gateway is absent from current signed policy")
            host = gateway["endpoint_host"]
            profile = verify_channel_certificate(
                gateway_certificate_pem, cohort_ca_pem, kind="gateway",
                expected_identity=gateway_id, now=sample.wall,
                uncertainty_seconds=sample.uncertainty, required_eku={"client", "server"},
                expected_dns=host if ":" not in host else None,
                expected_ip=host if ":" in host else None)
            if (profile.certificate_sha256 != gateway["certificate_sha256"]
                    or profile.public_key_sha256 != gateway["public_key_sha256"]
                    or profile.serial != gateway["serial"]):
                raise GatewayWorkerTLSError("local gateway credential differs from policy pin")
        except GatewayWorkerTLSError:
            raise
        except Exception as error:
            raise GatewayWorkerTLSError("gateway credential or policy is invalid") from error

        directory, paths = _write_private_files({
            "gateway.pem": gateway_certificate_pem,
            "gateway-key.pem": gateway_private_key_pem,
            "cohort-ca.pem": cohort_ca_pem,
        })
        context = None
        owner = None
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            context.maximum_version = ssl.TLSVersion.TLSv1_3
            context.verify_mode = ssl.CERT_REQUIRED
            if not hasattr(ssl, "OP_NO_RENEGOTIATION"):
                raise GatewayWorkerTLSError("TLS backend cannot disable renegotiation")
            context.options |= ssl.OP_NO_RENEGOTIATION
            context.post_handshake_auth = False
            context.load_verify_locations(cafile=paths["cohort-ca.pem"])
            context.load_cert_chain(paths["gateway.pem"], paths["gateway-key.pem"])
            incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
            ssl_object = context.wrap_bio(incoming, outgoing, server_side=True)
            owner = cls(_TOKEN, context=context, incoming=incoming, outgoing=outgoing,
                        ssl_object=ssl_object, policy_store=policy_store, clock=clock,
                        gateway_id=gateway_id, gateway_record=gateway, gateway_cert=local_cert,
                        ca_pem=cohort_ca_pem, started=sample.monotonic, directory=directory)
            owner._view = view
            owner._sample = sample
            owner._deadline = min(view.deadline_monotonic,
                                  sample.monotonic + view.expires_at - sample.latest_wall,
                                  sample.monotonic + gateway["not_after"] - sample.latest_wall,
                                  sample.monotonic + profile.not_after.timestamp()
                                  - sample.latest_wall)
            owner._cleanup_status = "pending"
            try:
                shutil.rmtree(directory)
            except OSError:
                owner._fault_locked()
                owner._cleanup_status = "uncertain"
                raise GatewayWorkerTLSError(
                    "gateway TLS credential cleanup is uncertain",
                    cleanup_status="uncertain", credential_directory=directory)
            owner._directory = None
            owner._cleanup_status = "removed"
            owner._drive_handshake_locked()
            with _MINT_LOCK:
                _OWNERS.add(owner)
            return owner
        except BaseException:
            if owner is not None:
                if owner.cleanup_status != "uncertain":
                    owner.close()
            else:
                try:
                    shutil.rmtree(directory)
                except OSError as error:
                    raise GatewayWorkerTLSError(
                        "gateway TLS credential cleanup is uncertain",
                        cleanup_status="uncertain", credential_directory=directory) from error
            raise

    @property
    def handshake_complete(self):
        with self._lock:
            return self._handshake_done and not self._closed and not self._faulted

    @property
    def authenticated_channel(self):
        with self._lock:
            if not self._handshake_done or self._channel is None:
                raise GatewayWorkerTLSError("worker handshake is incomplete or unauthenticated")
            self._assert_live_locked()
            return self._channel

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
        return self.cleanup_status == "uncertain"

    @property
    def credential_directory(self):
        with self._lock:
            return self._directory

    @property
    def is_live(self):
        with self._lock:
            if self._closed or self._faulted or not self._handshake_done:
                return False
            try:
                self._assert_live_locked()
                return True
            except GatewayWorkerTLSError:
                return False

    def take_encrypted(self, maximum=MAX_CHUNK_BYTES):
        with self._lock:
            self._require_live_locked()
            if type(maximum) is not int or not 1 <= maximum <= MAX_CHUNK_BYTES:
                raise ValueError("encrypted output chunk exceeds the bound")
            if self._handshake_done:
                self._assert_live_locked()
            else:
                sample = self._sample_clock_locked()
                if sample.monotonic >= self._started + MAX_HANDSHAKE_SECONDS:
                    self._fault_locked()
                    raise GatewayWorkerTLSError("TLS handshake deadline exceeded")
            if self.__outgoing.pending > MAX_PENDING_BIO_BYTES:
                self._fault_locked()
                raise GatewayWorkerTLSError("TLS output BIO exceeds its bound")
            data = self.__outgoing.read(maximum)
            self._sent_bytes += len(data)
            if (not self._handshake_done
                    and self._sent_bytes + self._received_bytes > MAX_HANDSHAKE_BYTES):
                self._fault_locked()
                raise GatewayWorkerTLSError("TLS handshake byte budget exceeded")
            return data

    def feed_encrypted(self, data):
        with self._lock:
            self._require_live_locked()
            if self._handshake_done:
                self._assert_live_locked()
            if type(data) is not bytes or not data or len(data) > MAX_CHUNK_BYTES:
                self._fault_locked()
                raise GatewayWorkerTLSError("encrypted input chunk is empty or exceeds its bound")
            if self.__incoming.pending + len(data) > MAX_PENDING_BIO_BYTES:
                self._fault_locked()
                raise GatewayWorkerTLSError("TLS input BIO exceeds its bound")
            if not self._handshake_done and (
                    self._sent_bytes + self._received_bytes + len(data) > MAX_HANDSHAKE_BYTES):
                self._fault_locked()
                raise GatewayWorkerTLSError("TLS handshake byte budget exceeded")
            try:
                self._received_bytes += len(data)
                self.__incoming.write(data)
                self._drive_handshake_locked()
                if self._handshake_done:
                    self._assert_live_locked()
            except BaseException:
                self._fault_locked()
                raise

    def do_handshake(self):
        with self._lock:
            self._require_live_locked()
            self._drive_handshake_locked()
            return self._handshake_done

    def write_plaintext(self, data):
        with self._lock:
            self._assert_live_locked()
            if type(data) is not bytes or not data or len(data) > MAX_CHUNK_BYTES:
                self._fault_locked()
                raise GatewayWorkerTLSError("TLS plaintext is empty or exceeds its bound")
            try:
                written = self.__ssl.write(data)
                self._check_output_locked()
                self._assert_live_locked()
                return written
            except BaseException:
                self._fault_locked()
                raise

    def read_plaintext(self, maximum=MAX_CHUNK_BYTES):
        with self._lock:
            self._assert_live_locked()
            if type(maximum) is not int or not 1 <= maximum <= MAX_CHUNK_BYTES:
                raise ValueError("TLS plaintext read exceeds the bound")
            try:
                try:
                    result = self.__ssl.read(maximum)
                except (ssl.SSLWantReadError, ssl.SSLWantWriteError):
                    result = None
                except ssl.SSLZeroReturnError:
                    self._fault_locked()
                    return b""
                self._check_output_locked()
                self._assert_live_locked()
                if result == b"":
                    self._fault_locked()
                return result
            except BaseException:
                self._fault_locked()
                raise

    def poll_unavailable(self):
        with self._lock:
            try:
                self._assert_live_locked()
                return False
            except GatewayWorkerTLSError:
                self._fault_locked()
                return True

    def assert_channel_live(self, channel):
        with self._lock:
            if channel is not self._channel or not is_authenticated_worker_channel(channel):
                raise GatewayWorkerTLSError("worker channel record is not owned here")
            self._assert_live_locked()

    def _channel_deadline(self, channel):
        with self._lock:
            if channel is not self._channel or not is_authenticated_worker_channel(channel):
                raise GatewayWorkerTLSError("worker channel record is not owned here")
            self._assert_live_locked()
            return self._deadline

    def close(self):
        with self._lock:
            if self._closed and self._cleanup_status == "uncertain":
                return
            self._closed = True
            self.__ssl = None
            self.__context = None
            self.__incoming = None
            self.__outgoing = None
            self._channel = None
            self._remove_credentials_locked()

    def _drive_handshake_locked(self):
        if self._handshake_done:
            self._assert_live_locked()
            return
        sample = self._sample_clock_locked()
        if sample.monotonic >= self._started + MAX_HANDSHAKE_SECONDS:
            self._fault_locked()
            raise GatewayWorkerTLSError("TLS handshake deadline exceeded")
        was_handshaking = not self._handshake_done
        try:
            self.__ssl.do_handshake()
            self._handshake_done = True
        except (ssl.SSLWantReadError, ssl.SSLWantWriteError):
            pass
        except BaseException as error:
            self._fault_locked()
            raise GatewayWorkerTLSError("worker TLS handshake failed") from error
        self._check_output_locked(handshake=was_handshaking)
        if self._handshake_done:
            self._authenticate_peer_locked()

    def _authenticate_peer_locked(self):
        try:
            der = self.__ssl.getpeercert(binary_form=True)
            if type(der) is not bytes or not der:
                raise GatewayWorkerTLSError("TLS peer did not present a verified certificate")
            cert = x509.load_der_x509_certificate(der)
            identity = _worker_uri_identity(cert)
            view, sample = self.policy_store.current_with_sample()
            if (view.revision != self._view.revision
                    or view.policy_digest != self._view.policy_digest):
                raise GatewayWorkerTLSError("channel policy changed during TLS handshake")
            profile = verify_channel_certificate(
                cert.public_bytes(serialization.Encoding.PEM), self._ca_pem,
                kind="worker_stream", expected_identity=identity, now=sample.wall,
                uncertainty_seconds=sample.uncertainty, required_eku={"client"})
            matches = [(key, worker) for key, worker in view.workers.items()
                       if worker["account_id"] == identity["account_id"]
                       and key[0] == identity["device_id"]
                       and worker["host_serial"] == identity["host_serial"]
                       and worker["host_credential_epoch"] == identity["credential_epoch"]
                       and worker["gateway_id"] == self.gateway_id
                       and worker["channel_serial"] == profile.serial
                       and worker["channel_certificate_sha256"] == profile.certificate_sha256
                       and worker["channel_public_key_sha256"] == profile.public_key_sha256]
            if len(matches) != 1:
                raise GatewayWorkerTLSError("TLS worker peer is not uniquely pinned by policy")
            worker_key, worker = matches[0]
            deadline = min(self._deadline, view.deadline_monotonic,
                           sample.monotonic + view.expires_at - sample.latest_wall,
                           sample.monotonic + profile.not_after.timestamp() - sample.latest_wall,
                           sample.monotonic + worker["not_after"] - sample.latest_wall,
                           sample.monotonic + self._gateway_record["not_after"]
                           - sample.latest_wall)
            if sample.monotonic >= deadline:
                raise GatewayWorkerTLSError("worker channel policy or certificate has expired")
            self._deadline = deadline
            self._view = view
            self._sample = sample
            self._peer_cert = cert
            record = AuthenticatedWorkerChannel(
                gateway_id=self.gateway_id,
                gateway_certificate_sha256=self._gateway_record["certificate_sha256"],
                account_id=worker["account_id"], device_id=worker_key[0],
                host_serial=worker["host_serial"],
                host_credential_epoch=worker["host_credential_epoch"],
                host_certificate_sha256=worker["host_certificate_sha256"],
                worker_boot_id=worker_key[1],
                assignment_id=worker["assignment_id"], model_id=worker["model_id"],
                channel_serial=profile.serial,
                channel_certificate_sha256=profile.certificate_sha256,
                channel_public_key_sha256=profile.public_key_sha256,
                policy_revision=view.revision, policy_digest=view.policy_digest,
                stream_generation=self._generation, _deadline_at_mint=deadline,
                _owner_ref=weakref.ref(self), _token=_TOKEN)
            with _MINT_LOCK:
                _CHANNELS.add(record)
            self._channel = record
            self._assert_live_locked()
        except BaseException as error:
            self._fault_locked()
            if isinstance(error, GatewayWorkerTLSError):
                raise
            raise GatewayWorkerTLSError("TLS peer worker authorization failed") from error

    def _assert_live_locked(self):
        self._require_live_locked()
        if not self._handshake_done:
            raise GatewayWorkerTLSError("worker TLS handshake is incomplete")
        try:
            view, sample = self.policy_store.current_with_sample()
        except Exception as error:
            self._fault_locked()
            raise GatewayWorkerTLSError("current channel policy or Clock is unavailable") from error
        if view.revision != self._view.revision or view.policy_digest != self._view.policy_digest:
            self._fault_locked()
            raise GatewayWorkerTLSError("channel policy changed; worker stream is retired")
        self._deadline = min(self._deadline, view.deadline_monotonic,
                             sample.monotonic + view.expires_at - sample.latest_wall,
                             sample.monotonic + self._gateway_record["not_after"]
                             - sample.latest_wall,
                             sample.monotonic + self._gateway_cert.not_valid_after_utc.timestamp()
                             - sample.latest_wall)
        if self._channel is not None:
            try:
                worker = view.worker(
                    self._channel.device_id, self._channel.worker_boot_id)
            except Exception:
                worker = None
            if (worker is None
                    or worker["channel_certificate_sha256"] != self._channel.channel_certificate_sha256
                    or worker["host_certificate_sha256"]
                    != self._channel.host_certificate_sha256
                    or worker["gateway_id"] != self.gateway_id):
                self._fault_locked()
                raise GatewayWorkerTLSError("worker channel authorization was revoked")
            self._deadline = min(self._deadline,
                                 sample.monotonic + worker["not_after"] - sample.latest_wall)
            if (self._peer_cert is None
                    or sample.earliest_wall < self._peer_cert.not_valid_before_utc.timestamp()):
                self._fault_locked()
                raise GatewayWorkerTLSError("worker certificate is not currently valid")
        if sample.earliest_wall < self._gateway_cert.not_valid_before_utc.timestamp():
            self._fault_locked()
            raise GatewayWorkerTLSError("gateway certificate is not currently valid")
        if sample.monotonic >= self._deadline:
            self._fault_locked()
            raise GatewayWorkerTLSError("worker TLS channel has expired")

    def _sample_clock_locked(self):
        try:
            return self.clock.sample()
        except Exception as error:
            self._fault_locked()
            raise GatewayWorkerTLSError("gateway TLS Clock is unavailable") from error

    def _check_output_locked(self, *, handshake=False):
        pending = self.__outgoing.pending
        if (pending > MAX_PENDING_BIO_BYTES
                or (handshake and self._sent_bytes + self._received_bytes + pending
                    > MAX_HANDSHAKE_BYTES)):
            self._fault_locked()
            raise GatewayWorkerTLSError("TLS output or handshake byte bound exceeded")

    def _require_live_locked(self):
        if self._closed or self._faulted:
            raise GatewayWorkerTLSError("gateway TLS owner is closed or faulted")

    def _fault_locked(self):
        self._faulted = True
        self._closed = True
        self.__ssl = None
        self.__context = None
        self.__incoming = None
        self.__outgoing = None
        self._channel = None
        self._remove_credentials_locked()

    def _remove_credentials_locked(self):
        if self._directory is None:
            if self._cleanup_status == "not_created":
                self._cleanup_status = "removed"
            return self._cleanup_status == "removed"
        try:
            shutil.rmtree(self._directory)
        except OSError:
            self._cleanup_status = "uncertain"
            return False
        self._directory = None
        self._cleanup_status = "removed"
        return True
