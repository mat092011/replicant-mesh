"""Owned inbound coordinator mTLS and C1/operator-route authentication.

The gateway proves its local channel credential to the connecting coordinator.
The coordinator is accepted only from the actual TLS peer certificate after its
C1 ``personal_coordinator`` enrollment and operator route pins are checked.
This prototype owns a MemoryBIO server transport; it does not provide sockets,
framing, worker dispatch, or readiness claims.

Its purpose-specific TLS shell mirrors the bounded worker server and reuses
that owner's exact-once private-file helper. It remains separate so worker and
coordinator peer profiles cannot be selected through a generic public factory.
"""

from __future__ import annotations

import ipaddress
import os
import shutil
import ssl
import threading
import weakref
from dataclasses import dataclass, field
from types import MappingProxyType

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from .authorization import (_verify_pinned_credential, authorize_scope)
from .channel_certificates import verify_channel_certificate
from .channel_policy import ChannelPolicyStore
from .channel_tls import (MAX_CHUNK_BYTES, MAX_HANDSHAKE_BYTES,
                          MAX_HANDSHAKE_SECONDS, MAX_PENDING_BIO_BYTES)
from .clock import Clock
from .errors import ScopeError, SecurityError
from .gateway_tls import _write_private_files
from .ids import validate_boot, validate_id
from .snapshot import SnapshotStore


class GatewayCoordinatorTLSError(SecurityError):
    """The coordinator TLS peer, enrollment, route, or lifetime is unavailable."""

    def __init__(self, message, *, cleanup_status=None, credential_directory=None):
        super().__init__(message)
        self.cleanup_status = cleanup_status
        self.credential_directory = credential_directory


_TOKEN = object()
_MINT_LOCK = threading.Lock()
_OWNERS = weakref.WeakSet()
_CHANNELS = weakref.WeakSet()
_GUARDS = weakref.WeakSet()


def is_owned_gateway_coordinator_tls(value):
    """Return true only for an owner minted by the fixed coordinator TLS factory."""
    if type(value) is not OwnedGatewayCoordinatorTLS:
        return False
    with _MINT_LOCK:
        return value in _OWNERS and value._token is _TOKEN


def _register_gateway_coordinator_tls_owner(value):
    """Register a freshly completed fixed-profile owner for internal consumers."""
    with _MINT_LOCK:
        _OWNERS.add(value)


def is_authenticated_coordinator_channel(value):
    if type(value) is not AuthenticatedCoordinatorChannel:
        return False
    with _MINT_LOCK:
        return value in _CHANNELS and value._token is _TOKEN


def is_coordinator_route_guard(value):
    if type(value) is not CoordinatorRouteGuard:
        return False
    with _MINT_LOCK:
        return value in _GUARDS and value._token is _TOKEN


def _endpoint_names(host):
    try:
        return None, str(ipaddress.ip_address(host))
    except ValueError:
        return host, None


def _pem_from_der(der):
    try:
        return x509.load_der_x509_certificate(der).public_bytes(serialization.Encoding.PEM)
    except Exception as error:
        raise GatewayCoordinatorTLSError("TLS coordinator certificate is malformed") from error


def _credential_time_deadline(sample, not_after):
    return sample.monotonic + float(not_after) - sample.latest_wall


@dataclass(frozen=True, eq=False)
class AuthenticatedCoordinatorChannel:
    """Identity-only capability for one enrolled coordinator TLS connection."""

    gateway_id: str
    gateway_certificate_sha256: str
    actor_account_id: str
    actor_device_id: str
    actor_serial: str
    actor_credential_epoch: int
    actor_certificate_sha256: str
    actor_certificate_pem: bytes
    coordinator_boot_id: str
    tenant_account_id: str
    policy_revision: int
    policy_digest: str
    stream_generation: str
    _owner_ref: object = field(repr=False, compare=False)
    _token: object = field(repr=False, compare=False)

    def assert_live(self):
        if not is_authenticated_coordinator_channel(self):
            raise GatewayCoordinatorTLSError("coordinator channel is not owner-minted")
        owner = self._owner_ref()
        if owner is None:
            raise GatewayCoordinatorTLSError("coordinator TLS owner is unavailable")
        owner.assert_channel_live(self)

    def authorize_route(self, *, method, target_device_id, worker_boot_id,
                        assignment_id, model_id):
        if not is_authenticated_coordinator_channel(self):
            raise GatewayCoordinatorTLSError("coordinator channel is not owner-minted")
        owner = self._owner_ref()
        if owner is None:
            raise GatewayCoordinatorTLSError("coordinator TLS owner is unavailable")
        return owner.authorize_route(
            self, method=method, target_device_id=target_device_id,
            worker_boot_id=worker_boot_id, assignment_id=assignment_id,
            model_id=model_id)


class CoordinatorRouteGuard:
    """Immutable owner-minted route result with live C1 and policy rechecks."""

    __slots__ = ("_owner_ref", "_channel", "_key", "_method", "_deadline",
                 "_token", "__weakref__")

    def __init__(self, token, owner, channel, key, method, deadline):
        if token is not _TOKEN:
            raise TypeError("coordinator route guards are owner-minted")
        object.__setattr__(self, "_owner_ref", weakref.ref(owner))
        object.__setattr__(self, "_channel", channel)
        object.__setattr__(self, "_key", key)
        object.__setattr__(self, "_method", method)
        object.__setattr__(self, "_deadline", deadline)
        object.__setattr__(self, "_token", token)

    def __setattr__(self, _name, _value):
        raise AttributeError("coordinator route guards are immutable")

    @property
    def deadline_monotonic(self):
        return self.assert_live()

    @property
    def target_device_id(self):
        return self._key[0]

    @property
    def worker_boot_id(self):
        return self._key[1]

    @property
    def assignment_id(self):
        return self._key[2]

    @property
    def model_id(self):
        return self._key[3]

    @property
    def method(self):
        return self._method

    def assert_live(self):
        if not is_coordinator_route_guard(self):
            raise GatewayCoordinatorTLSError("coordinator route guard is not owner-minted")
        owner = self._owner_ref()
        if owner is None:
            raise GatewayCoordinatorTLSError("coordinator TLS owner is unavailable")
        return owner._assert_guard_live(self)


class OwnedGatewayCoordinatorTLS:
    """Own a TLS server generation and authenticate its actual C1 coordinator."""

    def __init__(self, token, *, context, incoming, outgoing, ssl_object,
                 snapshot_store, policy_store, clock, gateway_id, gateway_record,
                 gateway_certificate, gateway_ca_pem, coordinator_boot_id,
                 tenant_account_id, target_certificates, started, directory):
        if token is not _TOKEN:
            raise TypeError("use OwnedGatewayCoordinatorTLS.accept()")
        self.__context = context
        self.__incoming = incoming
        self.__outgoing = outgoing
        self.__ssl = ssl_object
        self.snapshot_store = snapshot_store
        self.policy_store = policy_store
        self.clock = clock
        self.gateway_id = gateway_id
        self._gateway_record = gateway_record
        self._gateway_certificate = gateway_certificate
        self._gateway_ca_pem = gateway_ca_pem
        self.coordinator_boot_id = coordinator_boot_id
        self.tenant_account_id = tenant_account_id
        self._target_certificates = target_certificates
        self._started = started
        self._deadline = float("inf")
        self._policy_view = None
        self._snapshot_view = None
        self._actor = None
        self._actor_pem = None
        self._actor_certificate = None
        self._channel = None
        self._generation = os.urandom(16).hex()
        self._lock = threading.RLock()
        self._token = _TOKEN
        self._handshake_done = False
        self._closed = False
        self._faulted = False
        self._sent_bytes = 0
        self._received_bytes = 0
        self._directory = directory
        self._cleanup_status = "pending"

    @classmethod
    def accept(cls, *, gateway_certificate_pem, gateway_private_key_pem,
               gateway_ca_pem, snapshot_store: SnapshotStore,
               policy_store: ChannelPolicyStore, clock: Clock, gateway_id,
               coordinator_boot_id, tenant_account_id, target_certificates):
        """Create a purpose-fixed server; trust stores cannot be substituted."""
        if (type(snapshot_store) is not SnapshotStore
                or type(policy_store) is not ChannelPolicyStore or type(clock) is not Clock):
            raise TypeError("coordinator TLS requires exact core stores and Clock")
        if snapshot_store.clock is not clock or policy_store.clock is not clock:
            raise TypeError("coordinator TLS stores must share the exact Clock")
        validate_boot(coordinator_boot_id)
        tenant_account_id = validate_id(tenant_account_id, "acct")
        if (type(gateway_id) is not str or not gateway_id
                or type(target_certificates) is not dict or len(target_certificates) > 8):
            raise GatewayCoordinatorTLSError("coordinator gateway configuration is malformed")
        targets = {}
        for key, pem in target_certificates.items():
            if type(key) is not tuple or len(key) != 4:
                raise GatewayCoordinatorTLSError("configured worker route key is malformed")
            device_id = validate_id(key[0], "dev")
            boot_id = validate_boot(key[1])
            assignment_id = validate_id(key[2], "asg")
            if (type(key[3]) is not str or len(key[3]) != 64
                    or any(ch not in "0123456789abcdef" for ch in key[3])):
                raise GatewayCoordinatorTLSError("configured worker model fingerprint is malformed")
            if type(pem) is not bytes or not 1 <= len(pem) <= 64 * 1024:
                raise GatewayCoordinatorTLSError("configured target certificate exceeds its bound")
            targets[(device_id, boot_id, assignment_id, key[3])] = pem
        if len(targets) != len(target_certificates):
            raise GatewayCoordinatorTLSError("configured worker routes contain duplicates")
        gateway_certificate_pem = cls._bounded_pem(
            gateway_certificate_pem, "gateway certificate")
        gateway_private_key_pem = cls._bounded_pem(
            gateway_private_key_pem, "gateway private key")
        gateway_ca_pem = cls._bounded_pem(gateway_ca_pem, "gateway CA")
        try:
            gateway_root = x509.load_pem_x509_certificate(gateway_ca_pem)
            participant_root = x509.load_pem_x509_certificate(
                snapshot_store.ca_certificate_pem)
            if cls._spki(gateway_root.public_key()) == cls._spki(participant_root.public_key()):
                raise GatewayCoordinatorTLSError(
                    "gateway channel CA key must be distinct from participant CA")
        except GatewayCoordinatorTLSError:
            raise
        except Exception as error:
            raise GatewayCoordinatorTLSError("gateway channel CA input is malformed") from error
        try:
            local_cert = x509.load_pem_x509_certificate(gateway_certificate_pem)
            local_key = serialization.load_pem_private_key(gateway_private_key_pem,
                                                           password=None)
            if cls._spki(local_cert.public_key()) != cls._spki(local_key.public_key()):
                raise GatewayCoordinatorTLSError("gateway private key does not match its leaf")
            policy_view, sample = policy_store.current_with_sample()
            gateway = policy_view.gateway(gateway_id)
            if gateway is None:
                raise GatewayCoordinatorTLSError("gateway is absent from current channel policy")
            dns, ip = _endpoint_names(gateway["endpoint_host"])
            profile = verify_channel_certificate(
                gateway_certificate_pem, gateway_ca_pem, kind="gateway",
                expected_identity=gateway_id, now=sample.wall,
                uncertainty_seconds=sample.uncertainty,
                required_eku={"client", "server"}, expected_dns=dns, expected_ip=ip)
            if (profile.serial != gateway["serial"]
                    or profile.certificate_sha256 != gateway["certificate_sha256"]
                    or profile.public_key_sha256 != gateway["public_key_sha256"]):
                raise GatewayCoordinatorTLSError("local gateway certificate differs from policy")
        except GatewayCoordinatorTLSError:
            raise
        except Exception as error:
            raise GatewayCoordinatorTLSError("gateway channel credential is invalid") from error

        try:
            directory, paths = _write_private_files({
                "gateway.pem": gateway_certificate_pem,
                "gateway-key.pem": gateway_private_key_pem,
                "participant-ca.pem": snapshot_store.ca_certificate_pem,
            })
        except Exception as error:
            raise cls._translate_tls_error(error) from error
        context = None
        owner = None
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            context.maximum_version = ssl.TLSVersion.TLSv1_3
            context.verify_mode = ssl.CERT_REQUIRED
            if not hasattr(ssl, "OP_NO_RENEGOTIATION"):
                raise GatewayCoordinatorTLSError("TLS backend cannot disable renegotiation")
            context.options |= ssl.OP_NO_RENEGOTIATION
            context.post_handshake_auth = False
            context.load_verify_locations(cafile=paths["participant-ca.pem"])
            context.load_cert_chain(paths["gateway.pem"], paths["gateway-key.pem"])
            incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
            ssl_object = context.wrap_bio(incoming, outgoing, server_side=True)
            owner = cls(_TOKEN, context=context, incoming=incoming, outgoing=outgoing,
                        ssl_object=ssl_object, snapshot_store=snapshot_store,
                        policy_store=policy_store, clock=clock, gateway_id=gateway_id,
                        gateway_record=gateway, gateway_certificate=local_cert,
                        gateway_ca_pem=gateway_ca_pem,
                        coordinator_boot_id=coordinator_boot_id,
                        tenant_account_id=tenant_account_id,
                        target_certificates=MappingProxyType(targets),
                        started=sample.monotonic, directory=directory)
            owner._policy_view = policy_view
            owner._cleanup_status = "pending"
            try:
                shutil.rmtree(directory)
            except OSError as error:
                owner._mark_uncertain_cleanup_locked()
                raise GatewayCoordinatorTLSError(
                    "gateway TLS credential cleanup is uncertain",
                    cleanup_status="uncertain", credential_directory=directory) from error
            owner._directory = None
            owner._cleanup_status = "removed"
            owner._deadline = min(policy_view.deadline_monotonic,
                                  sample.monotonic + policy_view.expires_at - sample.latest_wall,
                                  sample.monotonic + gateway["not_after"] - sample.latest_wall,
                                  _credential_time_deadline(
                                      sample, profile.not_after.timestamp()))
            owner._drive_handshake_locked()
            _register_gateway_coordinator_tls_owner(owner)
            return owner
        except BaseException:
            if owner is not None:
                if owner._cleanup_status != "uncertain":
                    owner.close()
            else:
                try:
                    shutil.rmtree(directory)
                except OSError as error:
                    raise GatewayCoordinatorTLSError(
                        "gateway TLS credential cleanup is uncertain",
                        cleanup_status="uncertain", credential_directory=directory) from error
            raise

    @staticmethod
    def _spki(key):
        return key.public_bytes(serialization.Encoding.DER,
                                serialization.PublicFormat.SubjectPublicKeyInfo)

    @staticmethod
    def _bounded_pem(value, label):
        if type(value) is not bytes or not 1 <= len(value) <= 64 * 1024:
            raise GatewayCoordinatorTLSError(f"{label} input exceeds its bound")
        return value

    @staticmethod
    def _translate_tls_error(error):
        status = getattr(error, "cleanup_status", None)
        path = getattr(error, "credential_directory", None)
        return GatewayCoordinatorTLSError(
            "private gateway TLS credential setup failed",
            cleanup_status=status, credential_directory=path)

    @property
    def handshake_complete(self):
        with self._lock:
            return self._handshake_done and not self._closed and not self._faulted

    @property
    def is_live(self):
        with self._lock:
            if self._closed or self._faulted or not self._handshake_done:
                return False
            try:
                self._assert_live_locked()
                return True
            except GatewayCoordinatorTLSError:
                return False

    def assert_transport_live(self):
        """Check policy/clock liveness without taking ciphertext from the BIO."""
        with self._lock:
            self._require_open_locked()
            if self._handshake_done:
                self._assert_live_locked()
                return True
            sample = self._sample_clock_locked()
            if sample.monotonic >= self._started + MAX_HANDSHAKE_SECONDS:
                self._fault_locked()
                raise GatewayCoordinatorTLSError("TLS handshake deadline exceeded")
            try:
                current = self.policy_store.current()
            except Exception as error:
                self._fault_locked()
                raise GatewayCoordinatorTLSError("current channel policy is unavailable") from error
            if (current.revision != self._policy_view.revision
                    or current.policy_digest != self._policy_view.policy_digest):
                self._fault_locked()
                raise GatewayCoordinatorTLSError(
                    "channel policy changed during TLS handshake")
            return False

    @property
    def pending_encrypted_bytes(self):
        with self._lock:
            self._require_open_locked()
            return self.__outgoing.pending

    @property
    def authenticated_channel(self):
        with self._lock:
            if self._channel is None:
                raise GatewayCoordinatorTLSError("coordinator peer is not authenticated")
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

    def take_encrypted(self, maximum=MAX_CHUNK_BYTES):
        with self._lock:
            self._require_open_locked()
            if type(maximum) is not int or not 1 <= maximum <= MAX_CHUNK_BYTES:
                raise ValueError("encrypted output chunk exceeds its bound")
            if self._handshake_done:
                self._assert_live_locked()
            else:
                sample = self._sample_clock_locked()
                if sample.monotonic >= self._started + MAX_HANDSHAKE_SECONDS:
                    self._fault_locked()
                    raise GatewayCoordinatorTLSError("TLS handshake deadline exceeded")
            if self.__outgoing.pending > MAX_PENDING_BIO_BYTES:
                self._fault_locked()
                raise GatewayCoordinatorTLSError("TLS output BIO exceeds its bound")
            data = self.__outgoing.read(maximum)
            self._sent_bytes += len(data)
            self._check_handshake_bytes_locked()
            return data

    def feed_encrypted(self, data):
        with self._lock:
            self._require_open_locked()
            if self._handshake_done:
                self._assert_live_locked()
            if type(data) is not bytes or not data or len(data) > MAX_CHUNK_BYTES:
                self._fault_locked()
                raise GatewayCoordinatorTLSError("TLS input chunk is empty or exceeds its bound")
            if self.__incoming.pending + len(data) > MAX_PENDING_BIO_BYTES:
                self._fault_locked()
                raise GatewayCoordinatorTLSError("TLS input BIO exceeds its bound")
            if not self._handshake_done and (
                    self._sent_bytes + self._received_bytes + len(data) > MAX_HANDSHAKE_BYTES):
                self._fault_locked()
                raise GatewayCoordinatorTLSError("TLS handshake byte budget exceeded")
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
            self._require_open_locked()
            self._drive_handshake_locked()
            return self._handshake_done

    def write_plaintext(self, data):
        with self._lock:
            self._assert_live_locked()
            if type(data) is not bytes or not data or len(data) > MAX_CHUNK_BYTES:
                self._fault_locked()
                raise GatewayCoordinatorTLSError("TLS plaintext is empty or exceeds its bound")
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
                raise ValueError("TLS plaintext read exceeds its bound")
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
            except GatewayCoordinatorTLSError:
                self._fault_locked()
                return True

    def authorize_route(self, channel, *, method, target_device_id,
                        worker_boot_id, assignment_id, model_id):
        with self._lock:
            self._assert_channel_locked(channel)
            return self._mint_route_locked(
                channel, method=method, key=(target_device_id, worker_boot_id,
                                             assignment_id, model_id))

    def assert_channel_live(self, channel):
        with self._lock:
            self._assert_channel_locked(channel)

    def _assert_channel_locked(self, channel):
        if channel is not self._channel or not is_authenticated_coordinator_channel(channel):
            raise GatewayCoordinatorTLSError("coordinator channel is not owned here")
        self._assert_live_locked()

    def _mint_route_locked(self, channel, *, method, key):
        from .codec import WORKER_METHODS, WORKER_SERVICE
        self._assert_channel_locked(channel)
        if type(method) is not str or method not in WORKER_METHODS:
            raise GatewayCoordinatorTLSError("method is not a supported worker operation")
        target_pem = self._target_certificates.get(key)
        if target_pem is None:
            raise GatewayCoordinatorTLSError("target is not in the trusted configured map")
        try:
            scope = authorize_scope(
                self.snapshot_store, self.clock, service=WORKER_SERVICE, method=method,
                actor_certificate_pem=self._actor_pem,
                target_certificate_pem=target_pem,
                target_device_id=key[0], target_boot_id=key[1],
                actor_boot_id=self.coordinator_boot_id,
                assignment_id=key[2], model_id=key[3],
                tenant_account_id=self.tenant_account_id)
            view, sample = self.policy_store.current_with_sample()
            snapshot = self.snapshot_store.current(sample=sample)
            actor = _verify_pinned_credential(
                self.snapshot_store, self._actor_pem, snapshot, sample)
            target = _verify_pinned_credential(
                self.snapshot_store, target_pem, snapshot, sample)
            if (view.revision != self._policy_view.revision
                    or view.policy_digest != self._policy_view.policy_digest):
                raise GatewayCoordinatorTLSError("operator route policy changed")
            route = view.route(
                gateway_id=self.gateway_id, account_id=actor.account_id,
                device_id=actor.device_id, actor_serial=actor.serial,
                actor_credential_epoch=actor.credential_epoch,
                actor_certificate_sha256=actor.certificate_sha256,
                coordinator_boot_id=self.coordinator_boot_id,
                tenant_account_id=self.tenant_account_id,
                target_device_id=target.device_id, worker_boot_id=key[1],
                assignment_id=key[2], model_id=key[3], method=method)
            worker = view.worker(key[0], key[1])
            if (route is None or worker is None
                    or actor.role != "personal_coordinator"
                    or actor.certificate_pem != self._actor_pem
                    or actor.certificate_sha256 != channel.actor_certificate_sha256
                    or actor.account_id != self.tenant_account_id
                    or target.role != "host" or target.device_id != key[0]
                    or worker["account_id"] != target.account_id
                    or worker["host_serial"] != target.serial
                    or worker["host_credential_epoch"] != target.credential_epoch
                    or worker["host_certificate_sha256"] != target.certificate_sha256
                    or worker["assignment_id"] != key[2]
                    or worker["model_id"] != key[3]
                    or worker["gateway_id"] != self.gateway_id):
                raise GatewayCoordinatorTLSError(
                    "C1 scope does not match the exact operator worker route")
            grant = scope.grant
            deadline = min(self._deadline, view.deadline_monotonic,
                           snapshot.deadline_monotonic, scope.view.deadline_monotonic,
                           snapshot.credential_deadlines[actor.serial],
                           snapshot.credential_deadlines[target.serial],
                           snapshot.grant_deadlines[grant.identity],
                           _credential_time_deadline(sample, grant.not_after),
                           _credential_time_deadline(sample, actor.record.not_after),
                           _credential_time_deadline(sample, target.record.not_after))
            if sample.monotonic >= deadline:
                raise GatewayCoordinatorTLSError("coordinator route authorization has expired")
            guard = CoordinatorRouteGuard(_TOKEN, self, channel, key, method, deadline)
            with _MINT_LOCK:
                _GUARDS.add(guard)
            return guard
        except Exception as error:
            self._fault_locked()
            if isinstance(error, GatewayCoordinatorTLSError):
                raise
            if isinstance(error, ScopeError):
                raise GatewayCoordinatorTLSError("C1 coordinator/worker scope is unavailable") from error
            raise GatewayCoordinatorTLSError("coordinator route authorization failed") from error

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

    def __copy__(self):
        raise TypeError("gateway coordinator TLS owners cannot be copied")

    def __deepcopy__(self, _memo):
        raise TypeError("gateway coordinator TLS owners cannot be copied")

    def _drive_handshake_locked(self):
        if self._handshake_done:
            self._assert_live_locked()
            return
        sample = self._sample_clock_locked()
        if sample.monotonic >= self._started + MAX_HANDSHAKE_SECONDS:
            self._fault_locked()
            raise GatewayCoordinatorTLSError("TLS handshake deadline exceeded")
        try:
            self.__ssl.do_handshake()
            self._handshake_done = True
        except (ssl.SSLWantReadError, ssl.SSLWantWriteError):
            pass
        except BaseException as error:
            self._fault_locked()
            raise GatewayCoordinatorTLSError("coordinator TLS handshake failed") from error
        self._check_output_locked(handshake=True)
        if self._handshake_done:
            self._authenticate_peer_locked()

    def _authenticate_peer_locked(self):
        try:
            # Admission is bound to the policy snapshot captured when this TLS
            # owner was created. A policy installed during the handshake must
            # retire the flight instead of authorizing its old gateway pin under
            # a newer route set.
            captured = self._policy_view
            current, _ = self.policy_store.current_with_sample()
            if (captured is None or current.revision != captured.revision
                    or current.policy_digest != captured.policy_digest):
                raise GatewayCoordinatorTLSError(
                    "channel policy changed during coordinator TLS handshake")
            der = self.__ssl.getpeercert(binary_form=True)
            if type(der) is not bytes or not der:
                raise GatewayCoordinatorTLSError("TLS peer did not present a client certificate")
            pem = _pem_from_der(der)
            policy, sample = self.policy_store.current_with_sample()
            if (policy.revision != captured.revision
                    or policy.policy_digest != captured.policy_digest):
                raise GatewayCoordinatorTLSError(
                    "channel policy changed during coordinator TLS handshake")
            snapshot = self.snapshot_store.current(sample=sample)
            actor = _verify_pinned_credential(self.snapshot_store, pem, snapshot, sample)
            if (actor.role != "personal_coordinator"
                    or actor.account_id != self.tenant_account_id):
                raise GatewayCoordinatorTLSError(
                    "TLS peer is not the configured tenant personal coordinator")
            routes = [route for route in policy.routes
                      if route[0] == self.gateway_id
                      and route[1] == actor.account_id
                      and route[2] == actor.device_id
                      and route[3] == actor.serial
                      and route[4] == actor.credential_epoch
                      and route[5] == actor.certificate_sha256
                      and route[6] == self.coordinator_boot_id
                      and route[7] == self.tenant_account_id]
            allowed = []
            for route in routes:
                key = (route[8], route[9], route[10], route[11])
                worker = policy.worker(key[0], key[1])
                if (key not in self._target_certificates or worker is None
                        or worker["assignment_id"] != key[2]
                        or worker["model_id"] != key[3]
                        or worker["gateway_id"] != self.gateway_id):
                    continue
                allowed.append(route)
            if not allowed:
                raise GatewayCoordinatorTLSError(
                    "operator policy has no configured route for this coordinator")
            cert = actor.certificate
            deadline = min(self._deadline, policy.deadline_monotonic,
                           sample.monotonic + policy.expires_at - sample.latest_wall,
                           snapshot.deadline_monotonic,
                           snapshot.credential_deadlines[actor.serial],
                           _credential_time_deadline(sample, actor.record.not_after),
                           sample.monotonic + cert.not_valid_after_utc.timestamp()
                           - sample.latest_wall,
                           sample.monotonic + self._gateway_record["not_after"]
                           - sample.latest_wall,
                           sample.monotonic
                           + self._gateway_certificate.not_valid_after_utc.timestamp()
                           - sample.latest_wall)
            if sample.monotonic >= deadline:
                raise GatewayCoordinatorTLSError("coordinator channel authorization expired")
            self._actor_pem = pem
            self._actor = actor
            self._actor_certificate = cert
            self._snapshot_view = snapshot
            self._deadline = deadline
            channel = AuthenticatedCoordinatorChannel(
                gateway_id=self.gateway_id,
                gateway_certificate_sha256=self._gateway_record["certificate_sha256"],
                actor_account_id=actor.account_id, actor_device_id=actor.device_id,
                actor_serial=actor.serial,
                actor_credential_epoch=actor.credential_epoch,
                actor_certificate_sha256=actor.certificate_sha256,
                actor_certificate_pem=pem,
                coordinator_boot_id=self.coordinator_boot_id,
                tenant_account_id=self.tenant_account_id,
                policy_revision=policy.revision, policy_digest=policy.policy_digest,
                stream_generation=self._generation,
                _owner_ref=weakref.ref(self), _token=_TOKEN)
            with _MINT_LOCK:
                _CHANNELS.add(channel)
            self._channel = channel
            self._assert_live_locked()
        except BaseException as error:
            self._fault_locked()
            if isinstance(error, GatewayCoordinatorTLSError):
                raise
            raise GatewayCoordinatorTLSError("C1 coordinator TLS authentication failed") from error

    def _assert_live_locked(self):
        self._require_open_locked()
        if not self._handshake_done or self._channel is None:
            raise GatewayCoordinatorTLSError("coordinator TLS peer is not authenticated")
        try:
            policy, sample = self.policy_store.current_with_sample()
            snapshot = self.snapshot_store.current(sample=sample)
            actor = _verify_pinned_credential(
                self.snapshot_store, self._actor_pem, snapshot, sample)
        except Exception as error:
            self._fault_locked()
            raise GatewayCoordinatorTLSError(
                "coordinator policy, snapshot, or Clock is unavailable") from error
        if (policy.revision != self._policy_view.revision
                or policy.policy_digest != self._policy_view.policy_digest):
            self._fault_locked()
            raise GatewayCoordinatorTLSError("channel policy changed; reconnect required")
        if (actor.role != "personal_coordinator"
                or actor.account_id != self.tenant_account_id
                or actor.device_id != self._channel.actor_device_id
                or actor.serial != self._channel.actor_serial
                or actor.credential_epoch != self._channel.actor_credential_epoch
                or actor.certificate_sha256 != self._channel.actor_certificate_sha256):
            self._fault_locked()
            raise GatewayCoordinatorTLSError("coordinator C1 credential was revoked or replaced")
        self._deadline = min(self._deadline, policy.deadline_monotonic,
                             sample.monotonic + policy.expires_at - sample.latest_wall,
                             snapshot.deadline_monotonic,
                             snapshot.credential_deadlines[actor.serial],
                             _credential_time_deadline(sample, actor.record.not_after),
                             sample.monotonic
                             + self._actor_certificate.not_valid_after_utc.timestamp()
                             - sample.latest_wall,
                             sample.monotonic + self._gateway_record["not_after"]
                             - sample.latest_wall,
                             sample.monotonic
                             + self._gateway_certificate.not_valid_after_utc.timestamp()
                             - sample.latest_wall)
        if (sample.earliest_wall < self._actor_certificate.not_valid_before_utc.timestamp()
                or sample.earliest_wall
                < self._gateway_certificate.not_valid_before_utc.timestamp()
                or sample.monotonic >= self._deadline):
            self._fault_locked()
            raise GatewayCoordinatorTLSError("coordinator TLS channel is outside its validity")
        self._snapshot_view = snapshot

    def _assert_guard_current(self, _guard):
        raise NotImplementedError

    def _sample_clock_locked(self):
        try:
            return self.clock.sample()
        except Exception as error:
            self._fault_locked()
            raise GatewayCoordinatorTLSError("coordinator TLS Clock is unavailable") from error

    def _check_output_locked(self, *, handshake=False):
        pending = self.__outgoing.pending
        if (pending > MAX_PENDING_BIO_BYTES
                or (handshake and self._sent_bytes + self._received_bytes + pending
                    > MAX_HANDSHAKE_BYTES)):
            self._fault_locked()
            raise GatewayCoordinatorTLSError("TLS output or handshake bound exceeded")

    def _check_handshake_bytes_locked(self):
        if (not self._handshake_done
                and self._sent_bytes + self._received_bytes > MAX_HANDSHAKE_BYTES):
            self._fault_locked()
            raise GatewayCoordinatorTLSError("TLS handshake byte budget exceeded")

    def _require_open_locked(self):
        if self._closed or self._faulted:
            raise GatewayCoordinatorTLSError("coordinator TLS owner is closed or faulted")

    def _fault_locked(self):
        if self._closed and self._cleanup_status == "uncertain":
            return
        self._faulted = True
        self._closed = True
        self.__ssl = None
        self.__context = None
        self.__incoming = None
        self.__outgoing = None
        self._channel = None
        self._remove_credentials_locked()

    def _mark_uncertain_cleanup_locked(self):
        self._faulted = True
        self._closed = True
        self.__ssl = None
        self.__context = None
        self.__incoming = None
        self.__outgoing = None
        self._cleanup_status = "uncertain"

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

    def _assert_guard_live(self, guard):
        with self._lock:
            if (not is_coordinator_route_guard(guard)
                    or guard._owner_ref() is not self
                    or guard._channel is not self._channel):
                raise GatewayCoordinatorTLSError("coordinator route guard is stale or foreign")
            try:
                self._assert_live_locked()
                fresh = self._mint_route_locked(
                    guard._channel, method=guard._method, key=guard._key)
                return min(guard._deadline, fresh._deadline, self._deadline)
            except Exception:
                self._fault_locked()
                raise
