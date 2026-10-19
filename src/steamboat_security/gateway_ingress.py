"""Authenticated TLS ingress from a configured C2 gateway to one worker.

This is a connection-bound authorization primitive, not a TLS engine, request
framer, readiness signal, or C1 grant/revocation check. The caller owns the
already-handshaken SSLObject and must keep this owner alive with bounded
heartbeat polling. A stream is permanently closed on uncertainty or identity
change; replacing it requires a new TLS connection and generation.
"""

from __future__ import annotations

import ipaddress
import secrets
import ssl
import threading
import weakref
from dataclasses import dataclass, field

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from .authorization import LocalIdentity
from .certificates import certificate_sha256, public_key_sha256, serial_hex
from .channel_certificates import verify_channel_certificate
from .errors import SecurityError
from .gateway_delegation import GatewayDelegationVerifier, VerifiedDelegation
from .sessions import SessionBindings


class GatewayIngressError(SecurityError):
    """The authenticated gateway ingress is malformed, unauthorized, or stale."""


MAX_FRAME_SEQUENCE = 2**63 - 1
HEARTBEAT_TIMEOUT_SECONDS = 60.0
_TLS_OWNER_LOCK = threading.Lock()
_TLS_OWNERS = weakref.WeakKeyDictionary()


def _pem_from_der(der: bytes) -> bytes:
    if type(der) is not bytes or not der:
        raise GatewayIngressError("TLS peer certificate is unavailable")
    try:
        cert = x509.load_der_x509_certificate(der)
    except ValueError as error:
        raise GatewayIngressError("TLS peer certificate is malformed") from error
    return cert.public_bytes(serialization.Encoding.PEM)


@dataclass
class _IngressState:
    lock: threading.RLock = field(default_factory=threading.RLock)
    closed: bool = False
    faulted: bool = False
    next_sequence: int = 1
    last_heartbeat: float = 0.0
    deadline: float = 0.0


@dataclass(frozen=True, eq=False)
class GatewayOperationGuard:
    """An operation verified on one concrete, live TLS generation."""

    delegation: VerifiedDelegation = field(repr=False)
    ingress_identity: tuple[str, str, str]
    _owner: object = field(repr=False, compare=False)
    _token: object = field(repr=False, compare=False)

    @property
    def deadline_monotonic(self):
        return self._owner._guard_deadline(self)

    def assert_live(self):
        return self._owner._assert_guard_live(self)


class GatewayWorkerIngress:
    """Owns one authenticated gateway TLS connection and its sequence space."""

    def __init__(self, *args, **kwargs):
        raise TypeError("use GatewayWorkerIngress.from_tls()")

    @classmethod
    def from_tls(cls, ssl_object, *, verifier: GatewayDelegationVerifier,
                 sessions: SessionBindings, gateway_id: str,
                 local_worker_channel_certificate_pem: bytes):
        if type(ssl_object) is not ssl.SSLObject:
            raise TypeError("a real completed TLS SSLObject is required")
        if (type(verifier) is not GatewayDelegationVerifier
                or type(sessions) is not SessionBindings
                or sessions.clock is not verifier.clock
                or type(verifier.local_identity) is not LocalIdentity):
            raise TypeError("ingress requires exact verifier, session, and identity owners")
        context = ssl_object.context
        if (ssl_object.server_side is not False
                or ssl_object.server_hostname != verifier.endpoint_host
                or context.verify_mode is not ssl.CERT_REQUIRED
                or context.check_hostname is not True):
            raise GatewayIngressError("TLS object is not a verified client connection to the fixed endpoint")
        with _TLS_OWNER_LOCK:
            if ssl_object in _TLS_OWNERS:
                raise GatewayIngressError("TLS connection already has an ingress owner")
        try:
            peer_pem = _pem_from_der(ssl_object.getpeercert(binary_form=True))
            view, sample = verifier.policy_store.current_with_sample()
            gateway = view.gateway(gateway_id)
            local = verifier.local_identity
            worker = view.worker(_identity_device(local, view), local.boot_id)
            if gateway is None or worker is None or worker["gateway_id"] != gateway_id:
                raise GatewayIngressError("gateway or local worker is absent from current policy")
            if (worker["model_id"] != local.model_id
                    or worker["assignment_id"] != local.assignment_id):
                raise GatewayIngressError("local worker assignment differs from current policy")
            try:
                ipaddress.ip_address(verifier.endpoint_host)
                expected_dns, expected_ip = None, verifier.endpoint_host
            except ValueError:
                expected_dns, expected_ip = verifier.endpoint_host, None
            gateway_cert = verify_channel_certificate(
                peer_pem, verifier.gateway_ca_pem, kind="gateway",
                expected_identity=gateway_id, now=sample.wall,
                uncertainty_seconds=sample.uncertainty,
                required_eku={"client", "server"}, expected_dns=expected_dns,
                expected_ip=expected_ip)
            if (gateway_cert.certificate_sha256 != gateway["certificate_sha256"]
                    or gateway_cert.serial != gateway["serial"]
                    or gateway_cert.public_key_sha256 != gateway["public_key_sha256"]
                    or gateway["endpoint_host"] != verifier.endpoint_host
                    or gateway["endpoint_port"] != verifier.endpoint_port):
                raise GatewayIngressError("TLS gateway certificate is not current-policy pinned")
            worker_cert = verify_channel_certificate(
                local_worker_channel_certificate_pem, verifier.gateway_ca_pem,
                kind="worker_stream", expected_identity={
                    "account_id": worker["account_id"], "device_id": _worker_device(view, local),
                    "host_serial": worker["host_serial"],
                    "credential_epoch": worker["host_credential_epoch"]},
                now=sample.wall, uncertainty_seconds=sample.uncertainty,
                required_eku={"client"})
            if (worker_cert.certificate_sha256 != worker["channel_certificate_sha256"]
                    or worker_cert.serial != worker["channel_serial"]
                    or worker_cert.public_key_sha256 != worker["channel_public_key_sha256"]):
                raise GatewayIngressError("local worker channel credential is not policy-pinned")
            deadline = min(
                view.deadline_monotonic,
                sample.monotonic + view.expires_at - sample.latest_wall,
                sample.monotonic + gateway_cert.not_after.timestamp() - sample.latest_wall,
                sample.monotonic + worker_cert.not_after.timestamp() - sample.latest_wall,
            )
            if deadline <= sample.monotonic:
                raise GatewayIngressError("gateway ingress has no conservative live interval")
            ingress = cls.__new__(cls)
            ingress._ssl_object = ssl_object
            ingress.verifier = verifier
            ingress.sessions = sessions
            ingress.clock = verifier.clock
            ingress.gateway_id = gateway_id
            ingress.gateway_certificate_pem = peer_pem
            ingress.gateway_certificate_sha256 = gateway_cert.certificate_sha256
            ingress.worker_channel_certificate_pem = local_worker_channel_certificate_pem
            ingress._local_identity = local
            ingress.worker_identity = (_worker_device(view, local), local.boot_id)
            ingress.policy_revision = view.revision
            ingress.policy_digest = view.policy_digest
            ingress.stream_generation = secrets.token_hex(16)
            ingress.ingress_identity = ("gateway-v1", gateway_cert.certificate_sha256,
                                        ingress.stream_generation)
            ingress._state = _IngressState(last_heartbeat=sample.monotonic,
                                           deadline=deadline)
            ingress._guard_token = object()
            ingress._guards = weakref.WeakSet()
            ingress._fault_reason = None
            with _TLS_OWNER_LOCK:
                if ssl_object in _TLS_OWNERS:
                    raise GatewayIngressError("TLS connection already has an ingress owner")
                _TLS_OWNERS[ssl_object] = ingress.stream_generation
            return ingress
        except GatewayIngressError:
            raise
        except Exception as error:
            raise GatewayIngressError("gateway TLS ingress could not be authorized") from error

    def _policy_and_worker(self):
        if self._state.closed or self._state.faulted:
            raise GatewayIngressError("gateway TLS generation is closed")
        local = self.verifier.local_identity
        captured = self._local_identity
        if (type(local) is not LocalIdentity
                or local.certificate_pem != captured.certificate_pem
                or local.boot_id != captured.boot_id or local.model_id != captured.model_id
                or local.assignment_id != captured.assignment_id):
            raise GatewayIngressError("local worker identity was replaced")
        view, sample = self.verifier.policy_store.current_with_sample()
        if (view.revision != self.policy_revision
                or view.policy_digest != self.policy_digest):
            raise GatewayIngressError("policy changed; this TLS generation is retired")
        worker = view.worker(*self.worker_identity)
        gateway = view.gateway(self.gateway_id)
        if worker is None or gateway is None or worker["gateway_id"] != self.gateway_id:
            raise GatewayIngressError("worker or gateway was removed from policy")
        self._verify_live_pins(view, worker, gateway, sample)
        self._state.deadline = min(
            self._state.deadline,
            view.deadline_monotonic,
            sample.monotonic + view.expires_at - sample.latest_wall,
        )
        return view, worker, gateway, sample

    def _close_locked(self, reason):
        if not self._state.closed:
            self._state.closed = True
            self._state.faulted = True
            self._fault_reason = reason
            return self.sessions.invalidate_ingress(self.ingress_identity, reason)
        return 0

    def close(self, reason="gateway-stream-lost"):
        allowed = {"gateway-stream-lost", "gateway-heartbeat-timeout",
                   "gateway-policy-changed", "gateway-invalid-frame",
                   "gateway-clock-fault", "gateway-identity-changed"}
        if reason not in allowed:
            raise ValueError("gateway ingress close reason is not in the bounded vocabulary")
        with self._state.lock:
            return self._close_locked(reason)

    def poll_unavailable(self):
        """Bounded liveness poll for an integration-owned <=5s monitor loop."""
        try:
            with self._state.lock:
                _view, _worker, _gateway, sample = self._policy_and_worker()
                if sample.monotonic - self._state.last_heartbeat >= HEARTBEAT_TIMEOUT_SECONDS:
                    raise GatewayIngressError("gateway heartbeat timed out")
                if sample.monotonic >= self._state.deadline:
                    raise GatewayIngressError("gateway ingress expired")
                return False
        except Exception as error:
            self.close("gateway-heartbeat-timeout" if "heartbeat" in str(error)
                       else "gateway-policy-changed" if "policy" in str(error)
                       else "gateway-clock-fault")
            return True

    def heartbeat(self, generation: str, sequence: int):
        with self._state.lock:
            self._consume_locked(generation, sequence)
            try:
                _view, _worker, _gateway, sample = self._policy_and_worker()
                if sample.monotonic >= self._state.deadline:
                    raise GatewayIngressError("gateway ingress expired")
                self._state.last_heartbeat = sample.monotonic
                return True
            except Exception as error:
                self._close_locked("gateway-policy-changed" if "policy" in str(error)
                                   else "gateway-clock-fault")
                raise GatewayIngressError("gateway heartbeat could not be accepted") from error

    def _consume_locked(self, generation, sequence):
        if self._state.closed or self._state.faulted:
            raise GatewayIngressError("gateway TLS generation is closed")
        if (generation != self.stream_generation
                or type(sequence) is not int or sequence != self._state.next_sequence
                or sequence > MAX_FRAME_SEQUENCE):
            self._close_locked("gateway-invalid-frame")
            raise GatewayIngressError("gateway frame generation or sequence is invalid")
        self._state.next_sequence += 1

    def verify_operation(self, envelope, metadata, raw_request_bytes, frame_sequence):
        with self._state.lock:
            self._consume_locked(self.stream_generation, frame_sequence)
            try:
                delegation = self.verifier.verify(
                    envelope, gateway_peer_certificate_pem=self.gateway_certificate_pem,
                    metadata=metadata, request_bytes=raw_request_bytes,
                    expected_stream_generation=self.stream_generation,
                    expected_frame_sequence=frame_sequence)
                if delegation.ingress_identity != self.ingress_identity:
                    raise GatewayIngressError("delegation escaped its TLS generation")
                guard = GatewayOperationGuard(delegation, self.ingress_identity,
                                              self, self._guard_token)
                self._guards.add(guard)
                return guard
            except Exception as error:
                self._close_locked("gateway-invalid-frame")
                raise GatewayIngressError("gateway operation was rejected") from error

    def _guard_deadline(self, guard):
        if type(guard) is not GatewayOperationGuard or guard._owner is not self:
            raise GatewayIngressError("gateway operation guard is not owned by this ingress")
        self._assert_guard_live(guard)
        with self._state.lock:
            if (guard not in self._guards or guard._token is not self._guard_token
                    or self._state.closed):
                return float("-inf")
            return min(self._state.deadline, self._state.last_heartbeat + HEARTBEAT_TIMEOUT_SECONDS,
                       guard.delegation.deadline_monotonic)

    def _assert_guard_live(self, guard):
        if type(guard) is not GatewayOperationGuard or guard._owner is not self:
            raise GatewayIngressError("gateway operation guard is not owned by this ingress")
        try:
            with self._state.lock:
                if (guard not in self._guards or guard._token is not self._guard_token
                        or self._state.closed):
                    raise GatewayIngressError("gateway operation guard is retired")
                _view, _worker, _gateway, sample = self._policy_and_worker()
                if sample.monotonic >= min(
                        self._state.deadline,
                        self._state.last_heartbeat + HEARTBEAT_TIMEOUT_SECONDS,
                        guard.delegation.deadline_monotonic):
                    raise GatewayIngressError("gateway operation guard has expired")
                guard.delegation.assert_live(self.verifier)
                return True
        except Exception as error:
            self.close("gateway-policy-changed" if "policy" in str(error)
                       else "gateway-clock-fault")
            raise GatewayIngressError("gateway operation is no longer live") from error

    def _verify_live_pins(self, view, worker, gateway, sample):
        channel = verify_channel_certificate(
            self.gateway_certificate_pem, self.verifier.gateway_ca_pem,
            kind="gateway", expected_identity=self.gateway_id,
            now=sample.wall, uncertainty_seconds=sample.uncertainty,
            required_eku={"client", "server"},
            expected_dns=self.verifier.endpoint_host if not _is_ip(self.verifier.endpoint_host) else None,
            expected_ip=self.verifier.endpoint_host if _is_ip(self.verifier.endpoint_host) else None)
        local = verify_channel_certificate(
            self.worker_channel_certificate_pem, self.verifier.gateway_ca_pem,
            kind="worker_stream", expected_identity={
                "account_id": worker["account_id"], "device_id": self.worker_identity[0],
                "host_serial": worker["host_serial"],
                "credential_epoch": worker["host_credential_epoch"]},
            now=sample.wall, uncertainty_seconds=sample.uncertainty,
            required_eku={"client"})
        if (channel.certificate_sha256 != gateway["certificate_sha256"]
                or channel.serial != gateway["serial"]
                or channel.public_key_sha256 != gateway["public_key_sha256"]
                or local.certificate_sha256 != worker["channel_certificate_sha256"]
                or local.serial != worker["channel_serial"]
                or local.public_key_sha256 != worker["channel_public_key_sha256"]):
            raise GatewayIngressError("gateway or worker channel credential pin changed")
        self._state.deadline = min(
            self._state.deadline,
            sample.monotonic + channel.not_after.timestamp() - sample.latest_wall,
            sample.monotonic + local.not_after.timestamp() - sample.latest_wall,
        )


def _is_ip(host):
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _identity_device(local_identity, view):
    candidates = [device for (device, boot), record in view.workers.items()
                  if boot == local_identity.boot_id
                  and record["model_id"] == local_identity.model_id
                  and record["assignment_id"] == local_identity.assignment_id
                  and record["host_certificate_sha256"] == certificate_sha256(
                      x509.load_pem_x509_certificate(local_identity.certificate_pem))]
    if len(candidates) != 1:
        raise GatewayIngressError("local identity does not select exactly one policy worker")
    return candidates[0]


def _worker_device(view, local_identity):
    return _identity_device(local_identity, view)
