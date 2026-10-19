"""Coordinator-owned authenticated upstream channel to a trusted C2 gateway.

This module provides channel and route authorization only. It does not provide
socket framing, readiness, an end-to-end host proof, or a work scheduler.
"""

from __future__ import annotations

import ipaddress
import threading
import weakref

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from .authorization import LocalIdentity, _verify_pinned_credential
from .certificates import certificate_sha256
from .channel_certificates import verify_channel_certificate
from .channel_policy import ChannelPolicyStore
from .channel_tls import OwnedWorkerTLS, is_owned_worker_tls
from .errors import ScopeError, SessionError
from .outbound import OutboundAuthorizer


class GatewayEgressError(ScopeError):
    """The authenticated coordinator-to-gateway route is unavailable."""


_GUARD_TOKEN = object()
_GUARD_LOCK = threading.Lock()
_MINTED_GUARDS = weakref.WeakSet()


def _pem_from_der(value):
    try:
        return x509.load_der_x509_certificate(value).public_bytes(
            serialization.Encoding.PEM)
    except Exception as error:
        raise GatewayEgressError("gateway TLS peer certificate is malformed") from error


def _endpoint_names(host):
    try:
        return None, str(ipaddress.ip_address(host))
    except ValueError:
        return host, None


class GatewayRouteGuard:
    """Single-operation capability minted by a live pinned egress owner."""

    __slots__ = ("_owner", "_token", "_identity", "_method", "_context",
                 "deadline_monotonic", "_claimed", "_lock", "_sealed", "__weakref__")

    def __init__(self, token, owner, identity, method, context, deadline):
        if token is not _GUARD_TOKEN:
            raise TypeError("route guards are minted by GatewayCoordinatorEgress")
        self._owner, self._token = owner, token
        self._identity, self._method, self._context = identity, method, context
        self.deadline_monotonic = deadline
        self._claimed = False
        self._lock = threading.Lock()
        self._sealed = True

    def __setattr__(self, name, value):
        if getattr(self, "_sealed", False):
            raise AttributeError("gateway route guards are immutable")
        object.__setattr__(self, name, value)

    def _claim(self, owner, method, context):
        with self._lock:
            if (self._owner is not owner or self._token is not _GUARD_TOKEN
                    or self._method != method or self._context is not context
                    or self._claimed):
                raise GatewayEgressError("gateway route guard is foreign or already used")
            object.__setattr__(self, "_claimed", True)
        return self.assert_live()

    def assert_live(self):
        with self._lock:
            if self._token is not _GUARD_TOKEN or self._owner is None:
                raise GatewayEgressError("gateway route guard is unavailable")
            owner = self._owner
        return owner._assert_guard_live(self._identity, self.deadline_monotonic)


def is_gateway_route_guard(value):
    if type(value) is not GatewayRouteGuard:
        return False
    with _GUARD_LOCK:
        return value in _MINTED_GUARDS and value._token is _GUARD_TOKEN


class GatewayCoordinatorEgress:
    """Own one TLS client generation to a policy-pinned gateway endpoint."""

    def __init__(self, *, authorizer, policy_store, logical_host_certificate_pem,
                 gateway_id, gateway_ca_pem, coordinator_private_key_pem):
        if type(authorizer) is not OutboundAuthorizer:
            raise TypeError("egress requires the exact OutboundAuthorizer")
        if type(policy_store) is not ChannelPolicyStore:
            raise TypeError("egress requires the exact ChannelPolicyStore")
        if (authorizer.target.service != "steamboat.v1.Worker"
                or authorizer.local_identity.assignment_id is not None
                or policy_store.clock is not authorizer.clock):
            raise ValueError("egress requires a coordinator-to-worker adapter and shared Clock")
        if type(gateway_id) is not str or not gateway_id:
            raise ValueError("gateway ID is invalid")
        if type(logical_host_certificate_pem) is not bytes:
            raise TypeError("logical host certificate must be exact PEM bytes")
        self.authorizer = authorizer
        self.policy_store = policy_store
        self.logical_host_certificate_pem = logical_host_certificate_pem
        self.gateway_id = gateway_id
        self.clock = authorizer.clock
        self._lock = threading.RLock()
        self._closed = False
        self._faulted = False
        self._generation = object()
        self._guards = weakref.WeakSet()
        self._view, _sample = policy_store.current_with_sample()
        self._gateway_policy = self._view.gateway(gateway_id)
        self._worker_policy = self._view.worker(
            authorizer.target.device_id, authorizer.target.boot_id)
        self._validate_initial_policy()
        host_dns, host_ip = _endpoint_names(self._gateway_policy["endpoint_host"])
        self._tls = OwnedWorkerTLS.connect(
            worker_certificate_pem=authorizer.local_identity.certificate_pem,
            worker_private_key_pem=coordinator_private_key_pem,
            gateway_ca_pem=gateway_ca_pem,
            endpoint_host=self._gateway_policy["endpoint_host"],
            endpoint_port=self._gateway_policy["endpoint_port"], clock=self.clock)
        self._host_dns, self._host_ip = host_dns, host_ip
        self._gateway_ca_pem = gateway_ca_pem
        self._gateway_verified = False
        if self._tls.handshake_complete:
            self._verify_gateway_peer()
        self._initialized = True

    def __setattr__(self, name, value):
        if getattr(self, "_initialized", False) and name in {
                "authorizer", "policy_store", "logical_host_certificate_pem",
                "gateway_id", "clock", "_generation", "_view",
                "_gateway_policy", "_worker_policy", "_host_dns", "_host_ip",
                "_gateway_ca_pem", "_tls"}:
            raise AttributeError("gateway egress authority and transport are immutable")
        object.__setattr__(self, name, value)

    @classmethod
    def connect(cls, *, authorizer, policy_store, logical_host_certificate_pem,
                gateway_id, gateway_ca_pem, coordinator_private_key_pem):
        """Create the client owner; transport chunks are driven by the caller."""
        return cls(authorizer=authorizer, policy_store=policy_store,
                   logical_host_certificate_pem=logical_host_certificate_pem,
                   gateway_id=gateway_id, gateway_ca_pem=gateway_ca_pem,
                   coordinator_private_key_pem=coordinator_private_key_pem)

    def _validate_initial_policy(self):
        if self._gateway_policy is None or self._worker_policy is None:
            raise GatewayEgressError("gateway or fixed worker is absent from channel policy")
        target = self.authorizer.target
        worker = self._worker_policy
        if (worker["account_id"] != target.account_id
                or worker["host_serial"] != target.serial
                or worker["host_credential_epoch"] != target.credential_epoch
                or worker["host_certificate_sha256"] != target.certificate_sha256
                or worker["assignment_id"] != target.assignment_id
                or worker["model_id"] != target.model_id
                or worker["gateway_id"] != self.gateway_id):
            raise GatewayEgressError("channel policy worker differs from the immutable C1 target")
        host_dns, host_ip = _endpoint_names(self._gateway_policy["endpoint_host"])
        if host_dns is None and host_ip is None:
            raise GatewayEgressError("gateway endpoint is invalid")

    def _verify_gateway_peer(self):
        with self._lock:
            if self._gateway_verified:
                return
            try:
                peer_pem = _pem_from_der(self._tls.peer_certificate_der)
                sample = self.clock.sample()
                channel = verify_channel_certificate(
                    peer_pem, self._gateway_ca_pem, kind="gateway",
                    expected_identity=self.gateway_id, now=sample.latest_wall,
                    uncertainty_seconds=sample.uncertainty,
                    required_eku={"client", "server"}, expected_dns=self._host_dns,
                    expected_ip=self._host_ip)
                item = self._gateway_policy
                if (channel.serial != item["serial"]
                        or channel.certificate_sha256 != item["certificate_sha256"]
                        or channel.public_key_sha256 != item["public_key_sha256"]
                        or int(channel.not_before.timestamp()) != item["not_before"]
                        or int(channel.not_after.timestamp()) != item["not_after"]):
                    raise GatewayEgressError("gateway TLS identity differs from signed policy")
                self._gateway_verified = True
            except Exception as error:
                self._fault_locked()
                if isinstance(error, GatewayEgressError):
                    raise
                raise GatewayEgressError("gateway TLS identity verification failed") from error

    @property
    def handshake_complete(self):
        with self._lock:
            self._assert_transport_live_locked()
            if self._tls.handshake_complete and not self._gateway_verified:
                self._verify_gateway_peer()
            return self._gateway_verified

    def take_encrypted(self, maximum=16 * 1024):
        with self._lock:
            self._assert_transport_live_locked(check_policy=False)
            try:
                return self._tls.take_encrypted(maximum)
            except Exception:
                self._fault_locked()
                raise

    def feed_encrypted(self, data):
        with self._lock:
            self._assert_transport_live_locked(check_policy=False)
            try:
                self._tls.feed_encrypted(data)
            except Exception:
                self._fault_locked()
                raise
            if self._tls.handshake_complete:
                self._verify_gateway_peer()

    def write_plaintext(self, data):
        with self._lock:
            self._assert_transport_live_locked()
            if not self._gateway_verified:
                raise GatewayEgressError("gateway handshake and channel profile are incomplete")
            try:
                return self._tls.write_plaintext(data)
            except Exception:
                self._fault_locked()
                raise

    def read_plaintext(self, maximum=16 * 1024):
        with self._lock:
            self._assert_transport_live_locked()
            if not self._gateway_verified:
                raise GatewayEgressError("gateway handshake and channel profile are incomplete")
            try:
                data = self._tls.read_plaintext(maximum)
                if data == b"":
                    self._fault_locked()
                    raise GatewayEgressError("gateway closed the authenticated TLS channel")
                return data
            except Exception:
                self._fault_locked()
                raise

    def _assert_transport_live_locked(self, *, check_policy=True):
        if self._closed or self._faulted or not is_owned_worker_tls(self._tls):
            raise GatewayEgressError("gateway egress generation is closed or faulted")
        try:
            if not self._tls.handshake_complete:
                self._tls.do_handshake()
            elif not self._tls.is_live:
                raise GatewayEgressError("gateway TLS owner is no longer live")
        except Exception as error:
            self._fault_locked()
            if isinstance(error, GatewayEgressError):
                raise
            raise GatewayEgressError("gateway TLS owner is no longer live") from error
        if check_policy and self._gateway_verified:
            try:
                view, sample = self.policy_store.current_with_sample()
                if (view.revision != self._view.revision
                        or view.policy_digest != self._view.policy_digest):
                    raise GatewayEgressError("channel policy changed; reconnect required")
                if view.deadline_monotonic < self._view.deadline_monotonic:
                    # Preserve ChannelPolicyStore's conservative uncertainty
                    # clipping locally; never widen a generation's original cap.
                    object.__setattr__(self, "_view", view)
                if sample.monotonic >= self._view.deadline_monotonic:
                    raise GatewayEgressError("channel policy generation has expired")
            except Exception as error:
                self._fault_locked()
                if isinstance(error, GatewayEgressError):
                    raise
                raise GatewayEgressError("channel policy is no longer live") from error

    def _fault_locked(self):
        self._faulted = True
        self._tls.close()

    def _assert_guard_live(self, identity, deadline):
        with self._lock:
            self._assert_transport_live_locked()
            try:
                sample = self.clock.sample()
                if sample.monotonic >= min(deadline, self._view.deadline_monotonic):
                    raise SessionError("gateway route authorization expired")
                if identity[0] is not self._generation or identity[1] != self._view.policy_digest:
                    raise GatewayEgressError("gateway route belongs to a stale generation")
                return min(deadline, self._view.deadline_monotonic)
            except Exception as error:
                self._fault_locked()
                if isinstance(error, (GatewayEgressError, SessionError)):
                    raise
                raise GatewayEgressError("gateway route clock is unavailable") from error

    def mint_route_guard(self, *, method, trusted_request_context):
        """Authorize the exact coordinator/worker route for one C1 worker call."""
        from .codec import WORKER_METHODS
        with self._lock:
            self._assert_transport_live_locked()
            if not self._gateway_verified:
                raise GatewayEgressError("gateway TLS channel is not authenticated")
            if method not in WORKER_METHODS:
                raise GatewayEgressError("route method is not an exact worker method")
            adapter = self.authorizer
            context_values, _authorization, context_deadline = adapter._worker_context_values(
                trusted_request_context)
            sample = self.clock.sample()
            c1_view = adapter.snapshot_store.current(sample=sample)
            local = _verify_pinned_credential(
                adapter.snapshot_store, adapter.local_identity.certificate_pem,
                c1_view, sample)
            target = _verify_pinned_credential(
                adapter.snapshot_store, self.logical_host_certificate_pem,
                c1_view, sample)
            if (local.role != "personal_coordinator"
                    or target.role != "host"
                    or target.certificate_sha256 != adapter.target.certificate_sha256
                    or target.serial != adapter.target.serial
                    or target.credential_epoch != adapter.target.credential_epoch):
                raise GatewayEgressError("C1 enrollment differs from the fixed route identities")
            worker = self._view.worker(adapter.target.device_id, adapter.target.boot_id)
            if worker is None:
                raise GatewayEgressError("worker channel policy entry is unavailable")
            if (worker["host_serial"] != target.serial
                    or worker["host_credential_epoch"] != target.credential_epoch
                    or worker["host_certificate_sha256"] != target.certificate_sha256):
                raise GatewayEgressError("logical host credential differs from channel policy")
            route = self._view.route(
                gateway_id=self.gateway_id, account_id=local.account_id,
                device_id=local.device_id, actor_serial=local.serial,
                actor_credential_epoch=local.credential_epoch,
                actor_certificate_sha256=local.certificate_sha256,
                coordinator_boot_id=adapter.local_identity.boot_id,
                tenant_account_id=context_values["tenant_account_id"],
                target_device_id=adapter.target.device_id,
                worker_boot_id=adapter.target.boot_id,
                assignment_id=adapter.target.assignment_id,
                model_id=adapter.target.model_id, method=method)
            if route is None or local.account_id != context_values["tenant_account_id"]:
                raise GatewayEgressError("signed channel policy does not authorize this route")
            deadline = min(self._view.deadline_monotonic, context_deadline,
                           c1_view.deadline_monotonic,
                           c1_view.credential_deadlines[local.serial],
                           c1_view.credential_deadlines[target.serial])
            if sample.monotonic >= deadline:
                raise SessionError("gateway route authorization expired")
            guard = GatewayRouteGuard(
                _GUARD_TOKEN, self,
                (self._generation, self._view.policy_digest, route, target.certificate_sha256),
                method, trusted_request_context, deadline)
            with _GUARD_LOCK:
                _MINTED_GUARDS.add(guard)
            self._guards.add(guard)
            return guard

    def close(self):
        with self._lock:
            if not self._closed:
                self._closed = True
                self._tls.close()

    def __copy__(self):
        raise TypeError("gateway egress owners cannot be copied")

    def __deepcopy__(self, _memo):
        raise TypeError("gateway egress owners cannot be copied")
