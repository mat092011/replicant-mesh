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
from .channel_tls import OwnedWorkerTLS, OwnedWorkerTLSError, is_owned_worker_tls
from .errors import ScopeError, SessionError
from .outbound import OutboundAuthorizer


class GatewayEgressError(ScopeError):
    """The authenticated coordinator-to-gateway route is unavailable."""

    def __init__(self, message, *, cleanup_status=None, credential_directory=None):
        super().__init__(message)
        self.cleanup_status = cleanup_status
        self.credential_directory = credential_directory


_GUARD_TOKEN = object()
_GUARD_LOCK = threading.Lock()
_MINTED_GUARDS = weakref.WeakSet()
_MINTED_EGRESS = weakref.WeakSet()
_TARGET_TOKEN = object()
_MINTED_TARGETS = weakref.WeakSet()


def is_owned_gateway_coordinator_egress(value):
    """Recognize only a constructed egress owner with its minted TLS child."""
    if type(value) is not GatewayCoordinatorEgress:
        return False
    with _GUARD_LOCK:
        return value in _MINTED_EGRESS and is_owned_worker_tls(value._tls)


def _pem_from_der(value):
    try:
        return x509.load_der_x509_certificate(value).public_bytes(
            serialization.Encoding.PEM)
    except Exception as error:
        raise GatewayEgressError("gateway TLS peer certificate is malformed") from error


def _certificate_der(value):
    try:
        return x509.load_pem_x509_certificate(value).public_bytes(
            serialization.Encoding.DER)
    except Exception as error:
        raise GatewayEgressError("coordinator TLS client certificate is malformed") from error


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
            owner._assert_guard_target(self._identity, method)
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
        self._coordinator_identity = self._capture_coordinator_identity()
        self._configured_coordinator_certificate_pem = bytes(
            authorizer.local_identity.certificate_pem)
        self._configured_coordinator_certificate_der = _certificate_der(
            self._configured_coordinator_certificate_pem)
        self._target_views = {}
        host_dns, host_ip = _endpoint_names(
            self._gateway_policy["coordinator_endpoint_host"])
        try:
            self._tls = OwnedWorkerTLS.connect(
                worker_certificate_pem=self._configured_coordinator_certificate_pem,
                worker_private_key_pem=coordinator_private_key_pem,
                gateway_ca_pem=gateway_ca_pem,
                endpoint_host=self._gateway_policy["coordinator_endpoint_host"],
                endpoint_port=self._gateway_policy["coordinator_endpoint_port"],
                clock=self.clock)
        except OwnedWorkerTLSError as error:
            if error.cleanup_status == "uncertain":
                raise GatewayEgressError(
                    "gateway TLS credential cleanup is uncertain",
                    cleanup_status=error.cleanup_status,
                    credential_directory=error.credential_directory) from error
            raise
        if self._tls.cleanup_uncertain:
            raise GatewayEgressError(
                "gateway TLS credential cleanup is uncertain",
                cleanup_status=self._tls.cleanup_status,
                credential_directory=self._tls.credential_directory)
        self._host_dns, self._host_ip = host_dns, host_ip
        self._gateway_ca_pem = gateway_ca_pem
        self._gateway_verified = False
        if self._tls.handshake_complete:
            self._verify_gateway_peer()
        primary = GatewayEgressTargetView(
            _TARGET_TOKEN, self, authorizer, logical_host_certificate_pem)
        key = _target_key(authorizer)
        self._target_views[key] = primary
        self._primary_view = primary
        with _GUARD_LOCK:
            _MINTED_EGRESS.add(self)
            _MINTED_TARGETS.add(primary)
        self._initialized = True

    def __setattr__(self, name, value):
        if getattr(self, "_initialized", False) and name in {
                "authorizer", "policy_store", "logical_host_certificate_pem",
                "gateway_id", "clock", "_generation", "_view",
                "_gateway_policy", "_worker_policy", "_host_dns", "_host_ip",
                "_gateway_ca_pem", "_tls", "_coordinator_identity",
                "_configured_coordinator_certificate_pem",
                "_configured_coordinator_certificate_der", "_target_views",
                "_primary_view"}:
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
        host_dns, host_ip = _endpoint_names(
            self._gateway_policy["coordinator_endpoint_host"])
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

    def assert_transport_live(self):
        """Run the live policy/profile check without taking queued ciphertext."""
        with self._lock:
            self._assert_transport_live_locked()
            self._assert_primary_authority_locked()
            return self._gateway_verified

    @property
    def pending_encrypted_bytes(self):
        with self._lock:
            self._assert_transport_live_locked()
            return self._tls.pending_encrypted_bytes

    def take_encrypted(self, maximum=16 * 1024):
        with self._lock:
            self._assert_transport_live_locked()
            try:
                return self._tls.take_encrypted(maximum)
            except Exception:
                self._fault_locked()
                raise

    def feed_encrypted(self, data):
        with self._lock:
            self._assert_transport_live_locked()
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

    def _capture_coordinator_identity(self):
        identity = self.authorizer.local_identity
        return (identity.certificate_pem, identity.boot_id, identity.model_id,
                identity.assignment_id, identity.admission_epoch,
                identity.root_generation_sha256)

    def _assert_transport_live_locked(self):
        if self._closed or self._faulted or not is_owned_worker_tls(self._tls):
            raise GatewayEgressError("gateway egress generation is closed or faulted")
        if getattr(self, "_initialized", False):
            self._assert_primary_authority_locked()
        if not self._tls.handshake_complete:
            try:
                pending_view = self.policy_store.current()
                pending_gateway = pending_view.gateway(self.gateway_id)
                if (pending_view.revision != self._view.revision
                        or pending_view.policy_digest != self._view.policy_digest
                        or pending_gateway is None
                        or pending_gateway["coordinator_endpoint_host"]
                        != self._gateway_policy["coordinator_endpoint_host"]
                        or pending_gateway["coordinator_endpoint_port"]
                        != self._gateway_policy["coordinator_endpoint_port"]):
                    raise GatewayEgressError(
                        "coordinator gateway endpoint or policy changed; reconnect required")
            except Exception as error:
                self._fault_locked()
                if isinstance(error, GatewayEgressError):
                    raise
                raise GatewayEgressError(
                    "coordinator gateway policy is no longer live") from error
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
        # Policy identity and its monotonic cap govern the connection from
        # creation through teardown, including queued TLS handshake bytes.
        try:
            if self._capture_coordinator_identity() != self._coordinator_identity:
                raise GatewayEgressError(
                    "coordinator identity changed; reconnect required")
            if self._tls.handshake_complete:
                configured_der = _certificate_der(
                    self._tls.configured_local_certificate_pem)
                if configured_der != self._configured_coordinator_certificate_der:
                    raise GatewayEgressError(
                        "TLS client credential changed; reconnect required")
            view, sample = self.policy_store.current_with_sample()
            if (view.revision != self._view.revision
                    or view.policy_digest != self._view.policy_digest):
                raise GatewayEgressError("channel policy changed; reconnect required")
            current_gateway = view.gateway(self.gateway_id)
            if (current_gateway is None
                    or current_gateway["coordinator_endpoint_host"]
                    != self._gateway_policy["coordinator_endpoint_host"]
                    or current_gateway["coordinator_endpoint_port"]
                    != self._gateway_policy["coordinator_endpoint_port"]):
                raise GatewayEgressError(
                    "coordinator gateway endpoint changed; reconnect required")
            if view.deadline_monotonic < self._view.deadline_monotonic:
                object.__setattr__(self, "_view", view)
            if sample.monotonic >= self._view.deadline_monotonic:
                raise GatewayEgressError("channel policy generation has expired")
        except Exception as error:
            self._fault_locked()
            if isinstance(error, GatewayEgressError):
                raise
            raise GatewayEgressError("channel policy or coordinator identity is no longer live") from error

    def _fault_locked(self):
        self._faulted = True
        self._tls.close()

    def _assert_guard_live(self, identity, deadline):
        return self._assert_guard_live_for(identity, deadline, None)

    def _assert_guard_target(self, identity, method, authorizer=None):
        with self._lock:
            if authorizer is None:
                self._assert_primary_authority_locked()
                adapter = self.authorizer
            else:
                adapter = authorizer
            if (identity[2][8:12] != _target_key(adapter)
                    or identity[3] != adapter.target.certificate_sha256
                    or method not in identity[2][12]):
                raise GatewayEgressError("route guard target differs from its C1 authorizer")

    def _assert_primary_authority_locked(self):
        try:
            self._primary_view._assert_authority_live_locked()
        except Exception as error:
            self._fault_locked()
            if isinstance(error, GatewayEgressError):
                raise
            raise GatewayEgressError("primary target authority changed") from error

    def _assert_guard_live_for(self, identity, deadline, target_view):
        with self._lock:
            self._assert_transport_live_locked()
            if (target_view is not None
                    and (not is_owned_gateway_target_view(target_view)
                         or target_view._egress is not self
                         or self._target_views.get(target_view._key) is not target_view)):
                raise GatewayEgressError("gateway target view is no longer owned")
            if target_view is not None:
                target_view._assert_authority_live_locked()
            else:
                self._assert_primary_authority_locked()
            if identity[0] is not self._generation or identity[1] != self._view.policy_digest:
                self._fault_locked()
                raise GatewayEgressError("gateway route belongs to a stale generation")
            try:
                sample = self.clock.sample()
            except Exception as error:
                self._fault_locked()
                raise GatewayEgressError("gateway route clock is unavailable") from error
            if sample.monotonic >= deadline:
                # This exact request capability expired. The shared TLS and
                # signed policy generation remain usable for other routes.
                raise SessionError("gateway route authorization expired")
            return min(deadline, self._view.deadline_monotonic)

    def mint_route_guard(self, *, method, trusted_request_context):
        """Authorize the exact coordinator/worker route for one C1 worker call."""
        return self._mint_route_guard_for(
            self._primary_view.authorizer,
            self._primary_view.logical_host_certificate_pem, self,
            method=method, trusted_request_context=trusted_request_context)

    def _mint_route_guard_for(self, adapter, logical_host_certificate_pem,
                              guard_owner, *, method, trusted_request_context):
        """Shared exact C1/policy route check for a minted target view."""
        from .codec import WORKER_METHODS
        from .outbound import BootstrapContext
        with self._lock:
            self._assert_transport_live_locked()
            if type(guard_owner) is GatewayEgressTargetView:
                guard_owner._assert_authority_live_locked()
            else:
                self._assert_primary_authority_locked()
            if not self._gateway_verified:
                raise GatewayEgressError("gateway TLS channel is not authenticated")
            if method not in WORKER_METHODS:
                raise GatewayEgressError("route method is not an exact worker method")
            if type(trusted_request_context) is BootstrapContext:
                trusted_request_context._check_available(
                    adapter._capability_owner, self.clock.sample().monotonic)
            context_deadline = adapter._assert_context_for_auth(
                trusted_request_context, "steamboat.v1.Worker", method)
            if type(trusted_request_context) is BootstrapContext:
                # The eventual C1 admission consumes this finite capability;
                # route minting only validates it and must not spend a use.
                context_values = {"tenant_account_id": None}
            else:
                context_values, _authorization, _hard_deadline = adapter._worker_context_shape(
                    trusted_request_context)
            sample = self.clock.sample()
            c1_view = adapter.snapshot_store.current(sample=sample)
            local = _verify_pinned_credential(
                adapter.snapshot_store, adapter.local_identity.certificate_pem,
                c1_view, sample)
            if type(trusted_request_context) is BootstrapContext:
                context_values["tenant_account_id"] = local.account_id
            target = _verify_pinned_credential(
                adapter.snapshot_store, logical_host_certificate_pem,
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
                _GUARD_TOKEN, guard_owner,
                (self._generation, self._view.policy_digest, route, target.certificate_sha256),
                method, trusted_request_context, deadline)
            with _GUARD_LOCK:
                _MINTED_GUARDS.add(guard)
            self._guards.add(guard)
            return guard

    def register_target(self, authorizer, logical_host_certificate_pem):
        """Mint a bounded per-worker route view over this exact TLS owner."""
        if (type(authorizer) is not OutboundAuthorizer
                or type(logical_host_certificate_pem) is not bytes):
            raise TypeError("target view requires exact C1 authorizer and certificate bytes")
        key = _target_key(authorizer)
        from .codec import WORKER_METHODS
        with self._lock:
            self._assert_transport_live_locked()
            existing = self._target_views.get(key)
            if existing is not None:
                existing.assert_transport_live()
                if (existing.authorizer is authorizer
                        and existing.logical_host_certificate_pem == logical_host_certificate_pem):
                    return existing
                raise GatewayEgressError("target tuple is already bound to another authority")
            if len(self._target_views) >= 3:
                raise GatewayEgressError("coordinator cohort is limited to three targets")
            if (authorizer.clock is not self.clock
                    or authorizer.snapshot_store is not self.authorizer.snapshot_store
                    or _coordinator_identity(authorizer) != self._coordinator_identity
                    or authorizer.target.service != self.authorizer.target.service
                    or authorizer.target.model_id != self.authorizer.target.model_id
                    or authorizer.worker_request_type is not self.authorizer.worker_request_type
                    or authorizer.trusted_request_context_type
                       is not self.authorizer.trusted_request_context_type):
                raise GatewayEgressError("target authorizer differs from the exact coordinator identity")
            try:
                sample = self.clock.sample()
                c1_view = authorizer.snapshot_store.current(sample=sample)
                local = _verify_pinned_credential(
                    authorizer.snapshot_store,
                    authorizer.local_identity.certificate_pem, c1_view, sample)
                target = _verify_pinned_credential(
                    authorizer.snapshot_store, logical_host_certificate_pem,
                    c1_view, sample)
                worker = self._view.worker(authorizer.target.device_id,
                                           authorizer.target.boot_id)
                policy_route = any(self._view.route(
                    gateway_id=self.gateway_id, account_id=local.account_id,
                    device_id=local.device_id, actor_serial=local.serial,
                    actor_credential_epoch=local.credential_epoch,
                    actor_certificate_sha256=local.certificate_sha256,
                    coordinator_boot_id=authorizer.local_identity.boot_id,
                    tenant_account_id=local.account_id,
                    target_device_id=authorizer.target.device_id,
                    worker_boot_id=authorizer.target.boot_id,
                    assignment_id=authorizer.target.assignment_id,
                    model_id=authorizer.target.model_id, method=method) is not None
                    for method in WORKER_METHODS)
            except Exception as error:
                raise GatewayEgressError("target C1 identity or signed channel policy is invalid") from error
            if (local.role != "personal_coordinator" or target.role != "host"
                    or target.account_id != authorizer.target.account_id
                    or target.device_id != authorizer.target.device_id
                    or target.certificate_sha256 != authorizer.target.certificate_sha256
                    or target.public_key_sha256 != authorizer.target.public_key_sha256
                    or target.serial != authorizer.target.serial
                    or target.credential_epoch != authorizer.target.credential_epoch
                    or worker is None
                    or worker["account_id"] != authorizer.target.account_id
                    or worker["host_serial"] != target.serial
                    or worker["host_credential_epoch"] != target.credential_epoch
                    or worker["host_certificate_sha256"] != target.certificate_sha256
                    or worker["assignment_id"] != authorizer.target.assignment_id
                    or worker["model_id"] != authorizer.target.model_id
                    or worker["gateway_id"] != self.gateway_id
                    or not policy_route):
                raise GatewayEgressError("target differs from its exact C1 and signed policy assignment")
            view = GatewayEgressTargetView(
                _TARGET_TOKEN, self, authorizer, logical_host_certificate_pem)
            self._target_views[key] = view
            with _GUARD_LOCK:
                _MINTED_TARGETS.add(view)
            return view

    def close(self):
        with self._lock:
            if not self._closed:
                self._closed = True
                self._tls.close()

    def __copy__(self):
        raise TypeError("gateway egress owners cannot be copied")

    def __deepcopy__(self, _memo):
        raise TypeError("gateway egress owners cannot be copied")


def _target_key(authorizer):
    target = authorizer.target
    return (target.device_id, target.boot_id, target.assignment_id, target.model_id)


def _coordinator_identity(authorizer):
    identity = authorizer.local_identity
    return (identity.certificate_pem, identity.boot_id, identity.model_id,
            identity.assignment_id, identity.admission_epoch,
            identity.root_generation_sha256)


class GatewayEgressTargetView:
    """Sealed target-specific C1 route capability over a shared egress."""

    __slots__ = ("_egress", "_authorizer", "_target", "_coordinator_identity",
                 "_snapshot_store", "_clock", "_request_type", "_context_type",
                 "_allow_bootstrap", "logical_host_certificate_pem", "_key",
                 "_token", "__weakref__")

    def __init__(self, token, egress, authorizer, logical_host_certificate_pem):
        if token is not _TARGET_TOKEN:
            raise TypeError("gateway target views are minted by their egress owner")
        object.__setattr__(self, "_egress", egress)
        object.__setattr__(self, "_authorizer", authorizer)
        object.__setattr__(self, "_target", authorizer.target)
        object.__setattr__(self, "_coordinator_identity",
                           _coordinator_identity(authorizer))
        object.__setattr__(self, "_snapshot_store", authorizer.snapshot_store)
        object.__setattr__(self, "_clock", authorizer.clock)
        object.__setattr__(self, "_request_type", authorizer.worker_request_type)
        object.__setattr__(self, "_context_type",
                           authorizer.trusted_request_context_type)
        object.__setattr__(self, "_allow_bootstrap", authorizer.allow_bootstrap_describe)
        object.__setattr__(self, "logical_host_certificate_pem",
                           bytes(logical_host_certificate_pem))
        object.__setattr__(self, "_key", _target_key(authorizer))
        object.__setattr__(self, "_token", token)

    def __setattr__(self, _name, _value):
        raise AttributeError("gateway target views are immutable")

    @property
    def egress(self):
        return self._egress

    @property
    def authorizer(self):
        return self._authorizer

    @property
    def clock(self):
        return self._egress.clock

    def assert_transport_live(self):
        if not is_owned_gateway_target_view(self):
            raise GatewayEgressError("gateway target view is not owner-minted")
        with self._egress._lock:
            self._egress._assert_transport_live_locked()
            if self._egress._target_views.get(self._key) is not self:
                raise GatewayEgressError("gateway target view is no longer current")
            self._assert_authority_live_locked()
            return self._egress._gateway_verified

    def _assert_authority_live_locked(self):
        if (self._authorizer.target is not self._target
                or _target_key(self._authorizer) != self._key
                or _coordinator_identity(self._authorizer) != self._coordinator_identity
                or self._authorizer.snapshot_store is not self._snapshot_store
                or self._authorizer.clock is not self._clock
                or self._authorizer.worker_request_type is not self._request_type
                or self._authorizer.trusted_request_context_type is not self._context_type
                or self._authorizer.allow_bootstrap_describe is not self._allow_bootstrap):
            raise GatewayEgressError("target authorizer changed after view registration")

    def mint_route_guard(self, *, method, trusted_request_context):
        self.assert_transport_live()
        return self._egress._mint_route_guard_for(
            self.authorizer, self.logical_host_certificate_pem, self,
            method=method, trusted_request_context=trusted_request_context)

    def _assert_guard_live(self, identity, deadline):
        return self._egress._assert_guard_live_for(identity, deadline, self)

    def _assert_guard_target(self, identity, method):
        self._assert_authority_live_locked()
        self._egress._assert_guard_target(identity, method, self._authorizer)

    def close(self):
        """Close the shared coordinator cohort, as for the root egress."""
        self._egress.close()

    def __copy__(self):
        raise TypeError("gateway target views cannot be copied")

    def __deepcopy__(self, _memo):
        raise TypeError("gateway target views cannot be copied")


def is_owned_gateway_target_view(value):
    if type(value) is not GatewayEgressTargetView:
        return False
    with _GUARD_LOCK:
        return value in _MINTED_TARGETS and value._token is _TARGET_TOKEN
