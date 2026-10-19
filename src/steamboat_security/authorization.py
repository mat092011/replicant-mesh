"""Scoped two-ended admission API for the existing participant wire methods.

This module is transport-neutral. It accepts parsed bounded payloads, verifies
the authenticated TLS peer certificate and the configured local role credential,
then checks the signed current grants before a runtime handler is called.
"""

from __future__ import annotations

import re
import ssl
import threading
from collections import OrderedDict
from dataclasses import dataclass
from typing import Any

from cryptography import x509

from .certificates import (MAX_CERTIFICATE_BYTES, _pem_certificate,
                           certificate_sha256, public_key_sha256,
                           serial_hex, verify_leaf)
from .clock import Clock
from .codec import (COORDINATOR_METHODS, COORDINATOR_SERVICE, WORKER_METHODS,
                    WORKER_SERVICE, Binding, parse_metadata)
from .errors import (BindingError, ClockError, CredentialError, ScopeError,
                     SecurityError, SessionError, SnapshotError)
from .ids import validate_boot
from .sessions import SessionBindings, SessionClaim
from .snapshot import CredentialRecord, Grant, SnapshotStore, SnapshotView


MAX_REPLAY_RECORDS = 4096
REPLAY_TTL_SECONDS = 300.0
MAX_REFRESH_SECONDS = 30
MAX_EXPIRY_POLL_SECONDS = 5
MAX_REQUEST_BYTES = 1024 * 1024
_SESSION_TEXT = re.compile(r"^[A-Za-z0-9_-]{1,64}$", re.ASCII)


@dataclass(frozen=True)
class LocalIdentity:
    certificate_pem: bytes
    boot_id: str
    model_id: str
    assignment_id: str | None = None
    admission_epoch: int | None = None
    root_generation_sha256: str | None = None

    def __post_init__(self):
        if type(self.certificate_pem) is not bytes or not 1 <= len(self.certificate_pem) <= MAX_CERTIFICATE_BYTES:
            raise ValueError("local role certificate is invalid")
        validate_boot(self.boot_id)
        if type(self.model_id) is not str or not re.fullmatch(r"[0-9a-f]{64}", self.model_id, re.ASCII):
            raise ValueError("local model identity must be a SHA-256 fingerprint")
        if self.assignment_id is not None and (type(self.assignment_id) is not str
                                               or not re.fullmatch(r"asg_[0-9a-f]{32}", self.assignment_id, re.ASCII)):
            raise ValueError("local assignment ID is invalid")
        if self.admission_epoch is None and self.root_generation_sha256 is None:
            return
        if (type(self.admission_epoch) is not int or self.admission_epoch < 1
                or type(self.root_generation_sha256) is not str
                or not re.fullmatch(r"[0-9a-f]{64}", self.root_generation_sha256, re.ASCII)):
            raise ValueError("root-bound local identity needs a positive admission epoch and generation hash")


@dataclass(frozen=True)
class VerifiedCredential:
    record: CredentialRecord
    certificate: x509.Certificate
    certificate_pem: bytes

    @property
    def account_id(self):
        return self.record.account_id

    @property
    def device_id(self):
        return self.record.device_id

    @property
    def role(self):
        return self.record.role

    @property
    def serial(self):
        return self.record.serial

    @property
    def public_key_sha256(self):
        return self.record.public_key_sha256

    @property
    def certificate_sha256(self):
        return self.record.certificate_sha256

    @property
    def credential_epoch(self):
        return self.record.credential_epoch


@dataclass(frozen=True)
class ScopeAuthorization:
    """Current two-endpoint identity/grant decision, without session ownership."""

    view: SnapshotView
    sample: object
    actor: VerifiedCredential
    target: VerifiedCredential
    grant: Grant
    model_id: str


def _verify_pinned_credential(snapshot_store: SnapshotStore, pem: bytes,
                              view: SnapshotView, sample) -> VerifiedCredential:
    if type(pem) is not bytes or not 1 <= len(pem) <= MAX_CERTIFICATE_BYTES:
        raise CredentialError("endpoint certificate exceeds its bound")
    cert = _pem_certificate(pem)
    serial = serial_hex(cert.serial_number)
    record = view.credentials_by_serial.get(serial)
    if record is None:
        raise CredentialError("endpoint certificate is not currently enrolled")
    checked = verify_leaf(
        snapshot_store.ca_certificate_pem, pem, now=sample.wall,
        uncertainty_seconds=sample.uncertainty,
        account_id=record.account_id, device_id=record.device_id, role=record.role,
        serial=record.serial, public_key_hash=record.public_key_sha256,
        certificate_hash=record.certificate_sha256, ekus=record.ekus,
        dns_sans=record.dns_sans, ip_sans=record.ip_sans)
    if (int(checked.not_valid_before_utc.timestamp()) != record.not_before
            or int(checked.not_valid_after_utc.timestamp()) != record.not_after):
        raise CredentialError("snapshot credential validity differs from the pinned leaf")
    snapshot_store.assert_credential_live(view, record, sample)
    return VerifiedCredential(record, checked, pem)


def _credential_fingerprint(credential: VerifiedCredential) -> tuple:
    record = credential.record
    return (record.account_id, record.device_id, record.role, record.serial,
            record.public_key_sha256, record.certificate_sha256,
            record.credential_epoch)


def _select_current_grant(view: SnapshotView, *, service: str, method: str,
                          actor: VerifiedCredential, target: VerifiedCredential,
                          target_boot_id: str, actor_boot_id: str | None,
                          assignment_id: str | None, model_id: str,
                          tenant_account_id: str, sample) -> Grant:
    """One shared grant selector for incoming and outbound endpoint directions."""
    if service == WORKER_SERVICE:
        if method not in WORKER_METHODS:
            raise ScopeError("unknown worker method")
        if actor.role != "personal_coordinator" or target.role != "host":
            raise ScopeError("worker scope requires a personal coordinator and host")
        if tenant_account_id != actor.account_id or not assignment_id:
            raise ScopeError("worker tenant or fixed assignment scope is invalid")
        if method != "Describe" and actor_boot_id is None:
            raise ScopeError("worker session scope requires a coordinator boot")
    elif service == COORDINATOR_SERVICE:
        if method not in COORDINATOR_METHODS:
            raise ScopeError("unknown coordinator method")
        if (actor.role != "consumer" or target.role != "personal_coordinator"
                or actor.account_id != target.account_id
                or tenant_account_id != actor.account_id
                or assignment_id is not None or actor_boot_id is not None):
            raise ScopeError("coordinator scope must stay within one consumer account")
    else:
        raise BindingError("unknown secure service")
    full_method = f"{service}/{method}"
    candidates = []
    for grant in view.active_grants(sample):
        if (grant.account_id != actor.account_id or grant.device_id != actor.device_id
                or grant.role != actor.role or grant.target_device_id != target.device_id
                or grant.actor_serial != actor.serial
                or grant.actor_public_key_sha256 != actor.public_key_sha256
                or grant.actor_credential_epoch != actor.credential_epoch
                or grant.tenant_account_id != tenant_account_id
                or grant.target_account_id != target.account_id
                or grant.target_role != target.role
                or grant.target_serial != target.serial
                or grant.target_public_key_sha256 != target.public_key_sha256
                or grant.target_credential_epoch != target.credential_epoch
                or grant.target_boot_id != target_boot_id
                or grant.model_id != model_id or grant.method != full_method
                or grant.assignment_id != assignment_id):
            continue
        if actor_boot_id is not None and grant.actor_boot_id != actor_boot_id:
            continue
        if service == COORDINATOR_SERVICE and grant.actor_boot_id is not None:
            continue
        candidates.append(grant)
    if len(candidates) != 1:
        raise ScopeError("no exact current authorization grant")
    return candidates[0]


def authorize_scope(snapshot_store: SnapshotStore, clock: Clock, *, service: str,
                    method: str, actor_certificate_pem: bytes,
                    target_certificate_pem: bytes, target_device_id: str,
                    target_boot_id: str, actor_boot_id: str | None,
                    assignment_id: str | None, model_id: str,
                    tenant_account_id: str) -> ScopeAuthorization:
    """Verify a current endpoint pair and exact grant without claiming a session.

    Incoming ``Authorizer`` and the outbound adapter share this policy boundary.
    This helper never creates, reads, or bypasses server session ownership.
    """
    if snapshot_store.clock is not clock:
        raise ValueError("scope verifier and snapshot store must use the same clock")
    sample = clock.sample()
    view = snapshot_store.current(sample=sample)
    actor = _verify_pinned_credential(snapshot_store, actor_certificate_pem, view, sample)
    target = _verify_pinned_credential(snapshot_store, target_certificate_pem, view, sample)
    if target.device_id != target_device_id:
        raise ScopeError("target certificate differs from the configured target device")
    grant = _select_current_grant(
        view, service=service, method=method, actor=actor, target=target,
        target_boot_id=target_boot_id, actor_boot_id=actor_boot_id,
        assignment_id=assignment_id, model_id=model_id,
        tenant_account_id=tenant_account_id, sample=sample)
    return ScopeAuthorization(view, sample, actor, target, grant, model_id)


def _field(payload: Any, name: str, default=None):
    if type(payload) is dict:
        return payload.get(name, default)
    try:
        return getattr(payload, name)
    except (AttributeError, TypeError):
        return default


def _request(payload, request_type):
    if request_type is None or type(payload) is not request_type:
        raise BindingError("worker payload must be the configured generated Request type")
    descriptor = getattr(payload, "DESCRIPTOR", None)
    if getattr(descriptor, "full_name", None) != "steamboat.v1.Request":
        raise BindingError("worker payload must be the bounded parsed v1 Request")
    byte_size = getattr(payload, "ByteSize", None)
    if not callable(byte_size):
        raise BindingError("worker payload is not a parsed protobuf message")
    size = byte_size()
    if type(size) is not int or not 0 <= size <= MAX_REQUEST_BYTES:
        raise BindingError("worker request exceeds the parsed protobuf bound")
    return payload


def _coordinator_payload(payload):
    if type(payload) is not dict or len(payload) > 16:
        raise BindingError("coordinator payload must be a bounded JSON object")
    if any(type(key) is not str or len(key) > 64 for key in payload):
        raise BindingError("coordinator payload keys are invalid")
    return payload


class Authorization:
    """Single-RPC live authorization; close/fail never releases cache ownership."""

    def __init__(self, authorizer: "Authorizer", *, binding: Binding,
                 actor: VerifiedCredential, local: VerifiedCredential,
                 grant: Grant, model_id: str, payload: Any,
                 session_claim: SessionClaim | None = None,
                 session_key: tuple[str, str, str] | None = None,
                 lease_token: str = "", gateway_guard=None):
        self._authorizer = authorizer
        self._local_identity = authorizer.local_identity
        self.binding = binding
        self.binding_bytes = binding.encoded
        self.actor = actor
        self.local = local
        self.grant = grant
        self.model_id = model_id
        self.payload = payload
        self._session_claim = session_claim
        self._session_key = session_key
        self._lease_token = lease_token
        self._gateway_guard = gateway_guard
        self._finished = False
        self._failed = False
        self._terminal_complete = False

    def _live_deadline_state(self):
        authorizer = self._authorizer
        gateway_errors = ()
        if self._gateway_guard is not None:
            from .gateway_ingress import GatewayIngressError
            gateway_errors = (GatewayIngressError,)
        try:
            if authorizer.local_identity != self._local_identity:
                raise CredentialError("configured local identity was replaced")
            gateway_deadline = None
            if self._gateway_guard is not None:
                gateway_deadline = self._gateway_guard.deadline_monotonic
            view, sample = authorizer._current_view()
            authorizer._assert_credential(view, self.actor, sample)
            authorizer._assert_credential(view, self.local, sample)
            grant = authorizer._find_grant(
                view, service=self.binding.service, method=self.binding.method,
                actor=self.actor, local=self.local, binding=self.binding,
                model_id=self.model_id, assignment_id=self.grant.assignment_id,
                sample=sample)
            if grant.identity != self.grant.identity:
                raise ScopeError("authorization grant changed")
            grant_deadline = view.grant_deadlines.get(grant.identity, -1.0)
            if (sample.monotonic >= grant_deadline
                    or grant.not_before > sample.earliest_wall
                    or sample.latest_wall >= grant.not_after):
                raise ScopeError("authorization grant is outside its validity bound")
            deadlines = [view.deadline_monotonic,
                         view.credential_deadlines.get(self.actor.serial, -1.0),
                         view.credential_deadlines.get(self.local.serial, -1.0),
                         grant_deadline]
            if gateway_deadline is not None:
                deadlines.append(gateway_deadline)
            if self._terminal_complete:
                authorizer.session_bindings.assert_terminal(
                    self.binding, actor=self.actor.record, local=self.local.record,
                    grant=grant, model_id=self.model_id, key=self._session_key,
                    ingress_identity=self._ingress_identity)
                deadlines.append(authorizer.session_bindings.authorization_deadline(
                    self._session_key, now_monotonic=sample.monotonic,
                    terminal=True))
            elif self.binding.service == WORKER_SERVICE and self.binding.method == "OpenSession":
                if self._session_claim is None:
                    raise SessionError("OpenSession has no immutable owner claim")
                if self._lease_token:
                    authorizer.session_bindings.check(
                        self.binding, actor=self.actor.record, local=self.local.record,
                        grant=grant, model_id=self.model_id,
                        session_id=self.binding["session_id"],
                        worker_boot_id=self.binding["worker_boot_id"],
                        lease_token=self._lease_token,
                        ingress_identity=self._ingress_identity)
                else:
                    authorizer.session_bindings.assert_claim_live(self._session_claim)
                deadlines.append(authorizer.session_bindings.authorization_deadline(
                    self._session_key, now_monotonic=sample.monotonic,
                    claim=self._session_claim))
            elif self._session_key is not None:
                authorizer.session_bindings.check(
                    self.binding, actor=self.actor.record, local=self.local.record,
                    grant=grant, model_id=self.model_id,
                    session_id=self.binding["session_id"],
                    worker_boot_id=self.binding["worker_boot_id"],
                    lease_token=self._lease_token,
                    ingress_identity=self._ingress_identity)
                deadlines.append(authorizer.session_bindings.authorization_deadline(
                    self._session_key, now_monotonic=sample.monotonic))
            if self._gateway_guard is not None:
                final_gateway_deadline = self._gateway_guard.deadline_monotonic
                deadlines.append(final_gateway_deadline)
            deadline = min(deadlines)
            if sample.monotonic >= deadline:
                raise SessionError("authorization deadline expired")
        except (ClockError, SnapshotError):
            if authorizer.session_bindings is not None:
                authorizer.session_bindings.invalidate_all("clock-or-snapshot-unavailable")
            raise
        except (CredentialError, ScopeError, SessionError) + gateway_errors:
            if (self._session_key is not None
                    and self.binding.method != "SessionStatus"):
                authorizer.session_bindings.invalidate(
                    key=self._session_key, reason="authorization-invalidated")
            raise
        return deadline, sample.monotonic

    @property
    def _ingress_identity(self):
        return (None if self._gateway_guard is None
                else self._gateway_guard.ingress_identity)

    @property
    def deadline_monotonic(self) -> float:
        """Earliest current policy, credential, grant, and session deadline."""
        return self._live_deadline_state()[0]

    def remaining_seconds(self) -> float:
        """Recheck authorization and return seconds until its earliest bound."""
        deadline, now_monotonic = self._live_deadline_state()
        remaining = deadline - now_monotonic
        if remaining <= 0:
            raise SessionError("authorization deadline expired")
        return remaining

    def assert_live(self):
        self._live_deadline_state()
        return True

    def _assert_gateway_live(self):
        if self._gateway_guard is not None:
            self._gateway_guard.assert_live()

    def complete(self, response):
        try:
            return self._complete(response)
        finally:
            self._assert_gateway_live()

    def _complete(self, response):
        """Validate response identity and seal a new OpenSession lease before write."""
        if self._finished:
            raise SessionError("authorization response was already completed")
        self.assert_live()
        if self.binding.service == COORDINATOR_SERVICE:
            # Coordinator JSON response/event schemas remain owned by its service.
            # The adapter echoes binding_bytes as initial metadata and calls
            # assert_live() again immediately before every emitted event.
            self._assert_gateway_live()
            self._finished = True
            return response
        descriptor = getattr(response, "DESCRIPTOR", None)
        if getattr(descriptor, "full_name", None) != "steamboat.v1.Response":
            self._assert_gateway_live()
            raise BindingError("worker response must be the parsed v1 Response")
        if response.code != "OK":
            if self.binding.method == "OpenSession" and self._session_claim is not None:
                # A non-OK result is not proof that the handler never allocated
                # state. Retain the owner until the adapter confirms cleanup.
                self._authorizer.session_bindings.fail_open(self._session_claim, cache_may_exist=True)
            elif self._session_key is not None and self.binding.method in (
                    "RenewSession", "Step", "CloseSession", "CancelSession"):
                self._authorizer.session_bindings.invalidate(
                    key=self._session_key, reason="mutating-operation-failed")
            self._assert_gateway_live()
            self._finished = True
            return response
        if (response.protocol_version != 1 or response.manifest_fingerprint != self.model_id
                or response.worker_boot_id != self._authorizer.local_identity.boot_id):
            self.fail(cache_may_exist=True)
            self._assert_gateway_live()
            raise BindingError("worker response identity differs from the admitted target")
        method = self.binding.method
        if method != "Describe" and response.session_id != self.binding["session_id"]:
            self.fail(cache_may_exist=True)
            self._assert_gateway_live()
            raise BindingError("worker response session differs from the binding")
        if method == "OpenSession":
            if response.max_positions != _field(self.payload, "max_positions"):
                self.fail(cache_may_exist=True)
                self._assert_gateway_live()
                raise BindingError("OpenSession response reservation differs from the request")
            self._authorizer.session_bindings.seal_open(self._session_claim,
                                                        response.lease_token)
            self._lease_token = response.lease_token
        elif method != "Describe":
            if response.lease_token != self._lease_token:
                self.fail(cache_may_exist=True)
                self._assert_gateway_live()
                raise BindingError("worker response lease differs from the request")
        if method == "Step":
            if (response.sequence != _field(self.payload, "sequence")
                    or response.start_position != _field(self.payload, "start_position")
                    or response.token_count != _field(self.payload, "token_count")
                    or response.end_position != response.start_position + response.token_count
                    or response.next_sequence != response.sequence + 1):
                self.fail(cache_may_exist=True)
                self._assert_gateway_live()
                raise BindingError("Step response does not acknowledge the submitted operation")
        if method in ("CloseSession", "CancelSession"):
            self._authorizer.session_bindings.complete_operation(
                self._session_key, method, reclaimed=response.reclaimed is True)
            self._terminal_complete = True
        self._assert_gateway_live()
        self._finished = True
        return response

    def fail(self, *, cache_may_exist: bool = True):
        """End an ambiguous call; only explicit no-cache proof releases a pending Open."""
        if self._failed or self._finished:
            return
        self._failed = True
        if self.binding.service == WORKER_SERVICE:
            if self.binding.method == "OpenSession" and self._session_claim is not None:
                self._authorizer.session_bindings.fail_open(
                    self._session_claim, cache_may_exist=cache_may_exist)
            elif self._session_key is not None and self.binding.method in (
                    "RenewSession", "Step", "CloseSession", "CancelSession"):
                self._authorizer.session_bindings.invalidate(
                    key=self._session_key, reason="ambiguous-mutating-operation")

    def close(self):
        if not self._finished:
            self.fail(cache_may_exist=True)


class Authorizer:
    """Pure core for the parent transport hook ``authorize(service, method, ...)``."""

    def __init__(self, *, local_identity: LocalIdentity,
                 snapshot_store: SnapshotStore, clock: Clock,
                 session_bindings: SessionBindings | None = None,
                 worker_request_type=None,
                 max_replay_records: int = MAX_REPLAY_RECORDS,
                 replay_ttl_seconds: float = REPLAY_TTL_SECONDS):
        if type(max_replay_records) is not int or not 1 <= max_replay_records <= MAX_REPLAY_RECORDS:
            raise ValueError("operation replay bound is invalid")
        if not 0 < replay_ttl_seconds <= REPLAY_TTL_SECONDS:
            raise ValueError("operation replay lifetime exceeds 300 seconds")
        if snapshot_store.clock is not clock:
            raise ValueError("authorizer and snapshot store must use the same clock")
        if worker_request_type is not None:
            descriptor = getattr(worker_request_type, "DESCRIPTOR", None)
            if (not isinstance(worker_request_type, type)
                    or getattr(descriptor, "full_name", None) != "steamboat.v1.Request"):
                raise ValueError("worker_request_type must be the generated v1 Request class")
        self.local_identity = local_identity
        self.snapshot_store = snapshot_store
        self.clock = clock
        self.session_bindings = session_bindings
        self.worker_request_type = worker_request_type
        self.max_replay_records = max_replay_records
        self.replay_ttl_seconds = float(replay_ttl_seconds)
        self._operation_ids = OrderedDict()
        self._request_ids = OrderedDict()
        self._replay_lock = threading.RLock()
        if session_bindings is not None:
            snapshot_store.subscribe(self._snapshot_installed)

    def _snapshot_installed(self, view: SnapshotView):
        if self.session_bindings is None:
            return
        sample = self.clock.sample()
        self.session_bindings.revalidate_snapshot(view, sample=sample)

    def _current_view(self):
        sample = self.clock.sample()
        view = self.snapshot_store.current(sample=sample)
        return view, sample

    def _verify_certificate(self, pem: bytes, view: SnapshotView, sample) -> VerifiedCredential:
        return _verify_pinned_credential(self.snapshot_store, pem, view, sample)

    def _assert_credential(self, view: SnapshotView, credential: VerifiedCredential, sample):
        current = view.credentials_by_serial.get(credential.serial)
        if (current is None or current.identity != credential.record.identity
                or current.public_key_sha256 != credential.public_key_sha256
                or current.certificate_sha256 != credential.certificate_sha256
                or current.credential_epoch != credential.credential_epoch):
            raise CredentialError("endpoint credential identity changed")
        if (int(credential.certificate.not_valid_before_utc.timestamp()) != current.not_before
                or int(credential.certificate.not_valid_after_utc.timestamp()) != current.not_after):
            raise CredentialError("snapshot credential validity differs from the pinned leaf")
        self.snapshot_store.assert_credential_live(view, current, sample)

    def _model_for(self, service: str, method: str, payload) -> str:
        if service == WORKER_SERVICE and method != "Describe":
            value = _field(payload, "manifest_fingerprint", "")
            if type(value) is not str or value != self.local_identity.model_id:
                raise ScopeError("worker model is outside the local assignment")
            return value
        if service == WORKER_SERVICE:
            value = _field(payload, "manifest_fingerprint", "")
            if value and value != self.local_identity.model_id:
                raise ScopeError("worker model is outside the local assignment")
        return self.local_identity.model_id

    def _find_grant(self, view: SnapshotView, *, service: str, method: str,
                    actor: VerifiedCredential, local: VerifiedCredential,
                    binding: Binding, model_id: str,
                    assignment_id: str | None, sample=None) -> Grant:
        sample = sample or self.clock.sample()
        tenant = binding.get("tenant_account_id", actor.account_id)
        target_boot = binding.get("worker_boot_id", self.local_identity.boot_id)
        actor_boot = binding.get("coordinator_boot_id")
        if service == WORKER_SERVICE and method != "Describe":
            if binding.get("assignment_id") != assignment_id:
                raise ScopeError("worker binding differs from the fixed local assignment")
        if service == WORKER_SERVICE and method == "Describe":
            if (binding.get("assignment_id", assignment_id) != assignment_id
                    or binding.get("worker_boot_id", self.local_identity.boot_id)
                    != self.local_identity.boot_id):
                raise ScopeError("Describe binding differs from the fixed worker target")
            actor_boot = None
        return _select_current_grant(
            view, service=service, method=method, actor=actor, target=local,
            target_boot_id=target_boot, actor_boot_id=actor_boot,
            assignment_id=assignment_id, model_id=model_id,
            tenant_account_id=tenant, sample=sample)

    def _remember(self, table: OrderedDict, identity: str, now_mono: float):
        while table:
            first, timestamp = next(iter(table.items()))
            if now_mono - timestamp <= self.replay_ttl_seconds:
                break
            table.pop(first, None)
        if identity in table:
            raise ScopeError("operation identity was already used")
        if len(table) >= self.max_replay_records:
            raise ScopeError("bounded operation replay table is full")
        table[identity] = now_mono

    def authorize(self, service: str, method: str, payload: Any,
                  metadata, peer_certificate_pem: bytes) -> Authorization:
        """Authorize one direct-TLS request using only its TLS peer leaf."""
        return self._authorize_with_actor_pem(
            service, method, payload, metadata, peer_certificate_pem,
            ingress_guard=None)

    def authorize_gateway(self, service: str, method: str, payload: Any,
                          metadata, *, ingress, envelope: bytes,
                          request_bytes: bytes, frame_sequence: int,
                          wire_lane: str) -> Authorization:
        """Admit a single delegated request from one owned gateway TLS stream.

        This method is the only core boundary for gateway requests. It mints
        the ingress guard itself and then reuses the exact direct C1 checks.
        """
        from .gateway_ingress import (GatewayIngressError, GatewayOperationGuard,
                                      GatewayWorkerIngress)
        from .gateway_delegation import GatewayDelegationVerifier
        from .channel_tls import OwnedWorkerTLS

        if type(ingress) is not GatewayWorkerIngress:
            raise GatewayIngressError("an exact owned gateway ingress is required")
        verifier = ingress.verifier
        tls_owner = getattr(ingress, "_tls_owner", None)
        if (type(verifier) is not GatewayDelegationVerifier
                or type(tls_owner) is not OwnedWorkerTLS
                or not tls_owner.handshake_complete
                or tls_owner.endpoint_host != verifier.endpoint_host
                or tls_owner.endpoint_port != verifier.endpoint_port
                or tls_owner.clock is not self.clock
                or ingress.clock is not self.clock
                or verifier.clock is not self.clock
                or ingress.sessions is not self.session_bindings
                or verifier.local_identity != self.local_identity
                or ingress._local_identity != self.local_identity):
            raise GatewayIngressError("gateway ingress owners differ from this Authorizer")
        authorization = None
        c1_admission_started = False
        try:
            if type(request_bytes) is not bytes or not 1 <= len(request_bytes) <= MAX_REQUEST_BYTES:
                ingress.close("gateway-invalid-frame")
                raise BindingError("raw gateway request exceeds its 1 MiB bound")
            # Keep the ingress owner lock from guard minting through C1 checks
            # and the SessionBindings claim/check. Stream close therefore either
            # precedes admission or observes and invalidates the completed claim.
            with ingress.admission_transaction():
                guard = ingress.verify_operation(
                    envelope, metadata, request_bytes, frame_sequence, wire_lane)
                if type(guard) is not GatewayOperationGuard:
                    raise GatewayIngressError(
                        "ingress did not mint its concrete operation guard")
                guard.assert_live()
                delegated = guard.delegation
                if (delegated.payload["service"] != service
                        or delegated.payload["method"] != method
                        or service != WORKER_SERVICE or method not in WORKER_METHODS):
                    raise ScopeError(
                        "gateway delegation does not match the worker entrypoint")
                request = _request(payload, self.worker_request_type)
                serializer = getattr(request, "SerializeToString", None)
                if not callable(serializer):
                    raise BindingError(
                        "worker payload has no deterministic protobuf serializer")
                serialized = serializer(deterministic=True)
                if type(serialized) is not bytes or serialized != request_bytes:
                    raise BindingError(
                        "raw gateway bytes differ from the parsed worker payload")
                if delegated.payload["frame_sequence"] != frame_sequence:
                    raise ScopeError(
                        "gateway delegation sequence differs from ingress admission")
                c1_admission_started = True
                authorization = self._authorize_with_actor_pem(
                    service, method, request, metadata,
                    delegated.actor_certificate_pem, ingress_guard=guard)
                # The transaction exit also performs this liveness check. Keep
                # an explicit core check before publishing the Authorization.
                try:
                    authorization.assert_live()
                except BaseException:
                    # No handler dispatch has occurred yet. Roll back a new
                    # pending Open claim while its ingress transaction is still
                    # held, before exceptional-exit liveness can close the stream.
                    authorization.fail(cache_may_exist=False)
                    raise
            return authorization
        except Exception as error:
            if authorization is not None and not authorization._finished:
                try:
                    authorization.fail(cache_may_exist=False)
                finally:
                    authorization.close()
            if (not c1_admission_started
                    or isinstance(error, GatewayIngressError)):
                ingress.close("gateway-invalid-frame")
            if c1_admission_started and authorization is None:
                raise
            if isinstance(error, (SecurityError, GatewayIngressError)):
                raise
            raise BindingError("worker payload cannot be serialized deterministically") from error

    def _authorize_with_actor_pem(self, service: str, method: str, payload: Any,
                                  metadata, peer_certificate_pem: bytes,
                                  *, ingress_guard=None) -> Authorization:
        """Authorize one existing wire method before entering its runtime handler."""
        binding = parse_metadata(service, method, metadata)
        if type(peer_certificate_pem) is not bytes or len(peer_certificate_pem) > MAX_CERTIFICATE_BYTES:
            raise CredentialError("peer certificate exceeds its bound")
        view, sample = self._current_view()
        actor = self._verify_certificate(peer_certificate_pem, view, sample)
        local = self._verify_certificate(self.local_identity.certificate_pem,
                                         view, sample)
        if local.device_id != binding["target_device_id"]:
            raise ScopeError("target does not match this authenticated service")
        if (binding["account_id"] != actor.account_id or binding["device_id"] != actor.device_id
                or binding["role"] != actor.role
                or binding["credential_epoch"] != actor.credential_epoch):
            raise CredentialError("binding actor differs from the authenticated certificate")
        if service == WORKER_SERVICE:
            if method not in WORKER_METHODS or actor.role != "personal_coordinator" or local.role != "host":
                raise ScopeError("role cannot invoke this worker operation")
            request = _request(payload, self.worker_request_type)
            self._validate_worker_payload(method, binding, request)
            assignment = self.local_identity.assignment_id
            if assignment is None:
                raise ScopeError("host has no locally approved assignment")
        elif service == COORDINATOR_SERVICE:
            if method not in COORDINATOR_METHODS or actor.role != "consumer" or local.role != "personal_coordinator":
                raise ScopeError("role cannot invoke this coordinator operation")
            _coordinator_payload(payload)
            assignment = None
        else:
            raise BindingError("unknown secure service")
        model_id = self._model_for(service, method, payload)
        grant = self._find_grant(view, service=service, method=method, actor=actor,
                                 local=local, binding=binding, model_id=model_id,
                                 assignment_id=assignment, sample=sample)
        if service == WORKER_SERVICE and self.session_bindings is not None:
            self.session_bindings.assert_rotation_drained(actor=actor.record,
                                                          local=local.record)
        claim = None
        session_key = None
        lease = ""
        with self._replay_lock:
            self._remember(self._operation_ids, binding["operation_id"], sample.monotonic)
            if service == COORDINATOR_SERVICE and method == "Generate":
                request_key = f"{actor.account_id}/{actor.device_id}/{binding['request_id']}"
                self._remember(self._request_ids, request_key, sample.monotonic)
        if service == WORKER_SERVICE and method == "OpenSession":
            if self.session_bindings is None:
                raise ScopeError("worker session owner binding is unavailable")
            lifetime = _field(payload, "lifetime_ms", 0)
            positions = _field(payload, "max_positions", 0)
            idle_lease = _field(payload, "idle_lease_ms", 0)
            requested_expiry = (sample.monotonic + lifetime / 1000
                                if type(lifetime) is int else sample.monotonic)
            hard_expiry = min(
                requested_expiry,
                view.deadline_monotonic,
                view.credential_deadlines.get(actor.serial, sample.monotonic),
                view.credential_deadlines.get(local.serial, sample.monotonic),
                view.grant_deadlines.get(grant.identity, sample.monotonic),
                (ingress_guard.deadline_monotonic if ingress_guard is not None
                 else requested_expiry))
            claim = self.session_bindings.claim(
                binding, actor=actor.record, local=local.record, grant=grant,
                model_id=model_id, lifetime_ms=lifetime, max_positions=positions,
                idle_lease_ms=idle_lease, hard_expiry_monotonic=hard_expiry,
                requested_expiry_monotonic=requested_expiry,
                ingress_identity=(None if ingress_guard is None
                                  else ingress_guard.ingress_identity))
            session_key = claim.key
        elif service == WORKER_SERVICE and method not in ("Describe",):
            if self.session_bindings is None:
                raise ScopeError("worker session owner binding is unavailable")
            lease = _field(payload, "lease_token", "")
            session_key = self.session_bindings.check(
                binding, actor=actor.record, local=local.record, grant=grant,
                model_id=model_id, session_id=binding["session_id"],
                worker_boot_id=binding["worker_boot_id"], lease_token=lease,
                ingress_identity=(None if ingress_guard is None
                                  else ingress_guard.ingress_identity))
        return Authorization(self, binding=binding, actor=actor, local=local,
                             grant=grant, model_id=model_id, payload=payload,
                             session_claim=claim, session_key=session_key,
                             lease_token=lease, gateway_guard=ingress_guard)

    def _validate_worker_payload(self, method: str, binding: Binding, request):
        if type(_field(request, "protocol_version", 0)) is not int or _field(request, "protocol_version", 0) != 1:
            raise BindingError("worker payload protocol version must be 1")
        boot = _field(request, "worker_boot_id", "")
        model = _field(request, "manifest_fingerprint", "")
        if method == "Describe":
            if boot and boot != self.local_identity.boot_id:
                raise ScopeError("Describe expected another worker boot")
            if model and model != self.local_identity.model_id:
                raise ScopeError("Describe expected another model")
            if "worker_boot_id" in binding.fields and binding["worker_boot_id"] != self.local_identity.boot_id:
                raise BindingError("Describe boot binding differs from this worker")
            if "assignment_id" in binding.fields and binding["assignment_id"] != self.local_identity.assignment_id:
                raise BindingError("Describe assignment differs from this worker")
            return
        if boot != self.local_identity.boot_id or boot != binding["worker_boot_id"]:
            raise BindingError("worker boot differs between binding and payload")
        if model != self.local_identity.model_id:
            raise BindingError("model differs between worker payload and assignment")
        session_id = _field(request, "session_id", "")
        if type(session_id) is not str or not _SESSION_TEXT.fullmatch(session_id) or session_id != binding["session_id"]:
            raise BindingError("session identity differs between binding and worker payload")
        if method == "OpenSession":
            if _field(request, "lease_token", "") != "":
                raise BindingError("OpenSession must not carry a lease")
            if ("route_epoch" not in binding.fields or binding["route_epoch"] != 1
                    or binding["attempt"] != 1):
                raise BindingError("OpenSession route epoch and attempt must be 1")
        else:
            if method not in WORKER_METHODS:
                raise BindingError("unknown worker operation")
            if _field(request, "lease_token", "") == "":
                raise BindingError("worker session operation must carry its lease")

    def sweep(self):
        """Watcher tick: call at least every five seconds and cancel returned owners.

        A transport adapter must subscribe to SessionBindings notices and call
        worker/coordinator cancellation promptly. This core cannot terminate a
        handler thread or reclaim a runtime cache by itself.
        """
        if self.session_bindings is None:
            return ()
        try:
            view, sample = self._current_view()
            self.session_bindings.revalidate_snapshot(view, sample=sample)
            return self.session_bindings.poll()
        except (ClockError, SnapshotError):
            self.session_bindings.invalidate_all("clock-or-snapshot-unavailable")
            return self.session_bindings.records()
