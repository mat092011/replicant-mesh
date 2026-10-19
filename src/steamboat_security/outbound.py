"""Bounded outbound identity and authority adapter for secure clients.

This module deliberately does not create worker session/cache ownership.  It
pins each outbound RPC to the local role credential, configured remote leaf,
current signed grant, and (for worker calls) one trusted in-process request
context supplied by the transport integration.
"""

from __future__ import annotations

import asyncio
import json
import math
import threading
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Any

from .authorization import (Authorization as IncomingAuthorization,
                            LocalIdentity, ScopeAuthorization, VerifiedCredential,
                            authorize_scope)
from .certificates import MAX_CERTIFICATE_BYTES
from .clock import Clock
from .codec import (COORDINATOR_METHODS, COORDINATOR_SERVICE, WORKER_METHODS,
                    WORKER_SERVICE, encode_binding)
from .errors import (BindingError, ClockError, CredentialError, ScopeError,
                     SessionError, SnapshotError)
from .ids import new_id, validate_boot, validate_id
from .snapshot import SnapshotStore


MAX_OUTBOUND_CONTEXTS = 4096
MAX_CONTEXT_CLEANUP_SECONDS = 20.0
MAX_BOOTSTRAP_LIFETIME_SECONDS = 300.0
MAX_BOOTSTRAP_DESCRIBES = 8
MAX_CONSUMER_CONTEXT_LIFETIME_SECONDS = 300.0
MAX_WORKER_REQUEST_BYTES = 1024 * 1024
MAX_GENERATE_BYTES = 32 * 1024
MAX_TOKENIZE_BYTES = 512 * 1024
MAX_COORDINATOR_RESPONSE_BYTES = 1024 * 1024
MAX_TEXT_BYTES = 64 * 1024
MAX_POSITIONS = 1152
VOCAB_SIZE = 32000


def _positive_seconds(value: object, name: str, maximum: float) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{name} must be a finite positive number")
    try:
        result = float(value)
    except (OverflowError, ValueError):
        raise ValueError(f"{name} must be a finite positive number") from None
    if not math.isfinite(result) or result <= 0 or result > maximum:
        raise ValueError(f"{name} is outside its finite bound")
    return result


def _text(value: object, name: str, maximum: int = 128) -> str:
    if type(value) is not str or not value or len(value) > maximum:
        raise ValueError(f"{name} is invalid")
    return value


@dataclass(frozen=True)
class OutboundTarget:
    """Owner-configured immutable peer identity for one client adapter."""

    service: str
    account_id: str
    device_id: str
    role: str
    boot_id: str
    model_id: str
    assignment_id: str | None
    serial: str
    public_key_sha256: str
    certificate_sha256: str
    credential_epoch: int

    def __post_init__(self):
        if self.service == WORKER_SERVICE:
            if self.role != "host" or self.assignment_id is None:
                raise ValueError("Worker target must be a fixed host assignment")
        elif self.service == COORDINATOR_SERVICE:
            if self.role != "personal_coordinator" or self.assignment_id is not None:
                raise ValueError("Coordinator target must be a personal coordinator")
        else:
            raise ValueError("outbound service is not an exact v1 wire service")
        if not ((self.service == WORKER_SERVICE and self.role == "host")
                or (self.service == COORDINATOR_SERVICE and self.role == "personal_coordinator")):
            raise ValueError("target service and role do not match")
        from .ids import validate_id
        validate_id(self.account_id, "acct")
        validate_id(self.device_id, "dev")
        validate_boot(self.boot_id)
        if self.assignment_id is not None:
            validate_id(self.assignment_id, "asg")
        if (type(self.model_id) is not str or len(self.model_id) != 64
                or any(ch not in "0123456789abcdef" for ch in self.model_id)):
            raise ValueError("model ID must be a lowercase SHA-256 fingerprint")
        if (type(self.serial) is not str or not 1 <= len(self.serial) <= 40
                or self.serial[0] == "0"
                or any(ch not in "0123456789abcdef" for ch in self.serial)):
            raise ValueError("target serial is invalid")
        for value in (self.public_key_sha256, self.certificate_sha256):
            if type(value) is not str or len(value) != 64 or any(
                    ch not in "0123456789abcdef" for ch in value):
                raise ValueError("target certificate pin is invalid")
        if type(self.credential_epoch) is not int or self.credential_epoch < 1:
            raise ValueError("target credential epoch is invalid")

    @classmethod
    def from_record(cls, *, service: str, record, boot_id: str,
                    model_id: str, assignment_id: str | None = None):
        """Build a target from an operator-verified CredentialRecord or mapping."""
        def get(name):
            if isinstance(record, dict):
                return record[name]
            return getattr(record, name)
        return cls(service, get("account_id"), get("device_id"), get("role"),
                   boot_id, model_id, assignment_id, get("serial"),
                   get("public_key_sha256"), get("certificate_sha256"),
                   get("credential_epoch"))


class BootstrapContext:
    """Adapter-minted finite capability for Worker Describe during startup."""

    __slots__ = ("_owner", "deadline_monotonic", "_uses", "_lock")

    def __init__(self, owner, deadline_monotonic: float, uses: int):
        self._owner = owner
        self.deadline_monotonic = deadline_monotonic
        self._uses = uses
        self._lock = threading.Lock()

    def _claim(self, owner, now: float) -> float:
        with self._lock:
            if self._owner is not owner or self._uses <= 0 or now >= self.deadline_monotonic:
                raise ScopeError("Worker Describe bootstrap capability is unavailable")
            self._uses -= 1
            return self.deadline_monotonic


class ConsumerRequestContext:
    """Adapter-minted correlation/deadline capability for consumer client calls.

    The request ID is metadata correlation only.  It does not authenticate a
    consumer; the current signed actor credential and target grant do that.
    """

    __slots__ = ("request_id", "deadline_monotonic", "_owner", "_closed",
                 "_generate_claimed", "_lock")

    def __init__(self, owner, request_id: str, deadline_monotonic: float):
        self.request_id = validate_id(request_id, "req")
        self.deadline_monotonic = float(deadline_monotonic)
        self._owner = owner
        self._closed = False
        self._generate_claimed = False
        self._lock = threading.Lock()

    def _check(self, owner, now: float) -> None:
        with self._lock:
            if self._owner is not owner or self._closed:
                raise ScopeError("consumer request context is not owned by this adapter")
            if not math.isfinite(now) or now >= self.deadline_monotonic:
                raise SessionError("consumer request context has expired")

    def _claim_generate(self, owner, now: float) -> None:
        with self._lock:
            if self._owner is not owner or self._closed:
                raise ScopeError("consumer request context is not owned by this adapter")
            if not math.isfinite(now) or now >= self.deadline_monotonic:
                raise SessionError("consumer request context has expired")
            if self._generate_claimed:
                raise ScopeError("Generate request context was already used")
            self._generate_claimed = True

    def close(self) -> None:
        with self._lock:
            self._closed = True


@dataclass
class _ContextPin:
    context: object
    fingerprint: tuple
    deadline: float


def _identity_tuple(credential: VerifiedCredential) -> tuple:
    record = credential.record
    return (record.account_id, record.device_id, record.role, record.serial,
            record.public_key_sha256, record.certificate_sha256,
            record.credential_epoch)


def _finite_remaining(value: Any, category: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise SessionError(f"{category} returned an invalid deadline")
    try:
        result = float(value)
    except (OverflowError, ValueError):
        raise SessionError(f"{category} returned an invalid deadline") from None
    if not math.isfinite(result) or result <= 0:
        raise SessionError(f"{category} has expired")
    return result


def _call_live(authorization) -> None:
    method = getattr(authorization, "assert_live", None)
    if not callable(method):
        raise ScopeError("trusted authorization lacks assert_live()")
    result = method()
    if asyncio.iscoroutine(result) or hasattr(result, "__await__"):
        close = getattr(result, "close", None)
        if callable(close):
            close()
        raise ScopeError("trusted assert_live() must be synchronous")
    if result is not None and result is not True:
        raise ScopeError("trusted authorization is not live")


def _worker_payload(payload, request_type, method: str, target: OutboundTarget,
                    context_values: dict | None):
    if request_type is None or type(payload) is not request_type:
        raise BindingError("Worker payload must be the configured generated Request type")
    descriptor = getattr(payload, "DESCRIPTOR", None)
    if getattr(descriptor, "full_name", None) != "steamboat.v1.Request":
        raise BindingError("Worker payload descriptor must be steamboat.v1.Request")
    byte_size = getattr(payload, "ByteSize", None)
    if not callable(byte_size):
        raise BindingError("Worker payload is not a parsed protobuf Request")
    size = byte_size()
    if type(size) is not int or not 0 <= size <= MAX_WORKER_REQUEST_BYTES:
        raise BindingError("Worker Request exceeds the 1 MiB bound")
    list_fields = getattr(payload, "ListFields", None)
    if callable(list_fields):
        present_fields = {field.name for field, _value in list_fields()}
    else:
        # Only the explicitly injected dependency-free unit fixture takes this
        # path. Production generated protobuf messages expose ListFields().
        present_fields = set(vars(payload))
    allowed_fields = {"protocol_version", "manifest_fingerprint",
                      "worker_boot_id", "timeout_ms"}
    if method != "Describe":
        allowed_fields.add("session_id")
    if method == "OpenSession":
        allowed_fields.update(("max_positions", "lifetime_ms", "idle_lease_ms"))
    elif method != "Describe":
        allowed_fields.add("lease_token")
    if method == "Step":
        allowed_fields.update(("sequence", "start_position", "token_count", "tensor"))
    if present_fields - allowed_fields:
        raise BindingError("Worker Request contains fields unsupported by this method")
    if method == "Step" and "tensor" not in present_fields:
        raise BindingError("Step requires a bounded tensor envelope")
    # Reject protobuf unknown fields before the secure transport serializes the
    # message. The bounded transport parser is still responsible for body size.
    copy_from = getattr(payload, "CopyFrom", None)
    discard_unknown = getattr(payload, "DiscardUnknownFields", None)
    serialize = getattr(payload, "SerializeToString", None)
    if callable(copy_from) and callable(discard_unknown) and callable(serialize):
        clean = type(payload)()
        clean.CopyFrom(payload)
        clean.DiscardUnknownFields()
        try:
            original_bytes = serialize(deterministic=True)
            clean_bytes = clean.SerializeToString(deterministic=True)
        except TypeError:
            original_bytes = serialize()
            clean_bytes = clean.SerializeToString()
        if original_bytes != clean_bytes:
            raise BindingError("Worker Request contains unknown protobuf fields")
    if type(getattr(payload, "protocol_version", None)) is not int or payload.protocol_version != 1:
        raise BindingError("Worker protocol version must be exactly 1")
    boot = getattr(payload, "worker_boot_id", "")
    model = getattr(payload, "manifest_fingerprint", "")
    if method == "Describe":
        if boot and boot != target.boot_id:
            raise ScopeError("Describe payload names a different target boot")
        if model and model != target.model_id:
            raise ScopeError("Describe payload names a different model")
        if context_values is not None and context_values.get("coordinator_boot_id") is None:
            raise ScopeError("contextual Describe requires a validated consumer context")
        if not 1 <= getattr(payload, "timeout_ms", 0) <= 300_000:
            raise BindingError("Describe timeout is invalid")
        return

    if context_values is None:
        raise ScopeError("Worker session operations require a trusted request context")
    if boot != target.boot_id or model != target.model_id:
        raise ScopeError("Worker request differs from the fixed target boot or model")
    session_id = validate_id(getattr(payload, "session_id", None), "ses")
    if session_id != context_values["session_id"]:
        raise ScopeError("Worker request session differs from its trusted context")
    if not 1 <= getattr(payload, "timeout_ms", 0) <= 300_000:
        raise BindingError("Worker timeout is invalid")
    lease = getattr(payload, "lease_token", None)
    if type(lease) is not str or len(lease) > 256:
        raise BindingError("Worker lease field is invalid")
    if method == "OpenSession":
        if lease:
            raise BindingError("OpenSession must not carry a lease")
        if (type(getattr(payload, "lifetime_ms", None)) is not int
                or not 1 <= payload.lifetime_ms <= 300_000
                or type(getattr(payload, "idle_lease_ms", None)) is not int
                or not 1 <= payload.idle_lease_ms <= payload.lifetime_ms
                or type(getattr(payload, "max_positions", None)) is not int
                or not 1 <= payload.max_positions <= MAX_POSITIONS):
            raise BindingError("OpenSession reservation fields are invalid")
        if (type(getattr(payload, "sequence", None)) is not int or payload.sequence != 0
                or type(getattr(payload, "start_position", None)) is not int or payload.start_position != 0
                or type(getattr(payload, "token_count", None)) is not int or payload.token_count != 0):
            raise BindingError("OpenSession sequence fields are invalid")
    else:
        if not lease:
            raise BindingError("Worker session operation must carry its lease")
        if method == "Step":
            if (type(getattr(payload, "sequence", None)) is not int
                    or payload.sequence < 0
                    or type(getattr(payload, "start_position", None)) is not int
                    or not 0 <= payload.start_position < MAX_POSITIONS
                    or type(getattr(payload, "token_count", None)) is not int
                    or not 1 <= payload.token_count <= MAX_POSITIONS
                    or payload.start_position + payload.token_count > MAX_POSITIONS):
                raise BindingError("Step sequence or position fields are invalid")


def _coordinator_payload(method: str, payload: Any) -> tuple[bytes, int]:
    if type(payload) is not dict:
        raise BindingError("Coordinator payload must be a parsed JSON object")
    if method == "Describe":
        if payload:
            raise BindingError("Coordinator Describe payload must be empty")
        limit = 1024
    elif method == "Tokenize":
        if set(payload) != {"text", "add_special_tokens"}:
            raise BindingError("Coordinator Tokenize fields are invalid")
        text = payload["text"]
        if type(text) is not str or not text:
            raise BindingError("Coordinator text must be nonempty UTF-8")
        try:
            if len(text.encode("utf-8")) > MAX_TEXT_BYTES:
                raise BindingError("Coordinator text exceeds 64 KiB")
        except UnicodeError as error:
            raise BindingError("Coordinator text is invalid UTF-8") from error
        if type(payload["add_special_tokens"]) is not bool:
            raise BindingError("Coordinator tokenization option must be boolean")
        limit = MAX_TOKENIZE_BYTES
    elif method == "Generate":
        required = {"input_ids", "new_tokens", "timeout_seconds", "capture_logits"}
        if not required <= payload.keys() or payload.keys() - required - {"forced_tokens"}:
            raise BindingError("Coordinator Generate fields are invalid")
        ids = payload["input_ids"]
        count = payload["new_tokens"]
        if (type(ids) is not list or not 1 <= len(ids) <= MAX_POSITIONS
                or any(type(token) is not int or not 0 <= token < VOCAB_SIZE for token in ids)
                or type(count) is not int or count < 1 or len(ids) + count > MAX_POSITIONS):
            raise BindingError("Coordinator token sequence or budget is invalid")
        forced = payload.get("forced_tokens")
        if forced is not None and (type(forced) is not list or len(forced) != count - 1
                                   or any(type(token) is not int or not 0 <= token < VOCAB_SIZE
                                          for token in forced)):
            raise BindingError("Coordinator forced token sequence is invalid")
        timeout = payload["timeout_seconds"]
        if (isinstance(timeout, bool) or not isinstance(timeout, (int, float))
                or not math.isfinite(timeout) or not 0 < timeout <= 300
                or type(payload["capture_logits"]) is not bool):
            raise BindingError("Coordinator Generate timeout or options are invalid")
        limit = MAX_GENERATE_BYTES
    else:
        raise BindingError("Coordinator method is not an exact v1 wire method")
    try:
        encoded = json.dumps(payload, separators=(",", ":"), ensure_ascii=False,
                             allow_nan=False).encode("utf-8")
    except (TypeError, ValueError, UnicodeError, RecursionError) as error:
        raise BindingError("Coordinator payload is not bounded JSON") from error
    if len(encoded) > limit:
        raise BindingError("Coordinator payload exceeds its method byte bound")
    return encoded, limit


class OutboundAuthorization:
    """One outbound RPC authorization; owns no remote worker cache state."""

    def __init__(self, adapter: "OutboundAuthorizer", *, service: str,
                 method: str, payload: Any, target_pem: bytes,
                 scope: ScopeAuthorization, binding_bytes: bytes,
                 deadline_cap: float, context: object,
                 context_deadline: float | None, bootstrap: BootstrapContext | None):
        self._adapter = adapter
        self.service = service
        self.method = method
        self.payload = payload
        self._target_pem = target_pem
        self._scope_identity = (scope.actor, scope.target, scope.grant.identity)
        self._binding_bytes = binding_bytes
        self._deadline_cap = deadline_cap
        self._context = context
        self._context_deadline = context_deadline
        self._bootstrap = bootstrap
        self._lock = threading.RLock()
        self._completed = False
        self._failed = False
        self._closed = False
        self._invalid = False

    @property
    def binding_bytes(self) -> bytes:
        return self._binding_bytes

    @property
    def canonical_binding_bytes(self) -> bytes:
        return self._binding_bytes

    @property
    def completed(self) -> bool:
        with self._lock:
            return self._completed and not self._closed

    def _scope_live(self, context_deadline: float | None):
        current = authorize_scope(
            self._adapter.snapshot_store, self._adapter.clock,
            service=self.service, method=self.method,
            actor_certificate_pem=self._adapter.local_identity.certificate_pem,
            target_certificate_pem=self._target_pem,
            target_device_id=self._adapter.target.device_id,
            target_boot_id=self._adapter.target.boot_id,
            actor_boot_id=(self._adapter.local_identity.boot_id
                           if self.service == WORKER_SERVICE else None),
            assignment_id=self._adapter.target.assignment_id,
            model_id=self._adapter.target.model_id,
            tenant_account_id=self._adapter.local_identity_account_hint)
        self._adapter._assert_fixed_target(current)
        if (_identity_tuple(current.actor) != _identity_tuple(self._scope_identity[0])
                or _identity_tuple(current.target) != _identity_tuple(self._scope_identity[1])
                or current.grant.identity != self._scope_identity[2]):
            raise ScopeError("outbound identity or exact grant changed")
        deadlines = [current.view.deadline_monotonic,
                     current.view.credential_deadlines[current.actor.serial],
                     current.view.credential_deadlines[current.target.serial],
                     current.view.grant_deadlines[current.grant.identity],
                     self._deadline_cap]
        if context_deadline is not None:
            deadlines.append(context_deadline)
        if self._bootstrap is not None:
            deadlines.append(self._bootstrap.deadline_monotonic)
        deadline = min(deadlines)
        sample = current.sample
        if sample.monotonic >= deadline:
            raise SessionError("outbound authorization deadline expired")
        return deadline, sample.monotonic

    def _check_locked(self):
        if self._closed or self._failed or self._invalid:
            raise SessionError("outbound authorization is no longer usable")
        if self._completed:
            return self._deadline_cap, self._adapter.clock.sample().monotonic
        try:
            context_deadline = self._adapter._assert_context_for_auth(
                self._context, self.service, self.method,
                expected_deadline=self._context_deadline)
            return self._scope_live(context_deadline)
        except Exception:
            self._invalid = True
            raise

    @property
    def deadline_monotonic(self) -> float:
        with self._lock:
            return self._check_locked()[0]

    def remaining_seconds(self) -> float:
        with self._lock:
            deadline, now = self._check_locked()
            remaining = deadline - now
            if not math.isfinite(remaining) or remaining <= 0:
                self._invalid = True
                raise SessionError("outbound authorization deadline expired")
            return remaining

    def assert_live(self):
        with self._lock:
            self._check_locked()
        return True

    def complete(self, response):
        with self._lock:
            if self._completed or self._closed or self._failed:
                raise SessionError("outbound authorization cannot be completed twice")
            self._check_locked()
            self._adapter._validate_response(self, response)
            self._completed = True
            return response

    def fail(self, *, cache_may_exist: bool = True):
        if type(cache_may_exist) is not bool:
            raise TypeError("cache_may_exist must be boolean")
        with self._lock:
            if not self._completed and not self._closed:
                self._failed = True

    def close(self):
        with self._lock:
            self._closed = True


class OutboundAuthorizer:
    """Fixed-target outbound policy adapter for exact C0 service/method names."""

    def __init__(self, *, local_identity: LocalIdentity,
                 snapshot_store: SnapshotStore, clock: Clock,
                 target: OutboundTarget, worker_request_type=None,
                 trusted_request_context_type=None,
                 allow_bootstrap_describe: bool = False,
                 max_context_records: int = MAX_OUTBOUND_CONTEXTS,
                 cleanup_grace_seconds: float = MAX_CONTEXT_CLEANUP_SECONDS):
        if snapshot_store.clock is not clock:
            raise ValueError("outbound adapter and snapshot store must use the same clock")
        if type(max_context_records) is not int or not 1 <= max_context_records <= MAX_OUTBOUND_CONTEXTS:
            raise ValueError("outbound context retention bound is invalid")
        cleanup_grace = _positive_seconds(cleanup_grace_seconds,
                                          "cleanup_grace_seconds",
                                          MAX_CONTEXT_CLEANUP_SECONDS)
        if target.service == WORKER_SERVICE:
            if local_identity.assignment_id is not None:
                raise ValueError("outbound coordinator identity cannot carry a host assignment")
            if worker_request_type is None or not isinstance(worker_request_type, type):
                raise ValueError("the exact generated worker Request type is required")
            if (getattr(getattr(worker_request_type, "DESCRIPTOR", None), "full_name", None)
                    != "steamboat.v1.Request"):
                raise ValueError("worker_request_type must be steamboat.v1.Request")
            if not isinstance(trusted_request_context_type, type):
                raise ValueError("the exact TrustedRequestContext type is required")
            if local_identity.model_id != target.model_id:
                raise ValueError("coordinator and fixed worker assignment models differ")
        elif target.service == COORDINATOR_SERVICE:
            if local_identity.assignment_id is not None:
                raise ValueError("consumer identity cannot carry a worker assignment")
            if local_identity.model_id != target.model_id:
                raise ValueError("consumer and fixed coordinator model IDs differ")
        self.local_identity = local_identity
        self.snapshot_store = snapshot_store
        self.clock = clock
        self.target = target
        self.worker_request_type = worker_request_type
        self.trusted_request_context_type = trusted_request_context_type
        self.allow_bootstrap_describe = allow_bootstrap_describe is True
        if type(allow_bootstrap_describe) is not bool:
            raise ValueError("allow_bootstrap_describe must be boolean")
        self.max_context_records = max_context_records
        self.cleanup_grace_seconds = cleanup_grace
        self._capability_owner = object()
        self._contexts: OrderedDict[int, _ContextPin] = OrderedDict()
        self._lock = threading.RLock()
        self.local_identity_account_hint = self._read_local_account()

    def _read_local_account(self) -> str:
        sample = self.clock.sample()
        view = self.snapshot_store.current(sample=sample)
        from .authorization import _verify_pinned_credential
        credential = _verify_pinned_credential(
            self.snapshot_store, self.local_identity.certificate_pem, view, sample)
        expected_role = ("personal_coordinator" if self.target.service == WORKER_SERVICE
                         else "consumer")
        if credential.role != expected_role:
            raise CredentialError("local credential role does not match outbound service")
        return credential.account_id

    def _assert_fixed_target(self, scope: ScopeAuthorization) -> None:
        credential = scope.target
        target = self.target
        if (credential.account_id != target.account_id
                or credential.device_id != target.device_id
                or credential.role != target.role
                or credential.serial != target.serial
                or credential.public_key_sha256 != target.public_key_sha256
                or credential.certificate_sha256 != target.certificate_sha256
                or credential.credential_epoch != target.credential_epoch
                or scope.model_id != target.model_id):
            raise CredentialError("pinned outbound peer differs from the immutable target")

    def create_bootstrap_context(self, *, lifetime_seconds: float = 30.0,
                                 max_describes: int = MAX_BOOTSTRAP_DESCRIBES) -> BootstrapContext:
        if (self.target.service != WORKER_SERVICE or not self.allow_bootstrap_describe
                or type(max_describes) is not int
                or not 1 <= max_describes <= MAX_BOOTSTRAP_DESCRIBES):
            raise ScopeError("bootstrap Describe is not explicitly configured")
        lifetime = _positive_seconds(lifetime_seconds, "bootstrap lifetime",
                                     MAX_BOOTSTRAP_LIFETIME_SECONDS)
        sample = self.clock.sample()
        return BootstrapContext(self._capability_owner,
                                sample.monotonic + lifetime, max_describes)

    def create_consumer_request_context(self, *, lifetime_seconds: float = 300.0) -> ConsumerRequestContext:
        if self.target.service != COORDINATOR_SERVICE:
            raise ScopeError("consumer request contexts are only for Coordinator calls")
        lifetime = _positive_seconds(lifetime_seconds, "consumer context lifetime",
                                     MAX_CONSUMER_CONTEXT_LIFETIME_SECONDS)
        sample = self.clock.sample()
        # Verify that the local consumer credential is still in the signed store.
        from .authorization import _verify_pinned_credential
        view = self.snapshot_store.current(sample=sample)
        _verify_pinned_credential(self.snapshot_store, self.local_identity.certificate_pem,
                                  view, sample)
        return ConsumerRequestContext(self._capability_owner, new_id("req"),
                                      sample.monotonic + lifetime)

    def _worker_context_values(self, context) -> tuple[dict, object, float]:
        values, authorization, hard_deadline = self._worker_context_shape(context)
        _call_live(authorization)
        sample = self.clock.sample()
        remaining = _finite_remaining(authorization.remaining_seconds(),
                                      "consumer authorization")
        deadline = min(hard_deadline, sample.monotonic + remaining)
        if deadline <= sample.monotonic:
            with self._lock:
                prior = self._contexts.get(id(context))
                if prior is None or prior.context is not context:
                    raise SessionError("trusted consumer context expired before first observation")
            raise SessionError("trusted consumer context expired")
        self._remember_context(context, values, deadline, sample.monotonic)
        return values, authorization, deadline

    def _worker_context_shape(self, context) -> tuple[dict, object, float]:
        if type(context) is not self.trusted_request_context_type:
            raise ScopeError("Worker call requires the exact trusted consumer request context")
        authorization = getattr(context, "authorization", None)
        if type(authorization) is not IncomingAuthorization:
            raise ScopeError("trusted request context must contain a real core Authorization")
        actor = getattr(authorization, "actor", None)
        local = getattr(authorization, "local", None)
        binding = getattr(authorization, "binding", None)
        if (actor is None or local is None or binding is None
                or actor.role != "consumer" or actor.account_id != context.tenant_account_id
                or local.role != "personal_coordinator"
                or local.account_id != context.tenant_account_id
                or binding.service != COORDINATOR_SERVICE or binding.method != "Generate"
                or binding.get("request_id") != context.request_id
                or _identity_tuple(local) != self._local_credential_tuple()):
            raise ScopeError("trusted context owner differs from the current consumer authorization")
        if (context.coordinator_boot_id != self.local_identity.boot_id
                or type(context.route_epoch) is not int or context.route_epoch != 1
                or type(context.attempt) is not int or context.attempt != 1):
            raise ScopeError("trusted context tenant, coordinator boot, route or attempt is invalid")
        validate_id(context.tenant_account_id, "acct")
        validate_id(context.request_id, "req")
        validate_id(context.session_id, "ses")
        validate_id(context.route_id, "route")
        sample = self.clock.sample()
        hard_deadline = getattr(context, "hard_monotonic_deadline", None)
        if isinstance(hard_deadline, bool) or not isinstance(hard_deadline, (int, float)):
            raise SessionError("trusted context hard deadline is invalid")
        hard_deadline = float(hard_deadline)
        if not math.isfinite(hard_deadline):
            raise SessionError("trusted context hard deadline is invalid")
        values = {"tenant_account_id": context.tenant_account_id,
                  "request_id": context.request_id, "session_id": context.session_id,
                  "route_id": context.route_id,
                  "coordinator_boot_id": context.coordinator_boot_id,
                  "route_epoch": 1, "attempt": 1}
        return values, authorization, hard_deadline

    def _local_credential_tuple(self) -> tuple:
        sample = self.clock.sample()
        view = self.snapshot_store.current(sample=sample)
        from .authorization import _verify_pinned_credential
        credential = _verify_pinned_credential(self.snapshot_store,
            self.local_identity.certificate_pem, view, sample)
        return _identity_tuple(credential)

    def _remember_context(self, context, values, deadline, now):
        key = id(context)
        fingerprint = tuple(values[name] for name in (
            "tenant_account_id", "request_id", "session_id", "route_id",
            "coordinator_boot_id", "route_epoch", "attempt"))
        with self._lock:
            expired = [k for k, pin in self._contexts.items()
                       if now >= pin.deadline + self.cleanup_grace_seconds]
            for k in expired:
                self._contexts.pop(k, None)
            prior = self._contexts.get(key)
            if prior is not None and prior.context is not context:
                raise ScopeError("trusted context identity collision")
            if prior is None and len(self._contexts) >= self.max_context_records:
                raise ScopeError("bounded outbound context table is full")
            if prior is None:
                self._contexts[key] = _ContextPin(context, fingerprint, deadline)
            else:
                if prior.fingerprint != fingerprint:
                    raise ScopeError("trusted context immutable owner changed")
                # A fresh successful core authorization can observe a later
                # snapshot cap, but never extends the context's hard deadline.
                context_hard = min(deadline, getattr(context, "hard_monotonic_deadline"))
                prior.deadline = max(prior.deadline, context_hard)
                self._contexts.move_to_end(key)

    def _assert_context_for_auth(self, context, service, method, expected_deadline=None):
        # Worker contexts are checked at admission and on every auth liveness tick.
        if service == WORKER_SERVICE:
            if type(context) is BootstrapContext:
                if method != "Describe":
                    raise ScopeError("bootstrap context is limited to Worker Describe")
                if context._owner is not self._capability_owner:
                    raise ScopeError("bootstrap context belongs to another adapter")
                now = self.clock.sample().monotonic
                if now >= context.deadline_monotonic:
                    raise SessionError("bootstrap Describe capability expired")
                return context.deadline_monotonic
            try:
                values, _authorization, deadline = self._worker_context_values(context)
                sample = self.clock.sample()
                if sample.monotonic < deadline:
                    return deadline
                if method not in ("CloseSession", "CancelSession", "SessionStatus"):
                    raise SessionError("trusted consumer context expired")
            except Exception:
                if method not in ("CloseSession", "CancelSession", "SessionStatus"):
                    raise
                values, _authorization, _hard_deadline = self._worker_context_shape(context)
                sample = self.clock.sample()
            key = id(context)
            with self._lock:
                pin = self._contexts.get(key)
                expected = tuple(values[name] for name in (
                    "tenant_account_id", "request_id", "session_id", "route_id",
                    "coordinator_boot_id", "route_epoch", "attempt"))
                if (pin is None or pin.context is not context or pin.fingerprint != expected
                        or sample.monotonic < pin.deadline
                        or sample.monotonic >= pin.deadline + self.cleanup_grace_seconds):
                    raise SessionError("trusted context cleanup grace expired")
            # The exact previously observed owner can request terminal cleanup
            # after its consumer authorization expires. Current outbound local
            # identity and grants are still checked below.
            return pin.deadline + self.cleanup_grace_seconds
        if type(context) is not ConsumerRequestContext:
            raise ScopeError("Coordinator call requires this adapter's ConsumerRequestContext")
        if context._owner is not self._capability_owner:
            raise ScopeError("consumer request context belongs to another adapter")
        now = self.clock.sample().monotonic
        context._check(self._capability_owner, now)
        return context.deadline_monotonic

    def authorize_outbound(self, *, service: str, method: str, payload: Any,
                           trusted_request_context: object,
                           peer_certificate_pem: bytes) -> OutboundAuthorization:
        if service != self.target.service:
            raise ScopeError("outbound service differs from the adapter's immutable target")
        if type(peer_certificate_pem) is not bytes or not 1 <= len(peer_certificate_pem) <= MAX_CERTIFICATE_BYTES:
            raise CredentialError("pinned peer certificate is invalid or oversized")
        if service == WORKER_SERVICE:
            if method not in WORKER_METHODS:
                raise BindingError("Worker method name is not an exact v1 wire method")
            return self._authorize_worker(method, payload, trusted_request_context,
                                          peer_certificate_pem)
        if service == COORDINATOR_SERVICE:
            if method not in COORDINATOR_METHODS:
                raise BindingError("Coordinator method name is not an exact v1 wire method")
            return self._authorize_coordinator(method, payload, trusted_request_context,
                                               peer_certificate_pem)
        raise BindingError("outbound service name is not an exact v1 wire service")

    def _current_local(self, peer_pem, service, method, *, actor_boot_id,
                       assignment_id, tenant):
        return authorize_scope(
            self.snapshot_store, self.clock, service=service, method=method,
            actor_certificate_pem=self.local_identity.certificate_pem,
            target_certificate_pem=peer_pem,
            target_device_id=self.target.device_id,
            target_boot_id=self.target.boot_id,
            actor_boot_id=actor_boot_id,
            assignment_id=assignment_id,
            model_id=self.target.model_id,
            tenant_account_id=tenant)

    def _common_fields(self, scope: ScopeAuthorization) -> dict:
        actor = scope.actor
        return {"binding_version": 1, "operation_id": new_id("op"),
                "account_id": actor.account_id, "device_id": actor.device_id,
                "role": actor.role, "credential_epoch": actor.credential_epoch,
                "target_device_id": self.target.device_id}

    def _authorize_worker(self, method, payload, context, peer_pem):
        if method == "Describe" and type(context) is BootstrapContext:
            now = self.clock.sample().monotonic
            bootstrap_deadline = context._claim(self._capability_owner, now)
            context_values = None
            context_deadline = bootstrap_deadline
        else:
            try:
                context_values, _ctx_auth, context_deadline = self._worker_context_values(context)
            except Exception:
                if method not in ("CloseSession", "CancelSession", "SessionStatus"):
                    raise
                context_values, _ctx_auth, _hard_deadline = self._worker_context_shape(context)
                sample = self.clock.sample()
                expected = tuple(context_values[name] for name in (
                    "tenant_account_id", "request_id", "session_id", "route_id",
                    "coordinator_boot_id", "route_epoch", "attempt"))
                with self._lock:
                    pin = self._contexts.get(id(context))
                    if (pin is None or pin.context is not context or pin.fingerprint != expected
                            or sample.monotonic < pin.deadline
                            or sample.monotonic >= pin.deadline + self.cleanup_grace_seconds):
                        raise SessionError("trusted context is not eligible for cleanup")
                    context_deadline = pin.deadline + self.cleanup_grace_seconds
            if (method in ("CloseSession", "CancelSession", "SessionStatus")
                    and context_deadline is not None):
                sample = self.clock.sample()
                if sample.monotonic >= context_deadline:
                    with self._lock:
                        pin = self._contexts.get(id(context))
                        if pin is None or pin.context is not context:
                            raise SessionError("trusted context cleanup record is unavailable")
                        context_deadline = pin.deadline + self.cleanup_grace_seconds
            _context_shape, _ctx_auth, hard_deadline = self._worker_context_shape(context)
            if method not in ("CloseSession", "CancelSession", "SessionStatus"):
                context_deadline = hard_deadline
        _worker_payload(payload, self.worker_request_type, method, self.target,
                        context_values)
        if method != "Describe" and context_values is None:
            raise ScopeError("contextless worker session operations are forbidden")
        scope = self._current_local(peer_pem, WORKER_SERVICE, method,
                                    actor_boot_id=self.local_identity.boot_id,
                                    assignment_id=self.target.assignment_id,
                                    tenant=self.local_identity_account_hint)
        self._assert_fixed_target(scope)
        fields = self._common_fields(scope)
        if method == "Describe":
            # Describe is still pinned to the immutable target boot/stage.
            fields.update(worker_boot_id=self.target.boot_id,
                          assignment_id=self.target.assignment_id)
        else:
            fields.update(coordinator_boot_id=context_values["coordinator_boot_id"],
                          tenant_account_id=context_values["tenant_account_id"],
                          request_id=context_values["request_id"],
                          session_id=context_values["session_id"],
                          route_id=context_values["route_id"],
                          route_epoch=1, attempt=1,
                          assignment_id=self.target.assignment_id,
                          worker_boot_id=self.target.boot_id)
        binding = encode_binding(WORKER_SERVICE, method, fields)
        return OutboundAuthorization(
            self, service=WORKER_SERVICE, method=method, payload=payload,
            target_pem=peer_pem, scope=scope, binding_bytes=binding,
            deadline_cap=(context_deadline if context_deadline is not None else math.inf),
            context=context, context_deadline=context_deadline, bootstrap=(
                context if type(context) is BootstrapContext else None))

    def _authorize_coordinator(self, method, payload, context, peer_pem):
        _coordinator_payload(method, payload)
        self._assert_context_for_auth(context, COORDINATOR_SERVICE, method)
        sample = self.clock.sample()
        context_deadline = min(context.deadline_monotonic,
                               sample.monotonic + self._context_remaining(context))
        if method == "Generate":
            context._claim_generate(self._capability_owner, sample.monotonic)
        scope = self._current_local(peer_pem, COORDINATOR_SERVICE, method,
                                    actor_boot_id=None, assignment_id=None,
                                    tenant=self.local_identity_account_hint)
        self._assert_fixed_target(scope)
        fields = self._common_fields(scope)
        if method == "Generate":
            fields["request_id"] = context.request_id
        binding = encode_binding(COORDINATOR_SERVICE, method, fields)
        return OutboundAuthorization(
            self, service=COORDINATOR_SERVICE, method=method, payload=payload,
            target_pem=peer_pem, scope=scope, binding_bytes=binding,
            deadline_cap=context.deadline_monotonic, context=context,
            context_deadline=context_deadline, bootstrap=None)

    def _context_remaining(self, context) -> float:
        sample = self.clock.sample()
        return _finite_remaining(context.deadline_monotonic - sample.monotonic,
                                 "consumer request context")

    def _validate_response(self, authorization: OutboundAuthorization, response):
        if authorization.service == WORKER_SERVICE:
            descriptor = getattr(response, "DESCRIPTOR", None)
            if getattr(descriptor, "full_name", None) != "steamboat.v1.Response":
                raise BindingError("Worker response must be parsed steamboat.v1.Response")
            size_method = getattr(response, "ByteSize", None)
            if not callable(size_method) or type(size_method()) is not int or size_method() > MAX_WORKER_REQUEST_BYTES:
                raise BindingError("Worker response exceeds its parsed protobuf bound")
            if response.code != "OK":
                return
            if (response.protocol_version != 1
                    or response.manifest_fingerprint != self.target.model_id
                    or response.worker_boot_id != self.target.boot_id):
                raise BindingError("Worker response identity differs from the fixed target")
            if authorization.method != "Describe":
                context = authorization._context
                if response.session_id != context.session_id:
                    raise BindingError("Worker response session differs from trusted context")
                if authorization.method == "OpenSession" and not response.lease_token:
                    raise BindingError("successful OpenSession response omitted its lease")
        else:
            if type(response) is not dict:
                raise BindingError("Coordinator response must be a parsed JSON object")
            try:
                encoded = json.dumps(response, separators=(",", ":"), ensure_ascii=False,
                                     allow_nan=False).encode("utf-8")
            except (TypeError, ValueError, UnicodeError, RecursionError) as error:
                raise BindingError("Coordinator response is not bounded JSON") from error
            if len(encoded) > MAX_COORDINATOR_RESPONSE_BYTES:
                raise BindingError("Coordinator response exceeds the JSON bound")


class AuthorizationWatcher:
    """Async outbound watcher compatible with secure_transport's callable hook."""

    def __init__(self, *, poll_interval_seconds: float = 1.0):
        self.poll_interval_seconds = _positive_seconds(
            poll_interval_seconds, "watcher poll interval", 5.0)

    async def __call__(self, authorization) -> None:
        while True:
            try:
                if getattr(authorization, "completed", False):
                    await asyncio.Future()
                authorization.assert_live()
                remaining = authorization.remaining_seconds()
                delay = min(self.poll_interval_seconds,
                            _finite_remaining(remaining, "outbound authorization"))
                await asyncio.sleep(delay)
            except asyncio.CancelledError:
                raise
            except Exception:
                # complete() and watcher validation serialize on the auth lock;
                # if completion won, keep the watcher parked until transport close.
                if getattr(authorization, "completed", False):
                    await asyncio.Future()
                return
