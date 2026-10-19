"""Bounded immutable session owner bindings and cleanup notifications."""

from __future__ import annotations

import hashlib
import hmac
import math
import secrets
import threading
from dataclasses import dataclass
from typing import Callable

from .clock import Clock
from .errors import SessionError


MAX_SESSION_RECORDS = 4096
MAX_LIVE_SESSIONS = 8
TOMBSTONE_SECONDS = 30
MAX_SESSION_SECONDS = 300
MAX_SESSION_CALLBACKS = 16


@dataclass(frozen=True)
class SessionNotice:
    target_device_id: str
    worker_boot_id: str
    session_id: str
    reason: str


@dataclass
class _Record:
    key: tuple[str, str, str]
    owner: tuple
    grant_identity: tuple
    actor_serial: str
    actor_public_key_sha256: str
    actor_epoch: int
    local_serial: str
    local_public_key_sha256: str
    local_epoch: int
    state: str
    created_monotonic: float
    requested_expiry_monotonic: float
    hard_expiry_monotonic: float
    pending_deadline_monotonic: float
    lease_digest: bytes | None = None
    tombstone_deadline: float | None = None
    invalid_reason: str | None = None
    reclaimed: bool = False


@dataclass(frozen=True)
class SessionClaim:
    key: tuple[str, str, str]
    owner: tuple
    is_new: bool


def _credential_identity(credential):
    return (credential.account_id, credential.device_id, credential.role,
            credential.serial, credential.public_key_sha256,
            credential.certificate_sha256, credential.credential_epoch)


def _owner_tuple(binding, actor, local, grant, model_id, parameters):
    fields = binding.fields
    owner_fields = tuple((name, fields[name]) for name in sorted(fields) if name != "operation_id")
    return (owner_fields, _credential_identity(actor), _credential_identity(local),
            grant.identity, model_id, parameters)


def _expected_owner(record: _Record, binding, actor, local, grant, model_id):
    operation_owner = _owner_tuple(binding, actor, local, grant, model_id,
                                   record.owner[-1])
    # Per-method grants differ, while the session binds the exact Open grant
    # and the live Authorizer independently verifies this operation's grant.
    return operation_owner[:3] + (record.owner[3],) + operation_owner[4:]


def _same_principal(left, right):
    return left[:3] == right[:3]


def _request_route_namespace(fields):
    """Keep replay fences local to one fixed worker boot and assignment."""
    return (fields.get("target_device_id"), fields.get("worker_boot_id"),
            fields.get("assignment_id"))


def _expiry_reason(record: _Record) -> str:
    """Distinguish the requested hard limit from a shorter policy cap."""
    if record.requested_expiry_monotonic <= record.hard_expiry_monotonic:
        return "session-hard-expiry"
    return "authorization-snapshot-changed"


class SessionBindings:
    """Host-side owner table. It never exports a lease and never evicts live state."""

    def __init__(self, *, clock: Clock, max_records: int = MAX_SESSION_RECORDS,
                 max_live_sessions: int = MAX_LIVE_SESSIONS,
                 pending_seconds: float = 30.0,
                 tombstone_seconds: float = TOMBSTONE_SECONDS):
        if type(max_records) is not int or not 1 <= max_records <= MAX_SESSION_RECORDS:
            raise ValueError("session record bound is invalid")
        if type(max_live_sessions) is not int or not 1 <= max_live_sessions <= MAX_LIVE_SESSIONS:
            raise ValueError("live session bound is invalid")
        if not (0 < pending_seconds <= 30 and 0 < tombstone_seconds <= TOMBSTONE_SECONDS):
            raise ValueError("session retention interval exceeds its bound")
        self.clock = clock
        self.max_records = max_records
        self.max_live_sessions = max_live_sessions
        self.pending_seconds = float(pending_seconds)
        self.tombstone_seconds = float(tombstone_seconds)
        self._lease_key = secrets.token_bytes(32)
        self._records: dict[tuple[str, str, str], _Record] = {}
        self._lock = threading.RLock()
        self._affected: dict[tuple[str, str, str], SessionNotice] = {}
        self._callbacks: list[Callable[[SessionNotice], None]] = []
        self._callback_faulted = False

    @staticmethod
    def key_for(binding):
        return (binding["target_device_id"], binding["worker_boot_id"], binding["session_id"])

    def assert_rotation_drained(self, *, actor, local):
        """Block new bindings for a rotated principal until old owners are terminal."""
        sample = self.clock.sample()
        new_actor = _credential_identity(actor)
        new_local = _credential_identity(local)
        with self._lock:
            self._prune_locked(sample.monotonic)
            if self._callback_faulted:
                raise SessionError("session cleanup notification is unhealthy")
            for record in self._records.values():
                if record.state == "tombstone":
                    continue
                old_actor, old_local = record.owner[1], record.owner[2]
                if ((_same_principal(old_actor, new_actor) and old_actor != new_actor)
                        or (_same_principal(old_local, new_local) and old_local != new_local)):
                    raise SessionError("credential rotation is waiting for old bindings to drain")

    def subscribe(self, callback):
        if not callable(callback):
            raise TypeError("session invalidation callback must be callable")
        with self._lock:
            if len(self._callbacks) >= MAX_SESSION_CALLBACKS:
                raise SessionError("session invalidation callback bound is full")
            self._callbacks.append(callback)

    def _prune_locked(self, now: float):
        for key, record in tuple(self._records.items()):
            if record.state == "tombstone" and record.tombstone_deadline is not None and now >= record.tombstone_deadline:
                self._records.pop(key, None)
                self._affected.pop(key, None)
            elif record.state == "pending" and now >= record.pending_deadline_monotonic:
                # An abandoned handler might have allocated a cache. Do not free
                # its owner slot until the adapter confirms cache reclamation.
                self._invalidate_locked(record, "open-admission-timeout")

    def _notice_locked(self, record: _Record, reason: str):
        notice = SessionNotice(*record.key, reason[:64])
        self._affected[record.key] = notice
        for callback in tuple(self._callbacks):
            try:
                callback(notice)
            except Exception:
                self._callback_faulted = True

    def _invalidate_locked(self, record: _Record, reason: str):
        if record.state in ("tombstone", "invalidated", "terminating"):
            return
        record.state = "invalidated"
        record.invalid_reason = reason[:64]
        self._notice_locked(record, reason)

    def claim(self, binding, *, actor, local, grant, model_id: str,
              lifetime_ms: int, max_positions: int, idle_lease_ms: int,
              hard_expiry_monotonic: float | None = None,
              requested_expiry_monotonic: float | None = None) -> SessionClaim:
        if type(lifetime_ms) is not int or not 1 <= lifetime_ms <= 300_000:
            raise SessionError("OpenSession lifetime is outside the 300-second bound")
        if type(max_positions) is not int or not 1 <= max_positions <= 1152:
            raise SessionError("OpenSession positions exceed the v1 context bound")
        if type(idle_lease_ms) is not int or not 1 <= idle_lease_ms <= 120_000:
            raise SessionError("OpenSession idle lease exceeds the v1 bound")
        sample = self.clock.sample()
        admission_expiry = sample.monotonic + lifetime_ms / 1000
        requested_expiry = (admission_expiry if requested_expiry_monotonic is None
                            else requested_expiry_monotonic)
        hard_expiry = (requested_expiry if hard_expiry_monotonic is None
                       else hard_expiry_monotonic)
        deadlines = (requested_expiry, hard_expiry)
        if (not all(type(deadline) is int
                    or (type(deadline) is float and math.isfinite(deadline))
                    for deadline in deadlines)
                or not math.isfinite(admission_expiry)
                or requested_expiry <= sample.monotonic
                or hard_expiry <= sample.monotonic
                or requested_expiry > admission_expiry
                or hard_expiry > requested_expiry):
            raise SessionError("OpenSession has no remaining authorization lifetime")
        key = self.key_for(binding)
        parameters = (lifetime_ms, max_positions, idle_lease_ms)
        owner = _owner_tuple(binding, actor, local, grant, model_id, parameters)
        with self._lock:
            self._prune_locked(sample.monotonic)
            if self._callback_faulted:
                raise SessionError("session cleanup notification is unhealthy")
            existing = self._records.get(key)
            if existing is not None:
                if not hmac.compare_digest(repr(existing.owner).encode(), repr(owner).encode()):
                    raise SessionError("session operation is not authorized")
                if existing.state != "open":
                    raise SessionError("session operation is not authorized")
                if sample.monotonic >= existing.hard_expiry_monotonic:
                    self._invalidate_locked(existing, "session-hard-expiry")
                    raise SessionError("session operation is not authorized")
                return SessionClaim(key, owner, False)
            fields = dict(owner[0])
            namespace = _request_route_namespace(fields)
            for record in self._records.values():
                prior_fields = dict(record.owner[0])
                old_actor, old_local = record.owner[1], record.owner[2]
                new_actor, new_local = owner[1], owner[2]
                if (record.state != "tombstone"
                        and ((_same_principal(old_actor, new_actor) and old_actor != new_actor)
                             or (_same_principal(old_local, new_local) and old_local != new_local))):
                    raise SessionError("credential rotation is waiting for old bindings to drain")
                # Reclaimed tombstones continue to fence request/route reuse,
                # but never block rotation after reclamation. Names are scoped
                # per worker boot/assignment so a pipeline may reuse a caller
                # request and route identifier on another fixed worker target.
                if (_request_route_namespace(prior_fields) == namespace
                        and (prior_fields.get("request_id") == fields.get("request_id")
                             or prior_fields.get("route_id") == fields.get("route_id"))):
                    raise SessionError("request or route identity is already bound")
            active = sum(record.state in ("pending", "open", "invalidated", "terminating")
                         for record in self._records.values())
            if active >= self.max_live_sessions or len(self._records) >= self.max_records:
                raise SessionError("session admission capacity is exhausted")
            record = _Record(key=key, owner=owner, grant_identity=grant.identity,
                             actor_serial=actor.serial,
                             actor_public_key_sha256=actor.public_key_sha256,
                             actor_epoch=actor.credential_epoch,
                             local_serial=local.serial,
                             local_public_key_sha256=local.public_key_sha256,
                             local_epoch=local.credential_epoch,
                             state="pending", created_monotonic=sample.monotonic,
                             requested_expiry_monotonic=requested_expiry,
                             hard_expiry_monotonic=hard_expiry,
                             pending_deadline_monotonic=min(
                                 sample.monotonic + self.pending_seconds, hard_expiry))
            self._records[key] = record
            return SessionClaim(key, owner, True)

    def _lease_digest(self, lease: str) -> bytes:
        return hmac.digest(self._lease_key, lease.encode("ascii"), "sha256")

    def seal_open(self, claim: SessionClaim, lease_token: str):
        if type(lease_token) is not str or not 16 <= len(lease_token) <= 256 or not lease_token.isascii():
            raise SessionError("OpenSession response lease is malformed")
        digest = self._lease_digest(lease_token)
        sample = self.clock.sample()
        with self._lock:
            record = self._records.get(claim.key)
            if record is None or record.owner != claim.owner:
                raise SessionError("OpenSession owner claim was lost")
            if claim.is_new:
                if (record.state != "pending"
                        or sample.monotonic >= min(record.pending_deadline_monotonic,
                                                   record.hard_expiry_monotonic)):
                    self._invalidate_locked(record, "open-admission-timeout")
                    raise SessionError("OpenSession owner claim expired")
                record.lease_digest = digest
                record.state = "open"
            else:
                if record.state != "open":
                    raise SessionError("duplicate OpenSession returned a different owner lease")
                if record.lease_digest is None or not hmac.compare_digest(record.lease_digest, digest):
                    self._invalidate_locked(record, "duplicate-open-lease-mismatch")
                    raise SessionError("duplicate OpenSession returned a different owner lease")

    def fail_open(self, claim: SessionClaim, *, cache_may_exist: bool):
        with self._lock:
            record = self._records.get(claim.key)
            if record is None or not claim.is_new or record.owner != claim.owner:
                return
            if record.state != "pending":
                return
            if cache_may_exist:
                self._invalidate_locked(record, "open-failed-cache-cleanup-required")
            else:
                self._records.pop(claim.key, None)

    def check(self, binding, *, actor, local, grant, model_id: str,
              session_id: str, worker_boot_id: str, lease_token: str):
        sample = self.clock.sample()
        key = (binding["target_device_id"], worker_boot_id, session_id)
        with self._lock:
            self._prune_locked(sample.monotonic)
            if self._callback_faulted:
                raise SessionError("session cleanup notification is unhealthy")
            record = self._records.get(key)
            expected_owner = (_expected_owner(record, binding, actor, local, grant, model_id)
                              if record is not None else None)
            if record is None or record.state != "open" or record.owner != expected_owner:
                raise SessionError("session operation is not authorized")
            if sample.monotonic >= record.hard_expiry_monotonic:
                self._invalidate_locked(record, "session-hard-expiry")
                raise SessionError("session operation is not authorized")
            if type(lease_token) is not str or not lease_token:
                raise SessionError("session operation is not authorized")
            try:
                supplied = self._lease_digest(lease_token)
            except UnicodeError as error:
                raise SessionError("session operation is not authorized") from error
            if record.lease_digest is None or not hmac.compare_digest(record.lease_digest, supplied):
                raise SessionError("session operation is not authorized")
            return key

    def assert_claim_live(self, claim: SessionClaim):
        sample = self.clock.sample()
        with self._lock:
            self._prune_locked(sample.monotonic)
            record = self._records.get(claim.key)
            if (record is None or record.owner != claim.owner
                    or record.state not in (("pending", "open") if claim.is_new else ("open",))):
                raise SessionError("session owner claim is not live")
            limit = record.pending_deadline_monotonic if record.state == "pending" else record.hard_expiry_monotonic
            if sample.monotonic >= limit:
                self._invalidate_locked(record, "session-owner-expired")
                raise SessionError("session owner claim expired")

    def authorization_deadline(self, key: tuple[str, str, str], *,
                               now_monotonic: float,
                               claim: SessionClaim | None = None,
                               terminal: bool = False) -> float:
        """Return the current session bound for a live authorization object."""
        with self._lock:
            record = self._records.get(key)
            if record is None:
                raise SessionError("session owner record disappeared")
            if claim is not None and (record.key != claim.key or record.owner != claim.owner):
                raise SessionError("session owner claim changed")
            if record.state == "pending":
                if claim is None or not claim.is_new:
                    raise SessionError("pending session owner claim is not live")
                deadline = record.pending_deadline_monotonic
            elif record.state == "open":
                deadline = record.hard_expiry_monotonic
            elif terminal and record.state in ("terminating", "tombstone"):
                deadline = record.hard_expiry_monotonic
            else:
                raise SessionError("session owner is invalidated")
            if now_monotonic >= deadline:
                raise SessionError("session authorization deadline expired")
            return deadline

    def assert_terminal(self, binding, *, actor, local, grant, model_id: str,
                        key: tuple[str, str, str]):
        """Validate only the immutable owner of its own completed terminal RPC."""
        sample = self.clock.sample()
        with self._lock:
            self._prune_locked(sample.monotonic)
            record = self._records.get(key)
            if (self._callback_faulted or record is None
                    or record.state not in ("terminating", "tombstone")
                    or record.owner != _expected_owner(record, binding, actor, local,
                                                       grant, model_id)):
                raise SessionError("terminal response no longer matches its session owner")

    def complete_operation(self, key: tuple[str, str, str], method: str,
                           *, reclaimed: bool = False):
        if method not in ("CloseSession", "CancelSession"):
            return
        sample = self.clock.sample()
        with self._lock:
            record = self._records.get(key)
            if record is None:
                raise SessionError("session owner record disappeared")
            if record.state not in ("open", "invalidated", "terminating"):
                raise SessionError("session is no longer live")
            if reclaimed:
                record.state = "tombstone"
                record.reclaimed = True
                record.lease_digest = None
                record.tombstone_deadline = sample.monotonic + self.tombstone_seconds
                self._affected.pop(key, None)
            else:
                self._invalidate_locked(record, "cache-cleanup-pending")
                record.state = "terminating"

    def mark_reclaimed(self, *, target_device_id: str, worker_boot_id: str, session_id: str):
        sample = self.clock.sample()
        key = (target_device_id, worker_boot_id, session_id)
        with self._lock:
            record = self._records.get(key)
            if record is None:
                return False
            if record.state not in ("invalidated", "terminating", "open", "pending"):
                return record.state == "tombstone"
            record.state = "tombstone"
            record.reclaimed = True
            record.lease_digest = None
            record.tombstone_deadline = sample.monotonic + self.tombstone_seconds
            self._affected.pop(key, None)
            return True

    def invalidate(self, *, key: tuple[str, str, str], reason: str):
        with self._lock:
            record = self._records.get(key)
            if record is not None:
                self._invalidate_locked(record, reason)

    def invalidate_all(self, reason: str):
        with self._lock:
            for record in self._records.values():
                self._invalidate_locked(record, reason)

    def revalidate_snapshot(self, view, *, sample):
        """Keep unchanged grants/epochs; notify for revocation, expiry or rotation."""
        with self._lock:
            for record in self._records.values():
                if record.state not in ("pending", "open"):
                    continue
                actor = view.credentials_by_serial.get(record.actor_serial)
                local = view.credentials_by_serial.get(record.local_serial)
                matching_grants = [grant for grant in view.grants
                                   if grant.identity == record.grant_identity]
                grant = matching_grants[0] if len(matching_grants) == 1 else None
                grant_ok = (grant is not None
                            and grant.not_before <= sample.earliest_wall
                            and sample.latest_wall < grant.not_after
                            and sample.monotonic < view.grant_deadlines[grant.identity])
                actor_ok = (actor is not None and actor.public_key_sha256 == record.actor_public_key_sha256
                            and actor.certificate_sha256 == record.owner[1][5]
                            and actor.credential_epoch == record.actor_epoch
                            and actor.not_before <= sample.earliest_wall
                            and sample.latest_wall < actor.not_after
                            and actor.device_id not in view.revoked_devices
                            and actor.serial not in view.revoked_serials)
                local_ok = (local is not None and local.public_key_sha256 == record.local_public_key_sha256
                            and local.certificate_sha256 == record.owner[2][5]
                            and local.credential_epoch == record.local_epoch
                            and local.not_before <= sample.earliest_wall
                            and sample.latest_wall < local.not_after
                            and local.device_id not in view.revoked_devices
                            and local.serial not in view.revoked_serials)
                if not actor_ok or not local_ok or not grant_ok:
                    self._invalidate_locked(record, "authorization-snapshot-changed")
                    continue
                record.hard_expiry_monotonic = min(
                    record.requested_expiry_monotonic,
                    view.deadline_monotonic,
                    view.credential_deadlines[actor.serial],
                    view.credential_deadlines[local.serial],
                    view.grant_deadlines[grant.identity])
                record.pending_deadline_monotonic = min(
                    record.pending_deadline_monotonic, record.hard_expiry_monotonic)
                if sample.monotonic >= record.hard_expiry_monotonic:
                    self._invalidate_locked(record, _expiry_reason(record))

    def poll(self) -> tuple[SessionNotice, ...]:
        """Mark time-expired owners and return bounded cleanup work to the adapter."""
        sample = self.clock.sample()
        with self._lock:
            self._prune_locked(sample.monotonic)
            for record in self._records.values():
                if record.state in ("pending", "open") and sample.monotonic >= record.hard_expiry_monotonic:
                    self._invalidate_locked(record, _expiry_reason(record))
            if len(self._affected) > self.max_records:
                self._callback_faulted = True
                raise SessionError("affected-session notification bound exceeded")
            return tuple(self._affected.values())

    def records(self) -> tuple[SessionNotice, ...]:
        """Bounded, redacted list for trusted local cancellation watchers."""
        with self._lock:
            return tuple(SessionNotice(*record.key, record.invalid_reason or record.state)
                         for record in self._records.values()
                         if record.state in ("invalidated", "terminating"))

    def record_count(self) -> int:
        with self._lock:
            return len(self._records)
