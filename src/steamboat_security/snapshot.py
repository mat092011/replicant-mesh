"""Signed, bounded authorization snapshots with freshness and rollback checks."""

from __future__ import annotations

import base64
import hashlib
import ipaddress
import inspect
import json
import math
import re
import threading
from dataclasses import dataclass, replace
from types import MappingProxyType

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from .certificates import ROLE_EKUS, _DNS, public_key_sha256
from .clock import Clock
from .codec import canonical_json, COORDINATOR_SERVICE, WORKER_SERVICE
from .errors import BindingError, CredentialError, SnapshotError
from .ids import validate_boot, validate_id


MAX_SNAPSHOT_BYTES = 64 * 1024
MAX_SNAPSHOT_LIFETIME_SECONDS = 300
SNAPSHOT_REFRESH_SECONDS = 30
SNAPSHOT_EXPIRY_CHECK_SECONDS = 5
MAX_SNAPSHOT_CALLBACKS = 16
_HEX64 = re.compile(r"^[0-9a-f]{64}$", re.ASCII)
_SERIAL = re.compile(r"^[1-9a-f][0-9a-f]{0,39}$", re.ASCII)
_ROLES = frozenset(ROLE_EKUS)
_KNOWN_METHODS = frozenset(
    f"{WORKER_SERVICE}/{method}" for method in
    ("Describe", "OpenSession", "RenewSession", "Step", "CloseSession", "CancelSession", "SessionStatus")
) | frozenset(
    f"{COORDINATOR_SERVICE}/{method}" for method in ("Describe", "Tokenize", "Generate")
)


def canonical_policy_digest(payload: dict) -> str:
    """Hash the canonical snapshot payload used as the signature input.

    The ECDSA signature is deliberately excluded because signatures for the
    same payload are randomized. Callers must still verify the signed snapshot
    before treating this digest as an installed policy identity.
    """
    if type(payload) is not dict:
        raise SnapshotError("snapshot policy digest requires an object payload")
    return hashlib.sha256(canonical_json(payload)).hexdigest()


def _object_pairs(pairs):
    output = {}
    for key, value in pairs:
        if key in output:
            raise SnapshotError("snapshot contains a duplicate key")
        output[key] = value
    return output


def _reject_constant(_value):
    raise SnapshotError("snapshot contains a non-finite number")


def _exact_int(value, name, *, minimum=0):
    if type(value) is not int or value < minimum:
        raise SnapshotError(f"snapshot {name} is invalid")
    return value


def _hash(value, name):
    if type(value) is not str or not _HEX64.fullmatch(value):
        raise SnapshotError(f"snapshot {name} is invalid")
    return value


def _sorted_unique_strings(value, name, *, max_items, pattern=None):
    if type(value) is not list or len(value) > max_items:
        raise SnapshotError(f"snapshot {name} exceeds its bound")
    if any(type(item) is not str for item in value):
        raise SnapshotError(f"snapshot {name} must contain strings")
    if len(set(value)) != len(value) or value != sorted(value):
        raise SnapshotError(f"snapshot {name} must be sorted and unique")
    if pattern is not None and any(not pattern.fullmatch(item) for item in value):
        raise SnapshotError(f"snapshot {name} contains an invalid value")
    return tuple(value)


@dataclass(frozen=True)
class CredentialRecord:
    account_id: str
    device_id: str
    role: str
    serial: str
    public_key_sha256: str
    certificate_sha256: str
    credential_epoch: int
    not_before: int
    not_after: int
    ekus: tuple[str, ...]
    dns_sans: tuple[str, ...]
    ip_sans: tuple[str, ...]

    @property
    def identity(self):
        return self.account_id, self.device_id, self.role


@dataclass(frozen=True)
class Grant:
    account_id: str
    device_id: str
    role: str
    actor_serial: str
    actor_public_key_sha256: str
    actor_credential_epoch: int
    tenant_account_id: str
    target_account_id: str
    target_device_id: str
    target_role: str
    target_serial: str
    target_public_key_sha256: str
    target_credential_epoch: int
    target_boot_id: str
    actor_boot_id: str | None
    assignment_id: str | None
    model_id: str
    method: str
    not_before: int
    not_after: int

    @property
    def identity(self):
        return (self.account_id, self.device_id, self.role, self.tenant_account_id,
                self.actor_serial, self.actor_public_key_sha256, self.actor_credential_epoch,
                self.target_account_id, self.target_device_id, self.target_role,
                self.target_serial, self.target_public_key_sha256, self.target_credential_epoch,
                self.target_boot_id, self.actor_boot_id, self.assignment_id,
                self.model_id, self.method, self.not_before, self.not_after)


@dataclass(frozen=True)
class SnapshotView:
    revision: int
    issued_at: int
    expires_at: int
    deadline_monotonic: float
    credential_deadlines: object
    grant_deadlines: object
    credentials_by_serial: object
    grants: tuple[Grant, ...]
    revoked_serials: frozenset[str]
    revoked_devices: frozenset[str]
    canonical_payload: bytes
    published_monotonic: float = 0.0

    @property
    def policy_digest(self) -> str:
        """SHA-256 of the canonical signed payload, excluding randomized signature bytes."""
        return hashlib.sha256(self.canonical_payload).hexdigest()

    def credential(self, serial: str) -> CredentialRecord | None:
        return self.credentials_by_serial.get(serial)

    def active_grants(self, sample):
        return tuple(grant for grant in self.grants
                     if grant.not_before <= sample.earliest_wall
                     and sample.latest_wall < grant.not_after
                     and sample.monotonic < self.grant_deadlines[grant.identity])


def _validate_payload(payload: object, *, prohibited_key_hashes=()) -> tuple[dict[str, CredentialRecord], tuple[Grant, ...]]:
    required = {"version", "revision", "issued_at", "expires_at", "revoked_serials",
                "revoked_devices", "credentials", "grants"}
    if type(payload) is not dict or set(payload) != required:
        raise SnapshotError("snapshot payload has unknown or missing fields")
    if _exact_int(payload["version"], "version", minimum=1) != 1:
        raise SnapshotError("unsupported snapshot version")
    revision = _exact_int(payload["revision"], "revision", minimum=1)
    issued = _exact_int(payload["issued_at"], "issued_at")
    expires = _exact_int(payload["expires_at"], "expires_at", minimum=1)
    if expires <= issued or expires - issued > MAX_SNAPSHOT_LIFETIME_SECONDS:
        raise SnapshotError("snapshot lifetime exceeds 300 seconds")
    revoked_serials = _sorted_unique_strings(payload["revoked_serials"], "revoked_serials",
                                             max_items=4096, pattern=_SERIAL)
    revoked_devices = _sorted_unique_strings(payload["revoked_devices"], "revoked_devices",
                                              max_items=4096)
    for device in revoked_devices:
        validate_id(device, "dev")
    raw_credentials = payload["credentials"]
    if type(raw_credentials) is not list or len(raw_credentials) > 512:
        raise SnapshotError("snapshot credential list exceeds its bound")
    credentials = {}
    credentials_by_identity = {}
    accounts_by_device = {}
    role_keys = set()
    role_certificates = set()
    prohibited_key_hashes = frozenset(prohibited_key_hashes)
    c_fields = {"account_id", "device_id", "role", "serial", "public_key_sha256",
                "certificate_sha256", "credential_epoch", "not_before", "not_after",
                "ekus", "dns_sans", "ip_sans"}
    for item in raw_credentials:
        if type(item) is not dict or set(item) != c_fields:
            raise SnapshotError("credential record has unknown or missing fields")
        account = validate_id(item["account_id"], "acct")
        device = validate_id(item["device_id"], "dev")
        role = item["role"]
        if type(role) is not str or role not in _ROLES:
            raise SnapshotError("credential record role is invalid")
        serial = item["serial"]
        if type(serial) is not str or not _SERIAL.fullmatch(serial):
            raise SnapshotError("credential serial is invalid")
        pub_hash = _hash(item["public_key_sha256"], "public_key_sha256")
        cert_hash = _hash(item["certificate_sha256"], "certificate_sha256")
        epoch = _exact_int(item["credential_epoch"], "credential_epoch", minimum=1)
        not_before = _exact_int(item["not_before"], "credential not_before")
        not_after = _exact_int(item["not_after"], "credential not_after", minimum=1)
        if not_after <= not_before or not_after - not_before > 900:
            raise SnapshotError("credential validity exceeds 900 seconds")
        ekus = _sorted_unique_strings(item["ekus"], "ekus", max_items=2)
        if set(ekus) != ROLE_EKUS[role]:
            raise SnapshotError("credential EKU set does not match its exact role")
        dns = _sorted_unique_strings(item["dns_sans"], "dns_sans", max_items=8)
        ips = _sorted_unique_strings(item["ip_sans"], "ip_sans", max_items=8)
        if any(value != value.lower() or not _DNS.fullmatch(value) or "*" in value for value in dns):
            raise SnapshotError("credential DNS SANs must be canonical fixed host names")
        try:
            if any(str(ipaddress.ip_address(value)) != value for value in ips):
                raise SnapshotError("credential IP SANs must use canonical address text")
        except ValueError as error:
            raise SnapshotError("credential IP SAN is invalid") from error
        identity_key = account, device, role
        prior_account = accounts_by_device.setdefault(device, account)
        if prior_account != account:
            raise SnapshotError("one stable device ID cannot belong to multiple accounts")
        if pub_hash in role_keys or cert_hash in role_certificates:
            raise SnapshotError("role credentials must use distinct keys and certificates")
        if pub_hash in prohibited_key_hashes:
            raise SnapshotError("role key cannot reuse an authority signing or CA key")
        role_keys.add(pub_hash)
        role_certificates.add(cert_hash)
        previous = credentials_by_identity.get(identity_key)
        if previous is not None and previous.credential_epoch >= epoch:
            raise SnapshotError("credential epochs must increase for a role identity")
        # A snapshot has one active serial per identity/role; staged replacement
        # certificates belong in operator preparation, not an overlapping grant.
        if previous is not None:
            raise SnapshotError("snapshot cannot overlap role credentials")
        record = CredentialRecord(account, device, role, serial, pub_hash, cert_hash,
                                  epoch, not_before, not_after, ekus, dns, ips)
        if serial in credentials or device in revoked_devices or serial in revoked_serials:
            raise SnapshotError("revoked or duplicate credential cannot be active")
        credentials[serial] = record
        credentials_by_identity[identity_key] = record
    raw_grants = payload["grants"]
    if type(raw_grants) is not list or len(raw_grants) > 2048:
        raise SnapshotError("snapshot grant list exceeds its bound")
    grants = []
    g_fields = {"account_id", "device_id", "role", "actor_serial",
                "actor_public_key_sha256", "actor_credential_epoch", "tenant_account_id",
                "target_account_id", "target_device_id", "target_role", "target_serial",
                "target_public_key_sha256", "target_credential_epoch", "target_boot_id",
                "actor_boot_id", "assignment_id", "model_id", "method", "not_before", "not_after"}
    seen_grants = set()
    for item in raw_grants:
        if type(item) is not dict or set(item) != g_fields:
            raise SnapshotError("grant has unknown or missing fields")
        account = validate_id(item["account_id"], "acct")
        device = validate_id(item["device_id"], "dev")
        role = item["role"]
        if type(role) is not str or role not in _ROLES:
            raise SnapshotError("grant role is invalid")
        tenant = validate_id(item["tenant_account_id"], "acct")
        actor_serial = item["actor_serial"]
        if type(actor_serial) is not str or not _SERIAL.fullmatch(actor_serial):
            raise SnapshotError("grant actor serial is invalid")
        actor_key_hash = _hash(item["actor_public_key_sha256"], "grant actor key hash")
        actor_epoch = _exact_int(item["actor_credential_epoch"], "grant actor epoch", minimum=1)
        target_account = validate_id(item["target_account_id"], "acct")
        target = validate_id(item["target_device_id"], "dev")
        target_role = item["target_role"]
        if type(target_role) is not str or target_role not in _ROLES:
            raise SnapshotError("grant target role is invalid")
        target_serial = item["target_serial"]
        if type(target_serial) is not str or not _SERIAL.fullmatch(target_serial):
            raise SnapshotError("grant target serial is invalid")
        target_key_hash = _hash(item["target_public_key_sha256"], "grant target key hash")
        target_epoch = _exact_int(item["target_credential_epoch"], "grant target epoch", minimum=1)
        target_boot = validate_boot(item["target_boot_id"])
        actor_boot = item["actor_boot_id"]
        if actor_boot is not None:
            actor_boot = validate_boot(actor_boot)
        assignment = item["assignment_id"]
        if assignment is not None:
            validate_id(assignment, "asg")
        model = _hash(item["model_id"], "grant model_id")
        method = item["method"]
        if type(method) is not str or method not in _KNOWN_METHODS:
            raise SnapshotError("grant method is unknown")
        start = _exact_int(item["not_before"], "grant not_before")
        stop = _exact_int(item["not_after"], "grant not_after", minimum=1)
        if stop <= start or stop - start > MAX_SNAPSHOT_LIFETIME_SECONDS:
            raise SnapshotError("grant validity exceeds 300 seconds")
        if method.startswith(f"{COORDINATOR_SERVICE}/"):
            if role != "consumer" or tenant != account or assignment is not None or actor_boot is not None:
                raise SnapshotError("consumer grant exceeds personal scope")
        else:
            if role != "personal_coordinator" or tenant != account or assignment is None or actor_boot is None:
                raise SnapshotError("worker grant exceeds personal coordinator scope")
        actor_record = credentials.get(actor_serial)
        target_record = credentials.get(target_serial)
        if (actor_record is None or actor_record.identity != (account, device, role)
                or actor_record.public_key_sha256 != actor_key_hash
                or actor_record.credential_epoch != actor_epoch):
            raise SnapshotError("grant does not bind the exact enrolled actor credential")
        if (target_record is None or target_record.identity != (target_account, target, target_role)
                or target_record.public_key_sha256 != target_key_hash
                or target_record.credential_epoch != target_epoch):
            raise SnapshotError("grant does not bind the exact enrolled target credential")
        if method.startswith(f"{COORDINATOR_SERVICE}/") and target_role != "personal_coordinator":
            raise SnapshotError("consumer service grant target must be a personal coordinator")
        if method.startswith(f"{WORKER_SERVICE}/") and target_role != "host":
            raise SnapshotError("worker grant target must be a host")
        grant = Grant(account, device, role, actor_serial, actor_key_hash, actor_epoch,
                      tenant, target_account, target, target_role, target_serial,
                      target_key_hash, target_epoch, target_boot, actor_boot,
                      assignment, model, method, start, stop)
        if grant.identity in seen_grants:
            raise SnapshotError("duplicate exact grant")
        seen_grants.add(grant.identity)
        grants.append(grant)
    if (set(revoked_serials) & credentials.keys()
            or set(revoked_devices) & {record.device_id for record in credentials.values()}):
        raise SnapshotError("snapshot contains an active revoked identity")
    return credentials, tuple(grants)


def signing_public_key(pem: bytes):
    try:
        key = serialization.load_pem_public_key(pem)
    except (ValueError, TypeError) as error:
        raise SnapshotError("snapshot verification key is malformed") from error
    if not isinstance(key, ec.EllipticCurvePublicKey) or not isinstance(key.curve, ec.SECP256R1):
        raise SnapshotError("snapshot verification key must be ECDSA P-256")
    return key


def sign_snapshot(payload: dict, private_key_pem: bytes) -> bytes:
    """Test/operator helper. Signing key is separate from the cohort CA key."""
    try:
        key = serialization.load_pem_private_key(private_key_pem, password=None)
    except (ValueError, TypeError) as error:
        raise SnapshotError("snapshot signing key is malformed") from error
    if not isinstance(key, ec.EllipticCurvePrivateKey) or not isinstance(key.curve, ec.SECP256R1):
        raise SnapshotError("snapshot signing key must be ECDSA P-256")
    signer_hash = public_key_sha256(key.public_key())
    _validate_payload(payload, prohibited_key_hashes=(signer_hash,))
    signed = canonical_json(payload)
    signature = key.sign(signed, ec.ECDSA(hashes.SHA256()))
    envelope = {"payload": payload, "signature": base64.b64encode(signature).decode("ascii")}
    encoded = canonical_json(envelope)
    if len(encoded) > MAX_SNAPSHOT_BYTES:
        raise SnapshotError("signed snapshot exceeds 64 KiB")
    return encoded


class SnapshotStore:
    """Pinned-key snapshot verifier; installs remain explicit and offline.

    ``durable_commit`` is an optional synchronous commit seam invoked before
    in-memory publication. This class does not implement filesystem persistence,
    durable high-water storage, or restart recovery for that callback.
    """

    def __init__(self, *, verification_key_pem: bytes, ca_certificate_pem: bytes,
                 clock: Clock, minimum_revision: int | None = None,
                 minimum_policy_digest: str | None = None,
                 durable_commit=None):
        if minimum_revision is None and minimum_policy_digest is None:
            pass
        elif (type(minimum_revision) is not int or minimum_revision <= 0
              or type(minimum_policy_digest) is not str
              or not _HEX64.fullmatch(minimum_policy_digest)):
            raise ValueError("snapshot minimum revision and policy digest must be supplied as a valid pair")
        self._minimum_revision = minimum_revision
        self._minimum_policy_digest = minimum_policy_digest
        self.clock = clock
        self._verification_key = signing_public_key(verification_key_pem)
        self._ca_public_key_hash = None
        try:
            ca = serialization.load_pem_public_key(verification_key_pem)
        except Exception:
            ca = None
        # The CA is checked by certificate validation; reject accidental reuse of
        # its key as the independent snapshot signer when both PEMs are supplied.
        try:
            from .certificates import verify_ca
            sample = clock.sample()
            root = verify_ca(ca_certificate_pem, now=sample.wall,
                             uncertainty_seconds=sample.uncertainty)
            self._ca_public_key_hash = public_key_sha256(root.public_key())
        except Exception as error:
            raise SnapshotError("pinned cohort CA is invalid") from error
        if public_key_sha256(self._verification_key) == self._ca_public_key_hash:
            raise SnapshotError("snapshot signing key must be separate from cohort CA")
        self._prohibited_role_key_hashes = frozenset(
            (public_key_sha256(self._verification_key), self._ca_public_key_hash))
        self.ca_certificate_pem = ca_certificate_pem
        self._view: SnapshotView | None = None
        self._encoded: bytes | None = None
        self._callbacks = []
        self._faulted = False
        self._durable_faulted = False
        self._durable_commit = durable_commit
        if durable_commit is not None and not callable(durable_commit):
            raise TypeError("durable_commit must be a synchronous callable")
        self._lock = threading.RLock()
        self._installing = False
        self._persisting = False

    def subscribe(self, callback):
        if not callable(callback):
            raise TypeError("snapshot callback must be callable")
        with self._lock:
            if len(self._callbacks) >= MAX_SNAPSHOT_CALLBACKS:
                raise SnapshotError("snapshot callback bound is full")
            self._callbacks.append(callback)

    def assert_role_key_allowed(self, public_key_hash: str) -> None:
        if public_key_hash in self._prohibited_role_key_hashes:
            raise CredentialError("role key cannot reuse an authority signing or CA key")

    def install(self, encoded: bytes) -> SnapshotView:
        with self._lock:
            if self._installing:
                raise SnapshotError("reentrant snapshot installation is forbidden")
            if self._durable_faulted:
                raise SnapshotError("durable snapshot state is faulted; trusted reload is required")
            self._installing = True
            try:
                return self._install_locked(encoded)
            finally:
                self._installing = False

    def _install_locked(self, encoded: bytes) -> SnapshotView:
        if type(encoded) is not bytes or not 1 <= len(encoded) <= MAX_SNAPSHOT_BYTES:
            raise SnapshotError("snapshot exceeds its byte bound")
        try:
            text = encoded.decode("utf-8", errors="strict")
            envelope = json.loads(text, object_pairs_hook=_object_pairs,
                                  parse_constant=_reject_constant)
        except SnapshotError:
            raise
        except (UnicodeError, ValueError, TypeError, RecursionError) as error:
            raise SnapshotError("snapshot envelope is malformed") from error
        if type(envelope) is not dict or set(envelope) != {"payload", "signature"}:
            raise SnapshotError("snapshot envelope has unknown or missing fields")
        if canonical_json(envelope) != encoded:
            raise SnapshotError("snapshot envelope is not canonical JSON")
        payload = envelope["payload"]
        signed = canonical_json(payload)
        signature_text = envelope["signature"]
        if type(signature_text) is not str or len(signature_text) > 128:
            raise SnapshotError("snapshot signature is malformed")
        try:
            signature = base64.b64decode(signature_text, validate=True)
            self._verification_key.verify(signature, signed, ec.ECDSA(hashes.SHA256()))
        except (ValueError, InvalidSignature) as error:
            raise SnapshotError("snapshot signature is invalid") from error
        credentials, grants = _validate_payload(
            payload, prohibited_key_hashes=self._prohibited_role_key_hashes)
        revision = payload["revision"]
        issued = payload["issued_at"]
        expires = payload["expires_at"]
        if self._minimum_revision is not None:
            if revision < self._minimum_revision:
                raise SnapshotError("snapshot is below the configured minimum revision")
            if (revision == self._minimum_revision
                    and canonical_policy_digest(payload) != self._minimum_policy_digest):
                raise SnapshotError("snapshot policy conflicts with the configured minimum revision")
        previous = self._view
        payload_digest = canonical_policy_digest(payload)
        if previous is not None:
            if revision < previous.revision or issued < previous.issued_at:
                raise SnapshotError("snapshot rollback detected")
            if revision == previous.revision and signed != previous.canonical_payload:
                raise SnapshotError("snapshot revision was reused with different content")
        sample = self.clock.sample()
        if issued > sample.earliest_wall:
            raise SnapshotError("snapshot issue time is in the future")
        if expires <= sample.latest_wall:
            raise SnapshotError("snapshot has expired")
        if previous is not None and revision == previous.revision:
            if self._durable_commit is not None:
                self._persisting = True
                try:
                    self._call_durable_commit(encoded, revision, payload_digest)
                    sample = self._durable_post_commit_sample()
                finally:
                    self._persisting = False
                if (sample.monotonic < previous.published_monotonic
                        or issued > sample.earliest_wall):
                    self._latch_durable_fault()
                    raise SnapshotError("snapshot validity changed during durable reconciliation")
                bounded = self._clip_prepared_view(previous, sample)
                if (sample.latest_wall >= bounded.expires_at
                        or sample.monotonic >= bounded.deadline_monotonic):
                    self._latch_durable_fault()
                    raise SnapshotError("snapshot expired during durable reconciliation")
                self._view = replace(bounded, published_monotonic=sample.monotonic)
            return self._current_at(sample)
        snapshot_deadline = sample.monotonic + (expires - sample.latest_wall)
        if previous is not None and previous.expires_at == expires:
            snapshot_deadline = min(snapshot_deadline, previous.deadline_monotonic)
        credential_deadlines = {}
        for serial, record in credentials.items():
            deadline = sample.monotonic + (record.not_after - sample.latest_wall)
            old_record = (previous.credentials_by_serial.get(serial)
                          if previous is not None else None)
            old_deadline = (previous.credential_deadlines.get(serial)
                            if previous is not None else None)
            if (old_record is not None and old_deadline is not None
                    and old_record.certificate_sha256 == record.certificate_sha256
                    and old_record.public_key_sha256 == record.public_key_sha256):
                deadline = min(deadline, old_deadline)
            credential_deadlines[serial] = deadline
        grant_deadlines = {}
        for grant in grants:
            deadline = sample.monotonic + (grant.not_after - sample.latest_wall)
            if previous is not None and grant.identity in previous.grant_deadlines:
                deadline = min(deadline, previous.grant_deadlines[grant.identity])
            grant_deadlines[grant.identity] = deadline
        view = SnapshotView(
            revision=revision, issued_at=issued, expires_at=expires,
            deadline_monotonic=snapshot_deadline,
            credential_deadlines=MappingProxyType(credential_deadlines),
            grant_deadlines=MappingProxyType(grant_deadlines),
            credentials_by_serial=MappingProxyType(credentials), grants=grants,
            revoked_serials=frozenset(payload["revoked_serials"]),
            revoked_devices=frozenset(payload["revoked_devices"]),
            canonical_payload=signed,
            published_monotonic=sample.monotonic)
        if self._durable_commit is not None:
            self._persisting = True
            try:
                self._call_durable_commit(encoded, revision, payload_digest)
                final_sample = self._durable_post_commit_sample()
            finally:
                self._persisting = False
            if final_sample.monotonic < sample.monotonic:
                self._latch_durable_fault()
                raise SnapshotError("monotonic clock moved backwards during durable commit")
            if issued > final_sample.earliest_wall:
                self._latch_durable_fault()
                raise SnapshotError("snapshot became future-dated during durable commit")
            view = self._clip_prepared_view(view, final_sample)
            if (final_sample.latest_wall >= view.expires_at
                    or final_sample.monotonic >= view.deadline_monotonic):
                self._latch_durable_fault()
                raise SnapshotError("snapshot expired before durable publication")
            view = replace(view, published_monotonic=final_sample.monotonic)
        self._view = view
        self._encoded = encoded
        self._faulted = False
        try:
            for callback in tuple(self._callbacks):
                callback(view)
        except BaseException as error:
            self._faulted = True
            if self._durable_commit is not None:
                self._durable_faulted = True
            raise SnapshotError("snapshot invalidation callback failed closed") from error
        return view

    def _latch_durable_fault(self):
        self._faulted = True
        self._durable_faulted = True

    def _call_durable_commit(self, encoded, revision, policy_digest):
        try:
            result = self._durable_commit(encoded, revision, policy_digest)
            if inspect.isawaitable(result):
                close = getattr(result, "close", None)
                if callable(close):
                    close()
                raise SnapshotError("durable commit hook must be synchronous")
            if result is not None:
                raise SnapshotError("durable commit hook must return None")
        except BaseException as error:
            self._latch_durable_fault()
            if isinstance(error, SnapshotError):
                raise
            raise SnapshotError("durable snapshot commit failed closed") from error

    def _durable_post_commit_sample(self):
        try:
            return self.clock.sample()
        except BaseException as error:
            self._latch_durable_fault()
            raise SnapshotError("clock failed after durable snapshot commit") from error

    @staticmethod
    def _clip_prepared_view(view, sample):
        deadline = min(view.deadline_monotonic,
                       sample.monotonic + (view.expires_at - sample.latest_wall))
        credential_deadlines = {
            serial: min(view.credential_deadlines[serial],
                        sample.monotonic + (record.not_after - sample.latest_wall))
            for serial, record in view.credentials_by_serial.items()}
        grant_deadlines = {
            grant.identity: min(view.grant_deadlines[grant.identity],
                                sample.monotonic + (grant.not_after - sample.latest_wall))
            for grant in view.grants}
        return replace(view, deadline_monotonic=deadline,
                       credential_deadlines=MappingProxyType(credential_deadlines),
                       grant_deadlines=MappingProxyType(grant_deadlines))

    def _current_at(self, sample):
        view = self._view
        if view is None or self._faulted:
            raise SnapshotError("no healthy signed authorization snapshot is installed")
        if sample.monotonic < view.published_monotonic:
            raise SnapshotError("sample predates snapshot publication")
        credential_deadlines = {}
        for serial, record in view.credentials_by_serial.items():
            candidate = sample.monotonic + (record.not_after - sample.latest_wall)
            credential_deadlines[serial] = min(
                candidate, view.credential_deadlines.get(serial, candidate))
        grant_deadlines = {}
        for grant in view.grants:
            candidate = sample.monotonic + (grant.not_after - sample.latest_wall)
            grant_deadlines[grant.identity] = min(
                candidate, view.grant_deadlines.get(grant.identity, candidate))
        snapshot_candidate = sample.monotonic + (view.expires_at - sample.latest_wall)
        bounded = replace(
            view,
            deadline_monotonic=min(view.deadline_monotonic, snapshot_candidate),
            credential_deadlines=MappingProxyType(credential_deadlines),
            grant_deadlines=MappingProxyType(grant_deadlines))
        self._view = bounded
        view = bounded
        if sample.latest_wall >= view.expires_at or sample.monotonic >= view.deadline_monotonic:
            raise SnapshotError("authorization snapshot expired")
        return view

    def current(self, *, sample=None) -> SnapshotView:
        with self._lock:
            if self._persisting:
                raise SnapshotError("snapshot reads are unavailable during durable commit")
            return self._current_at(sample if sample is not None else self.clock.sample())

    def assert_credential_live(self, view: SnapshotView, record: CredentialRecord,
                               sample) -> None:
        if record.serial in view.revoked_serials or record.device_id in view.revoked_devices:
            raise CredentialError("credential is revoked")
        deadline = view.credential_deadlines.get(record.serial, -1.0)
        if (sample.earliest_wall < record.not_before
                or sample.latest_wall >= record.not_after
                or sample.monotonic >= deadline):
            raise CredentialError("credential is outside its validity bound")


def snapshot_public_key_pem(private_key_pem: bytes) -> bytes:
    try:
        key = serialization.load_pem_private_key(private_key_pem, password=None)
    except (ValueError, TypeError) as error:
        raise SnapshotError("snapshot signing key is malformed") from error
    if not isinstance(key, ec.EllipticCurvePrivateKey) or not isinstance(key.curve, ec.SECP256R1):
        raise SnapshotError("snapshot signing key must be ECDSA P-256")
    return key.public_key().public_bytes(serialization.Encoding.PEM,
                                         serialization.PublicFormat.SubjectPublicKeyInfo)
