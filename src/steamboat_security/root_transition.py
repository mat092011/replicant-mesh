"""Bounded declarations for offline, cold cohort-root transition preparation.

Parsing returns an immutable declaration only; it is not an owner-approved
operation and does not authorize certificate issuance or activation. The
protected loader adds only the existing safe-file and conservative-clock
checks. It does not verify external signatures, persist high-water state, or
provide CA key material.
"""

from __future__ import annotations

import ipaddress
import json
import math
import re
from dataclasses import dataclass
from os import PathLike

from .certificates import ROLE_EKUS, _DNS
from .clock import Clock
from .errors import BindingError, SnapshotError
from .files import safe_read
from .ids import validate_boot, validate_id


MAX_TRANSITION_APPROVAL_BYTES = 16 * 1024
MAX_TRANSITION_PRINCIPALS = 16
MAX_TRANSITION_SANS = 8
_HEX32 = re.compile(r"^[0-9a-f]{32}$", re.ASCII)
_HEX64 = re.compile(r"^[0-9a-f]{64}$", re.ASCII)
_SERIAL = re.compile(r"^[1-9a-f][0-9a-f]{0,39}$", re.ASCII)
_FIELDS = frozenset({
    "schema_version", "transition_id", "old_ca_sha256", "new_ca_sha256",
    "old_snapshot_key_sha256", "new_snapshot_key_sha256", "overlap_not_before",
    "overlap_not_after", "old_policy_revision", "old_policy_digest",
    "next_minimum_revision", "new_policy_digest", "affected_principals",
})
_PRINCIPAL_FIELDS = frozenset({
    "account_id", "device_id", "role", "old_boot_id", "old_serial",
    "old_certificate_sha256", "old_public_key_sha256", "old_credential_epoch",
    "old_admission_epoch", "new_csr_sha256", "dns_sans", "ip_sans",
})


@dataclass(frozen=True)
class AffectedPrincipal:
    account_id: str
    device_id: str
    role: str
    old_boot_id: str
    old_serial: str
    old_certificate_sha256: str
    old_public_key_sha256: str
    old_credential_epoch: int
    old_admission_epoch: int
    new_csr_sha256: str
    dns_sans: tuple[str, ...]
    ip_sans: tuple[str, ...]

    @property
    def identity(self) -> tuple[str, str, str]:
        return self.account_id, self.device_id, self.role

    @property
    def required_ekus(self) -> frozenset[str]:
        """Return the fixed EKUs for this role; the declaration cannot override them."""
        return ROLE_EKUS[self.role]


@dataclass(frozen=True)
class RootTransitionDeclaration:
    schema_version: int
    transition_id: str
    old_ca_sha256: str
    new_ca_sha256: str
    old_snapshot_key_sha256: str
    new_snapshot_key_sha256: str
    overlap_not_before: int
    overlap_not_after: int
    old_policy_revision: int
    old_policy_digest: str
    next_minimum_revision: int
    new_policy_digest: str
    affected_principals: tuple[AffectedPrincipal, ...]


@dataclass(frozen=True)
class LoadedRootTransitionApproval:
    """Protected-file/clock-checked declaration, not issuance authorization."""

    declaration: RootTransitionDeclaration


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise SnapshotError("root transition approval contains a duplicate field")
        result[key] = value
    return result


def _reject_constant(_value):
    raise SnapshotError("root transition approval contains a non-finite number")


def _reject_float(value):
    try:
        finite = math.isfinite(float(value))
    except (TypeError, ValueError, OverflowError):
        finite = False
    if not finite:
        raise SnapshotError("root transition approval contains a non-finite number")
    raise SnapshotError("root transition numeric fields must be integers")


def _exact_int(value, field: str, *, minimum: int) -> int:
    if type(value) is not int or value < minimum:
        raise SnapshotError(f"root transition {field} is invalid")
    return value


def _hash(value, field: str) -> str:
    if type(value) is not str or not _HEX64.fullmatch(value):
        raise SnapshotError(f"root transition {field} must be lowercase SHA-256 hex")
    return value


def _sorted_sans(value, field: str, *, dns: bool) -> tuple[str, ...]:
    if type(value) is not list or len(value) > MAX_TRANSITION_SANS:
        raise SnapshotError(f"root transition {field} exceeds its bound")
    if any(type(item) is not str for item in value):
        raise SnapshotError(f"root transition {field} must contain strings")
    if value != sorted(value) or len(value) != len(set(value)):
        raise SnapshotError(f"root transition {field} must be sorted and unique")
    if dns:
        if any(item != item.lower() or not _DNS.fullmatch(item) or "*" in item
               for item in value):
            raise SnapshotError("root transition DNS SAN is invalid")
    else:
        try:
            if any(str(ipaddress.ip_address(item)) != item for item in value):
                raise SnapshotError("root transition IP SAN must use canonical address text")
        except ValueError as error:
            raise SnapshotError("root transition IP SAN is invalid") from error
    return tuple(value)


def _principal(raw) -> AffectedPrincipal:
    if type(raw) is not dict or set(raw) != _PRINCIPAL_FIELDS:
        raise SnapshotError("root transition principal has unknown or missing fields")
    try:
        account_id = validate_id(raw["account_id"], "acct")
        device_id = validate_id(raw["device_id"], "dev")
        old_boot_id = validate_boot(raw["old_boot_id"])
    except BindingError as error:
        raise SnapshotError("root transition principal identity is invalid") from error
    role = raw["role"]
    if type(role) is not str or role not in ROLE_EKUS:
        raise SnapshotError("root transition principal role is invalid")
    serial = raw["old_serial"]
    if type(serial) is not str or not _SERIAL.fullmatch(serial):
        raise SnapshotError("root transition old serial is invalid")
    return AffectedPrincipal(
        account_id=account_id,
        device_id=device_id,
        role=role,
        old_boot_id=old_boot_id,
        old_serial=serial,
        old_certificate_sha256=_hash(raw["old_certificate_sha256"], "old certificate hash"),
        old_public_key_sha256=_hash(raw["old_public_key_sha256"], "old public key hash"),
        old_credential_epoch=_exact_int(raw["old_credential_epoch"], "old credential epoch", minimum=1),
        old_admission_epoch=_exact_int(raw["old_admission_epoch"], "old admission epoch", minimum=1),
        new_csr_sha256=_hash(raw["new_csr_sha256"], "new CSR hash"),
        dns_sans=_sorted_sans(raw["dns_sans"], "DNS SANs", dns=True),
        ip_sans=_sorted_sans(raw["ip_sans"], "IP SANs", dns=False),
    )


def parse_root_transition_declaration(encoded: bytes) -> RootTransitionDeclaration:
    """Parse a bounded closed v1 declaration; this does not establish trust."""
    if type(encoded) is not bytes or not 1 <= len(encoded) <= MAX_TRANSITION_APPROVAL_BYTES:
        raise SnapshotError("root transition approval exceeds its 16 KiB bound")
    try:
        raw = json.loads(encoded.decode("utf-8", errors="strict"),
                         object_pairs_hook=_pairs, parse_constant=_reject_constant,
                         parse_float=_reject_float)
    except SnapshotError:
        raise
    except (UnicodeError, ValueError, TypeError, RecursionError) as error:
        raise SnapshotError("root transition approval is malformed JSON") from error
    if type(raw) is not dict or set(raw) != _FIELDS:
        raise SnapshotError("root transition approval has unknown or missing fields")
    schema_version = _exact_int(raw["schema_version"], "schema version", minimum=1)
    if schema_version != 1:
        raise SnapshotError("unsupported root transition schema version")
    transition_id = raw["transition_id"]
    if type(transition_id) is not str or not _HEX32.fullmatch(transition_id):
        raise SnapshotError("root transition ID must be 32 lowercase hex characters")
    old_ca = _hash(raw["old_ca_sha256"], "old CA certificate hash")
    new_ca = _hash(raw["new_ca_sha256"], "new CA certificate hash")
    old_key = _hash(raw["old_snapshot_key_sha256"], "old snapshot key hash")
    new_key = _hash(raw["new_snapshot_key_sha256"], "new snapshot key hash")
    if old_ca == new_ca and old_key == new_key:
        raise SnapshotError("root transition must change at least one authority fingerprint")
    start = _exact_int(raw["overlap_not_before"], "overlap start", minimum=0)
    end = _exact_int(raw["overlap_not_after"], "overlap end", minimum=1)
    if end <= start or end - start > 300:
        raise SnapshotError("root transition overlap must be positive and at most 300 seconds")
    old_revision = _exact_int(raw["old_policy_revision"], "old policy revision", minimum=1)
    next_revision = _exact_int(raw["next_minimum_revision"], "next minimum revision", minimum=1)
    if next_revision != old_revision + 1:
        raise SnapshotError("next minimum revision must be old revision plus one")
    old_digest = _hash(raw["old_policy_digest"], "old policy digest")
    new_digest = _hash(raw["new_policy_digest"], "new policy digest")
    principals_raw = raw["affected_principals"]
    if (type(principals_raw) is not list
            or not 1 <= len(principals_raw) <= MAX_TRANSITION_PRINCIPALS):
        raise SnapshotError("root transition affected principal count is outside its bound")
    principals = tuple(_principal(item) for item in principals_raw)
    identities = tuple(item.identity for item in principals)
    if identities != tuple(sorted(identities)) or len(set(identities)) != len(identities):
        raise SnapshotError("affected principals must have sorted unique identities")
    for field, values in (
            ("old serial", tuple(item.old_serial for item in principals)),
            ("old certificate", tuple(item.old_certificate_sha256 for item in principals)),
            ("new CSR", tuple(item.new_csr_sha256 for item in principals))):
        if len(set(values)) != len(values):
            raise SnapshotError(f"root transition {field} pins must be unique")
    return RootTransitionDeclaration(
        schema_version=1,
        transition_id=transition_id,
        old_ca_sha256=old_ca,
        new_ca_sha256=new_ca,
        old_snapshot_key_sha256=old_key,
        new_snapshot_key_sha256=new_key,
        overlap_not_before=start,
        overlap_not_after=end,
        old_policy_revision=old_revision,
        old_policy_digest=old_digest,
        next_minimum_revision=next_revision,
        new_policy_digest=new_digest,
        affected_principals=principals,
    )


def _check_overlap_clock(declaration: RootTransitionDeclaration, clock: Clock) -> None:
    if not isinstance(clock, Clock):
        raise TypeError("root transition loader requires the configured Clock")
    sample = clock.sample()
    if (sample.earliest_wall < declaration.overlap_not_before
            or sample.latest_wall >= declaration.overlap_not_after):
        raise SnapshotError("trusted clock interval is outside the root transition overlap")


def load_protected_root_transition(
        path: str | PathLike, *, root: str | PathLike, expected_uid: int,
        clock: Clock) -> LoadedRootTransitionApproval:
    """Load a protected approval file and check its conservative overlap time.

    The result establishes neither issuance permission nor that any policy
    narrowing, new certificate, or activation step is valid.
    """
    encoded = safe_read(path, root=root, expected_uid=expected_uid,
                        max_bytes=MAX_TRANSITION_APPROVAL_BYTES)
    declaration = parse_root_transition_declaration(encoded)
    _check_overlap_clock(declaration, clock)
    return LoadedRootTransitionApproval(declaration=declaration)
