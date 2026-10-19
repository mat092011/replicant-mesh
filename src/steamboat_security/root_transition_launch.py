"""Closed launch declarations for a cold root-transition cohort.

These values describe intended launch configuration only. They do not prove
that a process started, loaded weights, or is ready to serve requests.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass

from .codec import canonical_json
from .errors import BindingError
from .ids import validate_boot, validate_id

_HEX64 = re.compile(r"^[0-9a-f]{64}$", re.ASCII)
_HEX32 = re.compile(r"^[0-9a-f]{32}$", re.ASCII)
_SERIAL = re.compile(r"^[1-9a-f][0-9a-f]{0,39}$", re.ASCII)
_FIELDS = frozenset({
    "generation_sha256", "account_id", "device_id", "role", "serial",
    "certificate_sha256", "public_key_sha256", "credential_epoch", "boot_id",
    "admission_epoch", "configuration_sha256", "launch_nonce",
})
_ROLES = frozenset({"consumer", "host", "personal_coordinator"})
MAX_LAUNCH_ROLES = 16


@dataclass(frozen=True)
class RoleLaunchSpec:
    generation_sha256: str
    account_id: str
    device_id: str
    role: str
    serial: str
    certificate_sha256: str
    public_key_sha256: str
    credential_epoch: int
    boot_id: str
    admission_epoch: int
    configuration_sha256: str
    launch_nonce: str

    @property
    def identity(self) -> tuple[str, str, str]:
        return self.account_id, self.device_id, self.role


def _sha(value: object, name: str) -> str:
    if type(value) is not str or not _HEX64.fullmatch(value):
        raise BindingError(f"launch {name} must be lowercase SHA-256 hex")
    return value


def parse_role_launch_spec(raw: dict) -> RoleLaunchSpec:
    """Parse a closed, exact-typed launch declaration."""
    if type(raw) is not dict or set(raw) != _FIELDS:
        raise BindingError("launch specification has unknown or missing fields")
    try:
        account_id = validate_id(raw["account_id"], "acct")
        device_id = validate_id(raw["device_id"], "dev")
        boot_id = validate_boot(raw["boot_id"])
    except BindingError as error:
        raise BindingError("launch specification identity is invalid") from error
    role, serial = raw["role"], raw["serial"]
    if type(role) is not str or role not in _ROLES:
        raise BindingError("launch role is invalid")
    if type(serial) is not str or not _SERIAL.fullmatch(serial):
        raise BindingError("launch serial is invalid")
    for name in ("credential_epoch", "admission_epoch"):
        if type(raw[name]) is not int or raw[name] < 1:
            raise BindingError(f"launch {name} must be a positive exact integer")
    nonce = raw["launch_nonce"]
    if type(nonce) is not str or not _HEX32.fullmatch(nonce):
        raise BindingError("launch nonce must be 32 lowercase hex characters")
    return RoleLaunchSpec(
        _sha(raw["generation_sha256"], "generation hash"), account_id, device_id,
        role, serial, _sha(raw["certificate_sha256"], "certificate hash"),
        _sha(raw["public_key_sha256"], "public-key hash"), raw["credential_epoch"],
        boot_id, raw["admission_epoch"], _sha(raw["configuration_sha256"], "configuration hash"),
        nonce)


def role_launch_document(spec: RoleLaunchSpec) -> dict:
    """Revalidate and return the exact JSON document for a declaration."""
    if type(spec) is not RoleLaunchSpec:
        raise BindingError("launch document requires an exact RoleLaunchSpec")
    raw = {
        "generation_sha256": spec.generation_sha256, "account_id": spec.account_id,
        "device_id": spec.device_id, "role": spec.role, "serial": spec.serial,
        "certificate_sha256": spec.certificate_sha256,
        "public_key_sha256": spec.public_key_sha256,
        "credential_epoch": spec.credential_epoch, "boot_id": spec.boot_id,
        "admission_epoch": spec.admission_epoch,
        "configuration_sha256": spec.configuration_sha256,
        "launch_nonce": spec.launch_nonce,
    }
    checked = parse_role_launch_spec(raw)
    # Return the normalized closed document rather than trusting direct
    # construction of the frozen dataclass.
    return {
        "generation_sha256": checked.generation_sha256,
        "account_id": checked.account_id,
        "device_id": checked.device_id,
        "role": checked.role,
        "serial": checked.serial,
        "certificate_sha256": checked.certificate_sha256,
        "public_key_sha256": checked.public_key_sha256,
        "credential_epoch": checked.credential_epoch,
        "boot_id": checked.boot_id,
        "admission_epoch": checked.admission_epoch,
        "configuration_sha256": checked.configuration_sha256,
        "launch_nonce": checked.launch_nonce,
    }


def canonical_role_launch_digest(specs: tuple[RoleLaunchSpec, ...]) -> str:
    """Hash a sorted, unique bounded set of role launch declarations."""
    if type(specs) is not tuple or not 1 <= len(specs) <= MAX_LAUNCH_ROLES:
        raise BindingError("launch cohort must contain one to sixteen roles")
    docs = [role_launch_document(spec) for spec in specs]
    identities = tuple(spec.identity for spec in specs)
    if identities != tuple(sorted(identities)) or len(set(identities)) != len(identities):
        raise BindingError("launch cohort identities must be sorted and unique")
    return hashlib.sha256(canonical_json(docs)).hexdigest()
