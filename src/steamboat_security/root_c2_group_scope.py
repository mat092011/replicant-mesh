"""Closed signed scope for one selected-root C2 host component group.

This module parses and verifies declarations only. It creates no C1 identity,
runtime binding, process, reservation, or readiness claim.
"""
from __future__ import annotations

import base64
import hashlib
import json
import re
from dataclasses import dataclass
from types import MappingProxyType

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature, encode_dss_signature,
)

from .certificates import public_key_sha256
from .channel_policy import _signing_key, _verification_key
from .clock import Clock
from .codec import canonical_json
from .errors import BindingError, SnapshotError
from .ids import validate_boot, validate_id

MAX_SCOPE_BYTES = 16 * 1024
MAX_SIGNED_POLICY_BYTES = 24 * 1024
MAX_POLICY_LIFETIME_SECONDS = 300
PROFILE = "native_posix_root_c2_host_group_v1"
POLICY_DOMAIN = b"steamboat-c2-host-group-policy-v1\0"
_HEX64 = re.compile(r"^[0-9a-f]{64}$", re.ASCII)
_SERIAL = re.compile(r"^[1-9a-f][0-9a-f]{0,39}$", re.ASCII)
_COMPONENTS = ("worker-1", "worker-2", "worker-3")
_SCOPE_FIELDS = frozenset({"version", "profile", "account_id", "device_id", "role",
    "credential", "generation_sha256", "admission_epoch", "parent_boot_id",
    "model_id", "catalog_sha256", "catalog_public_key_sha256",
    "operator_public_key_sha256", "components"})
_CREDENTIAL_FIELDS = frozenset({"serial", "credential_epoch", "certificate_sha256",
    "public_key_sha256"})
_COMPONENT_FIELDS = frozenset({"component", "worker_boot_id", "assignment_id",
    "assignment_sha256", "channel_certificate_sha256", "channel_public_key_sha256"})


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise SnapshotError("C2 group policy contains a duplicate key")
        result[key] = value
    return result


def _reject_number(value):
    raise SnapshotError("C2 group policy contains a non-integer number")


def _hash(value, label):
    if type(value) is not str or not _HEX64.fullmatch(value):
        raise SnapshotError(f"C2 group {label} must be lowercase SHA-256 hex")
    return value


def _positive(value, label):
    if type(value) is not int or not 1 <= value <= 2**63 - 1:
        raise SnapshotError(f"C2 group {label} must be a positive exact integer")
    return value


@dataclass(frozen=True)
class C2Credential:
    serial: str
    credential_epoch: int
    certificate_sha256: str
    public_key_sha256: str


@dataclass(frozen=True)
class C2Component:
    component: str
    worker_boot_id: str
    assignment_id: str
    assignment_sha256: str
    channel_certificate_sha256: str
    channel_public_key_sha256: str


@dataclass(frozen=True)
class C2HostGroupScope:
    version: int
    profile: str
    account_id: str
    device_id: str
    role: str
    credential: C2Credential
    generation_sha256: str
    admission_epoch: int
    parent_boot_id: str
    model_id: str
    catalog_sha256: str
    catalog_public_key_sha256: str
    operator_public_key_sha256: str
    components: tuple[C2Component, ...]

    def to_document(self) -> dict:
        return {
            "version": self.version, "profile": self.profile,
            "account_id": self.account_id, "device_id": self.device_id,
            "role": self.role,
            "credential": {"serial": self.credential.serial,
                "credential_epoch": self.credential.credential_epoch,
                "certificate_sha256": self.credential.certificate_sha256,
                "public_key_sha256": self.credential.public_key_sha256},
            "generation_sha256": self.generation_sha256,
            "admission_epoch": self.admission_epoch,
            "parent_boot_id": self.parent_boot_id, "model_id": self.model_id,
            "catalog_sha256": self.catalog_sha256,
            "catalog_public_key_sha256": self.catalog_public_key_sha256,
            "operator_public_key_sha256": self.operator_public_key_sha256,
            "components": [{"component": c.component,
                "worker_boot_id": c.worker_boot_id,
                "assignment_id": c.assignment_id,
                "assignment_sha256": c.assignment_sha256,
                "channel_certificate_sha256": c.channel_certificate_sha256,
                "channel_public_key_sha256": c.channel_public_key_sha256}
                for c in self.components],
        }


def parse_c2_host_group_scope(value) -> C2HostGroupScope:
    """Validate a closed scope object and copy it into immutable typed values."""
    if type(value) is not dict or set(value) != _SCOPE_FIELDS:
        raise SnapshotError("C2 host group scope has unknown or missing fields")
    if type(value["version"]) is not int or value["version"] != 1:
        raise SnapshotError("unsupported C2 host group scope version")
    if type(value["profile"]) is not str or value["profile"] != PROFILE:
        raise SnapshotError("unsupported C2 host group profile")
    try:
        account_id = validate_id(value["account_id"], "acct")
        device_id = validate_id(value["device_id"], "dev")
        parent_boot = validate_boot(value["parent_boot_id"])
    except BindingError as error:
        raise SnapshotError("C2 host group identity is invalid") from error
    if type(value["role"]) is not str or value["role"] != "host":
        raise SnapshotError("C2 host group role is invalid")
    credential = value["credential"]
    if type(credential) is not dict or set(credential) != _CREDENTIAL_FIELDS:
        raise SnapshotError("C2 host credential has unknown or missing fields")
    serial = credential["serial"]
    if type(serial) is not str or not _SERIAL.fullmatch(serial):
        raise SnapshotError("C2 host credential serial is invalid")
    cred = C2Credential(serial, _positive(credential["credential_epoch"], "credential epoch"),
        _hash(credential["certificate_sha256"], "certificate hash"),
        _hash(credential["public_key_sha256"], "public-key hash"))
    model_id = _hash(value["model_id"], "model ID")
    components_raw = value["components"]
    if type(components_raw) is not list or not 1 <= len(components_raw) <= 3:
        raise SnapshotError("C2 host group must contain one to three components")
    components = []
    for raw in components_raw:
        if type(raw) is not dict or set(raw) != _COMPONENT_FIELDS:
            raise SnapshotError("C2 component has unknown or missing fields")
        name = raw["component"]
        if type(name) is not str or name not in _COMPONENTS:
            raise SnapshotError("C2 component name is invalid")
        try:
            boot = validate_boot(raw["worker_boot_id"])
            assignment = validate_id(raw["assignment_id"], "asg")
        except BindingError as error:
            raise SnapshotError("C2 component boot or assignment is invalid") from error
        if boot == parent_boot:
            raise SnapshotError("C2 component boot must differ from parent boot")
        components.append(C2Component(name, boot, assignment,
            _hash(raw["assignment_sha256"], "assignment hash"),
            _hash(raw["channel_certificate_sha256"], "channel certificate hash"),
            _hash(raw["channel_public_key_sha256"], "channel public-key hash")))
    names = [c.component for c in components]
    if names != sorted(names) or len(set(names)) != len(names):
        raise SnapshotError("C2 components must be sorted and unique")
    for attr, label in (("worker_boot_id", "worker boots"), ("assignment_id", "assignments")):
        values = [getattr(c, attr) for c in components]
        if len(values) != len(set(values)):
            raise SnapshotError(f"C2 component {label} must be unique")
    return C2HostGroupScope(1, PROFILE, account_id, device_id, "host", cred,
        _hash(value["generation_sha256"], "generation hash"),
        _positive(value["admission_epoch"], "admission epoch"), parent_boot,
        model_id, _hash(value["catalog_sha256"], "catalog hash"),
        _hash(value["catalog_public_key_sha256"], "catalog public-key hash"),
        _hash(value["operator_public_key_sha256"], "operator public-key hash"),
        tuple(components))


def parse_c2_host_group_scope_bytes(encoded: bytes) -> C2HostGroupScope:
    if type(encoded) is not bytes or not 1 <= len(encoded) <= MAX_SCOPE_BYTES:
        raise SnapshotError("C2 group scope exceeds its byte bound")
    try:
        raw = json.loads(encoded.decode("utf-8", "strict"), object_pairs_hook=_pairs,
                         parse_constant=_reject_number, parse_float=_reject_number,
                         parse_int=lambda s: int(s) if s == str(int(s)) else _reject_number(s))
    except SnapshotError:
        raise
    except (UnicodeError, ValueError, TypeError, RecursionError) as error:
        raise SnapshotError("C2 group scope is malformed JSON") from error
    if canonical_json(raw) != encoded:
        raise SnapshotError("C2 group scope is not canonical JSON")
    return parse_c2_host_group_scope(raw)


def validate_c2_scope_expectations(scope: C2HostGroupScope, *, account_id: str,
        device_id: str, credential_serial: str, credential_epoch: int,
        certificate_sha256: str, public_key_sha256: str, parent_boot_id: str,
        generation_sha256: str, admission_epoch: int,
        forbidden_worker_boot_ids=()) -> C2HostGroupScope:
    """Compare trusted caller pins and return the same inert scope value."""
    if type(scope) is not C2HostGroupScope:
        raise SnapshotError("expected an exact parsed C2 host group scope")
    if (type(credential_epoch) is not int or type(admission_epoch) is not int
            or any(type(x) is not str for x in (account_id, device_id,
                credential_serial, certificate_sha256, public_key_sha256,
                parent_boot_id, generation_sha256))):
        raise SnapshotError("trusted C2 scope expectations have invalid types")
    expected = (account_id, device_id, credential_serial, credential_epoch,
        certificate_sha256, public_key_sha256, parent_boot_id,
        generation_sha256, admission_epoch)
    actual = (scope.account_id, scope.device_id, scope.credential.serial,
        scope.credential.credential_epoch, scope.credential.certificate_sha256,
        scope.credential.public_key_sha256, scope.parent_boot_id,
        scope.generation_sha256, scope.admission_epoch)
    if actual != expected:
        raise SnapshotError("C2 group scope differs from trusted principal or root pins")
    try:
        forbidden = frozenset(validate_boot(x) for x in forbidden_worker_boot_ids)
    except (BindingError, TypeError) as error:
        raise SnapshotError("forbidden C2 worker boot set is invalid") from error
    if forbidden.intersection(c.worker_boot_id for c in scope.components):
        raise SnapshotError("C2 component boot is forbidden by caller")
    return scope


def _policy_payload(payload, operator_hash):
    if type(payload) is not dict or set(payload) != {"version", "issued_at", "expires_at", "scope"}:
        raise SnapshotError("C2 group policy has unknown or missing fields")
    if type(payload["version"]) is not int or payload["version"] != 1:
        raise SnapshotError("unsupported C2 group policy version")
    issued, expires = payload["issued_at"], payload["expires_at"]
    if type(issued) is not int or not 0 <= issued <= 2**63-1:
        raise SnapshotError("C2 policy issued_at is invalid")
    if type(expires) is not int or not 1 <= expires <= 2**63-1 or expires <= issued or expires-issued > MAX_POLICY_LIFETIME_SECONDS:
        raise SnapshotError("C2 policy expiry or lifetime is invalid")
    scope = parse_c2_host_group_scope(payload["scope"])
    if scope.operator_public_key_sha256 != operator_hash:
        raise SnapshotError("C2 group scope operator key pin does not match verifier")
    return issued, expires, scope


def sign_c2_host_group_policy(payload: dict, private_key_pem: bytes) -> bytes:
    key = _signing_key(private_key_pem)
    _policy_payload(payload, public_key_sha256(key.public_key()))
    signature = key.sign(POLICY_DOMAIN + canonical_json(payload), ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(signature)
    order = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
    if s > order // 2:
        signature = encode_dss_signature(r, order-s)
    encoded = canonical_json({"payload": payload,
        "signature": base64.b64encode(signature).decode("ascii")})
    if len(encoded) > MAX_SIGNED_POLICY_BYTES:
        raise SnapshotError("signed C2 group policy exceeds its byte bound")
    return encoded


@dataclass(frozen=True)
class VerifiedC2HostGroupPolicy:
    issued_at: int
    expires_at: int
    deadline_monotonic: float
    scope: C2HostGroupScope
    policy_digest: str
    canonical_payload: bytes


def verify_c2_host_group_policy(encoded: bytes, verification_key_pem: bytes,
        *, clock: Clock) -> VerifiedC2HostGroupPolicy:
    if type(clock) is not Clock:
        raise SnapshotError("C2 policy verifier requires exact Clock")
    if type(encoded) is not bytes or not 1 <= len(encoded) <= MAX_SIGNED_POLICY_BYTES:
        raise SnapshotError("signed C2 group policy exceeds its byte bound")
    key = _verification_key(verification_key_pem)
    try:
        envelope = json.loads(encoded.decode("utf-8", "strict"), object_pairs_hook=_pairs,
            parse_constant=_reject_number, parse_float=_reject_number,
            parse_int=lambda s: int(s) if s == str(int(s)) else _reject_number(s))
    except SnapshotError:
        raise
    except (UnicodeError, ValueError, TypeError, RecursionError) as error:
        raise SnapshotError("signed C2 group policy is malformed JSON") from error
    if type(envelope) is not dict or set(envelope) != {"payload", "signature"} or canonical_json(envelope) != encoded:
        raise SnapshotError("signed C2 group policy is noncanonical or has unknown fields")
    payload = envelope["payload"]
    canonical = canonical_json(payload)
    issued, expires, scope = _policy_payload(payload, public_key_sha256(key))
    text = envelope["signature"]
    try:
        if type(text) is not str or len(text) > 128:
            raise ValueError("signature text invalid")
        signature = base64.b64decode(text, validate=True)
        if base64.b64encode(signature).decode("ascii") != text:
            raise ValueError("signature encoding invalid")
        r, s = decode_dss_signature(signature)
        order = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
        if not (1 <= r < order and 1 <= s <= order//2) or encode_dss_signature(r, s) != signature:
            raise ValueError("signature is noncanonical")
        key.verify(signature, POLICY_DOMAIN + canonical, ec.ECDSA(hashes.SHA256()))
    except (ValueError, InvalidSignature) as error:
        raise SnapshotError("C2 group policy signature is invalid or noncanonical") from error
    sample = clock.sample()
    if issued > sample.earliest_wall or expires <= sample.latest_wall:
        raise SnapshotError("C2 group policy is not currently valid")
    return VerifiedC2HostGroupPolicy(issued, expires,
        sample.monotonic + expires - sample.latest_wall, scope,
        hashlib.sha256(canonical).hexdigest(), canonical)
