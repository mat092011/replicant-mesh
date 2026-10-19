"""Closed parser for selected, opaque C2 host runtime settings.

Parsing declarations does not open referenced files or grant runtime authority.
The selected C2 host binding remains responsible for pinning and guarding the
opaque bytes; later consumers must separately verify every referenced material.
"""
from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import PurePosixPath
import re
from collections.abc import Mapping
from types import MappingProxyType

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from steamboat_connector.catalog import validate_public_key
from steamboat_connector.traffic_budget import _ALLOCATION_ID
from steamboat_security.channel_policy import _gateway_id
from steamboat_security.codec import canonical_json
from steamboat_security.errors import SnapshotError
from steamboat_security.root_c2_runtime import (
    C2HostRuntimeBinding, MAX_RUNTIME_CONFIGURATION_BYTES,
)

PROFILE = "native_posix_c2_host_runtime_v1"
MAX_PEM_BYTES = 4096
MAX_INTEGER = (1 << 63) - 1
_HEX64 = re.compile(r"^[0-9a-f]{64}$", re.ASCII)
_PUBLIC_POINT_HEX = re.compile(r"^[0-9a-f]{130}$", re.ASCII)
_TOP_FIELDS = frozenset({
    "schema_version", "profile", "artifact_root", "catalog_public_key_hex",
    "component_allocations", "gateway", "traffic",
})
_GATEWAY_FIELDS = frozenset({
    "gateway_id", "policy_root", "initial_policy", "verification_key_pem",
    "minimum_revision", "minimum_policy_digest", "gateway_ca",
})
_TRAFFIC_FIELDS = frozenset({"state_path", "allocation_id", "clock_domain"})
_ALLOC_FIELDS = frozenset({"sessions", "kv_bytes", "cache_positions", "queued_calls"})


class C2HostSettingsError(ValueError):
    """Host runtime settings are not canonical, closed, or well-typed."""


@dataclass(frozen=True)
class HostAllocation:
    sessions: int
    kv_bytes: int
    cache_positions: int
    queued_calls: int


@dataclass(frozen=True)
class PinnedFile:
    path: str
    sha256: str


@dataclass(frozen=True)
class HostGatewaySettings:
    gateway_id: str
    policy_root: str
    initial_policy: PinnedFile
    verification_key_pem: bytes
    minimum_revision: int
    minimum_policy_digest: str
    gateway_ca: PinnedFile


@dataclass(frozen=True)
class HostTrafficSettings:
    state_path: str
    allocation_id: str
    clock_domain: str


@dataclass(frozen=True)
class C2HostSettings:
    schema_version: int
    profile: str
    artifact_root: str
    catalog_public_key_hex: str
    component_allocations: Mapping[str, HostAllocation]
    gateway: HostGatewaySettings
    traffic: HostTrafficSettings


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise C2HostSettingsError("runtime settings contain duplicate object keys")
        result[key] = value
    return result


def _reject_number(value):
    raise C2HostSettingsError("runtime settings contain non-integer numeric data")


def _object(value, fields, label):
    if type(value) is not dict or set(value) != fields:
        raise C2HostSettingsError(f"{label} has unknown or missing fields")
    return value


def _integer(value, *, minimum, maximum=MAX_INTEGER, label):
    if type(value) is not int or not minimum <= value <= maximum:
        raise C2HostSettingsError(f"{label} must be a bounded integer")
    return value


def _path(value, label):
    if (type(value) is not str or not value.startswith("/")
            or "\\" in value or "\x00" in value or "//" in value):
        raise C2HostSettingsError(f"{label} must be a normalized absolute POSIX path")
    parsed = PurePosixPath(value)
    if (str(parsed) != value or value == "/" or ".." in parsed.parts
            or any(part in ("", ".") for part in parsed.parts)):
        raise C2HostSettingsError(f"{label} must be a normalized absolute POSIX path")
    return value


def _pin(value, label):
    item = _object(value, frozenset({"path", "sha256"}), label)
    path = _path(item["path"], f"{label}.path")
    digest = item["sha256"]
    if type(digest) is not str or not _HEX64.fullmatch(digest):
        raise C2HostSettingsError(f"{label}.sha256 must be lowercase SHA-256 hex")
    return PinnedFile(path, digest)


def _public_p256_pem(value):
    if type(value) is not str:
        raise C2HostSettingsError("gateway verification key must be canonical public PEM")
    try:
        encoded = value.encode("ascii", "strict")
        if not 1 <= len(encoded) <= MAX_PEM_BYTES:
            raise ValueError("PEM size")
        key = serialization.load_pem_public_key(encoded)
        if (not isinstance(key, ec.EllipticCurvePublicKey)
                or not isinstance(key.curve, ec.SECP256R1)):
            raise ValueError("not P-256 public key")
        canonical = key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        if canonical != encoded:
            raise ValueError("noncanonical or trailing PEM bytes")
    except Exception as error:
        raise C2HostSettingsError(
            "gateway verification key must be canonical public P-256 PEM"
        ) from error
    return bytes(encoded)


def _validate_public_point(value):
    if type(value) is not str or not _PUBLIC_POINT_HEX.fullmatch(value):
        raise C2HostSettingsError("catalog public key must be lowercase uncompressed P-256 hex")
    try:
        raw = bytes.fromhex(value)
        key = validate_public_key(raw)
        canonical = key.public_bytes(
            serialization.Encoding.X962,
            serialization.PublicFormat.UncompressedPoint,
        )
        if canonical != raw:
            raise ValueError("noncanonical point")
    except Exception as error:
        raise C2HostSettingsError("catalog public key is not a valid P-256 point") from error


def parse_c2_host_settings(encoded: bytes) -> C2HostSettings:
    """Parse exact canonical settings bytes without opening any declared path."""
    if type(encoded) is not bytes or not 1 <= len(encoded) <= MAX_RUNTIME_CONFIGURATION_BYTES:
        raise C2HostSettingsError("runtime settings must be 1..16 KiB of bytes")
    try:
        value = json.loads(
            encoded.decode("utf-8", "strict"), object_pairs_hook=_pairs,
            parse_constant=_reject_number, parse_float=_reject_number,
        )
    except C2HostSettingsError:
        raise
    except (UnicodeError, ValueError, TypeError, RecursionError) as error:
        raise C2HostSettingsError("runtime settings are malformed JSON") from error
    try:
        canonical = canonical_json(value)
    except Exception as error:
        raise C2HostSettingsError("runtime settings cannot be canonically encoded") from error
    if canonical != encoded:
        raise C2HostSettingsError("runtime settings must be canonical JSON")
    doc = _object(value, _TOP_FIELDS, "runtime settings")
    if type(doc["schema_version"]) is not int or doc["schema_version"] != 1:
        raise C2HostSettingsError("runtime settings schema version is unsupported")
    if type(doc["profile"]) is not str or doc["profile"] != PROFILE:
        raise C2HostSettingsError("runtime settings profile is unsupported")
    artifact_root = _path(doc["artifact_root"], "artifact_root")
    key_hex = doc["catalog_public_key_hex"]
    _validate_public_point(key_hex)

    allocation_doc = doc["component_allocations"]
    if (type(allocation_doc) is not dict or not 1 <= len(allocation_doc) <= 3
            or list(allocation_doc) != sorted(allocation_doc)
            or any(name not in ("worker-1", "worker-2", "worker-3")
                   for name in allocation_doc)):
        raise C2HostSettingsError("component_allocations must be a sorted map of 1..3 workers")
    allocations = {}
    for name, raw in allocation_doc.items():
        item = _object(raw, _ALLOC_FIELDS, f"allocation {name}")
        allocations[name] = HostAllocation(
            sessions=_integer(item["sessions"], minimum=1, label=f"{name}.sessions"),
            kv_bytes=_integer(item["kv_bytes"], minimum=1, label=f"{name}.kv_bytes"),
            cache_positions=_integer(item["cache_positions"], minimum=1,
                                     label=f"{name}.cache_positions"),
            queued_calls=_integer(item["queued_calls"], minimum=0, maximum=8,
                                  label=f"{name}.queued_calls"),
        )

    gateway_doc = _object(doc["gateway"], _GATEWAY_FIELDS, "gateway")
    try:
        gateway_id = _gateway_id(gateway_doc["gateway_id"])
    except (SnapshotError, TypeError) as error:
        raise C2HostSettingsError("gateway_id is invalid") from error
    policy_root = _path(gateway_doc["policy_root"], "gateway.policy_root")
    initial_policy = _pin(gateway_doc["initial_policy"], "gateway.initial_policy")
    gateway_ca = _pin(gateway_doc["gateway_ca"], "gateway.gateway_ca")
    verification_key = _public_p256_pem(gateway_doc["verification_key_pem"])
    minimum_revision = _integer(gateway_doc["minimum_revision"], minimum=1,
                                label="gateway.minimum_revision")
    minimum_digest = gateway_doc["minimum_policy_digest"]
    if type(minimum_digest) is not str or not _HEX64.fullmatch(minimum_digest):
        raise C2HostSettingsError("gateway.minimum_policy_digest must be lowercase SHA-256 hex")

    traffic_doc = _object(doc["traffic"], _TRAFFIC_FIELDS, "traffic")
    state_path = _path(traffic_doc["state_path"], "traffic.state_path")
    allocation_id = traffic_doc["allocation_id"]
    if type(allocation_id) is not str or not _ALLOCATION_ID.fullmatch(allocation_id):
        raise C2HostSettingsError("traffic.allocation_id has invalid ledger identity grammar")
    clock_domain = traffic_doc["clock_domain"]
    if type(clock_domain) is not str or not 1 <= len(clock_domain) <= 256:
        raise C2HostSettingsError("traffic.clock_domain must contain 1..256 characters")

    return C2HostSettings(
        1, PROFILE, artifact_root, key_hex,
        MappingProxyType(allocations),
        HostGatewaySettings(gateway_id, policy_root, initial_policy,
                            verification_key, minimum_revision, minimum_digest,
                            gateway_ca),
        HostTrafficSettings(state_path, allocation_id, clock_domain),
    )


def load_c2_host_settings(binding: C2HostRuntimeBinding) -> C2HostSettings:
    """Parse settings through the exact selected host binding's live guard."""
    if type(binding) is not C2HostRuntimeBinding:
        raise TypeError("binding must be the exact C2HostRuntimeBinding")
    encoded = binding.runtime_configuration_bytes
    settings = parse_c2_host_settings(encoded)
    binding.assert_live()
    return settings
