"""Closed, inert parser for selected C2 coordinator runtime settings."""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json

from steamboat_connector.catalog import validate_public_key
from steamboat_connector.c2_host_settings import (
    C2HostSettingsError, HostGatewaySettings, HostTrafficSettings,
    MAX_INTEGER, _GATEWAY_FIELDS, _HEX64, _TRAFFIC_FIELDS,
    _integer, _path, _pin, _public_p256_pem,
)
from steamboat_connector.traffic_budget import _ALLOCATION_ID
from steamboat_security.codec import canonical_json
from steamboat_security.errors import BindingError
from steamboat_security.ids import validate_id
from steamboat_security.root_c2_coordinator import C2CoordinatorRuntimeBinding
from steamboat_security.root_c2_runtime import MAX_RUNTIME_CONFIGURATION_BYTES

PROFILE = "native_posix_c2_coordinator_runtime_v1"
_TOP_FIELDS = frozenset({
    "schema_version", "profile", "artifact_root", "catalog_public_key_hex",
    "assignment", "gateway", "traffic",
})
_ASSIGNMENT_FIELDS = frozenset({
    "assignment_id", "catalog_sha256", "catalog_public_key_sha256",
    "assignment_sha256",
})


class C2CoordinatorSettingsError(ValueError):
    """Coordinator runtime settings are not canonical or well-typed."""


@dataclass(frozen=True)
class CoordinatorAssignmentSettings:
    assignment_id: str
    catalog_sha256: str
    catalog_public_key_sha256: str
    assignment_sha256: str


@dataclass(frozen=True)
class C2CoordinatorSettings:
    schema_version: int
    profile: str
    artifact_root: str
    catalog_public_key_hex: str
    assignment: CoordinatorAssignmentSettings
    gateway: HostGatewaySettings
    traffic: HostTrafficSettings


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise C2CoordinatorSettingsError(
                "coordinator settings contain duplicate object keys"
            )
        result[key] = value
    return result


def _reject_number(_value):
    raise C2CoordinatorSettingsError(
        "coordinator settings contain non-integer numeric data"
    )


def _object(value, fields, label):
    if type(value) is not dict or set(value) != fields:
        raise C2CoordinatorSettingsError(f"{label} has unknown or missing fields")
    return value


def _hash(value, label):
    if type(value) is not str or not _HEX64.fullmatch(value):
        raise C2CoordinatorSettingsError(f"{label} must be lowercase SHA-256 hex")
    return value


def parse_c2_coordinator_settings(encoded: bytes) -> C2CoordinatorSettings:
    """Parse canonical v1 declarations without opening any referenced path."""
    if type(encoded) is not bytes or not 1 <= len(encoded) <= MAX_RUNTIME_CONFIGURATION_BYTES:
        raise C2CoordinatorSettingsError("coordinator settings must be 1..16 KiB of bytes")
    try:
        value = json.loads(
            encoded.decode("utf-8", "strict"), object_pairs_hook=_pairs,
            parse_constant=_reject_number, parse_float=_reject_number,
        )
    except C2CoordinatorSettingsError:
        raise
    except (UnicodeError, ValueError, TypeError, RecursionError) as error:
        raise C2CoordinatorSettingsError("coordinator settings are malformed JSON") from error
    try:
        canonical = canonical_json(value)
    except Exception as error:
        raise C2CoordinatorSettingsError(
            "coordinator settings cannot be canonically encoded"
        ) from error
    if canonical != encoded:
        raise C2CoordinatorSettingsError("coordinator settings must be canonical JSON")
    doc = _object(value, _TOP_FIELDS, "coordinator settings")
    if type(doc["schema_version"]) is not int or doc["schema_version"] != 1:
        raise C2CoordinatorSettingsError("coordinator settings schema is unsupported")
    if type(doc["profile"]) is not str or doc["profile"] != PROFILE:
        raise C2CoordinatorSettingsError("coordinator settings profile is unsupported")
    try:
        artifact_root = _path(doc["artifact_root"], "artifact_root")
    except C2HostSettingsError as error:
        raise C2CoordinatorSettingsError(str(error)) from error

    key_hex = doc["catalog_public_key_hex"]
    if type(key_hex) is not str or len(key_hex) != 130 or any(
            char not in "0123456789abcdef" for char in key_hex):
        raise C2CoordinatorSettingsError(
            "catalog public key must be lowercase uncompressed P-256 hex"
        )
    try:
        public_key = bytes.fromhex(key_hex)
        validate_public_key(public_key)
    except Exception as error:
        raise C2CoordinatorSettingsError(
            "catalog public key is not a valid uncompressed P-256 point"
        ) from error

    assignment_doc = _object(doc["assignment"], _ASSIGNMENT_FIELDS, "assignment")
    assignment_id = assignment_doc["assignment_id"]
    try:
        assignment_id = validate_id(assignment_id, "asg")
    except BindingError as error:
        raise C2CoordinatorSettingsError("assignment_id is invalid") from error
    catalog_sha256 = _hash(assignment_doc["catalog_sha256"], "assignment.catalog_sha256")
    key_sha256 = _hash(
        assignment_doc["catalog_public_key_sha256"],
        "assignment.catalog_public_key_sha256",
    )
    if hashlib.sha256(public_key).hexdigest() != key_sha256:
        raise C2CoordinatorSettingsError(
            "assignment catalog key digest differs from catalog_public_key_hex"
        )
    assignment_sha256 = _hash(
        assignment_doc["assignment_sha256"], "assignment.assignment_sha256"
    )
    assignment = CoordinatorAssignmentSettings(
        assignment_id, catalog_sha256, key_sha256, assignment_sha256
    )

    # The two role settings share the exact closed field sets and validators.
    try:
        gateway_doc = _object(doc["gateway"], _GATEWAY_FIELDS, "gateway")
        from steamboat_security.channel_policy import _gateway_id
        from steamboat_security.errors import SnapshotError
        try:
            gateway_id = _gateway_id(gateway_doc["gateway_id"])
        except (SnapshotError, TypeError) as error:
            raise C2CoordinatorSettingsError("gateway_id is invalid") from error
        gateway = HostGatewaySettings(
            gateway_id,
            _path(gateway_doc["policy_root"], "gateway.policy_root"),
            _pin(gateway_doc["initial_policy"], "gateway.initial_policy"),
            _public_p256_pem(gateway_doc["verification_key_pem"]),
            _integer(gateway_doc["minimum_revision"], minimum=1,
                     maximum=MAX_INTEGER, label="gateway.minimum_revision"),
            _hash(gateway_doc["minimum_policy_digest"],
                  "gateway.minimum_policy_digest"),
            _pin(gateway_doc["gateway_ca"], "gateway.gateway_ca"),
        )
        traffic_doc = _object(doc["traffic"], _TRAFFIC_FIELDS, "traffic")
        allocation_id = traffic_doc["allocation_id"]
        if type(allocation_id) is not str or not _ALLOCATION_ID.fullmatch(allocation_id):
            raise C2CoordinatorSettingsError("traffic.allocation_id is invalid")
        clock_domain = traffic_doc["clock_domain"]
        if type(clock_domain) is not str or not 1 <= len(clock_domain) <= 256:
            raise C2CoordinatorSettingsError("traffic.clock_domain must contain 1..256 characters")
        traffic = HostTrafficSettings(
            _path(traffic_doc["state_path"], "traffic.state_path"),
            allocation_id, clock_domain,
        )
    except C2HostSettingsError as error:
        raise C2CoordinatorSettingsError(str(error)) from error

    return C2CoordinatorSettings(
        1, PROFILE, artifact_root, key_hex, assignment, gateway, traffic
    )


def load_c2_coordinator_settings(
    binding: C2CoordinatorRuntimeBinding,
) -> C2CoordinatorSettings:
    """Parse settings through the exact selected coordinator binding's guard."""
    if type(binding) is not C2CoordinatorRuntimeBinding:
        raise TypeError("binding must be the exact C2CoordinatorRuntimeBinding")
    encoded = binding.runtime_configuration
    settings = parse_c2_coordinator_settings(encoded)
    binding.assert_live()
    return settings
