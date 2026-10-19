"""Closed data contract for a future C2 physical-pool owner.

This module validates canonical configuration bytes only. It does not inspect
paths, authorize a host, acquire locks, or enforce operating-system limits.
"""

from dataclasses import dataclass
import hashlib
import unicodedata
from pathlib import PurePosixPath
import re

from .validation import json_bytes, strict_json_loads


MAX_CONFIG_BYTES = 4096
SCHEMA_VERSION = 2
PROFILE = "native_posix_c2_physical_pool_v1"
_MAX_I63 = (1 << 63) - 1
_HOST_OR_ALLOCATION_ID = re.compile(r"[0-9a-f]{64}\Z")
_CONFIG_FIELDS = frozenset({
    "schema_version", "profile", "physical_host_id", "allocation_id",
    "pool_kind", "pool_id", "owner_uid", "operator_root", "cgroup_parent",
    "memory_ceiling_bytes", "memory_headroom_bytes", "cpu_quota_millis",
    "pids_max", "swap_max_bytes", "disk_ceiling_bytes", "control",
})
_CONTROL_FIELDS = frozenset({
    "memory_bytes", "cpu_quota_millis", "pids_max", "disk_bytes",
})


class C2PoolConfigError(ValueError):
    """The supplied C2 pool configuration is malformed or out of bounds."""


@dataclass(frozen=True, slots=True)
class C2PoolControlAllocation:
    memory_bytes: int
    cpu_quota_millis: int
    pids_max: int
    disk_bytes: int


@dataclass(frozen=True, slots=True)
class C2PoolConfig:
    schema_version: int
    profile: str
    physical_host_id: str
    allocation_id: str
    pool_kind: str
    pool_id: str
    owner_uid: int
    operator_root: str
    cgroup_parent: str
    memory_ceiling_bytes: int
    memory_headroom_bytes: int
    cpu_quota_millis: int
    pids_max: int
    swap_max_bytes: int
    disk_ceiling_bytes: int
    control: C2PoolControlAllocation


def _integer(value, name, minimum, maximum):
    if type(value) is not int or not minimum <= value <= maximum:
        raise C2PoolConfigError(f"{name} must be an integer in [{minimum}, {maximum}]")
    return value


def _pool_id(value):
    if type(value) is not str or not value or len(value) > 128:
        raise C2PoolConfigError("pool_id must be nonempty UTF-8 text of at most 128 bytes")
    try:
        encoded = value.encode("utf-8")
    except UnicodeError as error:
        raise C2PoolConfigError("pool_id must be valid UTF-8 text") from error
    if len(encoded) > 128:
        raise C2PoolConfigError("pool_id must be nonempty UTF-8 text of at most 128 bytes")
    if any(unicodedata.category(character) == "Cc" for character in value):
        raise C2PoolConfigError("pool_id must not contain control characters")


def _absolute_path(value, name):
    if (type(value) is not str or not value or len(value) > MAX_CONFIG_BYTES
            or "\x00" in value or "\\" in value):
        raise C2PoolConfigError(f"{name} must be a normalized absolute POSIX path")
    try:
        value.encode("utf-8")
    except UnicodeError as error:
        raise C2PoolConfigError(f"{name} must be valid UTF-8 text") from error
    if any(unicodedata.category(character) == "Cc" for character in value):
        raise C2PoolConfigError(f"{name} must not contain control characters")
    if (not value.startswith("/") or value.startswith("//") or value.endswith("/")
            or "//" in value):
        raise C2PoolConfigError(f"{name} must be a normalized absolute POSIX path")
    parts = value.split("/")[1:]
    if not parts or any(part in ("", ".", "..") for part in parts):
        raise C2PoolConfigError(f"{name} must be normalized and traversal-free")
    if str(PurePosixPath(value)) != value:
        raise C2PoolConfigError(f"{name} must be a normalized absolute POSIX path")


def _validate_document(document):
    if type(document) is not dict or frozenset(document) != _CONFIG_FIELDS:
        raise C2PoolConfigError("C2 pool config fields do not match the closed schema")

    if type(document["schema_version"]) is not int or document["schema_version"] != SCHEMA_VERSION:
        raise C2PoolConfigError("unsupported C2 pool config schema version")
    if type(document["profile"]) is not str or document["profile"] != PROFILE:
        raise C2PoolConfigError("unsupported C2 pool config profile")
    for name in ("physical_host_id", "allocation_id"):
        value = document[name]
        if type(value) is not str or not _HOST_OR_ALLOCATION_ID.fullmatch(value):
            raise C2PoolConfigError(f"{name} must be 64 lowercase hexadecimal characters")
    if type(document["pool_kind"]) is not str or document["pool_kind"] != "system_ram":
        raise C2PoolConfigError("pool_kind must be system_ram")
    _pool_id(document["pool_id"])
    _integer(document["owner_uid"], "owner_uid", 0, (1 << 31) - 1)
    _absolute_path(document["operator_root"], "operator_root")
    _absolute_path(document["cgroup_parent"], "cgroup_parent")

    memory_ceiling = _integer(document["memory_ceiling_bytes"],
                              "memory_ceiling_bytes", 1, _MAX_I63)
    memory_headroom = _integer(document["memory_headroom_bytes"],
                               "memory_headroom_bytes", 0, _MAX_I63)
    cpu_quota = _integer(document["cpu_quota_millis"], "cpu_quota_millis", 1, 100_000)
    pids_max = _integer(document["pids_max"], "pids_max", 1, 1_000_000)
    _integer(document["swap_max_bytes"], "swap_max_bytes", 0, _MAX_I63)
    disk_ceiling = _integer(document["disk_ceiling_bytes"],
                            "disk_ceiling_bytes", 1, _MAX_I63)

    control = document["control"]
    if type(control) is not dict or frozenset(control) != _CONTROL_FIELDS:
        raise C2PoolConfigError("control allocation fields do not match the closed schema")
    control_memory = _integer(control["memory_bytes"], "control.memory_bytes", 1, _MAX_I63)
    control_cpu = _integer(control["cpu_quota_millis"],
                           "control.cpu_quota_millis", 1, 100_000)
    control_pids = _integer(control["pids_max"], "control.pids_max", 1, 1_000_000)
    control_disk = _integer(control["disk_bytes"], "control.disk_bytes", 0, _MAX_I63)

    if control_memory + memory_headroom >= memory_ceiling:
        raise C2PoolConfigError("control memory and headroom must be below the memory ceiling")
    if control_cpu >= cpu_quota:
        raise C2PoolConfigError("control CPU must leave execution quota available")
    if control_pids >= pids_max:
        raise C2PoolConfigError("control PID limit must leave execution PIDs available")
    if control_disk > disk_ceiling:
        raise C2PoolConfigError("control disk allocation exceeds the disk ceiling")


def _to_document(config):
    if type(config) is not C2PoolConfig or type(config.control) is not C2PoolControlAllocation:
        raise C2PoolConfigError("config must be an exact immutable C2PoolConfig value")
    document = {
        "schema_version": config.schema_version,
        "profile": config.profile,
        "physical_host_id": config.physical_host_id,
        "allocation_id": config.allocation_id,
        "pool_kind": config.pool_kind,
        "pool_id": config.pool_id,
        "owner_uid": config.owner_uid,
        "operator_root": config.operator_root,
        "cgroup_parent": config.cgroup_parent,
        "memory_ceiling_bytes": config.memory_ceiling_bytes,
        "memory_headroom_bytes": config.memory_headroom_bytes,
        "cpu_quota_millis": config.cpu_quota_millis,
        "pids_max": config.pids_max,
        "swap_max_bytes": config.swap_max_bytes,
        "disk_ceiling_bytes": config.disk_ceiling_bytes,
        "control": {
            "memory_bytes": config.control.memory_bytes,
            "cpu_quota_millis": config.control.cpu_quota_millis,
            "pids_max": config.control.pids_max,
            "disk_bytes": config.control.disk_bytes,
        },
    }
    _validate_document(document)
    return document


def parse_c2_pool_config(raw):
    """Parse canonical bounded JSON into an immutable, non-authoritative value."""
    if type(raw) is not bytes:
        raise C2PoolConfigError("C2 pool config must be supplied as UTF-8 bytes")
    try:
        document = strict_json_loads(raw, maximum_bytes=MAX_CONFIG_BYTES, maximum_depth=3)
        _validate_document(document)
        canonical = json_bytes(document, maximum_bytes=MAX_CONFIG_BYTES)
    except (TypeError, ValueError, UnicodeError) as error:
        if isinstance(error, C2PoolConfigError):
            raise
        raise C2PoolConfigError("C2 pool config JSON is malformed or exceeds its bound") from error
    if canonical != raw:
        raise C2PoolConfigError("C2 pool config JSON is not canonical")
    control = document["control"]
    return C2PoolConfig(
        schema_version=document["schema_version"],
        profile=document["profile"],
        physical_host_id=document["physical_host_id"],
        allocation_id=document["allocation_id"],
        pool_kind=document["pool_kind"],
        pool_id=document["pool_id"],
        owner_uid=document["owner_uid"],
        operator_root=document["operator_root"],
        cgroup_parent=document["cgroup_parent"],
        memory_ceiling_bytes=document["memory_ceiling_bytes"],
        memory_headroom_bytes=document["memory_headroom_bytes"],
        cpu_quota_millis=document["cpu_quota_millis"],
        pids_max=document["pids_max"],
        swap_max_bytes=document["swap_max_bytes"],
        disk_ceiling_bytes=document["disk_ceiling_bytes"],
        control=C2PoolControlAllocation(**control),
    )


def c2_pool_config_to_document(config):
    """Return a fresh canonicalizable mapping after rechecking value bounds."""
    return _to_document(config)


def canonical_c2_pool_config_bytes(config):
    """Serialize a validated config value deterministically within 4096 bytes."""
    try:
        return json_bytes(_to_document(config), maximum_bytes=MAX_CONFIG_BYTES)
    except (TypeError, ValueError, UnicodeError) as error:
        if isinstance(error, C2PoolConfigError):
            raise
        raise C2PoolConfigError("C2 pool config cannot be canonically encoded") from error


def c2_pool_config_sha256(config):
    """Return the deterministic digest of the canonical configuration bytes."""
    return hashlib.sha256(canonical_c2_pool_config_bytes(config)).hexdigest()
