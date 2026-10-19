"""Closed data-only contract for C2 physical pool role allocations.

Values in this module are declarations, not evidence of kernel enforcement,
process ownership, or release. A future protected owner/generation ledger must
bind these values to actual resource controls and retirement evidence.
"""
from dataclasses import dataclass
import hashlib
import re

from .c2_pool_config import (
    C2PoolConfig, C2PoolConfigError, canonical_c2_pool_config_bytes,
    c2_pool_config_sha256,
)
from .validation import json_bytes, strict_json_loads


MAX_ACCOUNTING_BYTES = 8192
MAX_REQUEST_SECONDS = 300
SCHEMA_VERSION = 1
PROFILE = "native_posix_c2_pool_accounting_v1"
_MAX_I63 = (1 << 63) - 1
_HEX32 = re.compile(r"[0-9a-f]{32}\Z", re.ASCII)
_HEX64 = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
_CGROUP_BASENAME = re.compile(r"participant-[a-z0-9-]{1,40}\Z", re.ASCII)
_ROLE_ORDER = ("host", "coordinator")
_PLAN_FIELDS = frozenset({
    "schema_version", "profile", "config_sha256", "role_allocations",
    "maximum_seconds",
})
_ALLOCATION_FIELDS = frozenset({
    "role", "memory_bytes", "cpu_quota_millis", "pids_max", "disk_bytes",
})
_GENERATION_FIELDS = frozenset({
    "schema_version", "profile", "role", "boot_id", "policy_sha256",
    "config_sha256", "cgroup_basename",
})


class C2PoolAccountingError(ValueError):
    """C2 accounting data is malformed, noncanonical, or exceeds the pool."""


@dataclass(frozen=True, slots=True)
class C2RoleAllocation:
    role: str
    memory_bytes: int
    cpu_quota_millis: int
    pids_max: int
    disk_bytes: int


@dataclass(frozen=True, slots=True)
class C2PoolAccountingPlan:
    schema_version: int
    profile: str
    config_sha256: str
    role_allocations: tuple[C2RoleAllocation, ...]
    # Sorted (role, max-seconds) pairs; request duration is not pool capacity.
    maximum_seconds: tuple[tuple[str, int], ...]


@dataclass(frozen=True, slots=True)
class C2PoolGenerationDescriptor:
    schema_version: int
    profile: str
    role: str
    boot_id: str
    policy_sha256: str
    config_sha256: str
    cgroup_basename: str


def _integer(value, name, minimum, maximum=_MAX_I63):
    if type(value) is not int or not minimum <= value <= maximum:
        raise C2PoolAccountingError(
            f"{name} must be an exact integer in [{minimum}, {maximum}]"
        )
    return value


def _hash(value, name):
    if type(value) is not str or not _HEX64.fullmatch(value):
        raise C2PoolAccountingError(f"{name} must be 64 lowercase hexadecimal characters")
    return value


def _config_digest(config):
    if type(config) is not C2PoolConfig:
        raise C2PoolAccountingError("config must be an exact immutable C2PoolConfig")
    try:
        # Serialization revalidates directly fabricated frozen dataclass values.
        canonical_c2_pool_config_bytes(config)
        return c2_pool_config_sha256(config)
    except (C2PoolConfigError, TypeError, ValueError) as error:
        raise C2PoolAccountingError("config is not a valid exact C2PoolConfig") from error


def _role_name(value):
    if type(value) is not str or value not in _ROLE_ORDER:
        raise C2PoolAccountingError("role must be host or coordinator")
    return value


def _validate_allocation(allocation):
    if type(allocation) is not C2RoleAllocation:
        raise C2PoolAccountingError("role allocation must be an exact C2RoleAllocation")
    _role_name(allocation.role)
    _integer(allocation.memory_bytes, f"{allocation.role}.memory_bytes", 1)
    _integer(allocation.cpu_quota_millis,
             f"{allocation.role}.cpu_quota_millis", 1, 100_000)
    _integer(allocation.pids_max, f"{allocation.role}.pids_max", 1, 1_000_000)
    _integer(allocation.disk_bytes, f"{allocation.role}.disk_bytes", 0)


def _validate_plan(plan, config):
    config_digest = _config_digest(config)
    if type(plan) is not C2PoolAccountingPlan:
        raise C2PoolAccountingError("plan must be an exact immutable C2PoolAccountingPlan")
    if type(plan.schema_version) is not int or plan.schema_version != SCHEMA_VERSION:
        raise C2PoolAccountingError("accounting schema version is unsupported")
    if type(plan.profile) is not str or plan.profile != PROFILE:
        raise C2PoolAccountingError("accounting profile is unsupported")
    if _hash(plan.config_sha256, "config_sha256") != config_digest:
        raise C2PoolAccountingError("plan config digest differs from the exact C2 pool config")
    allocations = plan.role_allocations
    if (type(allocations) is not tuple or not 1 <= len(allocations) <= 2):
        raise C2PoolAccountingError("role_allocations must be a tuple of one or two roles")
    for allocation in allocations:
        _validate_allocation(allocation)
    roles = tuple(item.role for item in allocations)
    if roles != tuple(role for role in _ROLE_ORDER if role in roles):
        raise C2PoolAccountingError("role allocations must use unique fixed host/coordinator order")
    if len(set(roles)) != len(roles):
        raise C2PoolAccountingError("role allocations contain duplicate roles")

    maxima = plan.maximum_seconds
    if type(maxima) is not tuple or len(maxima) != len(roles):
        raise C2PoolAccountingError("maximum_seconds must cover every enabled role exactly once")
    maximum_roles = []
    for item in maxima:
        if type(item) is not tuple or len(item) != 2:
            raise C2PoolAccountingError("maximum_seconds entries must be exact role/integer pairs")
        role, seconds = item
        _role_name(role)
        _integer(seconds, f"{role}.maximum_seconds", 1, MAX_REQUEST_SECONDS)
        maximum_roles.append(role)
    if tuple(maximum_roles) != roles:
        raise C2PoolAccountingError("maximum_seconds roles must match enabled roles in fixed order")

    control = config.control
    if (control.memory_bytes + config.memory_headroom_bytes
            + sum(item.memory_bytes for item in allocations) > config.memory_ceiling_bytes):
        raise C2PoolAccountingError("aggregate role, control, and headroom memory exceeds pool")
    if control.cpu_quota_millis + sum(
            item.cpu_quota_millis for item in allocations) > config.cpu_quota_millis:
        raise C2PoolAccountingError("aggregate role and control CPU exceeds pool")
    if control.pids_max + sum(item.pids_max for item in allocations) > config.pids_max:
        raise C2PoolAccountingError("aggregate role and control PIDs exceed pool")
    if control.disk_bytes + sum(item.disk_bytes for item in allocations) > config.disk_ceiling_bytes:
        raise C2PoolAccountingError("aggregate role and control disk exceeds pool")
    return config_digest


def build_c2_pool_accounting_plan(config, role_allocations, maximum_seconds):
    """Build a frozen plan from exact config, allocation tuple, and role maxima.

    Mutable maximum mappings are copied immediately into deterministic tuples.
    """
    digest = _config_digest(config)
    if type(role_allocations) is not tuple:
        raise C2PoolAccountingError("role_allocations must be supplied as an immutable tuple")
    if type(maximum_seconds) is not dict:
        raise C2PoolAccountingError("maximum_seconds must be supplied as an exact dictionary")
    if any(type(role) is not str or role not in _ROLE_ORDER
           for role in maximum_seconds):
        raise C2PoolAccountingError("maximum_seconds contains an unknown role")
    roles = tuple(item.role for item in role_allocations
                  if type(item) is C2RoleAllocation)
    if set(maximum_seconds) != set(roles):
        raise C2PoolAccountingError("maximum_seconds must cover every enabled role exactly once")
    ordered_roles = tuple(role for role in _ROLE_ORDER if role in roles)
    maxima = tuple((role, maximum_seconds[role]) for role in ordered_roles
                   if role in maximum_seconds)
    plan = C2PoolAccountingPlan(
        SCHEMA_VERSION, PROFILE, digest, role_allocations, maxima,
    )
    _validate_plan(plan, config)
    return plan


def c2_pool_accounting_to_document(plan, config):
    """Return a fresh closed document after revalidating all fields and totals."""
    digest = _validate_plan(plan, config)
    return {
        "schema_version": SCHEMA_VERSION,
        "profile": PROFILE,
        "config_sha256": digest,
        "role_allocations": [
            {
                "role": item.role,
                "memory_bytes": item.memory_bytes,
                "cpu_quota_millis": item.cpu_quota_millis,
                "pids_max": item.pids_max,
                "disk_bytes": item.disk_bytes,
            }
            for item in plan.role_allocations
        ],
        "maximum_seconds": {role: seconds for role, seconds in plan.maximum_seconds},
    }


def canonical_c2_pool_accounting_bytes(plan, config):
    """Serialize a bounded deterministic canonical JSON plan."""
    try:
        return json_bytes(c2_pool_accounting_to_document(plan, config),
                          maximum_bytes=MAX_ACCOUNTING_BYTES)
    except (TypeError, ValueError) as error:
        if isinstance(error, C2PoolAccountingError):
            raise
        raise C2PoolAccountingError("accounting plan cannot be canonically encoded") from error


def c2_pool_accounting_sha256(plan, config):
    """Return the stable digest of the canonical accounting plan."""
    return hashlib.sha256(canonical_c2_pool_accounting_bytes(plan, config)).hexdigest()


def parse_c2_pool_accounting(raw, config):
    """Parse canonical bounded plan bytes and validate them against exact config."""
    _config_digest(config)
    if type(raw) is not bytes:
        raise C2PoolAccountingError("accounting plan must be supplied as UTF-8 bytes")
    try:
        document = strict_json_loads(raw, maximum_bytes=MAX_ACCOUNTING_BYTES,
                                     maximum_depth=5)
        if type(document) is not dict or frozenset(document) != _PLAN_FIELDS:
            raise C2PoolAccountingError("accounting plan fields do not match closed schema")
        if type(document["role_allocations"]) is not list:
            raise C2PoolAccountingError("role_allocations must be an array")
        allocations = []
        for item in document["role_allocations"]:
            if type(item) is not dict or frozenset(item) != _ALLOCATION_FIELDS:
                raise C2PoolAccountingError("role allocation fields do not match closed schema")
            allocations.append(C2RoleAllocation(
                item["role"], item["memory_bytes"], item["cpu_quota_millis"],
                item["pids_max"], item["disk_bytes"],
            ))
        maxima_doc = document["maximum_seconds"]
        if type(maxima_doc) is not dict:
            raise C2PoolAccountingError("maximum_seconds must be a role map")
        maxima = tuple((role, maxima_doc[role]) for role in _ROLE_ORDER
                       if role in maxima_doc)
        plan = C2PoolAccountingPlan(
            document["schema_version"], document["profile"],
            document["config_sha256"], tuple(allocations), maxima,
        )
        _validate_plan(plan, config)
        if canonical_c2_pool_accounting_bytes(plan, config) != raw:
            raise C2PoolAccountingError("accounting plan JSON is not canonical")
        return plan
    except C2PoolAccountingError:
        raise
    except (TypeError, ValueError, UnicodeError, KeyError, RecursionError) as error:
        raise C2PoolAccountingError("accounting plan JSON is malformed or exceeds its bound") from error


def build_c2_pool_generation_descriptor(*, role, boot_id, policy_sha256,
                                        cgroup_basename, config, plan):
    """Create a frozen descriptor pinned to one role, boot, policy, and config."""
    digest = _config_digest(config)
    descriptor = C2PoolGenerationDescriptor(
        SCHEMA_VERSION, PROFILE, role, boot_id, policy_sha256, digest,
        cgroup_basename,
    )
    _validate_generation_descriptor(descriptor, config, plan)
    return descriptor


def _validate_generation_descriptor(descriptor, config, plan):
    digest = _config_digest(config)
    _validate_plan(plan, config)
    if type(descriptor) is not C2PoolGenerationDescriptor:
        raise C2PoolAccountingError(
            "generation must be an exact immutable C2PoolGenerationDescriptor"
        )
    if type(descriptor.schema_version) is not int or descriptor.schema_version != SCHEMA_VERSION:
        raise C2PoolAccountingError("generation schema version is unsupported")
    if type(descriptor.profile) is not str or descriptor.profile != PROFILE:
        raise C2PoolAccountingError("generation profile is unsupported")
    _role_name(descriptor.role)
    if descriptor.role not in {item.role for item in plan.role_allocations}:
        raise C2PoolAccountingError("generation role is not enabled by the accounting plan")
    if type(descriptor.boot_id) is not str or not _HEX32.fullmatch(descriptor.boot_id):
        raise C2PoolAccountingError("boot_id must use the current 32 lowercase hex grammar")
    _hash(descriptor.policy_sha256, "policy_sha256")
    if _hash(descriptor.config_sha256, "config_sha256") != digest:
        raise C2PoolAccountingError("generation config digest differs from exact pool config")
    if (type(descriptor.cgroup_basename) is not str
            or not _CGROUP_BASENAME.fullmatch(descriptor.cgroup_basename)):
        raise C2PoolAccountingError("cgroup_basename is outside the current bounded grammar")


def c2_pool_generation_to_document(descriptor, config, plan):
    """Return the exact closed descriptor document after revalidation."""
    _validate_generation_descriptor(descriptor, config, plan)
    return {
        "schema_version": SCHEMA_VERSION,
        "profile": PROFILE,
        "role": descriptor.role,
        "boot_id": descriptor.boot_id,
        "policy_sha256": descriptor.policy_sha256,
        "config_sha256": descriptor.config_sha256,
        "cgroup_basename": descriptor.cgroup_basename,
    }


def canonical_c2_pool_generation_bytes(descriptor, config, plan):
    """Encode a generation descriptor as bounded canonical JSON."""
    try:
        return json_bytes(c2_pool_generation_to_document(descriptor, config, plan),
                          maximum_bytes=MAX_ACCOUNTING_BYTES)
    except (TypeError, ValueError) as error:
        if isinstance(error, C2PoolAccountingError):
            raise
        raise C2PoolAccountingError("generation cannot be canonically encoded") from error


def c2_pool_generation_sha256(descriptor, config, plan):
    return hashlib.sha256(
        canonical_c2_pool_generation_bytes(descriptor, config, plan)
    ).hexdigest()


def parse_c2_pool_generation(raw, config, plan):
    """Parse canonical generation bytes, without asserting ownership or liveness."""
    _config_digest(config)
    if type(raw) is not bytes:
        raise C2PoolAccountingError("generation descriptor must be supplied as UTF-8 bytes")
    try:
        document = strict_json_loads(raw, maximum_bytes=MAX_ACCOUNTING_BYTES,
                                     maximum_depth=2)
        if type(document) is not dict or frozenset(document) != _GENERATION_FIELDS:
            raise C2PoolAccountingError("generation fields do not match closed schema")
        descriptor = C2PoolGenerationDescriptor(
            document["schema_version"], document["profile"], document["role"],
            document["boot_id"], document["policy_sha256"],
            document["config_sha256"], document["cgroup_basename"],
        )
        _validate_generation_descriptor(descriptor, config, plan)
        if canonical_c2_pool_generation_bytes(descriptor, config, plan) != raw:
            raise C2PoolAccountingError("generation JSON is not canonical")
        return descriptor
    except C2PoolAccountingError:
        raise
    except (TypeError, ValueError, UnicodeError, KeyError, RecursionError) as error:
        raise C2PoolAccountingError("generation JSON is malformed or exceeds its bound") from error
