"""Inert, bounded per-device projection of a selected C2 cohort.

This module derives launch declarations only. It creates no claims, identities,
processes, readiness state, or authority to start a worker.
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass

from .clock import Clock
from .codec import canonical_json
from .errors import BindingError, CredentialError, SnapshotError, StorageError
from .ids import validate_id
from .root_c2_group_scope import (C2HostGroupScope, parse_c2_host_group_scope,
    validate_c2_scope_expectations)
from .root_c2_selected import validate_c2_selected_cohort
from .root_transition_launch import RoleLaunchSpec, parse_role_launch_spec, role_launch_document

MAX_LOCAL_PLAN_BYTES = 64 * 1024
_ROLES = ("consumer", "host", "personal_coordinator")
_HEX64 = re.compile(r"^[0-9a-f]{64}$", re.ASCII)
_FIELDS = frozenset({"version", "generation_sha256", "selector_sha256",
    "activation_manifest_sha256", "global_cohort_sha256", "account_id", "device_id",
    "enable_epoch", "enabled_roles", "complete_local_specs", "enabled_specs",
    "disabled_specs", "enabled_host_groups", "disabled_host_groups", "localplan_sha256"})


def _hash(value, label):
    if type(value) is not str or not _HEX64.fullmatch(value):
        raise CredentialError(f"C2 local plan {label} must be lowercase SHA-256 hex")
    return value


def _spec(raw):
    return parse_role_launch_spec(role_launch_document(raw))


def _scope(raw):
    if type(raw) is not C2HostGroupScope:
        raise CredentialError("C2 local plan requires an exact parsed host scope")
    return parse_c2_host_group_scope(raw.to_document())


def _bounded_tuple(value, limit, label):
    if type(value) is not tuple or len(value) > limit:
        raise CredentialError(f"C2 local plan {label} exceeds its exact container bound")
    return value


def _bind_scope(scope, spec, generation):
    try:
        validate_c2_scope_expectations(scope, account_id=spec.account_id,
            device_id=spec.device_id, credential_serial=spec.serial,
            credential_epoch=spec.credential_epoch,
            certificate_sha256=spec.certificate_sha256,
            public_key_sha256=spec.public_key_sha256, parent_boot_id=spec.boot_id,
            generation_sha256=generation, admission_epoch=spec.admission_epoch)
    except SnapshotError as error:
        raise CredentialError("C2 local host scope differs from its selected launch spec") from error


def _plan_doc(plan, *, include_digest=True):
    if type(plan) is not C2LocalPlan:
        raise CredentialError("C2 local plan requires exact plan value")
    local_raw = _bounded_tuple(plan.complete_local_specs, 3, "complete local specs")
    enabled_raw = _bounded_tuple(plan.enabled_specs, 3, "enabled specs")
    disabled_raw = _bounded_tuple(plan.disabled_specs, 3, "disabled specs")
    eg_raw = _bounded_tuple(plan.enabled_host_groups, 1, "enabled host groups")
    dg_raw = _bounded_tuple(plan.disabled_host_groups, 1, "disabled host groups")
    local = tuple(_spec(x) for x in local_raw)
    enabled = tuple(_spec(x) for x in enabled_raw)
    disabled = tuple(_spec(x) for x in disabled_raw)
    eg = tuple(_scope(x) for x in eg_raw)
    dg = tuple(_scope(x) for x in dg_raw)
    account = validate_id(plan.account_id, "acct")
    device = validate_id(plan.device_id, "dev")
    if type(plan.enable_epoch) is not int or not 1 <= plan.enable_epoch <= 2**63 - 1:
        raise CredentialError("local enable epoch must be a positive exact 63-bit integer")
    if (type(plan.enabled_roles) is not tuple
            or any(type(x) is not str or x not in _ROLES for x in plan.enabled_roles)
            or plan.enabled_roles != tuple(sorted(set(plan.enabled_roles)))):
        raise CredentialError("enabled roles must be sorted, unique, and known")
    identities = tuple(x.identity for x in local)
    if (not local or identities != tuple(sorted(identities))
            or len(identities) != len(set(identities))
            or any((x.account_id, x.device_id) != (account, device) for x in local)):
        raise CredentialError("complete local specs do not match the local principal")
    generation = _hash(plan.generation_sha256, "generation hash")
    if any(x.generation_sha256 != generation for x in local):
        raise CredentialError("complete local specs differ from the plan generation")
    expected_enabled = tuple(x for x in local if x.role in plan.enabled_roles)
    expected_disabled = tuple(x for x in local if x.role not in plan.enabled_roles)
    if set(plan.enabled_roles) != {x.role for x in enabled}:
        raise CredentialError("enabled roles do not exactly match enabled launch specs")
    if enabled != expected_enabled or disabled != expected_disabled:
        raise CredentialError("enabled and disabled specs are not the exact canonical local projections")
    host_local = {x.identity for x in local if x.role == "host"}
    eg_ids = tuple((x.account_id, x.device_id, x.role) for x in eg)
    dg_ids = tuple((x.account_id, x.device_id, x.role) for x in dg)
    if (eg_ids != tuple(sorted(set(eg_ids))) or dg_ids != tuple(sorted(set(dg_ids)))
            or set(eg_ids) != host_local & {x.identity for x in expected_enabled}
            or set(dg_ids) != host_local & {x.identity for x in expected_disabled}):
        raise CredentialError("enabled and disabled host scopes do not match local host roles")
    local_by_identity = {x.identity: x for x in local}
    for scope in eg + dg:
        spec = local_by_identity.get((scope.account_id, scope.device_id, scope.role))
        if spec is None:
            raise CredentialError("local host scope has no exact selected launch role")
        _bind_scope(scope, spec, plan.generation_sha256)
    doc = {"version": 1, "generation_sha256": _hash(plan.generation_sha256, "generation hash"),
        "selector_sha256": _hash(plan.selector_sha256, "selector hash"),
        "activation_manifest_sha256": _hash(plan.activation_manifest_sha256, "manifest hash"),
        "global_cohort_sha256": _hash(plan.global_cohort_sha256, "global cohort hash"),
        "account_id": account, "device_id": device,
        "enable_epoch": plan.enable_epoch, "enabled_roles": list(plan.enabled_roles),
        "complete_local_specs": [role_launch_document(x) for x in local],
        "enabled_specs": [role_launch_document(x) for x in enabled],
        "disabled_specs": [role_launch_document(x) for x in disabled],
        "enabled_host_groups": [x.to_document() for x in eg],
        "disabled_host_groups": [x.to_document() for x in dg]}
    if include_digest:
        doc["localplan_sha256"] = _hash(plan.localplan_sha256, "digest")
    return doc


@dataclass(frozen=True)
class C2LocalPlan:
    generation_sha256: str
    selector_sha256: str
    activation_manifest_sha256: str
    global_cohort_sha256: str
    account_id: str
    device_id: str
    enable_epoch: int
    enabled_roles: tuple[str, ...]
    complete_local_specs: tuple[RoleLaunchSpec, ...]
    enabled_specs: tuple[RoleLaunchSpec, ...]
    disabled_specs: tuple[RoleLaunchSpec, ...]
    enabled_host_groups: tuple[C2HostGroupScope, ...]
    disabled_host_groups: tuple[C2HostGroupScope, ...]
    localplan_sha256: str

    def to_document(self):
        return c2_local_plan_document(self)


def _make(selector, cohort, account_id, device_id, enable_epoch, enabled_roles):
    if type(account_id) is not str or type(device_id) is not str:
        raise CredentialError("trusted local principal must use exact strings")
    if type(enable_epoch) is not int or not 1 <= enable_epoch <= 2**63 - 1:
        raise CredentialError("local enable epoch must be a positive exact 63-bit integer")
    if type(enabled_roles) is not tuple or any(type(x) is not str for x in enabled_roles):
        raise CredentialError("enabled roles must be an exact tuple")
    if enabled_roles != tuple(sorted(set(enabled_roles))) or any(x not in _ROLES for x in enabled_roles):
        raise CredentialError("enabled roles must be sorted, unique, and known")
    specs = tuple(_spec(x) for x in cohort.new_specs)
    identities = tuple(x.identity for x in specs)
    if identities != tuple(sorted(identities)) or len(set(identities)) != len(identities):
        raise CredentialError("selected global role specifications are not sorted and unique")
    local = tuple(x for x in specs if (x.account_id, x.device_id) == (account_id, device_id))
    if not local:
        raise CredentialError("selected cohort contains no roles for trusted local principal")
    local_roles = tuple(x.role for x in local)
    if any(role not in local_roles for role in enabled_roles):
        raise CredentialError("an enabled role is absent from the selected local principal")
    groups = tuple(_scope(x) for x in cohort.new_groups)
    group_ids = tuple((x.account_id, x.device_id, x.role) for x in groups)
    if group_ids != tuple(sorted(group_ids)) or len(set(group_ids)) != len(group_ids):
        raise CredentialError("selected host groups are not sorted and unique")
    scope_ids = {(x.account_id, x.device_id, x.role) for x in groups}
    if scope_ids != {x.identity for x in specs if x.role == "host"}:
        raise CredentialError("selected host groups do not exactly cover global host roles")
    enabled = tuple(x for x in local if x.role in enabled_roles)
    disabled = tuple(x for x in local if x.role not in enabled_roles)
    enabled_ids = {x.identity for x in enabled}
    eg = tuple(x for x in groups if (x.account_id, x.device_id, x.role) in enabled_ids)
    dg = tuple(x for x in groups if (x.account_id, x.device_id) == (account_id, device_id)
               and (x.account_id, x.device_id, x.role) not in enabled_ids)
    global_body = {"generation_sha256": cohort.generation_sha256,
        "new_role_launch_specs": [role_launch_document(x) for x in specs],
        "new_host_group_scopes": [x.to_document() for x in groups]}
    global_digest = hashlib.sha256(canonical_json(global_body)).hexdigest()
    bare = C2LocalPlan(cohort.generation_sha256, cohort.selector_sha256,
        cohort.activation_manifest_sha256, global_digest, account_id, device_id,
        enable_epoch, enabled_roles, local, enabled, disabled, eg, dg, "0" * 64)
    digest = hashlib.sha256(canonical_json(_plan_doc(bare, include_digest=False))).hexdigest()
    return C2LocalPlan(cohort.generation_sha256, cohort.selector_sha256,
        cohort.activation_manifest_sha256, global_digest, account_id, device_id,
        enable_epoch, enabled_roles, local, enabled, disabled, eg, dg, digest)


def derive_c2_local_plan(selector, bundle, active_policy, *, clock: Clock,
        account_id: str, device_id: str, enable_epoch: int,
        enabled_roles: tuple[str, ...]) -> C2LocalPlan:
    """Validate selected raw bytes and project the trusted daemon enable snapshot."""
    cohort = validate_c2_selected_cohort(selector, bundle, active_policy, clock=clock)
    return _make(selector, cohort, account_id, device_id, enable_epoch, enabled_roles)


def c2_local_plan_document(plan: C2LocalPlan) -> dict:
    doc = _plan_doc(plan, include_digest=False)
    digest = hashlib.sha256(canonical_json(doc)).hexdigest()
    if digest != plan.localplan_sha256:
        raise CredentialError("C2 local plan digest differs from its fields")
    return {**doc, "localplan_sha256": digest}


def parse_c2_local_plan(encoded: bytes) -> C2LocalPlan:
    if type(encoded) is not bytes or not 1 <= len(encoded) <= MAX_LOCAL_PLAN_BYTES:
        raise CredentialError("C2 local plan is empty or exceeds its byte bound")
    try:
        raw = json.loads(encoded.decode("utf-8", "strict"))
    except (UnicodeError, ValueError, TypeError, RecursionError) as error:
        raise CredentialError("C2 local plan JSON is malformed") from error
    if type(raw) is not dict or set(raw) != _FIELDS or type(raw.get("version")) is not int or raw["version"] != 1:
        raise CredentialError("C2 local plan has unknown fields or unsupported version")
    try:
        list_bounds = {"complete_local_specs": 3, "enabled_specs": 3,
            "disabled_specs": 3, "enabled_host_groups": 1, "disabled_host_groups": 1}
        for key, bound in list_bounds.items():
            if type(raw[key]) is not list or len(raw[key]) > bound:
                raise CredentialError(f"C2 local plan {key} exceeds its list bound")
        if type(raw["enabled_roles"]) is not list or len(raw["enabled_roles"]) > 3:
            raise CredentialError("C2 local plan roles exceed their list bound")
        values = [tuple(parse_role_launch_spec(x) for x in raw[key])
                  for key in ("complete_local_specs", "enabled_specs", "disabled_specs")]
        groups = [tuple(parse_c2_host_group_scope(x) for x in raw[key])
                  for key in ("enabled_host_groups", "disabled_host_groups")]
        roles = raw["enabled_roles"]
        plan = C2LocalPlan(_hash(raw["generation_sha256"], "generation hash"),
            _hash(raw["selector_sha256"], "selector hash"),
            _hash(raw["activation_manifest_sha256"], "manifest hash"),
            _hash(raw["global_cohort_sha256"], "global cohort hash"),
            raw["account_id"], raw["device_id"], raw["enable_epoch"], tuple(roles),
            values[0], values[1], values[2], groups[0], groups[1],
            _hash(raw["localplan_sha256"], "digest"))
        canonical = canonical_json(c2_local_plan_document(plan))
    except (BindingError, SnapshotError, KeyError, TypeError, ValueError) as error:
        if isinstance(error, CredentialError):
            raise
        raise CredentialError("C2 local plan nested values are invalid") from error
    if canonical != encoded:
        raise CredentialError("C2 local plan is not canonical JSON")
    return plan


def revalidate_c2_local_plan(encoded: bytes, selector, bundle, active_policy, *,
        clock: Clock, account_id: str, device_id: str, enable_epoch: int,
        enabled_roles: tuple[str, ...]) -> C2LocalPlan:
    """Re-derive from fresh selected bytes and an expected trusted enable snapshot."""
    parsed = parse_c2_local_plan(encoded)
    expected = derive_c2_local_plan(selector, bundle, active_policy, clock=clock,
        account_id=account_id, device_id=device_id, enable_epoch=enable_epoch,
        enabled_roles=enabled_roles)
    if canonical_json(c2_local_plan_document(parsed)) != canonical_json(c2_local_plan_document(expected)):
        raise CredentialError("C2 local plan differs from fresh selected head or trusted enable snapshot")
    return expected


def read_selected_c2_local_plan(root_store, *, clock: Clock, account_id: str,
        device_id: str, enable_epoch: int, enabled_roles: tuple[str, ...]) -> C2LocalPlan:
    """Capture inert plan from the RootGenerationStore callback contract."""
    capture = {}
    def validate(selector, bundle, active_policy):
        capture.clear()
        capture["plan"] = derive_c2_local_plan(selector, dict(bundle), active_policy,
            clock=clock, account_id=account_id, device_id=device_id,
            enable_epoch=enable_epoch, enabled_roles=enabled_roles)
        return None
    root_store.read_selected(validate=validate)
    plan = capture.get("plan")
    if type(plan) is not C2LocalPlan:
        raise StorageError("selected C2 local plan callback did not capture a plan")
    return plan
