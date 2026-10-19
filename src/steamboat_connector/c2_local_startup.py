"""Narrow C2 local compute startup composition (prototype, inert result).

This composes trusted owner consent, selected-root validation, a durable local
launch claim, and immediate owned-process publication. It launches only host
and personal-coordinator compute roles. Consumer ownership is deliberately a
separate future API.
"""
from __future__ import annotations

import hashlib
import threading
from dataclasses import dataclass
from pathlib import Path

from steamboat_connector.owner_consent import OwnerConsentSnapshot, OwnerConsentStore
from steamboat_connector.process_supervisor import ProcessRoleBackend
from steamboat_connector.validation import json_bytes
from steamboat_security.clock import Clock
from steamboat_security.errors import CredentialError, StorageError
from steamboat_security.root_c2_coordinator import load_c2_personal_coordinator_binding
from steamboat_security.root_c2_local_claim import C2LocalClaimStore
from steamboat_security.root_c2_local_plan import c2_local_plan_document, derive_c2_local_plan
from steamboat_security.root_c2_runtime import load_c2_host_runtime_binding
from steamboat_security.root_transition_launch import RoleLaunchSpec, parse_role_launch_spec, role_launch_document
from steamboat_security.root_transition_storage import RootGenerationStore

_PROFILE = "c2-local-compute-v1"
_SELECTED_ROLE = {"host": "host", "coordinator": "personal_coordinator"}


class C2LocalStartupError(StorageError):
    """A local startup attempt failed closed."""


@dataclass(frozen=True)
class C2LocalLaunchReference:
    """Operator-supplied protected header references for one selected role."""
    launch_spec: RoleLaunchSpec
    configuration_path: str
    configuration_root: str
    operator_verification_key_pem: bytes | None = None


@dataclass(frozen=True)
class C2LocalStartupResult:
    """Inert result; it is not identity, loaded-health, or readiness authority."""
    plan_sha256: str
    claim_sha256: str
    ready_roles: tuple[str, ...]


def closed_role_config(reference: C2LocalLaunchReference, *, selected_root: str,
                       role: str) -> dict:
    """Exact closed config required in the already artifact-pinned backend."""
    spec = parse_role_launch_spec(role_launch_document(reference.launch_spec))
    if role not in _SELECTED_ROLE or spec.role != _SELECTED_ROLE[role]:
        raise CredentialError("C2 role config does not match the selected local role")
    return {
        "version": 1, "profile": _PROFILE, "role": role,
        "selected_root": str(Path(selected_root).resolve()),
        "protected_root": str(Path(reference.configuration_root).resolve()),
        "configuration_path": str(Path(reference.configuration_path).resolve()),
        "account_id": spec.account_id, "device_id": spec.device_id,
        "selected_role": spec.role, "boot_id": spec.boot_id,
        "generation_sha256": spec.generation_sha256,
        "configuration_sha256": spec.configuration_sha256,
        "launch_nonce": spec.launch_nonce,
    }


class C2LocalStartup:
    """One in-process serialized startup adapter for a pinned local principal."""
    def __init__(self, *, root_store, owner_store, claim_store, backend, clock,
                 expected_uid: int, account_id: str, device_id: str,
                 references: dict, policies: dict, timeout_seconds: float = 30.0):
        if (type(root_store) is not RootGenerationStore
                or type(owner_store) is not OwnerConsentStore
                or type(claim_store) is not C2LocalClaimStore
                or type(backend) is not ProcessRoleBackend or type(clock) is not Clock):
            raise TypeError("C2 startup requires exact trusted store, backend, and Clock types")
        if (type(expected_uid) is not int or expected_uid != root_store._uid
                or expected_uid != owner_store._uid or expected_uid != claim_store._uid):
            raise CredentialError("C2 startup stores have mismatched pinned UIDs")
        if ((account_id, device_id) != (owner_store._account, owner_store._device)
                or (account_id, device_id) != (claim_store._account, claim_store._device)):
            raise CredentialError("C2 startup stores have mismatched pinned principals")
        if (type(references) is not dict or set(references) - set(_SELECTED_ROLE)
                or type(policies) is not dict or set(policies) - set(_SELECTED_ROLE)):
            raise TypeError("references and policies must be closed role mappings")
        if (type(timeout_seconds) not in (int, float)
                or not 0 <= timeout_seconds <= 30):
            raise ValueError("READY timeout must be within the backend bound")
        self._root, self._owner, self._claims = root_store, owner_store, claim_store
        self._backend, self._clock = backend, clock
        self._uid, self._account, self._device = expected_uid, account_id, device_id
        self._references, self._policies = dict(references), dict(policies)
        self._timeout = timeout_seconds
        self._active = threading.Lock()

    def start(self, roles, *, cancel_event: threading.Event):
        if (type(roles) is not tuple or not roles
                or roles != tuple(sorted(set(roles)))
                or any(type(role) is not str or role not in _SELECTED_ROLE for role in roles)):
            raise ValueError("explicit host/coordinator roles required; consumer is separate")
        if type(cancel_event) is not threading.Event:
            raise TypeError("cancellation must be an exact Event")
        if not self._active.acquire(blocking=False):
            raise C2LocalStartupError("another startup operation is active")
        handles = []
        try:
            if cancel_event.is_set():
                raise C2LocalStartupError("startup cancelled before owner intent")
            before = self._owner.snapshot()
            self._check_owner(before)
            requested = tuple(sorted(_SELECTED_ROLE[role] for role in roles))
            enabled = tuple(sorted(_SELECTED_ROLE[x] for x in before.enabled_roles
                                   if x in _SELECTED_ROLE))
            if ("consumer" in before.enabled_roles or requested != enabled
                    or set(self._references) != set(roles)
                    or set(self._policies) != set(roles)):
                raise C2LocalStartupError("roles must exactly equal the complete enabled compute projection")

            # Load guarded bindings before Root SH; loaders may initialize a
            # durable SnapshotStore and therefore must not run inside read_selected.
            bindings = {}
            selected_root = self._selected_root()
            for role in roles:
                reference = self._references[role]
                if type(reference) is not C2LocalLaunchReference:
                    raise TypeError("references must be exact trusted C2LocalLaunchReference values")
                spec = parse_role_launch_spec(role_launch_document(reference.launch_spec))
                if (spec.account_id, spec.device_id, spec.role) != (
                        self._account, self._device, _SELECTED_ROLE[role]):
                    raise CredentialError("launch reference is not for the pinned local principal/role")
                if role == "host":
                    if type(reference.operator_verification_key_pem) is not bytes:
                        raise CredentialError("host requires operator verification PEM")
                    binding = load_c2_host_runtime_binding(
                        root_store=self._root, clock=self._clock, expected_launch_spec=spec,
                        configuration_path=reference.configuration_path,
                        configuration_root=reference.configuration_root,
                        expected_uid=self._uid,
                        operator_verification_key_pem=reference.operator_verification_key_pem)
                else:
                    if reference.operator_verification_key_pem is not None:
                        raise CredentialError("coordinator must not carry a host operator key")
                    binding = load_c2_personal_coordinator_binding(
                        root_store=self._root, clock=self._clock, expected_launch_spec=spec,
                        configuration_path=reference.configuration_path,
                        configuration_root=reference.configuration_root,
                        expected_uid=self._uid)
                binding.assert_live()
                expected = closed_role_config(reference, selected_root=selected_root, role=role)
                if (self._backend._configured_role(role) != expected
                        or role not in self._backend._pinned_roles):
                    raise CredentialError("backend config and artifact pin do not match closed C2 profile")
                bindings[role] = binding

            connector_roles = tuple(sorted("coordinator" if r == "coordinator" else "host"
                                           for r in roles))
            captured = {}
            with self._owner.begin_start(connector_roles, cancel_event=cancel_event) as owner:
                self._check_owner(owner)
                def validate_selected(selector, bundle, active_policy):
                    plan = derive_c2_local_plan(selector, dict(bundle), active_policy,
                        clock=self._clock, account_id=self._account, device_id=self._device,
                        enable_epoch=owner.epoch, enabled_roles=owner.enabled_roles)
                    if tuple(sorted(plan.enabled_roles)) != requested:
                        raise CredentialError("fresh selected plan differs from explicit roles")
                    for role in roles:
                        matches = [s for s in plan.enabled_specs if s.role == _SELECTED_ROLE[role]]
                        if len(matches) != 1 or matches[0] != self._references[role].launch_spec:
                            raise CredentialError("fresh selected spec differs from trusted reference")
                    def fresh_claim_validator(_record):
                        fresh = derive_c2_local_plan(selector, dict(bundle), active_policy,
                            clock=self._clock, account_id=self._account, device_id=self._device,
                            enable_epoch=owner.epoch, enabled_roles=owner.enabled_roles)
                        if c2_local_plan_document(fresh) != c2_local_plan_document(plan):
                            raise CredentialError("fresh local claim plan changed")
                        return None
                    receipt = self._claims.claim(plan,
                        fresh_selected_validator=fresh_claim_validator)
                    for role in roles:
                        def before_popen_check(event=cancel_event):
                            if event.is_set():
                                raise C2LocalStartupError("startup cancelled before Popen")
                            return None
                        handle = self._backend.spawn_owned_start(
                            role, self._policies[role], cancel_event=cancel_event,
                            before_popen_check=before_popen_check,
                            expected_role_config_sha256=hashlib.sha256(
                                json_bytes(closed_role_config(self._references[role],
                                    selected_root=selected_root, role=role))).hexdigest())
                        if handle is None:
                            raise C2LocalStartupError("backend refused owned process publication")
                        handles.append(handle)
                    captured.update(plan=plan, receipt=receipt)
                    return None
                self._root.read_selected(validate=validate_selected)

            # Both durable serialization locks have exited before READY waits.
            ready = []
            for handle in handles:
                if cancel_event.is_set() or not self._backend.observe_owned_ready(
                        handle, timeout_seconds=self._timeout):
                    raise C2LocalStartupError("owned role did not become ready")
                ready.append(handle._role)

            final = self._owner.snapshot()
            self._check_owner(final)
            fresh = {}
            def validate_final(selector, bundle, active_policy):
                fresh["plan"] = derive_c2_local_plan(selector, dict(bundle), active_policy,
                    clock=self._clock, account_id=self._account, device_id=self._device,
                    enable_epoch=final.epoch, enabled_roles=final.enabled_roles)
                return None
            self._root.read_selected(validate=validate_final)
            if (final.epoch != captured["plan"].enable_epoch
                    or c2_local_plan_document(fresh.get("plan"))
                       != c2_local_plan_document(captured["plan"])):
                raise C2LocalStartupError("owner consent or selected head changed during startup")
            for binding in bindings.values():
                binding.assert_live()
            return C2LocalStartupResult(captured["plan"].localplan_sha256,
                captured["receipt"].record.claim_sha256, tuple(ready))
        except BaseException:
            if handles:
                owned_roles = tuple(sorted({handle._role for handle in handles}))
                self._backend.request_stop(owned_roles)
                self._backend.stop(owned_roles, 15.0)
            raise
        finally:
            self._active.release()

    def _check_owner(self, snapshot):
        if (type(snapshot) is not OwnerConsentSnapshot
                or (snapshot.account_id, snapshot.device_id) != (self._account, self._device)):
            raise CredentialError("trusted owner snapshot differs from pinned principal")

    def _selected_root(self):
        import os
        if not hasattr(os, "readlink") or self._root._root_fd < 0:
            raise StorageError("selected root descriptor is unavailable")
        return os.path.realpath(f"/proc/self/fd/{self._root._root_fd}")
