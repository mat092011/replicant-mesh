"""Cold-start selected root roles through durable claims and owned processes.

This composes existing protected stores, role bindings and local process
supervision. A returned capability means that the selected cohort emitted its
bounded READY records and was live at the final protected-head check. It does
not establish ongoing health, listener usability, weight loading, remote
connectivity, or kernel containment beyond the trusted process-group profile.
"""
from __future__ import annotations

import asyncio
import hashlib
import os
import time
from dataclasses import dataclass
from pathlib import Path

from .codec import canonical_json
from .errors import BindingError, CredentialError, StorageError
from .files import safe_read
from .root_runtime import (_configuration_header, _require_current_role_grants,
                           _selected_binding, load_root_runtime_binding)
from .root_transition_launch import (MAX_LAUNCH_ROLES, RoleLaunchSpec,
                                     canonical_role_launch_digest,
                                     role_launch_document)
from .root_transition_launch_claim import LaunchClaimStore
from .root_transition_retirement import (MAX_OWNED_PROCESSES, ObservedLaunch,
                                         PendingOwnedLaunch, RetirementSupervisor)
from .root_transition_storage import (RootGenerationStore,
                                     SelectedRootGeneration,
                                     root_generation_selector_document)
from .snapshot import SnapshotStore
from .clock import Clock

_startup_monotonic = time.monotonic

MAX_STARTUP_SECONDS = 60.0
MAX_CLEANUP_SECONDS = 15.0
_MAX_STARTED_CAPABILITIES = 16


@dataclass(frozen=True)
class RootRoleLaunch:
    """Trusted local file references for one selected role; never a command."""
    launch_spec: RoleLaunchSpec
    manifest_path: str
    protected_root: str
    configuration_path: str
    configuration_root: str


@dataclass(frozen=True, slots=True, init=False)
class StartedRootCohort:
    """Opaque startup evidence sealed to one coordinator instance."""
    _owner: object
    _record: object
    _seal: object

    def __init__(self, owner, record, seal):
        object.__setattr__(self, "_owner", owner)
        object.__setattr__(self, "_record", record)
        object.__setattr__(self, "_seal", seal)


@dataclass(frozen=True)
class _LaunchGroup:
    nonce: str
    manifest_path: str
    protected_root: str
    configuration_path: str
    specs: tuple[RoleLaunchSpec, ...]


class RootCohortStartup:
    """Serialize selection, one-time claim, spawn, READY and final recheck.

    The role specifications and paths are owner-supplied protected local
    declarations. This class accepts no peer command strings or remote exit
    reports. It owns only startup evidence; callers must separately supervise
    runtime health and must keep all referenced stores open while this object
    is in use.
    """

    def __init__(self, *, root_store: RootGenerationStore,
                 claim_store: LaunchClaimStore,
                 retirement_supervisor: RetirementSupervisor,
                 clock: Clock, expected_uid: int):
        if (type(root_store) is not RootGenerationStore
                or type(claim_store) is not LaunchClaimStore
                or type(retirement_supervisor) is not RetirementSupervisor
                or type(clock) is not Clock):
            raise BindingError("startup requires exact protected stores, supervisor and Clock")
        if (type(expected_uid) is not int or os.name != "posix"
                or not hasattr(os, "geteuid") or expected_uid != os.geteuid()
                or expected_uid != root_store._uid or expected_uid != claim_store._uid):
            raise BindingError("startup UID must match the native protected stores")
        self.root_store = root_store
        self.claim_store = claim_store
        self.retirement = retirement_supervisor
        self.clock = clock
        self.uid = expected_uid
        self._seal = object()
        self._started: list[StartedRootCohort] = []
        self._active = False

    @staticmethod
    def _validate_launches(launches) -> tuple[RootRoleLaunch, ...]:
        if type(launches) is not tuple or not 1 <= len(launches) <= MAX_LAUNCH_ROLES:
            raise BindingError("startup requires one to sixteen exact role launch inputs")
        if any(type(item) is not RootRoleLaunch
               or type(item.launch_spec) is not RoleLaunchSpec for item in launches):
            raise BindingError("startup role launch input has an unexpected type")
        specs = tuple(item.launch_spec for item in launches)
        canonical_role_launch_digest(specs)
        for item in launches:
            for name in ("manifest_path", "protected_root", "configuration_path",
                         "configuration_root"):
                value = getattr(item, name)
                if (type(value) is not str or not Path(value).is_absolute()
                        or os.path.normpath(value) != value):
                    raise BindingError(f"startup {name} must be a canonical absolute path")
        return launches

    @staticmethod
    def _capture_selected(root_store) -> SelectedRootGeneration:
        captured = {}

        def validate(selector, bundle, active_policy):
            specs = _selected_binding(selector, bundle, active_policy)
            captured["specs"] = specs
            return None

        selected = root_store.read_selected(validate=validate)
        return selected

    @staticmethod
    def _group_launches(launches):
        by_nonce = {}
        for item in launches:
            by_nonce.setdefault(item.launch_spec.launch_nonce, []).append(item)
        groups = []
        for nonce, members in sorted(by_nonce.items()):
            # Current protected role headers bind exactly one principal. A
            # multi-role process would need a separately specified multi-role
            # runtime binding format; do not infer it from a shared nonce.
            if len(members) != 1:
                raise BindingError("current protected role binding supports one role per process")
            first = members[0]
            key = (first.manifest_path, first.protected_root, first.configuration_path)
            if any((item.manifest_path, item.protected_root, item.configuration_path) != key
                   for item in members):
                raise BindingError("roles sharing one process nonce must share manifest and config")
            specs = tuple(sorted((item.launch_spec for item in members),
                                 key=lambda spec: spec.identity))
            if any(spec.launch_nonce != nonce for spec in specs):
                raise BindingError("process cohort nonce differs from role declaration")
            groups.append(_LaunchGroup(nonce, *key, specs))
        if not 1 <= len(groups) <= MAX_OWNED_PROCESSES:
            raise BindingError("startup process-group count is outside its bound")
        return tuple(groups)

    @staticmethod
    def _same_selected(left, selector, bundle, active_policy) -> bool:
        try:
            encoded_selector = canonical_json(root_generation_selector_document(selector))
            return (hashlib.sha256(encoded_selector).hexdigest() == left.selector_sha256
                    and selector == left.selector
                    and dict(bundle) == dict(left.artifacts)
                    and active_policy == left.active_policy_snapshot)
        except Exception:
            return False

    def _check_binding_files(self, launch: RootRoleLaunch, binding) -> dict:
        header = binding.configuration_header
        if (safe_read(launch.configuration_path, root=launch.configuration_root,
                      expected_uid=self.uid, max_bytes=16 * 1024) != header):
            raise CredentialError("protected role header changed during startup")
        import json
        from .root_runtime import _pairs
        raw = json.loads(header.decode("utf-8", errors="strict"), object_pairs_hook=_pairs)
        _configuration_header(raw)
        if (raw["protected_root"] != os.path.abspath(launch.configuration_root)
                or hashlib.sha256(header).hexdigest()
                    != launch.launch_spec.configuration_sha256):
            raise CredentialError("role header differs from selected launch specification")
        for path_field, data, bound in (
                ("runtime_configuration_path", binding.runtime_configuration, 16 * 1024),
                ("certificate_path", binding.tls_materials.certificate_pem, 64 * 1024),
                ("private_key_path", binding.tls_materials.private_key_pem, 64 * 1024)):
            current = safe_read(raw[path_field], root=launch.configuration_root,
                                expected_uid=self.uid, max_bytes=bound)
            if current != data:
                raise CredentialError("protected role runtime material changed during startup")
        return raw

    @staticmethod
    def _require_before_deadline(deadline: float, phase: str) -> None:
        if _startup_monotonic() >= deadline:
            raise TimeoutError(f"cohort startup deadline expired during {phase}")

    def _check_bindings_live(self, launches, bindings, expected_policy):
        raw_headers = []
        for launch, binding in zip(launches, bindings):
            if binding.snapshot_store.clock is not self.clock:
                raise CredentialError("role binding does not share the startup clock")
            if (binding.launch_spec != launch.launch_spec
                    or binding.local_identity.admission_epoch != launch.launch_spec.admission_epoch
                    or binding.local_identity.root_generation_sha256
                        != launch.launch_spec.generation_sha256):
                raise CredentialError("role binding differs from selected launch plan")
            raw_headers.append(self._check_binding_files(launch, binding))
        # All protected-file reads finish before the single common liveness
        # sample, so later roles cannot inherit an earlier role's old sample.
        sample = self.clock.sample()
        for launch, binding, raw in zip(launches, bindings, raw_headers):
            view = binding.snapshot_store.current(sample=sample)
            if ((view.revision, view.policy_digest) != expected_policy
                    or binding.snapshot_store.ca_certificate_pem == b""):
                raise CredentialError("original role policy store differs from selected head")
            record = view.credentials_by_serial.get(launch.launch_spec.serial)
            if record is None:
                raise CredentialError("selected role credential disappeared from current policy")
            binding.snapshot_store.assert_credential_live(view, record, sample)
            _require_current_role_grants(view, sample, record, launch.launch_spec, raw)

    def _validate_group_manifests(self, groups, launches, expected=None):
        manifests = {}
        for group in groups:
            manifest = self.retirement._load_manifest(
                group.manifest_path, group.protected_root, self.uid)
            if (manifest.configuration_path != group.configuration_path
                    or any(spec.configuration_sha256 != manifest.configuration_sha256
                           for spec in group.specs)):
                raise BindingError("protected launcher manifest differs from role configuration")
            manifests[group.nonce] = manifest
        if expected is not None and manifests != expected:
            raise BindingError("protected launcher declaration changed during startup")
        return manifests

    def _validate_observed_groups(self, groups, observed, manifests):
        if len(observed) != len(groups):
            raise BindingError("observed process groups do not cover the selected plan")
        for group, capability in zip(groups, observed):
            if (not self.retirement.validate_observed_launch(capability)
                    or capability._record.manifest != manifests[group.nonce]
                    or capability._record.specs != group.specs):
                raise BindingError("observed process differs from the frozen launcher cohort")

    async def start(self, launches: tuple[RootRoleLaunch, ...], *,
                    startup_timeout_seconds: float = MAX_STARTUP_SECONDS,
                    cleanup_timeout_seconds: float = MAX_CLEANUP_SECONDS
                    ) -> StartedRootCohort:
        if (type(startup_timeout_seconds) not in (int, float)
                or type(startup_timeout_seconds) is bool
                or not 0 < startup_timeout_seconds <= MAX_STARTUP_SECONDS
                or type(cleanup_timeout_seconds) not in (int, float)
                or type(cleanup_timeout_seconds) is bool
                or not 0 < cleanup_timeout_seconds <= MAX_CLEANUP_SECONDS):
            raise BindingError("startup and cleanup timeouts exceed fixed bounds")
        launches = self._validate_launches(launches)
        groups = self._group_launches(launches)
        specs = tuple(item.launch_spec for item in launches)
        with self.retirement._state_lock:
            if (self._active or self._started or self.retirement._owned
                    or self.retirement._root_startup_owner is not None
                    or len(self._started) >= _MAX_STARTED_CAPABILITIES):
                raise BindingError("startup supervisor already owns a cohort")
            self.retirement._root_startup_owner = self
            self._active = True
        started_at = _startup_monotonic()
        deadline = started_at + float(startup_timeout_seconds)
        pending: list[PendingOwnedLaunch] = []
        owned_records = []
        observed: list[ObservedLaunch] = []
        bindings = []
        claim_attempted = False
        cleanup_deadline = None
        cap_holder = {}
        generation = specs[0].generation_sha256
        try:
            initial = self._capture_selected(self.root_store)
            selected_specs = tuple(_selected_binding(
                initial.selector, initial.artifacts, initial.active_policy_snapshot))
            if tuple(spec.identity for spec in selected_specs) != tuple(
                    spec.identity for spec in specs):
                raise BindingError("startup inputs do not cover the complete selected role plan")
            if canonical_json([role_launch_document(x) for x in selected_specs]) != canonical_json(
                    [role_launch_document(x) for x in specs]):
                raise BindingError("startup role launch declarations differ from selected plan")
            selected_policy = SnapshotStore(
                verification_key_pem=initial.artifacts["snapshot_signer_public.pem"],
                ca_certificate_pem=initial.artifacts["ca_certificate.pem"], clock=self.clock,
                minimum_revision=initial.selector.policy_revision,
                minimum_policy_digest=initial.selector.policy_digest)
            initial_view = selected_policy.install(initial.active_policy_snapshot)
            if (initial_view.revision, initial_view.policy_digest) != (
                    initial.selector.policy_revision, initial.selector.policy_digest):
                raise CredentialError("selected policy bytes differ from protected selector")
            for launch in launches:
                binding = load_root_runtime_binding(
                    root_store=self.root_store, clock=self.clock,
                    expected_launch_spec=launch.launch_spec,
                    configuration_path=launch.configuration_path,
                    configuration_root=launch.configuration_root,
                    expected_uid=self.uid)
                bindings.append(binding)
            expected_policy = (initial.selector.policy_revision,
                               initial.selector.policy_digest)
            manifests = self._validate_group_manifests(groups, launches)
            self._check_bindings_live(launches, bindings, expected_policy)
            self._require_before_deadline(deadline, "protected preflight")

            captured_claim = {}

            def fresh_selected(selector, bundle, active_policy):
                if not self._same_selected(initial, selector, bundle, active_policy):
                    raise StorageError("selected root changed before durable cohort claim")
                current_specs = _selected_binding(selector, bundle, active_policy)
                if canonical_json([role_launch_document(x) for x in current_specs]) != canonical_json(
                        [role_launch_document(x) for x in specs]):
                    raise StorageError("selected role plan changed before cohort claim")
                self._validate_group_manifests(groups, launches, manifests)
                self._check_bindings_live(launches, bindings, expected_policy)
                self._require_before_deadline(deadline, "fresh-head validation")

                def claim_head_validator(record, claimed_specs):
                    if (record.selector_sha256 != initial.selector_sha256
                            or record.activation_manifest_sha256
                                != initial.selector.activation_manifest_sha256
                            or record.generation_sha256 != generation
                            or canonical_json([role_launch_document(x) for x in claimed_specs])
                                != canonical_json([role_launch_document(x) for x in specs])):
                        raise StorageError("durable claim differs from freshly checked root plan")
                    return None

                nonlocal claim_attempted
                claim_attempted = True
                receipt = self.claim_store.claim(
                    selector_sha256=initial.selector_sha256,
                    activation_manifest_sha256=initial.selector.activation_manifest_sha256,
                    generation_sha256=generation, role_launch_specs=specs,
                    fresh_selected_validator=claim_head_validator)
                captured_claim["receipt"] = receipt
                # Popen and immediate owner registration are synchronous and
                # remain inside RootGenerationStore's shared-head lock.
                for group in groups:
                    self._require_before_deadline(deadline, "cohort spawn")
                    with self.retirement._state_lock:
                        before = {id(item) for item in self.retirement._owned}
                        try:
                            launch = self.retirement.spawn_owned_process(
                                group.manifest_path, protected_root=group.protected_root,
                                expected_uid=self.uid, specs=group.specs,
                                expected_manifest=manifests[group.nonce],
                                before_popen_check=lambda: self._require_before_deadline(
                                    deadline, "cohort spawn after launcher validation"))
                            pending.append(launch)
                        finally:
                            # Also capture the supervisor's immediate strong
                            # owner if its post-Popen validation raised before
                            # returning the opaque pending handle.
                            owned_records.extend(
                                item for item in self.retirement._owned
                                if id(item) not in before)
                return None

            self.root_store.read_selected(validate=fresh_selected)
            if "receipt" not in captured_claim or len(pending) != len(groups):
                raise StorageError("cohort claim or synchronous process ownership is incomplete")

            tasks: list[asyncio.Task | None] = [None] * len(pending)

            def dispatch(indices):
                for index in indices:
                    # Compute the per-observation bound immediately before
                    # dispatch. Never manufacture a minimum window after the
                    # original cohort deadline has expired.
                    remaining = deadline - _startup_monotonic()
                    if remaining <= 0:
                        raise TimeoutError(
                            "cohort startup deadline expired before READY observation")
                    timeout = min(10.0, remaining)
                    tasks[index] = asyncio.create_task(
                        self.retirement.observe_ready(
                            pending[index], ready_timeout_seconds=timeout))

            async def wait_for_indices(indices):
                remaining = deadline - _startup_monotonic()
                if remaining <= 0:
                    raise TimeoutError(
                        "cohort startup deadline expired before READY observation")
                await asyncio.wait_for(
                    asyncio.gather(*(tasks[index] for index in indices)),
                    timeout=remaining)

            try:
                roles = tuple(group.specs[0].role for group in groups)
                host_indices = [index for index, role in enumerate(roles)
                                if role == "host"]
                coordinator_indices = [index for index, role in enumerate(roles)
                                      if role == "personal_coordinator"]
                known_roles = {"host", "personal_coordinator", "consumer"}
                staged_roles = (set(roles) <= known_roles
                                and all(len(group.specs) == 1 for group in groups)
                                and len(coordinator_indices) == 1
                                and bool(host_indices))
                if staged_roles:
                    independent_indices = [index for index, role in enumerate(roles)
                                           if role != "personal_coordinator"]
                    dispatch(independent_indices)
                    host_tasks = {tasks[index] for index in host_indices}
                    remaining_tasks = {tasks[index] for index in independent_indices}
                    while host_tasks:
                        remaining = deadline - _startup_monotonic()
                        if remaining <= 0:
                            raise TimeoutError(
                                "cohort startup deadline expired before READY observation")
                        done, _ = await asyncio.wait(
                            remaining_tasks, timeout=remaining,
                            return_when=asyncio.FIRST_COMPLETED)
                        if not done:
                            raise TimeoutError(
                                "cohort startup deadline expired before READY observation")
                        for task in done:
                            task.result()
                        remaining_tasks.difference_update(done)
                        host_tasks.difference_update(done)
                    # A consumer's success does not gate the coordinator, but
                    # any independent failure already visible at this barrier
                    # must be raised before coordinator observation is started.
                    for task in remaining_tasks:
                        if task.done():
                            task.result()
                    dispatch(coordinator_indices)
                else:
                    dispatch(range(len(pending)))
                all_indices = range(len(pending))
                await wait_for_indices(all_indices)
                observed = [task.result() for task in tasks]
            except BaseException:
                if cleanup_deadline is None:
                    cleanup_deadline = time.monotonic() + float(cleanup_timeout_seconds)
                for task in tasks:
                    if task is not None and not task.done():
                        task.cancel()
                try:
                    cleanup_remaining = cleanup_deadline - time.monotonic()
                    if cleanup_remaining <= 0:
                        raise asyncio.TimeoutError
                    active_tasks = [task for task in tasks if task is not None]
                    await asyncio.wait_for(asyncio.gather(*active_tasks,
                                                          return_exceptions=True),
                                           timeout=min(0.5, cleanup_remaining / 4.0))
                except asyncio.TimeoutError:
                    raise TimeoutError("READY observation tasks did not stop within cleanup bound")
                raise

            def validate_final(selector, bundle, active_policy):
                self._require_before_deadline(deadline, "final root recheck")
                if not self._same_selected(initial, selector, bundle, active_policy):
                    raise StorageError("selected root changed during cohort startup")
                self._validate_group_manifests(groups, launches, manifests)
                self._require_before_deadline(deadline, "final root recheck")
                self._validate_observed_groups(groups, observed, manifests)
                self._check_bindings_live(launches, bindings, expected_policy)
                self._require_before_deadline(deadline, "final root recheck")
                record = (initial.selector_sha256, generation, specs, tuple(observed),
                          tuple(zip(launches, bindings)), expected_policy,
                          groups, manifests)
                capability = StartedRootCohort(self, record, self._seal)
                self._started.append(capability)
                cap_holder["capability"] = capability
                return None

            self.root_store.read_selected(validate=validate_final)
            capability = cap_holder["capability"]
            self._active = False
            return capability
        except BaseException as error:
            self._started[:] = [item for item in self._started
                                if item is not cap_holder.get("capability")]
            try:
                if claim_attempted or pending:
                    if cleanup_deadline is None:
                        cleanup_deadline = time.monotonic() + float(cleanup_timeout_seconds)
                    self._cleanup_failed_start(generation, cleanup_deadline, owned_records)
            except BaseException as cleanup_error:
                raise RuntimeError("startup failed and owned-process cleanup is unknown") from cleanup_error
            self._active = False
            if not claim_attempted and not pending:
                with self.retirement._state_lock:
                    if self.retirement._root_startup_owner is self:
                        self.retirement._root_startup_owner = None
            raise

    def _cleanup_failed_start(self, generation: str, cleanup_deadline: float,
                              records) -> None:
        with self.retirement._state_lock:
            self.retirement._fenced_generations.add(generation)
        if not records:
            return
        for record in records:
            if any(spec.generation_sha256 != generation for spec in record.specs):
                raise BindingError("attempt-owned process escaped its selected generation")
            if record.process.poll() is None:
                timeout_seconds = cleanup_deadline - time.monotonic()
                if timeout_seconds <= 0:
                    raise TimeoutError("owned-process cleanup deadline expired")
                self.retirement.terminate_owned_process_group(
                    record.process, timeout_seconds=min(5.0, timeout_seconds))
        if not all(item.process.poll() is not None
                   and self.retirement._group_absent(item.pgid) for item in records):
            raise TimeoutError("registered process groups remain live or unknown")

    def validate_started_binding(self, capability: StartedRootCohort) -> bool:
        if not (type(capability) is StartedRootCohort
                and not self._active
                and capability._owner is self and capability._seal is self._seal
                and any(item is capability for item in self._started)):
            return False
        (selector_sha, generation, specs, observed, binding_records,
         expected_policy, groups, manifests) = capability._record
        if (len(specs) > MAX_LAUNCH_ROLES or len(observed) > MAX_OWNED_PROCESSES
                or any(spec.generation_sha256 != generation for spec in specs)):
            return False
        try:
            launches = tuple(item[0] for item in binding_records)
            bindings = tuple(item[1] for item in binding_records)
            def validate(selector, bundle, active_policy):
                selected = self._capture_selected_from_values(selector, bundle, active_policy)
                if selected != selector_sha:
                    raise StorageError("started root head is no longer selected")
                self._validate_group_manifests(groups, launches, manifests)
                self._validate_observed_groups(groups, observed, manifests)
                self._check_bindings_live(launches, bindings, expected_policy)
                return None
            self.root_store.read_selected(validate=validate)
            return True
        except Exception:
            return False

    @staticmethod
    def _capture_selected_from_values(selector, bundle, active_policy):
        _selected_binding(selector, bundle, active_policy)
        return hashlib.sha256(canonical_json(root_generation_selector_document(selector))).hexdigest()
