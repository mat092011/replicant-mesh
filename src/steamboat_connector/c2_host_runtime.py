"""Bounded assembly of assigned host stages under a selected C2 binding.

This module assembles resident stage handlers and secure worker bridges. It is
not a process entrypoint, transport listener, readiness signal, or whole-host
resource enforcer. Callers must retain this owner until bounded runtime cleanup
is confirmed and must not expose a bridge without its runtime guard.
"""
from __future__ import annotations

import asyncio
import inspect
import threading
import time
from types import MappingProxyType

from steamboat_connector.aggregate_artifact_pin import InheritedGroupPin
from steamboat_connector.artifacts import ArtifactInstaller
from steamboat_connector.catalog import CatalogVerifier
from steamboat_connector.c2_child_config import C2ChildBinding
from steamboat_connector.policy import validate_policy
from steamboat_connector.runtime_pin_handoff import ChildArtifactPinSet
from steamboat_security.authorization import Authorizer
from steamboat_security.clock import Clock
from steamboat_security.errors import CredentialError, StorageError
from steamboat_security.sessions import SessionBindings
from steamboat_runtime.assigned_executor import build_assigned_worker_handler
from steamboat_runtime.protocol.worker_pb2 import Request
from steamboat_runtime.secure_worker_runtime import SecureWorkerRuntimeBridge


_ALLOCATION_FIELDS = frozenset({"sessions", "kv_bytes", "cache_positions", "queued_calls"})


class C2HostRuntimeError(StorageError):
    """C2 host runtime assembly or confirmed shutdown failed closed."""


def _exact_positive_int(value, name):
    if type(value) is not int or value <= 0:
        raise CredentialError(f"{name} must be an exact positive integer")
    return value


def _validate_allocations(binding, child_pins, installer, policy, allocations):
    scope = binding.scope
    selected = {item.component: item for item in scope.components}
    if (not 1 <= len(selected) <= 3
            or len(selected) != len(scope.components)
            or type(allocations) is not dict
            or set(allocations) != set(selected)):
        raise CredentialError("component allocations must exactly cover the selected C2 scope")
    reservation = policy["reservations"].get("host")
    if type(reservation) is not dict:
        raise CredentialError("owner policy has no host reservation")

    if (type(child_pins) is not ChildArtifactPinSet or child_pins._state != "open"
            or len(child_pins.owners) != len(selected)
            or len(child_pins.guards) != len(selected)
            or type(installer) is not ArtifactInstaller or installer.read_only is not True
            or type(installer.verifier) is not CatalogVerifier
            or installer.verifier.clock is not binding._clock
            or installer.uid != binding._root_store._uid):
        raise CredentialError("host runtime requires exact live child pins and read-only installer")
    if installer.root != child_pins.owners[0].root:
        raise CredentialError("read-only installer root differs from inherited artifact pins")

    reference_record = None
    catalog_digest = None
    catalog_model_id = None
    catalog_fingerprint = None
    catalog = None
    for owner in child_pins.owners:
        if type(owner) is not InheritedGroupPin:
            raise CredentialError("child pin set contains a non-inherited group owner")
        owner.assert_open_descriptors()
        record = dict(owner.record)
        if reference_record is None:
            reference_record = record
            catalog_digest = record["catalog_sha256"]
            catalog = installer.verifier.verify_catalog(owner.signed_catalog)
            import hashlib
            if hashlib.sha256(catalog.document_bytes).hexdigest() != catalog_digest:
                raise CredentialError("inherited signed catalog differs from its group record")
            catalog_model_id = catalog.payload["model"]["model_id"]
            catalog_fingerprint = catalog.payload["manifest"]["fingerprint"]
        elif record != reference_record:
            raise CredentialError("inherited component owners do not share one group record")
        if (record["account_id"] != binding._spec.account_id
                or record["device_id"] != binding._spec.device_id
                or record["role"] != "host"
                or record["runtime_boot_id"] != binding._spec.boot_id
                or record["model_id"] != catalog_model_id
                or owner.root != installer.root or owner.uid != installer.uid
                or owner.clock is not binding._clock
                or owner.verifier is not installer.verifier):
            raise CredentialError("inherited group owner differs from selected host or catalog")
    if catalog_fingerprint != scope.model_id:
        raise CredentialError("signed catalog fingerprint differs from selected C2 model scope")

    guard_by_component = {}
    for guard in child_pins.guards:
        from steamboat_connector.artifact_pin import RuntimeAssignmentGuard
        if type(guard) is not RuntimeAssignmentGuard:
            raise CredentialError("child pin set contains a non-runtime assignment guard")
        if (guard.child_clock is not binding._clock
                or guard.child_verifier is not installer.verifier
                or guard.role != "host"
                or guard.account_id != binding._spec.account_id
                or guard.device_id != binding._spec.device_id
                or guard.manifest_fingerprint != scope.model_id
                or guard.component in guard_by_component):
            raise CredentialError("inherited assignment guard differs from selected C2 scope")
        guard.check()
        guard_by_component[guard.component] = guard
    if set(guard_by_component) != set(selected):
        raise CredentialError("inherited assignment guards do not exactly cover selected components")

    normalized = {}
    total_sessions = total_kv = total_queue = 0
    for component, selected_item in selected.items():
        allocation = allocations[component]
        if type(allocation) is not dict or set(allocation) != _ALLOCATION_FIELDS:
            raise CredentialError("component allocation fields do not match the closed schema")
        sessions = _exact_positive_int(allocation["sessions"], "sessions")
        kv_bytes = _exact_positive_int(allocation["kv_bytes"], "KV bytes")
        cache_positions = _exact_positive_int(allocation["cache_positions"], "cache positions")
        queued_calls = allocation["queued_calls"]
        if type(queued_calls) is not int or not 0 <= queued_calls <= 8:
            raise CredentialError("queued calls must be an integer in [0, 8]")
        guard = guard_by_component[component]
        if (guard.assignment_id != selected_item.assignment_id
                or guard.pin.record.get("boot_id") != selected_item.worker_boot_id):
            raise CredentialError("inherited assignment tuple differs from selected C2 component")
        view = installer.open_view(guard.assignment_id,
            account_id=binding._spec.account_id, device_id=binding._spec.device_id,
            role="host")
        manifest = view._locked_manifest()
        assignment = view.assignment
        if (view.installer is not installer or view.role != "host"
                or assignment is None or assignment.document_sha256 != guard.assignment_sha256
                or assignment.payload.get("component") != component
                or assignment.payload.get("manifest_fingerprint") != scope.model_id
                or manifest.get("fingerprint") != scope.model_id
                or manifest.get("model_id") != catalog_model_id):
            raise CredentialError("read-only assigned view differs from selected signed scope")
        limits = manifest["limits"]
        if (sessions > reservation["sessions"]
                or cache_positions > limits["worker_cache_positions"]
                or kv_bytes > limits["worker_cache_bytes"]):
            raise CredentialError("component allocation exceeds signed or assigned limits")
        request_timeout = min(reservation["max_request_seconds"],
                              limits["request_timeout_seconds"])
        owner_limits = {
            "max_sessions": sessions,
            "worker_cache_positions": cache_positions,
            "worker_cache_bytes": kv_bytes,
            "request_timeout_seconds": request_timeout,
        }
        # Validate all narrowing against the real assigned manifest before any
        # call that constructs AssignedStageExecutor and loads resident weights.
        from steamboat_runtime.assigned_executor import _validate_owner_limits
        _validate_owner_limits(manifest, owner_limits)
        normalized[component] = (view, guard, MappingProxyType(owner_limits),
                                 MappingProxyType(dict(allocation)))
        total_sessions += sessions
        total_kv += kv_bytes
        total_queue += queued_calls
    if (total_sessions > min(reservation["sessions"], policy["limits"]["max_sessions"])
            or total_kv > reservation["kv_bytes"]
            or total_queue > min(reservation["queued_calls"],
                                 policy["limits"]["max_queued_calls"])):
        raise CredentialError("aggregate component allocations exceed host reservation")
    return normalized


class C2HostRuntime:
    """Retained child-side model assembly and bridge owner; never READY authority."""
    def __init__(self, lease, binding, child_pins, installer):
        self._lease = lease
        self._binding = binding
        self._child_pins = child_pins
        self._installer = installer
        self._handlers = {}
        self._authorizers = {}
        self._sessions = {}
        self._bridges = {}
        self._started_bridges = set()
        self._loop = asyncio.get_running_loop()
        self._invalidated = threading.Event()
        self._state = "assembling"
        self._load_started = False
        self._close_error = None
        self._close_lock = asyncio.Lock()
        binding.subscribe_teardown(self._binding_invalidated)

    @property
    def components(self):
        self.assert_live()
        return tuple(sorted(self._handlers))

    def assert_live(self):
        if self._state not in {"open", "assembling"} or self._invalidated.is_set():
            raise C2HostRuntimeError("C2 host runtime is fenced")
        self._binding.assert_live()
        for guard in self._child_pins.guards:
            guard.check()
        return True

    def _binding_invalidated(self, reason):
        # The binding invokes teardown subscribers synchronously and outside its
        # own lock. This callback only fences already constructed bridges.
        self._invalidated.set()
        try:
            self._loop.call_soon_threadsafe(self._fence_bridges, str(reason)[:128])
        except RuntimeError:
            self._invalidated.set()

    def _fence_bridges(self, reason):
        for bridge in tuple(self._bridges.values()):
            try:
                bridge.request_runtime_invalidation(reason)
            except BaseException:
                self._invalidated.set()

    async def close(self, grace_seconds=5.0):
        if (type(grace_seconds) not in (int, float) or not 0 < grace_seconds <= 5.0):
            raise ValueError("host runtime shutdown grace must be in (0, 5]")
        async with self._close_lock:
            if self._state == "closed":
                return True
            if self._state == "faulted":
                raise C2HostRuntimeError("host runtime cleanup is uncertain") from self._close_error
            self._state = "closing"
            deadline = self._loop.time() + float(grace_seconds)
            try:
                for bridge in self._bridges.values():
                    if not getattr(bridge, "_started", False):
                        continue
                    remaining = deadline - self._loop.time()
                    if remaining <= 0 or not await asyncio.wait_for(
                            bridge.stop(grace_seconds=min(5.0, remaining)),
                            timeout=max(0.001, remaining)):
                        raise C2HostRuntimeError("secure worker bridge did not confirm cleanup")
                for handler in self._handlers.values():
                    remaining = deadline - self._loop.time()
                    if remaining <= 0 or not await asyncio.wait_for(
                            handler.shutdown(grace_seconds=remaining),
                            timeout=max(0.001, remaining)):
                        raise C2HostRuntimeError("assigned worker handler did not confirm shutdown")
                self._child_pins.close()
                self._lease.__exit__(None, None, None)
                self._state = "closed"
                return True
            except BaseException as error:
                self._close_error = error
                self._state = "faulted"
                raise C2HostRuntimeError(
                    "host runtime cleanup is uncertain; retain owners until process reap") from error


async def build_c2_host_runtime(child_binding_owner, child_pin_set, installer, *,
                                owner_policy, component_allocations):
    """Load 1–3 exact selected host stages and start guarded secure bridges.

    Ownership of the child pin set transfers to the returned runtime on success.
    If any model load or bridge start fails, the exception carries
    ``c2_host_runtime_owner`` so the caller can retain it through confirmed
    cleanup or process reaping. Pre-load validation failures release only the
    child-binding borrow and leave the caller's pin set untouched.
    """
    if type(child_binding_owner) is not C2ChildBinding:
        raise TypeError("host runtime requires the exact C2 child binding owner")
    if type(installer) is not ArtifactInstaller or installer.read_only is not True:
        raise TypeError("host runtime requires an exact read-only artifact installer")
    try:
        policy = validate_policy(owner_policy)
    except (TypeError, ValueError) as error:
        raise CredentialError("owner resource policy is invalid") from error
    if type(child_pin_set) is not ChildArtifactPinSet:
        raise TypeError("host runtime requires the exact inherited child pin set")
    bridge_parameters = inspect.signature(SecureWorkerRuntimeBridge.__init__).parameters
    if ("runtime_guard" not in bridge_parameters
            or not hasattr(SecureWorkerRuntimeBridge, "request_runtime_invalidation")):
        raise C2HostRuntimeError(
            "secure runtime bridge lacks the selected-root runtime guard interface")

    lease = child_binding_owner.borrow()
    binding = lease.__enter__()
    runtime = None
    try:
        binding.assert_live()
        normalized = _validate_allocations(binding, child_pin_set, installer,
                                           policy, component_allocations)
        # Every selected scope, inherited guard, view, and resource narrowing is
        # validated before the first call that loads assigned stage weights.
        runtime = C2HostRuntime(lease, binding, child_pin_set, installer)
        runtime.assert_live()
        from steamboat_security.sessions import SessionBindings
        for component, (view, guard, owner_limits, allocation) in normalized.items():
            binding.assert_live()
            guard.check()
            runtime._load_started = True
            handler = build_assigned_worker_handler(view,
                boot_id=guard.pin.record["boot_id"], clock=binding._clock,
                enable_queue=allocation["queued_calls"] > 0,
                queue_capacity=(allocation["queued_calls"]
                                if allocation["queued_calls"] > 0 else None),
                owner_limits=dict(owner_limits), guard=guard)
            runtime._handlers[component] = handler
            binding.assert_live()
            guard.check()
            sessions = SessionBindings(clock=binding._clock,
                max_live_sessions=allocation["sessions"])
            authorizer = Authorizer(local_identity=next(
                item.identity for item in binding._components if item.component == component),
                snapshot_store=binding._snapshot_store, clock=binding._clock,
                session_bindings=sessions, worker_request_type=Request)
            bridge = SecureWorkerRuntimeBridge(authorizer, handler,
                runtime_guard=binding.assert_live)
            runtime._sessions[component] = sessions
            runtime._authorizers[component] = authorizer
            runtime._bridges[component] = bridge
        runtime.assert_live()
        for bridge in runtime._bridges.values():
            binding.assert_live()
            await bridge.start()
            runtime._started_bridges.add(bridge)
            runtime.assert_live()
        runtime._state = "open"
        return runtime
    except BaseException as error:
        if runtime is None:
            lease.__exit__(type(error), error, error.__traceback__)
        else:
            runtime._started_bridges.update(
                bridge for bridge in runtime._bridges.values()
                if getattr(bridge, "_started", False))
            runtime._state = "partial"
            try:
                error.c2_host_runtime_owner = runtime
            except BaseException:
                pass
        raise
