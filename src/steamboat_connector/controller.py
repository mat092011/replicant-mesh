import copy
import os
import platform
import queue
import stat
import sys
import threading
import time
from pathlib import Path

from .errors import ConnectorError
from .policy import ROLE_NAMES, role_blockers, validate_policy
from .resources import (CgroupV2Controller, MemoryResourceLedger, ResourceError,
                        ResourceLedger, unsupported_enforcement)
from .state import OPERATION_STATES, copy_state, initial_state, validate_state
from .storage import FileStateStore, MemoryStateStore, StorageError
from .telemetry import TelemetryRegistry
from .validation import new_id, valid_typed_id


class InactiveRoleBackend:
    secure_runtime_ready = False

    def start(self, role, policy, *, cancel_event=None):
        return False

    def request_stop(self, roles):
        return {role: False for role in roles}

    def request_drain(self, roles):
        return {role: False for role in roles}

    def drain(self, roles, deadline, cancel_event):
        return {"drained": True, "reclaimed": True}

    def stop(self, roles, grace_seconds):
        return {role: True for role in roles}


class ManagementController:
    def __init__(self, *, state_directory=None, ledger=None, backend=None,
                 telemetry=None, cgroup=None, store=None, clock=time.monotonic,
                 start_workers=True):
        self.clock = clock
        self.state_directory = Path(state_directory) if state_directory is not None else None
        self.backend = backend or InactiveRoleBackend()
        self.telemetry = telemetry or TelemetryRegistry(clock=clock)
        self.cgroup = cgroup or CgroupV2Controller()
        if ledger is not None:
            self.ledger = ledger
        elif state_directory is not None:
            self.ledger = ResourceLedger(self.state_directory / "resource-ledger.json")
        else:
            self.ledger = MemoryResourceLedger()
        if store is not None:
            self.store = store
        elif state_directory is not None:
            self.store = FileStateStore(state_directory, initial_state=initial_state())
        else:
            self.store = MemoryStateStore(initial_state())
        self._lock = threading.RLock()
        self._normal = queue.Queue(maxsize=32)
        self._urgent = queue.Queue(maxsize=64)
        self._closing = threading.Event()
        self._drains = {}
        # A start owns its cancellation token before entering the lifecycle
        # queue. Retain it until backend.start returns, including after Stop.
        self._starts = {}
        self._stop_fences = {}
        self._stop_tokens = {}
        self._threads = []
        self._state = validate_state(self.store.load())
        self.boot_id = __import__("secrets").token_hex(16)
        self._recover_boot()
        if start_workers:
            self._start_workers()

    def _start_workers(self):
        for name, work_queue in (("connector-lifecycle", self._normal),
                                 ("connector-stop", self._urgent)):
            thread = threading.Thread(target=self._worker_loop, args=(work_queue,),
                                      name=name, daemon=True)
            thread.start()
            self._threads.append(thread)

    def _recover_boot(self):
        with self._lock:
            previous_boot = self._state["boot_id"]
            interrupted = False
            for operation in self._state["operations"]:
                if operation["status"] in ("queued", "running"):
                    operation["status"] = "interrupted"
                    operation["result"] = {"reclaimed": False,
                                            "reason": "daemon_restart_requires_revalidation"}
                    interrupted = True
            if previous_boot is not None:
                for role, enabled in self._state["roles"].items():
                    if enabled:
                        self._state["paused_roles"][role] = True
            if interrupted:
                for role in ROLE_NAMES:
                    if self._state["roles"][role]:
                        self._state["paused_roles"][role] = True
            self._state["boot_id"] = self.boot_id
            validate_state(self._state)
            self.store.save(self._state)
            if self._state["policy"] is not None:
                try:
                    self.ledger.configure(self._state["policy"])
                except ResourceError:
                    for role in ("host", "coordinator"):
                        self._state["paused_roles"][role] = True
                    self.store.save(self._state)

    def _persist(self):
        validate_state(self._state)
        self.store.save(self._state)

    def _state_copy(self):
        with self._lock:
            return copy_state(self._state)

    @staticmethod
    def _payload(payload, allowed):
        if type(payload) is not dict or not set(payload).issubset(allowed):
            raise ConnectorError("INVALID_ARGUMENT", "management payload is not allowed")

    @staticmethod
    def _role(role):
        if not isinstance(role, str) or role not in ROLE_NAMES:
            raise ConnectorError("INVALID_ARGUMENT", "role must be consumer, host, or coordinator")
        return role

    def _roles(self, payload, *, default_enabled=True):
        self._payload(payload, {"roles"})
        roles = payload.get("roles")
        if roles is None and default_enabled:
            roles = [name for name, enabled in self._state["roles"].items() if enabled]
        if type(roles) is not list or not roles or len(roles) > len(ROLE_NAMES):
            raise ConnectorError("INVALID_ARGUMENT", "roles must be a nonempty list")
        if (any(not isinstance(role, str) or role not in ROLE_NAMES for role in roles)
                or len(set(roles)) != len(roles)):
            raise ConnectorError("INVALID_ARGUMENT", "roles contains duplicates or an unknown role")
        return tuple(roles)

    def _record_operation(self, action, *, status="queued", result=None):
        active = [item for item in self._state["operations"]
                  if item["status"] in ("queued", "running")]
        if len(active) >= 48:
            raise ConnectorError("BUSY", "too many lifecycle operations are active")
        while len(self._state["operations"]) >= 64:
            removable = next((index for index, item in enumerate(self._state["operations"])
                              if item["status"] not in ("queued", "running")), None)
            if removable is None:
                raise ConnectorError("BUSY", "operation history is full")
            del self._state["operations"][removable]
        operation = {"operation_id": new_id("op"), "action": action,
                     "status": status, "result": result or {}}
        self._state["operations"].append(operation)
        self._persist()
        return operation

    def _find_operation(self, operation_id):
        if not valid_typed_id(operation_id, "op"):
            raise ConnectorError("INVALID_ARGUMENT", "operation identity is invalid")
        return next((item for item in self._state["operations"]
                     if item["operation_id"] == operation_id), None)

    def _operation_update(self, operation_id, status, result):
        if status not in OPERATION_STATES:
            raise ValueError("invalid lifecycle operation state")
        with self._lock:
            operation = self._find_operation(operation_id)
            if operation is None:
                return
            operation["status"] = status
            operation["result"] = result
            self._persist()

    def _enqueue(self, queue_target, operation_id, kind, payload):
        try:
            queue_target.put_nowait((operation_id, kind, payload))
            return True
        except queue.Full:
            self._stop_tokens.pop(operation_id, None)
            self._operation_update(operation_id, "incomplete", {"reason": "lifecycle_queue_full",
                                                                 "reclaimed": False})
            return False

    def _resource_snapshot(self):
        try:
            snapshot = self.ledger.snapshot()
            return {
                "pool_id": snapshot["pool_id"],
                "reserved_roles": sorted(snapshot["reservations"]),
                "reserved_memory_bytes": sum(
                    sum(reservation[field] for field in (
                        "weights_bytes", "kv_bytes", "temporary_bytes", "runtime_bytes",
                        "communication_bytes", "capture_bytes"))
                    for reservation in snapshot["reservations"].values()),
                "blocked": snapshot["blocked"],
                "block_reason": snapshot["block_reason"],
                "accounting": "atomic_bookkeeping_not_physical_enforcement",
            }
        except (ResourceError, StorageError):
            return {"pool_id": None, "reserved_roles": [], "reserved_memory_bytes": 0,
                    "blocked": True, "block_reason": "ledger_unavailable",
                    "accounting": "unavailable_fail_closed"}

    def _cgroup_snapshot(self):
        try:
            result = self.cgroup.probe()
            return {"available_for_delegated_children": bool(result.get("available")),
                    "reason": result.get("reason"),
                    "controllers": result.get("controllers", [])[:8]}
        except Exception:
            return {"available_for_delegated_children": False,
                    "reason": "cgroup_probe_failed", "controllers": []}

    def _role_statuses(self, state=None):
        state = state or self._state_copy()
        ledger = self._resource_snapshot()
        policy = state["policy"]
        telemetry = self.telemetry.diagnostics(
            policy["required_telemetry"] if policy is not None else (), now=self.clock())
        result = {}
        for role in ROLE_NAMES:
            enabled = state["roles"][role]
            blockers = role_blockers(policy, role, enforcement=unsupported_enforcement(),
                                     telemetry=telemetry,
                                     secure_runtime=getattr(self.backend,
                                                            "secure_runtime_ready", False))
            if role in ledger["reserved_roles"] and ledger["blocked"]:
                blockers.append("shared_resource_ledger_blocked")
            paused = state["paused_roles"][role]
            if state["removed"]:
                blockers.append("device_removed")
            elif paused and enabled:
                blockers.append("owner_paused")
            if not enabled:
                state_name = "disabled"
            elif paused:
                state_name = "paused"
            else:
                state_name = "unavailable" if blockers else "ready"
            result[role] = {"enabled": enabled, "state": state_name,
                            "ready": state_name == "ready", "blockers": sorted(set(blockers))}
        return result

    def status(self):
        state = self._state_copy()
        return {
            "boot_id": self.boot_id,
            "roles": self._role_statuses(state),
            "paused_roles": state["paused_roles"],
            "removed": state["removed"],
            "revocation_status": "pending_offline" if state["revocation_pending"] else "not_requested",
            "resources": self._resource_snapshot(),
            "recent_operations": [{key: item[key] for key in
                                    ("operation_id", "action", "status")}
                                   for item in state["operations"][-16:]],
        }

    def diagnostics(self):
        state = self._state_copy()
        return {
            "daemon": "headless_local_control",
            "platform": {"system": platform.system(), "machine": platform.machine(),
                         "supported_daemon": platform.system() == "Linux"},
            "execution": {"supported_path": platform.system() == "Linux"
                          and platform.machine().lower() in ("x86_64", "amd64"),
                          "runtime": "not_started", "security": "not_implemented_in_C2a"},
            "management": {"transport": "AF_UNIX", "connections_max": 4,
                           "frame_bytes_max": 65_536, "operation_seconds_max": 5,
                           "idle_seconds_max": 30},
            "resource_enforcement": {"memory_cpu": "not_applied_to_role_processes",
                                     "disk": "unavailable",
                                     "bandwidth": "unavailable",
                                     "telemetry": self.telemetry.diagnostics(
                                         state["policy"]["required_telemetry"]
                                         if state["policy"] else (), now=self.clock())},
            "cgroup_v2": self._cgroup_snapshot(),
            "resource_ledger": self._resource_snapshot(),
            "logging": {"payload_logging": False, "secret_logging": False,
                        "retained_records_max": 0},
        }

    def policy(self):
        return {"policy": self._state_copy()["policy"]}

    def _reserve_role(self, role, policy):
        if role == "consumer":
            return
        reservation = policy["reservations"].get(role)
        if reservation is None:
            raise ConnectorError("RESOURCE_POLICY_REQUIRED", "role reservation is required")
        try:
            self.ledger.configure(policy)
            self.ledger.reserve(role, reservation)
        except (ResourceError, StorageError) as error:
            raise ConnectorError("INSUFFICIENT_CAPACITY", str(error)) from error

    def _role_enable(self, payload):
        self._payload(payload, {"role"})
        role = self._role(payload.get("role"))
        with self._lock:
            if self._state["removed"]:
                raise ConnectorError("DEVICE_REMOVED", "removed device cannot enable roles")
            if role in ("host", "coordinator"):
                policy = self._state["policy"]
                if policy is None:
                    raise ConnectorError("RESOURCE_POLICY_REQUIRED", "owner policy must be set first")
                self._reserve_role(role, policy)
            self._state["roles"][role] = True
            self._persist()
            operation = self._record_operation("role.enable", status="succeeded",
                                               result={"role": role, "ready": False})
            return {"operation_id": operation["operation_id"], "role": role,
                    "enabled": True, "ready": False}

    def _role_disable(self, payload):
        self._payload(payload, {"role"})
        role = self._role(payload.get("role"))
        with self._lock:
            self._state["roles"][role] = False
            self._state["paused_roles"][role] = True
            self._cancel_starts((role,))
            operation = self._record_operation("role.disable", result={"role": role})
            self._fence_stop((role,), operation["operation_id"])
            self._notify_backend((role,), draining=False)
        self._enqueue(self._urgent, operation["operation_id"], "stop", (role,))
        return {"operation_id": operation["operation_id"], "role": role,
                "enabled": False, "admission": "disabled_immediately"}

    def _set_policy(self, payload):
        self._payload(payload, {"policy"})
        if "policy" not in payload:
            raise ConnectorError("INVALID_ARGUMENT", "policy is required")
        try:
            policy = validate_policy(payload["policy"])
        except ValueError as error:
            raise ConnectorError("INVALID_POLICY", str(error)) from error
        with self._lock:
            try:
                ledger_state = self.ledger.configure(policy)
            except (ResourceError, StorageError) as error:
                raise ConnectorError("INVALID_POLICY", str(error)) from error
            self._state["policy"] = policy
            affected = []
            # A queued start captured the previous policy. It may never use
            # that snapshot after the owner has replaced it.
            for role in ("host", "coordinator"):
                if role in self._starts:
                    self._starts[role][1].set()
                    self._state["paused_roles"][role] = True
                    affected.append(role)
            if ledger_state["blocked"]:
                for role in ("host", "coordinator"):
                    if self._state["roles"][role]:
                        self._state["paused_roles"][role] = True
                        if role not in affected:
                            affected.append(role)
            self._persist()
            operation = self._record_operation("policy.set", status=("queued" if affected else "succeeded"),
                                               result={"resource_ledger_blocked": ledger_state["blocked"],
                                                       "roles_paused": affected})
            if affected:
                self._fence_stop(affected, operation["operation_id"])
                self._notify_backend(tuple(affected), draining=False)
        if affected:
            self._enqueue(self._urgent, operation["operation_id"], "policy_reduction",
                          tuple(affected))
        return {"operation_id": operation["operation_id"],
                "resource_ledger_blocked": ledger_state["blocked"],
                "roles_paused": affected, "policy": policy}

    def _start(self, payload):
        self._payload(payload, {"roles"})
        with self._lock:
            roles = self._roles(payload)
            if self._closing.is_set():
                raise ConnectorError("SHUTTING_DOWN", "daemon is shutting down")
            if any(role in self._starts or role in self._stop_fences
                   or role in self._drains for role in roles):
                raise ConnectorError("BUSY", "prior lifecycle ownership is unresolved")
            if any(not self._state["roles"][role] for role in roles):
                raise ConnectorError("ROLE_DISABLED", "explicitly enable each role before start")
            statuses = self._role_statuses(self._state)
            # An explicit Start is the owner's permission to resume a paused
            # role; it cannot override any security or enforcement blocker.
            blockers = {role: [item for item in statuses[role]["blockers"]
                               if item != "owner_paused"] for role in roles}
            blockers = {role: items for role, items in blockers.items() if items}
            if blockers:
                operation = self._record_operation("start", status="blocked",
                                                   result={"blockers": blockers})
                return {"operation_id": operation["operation_id"], "state": "unavailable",
                        "blockers": blockers}
            policy = self._state["policy"]
            try:
                for role in roles:
                    self._reserve_role(role, policy)
            except ConnectorError as error:
                operation = self._record_operation("start", status="blocked",
                                                   result={"blockers": {role: [error.code]}})
                return {"operation_id": operation["operation_id"], "state": "unavailable",
                        "blockers": {role: [error.code]}}
            for role in roles:
                self._state["paused_roles"][role] = False
            operation = self._record_operation("start", result={"roles": list(roles)})
            tokens = {role: threading.Event() for role in roles}
            for role, token in tokens.items():
                self._starts[role] = (operation["operation_id"], token)
            if not self._enqueue(self._normal, operation["operation_id"], "start",
                                 (roles, policy, tokens)):
                for role, token in tokens.items():
                    token.set()
                    del self._starts[role]
                    self._state["paused_roles"][role] = True
                self._persist()
                return {"operation_id": operation["operation_id"], "state": "unavailable",
                        "reason": "lifecycle_queue_full"}
        return {"operation_id": operation["operation_id"], "state": "starting",
                "roles": list(roles)}

    def _drain(self, payload):
        self._payload(payload, {"roles", "deadline_seconds"})
        with self._lock:
            roles = self._roles({"roles": payload.get("roles")})
            deadline_seconds = payload.get("deadline_seconds", 30)
            if type(deadline_seconds) is not int or not 1 <= deadline_seconds <= 300:
                raise ConnectorError("INVALID_ARGUMENT", "drain deadline must be 1..300 seconds")
            already = {role: self._drains[role][0] for role in roles if role in self._drains}
            new_roles = tuple(role for role in roles if role not in self._drains)
            if new_roles and self._drains:
                raise ConnectorError("BUSY", "another bounded drain is in progress")
            for role in roles:
                self._state["paused_roles"][role] = True
            self._cancel_starts(roles)
            self._notify_backend(roles, draining=True)
            if not new_roles:
                operation_id = next(iter(already.values()))
                existing = self._find_operation(operation_id)
                return {"operation_id": operation_id, "state": existing["status"],
                        "deadline_extended": False, "already_draining": sorted(already)}
            operation = self._record_operation("drain", result={"roles": list(new_roles),
                                                                 "deadline_seconds": deadline_seconds})
            deadline = self.clock() + deadline_seconds
            cancel_event = threading.Event()
            for role in new_roles:
                self._drains[role] = (operation["operation_id"], deadline, cancel_event)
            self._state["drain"] = {"operation_id": operation["operation_id"],
                                    "roles": list(new_roles),
                                    "deadline_seconds": deadline_seconds}
            self._persist()
        self._enqueue(self._normal, operation["operation_id"], "drain",
                      (new_roles, deadline, cancel_event))
        return {"operation_id": operation["operation_id"], "state": "draining",
                "deadline_seconds": deadline_seconds, "deadline_extended": False,
                "already_draining": sorted(already)}

    def _stop(self, payload):
        self._payload(payload, {"roles"})
        with self._lock:
            roles = self._roles(payload)
            for role in roles:
                self._state["roles"][role] = False
                self._state["paused_roles"][role] = True
                drain = self._drains.get(role)
                if drain is not None:
                    drain[2].set()
            self._cancel_starts(roles)
            operation = self._record_operation("stop", result={"roles": list(roles),
                                                                 "reclaimed": False})
            self._fence_stop(roles, operation["operation_id"])
            self._notify_backend(roles, draining=False)
        self._enqueue(self._urgent, operation["operation_id"], "stop", roles)
        return {"operation_id": operation["operation_id"], "state": "stop_intent_recorded",
                "admission": "disabled_immediately", "reclaimed": False}

    def _remove(self, payload):
        self._payload(payload, {"delete_owned_data"})
        delete_owned_data = payload.get("delete_owned_data", False)
        if type(delete_owned_data) is not bool:
            raise ConnectorError("INVALID_ARGUMENT", "delete_owned_data must be boolean")
        with self._lock:
            for role in ROLE_NAMES:
                self._state["roles"][role] = False
                self._state["paused_roles"][role] = True
                drain = self._drains.get(role)
                if drain is not None:
                    drain[2].set()
            self._state["removed"] = True
            self._state["revocation_pending"] = True
            self._cancel_starts(ROLE_NAMES)
            operation = self._record_operation("remove", result={
                "delete_owned_data": delete_owned_data,
                "revocation_status": "pending_offline", "reclaimed": False})
            self._fence_stop(ROLE_NAMES, operation["operation_id"])
            self._notify_backend(ROLE_NAMES, draining=False)
        self._enqueue(self._urgent, operation["operation_id"], "remove",
                      (ROLE_NAMES, delete_owned_data))
        return {"operation_id": operation["operation_id"], "state": "removal_pending",
                "revocation_status": "pending_offline", "reclaimed": False}

    def _operation_status(self, payload):
        self._payload(payload, {"operation_id"})
        with self._lock:
            operation = self._find_operation(payload.get("operation_id"))
            if operation is None:
                raise ConnectorError("NOT_FOUND", "operation is not in this daemon's bounded history")
            return copy.deepcopy(operation)

    def handle(self, action, payload):
        if action == "status":
            self._payload(payload, set())
            return self.status()
        if action == "diagnostics":
            self._payload(payload, set())
            return self.diagnostics()
        if action == "policy.get":
            self._payload(payload, set())
            return self.policy()
        if action == "policy.set":
            return self._set_policy(payload)
        if action == "role.enable":
            return self._role_enable(payload)
        if action == "role.disable":
            return self._role_disable(payload)
        if action == "start":
            return self._start(payload)
        if action == "drain":
            return self._drain(payload)
        if action == "stop":
            return self._stop(payload)
        if action == "remove":
            return self._remove(payload)
        if action == "operation.status":
            return self._operation_status(payload)
        raise ConnectorError("UNKNOWN_ACTION", "management action is not allowed")

    def _worker_loop(self, work_queue):
        while not self._closing.is_set():
            try:
                item = work_queue.get(timeout=0.1)
            except queue.Empty:
                continue
            if item is None:
                return
            operation_id, kind, payload = item
            self._operation_update(operation_id, "running", {})
            try:
                if kind == "start":
                    result = self._perform_start(operation_id, payload)
                elif kind == "drain":
                    result = self._perform_drain(operation_id, payload)
                elif kind == "stop":
                    result = self._perform_stop(operation_id, payload, disable=True)
                elif kind == "policy_reduction":
                    result = self._perform_stop(operation_id, payload, disable=False)
                elif kind == "remove":
                    result = self._perform_remove(operation_id, payload)
                else:
                    result = {"reason": "unknown_internal_operation", "reclaimed": False}
                successful = result.get("success", result.get(
                    "drained", result.get("reclaimed", True)))
                status = "succeeded" if successful is True else "incomplete"
                self._operation_update(operation_id, status, result)
            except Exception:
                self._operation_update(operation_id, "incomplete",
                                       {"reason": "lifecycle_operation_failed", "reclaimed": False})
            finally:
                with self._lock:
                    self._stop_tokens.pop(operation_id, None)
                work_queue.task_done()

    def _cancel_starts(self, roles):
        # Caller holds _lock. No I/O, joins, or backend lock acquisition here.
        for role in roles:
            pending = self._starts.get(role)
            if pending is not None:
                pending[1].set()

    def _notify_backend(self, roles, *, draining):
        # The backend contract requires these intent hooks to be nonblocking.
        # A missing/failing hook never constitutes proof of reclamation.
        hook = getattr(self.backend, "request_drain" if draining else "request_stop", None)
        if hook is not None:
            try:
                hook(roles)
            except Exception:
                for role in roles:
                    self._stop_fences.setdefault(role, object())

    def _fence_stop(self, roles, operation_id):
        tokens = {role: object() for role in roles}
        self._stop_fences.update(tokens)
        self._stop_tokens[operation_id] = tokens

    def _perform_start(self, operation_id, payload):
        roles, policy, tokens = payload
        started = []
        try:
            for role in roles:
                token = tokens[role]
                with self._lock:
                    allowed = (self._starts.get(role) == (operation_id, token)
                               and not token.is_set() and not self._closing.is_set()
                               and self._state["roles"][role]
                               and not self._state["paused_roles"][role]
                               and not self._state["removed"])
                if not allowed:
                    return {"roles_started": started, "blocked_role": role,
                            "success": False, "reason": "start_cancelled"}
                # Stop may run between the check above and this call. The
                # backend must observe the same already-owned cancellation token.
                ready = self.backend.start(role, policy, cancel_event=token)
                with self._lock:
                    if not ready or token.is_set():
                        self._state["paused_roles"][role] = True
                        self._persist()
                        return {"roles_started": started, "blocked_role": role,
                                "success": False, "reason": "role_backend_not_ready"}
                started.append(role)
            return {"roles_started": started, "success": True}
        except Exception:
            with self._lock:
                for role, token in tokens.items():
                    if self._starts.get(role) == (operation_id, token):
                        self._state["paused_roles"][role] = True
                self._persist()
            raise
        finally:
            with self._lock:
                for role, token in tokens.items():
                    if self._starts.get(role) == (operation_id, token):
                        del self._starts[role]

    def _perform_drain(self, operation_id, payload):
        roles, deadline, cancel_event = payload
        try:
            outcome = self.backend.drain(roles, deadline, cancel_event)
            drained = bool(outcome.get("drained")) if isinstance(outcome, dict) else False
            reclaimed = bool(outcome.get("reclaimed")) if isinstance(outcome, dict) else False
            if not drained and not cancel_event.is_set():
                cancel_event.wait(max(0.0, deadline - self.clock()))
            if not drained and not cancel_event.is_set() and self.clock() >= deadline:
                stopped = self._backend_stop(roles)
                reclaimed = all(stopped.get(role, False) for role in roles)
                return {"drained": False, "success": reclaimed, "deadline_stop": True,
                        "reclaimed": reclaimed, "roles": list(roles)}
            return {"drained": drained, "success": drained and reclaimed,
                    "deadline_stop": False, "reclaimed": reclaimed,
                    "roles": list(roles)}
        finally:
            with self._lock:
                for role in roles:
                    drain = self._drains.get(role)
                    if drain is not None and drain[0] == operation_id:
                        del self._drains[role]
                if (self._state["drain"] is not None
                        and self._state["drain"]["operation_id"] == operation_id):
                    self._state["drain"] = None
                    self._persist()

    def _backend_stop(self, roles):
        result = self.backend.stop(roles, grace_seconds=15)
        if type(result) is bool:
            return {role: result for role in roles}
        if type(result) is not dict:
            return {role: False for role in roles}
        return {role: result.get(role) is True for role in roles}

    def _perform_stop(self, operation_id, roles, *, disable):
        reclaimed_map = self._backend_stop(roles)
        for role in roles:
            if reclaimed_map[role]:
                try:
                    self.ledger.release(role, reclaimed=True)
                except (ResourceError, StorageError):
                    reclaimed_map[role] = False
        with self._lock:
            tokens = self._stop_tokens.pop(operation_id, {})
            for role, reclaimed in reclaimed_map.items():
                if reclaimed and self._stop_fences.get(role) is tokens.get(role):
                    self._stop_fences.pop(role, None)
        return {"roles": list(roles), "reclaimed_by_role": reclaimed_map,
                "reclaimed": all(reclaimed_map.values()),
                "success": all(reclaimed_map.values()),
                "admission_disabled": True, "disable_persisted": disable}

    def _perform_remove(self, operation_id, payload):
        roles, delete_owned_data = payload
        result = self._perform_stop(operation_id, roles, disable=True)
        result["revocation_status"] = "pending_offline"
        result["owned_data_deleted"] = False
        if delete_owned_data and result["reclaimed"]:
            result["owned_data_deleted"] = self._delete_owned_data()
        result["success"] = result["reclaimed"] and (
            not delete_owned_data or result["owned_data_deleted"])
        return result

    def _delete_owned_data(self):
        if not sys.platform.startswith("linux") or self.state_directory is None:
            return False
        maximum_files = 4096
        maximum_bytes = 256 * 1024 * 1024
        maximum_depth = 8
        uid = os.getuid()
        root_fd = None
        try:
            from .storage import open_private_directory

            root_fd = open_private_directory(self.state_directory, uid=uid)
            try:
                root_info = os.fstat(root_fd)
                owned_info = os.stat("owned-data", dir_fd=root_fd,
                                     follow_symlinks=False)
            except FileNotFoundError:
                return True
            if (not stat.S_ISDIR(owned_info.st_mode) or owned_info.st_uid != uid
                    or stat.S_IMODE(owned_info.st_mode) != 0o700
                    or owned_info.st_dev != root_info.st_dev):
                return False

            directory_paths = [("owned-data",)]
            file_records = []
            total_entries = 0
            total_bytes = 0
            cursor = 0
            while cursor < len(directory_paths):
                relative = directory_paths[cursor]
                cursor += 1
                directory_fd = self._open_owned_directory(root_fd, relative, uid)
                try:
                    with os.scandir(directory_fd) as entries:
                        for entry in entries:
                            total_entries += 1
                            if total_entries > maximum_files:
                                return False
                            info = entry.stat(follow_symlinks=False)
                            child = relative + (entry.name,)
                            if stat.S_ISDIR(info.st_mode):
                                if (len(child) > maximum_depth + 1 or info.st_uid != uid
                                        or stat.S_IMODE(info.st_mode) != 0o700
                                        or info.st_dev != root_info.st_dev):
                                    return False
                                directory_paths.append(child)
                            elif stat.S_ISREG(info.st_mode):
                                if (info.st_uid != uid or info.st_dev != root_info.st_dev
                                        or info.st_nlink != 1 or info.st_mode & 0o077
                                        or info.st_mode & 0o111):
                                    return False
                                total_bytes += info.st_size
                                if total_bytes > maximum_bytes:
                                    return False
                                file_records.append((child, info.st_dev, info.st_ino,
                                                    info.st_size))
                            else:
                                return False
                finally:
                    os.close(directory_fd)

            for relative, device, inode, size in file_records:
                parent_fd = self._open_owned_directory(root_fd, relative[:-1], uid)
                try:
                    info = os.stat(relative[-1], dir_fd=parent_fd, follow_symlinks=False)
                    if (not stat.S_ISREG(info.st_mode) or info.st_uid != uid
                            or info.st_nlink != 1 or info.st_mode & 0o077
                            or info.st_mode & 0o111
                            or (info.st_dev, info.st_ino, info.st_size) !=
                            (device, inode, size)):
                        return False
                    os.unlink(relative[-1], dir_fd=parent_fd)
                finally:
                    os.close(parent_fd)

            for relative in reversed(directory_paths):
                parent_fd = self._open_owned_directory(root_fd, relative[:-1], uid) \
                    if len(relative) > 1 else os.dup(root_fd)
                try:
                    info = os.stat(relative[-1], dir_fd=parent_fd, follow_symlinks=False)
                    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != uid
                            or stat.S_IMODE(info.st_mode) != 0o700
                            or info.st_dev != root_info.st_dev):
                        return False
                    os.rmdir(relative[-1], dir_fd=parent_fd)
                finally:
                    os.close(parent_fd)
            os.fsync(root_fd)
            return True
        except (OSError, ValueError, StorageError):
            return False
        finally:
            if root_fd is not None:
                os.close(root_fd)

    @staticmethod
    def _open_owned_directory(root_fd, relative, uid):
        descriptor = os.dup(root_fd)
        try:
            for component in relative:
                next_descriptor = os.open(
                    component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                    dir_fd=descriptor)
                info = os.fstat(next_descriptor)
                if (not stat.S_ISDIR(info.st_mode) or info.st_uid != uid
                        or stat.S_IMODE(info.st_mode) != 0o700):
                    os.close(next_descriptor)
                    raise OSError("unsafe owned-data directory")
                os.close(descriptor)
                descriptor = next_descriptor
            return descriptor
        except Exception:
            os.close(descriptor)
            raise

    def check_telemetry(self):
        state = self._state_copy()
        policy = state["policy"]
        if policy is None or not policy["required_telemetry"]:
            return False
        samples = self.telemetry.status(policy["required_telemetry"], now=self.clock())
        if all(item.get("fresh") for item in samples.values()):
            return False
        affected = []
        with self._lock:
            for role in ("host", "coordinator"):
                if self._state["roles"][role] and not self._state["paused_roles"][role]:
                    self._state["paused_roles"][role] = True
                    affected.append(role)
            if not affected:
                return False
            operation = self._record_operation("stop", result={
                "roles": affected, "reason": "required_telemetry_unavailable",
                "reclaimed": False})
            self._cancel_starts(affected)
            self._fence_stop(affected, operation["operation_id"])
            self._notify_backend(tuple(affected), draining=False)
        self._enqueue(self._urgent, operation["operation_id"], "policy_reduction",
                      tuple(affected))
        return True

    def shutdown(self, *, wait_seconds=1.0):
        with self._lock:
            self._closing.set()
            self._cancel_starts(ROLE_NAMES)
            self._notify_backend(ROLE_NAMES, draining=False)
            for role, enabled in self._state["roles"].items():
                if enabled:
                    self._state["paused_roles"][role] = True
            self._persist()
        self._closing.set()
        for work_queue in (self._urgent, self._normal):
            try:
                work_queue.put_nowait(None)
            except queue.Full:
                pass
        deadline = self.clock() + wait_seconds
        for thread in self._threads:
            thread.join(max(0.0, deadline - self.clock()))
