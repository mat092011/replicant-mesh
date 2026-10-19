"""Owned CPU coordinator-head assembly under the selected C2 binding.

The runtime owns no process, listener, worker connection, credit, or READY
state. The inherited artifact pin set remains caller-owned and must be retained
through process reaping. This owner holds the selected-root binding lease until
model cleanup is confirmed.
"""
from __future__ import annotations

import asyncio
import hashlib
import os
import threading
from types import MappingProxyType

from steamboat_connector.artifacts import ArtifactInstaller
from steamboat_connector.c2_child_config import C2ChildBinding
from steamboat_connector.c2_coordinator_settings import load_c2_coordinator_settings
from steamboat_connector.catalog import CatalogVerifier
from steamboat_connector.policy import validate_policy
from steamboat_connector.runtime_pin_handoff import ChildArtifactPinSet
from steamboat_security.errors import CredentialError, StorageError


class C2CoordinatorRuntimeError(StorageError):
    """Coordinator model assembly or confirmed shutdown failed closed."""


def _exit_owned_binding_lease(lease):
    """Run the exact trusted context-manager exit away from the event loop."""
    lease.__exit__(None, None, None)
    return True


def _validate_coordinator(binding, child_pins, installer, owner_policy):
    from steamboat_connector.artifact_pin import InheritedArtifactPin, RuntimeAssignmentGuard
    from steamboat_connector.resources import _fit

    if (type(child_pins) is not ChildArtifactPinSet or child_pins._state != "open"
            or len(child_pins.owners) != 1 or len(child_pins.guards) != 1
            or type(child_pins.owners[0]) is not InheritedArtifactPin
            or type(child_pins.guards[0]) is not RuntimeAssignmentGuard
            or type(installer) is not ArtifactInstaller or installer.read_only is not True
            or type(installer.verifier) is not CatalogVerifier
            or installer.verifier.clock is not binding._clock
            or installer.uid != binding._root_store._uid):
        raise CredentialError("coordinator requires one exact inherited pin and read-only installer")
    owner, guard = child_pins.owners[0], child_pins.guards[0]
    if (owner.role != "coordinator" or owner.root != installer.root
            or owner.uid != installer.uid or guard.pin is not owner
            or guard.child_clock is not binding._clock
            or guard.child_verifier is not installer.verifier
            or guard.role != "coordinator" or guard.component != "coordinator"
            or guard.account_id != binding._spec.account_id
            or guard.device_id != binding._spec.device_id
            or guard.pin.record.get("boot_id") != binding._spec.boot_id
            or guard.manifest_fingerprint != binding._model_id):
        raise CredentialError("inherited coordinator pin differs from selected binding")
    owner.assert_open_descriptors()
    guard.check()

    settings = load_c2_coordinator_settings(binding)
    if settings.assignment.assignment_id != guard.assignment_id:
        raise CredentialError("selected coordinator assignment differs from inherited pin")
    # The signed selected settings choose the artifact store too.  Never let a
    # caller-supplied installer silently redirect that selection.
    if os.path.normcase(os.path.abspath(settings.artifact_root)) != os.path.normcase(
            os.path.abspath(os.fspath(installer.root))):
        raise CredentialError("selected coordinator artifact root differs from installer root")
    verifier = installer.verifier
    view = installer.open_view(settings.assignment.assignment_id,
        account_id=binding._spec.account_id, device_id=binding._spec.device_id,
        role="coordinator")
    if view.catalog is None or view.assignment is None:
        raise CredentialError("active coordinator view has no verified signed documents")
    # Single-component inherited pins retain only the exact anti-rollback
    # record.  The read-only installer view is the genuine signed-byte owner.
    signed_catalog = bytes(view.catalog.document_bytes)
    signed_assignment = bytes(view.assignment.document_bytes)
    if (hashlib.sha256(signed_catalog).hexdigest() != guard.catalog_sha256
            or hashlib.sha256(signed_assignment).hexdigest() != guard.assignment_sha256):
        raise CredentialError("installer signed documents differ from inherited pin")
    catalog = verifier.verify_catalog(signed_catalog)
    assignment = verifier.verify_assignment(
        signed_assignment, catalog, account_id=binding._spec.account_id,
        device_id=binding._spec.device_id, role="coordinator")
    if (settings.catalog_public_key_hex != verifier.public_key.hex()
            or settings.assignment.catalog_public_key_sha256
            != hashlib.sha256(verifier.public_key).hexdigest()
            or settings.assignment.catalog_sha256 != hashlib.sha256(signed_catalog).hexdigest()
            or settings.assignment.assignment_id != guard.assignment_id
            or settings.assignment.assignment_id != assignment.payload.get("assignment_id")
            or settings.assignment.assignment_sha256 != hashlib.sha256(signed_assignment).hexdigest()
            or settings.assignment.assignment_sha256 != guard.assignment_sha256
            or guard.catalog_sha256 != settings.assignment.catalog_sha256
            or assignment.document_sha256 != settings.assignment.assignment_sha256
            or assignment.payload.get("component") != "coordinator"
            or assignment.payload.get("manifest_fingerprint") != binding._model_id
            or catalog.payload.get("manifest", {}).get("fingerprint") != binding._model_id):
        raise CredentialError("signed coordinator catalog or assignment differs from selected anchors")

    try:
        policy = validate_policy(owner_policy)
    except (TypeError, ValueError) as error:
        raise CredentialError("coordinator owner resource policy is invalid") from error
    reservation = policy["reservations"].get("coordinator")
    if type(reservation) is not dict:
        raise CredentialError("owner policy has no coordinator reservation")
    fits, reason = _fit({"coordinator": reservation}, policy["limits"])
    if not fits:
        raise CredentialError(f"coordinator reservation exceeds global owner policy: {reason}")

    manifest = view._locked_manifest()
    if (view.installer is not installer or view.role != "coordinator"
            or view.assignment is None
            or view.catalog is None
            or view.catalog.document_sha256 != settings.assignment.catalog_sha256
            or view.assignment.payload.get("component") != "coordinator"
            or view.assignment.payload.get("assignment_id") != settings.assignment.assignment_id
            or view.assignment.payload.get("catalog_sha256") != settings.assignment.catalog_sha256
            or view.assignment.document_sha256 != guard.assignment_sha256
            or view.assignment.payload.get("manifest_fingerprint") != binding._model_id
            or manifest.get("fingerprint") != binding._model_id
            or manifest.get("model_id") != catalog.payload.get("model", {}).get("model_id")):
        raise CredentialError("active assigned coordinator view differs from selected C2 binding")
    try:
        with installer._locked():
            active = installer._load_state()
        record = active["installations"].get(settings.assignment.assignment_id)
        if (type(record) is not dict or record.get("role") != "coordinator"
                or active["active"].get("coordinator") != settings.assignment.assignment_id
                or record.get("assignment_sha256") != settings.assignment.assignment_sha256
                or record.get("catalog_sha256") != settings.assignment.catalog_sha256
                or record.get("manifest_fingerprint") != binding._model_id):
            raise CredentialError("coordinator installation is not the exact active signed assignment")
    except (KeyError, TypeError) as error:
        raise CredentialError("coordinator installation state is malformed") from error

    limits = manifest["limits"]
    component_file = catalog.payload["files"].get("coordinator.safetensors")
    if (type(component_file) is not dict
            or type(component_file.get("size_bytes")) is not int
            or component_file["size_bytes"] <= 0
            or reservation["weights_bytes"] < component_file["size_bytes"]):
        raise CredentialError("coordinator weight reservation is below the signed head artifact size")
    capacity = min(reservation["sessions"], policy["limits"]["max_sessions"],
                   limits["max_sessions"])
    request_timeout = min(reservation["max_request_seconds"],
                          policy["limits"]["max_request_seconds"],
                          limits["request_timeout_seconds"])
    if (type(capacity) is not int or capacity < 1
            or type(request_timeout) is not int or request_timeout < 1):
        raise CredentialError("coordinator capacity does not fit selected limits")
    return settings, view, guard, MappingProxyType({
        "max_sessions": capacity,
        "request_timeout_seconds": request_timeout,
    })


class C2CoordinatorRuntime:
    """Retained assigned coordinator model and selected-root lease."""

    def __init__(self, lease, binding, child_pins, installer, owner_policy, limits):
        self._lease = lease
        self._binding = binding
        self._child_pins = child_pins
        self._installer = installer
        self._owner_policy = owner_policy
        self._limits = limits
        self._model = None
        self._loop = asyncio.get_running_loop()
        self._invalidated = threading.Event()
        self._state = "assembling"
        self._close_error = None
        self._retryable_drain = False
        self._close_lock = asyncio.Lock()
        self._cleanup_tasks = []
        self._model_close_task = None
        self._lease_exit_task = None
        binding.subscribe_teardown(self._binding_invalidated)

    @property
    def limits(self):
        self.assert_live()
        return self._limits

    @property
    def model_diagnostics(self):
        self.assert_live()
        if self._model is None:
            raise C2CoordinatorRuntimeError("coordinator model is not available")
        return MappingProxyType(dict(self._model.diagnostics()))

    def assert_live(self):
        if self._state not in {"assembling", "open"} or self._invalidated.is_set():
            raise C2CoordinatorRuntimeError("C2 coordinator runtime is fenced")
        self._binding.assert_live()
        for guard in self._child_pins.guards:
            guard.check()
        return True

    def _binding_invalidated(self, reason):
        self._invalidated.set()
        try:
            self._loop.call_soon_threadsafe(self._schedule_invalidation_cleanup,
                                            str(reason)[:128])
        except RuntimeError:
            self._invalidated.set()

    def _schedule_invalidation_cleanup(self, reason):
        if self._state not in {"closed", "faulted"}:
            self._invalidated.set()
            task = asyncio.create_task(self.close())
            self._cleanup_tasks.append(task)
            task.add_done_callback(self._observe_cleanup)

    def _observe_cleanup(self, task):
        if task in self._cleanup_tasks:
            self._cleanup_tasks.remove(task)
        if task.cancelled():
            self._close_error = C2CoordinatorRuntimeError("invalidation cleanup was cancelled")
            self._state = "faulted"
        else:
            error = task.exception()
            if error is not None:
                self._close_error = error
                if not self._retryable_drain:
                    self._state = "faulted"

    async def _run_model_call(self, operation_factory):
        self.assert_live()
        try:
            operation = operation_factory()
            result = await asyncio.wait_for(
                operation, timeout=self._limits["request_timeout_seconds"])
        except BaseException:
            self.assert_live()
            raise
        self.assert_live()
        return result

    async def tokenize(self, text):
        return await self._run_model_call(lambda: self._model.tokenize(text))

    async def embed(self, ids):
        return await self._run_model_call(lambda: self._model.embed(ids))

    async def finish(self, hidden, *, all_logits=False):
        return await self._run_model_call(
            lambda: self._model.finish(hidden, all_logits=all_logits))

    async def health_check(self):
        """Run one deterministic assigned-head embed/finish shape check."""
        self.assert_live()
        import torch
        token = torch.tensor([[1]], dtype=torch.int64, device="cpu")
        hidden = await self._run_model_call(lambda: self._model.embed(token))
        logits = await self._run_model_call(lambda: self._model.finish(hidden))
        if (logits.device.type != "cpu" or logits.dtype != torch.float32
                or tuple(logits.shape) != (1, 1, self._model.config["vocab_size"])
                or not bool(torch.isfinite(logits).all())):
            raise C2CoordinatorRuntimeError("assigned coordinator head health check failed")
        self.assert_live()
        return True

    async def close(self, grace_seconds=5.0):
        if type(grace_seconds) not in (int, float) or not 0 < grace_seconds <= 5.0:
            raise ValueError("coordinator runtime shutdown grace must be in (0, 5]")
        deadline = self._loop.time() + float(grace_seconds)
        try:
            await asyncio.wait_for(self._close_lock.acquire(), timeout=float(grace_seconds))
        except asyncio.TimeoutError as error:
            self._invalidated.set()
            self._close_error = error
            raise C2CoordinatorRuntimeError(
                "coordinator cleanup lock remained busy; retain owners") from error
        try:
            if self._state == "closed":
                return True
            if self._state == "faulted":
                raise C2CoordinatorRuntimeError(
                    "coordinator runtime cleanup is uncertain") from self._close_error
            self._state = "closing"
            self._invalidated.set()
            self._retryable_drain = False
            try:
                if self._model is None:
                    raise C2CoordinatorRuntimeError(
                        "partial coordinator model construction requires process reap")
                remaining = deadline - self._loop.time()
                if remaining <= 0:
                    raise C2CoordinatorRuntimeError("coordinator cleanup deadline elapsed")
                model_grace = min(remaining,
                    self._model.limits["compute_cancel_grace_seconds"])
                task = self._model_close_task
                if task is None or task.done():
                    if task is not None:
                        if task in self._cleanup_tasks:
                            self._cleanup_tasks.remove(task)
                        if task.cancelled() or task.exception() is not None:
                            raise C2CoordinatorRuntimeError(
                                "assigned coordinator model cleanup task failed") from (
                                    None if task.cancelled() else task.exception())
                        if task.result() is True:
                            pass
                        else:
                            task = None
                    if task is None:
                        task = asyncio.create_task(
                            self._model.close(timeout_seconds=model_grace))
                        self._model_close_task = task
                        self._cleanup_tasks.append(task)
                done, pending = await asyncio.wait((task,), timeout=remaining)
                if pending:
                    # Keep this task and every owner for a later bounded retry.
                    self._retryable_drain = True
                    self._close_error = C2CoordinatorRuntimeError(
                        "assigned coordinator CPU work did not drain before this attempt ended")
                    raise C2CoordinatorRuntimeError(
                        "assigned coordinator CPU work did not drain")
                if task.cancelled():
                    raise C2CoordinatorRuntimeError(
                        "assigned coordinator model cleanup was cancelled")
                task_error = task.exception()
                if task_error is not None:
                    raise C2CoordinatorRuntimeError(
                        "assigned coordinator model cleanup failed") from task_error
                if task.result() is not True:
                    self._retryable_drain = True
                    raise C2CoordinatorRuntimeError(
                        "assigned coordinator CPU work did not drain")
                # Context-manager exit takes the selected-root store lock
                # synchronously. Run the one exact trusted lease exit off-loop
                # and retain its task so timeout/caller cancellation cannot
                # cancel or repeat the ownership transition.
                lease_task = self._lease_exit_task
                if lease_task is None:
                    lease_task = asyncio.create_task(asyncio.to_thread(
                        _exit_owned_binding_lease, self._lease))
                    self._lease_exit_task = lease_task
                remaining = deadline - self._loop.time()
                if remaining <= 0:
                    self._retryable_drain = True
                    raise C2CoordinatorRuntimeError(
                        "coordinator lease retirement exceeded the close budget")
                _done, lease_pending = await asyncio.wait((lease_task,), timeout=remaining)
                if lease_pending:
                    self._retryable_drain = True
                    raise C2CoordinatorRuntimeError(
                        "coordinator lease retirement remains in progress")
                if lease_task.cancelled():
                    raise C2CoordinatorRuntimeError(
                        "coordinator lease retirement task was cancelled")
                lease_error = lease_task.exception()
                if lease_error is not None:
                    raise C2CoordinatorRuntimeError(
                        "coordinator lease retirement failed") from lease_error
                if lease_task.result() is not True:
                    raise C2CoordinatorRuntimeError(
                        "coordinator lease retirement did not confirm")
                if task in self._cleanup_tasks:
                    self._cleanup_tasks.remove(task)
                self._model_close_task = None
                self._lease_exit_task = None
                self._model = None
                self._lease = None
                self._binding = None
                self._child_pins = None
                self._installer = None
                self._owner_policy = None
                self._state = "closed"
                self._retryable_drain = False
                return True
            except BaseException as error:
                self._close_error = error
                if self._model_close_task is not None and not self._model_close_task.done():
                    self._state = "closing"
                elif self._retryable_drain:
                    self._state = "closing"
                else:
                    self._state = "faulted"
                raise C2CoordinatorRuntimeError(
                    "coordinator cleanup is uncertain; retain owners through process reap") from error
        finally:
            self._close_lock.release()


async def build_c2_coordinator_runtime(child_binding_owner, child_pin_set, installer, *,
                                       owner_policy):
    """Load one exact selected coordinator head without process or READY authority."""
    if type(child_binding_owner) is not C2ChildBinding:
        raise TypeError("coordinator runtime requires the exact C2 child binding owner")
    if type(child_pin_set) is not ChildArtifactPinSet:
        raise TypeError("coordinator runtime requires the exact inherited child pin set")
    if type(installer) is not ArtifactInstaller or installer.read_only is not True:
        raise TypeError("coordinator runtime requires an exact read-only artifact installer")
    lease = child_binding_owner.borrow()
    binding = lease.__enter__()
    runtime = None
    try:
        from steamboat_security.root_c2_coordinator import C2CoordinatorRuntimeBinding
        if type(binding) is not C2CoordinatorRuntimeBinding:
            raise CredentialError("child binding does not own the exact coordinator binding")
        binding.assert_live()
        settings, view, guard, limits = _validate_coordinator(
            binding, child_pin_set, installer, owner_policy)
        runtime = C2CoordinatorRuntime(lease, binding, child_pin_set, installer,
                                       owner_policy, limits)
        runtime.assert_live()
        guard.check()
        # AssignedArtifactView re-verifies the active stored record and files;
        # the narrowed session cap is applied by the actual CoordinatorModel.
        runtime._model = view.load_coordinator_model(max_sessions=limits["max_sessions"])
        runtime.assert_live()
        if (runtime._model._capacity != limits["max_sessions"]
                or runtime._model.limits["max_sessions"] < limits["max_sessions"]):
            raise CredentialError("loaded coordinator model did not retain its narrowed capacity")
        await runtime.health_check()
        runtime.assert_live()
        runtime._state = "open"
        return runtime
    except BaseException as error:
        if runtime is None:
            lease.__exit__(type(error), error, error.__traceback__)
        else:
            runtime._state = "partial"
            try:
                error.c2_coordinator_runtime_owner = runtime
            except BaseException:
                pass
        raise
