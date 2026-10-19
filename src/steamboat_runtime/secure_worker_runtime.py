"""Bind the C0 worker authorizer to the existing loop-owned WorkerHandler."""

import asyncio
from dataclasses import dataclass
import math
import threading
import time
import weakref


WORKER_SERVICE = "steamboat.v1.Worker"
MAX_SWEEP_INTERVAL_SECONDS = 5.0
MAX_INFLIGHT_OPERATIONS = 32
_OWNER_RECLAIM_POLL_SECONDS = 0.01
_CAPTURE_UNSET = object()


class RuntimeBindingError(RuntimeError):
    pass


class RuntimeOpenAdmissionRejected(RuntimeBindingError):
    """A new session is not admitted while the worker is draining."""


class RuntimeBridgeUnavailable(RuntimeBindingError):
    pass


@dataclass(eq=False)
class _SessionOwner:
    target_device_id: str
    worker_boot_id: str
    assignment_id: str
    session_id: str
    core_owner: tuple
    core_identity: tuple
    ingress_identity: tuple | None = None
    invalidated: bool = False
    invalidation_reason: str = ""
    predispatch_aborted: bool = False
    terminal_reclaimed: bool = False
    invalidation_event: object = None

    @property
    def key(self):
        return (self.target_device_id, self.worker_boot_id,
                self.assignment_id, self.session_id)


@dataclass(eq=False)
class _Operation:
    request: object
    method: str
    core_authorization: object
    owner: _SessionOwner | None
    identity: tuple
    authorization: object = None
    dispatch_started: bool = False
    dispatch_done: bool = False
    authorization_closed: bool = False
    close_failed: bool = False
    terminal_rpc_completed: bool = False


@dataclass(frozen=True)
class _CapturedNotice:
    notice: object
    core_owner: tuple | None
    core_identity: tuple | None


class _BoundAuthorization:
    def __init__(self, bridge, operation):
        self._bridge = bridge
        self._operation = operation
        self._core = operation.core_authorization
        operation.authorization = self

    @property
    def binding_bytes(self):
        return self._core.binding_bytes

    @property
    def deadline_monotonic(self):
        deadline = self._core.deadline_monotonic
        drain_deadline = self._bridge._session_drain_deadline(self._operation)
        return deadline if drain_deadline is None else min(deadline, drain_deadline)

    @property
    def completed(self):
        return bool(getattr(self._core, "_finished", False)
                    or getattr(self._core, "_failed", False))

    def assert_live(self):
        self._bridge._assert_operation_live(
            self._operation,
            allow_terminal_rpc=(self._operation.terminal_rpc_completed
                                and not self._operation.authorization_closed))
        try:
            return self._core.assert_live()
        except BaseException as error:
            self._bridge._authorization_liveness_failed(self._operation, error)
            raise

    def remaining_seconds(self):
        remaining = self._core.remaining_seconds()
        drain_deadline = self._bridge._session_drain_deadline(self._operation)
        if drain_deadline is None:
            return remaining
        sample = self._bridge.authorizer_core.clock.sample()
        drain_remaining = drain_deadline - sample.monotonic
        if drain_remaining <= 0:
            self._bridge._expire_drain(sample)
            raise RuntimeBridgeUnavailable("worker drain deadline expired")
        return min(remaining, drain_remaining)

    def complete(self, response):
        self.assert_live()
        result = self._core.complete(response)
        owner = self._operation.owner
        if owner is not None:
            if self._operation.method == "OpenSession" and response.code == "OK":
                pass
            elif (self._operation.method in ("CloseSession", "CancelSession")
                  and response.code == "OK" and response.reclaimed is True):
                owner.terminal_reclaimed = True
                self._operation.terminal_rpc_completed = True
            elif (response.code != "OK" and self._operation.method in (
                    "OpenSession", "RenewSession", "Step", "CloseSession",
                    "CancelSession")):
                self._bridge._invalidate_owner(owner, "mutating-operation-failed")
        self._bridge._reconcile()
        return result

    def fail(self, *, cache_may_exist=True):
        try:
            result = self._core.fail(cache_may_exist=cache_may_exist)
        except BaseException:
            self._bridge._fence("core authorization failure could not be recorded")
            raise
        owner = self._operation.owner
        if owner is not None:
            if (self._operation.method == "OpenSession"
                    and not self._operation.dispatch_started
                    and cache_may_exist is False):
                claim = self._core._session_claim
                if claim is not None and claim.is_new:
                    owner.predispatch_aborted = True
            elif (self._operation.method == "OpenSession"
                  and not self._operation.dispatch_started
                  and self._core._session_claim is not None
                  and not self._core._session_claim.is_new):
                pass
            else:
                self._bridge._invalidate_owner(owner, "authorization-failed")
        self._bridge._reconcile()
        return result

    def close(self):
        try:
            result = self._core.close()
        except BaseException:
            self._operation.close_failed = True
            self._bridge._fence("core authorization close was unconfirmed")
            raise
        owner = self._operation.owner
        if owner is not None and getattr(self._core, "_failed", False):
            if (self._operation.method == "OpenSession"
                    and not self._operation.dispatch_started
                    and ((self._core._session_claim is not None
                          and not self._core._session_claim.is_new)
                         or owner.predispatch_aborted)):
                pass
            else:
                self._bridge._invalidate_owner(owner, "authorization-closed-ambiguous")
        self._operation.authorization_closed = True
        self._bridge._authorization_closed(self._operation)
        return result


class _IncomingAuthorizer:
    def __init__(self, bridge):
        self._bridge = bridge

    def authorize(self, *, service, method, payload, metadata, peer_certificate_pem):
        return self._bridge._authorize(
            service=service, method=method, payload=payload, metadata=metadata,
            peer_certificate_pem=peer_certificate_pem)

    def authorize_gateway(self, *, service, method, payload, metadata, ingress,
                          envelope, request_bytes, frame_sequence, wire_lane):
        """Admit a gateway request through the core Authorizer's owned ingress."""
        return self._bridge._authorize(
            service=service, method=method, payload=payload, metadata=metadata,
            ingress=ingress, envelope=envelope, request_bytes=request_bytes,
            frame_sequence=frame_sequence, wire_lane=wire_lane)


class _BoundWorkerHandler:
    def __init__(self, bridge):
        self._bridge = bridge

    async def handle(self, method, request):
        self._bridge._assert_loop()
        operation = self._bridge._begin_dispatch(method, request)
        try:
            self._bridge._process_notices()
            self._bridge._assert_operation_live(operation)
            operation.authorization.assert_live()
            self._bridge._process_notices()
            self._bridge._assert_operation_live(operation)
        except BaseException:
            operation.dispatch_done = True
            try:
                operation.authorization.fail(cache_may_exist=False)
            finally:
                self._bridge._reconcile()
            raise
        operation.dispatch_started = True
        try:
            response = await self._bridge._handler.handle(method, request)
            self._bridge._process_notices()
            self._bridge._assert_operation_live(operation)
            operation.authorization.assert_live()
            if (method == "Describe" and self._bridge._drain_deadline is not None
                    and hasattr(response, "ready")):
                response.ready = False
            return response
        finally:
            operation.dispatch_done = True
            if operation.owner is not None and operation.owner.invalidated:
                self._bridge._invalidate_owner(
                    operation.owner, operation.owner.invalidation_reason, force=True)
            self._bridge._dispatch_finished(operation)
            self._bridge._reconcile()


class SecureWorkerRuntimeBridge:
    """Explicit authorizer/handler pair for create_secure_worker_server.

    The bridge is exclusive to one freshly constructed WorkerHandler. It does
    not add authority to a request; every operation first passes the supplied
    core Authorizer and then must match that exact parsed request object.
    """

    def __init__(self, authorizer, handler, *, sweep_interval_seconds=1.0,
                 max_inflight_operations=MAX_INFLIGHT_OPERATIONS,
                 notice_capacity=None):
        if (isinstance(sweep_interval_seconds, bool)
                or not isinstance(sweep_interval_seconds, (int, float))
                or not math.isfinite(sweep_interval_seconds)
                or not 0 < sweep_interval_seconds <= MAX_SWEEP_INTERVAL_SECONDS):
            raise ValueError("authorization sweep interval must be in (0, 5] seconds")
        if (type(max_inflight_operations) is not int
                or not 1 <= max_inflight_operations <= MAX_INFLIGHT_OPERATIONS):
            raise ValueError("in-flight operation bound must be within 32")

        from steamboat_security.authorization import Authorizer
        from steamboat_security.errors import ClockError, SnapshotError
        from steamboat_security.sessions import SessionBindings, SessionNotice
        from .worker_state import WorkerHandler

        if type(authorizer) is not Authorizer:
            raise TypeError("runtime bridge requires the real C0 Authorizer")
        if type(handler) is not WorkerHandler:
            raise TypeError("runtime bridge requires the actual WorkerHandler")
        sessions = authorizer.session_bindings
        if type(sessions) is not SessionBindings:
            raise TypeError("runtime bridge requires the Authorizer's SessionBindings")
        if (notice_capacity is None):
            notice_capacity = sessions.max_records
        if (type(notice_capacity) is not int or not 1 <= notice_capacity
                <= sessions.max_records):
            raise ValueError("session notice queue bound exceeds the core record bound")

        local_view, local_sample = authorizer._current_view()
        local = authorizer._verify_certificate(
            authorizer.local_identity.certificate_pem, local_view, local_sample)
        if (local.role != "host" or authorizer.local_identity.assignment_id is None
                or authorizer.local_identity.boot_id != handler.boot_id
                or authorizer.local_identity.model_id != handler.manifest["fingerprint"]):
            raise ValueError("worker identity, assignment, model or boot differs from the handler")
        component = handler.manifest.get("components", {}).get(handler.worker_name)
        if (type(component) is not dict
                or tuple(component.get("layer_range", ())) != (handler.start, handler.end)):
            raise ValueError("WorkerHandler range differs from its assigned manifest component")
        if (handler.sessions or handler.tombstones or handler._queue
                or handler._active_operation is not None or handler._loop is not None
                or handler.stopping or handler.requires_restart):
            raise ValueError("secure runtime bridge must bind a fresh, idle WorkerHandler")

        self.authorizer_core = authorizer
        self.session_bindings = sessions
        self._handler = handler
        self.target_device_id = local.device_id
        self.worker_boot_id = handler.boot_id
        self.assignment_id = authorizer.local_identity.assignment_id
        self.sweep_interval_seconds = float(sweep_interval_seconds)
        self.max_inflight_operations = max_inflight_operations
        self.notice_capacity = notice_capacity
        self._SessionNotice = SessionNotice
        self._ClockError = ClockError
        self._SnapshotError = SnapshotError
        self._lock = threading.RLock()
        self._admitting = 0
        self._operations = {}
        self._owners = {}
        self._gateway_ingresses = {}
        self._capture_lock = threading.Lock()
        self._captured_owners = {}
        self._notice_lock = threading.Lock()
        self._pending_notices = {}
        self._callback_fault = threading.Event()
        self._wake_lock = threading.Lock()
        self._wake_scheduled = False
        self._loop = None
        self._wake = None
        self._maintenance_task = None
        self._started = False
        self._closed = False
        self._unavailable = False
        self._fault_reason = ""
        self._unconfirmed_cleanup = False
        self._drain_started_monotonic = None
        self._drain_deadline = None
        self._drain_deadline_reached = False
        self.incoming_authorizer = _IncomingAuthorizer(self)
        self.handler = _BoundWorkerHandler(self)
        self.authorization_watcher = self._watch_authorization
        bridge_ref = weakref.ref(self)

        def deliver_notice(notice):
            bridge = bridge_ref()
            if bridge is not None:
                bridge._receive_notice(notice)

        self._notice_callback = deliver_notice
        sessions.subscribe(deliver_notice)

    @property
    def unavailable(self):
        return self._unavailable or self._callback_fault.is_set()

    def status(self):
        supervision = self._handler.supervision_status()
        unavailable = (self.unavailable or self._unconfirmed_cleanup
                       or not supervision["ready"])
        return {
            "ready": (self._started and not self._closed and not unavailable
                      and self._drain_deadline is None),
            "unavailable": unavailable,
            "requires_restart": bool(supervision["requires_restart"] or unavailable),
            "cleanup_confirmed": not self._unconfirmed_cleanup,
            "active_authorizations": len(self._operations),
            "owned_sessions": len(self._owners),
            "pending_notices": self._pending_notice_count(),
            "fault": self._fault_reason,
        }

    async def wait_for_authorized_reclamation(self, authorization):
        """Wait until this authorization's invalidated session leaves WorkerHandler.

        The exact live bridge authorization is required so unrelated callers
        cannot use this observer to wait on or infer another session's state.
        A valid session is not waited on: successful Steps intentionally retain
        their cache. If a canceled computation cannot be confirmed reclaimed
        within the worker's cancellation grace, the bridge fences and reports
        uncertainty while its caller retains the authorization and capture.
        """
        if (type(authorization) is not _BoundAuthorization
                or authorization._bridge is not self):
            raise RuntimeBindingError(
                "reclamation wait requires this bridge's exact bound authorization")
        operation = authorization._operation
        with self._lock:
            if (operation.authorization is not authorization
                    or operation.core_authorization is not authorization._core
                    or self._operations.get(id(operation.request)) is not operation):
                raise RuntimeBindingError(
                    "reclamation wait authorization is not the current bridge operation")
        self._assert_loop()
        owner = operation.owner
        if owner is None or not owner.invalidated:
            return False
        if not operation.dispatch_done:
            raise RuntimeBindingError(
                "reclamation wait requires completed handler dispatch")

        grace = self._handler.limits["compute_cancel_grace_seconds"]
        sweep = self._handler.limits["lease_check_interval_seconds"]
        if (isinstance(grace, bool) or not isinstance(grace, (int, float))
                or not math.isfinite(grace) or grace <= 0
                or isinstance(sweep, bool) or not isinstance(sweep, (int, float))
                or not math.isfinite(sweep) or sweep <= 0):
            self._unconfirmed_cleanup = True
            self._fence("worker reclamation bounds are invalid")
            raise RuntimeBridgeUnavailable("worker reclamation bounds are invalid")
        deadline = time.monotonic() + float(grace) + min(float(sweep), 5.0) + 1.0
        while True:
            if (self._closed or self.unavailable or self._unconfirmed_cleanup
                    or self._handler.requires_restart):
                raise RuntimeBridgeUnavailable(
                    "worker session reclamation is unconfirmed")
            self._process_notices()
            # Notice processing can itself fence the bridge (for example, a
            # bounded notice queue fault). Never treat the pre-processing
            # health sample as proof that cleanup remains trustworthy.
            if (self._closed or self.unavailable or self._unconfirmed_cleanup
                    or self._handler.requires_restart):
                raise RuntimeBridgeUnavailable(
                    "worker session reclamation is unconfirmed")
            with self._lock:
                if (self._operations.get(id(operation.request)) is not operation
                        or operation.authorization_closed):
                    raise RuntimeBridgeUnavailable(
                        "worker authorization retired before reclamation was confirmed")
            if not owner.invalidated:
                raise RuntimeBridgeUnavailable(
                    "worker invalidated owner identity changed during reclamation")
            if not self._handler_owns_session(owner):
                self._reconcile()
                if (self._closed or self.unavailable or self._unconfirmed_cleanup
                        or self._handler.requires_restart):
                    raise RuntimeBridgeUnavailable(
                        "worker session reclamation was not confirmed")
                return True
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                self._unconfirmed_cleanup = True
                self._fence("worker session reclamation deadline expired")
                raise RuntimeBridgeUnavailable(
                    "worker session reclamation deadline expired")
            await asyncio.sleep(min(_OWNER_RECLAIM_POLL_SECONDS, remaining))

    def confirm_authorization_retirement(self, authorization):
        """Confirm one already-closed authorization left no uncertain owner state.

        This is an observation only: it never retries ``close``. A swallowed
        ledger-retirement error leaves the owner present or fences the bridge,
        so callers must retain their capture on any failure.
        """
        if (type(authorization) is not _BoundAuthorization
                or authorization._bridge is not self):
            raise RuntimeBindingError(
                "retirement confirmation requires this bridge's exact authorization")
        operation = authorization._operation
        with self._lock:
            if (operation.authorization is not authorization
                    or operation.core_authorization is not authorization._core
                    or not operation.authorization_closed):
                raise RuntimeBindingError(
                    "retirement confirmation requires the exact closed authorization")
        self._assert_loop()
        self._process_notices()
        self._reconcile()
        if (self._closed or self.unavailable or self._unconfirmed_cleanup
                or self._handler.requires_restart):
            raise RuntimeBridgeUnavailable(
                "authorization retirement remains unconfirmed")
        owner = operation.owner
        if owner is not None and owner.invalidated:
            if (self._owners.get(owner.key) is owner
                    or self._handler_owns_session(owner)):
                raise RuntimeBridgeUnavailable(
                    "invalidated session retirement remains unconfirmed")
        return True

    def begin_drain(self, timeout_seconds=30):
        """Stop new session admission and set one immutable owner deadline."""
        if type(timeout_seconds) is not int or not 1 <= timeout_seconds <= 300:
            raise ValueError("worker drain timeout must be an exact integer in [1, 300]")
        self._assert_loop()
        with self._lock:
            if not self._started or self._closed:
                raise RuntimeBridgeUnavailable("worker drain requires a live runtime bridge")
            if (self.unavailable or self._unconfirmed_cleanup
                    or self._handler.requires_restart or self._handler.stopping):
                raise RuntimeBridgeUnavailable("worker runtime is already unavailable")
            if self._drain_deadline is not None:
                return self._drain_deadline
            try:
                sample = self.authorizer_core.clock.sample()
                now = sample.monotonic
                if (type(now) not in (int, float) or not math.isfinite(now)):
                    raise self._ClockError("invalid monotonic sample")
            except BaseException:
                self._unconfirmed_cleanup = True
                self._fence("worker drain clock sample failed")
                raise RuntimeBridgeUnavailable("worker drain clock sample failed") from None
            self._drain_started_monotonic = float(now)
            self._drain_deadline = float(now) + timeout_seconds
            self._drain_deadline_reached = False
        self._signal_wake()
        return self._drain_deadline

    def owner_lifecycle_status(self):
        """Report owner drain phase separately from runtime fault supervision."""
        self._assert_loop()
        if not self._started or self._closed:
            raise RuntimeBridgeUnavailable("owner lifecycle requires a live runtime bridge")
        if self._drain_deadline is None:
            phase = "ready"
        else:
            try:
                sample = self.authorizer_core.clock.sample()
                if (type(sample.monotonic) not in (int, float)
                        or not math.isfinite(sample.monotonic)):
                    raise self._ClockError("invalid monotonic sample")
                self._expire_drain(sample)
            except BaseException:
                self._unconfirmed_cleanup = True
                self._fence("worker drain clock sample failed")
                raise RuntimeBridgeUnavailable("worker drain clock sample failed") from None
            phase = "paused" if self._drain_resources_reclaimed() else "draining"
        return {
            "phase": phase,
            "drain_started_monotonic": self._drain_started_monotonic,
            "drain_deadline_monotonic": self._drain_deadline,
            "deadline_reached": self._drain_deadline_reached,
        }

    async def start(self):
        loop = asyncio.get_running_loop()
        if self._started:
            if loop is not self._loop:
                raise RuntimeBindingError("runtime bridge belongs to another event loop")
            return self
        self._loop = loop
        self._wake = asyncio.Event()
        self._started = True
        self._maintenance_task = loop.create_task(self._maintenance())
        self._sweep_once()
        self._process_notices()
        self._reconcile()
        if self.unavailable:
            raise RuntimeBridgeUnavailable("runtime bridge failed its initial authorization sweep")
        return self

    def _assert_loop(self):
        try:
            current = asyncio.get_running_loop()
        except RuntimeError as error:
            raise RuntimeBridgeUnavailable(
                "secure worker runtime must be used from its owning event loop") from error
        if self._loop is None or current is not self._loop:
            raise RuntimeBridgeUnavailable(
                "secure worker runtime belongs to another event loop")

    async def _watch_authorization(self, authorization):
        if not isinstance(authorization, _BoundAuthorization) or authorization._bridge is not self:
            raise RuntimeBindingError("authorization watcher received an unrelated binding")
        operation = authorization._operation
        while True:
            if authorization.completed:
                await asyncio.Future()
            try:
                authorization.assert_live()
                remaining = authorization.remaining_seconds()
            except Exception:
                return
            if operation.owner is not None and operation.owner.invalidation_event.is_set():
                return
            delay = min(self.sweep_interval_seconds, remaining)
            if operation.owner is None:
                await asyncio.sleep(delay)
                continue
            try:
                await asyncio.wait_for(operation.owner.invalidation_event.wait(), timeout=delay)
                return
            except asyncio.TimeoutError:
                pass

    def _reserve_admission(self, method):
        with self._lock:
            if not self._started or self._closed:
                raise RuntimeBridgeUnavailable("secure worker runtime bridge is not running")
            if self.unavailable or self._handler.requires_restart or self._handler.stopping:
                self._mark_unavailable_on_loop("runtime is fenced")
                raise RuntimeBridgeUnavailable("secure worker runtime requires restart")
            if method == "OpenSession" and self._drain_deadline is not None:
                raise RuntimeOpenAdmissionRejected("worker owner is draining")
            if len(self._operations) + self._admitting >= self.max_inflight_operations:
                raise RuntimeBridgeUnavailable("secure worker authorization capacity is full")
            self._admitting += 1

    def _authorize(self, *, service, method, payload, metadata,
                   peer_certificate_pem=None, ingress=None, envelope=None,
                   request_bytes=None, frame_sequence=None, wire_lane=None):
        self._assert_loop()
        if service != WORKER_SERVICE:
            raise RuntimeBindingError("runtime bridge accepts only the worker service")
        self._reserve_admission(method)
        core_authorization = None
        registered = False
        try:
            if ingress is None:
                core_authorization = self.authorizer_core.authorize(
                    service=service, method=method, payload=payload, metadata=metadata,
                    peer_certificate_pem=peer_certificate_pem)
            else:
                core_authorization = self.authorizer_core.authorize_gateway(
                    service, method, payload, metadata, ingress=ingress,
                    envelope=envelope, request_bytes=request_bytes,
                    frame_sequence=frame_sequence, wire_lane=wire_lane)
                if core_authorization.payload is not payload:
                    raise RuntimeBindingError(
                        "gateway authorization changed the captured parsed Request object")
            operation = self._make_operation(method, payload, core_authorization)
            bound = _BoundAuthorization(self, operation)
            with self._lock:
                if self.unavailable or self._closed:
                    raise RuntimeBridgeUnavailable("runtime became unavailable during admission")
                key = id(payload)
                prior = self._operations.get(key)
                if prior is not None:
                    raise RuntimeBindingError("parsed Request object is already bound to an RPC")
                if operation.owner is not None and method == "OpenSession":
                    owner = operation.owner
                    current = self._owners.get(owner.key)
                    claim = core_authorization._session_claim
                    if claim.is_new:
                        if current is not None or len(self._owners) >= self.session_bindings.max_live_sessions:
                            raise RuntimeBindingError("session owner namespace is already occupied")
                        self._owners[owner.key] = owner
                    elif current is None or current.core_owner != owner.core_owner:
                        raise RuntimeBindingError("duplicate OpenSession has no matching captured owner")
                    else:
                        operation.owner = current
                        bound._operation.owner = current
                elif operation.owner is not None:
                    current = self._owners.get(operation.owner.key)
                    if current is None or current.core_identity != operation.identity:
                        raise RuntimeBindingError("session operation has no matching captured Open owner")
                    if current.invalidated or current.terminal_reclaimed:
                        raise RuntimeBindingError("session owner is already invalidated or reclaimed")
                    operation.owner = current
                    bound._operation.owner = current
                if operation.owner is not None:
                    self._capture_owner(operation.owner)
                    if ingress is not None:
                        self._gateway_ingresses[ingress.ingress_identity] = ingress
                self._operations[key] = operation
                registered = True
            return bound
        except BaseException:
            if core_authorization is not None and not registered:
                try:
                    core_authorization.fail(cache_may_exist=False)
                finally:
                    core_authorization.close()
            raise
        finally:
            with self._lock:
                self._admitting -= 1
            self._signal_wake()

    def _make_operation(self, method, request, authorization):
        from steamboat_security.sessions import SessionClaim

        if (authorization.binding.service != WORKER_SERVICE
                or authorization.binding.method != method
                or authorization.payload is not request):
            raise RuntimeBindingError("core Authorization does not bind the parsed Request")
        owner = None
        key = authorization._session_key
        if method == "Describe":
            if key is not None:
                raise RuntimeBindingError("Describe unexpectedly owns a session binding")
        else:
            binding = authorization.binding
            if (binding["target_device_id"] != authorization.local.device_id
                    or binding["worker_boot_id"] != self.worker_boot_id
                    or binding["assignment_id"] != self.assignment_id
                    or binding["session_id"] != request.session_id
                    or request.worker_boot_id != self.worker_boot_id
                    or request.manifest_fingerprint != authorization.model_id):
                raise RuntimeBindingError("core session identity differs from the local runtime")
            if type(key) is not tuple or key != (
                    self.target_device_id, self.worker_boot_id, request.session_id):
                raise RuntimeBindingError("core session key differs from the local runtime namespace")
            identity = self._core_identity(authorization)
            if method == "OpenSession":
                claim = authorization._session_claim
                if type(claim) is not SessionClaim or claim.key != key:
                    raise RuntimeBindingError("OpenSession has no actual core SessionClaim")
                core_owner = claim.owner
            else:
                claim = None
                current = self._owners.get((self.target_device_id, self.worker_boot_id,
                                            self.assignment_id, request.session_id))
                if current is None:
                    raise RuntimeBindingError("session operation has no locally captured Open owner")
                core_owner = current.core_owner
            owner = _SessionOwner(
                target_device_id=self.target_device_id,
                worker_boot_id=self.worker_boot_id,
                assignment_id=self.assignment_id,
                session_id=request.session_id,
                core_owner=core_owner,
                core_identity=identity,
                ingress_identity=authorization._ingress_identity,
                invalidation_event=asyncio.Event())
        identity = self._core_identity(authorization)
        return _Operation(request=request, method=method,
                          core_authorization=authorization, owner=owner,
                          identity=identity)

    @staticmethod
    def _core_identity(authorization):
        def credential(value):
            record = value.record
            return (record.account_id, record.device_id, record.role, record.serial,
                    record.public_key_sha256, record.certificate_sha256,
                    record.credential_epoch)

        fields = tuple(sorted((name, value) for name, value in authorization.binding.fields.items()
                              if name != "operation_id"))
        return (fields, credential(authorization.actor), credential(authorization.local),
                authorization.model_id)

    def _begin_dispatch(self, method, request):
        with self._lock:
            if self.unavailable or self._closed or not self._started:
                raise RuntimeBridgeUnavailable("secure worker runtime is unavailable")
            operation = self._operations.get(id(request))
            if (operation is None or operation.request is not request
                    or operation.method != method or operation.dispatch_started
                    or operation.authorization_closed):
                raise RuntimeBindingError("handler dispatch lacks its exact live authorization")
            return operation

    def _assert_operation_live(self, operation, *, allow_terminal_rpc=False):
        if self.unavailable or self._closed:
            raise RuntimeBridgeUnavailable("secure worker runtime is fenced")
        if operation.authorization_closed:
            raise RuntimeBridgeUnavailable("worker authorization is already closed")
        if (operation.method == "OpenSession" and self._drain_deadline is not None
                and not operation.dispatch_started):
            raise RuntimeBindingError("worker owner began draining before Open dispatch")
        owner = operation.owner
        if owner is not None and self._drain_deadline is not None:
            try:
                sample = self.authorizer_core.clock.sample()
            except BaseException:
                self._unconfirmed_cleanup = True
                self._fence("worker drain clock sample failed")
                raise RuntimeBridgeUnavailable("worker drain clock sample failed") from None
            if sample.monotonic >= self._drain_deadline:
                self._expire_drain(sample)
                raise RuntimeBridgeUnavailable("worker drain deadline expired")
        if owner is not None and (owner.invalidated or (
                owner.terminal_reclaimed and not (
                    allow_terminal_rpc and operation.terminal_rpc_completed
                    and operation.method in ("CloseSession", "CancelSession")))):
            raise RuntimeBridgeUnavailable("authorized session owner was invalidated")

    def _session_drain_deadline(self, operation):
        if operation.method == "Describe" or operation.owner is None:
            return None
        return self._drain_deadline

    def _expire_drain(self, sample):
        if self._drain_deadline is None or sample.monotonic < self._drain_deadline:
            return False
        self._drain_deadline_reached = True
        try:
            for owner in tuple(self._owners.values()):
                self.session_bindings.invalidate(
                    key=(owner.target_device_id, owner.worker_boot_id, owner.session_id),
                    reason="worker-owner-drain-deadline")
            self._poll_gateway_ingresses()
            self._process_notices()
            self._reconcile()
        except BaseException:
            self._unconfirmed_cleanup = True
            self._fence("worker drain invalidation was unconfirmed")
            raise
        return True

    def _drain_resources_reclaimed(self):
        handler = self._handler
        if (self._operations or self._admitting or self._owners
                or self._pending_notice_count() or self._unconfirmed_cleanup
                or handler.sessions or handler._queue
                or handler._active_operation is not None):
            return False
        task = getattr(handler, "_compute_task", None)
        if task is not None and not task.done():
            return False
        for entry in handler.tombstones.values():
            try:
                if (entry.in_flight or entry.queued or entry.committed_bytes != 0
                        or entry.cache.allocated_bytes() != 0
                        or any(entry.cache.lengths())):
                    return False
            except BaseException:
                return False
        return True

    def _authorization_liveness_failed(self, operation, error):
        if isinstance(error, (self._ClockError, self._SnapshotError)):
            self._fence("core clock or snapshot validation failed")
            return
        owner = operation.owner
        if owner is not None:
            self._invalidate_owner(owner, "core-authorization-no-longer-live")

    def _invalidate_owner(self, owner, reason, *, force=False):
        if owner.invalidated and not force:
            return
        if not owner.invalidated:
            owner.invalidated = True
            owner.invalidation_reason = str(reason)[:64]
            if owner.invalidation_event is not None:
                owner.invalidation_event.set()
        try:
            self._handler.invalidate_for_authorization(owner.session_id)
        except BaseException:
            self._unconfirmed_cleanup = True
            self._fence("WorkerHandler invalidation was unconfirmed")

    def _authorization_closed(self, operation):
        if operation.close_failed:
            return
        operation.authorization_closed = True
        if not operation.dispatch_started or operation.dispatch_done:
            self._drop_operation(operation)
        self._reconcile()
        self._signal_wake()

    def _dispatch_finished(self, operation):
        if operation.authorization_closed:
            self._drop_operation(operation)
        self._signal_wake()

    def _drop_operation(self, operation):
        with self._lock:
            key = id(operation.request)
            if self._operations.get(key) is operation:
                del self._operations[key]

    def _receive_notice(self, notice):
        if self._closed:
            return
        try:
            self._add_pending_notice(notice)
        except BaseException:
            self._callback_fault.set()
            self._unconfirmed_cleanup = True
        loop = self._loop
        if loop is None:
            return
        with self._wake_lock:
            if self._wake_scheduled:
                return
            self._wake_scheduled = True
        try:
            loop.call_soon_threadsafe(self._wake.set)
        except BaseException:
            with self._wake_lock:
                self._wake_scheduled = False
            self._callback_fault.set()
            self._unconfirmed_cleanup = True

    def _signal_wake(self):
        if self._loop is None or self._wake is None:
            return
        try:
            self._loop.call_soon_threadsafe(self._wake.set)
        except RuntimeError:
            self._callback_fault.set()
            self._unconfirmed_cleanup = True

    def _pending_notice_count(self):
        with self._notice_lock:
            return len(self._pending_notices)

    async def _maintenance(self):
        next_sweep = self._loop.time() + self.sweep_interval_seconds
        while not self._closed:
            self._wake.clear()
            with self._wake_lock:
                self._wake_scheduled = False
            if self._callback_fault.is_set():
                self._fence("session invalidation callback or bounded queue failed")
            self._poll_gateway_ingresses()
            self._process_notices()
            self._reconcile()
            if self._drain_deadline is not None:
                try:
                    sample = self.authorizer_core.clock.sample()
                    self._expire_drain(sample)
                except BaseException:
                    self._unconfirmed_cleanup = True
                    self._fence("worker drain clock or invalidation failed")
            delay = max(0.0, next_sweep - self._loop.time())
            if self._drain_deadline is not None and not self._drain_deadline_reached:
                try:
                    sample = self.authorizer_core.clock.sample()
                    delay = min(delay, max(0.0, self._drain_deadline - sample.monotonic))
                except BaseException:
                    self._unconfirmed_cleanup = True
                    self._fence("worker drain clock sample failed")
            try:
                await asyncio.wait_for(self._wake.wait(), timeout=delay)
            except asyncio.TimeoutError:
                pass
            if self._loop.time() >= next_sweep:
                self._sweep_once()
                next_sweep = self._loop.time() + self.sweep_interval_seconds

    def _poll_gateway_ingresses(self):
        # Ingress polling is bounded by SessionBindings' live-session limit.
        for ingress in tuple(self._gateway_ingresses.values()):
            try:
                ingress.poll_unavailable()
            except BaseException:
                self._unconfirmed_cleanup = True
                self._fence("gateway ingress liveness could not be confirmed")

    def _sweep_once(self):
        try:
            sample = self.authorizer_core.clock.sample()
            self._expire_drain(sample)
            self.authorizer_core.snapshot_store.current(sample=sample)
            notices = self.authorizer_core.sweep()
            for notice in notices:
                self._add_pending_notice(notice)
            self._process_notices()
            self._reconcile()
        except BaseException:
            self._unconfirmed_cleanup = True
            self._fence("Authorizer sweep failed")
            self._process_notices()
            self._reconcile()

    def _add_pending_notice(self, notice, *, captured_owner=_CAPTURE_UNSET):
        if type(notice) is not self._SessionNotice:
            self._callback_fault.set()
            self._unconfirmed_cleanup = True
            return
        key = (notice.target_device_id, notice.worker_boot_id,
               self.assignment_id, notice.session_id)
        if captured_owner is _CAPTURE_UNSET:
            with self._capture_lock:
                captured_owner = self._captured_owners.get(key)
        if captured_owner is None:
            captured = (None, None)
        else:
            captured = captured_owner
        with self._notice_lock:
            if (key not in self._pending_notices
                    and len(self._pending_notices) >= self.notice_capacity):
                self._callback_fault.set()
                self._unconfirmed_cleanup = True
                return
            prior = self._pending_notices.get(key)
            prior_notice = prior.notice if prior is not None else None
            selected = captured
            if prior is not None and prior.core_owner is not None:
                selected = (prior.core_owner, prior.core_identity)
            if (prior_notice is None
                    or notice.reason == "clock-or-snapshot-unavailable"
                    or prior_notice.reason != "clock-or-snapshot-unavailable"):
                self._pending_notices[key] = _CapturedNotice(
                    notice=notice, core_owner=selected[0], core_identity=selected[1])

    def _process_notices(self):
        if self._callback_fault.is_set():
            self._fence("session invalidation callback or bounded queue failed")
        with self._notice_lock:
            notices = tuple(self._pending_notices.items())
            self._pending_notices.clear()
        for key, captured_notice in notices:
            notice = captured_notice.notice
            if (notice.target_device_id != self.target_device_id
                    or notice.worker_boot_id != self.worker_boot_id):
                continue
            owner_key = (notice.target_device_id, notice.worker_boot_id,
                         self.assignment_id, notice.session_id)
            owner = self._owners.get(owner_key)
            if (captured_notice.core_owner is not None
                    and (owner is None or captured_notice.core_owner != owner.core_owner
                         or captured_notice.core_identity != owner.core_identity)):
                continue
            if notice.reason == "clock-or-snapshot-unavailable":
                if owner is None and not self._admitting:
                    self._unconfirmed_cleanup = True
                self._fence("core clock or snapshot is unavailable")
                continue
            if owner is None:
                if self._admitting:
                    if captured_notice.core_owner is None:
                        self._add_pending_notice(notice)
                    else:
                        self._add_pending_notice(
                            notice, captured_owner=(captured_notice.core_owner,
                                                    captured_notice.core_identity))
                    continue
                self._unconfirmed_cleanup = True
                self._fence("current-boot invalidation has no captured core owner")
                continue
            self._invalidate_owner(owner, notice.reason)

    def _has_live_rpc(self, owner):
        if self._admitting:
            return True
        return any(operation.owner is owner for operation in self._operations.values())

    def _handler_owns_session(self, owner):
        session_id = owner.session_id
        entry = self._handler.sessions.get(session_id)
        if entry is not None:
            return True
        active = self._handler._active_operation
        if active is not None and active.entry.session_id == session_id:
            return True
        if any(operation.entry.session_id == session_id for operation in self._handler._queue):
            return True
        tombstone = self._handler.tombstones.get(session_id)
        if tombstone is None:
            return False
        if (tombstone.in_flight or tombstone.queued
                or tombstone.committed_bytes != 0):
            return True
        try:
            return (tombstone.cache.allocated_bytes() != 0
                    or any(tombstone.cache.lengths()))
        except BaseException:
            return True

    def _reconcile(self):
        for owner in tuple(self._owners.values()):
            if owner.invalidated:
                if self._has_live_rpc(owner) or self._handler_owns_session(owner):
                    continue
                try:
                    reclaimed = self.session_bindings.mark_reclaimed(
                        target_device_id=owner.target_device_id,
                        worker_boot_id=owner.worker_boot_id,
                        session_id=owner.session_id)
                except BaseException:
                    self._unconfirmed_cleanup = True
                    self._fence("core session reclamation was unconfirmed")
                    continue
                if not reclaimed:
                    if owner.predispatch_aborted:
                        self._remove_owner(owner)
                        continue
                    self._unconfirmed_cleanup = True
                    self._fence("core did not confirm invalidated session reclamation")
                    continue
                self._remove_owner(owner)
            elif owner.predispatch_aborted and not self._has_live_rpc(owner):
                if not self._handler_owns_session(owner):
                    self._remove_owner(owner)
            elif owner.terminal_reclaimed and not self._has_live_rpc(owner):
                if not self._handler_owns_session(owner):
                    self._remove_owner(owner)

    def _remove_owner(self, owner):
        if self._owners.get(owner.key) is owner:
            self._owners.pop(owner.key, None)
        with self._capture_lock:
            captured = self._captured_owners.get(owner.key)
            if captured == (owner.core_owner, owner.core_identity):
                self._captured_owners.pop(owner.key, None)
        if owner.ingress_identity is not None and not any(
                item.ingress_identity == owner.ingress_identity
                for item in self._owners.values()):
            self._gateway_ingresses.pop(owner.ingress_identity, None)

    def _capture_owner(self, owner):
        with self._capture_lock:
            self._captured_owners[owner.key] = (owner.core_owner, owner.core_identity)

    def _mark_unavailable_on_loop(self, reason):
        self._fence(reason)

    def _fence(self, reason):
        first = not self._unavailable
        self._unavailable = True
        if not self._fault_reason:
            self._fault_reason = str(reason)[:128]
        self._handler.requires_restart = True
        try:
            self._handler._notify_supervisor()
        except BaseException:
            pass
        if not first:
            return
        try:
            self.session_bindings.invalidate_all("secure-runtime-bridge-unavailable")
        except BaseException:
            self._unconfirmed_cleanup = True
        for owner in tuple(self._owners.values()):
            owner.invalidated = True
            owner.invalidation_reason = self._fault_reason
            if owner.invalidation_event is not None:
                owner.invalidation_event.set()
            try:
                self._handler.invalidate_for_authorization(owner.session_id)
            except BaseException:
                self._unconfirmed_cleanup = True
        self._signal_wake()

    async def stop(self, grace_seconds=5.0):
        if (isinstance(grace_seconds, bool)
                or not isinstance(grace_seconds, (int, float))
                or not math.isfinite(grace_seconds)
                or not 0 < grace_seconds <= 5.0):
            raise ValueError("runtime bridge stop grace must be in (0, 5] seconds")
        if not self._started or asyncio.get_running_loop() is not self._loop:
            raise RuntimeBindingError("runtime bridge must stop on its owning event loop")
        self._fence("secure runtime bridge is stopping")
        deadline = self._loop.time() + grace_seconds
        while self._loop.time() < deadline:
            self._wake.clear()
            self._process_notices()
            self._reconcile()
            if (not self._operations and not self._owners and not self._admitting
                    and not self._unconfirmed_cleanup):
                self._closed = True
                if self._maintenance_task is not None:
                    self._maintenance_task.cancel()
                    await asyncio.gather(self._maintenance_task, return_exceptions=True)
                return True
            try:
                await asyncio.wait_for(self._wake.wait(), timeout=min(
                    0.05, max(0.0, deadline - self._loop.time())))
            except asyncio.TimeoutError:
                pass
        self._fence("runtime cleanup exceeded its bounded grace")
        self._unconfirmed_cleanup = True
        return False
