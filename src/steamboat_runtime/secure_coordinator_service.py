"""mTLS adapter for the bounded coordinator service.

The existing CoordinatorService remains the isolated plaintext lab service. This
adapter requires the C0 Authorizer and an explicit trusted request-context seam
through Coordinator.submit; it never reads authorization from task-local state.
"""

import asyncio
import inspect
import math
import re
import threading
import time
import uuid

from .protocol.secure_transport import (
    AuthorizationRejected,
    AuthorizationRevoked,
    BINDING_METADATA_KEY,
    COORDINATOR_MAX_CONCURRENT_RPCS,
    COORDINATOR_MAX_GENERATE_STREAMS,
    COORDINATOR_SERVICE,
    SecureTaskPending,
    SecureTransportError,
    _abort,
    _assert_live,
    _await_task_bounded,
    _authorization_status,
    _call_authorize,
    _close_failed_authorization,
    _cancel_tasks_bounded,
    _fail_authorization,
    _maybe_await,
    _peer_certificate_from_auth_context,
    _pending_task_descendants,
    _retain_tasks,
    _run_guarded,
    _wait_owned_tasks,
    _SecureRuntimeOwner,
    _secure_options,
    validate_metadata,
)
from .protocol import secure_transport as _secure_transport
from .participant_context import TrustedRequestContext
from .capture_budget import CaptureAdmissionError, CaptureBudget


_TYPED_CONTEXT_ID = re.compile(r"(?:acct|req|ses|route)_[0-9a-f]{32}\Z")
_CONTEXT_BOOT_ID = re.compile(r"[0-9a-f]{32}\Z")


def _known_pre_admission_capacity_error(coordinator, error):
    from .coordinator import Coordinator, CoordinatorError

    return (type(coordinator) is Coordinator
            and "submit" not in vars(coordinator)
            and type(error) is CoordinatorError
            and error.code == "CAPACITY_EXHAUSTED"
            and error.message == "Coordinator admission queue is full")


class _AuthorizedStreamContext:
    """Pass gRPC operations through while checking authorization on every write."""

    def __init__(self, context, authorization, runtime_check=None):
        self._context, self._authorization = context, authorization
        self._runtime_check = runtime_check

    async def _check(self):
        await _assert_live(self._authorization)
        if self._runtime_check is not None:
            self._runtime_check()

    def time_remaining(self):
        return self._context.time_remaining()

    async def write(self, payload):
        try:
            await self._check()
            result = await self._context.write(payload)
            await self._check()
            return result
        finally:
            payload = None

    async def send_initial_metadata(self, metadata):
        await self._check()
        result = await self._context.send_initial_metadata(metadata)
        await self._check()
        return result

    async def set_trailing_metadata(self, metadata):
        await self._check()
        setter = getattr(self._context, "set_trailing_metadata", None)
        if not callable(setter):
            raise SecureTransportError(
                "gRPC context cannot attach an authenticated capacity rejection marker")
        await _maybe_await(setter(metadata))
        await self._check()

    async def abort(self, code, details):
        await self._check()
        result = await self._context.abort(code, details)
        await self._check()
        return result

    def __getattr__(self, name):
        return getattr(self._context, name)


class SecureCoordinatorService:
    """Secure fixed-peer wrapper around the existing coordinator service."""

    def __init__(self, service, *, authorizer, authorization_watcher,
                 request_context_factory, capture_budget=None,
                 max_generate_streams=COORDINATOR_MAX_GENERATE_STREAMS,
                 runtime_guard=None):
        self.service = service
        self.authorizer = authorizer
        self.authorization_watcher = authorization_watcher
        self.request_context_factory = request_context_factory
        if capture_budget is not None and type(capture_budget) is not CaptureBudget:
            raise ValueError("secure capture requires an owner-configured CaptureBudget")
        self.capture_budget = capture_budget
        if not callable(getattr(authorizer, "authorize", None)):
            raise ValueError("secure coordinator service requires the C0 Authorizer")
        if not callable(authorization_watcher):
            raise ValueError("secure coordinator service requires an expiry/revocation watcher")
        if not callable(request_context_factory):
            raise ValueError("Generate requires a trusted consumer request-context factory")
        if runtime_guard is not None:
            if (not callable(runtime_guard)
                    or inspect.iscoroutinefunction(runtime_guard)
                    or inspect.isasyncgenfunction(runtime_guard)
                    or inspect.iscoroutinefunction(getattr(runtime_guard, "__call__", None))
                    or inspect.isasyncgenfunction(getattr(runtime_guard, "__call__", None))):
                raise ValueError("runtime guard must be a synchronous callable")
        self.runtime_guard = runtime_guard
        self._runtime_invalidated = threading.Event()
        self._runtime_notification_lock = threading.Lock()
        self._runtime_notification_scheduled = False
        self._runtime_async_event = None
        self._owner_loop = None
        if (type(max_generate_streams) is not int or not 1 <= max_generate_streams
                <= COORDINATOR_MAX_GENERATE_STREAMS):
            raise ValueError("Generate stream limit must be within the C0 ceiling of 40")
        if max_generate_streams > service.max_streams:
            raise ValueError("Generate stream limit exceeds the coordinator service stream bound")
        submit = getattr(service.coordinator, "submit", None)
        if not callable(submit) or "trusted_request_context" not in inspect.signature(submit).parameters:
            raise SecureTransportError(
                "Coordinator.submit must accept explicit trusted_request_context before secure readiness")
        self.max_generate_streams = max_generate_streams
        self.active_generate_streams = 0
        self.acceptor = None
        self.unavailable = False
        self.pending_tasks = set()
        self._unconfirmed_capacity_rejection_authorizations = {}
        self._unreclaimed_generate_slots = []
        self.runtime_owner = _SecureRuntimeOwner()

    def _bind_owner_loop(self):
        loop = asyncio.get_running_loop()
        if self._owner_loop is None:
            self._owner_loop = loop
            self._runtime_async_event = asyncio.Event()
        elif self._owner_loop is not loop:
            raise SecureTransportError("secure coordinator is bound to another event loop")

    def request_runtime_invalidation(self, reason="runtime invalidated"):
        """Synchronously fence work; listener pausing is scheduled on its owner loop."""
        self._runtime_invalidated.set()
        self.unavailable = True
        self.runtime_owner.unavailable = True
        loop = self._owner_loop
        if loop is not None and not loop.is_closed():
            if self._runtime_notification_lock.acquire(blocking=False):
                try:
                    if not self._runtime_notification_scheduled:
                        self._runtime_notification_scheduled = True
                        try:
                            loop.call_soon_threadsafe(
                                self._apply_runtime_invalidation, reason)
                        except RuntimeError:
                            self._runtime_notification_scheduled = False
                finally:
                    self._runtime_notification_lock.release()
        return True

    def _apply_runtime_invalidation(self, reason):
        if self._runtime_async_event is not None:
            self._runtime_async_event.set()
        if self.acceptor is not None:
            try:
                self.acceptor.pause()
            except BaseException:
                self.unavailable = True
                self.runtime_owner.unavailable = True

    def _check_runtime_guard(self):
        self._bind_owner_loop()
        if self._runtime_invalidated.is_set():
            raise AuthorizationRevoked("coordinator runtime was invalidated")
        if self.runtime_guard is None:
            return
        try:
            result = self.runtime_guard()
            if inspect.isawaitable(result):
                if inspect.iscoroutine(result):
                    result.close()
                raise SecureTransportError("runtime guard must return synchronously")
            if result is not None:
                raise SecureTransportError("runtime guard must return exactly None")
            if self._runtime_invalidated.is_set():
                raise AuthorizationRevoked("coordinator runtime was invalidated")
        except BaseException as error:
            self.request_runtime_invalidation("runtime guard refused")
            raise AuthorizationRevoked("coordinator runtime is no longer live") from error

    def _stream_context(self, context, authorization):
        return _AuthorizedStreamContext(context, authorization, self._check_runtime_guard)

    def _runtime_authorization_watcher(self, authorization):
        async def watch(_authorization):
            self._bind_owner_loop()
            original = asyncio.create_task(_maybe_await(
                self.authorization_watcher(authorization)))
            invalidated = asyncio.create_task(self._runtime_async_event.wait())
            try:
                done, _ = await asyncio.wait((original, invalidated),
                    return_when=asyncio.FIRST_COMPLETED)
                if invalidated in done:
                    raise AuthorizationRevoked("coordinator runtime was invalidated")
                await original
                raise AuthorizationRevoked("authorization watcher completed")
            finally:
                await _cancel_tasks_bounded((original, invalidated),
                    message="coordinator runtime watcher did not stop")
        return watch

    async def _set_capacity_rejection_marker(
            self, context, authorization, *, send_binding):
        wrapped = (context if isinstance(context, _AuthorizedStreamContext)
                   else self._stream_context(context, authorization))
        await _assert_live(authorization)
        if send_binding:
            await wrapped.send_initial_metadata(((BINDING_METADATA_KEY,
                                                   authorization.binding_bytes),))
        from .protocol.secure_transport import capacity_rejection_metadata

        await wrapped.set_trailing_metadata(
            capacity_rejection_metadata(authorization.binding_bytes))
        await _assert_live(authorization)

    def _capacity_rejection_owner(self, authorization, state, tasks=(), *,
                                  start_owner=True):
        roots = state.setdefault("roots", set())
        tracked = state.setdefault("tracked", set())
        observed = state.setdefault("observed", set())
        if tasks:
            state["transferred"] = True

        def mark_unavailable():
            self.unavailable = True
            self.runtime_owner.unavailable = True
            if self.acceptor is not None:
                self.acceptor.pause()

        def discover(task):
            try:
                descendants = _pending_task_descendants((task,))
                for descendant in descendants:
                    retain(descendant)
            except BaseException:
                state["unconfirmed"] = True
                self._unconfirmed_capacity_rejection_authorizations[id(authorization)] = authorization
                mark_unavailable()

        def retain(task):
            if task in roots:
                return
            roots.add(task)
            tracked.add(task)
            self.pending_tasks.add(task)
            self.runtime_owner.pending_tasks.add(task)
            _retain_tasks((task,))
            if task not in observed:
                observed.add(task)
                try:
                    task.add_done_callback(discover)
                except BaseException:
                    state["unconfirmed"] = True
                    self._unconfirmed_capacity_rejection_authorizations[id(authorization)] = authorization
                    mark_unavailable()
            if task.done():
                discover(task)

        for task in tasks:
            retain(task)

        if not start_owner:
            if state.get("transferred"):
                mark_unavailable()
            return state.get("owner")

        owner = state.get("owner")
        if owner is not None:
            mark_unavailable()
            return owner

        async def close_after_retirement():
            visited = set()
            try:
                while True:
                    for task in tuple(roots):
                        discover(task)
                    pending = roots - visited
                    if not pending:
                        await asyncio.sleep(0)
                        for task in tuple(roots):
                            discover(task)
                        pending = roots - visited
                        if not pending:
                            break
                    await _wait_owned_tasks(pending)
                    visited.update(pending)
                if state.get("unconfirmed"):
                    return
                state["close_started"] = True
                await _close_failed_authorization(
                    authorization, cache_may_exist=False)
                state["closed"] = True
            except BaseException:
                state["unconfirmed"] = True
                self._unconfirmed_capacity_rejection_authorizations[id(authorization)] = authorization
                mark_unavailable()
                raise

        owner = asyncio.create_task(close_after_retirement())
        state["owner"] = owner
        self.pending_tasks.add(owner)
        self.runtime_owner.pending_tasks.add(owner)
        _retain_tasks((owner,))

        def owner_done(task):
            try:
                failure = task.exception()
            except asyncio.CancelledError as error:
                failure = error
            if failure is not None:
                # Reuse the pending-task graph observer for both supported
                # pending exception types. Retain descendants before dropping
                # this failed owner from either registry; its exception is
                # not a durable task owner after that removal.
                discover(task)
            if failure is not None or not state.get("closed"):
                state["unconfirmed"] = True
                self._unconfirmed_capacity_rejection_authorizations[id(authorization)] = authorization
                mark_unavailable()
                self.pending_tasks.discard(task)
                self.runtime_owner.pending_tasks.discard(task)
                for owned in tracked:
                    self.pending_tasks.add(owned)
                    self.runtime_owner.pending_tasks.add(owned)
                    _retain_tasks((owned,))
            else:
                for owned in tracked | {task}:
                    self.pending_tasks.discard(owned)
                    self.runtime_owner.pending_tasks.discard(owned)
                self._unconfirmed_capacity_rejection_authorizations.pop(
                    id(authorization), None)

        owner.add_done_callback(owner_done)
        if state.get("transferred"):
            mark_unavailable()
        return owner

    def _capture_configuration_error(self):
        budget = self.capture_budget
        if budget is None:
            return "last-position logit capture is not configured by the owner"
        coordinator = self.service.coordinator
        manifest = getattr(coordinator, "manifest", None)
        limits = getattr(coordinator, "limits", None)
        try:
            vocabulary = manifest["config"]["vocab_size"]
            output_queue_slots = limits.output_queue_tokens
        except (AttributeError, KeyError, TypeError):
            return "capture cannot verify the coordinator vocabulary and output queue"
        config = budget.config
        if (type(vocabulary) is not int or type(output_queue_slots) is not int
                or vocabulary != config.vocabulary_size
                or output_queue_slots != config.output_queue_slots
                or output_queue_slots > 16):
            return "capture budget differs from the actual coordinator vocabulary or output queue"
        status = getattr(coordinator.model, "supervision_status", None)
        if not callable(status):
            return "capture cleanup requires the supervised CPU operation tracker"
        try:
            snapshot = status()
        except BaseException:
            return "capture cleanup status is unavailable"
        if (type(snapshot) is not dict
                or type(snapshot.get("active_compute")) is not bool):
            return "capture cleanup status is malformed"
        return None

    def _capture_cleanup_tasks(self, slot, extra=()):
        tasks = set(task for task in extra if task is not None)
        for name in ("cleanup_task", "capture_cleanup_task"):
            task = slot.get(name)
            if task is None:
                continue
            descendants = _pending_task_descendants((task,))
            failed = task.done() and (task.cancelled() or task.exception() is not None)
            if not task.done() or descendants or failed:
                tasks.add(task)
                tasks.update(descendants)
        return tuple(tasks)

    def _generate_resource_tasks(self, slot):
        tasks = set()
        for name in ("cleanup_task", "context_release_task",
                     "capture_cleanup_task"):
            task = slot.get(name)
            if task is not None:
                tasks.add(task)
        tasks.update(slot.get("admission_cleanup_tasks", ()))
        tasks.update(_pending_task_descendants(tasks))
        return tuple(tasks)

    def _generate_tasks_succeeded(self, slot):
        for task in self._generate_resource_tasks(slot):
            if not task.done() or task.cancelled():
                return False
            try:
                if task.exception() is not None:
                    return False
            except asyncio.CancelledError:
                return False
        return True

    @staticmethod
    async def _wait_generate_owned_tasks(tasks, producer_tasks):
        pending = list(tasks)
        visited = set()
        while pending:
            task = pending.pop()
            if task in visited:
                continue
            visited.add(task)
            if not task.done():
                await asyncio.wait((task,), return_when=asyncio.ALL_COMPLETED)
            if task.cancelled():
                if task in producer_tasks:
                    continue
                raise SecureTransportError(
                    "Generate cleanup dependency was cancelled before confirmation")
            try:
                error = task.exception()
            except asyncio.CancelledError:
                if task in producer_tasks:
                    continue
                raise SecureTransportError(
                    "Generate cleanup dependency was cancelled before confirmation")
            if error is None:
                continue
            if isinstance(error, SecureTaskPending):
                pending.extend(error.tasks)
                continue
            raise error

    @staticmethod
    def _generate_owner_confirmed(slot):
        return (slot.get("resource_cleanup_confirmed") is True
                and slot.get("authorization_closed") is True)

    @staticmethod
    def _capture_refusal_proves_no_submission(slot):
        return (
            slot.get("known_pre_admission_capture_capacity_refusal") is True
            and slot.get("capture_submission_attempted") is not True
            and slot.get("handle") is None
            and slot.get("capture_lease") is None
            and slot.get("cleanup_task") is None
            and slot.get("capture_cleanup_task") is None
            and slot.get("retained") is not True
            and slot.get("authorization_transferred") is not True
            and not slot.get("admission_cleanup_tasks")
            and not slot.get("admission_pending_tasks")
            and not slot.get("pending_cleanup_tasks")
            and slot.get("pending_cleanup_discovery_unconfirmed") is not True
        )

    async def _generate_failure_cache_may_exist(self, slot):
        if not self._capture_refusal_proves_no_submission(slot):
            return True
        cleanup = slot.get("context_release_task")
        if cleanup is None:
            return True
        try:
            await _await_task_bounded(
                cleanup,
                grace=_secure_transport.MAX_CANCELLATION_GRACE_SECONDS,
                message="pre-admission context cleanup remains pending")
        except asyncio.CancelledError:
            return True
        except Exception:
            return True
        if slot.get("context_release_task") is not cleanup:
            return True
        return not self._capture_refusal_proves_no_submission(slot)

    def _mark_capture_capacity_refusal(self, slot):
        if slot.get("known_pre_admission_capture_capacity_refusal") is True:
            return
        slot["known_pre_admission_capture_capacity_refusal"] = True
        self.service.counters["rejected_requests"] += 1

    def _retain_generate_pending_tasks(self, slot, tasks):
        roots = set(tasks)
        tracked = slot.setdefault("pending_cleanup_tasks", set())
        root_set = slot.setdefault("pending_cleanup_roots", set())
        watched = slot.setdefault("pending_cleanup_discovery_tasks", set())
        root_set.update(roots)
        changed = slot.setdefault("pending_cleanup_tasks_changed", asyncio.Event())

        def discover_completed(task):
            try:
                descendants = _pending_task_descendants((task,))
                root_set.update(descendants)
                for descendant in descendants:
                    retain(descendant)
            except BaseException:
                slot["pending_cleanup_discovery_unconfirmed"] = True
                self.pending_tasks.add(task)
                self.runtime_owner.pending_tasks.add(task)
                _retain_tasks((task,))
                self._mark_unavailable()
                return
            self.pending_tasks.discard(task)
            self.runtime_owner.pending_tasks.discard(task)

        def retain(task):
            tracked.add(task)
            changed.set()
            if task not in watched:
                watched.add(task)
                try:
                    task.add_done_callback(discover_completed)
                except RuntimeError:
                    slot["pending_cleanup_discovery_unconfirmed"] = True
                    self.pending_tasks.add(task)
                    self.runtime_owner.pending_tasks.add(task)
                    _retain_tasks((task,))
                    self._mark_unavailable()
                    return
            if task.done():
                return
            self.pending_tasks.add(task)
            self.runtime_owner.pending_tasks.add(task)
            _retain_tasks((task,))

        self._retain_unreclaimed_slot(slot, slot.get("trusted_context"))
        self._mark_unavailable()
        for task in roots:
            retain(task)

        existing_monitor = slot.get("pending_cleanup_monitor_task")
        if existing_monitor is not None and not existing_monitor.done():
            for task in roots:
                retain(task)
            return

        async def retain_late_descendants(frontier):
            visited = set()
            while frontier or root_set - visited:
                frontier.update(root_set - visited)
                live = tuple(task for task in frontier if not task.done())
                if live:
                    changed.clear()
                    changed_waiter = asyncio.create_task(changed.wait())
                    try:
                        await asyncio.wait(
                            (*live, changed_waiter),
                            return_when=asyncio.FIRST_COMPLETED)
                    finally:
                        if not changed_waiter.done():
                            changed_waiter.cancel()
                        await asyncio.gather(
                            changed_waiter, return_exceptions=True)
                completed = {task for task in frontier if task.done()}
                if not completed:
                    continue
                descendants = set(_pending_task_descendants(completed))
                root_set.update(descendants)
                for task in descendants:
                    retain(task)
                visited.update(completed)
                frontier.difference_update(completed)
                frontier.update(descendants - visited)

        def monitor_done(task):
            if (not task.cancelled()
                    or slot.get("pending_cleanup_monitor_task") is not task):
                return
            restarts = slot.get("pending_cleanup_monitor_restarts", 0)
            if restarts >= 1:
                slot["pending_cleanup_monitor_restart_exhausted"] = True
                self._mark_unavailable()
                return
            slot["pending_cleanup_monitor_restarts"] = restarts + 1
            loop = task.get_loop()
            if loop.is_closed() or not loop.is_running():
                slot["pending_cleanup_monitor_restart_exhausted"] = True
                self._mark_unavailable()
                return
            coroutine = retain_late_descendants(set(root_set))
            try:
                replacement = loop.create_task(coroutine)
            except RuntimeError:
                coroutine.close()
                slot["pending_cleanup_monitor_restart_exhausted"] = True
                self._mark_unavailable()
                return
            slot["pending_cleanup_monitor_task"] = replacement
            retain(replacement)
            replacement.add_done_callback(monitor_done)

        monitor = asyncio.create_task(retain_late_descendants(set(roots)))
        slot["pending_cleanup_monitor_task"] = monitor
        retain(monitor)
        monitor.add_done_callback(monitor_done)

    def _retain_generate_authorization_owner(self, authorization, slot):
        existing = slot.get("authorization_owner_task")
        if existing is not None:
            return existing
        slot["authorization"] = authorization

        async def close_after_resources():
            try:
                while True:
                    tasks = self._generate_resource_tasks(slot)
                    if tasks:
                        await _wait_owned_tasks(tasks)
                    current = self._generate_resource_tasks(slot)
                    if set(current) == set(tasks):
                        break
                resource_tasks = self._generate_resource_tasks(slot)
                if not self._generate_tasks_succeeded(slot):
                    pending = set()
                    for task in resource_tasks:
                        try:
                            error = task.exception() if task.done() else None
                        except asyncio.CancelledError:
                            error = None
                        if isinstance(error, SecureTaskPending):
                            pending.add(task)
                            pending.update(error.tasks)
                    if pending:
                        self._retain_generate_pending_tasks(slot, pending)
                    else:
                        self._retain_unreclaimed_slot(
                            slot, slot.get("trusted_context"))
                        self._mark_unavailable()
                    return
                known_no_admission = (
                    slot.get("known_pre_admission_capacity_rejection") is True)
                if (slot.get("capture_submission_attempted")
                        and ((slot.get("handle") is None and not known_no_admission)
                             or (slot.get("handle") is not None
                                 and slot.get("session_cleanup_confirmed") is not True))):
                    self._retain_unreclaimed_slot(
                        slot, slot.get("trusted_context"))
                    self._mark_unavailable()
                    return
                lease = slot.get("capture_lease")
                if lease is not None:
                    if slot.get("capture_write_reference_cleanup_unconfirmed"):
                        self._retain_unreclaimed_slot(slot, slot.get("trusted_context"))
                        self._mark_unavailable()
                        return
                    handle = slot.get("handle")
                    if handle is None:
                        if (slot.get("capture_submission_attempted")
                                and not known_no_admission):
                            self._retain_unreclaimed_slot(
                                slot, slot.get("trusted_context"))
                            self._mark_unavailable()
                            return
                    else:
                        reclaim = getattr(handle, "reclaim_capture_buffers", None)
                        if (not callable(reclaim)
                                or await _maybe_await(reclaim()) is not True):
                            self._retain_unreclaimed_slot(
                                slot, slot.get("trusted_context"))
                            self._mark_unavailable()
                            return
                    slot["capture_buffers_reclaimed"] = True

                trusted_context = slot.get("trusted_context")
                release = getattr(self.request_context_factory, "release", None)
                if (trusted_context is not None and callable(release)
                        and not slot.get("context_factory_released")):
                    await _maybe_await(release(trusted_context))
                    slot["context_factory_released"] = True

                if slot.get("authorization_close_attempted"):
                    if not slot.get("authorization_closed"):
                        self._retain_unreclaimed_slot(slot, trusted_context)
                        self._mark_unavailable()
                        return
                else:
                    slot["authorization_close_attempted"] = True
                    await _maybe_await(authorization.close())
                    slot["authorization_closed"] = True

                if lease is not None:
                    if not slot.get("capture_buffers_reclaimed"):
                        self._retain_unreclaimed_slot(slot, trusted_context)
                        self._mark_unavailable()
                        return
                    self._capture_lease_released(slot)
                slot["trusted_context"] = None
                slot["authorization"] = None
                slot["resource_cleanup_confirmed"] = True
                slot["retained"] = False
                self._release_generate_slot(slot, service=True)
                self._unreclaimed_generate_slots = [
                    existing for existing in self._unreclaimed_generate_slots
                    if existing is not slot]
            except SecureTaskPending as error:
                self._retain_generate_pending_tasks(slot, error.tasks)
            except BaseException:
                self._retain_unreclaimed_slot(slot, slot.get("trusted_context"))
                self._mark_unavailable()

        owner = asyncio.create_task(close_after_resources())
        slot["authorization_owner_task"] = owner
        self.pending_tasks.add(owner)
        self.runtime_owner.pending_tasks.add(owner)
        owner.add_done_callback(self.pending_tasks.discard)
        owner.add_done_callback(self.runtime_owner.pending_tasks.discard)
        _retain_tasks((owner,))
        self._watch_generate_cleanup(owner)
        return owner

    def _retain_unreclaimed_slot(self, slot, trusted_context=None):
        if trusted_context is not None:
            slot["trusted_context"] = trusted_context
        slot["retained"] = True
        slot["resource_cleanup_required"] = True
        slot["resource_cleanup_confirmed"] = False
        if not any(existing is slot for existing in self._unreclaimed_generate_slots):
            self._unreclaimed_generate_slots.append(slot)

    def _capture_lease_released(self, slot):
        lease = slot.get("capture_lease")
        if lease is None:
            return
        budget = slot.get("capture_budget", self.capture_budget)
        if not budget.release(lease, buffers_reclaimed=True):
            self._retain_unreclaimed_slot(slot)
            self._mark_unavailable()
            raise SecureTransportError("capture lease reclamation was not confirmed")
        slot["capture_lease"] = None
        slot["capture_pending"] = False

    def _reserve_capture(self, payload, trusted_context, slot):
        if not payload["capture_logits"]:
            return None
        problem = self._capture_configuration_error()
        if problem is not None:
            raise ServiceRequestError("INVALID_INPUT", problem)
        try:
            lease = self.capture_budget.reserve(trusted_context.request_id)
        except CaptureAdmissionError as error:
            raise ServiceRequestError(
                "CAPACITY_EXHAUSTED", "Owner capture capacity is exhausted") from error
        slot["capture_lease"] = lease
        slot["capture_budget"] = self.capture_budget
        slot["capture_pending"] = True
        slot["resource_cleanup_required"] = True
        slot["resource_cleanup_confirmed"] = False
        return lease

    def _mark_unavailable(self, tasks=()):
        self.unavailable = True
        self.runtime_owner.unavailable = True
        if self.acceptor is not None:
            self.acceptor.pause()
        tasks = tuple(tasks)
        live = tuple(set(task for task in tasks if not task.done())
                     | set(_pending_task_descendants(tasks)))
        for task in live:
            self.pending_tasks.add(task)
            self.runtime_owner.pending_tasks.add(task)
            _retain_tasks((task,))
            task.add_done_callback(self.pending_tasks.discard)
            task.add_done_callback(self.runtime_owner.pending_tasks.discard)
        if live:
            async def retain_descendants():
                await _wait_owned_tasks(live)

            owner = asyncio.create_task(retain_descendants())
            self.pending_tasks.add(owner)
            self.runtime_owner.pending_tasks.add(owner)
            _retain_tasks((owner,))
            owner.add_done_callback(self.pending_tasks.discard)
            owner.add_done_callback(self.runtime_owner.pending_tasks.discard)

    def _release_generate_slot(self, slot, *, service=True):
        if service and slot["service"]:
            self.service.active_streams -= 1
            slot["service"] = False
        if slot["generate"]:
            self.active_generate_streams -= 1
            slot["generate"] = False

    def _generate_cleanup_done(self, slot, task):
        self.service.cleanups.discard(task)
        self.runtime_owner.pending_tasks.discard(task)
        try:
            failure = task.exception()
        except asyncio.CancelledError as error:
            failure = error
        if failure is not None:
            self._retain_unreclaimed_slot(slot)
            self._mark_unavailable(_pending_task_descendants((task,)))
            return

    def _watch_generate_cleanup(self, cleanup):
        async def watch():
            done, pending = await asyncio.wait(
                (cleanup,), timeout=_secure_transport.MAX_CANCELLATION_GRACE_SECONDS,
                return_when=asyncio.ALL_COMPLETED)
            if pending:
                self._mark_unavailable((cleanup,))

        task = asyncio.create_task(watch())
        _retain_tasks((task,))

    def _validate_context(self, value, authorization, request_deadline):
        if type(value) is not TrustedRequestContext:
            raise SecureTransportError(
                "Generate context factory must return a validated TrustedRequestContext")
        if value.authorization is not authorization:
            raise SecureTransportError(
                "trusted request context is not bound to this consumer authorization")
        fields = ((value.tenant_account_id, "acct_"), (value.request_id, "req_"),
                  (value.session_id, "ses_"), (value.route_id, "route_"))
        if any(type(identifier) is not str or not _TYPED_CONTEXT_ID.fullmatch(identifier)
               or not identifier.startswith(prefix) for identifier, prefix in fields):
            raise SecureTransportError("trusted request context identifiers are malformed")
        if (type(value.coordinator_boot_id) is not str
                or not _CONTEXT_BOOT_ID.fullmatch(value.coordinator_boot_id)
                or type(value.route_epoch) is not int or value.route_epoch != 1
                or type(value.attempt) is not int or value.attempt != 1):
            raise SecureTransportError("trusted request context route is malformed")
        deadline = value.hard_monotonic_deadline
        if (isinstance(deadline, bool) or not isinstance(deadline, (int, float))
                or not math.isfinite(deadline) or deadline <= time.monotonic()
                or deadline > request_deadline):
            raise SecureTransportError("trusted request context deadline is invalid")
        try:
            value.assert_data_live()
            remaining = value.remaining_seconds()
        except Exception:
            raise AuthorizationRejected("consumer request authorization is no longer live") from None
        if (isinstance(remaining, bool) or not isinstance(remaining, (int, float))
                or not math.isfinite(remaining) or remaining <= 0):
            raise AuthorizationRejected("consumer request authorization has expired")
        return min(float(remaining), float(request_deadline - time.monotonic()))

    async def _authorize(self, method, data, payload, context):
        authorization = None
        self._check_runtime_guard()
        if self.unavailable:
            import grpc
            await _abort(context, grpc.StatusCode.UNAVAILABLE,
                         "Secure coordinator service is unavailable")
            raise AuthorizationRejected("secure coordinator service is unavailable")
        try:
            peer_certificate = _peer_certificate_from_auth_context(context)
            metadata, binding, _ = validate_metadata(context.invocation_metadata())
            authorization = await _call_authorize(self.authorizer, COORDINATOR_SERVICE,
                method, payload, metadata, peer_certificate)
            self._check_runtime_guard()
            if authorization.binding_bytes != binding:
                raise AuthorizationRejected("identity adapter binding differs from the request")
            await _assert_live(authorization)
            if (self.acceptor is None
                    or not await self.acceptor.mark_authenticated_peer(context.peer())):
                raise AuthorizationRejected(
                    "TLS connection is not tracked by the bounded acceptor")
            self._check_runtime_guard()
            return authorization
        except asyncio.CancelledError:
            await _close_failed_authorization(authorization, cache_may_exist=False)
            if self.acceptor is not None:
                await self.acceptor.reject_unestablished_peer(context.peer())
            raise
        except Exception as error:
            await _close_failed_authorization(authorization, cache_may_exist=False)
            if self.acceptor is not None:
                await self.acceptor.reject_unestablished_peer(context.peer())
            import grpc
            await _abort(context, _authorization_status(grpc, error),
                         "Peer is not authorized for this coordinator operation")
            raise AuthorizationRejected("coordinator request is not authorized") from None

    async def _unary(self, method, data, context, payload):
        import grpc

        authorization = await self._authorize(method, data, payload, context)
        authorization_transferred = False
        try:
            response = await _run_guarded(self._produce_unary(method, data, context, authorization),
                                      authorization, self._runtime_authorization_watcher(authorization),
                                      timeout=context.time_remaining(),
                                      on_pending=self._mark_unavailable,
                                      failure_cache_may_exist=False)
            self._check_runtime_guard()
            return response
        except SecureTaskPending as error:
            authorization_transferred = error.authorization_transferred
            self._mark_unavailable(error.tasks)
            raise
        except AuthorizationRevoked:
            await _fail_authorization(authorization, cache_may_exist=False)
            await _abort(context, grpc.StatusCode.UNAUTHENTICATED,
                         "Peer authorization is no longer valid")
        except asyncio.CancelledError:
            await _fail_authorization(authorization, cache_may_exist=False)
            raise
        except BaseException:
            await _fail_authorization(authorization, cache_may_exist=False)
            raise
        finally:
            if not authorization_transferred:
                await _maybe_await(authorization.close())

    async def _produce_unary(self, method, data, context, authorization):
        self._check_runtime_guard()
        await _assert_live(authorization)
        self._check_runtime_guard()
        await self._stream_context(context, authorization).send_initial_metadata(((BINDING_METADATA_KEY,
                                               authorization.binding_bytes),))
        self._check_runtime_guard()
        await _assert_live(authorization)
        self._check_runtime_guard()
        response = await self._delegate_unary(
            method, data, self._stream_context(context, authorization))
        self._check_runtime_guard()
        await _assert_live(authorization)
        self._check_runtime_guard()
        await _maybe_await(authorization.complete(response))
        self._check_runtime_guard()
        await _assert_live(authorization)
        self._check_runtime_guard()
        return response

    async def _delegate_unary(self, method, data, context):
        if method == "Describe":
            return await self.service.describe_rpc(data, context)
        return await self.service.tokenize_rpc(data, context)

    async def describe_rpc(self, data, context):
        from .remote_client import decode_json, RemoteError

        try:
            payload = decode_json(data, 64)
            if payload:
                raise RemoteError("INVALID_INPUT", "Describe accepts an empty object")
        except RemoteError as error:
            await self.service._abort(context, error)
            return b""
        return await self._unary("Describe", data, context, payload)

    async def tokenize_rpc(self, data, context):
        from .remote_client import MAX_TOKENIZE_BYTES, decode_json, validate_text, RemoteError

        try:
            payload = decode_json(data, MAX_TOKENIZE_BYTES)
            validate_text(payload)
        except RemoteError as error:
            await self.service._abort(context, error)
            return b""
        return await self._unary("Tokenize", data, context, payload)

    async def generate_rpc(self, data, context):
        from .remote_client import MAX_GENERATE_BYTES, decode_json, validate_generate, RemoteError
        import grpc

        received = time.monotonic()
        try:
            payload = validate_generate(decode_json(data, MAX_GENERATE_BYTES))
        except RemoteError as error:
            await self.service._abort(context, error)
            return
        authorization = await self._authorize("Generate", data, payload, context)
        request_deadline = received + payload["timeout_seconds"]
        rpc_remaining = context.time_remaining()
        if rpc_remaining is not None:
            if (isinstance(rpc_remaining, bool)
                    or not isinstance(rpc_remaining, (int, float))
                    or not math.isfinite(rpc_remaining)):
                await _fail_authorization(authorization, cache_may_exist=False)
                await _maybe_await(authorization.close())
                await self.service._abort(context, RemoteError(
                    "INVALID_INPUT", "Generate transport deadline is invalid"))
                return
            request_deadline = min(request_deadline,
                                   received + max(0.0, float(rpc_remaining)))

        if payload["capture_logits"]:
            problem = self._capture_configuration_error()
            if problem is not None:
                from .remote_client import RemoteError

                try:
                    await _fail_authorization(authorization, cache_may_exist=False)
                    await self.service._abort(
                        context, RemoteError("INVALID_INPUT", problem))
                finally:
                    await _maybe_await(authorization.close())
                return

        # Slot ownership begins synchronously after authorization and before the
        # request-context factory or initial-metadata operation can suspend.
        if (self.active_generate_streams >= self.max_generate_streams
                or self.service.active_streams >= self.service.max_streams):
            self.service.counters["rejected_requests"] += 1

            rejection_state = {}

            async def reject_capacity():
                await self._set_capacity_rejection_marker(
                    context, authorization, send_binding=True)
                await _abort(context, grpc.StatusCode.RESOURCE_EXHAUSTED,
                             "Generate stream capacity exhausted")

            def retain_rejection_tasks(tasks):
                self._capacity_rejection_owner(
                    authorization, rejection_state, tasks,
                    start_owner=False)

            async def close_rejection_authorization():
                owner = self._capacity_rejection_owner(
                    authorization, rejection_state)
                try:
                    await _await_task_bounded(
                        owner,
                        grace=_secure_transport.MAX_CANCELLATION_GRACE_SECONDS,
                        message="capacity rejection authorization cleanup remains pending")
                except SecureTaskPending as pending:
                    self._mark_unavailable()
                    pending.authorization_transferred = True
                    raise
                except asyncio.CancelledError:
                    if not owner.done():
                        self._mark_unavailable()
                    raise

            try:
                await _run_guarded(
                    reject_capacity(), authorization,
                    self._runtime_authorization_watcher(authorization),
                    timeout=max(0.0, request_deadline - time.monotonic()),
                    absolute_deadline=request_deadline,
                    cancel_grace_seconds=(
                        _secure_transport.MAX_CANCELLATION_GRACE_SECONDS),
                    on_pending=retain_rejection_tasks,
                    failure_cache_may_exist=False,
                    close_authorization_on_pending=False)
            except SecureTaskPending as error:
                self._capacity_rejection_owner(
                    authorization, rejection_state, error.tasks)
                raise
            except BaseException:
                await close_rejection_authorization()
                raise
            else:
                await close_rejection_authorization()
            return
        self.active_generate_streams += 1
        self.service.active_streams += 1
        slot = {"generate": True, "service": True, "entered": False,
                "retained": False, "cleanup_task": None,
                "capture_lease": None, "capture_pending": False,
                "trusted_context": None, "context_release_task": None,
                "capture_cleanup_task": None, "authorization_transferred": False,
                "resource_cleanup_required": False,
                "resource_cleanup_confirmed": True,
                "admission_cleanup_tasks": set(),
                "admission_pending_tasks": set(),
                "pending_cleanup_tasks": set(),
                "pending_cleanup_tasks_changed": asyncio.Event(),
                "pending_cleanup_monitor_task": None,
                "authorization_owner_task": None,
                "authorization_close_attempted": False,
                "authorization_closed": False,
                "capture_buffers_reclaimed": False,
                "known_pre_admission_capacity_rejection": False,
                "known_pre_admission_capture_capacity_refusal": False,
                "context_factory_released": False,
                "session_cleanup_confirmed": False,
                "producer_wrapper_tasks": set()}

        def retain_pending(tasks):
            self._mark_unavailable(tasks)
            slot["retained"] = True
            slot["resource_cleanup_required"] = True
            slot["resource_cleanup_confirmed"] = False
            slot["authorization_transferred"] = True
            slot["admission_pending_tasks"].update(tasks)
            if slot["admission_cleanup_tasks"]:
                return

            async def release_after_safe_exit():
                while True:
                    owned = tuple(slot["admission_pending_tasks"])
                    await _wait_owned_tasks(owned)
                    if set(owned) == slot["admission_pending_tasks"]:
                        break
                failed = any(
                    task.cancelled() or task.exception() is not None
                    for task in owned)
                if failed:
                    self._retain_unreclaimed_slot(slot, slot.get("trusted_context"))
                    self._mark_unavailable()
                    return
                slot["admission_cleanup_confirmed"] = True

            cleanup = asyncio.create_task(release_after_safe_exit())
            slot["admission_cleanup_tasks"].add(cleanup)
            self._mark_unavailable((cleanup,))

        authorization_transferred = False
        request_cancelled = False
        try:
            remaining = request_deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("Generate request deadline expired before admission")
            await _run_guarded(
                self._produce_generate(payload, context, request_deadline,
                                       authorization, slot),
                authorization, self._runtime_authorization_watcher(authorization),
                timeout=remaining, absolute_deadline=request_deadline,
                cancel_grace_seconds=_secure_transport.MAX_CANCELLATION_GRACE_SECONDS,
                on_pending=retain_pending, failure_cache_may_exist=True,
                close_authorization_on_pending=False)
        except SecureTaskPending as error:
            authorization_transferred = error.authorization_transferred
            retain_pending(error.tasks)
            raise
        except AuthorizationRevoked:
            await _fail_authorization(
                authorization,
                cache_may_exist=await self._generate_failure_cache_may_exist(slot))
            await _abort(context, grpc.StatusCode.UNAUTHENTICATED,
                         "Peer authorization is no longer valid")
        except asyncio.CancelledError:
            request_cancelled = True
            await _fail_authorization(
                authorization,
                cache_may_exist=await self._generate_failure_cache_may_exist(slot))
            raise
        except BaseException:
            await _fail_authorization(
                authorization,
                cache_may_exist=await self._generate_failure_cache_may_exist(slot))
            raise
        finally:
            if slot["authorization_transferred"]:
                authorization_transferred = True
            owner = self._retain_generate_authorization_owner(authorization, slot)
            if not authorization_transferred:
                try:
                    await _await_task_bounded(
                        owner, grace=_secure_transport.MAX_CANCELLATION_GRACE_SECONDS,
                        message="Generate cleanup remains pending")
                except SecureTaskPending as pending:
                    if owner.done():
                        await owner
                    if not (owner.done()
                            and self._generate_owner_confirmed(slot)):
                        slot["authorization_transferred"] = True
                        self._retain_unreclaimed_slot(
                            slot, slot.get("trusted_context"))
                        pending_tasks = set(pending.tasks)
                        pending_tasks.add(owner)
                        pending_tasks.update(slot.get("pending_cleanup_tasks", ()))
                        self._mark_unavailable(pending_tasks)
                        if not request_cancelled:
                            raise SecureTaskPending(
                                tuple(pending_tasks),
                                "Generate cleanup was not confirmed")
                except asyncio.CancelledError:
                    if not self._generate_owner_confirmed(slot):
                        slot["authorization_transferred"] = True
                        self._retain_unreclaimed_slot(
                            slot, slot.get("trusted_context"))
                        self._mark_unavailable((owner,))
                    raise
                if (not request_cancelled
                        and not self._generate_owner_confirmed(slot)):
                    slot["authorization_transferred"] = True
                    self._retain_unreclaimed_slot(
                        slot, slot.get("trusted_context"))
                    pending_tasks = set(slot.get("pending_cleanup_tasks", ()))
                    pending_tasks.add(owner)
                    self._mark_unavailable(pending_tasks)
                    raise SecureTaskPending(
                        tuple(pending_tasks), "Generate cleanup was not confirmed")

    async def _produce_generate(self, payload, context, request_deadline,
                                authorization, slot):
        current_task = asyncio.current_task()
        if current_task is not None:
            slot.setdefault("producer_wrapper_tasks", set()).add(current_task)
        create_with_deadline = getattr(
            self.request_context_factory, "create_with_deadline", None)
        self._check_runtime_guard()
        if callable(create_with_deadline):
            trusted_context = await _maybe_await(create_with_deadline(
                authorization, payload, absolute_deadline=request_deadline))
        else:
            trusted_context = await _maybe_await(self.request_context_factory(
                authorization, payload))
        slot["trusted_context"] = trusted_context
        slot["resource_cleanup_required"] = True
        slot["resource_cleanup_confirmed"] = False
        release_deferred = False
        try:
            self._check_runtime_guard()
            context_lifetime = self._validate_context(
                trusted_context, authorization, request_deadline)
            await _assert_live(authorization)
            trusted_context.assert_data_live()
            wrapped = self._stream_context(context, authorization)

            async def emit_initial_metadata():
                await _assert_live(authorization)
                trusted_context.assert_data_live()
                await wrapped.send_initial_metadata(((BINDING_METADATA_KEY,
                                                       authorization.binding_bytes),))
                await _assert_live(authorization)
                trusted_context.assert_data_live()

            await _run_guarded(emit_initial_metadata(), authorization,
                self._context_authorization_watcher(authorization, trusted_context),
                timeout=context_lifetime,
                absolute_deadline=min(request_deadline,
                                      trusted_context.hard_monotonic_deadline),
                cancel_grace_seconds=_secure_transport.MAX_CANCELLATION_GRACE_SECONDS,
                on_pending=self._mark_unavailable, failure_cache_may_exist=True,
                close_authorization_on_pending=False)
            slot["entered"] = True
            if payload["capture_logits"]:
                try:
                    self._reserve_capture(payload, trusted_context, slot)
                except ServiceRequestError as error:
                    from .remote_client import RemoteError

                    if error.code == "CAPACITY_EXHAUSTED":
                        self._mark_capture_capacity_refusal(slot)
                        trusted_context.assert_data_live()
                        await self._set_capacity_rejection_marker(
                            wrapped, authorization, send_binding=False)
                    await self.service._abort(
                        context, RemoteError(error.code, error.message))
                    await _fail_authorization(authorization, cache_may_exist=False)
                    return
            await _run_guarded(
                self._generate_with_context(payload, wrapped, request_deadline,
                    trusted_context, authorization, slot, context_lifetime),
                authorization, self._context_authorization_watcher(authorization,
                    trusted_context), timeout=min(context_lifetime,
                        max(0.0, request_deadline - time.monotonic())),
                absolute_deadline=min(request_deadline,
                                      trusted_context.hard_monotonic_deadline),
                cancel_grace_seconds=_secure_transport.MAX_CANCELLATION_GRACE_SECONDS,
                on_pending=self._mark_unavailable, failure_cache_may_exist=True,
                close_authorization_on_pending=False)
        except SecureTaskPending as error:
            release_deferred = True
            try:
                owned = self._capture_cleanup_tasks(slot, error.tasks)
                cleanup = self._defer_generate_resources(
                    trusted_context, owned, slot)
                error.tasks = tuple(set(error.tasks) | {cleanup})
                error.authorization_transferred = True
                slot["authorization_transferred"] = True
            except BaseException:
                self._retain_unreclaimed_slot(slot, trusted_context)
                self._mark_unavailable(error.tasks)
                raise
            raise
        finally:
            if not release_deferred:
                owned = self._capture_cleanup_tasks(slot)
                self._defer_generate_resources(trusted_context, owned, slot)

    def _defer_generate_resources(self, trusted_context, tasks, slot):
        owned = tuple(set(tasks) | set(self._capture_cleanup_tasks(slot)))
        producer_tasks = set(slot.get("producer_wrapper_tasks", ()))
        slot["resource_cleanup_required"] = True
        slot["resource_cleanup_confirmed"] = False
        lease = slot.get("capture_lease")
        if lease is not None and not slot.get("capture_lease_pending"):
            # False confirms that bytes remain charged in cleanup-pending state.
            # True here would mean a lease had already been released.
            if slot["capture_budget"].release(
                    lease, buffers_reclaimed=False) is not False:
                self._retain_unreclaimed_slot(slot, trusted_context)
                self._mark_unavailable()
                raise SecureTransportError(
                    "capture lease could not enter cleanup-pending state")
            slot["capture_lease_pending"] = True

        async def reclaim_after_owned_tasks():
            try:
                await self._wait_generate_owned_tasks(owned, producer_tasks)
            except BaseException:
                self._retain_unreclaimed_slot(slot, trusted_context)
                self._mark_unavailable()
                raise

        cleanup = asyncio.create_task(reclaim_after_owned_tasks())
        slot["context_release_task"] = cleanup
        if lease is not None:
            slot["capture_cleanup_task"] = cleanup
        self.pending_tasks.add(cleanup)
        self.runtime_owner.pending_tasks.add(cleanup)
        cleanup.add_done_callback(self.pending_tasks.discard)
        cleanup.add_done_callback(self.runtime_owner.pending_tasks.discard)
        _retain_tasks((cleanup,))
        self._watch_generate_cleanup(cleanup)
        return cleanup

    def _context_authorization_watcher(self, authorization, trusted_context):
        async def watch(_authorization):
            remaining = trusted_context.remaining_seconds()
            invalidation = asyncio.create_task(
                _maybe_await(self.authorization_watcher(authorization)))
            expiry = asyncio.create_task(asyncio.sleep(remaining))
            runtime = asyncio.create_task(self._runtime_async_event.wait())
            try:
                done, _ = await asyncio.wait((invalidation, expiry, runtime),
                    return_when=asyncio.FIRST_COMPLETED)
                if runtime in done:
                    raise AuthorizationRevoked("coordinator runtime was invalidated")
                if expiry in done:
                    raise AuthorizationRevoked("trusted request context expired")
                await invalidation
                raise AuthorizationRevoked("consumer authorization was revoked")
            finally:
                await _cancel_tasks_bounded((invalidation, expiry, runtime),
                    message="consumer authorization watcher did not stop")
        return watch

    async def _generate_with_context(self, request, context, request_deadline,
                                     trusted_request_context, authorization, slot,
                                     context_lifetime):
        from .coordinator import CoordinatorError
        import torch

        service = self.service
        current_task = asyncio.current_task()
        if current_task is not None:
            slot.setdefault("producer_wrapper_tasks", set()).add(current_task)
        handle = None
        finished = False
        event = message = logits_tensor = logits_values = input_tensor = None
        result = metrics = terminal = None
        try:
            self._check_runtime_guard()
            trusted_request_context.assert_data_live()
            deadline = min(request_deadline,
                           time.monotonic() + context_lifetime,
                           trusted_request_context.hard_monotonic_deadline)
            if deadline <= time.monotonic():
                raise ServiceRequestError("TIMEOUT", "Request deadline expired before admission")
            trusted_request_context.assert_data_live()
            self._check_runtime_guard()
            input_tensor = torch.tensor(
                [request["input_ids"]], dtype=torch.long)
            self._check_runtime_guard()
            slot["capture_submission_attempted"] = True
            try:
                handle = service.coordinator.submit(
                    input_tensor, request["new_tokens"],
                    forced_tokens=request.get("forced_tokens"),
                    capture_logits=request["capture_logits"],
                    timeout_seconds=deadline-time.monotonic(),
                    trusted_request_context=trusted_request_context)
            except CoordinatorError as error:
                if _known_pre_admission_capacity_error(service.coordinator, error):
                    slot["known_pre_admission_capacity_rejection"] = True
                raise
            finally:
                input_tensor = None
            slot["handle"] = handle
            self._check_runtime_guard()
            try:
                async for event in handle:
                    self._check_runtime_guard()
                    message = {"type": "token", "session_id": event.session_id,
                               "index": event.index, "token_id": event.token_id,
                               "position": event.position, "sequence": event.sequence}
                    logits_tensor = event.logits
                    if request["capture_logits"] and logits_tensor is None:
                        raise ServiceRequestError(
                            "EXECUTION_FAILED", "capture event omitted last-position logits")
                    if not request["capture_logits"] and logits_tensor is not None:
                        raise ServiceRequestError(
                            "EXECUTION_FAILED", "noncapture event unexpectedly contains logits")
                    if logits_tensor is not None:
                        vocabulary = service.coordinator.manifest["config"]["vocab_size"]
                        if (tuple(logits_tensor.shape) != (1, vocabulary)
                                or logits_tensor.dtype is not torch.float32
                                or logits_tensor.numel() != vocabulary
                                or not bool(torch.isfinite(logits_tensor).all())):
                            raise ServiceRequestError(
                                "EXECUTION_FAILED", "capture event shape or values are invalid")
                        logits_values = logits_tensor.reshape(-1).tolist()
                        message["logits"] = logits_values
                    await service._write(context, message, deadline)
                    event = message = logits_tensor = logits_values = None
            except CoordinatorError:
                # The terminal result carries the scheduler's sanitized failure.
                pass
            result = await handle.result()
            self._check_runtime_guard()
            metrics = service.metrics[handle.session_id].result(result)
            metrics["service_elapsed_ms"] = 1000 * (time.monotonic() -
                (request_deadline - request["timeout_seconds"]))
            terminal = {"type": "result", "session_id": result.session_id,
                        "status": result.status, "token_ids": list(result.token_ids),
                        "cleanup_complete": result.cleanup_complete, "error": result.error,
                        "error_code": result.error_code, "metrics": metrics}
            self._check_runtime_guard()
            await service._write(context, terminal, deadline)
            self._check_runtime_guard()
            await _assert_live(authorization)
            self._check_runtime_guard()
            if terminal["status"] == "completed":
                await _maybe_await(authorization.complete(terminal))
                self._check_runtime_guard()
            else:
                await _fail_authorization(authorization, cache_may_exist=True)
            finished = True
        except (ServiceRequestError, CoordinatorError) as error:
            service.counters["rejected_requests"] += int(handle is None)
            from .remote_client import RemoteError
            known_no_admission = (
                handle is None
                and slot.get("known_pre_admission_capacity_rejection") is True)
            code = error.code
            if code == "CAPACITY_EXHAUSTED" and not known_no_admission:
                code = "EXECUTION_FAILED"
            elif known_no_admission:
                trusted_request_context.assert_data_live()
                await self._set_capacity_rejection_marker(
                    context, authorization, send_binding=False)
            await service._abort(context, RemoteError(code, error.message))
            await _fail_authorization(
                authorization,
                cache_may_exist=(handle is not None or
                                 (slot.get("capture_submission_attempted")
                                  and not known_no_admission)))
        except TimeoutError:
            service.counters["transport_stalls"] += 1
            from .remote_client import RemoteError
            await service._abort(context, RemoteError(
                "TIMEOUT", "Output transport or request deadline expired"))
            await _fail_authorization(authorization, cache_may_exist=(handle is not None))
        except asyncio.CancelledError:
            service.counters["disconnected_streams"] += 1
            raise
        except BaseException as error:
            if (request["capture_logits"]
                    and getattr(error, "capture_reference_cleanup_unconfirmed", False)):
                slot["capture_write_reference_cleanup_unconfirmed"] = True
            raise
        finally:
            event = message = logits_tensor = logits_values = input_tensor = None
            result = metrics = terminal = None
            if handle is not None:
                async def finish_and_confirm_session():
                    try:
                        await service._finish(
                            handle, cancel=not finished,
                            release_active_stream=False)
                    except SecureTaskPending as error:
                        await _wait_owned_tasks(error.tasks)
                    result = await _maybe_await(handle.result())
                    if getattr(result, "cleanup_complete", None) is not True:
                        raise SecureTransportError(
                            "Generate session cleanup was not confirmed by its handle")
                    slot["session_cleanup_confirmed"] = True
                    return result

                cleanup = asyncio.create_task(finish_and_confirm_session())
                slot["cleanup_task"] = cleanup
                service.cleanups.add(cleanup)
                self.runtime_owner.pending_tasks.add(cleanup)
                cleanup.add_done_callback(lambda task: self._generate_cleanup_done(slot, task))
                self._watch_generate_cleanup(cleanup)
                try:
                    await asyncio.shield(cleanup)
                except asyncio.CancelledError:
                    # The cleanup task remains owned and its slot stays charged
                    # until its callback confirms successful completion.
                    raise


class ServiceRequestError(Exception):
    def __init__(self, code, message):
        self.code, self.message = code, message
        super().__init__(message)


async def create_secure_coordinator_server(service, *, listen_endpoint,
                                           allowed_listen_addresses, server_identity,
                                           client_ca_pem, authorizer,
                                           authorization_watcher, request_context_factory,
                                           connection_controller, listener_id,
                                           listener_slots, acceptor_directory,
                                           capture_budget=None,
                                           max_generate_streams=COORDINATOR_MAX_GENERATE_STREAMS,
                                           runtime_guard=None):
    """Start the explicit mTLS coordinator service (no public or insecure bind)."""
    import grpc
    from .protocol.secure_transport import (
        LocalTlsIdentity, SecureServerHandle, _maybe_await, parse_fixed_ipv4_endpoint)
    from .protocol.secure_acceptor import (
        SecureAcceptor, new_private_socket_path, validate_private_unix_directory)

    parse_fixed_ipv4_endpoint(listen_endpoint, allowed_listen_addresses, listen=True)
    if not isinstance(server_identity, LocalTlsIdentity):
        raise ValueError("role-specific coordinator TLS identity is required")
    if not isinstance(client_ca_pem, bytes) or not client_ca_pem:
        raise ValueError("pinned client cohort CA roots are required")
    if (connection_controller is None
            or not callable(getattr(connection_controller, "reserve_listener", None))
            or not callable(getattr(connection_controller, "reserve_pending", None))):
        raise ValueError("secure coordinator service requires node connection accounting")
    if type(listener_slots) is not int or listener_slots not in (1, 2):
        raise ValueError("secure coordinator listener must explicitly select one or two connection slots")
    private_directory = validate_private_unix_directory(acceptor_directory)
    backend_path = new_private_socket_path(private_directory,
        name=f"coordinator-{uuid.uuid4().hex[:12]}.sock")
    secure_service = SecureCoordinatorService(service, authorizer=authorizer,
        authorization_watcher=authorization_watcher,
        request_context_factory=request_context_factory,
        capture_budget=capture_budget,
        max_generate_streams=max_generate_streams, runtime_guard=runtime_guard)
    secure_service._bind_owner_loop()
    reservation = await _maybe_await(connection_controller.reserve_listener(
        listener_id, connection_slots=listener_slots, pending_slots=listener_slots))
    if reservation is None or not callable(getattr(reservation, "release", None)):
        raise SecureTransportError("connection controller did not reserve listener capacity")
    server = None
    acceptor = None
    try:
        acceptor = SecureAcceptor(listen_endpoint=listen_endpoint,
            allowed_listen_addresses=allowed_listen_addresses,
            backend_socket_path=backend_path, private_directory=private_directory,
            listener_slots=listener_slots, connection_controller=connection_controller,
            on_unavailable=secure_service._mark_unavailable)
        secure_service.acceptor = acceptor
        server = grpc.aio.server(options=_secure_options(1024 * 1024,
                                                         listener_slots=listener_slots),
            maximum_concurrent_rpcs=COORDINATOR_MAX_CONCURRENT_RPCS)
        server.add_generic_rpc_handlers((grpc.method_handlers_generic_handler(COORDINATOR_SERVICE, {
            "Describe": grpc.unary_unary_rpc_method_handler(secure_service.describe_rpc),
            "Tokenize": grpc.unary_unary_rpc_method_handler(secure_service.tokenize_rpc),
            "Generate": grpc.unary_stream_rpc_method_handler(secure_service.generate_rpc)}),))
        credentials = grpc.ssl_server_credentials(
            ((server_identity.private_key_pem, server_identity.certificate_chain_pem),),
            root_certificates=client_ca_pem, require_client_auth=True)
        backend_port = server.add_secure_port(f"unix:{backend_path}", credentials)
        if not backend_port:
            raise SecureTransportError(
                "C-core refused the private secure coordinator UDS backend")
        await server.start()
        port = await acceptor.start()
        return SecureServerHandle(server, port, reservation,
            secure_service.runtime_owner, acceptor), secure_service
    except BaseException as startup_error:
        if server is None and acceptor is None:
            await _maybe_await(reservation.release())
            raise

        async def cleanup_created_listener():
            errors = []
            if acceptor is not None:
                try:
                    await acceptor.stop()
                except BaseException as error:
                    errors.append(error)
            if server is not None:
                try:
                    await server.stop(0)
                except BaseException as error:
                    errors.append(error)
            if errors:
                raise errors[0]
            await _maybe_await(reservation.release())

        cleanup_task = asyncio.create_task(cleanup_created_listener())
        try:
            from .protocol.secure_transport import _await_task_bounded
            await _await_task_bounded(cleanup_task,
                message="created secure coordinator listener could not confirm startup cleanup")
        except BaseException as cleanup_error:
            _retain_tasks((cleanup_task,))
            if isinstance(cleanup_error, SecureTaskPending):
                raise cleanup_error from startup_error
            raise SecureTaskPending((cleanup_task,),
                "created secure coordinator listener shutdown failed; capacity remains reserved") from startup_error
        raise startup_error
