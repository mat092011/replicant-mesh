"""Trusted Generate cleanup ownership regressions; fakes are unit-only."""

import asyncio
import hashlib
import json
import math
import os
from pathlib import Path
import sys
import time
import types
import unittest
from unittest.mock import patch
import weakref

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from steamboat_runtime.secure_coordinator_service import SecureCoordinatorService, ServiceRequestError
from steamboat_runtime.secure_coordinator_service import _AuthorizedStreamContext
from steamboat_runtime.protocol.secure_transport import (
    AuthorizationRevoked, BINDING_METADATA_KEY, SecureTaskPending,
    SecureTransportError, _run_guarded,
)
from steamboat_runtime.capture_budget import (
    ActiveCaptureLimitError, CaptureBudget, CaptureBudgetConfig,
    MAX_CAPTURE_MESSAGE_BYTES,
)
from steamboat_runtime.coordinator_service import (
    CoordinatorService, _clear_write_error_payload_frames,
)
from steamboat_runtime.remote_client import encode_json


def _canonical_generate_binding(index):
    from steamboat_security.codec import encode_binding

    suffix = f"{index:032x}"
    fields = {
        "binding_version": 1,
        "operation_id": "op_" + suffix,
        "account_id": "acct_" + "1" * 32,
        "device_id": "dev_" + "2" * 32,
        "role": "consumer",
        "credential_epoch": 1,
        "target_device_id": "dev_" + "3" * 32,
        "request_id": "req_" + suffix,
    }
    return encode_binding("steamboat.v1.Coordinator", "Generate", fields)


def _assert_exact_capacity_marker(testcase, metadata, binding):
    testcase.assertEqual(len(metadata), 1)
    key, value = metadata[0]
    testcase.assertEqual(key, "steamboat-capacity-rejection-bin")
    testcase.assertEqual(len(value), 37)
    testcase.assertEqual(value[:5], b"SNCR\x01")
    testcase.assertEqual(value[5:], hashlib.sha256(binding).digest())


class _Authorizer:
    def authorize(self, **_kwargs):
        raise AssertionError("the cleanup ownership unit test does not authorize RPCs")


class _Coordinator:
    manifest = {"config": {"vocab_size": 32000}}
    limits = types.SimpleNamespace(
        output_queue_tokens=16, output_stall_timeout_seconds=1)

    class _Model:
        def supervision_status(self):
            return {"active_compute": False}

    model = _Model()

    def submit(self, input_ids, new_tokens, *, trusted_request_context=None):
        raise AssertionError("the cleanup ownership unit test does not submit inference")


class _Service:
    max_streams = 40

    def __init__(self):
        self.coordinator = _Coordinator()
        self.active_streams = 0
        self.cleanups = set()
        self.max_streams = 40
        self.counters = {"rejected_requests": 0}
        self.aborts = []

    async def _abort(self, context, error):
        self.aborts.append(error)
        await context.abort(None, error.message)


class _ContextFactory:
    def __init__(self):
        self.created = 0
        self.released = []
        self.released_event = asyncio.Event()
        self.release_started = asyncio.Event()
        self.release_gate = None
        self.release_error = None
        self.context = _RequestContext()

    async def __call__(self, _authorization, _payload):
        self.created += 1
        return self.context

    async def release(self, context):
        if self.release_gate is not None:
            self.release_started.set()
            await self.release_gate.wait()
        if self.release_error is not None:
            raise self.release_error
        self.released.append(context)
        self.released_event.set()


class _DeadlineContextFactory(_ContextFactory):
    def __init__(self):
        super().__init__()
        self.deadline_calls = []

    async def create_with_deadline(self, authorization, payload, *, absolute_deadline):
        self.deadline_calls.append((authorization, payload, absolute_deadline))
        return self.context


class _RequestContext:
    def __init__(self):
        self.hard_monotonic_deadline = time.monotonic() + 10
        self.request_id = "req_" + "1" * 32

    def assert_data_live(self):
        return None


class _Authorization:
    binding_bytes = b"unit-test-binding"

    def __init__(self):
        self.closed = asyncio.Event()
        self.deadline_monotonic = time.monotonic() + 30
        self.close_started = asyncio.Event()
        self.close_gate = None
        self.close_error = None
        self.close_count = 0
        self.failed = False

    def assert_live(self):
        if self.closed.is_set():
            raise RuntimeError("authorization already closed")
        return None

    def remaining_seconds(self):
        return max(0.0, self.deadline_monotonic - time.monotonic())

    async def close(self):
        self.close_count += 1
        self.close_started.set()
        if self.close_gate is not None:
            await self.close_gate.wait()
        if self.close_error is not None:
            raise self.close_error
        self.closed.set()

    async def fail(self, *, cache_may_exist=True):
        self.failed = True


class _RpcContext:
    def __init__(self):
        self.aborted = []

    def time_remaining(self):
        return 10

    async def send_initial_metadata(self, _metadata):
        return None

    async def abort(self, code, details):
        self.aborted.append((code, details))


class _NoTransportDeadlineRpcContext(_RpcContext):
    def time_remaining(self):
        return None


class _CaptureHandle:
    def __init__(self, *, confirmed, buffer_check=None, cleanup_complete=False):
        self.reclaim_started = asyncio.Event()
        self.reclaim_release = asyncio.Event()
        self.confirmed = confirmed
        self.buffer_check = buffer_check
        self.buffer_references_cleared = None
        self.cleanup_complete = cleanup_complete

    async def result(self):
        return types.SimpleNamespace(cleanup_complete=self.cleanup_complete)

    async def reclaim_capture_buffers(self):
        if self.buffer_check is not None:
            self.buffer_references_cleared = self.buffer_check()
        self.reclaim_started.set()
        await self.reclaim_release.wait()
        return self.confirmed and self.buffer_references_cleared is not False


class _PendingCaptureHandle:
    def __init__(self, operation_task):
        self.operation_task = operation_task

    async def reclaim_capture_buffers(self):
        return await self.operation_task


class _QueuedCaptureHandle:
    def __init__(self, queue, producer_task):
        self.queue = queue
        self.producer_task = producer_task
        self.reclaim_started = asyncio.Event()

    async def reclaim_capture_buffers(self):
        self.reclaim_started.set()
        if not self.producer_task.done():
            return False
        while not self.queue.empty():
            self.queue.get_nowait()
        return self.queue.empty()


class _TrackedList(list):
    __slots__ = ("__weakref__",)


class _FailedWriteRpcContext(_RpcContext):
    async def write(self, _payload):
        raise RuntimeError("synthetic stalled-stream write failure")


class _TimeoutWriteRpcContext(_RpcContext):
    def __init__(self):
        super().__init__()
        self.started = asyncio.Event()

    async def write(self, payload):
        self.started.set()
        await asyncio.Event().wait()


class _NestedTimeoutWriteRpcContext(_RpcContext):
    def __init__(self, container_kind):
        super().__init__()
        self.container_kind = container_kind
        self.started = asyncio.Event()

    async def write(self, payload):
        if self.container_kind == "tuple":
            held = (payload,)
        elif self.container_kind == "list":
            held = [{"outer": [payload]}]
        else:
            held = {"outer": {"inner": [payload]}}
        payload = None
        self.started.set()
        await asyncio.Event().wait()


def _exception_traceback_frames(error):
    pending = [error]
    seen_errors = set()
    seen_tracebacks = set()
    frames = []
    budget = 128
    while pending:
        current = pending.pop()
        if id(current) in seen_errors:
            continue
        seen_errors.add(id(current))
        budget -= 1
        if budget < 0:
            raise AssertionError("exception-chain traversal exceeded its test bound")
        if current.__cause__ is not None:
            pending.append(current.__cause__)
        if current.__context__ is not None:
            pending.append(current.__context__)
        traceback = current.__traceback__
        while traceback is not None and id(traceback) not in seen_tracebacks:
            seen_tracebacks.add(id(traceback))
            budget -= 1
            if budget < 0:
                raise AssertionError("traceback traversal exceeded its test bound")
            frames.append(traceback.tb_frame)
            traceback = traceback.tb_next
    return frames


def _contains_builtin_identity(root, target):
    pending = [root]
    seen = set()
    while pending:
        value = pending.pop()
        if value is target:
            return True
        value_type = type(value)
        if value_type in (dict, tuple, list, set, frozenset):
            if id(value) in seen:
                continue
            seen.add(id(value))
            if value_type is dict:
                for key, child in dict.items(value):
                    pending.extend((key, child))
            else:
                pending.extend(value)
    return False


class WriteErrorReferenceCleanupTests(unittest.TestCase):
    @staticmethod
    def _nested_timeout_error(container_kind, payload):
        marker = object()

        def writer(payload):
            if container_kind == "tuple":
                held = (payload,)
            elif container_kind == "list":
                held = [{"outer": [payload]}]
            else:
                held = {"outer": {"inner": [payload]}}
            payload = None
            raise RuntimeError("writer failed")

        try:
            writer(payload)
        except RuntimeError as cause:
            payload = None
            try:
                raise TimeoutError("wrapper timeout") from cause
            except TimeoutError as error:
                traceback = error.__cause__.__traceback__
                while (traceback is not None
                       and traceback.tb_frame.f_code.co_name != "writer"):
                    traceback = traceback.tb_next
                if traceback is None:
                    raise AssertionError("nested writer traceback frame is missing")
                writer_frame = traceback.tb_frame
                return error, sys._getframe(), marker, writer_frame

    def test_nested_builtin_references_clear_only_relevant_frames(self):
        for container_kind in ("tuple", "list", "dict"):
            with self.subTest(container_kind=container_kind):
                payload = b"x" * 128_001
                error, wrapper_frame, marker, writer_frame = (
                    self._nested_timeout_error(container_kind, payload))
                self.assertTrue(_contains_builtin_identity(
                    writer_frame.f_locals["held"], payload))

                self.assertTrue(_clear_write_error_payload_frames(
                    error, (payload,)))

                self.assertEqual(writer_frame.f_locals, {})
                self.assertIs(wrapper_frame.f_locals["marker"], marker)
                self.assertTrue(_exception_traceback_frames(error))

    def test_scan_does_not_invoke_custom_type_equality_hooks(self):
        class RejectEquality(type):
            def __eq__(cls, other):
                raise AssertionError("reference scan invoked custom type equality")

            def __instancecheck__(cls, value):
                raise AssertionError("reference scan invoked custom instance check")

        class Opaque(metaclass=RejectEquality):
            pass

        unrelated = Opaque()
        payload = b"z" * 128_001

        def writer(payload):
            opaque = unrelated
            held = (payload,)
            payload = None
            raise RuntimeError("writer failed")

        try:
            writer(payload)
        except RuntimeError as error:
            self.assertTrue(_clear_write_error_payload_frames(error, (payload,)))

    def test_scan_exhaustion_fails_closed_while_error_is_retained(self):
        payload = b"y" * 128_001
        error, wrapper_frame, marker, writer_frame = self._nested_timeout_error(
            "dict", payload)
        with patch(
                "steamboat_runtime.coordinator_service._WRITE_ERROR_REFERENCE_SCAN_LIMIT",
                1):
            self.assertFalse(_clear_write_error_payload_frames(
                error, (payload,)))

        self.assertTrue(_contains_builtin_identity(
            writer_frame.f_locals["held"], payload))
        self.assertIs(wrapper_frame.f_locals["marker"], marker)
        self.assertTrue(_clear_write_error_payload_frames(error, (payload,)))
        self.assertEqual(writer_frame.f_locals, {})


class WriteErrorReferenceTimeoutTests(unittest.IsolatedAsyncioTestCase):
    async def test_wait_for_timeout_clears_nested_writer_payload_containers(self):
        service = object.__new__(CoordinatorService)
        service.coordinator = types.SimpleNamespace(limits=types.SimpleNamespace(
            output_stall_timeout_seconds=0.01))
        for container_kind in ("tuple", "list", "dict"):
            with self.subTest(container_kind=container_kind):
                context = _NestedTimeoutWriteRpcContext(container_kind)
                with self.assertRaises(TimeoutError) as raised:
                    await service._write(
                        context, {"logits": [0.125] * 32000},
                        time.monotonic() + 1)

                self.assertIsInstance(raised.exception.__cause__, asyncio.CancelledError)
                await asyncio.wait_for(context.started.wait(), 1)
                writer_frames = [
                    frame for frame in _exception_traceback_frames(raised.exception)
                    if frame.f_code.co_name == "write"]
                self.assertTrue(writer_frames)
                self.assertTrue(all(not frame.f_locals for frame in writer_frames))


class _FinishedHandle:
    session_id = "ses_" + "a" * 32

    class _Result:
        status = "completed"
        cleanup_complete = True

    async def result(self):
        return self._Result()

    async def cancel(self):
        return self._Result()


class CoordinatorStreamCounterTests(unittest.IsolatedAsyncioTestCase):
    async def test_finish_keeps_legacy_default_and_supports_secure_owner(self):
        service = object.__new__(CoordinatorService)
        service.active_streams = 1
        service.metrics = {_FinishedHandle.session_id: object()}
        service.counters = {
            "completed_requests": 0, "cancelled_requests": 0,
            "failed_requests": 0, "cleanup_incomplete_requests": 0,
        }
        await CoordinatorService._finish(service, _FinishedHandle(), cancel=False)
        self.assertEqual(service.active_streams, 0)
        self.assertEqual(service.counters["completed_requests"], 1)

        service.active_streams = 1
        service.metrics[_FinishedHandle.session_id] = object()
        await CoordinatorService._finish(
            service, _FinishedHandle(), cancel=False,
            release_active_stream=False)
        self.assertEqual(service.active_streams, 1)
        self.assertEqual(service.counters["completed_requests"], 2)


class _CaptureServicePathTests(unittest.IsolatedAsyncioTestCase):
    def _adapter(self, *, budget=None):
        factory = _ContextFactory()
        service = _Service()
        adapter = SecureCoordinatorService(
            service, authorizer=_Authorizer(),
            authorization_watcher=lambda _authorization: asyncio.Future(),
            request_context_factory=factory, capture_budget=budget)
        return adapter, service, factory

    @staticmethod
    def _grpc_stub():
        module = types.ModuleType("grpc")
        module.StatusCode = types.SimpleNamespace(
            RESOURCE_EXHAUSTED=1, UNAUTHENTICATED=2, UNAVAILABLE=3)
        return module

    async def test_trailing_marker_fails_closed_without_context_api(self):
        wrapped = _AuthorizedStreamContext(_RpcContext(), _Authorization())
        with self.assertRaises(SecureTransportError):
            await wrapped.set_trailing_metadata(())

    async def _call_generate(self, adapter, authorization, *, capture=True,
                             producer=None, context=None):
        context = context or _RpcContext()
        payload = encode_json({
            "input_ids": [1], "new_tokens": 1,
            "timeout_seconds": 5, "capture_logits": capture})

        async def authorize(_method, _data, _parsed, _context):
            return authorization

        async def run_guarded(coroutine, *_args, **_kwargs):
            return await coroutine

        adapter._authorize = authorize
        if producer is not None:
            adapter._produce_generate = producer
        with patch.dict(sys.modules, {"grpc": self._grpc_stub()}), patch(
                "steamboat_runtime.secure_coordinator_service._run_guarded",
                run_guarded):
            await adapter.generate_rpc(payload, context)
        return context

    async def test_context_factory_receives_absolute_server_deadline_when_supported(self):
        factory = _DeadlineContextFactory()
        adapter = SecureCoordinatorService(
            _Service(), authorizer=_Authorizer(),
            authorization_watcher=lambda _authorization: asyncio.Future(),
            request_context_factory=factory)
        authorization = _Authorization()
        payload = {"capture_logits": False, "input_ids": [7], "new_tokens": 1}
        original_payload = dict(payload)
        request_deadline = time.monotonic() + 4
        slot = {
            "capture_lease": None,
            "capture_pending": False,
            "admission_cleanup_tasks": set(),
        }

        with patch.object(adapter, "_validate_context",
                          side_effect=ServiceRequestError("INVALID_INPUT", "stop")):
            with self.assertRaises(ServiceRequestError):
                await adapter._produce_generate(
                    payload, _RpcContext(), request_deadline, authorization, slot)

        await asyncio.wait_for(slot["context_release_task"], 1)
        self.assertEqual(factory.deadline_calls, [
            (authorization, payload, request_deadline)])
        self.assertEqual(payload, original_payload)

    async def test_authorization_waits_for_combined_capture_and_context_owner(self):
        budget = CaptureBudget()
        adapter, service, factory = self._adapter(budget=budget)
        authorization = _Authorization()
        cleanup_release = asyncio.Event()
        handle = _CaptureHandle(confirmed=True)
        slots = []
        factory.release_gate = asyncio.Event()

        async def producer(payload, _context, _deadline, _auth, slot):
            slots.append(slot)
            slot["entered"] = True
            slot["trusted_context"] = factory.context
            slot["resource_cleanup_required"] = True
            slot["resource_cleanup_confirmed"] = False
            adapter._reserve_capture(payload, factory.context, slot)
            slot["handle"] = handle
            cleanup = asyncio.create_task(cleanup_release.wait())
            slot["cleanup_task"] = cleanup
            adapter._defer_generate_resources(factory.context, (cleanup,), slot)
            slot["authorization_transferred"] = True

        await self._call_generate(adapter, authorization, producer=producer)
        slot = slots[0]
        cleanup = slot["cleanup_task"]
        owner = slot["authorization_owner_task"]
        self.assertIsNotNone(owner)
        self.assertFalse(authorization.closed.is_set())
        self.assertEqual(budget.status().cleanup_pending_captures, 1)

        cleanup_release.set()
        await asyncio.wait_for(handle.reclaim_started.wait(), 1)
        await asyncio.wait_for(cleanup, 1)
        self.assertFalse(authorization.closed.is_set())
        self.assertFalse(factory.released)
        self.assertGreater(budget.status().reserved_bytes, 0)
        self.assertEqual(service.active_streams, 1)

        handle.reclaim_release.set()
        await asyncio.wait_for(factory.release_started.wait(), 1)
        self.assertFalse(authorization.closed.is_set())
        self.assertGreater(budget.status().reserved_bytes, 0)
        self.assertFalse(factory.released)
        factory.release_gate.set()
        await asyncio.wait_for(owner, 1)
        self.assertTrue(authorization.closed.is_set())
        self.assertEqual(budget.status().reserved_bytes, 0)
        self.assertEqual(factory.released, [factory.context])
        self.assertEqual(service.active_streams, 0)
        self.assertEqual(adapter.active_generate_streams, 0)

    async def test_slow_authorization_close_keeps_context_capture_and_stream_slots(self):
        budget = CaptureBudget()
        adapter, service, factory = self._adapter(budget=budget)
        authorization = _Authorization()
        authorization.close_gate = asyncio.Event()
        factory.release_gate = asyncio.Event()
        handle = _CaptureHandle(confirmed=True)
        handle.reclaim_release.set()
        slots = []

        async def producer(payload, _context, _deadline, _auth, slot):
            slots.append(slot)
            slot["entered"] = True
            slot["trusted_context"] = factory.context
            adapter._reserve_capture(payload, factory.context, slot)
            slot["handle"] = handle
            cleanup = asyncio.create_task(asyncio.sleep(0))
            slot["cleanup_task"] = cleanup
            adapter._defer_generate_resources(factory.context, (cleanup,), slot)
            slot["authorization_transferred"] = True

        await self._call_generate(adapter, authorization, producer=producer)
        slot = slots[0]
        await asyncio.wait_for(factory.release_started.wait(), 1)
        self.assertFalse(authorization.closed.is_set())
        self.assertIs(slot["trusted_context"], factory.context)
        self.assertGreater(budget.status().reserved_bytes, 0)
        self.assertEqual(service.active_streams, 1)
        self.assertEqual(adapter.active_generate_streams, 1)

        factory.release_gate.set()
        await asyncio.wait_for(authorization.close_started.wait(), 1)
        self.assertFalse(authorization.closed.is_set())
        self.assertIs(slot["trusted_context"], factory.context)
        self.assertGreater(budget.status().reserved_bytes, 0)
        self.assertEqual(service.active_streams, 1)
        self.assertEqual(adapter.active_generate_streams, 1)

        authorization.close_gate.set()
        await asyncio.wait_for(slot["authorization_owner_task"], 1)
        self.assertEqual(authorization.close_count, 1)
        self.assertIsNone(slot["trusted_context"])
        self.assertEqual(budget.status().reserved_bytes, 0)
        self.assertEqual(service.active_streams, 0)
        self.assertEqual(adapter.active_generate_streams, 0)

    async def test_failed_authorization_close_keeps_context_capture_and_stream_slots(self):
        budget = CaptureBudget()
        adapter, service, factory = self._adapter(budget=budget)
        authorization = _Authorization()
        authorization.close_error = RuntimeError("close outcome is unconfirmed")
        handle = _CaptureHandle(confirmed=True)
        handle.reclaim_release.set()
        slots = []

        async def producer(payload, _context, _deadline, _auth, slot):
            slots.append(slot)
            slot["entered"] = True
            slot["trusted_context"] = factory.context
            adapter._reserve_capture(payload, factory.context, slot)
            slot["handle"] = handle
            cleanup = asyncio.create_task(asyncio.sleep(0))
            slot["cleanup_task"] = cleanup
            adapter._defer_generate_resources(factory.context, (cleanup,), slot)
            slot["authorization_transferred"] = True

        await self._call_generate(adapter, authorization, producer=producer)
        slot = slots[0]
        await asyncio.wait_for(slot["authorization_owner_task"], 1)

        self.assertEqual(authorization.close_count, 1)
        self.assertFalse(authorization.closed.is_set())
        self.assertIs(slot["trusted_context"], factory.context)
        self.assertTrue(slot["retained"])
        self.assertTrue(slot["capture_pending"])
        self.assertIn(slot, adapter._unreclaimed_generate_slots)
        self.assertTrue(adapter.unavailable)
        self.assertGreater(budget.status().reserved_bytes, 0)
        self.assertEqual(service.active_streams, 1)
        self.assertEqual(adapter.active_generate_streams, 1)
        self.assertEqual(factory.released, [factory.context])

    async def test_pending_cleanup_exception_retains_late_descendant_tree(self):
        budget = CaptureBudget()
        adapter, service, factory = self._adapter(budget=budget)
        authorization = _Authorization()
        child_release = asyncio.Event()
        grandchild_started = asyncio.Event()
        grandchild_release = asyncio.Event()
        grandchild_tasks = []

        async def pending_child():
            await child_release.wait()

            async def late_grandchild():
                grandchild_started.set()
                await grandchild_release.wait()

            grandchild = asyncio.create_task(late_grandchild())
            grandchild_tasks.append(grandchild)
            raise SecureTaskPending((grandchild,), "nested cleanup remains pending")

        child_task = asyncio.create_task(pending_child())

        async def already_observed_failure():
            raise SecureTaskPending((child_task,), "cleanup child remains pending")

        failed_operation = asyncio.create_task(already_observed_failure())
        observed = await asyncio.gather(failed_operation, return_exceptions=True)
        self.assertIsInstance(observed[0], SecureTaskPending)
        self.assertIsInstance(failed_operation.exception(), SecureTaskPending)

        adapter.active_generate_streams = 1
        service.active_streams = 1
        slot = {
            "generate": True, "service": True, "entered": True,
            "trusted_context": factory.context, "capture_lease": None,
            "capture_pending": False, "cleanup_task": None,
            "context_release_task": None, "capture_cleanup_task": None,
            "admission_cleanup_tasks": set(),
        }
        adapter._reserve_capture({"capture_logits": True}, factory.context, slot)
        slot["handle"] = _PendingCaptureHandle(failed_operation)
        owner = adapter._retain_generate_authorization_owner(authorization, slot)
        await asyncio.wait_for(owner, 1)

        child_set = slot["pending_cleanup_tasks"]
        changed = slot["pending_cleanup_tasks_changed"]
        self.assertIn(child_task, child_set)
        self.assertIn(child_task, adapter.pending_tasks)
        self.assertFalse(authorization.closed.is_set())
        self.assertTrue(slot["retained"])
        self.assertGreater(budget.status().reserved_bytes, 0)
        self.assertEqual(service.active_streams, 1)
        self.assertEqual(adapter.active_generate_streams, 1)

        changed.clear()
        child_release.set()
        await asyncio.wait_for(grandchild_started.wait(), 1)
        grandchild = grandchild_tasks[0]
        while grandchild not in child_set:
            changed.clear()
            if grandchild in child_set:
                break
            await asyncio.wait_for(changed.wait(), 1)
        self.assertIn(grandchild, adapter.pending_tasks)
        self.assertFalse(grandchild.done())
        self.assertGreater(budget.status().reserved_bytes, 0)
        self.assertFalse(authorization.closed.is_set())

        grandchild_release.set()
        await asyncio.wait_for(slot["pending_cleanup_monitor_task"], 1)
        self.assertTrue(child_task.done())
        self.assertTrue(grandchild.done())
        self.assertIn(child_task, child_set)
        self.assertIn(grandchild, child_set)
        self.assertTrue(slot["retained"])
        self.assertGreater(budget.status().reserved_bytes, 0)
        self.assertEqual(service.active_streams, 1)
        self.assertEqual(adapter.active_generate_streams, 1)

    async def test_cancelled_pending_monitor_preserves_child_and_tracks_late_grandchild(self):
        async def run_case(cancel_after_start):
            budget = CaptureBudget()
            adapter, service, factory = self._adapter(budget=budget)
            child_release = asyncio.Event()
            grandchild_started = asyncio.Event()
            grandchild_release = asyncio.Event()
            grandchild_tasks = []

            async def pending_child():
                await child_release.wait()

                async def late_grandchild():
                    grandchild_started.set()
                    await grandchild_release.wait()

                grandchild = asyncio.create_task(late_grandchild())
                grandchild_tasks.append(grandchild)
                raise SecureTaskPending(
                    (grandchild,), "late cleanup remains pending")

            child_task = asyncio.create_task(pending_child())
            adapter.active_generate_streams = 1
            service.active_streams = 1
            slot = {
                "generate": True, "service": True, "entered": True,
                "trusted_context": factory.context, "capture_lease": None,
                "capture_pending": False, "cleanup_task": None,
                "context_release_task": None, "capture_cleanup_task": None,
                "admission_cleanup_tasks": set(),
            }
            adapter._reserve_capture(
                {"capture_logits": True}, factory.context, slot)
            adapter._retain_generate_pending_tasks(slot, (child_task,))
            monitor = slot["pending_cleanup_monitor_task"]

            if cancel_after_start:
                await asyncio.sleep(0)
                self.assertFalse(monitor.done())
            monitor.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await monitor

            async def wait_for_replacement():
                async def replacement_created():
                    while slot["pending_cleanup_monitor_task"] is monitor:
                        await asyncio.sleep(0)

                await asyncio.wait_for(replacement_created(), 1)
                return slot["pending_cleanup_monitor_task"]

            replacement = await wait_for_replacement()
            self.assertIsNot(replacement, monitor)
            self.assertFalse(child_task.cancelled())
            self.assertIn(child_task, slot["pending_cleanup_tasks"])
            self.assertIn(child_task, adapter.pending_tasks)
            self.assertTrue(slot["retained"])
            self.assertGreater(budget.status().reserved_bytes, 0)
            self.assertEqual(service.active_streams, 1)
            self.assertEqual(adapter.active_generate_streams, 1)

            child_release.set()
            await asyncio.wait_for(grandchild_started.wait(), 1)
            grandchild = grandchild_tasks[0]
            changed = slot["pending_cleanup_tasks_changed"]
            while grandchild not in slot["pending_cleanup_tasks"]:
                changed.clear()
                if grandchild in slot["pending_cleanup_tasks"]:
                    break
                await asyncio.wait_for(changed.wait(), 1)
            self.assertIn(grandchild, adapter.pending_tasks)
            self.assertFalse(grandchild.done())
            self.assertGreater(budget.status().reserved_bytes, 0)
            self.assertFalse(child_task.cancelled())

            grandchild_release.set()
            await asyncio.wait_for(replacement, 1)
            self.assertIn(child_task, slot["pending_cleanup_tasks"])
            self.assertIn(grandchild, slot["pending_cleanup_tasks"])
            self.assertTrue(grandchild.done())
            self.assertTrue(slot["retained"])
            self.assertGreater(budget.status().reserved_bytes, 0)
            self.assertEqual(service.active_streams, 1)
            self.assertEqual(adapter.active_generate_streams, 1)

        for cancel_after_start in (False, True):
            with self.subTest(cancel_after_start=cancel_after_start):
                await run_case(cancel_after_start)

    async def test_pending_monitor_discovers_grandchild_before_unrelated_root_finishes(self):
        budget = CaptureBudget()
        adapter, service, factory = self._adapter(budget=budget)
        root_release = asyncio.Event()
        unrelated_release = asyncio.Event()
        grandchild_started = asyncio.Event()
        grandchild_release = asyncio.Event()
        grandchild_tasks = []

        async def pending_root():
            await root_release.wait()

            async def late_grandchild():
                grandchild_started.set()
                await grandchild_release.wait()

            grandchild = asyncio.create_task(late_grandchild())
            grandchild_tasks.append(grandchild)
            raise SecureTaskPending((grandchild,), "grandchild still pending")

        root_task = asyncio.create_task(pending_root())
        unrelated_task = asyncio.create_task(unrelated_release.wait())
        adapter.active_generate_streams = 1
        service.active_streams = 1
        slot = {
            "generate": True, "service": True, "entered": True,
            "trusted_context": factory.context, "capture_lease": None,
            "capture_pending": False, "cleanup_task": None,
            "context_release_task": None, "capture_cleanup_task": None,
            "admission_cleanup_tasks": set(),
        }
        adapter._reserve_capture({"capture_logits": True}, factory.context, slot)
        adapter._retain_generate_pending_tasks(
            slot, (root_task, unrelated_task))
        monitor = slot["pending_cleanup_monitor_task"]
        await asyncio.sleep(0)
        self.assertFalse(monitor.done())

        changed = slot["pending_cleanup_tasks_changed"]
        changed.clear()
        root_release.set()
        await asyncio.wait_for(grandchild_started.wait(), 1)
        grandchild = grandchild_tasks[0]
        while grandchild not in slot["pending_cleanup_tasks"]:
            changed.clear()
            if grandchild in slot["pending_cleanup_tasks"]:
                break
            await asyncio.wait_for(changed.wait(), 1)

        self.assertFalse(monitor.done())
        self.assertFalse(unrelated_task.done())
        self.assertFalse(unrelated_task.cancelled())
        self.assertIn(grandchild, adapter.pending_tasks)
        self.assertFalse(grandchild.done())
        self.assertTrue(slot["retained"])
        self.assertGreater(budget.status().reserved_bytes, 0)
        self.assertEqual(service.active_streams, 1)
        self.assertEqual(adapter.active_generate_streams, 1)

        grandchild_release.set()
        unrelated_release.set()
        await asyncio.wait_for(monitor, 1)
        self.assertTrue(root_task.done())
        self.assertTrue(unrelated_task.done())
        self.assertTrue(grandchild.done())

    async def test_exhausted_monitor_restart_tracks_late_grandchild_until_reclaim(self):
        budget = CaptureBudget()
        adapter, service, factory = self._adapter(budget=budget)
        child_release = asyncio.Event()
        grandchild_started = asyncio.Event()
        grandchild_release = asyncio.Event()
        grandchild_tasks = []
        authorization = _Authorization()

        async def pending_root():
            await child_release.wait()

            async def late_grandchild():
                grandchild_started.set()
                await grandchild_release.wait()

            grandchild = asyncio.create_task(late_grandchild())
            grandchild_tasks.append(grandchild)
            raise SecureTaskPending(
                (grandchild,), "late cleanup remains pending")

        child_task = asyncio.create_task(pending_root())

        class ReclaimAfterGrandchild:
            def __init__(self):
                self.reclaim_started = asyncio.Event()
                self.reclaim_confirmed = False

            async def reclaim_capture_buffers(self):
                self.reclaim_started.set()
                await asyncio.wait(
                    (grandchild_tasks[0],),
                    return_when=asyncio.ALL_COMPLETED)
                self.reclaim_confirmed = True
                return True

        handle = ReclaimAfterGrandchild()
        factory.release_gate = asyncio.Event()
        adapter.active_generate_streams = 1
        service.active_streams = 1
        slot = {
            "generate": True, "service": True, "entered": True,
            "trusted_context": factory.context,
            "authorization": authorization,
            "capture_lease": None,
            "capture_pending": False, "cleanup_task": None,
            "context_release_task": None, "capture_cleanup_task": None,
            "admission_cleanup_tasks": set(),
            "capture_submission_attempted": True,
            "session_cleanup_confirmed": True,
            "handle": handle,
        }
        adapter._reserve_capture({"capture_logits": True}, factory.context, slot)
        adapter._retain_generate_pending_tasks(slot, (child_task,))
        first_monitor = slot["pending_cleanup_monitor_task"]
        first_monitor.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await first_monitor

        async def wait_for_replacement(previous):
            async def replacement_created():
                while slot["pending_cleanup_monitor_task"] is previous:
                    await asyncio.sleep(0)

            await asyncio.wait_for(replacement_created(), 1)
            return slot["pending_cleanup_monitor_task"]

        replacement = await wait_for_replacement(first_monitor)
        replacement.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await replacement
        await asyncio.sleep(0)

        self.assertIs(slot["pending_cleanup_monitor_task"], replacement)
        self.assertTrue(slot["pending_cleanup_monitor_restart_exhausted"])
        self.assertTrue(adapter.unavailable)
        self.assertIn(child_task, slot["pending_cleanup_tasks"])
        self.assertIn(child_task, adapter.pending_tasks)
        self.assertIn(child_task, adapter.runtime_owner.pending_tasks)
        self.assertFalse(child_task.cancelled())
        self.assertTrue(slot["retained"])
        self.assertGreater(budget.status().reserved_bytes, 0)
        self.assertEqual(service.active_streams, 1)
        self.assertEqual(adapter.active_generate_streams, 1)

        child_release.set()
        await asyncio.wait_for(grandchild_started.wait(), 1)
        with self.assertRaises(SecureTaskPending):
            await asyncio.wait_for(child_task, 1)
        grandchild = grandchild_tasks[0]
        changed = slot["pending_cleanup_tasks_changed"]
        while (grandchild not in slot["pending_cleanup_tasks"]
               or grandchild not in adapter.pending_tasks
               or grandchild not in adapter.runtime_owner.pending_tasks):
            changed.clear()
            if (grandchild in slot["pending_cleanup_tasks"]
                    and grandchild in adapter.pending_tasks
                    and grandchild in adapter.runtime_owner.pending_tasks):
                break
            await asyncio.wait_for(changed.wait(), 1)

        self.assertTrue(slot["pending_cleanup_monitor_restart_exhausted"])
        self.assertIs(slot["pending_cleanup_monitor_task"], replacement)
        self.assertNotIn(child_task, adapter.pending_tasks)
        self.assertNotIn(child_task, adapter.runtime_owner.pending_tasks)
        self.assertIn(grandchild, slot["pending_cleanup_roots"])
        self.assertIn(grandchild, adapter.pending_tasks)
        self.assertIn(grandchild, adapter.runtime_owner.pending_tasks)
        self.assertFalse(grandchild.done())
        self.assertTrue(slot["retained"])
        self.assertIs(slot["trusted_context"], factory.context)
        self.assertFalse(authorization.closed.is_set())
        self.assertGreater(budget.status().reserved_bytes, 0)
        self.assertEqual(service.active_streams, 1)
        self.assertEqual(adapter.active_generate_streams, 1)

        owner = adapter._retain_generate_authorization_owner(
            authorization, slot)
        await asyncio.wait_for(handle.reclaim_started.wait(), 1)
        self.assertFalse(handle.reclaim_confirmed)
        self.assertFalse(grandchild.done())
        self.assertFalse(authorization.closed.is_set())
        self.assertFalse(factory.released)
        self.assertGreater(budget.status().reserved_bytes, 0)
        self.assertEqual(service.active_streams, 1)
        self.assertEqual(adapter.active_generate_streams, 1)

        grandchild_release.set()
        await asyncio.wait_for(grandchild, 1)
        await asyncio.wait_for(factory.release_started.wait(), 1)
        self.assertTrue(handle.reclaim_confirmed)
        self.assertFalse(authorization.closed.is_set())
        self.assertGreater(budget.status().reserved_bytes, 0)
        self.assertEqual(service.active_streams, 1)
        self.assertEqual(adapter.active_generate_streams, 1)

        factory.release_gate.set()
        await asyncio.wait_for(owner, 1)
        self.assertTrue(authorization.closed.is_set())
        self.assertEqual(factory.released, [factory.context])
        self.assertEqual(budget.status().reserved_bytes, 0)
        self.assertEqual(service.active_streams, 0)
        self.assertEqual(adapter.active_generate_streams, 0)

    async def test_pending_factory_release_and_close_keep_child_tasks_owned(self):
        for operation in ("release", "close"):
            with self.subTest(operation=operation):
                adapter, service, factory = self._adapter()
                authorization = _Authorization()
                child_release = asyncio.Event()
                child_task = asyncio.create_task(child_release.wait())
                pending_error = SecureTaskPending(
                    (child_task,), f"{operation} still pending")
                if operation == "release":
                    factory.release_error = pending_error
                else:
                    authorization.close_error = pending_error

                adapter.active_generate_streams = 1
                service.active_streams = 1
                slot = {
                    "generate": True, "service": True, "entered": True,
                    "trusted_context": factory.context, "capture_lease": None,
                    "capture_pending": False, "cleanup_task": None,
                    "context_release_task": None, "capture_cleanup_task": None,
                    "admission_cleanup_tasks": set(),
                }
                owner = adapter._retain_generate_authorization_owner(
                    authorization, slot)
                await asyncio.wait_for(owner, 1)

                self.assertIn(child_task, slot["pending_cleanup_tasks"])
                self.assertIn(child_task, adapter.pending_tasks)
                self.assertTrue(slot["retained"])
                self.assertTrue(adapter.unavailable)
                self.assertFalse(authorization.closed.is_set())
                self.assertEqual(service.active_streams, 1)
                self.assertEqual(adapter.active_generate_streams, 1)

                child_release.set()
                await asyncio.wait_for(
                    slot["pending_cleanup_monitor_task"], 1)
                self.assertTrue(child_task.done())
                self.assertIn(child_task, slot["pending_cleanup_tasks"])
                self.assertTrue(slot["retained"])
                self.assertEqual(service.active_streams, 1)
                self.assertEqual(adapter.active_generate_streams, 1)

    async def test_real_guard_pending_path_delegates_to_combined_close_owner(self):
        adapter, service, factory = self._adapter()
        authorization = _Authorization()
        authorization.close_gate = asyncio.Event()
        factory.release_gate = asyncio.Event()
        operation_started = asyncio.Event()
        operation_cancelled = asyncio.Event()
        operation_release = asyncio.Event()

        async def resistant_operation():
            operation_started.set()
            try:
                await asyncio.Future()
            except asyncio.CancelledError:
                operation_cancelled.set()
                await operation_release.wait()

        guarded = asyncio.create_task(_run_guarded(
            resistant_operation(), authorization,
            lambda _authorization: asyncio.Future(), timeout=10,
            cancel_grace_seconds=0.01,
            close_authorization_on_pending=False))
        await asyncio.wait_for(operation_started.wait(), 1)
        guarded.cancel()
        with self.assertRaises(SecureTaskPending) as pending:
            await guarded
        await asyncio.wait_for(operation_cancelled.wait(), 1)
        self.assertEqual(authorization.close_count, 0)

        operation = next(task for task in pending.exception.tasks if not task.done())
        trusted = factory.context
        adapter.active_generate_streams = 1
        service.active_streams = 1
        slot = {
            "service": True, "generate": True, "entered": True,
            "cleanup_task": operation, "capture_lease": None,
            "capture_pending": False, "trusted_context": trusted,
            "context_release_task": None, "capture_cleanup_task": None,
            "retained": True, "resource_cleanup_confirmed": False,
            "admission_cleanup_tasks": set(),
            "authorization_close_attempted": False,
            "authorization_closed": False,
        }
        self.assertTrue(pending.exception.authorization_transferred)
        adapter._defer_generate_resources(trusted, pending.exception.tasks, slot)
        owner = adapter._retain_generate_authorization_owner(authorization, slot)

        operation_release.set()
        await asyncio.wait_for(factory.release_started.wait(), 1)
        self.assertEqual(authorization.close_count, 0)
        self.assertIs(slot["trusted_context"], trusted)
        self.assertEqual(service.active_streams, 1)
        self.assertEqual(adapter.active_generate_streams, 1)

        factory.release_gate.set()
        await asyncio.wait_for(authorization.close_started.wait(), 1)
        self.assertFalse(authorization.closed.is_set())
        self.assertIs(slot["trusted_context"], trusted)
        self.assertEqual(service.active_streams, 1)
        self.assertEqual(adapter.active_generate_streams, 1)
        authorization.close_gate.set()
        await asyncio.wait_for(owner, 1)
        self.assertTrue(authorization.closed.is_set())
        self.assertEqual(authorization.close_count, 1)
        self.assertEqual(service.active_streams, 0)
        self.assertEqual(adapter.active_generate_streams, 0)

    async def test_failed_capture_write_traceback_cannot_retain_buffers_at_reclaim(self):
        budget = CaptureBudget()
        adapter, service, factory = self._adapter(budget=budget)
        authorization = _Authorization()
        cleanup_release = asyncio.Event()
        cleanup_release.set()
        factory.release_gate = asyncio.Event()
        logits_reference = None
        handle = None
        slots = []
        service._write = types.MethodType(CoordinatorService._write, service)

        async def producer(payload, rpc_context, deadline, _auth, slot):
            nonlocal logits_reference, handle
            slots.append(slot)
            slot["entered"] = True
            slot["trusted_context"] = factory.context
            slot["resource_cleanup_required"] = True
            slot["resource_cleanup_confirmed"] = False
            adapter._reserve_capture(payload, factory.context, slot)
            logits = _TrackedList([0.125] * 32000)
            logits_reference = weakref.ref(logits)
            message = {"type": "token", "logits": logits}
            wrapped = _AuthorizedStreamContext(rpc_context, authorization)
            try:
                await service._write(wrapped, message, deadline)
            except RuntimeError as error:
                slot["write_exception"] = error
            finally:
                logits = None
                message = None
            cleanup = asyncio.create_task(cleanup_release.wait())
            slot["cleanup_task"] = cleanup
            await cleanup
            handle = _CaptureHandle(
                confirmed=True,
                buffer_check=lambda: logits_reference() is None)
            slot["handle"] = handle
            adapter._defer_generate_resources(factory.context, (cleanup,), slot)
            slot["authorization_transferred"] = True

        await self._call_generate(
            adapter, authorization, producer=producer,
            context=_FailedWriteRpcContext())
        slot = slots[0]
        self.assertIsNotNone(slot.get("write_exception"))
        await asyncio.wait_for(handle.reclaim_started.wait(), 1)
        self.assertTrue(handle.buffer_references_cleared)
        self.assertIsNone(logits_reference())
        frames = _exception_traceback_frames(slot["write_exception"])
        self.assertTrue(frames)
        for frame in frames:
            locals_ = frame.f_locals.values()
            self.assertFalse(any(isinstance(value, _TrackedList) for value in locals_))
            self.assertFalse(any(type(value) is bytes and len(value) > 100_000
                                 for value in locals_))
        self.assertGreater(budget.status().reserved_bytes, 0)

        handle.reclaim_release.set()
        await asyncio.wait_for(factory.release_started.wait(), 1)
        self.assertGreater(budget.status().reserved_bytes, 0)
        self.assertFalse(authorization.closed.is_set())
        self.assertFalse(factory.released)
        factory.release_gate.set()
        await asyncio.wait_for(slot["authorization_owner_task"], 1)
        self.assertEqual(budget.status().reserved_bytes, 0)
        self.assertTrue(authorization.closed.is_set())

    async def test_wait_for_timeout_cause_chain_cannot_retain_capture_payload(self):
        budget = CaptureBudget()
        adapter, service, factory = self._adapter(budget=budget)
        authorization = _Authorization()
        cleanup_release = asyncio.Event()
        cleanup_release.set()
        factory.release_gate = asyncio.Event()
        handle = None
        logits_reference = None
        slots = []
        rpc_context = _TimeoutWriteRpcContext()
        service.coordinator.limits.output_stall_timeout_seconds = 0.01
        service._write = types.MethodType(CoordinatorService._write, service)

        async def producer(payload, _rpc_context, deadline, _auth, slot):
            nonlocal handle, logits_reference
            slots.append(slot)
            slot["entered"] = True
            slot["trusted_context"] = factory.context
            slot["resource_cleanup_required"] = True
            slot["resource_cleanup_confirmed"] = False
            adapter._reserve_capture(payload, factory.context, slot)
            logits = _TrackedList([0.125] * 32000)
            logits_reference = weakref.ref(logits)
            message = {"type": "token", "logits": logits}
            wrapped = _AuthorizedStreamContext(rpc_context, authorization)
            try:
                await service._write(wrapped, message, deadline)
            except TimeoutError as error:
                slot["write_exception"] = error
            finally:
                logits = None
                message = None
            cleanup = asyncio.create_task(cleanup_release.wait())
            slot["cleanup_task"] = cleanup
            await cleanup
            handle = _CaptureHandle(
                confirmed=True,
                buffer_check=lambda: logits_reference() is None)
            slot["handle"] = handle
            adapter._defer_generate_resources(factory.context, (cleanup,), slot)
            slot["authorization_transferred"] = True

        await self._call_generate(
            adapter, authorization, producer=producer, context=rpc_context)
        slot = slots[0]
        error = slot["write_exception"]
        self.assertIsInstance(error, TimeoutError)
        self.assertIsInstance(error.__cause__, asyncio.CancelledError)
        self.assertIsNone(logits_reference())
        frames = _exception_traceback_frames(error)
        self.assertTrue(frames)
        for frame in frames:
            locals_ = frame.f_locals.values()
            self.assertFalse(any(isinstance(value, _TrackedList) for value in locals_))
            self.assertFalse(any(type(value) is bytes and len(value) > 100_000
                                 for value in locals_))

        await asyncio.wait_for(handle.reclaim_started.wait(), 1)
        self.assertTrue(handle.buffer_references_cleared)
        self.assertGreater(budget.status().reserved_bytes, 0)
        self.assertFalse(factory.release_started.is_set())
        handle.reclaim_release.set()
        await asyncio.wait_for(factory.release_started.wait(), 1)
        self.assertGreater(budget.status().reserved_bytes, 0)
        self.assertFalse(authorization.closed.is_set())
        factory.release_gate.set()
        await asyncio.wait_for(slot["authorization_owner_task"], 1)
        self.assertEqual(budget.status().reserved_bytes, 0)
        self.assertTrue(authorization.closed.is_set())

    async def test_unconfirmed_capture_keeps_authorization_and_stream_reservations(self):
        budget = CaptureBudget()
        adapter, service, factory = self._adapter(budget=budget)
        authorization = _Authorization()
        cleanup_release = asyncio.Event()
        handle = _CaptureHandle(confirmed=False)
        slots = []

        async def producer(payload, _context, _deadline, _auth, slot):
            slots.append(slot)
            slot["entered"] = True
            slot["trusted_context"] = factory.context
            slot["resource_cleanup_required"] = True
            slot["resource_cleanup_confirmed"] = False
            adapter._reserve_capture(payload, factory.context, slot)
            slot["handle"] = handle
            cleanup = asyncio.create_task(cleanup_release.wait())
            slot["cleanup_task"] = cleanup
            adapter._defer_generate_resources(factory.context, (cleanup,), slot)
            slot["authorization_transferred"] = True

        await self._call_generate(adapter, authorization, producer=producer)
        slot = slots[0]
        cleanup_release.set()
        await asyncio.wait_for(handle.reclaim_started.wait(), 1)
        handle.reclaim_release.set()
        await asyncio.wait_for(slot["authorization_owner_task"], 1)

        self.assertFalse(authorization.closed.is_set())
        self.assertTrue(slot["retained"])
        self.assertTrue(slot["capture_pending"])
        self.assertIn(slot, adapter._unreclaimed_generate_slots)
        self.assertTrue(adapter.unavailable)
        self.assertGreater(budget.status().reserved_bytes, 0)
        self.assertEqual(service.active_streams, 1)
        self.assertFalse(factory.released)

    async def test_already_finished_cleanup_failures_keep_authorization_and_capture_lease(self):
        budget = CaptureBudget()
        adapter, service, factory = self._adapter(budget=budget)
        authorization = _Authorization()
        slots = []

        async def fail_cleanup():
            raise RuntimeError("synthetic cleanup failure")

        async def producer(payload, _context, _deadline, _auth, slot):
            slots.append(slot)
            slot["entered"] = True
            slot["trusted_context"] = factory.context
            adapter._reserve_capture(payload, factory.context, slot)
            cleanup = asyncio.create_task(fail_cleanup())
            context_release = asyncio.create_task(fail_cleanup())
            slot["cleanup_task"] = cleanup
            slot["context_release_task"] = context_release
            slot["capture_cleanup_task"] = context_release
            slot["resource_cleanup_required"] = True
            slot["resource_cleanup_confirmed"] = False
            slot["authorization_transferred"] = True
            await asyncio.gather(cleanup, context_release, return_exceptions=True)

        await self._call_generate(adapter, authorization, producer=producer)
        slot = slots[0]
        await asyncio.wait_for(slot["authorization_owner_task"], 1)

        self.assertTrue(slot["cleanup_task"].done())
        self.assertTrue(slot["context_release_task"].done())
        self.assertFalse(authorization.closed.is_set())
        self.assertEqual(authorization.close_count, 0)
        self.assertTrue(slot["retained"])
        self.assertTrue(slot["capture_pending"])
        self.assertIn(slot, adapter._unreclaimed_generate_slots)
        self.assertGreater(budget.status().reserved_bytes, 0)
        self.assertEqual(service.active_streams, 1)
        self.assertEqual(adapter.active_generate_streams, 1)
        self.assertFalse(factory.released)

    async def test_capture_configuration_rejects_before_generate_and_noncapture_remains_available(self):
        adapter, service, factory = self._adapter()
        authorization = _Authorization()
        called = []

        async def producer(*_args):
            called.append(True)

        context = await self._call_generate(adapter, authorization)
        self.assertFalse(called)
        self.assertEqual(factory.created, 0)
        self.assertTrue(authorization.closed.is_set())
        self.assertTrue(context.aborted)
        self.assertEqual(service.active_streams, 0)

        noncapture_auth = _Authorization()
        await self._call_generate(
            adapter, noncapture_auth, capture=False, producer=producer)
        self.assertEqual(len(called), 1)
        self.assertTrue(noncapture_auth.closed.is_set())

    async def test_capture_budget_must_match_actual_coordinator_queue(self):
        budget = CaptureBudget(CaptureBudgetConfig(output_queue_slots=15))
        adapter, service, _factory = self._adapter(budget=budget)
        authorization = _Authorization()
        called = []

        async def producer(*_args):
            called.append(True)

        context = await self._call_generate(adapter, authorization)
        self.assertFalse(called)
        self.assertEqual(_factory.created, 0)
        self.assertTrue(authorization.closed.is_set())
        self.assertTrue(context.aborted)
        self.assertEqual(budget.status().reserved_bytes, 0)
        self.assertEqual(service.active_streams, 0)

    async def test_vocabulary_mismatch_rejects_before_context_or_generate(self):
        budget = CaptureBudget()
        adapter, service, factory = self._adapter(budget=budget)
        adapter.service.coordinator.manifest = {"config": {"vocab_size": 32001}}
        authorization = _Authorization()
        called = []

        async def producer(*_args):
            called.append(True)

        context = await self._call_generate(adapter, authorization)
        self.assertFalse(called)
        self.assertEqual(factory.created, 0)
        self.assertFalse(factory.released)
        self.assertTrue(context.aborted)
        self.assertTrue(authorization.closed.is_set())
        self.assertEqual(budget.status().reserved_bytes, 0)
        self.assertEqual(service.active_streams, 0)

    async def test_full_queue_and_repeated_cancellation_keep_capture_until_producer_retires(self):
        budget = CaptureBudget()
        adapter, service, factory = self._adapter(budget=budget)
        authorization = _Authorization()
        queue = asyncio.Queue(maxsize=16)
        for index in range(16):
            queue.put_nowait(index)
        producer_waiting = asyncio.Event()
        producer_cancelled = asyncio.Event()
        producer_release = asyncio.Event()

        async def resistant_producer():
            producer_waiting.set()
            try:
                await queue.put("blocked-output")
            except asyncio.CancelledError:
                producer_cancelled.set()
                await producer_release.wait()

        producer = asyncio.create_task(resistant_producer())
        await producer_waiting.wait()
        adapter.active_generate_streams = 1
        service.active_streams = 1
        trusted = factory.context
        slot = {
            "generate": True, "service": True, "entered": True,
            "cleanup_task": producer, "capture_lease": None,
            "capture_pending": False, "trusted_context": trusted,
            "context_release_task": None, "capture_cleanup_task": None,
            "retained": False, "resource_cleanup_confirmed": False,
            "admission_cleanup_tasks": set(),
        }
        adapter._reserve_capture({"capture_logits": True}, trusted, slot)
        handle = _QueuedCaptureHandle(queue, producer)
        slot["handle"] = handle
        cleanup_owner = adapter._defer_generate_resources(
            trusted, (producer,), slot)
        authorization_owner = adapter._retain_generate_authorization_owner(
            authorization, slot)

        producer.cancel()
        await asyncio.wait_for(producer_cancelled.wait(), 1)
        self.assertEqual(queue.qsize(), 16)
        self.assertFalse(handle.reclaim_started.is_set())
        self.assertFalse(cleanup_owner.done())
        self.assertFalse(authorization.closed.is_set())
        self.assertGreater(budget.status().reserved_bytes, 0)

        first_cancelled = asyncio.Event()
        second_cancelled = asyncio.Event()
        waiter_started = asyncio.Event()

        async def wait_for_cleanup_owner():
            waiter_started.set()
            try:
                await asyncio.shield(cleanup_owner)
            except asyncio.CancelledError:
                first_cancelled.set()
                try:
                    await asyncio.shield(cleanup_owner)
                except asyncio.CancelledError:
                    second_cancelled.set()
                    raise

        waiter = asyncio.create_task(wait_for_cleanup_owner())
        await waiter_started.wait()
        waiter.cancel()
        await asyncio.wait_for(first_cancelled.wait(), 1)
        self.assertFalse(cleanup_owner.done())
        waiter.cancel()
        await asyncio.wait_for(second_cancelled.wait(), 1)
        with self.assertRaises(asyncio.CancelledError):
            await waiter
        self.assertFalse(cleanup_owner.cancelled())
        self.assertEqual(queue.qsize(), 16)
        self.assertFalse(factory.released)

        producer_release.set()
        await asyncio.wait_for(authorization_owner, 1)
        self.assertTrue(handle.reclaim_started.is_set())
        self.assertTrue(queue.empty())
        self.assertTrue(authorization.closed.is_set())
        self.assertEqual(budget.status().reserved_bytes, 0)
        self.assertEqual(factory.released, [trusted])
        self.assertEqual(service.active_streams, 0)

    async def test_eight_capture_reservations_are_atomic_and_ninth_is_rejected(self):
        adapter, _service, _factory = self._adapter(budget=CaptureBudget())
        slots = []
        for index in range(8):
            trusted = types.SimpleNamespace(request_id=f"req_{index:032x}")
            slot = {"capture_lease": None, "capture_pending": False}
            adapter._reserve_capture({"capture_logits": True}, trusted, slot)
            slots.append(slot)
        status = adapter.capture_budget.status()
        self.assertEqual(status.active_captures, 8)
        self.assertEqual(status.reserved_bytes, 8 * status.per_capture.total_bytes)
        with self.assertRaises(ServiceRequestError) as rejected:
            adapter._reserve_capture(
                {"capture_logits": True},
                types.SimpleNamespace(request_id="req_" + "f" * 32),
                {"capture_lease": None, "capture_pending": False})
        self.assertEqual(rejected.exception.code, "CAPACITY_EXHAUSTED")
        self.assertEqual(adapter.capture_budget.status().active_captures, 8)
        self.assertEqual(adapter.capture_budget.status().reserved_bytes, status.reserved_bytes)
        for slot in slots:
            adapter.capture_budget.release(slot["capture_lease"], buffers_reclaimed=True)

    async def test_valid_capture_capacity_denial_sends_binding_before_abort(self):
        budget = CaptureBudget()
        factory = _GatedContextFactory()
        factory.release_gate.set()
        service = _Service()
        adapter = SecureCoordinatorService(
            service, authorizer=_Authorizer(),
            authorization_watcher=lambda _authorization: asyncio.Future(),
            request_context_factory=factory, capture_budget=budget)
        authorization = _Authorization()
        authorization.binding_bytes = _canonical_generate_binding(9)
        leases = [budget.reserve(f"req_{index:032x}") for index in range(8)]
        context = _RpcContext()
        context.events = []

        async def send_initial_metadata(metadata):
            context.events.append(("metadata", tuple(metadata)))

        async def abort(code, details):
            context.events.append(("abort", code, details))
            context.aborted.append((code, details))

        async def set_trailing_metadata(metadata):
            context.events.append(("trailing", tuple(metadata)))

        context.send_initial_metadata = send_initial_metadata
        context.set_trailing_metadata = set_trailing_metadata
        context.abort = abort
        reserve_calls = []
        original_reserve = adapter._reserve_capture

        def record_reserve(payload, trusted_context, slot):
            reserve_calls.append((tuple(context.events), slot))
            return original_reserve(payload, trusted_context, slot)

        adapter._reserve_capture = record_reserve

        async def authorize(*_args):
            return authorization

        adapter._authorize = authorize
        coordinator_submissions = []

        def reject_unexpected_submission(*_args, **_kwargs):
            coordinator_submissions.append(True)
            raise AssertionError("capacity denial must precede coordinator submission")

        service.coordinator.submit = reject_unexpected_submission
        torch_calls = []
        torch_stub = types.ModuleType("torch")
        torch_stub.long = object()

        def record_tensor(*_args, **_kwargs):
            torch_calls.append(True)
            raise AssertionError("capacity denial must precede tensor allocation")

        torch_stub.tensor = record_tensor
        guarded_calls = []

        async def record_guard(coroutine, *args, **kwargs):
            guarded_calls.append((args, kwargs))
            return await coroutine

        request = encode_json({
            "input_ids": [1], "new_tokens": 1,
            "timeout_seconds": 5, "capture_logits": True})
        with patch.dict(sys.modules, {
                "grpc": self._grpc_stub(), "torch": torch_stub}), patch(
                "steamboat_runtime.secure_coordinator_service._run_guarded",
                record_guard):
            await adapter.generate_rpc(request, context)

        self.assertEqual(
            [event[0] for event in context.events],
            ["metadata", "trailing", "abort"])
        self.assertEqual(context.events[0][1],
                         ((BINDING_METADATA_KEY, authorization.binding_bytes),))
        _assert_exact_capacity_marker(
            self, context.events[1][1], authorization.binding_bytes)
        self.assertEqual(service.aborts[0].code, "CAPACITY_EXHAUSTED")
        self.assertEqual(len(reserve_calls), 1)
        self.assertEqual([event[0] for event in reserve_calls[0][0]], ["metadata"])
        slot = reserve_calls[0][1]
        self.assertTrue(slot["entered"])
        self.assertIsNone(slot["capture_lease"])
        self.assertEqual(len(guarded_calls), 2)
        metadata_guard_args, metadata_guard_kwargs = guarded_calls[1]
        self.assertIs(metadata_guard_args[0], authorization)
        self.assertIsNot(metadata_guard_args[1], adapter.authorization_watcher)
        self.assertEqual(
            metadata_guard_kwargs["absolute_deadline"],
            factory.context.hard_monotonic_deadline)
        self.assertEqual(metadata_guard_kwargs["absolute_deadline"],
                         guarded_calls[0][1]["absolute_deadline"])
        self.assertEqual(coordinator_submissions, [])
        self.assertEqual(torch_calls, [])
        self.assertEqual(budget.status().active_captures, 8)
        self.assertEqual(budget.status().reserved_bytes,
                         8 * budget.per_capture.total_bytes)
        self.assertTrue(authorization.failed)
        self.assertTrue(authorization.closed.is_set())
        self.assertEqual(factory.released, [factory.context])
        self.assertEqual(service.active_streams, 0)
        self.assertEqual(adapter.active_generate_streams, 0)
        for lease in leases:
            budget.release(lease, buffers_reclaimed=True)

    async def test_stream_limit_denial_is_bound_without_disturbing_active_stream(self):
        class CountingFactory(_GatedContextFactory):
            def __init__(self):
                super().__init__()
                self.create_calls = 0

            async def create_with_deadline(self, authorization, payload, *,
                                           absolute_deadline):
                self.create_calls += 1
                return await super().create_with_deadline(
                    authorization, payload, absolute_deadline=absolute_deadline)

        factory = CountingFactory()
        factory.release_gate.set()
        service = _Service()
        adapter = SecureCoordinatorService(
            service, authorizer=_Authorizer(),
            authorization_watcher=lambda _authorization: asyncio.Future(),
            request_context_factory=factory, max_generate_streams=1)
        authorization_first = _Authorization()
        authorization_second = _Authorization()
        authorization_first.binding_bytes = _canonical_generate_binding(10)
        authorization_second.binding_bytes = _canonical_generate_binding(11)
        first_context = _RpcContext()
        second_context = _RpcContext()

        def record_context(rpc_context):
            rpc_context.events = []

            async def send_initial_metadata(metadata):
                rpc_context.events.append(("metadata", tuple(metadata)))

            async def set_trailing_metadata(metadata):
                rpc_context.events.append(("trailing", tuple(metadata)))

            async def abort(code, details):
                rpc_context.events.append(("abort", code, details))
                rpc_context.aborted.append((code, details))

            rpc_context.send_initial_metadata = send_initial_metadata
            rpc_context.set_trailing_metadata = set_trailing_metadata
            rpc_context.abort = abort

        record_context(first_context)
        record_context(second_context)

        async def authorize(_method, _data, _payload, rpc_context):
            return (authorization_first if rpc_context is first_context
                    else authorization_second)

        adapter._authorize = authorize
        producer_started = asyncio.Event()
        release_first = asyncio.Event()

        async def blocked_generate(
                _request, _context, _deadline, _trusted, _authorization,
                _slot, _lifetime):
            producer_started.set()
            await release_first.wait()

        adapter._generate_with_context = blocked_generate

        request = encode_json({
            "input_ids": [1], "new_tokens": 1,
            "timeout_seconds": 5, "capture_logits": False})
        with patch.dict(sys.modules, {"grpc": self._grpc_stub()}):
            first_task = asyncio.create_task(
                adapter.generate_rpc(request, first_context))
            await asyncio.wait_for(producer_started.wait(), 1)
            await adapter.generate_rpc(request, second_context)

            self.assertFalse(first_task.done())
            self.assertFalse(authorization_first.closed.is_set())
            self.assertEqual([event[0] for event in first_context.events], ["metadata"])
            self.assertEqual(
                [event[0] for event in second_context.events],
                ["metadata", "trailing", "abort"])
            self.assertEqual(second_context.events[0][1],
                ((BINDING_METADATA_KEY, authorization_second.binding_bytes),))
            _assert_exact_capacity_marker(
                self, second_context.events[1][1],
                authorization_second.binding_bytes)
            self.assertEqual(
                second_context.aborted[0][0], self._grpc_stub().StatusCode.RESOURCE_EXHAUSTED)
            self.assertTrue(authorization_second.closed.is_set())
            self.assertEqual(authorization_second.close_count, 1)
            self.assertEqual(factory.create_calls, 1)
            self.assertEqual(adapter.active_generate_streams, 1)
            self.assertEqual(service.active_streams, 1)
            self.assertEqual(service.counters["rejected_requests"], 1)
            self.assertFalse(adapter.unavailable)

            release_first.set()
            await asyncio.wait_for(first_task, 1)

        self.assertTrue(authorization_first.closed.is_set())
        self.assertEqual(adapter.active_generate_streams, 0)
        self.assertEqual(service.active_streams, 0)

    async def test_stream_limit_metadata_observes_payload_deadline_without_rpc_deadline(self):
        class CountingFactory(_GatedContextFactory):
            def __init__(self):
                super().__init__()
                self.create_calls = 0

            async def create_with_deadline(self, authorization, payload, *,
                                           absolute_deadline):
                self.create_calls += 1
                return await super().create_with_deadline(
                    authorization, payload, absolute_deadline=absolute_deadline)

        factory = CountingFactory()
        factory.release_gate.set()
        service = _Service()
        adapter = SecureCoordinatorService(
            service, authorizer=_Authorizer(),
            authorization_watcher=lambda _authorization: asyncio.Future(),
            request_context_factory=factory, max_generate_streams=1)
        authorization_first = _Authorization()
        authorization_second = _Authorization()
        authorization_first.binding_bytes = _canonical_generate_binding(13)
        authorization_second.binding_bytes = _canonical_generate_binding(18)
        first_context = _RpcContext()
        second_context = _NoTransportDeadlineRpcContext()
        started = asyncio.Event()
        cancelled = asyncio.Event()
        producer_started = asyncio.Event()
        release_first = asyncio.Event()
        first_context.events = []
        second_context.events = []

        async def first_metadata(metadata):
            first_context.events.append(("metadata", tuple(metadata)))

        async def first_abort(code, details):
            first_context.events.append(("abort", code, details))

        first_context.send_initial_metadata = first_metadata
        first_context.abort = first_abort

        async def stalled_metadata(metadata):
            second_context.events.append(("metadata", tuple(metadata)))
            started.set()
            try:
                await asyncio.Event().wait()
            except asyncio.CancelledError:
                cancelled.set()
                raise

        async def set_trailing_metadata(metadata):
            second_context.events.append(("trailing", tuple(metadata)))

        async def second_abort(code, details):
            second_context.events.append(("abort", code, details))

        second_context.send_initial_metadata = stalled_metadata
        second_context.set_trailing_metadata = set_trailing_metadata
        second_context.abort = second_abort

        async def authorize(_method, _data, _payload, rpc_context):
            return (authorization_first if rpc_context is first_context
                    else authorization_second)

        async def hold_first_generate(
                _request, _context, _deadline, _trusted, _authorization,
                _slot, _lifetime):
            producer_started.set()
            await release_first.wait()

        adapter._authorize = authorize
        adapter._generate_with_context = hold_first_generate
        first_request = encode_json({
            "input_ids": [1], "new_tokens": 1,
            "timeout_seconds": 5, "capture_logits": False})
        second_request = encode_json({
            "input_ids": [1], "new_tokens": 1,
            "timeout_seconds": 0.08, "capture_logits": False})
        with patch.dict(sys.modules, {"grpc": self._grpc_stub()}):
            first_task = asyncio.create_task(
                adapter.generate_rpc(first_request, first_context))
            await asyncio.wait_for(producer_started.wait(), 1)
            second_task = asyncio.create_task(
                adapter.generate_rpc(second_request, second_context))
            await asyncio.wait_for(started.wait(), 1)
            with self.assertRaises(TimeoutError):
                await asyncio.wait_for(second_task, 1)

            self.assertFalse(first_task.done())
            self.assertFalse(authorization_first.closed.is_set())
            self.assertEqual(adapter.active_generate_streams, 1)
            self.assertEqual(service.active_streams, 1)
            release_first.set()
            await asyncio.wait_for(first_task, 1)

        self.assertTrue(cancelled.is_set())
        self.assertEqual([event[0] for event in second_context.events], ["metadata"])
        self.assertEqual(authorization_second.close_count, 1)
        self.assertTrue(authorization_second.failed)
        self.assertTrue(authorization_second.closed.is_set())
        self.assertEqual(authorization_first.close_count, 1)
        self.assertTrue(authorization_first.closed.is_set())
        self.assertEqual(factory.create_calls, 1)
        self.assertEqual(adapter.active_generate_streams, 0)
        self.assertEqual(service.active_streams, 0)
        self.assertEqual(service.counters["rejected_requests"], 1)
        self.assertFalse(adapter.unavailable)

    async def test_stream_limit_metadata_revocation_and_expiry_fail_closed(self):
        for expired in (False, True):
            with self.subTest(expired=expired):
                factory = _ContextFactory()
                service = _Service()
                service.active_streams = 1
                adapter = SecureCoordinatorService(
                    service, authorizer=_Authorizer(),
                    authorization_watcher=lambda _authorization: asyncio.Future(),
                    request_context_factory=factory, max_generate_streams=1)
                adapter.active_generate_streams = 1
                authorization = _Authorization()
                authorization.binding_bytes = _canonical_generate_binding(
                    14 if expired else 15)
                if expired:
                    authorization.deadline_monotonic = time.monotonic() - 1
                context = _NoTransportDeadlineRpcContext()
                context.events = []
                started = asyncio.Event()
                revoked = asyncio.Event()

                async def stalled_metadata(metadata):
                    context.events.append(("metadata", tuple(metadata)))
                    started.set()
                    await asyncio.Event().wait()

                context.send_initial_metadata = stalled_metadata
                context.set_trailing_metadata = lambda metadata: context.events.append(
                    ("trailing", tuple(metadata)))
                context.abort = lambda code, details: context.events.append(
                    ("abort", code, details))

                async def authorize(*_args):
                    return authorization

                async def watcher(_authorization):
                    await revoked.wait()

                adapter._authorize = authorize
                adapter.authorization_watcher = watcher
                request = encode_json({
                    "input_ids": [1], "new_tokens": 1,
                    "timeout_seconds": 5, "capture_logits": False})
                with patch.dict(sys.modules, {"grpc": self._grpc_stub()}):
                    task = asyncio.create_task(
                        adapter.generate_rpc(request, context))
                    if expired:
                        with self.assertRaises(AuthorizationRevoked):
                            await asyncio.wait_for(task, 1)
                    else:
                        await asyncio.wait_for(started.wait(), 1)
                        revoked.set()
                        with self.assertRaises(AuthorizationRevoked):
                            await asyncio.wait_for(task, 1)

                self.assertEqual([event[0] for event in context.events],
                                 [] if expired else ["metadata"])
                self.assertEqual(authorization.close_count, 1)
                self.assertTrue(authorization.failed)
                self.assertTrue(authorization.closed.is_set())
                self.assertEqual(factory.created, 0)
                self.assertEqual(adapter.active_generate_streams, 1)
                self.assertEqual(service.active_streams, 1)
                self.assertEqual(service.counters["rejected_requests"], 1)

    async def test_stream_limit_repeated_cancel_retains_late_pending_descendant(self):
        from steamboat_runtime.protocol import secure_transport

        factory = _ContextFactory()
        service = _Service()
        service.active_streams = 1
        adapter = SecureCoordinatorService(
            service, authorizer=_Authorizer(),
            authorization_watcher=lambda _authorization: asyncio.Future(),
            request_context_factory=factory, max_generate_streams=1)
        adapter.active_generate_streams = 1
        authorization = _Authorization()
        authorization.binding_bytes = _canonical_generate_binding(16)
        context = _NoTransportDeadlineRpcContext()
        operation_started = asyncio.Event()
        operation_cancelled = asyncio.Event()
        operation_release = asyncio.Event()
        child_release = asyncio.Event()
        child_started = asyncio.Event()
        context.events = []
        child_tasks = []

        async def wait_for_child_release():
            child_started.set()
            await child_release.wait()

        async def resistant_metadata(metadata):
            context.events.append(("metadata", tuple(metadata)))
            operation_started.set()
            try:
                await asyncio.Event().wait()
            except asyncio.CancelledError:
                operation_cancelled.set()
                await operation_release.wait()
                child = asyncio.create_task(wait_for_child_release())
                child_tasks.append(child)
                await child_started.wait()
                raise SecureTaskPending((child,), "late metadata descendant")

        context.send_initial_metadata = resistant_metadata
        context.set_trailing_metadata = lambda metadata: context.events.append(
            ("trailing", tuple(metadata)))
        context.abort = lambda code, details: context.events.append(
            ("abort", code, details))

        async def authorize(*_args):
            return authorization

        adapter._authorize = authorize
        request = encode_json({
            "input_ids": [1], "new_tokens": 1,
            "timeout_seconds": 5, "capture_logits": False})
        caller = None

        async def drain_owned_tasks():
            operation_release.set()
            child_release.set()
            if caller is not None and not caller.done():
                caller.cancel()
            if caller is not None:
                done, pending = await asyncio.wait((caller,), timeout=2)
                if pending:
                    caller.cancel()
                    done, pending = await asyncio.wait(pending, timeout=2)
                if pending:
                    raise AssertionError("late metadata caller did not drain")
                await asyncio.gather(*done, return_exceptions=True)
            for _ in range(3):
                tasks = set(adapter.pending_tasks)
                tasks.update(adapter.runtime_owner.pending_tasks)
                live = tuple(task for task in tasks if not task.done())
                if not live:
                    await asyncio.sleep(0)
                    if not adapter.pending_tasks and not adapter.runtime_owner.pending_tasks:
                        return
                    continue
                done, pending = await asyncio.wait(live, timeout=1)
                if pending:
                    for task in pending:
                        task.cancel()
                    done_late, pending = await asyncio.wait(pending, timeout=1)
                    done = set(done) | set(done_late)
                if pending:
                    raise AssertionError("late metadata ownership tasks did not drain")
                await asyncio.gather(*done, return_exceptions=True)
            if adapter.pending_tasks or adapter.runtime_owner.pending_tasks:
                raise AssertionError("late metadata task registries did not drain")

        self.addAsyncCleanup(drain_owned_tasks)
        with patch.dict(sys.modules, {"grpc": self._grpc_stub()}), patch.object(
                secure_transport, "MAX_CANCELLATION_GRACE_SECONDS", 0.08):
            caller = asyncio.create_task(adapter.generate_rpc(request, context))
            await asyncio.wait_for(operation_started.wait(), 1)
            cancellation_started = time.monotonic()
            caller.cancel()
            await asyncio.wait_for(operation_cancelled.wait(), 1)
            caller.cancel()
            with self.assertRaises(SecureTaskPending) as pending:
                await asyncio.wait_for(caller, 1)
            self.assertLess(time.monotonic() - cancellation_started, 0.5)

            operation_tasks = tuple(pending.exception.tasks)
            self.assertTrue(operation_tasks)
            self.assertEqual(child_tasks, [])
            self.assertEqual(authorization.close_count, 0)
            self.assertFalse(authorization.failed)
            self.assertFalse(authorization.closed.is_set())
            self.assertTrue(adapter.unavailable)
            self.assertTrue(any(task in adapter.pending_tasks
                                for task in operation_tasks))
            self.assertEqual(factory.created, 0)
            self.assertEqual(adapter.active_generate_streams, 1)
            self.assertEqual(service.active_streams, 1)
            self.assertEqual(service.counters["rejected_requests"], 1)

            operation_release.set()
            await asyncio.wait_for(asyncio.gather(
                *operation_tasks, return_exceptions=True), 1)
            self.assertEqual(len(child_tasks), 1)
            child = child_tasks[0]
            self.assertTrue(child_started.is_set())
            self.assertIn(child, adapter.pending_tasks)
            self.assertIn(child, adapter.runtime_owner.pending_tasks)
            self.assertEqual(authorization.close_count, 0)
            self.assertFalse(authorization.closed.is_set())

            child_release.set()
            await asyncio.wait_for(authorization.closed.wait(), 1)

            async def wait_for_registry_release():
                while (child in adapter.pending_tasks
                       or child in adapter.runtime_owner.pending_tasks):
                    await asyncio.sleep(0)

            await asyncio.wait_for(wait_for_registry_release(), 1)

        self.assertEqual(authorization.close_count, 1)
        self.assertTrue(authorization.failed)
        self.assertNotIn(child, adapter.pending_tasks)
        self.assertNotIn(child, adapter.runtime_owner.pending_tasks)
        self.assertEqual(factory.created, 0)
        self.assertEqual(adapter.active_generate_streams, 1)
        self.assertEqual(service.active_streams, 1)

    async def test_stream_limit_denial_fails_closed_when_trailer_api_is_missing(self):
        factory = _ContextFactory()
        service = _Service()
        service.active_streams = 1
        adapter = SecureCoordinatorService(
            service, authorizer=_Authorizer(),
            authorization_watcher=lambda _authorization: asyncio.Future(),
            request_context_factory=factory, max_generate_streams=1)
        adapter.active_generate_streams = 1
        authorization = _Authorization()
        authorization.binding_bytes = _canonical_generate_binding(17)
        context = _NoTransportDeadlineRpcContext()
        context.events = []

        async def send_initial_metadata(metadata):
            context.events.append(("metadata", tuple(metadata)))

        async def abort(code, details):
            context.events.append(("abort", code, details))

        context.send_initial_metadata = send_initial_metadata
        context.abort = abort

        async def authorize(*_args):
            return authorization

        adapter._authorize = authorize
        request = encode_json({
            "input_ids": [1], "new_tokens": 1,
            "timeout_seconds": 5, "capture_logits": False})
        with patch.dict(sys.modules, {"grpc": self._grpc_stub()}):
            with self.assertRaises(SecureTransportError):
                await adapter.generate_rpc(request, context)

        self.assertEqual([event[0] for event in context.events], ["metadata"])
        self.assertEqual(authorization.close_count, 1)
        self.assertTrue(authorization.failed)
        self.assertTrue(authorization.closed.is_set())
        self.assertEqual(factory.created, 0)
        self.assertEqual(adapter.active_generate_streams, 1)
        self.assertEqual(service.active_streams, 1)
        self.assertEqual(service.counters["rejected_requests"], 1)

    async def test_coordinator_queue_capacity_rejection_is_known_pre_admission(self):
        from collections import deque
        from steamboat_runtime.coordinator import Coordinator

        class InputTensor:
            detach_called = False

            def detach(self):
                self.detach_called = True
                raise AssertionError("queue rejection must precede coordinator cloning")

        tensor = InputTensor()
        torch_stub = types.ModuleType("torch")
        torch_stub.long = object()
        torch_stub.tensor = lambda *_args, **_kwargs: tensor

        coordinator = Coordinator.__new__(Coordinator)
        coordinator._ready = True
        coordinator._closed = False
        coordinator._fatal_error = None
        coordinator.model = types.SimpleNamespace(
            validate_tokens=lambda _input: 1,
            supervision_status=lambda: {"active_compute": False})
        coordinator.manifest = {
            "config": {"vocab_size": 32000},
            "limits": {"max_positions": 2048}}
        coordinator.limits = types.SimpleNamespace(
            request_timeout_seconds=30, max_sessions=1,
            max_waiting_admissions=1, output_queue_tokens=16)
        coordinator._slots = 1
        queued = object()
        coordinator._waiting = deque((queued,))
        coordinator._requests = {}

        factory = _GatedContextFactory()
        factory.release_gate.set()
        service = _Service()
        service.coordinator = coordinator
        budget = CaptureBudget()
        adapter = SecureCoordinatorService(
            service, authorizer=_Authorizer(),
            authorization_watcher=lambda _authorization: asyncio.Future(),
            request_context_factory=factory, capture_budget=budget)
        authorization = _Authorization()
        authorization.binding_bytes = _canonical_generate_binding(12)
        context = _RpcContext()
        events = []

        async def send_initial_metadata(metadata):
            events.append(("metadata", tuple(metadata)))

        async def abort(code, details):
            events.append(("abort", code, details))
            context.aborted.append((code, details))

        async def set_trailing_metadata(metadata):
            events.append(("trailing", tuple(metadata)))

        context.send_initial_metadata = send_initial_metadata
        context.set_trailing_metadata = set_trailing_metadata
        context.abort = abort
        async def authorize(*_args):
            return authorization

        adapter._authorize = authorize
        slots = []
        reserve = adapter._reserve_capture

        def record_reservation(payload, trusted, slot):
            slots.append(slot)
            return reserve(payload, trusted, slot)

        adapter._reserve_capture = record_reservation

        async def run_guarded(coroutine, *_args, **_kwargs):
            return await asyncio.create_task(coroutine)

        request = encode_json({
            "input_ids": [1], "new_tokens": 1,
            "timeout_seconds": 5, "capture_logits": True})
        with patch.dict(sys.modules, {
                "grpc": self._grpc_stub(), "torch": torch_stub}), patch(
                "steamboat_runtime.secure_coordinator_service._run_guarded",
                run_guarded):
            await adapter.generate_rpc(request, context)

        self.assertEqual(
            [event[0] for event in events], ["metadata", "trailing", "abort"])
        self.assertEqual(events[0][1],
                         ((BINDING_METADATA_KEY, authorization.binding_bytes),))
        _assert_exact_capacity_marker(self, events[1][1], authorization.binding_bytes)
        self.assertEqual(service.aborts[0].code, "CAPACITY_EXHAUSTED")
        self.assertEqual(len(slots), 1)
        self.assertTrue(slots[0]["capture_submission_attempted"])
        self.assertTrue(slots[0]["known_pre_admission_capacity_rejection"])
        self.assertIsNone(slots[0].get("handle"))
        self.assertFalse(tensor.detach_called)
        self.assertEqual(coordinator._requests, {})
        self.assertEqual(coordinator._slots, 1)
        self.assertEqual(tuple(coordinator._waiting), (queued,))
        self.assertEqual(budget.status().reserved_bytes, 0)
        self.assertFalse(adapter.unavailable)
        self.assertTrue(authorization.closed.is_set())
        self.assertEqual(factory.released, [factory.context])
        self.assertEqual(service.active_streams, 0)
        self.assertEqual(adapter.active_generate_streams, 0)

    async def test_post_handle_capacity_is_execution_failure_after_confirmed_cleanup(self):
        from steamboat_runtime.coordinator import CoordinatorError

        class CapacityHandle:
            session_id = "ses_" + "8" * 32

            def __init__(self):
                self.result_calls = 0
                self.buffers_reclaimed = False

            async def __aiter__(self):
                if False:
                    yield None

            async def result(self):
                self.result_calls += 1
                if self.result_calls == 1:
                    raise CoordinatorError(
                        "CAPACITY_EXHAUSTED", "late backend capacity failure")
                return types.SimpleNamespace(cleanup_complete=True)

            async def reclaim_capture_buffers(self):
                self.buffers_reclaimed = True
                return True

        factory = _GatedContextFactory()
        factory.release_gate.set()
        service = _Service()
        handle = CapacityHandle()

        def submit(_input, _new_tokens, *, trusted_request_context=None, **_kwargs):
            return handle

        service.coordinator.submit = submit

        async def finish(_handle, *, cancel, release_active_stream):
            return None

        service._finish = finish
        budget = CaptureBudget()
        adapter = SecureCoordinatorService(
            service, authorizer=_Authorizer(),
            authorization_watcher=lambda _authorization: asyncio.Future(),
            request_context_factory=factory, capture_budget=budget)
        authorization = _Authorization()
        async def authorize(*_args):
            return authorization

        adapter._authorize = authorize
        context = _RpcContext()
        events = []

        async def send_initial_metadata(metadata):
            events.append(("metadata", tuple(metadata)))

        async def abort(code, details):
            events.append(("abort", code, details))
            context.aborted.append((code, details))

        async def set_trailing_metadata(metadata):
            events.append(("trailing", tuple(metadata)))

        context.send_initial_metadata = send_initial_metadata
        context.set_trailing_metadata = set_trailing_metadata
        context.abort = abort
        torch_stub = types.ModuleType("torch")
        torch_stub.long = object()
        torch_stub.tensor = lambda *_args, **_kwargs: object()

        async def run_guarded(coroutine, *_args, **_kwargs):
            return await asyncio.create_task(coroutine)

        request = encode_json({
            "input_ids": [1], "new_tokens": 1,
            "timeout_seconds": 5, "capture_logits": True})
        with patch.dict(sys.modules, {
                "grpc": self._grpc_stub(), "torch": torch_stub}), patch(
                "steamboat_runtime.secure_coordinator_service._run_guarded",
                run_guarded):
            await adapter.generate_rpc(request, context)

        self.assertEqual(service.aborts[0].code, "EXECUTION_FAILED")
        self.assertNotEqual(service.aborts[0].code, "CAPACITY_EXHAUSTED")
        self.assertNotIn("trailing", [event[0] for event in events])
        self.assertEqual(handle.result_calls, 2)
        self.assertTrue(handle.buffers_reclaimed)
        self.assertEqual(budget.status().reserved_bytes, 0)
        self.assertTrue(authorization.closed.is_set())
        self.assertFalse(adapter.unavailable)
        self.assertEqual(service.active_streams, 0)
        self.assertEqual(adapter.active_generate_streams, 0)

    async def test_ambiguous_submit_capacity_fails_closed_without_releasing_lease(self):
        from steamboat_runtime.coordinator import CoordinatorError

        factory = _GatedContextFactory()
        service = _Service()
        possible_mutation = []

        def ambiguous_submit(_input, _new_tokens, *, trusted_request_context=None,
                             **_kwargs):
            possible_mutation.append(True)
            raise CoordinatorError(
                "CAPACITY_EXHAUSTED", "coordinator capacity is ambiguous")

        service.coordinator.submit = ambiguous_submit
        budget = CaptureBudget()
        adapter = SecureCoordinatorService(
            service, authorizer=_Authorizer(),
            authorization_watcher=lambda _authorization: asyncio.Future(),
            request_context_factory=factory, capture_budget=budget)
        authorization = _Authorization()
        async def authorize(*_args):
            return authorization

        adapter._authorize = authorize
        context = _RpcContext()
        events = []

        async def send_initial_metadata(metadata):
            events.append(("metadata", tuple(metadata)))

        async def set_trailing_metadata(metadata):
            events.append(("trailing", tuple(metadata)))

        async def abort(code, details):
            events.append(("abort", code, details))
            context.aborted.append((code, details))

        context.send_initial_metadata = send_initial_metadata
        context.set_trailing_metadata = set_trailing_metadata
        context.abort = abort
        torch_stub = types.ModuleType("torch")
        torch_stub.long = object()
        torch_stub.tensor = lambda *_args, **_kwargs: object()

        async def run_guarded(coroutine, *_args, **_kwargs):
            return await asyncio.create_task(coroutine)

        request = encode_json({
            "input_ids": [1], "new_tokens": 1,
            "timeout_seconds": 5, "capture_logits": True})
        with patch.dict(sys.modules, {
                "grpc": self._grpc_stub(), "torch": torch_stub}), patch(
                "steamboat_runtime.secure_coordinator_service._run_guarded",
                run_guarded):
            with self.assertRaises(SecureTaskPending):
                await adapter.generate_rpc(request, context)

        self.assertEqual(possible_mutation, [True])
        self.assertEqual(service.aborts[0].code, "EXECUTION_FAILED")
        self.assertNotIn("trailing", [event[0] for event in events])
        self.assertTrue(adapter.unavailable)
        self.assertEqual(len(adapter._unreclaimed_generate_slots), 1)
        slot = adapter._unreclaimed_generate_slots[0]
        self.assertTrue(slot["capture_submission_attempted"])
        self.assertFalse(slot["known_pre_admission_capacity_rejection"])
        self.assertTrue(slot["retained"])
        self.assertGreater(budget.status().reserved_bytes, 0)
        self.assertFalse(authorization.closed.is_set())
        self.assertEqual(factory.released, [])
        self.assertEqual(service.active_streams, 1)
        self.assertEqual(adapter.active_generate_streams, 1)


class _GatedContextFactory:
    def __init__(self):
        self.context = None
        self.release_started = asyncio.Event()
        self.release_gate = asyncio.Event()
        self.released = []

    async def __call__(self, auth, payload):
        return await self.create_with_deadline(
            auth, payload, absolute_deadline=time.monotonic() + 10)

    async def create_with_deadline(self, auth, _payload, *, absolute_deadline):
        from steamboat_runtime.participant_context import TrustedRequestContext

        self.context = TrustedRequestContext(
            tenant_account_id="acct_" + "1" * 32,
            request_id="req_" + "3" * 32,
            session_id="ses_" + "4" * 32,
            route_id="route_" + "5" * 32,
            coordinator_boot_id="6" * 32,
            route_epoch=1, attempt=1, authorization=auth,
            hard_monotonic_deadline=absolute_deadline)
        return self.context

    async def release(self, context):
        self.release_started.set()
        await self.release_gate.wait()
        self.released.append(context)


class SecureGenerateFinalWaitTests(unittest.IsolatedAsyncioTestCase):
    async def test_generate_returns_pending_while_combined_cleanup_owner_continues(self):
        authorization = _ModelAuthorization()
        authorization.close_gate = asyncio.Event()
        factory = _GatedContextFactory()
        service = _Service()
        budget = CaptureBudget()
        adapter = SecureCoordinatorService(
            service, authorizer=_Authorizer(),
            authorization_watcher=lambda _authorization: asyncio.Future(),
            request_context_factory=factory, capture_budget=budget)
        handle = _CaptureHandle(confirmed=True)

        async def successful_generate(
                _request, _context, _deadline, _trusted_context, auth, slot,
                _context_lifetime):
            slot["capture_submission_attempted"] = True
            slot["handle"] = handle
            cleanup = asyncio.create_task(asyncio.sleep(0))
            slot["cleanup_task"] = cleanup
            await cleanup
            handle.cleanup_complete = True
            result = await handle.result()
            slot["session_cleanup_confirmed"] = (
                result.cleanup_complete is True)
            await auth.complete({"status": "completed"})

        adapter._generate_with_context = successful_generate

        async def authorize(_method, _data, _payload, _context):
            return authorization

        adapter._authorize = authorize
        rpc_context = _NoTransportDeadlineRpcContext()
        request = encode_json({
            "input_ids": [1], "new_tokens": 1,
            "timeout_seconds": 5, "capture_logits": True})
        generate_task = None
        with patch.dict(sys.modules, {"grpc": self._grpc_stub()}), patch(
                "steamboat_runtime.protocol.secure_transport.MAX_CANCELLATION_GRACE_SECONDS",
                0.03):
            generate_task = asyncio.create_task(
                adapter.generate_rpc(request, rpc_context))
            await asyncio.wait_for(handle.reclaim_started.wait(), 1)
            with self.assertRaises(SecureTaskPending) as pending:
                await asyncio.wait_for(generate_task, 1)

        self.assertIsNone(rpc_context.time_remaining())
        self.assertTrue(adapter.unavailable)
        self.assertEqual(len(adapter._unreclaimed_generate_slots), 1)
        slot = adapter._unreclaimed_generate_slots[0]
        self.assertTrue(slot["retained"])
        self.assertIn(slot["authorization_owner_task"], pending.exception.tasks)
        self.assertFalse(slot["authorization_owner_task"].cancelled())
        self.assertFalse(authorization.closed.is_set())
        self.assertGreater(budget.status().reserved_bytes, 0)
        self.assertEqual(service.active_streams, 1)
        self.assertEqual(adapter.active_generate_streams, 1)

        handle.reclaim_release.set()
        await asyncio.wait_for(factory.release_started.wait(), 1)
        self.assertFalse(authorization.closed.is_set())
        self.assertGreater(budget.status().reserved_bytes, 0)
        self.assertEqual(service.active_streams, 1)

        factory.release_gate.set()
        await asyncio.wait_for(authorization.close_started.wait(), 1)
        self.assertFalse(authorization.closed.is_set())
        self.assertGreater(budget.status().reserved_bytes, 0)
        self.assertEqual(service.active_streams, 1)
        self.assertEqual(adapter.active_generate_streams, 1)

        authorization.close_gate.set()
        await asyncio.wait_for(slot["authorization_owner_task"], 1)
        self.assertTrue(authorization.closed.is_set())
        self.assertEqual(factory.released, [factory.context])
        self.assertEqual(budget.status().reserved_bytes, 0)
        self.assertEqual(service.active_streams, 0)
        self.assertEqual(adapter.active_generate_streams, 0)

    async def test_generate_cancellation_preserves_pending_owner(self):
        authorization = _ModelAuthorization()
        factory = _GatedContextFactory()
        service = _Service()
        adapter = SecureCoordinatorService(
            service, authorizer=_Authorizer(),
            authorization_watcher=lambda _authorization: asyncio.Future(),
            request_context_factory=factory)

        async def successful_generate(
                _request, _context, _deadline, _trusted_context, auth, slot,
                _context_lifetime):
            cleanup = asyncio.create_task(asyncio.sleep(0))
            slot["cleanup_task"] = cleanup
            await cleanup
            await auth.complete({"status": "completed"})

        adapter._generate_with_context = successful_generate

        async def authorize(_method, _data, _payload, _context):
            return authorization

        adapter._authorize = authorize
        rpc_context = _NoTransportDeadlineRpcContext()
        request = encode_json({
            "input_ids": [1], "new_tokens": 1,
            "timeout_seconds": 5, "capture_logits": False})
        with patch.dict(sys.modules, {"grpc": self._grpc_stub()}):
            generate_task = asyncio.create_task(
                adapter.generate_rpc(request, rpc_context))
            await asyncio.wait_for(factory.release_started.wait(), 1)
            generate_task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await generate_task

        self.assertIsNone(rpc_context.time_remaining())
        self.assertTrue(adapter.unavailable)
        self.assertEqual(len(adapter._unreclaimed_generate_slots), 1)
        slot = adapter._unreclaimed_generate_slots[0]
        owner = slot["authorization_owner_task"]
        self.assertFalse(owner.done())
        self.assertFalse(owner.cancelled())
        self.assertFalse(authorization.closed.is_set())
        self.assertEqual(service.active_streams, 1)
        self.assertEqual(adapter.active_generate_streams, 1)

        factory.release_gate.set()
        await asyncio.wait_for(owner, 1)
        self.assertTrue(authorization.closed.is_set())
        self.assertEqual(factory.released, [factory.context])
        self.assertEqual(service.active_streams, 0)
        self.assertEqual(adapter.active_generate_streams, 0)

    async def test_body_cancellation_is_not_replaced_by_pending_cleanup(self):
        authorization = _ModelAuthorization()
        factory = _GatedContextFactory()
        service = _Service()
        adapter = SecureCoordinatorService(
            service, authorizer=_Authorizer(),
            authorization_watcher=lambda _authorization: asyncio.Future(),
            request_context_factory=factory)
        operation_started = asyncio.Event()

        async def blocked_generate(
                _request, _context, _deadline, _trusted_context, _auth, _slot,
                _context_lifetime):
            operation_started.set()
            await asyncio.Future()

        adapter._generate_with_context = blocked_generate

        async def authorize(_method, _data, _payload, _context):
            return authorization

        adapter._authorize = authorize
        rpc_context = _NoTransportDeadlineRpcContext()
        request = encode_json({
            "input_ids": [1], "new_tokens": 1,
            "timeout_seconds": 5, "capture_logits": False})
        with patch.dict(sys.modules, {"grpc": self._grpc_stub()}), patch(
                "steamboat_runtime.protocol.secure_transport.MAX_CANCELLATION_GRACE_SECONDS",
                0.03):
            generate_task = asyncio.create_task(
                adapter.generate_rpc(request, rpc_context))
            await asyncio.wait_for(operation_started.wait(), 1)
            generate_task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await asyncio.wait_for(generate_task, 1)

        self.assertIsNone(rpc_context.time_remaining())
        self.assertTrue(adapter.unavailable)
        self.assertEqual(len(adapter._unreclaimed_generate_slots), 1)
        slot = adapter._unreclaimed_generate_slots[0]
        owner = slot["authorization_owner_task"]
        self.assertFalse(owner.done())
        self.assertFalse(owner.cancelled())
        self.assertFalse(authorization.closed.is_set())
        self.assertEqual(service.active_streams, 1)
        self.assertEqual(adapter.active_generate_streams, 1)

        factory.release_gate.set()
        await asyncio.wait_for(owner, 1)
        self.assertTrue(authorization.closed.is_set())
        self.assertEqual(service.active_streams, 0)
        self.assertEqual(adapter.active_generate_streams, 0)

    @staticmethod
    def _grpc_stub():
        module = types.ModuleType("grpc")
        module.StatusCode = types.SimpleNamespace(
            RESOURCE_EXHAUSTED=1, UNAUTHENTICATED=2, UNAVAILABLE=3)
        return module


_MODEL_TESTS_ENABLED = os.environ.get("STEAMBOAT_COORDINATOR_TESTS") == "1"
_ARTIFACT_DIR = os.environ.get("STEAMBOAT_ARTIFACT_DIR")
_REFERENCE_DIR = os.environ.get("STEAMBOAT_REFERENCE_DIR")


class _ModelAuthorization(_Authorization):
    def assert_live(self):
        if self.closed.is_set():
            raise RuntimeError("authorization already closed")

    def remaining_seconds(self):
        return 60.0

    async def complete(self, _response):
        return None


class _ModelContextFactory:
    def __init__(self, authorization):
        self.authorization = authorization
        self.released = []

    async def __call__(self, _authorization, _payload):
        from steamboat_runtime.participant_context import TrustedRequestContext

        sequence = len(self.released) + 1
        return TrustedRequestContext(
            tenant_account_id="acct_" + "1" * 32,
            request_id="req_" + f"{sequence:032x}",
            session_id="ses_" + f"{sequence:032x}",
            route_id="route_" + f"{sequence:032x}",
            coordinator_boot_id="2" * 32, route_epoch=1, attempt=1,
            authorization=self.authorization,
            hard_monotonic_deadline=time.monotonic() + 20)

    async def release(self, context):
        self.released.append(context)


class _ModelRpcContext(_RpcContext):
    def __init__(self):
        super().__init__()
        self.messages = []

    def time_remaining(self):
        return 40

    async def write(self, payload):
        self.messages.append(payload)


@unittest.skipUnless(
    _MODEL_TESTS_ENABLED,
    "Set STEAMBOAT_COORDINATOR_TESTS=1 for offline secure capture integration")
class SecureCaptureModelIntegrationTests(unittest.IsolatedAsyncioTestCase):
    @classmethod
    def setUpClass(cls):
        if not _ARTIFACT_DIR or not _REFERENCE_DIR:
            raise RuntimeError(
                "secure capture integration requires existing offline artifacts and reference")
        import torch
        from steamboat_runtime.coordinator import Coordinator
        from steamboat_runtime.coordinator_model import CoordinatorModel
        from steamboat_runtime.coordinator_service import supervised_model_class
        from steamboat_runtime.manifest import load_manifest
        from steamboat_runtime.prepare import verify_snapshot
        from steamboat_runtime.protocol.transport import InMemoryTransport
        from steamboat_runtime.worker_state import StageExecutor, WorkerHandler

        torch.set_num_threads(int(os.environ.get("OMP_NUM_THREADS", "2")))
        verify_snapshot(_REFERENCE_DIR)
        cls.manifest = load_manifest(_ARTIFACT_DIR)
        cls.executors = [StageExecutor(_ARTIFACT_DIR, f"worker-{index}")
                         for index in (1, 2, 3)]
        cls.Coordinator = Coordinator
        cls.CoordinatorModel = supervised_model_class()
        cls.WorkerHandler = WorkerHandler
        cls.InMemoryTransport = InMemoryTransport

    async def asyncSetUp(self):
        from steamboat_runtime.coordinator_service import CoordinatorService
        from steamboat_runtime.capture_budget import CaptureBudget, CaptureBudgetConfig

        self.authorization = _ModelAuthorization()
        self.factory = _ModelContextFactory(self.authorization)
        model = self.CoordinatorModel.from_artifacts(_ARTIFACT_DIR, _REFERENCE_DIR)
        handlers = [self.WorkerHandler(self.manifest, executor.worker_name,
                    executor, enable_queue=True) for executor in self.executors]
        class ContextCheckedInMemoryFixture:
            """Model/capture fixture only; this provides no authentication or TLS."""

            def __init__(self, handler):
                self.transport = self_outer.InMemoryTransport(handler)

            async def execute(self, method, request, *, trusted_request_context=None):
                if method != "Describe" and trusted_request_context is None:
                    raise AssertionError("capture model fixture lost the trusted context")
                if (trusted_request_context is not None
                        and method not in {"CloseSession", "CancelSession", "SessionStatus"}):
                    trusted_request_context.assert_data_live()
                return await self.transport.execute(method, request)

            async def close(self):
                await self.transport.close()

        self_outer = self
        clients = [ContextCheckedInMemoryFixture(handler) for handler in handlers]
        self.handlers = handlers
        self.coordinator = self.Coordinator(self.manifest, clients, model)
        await self.coordinator.start()
        self.service = CoordinatorService(self.coordinator)
        original_submit = self.coordinator.submit
        self.handles = []

        def submit(*args, trusted_request_context=None, **kwargs):
            handle = original_submit(*args, trusted_request_context=trusted_request_context,
                                     **kwargs)
            self.handles.append(handle)
            return handle

        self.coordinator.submit = submit
        self.budget = CaptureBudget(CaptureBudgetConfig(
            output_queue_slots=self.coordinator.limits.output_queue_tokens))
        self.adapter = SecureCoordinatorService(
            self.service, authorizer=_Authorizer(),
            authorization_watcher=lambda _authorization: asyncio.Future(),
            request_context_factory=self.factory, capture_budget=self.budget)

        async def authorize(_method, _data, _payload, _context):
            return self.authorization

        self.adapter._authorize = authorize

    async def asyncTearDown(self):
        self.assertTrue(await self.coordinator.close())
        for handler in self.handlers:
            self.assertTrue(await handler.shutdown())

    async def test_secure_generate_reclaims_real_capture_after_serialized_last_position(self):
        context = _ModelRpcContext()
        payload = encode_json({
            "input_ids": [7], "new_tokens": 1,
            "timeout_seconds": 30, "capture_logits": True})
        await self.adapter.generate_rpc(payload, context)
        await asyncio.wait_for(self.authorization.closed.wait(), 30)

        events = [json.loads(message) for message in context.messages]
        token_events = [event for event in events if event.get("type") == "token"]
        terminal = next(event for event in events if event.get("type") == "result")
        self.assertEqual(terminal["status"], "completed", terminal)
        self.assertEqual(len(token_events), 1)
        logits = token_events[0]["logits"]
        self.assertEqual(len(logits), self.manifest["config"]["vocab_size"])
        self.assertTrue(all(math.isfinite(value) for value in logits))
        self.assertLessEqual(len(context.messages[0]), MAX_CAPTURE_MESSAGE_BYTES)
        self.assertTrue(terminal["cleanup_complete"])
        self.assertEqual(len(self.handles), 1)
        handle = self.handles[0]
        self.assertTrue(handle._state.task.done())
        self.assertTrue(handle._state.output.empty())
        self.assertIsNone(handle._state.input_ids)
        self.assertIsNone(handle._state.forced_tokens)
        self.assertFalse(self.coordinator.model.supervision_status()["active_compute"])
        self.assertEqual(self.budget.status().reserved_bytes, 0)
        self.assertEqual(self.factory.released, [handle._state.trusted_request_context])
        self.assertEqual(self.service.active_streams, 0)
        self.assertEqual(self.adapter.active_generate_streams, 0)


class SecureGenerateCleanupOwnershipTests(unittest.IsolatedAsyncioTestCase):
    async def test_repeated_request_cancellation_retains_context_until_cleanup_retires(self):
        factory = _ContextFactory()
        adapter = SecureCoordinatorService(
            _Service(), authorizer=_Authorizer(),
            authorization_watcher=lambda _authorization: asyncio.Future(),
            request_context_factory=factory)
        adapter.active_generate_streams = 1
        context = object()
        authorization = _Authorization()
        cleanup_release = asyncio.Event()
        cleanup_task = asyncio.create_task(cleanup_release.wait())
        slot = {
            "generate": True,
            "service": False,
            "cleanup_task": cleanup_task,
            "capture_lease": None,
            "capture_pending": False,
            "trusted_context": context,
            "context_release_task": None,
            "capture_cleanup_task": None,
            "retained": False,
        }
        adapter._defer_generate_resources(context, (cleanup_task,), slot)
        owner = adapter._retain_generate_authorization_owner(authorization, slot)
        request_wait_started = asyncio.Event()
        first_cancel_seen = asyncio.Event()
        second_cancel_seen = asyncio.Event()

        async def request_waiter():
            request_wait_started.set()
            try:
                await asyncio.shield(owner)
            except asyncio.CancelledError:
                first_cancel_seen.set()
                try:
                    await asyncio.shield(owner)
                except asyncio.CancelledError:
                    second_cancel_seen.set()
                    raise

        request = asyncio.create_task(request_waiter())
        await request_wait_started.wait()
        request.cancel()
        await asyncio.wait_for(first_cancel_seen.wait(), 1)
        self.assertFalse(factory.released)
        self.assertFalse(cleanup_task.done())
        self.assertFalse(cleanup_task.cancelled())

        request.cancel()
        await asyncio.wait_for(second_cancel_seen.wait(), 1)
        with self.assertRaises(asyncio.CancelledError):
            await request
        self.assertFalse(factory.released)
        self.assertFalse(cleanup_task.done())
        self.assertFalse(cleanup_task.cancelled())

        cleanup_release.set()
        await asyncio.wait_for(owner, 1)
        self.assertTrue(authorization.closed.is_set())
        self.assertEqual(factory.released, [context])
        self.assertIsNone(slot["trusted_context"])
        self.assertFalse(adapter._unreclaimed_generate_slots)
        self.assertEqual(adapter.active_generate_streams, 0)

    async def test_generate_cancellation_defers_context_release_through_repeated_cancel(self):
        factory = _ContextFactory()
        adapter = SecureCoordinatorService(
            _Service(), authorizer=_Authorizer(),
            authorization_watcher=lambda _authorization: asyncio.Future(),
            request_context_factory=factory)
        adapter.active_generate_streams = 1
        context = factory.context
        authorization = _Authorization()
        cleanup_release = asyncio.Event()
        generate_started = asyncio.Event()
        cleanup_task = None
        slot = {
            "generate": True,
            "service": False,
            "entered": False,
            "cleanup_task": None,
            "capture_lease": None,
            "capture_pending": False,
            "trusted_context": context,
            "context_release_task": None,
            "capture_cleanup_task": None,
            "retained": False,
        }

        async def blocked_generate(_request, _wrapped, _deadline, _trusted,
                                   _authorization, request_slot, _lifetime):
            nonlocal cleanup_task
            cleanup_task = asyncio.create_task(cleanup_release.wait())
            request_slot["cleanup_task"] = cleanup_task
            generate_started.set()
            await asyncio.Future()

        async def run_guarded(coroutine, *_args, **_kwargs):
            return await coroutine

        adapter._validate_context = lambda *_args: 5.0
        adapter._generate_with_context = blocked_generate
        producer = asyncio.create_task(adapter._produce_generate(
            {"capture_logits": False}, _RpcContext(), time.monotonic() + 5,
            authorization, slot))
        with patch("steamboat_runtime.secure_coordinator_service._run_guarded",
                   run_guarded):
            await asyncio.wait_for(generate_started.wait(), 1)
            producer.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await producer

        self.assertIsNotNone(slot["context_release_task"])
        owner = adapter._retain_generate_authorization_owner(authorization, slot)
        self.assertFalse(factory.released)
        self.assertFalse(cleanup_task.done())
        self.assertFalse(cleanup_task.cancelled())

        request_wait_started = asyncio.Event()
        first_cancel_seen = asyncio.Event()
        second_cancel_seen = asyncio.Event()

        async def request_waiter():
            request_wait_started.set()
            try:
                await asyncio.shield(owner)
            except asyncio.CancelledError:
                first_cancel_seen.set()
                try:
                    await asyncio.shield(owner)
                except asyncio.CancelledError:
                    second_cancel_seen.set()
                    raise

        request = asyncio.create_task(request_waiter())
        await request_wait_started.wait()
        request.cancel()
        await asyncio.wait_for(first_cancel_seen.wait(), 1)
        self.assertFalse(factory.released)
        self.assertFalse(cleanup_task.done())

        request.cancel()
        await asyncio.wait_for(second_cancel_seen.wait(), 1)
        with self.assertRaises(asyncio.CancelledError):
            await request
        self.assertFalse(factory.released)
        self.assertFalse(cleanup_task.done())
        self.assertFalse(cleanup_task.cancelled())

        cleanup_release.set()
        await asyncio.wait_for(owner, 1)
        self.assertTrue(authorization.closed.is_set())
        self.assertEqual(factory.released, [context])
        self.assertIsNone(slot["trusted_context"])
        self.assertEqual(adapter.active_generate_streams, 0)


if __name__ == "__main__":
    unittest.main()
