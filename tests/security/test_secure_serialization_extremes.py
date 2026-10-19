from __future__ import annotations

import asyncio
import importlib
import json
import math
import struct
import sys
import time
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from steamboat_runtime.capture_budget import (
    MAX_CAPTURE_MESSAGE_BYTES,
    PINNED_VOCABULARY_SIZE,
    CaptureBudget,
    CaptureBudgetConfig,
    calculate_capture_reservation,
)
from steamboat_runtime.coordinator_service import CoordinatorService
from steamboat_runtime.participant_context import TrustedRequestContext
from steamboat_runtime.remote_client import (
    MAX_GENERATE_BYTES,
    RemoteError,
    decode_json,
    encode_json,
    validate_generate,
)


def _maximum_finite_float32_vector():
    patterns = (0x7F7FFFFF, 0xFF7FFFFF, 0x00800000,
                0x80800000, 0x00000001, 0x80000001)
    return [struct.unpack(">f", bits.to_bytes(4, "big"))[0]
            for bits in (patterns[index % len(patterns)]
                         for index in range(PINNED_VOCABULARY_SIZE))]


class _WireContext:
    def __init__(self):
        self.messages = []

    async def write(self, payload):
        self.messages.append(payload)


class SecureSerializationExtremeTests(unittest.IsolatedAsyncioTestCase):
    async def test_float32_extreme_vocabulary_vector_uses_production_writer(self):
        vector = _maximum_finite_float32_vector()
        self.assertEqual(len(vector), PINNED_VOCABULARY_SIZE)
        self.assertTrue(all(math.isfinite(value) for value in vector))
        self.assertEqual(max(vector), struct.unpack(">f", bytes.fromhex("7f7fffff"))[0])
        self.assertEqual(min(vector), struct.unpack(">f", bytes.fromhex("ff7fffff"))[0])

        event = {
            "type": "token",
            "session_id": "ses_" + "a" * 32,
            "index": 0,
            "token_id": 1,
            "position": 1,
            "sequence": 0,
            "logits": vector,
        }
        service = object.__new__(CoordinatorService)
        service.coordinator = SimpleNamespace(
            limits=SimpleNamespace(output_stall_timeout_seconds=2))
        context = _WireContext()
        await service._write(context, event, time.monotonic() + 10)

        self.assertEqual(len(context.messages), 1)
        encoded = context.messages[0]
        event_limit = calculate_capture_reservation(
            CaptureBudgetConfig()).event_limit_bytes
        self.assertEqual(event_limit, 1_028_096)
        self.assertLessEqual(len(encoded), event_limit)
        self.assertLessEqual(len(encoded), MAX_CAPTURE_MESSAGE_BYTES)
        decoded = decode_json(encoded, MAX_CAPTURE_MESSAGE_BYTES)
        self.assertEqual(decoded["logits"], vector)
        self.assertEqual(len(decoded["logits"]), PINNED_VOCABULARY_SIZE)
        self.assertTrue(all(math.isfinite(value) for value in decoded["logits"]))

    def test_production_json_serializer_rejects_over_budget_capture_event(self):
        event = {
            "type": "token",
            "session_id": "ses_" + "b" * 32,
            "index": 0,
            "token_id": 1,
            "position": 1,
            "sequence": 0,
            "logits": _maximum_finite_float32_vector(),
        }
        encoded = encode_json(event, MAX_CAPTURE_MESSAGE_BYTES)
        event["bounded_test_padding"] = "x" * (
            MAX_CAPTURE_MESSAGE_BYTES - len(encoded) + 1)
        with self.assertRaises(RemoteError) as caught:
            encode_json(event, MAX_CAPTURE_MESSAGE_BYTES)
        self.assertEqual(caught.exception.code, "INVALID_INPUT")

    def test_generate_parser_rejects_full_prefill_wire_capture_field(self):
        request = {
            "input_ids": [7],
            "new_tokens": 1,
            "timeout_seconds": 30,
            "capture_logits": True,
            "capture_prefill_logits": True,
        }
        with self.assertRaises(RemoteError) as caught:
            validate_generate(request)
        self.assertEqual(caught.exception.code, "INVALID_INPUT")


class _Authorization:
    binding_bytes = b'{"request":"serialization-extreme-test"}'

    def __init__(self):
        self.closed = 0
        self.failures = []

    def assert_live(self):
        return True

    def remaining_seconds(self):
        return 60

    async def fail(self, *, cache_may_exist):
        self.failures.append(cache_may_exist)

    async def close(self):
        self.closed += 1


class _RequestContextFactory:
    def __init__(self, authorization):
        self.authorization = authorization
        self.created = []
        self.released = []

    def __call__(self, authorization, _payload):
        if authorization is not self.authorization:
            raise AssertionError("test fixture received a different authorization")
        context = TrustedRequestContext(
            tenant_account_id="acct_" + "1" * 32,
            request_id="req_" + "2" * 32,
            session_id="ses_" + "3" * 32,
            route_id="route_" + "4" * 32,
            coordinator_boot_id="5" * 32,
            route_epoch=1,
            attempt=1,
            authorization=authorization,
            hard_monotonic_deadline=time.monotonic() + 20,
        )
        self.created.append(context)
        return context

    def release(self, context):
        self.released.append(context)


class _Coordinator:
    def __init__(self):
        self.manifest = {"config": {"vocab_size": PINNED_VOCABULARY_SIZE}}
        self.limits = SimpleNamespace(
            output_queue_tokens=16,
            max_sessions=4,
            max_waiting_admissions=4,
            output_stall_timeout_seconds=2,
        )
        self.model = SimpleNamespace(
            supervision_status=lambda: {"active_compute": False})
        self.trace = None
        self.submit_calls = 0

    def submit(self, *_args, trusted_request_context=None, **_kwargs):
        self.submit_calls += 1
        raise AssertionError("pre-admission rejection must not submit coordinator work")


class _RpcAbort(Exception):
    """Test RPC abort mirrors gRPC's non-returning abort operation."""

    def __init__(self, code, details):
        super().__init__("RPC aborted")
        self.code = code
        self.details = details


class _RpcContext:
    def __init__(self):
        self.initial_metadata = []
        self.trailing_metadata = []
        self.aborts = []

    def time_remaining(self):
        return 60

    async def send_initial_metadata(self, metadata):
        self.initial_metadata.extend(metadata)

    async def set_trailing_metadata(self, metadata):
        self.trailing_metadata.extend(metadata)

    async def abort(self, code, details):
        self.aborts.append((code, details))
        raise _RpcAbort(code, details)


def _grpc_or_skip(test_case):
    try:
        grpc = importlib.import_module("grpc")
        importlib.import_module("google.protobuf.message")
    except ModuleNotFoundError as error:
        if error.name in {"grpc", "google.protobuf", "google"}:
            test_case.skipTest("grpcio/protobuf base dependencies are unavailable")
        raise
    return grpc


class SecureGenerateSerializationBoundaryTests(unittest.IsolatedAsyncioTestCase):
    """Component-boundary evidence; these cases are not end-to-end TLS proof."""

    def _adapter(self, budget):
        from steamboat_runtime.secure_coordinator_service import SecureCoordinatorService

        def forbidden_component_authorization(*_args, **_kwargs):
            raise AssertionError("unexpected component authorizer call")

        authorization = _Authorization()
        factory = _RequestContextFactory(authorization)
        coordinator = _Coordinator()
        service = object.__new__(CoordinatorService)
        service.coordinator = coordinator
        service.max_streams = 8
        service.active_streams = 0
        service.counters = {name: 0 for name in (
            "completed_requests", "failed_requests", "cancelled_requests",
            "cleanup_incomplete_requests", "rejected_requests",
            "disconnected_streams", "transport_stalls")}
        service.cleanups = set()
        service.metrics = {}
        adapter = SecureCoordinatorService(
            service,
            # Component-only authorization fixture: this method must never run;
            # the test below explicitly supplies its synthetic _authorize result.
            authorizer=SimpleNamespace(authorize=forbidden_component_authorization),
            authorization_watcher=lambda _authorization: (
                asyncio.get_running_loop().create_future()),
            request_context_factory=factory,
            capture_budget=budget,
            max_generate_streams=8,
        )
        authorization_calls = []

        async def authorize(_method, _data, _payload, _context):
            authorization_calls.append(True)
            return authorization

        adapter._authorize = authorize
        return adapter, service, coordinator, factory, authorization, authorization_calls

    async def test_full_prefill_generate_request_is_rejected_before_authorization(self):
        grpc = _grpc_or_skip(self)
        budget = CaptureBudget()
        (adapter, service, coordinator, factory, authorization,
         authorization_calls) = self._adapter(budget)
        rpc_context = _RpcContext()
        request = {
            "input_ids": [7],
            "new_tokens": 1,
            "timeout_seconds": 30,
            "capture_logits": True,
            "capture_prefill_logits": True,
        }

        with self.assertRaises(_RpcAbort):
            await adapter.generate_rpc(
                encode_json(request, MAX_GENERATE_BYTES), rpc_context)

        self.assertEqual(len(rpc_context.aborts), 1)
        self.assertEqual(rpc_context.aborts[0][0], grpc.StatusCode.INVALID_ARGUMENT)
        self.assertEqual(authorization_calls, [])
        self.assertEqual(factory.created, [])
        self.assertEqual(factory.released, [])
        self.assertEqual(authorization.closed, 0)
        self.assertEqual(coordinator.submit_calls, 0)
        self.assertEqual(service.counters["rejected_requests"], 0)
        status = budget.status()
        self.assertEqual(status.active_captures, 0)
        self.assertEqual(status.cleanup_pending_captures, 0)
        self.assertEqual(status.reserved_bytes, 0)
        self.assertEqual(status.used_request_ids, 0)
        self.assertEqual(service.active_streams, 0)
        self.assertEqual(adapter.active_generate_streams, 0)

    async def test_underfunded_capture_is_rejected_before_tensor_or_submit(self):
        grpc = _grpc_or_skip(self)
        config = CaptureBudgetConfig(capacity_bytes=64 << 20)
        budget = CaptureBudget(config)
        self.assertGreater(budget.per_capture.total_bytes, config.capacity_bytes)
        (adapter, service, coordinator, factory, authorization,
         authorization_calls) = self._adapter(budget)
        slots = []
        reserve_capture = adapter._reserve_capture

        def record_reservation(payload, trusted_context, slot):
            slots.append(slot)
            return reserve_capture(payload, trusted_context, slot)

        adapter._reserve_capture = record_reservation
        rpc_context = _RpcContext()
        request = {
            "input_ids": [7],
            "new_tokens": 1,
            "timeout_seconds": 30,
            "capture_logits": True,
        }

        with patch.dict(sys.modules, {"torch": None}):
            with self.assertRaises(_RpcAbort):
                await adapter.generate_rpc(
                    encode_json(request, MAX_GENERATE_BYTES), rpc_context)

        self.assertEqual(len(authorization_calls), 1)
        self.assertEqual(len(factory.created), 1)
        self.assertEqual(factory.released, factory.created)
        self.assertEqual(factory.released.count(factory.created[0]), 1)
        self.assertEqual(authorization.failures, [False])
        self.assertEqual(authorization.closed, 1)
        self.assertEqual(coordinator.submit_calls, 0)
        self.assertEqual(len(slots), 1)
        self.assertTrue(
            slots[0]["known_pre_admission_capture_capacity_refusal"])
        self.assertFalse(slots[0].get("capture_submission_attempted", False))
        self.assertIsNone(slots[0].get("handle"))
        self.assertEqual(len(rpc_context.aborts), 1)
        self.assertEqual(rpc_context.aborts[0][0], grpc.StatusCode.RESOURCE_EXHAUSTED)
        self.assertTrue(rpc_context.initial_metadata)
        from steamboat_runtime.protocol.secure_transport import (
            has_capacity_rejection_metadata,
        )
        self.assertTrue(has_capacity_rejection_metadata(
            rpc_context.trailing_metadata, authorization.binding_bytes))
        status = budget.status()
        self.assertEqual(status.active_captures, 0)
        self.assertEqual(status.cleanup_pending_captures, 0)
        self.assertEqual(status.reserved_bytes, 0)
        self.assertEqual(status.used_request_ids, 0)
        self.assertEqual(service.active_streams, 0)
        self.assertEqual(service.counters["rejected_requests"], 1)
        self.assertEqual(adapter.active_generate_streams, 0)
        adapter._mark_capture_capacity_refusal(slots[0])
        self.assertEqual(service.counters["rejected_requests"], 1)

    async def test_no_submission_marker_does_not_override_ambiguous_work(self):
        _grpc_or_skip(self)
        adapter, *_ = self._adapter(CaptureBudget())
        cleanup = asyncio.get_running_loop().create_future()
        cleanup.set_result(None)
        safe_refusal = {
            "known_pre_admission_capture_capacity_refusal": True,
            "capture_submission_attempted": False,
            "handle": None,
            "capture_lease": None,
            "context_release_task": cleanup,
            "cleanup_task": None,
            "capture_cleanup_task": None,
            "retained": False,
            "authorization_transferred": False,
            "admission_cleanup_tasks": set(),
            "admission_pending_tasks": set(),
            "pending_cleanup_tasks": set(),
            "pending_cleanup_discovery_unconfirmed": False,
        }
        self.assertFalse(await adapter._generate_failure_cache_may_exist(safe_refusal))

        from steamboat_runtime.protocol.secure_transport import SecureTaskPending

        pending_cleanup = asyncio.get_running_loop().create_future()

        async def preserve_pending_cleanup(task, **_kwargs):
            self.assertIs(task, pending_cleanup)
            raise SecureTaskPending((task,), "cleanup remains pending")

        with patch(
                "steamboat_runtime.secure_coordinator_service._await_task_bounded",
                preserve_pending_cleanup):
            self.assertTrue(await adapter._generate_failure_cache_may_exist(
                {**safe_refusal, "context_release_task": pending_cleanup}))
        pending_cleanup.set_result(None)

        generic_capacity_claim = dict(safe_refusal)
        generic_capacity_claim.pop("known_pre_admission_capture_capacity_refusal")
        generic_capacity_claim["known_pre_admission_capacity_rejection"] = True
        self.assertTrue(await adapter._generate_failure_cache_may_exist(
            generic_capacity_claim))

        failed_cleanup = asyncio.get_running_loop().create_future()
        failed_cleanup.set_exception(RuntimeError("cleanup was not confirmed"))

        ambiguous_variants = (
            {"known_pre_admission_capture_capacity_refusal": False},
            {"capture_submission_attempted": True},
            {"handle": object()},
            {"capture_lease": object()},
            {"context_release_task": None},
            {"context_release_task": failed_cleanup},
            {"cleanup_task": object()},
            {"capture_cleanup_task": object()},
            {"retained": True},
            {"authorization_transferred": True},
            {"admission_cleanup_tasks": {object()}},
            {"admission_pending_tasks": {object()}},
            {"pending_cleanup_tasks": {object()}},
            {"pending_cleanup_discovery_unconfirmed": True},
        )
        for variant in ambiguous_variants:
            with self.subTest(variant=tuple(variant)):
                self.assertTrue(await adapter._generate_failure_cache_may_exist(
                    {**safe_refusal, **variant}))


if __name__ == "__main__":
    unittest.main()
