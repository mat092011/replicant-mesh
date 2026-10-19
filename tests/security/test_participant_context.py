"""Stdlib-only tests for trusted coordinator request-context propagation."""

import asyncio
import importlib
import runpy
import sys
import time
import types
import unittest
from dataclasses import replace
from pathlib import Path

from steamboat_runtime.participant_context import (
    TrustedRequestContext,
    TrustedRequestContextError,
    TrustedRequestContextExpired,
)


def _id(prefix, value):
    return f"{prefix}_{value:032x}"


class _Authorization:
    def __init__(self, seconds=60):
        self.deadline = time.monotonic() + seconds
        self.live = True

    def remaining_seconds(self):
        if not self.live:
            return 0.0
        return self.deadline - time.monotonic()

    def assert_live(self):
        if not self.live or self.remaining_seconds() <= 0:
            raise RuntimeError("expired synthetic authorization")

    def expire(self):
        self.live = False


def _context(value, *, authorization=None, session_id=None, deadline_seconds=60):
    authorization = authorization or _Authorization()
    return TrustedRequestContext(
        tenant_account_id=_id("acct", value),
        request_id=_id("req", value),
        session_id=session_id or _id("ses", value),
        route_id=_id("route", value),
        coordinator_boot_id=f"{value:032x}",
        route_epoch=1,
        attempt=1,
        authorization=authorization,
        hard_monotonic_deadline=time.monotonic() + deadline_seconds,
    )


class TrustedRequestContextTests(unittest.TestCase):
    def test_validates_typed_ids_boot_and_fixed_v1_fields(self):
        valid = _context(1)
        self.assertEqual(valid.session_id, _id("ses", 1))
        self.assertEqual(valid.route_epoch, 1)
        self.assertEqual(valid.attempt, 1)

        for field, value in (
            ("tenant_account_id", "acct_" + "A" * 32),
            ("tenant_account_id", "dev_" + "1" * 32),
            ("request_id", "req_" + "1" * 31),
            ("session_id", "ses_" + "1" * 32 + "x"),
            ("route_id", "req_" + "1" * 32),
            ("coordinator_boot_id", "g" * 32),
            ("route_epoch", True),
            ("attempt", 2),
            ("hard_monotonic_deadline", float("inf")),
        ):
            with self.subTest(field=field, value=value):
                values = {
                    "tenant_account_id": _id("acct", 2),
                    "request_id": _id("req", 2),
                    "session_id": _id("ses", 2),
                    "route_id": _id("route", 2),
                    "coordinator_boot_id": "2" * 32,
                    "route_epoch": 1,
                    "attempt": 1,
                    "authorization": _Authorization(),
                    "hard_monotonic_deadline": time.monotonic() + 60,
                }
                values[field] = value
                with self.assertRaises(ValueError):
                    TrustedRequestContext(**values)

    def test_deadline_and_authorization_lifetime_fail_closed(self):
        context = _context(3, deadline_seconds=0.2)
        self.assertGreater(context.remaining_seconds(), 0)
        auth = context.authorization
        auth.expire()
        with self.assertRaises(TrustedRequestContextExpired):
            context.remaining_seconds()
        with self.assertRaises(TrustedRequestContextExpired):
            context.assert_data_live()

    def test_admission_claim_is_one_use(self):
        context = _context(4)
        context.claim_admission()
        with self.assertRaises(TrustedRequestContextError):
            context.claim_admission()
        context.complete_admission()
        with self.assertRaises(TrustedRequestContextError):
            context.claim_admission()


def _load_coordinator_with_test_doubles():
    """Import Coordinator without host Protobuf or Torch installations."""
    names = (
        "steamboat_runtime.coordinator",
        "steamboat_runtime.protocol.worker_pb2",
        "steamboat_runtime.protocol.wire",
        "steamboat_runtime.worker",
    )
    missing = object()
    previous_modules = {name: sys.modules.get(name, missing) for name in names}
    runtime_package = importlib.import_module("steamboat_runtime")
    protocol_package = importlib.import_module("steamboat_runtime.protocol")
    package_attrs = {
        (runtime_package, "coordinator"): getattr(runtime_package, "coordinator", missing),
        (runtime_package, "worker"): getattr(runtime_package, "worker", missing),
        (protocol_package, "worker_pb2"): getattr(protocol_package, "worker_pb2", missing),
        (protocol_package, "wire"): getattr(protocol_package, "wire", missing),
    }

    class Request:
        def __init__(self, **fields):
            self.__dict__.update(fields)

        def ByteSize(self):
            return 1

    worker_pb2 = types.ModuleType(names[1])
    worker_pb2.Request = Request
    wire = types.ModuleType(names[2])
    wire.validate_response = lambda method, request, response: response
    worker = types.ModuleType(names[3])
    worker.validate_ready = lambda response, manifest, expected: None

    try:
        sys.modules[names[1]] = worker_pb2
        sys.modules[names[2]] = wire
        sys.modules[names[3]] = worker
        sys.modules.pop(names[0], None)
        module = importlib.import_module(names[0])
        return module
    finally:
        sys.modules.pop(names[0], None)
        for name, previous in previous_modules.items():
            if previous is missing:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = previous
        for (package, name), previous in package_attrs.items():
            if previous is missing:
                try:
                    delattr(package, name)
                except AttributeError:
                    pass
            else:
                setattr(package, name, previous)


class _Response:
    def __init__(self, index, method, request):
        self.protocol_version = 1
        self.code = "OK"
        self.message = ""
        self.manifest_fingerprint = request.manifest_fingerprint
        self.worker_boot_id = f"{index + 1:032x}"
        self.session_id = getattr(request, "session_id", "")
        self.lease_token = (f"lease-{index}-{self.session_id}"
                            if method == "OpenSession" else getattr(request, "lease_token", ""))
        self.max_positions = getattr(request, "max_positions", 0)
        self.reclaimed = method in {"SessionStatus", "CloseSession"}
        self.queue_ms = self.compute_ms = 0.0
        self.compute_start_ns = self.compute_end_ns = self.monotonic_ns = 0
        self.clock_id = ""
        self.tensor = b"result"

    def ByteSize(self):
        return 1


class _Client:
    def __init__(self, index):
        self.index = index
        self.calls = []

    async def execute(self, method, request, **kwargs):
        self.calls.append((method, request, dict(kwargs)))
        await asyncio.sleep(0)
        return _Response(self.index, method, request)

    async def close(self):
        return None


class _Model:
    def __init__(self):
        self.validations = 0

    def validate_tokens(self, tokens):
        self.validations += 1
        return 1

    async def close(self):
        return True


class _Input:
    def detach(self):
        return self

    def clone(self):
        return self


class CoordinatorContextTests(unittest.IsolatedAsyncioTestCase):
    @classmethod
    def setUpClass(cls):
        cls.runtime = _load_coordinator_with_test_doubles()
        cls.manifest = staticmethod(runpy.run_path(
            str(Path(__file__).parents[1] / "runtime" / "test_manifest.py"))["sample_manifest"])

    def make_coordinator(self):
        clients = [_Client(index) for index in range(3)]
        model = _Model()
        coordinator = self.runtime.Coordinator(
            self.manifest(), clients, model, limits=self.runtime.SchedulerLimits())
        return coordinator, clients, model

    @staticmethod
    def make_state(context):
        return types.SimpleNamespace(
            session_id=context.session_id,
            trusted_request_context=context,
            deadline=time.monotonic() + 20,
            prompt_length=1,
            new_tokens=1,
            leases={},
            unknown_opens=set(),
            pending_tasks=set(),
            cleanup_status_only=set(),
            cleanup_deadline=time.monotonic() + 5,
            abort_error=None,
            cleaning=False,
        )

    async def test_interleaved_shared_stages_keep_context_through_all_worker_operations(self):
        coordinator, clients, _ = self.make_coordinator()
        auth_a, auth_b = _Authorization(), _Authorization()
        context_a, context_b = _context(11, authorization=auth_a), _context(22, authorization=auth_b)
        state_a, state_b = self.make_state(context_a), self.make_state(context_b)

        # Bootstrap discovery remains unscoped; request preflight is explicit.
        await coordinator._preflight()
        await coordinator._preflight(state_a)
        await coordinator._preflight(state_b)
        for state in (state_a, state_b):
            for index in range(3):
                await coordinator._reserve(state, index)

        coordinator.limits = replace(coordinator.limits, renew_interval_seconds=0.002)
        renewals = [asyncio.create_task(coordinator._renew(state))
                    for state in (state_a, state_b)]
        for task in renewals:
            self.addAsyncCleanup(self._cancel_task, task)

        stage = asyncio.create_task(coordinator._stage_loop(0))
        loop = asyncio.get_running_loop()
        jobs = []
        for state, sequence in ((state_a, 0), (state_b, 1)):
            future = loop.create_future()
            jobs.append((state, future))
            await coordinator._queues[0].put(self.runtime._Job(
                state, sequence, sequence, 1, b"activation", future, time.monotonic_ns()))
        await asyncio.wait_for(asyncio.gather(*(future for _, future in jobs)), 2)
        await self._wait_for(lambda: all(
            any(method == "RenewSession" and
                kwargs.get("trusted_request_context") is context
                for method, _, kwargs in client.calls)
            for client in clients for context in (context_a, context_b)), 2)
        for task in renewals:
            task.cancel()
        await asyncio.gather(*renewals, return_exceptions=True)
        stage.cancel()
        await asyncio.gather(stage, return_exceptions=True)

        # Consumer expiry blocks data calls but preserves exact context for owner cleanup.
        auth_a.expire()
        self.assertTrue(await coordinator._cleanup(state_a, cancel=True))
        self.assertTrue(await coordinator._cleanup(state_b, cancel=False))

        calls = [call for client in clients for call in client.calls]
        for method in ("Describe", "OpenSession", "Step", "RenewSession"):
            for context in (context_a, context_b):
                self.assertTrue(any(
                    call_method == method and kwargs.get("trusted_request_context") is context
                    for call_method, _, kwargs in calls), (method, context.session_id))
        for method in ("CancelSession", "SessionStatus"):
            self.assertTrue(any(call_method == method and
                                kwargs.get("trusted_request_context") is context_a
                                for call_method, _, kwargs in calls))
        self.assertTrue(any(call_method == "CloseSession" and
                            kwargs.get("trusted_request_context") is context_b
                            for call_method, _, kwargs in calls))
        startup_describes = [call for call in calls if call[0] == "Describe"
                             and "trusted_request_context" not in call[2]]
        self.assertTrue(startup_describes)
        self.assertTrue(all(kwargs == {} for _, _, kwargs in startup_describes))
        for context in (context_a, context_b):
            for method in ("Describe", "OpenSession", "Step", "RenewSession",
                           "CancelSession", "CloseSession", "SessionStatus"):
                self.assertTrue(all(
                    kwargs.get("trusted_request_context") is context
                    for call_method, _, kwargs in calls
                    if call_method == method and
                    kwargs.get("trusted_request_context") is context),
                    (method, context.session_id))
        self.assertEqual(
            (context_a.tenant_account_id, context_a.request_id, context_a.session_id,
             context_a.route_id, context_a.coordinator_boot_id),
            (_id("acct", 11), _id("req", 11), _id("ses", 11),
             _id("route", 11), f"{11:032x}"))
        self.assertEqual(
            (context_b.tenant_account_id, context_b.request_id, context_b.session_id,
             context_b.route_id, context_b.coordinator_boot_id),
            (_id("acct", 22), _id("req", 22), _id("ses", 22),
             _id("route", 22), f"{22:032x}"))
        for method, request, kwargs in calls:
            context = kwargs.get("trusted_request_context")
            if context is not None and method != "Describe":
                self.assertEqual(request.session_id, context.session_id)

    async def test_expired_context_rejected_before_model_work_or_enqueue(self):
        coordinator, _, model = self.make_coordinator()
        coordinator._ready = True
        authorization = _Authorization()
        context = _context(31, authorization=authorization)
        authorization.expire()
        with self.assertRaises(self.runtime.CoordinatorError) as raised:
            coordinator.submit(_Input(), 1, trusted_request_context=context)
        self.assertEqual(raised.exception.code, "TIMEOUT")
        self.assertEqual(model.validations, 0)
        self.assertEqual(coordinator._requests, {})
        self.assertEqual(len(coordinator._waiting), 0)

    async def test_typed_session_duplicate_active_single_use_and_deadline_clipping(self):
        coordinator, _, _ = self.make_coordinator()
        coordinator._ready = True
        coordinator._slots = coordinator.limits.max_sessions
        context = _context(41, deadline_seconds=5)
        handle = coordinator.submit(_Input(), 1, trusted_request_context=context)
        self.assertEqual(handle.session_id, _id("ses", 41))
        state = coordinator._requests[handle.session_id]
        self.assertIs(state.trusted_request_context, context)
        self.assertLessEqual(state.deadline, context.hard_monotonic_deadline)

        duplicate_context = _context(42, session_id=context.session_id)
        with self.assertRaises(self.runtime.CoordinatorError) as raised:
            coordinator.submit(_Input(), 1, trusted_request_context=duplicate_context)
        self.assertEqual(raised.exception.code, "INVALID_INPUT")
        self.assertIs(coordinator._requests[handle.session_id], state)

        result = await handle.cancel()
        self.assertEqual(result.session_id, _id("ses", 41))
        self.assertNotIn(result.session_id, coordinator._requests)
        coordinator._slots = 0
        with self.assertRaises(self.runtime.CoordinatorError) as raised:
            coordinator.submit(_Input(), 1, trusted_request_context=context)
        self.assertEqual(raised.exception.code, "INVALID_INPUT")

    async def test_legacy_execute_calls_and_session_ids_keep_their_original_shape(self):
        coordinator, clients, _ = self.make_coordinator()
        await coordinator._preflight()
        self.assertTrue(all(kwargs == {} for client in clients
                            for method, _, kwargs in client.calls if method == "Describe"))

        request = self.runtime.Request(protocol_version=1,
                                       manifest_fingerprint=coordinator.manifest["fingerprint"],
                                       timeout_ms=1000, session_id="", lease_token="")
        for method in ("Describe", "OpenSession", "Step", "RenewSession",
                       "CancelSession", "CloseSession", "SessionStatus"):
            await coordinator._execute(0, method, request)
            self.assertEqual(clients[0].calls[-1][2], {})

        coordinator._ready = True
        coordinator._slots = coordinator.limits.max_sessions
        handle = coordinator.submit(_Input(), 1)
        self.assertRegex(handle.session_id, r"^[0-9a-f]{32}$")
        result = await handle.cancel()
        self.assertEqual(result.session_id, handle.session_id)

    async def _wait_for(self, predicate, timeout):
        deadline = time.monotonic() + timeout
        while not predicate():
            if time.monotonic() >= deadline:
                self.fail("condition did not become true before test deadline")
            await asyncio.sleep(0.001)

    async def _cancel_task(self, task):
        if not task.done():
            task.cancel()
        await asyncio.gather(task, return_exceptions=True)


if __name__ == "__main__":
    unittest.main()
