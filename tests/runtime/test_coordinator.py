"""M4 deterministic scheduler/lifecycle checks without downloaded model weights."""

import asyncio
from dataclasses import replace
import importlib
import os
import time
import unittest


class FakeModel:
    def __init__(self, torch):
        self.torch = torch
        self.closed = False
        self.embedded = []

    def validate_tokens(self, tokens):
        torch = self.torch
        if (not isinstance(tokens, torch.Tensor) or tokens.dtype != torch.long
                or tokens.device.type != "cpu" or tokens.ndim != 2
                or tokens.shape[0] != 1 or not 1 <= tokens.shape[1] <= 1152
                or int(tokens.min()) < 0 or int(tokens.max()) >= 32000):
            raise ValueError("Invalid token IDs")
        return tokens.shape[1]

    async def embed(self, tokens):
        self.embedded.append(tokens.clone())
        await asyncio.sleep(0)
        return tokens.to(self.torch.float32).unsqueeze(-1).expand(-1, -1, 64).contiguous()

    async def finish(self, hidden, *, all_logits=False):
        await asyncio.sleep(0)
        logits = self.torch.zeros((1, 1, 32000))
        token = (int(hidden[0, -1, 0]) + 1) % 32000
        logits[0, 0, token] = 1
        return logits

    async def close(self):
        self.closed = True
        return True


class FakeClient:
    """A real lifecycle handler behind a deterministic asynchronous RPC gate."""

    def __init__(self, handler):
        self.handler = handler
        self.calls = []
        self.spans = []
        self.step_gate = None
        self.open_gate = None
        self.after_open_gate = None
        self.step_started = asyncio.Event()
        self.open_started = asyncio.Event()
        self.active = self.peak_active = 0
        self.fail_open = None
        self.fail_step = None
        self.fail_describe = None
        self.delay = 0
        self.closed = False

    async def execute(self, method, request):
        from steamboat_runtime.protocol.errors import ProtocolError
        self.calls.append((method, request.session_id, request.sequence))
        if method == "Describe" and self.fail_describe:
            raise ProtocolError(self.fail_describe, "Injected readiness failure")
        if method == "OpenSession":
            self.open_started.set()
            if self.open_gate:
                await self.open_gate.wait()
            if self.fail_open:
                raise ProtocolError(self.fail_open, "Injected open failure")
            response = await self.handler.handle(method, request)
            if self.after_open_gate:
                await self.after_open_gate.wait()
            return response
        if method != "Step":
            return await self.handler.handle(method, request)
        started = time.monotonic_ns()
        self.active += 1
        self.peak_active = max(self.peak_active, self.active)
        self.step_started.set()
        try:
            if self.step_gate:
                await self.step_gate.wait()
            if self.delay:
                await asyncio.sleep(self.delay)
            if self.fail_step:
                raise ProtocolError(self.fail_step, "Injected worker failure")
            return await self.handler.handle(method, request)
        finally:
            self.active -= 1
            self.spans.append((request.session_id, request.sequence, started, time.monotonic_ns()))

    async def close(self):
        self.closed = True


@unittest.skipUnless(os.environ.get("STEAMBOAT_PROTOCOL_TESTS") == "1",
                     "Set STEAMBOAT_PROTOCOL_TESTS=1 for coordinator checks")
class CoordinatorTests(unittest.IsolatedAsyncioTestCase):
    @classmethod
    def setUpClass(cls):
        import torch
        from steamboat_runtime.coordinator import Coordinator, CoordinatorError, SchedulerLimits
        from steamboat_runtime.worker_state import WorkerHandler
        support = importlib.import_module(
            f"{__package__}.test_worker_state" if __package__ else "test_worker_state")
        manifest = importlib.import_module(
            f"{__package__}.test_manifest" if __package__ else "test_manifest")
        cls.torch, cls.Coordinator = torch, Coordinator
        torch.set_num_threads(2)
        cls.Error, cls.Limits, cls.Handler = CoordinatorError, SchedulerLimits, WorkerHandler
        cls.Executor, cls.Clock = support.FakeExecutor, support.FakeClock
        cls.sample_manifest = staticmethod(manifest.sample_manifest)

    async def asyncSetUp(self):
        self.manifest = self.sample_manifest()
        self.clock = self.Clock()
        self.executors = [self.Executor(self.torch) for _ in range(3)]
        self.handlers = [self.Handler(self.manifest, f"worker-{index + 1}", executor,
                                      clock=self.clock, enable_queue=True,
                                      boot_id=str(index + 1) * 32)
                         for index, executor in enumerate(self.executors)]
        self.clients = [FakeClient(handler) for handler in self.handlers]
        self.model = FakeModel(self.torch)
        self.coordinator = None

    async def asyncTearDown(self):
        for executor in self.executors:
            executor.release.set()
        for client in self.clients:
            for gate in (client.step_gate, client.open_gate, client.after_open_gate):
                if gate:
                    gate.set()
        if self.coordinator:
            await asyncio.wait_for(self.coordinator.close(), 5)
        for handler in self.handlers:
            await asyncio.wait_for(handler.shutdown(), 4)

    async def start(self, **overrides):
        limits = replace(self.Limits(), **{"cleanup_timeout_seconds": 1, **overrides})
        self.coordinator = self.Coordinator(self.manifest, self.clients, self.model, limits=limits)
        await self.coordinator.start()
        return self.coordinator

    def ids(self, *tokens):
        return self.torch.tensor([list(tokens)], dtype=self.torch.long)

    async def collect(self, handle):
        events = [event async for event in handle]
        result = await handle.result()
        self.assertEqual(result.status, "completed")
        self.assertTrue(result.cleanup_complete)
        return events

    async def wait_for(self, predicate, timeout=1):
        deadline = time.monotonic() + timeout
        while not predicate():
            if time.monotonic() >= deadline:
                self.fail("Condition did not become true before test deadline")
            await asyncio.sleep(0.001)

    def assert_clean(self):
        self.assertTrue(all(not handler.sessions for handler in self.handlers))
        stats = self.coordinator.stats()
        self.assertEqual(stats["active_requests"], 0)
        self.assertEqual(stats["waiting_admissions"], 0)
        self.assertEqual(stats["stage_queue_sizes"], [0, 0, 0])

    async def test_execute_for_request_preserves_legacy_and_secure_call_signatures(self):
        from steamboat_runtime.participant_context import TrustedRequestContext

        coordinator = await self.start()
        calls = []

        async def legacy_execute(index, method, request):
            calls.append((index, method, request, {}))
            return "legacy"

        coordinator._execute = legacy_execute
        request = object()
        self.assertEqual(await coordinator._execute_for_request(0, "Describe", request),
                         "legacy")
        self.assertEqual(calls, [(0, "Describe", request, {})])

        class Authorization:
            def assert_live(self):
                return None

            def remaining_seconds(self):
                return 60.0

        context = TrustedRequestContext(
            tenant_account_id="acct_" + "1" * 32,
            request_id="req_" + "2" * 32,
            session_id="ses_" + "3" * 32,
            route_id="route_" + "4" * 32,
            coordinator_boot_id="5" * 32,
            route_epoch=1,
            attempt=1,
            authorization=Authorization(),
            hard_monotonic_deadline=time.monotonic() + 30,
        )
        scoped_calls = []

        async def scoped_execute(index, method, request, **kwargs):
            scoped_calls.append((index, method, request, kwargs))
            return "scoped"

        coordinator._execute = scoped_execute
        self.assertEqual(await coordinator._execute_for_request(
            1, "Step", request, trusted_request_context=context), "scoped")
        self.assertEqual(await coordinator._execute_for_request(
            1, "CloseSession", request, trusted_request_context=context, cleanup=True),
            "scoped")
        self.assertIs(scoped_calls[0][3]["trusted_request_context"], context)
        self.assertNotIn("cleanup", scoped_calls[0][3])
        self.assertIs(scoped_calls[1][3]["trusted_request_context"], context)
        self.assertIs(scoped_calls[1][3]["cleanup"], True)

    async def test_one_three_eight_requests_preserve_greedy_causal_feedback(self):
        coordinator = await self.start()
        for concurrency in (1, 3, 8):
            handles = [coordinator.submit(self.ids(9, 20 + index), 4, capture_logits=True)
                       for index in range(concurrency)]
            streams = await asyncio.gather(*(self.collect(handle) for handle in handles))
            for index, stream in enumerate(streams):
                self.assertEqual([event.token_id for event in stream],
                                 [24 + index, 28 + index, 32 + index, 36 + index])
                self.assertEqual([event.index for event in stream], list(range(4)))
                self.assertEqual([event.position for event in stream], [2, 3, 4, 5])
                self.assertTrue(all(event.logits.shape == (1, 32000) for event in stream))
                for client in self.clients:
                    steps = [sequence for method, session, sequence in client.calls
                             if method == "Step" and session == handles[index].session_id]
                    self.assertEqual(steps, list(range(4)))
            self.assert_clean()
        self.assertEqual([client.peak_active for client in self.clients], [1, 1, 1])

    async def test_forced_inputs_do_not_replace_emitted_greedy_tokens(self):
        coordinator = await self.start()
        handle = coordinator.submit(self.ids(7), 3, forced_tokens=[101, 203])
        events = await self.collect(handle)
        self.assertEqual([event.token_id for event in events], [11, 105, 207])
        self.assertEqual([int(value[0, 0]) for value in self.model.embedded], [7, 101, 203])

    async def test_fifo_at_stage_boundaries_allows_other_sessions_to_progress(self):
        coordinator = await self.start()
        self.clients[1].step_gate = asyncio.Event()
        first = coordinator.submit(self.ids(10), 2)
        await asyncio.wait_for(self.clients[1].step_started.wait(), 2)
        second = coordinator.submit(self.ids(30), 2)
        await self.wait_for(lambda: coordinator.stats()["stage_queue_sizes"][1] == 1)
        self.assertEqual(len([c for c in self.clients[1].calls if c[0] == "Step"]), 1)
        self.assertEqual(coordinator.stats()["stage_queue_sizes"][1], 1)
        self.clients[1].step_gate.set()
        await asyncio.gather(self.collect(first), self.collect(second))
        self.assertEqual([c[1] for c in self.clients[1].calls if c[0] == "Step"][:2],
                         [first.session_id, second.session_id])
        self.assertTrue(any(a[0] != b[0] and max(a[2], b[2]) < min(a[3], b[3])
                            for a in self.clients[0].spans for b in self.clients[1].spans))
        self.assert_clean()

    async def test_partial_admission_refusal_releases_known_leases(self):
        coordinator = await self.start()
        self.clients[1].fail_open = "CAPACITY_EXHAUSTED"
        handle = coordinator.submit(self.ids(10), 2)
        result = await handle.result()
        self.assertEqual(result.error_code, "CAPACITY_EXHAUSTED")
        self.assertTrue(result.cleanup_complete)
        self.assertFalse(any(call[0] == "Step" for client in self.clients for call in client.calls))
        self.assertFalse(any(call[0] == "OpenSession" for call in self.clients[2].calls))
        self.assert_clean()

    async def test_admission_deadline_includes_partial_open_not_only_slot_wait(self):
        coordinator = await self.start(admission_timeout_seconds=0.2)
        self.clients[1].open_gate = asyncio.Event()
        handle = coordinator.submit(self.ids(10), 2)
        result = await asyncio.wait_for(handle.result(), 1)
        self.assertEqual(result.error_code, "ADMISSION_TIMEOUT")
        self.assertIsNone(result.admitted_at)
        self.assertFalse(result.cleanup_complete)  # An unacknowledged open is ambiguous.
        self.assert_clean()

    async def test_lost_open_reply_is_never_retried_and_expiry_is_explicit(self):
        coordinator = await self.start(admission_timeout_seconds=0.2)
        self.clients[1].after_open_gate = asyncio.Event()
        handle = coordinator.submit(self.ids(10), 2)
        result = await handle.result()
        self.assertFalse(result.cleanup_complete)
        self.assertEqual(len(self.handlers[1].sessions), 1)
        self.assertEqual(len([call for call in self.clients[1].calls if call[0] == "OpenSession"]), 1)
        self.assertFalse(self.handlers[0].sessions)
        self.clock.advance(121)
        await self.handlers[1].reap()
        self.assert_clean()

    async def test_missing_worker_prevents_any_reservation(self):
        coordinator = await self.start()
        self.clients[2].fail_describe = "EXECUTION_FAILED"
        result = await coordinator.submit(self.ids(8), 1).result()
        self.assertEqual(result.status, "failed")
        self.assertFalse(any(call[0] == "OpenSession" for client in self.clients for call in client.calls))
        self.assert_clean()

    async def test_cancel_before_task_starts_and_while_waiting_unlinks_admissions(self):
        coordinator = await self.start(max_sessions=1, max_waiting_admissions=1)
        immediate = coordinator.submit(self.ids(1), 2)
        self.assertEqual((await immediate.cancel()).status, "cancelled")
        self.clients[0].step_gate = asyncio.Event()
        first = coordinator.submit(self.ids(10), 2)
        await asyncio.wait_for(self.clients[0].step_started.wait(), 2)
        waiting = coordinator.submit(self.ids(20), 2)
        with self.assertRaises(self.Error) as exhausted:
            coordinator.submit(self.ids(30), 2)
        self.assertEqual(exhausted.exception.code, "CAPACITY_EXHAUSTED")
        await waiting.cancel()
        replacement = coordinator.submit(self.ids(40), 2)
        self.assertEqual(coordinator.stats()["waiting_admissions"], 1)
        await replacement.cancel()
        await first.cancel()
        self.assert_clean()

    async def test_waiting_admission_times_out_from_submission(self):
        coordinator = await self.start(max_sessions=1, admission_timeout_seconds=0.2)
        self.clients[0].step_gate = asyncio.Event()
        first = coordinator.submit(self.ids(10), 2)
        await asyncio.wait_for(self.clients[0].step_started.wait(), 2)
        waiting = coordinator.submit(self.ids(20), 2)
        result = await waiting.result()
        self.assertEqual(result.error_code, "ADMISSION_TIMEOUT")
        self.assertIsNone(result.admitted_at)
        self.assertFalse(any(c[1] == waiting.session_id and c[0] == "OpenSession"
                             for client in self.clients for c in client.calls))
        await first.cancel()
        self.assert_clean()

    async def test_cancellation_removes_queued_work_without_stopping_other_session(self):
        coordinator = await self.start()
        self.clients[0].step_gate = asyncio.Event()
        first = coordinator.submit(self.ids(10), 2)
        await asyncio.wait_for(self.clients[0].step_started.wait(), 2)
        queued = coordinator.submit(self.ids(20), 2)
        await self.wait_for(lambda: coordinator.stats()["stage_queue_sizes"][0] == 1)
        self.assertTrue((await queued.cancel()).cleanup_complete)
        self.assertEqual(coordinator.stats()["stage_queue_sizes"], [0, 0, 0])
        self.clients[0].step_gate.set()
        await self.collect(first)
        self.assertFalse(any(c[0] == "Step" and c[1] == queued.session_id
                             for client in self.clients for c in client.calls))
        self.assert_clean()

    async def test_slow_consumer_does_not_block_other_sessions(self):
        coordinator = await self.start(output_queue_tokens=1, output_stall_timeout_seconds=0.08)
        stalled = coordinator.submit(self.ids(10), 8)
        await self.wait_for(lambda: stalled._state.output.full())
        other = coordinator.submit(self.ids(20), 2)
        self.assertEqual(len(await self.collect(other)), 2)
        result = await stalled.result()
        self.assertEqual(result.error_code, "SLOW_CONSUMER")
        self.assertTrue(stalled._state.output.empty())
        self.assertTrue(result.cleanup_complete)
        self.assert_clean()

    async def test_renewal_runs_while_queued_and_while_output_is_full(self):
        coordinator = await self.start(renew_interval_seconds=0.01, output_queue_tokens=1,
                                      output_stall_timeout_seconds=0.2)
        self.clients[0].step_gate = asyncio.Event()
        first = coordinator.submit(self.ids(10), 3)
        await asyncio.wait_for(self.clients[0].step_started.wait(), 2)
        second = coordinator.submit(self.ids(20), 3)
        await self.wait_for(lambda: coordinator.stats()["stage_queue_sizes"][0] == 1)
        await self.wait_for(lambda: all(any(c[0] == "RenewSession" and c[1] == second.session_id
                                            for c in client.calls) for client in self.clients))
        self.clients[0].step_gate.set()
        await self.wait_for(lambda: first._state.output.full())
        renewals = sum(c[0] == "RenewSession" for c in self.clients[0].calls)
        await self.wait_for(lambda: sum(c[0] == "RenewSession" for c in self.clients[0].calls) > renewals)
        await asyncio.gather(first.cancel(), second.cancel())
        self.assert_clean()

    async def test_request_timeout_cancels_active_rpc_without_retry(self):
        coordinator = await self.start()
        self.clients[0].step_gate = asyncio.Event()
        handle = coordinator.submit(self.ids(10), 3, timeout_seconds=0.3)
        await asyncio.wait_for(self.clients[0].step_started.wait(), 1)
        result = await handle.result()
        self.assertEqual(result.error_code, "TIMEOUT")
        self.assertTrue(result.cleanup_complete)
        self.assertEqual(len([c for c in self.clients[0].calls if c[0] == "Step"]), 1)
        self.assert_clean()

    async def test_cancel_waits_for_running_compute_to_release_cache(self):
        coordinator = await self.start()
        self.executors[0].block = True
        handle = coordinator.submit(self.ids(10), 3)
        await self.wait_for(self.executors[0].started.is_set)
        cancelling = asyncio.create_task(handle.cancel())
        await self.wait_for(lambda: bool(self.handlers[0].sessions[handle.session_id].terminal_code))
        self.assertFalse(cancelling.done())
        self.assertGreater(self.executors[0].caches[0].allocated_bytes(), 0)
        self.executors[0].release.set()
        result = await cancelling
        self.assertTrue(result.cleanup_complete)
        self.assertEqual(self.executors[0].caches[0].allocated_bytes(), 0)
        self.assert_clean()

    async def test_cancellation_preserves_an_open_reply_racing_with_cancel(self):
        coordinator = await self.start()
        original = coordinator._execute
        ready = asyncio.Event()

        async def racing_execute(index, method, request):
            response = await original(index, method, request)
            if index == 1 and method == "OpenSession":
                ready.set()
                try:
                    await asyncio.Event().wait()
                except asyncio.CancelledError:
                    return response
            return response

        coordinator._execute = racing_execute
        handle = coordinator.submit(self.ids(10), 3)
        await asyncio.wait_for(ready.wait(), 1)
        result = await handle.cancel()
        self.assertTrue(result.cleanup_complete)
        self.assertFalse(any(c[0] == "Step" for client in self.clients for c in client.calls))
        self.assert_clean()

    async def test_small_stage_queue_backpressure_and_cancel_do_not_starve_followers(self):
        coordinator = await self.start(max_stage_queue=1)
        self.clients[0].step_gate = asyncio.Event()
        handles = [coordinator.submit(self.ids(10 + index), 2) for index in range(4)]
        await self.wait_for(lambda: coordinator.stats()["stage_queue_sizes"][0] == 1)
        await handles[2].cancel()
        self.assertLessEqual(coordinator.stats()["stage_queue_sizes"][0], 1)
        self.clients[0].step_gate.set()
        await asyncio.gather(*(self.collect(handles[index]) for index in (0, 1, 3)))
        self.assert_clean()

    async def test_worker_failure_fails_requests_and_disables_new_admission(self):
        coordinator = await self.start()
        self.clients[1].fail_step = "EXECUTION_FAILED"
        handles = [coordinator.submit(self.ids(10 + index), 3) for index in range(3)]
        results = await asyncio.gather(*(handle.result() for handle in handles))
        self.assertTrue(all(result.status == "failed" for result in results))
        self.assertTrue(all(result.cleanup_complete for result in results))
        with self.assertRaises(self.Error):
            coordinator.submit(self.ids(1), 1)
        self.assert_clean()

    async def test_restart_between_start_and_admission_rejects_old_boot(self):
        coordinator = await self.start()
        self.handlers[1].boot_id = "e" * 32
        result = await coordinator.submit(self.ids(10), 1).result()
        self.assertEqual(result.error_code, "STALE_WORKER")
        self.assertFalse(any(c[0] == "OpenSession" for client in self.clients for c in client.calls))
        self.assert_clean()

    async def test_invalid_input_is_rejected_before_any_reservation(self):
        coordinator = await self.start()
        cases = [(self.ids(1), 0, {}), (self.ids(1), True, {}),
                 (self.ids(-1), 1, {}), (self.ids(32000), 1, {}),
                 (self.torch.ones((1, 1152), dtype=self.torch.long), 1, {}),
                 (self.ids(1), 3, {"forced_tokens": [2]}),
                 (self.ids(1), 2, {"forced_tokens": [True]}),
                 (self.ids(1), 1, {"timeout_seconds": float("nan")})]
        for tokens, count, options in cases:
            with self.subTest(count=count, options=options), self.assertRaises(ValueError):
                coordinator.submit(tokens, count, **options)
        self.assertFalse(any(c[0] == "OpenSession" for client in self.clients for c in client.calls))

    async def test_concurrent_start_has_only_three_consumers_and_bounded_trace(self):
        limits = replace(self.Limits(), trace_events=4, cleanup_timeout_seconds=1)
        def bad_trace(_):
            raise RuntimeError("Tracing must not orphan submitted requests")
        self.coordinator = self.Coordinator(self.manifest, self.clients, self.model,
                                             limits=limits, trace=bad_trace)
        await asyncio.gather(*(self.coordinator.start() for _ in range(3)))
        self.assertEqual(len(self.coordinator._consumers), 3)
        await self.collect(self.coordinator.submit(self.ids(10), 2))
        self.assertEqual(len(self.coordinator.events), 4)
        self.assertGreater(self.coordinator.trace_dropped, 0)
        self.assertGreater(self.coordinator.trace_errors, 0)
        self.assert_clean()

    async def test_iterator_cancellation_propagates_to_workers(self):
        coordinator = await self.start()
        self.clients[0].step_gate = asyncio.Event()
        handle = coordinator.submit(self.ids(10), 3)
        waiting = asyncio.create_task(anext(handle))
        await asyncio.wait_for(self.clients[0].step_started.wait(), 2)
        waiting.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await waiting
        self.assertEqual((await handle.result()).status, "cancelled")
        self.assert_clean()

    async def test_shutdown_cancels_all_and_closes_owned_model_and_clients(self):
        coordinator = await self.start()
        self.clients[0].step_gate = asyncio.Event()
        handles = [coordinator.submit(self.ids(10 + i), 3) for i in range(3)]
        await asyncio.wait_for(self.clients[0].step_started.wait(), 2)
        self.assertTrue(await coordinator.close())
        self.assertTrue(self.model.closed)
        self.assertTrue(all(client.closed for client in self.clients))
        results = await asyncio.gather(*(handle.result() for handle in handles))
        self.assertTrue(all(result.status == "cancelled" for result in results))
        self.assert_clean()

    async def test_shutdown_returns_failure_after_ordinary_client_close_error(self):
        from steamboat_runtime.protocol.secure_transport import SecureTransportError

        coordinator = await self.start()

        async def fail_client_close():
            raise SecureTransportError("physical close was not confirmed")

        self.clients[0].close = fail_client_close
        self.assertFalse(await coordinator.close())
        # Local model cleanup can succeed, but it cannot turn a failed worker
        # transport close into a successful coordinator shutdown.
        self.assertTrue(self.model.closed)
        self.assertTrue(coordinator.model_cleanup_complete)
        self.assertIsNotNone(coordinator._fatal_error)

    async def test_shutdown_inspects_consumed_completed_startup_wrapper(self):
        from unittest.mock import patch
        from steamboat_runtime.protocol.secure_transport import SecureTaskPending
        import steamboat_runtime.coordinator as coordinator_module

        coordinator = self.Coordinator(self.manifest, self.clients, self.model)
        self.coordinator = coordinator
        child_started, release_child = asyncio.Event(), asyncio.Event()

        async def resistant_child():
            child_started.set()
            try:
                await release_child.wait()
            except asyncio.CancelledError:
                await release_child.wait()

        async def completed_start_wrapper():
            child = asyncio.create_task(resistant_child())
            await child_started.wait()
            raise SecureTaskPending((child,), "startup still owns a child")

        wrapper = asyncio.create_task(completed_start_wrapper())
        observed = (await asyncio.gather(wrapper, return_exceptions=True))[0]
        self.assertIsInstance(observed, SecureTaskPending)
        coordinator._start_task = wrapper

        try:
            with patch.object(coordinator_module,
                              "MAX_CANCELLATION_GRACE_SECONDS", 0.05):
                started = time.monotonic()
                self.assertFalse(await coordinator.close())
                self.assertLess(time.monotonic() - started, 0.5)
            child = next(iter(coordinator._shutdown_pending_tasks))
            self.assertNotIn(wrapper, coordinator._shutdown_pending_tasks)
            self.assertFalse(child.done())
            self.assertFalse(self.model.closed)
            self.assertFalse(any(client.closed for client in self.clients))
            release_child.set()
            await asyncio.wait_for(child, 1)
            self.assertTrue(await coordinator._wait_shutdown_tasks_until(
                time.monotonic() + 0.5))
        finally:
            release_child.set()

    async def test_pending_client_close_stays_bounded_and_retained_until_child_retires(self):
        from unittest.mock import patch
        from steamboat_runtime.protocol.secure_transport import SecureTaskPending
        import steamboat_runtime.coordinator as coordinator_module

        coordinator = await self.start()
        child_started, release_child = asyncio.Event(), asyncio.Event()
        owned = []

        async def resistant_close_child():
            child_started.set()
            try:
                await release_child.wait()
            except asyncio.CancelledError:
                await release_child.wait()

        async def pending_client_close():
            async def completed_wrapper():
                child = asyncio.create_task(resistant_close_child())
                owned.append(child)
                await child_started.wait()
                raise SecureTaskPending((child,), "close wrapper still owns a child")

            wrapper = asyncio.create_task(completed_wrapper())
            observed = (await asyncio.gather(wrapper, return_exceptions=True))[0]
            self.assertIsInstance(observed, SecureTaskPending)
            raise SecureTaskPending((wrapper,), "client close wrapper was observed")

        self.clients[0].close = pending_client_close
        try:
            with patch.object(coordinator_module,
                              "MAX_CANCELLATION_GRACE_SECONDS", 0.05):
                started = time.monotonic()
                self.assertFalse(await coordinator.close())
                self.assertLess(time.monotonic() - started, 0.5)
            self.assertTrue(owned)
            child = owned[0]
            self.assertFalse(child.done())
            self.assertIn(child, coordinator._shutdown_pending_tasks)
            self.assertFalse(self.model.closed)
            self.assertFalse(self.clients[0].closed)

            release_child.set()
            await asyncio.wait_for(child, 1)
            self.assertTrue(await coordinator._wait_shutdown_tasks_until(
                time.monotonic() + 0.5))
        finally:
            release_child.set()

    async def test_shutdown_callback_owns_child_announced_after_close_deadline(self):
        from unittest.mock import patch
        from steamboat_runtime.protocol.secure_transport import SecureTaskPending
        from steamboat_runtime.protocol import secure_transport
        import steamboat_runtime.coordinator as coordinator_module

        coordinator = await self.start()
        close_started, release_close, child_started, release_child = (
            asyncio.Event(), asyncio.Event(), asyncio.Event(), asyncio.Event())
        child_tasks = []

        async def resistant_child():
            child_started.set()
            try:
                await release_child.wait()
            except asyncio.CancelledError:
                await release_child.wait()

        async def delayed_pending_close():
            close_started.set()
            await release_close.wait()
            child = asyncio.create_task(resistant_child())
            child_tasks.append(child)
            await child_started.wait()
            raise SecureTaskPending((child,), "late close child")

        self.clients[0].close = delayed_pending_close
        try:
            with patch.object(coordinator_module,
                              "MAX_CANCELLATION_GRACE_SECONDS", 0.05):
                started = time.monotonic()
                self.assertFalse(await coordinator.close())
                self.assertLess(time.monotonic() - started, 0.5)
            await asyncio.wait_for(close_started.wait(), 1)
            self.assertFalse(coordinator.stats()["ready"])
            self.assertTrue(coordinator._closed)
            root = next(task for task in coordinator._shutdown_pending_tasks
                        if not task.done())
            self.assertIn(root, coordinator._shutdown_watched_tasks)

            release_close.set()
            await asyncio.wait_for(child_started.wait(), 1)
            child = child_tasks[0]
            await self.wait_for(lambda: child in coordinator._shutdown_pending_tasks, 1)
            self.assertTrue(root.done())
            self.assertIn(child, coordinator._shutdown_watched_tasks)
            self.assertIn(child, secure_transport._RETAINED_TASKS)
            self.assertFalse(child.done())
            self.assertFalse(coordinator.stats()["ready"])
        finally:
            release_close.set()
            release_child.set()
            remaining = tuple(task for task in coordinator._shutdown_pending_tasks
                              if not task.done())
            if remaining:
                await asyncio.wait_for(asyncio.gather(*remaining,
                                                       return_exceptions=True), 1)
            if child_tasks:
                await asyncio.wait_for(asyncio.gather(*child_tasks,
                                                       return_exceptions=True), 1)

    async def test_model_close_timeout_is_bounded_after_clients_close(self):
        from unittest.mock import patch
        import steamboat_runtime.coordinator as coordinator_module

        coordinator = await self.start()
        model_close_started, release_model = asyncio.Event(), asyncio.Event()
        model_tasks = []

        async def delayed_model_close():
            model_tasks.append(asyncio.current_task())
            model_close_started.set()
            try:
                await release_model.wait()
            except asyncio.CancelledError:
                await release_model.wait()
            self.model.closed = True
            return True

        self.model.close = delayed_model_close
        try:
            with patch.object(coordinator_module,
                              "MAX_CANCELLATION_GRACE_SECONDS", 0.15):
                started = time.monotonic()
                self.assertFalse(await coordinator.close())
                self.assertLess(time.monotonic() - started, 0.6)
            await asyncio.wait_for(model_close_started.wait(), 1)
            self.assertTrue(all(client.closed for client in self.clients))
            self.assertIsNone(coordinator.model_cleanup_complete)
            self.assertTrue(model_tasks)
            model_task = model_tasks[0]
            self.assertFalse(model_task.done())
            self.assertIn(model_task, coordinator._shutdown_pending_tasks)
            self.assertFalse(self.model.closed)
            self.assertFalse(coordinator.stats()["ready"])

            release_model.set()
            await asyncio.wait_for(model_task, 1)
            self.assertTrue(self.model.closed)
            self.assertIsNone(coordinator.model_cleanup_complete)
            self.assertFalse(await coordinator.close())
        finally:
            release_model.set()
            if model_tasks:
                await asyncio.gather(model_tasks[0], return_exceptions=True)

    async def test_limits_cannot_exceed_frozen_manifest_bounds(self):
        for values in ({"max_sessions": 9}, {"max_stage_queue": 9},
                       {"request_timeout_seconds": 301}, {"trace_events": 0},
                       {"output_queue_tokens": True}, {"renew_interval_seconds": float("nan")}):
            with self.subTest(values=values), self.assertRaises(ValueError):
                self.Coordinator(self.manifest, self.clients, self.model,
                                 limits=replace(self.Limits(), **values))

    def trusted_context(self):
        from steamboat_runtime.participant_context import TrustedRequestContext

        class Authorization:
            def assert_live(self):
                return True

            def remaining_seconds(self):
                return 60.0

        return TrustedRequestContext(
            tenant_account_id="acct_" + "1" * 32,
            request_id="req_" + "2" * 32,
            session_id="ses_" + "3" * 32,
            route_id="route_" + "4" * 32,
            coordinator_boot_id="5" * 32,
            route_epoch=1,
            attempt=1,
            authorization=Authorization(),
            hard_monotonic_deadline=time.monotonic() + 60,
        )

    def install_context_clients(self, after_response):
        for index, client in enumerate(self.clients):
            original = client.execute

            async def execute(method, request, *, trusted_request_context=None,
                              _original=original, _index=index):
                response = await _original(method, request)
                await after_response(_index, method, request, response)
                return response

            client.execute = execute

    async def test_step_pending_child_keeps_context_and_admission_until_cleanup(self):
        from steamboat_runtime.protocol.secure_transport import SecureTaskPending

        coordinator = await self.start(cleanup_timeout_seconds=1)
        context = self.trusted_context()
        child_started, release_child = asyncio.Event(), asyncio.Event()
        injected = False

        async def after_response(index, method, request, response):
            nonlocal injected
            if index != 1 or method != "Step" or injected:
                return
            injected = True

            async def resistant_child():
                child_started.set()
                try:
                    await release_child.wait()
                except asyncio.CancelledError:
                    await release_child.wait()

            async def wrapper():
                child = asyncio.create_task(resistant_child())
                await child_started.wait()
                raise SecureTaskPending((child,), "injected pending step owner")

            completed_wrapper = asyncio.create_task(wrapper())
            observed = (await asyncio.gather(completed_wrapper,
                                             return_exceptions=True))[0]
            self.assertIsInstance(observed, SecureTaskPending)
            raise observed

        self.install_context_clients(after_response)
        handle = coordinator.submit(self.ids(9), 2, trusted_request_context=context)
        await asyncio.wait_for(child_started.wait(), 2)
        state = handle._state
        await asyncio.sleep(0.05)
        self.assertFalse(state.completion.done())
        self.assertFalse(context._admission.completed)
        self.assertIn(state.session_id, coordinator._requests)
        self.assertEqual(coordinator.stats()["active_requests"], 1)
        self.assertFalse(any(method in {"CancelSession", "CloseSession"}
                             for client in self.clients for method, _, _ in client.calls))

        release_child.set()
        result = await asyncio.wait_for(handle.result(), 2)
        self.assertTrue(result.cleanup_complete)
        self.assertTrue(context._admission.completed)
        self.assertTrue(state.retirement_event.is_set())
        self.assert_clean()

    async def test_open_pending_child_preserves_unknown_owner_and_requires_restart(self):
        from steamboat_runtime.protocol.secure_transport import SecureTaskPending

        coordinator = await self.start(cleanup_timeout_seconds=1)
        context = self.trusted_context()
        child_started, release_child = asyncio.Event(), asyncio.Event()
        injected = False

        async def after_response(index, method, request, response):
            nonlocal injected
            if index != 0 or method != "OpenSession" or injected:
                return
            injected = True

            async def resistant_child():
                child_started.set()
                try:
                    await release_child.wait()
                except asyncio.CancelledError:
                    await release_child.wait()

            async def wrapper():
                child = asyncio.create_task(resistant_child())
                await child_started.wait()
                raise SecureTaskPending((child,), "injected pending open owner")

            completed_wrapper = asyncio.create_task(wrapper())
            observed = (await asyncio.gather(completed_wrapper,
                                             return_exceptions=True))[0]
            self.assertIsInstance(observed, SecureTaskPending)
            raise observed

        self.install_context_clients(after_response)
        handle = coordinator.submit(self.ids(9), 2, trusted_request_context=context)
        await asyncio.wait_for(child_started.wait(), 2)
        state = handle._state
        self.assertIn(0, state.unknown_opens)
        self.assertFalse(context._admission.completed)
        self.assertEqual(coordinator.stats()["active_requests"], 1)
        release_child.set()
        result = await asyncio.wait_for(handle.result(), 2)
        self.assertFalse(result.cleanup_complete)
        self.assertEqual(result.error_code, "WORKER_PENDING")
        self.assertTrue(state.restart_required)
        self.assertIn(state.session_id, coordinator._requests)
        self.assertFalse(context._admission.completed)
        self.assertFalse(state.retirement_event.is_set())
        self.assertEqual(len([call for call in self.clients[0].calls
                              if call[0] == "OpenSession"]), 1)
        self.assertEqual(len(self.handlers[0].sessions), 1)
        self.assertFalse(await coordinator.close())
        self.assertFalse(self.model.closed)
        self.assertFalse(any(client.closed for client in self.clients))

    async def test_renew_pending_child_is_owned_before_session_cleanup(self):
        from steamboat_runtime.protocol.secure_transport import SecureTaskPending

        coordinator = await self.start(renew_interval_seconds=0.01,
                                       cleanup_timeout_seconds=1)
        context = self.trusted_context()
        self.clients[0].step_gate = asyncio.Event()
        child_started, release_child = asyncio.Event(), asyncio.Event()
        injected = False

        async def after_response(index, method, request, response):
            nonlocal injected
            if index != 0 or method != "RenewSession" or injected:
                return
            injected = True

            async def resistant_child():
                child_started.set()
                try:
                    await release_child.wait()
                except asyncio.CancelledError:
                    await release_child.wait()

            async def wrapper():
                child = asyncio.create_task(resistant_child())
                await child_started.wait()
                raise SecureTaskPending((child,), "injected pending renew owner")

            completed_wrapper = asyncio.create_task(wrapper())
            observed = (await asyncio.gather(completed_wrapper,
                                             return_exceptions=True))[0]
            self.assertIsInstance(observed, SecureTaskPending)
            raise observed

        self.install_context_clients(after_response)
        handle = coordinator.submit(self.ids(9), 3, trusted_request_context=context)
        await asyncio.wait_for(self.clients[0].step_started.wait(), 2)
        await asyncio.wait_for(child_started.wait(), 2)
        state = handle._state
        self.assertFalse(context._admission.completed)
        self.assertIn(state.session_id, coordinator._requests)
        self.assertEqual(coordinator.stats()["active_requests"], 1)
        self.assertFalse(any(method in {"CancelSession", "CloseSession"}
                             for client in self.clients for method, _, _ in client.calls))
        release_child.set()
        result = await asyncio.wait_for(handle.result(), 2)
        self.assertTrue(result.cleanup_complete)
        self.assertTrue(context._admission.completed)
        self.assertEqual(len([call for call in self.clients[0].calls
                              if call[0] == "RenewSession"]), 1)
        self.assert_clean()

    async def test_pending_cancel_switches_to_status_without_replaying_mutation(self):
        from steamboat_runtime.protocol.secure_transport import SecureTaskPending

        coordinator = await self.start(cleanup_timeout_seconds=1)
        context = self.trusted_context()
        self.clients[0].step_gate = asyncio.Event()
        child_started, release_child = asyncio.Event(), asyncio.Event()
        injected = False

        async def after_response(index, method, request, response):
            nonlocal injected
            if index != 0 or method != "CancelSession" or injected:
                return
            injected = True

            async def resistant_child():
                child_started.set()
                try:
                    await release_child.wait()
                except asyncio.CancelledError:
                    await release_child.wait()

            async def wrapper():
                child = asyncio.create_task(resistant_child())
                await child_started.wait()
                raise SecureTaskPending((child,), "injected pending cancel owner")

            completed_wrapper = asyncio.create_task(wrapper())
            observed = (await asyncio.gather(completed_wrapper,
                                             return_exceptions=True))[0]
            self.assertIsInstance(observed, SecureTaskPending)
            raise observed

        self.install_context_clients(after_response)
        handle = coordinator.submit(self.ids(9), 3, trusted_request_context=context)
        await asyncio.wait_for(self.clients[0].step_started.wait(), 2)
        cancelling = asyncio.create_task(handle.cancel())
        await asyncio.wait_for(child_started.wait(), 2)
        state = handle._state
        await asyncio.sleep(0.05)
        self.assertFalse(cancelling.done())
        self.assertFalse(context._admission.completed)
        self.assertIn(state.session_id, coordinator._requests)
        self.assertEqual(coordinator.stats()["active_requests"], 1)
        self.assertEqual(len([call for call in self.clients[0].calls
                              if call[0] == "CancelSession"]), 1)
        release_child.set()
        result = await asyncio.wait_for(cancelling, 2)
        self.assertTrue(result.cleanup_complete)
        self.assertTrue(context._admission.completed)
        self.assertEqual(len([call for call in self.clients[0].calls
                              if call[0] == "CancelSession"]), 1)
        self.assertGreaterEqual(len([call for call in self.clients[0].calls
                                     if call[0] == "SessionStatus"]), 1)
        self.assert_clean()
