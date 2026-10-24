"""M3 FIFO admission, cancellation and external-watchdog snapshots.

Use the pinned runtime with REPLICANT_MESH_PROTOCOL_TESTS=1; no weights are needed.
Barriers hold the only compute thread while queued operations are inspected.
"""

import asyncio
import importlib
import os
import struct
import time
import unittest


support = importlib.import_module(
    f"{__package__}.test_worker_state" if __package__ else "test_worker_state")


@unittest.skipUnless(os.environ.get("REPLICANT_MESH_PROTOCOL_TESTS") == "1",
                     "Set REPLICANT_MESH_PROTOCOL_TESTS=1 for M3 queue checks")
class WorkerQueueTests(unittest.IsolatedAsyncioTestCase):
    setUpClass = classmethod(support.WorkerStateTests.setUpClass.__func__)
    asyncTearDown = support.WorkerStateTests.asyncTearDown
    request = support.WorkerStateTests.request
    call = support.WorkerStateTests.call
    open = support.WorkerStateTests.open
    step_request = support.WorkerStateTests.step_request
    step = support.WorkerStateTests.step
    start_step = support.WorkerStateTests.start_step
    await_started = support.WorkerStateTests.await_started
    assert_no_live_cache = support.WorkerStateTests.assert_no_live_cache

    async def asyncSetUp(self):
        await support.WorkerStateTests.asyncSetUp(self)
        self.snapshots = []
        self.handler = self.Handler(self.manifest, "worker-1", self.executor,
                                    clock=self.clock, boot_id="test-boot", enable_queue=True,
                                    queue_capacity=2, on_supervision=self.snapshots.append)
        self.handlers.append(self.handler)

    async def await_queued(self, count):
        for _ in range(100):
            if len(self.handler._queue) == count:
                return
            await asyncio.sleep(0)
        self.fail(f"Expected {count} queued operations; got {len(self.handler._queue)}")

    async def block_first(self, **kwargs):
        await self.open("A", **kwargs)
        self.executor.block = True
        pending = self.start_step("A")
        await self.await_started()
        return pending

    async def test_fifo_single_compute_and_explicit_queue_capacity(self):
        first = await self.block_first()
        for name in ("B", "C", "D"):
            await self.open(name)
        second = self.start_step("B", count=2)
        await self.await_queued(1)
        third = self.start_step("C", count=3)
        await self.await_queued(2)
        self.assertEqual((await self.step("B", count=2)).code, "OUT_OF_ORDER")
        self.assertEqual((await self.step("D")).code, "CAPACITY_EXHAUSTED")
        state = await self.call("Describe")
        self.assertEqual((state.active_operations, state.queued_operations, state.max_stage_queue), (1, 2, 2))
        self.assertEqual(state.reserved_positions, 128)
        queued = await self.call("SessionStatus", "B")
        self.assertEqual(queued.state, "QUEUED")
        self.assertTrue(queued.cache_bytes_exact)
        self.assertEqual(queued.end_position, 0)
        self.assertEqual(len(self.executor.calls), 1)
        await asyncio.sleep(0.03)
        self.executor.release.set()
        responses = await asyncio.gather(first, second, third)
        self.assertEqual([r.code for r in responses], ["OK"] * 3)
        self.assertEqual([call[1] for call in self.executor.calls], [1, 2, 3])
        self.assertEqual(len({call[2] for call in self.executor.calls}), 1)
        self.assertGreater(responses[1].queue_ms, 20)
        self.assertGreater(responses[2].queue_ms, 20)
        self.assertTrue(all(r.compute_ms >= 0 for r in responses))
        self.assertEqual((await self.step("D")).code, "OK")

    async def test_queue_configuration_is_bounded_by_manifest(self):
        for capacity in (0, -1, 9, True, 1.5):
            with self.subTest(capacity=capacity), self.assertRaises(ValueError):
                self.Handler(self.manifest, "worker-1", self.executor,
                             enable_queue=True, queue_capacity=capacity)
        with self.assertRaises(ValueError):
            self.Handler(self.manifest, "worker-1", self.executor, enable_queue=1)
        with self.assertRaises(ValueError):
            self.Handler(self.manifest, "worker-1", self.executor, on_supervision=1)

    async def test_eight_session_limit_bounds_default_queue_and_reservations(self):
        self.handler = self.Handler(self.manifest, "worker-1", self.executor,
                                    clock=self.clock, boot_id="test-boot", enable_queue=True)
        self.handlers.append(self.handler)
        first = await self.block_first()
        pending = []
        for index in range(7):
            name = f"waiter-{index}"
            await self.open(name)
            pending.append(self.start_step(name))
        await self.await_queued(7)
        refused = await self.call("OpenSession", "ninth", max_positions=32,
                                  lifetime_ms=300000, idle_lease_ms=120000)
        self.assertEqual(refused.code, "CAPACITY_EXHAUSTED")
        state = await self.call("Describe")
        self.assertEqual((state.active_sessions, state.active_operations,
                          state.queued_operations, state.max_stage_queue), (8, 1, 7, 8))
        self.assertEqual(state.reserved_positions, 8 * 32)
        self.executor.release.set()
        self.assertTrue(all(r.code == "OK" for r in await asyncio.gather(first, *pending)))
        for name in list(self.leases):
            await self.call("CloseSession", name)
        await self.assert_no_live_cache()

    async def test_cancel_and_close_remove_queued_work_without_execution(self):
        first = await self.block_first()
        for name, method, code in (("B", "CancelSession", "CANCELLED"),
                                    ("C", "CloseSession", "CLOSED_SESSION")):
            await self.open(name)
            pending = self.start_step(name, count=2)
            await self.await_queued(1)
            stopped = await self.call(method, name)
            self.assertTrue(stopped.reclaimed)
            result = await asyncio.wait_for(pending, 1)
            self.assertEqual(result.code, code)
            self.assertFalse(result.HasField("tensor"))
            self.assertEqual(result.queued_operations, 0)
            self.assertEqual((await self.step(name)).code, code)
        self.assertEqual(len(self.executor.calls), 1)
        self.assertEqual((await self.call("Describe")).reserved_positions, 32)
        self.assertEqual([cache.clears for cache in self.executor.caches], [0, 1, 1])
        self.executor.release.set()
        self.assertEqual((await first).code, "OK")

    async def test_disconnected_queued_caller_reclaims_without_touching_active_cache(self):
        first = await self.block_first()
        await self.open("B")
        pending = self.start_step("B", count=2)
        await self.await_queued(1)
        pending.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await pending
        self.assertEqual((await self.step("B")).code, "CANCELLED")
        self.assertEqual(len(self.handler._queue), 0)
        self.assertEqual([cache.clears for cache in self.executor.caches], [0, 1])
        self.executor.release.set()
        self.assertEqual((await first).code, "OK")

    async def test_rpc_deadline_includes_queue_wait_and_prevents_dispatch(self):
        first = await self.block_first()
        await self.open("B")
        pending = self.start_step("B", timeout_ms=50)
        await self.await_queued(1)
        timed_out = await asyncio.wait_for(pending, 1)
        self.assertEqual(timed_out.code, "TIMEOUT")
        self.assertGreater(timed_out.queue_ms, 0)
        self.assertEqual(timed_out.compute_ms, 0)
        self.assertEqual(len(self.handler._queue), 0)
        self.assertEqual(self.executor.caches[1].clears, 1)
        self.executor.release.set()
        self.assertEqual((await first).code, "OK")
        self.assertEqual(len(self.executor.calls), 1)

    async def test_idle_expiry_removes_queued_work_and_renewal_preserves_other_waiter(self):
        first = await self.block_first()
        await self.open("B", idle_lease_ms=1000)
        await self.open("C", idle_lease_ms=1000)
        expiring = self.start_step("B", timeout_ms=30000)
        renewing = self.start_step("C", timeout_ms=30000)
        await self.await_queued(2)
        self.clock.advance(0.75)
        self.assertEqual((await self.call("RenewSession", "C")).code, "OK")
        self.clock.advance(0.25)
        await self.handler.reap()
        self.assertEqual((await expiring).code, "EXPIRED_SESSION")
        self.assertEqual(len(self.handler._queue), 1)
        self.assertEqual((await self.call("SessionStatus", "C")).state, "QUEUED")
        # The A request uses the fixture's one-second budget; keep this case about
        # lease expiry by accepting its timeout, then allow C's valid queued work.
        self.executor.release.set()
        self.assertEqual((await first).code, "TIMEOUT")
        self.assertEqual((await renewing).code, "OK")
        self.assertEqual(len(self.executor.calls), 2)

    async def test_hard_lifetime_expires_queued_session_despite_renewal(self):
        first = await self.block_first()
        await self.open("B", lifetime_ms=2000, idle_lease_ms=120000)
        pending = self.start_step("B", timeout_ms=30000)
        await self.await_queued(1)
        self.clock.advance(1)
        renewal = await self.call("RenewSession", "B")
        self.assertEqual(renewal.remaining_lifetime_ms, 1000)
        self.clock.advance(1)
        await self.handler.reap()
        self.assertEqual((await pending).code, "EXPIRED_SESSION")
        self.assertEqual(len(self.handler._queue), 0)
        self.executor.release.set()
        self.assertEqual((await first).code, "TIMEOUT")
        self.assertEqual(len(self.executor.calls), 1)

    async def test_malformed_or_nonfinite_input_does_not_renew_or_queue_even_when_full(self):
        first = await self.block_first()
        for name in ("B", "C", "D"):
            await self.open(name, idle_lease_ms=1000)
        queued = [self.start_step("B"), self.start_step("C")]
        await self.await_queued(2)
        original_deadline = self.handler.sessions["D"].idle_deadline
        self.clock.advance(0.25)
        for kind in ("nan", "length", "shape"):
            request = self.step_request("D")
            if kind == "nan":
                request.tensor.data = struct.pack("<f", float("nan")) + request.tensor.data[4:]
            elif kind == "length":
                request.tensor.byte_count += 1
            else:
                request.tensor.shape[2] = 65
            self.assertEqual((await self.handler.handle("Step", request)).code, "INVALID_INPUT")
            self.assertEqual(len(self.handler._queue), 2)
            self.assertEqual(self.handler.sessions["D"].idle_deadline, original_deadline)
            self.assertEqual(self.executor.caches[3].position, 0)
        self.executor.release.set()
        self.assertTrue(all(r.code == "OK" for r in await asyncio.gather(first, *queued)))

    async def test_acceptance_renews_idle_lease_before_waiting_in_queue(self):
        first = await self.block_first()
        await self.open("B", idle_lease_ms=1000)
        self.clock.advance(0.75)
        pending = self.start_step("B", timeout_ms=30000)
        await self.await_queued(1)
        self.assertEqual(self.handler.sessions["B"].idle_deadline, 1001.75)
        self.clock.advance(0.75)
        await self.handler.reap()
        self.assertEqual((await self.call("SessionStatus", "B")).state, "QUEUED")
        self.executor.release.set()
        self.assertEqual((await first).code, "TIMEOUT")
        self.assertEqual((await pending).code, "OK")

    async def test_active_cancellation_does_not_discard_another_sessions_queued_work(self):
        first = await self.block_first()
        await self.open("B")
        pending = self.start_step("B", count=3)
        await self.await_queued(1)
        stopped = await self.call("CancelSession", "A")
        self.assertFalse(stopped.reclaimed)
        self.assertEqual(len(self.handler._queue), 1)
        self.assertEqual(self.executor.caches[0].clears, 0)
        self.executor.release.set()
        self.assertEqual((await first).code, "CANCELLED")
        survivor = await pending
        self.assertEqual(survivor.code, "OK")
        self.assertEqual(survivor.end_position, 3)
        self.assertEqual(self.executor.caches[0].clears, 1)
        self.assertEqual(self.executor.caches[1].clears, 0)

    async def test_queued_metadata_and_activation_are_owned_copies(self):
        first = await self.block_first()
        await self.open("B")
        request = self.step_request("B", count=2)
        pending = asyncio.create_task(self.handler.handle("Step", request))
        self.pending.append(pending)
        await self.await_queued(1)
        request.sequence = 99
        request.start_position = 98
        request.tensor.data = b""
        request.session_id = "corrupted-after-admission"
        self.executor.release.set()
        self.assertEqual((await first).code, "OK")
        result = await pending
        self.assertEqual(result.code, "OK")
        self.assertEqual((result.session_id, result.sequence, result.start_position,
                          result.end_position), ("B", 0, 0, 2))
        self.assertTrue(self.torch.equal(self.decode(result.tensor, 2), self.torch.ones((1, 2, 64))))

    async def test_watchdog_snapshot_precedes_thread_and_tightens_on_cancel(self):
        original = self.executor.execute

        def inspect_before_execute(*args):
            snapshot = self.snapshots[-1]
            self.assertTrue(snapshot["active_compute"])
            self.assertIsInstance(snapshot["compute_id"], str)
            self.assertGreater(snapshot["compute_deadline"], time.monotonic())
            self.assertIsNone(snapshot["terminate_deadline"])
            return original(*args)

        self.executor.execute = inspect_before_execute
        first = await self.block_first()
        initial = self.handler.supervision_status()
        self.assertTrue(initial["active_compute"])
        self.assertGreaterEqual(initial["compute_deadline"], initial["compute_started_at"])
        self.assertLessEqual(initial["compute_deadline"] - initial["compute_started_at"], 1)
        before = time.monotonic()
        await self.call("CancelSession", "A")
        cancelled = self.handler.supervision_status()
        self.assertEqual(cancelled["compute_id"], initial["compute_id"])
        self.assertGreaterEqual(cancelled["terminate_deadline"], before + 15)
        self.assertLessEqual(cancelled["terminate_deadline"], time.monotonic() + 15)
        await self.call("CancelSession", "A")
        self.assertEqual(self.handler.supervision_status()["terminate_deadline"], cancelled["terminate_deadline"])
        self.clock.advance(15)
        await self.handler.reap()
        self.assertTrue(self.snapshots[-1]["requires_restart"])
        self.assertFalse(self.snapshots[-1]["ready"])
        self.executor.release.set()
        self.assertEqual((await first).code, "CANCELLED")
        completed = self.handler.supervision_status()
        self.assertFalse(completed["active_compute"])
        self.assertIsNone(completed["compute_deadline"])

    async def test_cancel_during_dispatch_handoff_never_enters_compute_thread(self):
        selected, dispatch = asyncio.Event(), asyncio.Event()
        original = self.handler._compute

        async def hold_dispatch(*args):
            selected.set()
            await dispatch.wait()
            return await original(*args)

        self.handler._compute = hold_dispatch
        await self.open("A")
        pending = self.start_step("A")
        try:
            await asyncio.wait_for(selected.wait(), 1)
            self.assertEqual(self.executor.calls, [])
            await self.call("CancelSession", "A")
        finally:
            dispatch.set()
        result = await pending
        self.assertEqual(result.code, "CANCELLED")
        self.assertEqual(result.compute_ms, 0)
        self.assertEqual(self.executor.calls, [])
        self.assertEqual(self.executor.caches[0].clears, 1)
        await self.assert_no_live_cache()

    async def test_shutdown_discards_waiting_work_and_preserves_active_ownership(self):
        first = await self.block_first()
        await self.open("B")
        pending = self.start_step("B")
        await self.await_queued(1)
        self.assertFalse(await self.handler.shutdown(grace_seconds=0.01))
        self.assertEqual((await pending).code, "CANCELLED")
        self.assertEqual([cache.clears for cache in self.executor.caches], [0, 1])
        self.assertEqual(len(self.handler._queue), 0)
        self.assertFalse(self.handler.supervision_status()["ready"])
        self.executor.release.set()
        self.assertEqual((await first).code, "CANCELLED")
        await self.assert_no_live_cache()


if __name__ == "__main__":
    unittest.main()
