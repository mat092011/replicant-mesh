"""Per-component handler ceilings layered over the unchanged v1 manifest."""

import asyncio
import importlib
import os
import unittest
from unittest import mock


support = importlib.import_module(
    f"{__package__}.test_worker_state" if __package__ else "test_worker_state")


@unittest.skipUnless(os.environ.get("STEAMBOAT_PROTOCOL_TESTS") == "1",
                     "Set STEAMBOAT_PROTOCOL_TESTS=1 for worker owner-limit checks")
class WorkerOwnerLimitTests(unittest.IsolatedAsyncioTestCase):
    setUpClass = classmethod(support.WorkerStateTests.setUpClass.__func__)
    asyncTearDown = support.WorkerStateTests.asyncTearDown
    request = support.WorkerStateTests.request
    call = support.WorkerStateTests.call
    open = support.WorkerStateTests.open
    step_request = support.WorkerStateTests.step_request
    step = support.WorkerStateTests.step
    start_step = support.WorkerStateTests.start_step
    await_started = support.WorkerStateTests.await_started

    async def asyncSetUp(self):
        await support.WorkerStateTests.asyncSetUp(self)
        original = self.manifest["limits"]
        self.handler = self.Handler(
            self.manifest, "worker-1", self.executor, clock=self.clock,
            boot_id="test-boot", owner_limits={"max_sessions": 8,
                "worker_cache_positions": 64, "worker_cache_bytes": 60000,
                "request_timeout_seconds": 10})
        self.handlers.append(self.handler)
        self.assertEqual(self.manifest["limits"], original)
        self.assertIsNot(self.handler.limits, self.manifest["limits"])

    async def test_open_enforces_narrow_session_position_and_cache_limits(self):
        first = await self.open("A", maximum=32, lifetime_ms=10000)
        self.assertEqual(first.code, "OK")
        too_many_positions = await self.call(
            "OpenSession", "B", lease_token="", max_positions=33,
            lifetime_ms=1000, idle_lease_ms=1000)
        self.assertEqual(too_many_positions.code, "CAPACITY_EXHAUSTED")
        too_many_cache_bytes = await self.call(
            "OpenSession", "C", lease_token="", max_positions=32,
            lifetime_ms=1000, idle_lease_ms=1000)
        self.assertEqual(too_many_cache_bytes.code, "CAPACITY_EXHAUSTED")
        status = await self.call("Describe")
        self.assertEqual((status.active_sessions, status.reserved_positions), (1, 32))
        self.assertEqual(status.max_sessions, 8)
        self.assertEqual(status.max_cache_positions, 64)
        self.assertEqual(status.max_cache_bytes, 60000)

    async def test_open_enforces_narrow_session_count(self):
        limited = self.Handler(self.manifest, "worker-1", self.executor,
                               clock=self.clock, boot_id="one-session",
                               owner_limits={"max_sessions": 1})
        self.handlers.append(limited)
        first = await limited.handle("OpenSession", self.request(
            "A", lease_token="", max_positions=1, lifetime_ms=1000,
            idle_lease_ms=1000, worker_boot_id="one-session"))
        self.assertEqual(first.code, "OK")
        second = await limited.handle("OpenSession", self.request(
            "B", lease_token="", max_positions=1, lifetime_ms=1000,
            idle_lease_ms=1000, worker_boot_id="one-session"))
        self.assertEqual(second.code, "CAPACITY_EXHAUSTED")

    async def test_request_timeout_narrows_open_session_lifetime(self):
        response = await self.call("OpenSession", "long", lease_token="",
                                   max_positions=1, lifetime_ms=10001,
                                   idle_lease_ms=1000)
        self.assertEqual(response.code, "INVALID_INPUT")
        self.assertEqual(self.executor.caches, [])

    async def test_cancel_keeps_cache_and_reservation_until_compute_reclaims(self):
        await self.open("A", maximum=32, lifetime_ms=10000)
        self.executor.block = True
        pending = self.start_step("A", count=3)
        await self.await_started()
        cancelled = await self.call("CancelSession", "A")
        self.assertFalse(cancelled.reclaimed)
        describe = await self.call("Describe")
        self.assertEqual(describe.reserved_positions, 32)
        self.assertEqual(self.executor.caches[0].clears, 0)
        self.executor.release.set()
        self.assertEqual((await pending).code, "CANCELLED")
        self.assertEqual(self.executor.caches[0].clears, 1)
        self.assertEqual((await self.call("Describe")).active_sessions, 0)

    async def test_handler_limits_are_independent_and_legacy_defaults_are_unchanged(self):
        second_executor = support.FakeExecutor(self.torch)
        second = self.Handler(self.manifest, "worker-1", second_executor,
                              clock=self.clock, boot_id="second",
                              owner_limits={"max_sessions": 1})
        self.handlers.append(second)
        self.executors.append(second_executor)
        legacy_executor = support.FakeExecutor(self.torch)
        legacy = self.Handler(self.manifest, "worker-1", legacy_executor,
                              clock=self.clock, boot_id="legacy")
        self.handlers.append(legacy)
        self.executors.append(legacy_executor)
        self.assertEqual(second.limits["max_sessions"], 1)
        self.assertEqual(legacy.limits["max_sessions"], self.manifest["limits"]["max_sessions"])
        self.assertEqual(self.manifest["limits"]["max_sessions"], 8)

    async def test_queued_calls_respect_existing_queue_capacity(self):
        queued = self.Handler(self.manifest, "worker-1", self.executor,
                              clock=self.clock, boot_id="queued", enable_queue=True,
                              queue_capacity=1,
                              owner_limits={"max_sessions": 3})
        self.handlers.append(queued)
        leases = {}
        for name in ("A", "B", "C"):
            opened = await queued.handle("OpenSession", self.request(
                name, lease_token="", max_positions=32, lifetime_ms=300000,
                idle_lease_ms=120000, worker_boot_id="queued"))
            self.assertEqual(opened.code, "OK")
            leases[name] = opened.lease_token
        queued.executor.block = True
        first = asyncio.create_task(queued.handle("Step", self.step_request(
            "A", lease_token=leases["A"], worker_boot_id="queued")))
        self.pending.append(first)
        await self.await_started()
        second = asyncio.create_task(queued.handle("Step", self.step_request(
            "B", lease_token=leases["B"], worker_boot_id="queued")))
        self.pending.append(second)
        for _ in range(100):
            if len(queued._queue) == 1:
                break
            await asyncio.sleep(0)
        third = await queued.handle("Step", self.step_request(
            "C", lease_token=leases["C"], worker_boot_id="queued"))
        self.assertEqual(third.code, "CAPACITY_EXHAUSTED")
        self.assertEqual(len(queued._queue), 1)
        self.assertEqual(len(queued.executor.calls), 1)
        queued.executor.release.set()
        self.assertEqual((await first).code, "OK")
        self.assertEqual((await second).code, "OK")

    def test_invalid_narrowing_rejects_nonexact_nonpositive_oversized_and_unknown(self):
        for limits in ({"max_sessions": True}, {"max_sessions": 0},
                       {"max_sessions": 9}, {"other": 1},
                       [("max_sessions", 1)]):
            with self.subTest(limits=limits), self.assertRaises(ValueError):
                self.Handler(self.manifest, "worker-1", self.executor,
                             owner_limits=limits)

    def test_assigned_builder_rejects_bad_owner_limit_before_executor_construction(self):
        assigned_tests = importlib.import_module(
            "tests.connector.test_assigned_executor")
        from steamboat_runtime import assigned_executor
        view = assigned_tests._view()
        view.manifest["limits"] = dict(self.manifest["limits"])
        with mock.patch.object(assigned_executor, "AssignedStageExecutor") as executor_type:
            with self.assertRaises(assigned_tests.AssignedArtifactError):
                assigned_executor.build_assigned_worker_handler(
                    view, allow_unpinned_test_only=True,
                    owner_limits={"max_sessions": True})
        executor_type.assert_not_called()
        view.load_stage.assert_not_called()


if __name__ == "__main__":
    unittest.main()
