"""M2 lifecycle contracts with deterministic compute barriers and a fake clock.

These checks need the isolated PyTorch/Protobuf environment, but no model files.
Set REPLICANT_MESH_PROTOCOL_TESTS=1 to run them. Imports stay inside the opted-in
class so the historical Petals and dependency-free suites remain runnable.
"""

import asyncio
import importlib
import os
import threading
import unittest


class FakeClock:
    def __init__(self):
        self.value = 1000.0

    def __call__(self):
        return self.value

    def advance(self, seconds):
        self.value += seconds


class FakeCache:
    """Three layers with realistic K+V byte accounting, without model weights."""

    def __init__(self):
        self.position = 0
        self.clears = 0

    def lengths(self):
        return [self.position] * 3

    def allocated_bytes(self):
        return self.position * 3 * 2 * 64 * 4

    def clear(self):
        self.position = 0
        self.clears += 1


class FakeExecutor:
    def __init__(self, torch):
        self.torch = torch
        self.caches = []
        self.calls = []
        self.block = False
        self.fail = False
        self.started = threading.Event()
        self.release = threading.Event()

    def new_cache(self):
        cache = FakeCache()
        self.caches.append(cache)
        return cache

    def execute(self, hidden, cache, position):
        self.calls.append((position, hidden.shape[1], threading.get_ident()))
        if cache.position != position:
            raise AssertionError("worker passed an uncommitted cache prefix")
        # Mutate before blocking: cancelling must not clear a cache still owned
        # by this thread, even when the response has already timed out.
        cache.position += hidden.shape[1]
        self.started.set()
        if self.block and not self.release.wait(3):
            raise RuntimeError("test compute barrier was never released")
        if self.fail:
            raise RuntimeError("injected failure after cache mutation")
        return hidden + 1


@unittest.skipUnless(os.environ.get("REPLICANT_MESH_PROTOCOL_TESTS") == "1",
                     "Set REPLICANT_MESH_PROTOCOL_TESTS=1 for M2 lifecycle checks")
class WorkerStateTests(unittest.IsolatedAsyncioTestCase):
    @classmethod
    def setUpClass(cls):
        import torch
        from replicant_mesh.protocol import worker_pb2
        from replicant_mesh.protocol.codec import encode_tensor, decode_tensor
        from replicant_mesh.worker_state import WorkerHandler

        manifest_module = importlib.import_module(
            f"{__package__}.test_manifest" if __package__ else "test_manifest")
        cls.sample_manifest = staticmethod(manifest_module.sample_manifest)
        cls.torch = torch
        cls.pb = worker_pb2
        cls.encode = staticmethod(encode_tensor)
        cls.decode = staticmethod(decode_tensor)
        cls.Handler = WorkerHandler

    async def asyncSetUp(self):
        self.clock = FakeClock()
        self.manifest = self.sample_manifest()
        self.executor = FakeExecutor(self.torch)
        self.handler = self.Handler(self.manifest, "worker-1", self.executor,
                                    clock=self.clock, boot_id="test-boot")
        self.handlers = [self.handler]
        self.executors = [self.executor]
        self.leases = {}
        self.pending = []

    async def asyncTearDown(self):
        for executor in self.executors:
            executor.release.set()
        if self.pending:
            await asyncio.wait_for(asyncio.gather(*self.pending, return_exceptions=True), 4)
        for handler in self.handlers:
            await asyncio.wait_for(handler.shutdown(), 4)

    def request(self, session_id="", **changes):
        fields = {
            "protocol_version": 1,
            "manifest_fingerprint": self.manifest["fingerprint"],
            "worker_boot_id": "test-boot",
            "session_id": session_id,
            "lease_token": self.leases.get(session_id, ""),
            "timeout_ms": 1000,
        }
        fields.update(changes)
        return self.pb.Request(**fields)

    async def call(self, method, session_id="", **changes):
        return await self.handler.handle(method, self.request(session_id, **changes))

    async def open(self, session_id="session-A", maximum=32,
                   lifetime_ms=300000, idle_lease_ms=120000):
        response = await self.call("OpenSession", session_id, lease_token="",
                                   max_positions=maximum, lifetime_ms=lifetime_ms,
                                   idle_lease_ms=idle_lease_ms)
        self.assertEqual(response.code, "OK", response.message)
        self.assertTrue(response.lease_token)
        self.leases[session_id] = response.lease_token
        return response

    def step_request(self, session_id="session-A", position=0, sequence=0,
                     count=1, **changes):
        fields = {"start_position": position, "sequence": sequence,
                  "token_count": count,
                  "tensor": self.encode(self.torch.zeros((1, count, 64)))}
        fields.update(changes)
        return self.request(session_id, **fields)

    async def step(self, session_id="session-A", **changes):
        return await self.handler.handle("Step", self.step_request(session_id, **changes))

    def start_step(self, session_id="session-A", **changes):
        task = asyncio.create_task(self.step(session_id, **changes))
        self.pending.append(task)
        return task

    async def await_started(self):
        started = await asyncio.to_thread(self.executor.started.wait, 2)
        self.assertTrue(started, "compute thread never entered its test barrier")

    async def assert_no_live_cache(self):
        response = await self.call("Describe")
        self.assertEqual(response.code, "OK", response.message)
        self.assertEqual(response.active_sessions, 0)
        self.assertEqual(response.active_operations, 0)
        self.assertEqual(response.reserved_positions, 0)
        self.assertEqual(response.allocated_cache_bytes, 0)
        self.assertTrue(response.cache_bytes_exact)

    async def test_describe_reports_identity_assignment_and_frozen_capacity(self):
        response = await self.handler.handle("Describe", self.pb.Request(protocol_version=1,
                                                                         timeout_ms=1000))
        self.assertEqual(response.code, "OK")
        self.assertTrue(response.ready)
        self.assertEqual(response.protocol_version, 1)
        self.assertEqual(response.manifest_fingerprint, self.manifest["fingerprint"])
        self.assertEqual(response.worker_boot_id, "test-boot")
        self.assertEqual((response.layer_start, response.layer_end), (0, 3))
        self.assertEqual(response.hidden_size, 64)
        self.assertEqual(response.max_sessions, 8)
        self.assertEqual(response.max_positions_limit, 1152)
        self.assertEqual(response.max_message_bytes, 1048576)
        self.assertEqual(response.max_cache_positions, 12288)
        self.assertEqual(response.max_cache_bytes, 16777216)
        self.assertEqual(response.rpc_timeout_ms, 30000)
        self.assertLessEqual(response.lease_check_interval_ms, 5000)
        await self.assert_no_live_cache()

    async def test_open_is_idempotent_but_conflicting_reservations_are_rejected(self):
        first = await self.open(maximum=11, lifetime_ms=90000, idle_lease_ms=40000)
        repeated = await self.call("OpenSession", "session-A", lease_token="",
                                   max_positions=11, lifetime_ms=90000, idle_lease_ms=40000)
        self.assertEqual(repeated.code, "OK")
        self.assertEqual(repeated.lease_token, first.lease_token)
        self.assertEqual(len(self.executor.caches), 1)
        for field, value in (("max_positions", 12), ("lifetime_ms", 90001),
                             ("idle_lease_ms", 40001)):
            arguments = {"max_positions": 11, "lifetime_ms": 90000,
                         "idle_lease_ms": 40000, field: value}
            with self.subTest(field=field):
                response = await self.call("OpenSession", "session-A", lease_token="", **arguments)
                self.assertEqual(response.code, "INVALID_INPUT")
        status = await self.call("Describe")
        self.assertEqual((status.active_sessions, status.reserved_positions), (1, 11))

    async def test_open_bounds_reject_without_reserving_memory(self):
        defaults = {"max_positions": 32, "lifetime_ms": 300000, "idle_lease_ms": 120000}
        for field, value in (("max_positions", 0), ("max_positions", 1153),
                             ("lifetime_ms", 0), ("lifetime_ms", 300001),
                             ("idle_lease_ms", 0), ("idle_lease_ms", 120001),
                             ("timeout_ms", 0), ("timeout_ms", 30001)):
            with self.subTest(field=field, value=value):
                response = await self.call("OpenSession", "invalid", **(defaults | {field: value}))
                self.assertEqual(response.code, "INVALID_INPUT")
                await self.assert_no_live_cache()
        self.assertEqual(self.executor.caches, [])

    async def test_identity_and_lease_errors_do_not_mutate_live_state(self):
        await self.open()
        variants = [({"manifest_fingerprint": "0" * 64}, "INCOMPATIBLE_MODEL"),
                    ({"worker_boot_id": "old-boot"}, "STALE_WORKER"),
                    ({"protocol_version": 2}, "INVALID_INPUT"),
                    ({"lease_token": "wrong-lease"}, "INVALID_INPUT"),
                    ({"lease_token": ""}, "INVALID_INPUT")]
        for changes, code in variants:
            with self.subTest(changes=changes):
                response = await self.step(**changes)
                self.assertEqual(response.code, code)
                self.assertEqual(self.executor.caches[0].position, 0)
        missing = await self.step("unknown")
        self.assertEqual(missing.code, "UNKNOWN_SESSION")
        valid = await self.step()
        self.assertEqual(valid.code, "OK")
        self.assertEqual(len(self.executor.calls), 1)

    async def test_eight_sessions_and_cleanup_release_capacity_independently(self):
        for index in range(8):
            await self.open(f"session-{index}", maximum=1152)
        excess = await self.call("OpenSession", "overflow", max_positions=1,
                                 lifetime_ms=300000, idle_lease_ms=120000)
        self.assertEqual(excess.code, "CAPACITY_EXHAUSTED")
        status = await self.call("Describe")
        self.assertEqual((status.active_sessions, status.reserved_positions), (8, 9216))
        closed = await self.call("CloseSession", "session-0")
        self.assertEqual(closed.code, "OK")
        self.assertTrue(closed.reclaimed)
        await self.open("replacement", maximum=1152)
        for name in list(self.leases):
            response = await self.call("CloseSession", name)
            self.assertEqual(response.code, "OK")
            self.assertTrue(response.reclaimed)
        await self.assert_no_live_cache()

    async def test_interleaved_sessions_echo_positions_and_keep_independent_caches(self):
        await self.open("A", maximum=20)
        await self.open("B", maximum=20)
        for name, position, sequence, count in (("A", 0, 0, 3), ("B", 0, 0, 7),
                                                 ("A", 3, 1, 1), ("B", 7, 1, 2)):
            result = await self.step(name, position=position, sequence=sequence, count=count)
            self.assertEqual(result.code, "OK", result.message)
            self.assertEqual(result.session_id, name)
            self.assertEqual(result.lease_token, self.leases[name])
            self.assertEqual(result.sequence, sequence)
            self.assertEqual(result.start_position, position)
            self.assertEqual(result.token_count, count)
            self.assertEqual(result.end_position, position + count)
            self.assertEqual(result.next_sequence, sequence + 1)
            self.torch.testing.assert_close(self.decode(result.tensor, count),
                                            self.torch.ones((1, count, 64)))
        first = await self.call("SessionStatus", "A")
        second = await self.call("SessionStatus", "B")
        self.assertEqual(first.end_position, 4)
        self.assertEqual(second.end_position, 9)
        self.assertEqual(first.allocated_cache_bytes, 4 * 1536)
        self.assertEqual(second.allocated_cache_bytes, 9 * 1536)
        await self.call("CloseSession", "A")
        survivor = await self.step("B", position=9, sequence=2)
        self.assertEqual(survivor.code, "OK")
        self.assertEqual(survivor.end_position, 10)

    async def test_duplicate_lost_reply_and_reordered_steps_never_reexecute(self):
        await self.open()
        accepted = await self.step(count=3)
        self.assertEqual(accepted.code, "OK")
        # Model a lost response by discarding it and retrying the same operation.
        for position, sequence in ((0, 0), (3, 0), (3, 2), (2, 1), (4, 1)):
            with self.subTest(position=position, sequence=sequence):
                result = await self.step(position=position, sequence=sequence)
                self.assertEqual(result.code, "OUT_OF_ORDER")
        self.assertEqual(len(self.executor.calls), 1)
        status = await self.call("SessionStatus", "session-A")
        self.assertEqual((status.end_position, status.next_sequence), (3, 1))
        accepted = await self.step(position=3, sequence=1)
        self.assertEqual(accepted.code, "OK")
        self.assertEqual(accepted.end_position, 4)

    async def test_context_overflow_and_malformed_envelopes_preserve_prefix(self):
        await self.open(maximum=4)
        self.assertEqual((await self.step(count=3)).code, "OK")
        overflow = await self.step(position=3, sequence=1, count=2)
        self.assertEqual(overflow.code, "INVALID_INPUT")
        for mutate in (lambda tensor: setattr(tensor, "dtype", "float16"),
                       lambda tensor: setattr(tensor, "byte_count", 3),
                       lambda tensor: setattr(tensor, "data", tensor.data[:-1]),
                       lambda tensor: tensor.shape.__setitem__(2, 65)):
            request = self.step_request(position=3, sequence=1)
            mutate(request.tensor)
            result = await self.handler.handle("Step", request)
            self.assertEqual(result.code, "INVALID_INPUT")
            self.assertEqual(self.executor.caches[0].position, 3)
        accepted = await self.step(position=3, sequence=1)
        self.assertEqual(accepted.code, "OK")
        self.assertEqual(accepted.end_position, 4)

    async def test_idle_expiry_and_renewal_cannot_extend_hard_lifetime(self):
        await self.open(lifetime_ms=100000, idle_lease_ms=40000)
        self.clock.advance(30)
        renewed = await self.call("RenewSession", "session-A")
        self.assertEqual(renewed.code, "OK")
        self.assertEqual(renewed.remaining_lifetime_ms, 70000)
        self.assertEqual(renewed.remaining_idle_ms, 40000)
        self.clock.advance(30)
        self.assertEqual((await self.call("RenewSession", "session-A")).code, "OK")
        self.clock.advance(30)
        renewed = await self.call("RenewSession", "session-A")
        self.assertEqual(renewed.code, "OK")
        self.assertEqual(renewed.remaining_lifetime_ms, 10000)
        self.assertLessEqual(renewed.remaining_idle_ms, 10000)
        self.clock.advance(10)
        await self.handler.reap()
        self.assertEqual((await self.step()).code, "EXPIRED_SESSION")
        self.assertEqual((await self.call("RenewSession", "session-A")).code, "EXPIRED_SESSION")
        await self.assert_no_live_cache()

    async def test_idle_expiry_releases_abandoned_cache_and_rejects_resurrection(self):
        await self.open(idle_lease_ms=1000)
        await self.step(count=3)
        self.clock.advance(1)
        await self.handler.reap()
        self.assertEqual(self.executor.caches[0].position, 0)
        self.assertEqual((await self.call("RenewSession", "session-A")).code, "EXPIRED_SESSION")
        reopened = await self.call("OpenSession", "session-A", lease_token="",
                                   max_positions=32, lifetime_ms=300000, idle_lease_ms=1000)
        self.assertEqual(reopened.code, "EXPIRED_SESSION")
        await self.assert_no_live_cache()

    async def test_accepted_steps_renew_idle_lease(self):
        await self.open(idle_lease_ms=1000)
        self.clock.advance(0.75)
        self.assertEqual((await self.step()).code, "OK")
        self.clock.advance(0.75)
        await self.handler.reap()
        self.assertEqual((await self.step(position=1, sequence=1)).code, "OK")
        self.clock.advance(1)
        await self.handler.reap()
        self.assertEqual((await self.step(position=2, sequence=2)).code, "EXPIRED_SESSION")

    async def test_close_cancel_are_idempotent_and_reject_late_steps(self):
        for operation, code in (("CloseSession", "CLOSED_SESSION"),
                                ("CancelSession", "CANCELLED")):
            name = operation
            await self.open(name)
            await self.step(name, count=3)
            for _ in range(2):
                result = await self.call(operation, name)
                self.assertEqual(result.code, "OK")
                self.assertTrue(result.reclaimed)
            self.assertEqual((await self.step(name, position=3, sequence=1)).code, code)
        await self.assert_no_live_cache()

    async def test_tombstones_bound_admission_without_evicting_protected_ids(self):
        self.handler = self.Handler(self.manifest, "worker-1", self.executor,
                                    clock=self.clock, boot_id="test-boot", max_tombstones=2)
        self.handlers.append(self.handler)
        original = await self.open("A")
        await self.open("B")
        await self.call("CloseSession", "A")
        blocked = await self.call("OpenSession", "C", max_positions=32,
                                  lifetime_ms=300000, idle_lease_ms=120000)
        self.assertEqual(blocked.code, "CAPACITY_EXHAUSTED")
        duplicate = await self.call("OpenSession", "A", lease_token="", max_positions=32,
                                    lifetime_ms=300000, idle_lease_ms=120000)
        self.assertEqual(duplicate.code, "CLOSED_SESSION")
        self.clock.advance(30.001)
        await self.handler.reap()
        replacement = await self.open("A")
        self.assertNotEqual(replacement.lease_token, original.lease_token)
        stale = await self.step("A", lease_token=original.lease_token)
        self.assertEqual(stale.code, "INVALID_INPUT")
        self.assertEqual((await self.step("A")).code, "OK")

    async def test_default_tombstone_capacity_supports_100_request_cohort(self):
        # Benchmark cohorts close each request while their IDs remain protected
        # for the full RPC replay window. That retention must not cap a cohort
        # at the historical 64-record default.
        self.assertEqual(self.handler.max_tombstones, 4096)
        for index in range(100):
            session_id = f"cohort-{index}"
            opened = await self.open(session_id)
            self.assertEqual(opened.code, "OK", session_id)
            closed = await self.call("CloseSession", session_id)
            self.assertEqual(closed.code, "OK", session_id)
        status = await self.call("Describe")
        self.assertEqual(status.active_sessions, 0)
        self.assertEqual(status.tombstones, 100)
        # Recent IDs stay protected for duplicate/delayed calls throughout the
        # retention period, even after the cohort has completed.
        duplicate = await self.call("OpenSession", "cohort-0", lease_token="",
                                    max_positions=32, lifetime_ms=300000,
                                    idle_lease_ms=120000)
        self.assertEqual(duplicate.code, "CLOSED_SESSION")
        self.assertEqual((await self.open("cohort-after-100")).code, "OK")
        self.assertEqual((await self.call("CloseSession", "cohort-after-100")).code, "OK")
        await self.assert_no_live_cache()

    async def test_busy_worker_and_duplicate_inflight_operation_fail_without_queueing(self):
        await self.open("A")
        await self.open("B")
        self.executor.block = True
        pending = self.start_step("A")
        await self.await_started()
        duplicate = await self.step("A")
        self.assertEqual(duplicate.code, "OUT_OF_ORDER")
        busy = await self.step("B")
        self.assertEqual(busy.code, "CAPACITY_EXHAUSTED")
        status = await self.call("SessionStatus", "A")
        self.assertEqual(status.active_operations, 1)
        self.assertFalse(status.cache_bytes_exact)
        self.assertEqual(status.end_position, 0)
        self.executor.release.set()
        self.assertEqual((await pending).code, "OK")
        self.assertEqual((await self.step("B")).code, "OK")

    async def test_cancel_during_compute_preserves_cache_until_completion_and_suppresses_output(self):
        await self.open()
        self.executor.block = True
        pending = self.start_step(count=3)
        await self.await_started()
        cancelled = await self.call("CancelSession", "session-A")
        self.assertEqual(cancelled.code, "OK")
        self.assertFalse(cancelled.reclaimed)
        self.assertEqual(self.executor.caches[0].position, 3)
        self.assertEqual(self.executor.caches[0].clears, 0)
        self.assertEqual((await self.step()).code, "CANCELLED")
        self.executor.release.set()
        result = await pending
        self.assertEqual(result.code, "CANCELLED")
        self.assertFalse(result.HasField("tensor"))
        self.assertEqual(self.executor.caches[0].position, 0)
        self.assertTrue((await self.call("CancelSession", "session-A")).reclaimed)
        await self.assert_no_live_cache()

    async def test_expiry_during_compute_defers_reclamation_and_discards_late_result(self):
        await self.open(idle_lease_ms=1000)
        self.executor.block = True
        pending = self.start_step(count=2)
        await self.await_started()
        self.clock.advance(1)
        await self.handler.reap()
        self.assertEqual(self.executor.caches[0].position, 2)
        self.assertEqual(self.executor.caches[0].clears, 0)
        self.assertEqual((await self.call("RenewSession", "session-A")).code, "EXPIRED_SESSION")
        self.executor.release.set()
        result = await pending
        self.assertEqual(result.code, "EXPIRED_SESSION")
        self.assertFalse(result.HasField("tensor"))
        await self.assert_no_live_cache()

    async def test_rpc_timeout_invalidates_cache_but_retains_busy_reservation(self):
        await self.open()
        self.executor.block = True
        pending = self.start_step(count=2, timeout_ms=100)
        await self.await_started()
        result = await asyncio.wait_for(pending, 1)
        self.assertEqual(result.code, "TIMEOUT")
        self.assertFalse(result.HasField("tensor"))
        status = await self.call("Describe")
        self.assertEqual(status.active_operations, 1)
        self.assertEqual(status.reserved_positions, 32)
        self.assertFalse(status.cache_bytes_exact)
        self.assertEqual(self.executor.caches[0].clears, 0)
        self.assertEqual((await self.step()).code, "TIMEOUT")
        self.executor.release.set()
        # shutdown joins the released compute future before final accounting.
        await self.handler.shutdown()
        self.assertEqual(self.executor.caches[0].position, 0)
        self.assertEqual(self.executor.caches[0].clears, 1)

    async def test_cancelled_handler_task_invalidates_session_without_freeing_running_cache(self):
        await self.open()
        self.executor.block = True
        pending = self.start_step(count=2)
        await self.await_started()
        pending.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await pending
        self.assertEqual(self.executor.caches[0].clears, 0)
        self.assertEqual((await self.step()).code, "CANCELLED")
        self.executor.release.set()
        await self.handler.shutdown()
        self.assertEqual(self.executor.caches[0].position, 0)
        self.assertEqual(self.executor.caches[0].clears, 1)

    async def test_failure_after_mutation_invalidates_only_the_affected_session(self):
        await self.open("A")
        await self.open("B")
        self.assertEqual((await self.step("B", count=3)).code, "OK")
        self.executor.fail = True
        result = await self.step("A", count=2)
        self.assertEqual(result.code, "EXECUTION_FAILED")
        self.assertEqual(self.executor.caches[0].position, 0)
        self.assertEqual((await self.step("A")).code, "EXECUTION_FAILED")
        self.executor.fail = False
        survivor = await self.step("B", position=3, sequence=1)
        self.assertEqual(survivor.code, "OK")
        self.assertEqual(survivor.end_position, 4)
        await self.call("CloseSession", "B")
        await self.assert_no_live_cache()

    async def test_new_boot_invalidates_old_leases_before_execution(self):
        await self.open()
        executor = FakeExecutor(self.torch)
        restarted = self.Handler(self.manifest, "worker-1", executor,
                                 clock=self.clock, boot_id="new-boot")
        self.handlers.append(restarted)
        self.executors.append(executor)
        result = await restarted.handle("Step", self.step_request())
        self.assertEqual(result.code, "STALE_WORKER")
        self.assertEqual(executor.calls, [])

    async def test_close_during_compute_acknowledges_reclamation_only_after_completion(self):
        await self.open()
        self.executor.block = True
        pending = self.start_step(count=3)
        await self.await_started()
        closing = await self.call("CloseSession", "session-A")
        self.assertEqual(closing.code, "OK")
        self.assertFalse(closing.reclaimed)
        self.assertEqual(closing.reserved_positions, 32)
        self.assertEqual(self.executor.caches[0].clears, 0)
        self.executor.release.set()
        result = await pending
        self.assertEqual(result.code, "CLOSED_SESSION")
        self.assertFalse(result.HasField("tensor"))
        closed = await self.call("CloseSession", "session-A")
        self.assertTrue(closed.reclaimed)
        await self.assert_no_live_cache()

    async def test_unresponsive_compute_marks_restart_required_without_unsafe_free(self):
        await self.open()
        self.executor.block = True
        pending = self.start_step(count=3)
        await self.await_started()
        await self.call("CancelSession", "session-A")
        self.clock.advance(15)
        await self.handler.reap()
        status = await self.call("Describe")
        self.assertTrue(status.requires_restart)
        self.assertFalse(status.ready)
        self.assertEqual(status.reserved_positions, 32)
        self.assertEqual(self.executor.caches[0].clears, 0)
        refused = await self.call("OpenSession", "new", max_positions=32,
                                  lifetime_ms=300000, idle_lease_ms=120000)
        self.assertEqual(refused.code, "CAPACITY_EXHAUSTED")
        self.executor.release.set()
        self.assertEqual((await pending).code, "CANCELLED")
        await self.assert_no_live_cache()
        self.assertTrue((await self.call("Describe")).requires_restart)

    async def test_shutdown_grace_is_bounded_and_does_not_kill_or_free_running_compute(self):
        await self.open()
        self.executor.block = True
        pending = self.start_step(count=3)
        await self.await_started()
        self.assertFalse(await self.handler.shutdown(grace_seconds=0.01))
        self.assertTrue((await self.call("Describe")).requires_restart)
        self.assertEqual(self.executor.caches[0].clears, 0)
        self.executor.release.set()
        self.assertEqual((await pending).code, "CANCELLED")
        await self.assert_no_live_cache()

    async def test_metadata_invalid_unicode_lease_and_nonfinite_input_never_reach_compute(self):
        await self.open()
        for changes in ({"lease_token": "\u2603"}, {"max_positions": 1},
                        {"session_id": "x" * 65}):
            request = self.step_request()
            for key, value in changes.items():
                setattr(request, key, value)
            self.assertEqual((await self.handler.handle("Step", request)).code, "INVALID_INPUT")
        import struct
        request = self.step_request()
        request.tensor.data = struct.pack("<f", float("nan")) + request.tensor.data[4:]
        self.assertEqual((await self.handler.handle("Step", request)).code, "INVALID_INPUT")
        self.assertEqual(self.executor.calls, [])
        self.assertEqual(self.executor.caches[0].position, 0)

    async def test_periodic_reaper_reclaims_abandoned_session_without_another_request(self):
        from replicant_mesh.manifest import fingerprint

        manifest = self.sample_manifest()
        manifest["limits"]["lease_check_interval_seconds"] = 1
        manifest["fingerprint"] = fingerprint(manifest)
        self.manifest = manifest
        self.handler = self.Handler(manifest, "worker-1", self.executor,
                                    clock=self.clock, boot_id="test-boot")
        self.handlers.append(self.handler)
        await self.open(idle_lease_ms=1000)
        reclaimed = asyncio.Event()
        cache = self.executor.caches[0]
        clear = cache.clear

        def notify_reclaimed():
            clear()
            reclaimed.set()

        cache.clear = notify_reclaimed
        self.clock.advance(1)
        await asyncio.wait_for(reclaimed.wait(), 2)
        self.assertEqual(cache.clears, 1)
        self.assertEqual(len(self.handler.sessions), 0)

    async def test_grpc_caller_cancellation_reaches_worker_without_freeing_compute_cache(self):
        from replicant_mesh.protocol.transport import create_server, GrpcClient

        await self.open()
        self.executor.block = True
        interrupted = asyncio.Event()
        handler = self.handler

        class ObserveCancellation:
            async def handle(self, method, request):
                try:
                    return await handler.handle(method, request)
                except asyncio.CancelledError:
                    interrupted.set()
                    raise

        server, port = await create_server(ObserveCancellation())
        try:
            async with GrpcClient(f"127.0.0.1:{port}") as client:
                pending = asyncio.create_task(client.execute("Step", self.step_request(count=3)))
                self.pending.append(pending)
                await self.await_started()
                pending.cancel()
                with self.assertRaises(asyncio.CancelledError):
                    await pending
                await asyncio.wait_for(interrupted.wait(), 1)
                self.assertEqual(self.executor.caches[0].clears, 0)
                self.assertEqual((await self.step()).code, "CANCELLED")
                self.executor.release.set()
                await self.handler.shutdown()
                await self.assert_no_live_cache()
        finally:
            self.executor.release.set()
            await server.stop(0)

    async def test_result_encoding_cannot_commit_after_the_operation_deadline(self):
        from unittest.mock import patch
        from replicant_mesh import worker_state

        await self.open()
        original = worker_state.encode_tensor

        def slow_encode(*args, **kwargs):
            result = original(*args, **kwargs)
            self.clock.advance(2)
            return result

        with patch.object(worker_state, "encode_tensor", side_effect=slow_encode):
            result = await self.step(timeout_ms=1000)
        self.assertEqual(result.code, "TIMEOUT")
        self.assertEqual(result.end_position, 0)
        self.assertFalse(result.HasField("tensor"))
        await self.assert_no_live_cache()


if __name__ == "__main__":
    unittest.main()
