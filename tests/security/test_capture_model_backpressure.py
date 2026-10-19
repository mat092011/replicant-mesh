"""Offline model capture backpressure ownership checks.

These tests exercise the secure coordinator adapter with the real pinned CPU
model and supervised workers. The reused fixture has fake authorization and
InMemoryTransport clients; it provides component evidence only, with no TLS,
authentication, or real-network claim.
"""

from __future__ import annotations

import asyncio
import gc
import importlib
import json
import os
from pathlib import Path
import sys
import threading
import time
import types
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]
SRC = ROOT / "src"
SECURITY_TESTS = Path(__file__).resolve().parent
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))
if str(SECURITY_TESTS) not in sys.path:
    sys.path.insert(0, str(SECURITY_TESTS))

ENABLED = os.environ.get("STEAMBOAT_CAPTURE_BACKPRESSURE_TESTS") == "1"
PINNED_MODEL = "Maykeye/TinyLLama-v0"
PINNED_REVISION = "298338802ab94432b917bcce11382aa151aee50f"
VOCABULARY_SIZE = 32_000
QUEUE_SLOTS = 16
CAPTURE_CAPACITY_BYTES = 1 << 30
EXPECTED_CAPTURE_BYTES = 92_032_256
MAX_EVENT_BYTES = VOCABULARY_SIZE * 32 + 4096


async def _wait_until(predicate, *, timeout_seconds: float, description: str) -> None:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        if predicate():
            return
        await asyncio.sleep(0.02)
    raise AssertionError(f"timed out waiting for {description}")


class _ProcessRssSampler:
    """Bounded process-local RSS observations; never an admission controller."""

    def __init__(self) -> None:
        if not sys.platform.startswith("linux"):
            raise RuntimeError("capture RSS observations require Linux ru_maxrss units")
        import psutil
        import resource

        self._process = psutil.Process(os.getpid())
        self._resource = resource
        self._stop = asyncio.Event()
        self._task: asyncio.Task | None = None
        self._sample_count = 0
        self._peak_sampled_rss = 0
        self._peak_ru_maxrss = 0
        self.checkpoints: dict[str, dict[str, int]] = {}

    def _sample(self) -> dict[str, int]:
        rss = int(self._process.memory_info().rss)
        # Linux reports ru_maxrss in KiB; this value is the process high-water
        # mark, not a per-test allocation measurement.
        peak = int(self._resource.getrusage(self._resource.RUSAGE_SELF).ru_maxrss) * 1024
        self._sample_count += 1
        self._peak_sampled_rss = max(self._peak_sampled_rss, rss)
        self._peak_ru_maxrss = max(self._peak_ru_maxrss, peak)
        return {"rss_bytes": rss, "process_ru_maxrss_bytes": peak}

    async def _sample_loop(self) -> None:
        while not self._stop.is_set():
            self._sample()
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=0.05)
            except TimeoutError:
                pass

    async def start(self) -> None:
        if self._task is not None:
            raise RuntimeError("RSS sampler already started")
        self.checkpoints["baseline"] = self._sample()
        self._task = asyncio.create_task(self._sample_loop())

    def mark(self, name: str) -> dict[str, int]:
        sample = self._sample()
        self.checkpoints[name] = sample
        return sample

    async def stop(self) -> None:
        if self._task is None:
            return
        self._stop.set()
        done, pending = await asyncio.wait((self._task,), timeout=2)
        if pending:
            raise AssertionError("RSS sampler did not stop within its bound")
        await asyncio.gather(*done, return_exceptions=False)
        self._task = None

    def summary(self) -> dict[str, object]:
        return {
            "checkpoints": self.checkpoints,
            "peak_sampled_rss_bytes": self._peak_sampled_rss,
            "process_ru_maxrss_high_water_bytes": self._peak_ru_maxrss,
            "sample_count": self._sample_count,
        }


class _StalledWriteContext:
    """A component-only writer that holds one real serialized token event."""

    def __init__(self) -> None:
        self.write_started = asyncio.Event()
        self.release_write = asyncio.Event()
        self.write_cancelled = asyncio.Event()
        self.write_finished = asyncio.Event()
        self.first_write_bytes: int | None = None
        self.write_count = 0
        self.aborted: list[tuple[object, str]] = []

    def time_remaining(self) -> float:
        return 120.0

    async def send_initial_metadata(self, _metadata) -> None:
        return None

    async def write(self, payload) -> None:
        self.write_count += 1
        if self.first_write_bytes is None:
            self.first_write_bytes = len(payload)
        self.write_started.set()
        try:
            await self.release_write.wait()
        except asyncio.CancelledError:
            self.write_cancelled.set()
            raise
        finally:
            payload = None
            self.write_finished.set()

    async def abort(self, code, details: str) -> None:
        self.aborted.append((code, details))


async def _rpc_outcome(task: asyncio.Task, *, timeout_seconds: float) -> tuple[str, tuple[asyncio.Task, ...]]:
    from steamboat_runtime.protocol.secure_transport import SecureTaskPending

    done, pending = await asyncio.wait((task,), timeout=timeout_seconds)
    if pending:
        raise AssertionError("Generate caller did not exit within the cleanup bound")
    try:
        task.result()
    except asyncio.CancelledError:
        return "cancelled", ()
    except SecureTaskPending as error:
        return "secure_task_pending", tuple(error.tasks)
    return "returned", ()


async def _join_owned_tasks(tasks, *, fixture, timeout_seconds: float) -> None:
    """Boundedly join test-owned production tasks and their reported children."""
    from steamboat_runtime.protocol.secure_transport import (
        SecureTaskPending,
        _pending_task_descendants,
    )

    owned = {task for task in tasks if task is not None}
    deadline = time.monotonic() + timeout_seconds
    while True:
        owned.update(fixture.service.cleanups)
        owned.update(fixture.adapter.pending_tasks)
        owned.update(fixture.adapter.runtime_owner.pending_tasks)
        owned.update(_pending_task_descendants(tuple(owned)))
        live = {task for task in owned if not task.done()}
        if not live:
            break
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise AssertionError("owned model, request, or cleanup task did not retire")
        done, pending = await asyncio.wait(live, timeout=remaining)
        if pending:
            raise AssertionError("owned model, request, or cleanup task exceeded its bound")
        await asyncio.gather(*done, return_exceptions=True)

    for task in owned:
        if task.cancelled():
            continue
        error = task.exception()
        if error is not None and not isinstance(error, SecureTaskPending):
            raise error


class PendingOwnedTaskJoinTests(unittest.IsolatedAsyncioTestCase):
    async def test_join_collects_completed_pending_wrapper_children_first(self) -> None:
        from steamboat_runtime.protocol.secure_transport import SecureTaskPending

        child_started = asyncio.Event()
        release_child = asyncio.Event()

        async def held_child() -> None:
            child_started.set()
            await release_child.wait()

        child = asyncio.create_task(held_child())
        joiner = None
        try:
            await asyncio.wait_for(child_started.wait(), 1)

            async def pending_wrapper() -> None:
                raise SecureTaskPending((child,))

            wrapper = asyncio.create_task(pending_wrapper())
            observed = await asyncio.gather(wrapper, return_exceptions=True)
            self.assertIsInstance(observed[0], SecureTaskPending)
            fixture = types.SimpleNamespace(
                service=types.SimpleNamespace(cleanups={wrapper}),
                adapter=types.SimpleNamespace(
                    pending_tasks=set(),
                    runtime_owner=types.SimpleNamespace(pending_tasks=set()),
                ),
            )
            joiner = asyncio.create_task(_join_owned_tasks(
                (), fixture=fixture, timeout_seconds=2))
            await asyncio.sleep(0.05)
            self.assertFalse(
                joiner.done(),
                "join returned before following a child of the registered wrapper",
            )
            release_child.set()
            await asyncio.wait_for(joiner, 1)
            self.assertTrue(child.done())
        finally:
            release_child.set()
            try:
                if joiner is not None and not joiner.done():
                    await asyncio.wait_for(joiner, 1)
            finally:
                if not child.done():
                    await asyncio.wait_for(child, 1)


def _state_snapshot(fixture, handle=None) -> dict[str, object]:
    status = fixture.budget.status()
    model_status = fixture.coordinator.model.supervision_status()
    model_diagnostics = fixture.coordinator.model.diagnostics()
    queue = handle._state.output if handle is not None else None
    return {
        "ledger": {
            "active_captures": status.active_captures,
            "cleanup_pending_captures": status.cleanup_pending_captures,
            "reserved_bytes": status.reserved_bytes,
            "per_capture_bytes": status.per_capture.total_bytes,
            "capacity_bytes": status.capacity_bytes,
        },
        "queue": None if queue is None else {
            "items": queue.qsize(),
            "maximum": queue.maxsize,
            "raw_float32_logit_bytes": queue.qsize() * VOCABULARY_SIZE * 4,
            "blocked_putters": len(queue._putters),
        },
        "producer": None if handle is None else {
            "alive": not handle._state.task.done(),
            "task_done": handle._state.task.done(),
        },
        "model": {
            "active_compute": model_status.get("active_compute"),
            "pending_cpu_operations": model_diagnostics.get("pending_cpu_operations"),
            "requires_restart": model_status.get("requires_restart"),
        },
        "streams": {
            "secure_generate": fixture.adapter.active_generate_streams,
            "coordinator_service": fixture.service.active_streams,
        },
        "coordinator": {
            "active_requests": fixture.coordinator.stats()["active_requests"],
            "ready": fixture.coordinator.stats()["ready"],
        },
        "availability": {
            "secure_service_unavailable": fixture.adapter.unavailable,
            "runtime_owner_unavailable": fixture.adapter.runtime_owner.unavailable,
            "live_adapter_owned_tasks": sum(
                not task.done() for task in fixture.adapter.pending_tasks),
            "live_runtime_owned_tasks": sum(
                not task.done() for task in fixture.adapter.runtime_owner.pending_tasks),
        },
        "worker_sessions": sum(len(handler.sessions) for handler in fixture.handlers),
        "worker_cache_committed_bytes": sum(
            entry.committed_bytes
            for handler in fixture.handlers
            for entry in (*handler.sessions.values(), *handler.tombstones.values())
        ),
        "context_releases": len(fixture.factory.released),
        "authorization_closed": fixture.authorization.closed.is_set(),
    }


@unittest.skipUnless(
    ENABLED,
    "Set STEAMBOAT_CAPTURE_BACKPRESSURE_TESTS=1 for the offline model capture gate",
)
class CaptureModelBackpressureTests(unittest.IsolatedAsyncioTestCase):
    """Component-level capture ownership tests with real local CPU inference."""

    @classmethod
    def setUpClass(cls) -> None:
        artifact_dir = os.environ.get("STEAMBOAT_ARTIFACT_DIR")
        reference_dir = os.environ.get("STEAMBOAT_REFERENCE_DIR")
        if not artifact_dir or not Path(artifact_dir).is_dir():
            raise RuntimeError("capture backpressure tests require STEAMBOAT_ARTIFACT_DIR")
        if not reference_dir or not Path(reference_dir).is_dir():
            raise RuntimeError("capture backpressure tests require STEAMBOAT_REFERENCE_DIR")
        if not sys.platform.startswith("linux"):
            raise RuntimeError("capture backpressure integration must run in Linux")

        import torch

        cls.torch = torch
        torch.set_num_threads(2)
        try:
            torch.set_num_interop_threads(2)
        except RuntimeError:
            # Full-suite runners may initialize Torch before this module.
            if torch.get_num_interop_threads() > 2:
                raise RuntimeError(
                    "capture backpressure integration requires at most two Torch threads")
        if torch.get_num_threads() > 2 or torch.get_num_interop_threads() > 2:
            raise RuntimeError(
                "capture backpressure integration requires at most two Torch threads")

        module_name = (f"{__package__}.test_secure_capture"
                       if __package__ else "test_secure_capture")
        cls.fixture_module = importlib.import_module(module_name)
        cls.fixture_type = cls.fixture_module.SecureCaptureModelIntegrationTests
        if not hasattr(cls.fixture_type, "executors"):
            # The reused helper reads OMP_NUM_THREADS while setting up its
            # real StageExecutors. Keep that setup inside the same CPU cap.
            with patch.dict(os.environ, {"OMP_NUM_THREADS": "2"}):
                cls.fixture_type.setUpClass()
        if torch.get_num_threads() > 2 or torch.get_num_interop_threads() > 2:
            raise RuntimeError(
                "capture fixture exceeded the two-thread CPU cap")
        if (cls.fixture_type.manifest.get("model_id") != PINNED_MODEL
                or cls.fixture_type.manifest.get("revision") != PINNED_REVISION):
            raise RuntimeError("capture backpressure artifacts differ from the pinned model")

    async def asyncSetUp(self) -> None:
        from steamboat_runtime.capture_budget import CaptureBudget, CaptureBudgetConfig

        self.fixture = None
        self.sampler: _ProcessRssSampler | None = None
        self.report: dict[str, object] | None = None
        self._original_queue_put = None
        self._original_reclaim = None
        self._reclaim_results: list[bool] = []
        self.fixture = self.fixture_type(
            "test_secure_generate_reclaims_real_capture_after_serialized_last_position")
        await self.fixture.asyncSetUp()
        self.budget = CaptureBudget(CaptureBudgetConfig(
            vocabulary_size=VOCABULARY_SIZE,
            output_queue_slots=QUEUE_SLOTS,
            max_active_captures=8,
            capacity_bytes=CAPTURE_CAPACITY_BYTES,
        ))
        self.fixture.budget = self.budget
        self.fixture.adapter.capture_budget = self.budget
        if self.fixture.coordinator.limits.output_queue_tokens != QUEUE_SLOTS:
            raise AssertionError("capture fixture does not use the required 16-item output queue")
        if self.fixture.manifest["config"]["vocab_size"] != VOCABULARY_SIZE:
            raise AssertionError("capture fixture vocabulary differs from the pinned 32,000")
        self.assertEqual(self.budget.status().per_capture.total_bytes,
                         EXPECTED_CAPTURE_BYTES)

    async def asyncTearDown(self) -> None:
        fixture = getattr(self, "fixture", None)
        cleanup_errors: list[str] = []
        try:
            if fixture is not None:
                roots = [*tuple(getattr(getattr(fixture, "service", None), "cleanups", ())),
                         *tuple(getattr(getattr(fixture, "adapter", None), "pending_tasks", ())),
                         *tuple(getattr(getattr(getattr(fixture, "adapter", None),
                                                "runtime_owner", None),
                                             "pending_tasks", ()))]
                roots.extend(handle._state.task for handle in
                             getattr(fixture, "handles", ()))
                if roots:
                    try:
                        await _join_owned_tasks(roots, fixture=fixture,
                                                timeout_seconds=20)
                    except BaseException as error:
                        cleanup_errors.append(f"owned task cleanup: {type(error).__name__}")
                coordinator = getattr(fixture, "coordinator", None)
                if coordinator is not None:
                    try:
                        closed = await asyncio.wait_for(coordinator.close(), 30)
                        if closed is not True:
                            cleanup_errors.append("coordinator close returned false")
                    except BaseException as error:
                        cleanup_errors.append(f"coordinator close: {type(error).__name__}")
                for handler in getattr(fixture, "handlers", ()):
                    try:
                        if not handler.stopping:
                            stopped = await asyncio.wait_for(handler.shutdown(), 10)
                            if stopped is not True:
                                cleanup_errors.append("worker shutdown returned false")
                    except BaseException as error:
                        cleanup_errors.append(f"worker shutdown: {type(error).__name__}")
                budget = getattr(self, "budget", None)
                if budget is not None and budget.status().reserved_bytes != 0:
                    cleanup_errors.append("capture bytes remain reserved after fixture shutdown")
                adapter = getattr(fixture, "adapter", None)
                service = getattr(fixture, "service", None)
                if adapter is not None and adapter.active_generate_streams != 0:
                    cleanup_errors.append("secure Generate stream remains owned after fixture shutdown")
                if service is not None and service.active_streams != 0:
                    cleanup_errors.append("coordinator service stream remains owned after fixture shutdown")
        finally:
            gc.collect()
            if self.sampler is not None:
                self.sampler.mark("after_fixture_shutdown")
                await self.sampler.stop()
            if self.report is not None and self.sampler is not None:
                self.report["memory"] = self.sampler.summary()
                if fixture is not None:
                    self.report["final_state"] = _state_snapshot(
                        fixture, fixture.handles[-1] if fixture.handles else None)
                print("capture-backpressure " + json.dumps(
                    self.report, sort_keys=True, separators=(",", ":")))
        if cleanup_errors:
            self.fail("; ".join(cleanup_errors))

    def _start_case_report(self, name: str) -> None:
        self.sampler = _ProcessRssSampler()
        self.report = {
            "case": name,
            "configuration": {
                "model": PINNED_MODEL,
                "revision": PINNED_REVISION,
                "device": "cpu",
                "torch_threads_max": 2,
                "vocabulary_size": VOCABULARY_SIZE,
                "output_queue_slots": QUEUE_SLOTS,
                "active_capture_limit": 8,
                "logical_capture_capacity_bytes": CAPTURE_CAPACITY_BYTES,
                "input_token_formula": "3+((i*37+11)%(32000-3))",
                "authorization": "fake component fixture",
                "worker_transport": "InMemoryTransport component fixture",
                "tls_or_network_evidence": False,
                "configured_expected_container_memory_limit_bytes": 6 * (1 << 30),
                "actual_container_memory_limit_verified_by_test": False,
            },
            "logits": {
                "event_limit_bytes": MAX_EVENT_BYTES,
                "observed_first_wire_event_bytes": None,
                "per_capture_logical_reservation_bytes": EXPECTED_CAPTURE_BYTES,
            },
        }

    async def _start_sampler(self) -> None:
        assert self.sampler is not None
        await self.sampler.start()

    def _install_handle_observer(self, *, queue_full: asyncio.Event | None = None,
                                 reclaim_started: asyncio.Event | None = None,
                                 reclaim_gate: asyncio.Event | None = None) -> None:
        fixture = self.fixture
        original_submit = fixture.coordinator.submit

        def submit(*args, **kwargs):
            handle = original_submit(*args, **kwargs)
            if queue_full is not None:
                queue = handle._state.output
                original_put = queue.put
                self._original_queue_put = original_put

                async def observe_put(item):
                    if queue.full():
                        queue_full.set()
                    await original_put(item)

                queue.put = observe_put
            if reclaim_started is not None:
                original_reclaim = handle.reclaim_capture_buffers
                self._original_reclaim = original_reclaim

                async def observe_reclaim():
                    reclaim_started.set()
                    if reclaim_gate is not None:
                        await reclaim_gate.wait()
                    result = await original_reclaim()
                    self._reclaim_results.append(result)
                    return result

                handle.reclaim_capture_buffers = observe_reclaim
            return handle

        fixture.coordinator.submit = submit

    def _capture_payload(self, *, new_tokens: int) -> bytes:
        from steamboat_runtime.remote_client import encode_json

        prompt = [3 + ((index * 37 + 11) % (VOCABULARY_SIZE - 3))
                  for index in range(1)]
        return encode_json({
            "input_ids": prompt,
            "new_tokens": new_tokens,
            "timeout_seconds": 30,
            "capture_logits": True,
        })

    async def _assert_released(self, handle) -> None:
        fixture = self.fixture
        await _wait_until(
            lambda: (fixture.authorization.closed.is_set()
                     and fixture.factory.released
                     and fixture.adapter.active_generate_streams == 0
                     and fixture.service.active_streams == 0
                     and not fixture.service.cleanups
                     and self.budget.status().reserved_bytes == 0
                     and self.budget.status().active_captures == 0
                     and self.budget.status().cleanup_pending_captures == 0
                     and fixture.coordinator.stats()["active_requests"] == 0
                     and not fixture.coordinator.model.supervision_status()["active_compute"]
                     and all(not handler.sessions for handler in fixture.handlers)),
            timeout_seconds=20,
            description="capture reclamation and deferred owner release",
        )
        state = handle._state
        self.assertTrue(state.task.done())
        self.assertTrue(state.output.empty())
        self.assertIsNone(state.input_ids)
        self.assertIsNone(state.forced_tokens)
        self.assertTrue(state.completion.done())
        self.assertTrue(state.completion.result().cleanup_complete)
        self.assertEqual(self.budget.status().reserved_bytes, 0)
        self.assertEqual(self.budget.status().active_captures, 0)
        self.assertEqual(self.budget.status().cleanup_pending_captures, 0)
        self.assertEqual(fixture.factory.released,
                         [state.trusted_request_context])
        self.assertFalse(fixture.coordinator.model.supervision_status()["active_compute"])
        self.assertEqual(fixture.coordinator.model.diagnostics()["pending_cpu_operations"], 0)
        self.assertTrue(all(
            entry.committed_bytes == 0 and entry.cache.allocated_bytes() == 0
            and not any(entry.cache.lengths())
            for handler in fixture.handlers for entry in handler.tombstones.values()))

    async def test_generate_full_queue_stalled_write_retains_until_reclamation(self) -> None:
        from steamboat_runtime.protocol.secure_transport import (
            MAX_CANCELLATION_GRACE_SECONDS,
            SecureTaskPending,
            _pending_task_descendants,
        )

        self._start_case_report("full_queue_stalled_write")
        await self._start_sampler()
        fixture = self.fixture
        context = _StalledWriteContext()
        full_put = asyncio.Event()
        reclaim_started = asyncio.Event()
        release_reclaim = asyncio.Event()
        rpc_task: asyncio.Task | None = None
        handle = None
        outcome = "not_started"
        pending_roots: tuple[asyncio.Task, ...] = ()
        cancel_requested = False
        self._install_handle_observer(
            queue_full=full_put,
            reclaim_started=reclaim_started,
            reclaim_gate=release_reclaim,
        )
        try:
            rpc_task = asyncio.create_task(fixture.adapter.generate_rpc(
                self._capture_payload(new_tokens=19), context))
            await asyncio.wait_for(context.write_started.wait(), 12)
            await _wait_until(lambda: bool(fixture.handles), timeout_seconds=5,
                              description="real coordinator request handle")
            handle = fixture.handles[-1]
            queue = handle._state.output
            stall_bound = fixture.coordinator.limits.output_stall_timeout_seconds
            if stall_bound <= 1:
                raise AssertionError("output stall timeout is too short for this bounded CPU check")
            await _wait_until(
                lambda: (full_put.is_set() and queue.full()
                         and len(queue._putters) >= 1),
                timeout_seconds=min(18, stall_bound - 0.5),
                description="16 real captured logits queued with the producer blocked",
            )
            self.assertEqual(queue.qsize(), QUEUE_SLOTS)
            self.assertEqual(queue.maxsize, QUEUE_SLOTS)
            queued_events = tuple(queue._queue)
            self.assertEqual(len(queued_events), QUEUE_SLOTS)
            self.assertTrue(all(event.logits is not None for event in queued_events))
            self.assertTrue(all(tuple(event.logits.shape) == (1, VOCABULARY_SIZE)
                                and event.logits.dtype is self.torch.float32
                                and bool(self.torch.isfinite(event.logits).all().item())
                                for event in queued_events))
            # The observer must not keep tensor references after this check.
            del queued_events
            self.assertFalse(handle._state.task.done())
            self.assertFalse(fixture.authorization.closed.is_set())
            active = self.budget.status()
            self.assertEqual(active.active_captures, 1)
            self.assertEqual(active.cleanup_pending_captures, 0)
            self.assertEqual(active.reserved_bytes, EXPECTED_CAPTURE_BYTES)
            self.assertFalse(fixture.coordinator.model.supervision_status()["active_compute"])
            self.assertEqual(fixture.coordinator.model.diagnostics()["pending_cpu_operations"], 0)
            self.assertIsNotNone(context.first_write_bytes)
            self.assertLessEqual(context.first_write_bytes, MAX_EVENT_BYTES)
            self.sampler.mark("queue_full_producer_blocked")
            assert self.report is not None
            self.report["logits"]["observed_first_wire_event_bytes"] = context.first_write_bytes
            self.report["queue_full_state"] = _state_snapshot(fixture, handle)

            original_reclaim = handle.reclaim_capture_buffers
            self.assertTrue(callable(original_reclaim))
            cancellation_started_at = time.monotonic()
            rpc_task.cancel()
            cancel_requested = True
            await asyncio.wait_for(reclaim_started.wait(), 12)
            self.assertEqual(handle._state.output.qsize(), 0)
            self.assertTrue(handle._state.task.done())
            self.assertFalse(fixture.coordinator.model.supervision_status()["active_compute"])
            pending = self.budget.status()
            self.assertEqual(pending.active_captures, 0)
            self.assertEqual(pending.cleanup_pending_captures, 1)
            self.assertEqual(pending.reserved_bytes, EXPECTED_CAPTURE_BYTES)
            self.assertFalse(fixture.authorization.closed.is_set())
            self.assertEqual(fixture.factory.released, [])
            self.assertEqual(fixture.adapter.active_generate_streams, 1)
            self.assertEqual(fixture.service.active_streams, 1)
            await asyncio.wait_for(context.write_cancelled.wait(), 5)
            if rpc_task.done():
                try:
                    rpc_task.result()
                except SecureTaskPending as error:
                    outcome = "secure_task_pending"
                    pending_roots = tuple(error.tasks)
                except asyncio.CancelledError:
                    outcome = "cancelled_before_reclamation"
                else:
                    raise AssertionError("Generate exited before gated reclamation completed")
            else:
                outcome = "running_until_reclamation"
            self.sampler.mark("reclamation_held")
            self.report["reclamation_held_state"] = _state_snapshot(fixture, handle)
            self.report["cancellation_outcome_before_reclamation"] = outcome
            self.assertEqual(self._reclaim_results, [])
            elapsed_before_release = time.monotonic() - cancellation_started_at
            self.assertLess(elapsed_before_release, MAX_CANCELLATION_GRACE_SECONDS)
            self.report["cleanup_grace_elapsed_before_reclaim_release_seconds"] = (
                elapsed_before_release)
            self.assertFalse(fixture.adapter.unavailable)
            self.assertFalse(fixture.adapter.runtime_owner.unavailable)
            self.assertTrue(fixture.coordinator.stats()["ready"])
            self.assertFalse(
                fixture.coordinator.model.supervision_status()["requires_restart"])

            release_reclaim.set()
            outcome_after_release, more_pending = await _wait_rpc_task(rpc_task, 20)
            if outcome_after_release == "secure_task_pending":
                pending_roots = tuple(set(pending_roots) | set(more_pending))
            outcome = outcome_after_release
            self.report["cancellation_outcome_after_reclamation"] = outcome
            await _join_owned_tasks(
                (*pending_roots, handle._state.task, *tuple(fixture.service.cleanups),
                 *tuple(fixture.adapter.pending_tasks),
                 *tuple(_pending_task_descendants((rpc_task,)))),
                fixture=fixture, timeout_seconds=20)
            self.assertEqual(outcome, "cancelled")
            self.assertEqual(self._reclaim_results, [True])
            await self._assert_released(handle)
            self.assertFalse(fixture.adapter.unavailable)
            self.assertFalse(fixture.adapter.runtime_owner.unavailable)
            self.assertTrue(fixture.coordinator.stats()["ready"])
            self.assertFalse(
                fixture.coordinator.model.supervision_status()["requires_restart"])
            self.sampler.mark("after_request_cleanup")
            self.report["after_request_cleanup_state"] = _state_snapshot(fixture, handle)
        finally:
            context.release_write.set()
            release_reclaim.set()
            if rpc_task is not None:
                if not rpc_task.done() and not cancel_requested:
                    rpc_task.cancel()
                    cancel_requested = True
                try:
                    await _wait_rpc_task(rpc_task, 20)
                finally:
                    from steamboat_runtime.protocol.secure_transport import _pending_task_descendants
                    roots = [rpc_task, *tuple(fixture.service.cleanups),
                             *tuple(fixture.adapter.pending_tasks),
                             *tuple(fixture.adapter.runtime_owner.pending_tasks),
                             *tuple(_pending_task_descendants((rpc_task,)))]
                    if handle is not None:
                        roots.append(handle._state.task)
                    try:
                        await _join_owned_tasks(roots, fixture=fixture,
                                                timeout_seconds=20)
                    finally:
                        if handle is not None:
                            if self._original_queue_put is not None:
                                handle._state.output.put = self._original_queue_put
                            if self._original_reclaim is not None:
                                handle.reclaim_capture_buffers = self._original_reclaim

    async def test_cancellation_retains_capture_while_real_supervised_cpu_future_runs(self) -> None:
        from steamboat_runtime.protocol.secure_transport import (
            MAX_CANCELLATION_GRACE_SECONDS,
            SecureTaskPending,
            _pending_task_descendants,
        )

        self._start_case_report("pending_supervised_cpu_future")
        await self._start_sampler()
        fixture = self.fixture
        context = self.fixture_module._ModelRpcContext()
        compute_entered = threading.Event()
        release_compute = threading.Event()
        compute_finished = threading.Event()
        compute_succeeded = threading.Event()
        compute_error_types: list[str] = []
        reclaim_started = asyncio.Event()
        original_finish = fixture.coordinator.model._finish

        def blocked_real_finish(hidden, all_logits):
            compute_entered.set()
            try:
                if not release_compute.wait(timeout=25):
                    raise TimeoutError("test did not release the supervised CPU gate")
                result = original_finish(hidden, all_logits)
            except BaseException as error:
                compute_error_types.append(type(error).__name__)
                raise
            else:
                compute_succeeded.set()
                return result
            finally:
                compute_finished.set()

        fixture.coordinator.model._finish = blocked_real_finish
        self._install_handle_observer(reclaim_started=reclaim_started)
        rpc_task: asyncio.Task | None = None
        handle = None
        outcome = "not_started"
        pending_roots: tuple[asyncio.Task, ...] = ()
        cancel_requested = False
        try:
            rpc_task = asyncio.create_task(fixture.adapter.generate_rpc(
                self._capture_payload(new_tokens=1), context))
            await _wait_until(compute_entered.is_set, timeout_seconds=12,
                              description="actual supervised coordinator CPU operation")
            await _wait_until(lambda: bool(fixture.handles), timeout_seconds=5,
                              description="real coordinator request handle")
            handle = fixture.handles[-1]
            self.assertTrue(fixture.coordinator.model.supervision_status()["active_compute"])
            self.assertEqual(fixture.coordinator.model.diagnostics()["pending_cpu_operations"], 1)
            active = self.budget.status()
            self.assertEqual(active.active_captures, 1)
            self.assertEqual(active.reserved_bytes, EXPECTED_CAPTURE_BYTES)
            self.assertFalse(fixture.authorization.closed.is_set())
            self.assertEqual(fixture.factory.released, [])
            self.assertEqual(fixture.adapter.active_generate_streams, 1)
            self.assertEqual(fixture.service.active_streams, 1)
            self.sampler.mark("supervised_cpu_future_blocked")
            assert self.report is not None
            self.report["pending_compute_state"] = _state_snapshot(fixture, handle)

            cancellation_started_at = time.monotonic()
            fence_deadline = (
                cancellation_started_at + MAX_CANCELLATION_GRACE_SECONDS + 1)
            rpc_task.cancel()
            cancel_requested = True
            reclaim_wait_remaining = max(0.0, fence_deadline - time.monotonic())
            await asyncio.wait_for(reclaim_started.wait(), reclaim_wait_remaining)
            pending = self.budget.status()
            self.assertEqual(pending.active_captures, 0)
            self.assertEqual(pending.cleanup_pending_captures, 1)
            self.assertEqual(pending.reserved_bytes, EXPECTED_CAPTURE_BYTES)
            self.assertTrue(fixture.coordinator.model.supervision_status()["active_compute"])
            self.assertEqual(fixture.coordinator.model.diagnostics()["pending_cpu_operations"], 1)
            self.assertFalse(fixture.authorization.closed.is_set())
            self.assertEqual(fixture.factory.released, [])
            self.assertEqual(fixture.adapter.active_generate_streams, 1)
            self.assertEqual(fixture.service.active_streams, 1)
            if rpc_task.done():
                try:
                    rpc_task.result()
                except SecureTaskPending as error:
                    outcome = "secure_task_pending"
                    pending_roots = tuple(error.tasks)
                except asyncio.CancelledError:
                    outcome = "cancelled_before_compute_retirement"
                else:
                    raise AssertionError("Generate exited while supervised CPU work was active")
            else:
                outcome = "running_until_compute_retired"
            self.sampler.mark("compute_reclamation_waiting")
            self.report["compute_reclamation_waiting_state"] = _state_snapshot(fixture, handle)
            self.report["cancellation_outcome_before_compute_retirement"] = outcome
            self.assertEqual(self._reclaim_results, [])
            self.assertFalse(compute_finished.is_set())
            self.assertFalse(compute_succeeded.is_set())
            self.assertEqual(compute_error_types, [])

            await _wait_until(
                lambda: (fixture.adapter.unavailable
                         and fixture.adapter.runtime_owner.unavailable),
                timeout_seconds=max(0.0, fence_deadline - time.monotonic()),
                description="secure service fencing after the cleanup grace",
            )
            grace_elapsed = time.monotonic() - cancellation_started_at
            self.assertGreaterEqual(grace_elapsed, MAX_CANCELLATION_GRACE_SECONDS)
            self.assertLessEqual(
                grace_elapsed, MAX_CANCELLATION_GRACE_SECONDS + 1)
            self.assertTrue(fixture.coordinator.model.supervision_status()["active_compute"])
            self.assertEqual(fixture.coordinator.model.diagnostics()["pending_cpu_operations"], 1)
            self.assertEqual(self.budget.status().reserved_bytes, EXPECTED_CAPTURE_BYTES)
            self.assertFalse(fixture.authorization.closed.is_set())
            self.assertEqual(fixture.factory.released, [])
            self.assertEqual(fixture.adapter.active_generate_streams, 1)
            self.assertEqual(fixture.service.active_streams, 1)
            assert self.report is not None
            self.report["cleanup_grace_elapsed_seconds"] = grace_elapsed
            self.report["after_cleanup_grace_state"] = _state_snapshot(fixture, handle)
            # Caller cancellation and an explicit pending failure are both
            # supported bounded outcomes; neither confirms physical cleanup.
            # The fence can latch just before the caller's final wait ends.
            outcome, more_pending = await _wait_rpc_task(rpc_task, 1)
            pending_roots = tuple(set(pending_roots) | set(more_pending))
            self.assertIn(outcome, ("cancelled", "secure_task_pending"))
            self.report["bounded_outcome_after_cleanup_grace"] = outcome

            release_compute.set()
            await _wait_until(compute_finished.is_set, timeout_seconds=12,
                              description="original coordinator CPU computation completion")
            await _wait_until(
                lambda: not fixture.coordinator.model.supervision_status()["active_compute"],
                timeout_seconds=12, description="supervised CPU future retirement",
            )
            outcome_after_release, more_pending = await _wait_rpc_task(rpc_task, 20)
            if outcome_after_release == "secure_task_pending":
                pending_roots = tuple(set(pending_roots) | set(more_pending))
            outcome = outcome_after_release
            self.report["cancellation_outcome_after_compute_retirement"] = outcome
            await _join_owned_tasks(
                (*pending_roots, handle._state.task, *tuple(fixture.service.cleanups),
                 *tuple(fixture.adapter.pending_tasks)),
                fixture=fixture, timeout_seconds=20)
            self.assertTrue(compute_finished.is_set())
            self.report["original_compute"] = {
                "entered": compute_entered.is_set(),
                "finished": compute_finished.is_set(),
                "succeeded": compute_succeeded.is_set(),
                "error_types": list(compute_error_types),
            }
            self.assertTrue(compute_succeeded.is_set(),
                            f"original CPU computation failed: {compute_error_types}")
            self.assertEqual(compute_error_types, [])
            self.assertIn(outcome, ("cancelled", "secure_task_pending"))
            self.assertEqual(self._reclaim_results, [True])
            await self._assert_released(handle)
            self.assertTrue(fixture.adapter.unavailable)
            self.assertTrue(fixture.adapter.runtime_owner.unavailable)
            self.sampler.mark("after_request_cleanup")
            self.report["after_request_cleanup_state"] = _state_snapshot(fixture, handle)
        finally:
            release_compute.set()
            if rpc_task is not None:
                if not rpc_task.done() and not cancel_requested:
                    rpc_task.cancel()
                    cancel_requested = True
                try:
                    await _wait_rpc_task(rpc_task, 20)
                finally:
                    from steamboat_runtime.protocol.secure_transport import _pending_task_descendants
                    roots = [rpc_task, *tuple(fixture.service.cleanups),
                             *tuple(fixture.adapter.pending_tasks),
                             *tuple(fixture.adapter.runtime_owner.pending_tasks),
                             *tuple(_pending_task_descendants((rpc_task,)))]
                    if handle is not None:
                        roots.append(handle._state.task)
                    try:
                        await _join_owned_tasks(roots, fixture=fixture,
                                                timeout_seconds=20)
                    finally:
                        try:
                            if compute_entered.is_set():
                                await _wait_until(
                                    compute_finished.is_set, timeout_seconds=12,
                                    description="actual CPU gate retirement during test cleanup")
                                await _wait_until(
                                    lambda: not fixture.coordinator.model.supervision_status()["active_compute"],
                                    timeout_seconds=12,
                                    description="supervised CPU future retirement during test cleanup",
                                )
                        finally:
                            fixture.coordinator.model._finish = original_finish
                            if (handle is not None
                                    and self._original_reclaim is not None):
                                handle.reclaim_capture_buffers = self._original_reclaim


async def _wait_rpc_task(task: asyncio.Task, timeout_seconds: float) -> tuple[str, tuple[asyncio.Task, ...]]:
    return await _rpc_outcome(task, timeout_seconds=timeout_seconds)
