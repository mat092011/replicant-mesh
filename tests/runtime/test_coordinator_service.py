"""M5 wire validation, bounded remote streaming and coordinator watchdog wiring."""

import asyncio
import importlib
import json
import os
from pathlib import Path
import subprocess
import sys
import threading
import time
import unittest

from steamboat_runtime.remote_client import (
    MAX_GENERATE_BYTES, MAX_TEXT_BYTES, RemoteError, decode_json, encode_json,
    validate_generate, validate_text,
)


class ServiceProtocolTests(unittest.TestCase):
    def test_trace_sample_is_bounded_while_counters_cover_all_dispatches(self):
        from types import SimpleNamespace
        from steamboat_runtime.coordinator_service import RequestMetrics
        metrics = RequestMetrics()
        for sequence in range(100):
            metrics.record({"event": "stage_dispatch", "worker": 1, "sequence": sequence,
                            "dispatch_ns": 200, "queued_ns": 100, "request_bytes": 256})
        value = metrics.result(SimpleNamespace(finished_at=2, submitted_at=1))
        self.assertEqual(len(value["trace_sample"]), 12)
        self.assertEqual([item["sequence"] for item in value["trace_sample"]],
                         list(range(6)) + list(range(94,100)))
        self.assertEqual(sum(item["dispatches"] for item in value["stages"]), 100)
        self.assertEqual(sum(item["request_bytes"] for item in value["stages"]), 25600)

    def request(self, **changes):
        return {"input_ids": [1, 2], "new_tokens": 3, "forced_tokens": [4, 5],
                "capture_logits": False, "timeout_seconds": 5, **changes}

    def test_strict_json_rejects_duplicates_nonfinite_deep_or_oversized_messages(self):
        for payload in (b'{"x":1,"x":2}', b'{"x":NaN}', b'{"x":Infinity}',
                        b'{"x":1e400}', b'{"x":[-1e400]}',
                        b'[]', b'{"x":' + b'[' * 2000 + b']' * 2000 + b'}', b'\xff'):
            with self.subTest(payload=payload[:30]), self.assertRaises(RemoteError):
                decode_json(payload)
        with self.assertRaises(RemoteError):
            decode_json(b" " * (MAX_GENERATE_BYTES + 1), MAX_GENERATE_BYTES)
        with self.assertRaises(RemoteError):
            encode_json({"x": float("nan")})

    def test_generation_bounds_reject_coercion_and_malformed_feedback(self):
        validate_generate(self.request())
        invalid = [{"input_ids": [True]}, {"input_ids": [-1]}, {"input_ids": [32000]},
                   {"input_ids": []}, {"input_ids": [1] * 1152}, {"new_tokens": True},
                   {"new_tokens": 0}, {"forced_tokens": []}, {"forced_tokens": [4, False]},
                   {"timeout_seconds": float("inf")}, {"timeout_seconds": 301},
                   {"timeout_seconds": 10 ** 400},
                   {"timeout_seconds": True}, {"capture_logits": 1}, {"unknown": 1}]
        for change in invalid:
            with self.subTest(change=change), self.assertRaises(RemoteError):
                validate_generate(self.request(**change))

    def test_text_bound_counts_utf8_and_requires_boolean_special_token_policy(self):
        self.assertEqual(validate_text({"text": "public", "add_special_tokens": False}), "public")
        for value in ({"text": ""}, {"text": "é" * MAX_TEXT_BYTES},
                      {"text": "x", "add_special_tokens": 0}, {"text": "\ud800"}):
            with self.assertRaises(RemoteError):
                validate_text(value)

    def test_remote_client_module_does_not_import_torch_or_transformers(self):
        result = subprocess.run([sys.executable, "-c",
            "import sys; import steamboat_runtime.remote_client; "
            "assert 'torch' not in sys.modules; assert 'transformers' not in sys.modules"],
            capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)


ENABLED = os.environ.get("STEAMBOAT_SERVICE_TESTS") == "1"


@unittest.skipUnless(ENABLED, "Set STEAMBOAT_SERVICE_TESTS=1 for M5 service checks")
class CoordinatorServiceTests(unittest.IsolatedAsyncioTestCase):
    @classmethod
    def setUpClass(cls):
        import torch
        from steamboat_runtime.coordinator import Coordinator, SchedulerLimits
        from steamboat_runtime.coordinator_service import CoordinatorService, create_server
        from steamboat_runtime.remote_client import RemoteClient
        from steamboat_runtime.worker_state import WorkerHandler
        prefix = f"{__package__}." if __package__ else ""
        support = importlib.import_module(prefix + "test_worker_state")
        model = importlib.import_module(prefix + "test_coordinator")
        manifest = importlib.import_module(prefix + "test_manifest")
        cls.torch, cls.Coordinator, cls.Limits = torch, Coordinator, SchedulerLimits
        cls.Service, cls.create_server = CoordinatorService, staticmethod(create_server)
        cls.RemoteClient, cls.Handler = RemoteClient, WorkerHandler
        cls.Model, cls.Client = model.FakeModel, model.FakeClient
        cls.Executor, cls.Clock = support.FakeExecutor, support.FakeClock
        cls.sample_manifest = staticmethod(manifest.sample_manifest)
        torch.set_num_threads(2)

    async def asyncSetUp(self):
        from dataclasses import replace
        self.manifest = self.sample_manifest()
        self.executors = [self.Executor(self.torch) for _ in range(3)]
        self.handlers = [self.Handler(self.manifest, f"worker-{index + 1}", executor,
                        clock=self.Clock(), enable_queue=True, boot_id=str(index + 1) * 32)
                         for index, executor in enumerate(self.executors)]
        self.workers = [self.Client(handler) for handler in self.handlers]
        self.coordinator = self.Coordinator(self.manifest, self.workers, self.Model(self.torch),
            limits=replace(self.Limits(), cleanup_timeout_seconds=1,
                           output_stall_timeout_seconds=0.1))
        await self.coordinator.start()
        self.service = self.Service(self.coordinator)
        self.server, port = await self.create_server(self.service)
        self.client = self.RemoteClient(f"127.0.0.1:{port}")

    async def asyncTearDown(self):
        for worker in self.workers:
            for gate in (worker.step_gate, worker.open_gate, worker.after_open_gate):
                if gate:
                    gate.set()
        for executor in self.executors:
            executor.release.set()
        await self.client.close()
        await self.server.stop(0)
        await asyncio.wait_for(self.service.close(), 5)
        for handler in self.handlers:
            await handler.shutdown()

    async def wait_for(self, predicate, timeout=2):
        deadline = time.monotonic() + timeout
        while not predicate():
            if time.monotonic() >= deadline:
                self.fail("Condition did not become true")
            await asyncio.sleep(0.005)

    async def collect(self, **kwargs):
        return [event async for event in self.client.generate([9, 20], 4, **kwargs)]

    async def clean(self):
        await self.wait_for(lambda: self.service.active_streams == 0)
        self.assertEqual(self.service.metrics, {})
        self.assertTrue(all(not handler.sessions for handler in self.handlers))
        self.assertEqual(self.coordinator.stats()["active_requests"], 0)

    async def test_one_three_eight_remote_streams_preserve_tokens_and_accounting(self):
        for concurrency in (1, 3, 8):
            streams = await asyncio.gather(*(self.collect() for _ in range(concurrency)))
            for events in streams:
                self.assertEqual([event["token_id"] for event in events[:-1]], [24, 28, 32, 36])
                result = events[-1]
                self.assertEqual(result["status"], "completed")
                self.assertTrue(result["cleanup_complete"])
                self.assertEqual(sum(cell["responses"] for cell in result["metrics"]["stages"]), 12)
                self.assertGreater(sum(cell["request_bytes"] for cell in result["metrics"]["stages"]), 0)
                self.assertGreaterEqual(result["metrics"]["admission_ms"], 0)
            await self.clean()
        description = await self.client.describe()
        self.assertTrue(description["ready"])
        self.assertEqual(description["service"]["completed_requests"], 12)
        self.assertEqual(description["service"]["active_streams"], 0)
        self.assertTrue(all(item["active_sessions"] == 0 for item in description["workers"]))

    async def test_forced_feedback_and_logit_stream_have_exact_shapes(self):
        events = await self.collect(forced_tokens=[101, 102, 103], capture_logits=True)
        self.assertEqual([event["token_id"] for event in events[:-1]], [24, 105, 106, 107])
        self.assertTrue(all(len(event["logits"]) == 32000 for event in events[:-1]))
        await self.clean()

    async def test_raw_malformed_rpc_is_rejected_before_scheduler_admission(self):
        import grpc
        from steamboat_runtime.remote_client import SERVICE
        huge_timeout = encode_json({"input_ids": [9], "new_tokens": 1,
                                    "capture_logits": False, "timeout_seconds": 10 ** 400})
        for data in (b'{"input_ids":[1],"input_ids":[2]}', b"x" * (MAX_GENERATE_BYTES + 1),
                     huge_timeout):
            call = self.client.channel.unary_stream(f"/{SERVICE}/Generate")(data, timeout=1)
            with self.assertRaises(grpc.aio.AioRpcError) as raised:
                await call.read()
            self.assertEqual(raised.exception.code(), grpc.StatusCode.INVALID_ARGUMENT)
        self.assertEqual(self.service.counters["rejected_requests"], 3)
        await self.clean()

    async def test_transport_stream_bound_includes_pending_admissions(self):
        self.service.max_streams = 1
        self.workers[0].step_gate = asyncio.Event()
        first = asyncio.create_task(self.collect())
        await self.workers[0].step_started.wait()
        with self.assertRaises(RemoteError) as raised:
            await self.collect()
        self.assertEqual(raised.exception.code, "CAPACITY_EXHAUSTED")
        self.assertEqual(self.service.active_streams, 1)
        self.workers[0].step_gate.set()
        await first
        await self.clean()

    async def test_closing_remote_stream_cancels_it_and_preserves_survivor(self):
        for worker in self.workers:
            worker.delay = 0.003
        interrupted = self.client.generate([9, 20], 64)
        first = await anext(interrupted)
        self.assertEqual(first["index"], 0)
        survivor = asyncio.create_task(self.collect())
        await interrupted.aclose()
        events = await survivor
        self.assertEqual(events[-1]["status"], "completed")
        await self.clean()
        self.assertEqual(self.service.counters["cancelled_requests"], 1)
        self.assertEqual(self.service.counters["completed_requests"], 1)

    async def test_remote_deadline_cancels_inflight_stage_and_releases_admission(self):
        self.workers[0].step_gate = asyncio.Event()
        with self.assertRaises(RemoteError) as raised:
            await self.collect(timeout_seconds=0.05)
        self.assertEqual(raised.exception.code, "TIMEOUT")
        await self.clean()

    async def test_worker_failure_is_explicit_and_service_becomes_not_ready(self):
        self.workers[1].fail_step = "EXECUTION_FAILED"
        events = []
        with self.assertRaises(RemoteError) as raised:
            async for event in self.client.generate([9], 4):
                events.append(event)
        self.assertEqual(raised.exception.code, "EXECUTION_FAILED")
        self.assertEqual(events[-1]["status"], "failed")
        await self.clean()
        self.assertFalse((await self.client.describe())["ready"])

    async def test_idle_worker_boot_change_invalidates_coordinator_on_describe(self):
        self.handlers[1].boot_id = "a" * 32
        description = await self.client.describe()
        self.assertFalse(description["ready"])
        self.assertFalse(description["workers"][1]["ready"])
        self.assertEqual(self.coordinator._fatal_error.code, "STALE_WORKER")
        with self.assertRaises(RemoteError) as raised:
            await self.collect()
        self.assertEqual(raised.exception.code, "NOT_READY")
        await self.clean()

    async def test_transport_backpressure_has_own_deadline_and_cleans_scheduler(self):
        class Abort(Exception):
            pass

        class StalledContext:
            def time_remaining(self):
                return 3

            async def write(self, _):
                await asyncio.Event().wait()

            async def abort(self, code, details):
                raise Abort(str(code))

        request = {"input_ids": [9, 20], "new_tokens": 64, "capture_logits": False,
                   "timeout_seconds": 3}
        with self.assertRaises(Abort):
            await asyncio.wait_for(self.service.generate_rpc(encode_json(request), StalledContext()), 2)
        await self.clean()
        self.assertEqual(self.service.counters["transport_stalls"], 1)


@unittest.skipUnless(ENABLED, "Set STEAMBOAT_SERVICE_TESTS=1 for M5 watchdog checks")
class CoordinatorModelWatchdogTests(unittest.IsolatedAsyncioTestCase):
    async def test_publish_precedes_compute_and_cancel_retains_actual_thread_deadline(self):
        import torch
        from steamboat_runtime.coordinator_service import supervised_model_class
        prefix = f"{__package__}." if __package__ else ""
        manifest = importlib.import_module(prefix + "test_manifest").sample_manifest()
        model = supervised_model_class()(manifest, torch.nn.Identity(), None)
        started, release = threading.Event(), threading.Event()
        snapshots = []
        model.on_supervision = lambda value: snapshots.append(value)

        def blocked():
            started.set()
            release.wait(5)
            return 1

        task = asyncio.create_task(model._call(blocked))
        try:
            while not started.is_set():
                await asyncio.sleep(0.001)
            self.assertTrue(snapshots[0]["active_compute"])
            self.assertIsNone(snapshots[0]["terminate_deadline"])
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task
            status = model.supervision_status()
            self.assertTrue(status["active_compute"])
            self.assertAlmostEqual(status["terminate_deadline"] - time.monotonic(), 15, delta=0.2)
            self.assertEqual(model.diagnostics()["pending_cpu_operations"], 1)
            self.assertFalse(await model.close(timeout_seconds=0))
        finally:
            release.set()
            await asyncio.to_thread(model._executor.shutdown, wait=True)

    async def test_supervisor_kills_coordinator_child_with_cancelled_stuck_model(self):
        from steamboat_runtime.supervisor import ProcessSupervisor
        records = []
        fixture = Path(__file__).with_name("coordinator_service_fixture.py")
        parent = ProcessSupervisor([sys.executable, "-u", str(fixture)],
            startup_timeout=30, heartbeat_timeout=2, shutdown_grace=0.15,
            restart_limit=0, log=lambda event, **values: records.append({"event": event, **values}))
        code = await asyncio.to_thread(parent.run)
        self.assertEqual(code, 70)
        self.assertIsNotNone(parent.child.poll())
        self.assertTrue(any(item.get("reason") == "compute_cancel_grace_exceeded" for item in records), records)

    async def test_long_shutdown_grace_does_not_extend_compute_deadline_grace(self):
        from steamboat_runtime.supervisor import ProcessSupervisor
        records = []
        fixture = Path(__file__).with_name("coordinator_service_fixture.py")
        parent = ProcessSupervisor([sys.executable, "-u", str(fixture), "deadline"],
            startup_timeout=30, heartbeat_timeout=2, shutdown_grace=0.15,
            child_shutdown_grace=5, restart_limit=0,
            log=lambda event, **values: records.append({"event": event, "at": time.monotonic(), **values}))
        code = await asyncio.to_thread(parent.run)
        self.assertEqual(code, 70)
        ready = next(item for item in records if item["event"] == "worker_ready")
        killed = next(item for item in records if item["event"] == "worker_terminate")
        self.assertEqual(killed["reason"], "compute_deadline_grace_exceeded")
        self.assertLess(killed["at"] - ready["at"], 2)


if __name__ == "__main__":
    unittest.main()
