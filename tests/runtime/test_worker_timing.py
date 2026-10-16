"""Execution-thread timing and same-host clock-domain checks for M4 traces."""

import asyncio
import os
import threading
import time
import unittest
from unittest.mock import patch


class ClockIdentityTests(unittest.TestCase):
    def test_clock_domain_depends_on_kernel_boot_and_monotonic_offset(self):
        from steamboat_runtime.protocol.clock import clock_identity
        boot = "12345678-1234-1234-1234-123456789abc"
        try:
            identities = []
            for offsets in ("monotonic 0 0\nboottime 0 0\n", "monotonic 0 0\nboottime 8 0\n",
                            "monotonic 1 1\n", "monotonic -1 2\n"):
                clock_identity.cache_clear()
                with patch("sys.platform", "linux"), patch("pathlib.Path.read_text", side_effect=[boot, offsets]):
                    identities.append(clock_identity())
            self.assertTrue(identities[0])
            self.assertEqual(identities[0], identities[1])
            self.assertNotEqual(identities[0], identities[2])
            self.assertTrue(identities[3].endswith(":-999999998"))
        finally:
            clock_identity.cache_clear()

    def test_missing_or_malformed_clock_evidence_never_verifies(self):
        from steamboat_runtime.protocol.clock import clock_identity
        boot = "12345678-1234-1234-1234-123456789abc"
        try:
            for offsets in ("", "boottime 0 0", "monotonic 1", "monotonic 0 1000000000",
                            "monotonic x 0", "monotonic 0 0\nmonotonic 0 0"):
                clock_identity.cache_clear()
                with patch("sys.platform", "linux"), patch("pathlib.Path.read_text", side_effect=[boot, offsets]):
                    self.assertEqual(clock_identity(), "")
            clock_identity.cache_clear()
            with patch("sys.platform", "linux"), patch("pathlib.Path.read_text", side_effect=OSError):
                self.assertEqual(clock_identity(), "")
        finally:
            clock_identity.cache_clear()


@unittest.skipUnless(os.environ.get("STEAMBOAT_PROTOCOL_TESTS") == "1",
                     "Set STEAMBOAT_PROTOCOL_TESTS=1 in the pinned image")
class WorkerTimingTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        import torch
        from steamboat_runtime.worker_state import WorkerHandler
        from steamboat_runtime.protocol.worker_pb2 import Request
        from steamboat_runtime.protocol.codec import encode_tensor
        from .test_manifest import sample_manifest
        from .test_worker_state import FakeExecutor
        self.manifest = sample_manifest()
        self.executor = FakeExecutor(torch)
        self.handler = WorkerHandler(self.manifest, "worker-1", self.executor, enable_queue=True)
        self.Request = Request
        self.tensor = encode_tensor(torch.zeros(1, 1, 64))
        self.pending = []

    async def asyncTearDown(self):
        self.executor.release.set()
        await asyncio.gather(*self.pending, return_exceptions=True)
        await self.handler.shutdown()

    def request(self, **fields):
        return self.Request(protocol_version=1, manifest_fingerprint=self.manifest["fingerprint"],
                            worker_boot_id=self.handler.boot_id, timeout_ms=3000, **fields)

    async def start_step(self, name):
        opened = await self.handler.handle("OpenSession", self.request(
            session_id=name, max_positions=32, idle_lease_ms=120000, lifetime_ms=300000))
        self.assertEqual(opened.code, "OK")
        task = asyncio.create_task(self.handler.handle("Step", self.request(
            session_id=name, lease_token=opened.lease_token, token_count=1, tensor=self.tensor)))
        self.pending.append(task)
        return task

    async def test_describe_clock_sample_and_compute_span_are_bracketed(self):
        from steamboat_runtime.protocol.clock import clock_identity
        start = time.monotonic_ns()
        response = await self.handler.handle("Describe", self.request())
        end = time.monotonic_ns()
        self.assertEqual(response.clock_id, clock_identity())
        self.assertTrue(start <= response.monotonic_ns <= end)
        start = time.monotonic_ns()
        result = await (await self.start_step("A"))
        end = time.monotonic_ns()
        self.assertTrue(start <= result.compute_start_ns <= result.compute_end_ns <= result.monotonic_ns <= end)
        self.assertNotEqual(self.executor.calls[0][2], threading.get_ident())
        span_ms = (result.compute_end_ns - result.compute_start_ns) / 1_000_000
        self.assertAlmostEqual(result.compute_ms, span_ms, delta=1)

    async def test_queue_wait_is_outside_nonoverlapping_compute_spans(self):
        self.executor.block = True
        first = await self.start_step("A")
        self.assertTrue(await asyncio.to_thread(self.executor.started.wait, 1))
        second = await self.start_step("B")
        await asyncio.sleep(0.05)
        self.executor.release.set()
        a, b = await asyncio.gather(first, second)
        self.assertEqual((a.code, b.code), ("OK", "OK"))
        self.assertGreater(b.queue_ms, 30)
        self.assertGreaterEqual(b.compute_start_ns, a.compute_end_ns)
        self.assertLess(b.compute_ms, b.queue_ms)

    async def test_wire_rejects_incomplete_or_reversed_compute_timestamps(self):
        from steamboat_runtime.protocol.worker_pb2 import Response
        from steamboat_runtime.protocol.wire import validate_response
        from steamboat_runtime.protocol.errors import ProtocolError
        for start, end, sample in ((0, 1, 2), (1, 0, 2), (3, 2, 4), (1, 3, 2)):
            with self.subTest(start=start, end=end, sample=sample), self.assertRaises(ProtocolError):
                validate_response("Describe", self.request(), Response(protocol_version=1, code="OK",
                    compute_start_ns=start, compute_end_ns=end, monotonic_ns=sample))
