"""Focused tests for matched complete-model control routing."""

import unittest
import asyncio
import os
from unittest.mock import patch
from types import SimpleNamespace
import threading
import time

from lab.matched_control import MatchedReplicaPool


class MatchedControlTests(unittest.TestCase):
    def test_benchmark_constructs_grpc_clients_in_measurement_loop(self):
        from lab.benchmark import run_bench
        loops = []
        def client(*args, **kwargs):
            loops.append(asyncio.get_running_loop())
            return object()
        async def measure(args, report, client):
            self.assertEqual(len(loops), 4)
            self.assertTrue(all(loop is asyncio.get_running_loop() for loop in loops))
            report['success'] = True
        args = SimpleNamespace(prompt_tokens=128, new_tokens=64, concurrency=3,
                               requests=100, backend='matched', mode='pipeline')
        report = {}
        with patch('replicant_mesh.remote_client.RemoteClient', client), patch('lab.pipeline_benchmark.run_remote_bench', measure):
            run_bench(args, report)
        self.assertTrue(report['success'])

    def test_pool_requires_four_replicas(self):
        with self.assertRaises(ValueError):
            MatchedReplicaPool([object() for _ in range(3)])

    def test_least_loaded_routing_spreads_and_rebalances_requests(self):
        pool = MatchedReplicaPool([object() for _ in range(4)])
        routed = [pool.reserve_replica() for _ in range(4)]
        self.assertEqual(routed, [0, 1, 2, 3])
        self.assertEqual(pool.reserve_replica(), 0)
        pool.in_flight[1] -= 1
        self.assertEqual(pool.reserve_replica(), 1)
        self.assertEqual(pool.in_flight, [2, 1, 1, 1])


@unittest.skipUnless(os.environ.get("REPLICANT_MESH_PROTOCOL_TESTS") == "1", "runtime opt-in")
class ReplicaExecutionTests(unittest.IsolatedAsyncioTestCase):
    async def test_cancel_retains_session_until_compute_drains(self):
        import torch
        from lab.matched_control import ReplicaService
        from replicant_mesh.remote_client import encode_json
        entered, release = threading.Event(), threading.Event()
        observed = {}
        def step(session, ids):
            observed["inference_mode"] = torch.is_inference_mode_enabled()
            entered.set()
            release.wait(2)
            observed["closed_during_compute"] = session.closed
            return torch.zeros(1, 1, 8)
        context = SimpleNamespace(cancelled=lambda: False)
        model = SimpleNamespace(config=SimpleNamespace(vocab_size=8, max_position_embeddings=1152))
        with patch("replicant_mesh.manifest.load_manifest", return_value={}), patch("lab.benchmark.LocalSession.step", step):
            service = ReplicaService(model, None)
            request = encode_json(dict(input_ids=[1], new_tokens=1, timeout_seconds=5, capture_logits=False))
            task = asyncio.create_task(service.generate_rpc(request, context))
            try:
                while not entered.is_set():
                    await asyncio.sleep(.005)
                task.cancel()
                await asyncio.sleep(.02)
                task.cancel()
                await asyncio.sleep(.02)
                self.assertEqual(len(service.sessions), 1)
                self.assertEqual(service.active_operations, 1)
            finally:
                release.set()
            with self.assertRaises(asyncio.CancelledError):
                await task
            self.assertTrue(observed["inference_mode"])
            self.assertFalse(observed["closed_during_compute"])
            self.assertEqual(service.sessions, {})
            self.assertEqual(service.active_operations, 0)

    async def test_deadline_drains_compute_then_reports_failure(self):
        import torch
        from lab.matched_control import ReplicaService
        from replicant_mesh.remote_client import encode_json
        def step(session, ids):
            time.sleep(.05)
            self.assertFalse(session.closed)
            return torch.zeros(1, 1, 8)
        errors = []
        async def abort(code, message):
            errors.append(code.name)
            raise RuntimeError(message)
        context = SimpleNamespace(cancelled=lambda: False, abort=abort)
        model = SimpleNamespace(config=SimpleNamespace(vocab_size=8, max_position_embeddings=1152))
        with patch("replicant_mesh.manifest.load_manifest", return_value={}), patch("lab.benchmark.LocalSession.step", step):
            service = ReplicaService(model, None)
            request = encode_json(dict(input_ids=[1], new_tokens=1, timeout_seconds=.01, capture_logits=False))
            with self.assertRaises(RuntimeError):
                await service.generate_rpc(request, context)
            self.assertEqual(errors, ["DEADLINE_EXCEEDED"])
            self.assertEqual(service.sessions, {})
            self.assertEqual(service.active_operations, 0)

if __name__ == "__main__":
    unittest.main()
