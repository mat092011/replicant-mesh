"""M4 trace-proof checks and opt-in same-stack model integration.

Real-model tests use in-process worker handlers through binary transport. Only
the separate container validation run supports the remote compute-overlap claim.
"""

import asyncio
import copy
import os
import unittest


ENABLED = os.environ.get("REPLICANT_MESH_COORDINATOR_TESTS") == "1"
ARTIFACT_DIR = os.environ.get("REPLICANT_MESH_ARTIFACT_DIR")
REFERENCE_DIR = os.environ.get("REPLICANT_MESH_REFERENCE_DIR")


class TraceProofTests(unittest.TestCase):
    @staticmethod
    def fixture():
        # Every session is causal and every worker has one active call. There
        # is real cross-worker overlap between A2 and B1, then A3 and B2.
        intervals = {("a", 1): (10, 20), ("a", 2): (22, 42), ("a", 3): (44, 64),
                     ("b", 1): (22, 32), ("b", 2): (44, 54), ("b", 3): (66, 76)}
        events = []
        for (session, worker), (start, end) in intervals.items():
            common = {"session_id": session, "worker": worker, "sequence": 0}
            events.append({**common, "event": "stage_dispatch", "coordinator_ns": start})
            events.append({**common, "event": "stage_response", "coordinator_ns": end,
                           "compute_start_ns": start + 1, "compute_end_ns": end - 1,
                           "clock_id": "verified-fixture-clock"})
        return sorted(events, key=lambda event: event["coordinator_ns"])

    def verify(self, events, **kwargs):
        from replicant_mesh.coordinator_check import inspect_trace
        return inspect_trace(events, ["a", "b"], 1, clock_id="verified-fixture-clock", **kwargs)

    def test_causal_trace_with_actual_compute_overlap_passes(self):
        result = self.verify(self.fixture(), require_overlap=True)
        self.assertEqual(result["stage_operations"], 6)
        self.assertGreater(result["overlapping_compute_pairs"], 0)

    def test_rpc_overlap_without_compute_overlap_cannot_pass(self):
        events = self.fixture()
        for event in events:
            if event["event"] == "stage_response":
                # Computations themselves happen at distinct instants.
                event["compute_end_ns"] = event["compute_start_ns"]
        with self.assertRaisesRegex(AssertionError, "No verified useful compute overlap"):
            self.verify(events, require_overlap=True)

    def test_unknown_clock_cannot_establish_overlap(self):
        events = self.fixture()
        next(event for event in events if event["event"] == "stage_response")["clock_id"] = "remote-clock"
        with self.assertRaisesRegex(AssertionError, "local-clock bracket"):
            self.verify(events, require_overlap=True)

    def test_future_stage_before_prior_response_is_rejected(self):
        events = self.fixture()
        next(event for event in events if event["event"] == "stage_dispatch"
             and event["session_id"] == "a" and event["worker"] == 2)["coordinator_ns"] = 19
        with self.assertRaisesRegex(AssertionError, "preceding response"):
            self.verify(events)

    def test_duplicate_or_missing_stage_event_is_rejected(self):
        events = self.fixture()
        with self.assertRaisesRegex(AssertionError, "Duplicate"):
            self.verify(events + [copy.deepcopy(events[0])])
        with self.assertRaisesRegex(AssertionError, "incomplete"):
            self.verify(events[1:])


@unittest.skipUnless(ENABLED, "Set REPLICANT_MESH_COORDINATOR_TESTS=1 for offline M4 integration")
class CoordinatorModelIntegrationTests(unittest.IsolatedAsyncioTestCase):
    @classmethod
    def setUpClass(cls):
        if not ARTIFACT_DIR or not REFERENCE_DIR:
            raise RuntimeError("M4 integration requires offline artifacts and reference")
        import torch
        from transformers import AutoModelForCausalLM
        from replicant_mesh.coordinator import Coordinator
        from replicant_mesh.coordinator_model import CoordinatorModel
        from replicant_mesh.manifest import load_manifest
        from replicant_mesh.prepare import verify_snapshot
        from replicant_mesh.protocol.transport import InMemoryTransport
        from replicant_mesh.worker_state import StageExecutor, WorkerHandler
        torch.set_num_threads(int(os.environ.get("OMP_NUM_THREADS", "2")))
        verify_snapshot(REFERENCE_DIR)
        cls.reference = AutoModelForCausalLM.from_pretrained(
            REFERENCE_DIR, dtype=torch.float32, attn_implementation="eager",
            local_files_only=True, use_safetensors=True).eval().requires_grad_(False)
        cls.manifest = load_manifest(ARTIFACT_DIR)
        cls.executors = [StageExecutor(ARTIFACT_DIR, f"worker-{index}") for index in (1, 2, 3)]
        cls.Coordinator, cls.Model = Coordinator, CoordinatorModel
        cls.Handler, cls.Transport = WorkerHandler, InMemoryTransport

    async def asyncSetUp(self):
        self.model = self.Model.from_artifacts(ARTIFACT_DIR, REFERENCE_DIR)
        self.handlers = [self.Handler(self.manifest, executor.worker_name, executor, enable_queue=True)
                         for executor in self.executors]
        self.clients = [self.Transport(handler) for handler in self.handlers]
        self.coordinator = self.Coordinator(self.manifest, self.clients, self.model)
        self.evidence = {}
        await self.coordinator.start()

    async def asyncTearDown(self):
        from replicant_mesh.coordinator_check import assert_worker_cleanup
        self.assertTrue(await self.coordinator.close())
        for handler in self.handlers:
            self.assertTrue(await handler.shutdown())
        await assert_worker_cleanup(self.clients, self.manifest, self.evidence, self.id())

    async def test_one_three_eight_concurrent_requests_and_greedy_match_reference(self):
        from replicant_mesh.coordinator_check import validate_cohorts
        await validate_cohorts(self.coordinator, self.reference, self.evidence,
                               clients=self.clients, manifest=self.manifest,
                               cohorts=((1, (7,)), (3, (7, 13, 31)),
                                        (8, (7, 13, 31, 17, 23, 3, 11, 29))))
        self.assertEqual(len(self.evidence["comparisons"]), 117)
        self.assertTrue(all(item["cleanup_complete"] for item in self.evidence["requests"]))

    async def test_cancelling_one_stream_preserves_another_real_cache(self):
        from replicant_mesh.coordinator_check import (
            consume_checked, fixture_tokens, reference_logits, assert_worker_cleanup,
        )
        prompt = fixture_tokens(31, 847, self.reference.config.vocab_size)
        expected = reference_logits(self.reference, prompt, 9)
        interrupted = self.coordinator.submit(prompt, 64)
        survivor = self.coordinator.submit(prompt, 9, capture_logits=True)
        survivor_task = asyncio.create_task(consume_checked(survivor, expected, "survivor", self.evidence))
        first = await anext(interrupted)
        self.assertEqual(first.index, 0)
        await interrupted.cancel()
        result = await interrupted.result()
        self.assertTrue(result.cleanup_complete)
        self.assertLess(len(result.token_ids), 64)
        self.assertIsNotNone(result.error)
        await survivor_task
        await assert_worker_cleanup(self.clients, self.manifest, self.evidence, "cancelled-and-survivor")


if __name__ == "__main__":
    unittest.main()
