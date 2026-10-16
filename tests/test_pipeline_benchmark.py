"""Remote load-generator measurement and failure accounting without model imports."""

import asyncio
import copy
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from lab import benchmark
from lab.pipeline_benchmark import assert_reclaimed, generate_remote_request, run_remote_bench


def description():
    return {"ready": True, "config": {"vocab_size": 32000}, "limits": {"max_positions": 1152},
            "service": {"active_streams": 0, "loading_seconds": 1.5, "metrics_sessions": 0},
            "scheduler": {"active_requests": 0, "waiting_admissions": 0,
                          "stage_queue_sizes": [0, 0, 0], "active_stage_calls": [0, 0, 0]},
            "workers": [{"active_sessions": 0, "reserved_positions": 0, "allocated_cache_bytes": 0,
                         "active_operations": 0, "queued_operations": 0, "cache_bytes_exact": True}
                        for _ in range(3)]}


class FakeClient:
    def __init__(self, events=None, fail_attempts=()):
        self.events = events
        self.fail_attempts = set(fail_attempts)
        self.closed = False
        self.calls = 0
        self.streams_closed = 0
        self.active = 0
        self.peak_active = 0

    async def describe(self):
        return description()

    async def tokenize(self, text, *, add_special_tokens=True):
        assert add_special_tokens is False
        self.fixture = text
        return [7, 11, 13]

    async def generate(self, prompt, new_tokens, **kwargs):
        request = self.calls
        self.calls += 1
        self.active += 1
        self.peak_active = max(self.peak_active, self.active)
        try:
            await asyncio.sleep(0)
            if self.events is not None:
                for event in self.events:
                    if isinstance(event, Exception):
                        raise event
                    yield event
                return
            tokens = list(range(20, 20 + new_tokens))
            for index, token in enumerate(tokens):
                yield {"type": "token", "token_id": token, "index": index, "session_id": f"session-{request}"}
            failed = request in self.fail_attempts
            yield {"type": "result", "status": "failed" if failed else "completed",
                   "cleanup_complete": True, "token_ids": tokens,
                   "error": "worker unavailable" if failed else None,
                   "error_code": "EXECUTION_FAILED" if failed else None,
                   "metrics": {"admission_ms": 5}}
        finally:
            self.active -= 1
            self.streams_closed += 1

    async def close(self):
        self.closed = True


class RemoteMeasurementTests(unittest.IsolatedAsyncioTestCase):
    async def test_client_clock_includes_rpc_to_first_token_and_excludes_cleanup_from_decode(self):
        client = FakeClient()
        with patch("lab.pipeline_benchmark.time", SimpleNamespace(monotonic=Mock(side_effect=[10, 11, 13, 16, 17]))):
            record = await generate_remote_request(client, [3], 3, 9)
        self.assertTrue(record["success"])
        self.assertEqual(record["ttft_seconds"], 1)
        self.assertEqual(record["inter_token_seconds"], [2, 3])
        self.assertEqual(record["elapsed_seconds"], 7)
        self.assertEqual(record["decode_output_tokens_per_second"], 2 / 5)
        self.assertEqual(record["server_metrics"], {"admission_ms": 5})
        self.assertEqual(record["retry_count"], 0)

    async def test_transport_failure_retains_partial_output_and_closes_stream(self):
        client = FakeClient([{"type": "token", "index": 0, "token_id": 12}, TimeoutError("lost stream")])
        record = await generate_remote_request(client, [3], 3, 0)
        self.assertFalse(record["success"])
        self.assertEqual(record["output_token_ids"], [12])
        self.assertIn("lost stream", record["error"])
        self.assertFalse(record["cleanup_complete"])
        self.assertEqual(client.streams_closed, 1)

    async def test_failed_terminal_metrics_survive_error_raised_after_yield(self):
        error = RuntimeError("request expired")
        error.code = "TIMEOUT"
        terminal = {"type": "result", "status": "failed", "cleanup_complete": True,
                    "session_id": "failed-session", "token_ids": [12],
                    "error": "request expired", "error_code": "TIMEOUT",
                    "metrics": {"admission_ms": 17, "stages": [{"worker_compute_ms": 23}]}}
        client = FakeClient([{"type": "token", "index": 0, "token_id": 12}, terminal, error])
        record = await generate_remote_request(client, [3], 3, 0)
        self.assertFalse(record["success"])
        self.assertEqual(record["status"], "failed")
        self.assertTrue(record["cleanup_complete"])
        self.assertEqual(record["server_metrics"], terminal["metrics"])
        self.assertEqual(record["error_code"], "TIMEOUT")
        self.assertEqual(record["terminal_result"], terminal)
        self.assertEqual(record["session_id"], "failed-session")
        self.assertEqual(record["output_token_ids"], [12])

    async def test_duplicate_streamed_token_fails_without_counting_duplicate(self):
        client = FakeClient([{"type": "token", "index": 0, "token_id": 12},
                             {"type": "token", "index": 0, "token_id": 13}])
        record = await generate_remote_request(client, [3], 3, 0)
        self.assertFalse(record["success"])
        self.assertEqual(record["output_tokens"], 1)
        self.assertIn("duplicated", record["error"])

    async def test_missing_terminal_or_unreclaimed_cache_never_counts_as_complete(self):
        for terminal in (None, {"type": "result", "status": "completed", "cleanup_complete": False,
                               "token_ids": [12], "metrics": {}}):
            events = [{"type": "token", "index": 0, "token_id": 12}]
            if terminal:
                events.append(terminal)
            record = await generate_remote_request(FakeClient(events), [3], 1, 0)
            self.assertFalse(record["success"])

    async def test_terminal_token_mismatch_is_rejected(self):
        events = [{"type": "token", "index": 0, "token_id": 12},
                  {"type": "result", "status": "completed", "cleanup_complete": True,
                   "token_ids": [13], "metrics": {}}]
        record = await generate_remote_request(FakeClient(events), [3], 1, 0)
        self.assertFalse(record["success"])
        self.assertIn("Terminal token IDs", record["error"])


class RemoteBenchmarkTests(unittest.IsolatedAsyncioTestCase):
    @staticmethod
    def args(**kwargs):
        values = dict(prompt_tokens=7, new_tokens=3, concurrency=3, requests=5)
        values.update(kwargs)
        return SimpleNamespace(**values)

    async def test_warmup_excluded_and_failed_partial_tokens_separate(self):
        client, report = FakeClient(fail_attempts={2}), {}
        await run_remote_bench(self.args(), report, client=client)
        self.assertTrue(client.closed)
        self.assertEqual(client.calls, 6)
        self.assertEqual(client.peak_active, 3)
        self.assertEqual(report["prompt_token_ids"], [7, 11, 13, 7, 11, 13, 7])
        self.assertEqual(report["summary"]["attempted"], 5)
        self.assertEqual(report["summary"]["completed"], 4)
        self.assertEqual(report["summary"]["accepted_output_tokens"], 12)
        self.assertEqual(report["partial_output_tokens_from_failed_requests"], 3)
        self.assertEqual(report["error_counts"], {"EXECUTION_FAILED": 1})
        self.assertFalse(report["success"])
        self.assertEqual(report["client_model_parameter_bytes"], 0)

    async def test_completion_target_retains_failed_attempt_and_stops_at_goal(self):
        client, report = FakeClient(fail_attempts={1}), {}
        await run_remote_bench(self.args(concurrency=1, completion_target=3, max_attempts=5),
                               report, client=client)
        self.assertEqual(report["summary"]["attempted"], 4)
        self.assertEqual(report["summary"]["completed"], 3)
        self.assertEqual(report["attempt_policy"]["stop_reason"], "target_reached")
        self.assertTrue(report["attempt_policy"]["target_reached"])
        self.assertFalse(report["success"])

    async def test_attempt_cap_publishes_underfilled_run(self):
        client, report = FakeClient(fail_attempts=set(range(1, 20))), {}
        await run_remote_bench(self.args(concurrency=3, completion_target=3, max_attempts=4),
                               report, client=client)
        self.assertEqual(report["summary"]["attempted"], 4)
        self.assertEqual(report["summary"]["completed"], 0)
        self.assertFalse(report["attempt_policy"]["target_reached"])
        self.assertEqual(report["attempt_policy"]["stop_reason"], "attempt_limit")

    async def test_failed_warmup_saved_and_no_measurement_started(self):
        client, report = FakeClient(fail_attempts={0}), {}
        with self.assertRaisesRegex(RuntimeError, "Warm-up failed"):
            await run_remote_bench(self.args(), report, client=client)
        self.assertFalse(report["warmup"]["success"])
        self.assertNotIn("summary", report)
        self.assertEqual(client.calls, 1)
        self.assertTrue(client.closed)


class CleanupAndPolicyTests(unittest.TestCase):
    def test_logical_worker_or_coordinator_ownership_prevents_clean_result(self):
        assert_reclaimed(description())
        for field in ("active_sessions", "allocated_cache_bytes", "queued_operations"):
            item = copy.deepcopy(description())
            item["workers"][1][field] = 1
            with self.assertRaises(AssertionError):
                assert_reclaimed(item)
        item = description()
        item["scheduler"]["active_requests"] = 1
        with self.assertRaises(AssertionError):
            assert_reclaimed(item)

    def test_attempt_policy_defaults_and_invalid_bounds(self):
        self.assertEqual(benchmark.validate_attempt_policy(SimpleNamespace(requests=7)), (None, 7))
        self.assertEqual(benchmark.validate_attempt_policy(SimpleNamespace(requests=7, completion_target=100)),
                         (100, 200))
        for values in ({"max_attempts": 4}, {"completion_target": 0},
                       {"completion_target": 5, "max_attempts": 4}):
            with self.assertRaises(ValueError):
                benchmark.validate_attempt_policy(SimpleNamespace(requests=7, **values))

    def test_queued_stage_active_call_or_metrics_retention_fails_cleanup(self):
        for field in ("stage_queue_sizes", "active_stage_calls"):
            for value in ([0, 1, 0], [0, 0], None):
                item = description()
                item["scheduler"][field] = value
                with self.subTest(field=field, value=value), self.assertRaises(AssertionError):
                    assert_reclaimed(item)
        item = description()
        item["service"]["metrics_sessions"] = 1
        with self.assertRaisesRegex(AssertionError, "metrics"):
            assert_reclaimed(item)


if __name__ == "__main__":
    unittest.main()
