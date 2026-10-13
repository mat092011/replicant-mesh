"""Workload, token feedback, and failure bookkeeping checks without PyTorch."""

from contextlib import nullcontext
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from lab import benchmark


class WorkloadTests(unittest.TestCase):
    def test_exact_context_and_concurrency_limits_are_allowed(self):
        benchmark.validate_workload(1024, 128, 8, 1)
        benchmark.validate_workload(1, 1, 1, 1)

    def test_each_workload_count_must_be_positive(self):
        for index in range(4):
            for value in (0, -1):
                workload = [16, 8, 3, 10]
                workload[index] = value
                with self.subTest(index=index, value=value), self.assertRaises(ValueError):
                    benchmark.validate_workload(*workload)

    def test_excessive_context_or_concurrency_is_rejected(self):
        for workload in [(1025, 128, 1, 1), (1, 1, 9, 1)]:
            with self.subTest(workload=workload), self.assertRaises(ValueError):
                benchmark.validate_workload(*workload)

    def test_fixture_is_repeated_and_truncated_to_exact_requested_lengths(self):
        tokenizer = Mock()
        tokenizer.encode.return_value = [10, 20, 30]
        for count, expected in [(1, [10]), (3, [10, 20, 30]),
                                (7, [10, 20, 30, 10, 20, 30, 10])]:
            with self.subTest(count=count):
                self.assertEqual(benchmark.fixture_ids(tokenizer, count), expected)
        tokenizer.encode.assert_called_with(benchmark.FIXTURE, add_special_tokens=False)

    def test_empty_tokenizer_fixture_fails_explicitly(self):
        tokenizer = Mock()
        tokenizer.encode.return_value = []
        with self.assertRaises(ValueError):
            benchmark.fixture_ids(tokenizer, 16)


class FakeLogits:
    def __init__(self, token):
        self.token = token

    def __getitem__(self, _):
        return self

    def argmax(self):
        return self.token


class ScriptedSession:
    def __init__(self, steps):
        self.steps = iter(steps)
        self.inputs = []
        self.closed = False

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.closed = True

    def step(self, ids):
        self.inputs.append(ids)
        value = next(self.steps)
        if isinstance(value, Exception):
            raise value
        return FakeLogits(value)


class GenerationTests(unittest.TestCase):
    def run_request(self, session, new_tokens, times):
        fake_torch = SimpleNamespace(inference_mode=nullcontext, long="long",
                                     tensor=lambda data, dtype: data)
        with patch.dict(sys.modules, {"torch": fake_torch}), \
                patch.object(benchmark, "make_session", return_value=session), \
                patch.object(benchmark.time, "perf_counter", side_effect=times):
            return benchmark.generate_request(object(), "pipeline", [3, 4], new_tokens, 7)

    def test_decode_feeds_back_previous_token_and_counts_only_outputs(self):
        session = ScriptedSession([10, 11, 12])
        result = self.run_request(session, 3, [10, 11, 13, 16, 17])
        self.assertTrue(result["success"])
        self.assertEqual(session.inputs, [[[3, 4]], [[10]], [[11]]])
        self.assertEqual(result["output_token_ids"], [10, 11, 12])
        self.assertEqual(result["output_tokens"], 3)
        self.assertEqual(result["ttft_seconds"], 1)
        self.assertEqual(result["inter_token_seconds"], [2, 3])
        self.assertEqual(result["decode_output_tokens_per_second"], 2 / 5)
        self.assertEqual(result["elapsed_seconds"], 7)
        self.assertTrue(session.closed)

    def test_decode_failure_preserves_partial_output_and_closes_session(self):
        session = ScriptedSession([10, TimeoutError("worker unavailable")])
        result = self.run_request(session, 3, [10, 11, 12])
        self.assertFalse(result["success"])
        self.assertEqual(result["output_tokens"], 1)
        self.assertEqual(result["output_token_ids"], [10])
        self.assertEqual(result["error"], "TimeoutError: worker unavailable")
        self.assertEqual(result["ttft_seconds"], 1)
        self.assertIsNone(result["decode_output_tokens_per_second"])
        self.assertTrue(session.closed)

    def test_prefill_failure_has_no_first_token_measurement(self):
        session = ScriptedSession([RuntimeError("no route")])
        result = self.run_request(session, 2, [10, 12])
        self.assertFalse(result["success"])
        self.assertEqual(result["output_tokens"], 0)
        self.assertIsNone(result["ttft_seconds"])
        self.assertEqual(result["inter_token_seconds"], [])
        self.assertTrue(session.closed)


class BenchmarkTests(unittest.TestCase):
    @staticmethod
    def args(**overrides):
        values = dict(mode="pipeline", prompt_tokens=16, new_tokens=6,
                      concurrency=3, requests=5)
        values.update(overrides)
        return SimpleNamespace(**values)

    def test_closed_loop_reports_all_requests_once_and_excludes_warmup(self):
        tokenizer = Mock()
        tokenizer.encode.return_value = [1, 2, 3]
        model = SimpleNamespace(config=SimpleNamespace(max_position_embeddings=1152))

        def generate(_model, _mode, _prompt, _new_tokens, request_id):
            return {"request_id": request_id, "success": request_id != 1,
                    "output_tokens": 3 if request_id == 1 else 6,
                    "ttft_seconds": 0.1, "inter_token_seconds": [0.1] * 5}

        report = {}
        with patch.object(benchmark, "load_model", return_value=(model, tokenizer, 9)), \
                patch.object(benchmark, "generate_request", side_effect=generate) as generator, \
                patch.object(benchmark.time, "perf_counter", side_effect=[100, 102]):
            benchmark.run_bench(self.args(), report)
        self.assertEqual(generator.call_count, 6)  # Five measured calls plus warm-up.
        self.assertEqual([r["request_id"] for r in report["requests"]], list(range(5)))
        self.assertEqual(report["summary"]["attempted"], 5)
        self.assertEqual(report["summary"]["accepted_output_tokens"], 24)
        self.assertEqual(report["summary"]["aggregate_output_tokens_per_second"], 12)
        self.assertEqual(report["partial_output_tokens_from_failed_requests"], 3)
        self.assertEqual(report["model_loading_seconds"], 9)
        self.assertFalse(report["success"])

    def test_failed_warmup_is_preserved_and_prevents_measurement(self):
        model = SimpleNamespace(config=SimpleNamespace(max_position_embeddings=1152))
        tokenizer = Mock()
        tokenizer.encode.return_value = [1]
        warmup = {"success": False, "error": "worker not ready", "output_tokens": 0}
        report = {}
        with patch.object(benchmark, "load_model", return_value=(model, tokenizer, 1)), \
                patch.object(benchmark, "generate_request", return_value=warmup) as generator:
            with self.assertRaisesRegex(RuntimeError, "Warm-up failed"):
                benchmark.run_bench(self.args(), report)
        generator.assert_called_once()
        self.assertIs(report["warmup"], warmup)
        self.assertNotIn("summary", report)

    def test_checkpoint_limit_is_checked_before_any_request(self):
        model = SimpleNamespace(config=SimpleNamespace(max_position_embeddings=20))
        with patch.object(benchmark, "load_model", return_value=(model, Mock(), 1)), \
                patch.object(benchmark, "generate_request") as generator:
            with self.assertRaisesRegex(ValueError, "checkpoint context limit"):
                benchmark.run_bench(self.args(), {})
        generator.assert_not_called()


if __name__ == "__main__":
    unittest.main()
