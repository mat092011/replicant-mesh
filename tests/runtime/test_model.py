"""M1 numerical and ownership gates against an offline complete-model reference.

Set STEAMBOAT_ARTIFACT_DIR to prepared slices and STEAMBOAT_REFERENCE_DIR to
the original checkpoint snapshot to run these integration tests. Neither path
is fetched here. Without both paths the class is explicitly skipped, so the
dependency-free tests remain runnable without installing the inference stack.
"""

from contextlib import ExitStack
from datetime import datetime, timezone
import importlib.metadata
import json
import os
from pathlib import Path
import re
import unittest
from unittest.mock import patch


ATOL = 1e-3
MAX_LENGTH = 1152
ASSIGNMENTS = ((0, 3), (3, 6), (6, 8))
ARTIFACT_DIR = os.environ.get("STEAMBOAT_ARTIFACT_DIR")
REFERENCE_DIR = os.environ.get("STEAMBOAT_REFERENCE_DIR")


@unittest.skipUnless(
    ARTIFACT_DIR and REFERENCE_DIR,
    "Set STEAMBOAT_ARTIFACT_DIR and STEAMBOAT_REFERENCE_DIR for offline M1 checks",
)
class PartitionedModelTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import torch
        from transformers import AutoModelForCausalLM
        from steamboat_runtime.model import PipelineModel
        from steamboat_runtime.prepare import verify_snapshot

        cls.torch = torch
        torch.set_num_threads(int(os.environ.get("OMP_NUM_THREADS", "2")))
        verify_snapshot(REFERENCE_DIR)
        cls.reference = AutoModelForCausalLM.from_pretrained(
            REFERENCE_DIR, dtype=torch.float32, attn_implementation="eager",
            local_files_only=True,
        ).eval()
        cls.pipeline = PipelineModel(ARTIFACT_DIR)
        cls.evidence = {
            "created_utc": datetime.now(timezone.utc).isoformat(),
            "runtime": {name: importlib.metadata.version(name) for name in
                        ("torch", "transformers", "grpcio", "protobuf", "safetensors")},
            "execution": "in_process_serialized; no network transport",
            "atol": ATOL, "rtol": 0,
            "model_revision": "298338802ab94432b917bcce11382aa151aee50f",
            "fixture": "token[i] = 3 + ((i * 37 + offset) % (vocab_size - 3))",
            "comparisons": [], "greedy": [],
        }

    @classmethod
    def tearDownClass(cls):
        cls.evidence["final_diagnostics"] = cls.pipeline.diagnostics()
        output = os.environ.get("STEAMBOAT_TEST_REPORT")
        if output:
            path = Path(output)
            if path.suffix != ".json":
                path = path / f"{datetime.now(timezone.utc):%Y%m%dT%H%M%S%fZ}-m1-validation.json"
            path.parent.mkdir(parents=True, exist_ok=True)
            # Refuse to overwrite earlier evidence, including a failed run.
            with path.open("x", encoding="utf-8") as stream:
                stream.write(json.dumps(cls.evidence, indent=2, allow_nan=False) + "\n")
            print(f"M1 numerical observations: {path}")

    def ids(self, count, offset=0):
        values = [3 + ((i * 37 + offset) % (self.reference.config.vocab_size - 3))
                  for i in range(count)]
        return self.torch.tensor([values], dtype=self.torch.long)

    def reference_step(self, ids, cache=None):
        with self.torch.inference_mode():
            result = self.reference(input_ids=ids, past_key_values=cache,
                                    use_cache=True, return_dict=True)
        return result.logits, result.past_key_values

    def assert_logits(self, name, actual, expected):
        self.assertEqual(tuple(actual.shape), tuple(expected.shape))
        self.assertTrue(bool(self.torch.isfinite(actual).all()), name)
        self.assertTrue(bool(self.torch.isfinite(expected).all()), name)
        error = float((actual - expected).abs().max())
        self.evidence["comparisons"].append({
            "name": name, "shape": list(actual.shape), "max_absolute_error": error,
        })
        self.torch.testing.assert_close(actual, expected, atol=ATOL, rtol=0, msg=name)

    def test_every_prefill_logit_and_forced_decode_matches_reference(self):
        for prompt_length in (1, 128, 1024):
            with self.subTest(prompt_length=prompt_length), \
                    self.pipeline.open_session(prompt_length + 8) as session:
                prompt = self.ids(prompt_length)
                expected, cache = self.reference_step(prompt)
                actual = session.step(prompt, return_all_logits=True)
                self.assert_logits(f"prefill-{prompt_length}", actual, expected)
                self.assertEqual(session.position, prompt_length)
                for step in range(8):
                    token = self.ids(1, offset=900 + step * 13)
                    expected, cache = self.reference_step(token, cache)
                    actual = session.step(token)
                    self.assert_logits(f"forced-{prompt_length}-{step}", actual, expected)
                    self.assertEqual(session.position, prompt_length + step + 1)

    def test_unequal_interleaved_sessions_survive_other_session_close(self):
        with self.pipeline.open_session(256) as first, \
                self.pipeline.open_session(256) as second:
            first_prompt, second_prompt = self.ids(7), self.ids(128, offset=211)
            expected_first, cache_first = self.reference_step(first_prompt)
            self.assert_logits("interleave-A-prefill", first.step(first_prompt),
                               expected_first[:, -1:, :])
            expected_second, cache_second = self.reference_step(second_prompt)
            self.assert_logits("interleave-B-prefill", second.step(second_prompt),
                               expected_second[:, -1:, :])
            for step in range(4):
                first_token = self.ids(1, offset=300 + step)
                second_token = self.ids(1, offset=600 + step)
                expected_second, cache_second = self.reference_step(second_token, cache_second)
                self.assert_logits(f"interleave-B-{step}", second.step(second_token), expected_second)
                expected_first, cache_first = self.reference_step(first_token, cache_first)
                self.assert_logits(f"interleave-A-{step}", first.step(first_token), expected_first)
            self.assertEqual(first.position, 11)
            self.assertEqual(second.position, 132)
            first.close()
            token = self.ids(1, offset=1111)
            expected_second, cache_second = self.reference_step(token, cache_second)
            self.assert_logits("interleave-B-after-A-close", second.step(token), expected_second)
            self.assertEqual(second.position, 133)

    def test_greedy_sequences_match_with_independent_feedback(self):
        for prompt_length in (1, 128):
            with self.subTest(prompt_length=prompt_length), \
                    self.pipeline.open_session(prompt_length + 16) as session:
                pipeline_ids = reference_ids = self.ids(prompt_length, offset=137)
                cache = None
                actual_tokens, expected_tokens = [], []
                divergences = []
                for step in range(16):
                    expected, cache = self.reference_step(reference_ids, cache)
                    actual = session.step(pipeline_ids)
                    actual_token = int(actual[0, -1].argmax())
                    expected_token = int(expected[0, -1].argmax())
                    actual_tokens.append(actual_token)
                    expected_tokens.append(expected_token)
                    if actual_token != expected_token:
                        divergences.append({
                            "step": step,
                            "pipeline_top_two": self.torch.topk(actual[0, -1], 2).values.tolist(),
                            "reference_top_two": self.torch.topk(expected[0, -1], 2).values.tolist(),
                            "pipeline_token": actual_token, "reference_token": expected_token,
                        })
                    pipeline_ids = self.torch.tensor([[actual_token]], dtype=self.torch.long)
                    reference_ids = self.torch.tensor([[expected_token]], dtype=self.torch.long)
                record = {"prompt_length": prompt_length, "pipeline_tokens": actual_tokens,
                          "reference_tokens": expected_tokens, "divergences": divergences}
                self.evidence["greedy"].append(record)
                self.assertEqual(actual_tokens, expected_tokens, json.dumps(record))

    def test_exact_context_limit_and_rejection_preserve_committed_cache(self):
        with self.pipeline.open_session(MAX_LENGTH) as session:
            prompt = self.ids(MAX_LENGTH - 1, offset=29)
            expected, cache = self.reference_step(prompt)
            self.assert_logits("context-1151", session.step(prompt), expected[:, -1:, :])
            token = self.ids(1, offset=31)
            expected, cache = self.reference_step(token, cache)
            self.assert_logits("context-1152", session.step(token), expected)
            self.assertEqual(session.position, MAX_LENGTH)
            before = session.diagnostics()
            with self.assertRaises(ValueError):
                session.step(token)
            self.assertEqual(session.position, MAX_LENGTH)
            self.assertEqual(session.diagnostics(), before)

    def test_invalid_input_is_rejected_before_mutating_session(self):
        torch = self.torch
        with self.pipeline.open_session(32) as session:
            prompt = self.ids(7)
            expected, cache = self.reference_step(prompt)
            self.assert_logits("invalid-prefill", session.step(prompt), expected[:, -1:, :])
            invalid_inputs = [
                torch.tensor([1, 2], dtype=torch.long),
                torch.tensor([[1], [2]], dtype=torch.long),
                torch.empty((1, 0), dtype=torch.long),
                torch.tensor([[1.0]], dtype=torch.float32),
                torch.tensor([[1]], dtype=torch.int32),
                torch.tensor([[-1]], dtype=torch.long),
                torch.tensor([[self.reference.config.vocab_size]], dtype=torch.long),
            ]
            for invalid in invalid_inputs:
                before = session.diagnostics()
                with self.subTest(shape=list(invalid.shape), dtype=str(invalid.dtype)), \
                        self.assertRaises((ValueError, TypeError)):
                    session.step(invalid)
                self.assertEqual(session.position, 7)
                self.assertEqual(session.diagnostics(), before)
            token = self.ids(1, offset=411)
            expected, cache = self.reference_step(token, cache)
            self.assert_logits("after-invalid-input", session.step(token), expected)

    def test_invalid_reservations_do_not_consume_capacity(self):
        before = self.pipeline.diagnostics()
        for maximum in (0, -1, MAX_LENGTH + 1, True, 1.5):
            with self.subTest(maximum=maximum), self.assertRaises((ValueError, TypeError)):
                self.pipeline.open_session(maximum)
            self.assertEqual(self.pipeline.diagnostics(), before)

    def test_close_is_idempotent_and_context_manager_cleans_up_on_error(self):
        before = self.pipeline.diagnostics()
        with self.assertRaisesRegex(RuntimeError, "test cancellation"):
            with self.pipeline.open_session(32) as session:
                session.step(self.ids(7))
                raise RuntimeError("test cancellation")
        self.assertEqual(self.pipeline.diagnostics(), before)
        session.close()
        self.assertEqual(self.pipeline.diagnostics(), before)
        with self.assertRaises(RuntimeError):
            session.step(self.ids(1))

    def test_eight_sessions_reserve_and_release_cache_independently(self):
        baseline = self.pipeline.diagnostics()
        self.assertEqual(baseline["active_sessions"], 0)
        self.assertEqual(baseline["allocated_cache_bytes"], 0)
        self.assertEqual(baseline["reserved_positions"], 0)
        with ExitStack() as cleanup:
            sessions = [cleanup.enter_context(self.pipeline.open_session(32)) for _ in range(8)]
            before_excess = self.pipeline.diagnostics()
            self.assertEqual(before_excess["active_sessions"], 8)
            self.assertEqual(before_excess["reserved_positions"], 8 * 32)
            with self.assertRaises(RuntimeError):
                self.pipeline.open_session(32)
            self.assertEqual(self.pipeline.diagnostics(), before_excess)
            allocated = 0
            for index, session in enumerate(sessions):
                count = index + 1
                session.step(self.ids(count, offset=97 * index))
                diagnostic = session.diagnostics()
                self.assertEqual(diagnostic["position"], count)
                self.assertEqual(diagnostic["max_length"], 32)
                self.assertFalse(diagnostic["closed"])
                self.assertEqual([(s["start"], s["end"]) for s in diagnostic["stages"]],
                                 list(ASSIGNMENTS))
                for stage in diagnostic["stages"]:
                    self.assertEqual(stage["logical_length"], count)
                    self.assertEqual(stage["reserved_positions"], 32)
                    self.assertGreater(stage["allocated_bytes"], 0)
                    allocated += stage["allocated_bytes"]
            self.assertEqual(self.pipeline.diagnostics()["allocated_cache_bytes"], allocated)
            self.evidence["eight_session_diagnostics"] = self.pipeline.diagnostics()
            released = sum(s["allocated_bytes"] for s in sessions[0].diagnostics()["stages"])
            sessions[0].close()
            after_close = self.pipeline.diagnostics()
            self.assertEqual(after_close["active_sessions"], 7)
            self.assertEqual(after_close["reserved_positions"], 7 * 32)
            self.assertEqual(after_close["allocated_cache_bytes"], allocated - released)
            closed = sessions[0].diagnostics()
            self.assertTrue(closed["closed"])
            self.assertTrue(all(s["allocated_bytes"] == 0 for s in closed["stages"]))
            self.assertTrue(all(s["reserved_positions"] == 0 for s in closed["stages"]))
            replacement = cleanup.enter_context(self.pipeline.open_session(32))
            replacement.step(self.ids(1))
            self.assertEqual(self.pipeline.diagnostics()["active_sessions"], 8)
        self.assertEqual(self.pipeline.diagnostics(), baseline)

    def test_parameters_reside_only_in_their_assigned_components(self):
        expected = dict(self.reference.named_parameters(remove_duplicate=False))
        inventory = self.pipeline.parameter_inventory()
        self.assertEqual(len(inventory), 4)
        observed_names = set()
        layer_groups, coordinator_groups = [], []
        observed_storages = {}
        for component, parameters in inventory.items():
            self.assertTrue(parameters, component)
            owned_layers, non_layer_names = set(), []
            for parameter in parameters:
                name = parameter["name"]
                self.assertNotIn(name, observed_names, f"Duplicate ownership of {name}")
                observed_names.add(name)
                self.assertIn(name, expected)
                self.assertEqual(list(parameter["shape"]), list(expected[name].shape))
                self.assertEqual(parameter["numel"], expected[name].numel())
                self.assertGreater(parameter["data_ptr"], 0)
                previous = observed_storages.setdefault(parameter["data_ptr"], name)
                # Tied weights are allowed only if the complete model ties the same names.
                self.assertEqual(expected[name].data_ptr(), expected[previous].data_ptr(),
                                 f"Unexpected shared parameter storage: {name}, {previous}")
                layer = re.match(r"model\.layers\.(\d+)\.", name)
                if layer:
                    owned_layers.add(int(layer.group(1)))
                else:
                    non_layer_names.append(name)
            if owned_layers:
                self.assertEqual(non_layer_names, [], component)
                layer_groups.append(frozenset(owned_layers))
            else:
                coordinator_groups.append(set(non_layer_names))
        self.assertEqual(observed_names, set(expected))
        self.assertCountEqual(layer_groups, [frozenset(range(start, end))
                                            for start, end in ASSIGNMENTS])
        self.assertEqual(coordinator_groups, [{"model.embed_tokens.weight",
                                              "model.norm.weight", "lm_head.weight"}])
        self.evidence["parameter_counts"] = {
            component: sum(p["numel"] for p in parameters)
            for component, parameters in inventory.items()
        }

    def test_compute_failure_releases_mutated_cache_without_harming_another_session(self):
        baseline = self.pipeline.diagnostics()
        with self.pipeline.open_session(32) as survivor, \
                self.pipeline.open_session(32) as failing:
            prompt = self.ids(7, offset=827)
            expected, cache = self.reference_step(prompt)
            self.assert_logits("failure-survivor-prefill", survivor.step(prompt), expected[:, -1:, :])
            with patch.object(self.pipeline.stages[1], "forward",
                              side_effect=RuntimeError("injected compute failure")):
                with self.assertRaisesRegex(RuntimeError, "injected compute failure"):
                    failing.step(self.ids(11))
            self.assertTrue(failing.diagnostics()["closed"])
            self.assertTrue(all(s["allocated_bytes"] == 0
                                for s in failing.diagnostics()["stages"]))
            self.assertEqual(self.pipeline.diagnostics()["active_sessions"], 1)
            with self.assertRaises(RuntimeError):
                failing.step(self.ids(1))
            token = self.ids(1, offset=828)
            expected, cache = self.reference_step(token, cache)
            self.assert_logits("failure-survivor-decode", survivor.step(token), expected)
        self.assertEqual(self.pipeline.diagnostics(), baseline)


if __name__ == "__main__":
    unittest.main()
