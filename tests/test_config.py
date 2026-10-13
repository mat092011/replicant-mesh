"""Configuration and reporting contracts, runnable without inference packages."""

import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from lab import config


class ConfigurationTests(unittest.TestCase):
    def test_default_model_and_revision_are_immutable(self):
        with patch.dict(os.environ, {}, clear=True):
            self.assertEqual(config.model_settings(),
                             (config.DEFAULT_MODEL, config.DEFAULT_REVISION))

    def test_model_override_requires_a_full_checkpoint_sha(self):
        with patch.dict(os.environ, {"MODEL_ID": "example/model", "MODEL_REVISION": "a" * 40}):
            self.assertEqual(config.model_settings(), ("example/model", "a" * 40))
        for revision in ("main", "a" * 39, "a" * 41, "z" * 40):
            with self.subTest(revision=revision), patch.dict(os.environ, {"MODEL_REVISION": revision}):
                with self.assertRaises(ValueError):
                    config.model_settings()

    def test_layer_ranges_are_nonempty_and_nonnegative(self):
        self.assertEqual(config.block_range("0:3"), (0, 3))
        self.assertEqual(config.block_range("6:8"), (6, 8))
        for value in ("-1:3", "3:3", "5:2", "0", "0:2:4", "zero:three"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                config.block_range(value)

    def test_bootstrap_file_is_a_nonempty_string_list(self):
        with tempfile.TemporaryDirectory() as directory:
            peer_file = Path(directory) / "peers.json"
            with patch.object(config, "PEER_FILE", peer_file):
                peers = ["/ip4/172.20.0.2/tcp/31337/p2p/test-peer"]
                peer_file.write_text(json.dumps(peers), encoding="utf-8")
                self.assertEqual(config.read_peers(), peers)
                for value in ([], {}, "peer", [123], ["peer", None]):
                    peer_file.write_text(json.dumps(value), encoding="utf-8")
                    with self.subTest(value=value), self.assertRaises(ValueError):
                        config.read_peers()


class ReportingTests(unittest.TestCase):
    def test_nearest_rank_percentile_sorts_without_mutating_measurements(self):
        values = [4, 1, 3, 2]
        self.assertEqual(config.percentile(values, 50), 2)
        self.assertEqual(config.percentile(values, 95), 4)
        self.assertEqual(config.percentile(values, 100), 4)
        self.assertEqual(values, [4, 1, 3, 2])

    def test_empty_and_single_measurement_percentiles(self):
        self.assertIsNone(config.percentile([], 95))
        self.assertEqual(config.percentile([0.25], 95), 0.25)

    def test_failed_partial_outputs_do_not_inflate_accepted_throughput(self):
        records = [
            {"success": True, "output_tokens": 4, "ttft_seconds": 0.2,
             "inter_token_seconds": [0.1, 0.2, 0.3]},
            {"success": False, "output_tokens": 3, "ttft_seconds": 90,
             "inter_token_seconds": [80, 90]},
            {"success": True, "output_tokens": 2, "ttft_seconds": 0.4,
             "inter_token_seconds": [0.4]},
        ]
        result = config.summarize_requests(records, 2)
        self.assertEqual((result["attempted"], result["completed"], result["failed"]), (3, 2, 1))
        self.assertEqual(result["accepted_output_tokens"], 6)
        self.assertEqual(result["aggregate_output_tokens_per_second"], 3)
        self.assertEqual(result["ttft_seconds_p50"], 0.2)
        self.assertEqual(result["ttft_seconds_p95"], 0.4)
        self.assertEqual(result["inter_token_seconds_p50"], 0.2)
        self.assertEqual(result["inter_token_seconds_p95"], 0.4)

    def test_all_failed_run_has_no_success_latency_estimates(self):
        result = config.summarize_requests([{"success": False, "output_tokens": 2}], 5)
        self.assertEqual(result["failed"], 1)
        self.assertEqual(result["accepted_output_tokens"], 0)
        self.assertEqual(result["aggregate_output_tokens_per_second"], 0)
        self.assertIsNone(result["ttft_seconds_p50"])
        self.assertIsNone(result["inter_token_seconds_p95"])

    def test_zero_duration_does_not_report_infinite_throughput(self):
        result = config.summarize_requests([], 0)
        self.assertIsNone(result["aggregate_output_tokens_per_second"])

    def test_single_output_request_has_no_decode_interval(self):
        result = config.summarize_requests([
            {"success": True, "output_tokens": 1, "ttft_seconds": 0.5,
             "inter_token_seconds": []},
        ], 1)
        self.assertEqual(result["accepted_output_tokens"], 1)
        self.assertIsNone(result["inter_token_seconds_p50"])


if __name__ == "__main__":
    unittest.main()
