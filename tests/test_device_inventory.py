import unittest
from unittest import mock

from lab import device_inventory


def configuration(capacities=(100, 100, 100, 100)):
    return {
        "model": "future-model-revision-pinned-by-caller",
        "revision": "sha-or-version-selected-by-caller",
        "precision": "caller-specified",
        "devices": [{"usable_bytes": value, "capacity_basis": "measured", "memory_kind": "vram"}
                    for value in capacities],
        "assignments": {"coordinator": 0, "worker-1": 1, "worker-2": 2, "worker-3": 3},
        "components": [
            {"name": "coordinator-embed", "placement": "coordinator",
             "owns": ["input_embeddings"], "weight_bytes": 10, "kv_cache_bytes": 0,
             "temporary_headroom_bytes": 0, "budget_basis": "measured"},
            {"name": "coordinator-norm", "placement": "coordinator",
             "owns": ["final_norm"], "weight_bytes": 2, "kv_cache_bytes": 0,
             "temporary_headroom_bytes": 0, "budget_basis": "measured"},
            {"name": "coordinator-head", "placement": "coordinator",
             "owns": ["output_head"], "weight_bytes": 12, "kv_cache_bytes": 0,
             "temporary_headroom_bytes": 0, "budget_basis": "measured"},
            {"name": "stage-1", "placement": "worker-1", "owns": ["layers[0:3]"],
             "layer_range": [0, 3], "weight_bytes": 30, "kv_cache_bytes": 30,
             "temporary_headroom_bytes": 10, "budget_basis": "estimated"},
            {"name": "stage-2", "placement": "worker-2", "owns": ["layers[3:6]"],
             "layer_range": [3, 6], "weight_bytes": 30, "kv_cache_bytes": 30,
             "temporary_headroom_bytes": 10, "budget_basis": "estimated"},
            {"name": "stage-3", "placement": "worker-3", "owns": ["layers[6:8]"],
             "layer_range": [6, 8], "weight_bytes": 20, "kv_cache_bytes": 20,
             "temporary_headroom_bytes": 10, "budget_basis": "estimated"},
        ],
    }


class DeviceInventoryTests(unittest.TestCase):
    def test_boundary_fits_and_returns_separate_stage_budgets(self):
        config = configuration((24, 70, 70, 50))
        result = device_inventory.plan_fit(config)
        self.assertEqual(result["placements"]["coordinator"]["required_bytes"], 24)
        self.assertEqual(result["placements"]["worker-1"]["required_bytes"], 70)
        self.assertTrue(result["assigned_stage_fit"])
        self.assertTrue(result["aggregate_capacity_fit"])
        self.assertFalse(result["single_device_fit"])
        self.assertEqual(result["component_budget_basis"], ["estimated", "measured"])

    def test_tied_embedding_and_head_are_counted_once_as_one_explicit_component(self):
        config = configuration()
        config["components"] = [c for c in config["components"]
                                if c["name"] not in ("coordinator-embed", "coordinator-head")]
        config["components"].insert(0, {
            "name": "coordinator-tied-embed-head", "placement": "coordinator",
            "owns": ["input_embeddings", "output_head"], "weight_bytes": 12,
            "kv_cache_bytes": 0, "temporary_headroom_bytes": 0,
            "budget_basis": "measured"})
        result = device_inventory.plan_fit(config)
        self.assertEqual(result["placements"]["coordinator"]["weights_bytes"], 14)

    def test_coordinator_omission_is_rejected(self):
        config = configuration()
        config["components"] = [c for c in config["components"] if c["name"] != "coordinator-head"]
        with self.assertRaisesRegex(ValueError, "coordinator must explicitly account"):
            device_inventory.plan_fit(config)

    def test_kv_cache_and_temporary_headroom_are_included_in_fit(self):
        config = configuration((100, 69, 100, 100))
        result = device_inventory.plan_fit(config)
        self.assertEqual(result["placements"]["worker-1"]["required_bytes"], 70)
        self.assertFalse(result["assigned_stage_fit"])
        config["components"][3]["kv_cache_bytes"] = 29
        result = device_inventory.plan_fit(config)
        self.assertTrue(result["assigned_stage_fit"])

    def test_aggregate_capacity_does_not_claim_single_device_or_assignment_fit(self):
        config = configuration((60, 60, 60, 60))
        result = device_inventory.plan_fit(config)
        self.assertTrue(result["aggregate_capacity_fit"])
        self.assertFalse(result["single_device_fit"])
        self.assertFalse(result["assigned_stage_fit"])

    def test_colocated_stages_must_fit_the_sum_on_the_assigned_device(self):
        config = configuration((24, 100, 60, 500, 500))
        config["assignments"]["worker-2"] = 1
        result = device_inventory.plan_fit(config)
        self.assertTrue(result["placements"]["worker-1"]["fits"])
        self.assertTrue(result["placements"]["worker-2"]["fits"])
        self.assertTrue(result["aggregate_capacity_fit"])
        self.assertFalse(result["assigned_stage_fit"])
        self.assertFalse(result["devices"][1]["assigned_fit"])

    def test_aggregate_capacity_does_not_mix_ram_and_vram(self):
        config = configuration((24, 100, 100, 100))
        config["devices"][0]["memory_kind"] = "ram"
        config["assignments"] = {"coordinator": 0, "worker-1": 1,
                                  "worker-2": 1, "worker-3": 1}
        config["devices"] = config["devices"][:2]
        result = device_inventory.plan_fit(config)
        self.assertFalse(result["aggregate_capacity_fit"])

    def test_single_device_fit_is_unavailable_for_mixed_ram_and_vram_components(self):
        config = configuration((100, 500, 500, 500))
        config["devices"][0]["memory_kind"] = "ram"
        result = device_inventory.plan_fit(config)
        self.assertIsNone(result["single_device_fit"])
        self.assertIn("both RAM and VRAM", result["single_device_fit_unavailable_reason"])
        self.assertIsInstance(result["whole_budget_single_pool_fit"], bool)

    def test_layer_ranges_can_cover_a_larger_model_with_three_contiguous_partitions(self):
        config = configuration()
        config["total_layers"] = 10
        config["layer_ranges"] = {"worker-1": [0, 4], "worker-2": [4, 7],
                                  "worker-3": [7, 10]}
        config["components"][3]["layer_range"] = [0, 4]
        config["components"][3]["owns"] = ["layers[0:4]"]
        config["components"][4]["layer_range"] = [4, 7]
        config["components"][4]["owns"] = ["layers[4:7]"]
        config["components"][5]["layer_range"] = [7, 10]
        config["components"][5]["owns"] = ["layers[7:10]"]
        self.assertEqual(device_inventory.plan_fit(config)["total_layers"], 10)
        config["layer_ranges"]["worker-2"] = [3, 7]
        with self.assertRaisesRegex(ValueError, "contiguous, nonoverlapping"):
            device_inventory.plan_fit(config)

    def test_missing_coordinator_or_worker_assignment_is_rejected(self):
        config = configuration()
        del config["assignments"]["coordinator"]
        with self.assertRaisesRegex(ValueError, "assignments must map"):
            device_inventory.plan_fit(config)

    def test_worker_range_must_match_fixed_contiguous_partition(self):
        config = configuration()
        config["components"][3]["layer_range"] = [0, 2]
        with self.assertRaisesRegex(ValueError, "fixed contiguous range"):
            device_inventory.plan_fit(config)

    def test_unknown_nvidia_inventory_does_not_invent_free_vram(self):
        with mock.patch.object(device_inventory.shutil, "which", return_value=None):
            gpu = device_inventory._gpus()
        self.assertEqual(gpu["status"], "unknown")
        self.assertEqual(gpu["devices"], [])
        self.assertIn("not established", gpu["reason"])

    def test_gpu_query_rejects_negative_or_impossible_free_memory(self):
        with mock.patch.object(device_inventory.shutil, "which", return_value="nvidia-smi"), \
             mock.patch.object(device_inventory, "_run", return_value="GPU,100,101,driver"):
            gpu = device_inventory._gpus()
        self.assertEqual(gpu["status"], "unknown")
        self.assertEqual(gpu["devices"], [])

    def test_inventory_marks_unavailable_memory_and_unsupported_gpu_unknown(self):
        unknown_gpu = {"status": "unknown", "reason": "unsupported vendor", "devices": []}
        with mock.patch.object(device_inventory, "_memory", return_value=None), \
             mock.patch.object(device_inventory, "_gpus", return_value=unknown_gpu), \
             mock.patch.object(device_inventory, "_cpu_name", return_value="test CPU"):
            result = device_inventory.collect_inventory()
        self.assertIsNone(result["memory"])
        self.assertEqual(result["gpu"]["status"], "unknown")
        self.assertNotIn("hostname", result)
        self.assertNotIn("serial", result)
        self.assertIn("observed_at_utc", result)


if __name__ == "__main__":
    unittest.main()
