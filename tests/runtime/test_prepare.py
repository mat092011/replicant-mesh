"""Source integrity checks plus opt-in real-checkpoint artifact preparation."""

from dataclasses import replace
import os
from pathlib import Path
import tempfile
import unittest

from replicant_mesh.manifest import ResourceLimits, SOURCE_HASHES, load_manifest
from replicant_mesh.prepare import prepare_artifacts, verify_snapshot


class PreparationValidationTests(unittest.TestCase):
    def test_missing_snapshot_rejected_before_loading_libraries(self):
        with tempfile.TemporaryDirectory() as folder:
            with self.assertRaisesRegex(ValueError, "pinned source hash mismatch"):
                verify_snapshot(folder)

    def test_corrupt_source_is_not_trusted_by_snapshot_path(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "model.safetensors").write_bytes(b"wrong weights")
            with self.assertRaisesRegex(ValueError, "model.safetensors"):
                prepare_artifacts(root / "output", snapshot=root)
            self.assertFalse((root / "output").exists())

    def test_partial_existing_output_is_not_overwritten(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "keep.txt"
            path.write_text("unrelated work", encoding="utf-8")
            with self.assertRaises(FileNotFoundError):
                prepare_artifacts(folder, snapshot="unused")
            self.assertEqual(path.read_text(encoding="utf-8"), "unrelated work")


@unittest.skipUnless(os.environ.get("REPLICANT_MESH_TEST_SNAPSHOT"),
                     "set REPLICANT_MESH_TEST_SNAPSHOT to the verified pinned snapshot for artifact integration")
class PreparationIntegrationTests(unittest.TestCase):
    def test_real_slices_are_reusable_and_detect_tampering(self):
        from safetensors import safe_open
        with tempfile.TemporaryDirectory() as folder:
            output = Path(folder) / "artifacts"
            manifest = prepare_artifacts(output, os.environ["REPLICANT_MESH_TEST_SNAPSHOT"])
            self.assertEqual(load_manifest(output), manifest)
            self.assertEqual(prepare_artifacts(output), manifest)
            with self.assertRaisesRegex(ValueError, "limits differ"):
                prepare_artifacts(output, limits=replace(ResourceLimits(), max_sessions=4))
            self.assertEqual(manifest["source_files"], SOURCE_HASHES)
            self.assertNotIn("model.safetensors", manifest["files"])
            for component in manifest["components"].values():
                with safe_open(str(output / component["file"]), framework="pt") as weights:
                    self.assertEqual(set(weights.keys()), set(component["tensors"]))
                    for name, expected in component["tensors"].items():
                        self.assertEqual(weights.get_slice(name).get_shape(), expected["shape"])
                        self.assertEqual(weights.get_slice(name).get_dtype(), "F32")
            (output / "worker-1.safetensors").write_bytes(b"corrupt")
            with self.assertRaisesRegex(ValueError, "hash mismatch"):
                load_manifest(output)


if __name__ == "__main__":
    unittest.main()
