"""Dependency-free validation tests; synthetic hashes never identify real weights."""

from copy import deepcopy
from dataclasses import asdict, replace
import json
from pathlib import Path
import tempfile
import unittest

from steamboat_runtime.manifest import (
    MODEL_ID, MODEL_REVISION, LAYER_RANGES, SOURCE_HASHES, PINNED_CONFIG,
    ResourceLimits, artifact_path, cache_bytes, expected_tensors, fingerprint,
    load_manifest, safe_path, sha256_file, validate_manifest,
)


def sample_manifest():
    components = {}
    files = {name: digest for name, digest in SOURCE_HASHES.items() if name != "model.safetensors"}
    for name in ("coordinator", "worker-1", "worker-2", "worker-3"):
        components[name] = {
            "file": f"{name}.safetensors", "sha256": "a" * 64,
            "layer_range": None if name == "coordinator" else list(LAYER_RANGES[int(name[-1]) - 1]),
            "tensors": expected_tensors(name),
        }
        files[f"{name}.safetensors"] = "a" * 64
    manifest = {
        "schema_version": 1, "model_id": MODEL_ID, "revision": MODEL_REVISION,
        "architecture": "LlamaForCausalLM", "dtype": "float32", "device": "cpu",
        "attention": "eager", "layout": "batch_sequence_hidden", "config": deepcopy(PINNED_CONFIG),
        "limits": asdict(ResourceLimits()), "source_files": dict(SOURCE_HASHES),
        "components": components, "files": files,
    }
    manifest["fingerprint"] = fingerprint(manifest)
    return manifest


class ManifestTests(unittest.TestCase):
    def test_valid_manifest(self):
        validate_manifest(sample_manifest())

    def test_coverage_rejects_gap_overlap_and_bool_index(self):
        for invalid in ([2, 6], [4, 6], [3, 7], [True, 6]):
            with self.subTest(invalid=invalid):
                manifest = sample_manifest()
                manifest["components"]["worker-2"]["layer_range"] = invalid
                manifest["fingerprint"] = fingerprint(manifest)
                with self.assertRaisesRegex(ValueError, "assignments"):
                    validate_manifest(manifest)

    def test_identity_and_source_hashes_are_pinned_even_when_resigned(self):
        for key, value in (("revision", "b" * 40), ("model_id", "different/model"),
                           ("dtype", "float16"), ("attention", "sdpa"),
                           ("architecture", "BloomForCausalLM"), ("schema_version", True)):
            with self.subTest(key=key):
                manifest = sample_manifest()
                manifest[key] = value
                manifest["fingerprint"] = fingerprint(manifest)
                with self.assertRaises(ValueError):
                    validate_manifest(manifest)
        manifest = sample_manifest()
        manifest["source_files"]["model.safetensors"] = "b" * 64
        manifest["fingerprint"] = fingerprint(manifest)
        with self.assertRaisesRegex(ValueError, "pinned revision"):
            validate_manifest(manifest)

    def test_wrong_tensor_keys_shape_dtype_and_owner_fail(self):
        for change in ("shape", "dtype", "key", "owner"):
            manifest = sample_manifest()
            tensors = manifest["components"]["worker-1"]["tensors"]
            key = next(iter(tensors))
            if change == "shape":
                tensors[key]["shape"] = [1, 64]
            elif change == "dtype":
                tensors[key]["dtype"] = "BF16"
            elif change == "key":
                tensors["other.weight"] = tensors.pop(key)
            else:
                tensors["model.layers.3.input_layernorm.weight"] = tensors.pop(key)
            manifest["fingerprint"] = fingerprint(manifest)
            with self.subTest(change=change), self.assertRaisesRegex(ValueError, "tensor keys"):
                validate_manifest(manifest)

    def test_fingerprint_detects_unsigned_mutation(self):
        manifest = sample_manifest()
        manifest["limits"]["max_sessions"] = 4
        with self.assertRaisesRegex(ValueError, "fingerprint"):
            validate_manifest(manifest)

    def test_traversal_absolute_and_windows_paths_fail(self):
        with tempfile.TemporaryDirectory() as folder:
            for value in ("../outside", "/absolute", "C:/absolute", "C:relative",
                          "..\\outside", "sub/../outside", "./same", ""):
                with self.subTest(path=value), self.assertRaises(ValueError):
                    safe_path(folder, value)
            manifest = sample_manifest()
            manifest["components"]["worker-1"]["file"] = "../escape.safetensors"
            with self.assertRaises(ValueError):
                artifact_path(folder, manifest, "worker-1")

    def test_symlink_escape_fails_when_supported(self):
        with tempfile.TemporaryDirectory() as folder, tempfile.TemporaryDirectory() as outside:
            link = Path(folder) / "link"
            try:
                link.symlink_to(outside, target_is_directory=True)
            except OSError:
                self.skipTest("symlink creation is unavailable on this host")
            with self.assertRaises(ValueError):
                safe_path(folder, "link/weights")

    def test_missing_and_tampered_artifacts_fail(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            manifest = sample_manifest()
            (root / "modelmanifest.json").write_text(json.dumps(manifest), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "missing artifact"):
                load_manifest(root)
            for name in manifest["files"]:
                (root / name).write_bytes(b"corrupt bytes")
            with self.assertRaisesRegex(ValueError, "hash mismatch"):
                load_manifest(root)

    def test_hash_and_fingerprint_are_stable(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "sample"
            path.write_bytes(b"abc")
            self.assertEqual(sha256_file(path), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
        manifest = sample_manifest()
        self.assertEqual(fingerprint(dict(reversed(list(manifest.items())))), manifest["fingerprint"])


class ResourceLimitTests(unittest.TestCase):
    def test_exact_kv_storage_and_default_reservations(self):
        limits = ResourceLimits().validate(PINNED_CONFIG)
        self.assertEqual(cache_bytes(PINNED_CONFIG, 3, 1152, 8), 14155776)
        self.assertGreaterEqual(limits.worker_cache_bytes, 14155776)

    def test_invalid_scalar_and_oversized_reservations_fail(self):
        variants = [replace(ResourceLimits(), max_sessions=value) for value in (0, -1, True, 1.5, 9)]
        variants += [replace(ResourceLimits(), max_positions=1153),
                     replace(ResourceLimits(), worker_cache_positions=9215),
                     replace(ResourceLimits(), worker_cache_bytes=14155775),
                     replace(ResourceLimits(), worker_memory_bytes=1024),
                     replace(ResourceLimits(), max_message_bytes=294912),
                     replace(ResourceLimits(), max_compute_calls=2),
                     replace(ResourceLimits(), idle_lease_seconds=30),
                     replace(ResourceLimits(), lease_check_interval_seconds=6),
                     replace(ResourceLimits(), request_timeout_seconds=10)]
        for limits in variants:
            with self.subTest(limits=limits), self.assertRaises(ValueError):
                limits.validate(PINNED_CONFIG)

    def test_invalid_model_config_and_dimension_types_fail(self):
        for key, value in (("model_type", "bloom"), ("hidden_size", 65),
                           ("num_hidden_layers", 9), ("bos_token_id", True)):
            config = deepcopy(PINNED_CONFIG)
            config[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                ResourceLimits().validate(config)
        for count in (0, True, 9):
            with self.subTest(count=count), self.assertRaises(ValueError):
                cache_bytes(PINNED_CONFIG, count, 1)


if __name__ == "__main__":
    unittest.main()
