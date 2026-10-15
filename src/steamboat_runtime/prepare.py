"""Create immutable, offline float32 slices from the pinned safetensors model."""

import argparse
from dataclasses import asdict
import json
from pathlib import Path
import shutil
import tempfile

from .manifest import (MODEL_ID, MODEL_REVISION, LAYER_RANGES, SOURCE_HASHES,
                       ResourceLimits, expected_tensors, fingerprint,
                       load_manifest, sha256_file, validate_config, validate_manifest)


def verify_snapshot(snapshot):
    """Verify source bytes before deserializing any config or weight tensors."""
    snapshot = Path(snapshot)
    for name, expected in SOURCE_HASHES.items():
        path = snapshot / name
        if not path.is_file() or sha256_file(path) != expected:
            raise ValueError(f"pinned source hash mismatch: {name}")
    config = json.loads((snapshot / "config.json").read_text(encoding="utf-8"))
    validate_config(config)
    return config


def prepare_artifacts(output, snapshot=None, limits=None):
    """Write verified slices once; validate and reuse an existing complete output.

    A supplied snapshot is held to the same pinned hashes as a downloaded one.
    Only safetensors is read. No pickle-based checkpoint fallback is supported.
    """
    output = Path(output)
    limits = limits or ResourceLimits()
    if output.exists() and any(output.iterdir()):
        existing = load_manifest(output)
        if existing["limits"] != asdict(limits):
            raise ValueError("existing artifact resource limits differ; use a new output directory")
        return existing
    if snapshot is None:
        from huggingface_hub import snapshot_download
        snapshot = snapshot_download(MODEL_ID, revision=MODEL_REVISION,
                                     allow_patterns=list(SOURCE_HASHES))
    snapshot = Path(snapshot)
    config = verify_snapshot(snapshot)
    limits.validate(config)
    from safetensors import safe_open
    from safetensors.torch import save_file
    import torch

    output.parent.mkdir(parents=True, exist_ok=True)
    # Build in a sibling staging directory. A failure leaves no valid manifest.
    with tempfile.TemporaryDirectory(prefix=f".{output.name}-", dir=output.parent) as temporary:
        staging = Path(temporary)
        files = {}
        for name in SOURCE_HASHES:
            if name != "model.safetensors":
                shutil.copyfile(snapshot / name, staging / name)
                files[name] = sha256_file(staging / name)
        components = {}
        names = ("coordinator", "worker-1", "worker-2", "worker-3")
        with safe_open(str(snapshot / "model.safetensors"), framework="pt", device="cpu") as source:
            expected_keys = {key for name in names for key in expected_tensors(name)}
            if set(source.keys()) != expected_keys:
                raise ValueError("checkpoint contains missing or unexpected tensor keys")
            for name in names:
                metadata = expected_tensors(name)
                tensors = {}
                for key, specification in metadata.items():
                    tensor = source.get_tensor(key)
                    if list(tensor.shape) != specification["shape"] or tensor.dtype != torch.bfloat16:
                        raise ValueError(f"checkpoint tensor shape/dtype mismatch: {key}")
                    if not torch.isfinite(tensor).all():
                        raise ValueError(f"checkpoint tensor is non-finite: {key}")
                    tensors[key] = tensor.to(dtype=torch.float32).contiguous()
                filename = f"{name}.safetensors"
                save_file(tensors, str(staging / filename))
                digest = sha256_file(staging / filename)
                files[filename] = digest
                components[name] = {
                    "file": filename, "sha256": digest,
                    "layer_range": None if name == "coordinator" else list(LAYER_RANGES[int(name[-1]) - 1]),
                    "tensors": metadata,
                }
                del tensors
        manifest = {
            "schema_version": 1, "model_id": MODEL_ID, "revision": MODEL_REVISION,
            "architecture": "LlamaForCausalLM", "dtype": "float32", "device": "cpu",
            "attention": "eager", "layout": "batch_sequence_hidden", "config": config,
            "limits": asdict(limits), "source_files": dict(SOURCE_HASHES),
            "components": components, "files": files,
        }
        manifest["fingerprint"] = fingerprint(manifest)
        validate_manifest(manifest)
        (staging / "modelmanifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n",
                                                   encoding="utf-8")
        load_manifest(staging)
        output.mkdir(exist_ok=True)
        # Refuse racing writers and publish the manifest last.
        for path in sorted(staging.iterdir(), key=lambda p: p.name == "modelmanifest.json"):
            with path.open("rb") as source, (output / path.name).open("xb") as destination:
                shutil.copyfileobj(source, destination)
    return load_manifest(output)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--snapshot", type=Path, help="existing snapshot; all pinned hashes are verified")
    args = parser.parse_args()
    manifest = prepare_artifacts(args.output, args.snapshot)
    print(json.dumps({"output": str(args.output), "model_id": MODEL_ID,
                      "revision": MODEL_REVISION, "fingerprint": manifest["fingerprint"]}))


if __name__ == "__main__":
    main()
