"""Pinned, dependency-free artifact and resource contract for the CPU prototype.

The queue, RPC, lease and supervisor limits are a frozen contract for M2--M4;
declaring them here does not implement a network service or enforce its timers.
"""

from dataclasses import asdict, dataclass
import hashlib
import json
from pathlib import Path, PurePosixPath
import re


MODEL_ID = "Maykeye/TinyLLama-v0"
MODEL_REVISION = "298338802ab94432b917bcce11382aa151aee50f"
LAYER_RANGES = ((0, 3), (3, 6), (6, 8))
SOURCE_HASHES = {
    "model.safetensors": "c302246d91e2854ff350e52a79938a818c203186c2f0671213ce372a0289cd91",
    "config.json": "92d9f842bbff69a6646eb69472d5f342ad832e718c079bf04d605ae4a4634dfd",
    "tokenizer.model": "ab1b681ec7fc02fed5edd3026687d7a692a918c4dd8e150ca2e3994a6229843b",
    "tokenizer_config.json": "be843e84b4b7d0b226b500a22dceabcbbf54b8e8b0dab85a252b0958e230ffbf",
    "special_tokens_map.json": "ff3b4a612c4e447acb02d40071bddd989fe0da87eb5b7fe0dbadfc4f74de7531",
    "tokenizer.json": "608ef1b5bb4bbfe6d3fdff0a5d3a4baaef0fd99fa678311a1e013bf5b37cd2a0",
    "generation_config.json": "e594efa3d5f29e494af0ab38ec7f341f31cdd45a3a570657f260d1f4b5c6ced2",
}
PINNED_CONFIG = {
    "architectures": ["LlamaForCausalLM"], "bos_token_id": 1,
    "eos_token_id": 2, "hidden_act": "silu", "hidden_size": 64,
    "initializer_range": 0.02, "intermediate_size": 256,
    "max_position_embeddings": 2048, "model_type": "llama",
    "num_attention_heads": 16, "num_hidden_layers": 8, "pad_token_id": 0,
    "rms_norm_eps": 1e-6, "tie_word_embeddings": False,
    "torch_dtype": "bfloat16", "transformers_version": "4.30.2",
    "use_cache": True, "vocab_size": 32000,
}


def positive_int(value, name):
    """Reject bool, floats, and coercions at configuration boundaries."""
    if type(value) is not int or value <= 0:
        raise ValueError(f"{name} must be a positive integer")
    return value


def validate_config(config):
    if not isinstance(config, dict) or config != PINNED_CONFIG:
        raise ValueError("only the pinned tiny Llama configuration is supported")
    # Dict equality permits True == 1; canonical JSON does not.
    if canonical_bytes(config) != canonical_bytes(PINNED_CONFIG):
        raise ValueError("model configuration contains invalid value types")


def cache_bytes(config, layer_count, positions, sessions=1):
    """Float32 K+V storage; allocator overhead/temporary attention are separate."""
    validate_config(config)
    for name, value in (("layer_count", layer_count), ("positions", positions),
                        ("sessions", sessions)):
        positive_int(value, name)
    if layer_count > config["num_hidden_layers"]:
        raise ValueError("layer_count exceeds the model")
    if positions > config["max_position_embeddings"]:
        raise ValueError("positions exceed the model context")
    heads = config["num_attention_heads"]
    kv_heads = config.get("num_key_value_heads", heads)
    return sessions * layer_count * positions * 2 * kv_heads * (config["hidden_size"] // heads) * 4


@dataclass(frozen=True)
class ResourceLimits:
    max_sessions: int = 8
    max_positions: int = 1152
    max_compute_calls: int = 1
    max_stage_queue: int = 8
    max_waiting_admissions: int = 32
    admission_timeout_seconds: int = 30
    request_timeout_seconds: int = 300
    rpc_timeout_seconds: int = 30
    output_queue_tokens: int = 16
    output_stall_timeout_seconds: int = 30
    idle_lease_seconds: int = 120
    lease_check_interval_seconds: int = 5
    renew_interval_seconds: int = 30
    compute_cancel_grace_seconds: int = 15
    max_message_bytes: int = 1048576
    worker_cache_positions: int = 12288
    worker_cache_bytes: int = 16777216
    worker_memory_bytes: int = 3221225472

    def validate(self, config):
        validate_config(config)
        for name, value in asdict(self).items():
            positive_int(value, name)
        if self.max_sessions > 8 or self.max_positions > 1152:
            raise ValueError("the initial runtime supports at most 8 sessions and 1152 positions")
        if self.max_compute_calls != 1:
            raise ValueError("one active compute call per worker is supported")
        if self.max_stage_queue > 8 or self.max_waiting_admissions > 32 or self.output_queue_tokens > 16:
            raise ValueError("queue capacity exceeds the initial contract")
        if not self.lease_check_interval_seconds <= 5:
            raise ValueError("idle leases must be checked at least every five seconds")
        if self.renew_interval_seconds + self.lease_check_interval_seconds >= self.idle_lease_seconds:
            raise ValueError("lease renewals must precede idle expiry")
        if max(self.admission_timeout_seconds, self.rpc_timeout_seconds) > self.request_timeout_seconds:
            raise ValueError("admission/RPC timeout exceeds the request budget")
        required = cache_bytes(config, max(stop - start for start, stop in LAYER_RANGES),
                               self.max_positions, self.max_sessions)
        if self.max_positions * self.max_sessions > self.worker_cache_positions:
            raise ValueError("worker cache position capacity cannot cover all session reservations")
        if required > self.worker_cache_bytes:
            raise ValueError(f"worker cache budget cannot reserve {required} bytes")
        weight_bytes = max(sum(_tensor_elements(tensor["shape"]) * 4
                               for tensor in expected_tensors(name).values())
                           for name in ("worker-1", "worker-2", "worker-3"))
        if weight_bytes + self.worker_cache_bytes > self.worker_memory_bytes:
            raise ValueError("worker memory budget cannot contain its weights and cache budget")
        tensor_bytes = self.max_positions * config["hidden_size"] * 4
        if self.max_message_bytes < tensor_bytes + 65536:
            raise ValueError("message ceiling cannot hold the maximum tensor and bounded metadata")
        return self


def canonical_bytes(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("utf-8")


def _tensor_elements(shape):
    result = 1
    for dimension in shape:
        result *= dimension
    return result


def fingerprint(manifest):
    return hashlib.sha256(canonical_bytes({k: v for k, v in manifest.items()
                                          if k != "fingerprint"})).hexdigest()


def sha256_file(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def safe_path(directory, relative):
    """Restrict artifacts to regular children, including across symlinks."""
    if not isinstance(relative, str) or not relative or "\\" in relative or ":" in relative:
        raise ValueError("invalid artifact path")
    part = PurePosixPath(relative)
    if part.is_absolute() or any(p in ("..", ".") for p in relative.split("/")):
        raise ValueError("artifact paths must be relative without traversal")
    root = Path(directory).resolve()
    result = (root / relative).resolve()
    if not result.is_relative_to(root) or result == root:
        raise ValueError("artifact path escapes its directory")
    return result


def expected_tensors(component):
    if component == "coordinator":
        shapes = {"model.embed_tokens.weight": [32000, 64],
                  "model.norm.weight": [64], "lm_head.weight": [32000, 64]}
    elif component in ("worker-1", "worker-2", "worker-3"):
        start, stop = LAYER_RANGES[int(component[-1]) - 1]
        shapes = {}
        for index in range(start, stop):
            prefix = f"model.layers.{index}."
            for name, shape in {
                "input_layernorm.weight": [64], "post_attention_layernorm.weight": [64],
                "self_attn.q_proj.weight": [64, 64], "self_attn.k_proj.weight": [64, 64],
                "self_attn.v_proj.weight": [64, 64], "self_attn.o_proj.weight": [64, 64],
                "self_attn.rotary_emb.inv_freq": [2],
                "mlp.gate_proj.weight": [256, 64], "mlp.up_proj.weight": [256, 64],
                "mlp.down_proj.weight": [64, 256],
            }.items():
                shapes[prefix + name] = shape
    else:
        raise ValueError(f"unknown component {component!r}")
    return {name: {"shape": shape, "dtype": "F32"} for name, shape in shapes.items()}


def validate_manifest(manifest):
    if not isinstance(manifest, dict):
        raise ValueError("manifest must be an object")
    identity = {"schema_version": 1, "model_id": MODEL_ID, "revision": MODEL_REVISION,
                "architecture": "LlamaForCausalLM", "dtype": "float32", "device": "cpu",
                "attention": "eager", "layout": "batch_sequence_hidden"}
    for name, expected in identity.items():
        if type(manifest.get(name)) is not type(expected) or manifest[name] != expected:
            raise ValueError(f"unsupported manifest {name}")
    validate_config(manifest.get("config"))
    try:
        if set(manifest["limits"]) != set(asdict(ResourceLimits())):
            raise ValueError("resource limits must declare every contract field")
        ResourceLimits(**manifest["limits"]).validate(manifest["config"])
    except (KeyError, TypeError) as error:
        raise ValueError("invalid resource limits") from error
    if manifest.get("source_files") != SOURCE_HASHES:
        raise ValueError("checkpoint/tokenizer hashes do not match the pinned revision")
    components = manifest.get("components")
    names = {"coordinator", "worker-1", "worker-2", "worker-3"}
    if not isinstance(components, dict) or set(components) != names:
        raise ValueError("manifest must contain coordinator and three workers")
    files = manifest.get("files")
    if not isinstance(files, dict):
        raise ValueError("manifest files must be an object")
    expected_files = {k: v for k, v in SOURCE_HASHES.items() if k != "model.safetensors"}
    for name, component in components.items():
        if not isinstance(component, dict):
            raise ValueError("component must be an object")
        expected_range = None if name == "coordinator" else list(LAYER_RANGES[int(name[-1]) - 1])
        if canonical_bytes(component.get("layer_range")) != canonical_bytes(expected_range):
            raise ValueError("layer assignments must cover [0,3), [3,6), [6,8) exactly")
        if component.get("file") != f"{name}.safetensors":
            raise ValueError("component artifact path must use its fixed filename")
        if canonical_bytes(component.get("tensors")) != canonical_bytes(expected_tensors(name)):
            raise ValueError(f"invalid tensor keys, shapes or dtypes for {name}")
        digest = component.get("sha256")
        if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise ValueError("invalid component hash")
        expected_files[component["file"]] = digest
    if files != expected_files:
        raise ValueError("artifact file inventory or hashes are inconsistent")
    if manifest.get("fingerprint") != fingerprint(manifest):
        raise ValueError("manifest fingerprint mismatch")


def load_manifest(directory, verify_hashes=True):
    directory = Path(directory)
    with safe_path(directory, "modelmanifest.json").open(encoding="utf-8") as stream:
        manifest = json.load(stream)
    validate_manifest(manifest)
    for relative, expected in manifest["files"].items():
        path = safe_path(directory, relative)
        if not path.is_file():
            raise ValueError(f"missing artifact {relative}")
        if verify_hashes and sha256_file(path) != expected:
            raise ValueError(f"artifact hash mismatch: {relative}")
    return manifest


def artifact_path(directory, manifest, component):
    if component not in manifest["components"]:
        raise ValueError(f"unknown component {component!r}")
    return safe_path(directory, manifest["components"][component]["file"])
