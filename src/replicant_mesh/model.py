"""Three explicit Llama partitions, executed serially in one process for M1.

The adapter targets the locked Transformers version. Only the complete-model
control constructs an AutoModel; each stage here instantiates its own layers.
"""

from pathlib import Path
import threading
import time
import uuid

import torch
from torch import nn
from safetensors.torch import load_file
from transformers import LlamaConfig
from transformers.models.llama.modeling_llama import (
    LlamaDecoderLayer, LlamaRMSNorm, LlamaRotaryEmbedding,
)

from .manifest import artifact_path, load_manifest


class LayerCache:
    """Cache keyed by original global layer IDs, confined to one session/stage."""

    def __init__(self, start, end):
        self.start, self.end = start, end
        self.entries = {}
        self.expected_position = 0

    def update(self, keys, values, layer_idx, *args, **kwargs):
        if not self.start <= layer_idx < self.end:
            raise RuntimeError("Layer attempted to write outside its cache assignment")
        previous = self.entries.get(layer_idx)
        length = 0 if previous is None else previous[0].shape[-2]
        if length != self.expected_position:
            raise RuntimeError("Cache position mismatch before layer update")
        if previous is not None:
            keys = torch.cat((previous[0], keys), dim=-2)
            values = torch.cat((previous[1], values), dim=-2)
        self.entries[layer_idx] = (keys, values)
        return keys, values

    def lengths(self):
        return [self.entries[i][0].shape[-2] if i in self.entries else 0
                for i in range(self.start, self.end)]

    def allocated_bytes(self):
        return sum(t.numel() * t.element_size() for pair in self.entries.values() for t in pair)

    def clear(self):
        self.entries.clear()


class LayerStage(nn.Module):
    def __init__(self, config, start, end, weights):
        super().__init__()
        self.start, self.end = start, end
        self.layers = nn.ModuleDict({str(i): LlamaDecoderLayer(config, i) for i in range(start, end)})
        self.rotary = LlamaRotaryEmbedding(config)
        self.ignored_derived_buffers = []
        for i in range(start, end):
            prefix = f"model.layers.{i}."
            state = {name[len(prefix):]: value for name, value in weights.items() if name.startswith(prefix)}
            # This exact legacy buffer is stored in the BF16 source checkpoint.
            # Current Transformers derives it from config. Verify before omitting.
            legacy = state.pop("self_attn.rotary_emb.inv_freq", None)
            if legacy is not None:
                expected = self.rotary.inv_freq.to(torch.bfloat16).float()
                if not torch.equal(legacy, expected):
                    raise ValueError("Legacy RoPE buffer disagrees with the pinned configuration")
                self.ignored_derived_buffers.append(prefix + "self_attn.rotary_emb.inv_freq")
            self.layers[str(i)].load_state_dict(state, strict=True)
        accepted = {f"model.layers.{i}.{name}" for i in range(start, end)
                    for name in self.layers[str(i)].state_dict()} | set(self.ignored_derived_buffers)
        if set(weights) != accepted:
            raise ValueError("Stage artifact contains missing or unassigned tensors")
        self.float().eval().requires_grad_(False)

    def forward(self, hidden, cache, position):
        count = hidden.shape[1]
        if any(length != position for length in cache.lengths()):
            raise RuntimeError("Stage cache does not match the session position")
        positions = torch.arange(position, position + count, device=hidden.device).unsqueeze(0)
        # Every query may attend to the committed prefix and to preceding tokens
        # in this same call, never future positions. No padding/batching in M1.
        keys = torch.arange(position + count, device=hidden.device)
        future = keys.unsqueeze(0) > positions.squeeze(0).unsqueeze(1)
        mask = torch.zeros((count, position + count), dtype=hidden.dtype, device=hidden.device)
        mask.masked_fill_(future, torch.finfo(hidden.dtype).min)
        mask = mask.unsqueeze(0).unsqueeze(0)
        embeddings = self.rotary(hidden, positions)
        cache.expected_position = position
        for layer in self.layers.values():
            hidden = layer(hidden, attention_mask=mask, position_ids=positions,
                           past_key_values=cache, use_cache=True, position_embeddings=embeddings)
        if any(length != position + count for length in cache.lengths()):
            raise RuntimeError("Stage did not advance all owned layer caches")
        return hidden


class InputOutput(nn.Module):
    def __init__(self, config, weights):
        super().__init__()
        self.embed_tokens = nn.Embedding(config.vocab_size, config.hidden_size, config.pad_token_id)
        self.norm = LlamaRMSNorm(config.hidden_size, eps=config.rms_norm_eps)
        self.lm_head = nn.Linear(config.hidden_size, config.vocab_size, bias=False)
        mapped = {name.removeprefix("model."): value for name, value in weights.items()}
        if config.tie_word_embeddings:
            self.lm_head.weight = self.embed_tokens.weight
            if "lm_head.weight" in mapped and not torch.equal(mapped["lm_head.weight"], mapped["embed_tokens.weight"]):
                raise ValueError("Tied embedding/head tensors disagree")
            mapped.setdefault("lm_head.weight", mapped["embed_tokens.weight"])
        self.load_state_dict(mapped, strict=True)
        self.float().eval().requires_grad_(False)


class PipelineModel:
    """Resident partitions with bounded sessions; no remote calls or scheduler yet."""

    runtime_backend = "pytorch"

    def __init__(self, directory):
        started = time.perf_counter()
        self.directory = Path(directory)
        self.manifest = load_manifest(self.directory)
        self.config = LlamaConfig.from_dict(self.manifest["config"])
        self.config._attn_implementation = "eager"
        self.limits = self.manifest["limits"]
        self.lock = threading.RLock()
        self.sessions = {}
        self.input_output = InputOutput(self.config, load_file(
            str(artifact_path(self.directory, self.manifest, "coordinator")), device="cpu"))
        self.stages = []
        for name in ("worker-1", "worker-2", "worker-3"):
            start, end = self.manifest["components"][name]["layer_range"]
            self.stages.append(LayerStage(self.config, start, end, load_file(
                str(artifact_path(self.directory, self.manifest, name)), device="cpu")))
        self.loading_seconds = time.perf_counter() - started

    def eval(self):
        return self

    def open_session(self, max_length):
        if type(max_length) is not int or not 1 <= max_length <= self.limits["max_positions"]:
            raise ValueError("Session context reservation is outside the configured limit")
        with self.lock:
            if len(self.sessions) >= self.limits["max_sessions"]:
                raise RuntimeError("Session capacity exhausted")
            reserved = sum(session.max_length for session in self.sessions.values())
            if reserved + max_length > self.limits["worker_cache_positions"]:
                raise RuntimeError("Cache reservation capacity exhausted")
            session = PipelineSession(self, max_length)
            self.sessions[session.session_id] = session
            return session

    def diagnostics(self):
        with self.lock:
            sessions = list(self.sessions.values())
            reserved = sum(s.max_length for s in sessions)
            stages = [{"start": stage.start, "end": stage.end,
                       "active_sessions": len(sessions), "reserved_positions": reserved,
                       "allocated_bytes": sum(s.caches[i].allocated_bytes() for s in sessions)}
                      for i, stage in enumerate(self.stages)]
            return {"active_sessions": len(sessions), "reserved_positions": reserved,
                    "allocated_cache_bytes": sum(s["allocated_bytes"] for s in stages), "stages": stages,
                    "execution": "in_process_serialized", "manifest_fingerprint": self.manifest["fingerprint"]}

    def parameter_inventory(self):
        def describe(name, parameter):
            return {"name": name, "shape": list(parameter.shape), "numel": parameter.numel(),
                    "data_ptr": parameter.data_ptr(), "bytes": parameter.numel() * parameter.element_size()}
        inventory = {"coordinator": [describe(name if name.startswith("lm_head.") else "model." + name, p)
                                      for name, p in self.input_output.named_parameters(remove_duplicate=False)]}
        for i, stage in enumerate(self.stages, 1):
            inventory[f"worker-{i}"] = [describe("model." + name, p)
                                         for name, p in stage.named_parameters()]
        return inventory


class PipelineSession:
    def __init__(self, model, max_length):
        self.model = model
        self.max_length = max_length
        self.session_id = uuid.uuid4().hex
        self.position = 0
        self.closed = False
        self.caches = [LayerCache(stage.start, stage.end) for stage in model.stages]

    def __enter__(self):
        if self.closed:
            raise RuntimeError("Session is closed")
        return self

    def step(self, input_ids, *, return_all_logits=False):
        with self.model.lock, torch.inference_mode():
            if self.closed:
                raise RuntimeError("Session is closed")
            if not isinstance(input_ids, torch.Tensor) or input_ids.device.type != "cpu":
                raise ValueError("Input IDs must be a CPU tensor")
            if input_ids.dtype != torch.long or input_ids.ndim != 2 or input_ids.shape[0] != 1 or input_ids.shape[1] < 1:
                raise ValueError("Input IDs must be a nonempty int64 tensor with shape [1, tokens]")
            count = input_ids.shape[1]
            if self.position + count > self.max_length:
                raise ValueError("Session context limit exceeded")
            if int(input_ids.min()) < 0 or int(input_ids.max()) >= self.model.config.vocab_size:
                raise ValueError("Input token outside the model vocabulary")
            try:
                hidden = self.model.input_output.embed_tokens(input_ids)
                for stage, cache in zip(self.model.stages, self.caches):
                    hidden = stage(hidden, cache, self.position)
                if not return_all_logits:
                    hidden = hidden[:, -1:, :]
                logits = self.model.input_output.lm_head(self.model.input_output.norm(hidden))
                if not bool(torch.isfinite(logits).all()):
                    raise RuntimeError("Non-finite model output")
                self.position += count
                return logits
            except Exception:
                # Earlier stages may already have mutated state. Never reuse an
                # ambiguously advanced cache; closing affects only this session.
                self.close()
                raise

    def diagnostics(self):
        with self.model.lock:
            return {"position": self.position, "max_length": self.max_length, "closed": self.closed,
                    "stages": [{"start": c.start, "end": c.end,
                                "logical_length": c.lengths()[0],
                                "reserved_positions": 0 if self.closed else self.max_length,
                                "allocated_bytes": c.allocated_bytes()} for c in self.caches]}

    def close(self):
        with self.model.lock:
            if not self.closed:
                for cache in self.caches:
                    cache.clear()
                self.model.sessions.pop(self.session_id, None)
                self.closed = True

    def __exit__(self, *exc):
        self.close()
