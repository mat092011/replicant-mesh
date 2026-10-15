"""Adapters used by the existing lab runner; imports never require Petals."""

import time

from .manifest import MODEL_ID, MODEL_REVISION, SOURCE_HASHES, load_manifest
from .prepare import verify_snapshot


def load_model(mode, artifacts, reference=None):
    import torch
    from transformers import AutoModelForCausalLM, AutoTokenizer

    started = time.perf_counter()
    load_manifest(artifacts)
    tokenizer = AutoTokenizer.from_pretrained(artifacts, local_files_only=True)
    if mode == "pipeline":
        from .model import PipelineModel
        model = PipelineModel(artifacts)
    elif mode == "local":
        if reference is None:
            from huggingface_hub import snapshot_download
            reference = snapshot_download(MODEL_ID, revision=MODEL_REVISION,
                                          allow_patterns=list(SOURCE_HASHES), local_files_only=True)
        verify_snapshot(reference)
        model = AutoModelForCausalLM.from_pretrained(
            reference, dtype=torch.float32, attn_implementation="eager",
            local_files_only=True, use_safetensors=True,
        ).eval().requires_grad_(False)
    else:
        raise ValueError(f"Unknown execution mode: {mode}")
    return model, tokenizer, time.perf_counter() - started
