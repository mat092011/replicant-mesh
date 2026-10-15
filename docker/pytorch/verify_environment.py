"""Build-time check that the independent CPU image imports without Petals."""

import importlib.util
import json
import platform
from importlib.metadata import version

import grpc
import torch
from google.protobuf import __version__ as protobuf_version
from transformers import AutoTokenizer, LlamaConfig, LlamaForCausalLM
from transformers.models.llama.modeling_llama import LlamaDecoderLayer


for forbidden in ("petals", "hivemind", "bitsandbytes"):
    if importlib.util.find_spec(forbidden) is not None:
        raise RuntimeError(f"unexpected legacy dependency: {forbidden}")
if torch.version.cuda is not None:
    raise RuntimeError("this image must use the CPU-only torch wheel")

# This exercises the actual eager-attention Llama/cache API without a download.
config = LlamaConfig(
    vocab_size=32, hidden_size=16, intermediate_size=32,
    num_hidden_layers=2, num_attention_heads=2, num_key_value_heads=2,
)
config._attn_implementation = "eager"
model = LlamaForCausalLM(config).eval()
with torch.inference_mode():
    output = model(torch.tensor([[1, 2, 3]]), use_cache=True)
    next_output = model(torch.tensor([[4]]), past_key_values=output.past_key_values, use_cache=True)
if next_output.logits.shape != (1, 1, 32) or not torch.isfinite(next_output.logits).all():
    raise RuntimeError("Llama eager-attention decode smoke failed")
print(json.dumps({
    "python": platform.python_version(),
    "torch": torch.__version__,
    "transformers": version("transformers"),
    "grpcio": grpc.__version__,
    "protobuf": protobuf_version,
    "legacy_dependencies_present": False,
    "eager_prefill_and_cached_decode": "passed",
}, sort_keys=True))
