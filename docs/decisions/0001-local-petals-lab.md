# CPU Petals baseline on one laptop

Date: 2026-10-13.

Use the existing Petals implementation before writing an inference engine. Pin
Petals and Hivemind Git commits, Transformers 4.43.1, and the model/tokenizer
revision. Use the tiny eight-layer `Maykeye/TinyLLama-v0` checkpoint for fast
correctness and network experiments on this CPU-only Docker configuration.
BLOOM-560m is an optional larger follow-up, not yet validated here.

The three workers own consecutive blocks. The client retains embeddings, final
normalization, and output projection. Use explicit per-request inference sessions
so concurrent requests do not share a KV cache. Use float32 and eager attention,
with no quantization or lossy activation compression.

For a fixed, inspectable traffic route, disable Petals server-to-server push.
The client sends activations to each stage and receives its outputs before calling
the next stage. This adds client traffic and round trips; results apply to this
client-mediated topology. Direct stage-to-stage forwarding is a later comparison.

The network is private and internal to Docker. Only model preparation and image
building require internet access. Workers load a resolved local snapshot path;
the shared Hugging Face and Petals cache avoids fallback downloads, including an
upstream sharded-index lookup that does not propagate the model revision.

The wrapper disables the pinned Petals CLI's unbounded online version-notification
request before it starts the standard server. This does not modify transformer
computation or scheduling. Isolated-build constraints preserve the older runtime's
setuptools and protobuf/gRPC compatibility. Other transitive versions are recorded
from the built image, rather than claimed to be fully locked.

Packet shaping uses Linux netem inside containers. Host networking is untouched.
CPU quotas, memory limits, and artificial delay emulate constrained peers while
all containers still compete for one laptop's physical resources. This experiment
cannot establish pooled GPU capacity, energy savings, or real-internet viability.

Upstream sources used to check the wrapper and sessions:

- [Pinned Petals server CLI](https://github.com/bigscience-workshop/petals/blob/22afba627a7eb4fcfe9418c49472c6a51334b8ac/src/petals/cli/run_server.py)
- [Pinned block loader](https://github.com/bigscience-workshop/petals/blob/22afba627a7eb4fcfe9418c49472c6a51334b8ac/src/petals/server/from_pretrained.py)
- [Pinned inference sessions](https://github.com/bigscience-workshop/petals/blob/22afba627a7eb4fcfe9418c49472c6a51334b8ac/src/petals/client/inference_session.py)
