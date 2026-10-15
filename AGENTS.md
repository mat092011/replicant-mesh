# Agent guidance

## Project purpose

`steamboat_net` investigates whether consumer devices connected over the internet
can cooperate on useful large language model inference. Participants may later
earn credits for accepted computation and spend them on inference for themselves.

The primary hypothesis is that pooled GPU memory and otherwise idle compute can
provide access to larger models or more available capacity at acceptable latency
and resource cost. Faster generation for one user is a separate hypothesis.

Read [docs/PLAN.md](docs/PLAN.md) before implementation. The repository contains a
prototype private Petals container lab, correctness checks, and a benchmark runner.
The tiny-model local smoke experiment passed; see [docs/LOCAL_LAB.md](docs/LOCAL_LAB.md)
for setup and [the report](docs/experiments/2026-10-13-local-lab.md) for evidence and
limitations. The broader research phase gates remain incomplete.

For the planned runtime replacement, also read
[docs/PYTORCH_PIPELINE_PLAN.md](docs/PYTORCH_PIPELINE_PLAN.md). That plan adds an
owned PyTorch execution path; Petals remains an optional comparison baseline.
M0–M3 are implemented: see [docs/PYTORCH_RUNTIME.md](docs/PYTORCH_RUNTIME.md) for
the verified setup, current limits and test commands.
[docs/PYTORCH_PROTOCOL.md](docs/PYTORCH_PROTOCOL.md) describes the binary protocol
and worker lifecycle. [docs/PYTORCH_WORKERS.md](docs/PYTORCH_WORKERS.md) runs three
supervised worker containers with bounded queues and remote numerical validation.
M4 scheduling and M5 network experiments remain pending; same-host container tests
do not establish separate-device performance or useful pipeline overlap.

## Technical principles

- Start with ordinary autoregressive inference and contiguous groups of model
  layers. Each output token depends on preceding tokens. Pipeline overlap comes
  from independent requests or supported prompt microbatches, not independently
  generating consecutive tokens of one answer.
- Keep weights resident. Keep each session's KV cache with the worker owning its
  layers. Account for embeddings, output heads, tied weights, caches, temporary
  buffers, and token feedback when describing memory and communication.
- Preserve the measured private Petals baseline. Develop the new runtime using
  the PyTorch implementation plan, with isolated dependencies and a complete-model
  reference on the same stack. Record runtime, scheduler, or topology changes as
  experimental variables; do not require Petals in the new execution path.
- Treat a trusted coordinator and central credit ledger as deliberate prototype
  components. Describe their trust requirements accurately. Decentralized compute,
  discovery, scheduling, and accounting are different milestones.
- Use measured stage time, free memory, and network performance for placement.
  Equal layer counts are only an initial assignment on comparable devices.

## Research and measurement

- Separate implementation correctness, performance, resource cost, and user
  experience. Label assumptions, simulations, measured results, and targets.
- Pin model and tokenizer revisions, runtime versions, precision, attention
  backend, compression, workload, hardware, and network configuration in reports.
- Validate logits using identical input tokens and forced continuations before
  benchmarking. Test interleaved sessions, cache cleanup, cancellation, and context
  limits. Use justified numerical tolerances; plausible text is not a proof.
- Report per-user first-token and inter-token latency alongside aggregate output
  throughput, failures, retries, and memory use. Separate prefill, decode, startup,
  and recovery. Do not count prompt tokens as generated output tokens.
- Compare like-for-like configurations. Whole-model replicas are a control when
  the model fits locally; same-model CPU/RAM offloading is a relevant baseline when
  it does not. Several processes on one GPU establish no multi-GPU speedup.
- Define acceptance criteria before collecting results. Preserve failed runs and
  report exclusions. A negative finding is a valid research result.
- Use monotonic client timing and synchronized GPU measurements. Do not subtract
  timestamps from different hosts without accounting for clock synchronization.

## Workers, trust, and credits

- Start with invited workers and public or synthetic prompts. Encryption in
  transit does not hide computations from worker owners, and activations are not
  a privacy guarantee. Avoid logging real user prompts by default.
- Bound memory, queues, request size, concurrency, and execution time. Workers
  execute supported inference operations, not arbitrary code supplied by peers.
- Pin and verify model artifacts. Validate message shapes, positions, session IDs,
  and sequence numbers. Fail explicitly when a session cannot safely continue.
- Treat spot checks and signed receipts as limited checks, not proof against
  malicious or colluding workers. Document the trust model for every experiment.
- Credits represent accepted, normalized work. Raw token counts, advertised
  hardware, and self-reported elapsed time are insufficient payment measures.
  Reserve and settle credits idempotently; retries must not create duplicate
  rewards. Account explicitly for grants, fees, verification, and recovery costs.

## Working in this repository

- Keep changes aligned with the current phase and update its evidence and status
  in `docs/PLAN.md`. Later phase completion must reference actual results.
- Keep executable code, tests, benchmarks, and reports separate. Document real
  setup and test commands when the relevant tooling exists; do not invent passing
  test runs or imply that a proposed command was executed.
- Keep model weights, caches, secrets, private prompts, and large raw traces out of
  Git. Commit reproducible configuration and compact, sanitized result summaries.
- Run checks appropriate to the change. For documentation changes, check links,
  consistency, and `git diff --check`; application tests are not required.
- Preserve unrelated work. Follow the user's requested branch and publishing
  workflow. Use normal pushes; never force-push `main`.
- In completion reports, state what changed, what was verified, and what remains
  untested. Keep claims proportional to the evidence.
