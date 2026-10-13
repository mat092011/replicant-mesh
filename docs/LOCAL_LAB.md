# Local container lab

This prototype runs real transformer inference through three private Petals
workers on one laptop. Each worker owns a consecutive range of transformer
blocks and its sessions' KV caches. The client holds the embeddings, final
normalization, and output head. The client relays activations between stages;
server-to-server push is disabled to fix the experiment's traffic route.
Independent requests can share the pipeline;
successive output tokens in one request still depend on earlier tokens.

**Validation status, 2026-10-13:** image build, 21 unit tests, model loading,
three-worker correctness, packet shaping/reset, and short benchmarks passed on
the development laptop. See the [measured smoke report](experiments/2026-10-13-local-lab.md).
The larger BLOOM option and separate physical devices remain untested.

## Scope and configuration

All containers share the same physical CPU, memory, power budget, and Docker VM.
CPU and memory limits approximate constrained peers. They do not reproduce
different GPU architectures, independent memory bandwidth, real ISP paths, NAT,
or power costs. The tiny checkpoint tests computation and transport mechanics;
it is not an answer-quality demonstration or a pooled-memory benefit experiment.

| Component | Default |
| --- | --- |
| Model and tokenizer | `Maykeye/TinyLLama-v0` |
| Immutable revision | `298338802ab94432b917bcce11382aa151aee50f` |
| Worker block ranges | `[0, 3)`, `[3, 6)`, `[6, 8)` |
| Petals revision | `22afba627a7eb4fcfe9418c49472c6a51334b8ac` |
| Python / PyTorch / Transformers | 3.10.16 / 2.3.1+cpu / 4.43.1 |
| Precision and transport | CPU float32; no weight quantization or activation compression |
| Each worker | 2 CPU quota, 3 GiB memory limit |
| Client | 2 CPU quota, 5 GiB memory limit |
| Discovery service | 0.5 CPU quota, 512 MiB memory limit |

See [requirements](../docker/requirements.txt), [Dockerfile](../docker/Dockerfile),
and [Compose configuration](../compose.yaml) for the exact selected settings.
Some transitive dependencies remain resolver-selected; this is not a fully locked
environment. Runtime compatibility was established for the measured smoke image;
future builds must repeat checks before being used for research comparisons.
See the [runtime decision](decisions/0001-local-petals-lab.md) for wrapper changes.

The `prepare` service downloads public artifacts at the pinned revision into a
Docker volume. Workers, discovery, and client use an internal Docker network and
offline model loading. They receive explicit private discovery addresses and do
not join the public Petals swarm. No host ports or Docker socket are exposed.
The image build and artifact preparation need internet access.

The prototype trusts all its containers and the laptop owner. Network isolation
does not implement worker admission, hostile-peer verification, or a credit
ledger. Only public synthetic prompts are used.

## First workstation inventory

The inspected development machine is an ASUS Vivobook S16 M5606WA running
Windows, with an AMD Ryzen AI 9 HX 370 (12 cores, 24 logical processors), about
32 GB RAM, and an integrated AMD Radeon 890M. No NVIDIA GPU was found. The lab
therefore uses Linux CPU containers; the integrated GPU is not passed through.
The measured run used Docker Engine 29.8.2, Desktop 4.95.0, and Compose 5.6.0.
The WSL2 backend exposed 24 logical CPUs and 16,299,233,280 bytes (15.18 GiB) RAM.

## Launch and verify

Use PowerShell from the repository root. Docker Desktop must show a running
Linux engine. Host Python is not required. Commands using `docker.exe` avoid
PowerShell functions or aliases named `docker`.

```powershell
docker.exe version
docker.exe compose config --quiet
docker.exe compose build client
docker.exe compose up -d --no-build
docker.exe compose ps -a
docker.exe compose logs --tail 100 bootstrap worker-1 worker-2 worker-3
docker.exe compose exec -T client python -m lab.benchmark check
```

All services use the same image, so building `client` builds it for the whole lab.
Stop if a command fails. Initial image building and model downloads can take time.
Compose health checks establish that the discovery listeners are reachable;
they do not prove that all model blocks are loaded. The correctness run is the
next gate before timing experiments.

The check compares a complete-model reference with the distributed model using
identical prompt tokens and forced continuation tokens, avoiding comparisons
between already-divergent generated contexts. It interleaves two different
contexts, closes one early while the other continues, opens a fresh session, and
checks rejection beyond a declared session limit. It records maximum absolute
logit error and greedy-token agreement. The default absolute tolerance is `1e-3`
with zero relative tolerance, a provisional upstream CPU tolerance that still
needs justification against this configuration's local control runs.
Passing this check alone does not complete P2: worker memory, cache reclamation,
message rejection, overlap traces, and separate-device execution still need evidence.

## Small timing experiment

Start with these short smoke runs after correctness passes:

```powershell
.\scripts\Set-NetworkProfile.ps1 -Profile lan
docker.exe compose exec -T client python -m lab.benchmark bench --mode local --requests 10 --concurrency 1 --prompt-tokens 128 --new-tokens 8 --label local-smoke
docker.exe compose exec -T client python -m lab.benchmark bench --mode pipeline --requests 10 --concurrency 1 --prompt-tokens 128 --new-tokens 8 --label lan-c1
docker.exe compose exec -T client python -m lab.benchmark bench --mode pipeline --requests 10 --concurrency 3 --prompt-tokens 128 --new-tokens 8 --label lan-c3
```

Keep model, dtype, prompt/output lengths, and request count fixed when comparing
concurrency or networks. The local reference executes inside the client container,
which has a 2-CPU quota; pipeline workers have separate quotas on the same host.
This comparison measures this configured prototype, not equal-resource speedup.
Independent whole-model replicas and an equal-resource comparison remain controls
to add before drawing a capacity or efficiency conclusion.

Reports are written under `/results` in the container, mapped to the ignored
`.lab/results/` directory on the host. Preserve failed runs as well as successes.
Ten requests are a smoke test, not enough for a stable p95 estimate. The research
protocol in [PLAN.md](PLAN.md#benchmark-protocol) calls for at least 100 completed
requests per configuration with all failures retained.

These flags also show the runner defaults: 10 requests, one active session,
128 prompt tokens, and eight generated tokens. The fixture is a repeated public
sentence, truncated to the requested token count. Decoding uses greedy selection
and ignores EOS to preserve the fixed output length. The driver is closed-loop:
each slot starts another request after its preceding request ends. It accepts at
most eight concurrent sessions and 1,152 prompt-plus-output tokens per session,
subject to the checkpoint's context limit and the workers' cache capacity.

Default report filenames contain a UTC timestamp, command, and mode. Use
`--output /results/chosen-name.json` for an explicit destination; use unique names
to preserve earlier runs.

## Simulate network conditions

The shaping script changes only `eth0` egress inside the selected worker/client
containers. It needs the `NET_ADMIN` capability already granted in Compose.
It does not change the laptop's host network. Settings last until reset or
container recreation.

```powershell
.\scripts\Set-NetworkProfile.ps1 -StatusOnly
docker.exe compose exec -T client ping -c 5 worker-1
.\scripts\Set-NetworkProfile.ps1 -Profile wan
docker.exe compose exec -T client ping -c 5 worker-1
docker.exe compose exec -T client python -m lab.benchmark bench --mode pipeline --requests 10 --concurrency 3 --prompt-tokens 128 --new-tokens 8 --label wan-c3
.\scripts\Set-NetworkProfile.ps1 -Profile lan
```

The `wan` preset adds 25 ms egress delay and a 100 Mbit/s cap to each worker and
the client. Shaping both ends of a link adds approximately 50 ms to its RTT;
measure achieved RTT instead of reporting the configured delay as a measurement.
The bandwidth cap applies to each container's aggregate egress, not independently
to each peer connection. A `lan` profile removes the script's shaping; it does
not remove the underlying Docker network's latency.

Vary delay and rate separately before combining them. For example:

```powershell
.\scripts\Set-NetworkProfile.ps1 -Profile custom -DelayMs 10
.\scripts\Set-NetworkProfile.ps1 -Profile custom -RateMbit 20
.\scripts\Set-NetworkProfile.ps1 -Profile custom -DelayMs 50 -JitterMs 5 -LossPercent 0.1 -RateMbit 20 -Services worker-2
.\scripts\Set-NetworkProfile.ps1 -StatusOnly
.\scripts\Set-NetworkProfile.ps1 -Profile lan
```

Each custom profile replaces selected containers' previous settings. Selecting
only one worker affects only its outgoing traffic; others retain their settings.
Record the status of all four containers and ping results with each run. The
script reports any partial application failure; inspect status and restore `lan`
before continuing. Do not infer real WAN behavior from one artificial profile.

## What the initial runner measures

The initial reports cover client-observed first-token latency, intervals between
output tokens, aggregate output throughput, completed/failed requests, workload,
and model/runtime metadata. Timing uses the client's monotonic clock. Prompt
tokens do not count as generated output. Failed requests remain in the report;
only output from completed requests counts toward accepted throughput.

Model loading is reported separately and warm-up is excluded from the request
measurement interval. First-token latency includes session setup and prefill; it is not an
isolated prefill compute measurement. Inter-token timing also includes network
and client work. Pooled token-interval percentiles weight longer outputs more
heavily than per-session percentiles.

The prototype does not yet provide complete worker memory peaks, retry counts,
stage compute/queue/serialization timings, transferred bytes, overlap traces,
recovery costs, or energy measurements. Cancellation and cache behavior need
worker-side instrumentation. These omissions prevent completion of the P1–P3
research gates even after a successful smoke run.

## Larger checkpoint

After the tiny model passes, copy `.env.example` to `.env` and change all five
model/revision/range values to its commented BLOOM example:

| Setting | BLOOM follow-up |
| --- | --- |
| Model | `bigscience/bloom-560m` |
| Model/tokenizer revision | `ac2ae5fab2ce3f9f40dc79b5ca9f637430d24971` |
| Worker ranges | `0:8`, `8:16`, `16:24` |

Recreate the lab and repeat correctness before benchmarking:

```powershell
docker.exe compose down
docker.exe compose up -d
docker.exe compose exec -T client python -m lab.benchmark check
```

BLOOM requires substantially more download space, RAM, and CPU time. Its
client-side embedding/output components also consume memory. The current limits
are prototype settings, not validated capacity guarantees. Record any changes
to limits or runtime as experimental variables. Neither checkpoint demonstrates
a model that requires pooled GPU memory.

## Stop and troubleshoot

```powershell
.\scripts\Set-NetworkProfile.ps1 -Profile lan
docker.exe compose logs --tail 200
docker.exe compose down
```

`down` stops this Compose project and removes its containers/network. Cached model
artifacts remain in named volumes and reports remain in `.lab/results/`. Do not
add `--volumes` unless deliberately discarding cached artifacts and discovery state.

The initial workstation startup error involving `sailor-ingest.sock` was resolved
before the measured run. If the Linux engine pipe is unavailable, restore Docker
Desktop's normal engine operation before retrying the launch sequence. A factory
reset is not part of this lab's setup procedure.
