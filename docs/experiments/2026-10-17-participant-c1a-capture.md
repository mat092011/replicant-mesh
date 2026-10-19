# Local capture backpressure observations, 2026-10-17

**C1a and C1 remain unfinished.** These are component-level CPU observations
alongside the [secure pipeline evidence](2026-10-17-participant-c1a-local.md).
The fixture uses fake authorization and in-memory worker transport, while the
supervised coordinator model, three StageExecutors, worker handlers, scheduler,
output queue and capture reclaimer are real. It establishes no TLS backpressure,
separate-device, GPU, or pooled-memory result.

## Frozen configuration and checks

The pinned Linux amd64 CPU stack and model/tokenizer revision are unchanged:
`Maykeye/TinyLLama-v0@298338802ab94432b917bcce11382aa151aee50f`, float32/eager,
batch one, no compression, two Torch intra-op and inter-op threads. Prepared
artifacts and model cache were read-only. The parent serialized all model runs.
Before this run, the wrapper read and verified actual cgroup limits: memory
6,442,450,944 bytes, CPU quota/period `200000 100000`, and 256 PIDs. The configured
container used no external network.

The owner explicitly reserved 92,032,256 logical bytes for one capture at
V=32,000 and Q=16, within a 1 GiB pool and at most eight active captures.
This arithmetic is not a physical RSS enforcement result.

The enabled module passed **3 tests, zero skips**: one task-join regression and
two actual model cases. One stalled writer held a serialized event while 16 real
finite `[1,32000]` float32 logit tensors filled the queue and another put blocked.
Those queued raw logits totalled 2,048,000 bytes; the observed serialized event
was 622,264 bytes, below the 1,028,096-byte contract. Cancellation kept capture,
authorization, context and stream accounting until reclamation. After physical
cleanup, all request/cache/queue/capture/stream accounting reached zero and the
service remained available.

The second case held a real supervised CPU operation past its five-second
cleanup grace. One absolute deadline required the service fence within six
seconds from cancellation; caller exit had a separate one-second bound. The
caller was cancelled while its 92,032,256-byte reservation and cleanup owner
remained held. After gate release, the original model computation succeeded
without an exception, physical cleanup completed, and reservations reached
zero. The service/runtime fence stayed latched for operator recovery.

## Observed memory

Baseline is sampled after fixture/model loading, before the request. Values
below are bytes from `psutil` RSS sampling and Linux `ru_maxrss`.

| Case | Baseline RSS | Sampled peak RSS | Process high-water RSS |
| --- | ---: | ---: | ---: |
| pending_supervised_cpu_future | 413,364,224 | 425,553,920 | 425,553,920 |
| full_queue_stalled_write | 471,396,352 | 472,772,608 | 475,500,544 |

The observed CPU-case fence elapsed time was 5.026334
seconds. These are one-run observations; no RSS pass threshold was adopted.
`ru_maxrss` is a process-wide high-water mark shared across the two cases,
including fixture history, not a per-case allocation total. Sampling can miss
short peaks. This does not establish an eight-capture worst-case physical bound
or memory available on other devices.

## Provenance and remaining work

Source manifest: 211 files, digest
`ca4c074c4f43c0839a753705d8fafad11323680c686a61132dcf7578f664caab`.
Image: `sha256:bb00d80b50b8a51b44ecbe0f55823b339aa8d6790a2c0831d399f4bb2ee42b3e`.
All 211 baked source files matched the frozen manifest. Test log SHA-256:
`debf4d77d25e76a1142f8f9adf2a13fe44d85847d126a7ac4d385a0c9194cd0c`;
source-proof log SHA-256:
`0f6c3e11f8e8aa0432700803cf22d64be88621004603ee8cd1913f5c0adc9295`.
The source identity predates this evidence document and subsequent transport
fixes. Exact argument arrays, timestamps, raw samples and failed attempts stay
in the ignored local journal/results.

Prior independent review found missing detached-compute success checks,
missed descendants during task joining, undefined fence outcomes and a relative
fence deadline. The executed revision addresses those oracles. It preserves
ordinary cancellation or explicit pending failure as supported bounded outcomes;
neither is treated as completed inference. Remaining secure lifecycle/fault
coverage, listener shutdown fixes and paired capacity-error transport behavior
require their own validation and review before C1a acceptance. C1b still requires
actual separate physical machines.
