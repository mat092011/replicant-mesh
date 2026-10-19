# C2 component validation, 2026-10-19

Status: C2 implementation resumed at the maintainer's request after publication
of C1 (`89ea4b1`). No C2 checklist item or phase exit gate is accepted by this
report. The [implementation design](../PARTICIPANT_CONNECTOR_DESIGN.md) records
the frozen acceptance criteria and remaining integration boundaries.

The private candidate preserves the earlier C2a local foundation on the
completed C1 base. It adds conservative artifact authority checks, a separate
channel certificate profile, and an assigned-stage adapter for the real worker
handler. The earlier [C2a report](2026-10-17-participant-c2a-local.md) remains
historical component evidence; its test counts overlap and must not be added to
the counts below.

## Frozen component runs

Both runs used Linux/amd64 Docker, the pinned Python 3.12.15 and CPU runtime
lock, Torch 2.14.1+cpu, Transformers 5.19.0, eager attention, float32 and no
compression. The model/tokenizer revision remained
`Maykeye/TinyLLama-v0@298338802ab94432b917bcce11382aa151aee50f`.
Cryptography 50.0.2, cffi 2.1.1 and pycparser 3.11 were hash-pinned by the
artifact image. Model artifacts came from the existing read-only verified lab
volume; no network download was allowed during the tests.

The test containers had 2 CPUs, 6 GiB memory, 256 PIDs, no network, a read-only
root, all capabilities dropped and no-new-privileges. Writable tmpfs ceilings
were 256 MiB for scratch and 16 MiB for lab state. The harness required every
discovered case and rejected skips, failures, errors and inventory mismatch.
It had a 180-second outer traceback/termination timer. Actual container limits
were inspected before starting; each terminal container was inspected and
removed afterward.

| Run | Frozen source | Baked image | Result |
| --- | --- | --- | --- |
| Component 1, corrected harness | `a52c92cfbbdbb167cd88eef5837e4c0e76d1324c6f7dae945cfab1411c75d4df`, 340 files | `5b74e1b1b34a0054db1157b5bb599994ea2945ea6a655457461cf20bd313ef8c` | 78 unique cases passed, zero skips/failures/errors, 9.411 s |
| Component 2 | `b2eb5874905769ea895ef707557ffa4e351306da799a9365640703bb6e3a5111`, 342 files | `eb915bd9c1a31768fa5cac3caf67f9a4def20a4976ade3b2e8b7019a42a6e893` | 87 unique cases passed, zero skips/failures/errors, 9.953 s |

Full baked-source comparisons found zero mismatches for all 340 and 342 files,
respectively. The component-2 private code checkpoint was `3e512b1`; subsequent
documentation and later component implementations are not part of that image.

| Evidence | SHA-256 |
| --- | --- |
| Component-1 all-source proof log | `ac54772ac1011c013fcf3efc7bc11919b4eb3821ae6a6cf2d540c808e7ca6098` |
| Component-1 corrected test log | `8ea602b89f8aa211a6207cdf1d28c23cb12eb19c22366d5fb99d3c33ec838148` |
| Component-2 all-source proof log | `a2cbe164ac00cfc6bcec15689de11b90fd5e3af4eee9b047618462c77c773ed6` |
| Component-2 test log | `f1e35f7d4f85cbfe770e03e54c80c083f176e37d36882b8c60f976b942bf3fe4` |

The counts are successive complete component inventories; they are not 165
distinct tests. Component 2 includes the prior inventory, the reverse channel
credential separation control, seven adapter contract cases and one real
assigned-handler numerical case.

## What was checked

The local IPC and ledger checks exercise real Linux owner-only sockets and file
locks. They do not establish physical cgroup, disk or network enforcement for
executing roles. Conservative artifact verification uses the core `Clock`,
checks the signed parent catalog and assignment in one sampled transaction,
preserves monotonic fences across re-signing and uncertainty changes, and rejects
an assignment whose cached parent authority has expired. Unconfigured clock
accuracy fails closed. The numerical fixture explicitly assumes an accurate
test clock; it does not validate an operator clock source for real readiness.

The channel certificate tests check the new client-capable worker profile and
gateway service profile without changing C1's existing role/EKU definitions.
They reject profile substitution in both directions, malformed CA-signed
leaves, endpoint mismatch, excessive lifetime and conservative validity failure.
Certificate validation alone does not establish TLS channel authentication,
revocation, readiness or gateway delegation authority.

The new numerical test installs three separate signed host assignments, loads
only each assigned shard and builds actual `WorkerHandler` instances through
the adapter. Two unequal sessions interleave multi-token prefill and forced
continuations through actual protobuf requests and tensor encoding/decoding.
The synthetic token sequences are A: `[1,17,19]`, `[23]`, `[31]`; B: `[5,7]`,
`[29]`, `[37]`. Last-position logits match the complete `PipelineModel` on the
same stack with `atol=1e-3`, `rtol=0`. The test checks that closing A leaves B's
session/cache, closing B leaves zero sessions/cache, and handler shutdowns
confirm completion. This is a same-container component correctness result.

## Retained failure and corrections

The first component-1 attempt ran all 78 cases and ended with one error. The
parent's private harness lacked an `if __name__ == "__main__"` guard; spawned
ledger-test children re-executed scratch-directory creation and raised
`FileExistsError`. The resulting queue wait failed. The failed log is retained
with SHA-256
`5b7d7b645055513f718c6b6451eb968fb2317b21929e991a2b739ca3c591443b`.
The corrected attempt changed only that private harness guard and used the same
frozen source, image, 78-case inventory and resource limits. No product defect
or hardware cause is attributed to that failure.

Pre-measurement review also corrected monotonic-fence pruning, dependent catalog
authority, missing post-compute assignment checks and the numerical fixture's
interleaved cleanup expectations. Portable failures are preserved in the private
journal; they are not represented as successful runs.

## Remaining acceptance work

The daemon still needs actual backend, assigned artifact ownership and readiness
integration. The adapter's blocking file verification must be replaced in the
executing path by a reviewed, supervisor-owned artifact pin and live in-memory
authority guard. Prepared process-supervision, physical-pool lock and channel
policy changes have separate pending review and Linux checks; their Windows
mock/skip results are not included in these Docker claims.

C2 still requires actual shared CPU/RAM, disk/staging/log and traffic enforcement;
authenticated enrollment and expiring loaded readiness; the trusted terminating
gateway with two authenticated mTLS hops and signed delegation; bounded work and
independent cancellation lanes; a real consumer/personal-coordinator route; and
the exact CT-11/CT-13 numerical and lifecycle checks with executing stages and
their coordinator spanning at least two physical machines. The laptop and
ZimaBlade CPU host are available. No additional hardware requirement has been
established. No WAN/NAT universality, GPU, pooled-capacity, performance or later
research gate is claimed. C2 remains unpublished until all of its gates pass.
