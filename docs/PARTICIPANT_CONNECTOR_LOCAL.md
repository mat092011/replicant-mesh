# Local participant connector (C2a foundation)

Date: 2026-10-17. This guide describes the local daemon, standard-library
client, and resource/lifecycle foundation in `src/steamboat_connector/`. It is
implementation work in progress, not a C2a acceptance or phase pass. The
normative identity, permission, protocol, runtime and trust decisions remain in
the [C0 participant contracts](PARTICIPANT_CONTRACTS.md). This C2a work does not
change P0–P8 research evidence or claim a new M0–M5 runtime milestone; those
status and baseline limits remain with their existing guides.

## Implemented surface

The package imports no PyTorch, Transformers, model artifact, or network
transport in the consumer path. `ConsumerClient` validates a bounded request and
creates a fresh `req_` identity with `attempt=1`; it only delegates to an
explicitly injected transport. C1a/C2b authenticated inference transport is not
included, so a client without that dependency reports `TRANSPORT_UNAVAILABLE`.
It never retries a request after an ambiguous failure.

The consumer/foundation environment stays standard-library-only. Artifact
signature verification uses a separate, hash-pinned `cryptography==50.0.2`
dependency in the artifact-validation image; it does not alter the CPU runtime
lock.

The headless management daemon is Linux-only. It exposes a fixed action set over
AF_UNIX: status, sanitized diagnostics, policy get/set, role enable/disable,
start, drain, stop, remove, and bounded operation status. There is no TCP,
loopback HTTP, browser endpoint, arbitrary command, peer-selected executable,
or payload logging. The daemon accepts only same-UID peers and a random per-boot
secret read from a private file. Runtime directory mode is `0700`; socket and
boot-token files are `0600`. A daemon lock prevents concurrent instances from
overwriting active boot state. Management is capped at four connections,
65,536-byte JSON frames, five seconds per operation, and 30 seconds idle.
Duplicate JSON keys, nonfinite numbers, excessive nesting, malformed frames,
and oversized frames are rejected.

These controls protect the local same-UID boundary, not against the same OS user,
root, a compromised daemon, or hostile physical access. The token is a local
management credential, not a remote participant credential. This interface is
not a substitute for C1a mTLS, admission, operation authorization, or secure
inference transport.

All role flags start off. A restart persists opt-in but pauses enabled roles;
it does not make a role ready. Host/coordinator status fails closed when policy,
credential/runtime readiness, resource enforcement, or required fresh telemetry
is missing. Unsupported or stale required telemetry is treated as unavailable;
the connector invents no hardware sensors. Diagnostics distinguish atomic
bookkeeping from enforcement. The cross-process Linux ledger serializes
reservations across daemon processes and counts weights, KV, temporary/runtime,
communication/capture memory, CPU, disk, network, cleanup bandwidth, sessions,
queues, and deadlines in shared physical-pool totals. It does not itself enforce
those limits.

The existing cgroup-v2 helper probes delegation and can write/read back memory
and CPU limits for a caller-provided role group, but the management controller
does not attach role processes to that group. Disk/bandwidth quotas and real
telemetry are also not applied. Accordingly, current execution roles remain
unavailable; a reservation or successful arithmetic check never means ready.
No role process, artifact installer, signed artifact verification, inference
service, secure credentials, admission authority, registry, catalog, or outbound
gateway is wired here. The existing baseline gRPC runtime remains a private,
unauthenticated comparison and is not launched as a participant role.

## Lifecycle and limits

`drain` disables admission for the selected roles and records a monotonic,
non-sliding deadline (default 30 seconds; accepted range 1–300 seconds). A
repeated drain of those roles returns the same operation and does not extend its
deadline; another disjoint drain is rejected while one is active. On deadline,
the backend is asked to stop with a 15-second grace. `stop` and `remove` persist
disabled admission intent before queuing work on an independent urgent lifecycle
worker. The immediate response explicitly does not claim resources reclaimed.
Reservations remain held unless the backend confirms reclamation; unknown or
ambiguous outcomes retain them. The fake/backend interface can exercise a hung
child, but this C2a slice has no real child launcher and does not establish a
one-second latency guarantee on arbitrary filesystems.

`remove` persists all roles disabled and `revocation_status=pending_offline`;
this local action does not claim that a remote authority revoked credentials.
Optional deletion is restricted to the fixed state-directory `owned-data`
subtree. It refuses symlinks, non-regular or multiply linked files, foreign
ownership, permissive modes, cross-device entries, depth over 8, more than 4,096
entries, or more than 256 MiB total file size. Deletion is attempted only after
backend-reported reclamation. State, resource ledger, runtime credentials, and
arbitrary paths are not deletion targets. A deletion refusal leaves removal
pending and is reported in operation status.

The operation queue/history, parser, frame sizes, output, and local state are
bounded. Mutating client calls are never automatically replayed; a lost response
may mean the action completed. The management request correlation ID is not a
durable action ID, so callers must treat a lost mutating response as ambiguous;
re-reading status may not identify which action completed. No query reconstructs
an inference session or reverses a completed action.

## Linux local use

From the repository root on the supported Linux environment, run the daemon in
one terminal:

```sh
PYTHONPATH=src python3 -m steamboat_connector daemon
```

Use a second terminal for the implemented local read-only commands:

```sh
PYTHONPATH=src python3 -m steamboat_connector status
PYTHONPATH=src python3 -m steamboat_connector diagnostics
PYTHONPATH=src python3 -m steamboat_connector policy show
```

The daemon uses the private per-user paths under `XDG_RUNTIME_DIR` and
`XDG_STATE_HOME`, or the documented per-user fallbacks in `paths.py`. Explicit
`--runtime-dir` and `--state-dir` overrides must resolve to owner-controlled
Linux directories; the storage layer rejects symlinked path components and
unsafe ownership/modes. Stop the daemon with SIGINT or SIGTERM. Role management
commands are present, but no consumer network transport or executable role
backend is wired, so execution cannot become ready in this slice.

## Tests and platform limits

Run the focused connector suite on Linux:

```sh
PYTHONPATH=src python3 scripts/check_participant_connector.py
```

Portable tests cover IDs, strict JSON, no-retry consumer request building,
shared-ledger contention, policy reduction, telemetry fail-closed behavior,
restart pause, bounded drain, stop acknowledgement independent of a hung fake
backend, and pending removal. Linux-only tests exercise AF_UNIX peer UID/token
checks, boot-token rotation, private modes, duplicate daemon startup, connection
caps, malformed/oversized frames, symlink refusal, and bounded owned-data
deletion. A real two-process test checks one file-backed pool admits only one
conflicting reservation; it establishes serialization, not kernel enforcement
or memory fit. Linux cases are conditionally excluded on non-Linux hosts; the
parent-run Linux results are recorded below. The
[2026-10-17 local validation report](experiments/2026-10-17-participant-c2a-local.md)
records parent-run Linux Docker results: 23 foundation tests and a 58-test
combined artifact/connector run, both with zero skips. The 23 foundation tests
overlap the 58-test run and are not additive. The combined run includes the
assigned-only model/reference check; these results do not establish a wired role
backend, enforced physical resource limits, live identity enforcement, or a real
route. Native Windows and AMD/GPU execution are unsupported. A Windows host run
cannot validate Linux `SO_PEERCRED`, `openat`, `flock`, AF_UNIX, or cgroup-v2
behavior.

## Deferred work and trust limits

C2.3 owns the signed artifact installer. C1a owns secure transport and identity
enforcement. C2b owns real network registration and the trusted terminating
outbound gateway. This local foundation does not implement those gates and does
not start the existing insecure runtime. Only invited operators and
public/synthetic prompts remain in scope; a coordinator, worker owner, and future
terminating gateway can inspect prompt-derived computation. TLS would protect
traffic in transit, not hide activations or KV state from their hosts. No
inference correctness, security, privacy, billing, resource-enforcement, phase
acceptance, or separate-device performance claim follows from these local tests.
