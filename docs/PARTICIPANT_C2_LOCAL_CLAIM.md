# C2 per-device durable local launch claims

`steamboat_security.root_c2_local_claim` is a versioned persistence domain for
one operator-pinned account and device. It accepts only a reparsed canonical
`C2LocalPlan` or its canonical bytes. Every record stores the complete plan,
including the disabled local declarations, selected generation and head digests,
and trusted owner `enable_epoch`; a separate sorted boot list covers exactly
the enabled local parent and host-child boots. The existing global
`C2LaunchClaimStore` remains unchanged and continues to represent complete
selected global startup.

The local claim requires at least one enabled role. Grants and remote roles do
not opt a device in. Its enabled spec and host-scope projection is inherited
from the locally validated plan, so disabled and remote roles are never claimed
for startup. A store pins account/device at construction and rejects another
principal. Across the append-only local history, enabled parent and child boots
cannot recur; a new attempt also requires a strictly greater owner enable epoch
and strictly greater admission epochs for returning enabled principals. There
is no implicit retry after a claim attempt.

The native POSIX store requires an operator-provisioned daemon-owned `0700`
directory. It uses dirfd-relative no-follow operations, `0600` single-link
regular files, an exclusive lock, at most 16 claim records of 64 KiB each, a
1 MiB total scan bound, and incremental directory enumeration capped at 17
entries including the lock. A created file is sticky: write, fsync, or close
uncertainty latches the live store, consumes the descriptor before its one close
attempt, and never deletes or retries the record. Parsing rechecks canonical
JSON, closed versioned fields, complete nested local-plan validity and digests.
Each store instance serializes claim and close over the directory-descriptor
lifetime: another thread's close waits through the final root fsync, while a
callback cannot reenter claim or close on that instance.

Before creating the exclusive file, `claim` invokes a fresh synchronous
validator and accepts exactly `None`; awaitables and all other results reject.
The callback is an integration boundary, not evidence by itself that upstream
synchronization was held. The owner must serialize fresh raw selected-head and
owner-enable validation, local claim creation, and immediate ownership
publication for every `Popen` under the same `RootGenerationStore` head and
owner-enable serialization. Release it before waiting for child readiness.
`RootCohortStartup` continues to spawn every global role and is intentionally
unchanged; this module does not wire local startup, provide process authority,
or make a receipt a readiness or identity capability.

Run the portable and host-supported checks with:

```powershell
uv run --no-project python -Xutf8 -B -m unittest tests.security.test_root_c2_local_claim -v
```

Native persistence and process-race cases require POSIX `O_NOFOLLOW` and fork;
they skip on Windows. Passing portable tests or POSIX component tests does not
establish lock integration, Popen publication, worker readiness, execution,
startup wiring, or C2 phase acceptance.
