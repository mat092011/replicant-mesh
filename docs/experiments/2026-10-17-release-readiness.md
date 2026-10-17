# Source-release engineering validation

Date: 2026-10-17. This work implements release tooling and checks the existing
CPU lab. It does not publish the project, establish new performance results or
complete any P0–P8 research phase. The repository remains private and the working
changes are uncommitted. See the [compact evidence](2026-10-17-release-readiness-summary.json).

## Scope and ownership

The maintainer selected Apache-2.0 and explicitly confirmed authority to license
the original project code, including employer/collaborator rights. The ten
fetched/local history commits are attributed to `mat092011`; attribution is not
independent proof of ownership. [Third-party notices](../../THIRD_PARTY_NOTICES.md)
and [the review](../THIRD_PARTY.md) keep external terms separate.

Installed-image inventories record 39 packages in the owned image (38 locked
application packages plus base-image pip), 68 in the preserved Petals image,
165/100 available installed notice files, and 112/172 Debian packages.
Owned installed versions match the lock. Exact image identities, package
metadata, direct source information and notice-file hashes are retained in the
[owned](../third_party/dependencies-owned.json) and
[legacy](../third_party/dependencies-legacy.json) inventories. They do not
constitute clearance to redistribute every wheel, native library or OS package.

The pinned TinyLLama card declares Apache-2.0. Its binary tokenizer SHA256 matches
OpenLLaMA 3B revision `141067009124b9c0aea62c76b3eb952174864057`, whose model card
also declares Apache-2.0. JSON tokenizer conversions remain pinned by the
TinyLLama manifest; no claim of identical upstream JSON files is made. No model
weights, tokenizer binaries or datasets were added to Git.

## Secret scan

Gitleaks **8.30.1** was downloaded from its official release with a pinned
platform-specific SHA256. After fetching configured remote branches/tags, the
tool scanned all local refs/reflogs (ten commits) and an export of tracked and
unignored candidate files. Reports/logs are fully redacted and kept under
ignored `.lab/release/`. Archive traversal depth is three, decoding depth five,
with no target file-size cutoff. A synthetic token control checks both detection
and redaction before the actual scans.

The first scan reported 17 matches in history and 17 in the source export, all
from the generic API-key rule. Review identified four exact public tokenizer
file hashes and the public checkpoint revision, repeated across manifests and
reports. `.gitleaks.toml` allows only those five exact values. The subsequent
scans report **zero unallowlisted findings**, with the positive control passing.
No project path-wide exclusions or inline allow comments were used. This does not prove
that every possible secret/private datum is absent; ignored local caches and
unreachable objects outside refs/reflogs are not published-source scan claims.
Both Windows and Linux scanner archives were exercised successfully against
ten history commits and 135 candidate files, with their separate verified
archive hashes recorded in the compact evidence.

## CI implementation and local checks

- The source workflow runs source/link/whitespace checks, **82 dependency-free
  Linux tests with zero skips**, both Compose configuration checks and mocked
  PowerShell network-reset regressions.
- Final static checks cover 135 source files, 30 Markdown files and 189 local
  links, with no missing targets or whitespace errors. The reproduced image's
  complete dependency/OS inventory matches the preserved owned image exactly.
- The secret job uses a full-history checkout and the same pinned scanner.
- A separate manually dispatched workflow builds the CPU image, prepares the
  pinned model, runs the full suite, checks remote numerical/lifecycle behavior,
  performs a six-request smoke and cleans up its project volumes. No image push
  or registry publication is configured.
- Checkout 7.0.1, Setup Python 7.0.0 and Upload Artifact 7.0.2 are pinned to full
  official commit SHAs. Workflows use read-only repository permissions and do not
  persist checkout credentials. Both YAML documents parse locally.

These commands were exercised locally, not on GitHub-hosted runners. The new
workflow files have not been pushed or dispatched. A direct Windows fast-suite
attempt exposed an existing zero-duration TCP-probe measurement and initially
included two opt-in cases; its failure is retained. The fast runner now selects
the dependency-free cases explicitly and targets Linux. No unrelated networking
implementation was changed to make the Windows attempt pass.

## Clean candidate reproduction

`scripts/reproduce_release.py` creates a fresh local clone at HEAD
`70c7de8b7028c58e3115c3dbc59a0ab974c565a8`, overlays the uncommitted candidate,
verifies a source digest, then uses a unique Compose project/image and fresh
model/artifact volumes. This tests a clean candidate checkout without creating a
commit. Docker build cache is allowed and recorded. Neither historical model
volumes nor the historical image tag are replaced. Per-step logs, failed attempts
and final summaries remain under ignored `.lab/release/reproduction/`.

| Attempt | Outcome |
| --- | --- |
| `20261017T122600Z-6f83746b` | Build/preparation passed; full suite failed because the new release test imported scripts not copied into the image. Added `COPY scripts /app/scripts`; retained the failed run and successful cleanup. |
| `20261017T122855Z-ed30a07a` | 263 tests passed, zero skipped; 144 remote logit comparisons/lifecycle gate passed; smoke completed 6/6 requests and 48 output tokens; isolated cleanup passed. |
| `20261017T123303Z-22d56832` | 263 tests ran with one failure: the existing oversized-gRPC-message test returned DEADLINE_EXCEEDED instead of RESOURCE_EXHAUSTED within its one-second deadline. Cleanup passed; failure retained. |
| `20261017T123541Z-961b89cb` | Final bounded rerun: 263 tests passed in 69.828 seconds, zero skipped; 144 remote comparisons/lifecycle checks passed; smoke completed 6/6 requests and 48 output tokens; isolated cleanup passed. Image/runtime digest is in the compact evidence. |

After the gRPC failure, three explicitly bounded focused runs on that same
image each passed all nine transport tests. One full clean reproduction was
then repeated; the compact summary records its outcome. No transport timeout
or expected error was relaxed and no automatic test retry was added to CI.
This observed intermittency remains a test-reliability concern to investigate
before describing the suite as stable; passing runs do not erase the failure.

The verified environment is the same Windows laptop and Docker Desktop Linux
engine: Engine 29.8.2, Linux x86_64, 24 exposed logical CPUs, 16,299,212,800 bytes
VM RAM. The driver uses Python 3.12.14; the image pins Python 3.12.15 and the
existing CPU float32/eager runtime. Resource limits and image configuration remain
those in Compose apart from the isolated image/project identities. No shaping or
performance sweep was run. Independent-person/device reproduction remains pending.

## Private reporting and remaining gates

The maintainer prefers no published email address. GitHub metadata confirms
private visibility and admin access; the private-reporting endpoint returned
404. [GitHub documents this feature for public repositories](https://docs.github.com/en/code-security/how-tos/report-and-fix-vulnerabilities/configure-vulnerability-reporting/configure-for-a-repository).
`SECURITY.md` documents the no-email GitHub route and its current unavailability.
`scripts/verify_security_reporting.py` returns an explicit blocked status for a
private repository and never changes visibility. Its unit tests verify that
enabling an already public repository requires a read-back check.

No reporting email, test advisory, message, remote commit, push, release tag,
public image or visibility change was made. At a later authorized publication,
run hosted CI and enable/read back private reporting before announcing the source
preview. New model/image distribution still requires its own obligations review.
See [release readiness](../OPEN_SOURCE_RELEASE.md) for the remaining decisions.
