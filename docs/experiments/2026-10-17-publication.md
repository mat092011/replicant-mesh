# Public source preview

Date: 2026-10-17. The maintainer explicitly authorized committing and pushing all
prepared source changes and making `mat092011/steamboat_net` public.
Commit `d10d762e3095fdec488ac33894519a3291c3cb58` contains the Apache-2.0 source
preview, documentation, inventories, CI and release tooling. It was pushed
normally to `main`; no force push, package/image upload or versioned release tag
was used.

## Publication and reporting

- [Repository](https://github.com/mat092011/steamboat_net) visibility is public,
  verified through authenticated metadata and an anonymous GitHub API request.
- Private vulnerability reporting was enabled and the setting read back as
  `enabled: true` using `scripts/verify_security_reporting.py --enable`.
- [Report a vulnerability](https://github.com/mat092011/steamboat_net/security/advisories/new)
  is the GitHub-only route; no email address is required or published.
  Verification checked the setting; no test advisory or message was submitted.

## Hosted checks

The initial [Source checks run](https://github.com/mat092011/steamboat_net/actions/runs/39034954408)
completed successfully for `d10d762`: both `source` and `secrets` jobs passed.
This covers the explicit Linux fast suite, source/local-link checks, both Compose
configurations, mocked network-reset regressions and pinned full-history/source
secret scanning. The separate
[CPU runtime gate](https://github.com/mat092011/steamboat_net/actions/runs/39034964582)
also completed successfully for that same commit. It built the pinned image,
prepared fresh model artifacts, passed 263 tests and 144 remote comparisons,
completed all six smoke requests with 48 output tokens, cleaned up its isolated
volumes, and uploaded the synthetic-workload evidence. The source workflow passed
82 fast tests with zero skips and reported no unallowlisted history/source secret
findings. Documentation follow-ups receive their own source-check runs; runtime
source/configuration is unchanged by the publication documentation update.

## Scope and retained limitations

The [pre-publication record](2026-10-17-release-readiness.md) preserves the clean
local reproduction, licensing/ownership evidence, reviewed scanner exceptions
and failed attempts. One existing one-second gRPC size-limit test returned a
deadline error in a local full-suite attempt; three focused transport runs and
the final full-suite rerun passed without relaxing the assertion. Publication
does not establish that this test is stable.

The software remains an experimental private-network runtime. Making its source
public does not expose inference services or make unauthenticated RPC suitable
for public deployment. No new WAN performance, pooled-GPU, credit or broader
research-phase completion is claimed. Model/image distribution and future
versioned releases need separate review.
