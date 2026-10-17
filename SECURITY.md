# Security policy

## Supported scope

This is an experimental trusted private lab, with no production deployment or
stable supported releases. Security fixes target the current development code;
older experiment images remain historical evidence, not supported services.
RPC currently has no authentication or encryption. Do not publish its ports or
use untrusted workers. Use public/synthetic prompts; worker owners can inspect
computation and activations do not provide prompt confidentiality.

## Private vulnerability reporting

The maintainer chose GitHub reporting without publishing an email address.
The repository is currently private. GitHub private vulnerability reporting is
available for public repositories, so an external reporting route cannot yet be
verified under that visibility. No email address or functioning public reporting
channel is implied by this policy.

Before any public source release, the maintainer must enable private reporting
and verify it with:

```powershell
python scripts/verify_security_reporting.py --enable
```

This command never changes visibility. Once the public repository's setting is
verified, use [Report a vulnerability](https://github.com/mat092011/steamboat_net/security/advisories/new)
to open a private GitHub report. If the link is unavailable, do not submit
credentials, private data or exploit details to a public issue. The source
release remains gated until the intended private route is available.

A report should identify the affected revision, environment, impact and minimal
reproduction using synthetic data. Include sensitive detail only inside a
verified private report. There is no automated response-time or bounty promise.

The current verification result and release limitations are recorded in the
[release review](docs/OPEN_SOURCE_RELEASE.md). No test advisory or message is
sent by the verification command.
