# Security policy

## Supported scope

This is an experimental trusted private lab, with no production deployment or
stable supported releases. Security fixes target the current development code;
older experiment images remain historical evidence, not supported services.
RPC currently has no authentication or encryption. Do not publish its ports or
use untrusted workers. Use public/synthetic prompts; worker owners can inspect
computation and activations do not provide prompt confidentiality.

## Private vulnerability reporting

GitHub private vulnerability reporting is enabled and its repository setting was
verified again after the repository rename on 2026-10-24. No email address is required. Use
[Report a vulnerability](https://github.com/mat092011/replicant-mesh/security/advisories/new)
to submit a private GitHub report to the maintainer.
The verification script resolves the live repository name by its stable GitHub ID.

The maintainer can recheck the live setting with:

```powershell
python scripts/verify_security_reporting.py
```

The optional `--enable` flag can restore reporting on an already public
repository; the tool never changes visibility. If the reporting link becomes
unavailable, do not submit credentials, private data or exploit details to a
public issue. No test advisory or message was submitted during setup.

A report should identify the affected revision, environment, impact and minimal
reproduction using synthetic data. Include sensitive detail only inside a
verified private report. There is no automated response-time or bounty promise.

The current verification result and release limitations are recorded in the
[release review](docs/OPEN_SOURCE_RELEASE.md). No test advisory or message is
sent by the verification command.
