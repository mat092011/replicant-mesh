# C2 coordinator channel integration fixture (WIP)

`tests/connector/c2_coordinator_channel_fixture.py` is a native-only fixture
scaffold that starts from the real selected coordinator/artifact fixture and
prepares separate persistent policy and traffic owners for a loopback gateway.
It does not claim model execution, coordinator listener readiness, or a complete
three-worker route.

The integration test is deliberately skipped until the fixture's selected
generation rewrite, signed C1 worker grants, worker HELLO client progression,
and teardown ordering have been completed and checked on the pinned Linux
runtime. In particular, the current fixture does not yet complete worker HELLO
before waiting for gateway worker registration. Do not count this WIP entry
point as a passing C2 component gate.

The intended native command is the repository's selected connector/security
component gate with `STEAMBOAT_C2_STARTUP_ARTIFACTS` pointing at the approved
offline artifact directory. It has not been run for this WIP.
