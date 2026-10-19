# C2 selected-cohort validation foundation

`steamboat_security.root_c2_selected.validate_c2_selected_cohort` is the bounded
parser for C2 selected data. `make_c2_selected_validation_callback` adapts it to
`RootGenerationStore.read_selected`: the callback captures the validated view
and returns `None`, as the store requires. It accepts only the distinct
`steamboat-root-c2-activation-v1` version-1 manifest, verifies selected artifact
hashes and exact old/new launch documents, validates closed host-group scopes,
and checks the baseline and currently selected signed policy with pinned
authorities and the supplied trusted `Clock`.

Empty host-group lists are supported only when the new launch cohort has no host
roles. Every new host role requires a corresponding closed scope with its exact
one-to-three component tuples. Old group lists may be empty when the previous
generation used the earlier singular host profile. Old and new launch plans must
cover the same identities; old roles share one generation, and credential and
admission epochs advance by one. The returned frozen view contains parsed launch
specs and scopes; nested scope output is freshly serialized from immutable values.

This component does not mint local identity, create a runtime binding, start a
role, consume a launch claim, authorize bootstrap, prove readiness, or establish
that workers executed the declared components. It does not implement the retained
grant-rotation mapping builder. Current-policy checks constrain grants to the
selected cohort and declared scope but do not prove truthful execution or resist
collusion. C1's singular profile and activation manifest remain unchanged, and
the C1 manifest domain is rejected by this callback.

The validator enforces the root store limits of 13 artifacts, 64 KiB per
artifact, and 512 KiB total, plus a 16 KiB total bound across host-group scope
documents. Baseline snapshots have their signature and schema checked without
requiring the immutable baseline grants to remain live; the selector's exact
bounded active snapshot bytes are independently checked against its hash and
current policy head. Portable tests use real signed snapshot and CA fixtures.
The store-adapter integration test uses the durable POSIX root-store layout. Run
them with the repository's configured Python from the repository root:

```text
PYTHONPATH=src python -Xutf8 -B -m unittest tests.security.test_root_c2_selected -v
```

Windows does not implement the durable `RootGenerationStore` tests; those cases
are skipped there. No C2 activation, startup, claims, grant rotation, or runtime
binding is implied by this validation foundation.
