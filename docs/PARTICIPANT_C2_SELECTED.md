# C2 selected-cohort validation foundation

`steamboat_security.root_c2_selected.validate_c2_selected_cohort` is a bounded
callback for `RootGenerationStore.read_selected`. It accepts only the distinct
`steamboat-root-c2-activation-v1` version-1 manifest, verifies selected artifact
hashes and exact old/new launch documents, validates closed host-group scopes,
and checks the baseline and currently selected signed policy with pinned
authorities and the supplied trusted `Clock`.

Empty host-group lists are supported for coordinator-only C2 cohorts. When groups
are present, the declaration pins a host identity and its exact one-to-three
component tuples. The returned frozen view contains parsed launch specs and
scopes; nested scope output is freshly serialized from immutable values.

This component does not mint local identity, create a runtime binding, start a
role, consume a launch claim, authorize bootstrap, prove readiness, or establish
that workers executed the declared components. It does not implement the retained
grant-rotation mapping builder. Current-policy checks constrain grants to the
selected cohort and declared scope but do not prove truthful execution or resist
collusion. C1's singular profile and activation manifest remain unchanged, and
the C1 manifest domain is rejected by this callback.

The validator enforces the root store limits of 13 artifacts, 64 KiB per
artifact, and 512 KiB total, plus a 16 KiB total bound across host-group scope
documents. Focused native POSIX tests use real signed snapshot and CA fixtures
and the durable root-store layout. Run them with the repository's configured
Python from the repository root:

```text
PYTHONPATH=src python -Xutf8 -B -m unittest tests.security.test_root_c2_selected -v
```

Windows does not implement the durable `RootGenerationStore` tests; those cases
are skipped there. No C2 activation, startup, claims, grant rotation, or runtime
binding is implied by this validation foundation.
