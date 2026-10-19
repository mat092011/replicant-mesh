# C2 per-device local plan foundation

`steamboat_security.root_c2_local_plan` derives an immutable, bounded projection
of the selected global C2 cohort for one local account and device. It first
calls `validate_c2_selected_cohort` with the raw selected selector, artifact
bytes, active policy bytes, and exact `Clock`; a caller-supplied
`C2SelectedCohort` object is not accepted as evidence. The account, device,
enable epoch, and enabled-role tuple are inputs from the protected local daemon
owner state. Peers and selected grants do not choose local opt-in.

The plan retains every selected role belonging to that account/device, divides
those declarations into enabled and disabled projections, and carries the
matching host-group scopes. Remote selected roles remain part of the global
cohort digest and never enter the local enabled projection. Disabled host
scope data remains inert; only enabled host groups are represented as enabled.
An empty enabled-role tuple is a valid paused plan with no enabled launch work.
The canonical document has a SHA-256 digest over all plan fields except that
digest itself. Parsing applies the existing closed launch-spec and host-scope
grammars again. Revalidation derives a fresh plan from fresh raw global inputs
and compares it with the document and the expected trusted enable snapshot, so
global-head, principal, enable-epoch, role omission, disabled-role activation,
and field changes reject.

`read_selected_c2_local_plan` follows `RootGenerationStore.read_selected`'s
callback contract: its callback captures the inert plan and returns exactly
`None`. The adapter's returned object is not a launch capability.

This is a projection foundation only. A future local claim version and API
must bind the local plan digest, enable epoch, selector/activation/global
cohort digests, and the exact enabled local specs. The current global
`C2LaunchClaimStore` claims the entire selected cohort; that claim cannot prove
local opt-in, process start, process ownership, or retirement. A startup caller
will need to hold synchronization for the protected local enable snapshot and
the global protected head through local claim creation and immediate
`Popen`-ownership registration, then release it before waiting for readiness.
Stop cancellation and retirement require their own checks. No such local
claim/startup/readiness integration is implemented here, and this work does
not close C1a, C1b, C1, P2, or a C2 gate.

Run the portable component checks with:

```powershell
python -m unittest tests.security.test_root_c2_local_plan -v
```

The tests use the existing signed C2 selected-cohort fixture. They exercise
validation, local projection, paused state, canonical revalidation, and the
store callback shape. The optional native protected-store integration remains
outside this module's portable test matrix.
