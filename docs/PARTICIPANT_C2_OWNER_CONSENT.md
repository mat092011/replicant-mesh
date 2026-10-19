# C2 device owner-consent store

`steamboat_connector.owner_consent` is a private preparatory primitive for future
C2 local startup wiring. Operator setup explicitly provisions a protected
`owner-consent.json` in an existing native 0700 directory. The file pins one
account/device and starts with an empty enabled-role set at epoch zero. Existing
connector state v1 booleans are never imported. Re-provisioning an existing
store fails; there is no silent reset or re-enrollment path.

`OwnerConsentStore.set_role_enabled(role, enabled)` requires an exact supported
role and boolean, persists the full sorted role projection, and advances the
single device-wide epoch for every explicit enable/disable call. `begin_start`
requires the exact nonempty sorted enabled-role tuple, advances that same epoch
for the start intent, durably writes before yielding, and holds both per-instance
lifetime ownership and cross-process flock until context exit. Callers must keep
selected-head serialization through the local launch claim and every immediate
owned process publication; they must check the independent cancellation event at
each publication. Stop/cancel must only signal that event and must not acquire
this store lock. Release the context before READY observation.

The immutable snapshot and its digest are inert bookkeeping. They do not prove
enrollment, selected-head validity, claim acceptance, process ownership, or
readiness. The principal arguments must come from trusted operator setup, not a
public request or parsed plan. A same-UID actor able to replace protected local
storage can roll back a file; this prototype has no external rollback anchor.
A failed write after temporary-file creation latches the instance and leaves
recovery debris, causing a later constructor to fail closed for operator
inspection. There is no automatic recovery or migration from v1 state.

Native POSIX permission, no-follow, flock, file fsync, and directory fsync
guarantees are platform-specific; native store tests skip on Windows. Focused
test command: `python -m unittest tests.connector.test_owner_consent`.
