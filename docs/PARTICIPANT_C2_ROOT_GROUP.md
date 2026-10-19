# C2 selected-root host group scope

This document records a bounded parser and signed-policy primitive for a C2
host group. It is not an implementation of C2 admission, worker startup,
resource enforcement, or readiness. The scope authorizes a declaration covering
one to three named worker component tuples under one host credential and one
parent runtime boot. It does not derive multiple C1 local identities from that
credential.

The canonical JSON scope pins the selected generation, host account/device and
credential, admission epoch, parent boot, model and catalog identity, operator
key, and each sorted component's worker boot, assignment, and channel keys.
Closed schemas, exact integer types, duplicate-key rejection, C1 identity
grammars, and the 16 KiB limit are enforced. Parsed values are immutable typed
objects. The signed policy has a separate C2 P-256/SHA-256 domain, low-S
signatures, a 24 KiB envelope limit, and a maximum 300-second lifetime. The
caller supplies the trusted operator verification key and expected principal
and selected-root pins.

The scope contains no file paths, resource allocations, local identity,
readiness state, or self-referential policy hash. A later selected runtime
configuration must pin the signed policy document digest and separately bind
protected references and compiled resource allocations. Loader, claim,
rotation, daemon, installation, and runtime integration remain out of scope.

The existing C1 validators and behavior are unchanged. The parser/policy tests
exercise malformed, swapped, missing, repeated, and mismatched fields, canonical
encoding, bounds, signature/key pins, deadlines, clock rollback, and caller
mutation. Passing these unit tests is component validation only; it does not
pass any C2 phase gate or establish process execution or readiness.
