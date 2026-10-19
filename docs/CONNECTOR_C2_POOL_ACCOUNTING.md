# C2 physical pool accounting data contract

`steamboat_connector.c2_pool_accounting` defines a closed, immutable declaration
of the enabled C2 compute-role allocations and per-request duration maxima. It
validates those declarations against one exact
[`C2PoolConfig`](CONNECTOR_C2_POOL_CONFIG.md), including that config's canonical
SHA-256 digest. The role set may contain `host`, `coordinator`, or both, in that
order. Each enabled role has exactly one allocation and one request-duration
maximum.

The pool charge counts control memory, CPU, PIDs, and disk once. Memory also
reserves configured headroom once. The sum must fit the configured ceiling;
equality is accepted. Request durations are independent per-request limits in
the range 1–300 seconds and are not summed or treated as resource capacity.
Role memory, CPU, and PIDs must be positive exact integers. Role disk is a
nonnegative exact integer. Booleans, floats, non-finite JSON values, and
integer subclasses are rejected.

The immutable generation descriptor binds one enabled plan role, the current
32-lowercase-hex boot ID grammar, a 64-character lowercase policy SHA-256, the
same C2 config digest, and a cgroup basename matching the existing bounded
`participant-[a-z0-9-]{1,40}` resource-controller grammar. Generation codec
operations require the exact accounting plan as well as the pool config, so a
descriptor cannot name a role absent from that plan. It is a data declaration;
it does not establish that the named generation or cgroup exists.

Plan and generation values each have a closed canonical JSON codec bounded to
8,192 bytes, with duplicate-key rejection, deterministic key ordering, compact
UTF-8 encoding, and SHA-256 helpers. Parsing and serialization revalidate exact
dataclass classes, nested exact types, role order and uniqueness, request
coverage, aggregate fit, and config digest. Output documents are fresh copies.

Example use:

```python
from steamboat_connector.c2_pool_accounting import (
    C2RoleAllocation,
    build_c2_pool_accounting_plan,
    canonical_c2_pool_accounting_bytes,
    c2_pool_accounting_sha256,
)

plan = build_c2_pool_accounting_plan(
    config,
    (C2RoleAllocation("host", 2_000_000_000, 900, 64, 100_000_000),),
    {"host": 120},
)
encoded = canonical_c2_pool_accounting_bytes(plan, config)
digest = c2_pool_accounting_sha256(plan, config)
```

This module is data-only. It performs no filesystem access, locking, persistence,
kernel inspection, resource enforcement, process ownership checks, request
execution, release, or reclamation. It exposes no `reclaimed=True` operation and
does not mint physical capabilities. A future protected owner/generation ledger
must establish admission, reserve resources, bind descriptors to actual
generations, and require exact retirement evidence before releasing an
allocation. The existing v1 resource ledger remains unchanged. This contract
does not establish physical C2 acceptance or any performance result.

Run its portable unit tests from the repository root with:

```text
python -m unittest -v tests.connector.test_c2_pool_accounting
```
