# C2 physical-pool config data contract

`steamboat_connector.c2_pool_config` defines the closed, bounded data contract
for a future native POSIX physical-resource owner. It parses canonical UTF-8
JSON of at most 4,096 bytes into frozen Python dataclasses, validates internal
resource-allocation relationships, and can serialize the value deterministically
or calculate its SHA-256 digest.

The exact root profile is `native_posix_c2_physical_pool_v1` with integer
`schema_version: 2`. The root document contains exactly:

| Field | Constraint |
| --- | --- |
| `physical_host_id`, `allocation_id` | Exactly 64 lowercase hexadecimal characters each |
| `pool_kind` | Exactly `system_ram` |
| `pool_id` | Nonempty UTF-8 text, at most 128 bytes, no control characters |
| `owner_uid` | Exact integer, 0 through 2³¹−1 |
| `operator_root`, `cgroup_parent` | Normalized absolute POSIX paths; neither may be `/` |
| `memory_ceiling_bytes`, `disk_ceiling_bytes` | Exact positive integers up to 2⁶³−1 |
| `memory_headroom_bytes`, `swap_max_bytes` | Exact nonnegative integers up to 2⁶³−1 |
| `cpu_quota_millis` | Exact integer from 1 through 100,000 |
| `pids_max` | Exact integer from 1 through 1,000,000 |
| `control` | Closed nested allocation described below |

`control` contains exactly `memory_bytes`, `cpu_quota_millis`, `pids_max` and
`disk_bytes`. Memory, CPU and PID values must be positive exact integers;
control disk bytes may be zero. The control allocation plus memory headroom
must remain strictly below the memory ceiling; control CPU and PIDs must leave
some allocation available for execution; control disk may equal, but cannot
exceed, the disk ceiling. Boolean values are rejected for integer fields.

The parser rejects duplicate keys, unknown or missing fields, non-finite
numbers, floats, noncanonical encodings, invalid UTF-8, and documents larger
than 4,096 bytes. Canonical input uses sorted keys, compact separators, UTF-8,
and no trailing newline, matching the repository's `json_bytes` encoding.
Paths are checked lexically for absolute normalized POSIX form, traversal,
repeated separators, dot segments, trailing separators, control characters,
NUL and backslash.
No filesystem call is made.

Example document, shown pretty-printed for readability:

```json
{
  "schema_version": 2,
  "profile": "native_posix_c2_physical_pool_v1",
  "physical_host_id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "allocation_id": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
  "pool_kind": "system_ram",
  "pool_id": "primary-system-memory",
  "owner_uid": 1000,
  "operator_root": "/var/lib/steamboat/operator",
  "cgroup_parent": "/sys/fs/cgroup/steamboat",
  "memory_ceiling_bytes": 8589934592,
  "memory_headroom_bytes": 536870912,
  "cpu_quota_millis": 4000,
  "pids_max": 256,
  "swap_max_bytes": 0,
  "disk_ceiling_bytes": 10737418240,
  "control": {
    "memory_bytes": 1073741824,
    "cpu_quota_millis": 500,
    "pids_max": 32,
    "disk_bytes": 1073741824
  }
}
```

To validate a canonical byte document and inspect its stable identity:

```python
from steamboat_connector.c2_pool_config import (
    c2_pool_config_sha256,
    parse_c2_pool_config,
)

config = parse_c2_pool_config(raw_config_bytes)
config_sha256 = c2_pool_config_sha256(config)
```

This contract is data validation only. A config value, its digest, or its
paths are not authority and do not prove a shared operator directory, cgroup
mount, physical-host identity, or quota. The trusted launcher must independently
pin the expected host ID, operator root, cgroup parent, UID and document digest.
The future kernel owner must then inspect actual cgroup-v2 descriptors, mounts,
hierarchy, ancestor limits and capabilities; it must also coordinate
generation-ledger admission and retirement. This module has no file access,
locks, callbacks, Torch imports, kernel enforcement, disk enforcement or
bandwidth enforcement. It leaves the existing v1 `PoolControllerLock` and
resource-ledger APIs unchanged. No physical-pool implementation or C2 gate is
completed by adding this schema parser.

Run the portable tests from the repository root with:

```text
python -m unittest -v tests.connector.test_c2_pool_config
```
