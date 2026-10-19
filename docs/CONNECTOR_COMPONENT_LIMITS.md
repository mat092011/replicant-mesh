# Component handler allocations

`WorkerHandler` normally uses the complete limits from the verified v1 model
manifest. When several component handlers run under one host role, the trusted
role owner may pass an explicit `owner_limits` dictionary to
`WorkerHandler` or `build_assigned_worker_handler`. The supported keys are
`max_sessions`, `worker_cache_positions`, `worker_cache_bytes`, and
`request_timeout_seconds`. Each supplied value must be an exact positive
integer no larger than that field's manifest value. Omitted fields keep the
manifest value.

The handler copies its limit mapping before applying these values. The signed
manifest, nested manifest limits, and fingerprint remain unchanged. A worker
builder validates the narrowing before constructing the assigned executor, so
invalid allocations fail before stage weights are loaded. The existing queue
capacity remains a separate handler setting and continues to be bounded by the
manifest queue ceiling.

These are per-handler admission ceilings. The caller that creates component
handlers must provide explicit, disjoint allocations and ensure their aggregate
fits the host role's unchanged v1 budgets. The handler does not prove that
other handlers or processes have been counted, that the caller is authorized to
allocate the host, or that physical memory, queues, CPU, disk, or traffic are
actually reserved. Trusted binding of the caller to an aggregate allocation
authority remains pending C2 work. Narrowing one handler alone is therefore
not proof of aggregate resource safety or physical enforcement.
