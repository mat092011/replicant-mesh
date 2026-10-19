# C2 retained-capture reservation and parser controls

The worker RPC admission constants currently reserve a full supported capture
for every slot before decoding. Their arithmetic is:

| Lane | Per admission | Slots | Reserved total |
| --- | ---: | ---: | ---: |
| Data | `8 × 1,048,576 + 64 × 32,768 + 16 × 8,192 + 131,072` = **10,747,904 B** | 9 | **96,731,136 B** |
| Control | `8 × 8,192 + 64 × 32,768 + 16 × 8,192 + 131,072` = **2,424,832 B** | 8 | **19,398,656 B** |

The combined capture reservation is **116,129,792 B** (about 110.75 MiB) for
the two lanes. This is a per-role logical reservation, not a measurement of
resident memory and not the worker's whole-process or OS memory limit.

The terms follow the objects retained or created while one admitted operation
is decoded and owned:

- The immutable transport message remains reachable from the capture owner;
  `decode_bundle` makes separate envelope, binding and protobuf byte strings.
- The generated protobuf parser builds native message storage while the decoded
  protobuf bytes remain retained. Request authorization and execution also
  retain the parsed request until confirmed retirement. The `8 × protobuf`
  term reserves overlap for these byte and native-message representations and
  transient serialization/validation copies. It is a conservative budget
  multiplier, not a claim that eight full copies were observed simultaneously.
- The envelope is decoded as UTF-8 and parsed into Python dictionaries, lists,
  strings and scalar objects before signature/schema checks complete. The
  `64 × envelope` term is an explicit expansion allowance for short JSON values
  and Python container/object overhead. The binding is separately parsed and
  canonicalized; `16 × binding` reserves its corresponding expansion and
  temporary canonical representation.
- The fixed 128 KiB covers bounded RPC owner records, tuples, metadata, task
  bookkeeping and small temporary objects per capture. It does not include the
  independently reserved stream/reassembly buffers or decoded-message queues.

The factors are admission assumptions requiring empirical review. They do not
prove a whole-role peak: multiple phases can overlap with TLS buffers, framed
transport/reassembly, queued messages, active authorizations, model weights,
session KV state, allocator arenas and other process state. The capture parser
subprocess test reports Python `tracemalloc` peak and Linux RSS/high-water
observations after imports and fixture construction. Since native protobuf
allocations are invisible to `tracemalloc`, the RSS observation complements
it; it still measures one parser subprocess only, and a before/after high-water
measurement may miss allocator-retained pages or peaks attributable to the
runtime baseline. It is not OS isolation evidence.

`tests/connector/test_channel_capture_bounds.py` covers the exact generated
`Worker.proto` parser with the supported `1×1152×64 float32` tensor, rejects a
near-megabyte repeated shape in preflight before the parse stage, and exercises
duplicate/nonminimal wire encodings plus a near-limit JSON envelope. Its Linux
subprocess measurement is explicitly skipped on non-Linux hosts. These checks
do not alter C1 authority, resource limits, behavior or protocol grace.
