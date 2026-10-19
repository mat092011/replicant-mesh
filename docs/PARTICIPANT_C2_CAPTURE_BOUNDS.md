# C2 retained-capture reservation and parser controls

The worker RPC admission constants reserve a full supported capture for every
slot before decoding. Their arithmetic is:

| Lane | Per admission | Slots | Reserved total |
| --- | ---: | ---: | ---: |
| Data | `8 × 1,048,576 + 64 × 32,768 + 16 × 8,192 + 131,072` = **10,747,904 B** | 9 | **96,731,136 B** |
| Control | `8 × 8,192 + 64 × 32,768 + 16 × 8,192 + 131,072` = **2,424,832 B** | 8 | **19,398,656 B** |

The combined capture reservation is **116,129,792 B** (about 110.75 MiB) for
the two lanes. It is a logical per-role reservation, not measured resident
memory or the worker's whole-process or OS memory limit.

The budget terms account for representations that can coexist during one
admission:

- The immutable transport message remains reachable from the capture owner;
  `decode_bundle` creates separate envelope, binding and protobuf byte strings.
- The generated protobuf parser builds native message storage while decoded
  bytes remain owned. The parsed Request, authorization and operation remain
  retained until retirement. The `8 × protobuf` term allows overlap for these
  byte/native forms and transient serialization or validation copies. It is a
  conservative allowance, not evidence that eight full copies coexist.
- Envelope UTF-8 decoding and JSON parsing can expand short values into Python
  strings, dictionaries, lists and object references before schema/signature
  checks finish. The `64 × envelope` term allows this object expansion and
  temporary copies. The `16 × binding` term reserves parsing, canonical
  representation and temporary binding copies.
- The fixed 128 KiB covers bounded RPC owner records, metadata, task bookkeeping
  and small temporaries per capture. It excludes separately reserved transport
  and reassembly buffers, TLS state, decoded-message queues and model/session
  state.

These are explicit accounting assumptions pending role-level measurement. They
do not prove a whole-role peak: parser phases overlap with TLS, transport,
queues, authorizations, model weights, KV state and allocator-retained pages.

The Linux regression launches one fresh CPython process per fixture using
`-I -S`. It explicitly bootstraps the checkout source plus that interpreter's
purelib/platlib paths; it does not depend on `PYTHONPATH`. Imports complete
before the RSS/high-water baseline, then tracemalloc starts before construction
of the wire payload and retained owners. Three cases retain their raw bundle,
decoded fields, parsed Request, `CopyFrom` copy and serialized round trip where
applicable: the maximum supported data tensor, a 900 KB repeated-shape payload
refused by preflight, and a maximum-control envelope containing a dense array of
short dictionaries plus an 8 KiB protobuf. The JSON dictionary array gives the
64× expansion allowance a high-object-count parser case.

Each case reports Python traced current/peak, current RSS before/after, and
`ru_maxrss` before/after. Python traced peak is checked against that lane's
per-admission reservation because fixture construction, wire copies and retained
representations are included. A native high-water delta is checked against the
same bound only when the process high-water baseline did not exceed current RSS
and the case advances the high-water. Otherwise native peak is explicitly
reported as unmeasured: an earlier high-water can hide the target allocation.
Neither result proves isolated process or OS containment.

The fixtures are parser/wire captures, not authenticated C1 captures: their
binding bytes are placeholders and no signature or authorization check is
claimed. The max-envelope test validates only the bounded envelope parser path.
The native probe is skipped outside Linux. No C1 authority, resource limits,
behavior or protocol grace changes are implied.
