# Protocol v1 source and generated binding

`worker.proto` is the source schema. `worker_pb2.py` was generated with
`grpcio-tools==1.84.0` (bundled Protobuf compiler 7.35.1); the runtime image pins
`protobuf==7.36.2` and `grpcio==1.84.0`. The generic async gRPC adapter uses the
service descriptor's explicit method names and needs no generated gRPC stub.

Regenerate from the repository root in the pinned Linux image (PowerShell):

```powershell
docker.exe run --rm -v "${PWD}:/app" steamboat-pytorch:cpu sh -c 'python -m pip install --no-deps --target /tmp/protoc "https://files.pythonhosted.org/packages/74/18/d9fa4b43c4974094a9e720e97fc90fcba1908f8c806b36eefabf6c148d88/grpcio_tools-1.84.0-cp312-cp312-manylinux2014_x86_64.manylinux_2_17_x86_64.whl#sha256=fc1708de3ba6cc46eff02de1aea865442418167794ca963a2cf6ea2013930146" && PYTHONPATH=/tmp/protoc python -m grpc_tools.protoc -I/app/src --python_out=/app/src /app/src/steamboat_runtime/protocol/worker.proto'
```

The compiler is installed only in the disposable generation container. It does
not change the image or its runtime dependency lock. The generated binding is
checked in so normal execution does not install development tooling.

Requests and responses are capped at 1 MiB before Protobuf parsing and unknown
fields are rejected in v1. Activation bytes are dense little-endian float32 with
shape `[1, token_count, 64]`; empty, non-finite, oversized, incorrectly typed and
inconsistently sized activations are rejected. No Python object serialization is
accepted. The serialized in-memory and loopback gRPC transports use the same
handler and parsing boundary; neither retries an operation automatically.

The gRPC adapter defaults to loopback. M3's explicit `private_network=True` option
also supports RFC1918 IPv4 addresses, simple Docker service names for clients,
and `0.0.0.0` for container listeners. Compose supplies the network isolation;
the option supplies no authentication or encryption. No host ports are published.
All participants must use the same schema build: M3 adds response fields 39/40
for queue counts/capacity, and M4 adds fields 41–44 for execution-thread monotonic
spans, clock identity and a Describe clock sample. Older strict v1 decoders reject
unknown fields. Rebuild/recreate all workers when moving to the M4 code.
Timeout/disconnect can leave an operation committed without a received reply.
Callers must terminate the affected session and release reservations; resending
the same step is not recovery. The later coordinator owns cross-worker cleanup.
