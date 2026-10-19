# Consumer runtime guard

`SecureConsumerTransport` accepts an optional synchronous `runtime_guard`.
The callback must return exactly `None`; it runs before a request is admitted,
before consumer tokenization and generation, after awaited coordinator work, and
before generated events or results are made observable. The event iterator and
the result awaitable check again when the caller resumes them, so queued output
is withheld after a later invalidation.

`request_runtime_invalidation(reason)` sets a sticky local invalidation event
without waiting for the transport's run-state lock. It may enqueue one
owner-loop cancellation callback; a `False` return means that optional
cancellation was skipped, while admission and delivery remain fenced by the
sticky event. Cancellation records intent only. The existing bounded
`aclose()` and context-close paths still run, and unresolved task/context
ownership remains retained under the existing cleanup-uncertainty rules.

The constructor continues to require the exact `SecureCoordinatorClient` and
`OutboundAuthorizer` instances with their existing shared-authorizer check.
The guard adds no C1 grant, peer identity, or readiness authority. It is an
integration point for a future genuine C2 consumer binding.

`tests/connector/test_consumer_runtime_guard.py` uses the transport's private
fake-client test seam to exercise races, callback ordering, and retained cleanup
ownership. It does not exercise a real C1 coordinator RPC, socket, or C2 owner
binding. The focused command is:

```text
python -m unittest tests.connector.test_consumer_runtime_guard
```
