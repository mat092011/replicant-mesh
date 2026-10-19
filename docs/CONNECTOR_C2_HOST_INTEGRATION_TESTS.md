# C2 selected host process integration fixture

This test composes one already selected host role through the fixed process
supervisor. The intended native run uses the approved offline `/artifacts`
directory and Linux CPython 3.12. It starts the real child with `Popen`, passes
the artifact pin and ClockBridge through the supervisor gate, loads the actual
selected C2 binding and assigned worker stage, connects over signed loopback
mTLS, completes worker TLS/HELLO, observes the supervisor's `READY`, then asks
the supervisor to stop, reap and release the process.

The parent event loop continues pumping the actual `GatewayService` while the
blocking supervisor start, READY and Stop operations run in worker threads.
Both gateway listener endpoints are signed into the policy with distinct
purpose and distinct ports. The host endpoint is numeric loopback and the
operator-issued gateway certificate has a matching IP subject alternative
name. No DNS remapping or TLS verification bypass is used.

The fixture preserves the selected root's test-controlled wall time and uses
the actual Linux monotonic clock for the exact `Clock` passed to the store,
artifact verifier, traffic ledger and supervisor. This allows the inherited
ClockBridge to compare against the kernel clock. Its uncertainty callback is a
test fixture setting; this does not establish trusted wall-clock accuracy.

`LifecycleCgroupStandIn` supplies only the filesystem events that the
supervisor uses to verify child-tree lifecycle and removal. It does not apply
CPU or memory limits. Child creation, process ownership, signal delivery,
reaping, pin release, protected storage, signatures, model stage execution,
TLS and HELLO are the actual implementations. The test does not start a
coordinator, establish a complete gateway route, send inference requests, or
claim physically enforced resource quotas.

Run the focused native case with:

```text
python -m unittest tests.connector.test_c2_host_process_integration -v
```

On other platforms or without the offline artifacts, unittest reports the
single native case as skipped. No result is recorded by this preparation
change; the parent native runner must record the bounded environment and
output before the test can count as evidence.
