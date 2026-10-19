"""Selected-C2 binding checks around the real C1 worker runtime bridge."""

from __future__ import annotations

import asyncio
import hashlib
import importlib.util
import os
from pathlib import Path
import threading
import unittest
from unittest import mock

from tests.security import test_gateway_authorization as gateway_tests
from steamboat_security.codec import WORKER_SERVICE, parse_metadata, encode_binding
from steamboat_runtime.secure_worker_runtime import (
    RuntimeBindingError, RuntimeBridgeUnavailable, SecureWorkerRuntimeBridge)


@unittest.skipUnless(
    os.environ.get("STEAMBOAT_ASSIGNED_TEST_SOURCE")
    and importlib.util.find_spec("google.protobuf")
    and importlib.util.find_spec("torch"),
    "Requires the assigned runtime artifacts, protobuf and Torch",
)
class RuntimeC2GuardTests(unittest.IsolatedAsyncioTestCase):
    """Use signed C1 ingress and actual WorkerHandler ownership, not fakes."""

    @classmethod
    def setUpClass(cls):
        from steamboat_runtime.manifest import load_manifest
        cls.artifact_dir = Path(os.environ["STEAMBOAT_ASSIGNED_TEST_SOURCE"]).resolve()
        cls.manifest = load_manifest(cls.artifact_dir)
        cls.model_id = cls.manifest["fingerprint"]

    async def asyncSetUp(self):
        from steamboat_runtime.protocol.worker_pb2 import Request
        from steamboat_runtime.worker_state import WorkerHandler
        from steamboat_security import Authorizer, LocalIdentity

        self.request_type = Request
        self.entered_compute = threading.Event()
        self.release_compute = threading.Event()
        self.guard_live = True

        class Cache:
            def __init__(self, start, end):
                self.start, self.end = start, end
                self.position = 0
                self.bytes = 0

            def lengths(self):
                return [self.position] * (self.end - self.start)

            def allocated_bytes(self):
                return self.bytes

            def clear(self):
                self.position = self.bytes = 0

        class Executor:
            def __init__(self, outer):
                self.outer = outer
                self.start, self.end = outer.manifest["components"]["worker-1"]["layer_range"]

            def new_cache(self):
                return Cache(self.start, self.end)

            def execute(self, hidden, cache, position):
                cache.bytes = 64
                self.outer.entered_compute.set()
                if not self.outer.release_compute.wait(8):
                    raise TimeoutError("test compute was not released")
                cache.position = position + hidden.shape[1]
                return hidden.clone()

        self.fixture = gateway_tests.GatewayAuthorizationTests(
            methodName="test_gateway_open_step_close_share_c1_and_ingress_session_ownership")
        # The C1 fixture is real; bind its signed policy to the actual assigned
        # manifest used by WorkerHandler below.
        self.model_patch = mock.patch.object(
            gateway_tests.ingress_tests.delegation_tests, "MODEL", self.model_id)
        self.model_patch.start()
        self.addCleanup(self.model_patch.stop)
        gateway_tests.GatewayAuthorizationTests.setUpClass()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.worker = self.fixture.fixture.payload["workers"][0]
        self.authorizer = Authorizer(
            local_identity=LocalIdentity(
                self.fixture.fixture.host_pem, self.worker["worker_boot_id"],
                self.model_id, self.worker["assignment_id"]),
            snapshot_store=self.fixture.snapshot_store,
            clock=self.fixture.clock,
            session_bindings=self.fixture.ingress_fixture.sessions,
            worker_request_type=Request)
        self.handler = WorkerHandler(
            self.manifest, "worker-1", Executor(self),
            boot_id=self.worker["worker_boot_id"])

        def guard():
            if not self.guard_live:
                raise RuntimeError("fixture binding expired")

        self.guard = guard
        self.bridge = SecureWorkerRuntimeBridge(
            self.authorizer, self.handler, runtime_guard=guard,
            sweep_interval_seconds=0.02)
        await self.bridge.start()

    async def asyncTearDown(self):
        self.release_compute.set()
        if self.bridge._started and not self.bridge._closed:
            await self.bridge.stop(grace_seconds=1)
        if not self.handler.stopping:
            await self.handler.shutdown(grace_seconds=1)

    def _request(self, method, *, session_id=None, lease_token=""):
        from steamboat_runtime.protocol.worker_pb2 import Request
        metadata = parse_metadata(WORKER_SERVICE, "OpenSession", self.fixture.fixture.metadata)
        values = dict(
            protocol_version=1, manifest_fingerprint=self.model_id,
            worker_boot_id=self.worker["worker_boot_id"],
            session_id=session_id or metadata["session_id"], timeout_ms=30_000,
            lease_token=lease_token)
        if method == "OpenSession":
            values.update(max_positions=2, lifetime_ms=60_000, idle_lease_ms=30_000)
        elif method == "Step":
            import torch
            from steamboat_runtime.protocol.codec import encode_tensor
            values.update(sequence=0, start_position=0, token_count=1,
                          tensor=encode_tensor(torch.zeros(
                              (1, 1, self.manifest["config"]["hidden_size"]))))
        return Request(**values)

    def _admit(self, method, request, *, binding=None):
        f = self.fixture
        binding = binding or f._binding(method)
        raw = request.SerializeToString(deterministic=True)
        ingress = f.ingress_fixture.ingress
        lane = ("control" if method in {"CloseSession", "CancelSession", "SessionStatus"}
                else "data")
        sequence = f.lane_sequences[lane]
        f.lane_sequences[lane] += 1
        envelope = f.fixture.make_delegation(changes={
            "policy_revision": ingress.policy_revision,
            "policy_digest": ingress.policy_digest,
            "stream_generation": ingress.stream_generation,
            "frame_sequence": sequence, "lane": lane,
            "service": WORKER_SERVICE, "method": method,
            "binding_sha256": hashlib.sha256(binding).hexdigest(),
            "request_sha256": hashlib.sha256(raw).hexdigest(),
        })
        auth = self.bridge.incoming_authorizer.authorize_gateway(
            service=WORKER_SERVICE, method=method, payload=request,
            metadata=(("steamboat-binding-bin", binding),), ingress=ingress,
            envelope=envelope, request_bytes=raw,
            frame_sequence=sequence, wire_lane=lane)
        return auth

    async def _open(self):
        request = self._request("OpenSession")
        auth = self._admit("OpenSession", request)
        response = await self.bridge.handler.handle("OpenSession", request)
        auth.complete(response)
        auth.close()
        return request, response

    def test_invalid_and_async_guards_are_rejected(self):
        async def async_guard():
            return None
        with self.assertRaises(TypeError):
            SecureWorkerRuntimeBridge(self.authorizer, self.handler, runtime_guard=object())
        with self.assertRaises(TypeError):
            SecureWorkerRuntimeBridge(self.authorizer, self.handler, runtime_guard=async_guard)

    async def test_guard_must_return_exact_none(self):
        self.bridge._runtime_guard = lambda: True
        with self.assertRaises(RuntimeBridgeUnavailable):
            self.bridge._check_runtime_guard()
        self.assertTrue(self.bridge.unavailable)

    async def test_sync_guard_awaitable_result_is_closed_and_fences(self):
        created = []

        async def returned_coroutine():
            return None

        def guard_returning_coroutine():
            result = returned_coroutine()
            created.append(result)
            return result

        self.bridge._runtime_guard = guard_returning_coroutine
        with self.assertRaises(RuntimeBridgeUnavailable):
            self.bridge._check_runtime_guard()
        self.assertEqual(len(created), 1)
        self.assertIsNone(created[0].cr_frame)
        self.assertTrue(self.bridge.unavailable)

    async def test_guard_failure_prevents_c1_admission_and_handler_dispatch(self):
        calls = []
        original = self.authorizer.authorize_gateway

        def counted(*args, **kwargs):
            calls.append(1)
            return original(*args, **kwargs)

        self.authorizer.authorize_gateway = counted
        self.guard_live = False
        request = self._request("OpenSession")
        with self.assertRaises(RuntimeBridgeUnavailable):
            self.bridge.incoming_authorizer.authorize_gateway(
                service=WORKER_SERVICE, method="OpenSession", payload=request,
                metadata=(), ingress=self.fixture.ingress_fixture.ingress,
                envelope=None, request_bytes=b"", frame_sequence=1, wire_lane="data")
        self.assertEqual(calls, [])
        self.assertEqual(self.handler.sessions, {})
        self.assertTrue(self.bridge.unavailable)
        self.assertTrue(self.bridge.status()["cleanup_confirmed"])

    async def test_guard_change_during_c1_authorization_is_not_published(self):
        original = self.authorizer.authorize_gateway

        def expire_after_core(*args, **kwargs):
            result = original(*args, **kwargs)
            self.guard_live = False
            return result

        self.authorizer.authorize_gateway = expire_after_core
        request = self._request("OpenSession")
        binding = self.fixture._binding("OpenSession")
        raw = request.SerializeToString(deterministic=True)
        ingress = self.fixture.ingress_fixture.ingress
        envelope = self.fixture.fixture.make_delegation(changes={
            "policy_revision": ingress.policy_revision,
            "policy_digest": ingress.policy_digest,
            "stream_generation": ingress.stream_generation,
            "frame_sequence": 1, "lane": "data",
            "service": WORKER_SERVICE, "method": "OpenSession",
            "binding_sha256": hashlib.sha256(binding).hexdigest(),
            "request_sha256": hashlib.sha256(raw).hexdigest(),
        })
        with self.assertRaises(RuntimeBridgeUnavailable):
            self.bridge.incoming_authorizer.authorize_gateway(
                service=WORKER_SERVICE, method="OpenSession", payload=request,
                metadata=(("steamboat-binding-bin", binding),), ingress=ingress,
                envelope=envelope, request_bytes=raw,
                frame_sequence=1, wire_lane="data")
        self.assertEqual(self.bridge.status()["active_authorizations"], 0)
        self.assertEqual(self.handler.sessions, {})
        self.assertTrue(self.bridge.unavailable)

    async def test_blocked_compute_is_retained_until_guarded_delivery_is_denied(self):
        opened, opened_response = await self._open()
        request = self._request(
            "Step", session_id=opened.session_id,
            lease_token=opened_response.lease_token)
        fields = dict(parse_metadata(
            WORKER_SERVICE, "OpenSession", self.fixture.fixture.metadata).fields)
        fields["operation_id"] = "op_" + "a" * 32
        binding = encode_binding(WORKER_SERVICE, "Step", fields)
        # Admission uses the real same-session C1 binding and raw protobuf.
        auth = self._admit("Step", request, binding=binding)
        task = asyncio.create_task(self.bridge.handler.handle("Step", request))
        self.assertTrue(await asyncio.to_thread(self.entered_compute.wait, 2))
        entry = self.handler.sessions[request.session_id]
        self.assertTrue(entry.in_flight)
        self.assertGreater(entry.cache.allocated_bytes(), 0)
        self.guard_live = False
        self.release_compute.set()
        with self.assertRaises(RuntimeBridgeUnavailable):
            await asyncio.wait_for(task, 3)
        self.assertTrue(self.bridge.unavailable)
        self.assertTrue(task.done(), "the guarded handler must not deliver an untrusted result")
        auth.close()
        await asyncio.sleep(0)
        self.assertFalse(self.handler.sessions)
        self.assertEqual(self.handler.tombstones[request.session_id].cache.allocated_bytes(), 0)

    async def test_off_loop_invalidation_is_fast_while_bridge_lock_is_held(self):
        lock_held = threading.Event()
        release_lock = threading.Event()
        callback_done = threading.Event()
        callback_result = []
        self.addCleanup(release_lock.set)

        def hold_bridge_lock():
            with self.bridge._lock:
                lock_held.set()
                release_lock.wait(2)

        locker = threading.Thread(target=hold_bridge_lock, daemon=True)
        locker.start()
        self.assertTrue(await asyncio.to_thread(lock_held.wait, 1))

        def invalidate():
            callback_result.append(self.bridge.request_runtime_invalidation("private detail"))
            callback_done.set()

        caller = threading.Thread(target=invalidate, daemon=True)
        caller.start()
        # Deliberately block the owner loop briefly: the synchronous teardown
        # request must only set the sticky event and enqueue one callback.
        self.assertTrue(callback_done.wait(1))
        self.assertTrue(callback_result[0])
        self.assertTrue(self.bridge.unavailable)
        release_lock.set()
        locker.join(1)
        caller.join(1)
        await asyncio.sleep(0)
        self.assertTrue(self.bridge._runtime_fence_applied)
        self.assertFalse(self.handler.requires_restart)
        self.assertNotIn("private detail", self.bridge.status()["fault"])

    async def test_off_loop_invalidation_does_not_wait_for_wake_lock(self):
        self.bridge._wake_lock.acquire()
        self.addCleanup(lambda: self.bridge._wake_lock.release()
                        if self.bridge._wake_lock.locked() else None)
        finished = threading.Event()
        result = []

        def invalidate():
            result.append(self.bridge.request_runtime_invalidation("wake lock test"))
            finished.set()

        thread = threading.Thread(target=invalidate, daemon=True)
        thread.start()
        self.assertTrue(finished.wait(1))
        self.assertFalse(result[0])  # optional wake was skipped; sticky event remains
        self.assertTrue(self.bridge.unavailable)
        self.bridge._wake_lock.release()
        await asyncio.wait_for(self._wait_for_runtime_fence(), 1)
        self.assertTrue(self.bridge._runtime_fence_applied)

    async def _wait_for_runtime_fence(self):
        while not self.bridge._runtime_fence_applied:
            await asyncio.sleep(0.005)

    async def test_c2_fence_is_single_application_and_maintenance_stays_bounded(self):
        await self._open()
        counts = {name: 0 for name in (
            "binding_invalidation", "handler_invalidation", "supervisor",
            "wake", "maintenance_pass")}
        sweep_times = []

        def counted(obj, method_name, key):
            original = getattr(obj, method_name)

            def invoke(*args, **kwargs):
                counts[key] += 1
                return original(*args, **kwargs)
            return invoke

        original_sweep = self.bridge._sweep_once

        def counted_sweep():
            sweep_times.append(asyncio.get_running_loop().time())
            original_sweep()

        patches = (
            mock.patch.object(self.bridge.session_bindings, "invalidate_all",
                side_effect=counted(self.bridge.session_bindings,
                                    "invalidate_all", "binding_invalidation")),
            mock.patch.object(self.bridge._handler, "invalidate_for_authorization",
                side_effect=counted(self.bridge._handler,
                                    "invalidate_for_authorization", "handler_invalidation")),
            mock.patch.object(self.bridge._handler, "_notify_supervisor",
                side_effect=counted(self.bridge._handler, "_notify_supervisor", "supervisor")),
            mock.patch.object(self.bridge, "_signal_wake",
                side_effect=counted(self.bridge, "_signal_wake", "wake")),
            mock.patch.object(self.bridge, "_poll_gateway_ingresses",
                side_effect=counted(self.bridge, "_poll_gateway_ingresses", "maintenance_pass")),
            mock.patch.object(self.bridge, "_sweep_once", side_effect=counted_sweep),
        )
        with patches[0], patches[1], patches[2], patches[3], patches[4], patches[5]:
            self.bridge.request_runtime_invalidation("cadence test")
            await asyncio.wait_for(self._wait_for_runtime_fence(), 1)
            # Observe several ordinary sweep periods after the one immediate
            # fence wake; a repeated wake loop would drive maintenance passes
            # far beyond the configured 20 ms sweep cadence.
            await asyncio.sleep(0.16)

        self.assertEqual(counts["binding_invalidation"], 1)
        self.assertEqual(counts["handler_invalidation"], 1)
        self.assertEqual(counts["supervisor"], 1)
        self.assertEqual(counts["wake"], 1)
        self.assertTrue(self.bridge._runtime_fence_applied)
        self.assertGreaterEqual(len(sweep_times), 4)
        self.assertLessEqual(len(sweep_times), 12)
        self.assertGreaterEqual(counts["maintenance_pass"], len(sweep_times))
        self.assertLessEqual(counts["maintenance_pass"], len(sweep_times) + 4)
        if len(sweep_times) > 1:
            gaps = [right - left for left, right in zip(sweep_times, sweep_times[1:])]
            self.assertTrue(all(gap >= 0.008 for gap in gaps), gaps)
        self.assertFalse(self.bridge._unconfirmed_cleanup)
        self.assertFalse(self.bridge._unavailable)
        self.assertTrue(self.bridge.unavailable)
        self.assertTrue(await self.bridge.stop(grace_seconds=1))
        self.assertTrue(self.bridge.status()["cleanup_confirmed"])

    async def test_real_c1_sweep_fault_stays_unconfirmed_after_c2_fence(self):
        self.bridge.request_runtime_invalidation("C1 fault regression")
        await asyncio.wait_for(self._wait_for_runtime_fence(), 1)
        with mock.patch.object(
                self.bridge.authorizer_core.clock, "sample",
                side_effect=RuntimeError("injected C1 clock failure")):
            self.bridge._sweep_once()
        self.assertTrue(self.bridge.unavailable)
        self.assertTrue(self.bridge._unconfirmed_cleanup)
        self.assertFalse(self.bridge.status()["cleanup_confirmed"])

if __name__ == "__main__":
    unittest.main()
