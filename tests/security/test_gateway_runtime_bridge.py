"""Gateway admission through the secure WorkerHandler bridge.

The TLS object, delegation verifier, C1 Authorizer and SessionBindings are real.
The bridge's type contract is exercised with its lightweight handler fixture;
this file tests authorization/ownership wiring, not numerical worker execution.
"""

from __future__ import annotations

import asyncio
import hashlib
import importlib.util
import os
import sys
import threading
import unittest
from types import ModuleType
from unittest import mock

from tests.security import test_gateway_authorization as gateway_tests
from tests.security.test_runtime_binding import _UnitOnlyWorkerHandler

from steamboat_security.codec import WORKER_SERVICE, encode_binding, parse_metadata
from steamboat_security.errors import ScopeError, SessionError
from steamboat_runtime.secure_worker_runtime import (
    RuntimeBridgeUnavailable, SecureWorkerRuntimeBridge)
from steamboat_security.gateway_ingress import GatewayIngressError


class GatewayRuntimeBridgeTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.auth_fixture = gateway_tests.GatewayAuthorizationTests(
            methodName="test_gateway_open_step_close_share_c1_and_ingress_session_ownership")
        self.auth_fixture.setUp()
        self.addCleanup(self.auth_fixture.doCleanups)
        self.handler = _UnitOnlyWorkerHandler()
        worker = self.auth_fixture.fixture.payload["workers"][0]
        self.handler.manifest = {
            "fingerprint": worker["model_id"],
            "components": {"worker-1": {"layer_range": [0, 1]}},
        }
        self.handler.boot_id = worker["worker_boot_id"]
        self.bridge_module = ModuleType("steamboat_runtime.worker_state")
        self.bridge_module.WorkerHandler = _UnitOnlyWorkerHandler
        with mock.patch.dict(sys.modules, {"steamboat_runtime.worker_state": self.bridge_module}):
            self.bridge = SecureWorkerRuntimeBridge(
                self.auth_fixture.authorizer, self.handler,
                sweep_interval_seconds=0.02)
        await self.bridge.start()

    async def asyncTearDown(self):
        if self.bridge._started and not self.bridge._closed:
            await self.bridge.stop(grace_seconds=0.5)

    def _gateway_admit(self, method, payload, *, binding=None, ingress=None,
                       sequence=None, envelope_changes=None):
        f = self.auth_fixture
        binding = binding or f._binding(method)
        metadata = (("steamboat-binding-bin", binding),)
        raw = payload.SerializeToString(deterministic=True)
        ingress = ingress or f.ingress_fixture.ingress
        if sequence is None:
            lane = ("control" if method in {"CloseSession", "CancelSession", "SessionStatus"}
                    else "data")
            sequence = f.lane_sequences[lane]
            f.lane_sequences[lane] += 1
        else:
            lane = ("control" if method in {"CloseSession", "CancelSession", "SessionStatus"}
                    else "data")
        changes = {
            "policy_revision": ingress.policy_revision,
            "policy_digest": ingress.policy_digest,
            "stream_generation": ingress.stream_generation,
            "frame_sequence": sequence,
            "lane": lane,
            "service": WORKER_SERVICE,
            "method": method,
            "binding_sha256": hashlib.sha256(binding).hexdigest(),
            "request_sha256": hashlib.sha256(raw).hexdigest(),
        }
        if envelope_changes:
            changes.update(envelope_changes)
        envelope = f.fixture.make_delegation(changes=changes)
        authorization = self.bridge.incoming_authorizer.authorize_gateway(
            service=WORKER_SERVICE, method=method, payload=payload,
            metadata=metadata, ingress=ingress, envelope=envelope,
            request_bytes=raw, frame_sequence=sequence, wire_lane=lane)
        self.assertIs(authorization._operation.request, payload)
        return payload, authorization

    async def test_gateway_open_step_use_same_bridge_admission_and_capture(self):
        f = self.auth_fixture
        open_binding = f._binding("OpenSession")
        opened_payload = f._payload("OpenSession")
        payload, opened = self._gateway_admit("OpenSession", opened_payload,
                                              binding=open_binding)
        response = await self.bridge.handler.handle("OpenSession", payload)
        self.assertEqual(response.code, "OK")
        opened.complete(f._response(opened._core))
        opened.close()
        self.assertIn(payload.session_id, self.handler.sessions)
        self.assertNotIn("lease_token_0123456789", repr(opened._core.binding.fields))

        fields = dict(parse_metadata(WORKER_SERVICE, "OpenSession",
                                     f.fixture.metadata).fields)
        fields["operation_id"] = "op_" + "b" * 32
        step_binding = encode_binding(WORKER_SERVICE, "Step", fields)
        step_payload = f._payload("Step", lease_token="lease_token_0123456789")
        step_payload, step = self._gateway_admit("Step", step_payload,
                                                  binding=step_binding)
        self.handler.step_release.set()
        result = await self.bridge.handler.handle("Step", step_payload)
        self.assertEqual(result.code, "OK")
        step.complete(f._response(step._core))
        step.close()

    async def test_replay_and_new_stream_generation_cannot_reach_dispatch(self):
        f = self.auth_fixture
        binding = f._binding("OpenSession")
        payload, authorization = self._gateway_admit(
            "OpenSession", f._payload("OpenSession"), binding=binding)
        response = await self.bridge.handler.handle("OpenSession", payload)
        self.assertEqual(response.code, "OK")
        authorization.complete(f._response(authorization._core))
        authorization.close()
        calls_before = len(self.handler.handle_calls)
        with self.assertRaises(ScopeError):
            self._gateway_admit("OpenSession", f._payload("OpenSession"),
                                binding=binding)
        self.assertEqual(len(self.handler.handle_calls), calls_before)
        self.assertEqual(self.bridge.status()["active_authorizations"], 0)

        # A fresh authenticated stream cannot inherit the captured session owner.
        new_tls_owner = f.ingress_fixture._make_tls_client()
        new_ingress = f.ingress_fixture.ingress.__class__.from_tls(
            new_tls_owner, verifier=f.fixture.verifier,
            sessions=f.ingress_fixture.sessions, gateway_id="gw-east")
        self.addCleanup(new_ingress.close)
        fields = dict(parse_metadata(WORKER_SERVICE, "OpenSession",
                                     f.fixture.metadata).fields)
        fields["operation_id"] = "op_" + "d" * 32
        new_binding = encode_binding(WORKER_SERVICE, "OpenSession", fields)
        with self.assertRaises(SessionError):
            self._gateway_admit("OpenSession", f._payload("OpenSession"),
                                binding=new_binding, ingress=new_ingress,
                                sequence=1)
        self.assertEqual(len(self.handler.handle_calls), calls_before)
        self.assertEqual(len(self.bridge._owners), 1)
        self.assertTrue(self.handler.sessions)

    async def test_denied_gateway_admission_rolls_back_count_and_does_not_dispatch(self):
        f = self.auth_fixture
        payload = f._payload("OpenSession")
        with self.assertRaises(Exception):
            self._gateway_admit("OpenSession", payload,
                                envelope_changes={"method": "Describe"})
        self.assertEqual(self.bridge.status()["active_authorizations"], 0)
        self.assertEqual(self.bridge._admitting, 0)
        self.assertEqual(self.handler.handle_calls, [])
        self.assertTrue(f.ingress_fixture.ingress._state.closed)

    async def test_close_waits_for_real_core_claim_then_notice_reclaims_pending_owner(self):
        f = self.auth_fixture
        ingress = f.ingress_fixture.ingress
        sessions = f.ingress_fixture.sessions
        original_claim = sessions.claim
        entered_claim = threading.Event()
        close_started = threading.Event()
        close_finished = threading.Event()

        def close_from_other_thread():
            close_started.set()
            ingress.close("gateway-stream-lost")
            close_finished.set()

        def blocked_claim(*args, **kwargs):
            result = original_claim(*args, **kwargs)
            entered_claim.set()
            closer = threading.Thread(target=close_from_other_thread, daemon=True)
            closer.start()
            self.assertTrue(close_started.wait(1))
            # This is deterministic: the ingress lock is held across the actual
            # SessionBindings.claim call, so concurrent stream loss cannot miss it.
            self.assertFalse(close_finished.wait(0.05))
            return result

        with mock.patch.object(sessions, "claim", side_effect=blocked_claim):
            payload, authorization = self._gateway_admit(
                "OpenSession", f._payload("OpenSession"))
        self.assertTrue(entered_claim.is_set())
        await asyncio.sleep(0.1)
        self.assertTrue(close_finished.is_set())
        self.assertEqual(self.bridge.status()["active_authorizations"], 1)
        self.assertFalse(self.handler.handle_calls)
        self.assertTrue(any(owner.invalidated for owner in self.bridge._owners.values()))
        authorization.close()
        await asyncio.sleep(0.05)
        self.assertFalse(self.bridge._owners)
        self.assertEqual(self.bridge.status()["active_authorizations"], 0)
        self.assertEqual(self.bridge.status()["pending_notices"], 0)

    async def test_postclaim_ingress_expiry_fails_closed_without_dispatch_or_false_reclaim(self):
        f = self.auth_fixture
        ingress = f.ingress_fixture.ingress
        sessions = f.ingress_fixture.sessions
        original_claim = sessions.claim

        def expire_after_claim(*args, **kwargs):
            claim = original_claim(*args, **kwargs)
            # Force the admission transaction's final conservative check to fail
            # after the real SessionBindings claim has been created.
            ingress._state.deadline = 0.0
            return claim

        with mock.patch.object(sessions, "claim", side_effect=expire_after_claim):
            with self.assertRaises(GatewayIngressError):
                self._gateway_admit("OpenSession", f._payload("OpenSession"))
        await asyncio.sleep(0.1)
        self.assertFalse(self.handler.handle_calls)
        self.assertEqual(self.bridge.status()["active_authorizations"], 0)
        self.assertEqual(self.bridge._admitting, 0)
        self.assertTrue(self.bridge.unavailable)
        self.assertFalse(self.bridge.status()["cleanup_confirmed"])
        records = tuple(sessions._records.values())
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].state, "invalidated")
        self.assertFalse(records[0].reclaimed)
        self.assertEqual(self.bridge.status()["pending_notices"], 0)

    async def test_stream_loss_invalidates_bridge_owner_and_waits_for_inflight_cleanup(self):
        f = self.auth_fixture
        open_payload, opened = self._gateway_admit("OpenSession", f._payload())
        response = await self.bridge.handler.handle("OpenSession", open_payload)
        opened.complete(f._response(opened._core))
        opened.close()

        fields = dict(parse_metadata(WORKER_SERVICE, "OpenSession",
                                     f.fixture.metadata).fields)
        fields["operation_id"] = "op_" + "c" * 32
        step_binding = encode_binding(WORKER_SERVICE, "Step", fields)
        step_payload = f._payload("Step", lease_token="lease_token_0123456789")
        step_payload, step = self._gateway_admit("Step", step_payload,
                                                  binding=step_binding)
        self.handler.step_release.clear()
        task = asyncio.create_task(self.bridge.handler.handle("Step", step_payload))
        await asyncio.wait_for(self.handler.step_started.wait(), 1)
        f.ingress_fixture.ingress.close("gateway-stream-lost")
        await asyncio.sleep(0.05)
        self.assertTrue(self.bridge._owners)
        entry = self.handler.sessions[step_payload.session_id]
        self.assertTrue(entry.in_flight)
        self.assertGreater(entry.cache.allocated_bytes(), 0)
        self.handler.step_release.set()
        with self.assertRaises(RuntimeBridgeUnavailable):
            await asyncio.wait_for(task, 1)
        with self.assertRaises(Exception):
            step.assert_live()
        step.close()
        await asyncio.sleep(0.05)
        self.assertFalse(self.handler.sessions)
        tombstone = self.handler.tombstones[step_payload.session_id]
        self.assertEqual(tombstone.cache.allocated_bytes(), 0)
        self.assertFalse(self.bridge._owners)
        self.assertTrue(self.bridge.status()["cleanup_confirmed"])


if __name__ == "__main__":
    unittest.main()


@unittest.skipUnless(
    os.environ.get("STEAMBOAT_ASSIGNED_TEST_SOURCE")
    and importlib.util.find_spec("torch")
    and importlib.util.find_spec("google.protobuf"),
    "Requires STEAMBOAT_ASSIGNED_TEST_SOURCE and native Torch/protobuf",
)
class GatewayRuntimeNativeHandlerTests(unittest.IsolatedAsyncioTestCase):
    """Real WorkerHandler lifecycle via gateway; executor is lifecycle-only."""

    async def test_stream_loss_during_step_reclaims_real_handler_cache(self):
        import torch
        from steamboat_runtime.manifest import load_manifest
        from steamboat_runtime.protocol.codec import encode_tensor
        from steamboat_runtime.protocol.worker_pb2 import Request
        from steamboat_runtime.worker_state import WorkerHandler
        from steamboat_security.authorization import Authorizer

        manifest = load_manifest(os.environ["STEAMBOAT_ASSIGNED_TEST_SOURCE"])
        self.enterContext(mock.patch.object(
            gateway_tests.ingress_tests.delegation_tests, "MODEL", manifest["fingerprint"]))
        auth_fixture = gateway_tests.GatewayAuthorizationTests(
            methodName="test_gateway_open_step_close_share_c1_and_ingress_session_ownership")
        auth_fixture.setUp()
        self.addCleanup(auth_fixture.doCleanups)
        f = auth_fixture
        worker = f.fixture.payload["workers"][0]

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
            def __init__(self, start, end, started, release):
                self.start, self.end = start, end
                self.started, self.release = started, release

            def new_cache(self):
                return Cache(self.start, self.end)

            def execute(self, hidden, cache, position):
                cache.bytes = 64
                self.started.set()
                if not self.release.wait(10):
                    raise TimeoutError("test executor was not released")
                cache.position = position + hidden.shape[1]
                return hidden.clone()

        # The test uses a genuine validated artifact manifest and WorkerHandler,
        # with signed synthetic policy targeting that manifest's real fingerprint.
        # The deterministic executor isolates lifecycle ownership, not numerics.
        started, release = threading.Event(), threading.Event()
        executor = Executor(*manifest["components"]["worker-1"]["layer_range"],
                            started, release)
        handler = WorkerHandler(manifest, "worker-1", executor,
                                boot_id=worker["worker_boot_id"])
        store, clock = f.snapshot_store, f.clock
        authorizer = Authorizer(
            local_identity=f.authorizer.local_identity, snapshot_store=store,
            clock=clock, session_bindings=f.ingress_fixture.sessions,
            worker_request_type=Request)
        bridge = SecureWorkerRuntimeBridge(authorizer, handler, sweep_interval_seconds=0.02)
        await bridge.start()
        ingress = f.ingress_fixture.ingress
        pending = []

        async def cleanup():
            release.set()
            for authorization in pending:
                try:
                    authorization.fail(cache_may_exist=True)
                    authorization.close()
                except Exception:
                    pass
            if bridge._started and not bridge._closed:
                await bridge.stop(grace_seconds=1)
            if not handler.stopping:
                await handler.shutdown(grace_seconds=1)

        self.addAsyncCleanup(cleanup)

        def admit(method, request, binding):
            raw = request.SerializeToString(deterministic=True)
            lane = ("control" if method in {"CloseSession", "CancelSession", "SessionStatus"}
                    else "data")
            sequence = f.lane_sequences[lane]
            f.lane_sequences[lane] += 1
            envelope = f.fixture.make_delegation(changes={
                "policy_revision": ingress.policy_revision,
                "policy_digest": ingress.policy_digest,
                "stream_generation": ingress.stream_generation,
                "frame_sequence": sequence, "service": WORKER_SERVICE,
                "lane": lane,
                "method": method, "binding_sha256": hashlib.sha256(binding).hexdigest(),
                "request_sha256": hashlib.sha256(raw).hexdigest(),
            })
            auth = bridge.incoming_authorizer.authorize_gateway(
                service=WORKER_SERVICE, method=method, payload=request,
                metadata=(("steamboat-binding-bin", binding),), ingress=ingress,
                envelope=envelope, request_bytes=raw, frame_sequence=sequence,
                wire_lane=lane)
            pending.append(auth)
            return auth

        opened_request = Request(
            protocol_version=1, manifest_fingerprint=worker["model_id"],
            worker_boot_id=worker["worker_boot_id"], session_id=f._payload().session_id,
            timeout_ms=30_000, max_positions=3, lifetime_ms=60_000,
            idle_lease_ms=30_000)
        open_binding = f._binding("OpenSession")
        opened_auth = admit("OpenSession", opened_request, open_binding)
        opened_response = await bridge.handler.handle("OpenSession", opened_request)
        self.assertEqual(opened_response.code, "OK")
        opened_auth.complete(opened_response)
        opened_auth.close()
        pending.remove(opened_auth)

        fields = dict(parse_metadata(WORKER_SERVICE, "OpenSession", f.fixture.metadata).fields)
        fields["operation_id"] = "op_" + "e" * 32
        step_binding = encode_binding(WORKER_SERVICE, "Step", fields)
        step_request = Request(
            protocol_version=1, manifest_fingerprint=worker["model_id"],
            worker_boot_id=worker["worker_boot_id"], session_id=opened_request.session_id,
            lease_token=opened_response.lease_token, timeout_ms=30_000,
            sequence=0, start_position=0, token_count=1,
            tensor=encode_tensor(torch.zeros((1, 1, manifest["config"]["hidden_size"]))))
        step_auth = admit("Step", step_request, step_binding)
        task = asyncio.create_task(bridge.handler.handle("Step", step_request))
        self.assertTrue(await asyncio.to_thread(started.wait, 5))
        entry = handler.sessions[opened_request.session_id]
        self.assertGreater(entry.cache.allocated_bytes(), 0)
        ingress.close("gateway-stream-lost")
        await asyncio.sleep(0.05)
        self.assertTrue(entry.in_flight)
        self.assertGreater(entry.cache.allocated_bytes(), 0)
        release.set()
        with self.assertRaises(RuntimeBridgeUnavailable):
            await asyncio.wait_for(task, 5)
        step_auth.close()
        pending.remove(step_auth)
        await asyncio.sleep(0.05)
        tombstone = handler.tombstones[opened_request.session_id]
        self.assertEqual(tombstone.cache.allocated_bytes(), 0)
        self.assertEqual(tombstone.cache.lengths(), [0] * len(tombstone.cache.lengths()))
        self.assertFalse(bridge._owners)
