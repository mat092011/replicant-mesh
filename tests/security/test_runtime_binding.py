"""Tests for binding core authorization to runtime session ownership.

The dependency-free handler and parsed Request fixtures below are unit-only.
The opt-in protocol case uses the generated Request and real WorkerHandler.
"""

from __future__ import annotations

import asyncio
from collections import deque
import os
from pathlib import Path
import sys
from types import ModuleType
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from steamboat_runtime.secure_worker_runtime import (
    RuntimeBindingError,
    RuntimeBridgeUnavailable,
    SecureWorkerRuntimeBridge,
)
from steamboat_security import (
    SessionError,
    SessionBindings,
    SnapshotError,
    generate_private_key_pem,
    issue_leaf,
    make_csr,
    new_id,
    sign_snapshot,
)
from steamboat_security.operator import _record_from_leaf
from tests.security.test_identity_core import (
    ACCOUNT_A,
    ASSIGNMENT,
    BOOT_HOST,
    DEVICE_COORDINATOR,
    DEVICE_HOST,
    IdentityFixture,
    MODEL,
    NOW,
    ParsedWorkerRequest,
)


class _FakeCache:
    def __init__(self):
        self.bytes = 0
        self.position = 0

    def allocated_bytes(self):
        return self.bytes

    def lengths(self):
        return [self.position]

    def clear(self):
        self.bytes = 0
        self.position = 0


class _FakeEntry:
    def __init__(self, session_id, lease):
        self.session_id = session_id
        self.lease = lease
        self.cache = _FakeCache()
        self.in_flight = False
        self.queued = False
        self.committed_bytes = 0
        self.terminal_code = ""


class _UnitOnlyWorkerHandler:
    """Unit-only stand-in; production requires the actual WorkerHandler."""

    def __init__(self):
        self.manifest = {
            "fingerprint": MODEL,
            "components": {"worker-1": {"layer_range": [0, 1]}},
        }
        self.worker_name = "worker-1"
        self.start = 0
        self.end = 1
        self.boot_id = BOOT_HOST
        self.sessions = {}
        self.tombstones = {}
        self._queue = deque()
        self._active_operation = None
        self._loop = None
        self.stopping = False
        self.requires_restart = False
        self._supervision_notifications = 0
        self.handle_calls = []
        self.step_started = asyncio.Event()
        self.step_release = asyncio.Event()
        self.compute_task = None
        self.block_open_before_allocate = False
        self.open_started = asyncio.Event()
        self.open_release = asyncio.Event()

    def supervision_status(self):
        return {"ready": not self.stopping and not self.requires_restart,
                "requires_restart": self.requires_restart,
                "active_compute": self._active_operation is not None}

    def _notify_supervisor(self):
        self._supervision_notifications += 1

    def _terminate(self, entry, code):
        if not entry.terminal_code:
            entry.terminal_code = code
        if entry.queued:
            entry.queued = False
        if not entry.in_flight and entry.session_id in self.sessions:
            entry.cache.clear()
            entry.committed_bytes = 0
            del self.sessions[entry.session_id]
            self.tombstones[entry.session_id] = entry
        self._notify_supervisor()

    def invalidate_for_authorization(self, session_id):
        entry = self.sessions.get(session_id) or self.tombstones.get(session_id)
        if entry is None:
            return True
        self._terminate(entry, "CANCELLED")
        return not entry.in_flight and entry.cache.allocated_bytes() == 0

    async def handle(self, method, request):
        self.handle_calls.append((method, request))
        entry = self.sessions.get(request.session_id) or self.tombstones.get(request.session_id)
        if method == "OpenSession":
            if self.block_open_before_allocate:
                self.open_started.set()
                await self.open_release.wait()
            if entry is None:
                import secrets
                entry = _FakeEntry(request.session_id, secrets.token_hex(16))
                self.sessions[request.session_id] = entry
            return _response(method, request, entry)
        if entry is None:
            raise AssertionError("unit handler received an unknown session")
        if method == "Step":
            entry.in_flight = True
            entry.cache.bytes = 128
            entry.cache.position = 1
            self._active_operation = type("Active", (), {"entry": entry})()
            self.step_started.set()

            async def compute():
                await self.step_release.wait()
                entry.in_flight = False
                self._active_operation = None
                if entry.terminal_code:
                    self._terminate(entry, entry.terminal_code)
                else:
                    entry.committed_bytes = entry.cache.allocated_bytes()
                return _response(method, request, entry,
                                 code=entry.terminal_code or "OK")

            self.compute_task = asyncio.create_task(compute())
            return await asyncio.shield(self.compute_task)
        if method in ("CancelSession", "CloseSession"):
            self._terminate(entry, "CANCELLED" if method == "CancelSession" else "CLOSED_SESSION")
        return _response(method, request, entry,
                         reclaimed=not entry.in_flight and entry.cache.allocated_bytes() == 0)


def _response(method, request, entry, *, code="OK", reclaimed=False):
    return IdentityFixture.response(method=method, payload=request,
                                    lease=entry.lease, code=code,
                                    reclaimed=reclaimed)


def _fixture():
    if not hasattr(IdentityFixture, "credentials"):
        IdentityFixture.setUpClass()
    return object.__new__(IdentityFixture)


def _owner_key(session_id):
    return DEVICE_HOST, BOOT_HOST, ASSIGNMENT, session_id


def _rotated_coordinator_record(fixture):
    private_key = generate_private_key_pem()
    csr = make_csr(private_key, account_id=ACCOUNT_A,
                   device_id=DEVICE_COORDINATOR,
                   role="personal_coordinator",
                   dns_sans=("coordinator.example",))
    certificate = issue_leaf(
        fixture.ca_pem, fixture.ca_key, csr, account_id=ACCOUNT_A,
        device_id=DEVICE_COORDINATOR, role="personal_coordinator",
        not_before=NOW - 60, not_after=NOW + 840,
        ekus=("client", "server"))
    return _record_from_leaf(
        certificate, account_id=ACCOUNT_A, device_id=DEVICE_COORDINATOR,
        role="personal_coordinator", credential_epoch=2)


def _bridge_for_unit(authorizer, handler, **kwargs):
    fake_module = ModuleType("steamboat_runtime.worker_state")
    fake_module.WorkerHandler = _UnitOnlyWorkerHandler
    with mock.patch.dict(sys.modules, {"steamboat_runtime.worker_state": fake_module}):
        return SecureWorkerRuntimeBridge(authorizer, handler, **kwargs)


class RuntimeBindingUnitTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.fixture = _fixture()
        self.authorizer, self.sessions, self.time_source = self.fixture.worker_authorizer()
        self.handler = _UnitOnlyWorkerHandler()
        self.bridge = _bridge_for_unit(self.authorizer, self.handler,
                                       sweep_interval_seconds=0.05)
        await self.bridge.start()

    async def asyncTearDown(self):
        if self.bridge._started and not self.bridge._closed:
            stopped = await self.bridge.stop(grace_seconds=0.25)
            if not stopped and self.bridge._maintenance_task is not None:
                self.bridge._maintenance_task.cancel()
                await asyncio.gather(self.bridge._maintenance_task,
                                     return_exceptions=True)

    def _open(self, *, session_id=None):
        binding = self.fixture.worker_binding("OpenSession", session_id=session_id)
        payload = self.fixture.open_payload(binding)
        authorization = self.bridge.incoming_authorizer.authorize(
            service="steamboat.v1.Worker", method="OpenSession", payload=payload,
            metadata=self.fixture.metadata("steamboat.v1.Worker", "OpenSession", binding),
            peer_certificate_pem=self.fixture.credentials["coordinator"]["certificate"])
        return binding, payload, authorization

    async def _open_and_close(self):
        binding, payload, authorization = self._open()
        response = await self.bridge.handler.handle("OpenSession", payload)
        authorization.complete(response)
        authorization.close()
        return binding, payload, response

    def _open_authorization(self, binding, *, lifetime_ms=120_000,
                            idle_lease_ms=30_000):
        payload = self.fixture.open_payload(
            binding, lifetime_ms=lifetime_ms, idle_lease_ms=idle_lease_ms)
        authorization = self.bridge.incoming_authorizer.authorize(
            service="steamboat.v1.Worker", method="OpenSession", payload=payload,
            metadata=self.fixture.metadata("steamboat.v1.Worker", "OpenSession", binding),
            peer_certificate_pem=self.fixture.credentials["coordinator"]["certificate"])
        return payload, authorization

    def _session_call(self, opened_binding, method, lease):
        binding = self.fixture.worker_binding(
            method, session_id=opened_binding["session_id"],
            request_id=opened_binding["request_id"], route_id=opened_binding["route_id"])
        payload = self.fixture.session_payload(binding, method, lease)
        authorization = self.bridge.incoming_authorizer.authorize(
            service="steamboat.v1.Worker", method=method, payload=payload,
            metadata=self.fixture.metadata("steamboat.v1.Worker", method, binding),
            peer_certificate_pem=self.fixture.credentials["coordinator"]["certificate"])
        return binding, payload, authorization

    async def test_open_duplicate_status_cancel_and_stolen_lease_use_real_core_authorizer(self):
        binding, payload, authorization = self._open()
        response = await self.bridge.handler.handle("OpenSession", payload)
        with self.assertRaises(RuntimeBindingError):
            await self.bridge.handler.handle(
                "OpenSession", self.fixture.open_payload(binding))
        with self.assertRaises(RuntimeBindingError):
            await self.bridge.handler.handle("OpenSession", payload)
        authorization.complete(response)
        authorization.close()
        self.assertEqual(self.bridge.status()["owned_sessions"], 1)

        unused_binding = dict(binding, operation_id=new_id("op"))
        unused_payload = self.fixture.open_payload(unused_binding)
        unused = self.bridge.incoming_authorizer.authorize(
            service="steamboat.v1.Worker", method="OpenSession", payload=unused_payload,
            metadata=self.fixture.metadata("steamboat.v1.Worker", "OpenSession", unused_binding),
            peer_certificate_pem=self.fixture.credentials["coordinator"]["certificate"])
        unused.close()
        self.assertFalse(self.bridge._owners[_owner_key(binding["session_id"])].invalidated)
        self.assertIn(binding["session_id"], self.handler.sessions)

        duplicate_binding = dict(binding, operation_id=new_id("op"))
        duplicate_payload = self.fixture.open_payload(duplicate_binding)
        duplicate = self.bridge.incoming_authorizer.authorize(
            service="steamboat.v1.Worker", method="OpenSession", payload=duplicate_payload,
            metadata=self.fixture.metadata("steamboat.v1.Worker", "OpenSession", duplicate_binding),
            peer_certificate_pem=self.fixture.credentials["coordinator"]["certificate"])
        duplicate_response = await self.bridge.handler.handle("OpenSession", duplicate_payload)
        duplicate.complete(duplicate_response)
        duplicate.close()
        self.assertEqual(duplicate_response.lease_token, response.lease_token)

        _, status_payload, status_auth = self._session_call(
            binding, "SessionStatus", response.lease_token)
        status_response = await self.bridge.handler.handle("SessionStatus", status_payload)
        status_auth.complete(status_response)
        status_auth.close()

        stolen_binding = self.fixture.worker_binding(
            "SessionStatus", session_id=binding["session_id"],
            request_id=binding["request_id"], route_id=binding["route_id"])
        stolen_payload = self.fixture.session_payload(stolen_binding, "SessionStatus", "2" * 32)
        with self.assertRaises(SessionError):
            self.bridge.incoming_authorizer.authorize(
                service="steamboat.v1.Worker", method="SessionStatus", payload=stolen_payload,
                metadata=self.fixture.metadata("steamboat.v1.Worker", "SessionStatus", stolen_binding),
                peer_certificate_pem=self.fixture.credentials["coordinator"]["certificate"])
        self.assertIn(binding["session_id"], self.handler.sessions)

        _, cancel_payload, cancel_auth = self._session_call(
            binding, "CancelSession", response.lease_token)
        cancel_response = await self.bridge.handler.handle("CancelSession", cancel_payload)
        cancel_auth.complete(cancel_response)
        cancel_auth.assert_live()
        cancel_auth.close()
        with self.assertRaises(RuntimeBridgeUnavailable):
            cancel_auth.assert_live()
        self.bridge._reconcile()
        self.assertNotIn(_owner_key(binding["session_id"]), self.bridge._owners)
        self.assertEqual(self.sessions.record_count(), 1)
        replay_binding = self.fixture.worker_binding(
            "CancelSession", session_id=binding["session_id"],
            request_id=binding["request_id"], route_id=binding["route_id"])
        replay_payload = self.fixture.session_payload(
            replay_binding, "CancelSession", response.lease_token)
        with self.assertRaises(SessionError):
            self.bridge.incoming_authorizer.authorize(
                service="steamboat.v1.Worker", method="CancelSession",
                payload=replay_payload,
                metadata=self.fixture.metadata(
                    "steamboat.v1.Worker", "CancelSession", replay_binding),
                peer_certificate_pem=self.fixture.credentials["coordinator"]["certificate"])
        other_method_binding = self.fixture.worker_binding(
            "SessionStatus", session_id=binding["session_id"],
            request_id=binding["request_id"], route_id=binding["route_id"])
        other_method_payload = self.fixture.session_payload(
            other_method_binding, "SessionStatus", response.lease_token)
        with self.assertRaises(SessionError):
            self.bridge.incoming_authorizer.authorize(
                service="steamboat.v1.Worker", method="SessionStatus",
                payload=other_method_payload,
                metadata=self.fixture.metadata(
                    "steamboat.v1.Worker", "SessionStatus", other_method_binding),
                peer_certificate_pem=self.fixture.credentials["coordinator"]["certificate"])

    async def test_drain_timeout_validation_and_deadline_are_immutable(self):
        for invalid in (True, False, 1.0, float("nan"), 0, 301, "30"):
            with self.assertRaises(ValueError):
                self.bridge.begin_drain(invalid)
            self.assertIsNone(self.bridge._drain_deadline)
        deadline = self.bridge.begin_drain(30)
        started = self.bridge._drain_started_monotonic
        self.time_source.advance(2)
        self.assertEqual(self.bridge.begin_drain(1), deadline)
        self.assertEqual(self.bridge._drain_started_monotonic, started)
        self.assertEqual(self.bridge._drain_deadline, 130.0)
        self.assertFalse(self.handler.stopping)
        self.assertFalse(self.handler.requires_restart)
        status = self.bridge.status()
        self.assertFalse(status["ready"])
        self.assertFalse(status["unavailable"])
        self.assertFalse(status["requires_restart"])
        lifecycle = self.bridge.owner_lifecycle_status()
        self.assertEqual(lifecycle, {
            "phase": "paused", "drain_started_monotonic": 100.0,
            "drain_deadline_monotonic": 130.0, "deadline_reached": False,
        })

    async def test_begin_drain_rejects_worker_already_stopping_or_restart_fenced(self):
        for field in ("stopping", "requires_restart"):
            with self.subTest(field=field):
                setattr(self.handler, field, True)
                try:
                    self.assertFalse(self.bridge.unavailable)
                    with self.assertRaises(RuntimeBridgeUnavailable):
                        self.bridge.begin_drain(30)
                    self.assertIsNone(self.bridge._drain_started_monotonic)
                    self.assertIsNone(self.bridge._drain_deadline)
                    self.assertFalse(self.bridge._drain_deadline_reached)
                finally:
                    setattr(self.handler, field, False)

    async def test_drain_refuses_new_open_before_core_claim_and_pending_open_at_dispatch(self):
        binding = self.fixture.worker_binding("OpenSession")
        payload = self.fixture.open_payload(binding)
        metadata = self.fixture.metadata("steamboat.v1.Worker", "OpenSession", binding)
        with mock.patch.object(self.authorizer, "authorize",
                               wraps=self.authorizer.authorize) as core_authorize:
            self.bridge.begin_drain(30)
            with self.assertRaises(RuntimeBindingError):
                self.bridge.incoming_authorizer.authorize(
                    service="steamboat.v1.Worker", method="OpenSession", payload=payload,
                    metadata=metadata,
                    peer_certificate_pem=self.fixture.credentials["coordinator"]["certificate"])
            core_authorize.assert_not_called()
        self.assertEqual(self.sessions.record_count(), 0)

    async def test_drain_refuses_pre_authorized_open_at_dispatch_without_claim_leak(self):
        binding, payload, authorization = self._open()
        self.bridge.begin_drain(30)
        with self.assertRaises(RuntimeBindingError):
            await self.bridge.handler.handle("OpenSession", payload)
        self.assertEqual(self.handler.handle_calls, [])
        authorization.close()
        self.assertNotIn(_owner_key(binding["session_id"]), self.bridge._owners)
        self.assertEqual(self.sessions.record_count(), 0)

    async def test_drain_rejecting_pre_authorized_duplicate_preserves_existing_lease(self):
        binding, _payload, opened = await self._open_and_close()
        duplicate_binding = dict(binding, operation_id=new_id("op"))
        duplicate_payload, duplicate_authorization = self._open_authorization(
            duplicate_binding)
        self.bridge.begin_drain(30)
        with self.assertRaises(RuntimeBindingError):
            await self.bridge.handler.handle("OpenSession", duplicate_payload)
        duplicate_authorization.close()
        key = (DEVICE_HOST, BOOT_HOST, binding["session_id"])
        self.assertEqual(self.sessions._records[key].state, "open")
        self.assertEqual(self.handler.sessions[binding["session_id"]].lease,
                         opened.lease_token)
        self.assertFalse(self.bridge._owners[_owner_key(binding["session_id"])].invalidated)

    async def test_drain_caps_session_authorization_without_extending_original_caps(self):
        binding = self.fixture.worker_binding("OpenSession")
        payload, authorization = self._open_authorization(
            binding, lifetime_ms=1_000, idle_lease_ms=1_000)
        response = await self.bridge.handler.handle("OpenSession", payload)
        authorization.complete(response)
        authorization.close()
        _deadline = self.bridge.begin_drain(30)
        _renew_binding, renew_payload, renew_authorization = self._session_call(
            binding, "RenewSession", response.lease_token)
        self.assertEqual(renew_authorization.deadline_monotonic, 101.0)
        self.assertLessEqual(renew_authorization.remaining_seconds(), 1.0)
        renew_response = await self.bridge.handler.handle("RenewSession", renew_payload)
        renew_authorization.complete(renew_response)
        renew_authorization.close()
        self.assertEqual(self.bridge._drain_deadline, 130.0)

    async def test_admitted_step_completes_during_drain_before_deadline(self):
        binding, _payload, opened = await self._open_and_close()
        self.bridge.begin_drain(30)
        _step_binding, step_payload, step_authorization = self._session_call(
            binding, "Step", opened.lease_token)
        self.handler.step_release.set()
        response = await self.bridge.handler.handle("Step", step_payload)
        self.assertEqual(response.code, "OK")
        step_authorization.complete(response)
        step_authorization.close()
        self.assertEqual(self.bridge.owner_lifecycle_status()["phase"], "draining")
        self.assertIn(_owner_key(binding["session_id"]), self.bridge._owners)
        self.assertFalse(self.bridge.unavailable)
        self.assertFalse(self.handler.requires_restart)

    async def test_drain_deadline_invalidates_session_but_waits_for_compute_owners(self):
        binding, _payload, opened = await self._open_and_close()
        _step_binding, step_payload, step_authorization = self._session_call(
            binding, "Step", opened.lease_token)
        rpc = asyncio.create_task(self.bridge.handler.handle("Step", step_payload))
        await asyncio.wait_for(self.handler.step_started.wait(), 1)
        self.bridge.begin_drain(1)
        self.time_source.advance(1)
        lifecycle = self.bridge.owner_lifecycle_status()
        self.assertEqual(lifecycle["phase"], "draining")
        self.assertTrue(lifecycle["deadline_reached"])
        self.assertFalse(self.bridge.unavailable)
        self.assertFalse(self.handler.requires_restart)
        self.assertTrue(self.handler._active_operation is not None)
        self.handler.step_release.set()
        with self.assertRaises(RuntimeBridgeUnavailable):
            await asyncio.wait_for(rpc, 1)
        step_authorization.close()
        self.bridge._reconcile()
        self.assertEqual(self.bridge.owner_lifecycle_status()["phase"], "paused")

    async def test_drain_reclaims_idle_owner_and_describe_stays_ok_not_ready(self):
        binding, _payload, opened = await self._open_and_close()
        self.bridge.begin_drain(1)
        self.time_source.advance(1)
        self.assertEqual(self.bridge.owner_lifecycle_status()["phase"], "paused")
        self.assertFalse(self.bridge.unavailable)
        self.assertFalse(self.handler.requires_restart)
        describe_binding = self.fixture.worker_binding("Describe")
        describe_payload = ParsedWorkerRequest(
            protocol_version=1, manifest_fingerprint=MODEL,
            worker_boot_id=BOOT_HOST, session_id="", timeout_ms=30_000)
        describe_authorization = self.bridge.incoming_authorizer.authorize(
            service="steamboat.v1.Worker", method="Describe", payload=describe_payload,
            metadata=self.fixture.metadata("steamboat.v1.Worker", "Describe",
                                           describe_binding),
            peer_certificate_pem=self.fixture.credentials["coordinator"]["certificate"])

        async def describe_handler(method, request):
            response = _response(method, request, _FakeEntry("", ""))
            response.ready = True
            return response

        self.handler.handle = describe_handler
        response = await self.bridge.handler.handle("Describe", describe_payload)
        self.assertEqual(response.code, "OK")
        self.assertFalse(response.ready)
        describe_authorization.complete(response)
        describe_authorization.close()
        self.assertNotIn(_owner_key(binding["session_id"]), self.bridge._owners)

    async def test_pending_open_revocation_cannot_be_reclaimed_before_dispatch_closes(self):
        binding, _payload, authorization = self._open()
        key = (DEVICE_HOST, BOOT_HOST, binding["session_id"])
        self.sessions.invalidate(key=key, reason="test-revocation")
        self.bridge._process_notices()
        owner = self.bridge._owners[(DEVICE_HOST, BOOT_HOST, ASSIGNMENT, binding["session_id"])]
        self.assertTrue(owner.invalidated)
        self.assertTrue(self.sessions._records[key].state == "invalidated")
        with self.assertRaises(RuntimeBridgeUnavailable):
            await self.bridge.handler.handle("OpenSession", _payload)
        self.assertEqual(self.handler.handle_calls, [])
        self.assertIn(_owner_key(binding["session_id"]), self.bridge._owners)
        authorization.close()
        self.assertNotIn(_owner_key(binding["session_id"]), self.bridge._owners)
        self.assertEqual(self.sessions._records[key].state, "tombstone")
        self.assertEqual(self.sessions.record_count(), 1)

    async def test_handler_dispatch_ownership_outlives_rpc_close_and_catches_late_open(self):
        self.handler.block_open_before_allocate = True
        binding, payload, authorization = self._open()
        rpc = asyncio.create_task(self.bridge.handler.handle("OpenSession", payload))
        await asyncio.wait_for(self.handler.open_started.wait(), 1)
        owner_key = _owner_key(binding["session_id"])
        authorization.close()
        self.bridge._process_notices()
        self.bridge._reconcile()
        self.assertIn(owner_key, self.bridge._owners)
        self.assertIn(id(payload), self.bridge._operations)
        self.assertNotIn(binding["session_id"], self.handler.sessions)

        self.handler.open_release.set()
        with self.assertRaises(RuntimeBridgeUnavailable):
            await asyncio.wait_for(rpc, 1)
        self.bridge._reconcile()
        self.assertNotIn(binding["session_id"], self.handler.sessions)
        self.assertNotIn(owner_key, self.bridge._owners)
        self.assertNotIn(id(payload), self.bridge._operations)

    async def test_lost_open_reply_invalidates_and_reclaims_created_handler_session(self):
        binding, payload, authorization = self._open()
        await self.bridge.handler.handle("OpenSession", payload)
        self.assertIn(binding["session_id"], self.handler.sessions)
        authorization.close()
        self.bridge._process_notices()
        self.bridge._reconcile()
        self.assertNotIn(binding["session_id"], self.handler.sessions)
        self.assertNotIn(_owner_key(binding["session_id"]), self.bridge._owners)
        self.assertEqual(self.sessions._records[(DEVICE_HOST, BOOT_HOST,
                                                 binding["session_id"])].state, "tombstone")

    async def test_failed_open_response_reclaims_maybe_allocated_handler_session(self):
        binding, payload, authorization = self._open()
        response = await self.bridge.handler.handle("OpenSession", payload)
        response.code = "EXECUTION_FAILED"
        authorization.complete(response)
        authorization.close()
        self.bridge._process_notices()
        self.bridge._reconcile()
        self.assertNotIn(binding["session_id"], self.handler.sessions)
        self.assertNotIn(_owner_key(binding["session_id"]), self.bridge._owners)
        self.assertEqual(self.sessions._records[(DEVICE_HOST, BOOT_HOST,
                                                 binding["session_id"])].state, "tombstone")

    async def test_inflight_compute_retains_cache_and_core_ownership_after_rpc_cancel(self):
        binding, _, opened = await self._open_and_close()
        _, step_payload, step_auth = self._session_call(
            binding, "Step", opened.lease_token)
        rpc = asyncio.create_task(self.bridge.handler.handle("Step", step_payload))
        await asyncio.wait_for(self.handler.step_started.wait(), 1)
        entry = self.handler.sessions[binding["session_id"]]
        key = (DEVICE_HOST, BOOT_HOST, binding["session_id"])
        self.assertGreater(entry.cache.allocated_bytes(), 0)

        self.sessions.invalidate(key=key, reason="credential-rotation")
        self.bridge._process_notices()
        self.assertTrue(entry.terminal_code)
        self.assertGreater(entry.cache.allocated_bytes(), 0)
        self.assertIn(_owner_key(binding["session_id"]), self.bridge._owners)

        rpc.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await rpc
        step_auth.fail(cache_may_exist=True)
        self.bridge._reconcile()
        self.assertIn(_owner_key(binding["session_id"]), self.bridge._owners)
        self.assertGreater(entry.cache.allocated_bytes(), 0)

        self.handler.step_release.set()
        await asyncio.wait_for(self.handler.compute_task, 1)
        self.bridge._reconcile()
        self.assertEqual(entry.cache.allocated_bytes(), 0)
        self.assertIn(_owner_key(binding["session_id"]), self.bridge._owners)
        step_auth.close()
        self.assertNotIn(_owner_key(binding["session_id"]), self.bridge._owners)

    async def test_credential_epoch_rotation_reclaims_existing_binding(self):
        binding, _, opened = await self._open_and_close()
        rotated_record = _rotated_coordinator_record(self.fixture)
        records = [record for record in self.fixture.records.values()
                   if record["serial"] != self.fixture.records["coordinator"]["serial"]]
        records.append(rotated_record)
        grants = self.fixture.grants(coordinator_record=rotated_record)
        updated = self.fixture.payload(revision=2, records=records, grants=grants)
        self.authorizer.snapshot_store.install(sign_snapshot(updated, self.fixture.signing_key))
        self.bridge._process_notices()
        self.bridge._reconcile()
        self.assertNotIn(binding["session_id"], self.handler.sessions)
        self.assertNotIn(_owner_key(binding["session_id"]), self.bridge._owners)
        self.assertEqual(self.sessions._records[(DEVICE_HOST, BOOT_HOST,
                                                 binding["session_id"])].state, "tombstone")

    async def test_clock_failure_fences_without_falsely_reclaiming_until_clock_recovers(self):
        binding, _, _ = await self._open_and_close()
        session_key = (DEVICE_HOST, BOOT_HOST, binding["session_id"])
        owner_key = _owner_key(binding["session_id"])
        self.time_source.wall = float("nan")
        self.bridge._sweep_once()
        self.assertTrue(self.bridge.unavailable)
        self.assertFalse(self.bridge.status()["ready"])
        self.assertIn(owner_key, self.bridge._owners)
        entry = self.handler.tombstones[binding["session_id"]]
        self.assertEqual(entry.cache.allocated_bytes(), 0)
        self.assertEqual(self.sessions._records[session_key].state, "invalidated")
        self.assertFalse(self.bridge.status()["cleanup_confirmed"])

        self.time_source.wall = NOW + 1
        self.time_source.monotonic += 1
        recovered_clock = self.time_source.clock()
        self.authorizer.clock = recovered_clock
        self.authorizer.snapshot_store.clock = recovered_clock
        self.sessions.clock = recovered_clock
        self.bridge._reconcile()
        self.assertNotIn(owner_key, self.bridge._owners)
        self.assertTrue(self.bridge.unavailable)

    async def test_snapshot_expiry_fences_and_reclaims_only_after_handler_cleanup(self):
        binding, _, _ = await self._open_and_close()
        owner_key = _owner_key(binding["session_id"])
        self.time_source.wall = NOW + 301
        self.time_source.monotonic += 301
        self.bridge._sweep_once()
        self.assertTrue(self.bridge.unavailable)
        self.assertFalse(self.bridge.status()["ready"])
        self.assertNotIn(owner_key, self.bridge._owners)
        self.assertEqual(self.handler.tombstones[binding["session_id"]]
                         .cache.allocated_bytes(), 0)

    async def test_empty_session_sweep_fences_clock_failure(self):
        self.assertEqual(self.sessions.record_count(), 0)
        self.time_source.wall = float("nan")
        self.bridge._sweep_once()
        self.assertTrue(self.bridge.unavailable)
        self.assertFalse(self.bridge.status()["ready"])

    async def test_empty_session_startup_fences_snapshot_failure(self):
        time_source = self.fixture.fresh_time()
        store, _clock = self.fixture.store(time_source)
        sessions = SessionBindings(clock=store.clock)
        authorizer, _, _ = self.fixture.worker_authorizer(
            time_source=time_source, store=store, sessions=sessions)
        bridge = _bridge_for_unit(
            authorizer, _UnitOnlyWorkerHandler(), sweep_interval_seconds=0.05)
        self.assertEqual(sessions.record_count(), 0)
        store._current_at = mock.Mock(side_effect=SnapshotError("snapshot unavailable"))
        with self.assertRaises(RuntimeBridgeUnavailable):
            await bridge.start()
        self.assertFalse(bridge.status()["ready"])
        if bridge._maintenance_task is not None:
            bridge._maintenance_task.cancel()
            await asyncio.gather(bridge._maintenance_task, return_exceptions=True)

    async def test_grant_expiry_invalidates_and_reclaims_live_owner(self):
        time_source = self.fixture.fresh_time()
        payload = self.fixture.payload(
            grants=self.fixture.grants(expires=NOW + 10), expiry=NOW + 300)
        store, clock = self.fixture.store(time_source, payload)
        sessions = SessionBindings(clock=clock)
        authorizer, _sessions, _ = self.fixture.worker_authorizer(
            time_source=time_source, store=store, sessions=sessions)
        handler = _UnitOnlyWorkerHandler()
        bridge = _bridge_for_unit(authorizer, handler, sweep_interval_seconds=0.05)
        await bridge.start()

        async def cleanup_bridge():
            if not bridge._closed:
                await bridge.stop(grace_seconds=0.5)

        self.addAsyncCleanup(cleanup_bridge)
        binding = self.fixture.worker_binding("OpenSession")
        request = self.fixture.open_payload(binding)
        authorization = bridge.incoming_authorizer.authorize(
            service="steamboat.v1.Worker", method="OpenSession", payload=request,
            metadata=self.fixture.metadata("steamboat.v1.Worker", "OpenSession", binding),
            peer_certificate_pem=self.fixture.credentials["coordinator"]["certificate"])
        response = await bridge.handler.handle("OpenSession", request)
        authorization.complete(response)
        authorization.close()
        owner_key = _owner_key(binding["session_id"])

        time_source.advance(11)
        bridge._sweep_once()
        bridge._reconcile()
        self.assertNotIn(owner_key, bridge._owners)
        self.assertNotIn(binding["session_id"], handler.sessions)
        self.assertEqual(sessions._records[(DEVICE_HOST, BOOT_HOST,
                                            binding["session_id"])].state, "tombstone")
        self.assertFalse(bridge.unavailable)
        self.assertTrue(await bridge.stop(grace_seconds=0.5))

    async def test_started_maintenance_automatically_reclaims_expired_grant(self):
        time_source = self.fixture.fresh_time()
        payload = self.fixture.payload(
            grants=self.fixture.grants(expires=NOW + 10), expiry=NOW + 300)
        store, clock = self.fixture.store(time_source, payload)
        sessions = SessionBindings(clock=clock)
        authorizer, _, _ = self.fixture.worker_authorizer(
            time_source=time_source, store=store, sessions=sessions)
        handler = _UnitOnlyWorkerHandler()
        bridge = _bridge_for_unit(
            authorizer, handler, sweep_interval_seconds=0.02)
        await bridge.start()

        async def cleanup_bridge():
            if not bridge._closed:
                stopped = await bridge.stop(grace_seconds=0.5)
                if not stopped and bridge._maintenance_task is not None:
                    bridge._maintenance_task.cancel()
                    await asyncio.gather(bridge._maintenance_task,
                                         return_exceptions=True)

        self.addAsyncCleanup(cleanup_bridge)
        binding = self.fixture.worker_binding("OpenSession")
        request = self.fixture.open_payload(binding)
        authorization = bridge.incoming_authorizer.authorize(
            service="steamboat.v1.Worker", method="OpenSession", payload=request,
            metadata=self.fixture.metadata("steamboat.v1.Worker", "OpenSession", binding),
            peer_certificate_pem=self.fixture.credentials["coordinator"]["certificate"])
        response = await bridge.handler.handle("OpenSession", request)
        authorization.complete(response)
        authorization.close()
        owner_key = _owner_key(binding["session_id"])

        time_source.advance(11)
        deadline = asyncio.get_running_loop().time() + 0.5
        while owner_key in bridge._owners and asyncio.get_running_loop().time() < deadline:
            await asyncio.sleep(0.005)
        self.assertNotIn(owner_key, bridge._owners)
        self.assertNotIn(binding["session_id"], handler.sessions)
        self.assertEqual(sessions._records[(DEVICE_HOST, BOOT_HOST,
                                            binding["session_id"])].state, "tombstone")
        self.assertFalse(bridge.unavailable)
        self.assertTrue(await bridge.stop(grace_seconds=0.5))
        self.assertTrue(bridge._closed)
        self.assertTrue(bridge._maintenance_task.done())
        self.assertFalse(bridge._operations)
        self.assertFalse(bridge._owners)

    async def test_stale_boot_notices_are_ignored_and_notice_overflow_fences(self):
        binding, _, opened = await self._open_and_close()
        from steamboat_security.sessions import SessionNotice

        stale = SessionNotice(DEVICE_HOST, "f" * 32, binding["session_id"], "stale")
        self.bridge._add_pending_notice(stale)
        wrong_target = SessionNotice("dev_" + "9" * 32, BOOT_HOST,
                                     binding["session_id"], "wrong-target")
        self.bridge._add_pending_notice(wrong_target)
        delayed_old_owner = SessionNotice(
            DEVICE_HOST, BOOT_HOST, binding["session_id"], "delayed-old-owner")
        self.bridge._add_pending_notice(
            delayed_old_owner, captured_owner=(("old-core-owner",), ("old-core-identity",)))
        self.bridge._process_notices()
        self.assertFalse(self.bridge.unavailable)
        self.assertFalse(self.bridge._owners[_owner_key(binding["session_id"])].invalidated)
        self.assertIn(binding["session_id"], self.handler.sessions)

        other_authorizer, _other_sessions, _other_time = self.fixture.worker_authorizer()
        other = _bridge_for_unit(other_authorizer, _UnitOnlyWorkerHandler(),
                                 sweep_interval_seconds=0.05, notice_capacity=1)
        await other.start()
        other._add_pending_notice(SessionNotice(DEVICE_HOST, BOOT_HOST,
                                                binding["session_id"], "first"))
        other._add_pending_notice(SessionNotice(DEVICE_HOST, BOOT_HOST,
                                                new_id("ses"), "overflow"))
        self.assertTrue(other.unavailable)
        self.assertFalse(other.status()["ready"])
        self.assertFalse(await other.stop(grace_seconds=0.1))
        other._maintenance_task.cancel()
        await asyncio.gather(other._maintenance_task, return_exceptions=True)


@unittest.skipUnless(os.environ.get("STEAMBOAT_PROTOCOL_TESTS") == "1",
                     "Set STEAMBOAT_PROTOCOL_TESTS=1 for real WorkerHandler lifecycle checks")
class RuntimeBindingProtocolTests(unittest.IsolatedAsyncioTestCase):
    @classmethod
    def setUpClass(cls):
        artifact_dir = os.environ.get("STEAMBOAT_ARTIFACT_DIR")
        if not artifact_dir or not Path(artifact_dir).is_dir():
            raise RuntimeError("protocol lifecycle checks require STEAMBOAT_ARTIFACT_DIR")
        cls.artifact_dir = Path(artifact_dir)
        from steamboat_runtime.manifest import load_manifest
        from steamboat_runtime.protocol.worker_pb2 import Request

        cls.manifest = load_manifest(cls.artifact_dir)
        cls.Request = Request

    async def test_real_worker_cache_is_retained_until_blocked_stage_returns(self):
        import threading
        import torch
        from steamboat_runtime.protocol.codec import encode_tensor
        from steamboat_runtime.protocol.worker_pb2 import Request
        from steamboat_runtime.worker_state import StageExecutor, WorkerHandler
        from steamboat_security import Authorizer, LocalIdentity, SessionBindings

        fixture = _fixture()
        fingerprint = self.manifest["fingerprint"]
        time_source = fixture.fresh_time()
        grants = [dict(grant, model_id=fingerprint) for grant in fixture.grants()]
        snapshot = fixture.payload(grants=grants)
        store, clock = fixture.store(time_source, snapshot)
        sessions = SessionBindings(clock=clock)
        authorizer = Authorizer(
            local_identity=LocalIdentity(fixture.credentials["host"]["certificate"],
                                          BOOT_HOST, fingerprint, ASSIGNMENT),
            snapshot_store=store, clock=clock, session_bindings=sessions,
            worker_request_type=Request)
        executor = StageExecutor(self.artifact_dir, "worker-1")
        handler = WorkerHandler(self.manifest, "worker-1", executor, boot_id=BOOT_HOST)
        bridge = SecureWorkerRuntimeBridge(authorizer, handler, sweep_interval_seconds=0.05)
        await bridge.start()
        started, release = threading.Event(), threading.Event()
        pending_authorizations = []

        async def cleanup_protocol_case():
            release.set()
            if handler._compute_task is not None and not handler._compute_task.done():
                try:
                    await asyncio.wait_for(asyncio.shield(handler._compute_task), 15)
                except asyncio.TimeoutError:
                    pass
            for pending_authorization in pending_authorizations:
                try:
                    pending_authorization.fail(cache_may_exist=True)
                    pending_authorization.close()
                except Exception:
                    pass
            if not bridge._closed:
                stopped = await bridge.stop(grace_seconds=1)
                if not stopped and bridge._maintenance_task is not None:
                    bridge._maintenance_task.cancel()
                    await asyncio.gather(bridge._maintenance_task,
                                         return_exceptions=True)
            if not handler.stopping:
                await handler.shutdown(grace_seconds=1)

        self.addAsyncCleanup(cleanup_protocol_case)
        session_id = new_id("ses")
        open_binding = fixture.worker_binding("OpenSession", session_id=session_id)
        open_request = Request(
            protocol_version=1, manifest_fingerprint=fingerprint,
            worker_boot_id=BOOT_HOST, session_id=session_id, timeout_ms=30_000,
            max_positions=3, lifetime_ms=60_000, idle_lease_ms=30_000)
        open_auth = bridge.incoming_authorizer.authorize(
            service="steamboat.v1.Worker", method="OpenSession", payload=open_request,
            metadata=fixture.metadata("steamboat.v1.Worker", "OpenSession", open_binding),
            peer_certificate_pem=fixture.credentials["coordinator"]["certificate"])
        open_response = await bridge.handler.handle("OpenSession", open_request)
        open_auth.complete(open_response)
        open_auth.close()

        first_binding = fixture.worker_binding(
            "Step", session_id=session_id, request_id=open_binding["request_id"],
            route_id=open_binding["route_id"])
        first_request = Request(
            protocol_version=1, manifest_fingerprint=fingerprint,
            worker_boot_id=BOOT_HOST, session_id=session_id,
            lease_token=open_response.lease_token, timeout_ms=30_000,
            sequence=0, start_position=0, token_count=1,
            tensor=encode_tensor(torch.zeros((1, 1, self.manifest["config"]["hidden_size"]),
                                             dtype=torch.float32)))
        first_auth = bridge.incoming_authorizer.authorize(
            service="steamboat.v1.Worker", method="Step", payload=first_request,
            metadata=fixture.metadata("steamboat.v1.Worker", "Step", first_binding),
            peer_certificate_pem=fixture.credentials["coordinator"]["certificate"])
        first_response = await bridge.handler.handle("Step", first_request)
        first_auth.complete(first_response)
        first_auth.close()
        entry = handler.sessions[session_id]
        self.assertGreater(entry.cache.allocated_bytes(), 0)

        execute = executor.execute

        def blocked_execute(*args):
            started.set()
            if not release.wait(15):
                raise TimeoutError("test compute release deadline expired")
            return execute(*args)

        executor.execute = blocked_execute
        second_binding = fixture.worker_binding(
            "Step", session_id=session_id, request_id=open_binding["request_id"],
            route_id=open_binding["route_id"])
        second_request = Request(
            protocol_version=1, manifest_fingerprint=fingerprint,
            worker_boot_id=BOOT_HOST, session_id=session_id,
            lease_token=open_response.lease_token, timeout_ms=30_000,
            sequence=1, start_position=1, token_count=1,
            tensor=encode_tensor(torch.zeros((1, 1, self.manifest["config"]["hidden_size"]),
                                             dtype=torch.float32)))
        second_auth = bridge.incoming_authorizer.authorize(
            service="steamboat.v1.Worker", method="Step", payload=second_request,
            metadata=fixture.metadata("steamboat.v1.Worker", "Step", second_binding),
            peer_certificate_pem=fixture.credentials["coordinator"]["certificate"])
        pending_authorizations.append(second_auth)
        rpc = asyncio.create_task(bridge.handler.handle("Step", second_request))
        self.assertTrue(await asyncio.to_thread(started.wait, 10))
        rotated_record = _rotated_coordinator_record(fixture)
        records = [record for record in fixture.records.values()
                   if record["serial"] != fixture.records["coordinator"]["serial"]]
        records.append(rotated_record)
        rotated_grants = [dict(grant, model_id=fingerprint) for grant in
                          fixture.grants(coordinator_record=rotated_record)]
        rotated = fixture.payload(
            revision=2, records=records, grants=rotated_grants)
        store.install(sign_snapshot(rotated, fixture.signing_key))
        for _ in range(100):
            if entry.terminal_code:
                break
            await asyncio.sleep(0.01)
        self.assertTrue(entry.terminal_code)
        self.assertGreater(entry.cache.allocated_bytes(), 0)

        rpc.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await rpc
        second_auth.fail(cache_may_exist=True)
        self.assertGreater(entry.cache.allocated_bytes(), 0)
        self.assertIn(_owner_key(session_id), bridge._owners)

        release.set()
        await asyncio.wait_for(handler._compute_task, 15)
        self.assertEqual(entry.cache.allocated_bytes(), 0)
        self.assertEqual(entry.position, 1)
        self.assertEqual(entry.sequence, 1)
        self.assertIn(_owner_key(session_id), bridge._owners)
        second_auth.close()
        bridge._reconcile()
        self.assertNotIn(_owner_key(session_id), bridge._owners)
        self.assertEqual(handler.tombstones[session_id].cache.allocated_bytes(), 0)
        self.assertTrue(await bridge.stop(grace_seconds=1))
        self.assertTrue(await handler.shutdown(grace_seconds=1))
