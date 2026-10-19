"""Public Generate ownership regression for pending authorization close graphs."""

from __future__ import annotations

import asyncio
from pathlib import Path
import sys
import time
import types
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from steamboat_runtime.remote_client import encode_json
from steamboat_runtime.secure_coordinator_service import SecureCoordinatorService
from steamboat_runtime.protocol.secure_transport import (
    BINDING_METADATA_KEY,
    SecureTaskPending,
    capacity_rejection_metadata,
)
from steamboat_runtime.protocol.secure_connector import SecureConnectorPending
from steamboat_security.codec import encode_binding


def _grpc_stub():
    module = types.ModuleType("grpc")
    module.StatusCode = types.SimpleNamespace(RESOURCE_EXHAUSTED=1)
    return module


def _generate_binding():
    suffix = "a" * 32
    return encode_binding(
        "steamboat.v1.Coordinator", "Generate", {
            "binding_version": 1,
            "operation_id": "op_" + suffix,
            "account_id": "acct_" + "1" * 32,
            "device_id": "dev_" + "2" * 32,
            "role": "consumer",
            "credential_epoch": 1,
            "target_device_id": "dev_" + "3" * 32,
            "request_id": "req_" + suffix,
        })


class _Coordinator:
    def submit(self, _input_ids, _new_tokens, *, trusted_request_context=None):
        raise AssertionError("capacity rejection must precede coordinator submission")


class _Service:
    def __init__(self):
        self.coordinator = _Coordinator()
        self.max_streams = 1
        self.active_streams = 1
        self.counters = {"rejected_requests": 0}


class _RpcContext:
    def __init__(self):
        self.events = []

    def time_remaining(self):
        return None

    async def send_initial_metadata(self, metadata):
        self.events.append(("initial", tuple(metadata)))

    async def set_trailing_metadata(self, metadata):
        self.events.append(("trailing", tuple(metadata)))

    async def abort(self, code, details):
        self.events.append(("abort", code, details))


class _PendingCloseAuthorization:
    def __init__(self, *, binding_bytes, child_factory, events):
        self.binding_bytes = binding_bytes
        self.deadline_monotonic = time.monotonic() + 30.0
        self.child_factory = child_factory
        self.events = events
        self.child_tasks = []
        self.close_calls = 0
        self.fail_calls = []
        self.closed = False

    def assert_live(self):
        if self.closed:
            raise RuntimeError("authorization is closed")

    def remaining_seconds(self):
        return self.deadline_monotonic - time.monotonic()

    async def complete(self, _response):
        raise AssertionError("capacity rejection cannot complete Generate")

    async def fail(self, *, cache_may_exist=True):
        self.fail_calls.append(cache_may_exist)
        self.events.append(("fail", cache_may_exist))

    async def close(self):
        self.close_calls += 1
        self.events.append(("close",))
        if self.close_calls != 1:
            raise AssertionError("capacity authorization close must be attempted once")
        child = asyncio.create_task(self.child_factory())
        self.child_tasks.append(child)
        raise SecureConnectorPending((child,), "authorization close remains pending")


class CapacityRejectionOwnerTests(unittest.IsolatedAsyncioTestCase):
    async def test_pending_close_children_and_late_grandchildren_remain_quarantined(self):
        release_child = asyncio.Event()
        release_grandchild = asyncio.Event()
        child_started = asyncio.Event()
        grandchild_created = asyncio.Event()
        grandchild_tasks = []
        events = []
        authorization = None

        async def grandchild_work():
            await release_grandchild.wait()

        async def close_child_work():
            child_started.set()
            await release_child.wait()
            grandchild = asyncio.create_task(grandchild_work())
            grandchild_tasks.append(grandchild)
            grandchild_created.set()
            raise SecureTaskPending(
                (grandchild,), "authorization close grandchild remains pending")

        child_tasks = []

        async def cleanup_owned_tasks():
            # Register cleanup before Generate so even an assertion failure
            # releases and joins every task created by the fake async close.
            release_child.set()
            release_grandchild.set()
            if authorization is not None:
                for task in authorization.child_tasks:
                    if task not in child_tasks:
                        child_tasks.append(task)
            if child_tasks:
                child_results = await asyncio.wait_for(
                    asyncio.gather(*child_tasks, return_exceptions=True), 1.0)
                self.assertEqual(len(child_results), len(child_tasks))
                self.assertTrue(all(isinstance(result, SecureTaskPending)
                                    for result in child_results))
                await asyncio.wait_for(grandchild_created.wait(), 1.0)
            if grandchild_tasks:
                grandchild_results = await asyncio.wait_for(
                    asyncio.gather(*grandchild_tasks, return_exceptions=True), 1.0)
                self.assertEqual(grandchild_results, [None] * len(grandchild_tasks))

        self.addAsyncCleanup(cleanup_owned_tasks)

        binding = _generate_binding()
        rpc_context = _RpcContext()
        rpc_context.events = events
        authorization = _PendingCloseAuthorization(
            binding_bytes=binding, child_factory=close_child_work, events=events)
        service = _Service()

        async def never_revoke(_authorization):
            await asyncio.Future()

        adapter = SecureCoordinatorService(
            service, authorizer=types.SimpleNamespace(authorize=lambda **_kw: None),
            authorization_watcher=never_revoke,
            request_context_factory=lambda *_args: self.fail(
                "capacity rejection must precede request-context creation"),
            max_generate_streams=1)
        original_owner = adapter._capacity_rejection_owner
        owner_tasks = []

        def record_owner(auth, state, tasks=(), **kwargs):
            owner = original_owner(auth, state, tasks, **kwargs)
            if owner is not None:
                owner_tasks.append(owner)
            return owner

        adapter._capacity_rejection_owner = record_owner
        self.addCleanup(setattr, adapter, "_capacity_rejection_owner", original_owner)

        async def authorize(_method, _data, _payload, _context):
            return authorization

        adapter._authorize = authorize
        self.assertEqual(adapter.pending_tasks, set())
        self.assertEqual(adapter.runtime_owner.pending_tasks, set())
        request = encode_json({
            "input_ids": [3], "new_tokens": 1,
            "timeout_seconds": 5, "capture_logits": False})

        with patch.dict(sys.modules, {"grpc": _grpc_stub()}):
            with self.assertRaises(SecureConnectorPending) as pending:
                await asyncio.wait_for(
                    adapter.generate_rpc(request, rpc_context), timeout=1.0)

        self.assertEqual([event[0] for event in rpc_context.events],
                         ["initial", "trailing", "abort", "fail", "close"])
        self.assertEqual(
            rpc_context.events[0][1], ((BINDING_METADATA_KEY, binding),))
        self.assertEqual(
            rpc_context.events[1][1], capacity_rejection_metadata(binding))
        self.assertEqual(rpc_context.events[2][1], 1)
        self.assertEqual(rpc_context.events[3:], [("fail", False), ("close",)])
        self.assertEqual(authorization.fail_calls, [False])
        self.assertEqual(authorization.close_calls, 1)
        self.assertFalse(authorization.closed)

        child = authorization.child_tasks[0]
        child_tasks.extend(authorization.child_tasks)
        self.assertIn(child, pending.exception.tasks)
        await asyncio.wait_for(child_started.wait(), 1.0)

        # Let the owner's done callback run after the caller has received the
        # pending error. It must replace the failed owner's registry entry with
        # strong ownership of the task graph it reported.
        for _ in range(8):
            if (child in adapter.pending_tasks
                    and child in adapter.runtime_owner.pending_tasks):
                break
            await asyncio.sleep(0)
        self.assertTrue(owner_tasks)
        owner = owner_tasks[0]
        self.assertTrue(owner.done())
        self.assertNotIn(owner, adapter.pending_tasks)
        self.assertNotIn(owner, adapter.runtime_owner.pending_tasks)
        self.assertIn(child, adapter.pending_tasks)
        self.assertIn(child, adapter.runtime_owner.pending_tasks)
        self.assertIs(
            adapter._unconfirmed_capacity_rejection_authorizations[id(authorization)],
            authorization)
        self.assertTrue(adapter.unavailable)
        self.assertTrue(adapter.runtime_owner.unavailable)
        self.assertFalse(child.done())

        # The child reports its grandchild only after the public Generate call
        # has returned. The same observers must retain it without retrying close.
        release_child.set()
        await asyncio.wait_for(grandchild_created.wait(), 1.0)
        child_result = await asyncio.wait_for(
            asyncio.gather(child, return_exceptions=True), 1.0)
        self.assertIsInstance(child_result[0], SecureTaskPending)
        grandchild = grandchild_tasks[0]
        for _ in range(8):
            if (grandchild in adapter.pending_tasks
                    and grandchild in adapter.runtime_owner.pending_tasks):
                break
            await asyncio.sleep(0)
        self.assertIn(grandchild, adapter.pending_tasks)
        self.assertIn(grandchild, adapter.runtime_owner.pending_tasks)

        release_grandchild.set()
        self.assertEqual(await asyncio.wait_for(
            asyncio.gather(grandchild, return_exceptions=True), 1.0), [None])
        await asyncio.sleep(0)
        self.assertEqual(authorization.close_calls, 1)
        self.assertFalse(authorization.closed)
        self.assertIs(
            adapter._unconfirmed_capacity_rejection_authorizations[id(authorization)],
            authorization)
        self.assertTrue(adapter.unavailable)
        self.assertTrue(adapter.runtime_owner.unavailable)


if __name__ == "__main__":
    unittest.main()
