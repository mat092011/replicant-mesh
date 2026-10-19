"""Runtime-fence regressions for the existing secure coordinator adapter.

These tests use bounded fake C1 authorizations and gRPC contexts. They exercise
the adapter's guard/watcher composition, not a real TLS connection or C2 binding.
"""

from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from steamboat_runtime.secure_coordinator_service import (
    SecureCoordinatorService, _AuthorizedStreamContext,
)
from steamboat_runtime.protocol.secure_transport import AuthorizationRevoked


class _Coordinator:
    def submit(self, _input_ids, _new_tokens, *, trusted_request_context=None):
        return None


class _Service:
    coordinator = _Coordinator()
    max_streams = 2
    active_streams = 0


class _Auth:
    binding_bytes = b"binding"

    async def assert_live(self):
        return None


class _Context:
    def __init__(self, on_write=None):
        self.on_write = on_write
        self.writes = []

    async def write(self, payload):
        if self.on_write is not None:
            await self.on_write()
        self.writes.append(payload)
        return None

    async def send_initial_metadata(self, _metadata):
        return None

    async def set_trailing_metadata(self, _metadata):
        return None

    async def abort(self, *_args):
        return None

    def time_remaining(self):
        return 1.0

    def invocation_metadata(self):
        raise AssertionError("invalidated runtime must refuse before metadata access")

    def invocation_metadata(self):
        raise AssertionError("invalidated runtime must refuse before metadata access")


def _adapter(guard=None):
    async def watcher(_authorization):
        import asyncio
        await asyncio.Future()

    return SecureCoordinatorService(
        _Service(), authorizer=type("Authorizer", (), {"authorize": lambda *_a, **_k: None})(),
        authorization_watcher=watcher, request_context_factory=lambda *_a: None,
        runtime_guard=guard)


class CoordinatorRuntimeGuardTests(unittest.IsolatedAsyncioTestCase):
    async def test_none_guard_keeps_existing_stream_behavior(self):
        adapter = _adapter()
        context = _Context()
        await _AuthorizedStreamContext(context, _Auth(), adapter._check_runtime_guard).write(
            {"type": "token"})
        self.assertEqual(context.writes, [{"type": "token"}])
        self.assertFalse(adapter._runtime_invalidated.is_set())

    async def test_guard_requires_exact_none_and_latches_fail_closed(self):
        for bad in (False, True, 0, object()):
            adapter = _adapter(lambda value=bad: value)
            with self.subTest(value=bad), self.assertRaises(AuthorizationRevoked):
                adapter._check_runtime_guard()
            self.assertTrue(adapter.unavailable)
            with self.assertRaises(AuthorizationRevoked):
                adapter._check_runtime_guard()

    async def test_invalid_runtime_refuses_before_authorization(self):
        calls = []
        adapter = _adapter(lambda: (_ for _ in ()).throw(RuntimeError("stale binding")))
        adapter.authorizer.authorize = lambda **_kwargs: calls.append("authorize")
        with self.assertRaises(AuthorizationRevoked):
            await adapter._authorize("Describe", b"", {}, _Context())
        self.assertEqual(calls, [])
        self.assertTrue(adapter._runtime_invalidated.is_set())

    async def test_invalid_runtime_refuses_before_authorization(self):
        calls = []
        adapter = _adapter(lambda: (_ for _ in ()).throw(RuntimeError("stale binding")))
        adapter.authorizer.authorize = lambda **_kwargs: calls.append("authorize")
        with self.assertRaises(AuthorizationRevoked):
            await adapter._authorize("Describe", b"", {}, _Context())
        self.assertEqual(calls, [])
        self.assertTrue(adapter._runtime_invalidated.is_set())

    async def test_awaitable_guard_is_closed_and_rejected(self):
        created = []

        async def async_guard():
            return None

        def guard():
            coroutine = async_guard()
            created.append(coroutine)
            return coroutine

        adapter = _adapter(guard)
        with self.assertRaises(AuthorizationRevoked):
            adapter._check_runtime_guard()
        self.assertEqual(created[0].cr_frame, None)
        self.assertTrue(adapter._runtime_invalidated.is_set())

    async def test_invalidation_wakes_active_authorization_watcher(self):
        import asyncio
        adapter = _adapter()
        auth = _Auth()
        adapter._bind_owner_loop()
        watcher = adapter._runtime_authorization_watcher(auth)(auth)
        task = asyncio.create_task(watcher)
        await asyncio.sleep(0)
        adapter.request_runtime_invalidation("owner binding changed")
        with self.assertRaises(AuthorizationRevoked):
            await asyncio.wait_for(task, 1.0)
        self.assertTrue(adapter.unavailable)

    async def test_runtime_invalidated_during_write_withholds_completion(self):
        import asyncio
        adapter = _adapter()
        entered = asyncio.Event()
        release = asyncio.Event()

        async def paused_write():
            entered.set()
            await release.wait()

        context = _Context(paused_write)
        writer = asyncio.create_task(_AuthorizedStreamContext(
            context, _Auth(), adapter._check_runtime_guard).write({"type": "result"}))
        await asyncio.wait_for(entered.wait(), 1.0)
        adapter.request_runtime_invalidation("runtime stopped")
        release.set()
        with self.assertRaises(AuthorizationRevoked):
            await asyncio.wait_for(writer, 1.0)
        self.assertEqual(context.writes, [{"type": "result"}])

    async def test_invalidation_api_is_sticky_and_idempotent(self):
        adapter = _adapter()
        self.assertTrue(adapter.request_runtime_invalidation("first"))
        self.assertTrue(adapter.request_runtime_invalidation("again"))
        self.assertTrue(adapter.unavailable)
        with self.assertRaises(AuthorizationRevoked):
            adapter._check_runtime_guard()


if __name__ == "__main__":
    unittest.main()
