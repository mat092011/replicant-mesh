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
from steamboat_runtime.protocol.secure_transport import SecureTaskPending


class _Coordinator:
    def submit(self, _input_ids, _new_tokens, *, trusted_request_context=None):
        return None


class _Service:
    coordinator = _Coordinator()
    max_streams = 2
    active_streams = 0


class _Auth:
    binding_bytes = b"binding"
    complete_calls = 0

    async def assert_live(self):
        callback = getattr(self, "on_assert_live", None)
        if callback is not None:
            callback()
        return None

    async def complete(self, _response):
        self.complete_calls += 1


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


def _adapter(guard=None):
    async def watcher(_authorization):
        import asyncio
        await asyncio.Future()

    return SecureCoordinatorService(
        _Service(), authorizer=type("Authorizer", (), {"authorize": lambda *_a, **_k: None})(),
        authorization_watcher=watcher, request_context_factory=lambda *_a: None,
        max_generate_streams=2, runtime_guard=guard)


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

    async def test_late_unary_response_is_not_returned_or_completed(self):
        adapter = _adapter()
        auth = _Auth()

        async def describe(_payload, _context):
            adapter.request_runtime_invalidation("unary completed after stop")
            return b"result"

        adapter.service.describe_rpc = describe
        with self.assertRaises(AuthorizationRevoked):
            await adapter._produce_unary("Describe", b"", _Context(), auth)
        self.assertEqual(auth.complete_calls, 0)

    async def test_runtime_is_rechecked_after_c1_live_check_before_unary_delegate(self):
        adapter = _adapter()
        auth = _Auth()
        assert_calls = []
        calls = []

        def invalidate_on_fourth_live_check():
            assert_calls.append(True)
            if len(assert_calls) == 4:
                adapter.request_runtime_invalidation(
                    "C1 live check completed after stop")

        auth.on_assert_live = invalidate_on_fourth_live_check

        async def describe(_payload, _context):
            calls.append("delegate")
            return b"response"

        adapter.service.describe_rpc = describe
        with self.assertRaises(AuthorizationRevoked):
            await adapter._produce_unary("Describe", b"", _Context(), auth)
        self.assertEqual(len(assert_calls), 4)
        self.assertEqual(calls.count("delegate"), 0)
        self.assertEqual(auth.complete_calls, 0)

    async def test_runtime_is_rechecked_after_c1_live_check_before_unary_complete(self):
        adapter = _adapter()
        auth = _Auth()
        assert_calls = []
        calls = []

        def invalidate_on_fifth_live_check():
            assert_calls.append(True)
            if len(assert_calls) == 5:
                adapter.request_runtime_invalidation(
                    "C1 live check completed after stop")

        auth.on_assert_live = invalidate_on_fifth_live_check

        async def describe(_payload, _context):
            calls.append("delegate")
            return b"response"

        adapter.service.describe_rpc = describe
        with self.assertRaises(AuthorizationRevoked):
            await adapter._produce_unary("Describe", b"", _Context(), auth)
        self.assertEqual(len(assert_calls), 5)
        self.assertEqual(calls.count("delegate"), 1)
        self.assertEqual(auth.complete_calls, 0)

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

    async def test_guard_that_invalidates_concurrently_then_returns_none_is_rejected(self):
        holder = {}

        def guard():
            holder["adapter"].request_runtime_invalidation("inside guard")
            return None

        adapter = _adapter(guard)
        holder["adapter"] = adapter
        with self.assertRaises(AuthorizationRevoked):
            adapter._check_runtime_guard()

    async def test_repeated_invalidations_schedule_one_owner_loop_wakeup(self):
        import asyncio
        adapter = _adapter()
        loop = asyncio.get_running_loop()
        adapter._bind_owner_loop()
        calls = []

        class LoopProxy:
            def is_closed(self):
                return False

            def call_soon_threadsafe(self, callback, *args):
                calls.append((callback, args))
                loop.call_soon(callback, *args)

        adapter._owner_loop = LoopProxy()
        class Acceptor:
            pauses = 0

            def pause(self):
                self.pauses += 1

        adapter.acceptor = Acceptor()
        for _ in range(20):
            adapter.request_runtime_invalidation("coalesced")
        await asyncio.sleep(0)
        self.assertEqual(len(calls), 1)
        self.assertEqual(adapter.acceptor.pauses, 1)

    async def test_generate_factory_context_is_owned_before_post_factory_guard(self):
        import asyncio
        adapter = _adapter()
        returned_context = object()
        cleanup_contexts = []

        async def factory(_authorization, _payload):
            adapter.request_runtime_invalidation("factory observed stop")
            return returned_context

        adapter.request_context_factory = factory
        adapter._capture_cleanup_tasks = lambda _slot: ()
        adapter._defer_generate_resources = lambda ctx, _tasks, _slot: cleanup_contexts.append(ctx)
        slot = {"producer_wrapper_tasks": set()}
        with self.assertRaises(AuthorizationRevoked):
            await adapter._produce_generate(
                {}, _Context(), 100.0, _Auth(), slot)
        self.assertIs(slot["trusted_context"], returned_context)
        self.assertTrue(slot["resource_cleanup_required"])
        self.assertEqual(cleanup_contexts, [returned_context])

    async def test_constructor_rejects_async_guard_callable(self):
        class AsyncCallable:
            async def __call__(self):
                return None

        with self.assertRaises(ValueError):
            _adapter(AsyncCallable())

        async def async_guard():
            return None

        async def async_generator_guard():
            yield None

        for guard in (async_guard, async_generator_guard):
            with self.subTest(guard=guard.__name__), self.assertRaises(ValueError):
                _adapter(guard)

    async def test_submit_handle_is_owned_before_post_submit_guard(self):
        import asyncio
        import types
        from unittest.mock import patch

        adapter = _adapter()
        class Handle:
            session_id = "session"

            def __aiter__(self):
                return self

            async def __anext__(self):
                raise StopAsyncIteration

            async def result(self):
                return types.SimpleNamespace(cleanup_complete=True)

        handle = Handle()
        submit_calls = []
        finish_calls = []

        class Coordinator:
            def submit(self, *_args, **_kwargs):
                submit_calls.append(True)
                adapter.request_runtime_invalidation("submit returned after stop")
                return handle

        adapter.service.coordinator = Coordinator()
        adapter.service.cleanups = set()
        async def finish(_handle, **_kwargs):
            finish_calls.append((_handle, _kwargs))
            return None
        adapter.service._finish = finish
        fake_torch = types.SimpleNamespace(
            long=object(), tensor=lambda *_a, **_kw: object())
        deadline = __import__("time").monotonic() + 30.0
        trusted_context = types.SimpleNamespace(
            assert_data_live=lambda: None,
            hard_monotonic_deadline=deadline)
        slot = {"producer_wrapper_tasks": set()}
        with patch.dict(sys.modules, {"torch": fake_torch}):
            with self.assertRaises(AuthorizationRevoked):
                await adapter._generate_with_context(
                    {"input_ids": [1], "new_tokens": 1, "capture_logits": False,
                     "timeout_seconds": 5}, _Context(), deadline,
                    trusted_context, _Auth(), slot, 20.0)
        self.assertIs(slot["handle"], handle)
        self.assertEqual(submit_calls, [True])
        self.assertEqual(len(finish_calls), 1)
        self.assertIs(finish_calls[0][0], handle)
        self.assertTrue(slot["session_cleanup_confirmed"])
        self.assertEqual(adapter._unreclaimed_generate_slots, [])

    async def test_runtime_is_rechecked_after_tensor_creation_before_submit(self):
        import time
        import types
        from unittest.mock import patch

        adapter = _adapter()
        submit_calls = []
        deadline = time.monotonic() + 30.0
        trusted_context = types.SimpleNamespace(
            assert_data_live=lambda: None, hard_monotonic_deadline=deadline)

        class Coordinator:
            def submit(self, *_args, **_kwargs):
                submit_calls.append(True)
                return object()

        adapter.service.coordinator = Coordinator()
        adapter.service.cleanups = set()
        tensor_calls = []

        def tensor(*_args, **_kwargs):
            tensor_calls.append(True)
            adapter.request_runtime_invalidation("tensor completed after stop")
            return object()

        fake_torch = types.SimpleNamespace(long=object(), tensor=tensor)
        slot = {"producer_wrapper_tasks": set()}
        with patch.dict(sys.modules, {"torch": fake_torch}):
            with self.assertRaises(AuthorizationRevoked):
                await adapter._generate_with_context(
                    {"input_ids": [1], "new_tokens": 1, "capture_logits": False,
                     "timeout_seconds": 5}, _Context(), deadline,
                    trusted_context, _Auth(), slot, 20.0)
        self.assertEqual(tensor_calls, [True])
        self.assertEqual(submit_calls, [])
        self.assertIsNone(slot.get("handle"))

    async def test_runtime_is_rechecked_after_c1_live_check_before_generate_complete(self):
        import time
        import types
        from unittest.mock import patch

        adapter = _adapter()
        auth = _Auth()
        auth.on_assert_live = lambda: adapter.request_runtime_invalidation(
            "C1 live check completed after stop")
        deadline = time.monotonic() + 30.0
        result = types.SimpleNamespace(session_id="session", status="completed",
            token_ids=(), cleanup_complete=True, error=None, error_code=None)

        class Handle:
            session_id = "session"

            def __aiter__(self):
                return self

            async def __anext__(self):
                raise StopAsyncIteration

            async def result(self):
                return result

        handle = Handle()
        class Coordinator:
            manifest = {"config": {"vocab_size": 1}}

            def submit(self, *_args, **_kwargs):
                return handle

        adapter.service.coordinator = Coordinator()
        adapter.service.cleanups = set()
        adapter.service.metrics = {"session": types.SimpleNamespace(result=lambda _r: {})}
        adapter.service.counters = {"rejected_requests": 0, "transport_stalls": 0,
                                    "disconnected_streams": 0}
        writes = []
        async def write(_context, payload, _deadline):
            writes.append(payload)
        adapter.service._write = write
        finishes = []
        async def finish(_handle, **_kwargs):
            finishes.append(_handle)
        adapter.service._finish = finish
        fake_torch = types.SimpleNamespace(long=object(), tensor=lambda *_a, **_kw: object())
        trusted_context = types.SimpleNamespace(
            assert_data_live=lambda: None, hard_monotonic_deadline=deadline)
        slot = {"producer_wrapper_tasks": set()}
        with patch.dict(sys.modules, {"torch": fake_torch}):
            with self.assertRaises(AuthorizationRevoked):
                await adapter._generate_with_context(
                    {"input_ids": [1], "new_tokens": 1, "capture_logits": False,
                     "timeout_seconds": 5}, _Context(), deadline,
                    trusted_context, auth, slot, 20.0)
        self.assertEqual(len(writes), 1)
        self.assertEqual(auth.complete_calls, 0)
        self.assertTrue(slot["session_cleanup_confirmed"])
        self.assertEqual(finishes, [handle])

    async def test_pending_c1_watcher_remains_owned_before_authorization_close(self):
        import asyncio
        from unittest.mock import patch
        from steamboat_runtime.protocol import secure_transport

        adapter = _adapter()
        cancellation_seen = asyncio.Event()
        release_watcher = asyncio.Event()
        watcher_tasks = []

        async def stubborn_c1_watcher(_authorization):
            watcher_tasks.append(asyncio.current_task())
            try:
                await asyncio.Future()
            except asyncio.CancelledError:
                cancellation_seen.set()
                await release_watcher.wait()

        adapter.authorization_watcher = stubborn_c1_watcher

        class TrackedAuthorization(_Auth):
            def __init__(self):
                self.close_calls = 0
                self.closed = asyncio.Event()

            def remaining_seconds(self):
                return 20.0

            async def close(self):
                self.close_calls += 1
                self.closed.set()

        authorization = TrackedAuthorization()
        operation_cancelled = asyncio.Event()

        async def blocked_operation():
            try:
                await asyncio.Future()
            except asyncio.CancelledError:
                operation_cancelled.set()
                raise

        adapter._bind_owner_loop()
        with patch.object(secure_transport, "MAX_CANCELLATION_GRACE_SECONDS", 0.05):
            operation = asyncio.create_task(secure_transport._run_guarded(
                blocked_operation(), authorization,
                adapter._runtime_authorization_watcher(authorization), timeout=10.0))
            while not watcher_tasks:
                await asyncio.sleep(0)
            adapter.request_runtime_invalidation("runtime binding changed")
            with self.assertRaises(SecureTaskPending) as raised:
                await asyncio.wait_for(operation, 1.0)
            self.assertTrue(cancellation_seen.is_set())
            self.assertTrue(operation_cancelled.is_set())
            self.assertIn(watcher_tasks[0], raised.exception.tasks)
            self.assertEqual(authorization.close_calls, 0)
            release_watcher.set()
            await asyncio.wait_for(asyncio.gather(
                *raised.exception.tasks, return_exceptions=True), 1.0)
            await asyncio.wait_for(authorization.closed.wait(), 1.0)
            self.assertEqual(authorization.close_calls, 1)

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
