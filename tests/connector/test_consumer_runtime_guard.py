"""Consumer runtime-guard races using the explicit fake transport seam."""

import asyncio
import threading
import time
import unittest
from types import SimpleNamespace

from steamboat_connector.client import ConsumerSubmission
from steamboat_connector.consumer_transport import SecureConsumerTransport
from steamboat_connector.errors import ConnectorError
from steamboat_runtime.protocol.secure_transport import SecureTaskPending


class FakeContext:
    def __init__(self, request_id, deadline):
        self.request_id = request_id
        self.deadline_monotonic = deadline
        self.closed = False

    def close(self):
        self.closed = True


class FakeAuthorizer:
    def __init__(self):
        self.clock = SimpleNamespace(sample=lambda: SimpleNamespace(
            monotonic=time.monotonic()))
        self.contexts = []

    def create_consumer_request_context(self, *, lifetime_seconds, request_id):
        context = FakeContext(request_id, time.monotonic() + lifetime_seconds)
        self.contexts.append(context)
        return context


class FakeClient:
    def __init__(self, *, tokenize=None, generation=None):
        self.tokenize_behavior = tokenize
        self.generation_behavior = generation
        self.tokenize_calls = []
        self.generate_calls = []

    async def tokenize(self, prompt, *, trusted_request_context):
        self.tokenize_calls.append((prompt, trusted_request_context))
        if self.tokenize_behavior is not None:
            return await self.tokenize_behavior(prompt, trusted_request_context)
        return [17]

    def generate(self, input_ids, new_tokens, *, trusted_request_context,
                 forced_tokens, capture_logits, timeout_seconds):
        self.generate_calls.append((input_ids, trusted_request_context))
        if self.generation_behavior is not None:
            return self.generation_behavior(input_ids, new_tokens)

        async def events():
            for index in range(new_tokens):
                yield {"type": "token", "index": index, "token_id": 100 + index}
            yield {"type": "result", "status": "completed",
                   "cleanup_complete": True,
                   "token_ids": [100 + index for index in range(new_tokens)]}
        return events()


class ConsumerRuntimeGuardTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.sequence = 0

    def submission(self, *, tokens=1, deadline=10):
        self.sequence += 1
        return ConsumerSubmission(
            f"req_{self.sequence:032x}", "synthetic prompt", tokens, deadline)

    async def test_pre_admission_guard_failure_skips_client_calls(self):
        client = FakeClient()
        transport = SecureConsumerTransport._for_tests(
            client, FakeAuthorizer(), runtime_guard=lambda: True)
        with self.assertRaises(ConnectorError) as caught:
            await transport.submit(self.submission())
        self.assertEqual(caught.exception.code, "UNAVAILABLE")
        self.assertEqual(client.tokenize_calls, [])
        self.assertEqual(client.generate_calls, [])
        self.assertEqual(transport.status()["active_runs"], 0)
        self.assertTrue(transport._runtime_invalidated.is_set())

    async def test_async_guard_is_rejected_and_awaitable_result_is_closed(self):
        async def async_guard():
            return None

        with self.assertRaises(TypeError):
            SecureConsumerTransport._for_tests(
                FakeClient(), FakeAuthorizer(), runtime_guard=async_guard)

        created = []

        async def returned_awaitable():
            return None

        def sync_guard_returning_awaitable():
            result = returned_awaitable()
            created.append(result)
            return result

        client = FakeClient()
        transport = SecureConsumerTransport._for_tests(
            client, FakeAuthorizer(), runtime_guard=sync_guard_returning_awaitable)
        with self.assertRaises(ConnectorError):
            await transport.submit(self.submission())
        self.assertEqual(len(created), 1)
        self.assertIsNone(created[0].cr_frame)
        self.assertEqual(client.tokenize_calls, [])

    async def test_invalidation_cancels_pending_tokenization_and_closes_context(self):
        started, never_release = asyncio.Event(), asyncio.Event()

        async def pending_tokenize(_prompt, _context):
            started.set()
            await never_release.wait()
            return [17]

        client = FakeClient(tokenize=pending_tokenize)
        authorizer = FakeAuthorizer()
        transport = SecureConsumerTransport._for_tests(client, authorizer)
        run = await transport.submit(self.submission())
        await asyncio.wait_for(started.wait(), 1)
        self.assertTrue(transport.request_runtime_invalidation("owner stopped"))
        await asyncio.wait_for(run.closed, 1)
        self.assertEqual(client.generate_calls, [])
        self.assertTrue(authorizer.contexts[0].closed)
        with self.assertRaises(ConnectorError) as caught:
            await run.result
        self.assertEqual(caught.exception.code, "CANCELLED")
        await run.aclose()

    async def test_guard_failure_after_pending_tokenization_is_rechecked(self):
        started, release = asyncio.Event(), asyncio.Event()
        guard_live = [True]

        def guard():
            if not guard_live[0]:
                raise RuntimeError("selected binding expired")

        async def pending_tokenize(_prompt, _context):
            started.set()
            await release.wait()
            return [17]

        client = FakeClient(tokenize=pending_tokenize)
        authorizer = FakeAuthorizer()
        transport = SecureConsumerTransport._for_tests(
            client, authorizer, runtime_guard=guard)
        run = await transport.submit(self.submission())
        await asyncio.wait_for(started.wait(), 1)
        guard_live[0] = False
        release.set()
        await asyncio.wait_for(run.closed, 1)
        self.assertEqual(client.generate_calls, [])
        self.assertTrue(authorizer.contexts[0].closed)
        with self.assertRaises(ConnectorError) as caught:
            await run.result
        self.assertEqual(caught.exception.code, "UNAVAILABLE")
        await run.aclose()

    async def test_invalidation_during_pending_stream_closes_stream_without_token(self):
        started, never_release, stream_closed = (
            asyncio.Event(), asyncio.Event(), asyncio.Event())
        guard_live = [True]

        def guard():
            if not guard_live[0]:
                raise RuntimeError("selected binding expired")

        async def generation(_ids, _count):
            try:
                started.set()
                await never_release.wait()
                yield {"type": "token", "index": 0, "token_id": 9}
            finally:
                stream_closed.set()

        client = FakeClient(generation=generation)
        authorizer = FakeAuthorizer()
        transport = SecureConsumerTransport._for_tests(
            client, authorizer, runtime_guard=guard)
        run = await transport.submit(self.submission())
        await asyncio.wait_for(started.wait(), 1)
        guard_live[0] = False
        never_release.set()
        await asyncio.wait_for(run.closed, 1)
        self.assertTrue(stream_closed.is_set())
        self.assertTrue(authorizer.contexts[0].closed)
        self.assertTrue(run._queue.empty())
        with self.assertRaises(ConnectorError) as caught:
            await run.result
        self.assertEqual(caught.exception.code, "UNAVAILABLE")
        await run.aclose()

    async def test_already_queued_token_is_withheld_after_invalidation(self):
        client = FakeClient()
        transport = SecureConsumerTransport._for_tests(client, FakeAuthorizer())
        run = await transport.submit(self.submission(tokens=2))
        await asyncio.wait_for(run.closed, 1)
        self.assertEqual(run._queue.qsize(), 3)
        transport.request_runtime_invalidation("owner stopped")
        with self.assertRaises(ConnectorError) as event_error:
            await run.__anext__()
        self.assertEqual(event_error.exception.code, "UNAVAILABLE")
        with self.assertRaises(ConnectorError) as result_error:
            await run.result
        self.assertEqual(result_error.exception.code, "UNAVAILABLE")
        self.assertTrue(run._queue.empty())
        await run.aclose()

    async def test_off_thread_invalidation_skips_contended_schedule_without_waiting(self):
        started, release = asyncio.Event(), asyncio.Event()

        async def pending_tokenize(_prompt, _context):
            started.set()
            await release.wait()
            return [17]

        client = FakeClient(tokenize=pending_tokenize)
        transport = SecureConsumerTransport._for_tests(client, FakeAuthorizer())
        run = await transport.submit(self.submission())
        await asyncio.wait_for(started.wait(), 1)
        transport._invalidation_lock.acquire()
        self.addCleanup(lambda: transport._invalidation_lock.release()
                        if transport._invalidation_lock.locked() else None)
        finished = threading.Event()
        receipt = []

        def invalidate():
            receipt.append(transport.request_runtime_invalidation("owner stopped"))
            finished.set()

        worker = threading.Thread(target=invalidate, daemon=True)
        before = time.monotonic()
        worker.start()
        await asyncio.wait_for(asyncio.to_thread(finished.wait, 1), 1.2)
        elapsed = time.monotonic() - before
        self.assertEqual(receipt, [False])
        self.assertLess(elapsed, 0.1)
        self.assertTrue(transport._runtime_invalidated.is_set())
        transport._invalidation_lock.release()
        worker.join(1)
        release.set()
        await asyncio.wait_for(run.closed, 1)
        self.assertEqual(client.generate_calls, [])
        self.assertFalse(transport.status()["available"])
        await run.aclose()

    async def test_pending_cleanup_owner_is_retained_after_runtime_invalidation(self):
        child_gate, started = asyncio.Event(), asyncio.Event()
        children = []

        async def pending_tokenize(_prompt, _context):
            child = asyncio.create_task(child_gate.wait())
            children.append(child)
            started.set()
            try:
                await asyncio.Future()
            except asyncio.CancelledError:
                raise SecureTaskPending((child,), "tokenizer child remains owned")

        client = FakeClient(tokenize=pending_tokenize)
        authorizer = FakeAuthorizer()
        transport = SecureConsumerTransport._for_tests(client, authorizer)
        run = await transport.submit(self.submission())
        await asyncio.wait_for(started.wait(), 1)
        transport.request_runtime_invalidation("owner stopped")
        await asyncio.wait_for(run.closed, 2)
        child = children[0]
        context = authorizer.contexts[0]
        self.assertIn(child, transport._pending_tasks)
        self.assertIn(context, transport._pending_contexts)
        self.assertFalse(context.closed)
        owner = transport._pending_context_owners[context]
        child_gate.set()
        await asyncio.wait_for(owner["watcher"], 1)
        self.assertTrue(context.closed)
        self.assertNotIn(context, transport._pending_contexts)
        await run.aclose()


if __name__ == "__main__":
    unittest.main()
