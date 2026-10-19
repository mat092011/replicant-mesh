from __future__ import annotations

import asyncio
import os
import subprocess
import sys
import time
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from steamboat_connector.client import ConsumerSubmission
from steamboat_connector.errors import ConnectorError
from steamboat_connector.consumer_transport import (
    MAX_ACTIVE_RUNS,
    MAX_PENDING_EVENTS,
    ConsumerEvent,
    SecureConsumerTransport,
)
from steamboat_runtime.protocol.secure_transport import (
    SecureCoordinatorClient,
    SecureTaskPending,
)
from steamboat_security.clock import Clock
from steamboat_security.outbound import (
    ConsumerRequestContext,
    OutboundAuthorizer,
)


class FakeContext:
    def __init__(self, request_id, deadline):
        self.request_id = request_id
        self.deadline_monotonic = deadline
        self.closed = False

    def close(self):
        self.closed = True


class FakeAuthorizer:
    def __init__(self):
        self.clock = Clock(uncertainty_seconds=lambda: 0.0)
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
        return [11, 12]

    def generate(
        self,
        input_ids,
        new_tokens,
        *,
        trusted_request_context,
        forced_tokens,
        capture_logits,
        timeout_seconds,
    ):
        self.generate_calls.append(
            {
                "input_ids": input_ids,
                "new_tokens": new_tokens,
                "trusted_request_context": trusted_request_context,
                "forced_tokens": forced_tokens,
                "capture_logits": capture_logits,
                "timeout_seconds": timeout_seconds,
            }
        )
        if self.generation_behavior is not None:
            return self.generation_behavior(input_ids, new_tokens)

        async def events():
            for index in range(new_tokens):
                yield {
                    "type": "token",
                    "session_id": "ses_" + "3" * 32,
                    "index": index,
                    "token_id": 100 + index,
                }
            yield {
                "type": "result",
                "session_id": "ses_" + "3" * 32,
                "status": "completed",
                "cleanup_complete": True,
                "token_ids": [100 + index for index in range(new_tokens)],
                "metrics": {},
            }

        return events()


class SecureConsumerTransportTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.client = FakeClient()
        self.authorizer = FakeAuthorizer()
        self.transport = SecureConsumerTransport._for_tests(
            self.client, self.authorizer
        )
        self.sequence = 1

    def submission(self, *, deadline=10, tokens=2, request_id=None):
        request_id = request_id or f"req_{self.sequence:032x}"
        self.sequence += 1
        return ConsumerSubmission(request_id, "synthetic prompt", tokens, deadline)

    async def finish(self, run):
        events = [event async for event in run]
        result = await run.result
        await run.closed
        return events, result

    async def test_secure_generation_stream_correlation_and_defaults(self):
        submission = self.submission()
        run = await self.transport.submit(submission)
        events, result = await self.finish(run)
        self.assertEqual([event.type for event in events], ["token", "token", "result"])
        self.assertEqual(result.request_id, submission.request_id)
        self.assertEqual(result.generated_tokens, 2)
        self.assertEqual(self.authorizer.contexts[0].request_id, submission.request_id)
        self.assertIs(self.client.tokenize_calls[0][1], self.authorizer.contexts[0])
        generate = self.client.generate_calls[0]
        self.assertIs(generate["trusted_request_context"], self.authorizer.contexts[0])
        self.assertIsNone(generate["forced_tokens"])
        self.assertFalse(generate["capture_logits"])
        self.assertEqual(len(self.client.generate_calls), 1)
        self.assertTrue(self.authorizer.contexts[0].closed)
        self.assertEqual(self.transport.status()["active_runs"], 0)

    async def test_request_limits_and_duplicate_request_are_rejected(self):
        bad = [
            ConsumerSubmission("bad", "x", 1, 1),
            ConsumerSubmission("req_" + "1" * 32, "x", 0, 1),
            ConsumerSubmission("req_" + "2" * 32, "x", 1, 301),
            ConsumerSubmission("req_" + "3" * 32, "x", 1, 1, attempt=2),
            ConsumerSubmission("req_" + "4" * 32, "x" * 65537, 1, 1),
        ]
        for submission in bad:
            with self.subTest(request_id=submission.request_id), self.assertRaises(
                ConnectorError
            ):
                await self.transport.submit(submission)
        duplicate = self.submission()
        run = await self.transport.submit(duplicate)
        with self.assertRaises(ConnectorError):
            await self.transport.submit(duplicate)
        await self.finish(run)

    async def test_active_run_count_is_bounded(self):
        gate = asyncio.Event()

        async def wait_tokenize(_prompt, _context):
            await gate.wait()
            return [1]

        client = FakeClient(tokenize=wait_tokenize)
        transport = SecureConsumerTransport._for_tests(client, FakeAuthorizer())
        runs = [
            await transport.submit(self.submission()) for _ in range(MAX_ACTIVE_RUNS)
        ]
        with self.assertRaises(ConnectorError) as busy:
            await transport.submit(self.submission())
        self.assertEqual(busy.exception.code, "BUSY")
        self.assertEqual(transport.status()["active_runs"], MAX_ACTIVE_RUNS)
        for run in runs:
            transport.cancel(run.request_id)
        await asyncio.gather(*(run.closed for run in runs))
        for run in runs:
            run._discard_output()
            transport._release(run.request_id, run)

    async def test_active_id_remains_reserved_after_recent_cache_eviction(self):
        gate = asyncio.Event()

        class Client(FakeClient):
            async def tokenize(self, prompt, *, trusted_request_context):
                self.tokenize_calls.append((prompt, trusted_request_context))
                if prompt == "held request":
                    await gate.wait()
                return [11]

        client = Client()
        authorizer = FakeAuthorizer()
        transport = SecureConsumerTransport._for_tests(client, authorizer)
        active_submission = self.submission()
        active_submission = ConsumerSubmission(
            active_submission.request_id, "held request", 1, 300
        )
        active = await transport.submit(active_submission)
        for _ in range(256):
            run = await transport.submit(self.submission(tokens=1))
            await self.finish(run)
        self.assertNotIn(active.request_id, transport._recent_ids)
        with self.assertRaises(ConnectorError) as duplicate:
            await transport.submit(active_submission)
        self.assertEqual(duplicate.exception.code, "DUPLICATE")
        self.assertIs(transport._active[active.request_id], active)
        transport.cancel(active.request_id)
        await active.closed
        active._discard_output()
        transport._release(active.request_id, active)

    async def test_cancel_is_fast_local_intent_and_does_not_claim_reclamation(self):
        gate = asyncio.Event()

        async def wait_tokenize(_prompt, _context):
            await gate.wait()
            return [1]

        client = FakeClient(tokenize=wait_tokenize)
        transport = SecureConsumerTransport._for_tests(client, FakeAuthorizer())
        run = await transport.submit(self.submission())
        before = time.monotonic()
        receipt = transport.cancel(run.request_id)
        self.assertLess(time.monotonic() - before, 0.1)
        self.assertEqual(receipt["state"], "cancel_intent_recorded")
        self.assertFalse(receipt["remote_reclamation_confirmed"])
        await run.closed
        with self.assertRaises(ConnectorError) as cancelled:
            await run.result
        self.assertEqual(cancelled.exception.code, "CANCELLED")
        self.assertEqual(client.generate_calls, [])

    async def test_repeated_cancel_is_idempotent(self):
        gate = asyncio.Event()

        async def wait_tokenize(_prompt, _context):
            await gate.wait()
            return [1]

        client = FakeClient(tokenize=wait_tokenize)
        transport = SecureConsumerTransport._for_tests(client, FakeAuthorizer())
        run = await transport.submit(self.submission())
        first = transport.cancel(run.request_id)
        second = transport.cancel(run.request_id)
        self.assertEqual(first["state"], second["state"])
        await asyncio.sleep(0)
        self.assertEqual(run._task.cancelling(), 1)
        await run.closed
        run._discard_output()
        transport._release(run.request_id, run)

    async def test_cancelled_aclose_waiter_does_not_cancel_shared_closed_state(self):
        gate = asyncio.Event()

        async def wait_tokenize(_prompt, _context):
            await gate.wait()
            return [1]

        client = FakeClient(tokenize=wait_tokenize)
        transport = SecureConsumerTransport._for_tests(client, FakeAuthorizer())
        run = await transport.submit(self.submission())
        close_waiter = asyncio.create_task(run.aclose())
        await asyncio.sleep(0)
        close_waiter.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await close_waiter
        self.assertFalse(run._closed.cancelled())
        await asyncio.wait_for(run.closed, timeout=1)
        run._discard_output()
        transport._release(run.request_id, run)

    async def test_interrupted_cleanup_wait_retains_task_graph_and_context(self):
        gate = asyncio.Event()
        started = asyncio.Event()
        child_tasks = []
        transport = self.transport
        context = FakeContext("req_" + "b" * 32, time.monotonic() + 30)

        async def close_stream():
            async def wait_for_close():
                started.set()
                await gate.wait()

            child = asyncio.create_task(wait_for_close())
            child_tasks.append(child)
            await asyncio.shield(child)

        with patch(
            "steamboat_connector.consumer_transport.MAX_CANCELLATION_GRACE_SECONDS", 0.5
        ):
            cleanup_wait = asyncio.create_task(
                transport._await_cleanup(close_stream(), context)
            )
            await started.wait()
            cleanup_wait.cancel()
            with self.assertRaises(SecureTaskPending) as pending:
                await cleanup_wait
        self.assertFalse(context.closed)
        self.assertFalse(transport.status()["available"])
        self.assertEqual(len(child_tasks), 1)
        self.assertIn(pending.exception.tasks[0], transport._pending_tasks)
        owner = transport._pending_context_owners[context]
        transport._finish_context_driver(context)
        gate.set()
        await asyncio.wait_for(child_tasks[0], timeout=1)
        await asyncio.wait_for(owner["watcher"], timeout=1)
        self.assertTrue(context.closed)

    async def test_interrupted_bounded_cancel_retains_c1_reported_descendant(self):
        gate = asyncio.Event()
        started = asyncio.Event()
        child_tasks = []
        context = FakeContext("req_" + "c" * 32, time.monotonic() + 30)
        transport = self.transport

        async def operation():
            async def child_work():
                started.set()
                await gate.wait()

            child = asyncio.create_task(child_work())
            child_tasks.append(child)
            try:
                await asyncio.shield(child)
            except asyncio.CancelledError:
                raise SecureTaskPending((child,), "operation reported pending child")

        operation_task = asyncio.create_task(operation())
        await started.wait()
        with self.assertRaises(SecureTaskPending) as pending:
            await transport._cancel_bounded(operation_task, context=context)
        self.assertIn(child_tasks[0], pending.exception.tasks)
        self.assertIn(child_tasks[0], transport._pending_tasks)
        self.assertFalse(context.closed)
        owner = transport._pending_context_owners[context]
        transport._finish_context_driver(context)
        gate.set()
        await asyncio.wait_for(child_tasks[0], timeout=1)
        await asyncio.wait_for(owner["watcher"], timeout=1)
        self.assertTrue(context.closed)

    async def test_pending_context_waits_for_all_groups_and_nested_descendants(self):
        first_gate = asyncio.Event()
        nested_gate = asyncio.Event()
        context = FakeContext("req_" + "a" * 32, time.monotonic() + 30)

        async def first_group():
            await first_gate.wait()

        async def nested_child():
            await nested_gate.wait()

        async def second_group():
            child = asyncio.create_task(nested_child())
            raise SecureTaskPending((child,), "nested cleanup still pending")

        first = asyncio.create_task(first_group())
        second = asyncio.create_task(second_group())
        transport = self.transport
        transport._mark_uncertain(SecureTaskPending((first,)), context)
        transport._mark_uncertain(SecureTaskPending((second,)), context)
        transport._finish_context_driver(context)
        await asyncio.sleep(0)
        first_gate.set()
        await first
        await asyncio.sleep(0.01)
        self.assertFalse(context.closed)
        self.assertGreaterEqual(transport.status()["pending_secure_tasks"], 1)
        nested_gate.set()
        await asyncio.wait_for(transport._pending_context_owners[context]["watcher"], 1)
        self.assertTrue(context.closed)

    async def test_unknown_cleanup_fault_is_sticky_after_known_tasks_finish(self):
        gate = asyncio.Event()
        context = FakeContext("req_" + "d" * 32, time.monotonic() + 30)

        async def known_group():
            await gate.wait()

        known = asyncio.create_task(known_group())
        self.transport._mark_uncertain(None, context)
        self.transport._mark_uncertain(SecureTaskPending((known,)), context)
        self.transport._finish_context_driver(context)
        owner = self.transport._pending_context_owners[context]
        gate.set()
        await known
        if owner["watcher"] is not None:
            await asyncio.wait_for(owner["watcher"], 1)
        self.assertTrue(owner["sticky_unknown"])
        self.assertFalse(context.closed)

    async def test_pending_generation_waits_for_driver_cleanup_before_context_close(
        self,
    ):
        pending_gate = asyncio.Event()
        cleanup_gate = asyncio.Event()
        cleanup_started = asyncio.Event()

        async def pending_rpc():
            await pending_gate.wait()

        pending = asyncio.create_task(pending_rpc())

        class PendingThenCloseStream:
            def __aiter__(self):
                return self

            async def __anext__(self):
                raise SecureTaskPending((pending,), "generation RPC remains pending")

            async def aclose(self):
                cleanup_started.set()
                await cleanup_gate.wait()

        client = FakeClient(generation=lambda *_args: PendingThenCloseStream())
        authorizer = FakeAuthorizer()
        transport = SecureConsumerTransport._for_tests(client, authorizer)
        run = await transport.submit(self.submission())
        await cleanup_started.wait()
        pending_gate.set()
        await pending
        await asyncio.sleep(0.01)
        context = authorizer.contexts[0]
        self.assertFalse(context.closed)
        self.assertIn(context, transport._pending_contexts)
        cleanup_gate.set()
        await asyncio.wait_for(run.closed, 1)
        for _ in range(20):
            if context.closed:
                break
            await asyncio.sleep(0)
        self.assertTrue(context.closed)

    async def test_immediate_cancel_before_driver_start_still_closes_run(self):
        run = await self.transport.submit(self.submission())
        receipt = self.transport.cancel(run.request_id)
        self.assertTrue(receipt["accepted"])
        await asyncio.wait_for(run.closed, timeout=1)
        with self.assertRaises(ConnectorError) as cancelled:
            await run.result
        self.assertEqual(cancelled.exception.code, "CANCELLED")
        run._discard_output()
        self.transport._release(run.request_id, run)

    async def test_original_deadline_covers_tokenization_and_skips_generate(self):
        async def slow_tokenize(_prompt, _context):
            await asyncio.sleep(1.1)
            return [1]

        client = FakeClient(tokenize=slow_tokenize)
        transport = SecureConsumerTransport._for_tests(client, FakeAuthorizer())
        run = await transport.submit(self.submission(deadline=1))
        await run.closed
        with self.assertRaises(ConnectorError) as expired:
            await run.result
        self.assertEqual(expired.exception.code, "DEADLINE_EXCEEDED")
        self.assertEqual(client.generate_calls, [])

    async def test_original_deadline_covers_generation_stream(self):
        async def slow_generation(_input_ids, _new_tokens):
            await asyncio.sleep(1.1)
            yield {"type": "token", "index": 0, "token_id": 100}

        client = FakeClient(generation=slow_generation)
        transport = SecureConsumerTransport._for_tests(client, FakeAuthorizer())
        run = await transport.submit(self.submission(deadline=1, tokens=1))
        await run.closed
        with self.assertRaises(ConnectorError) as expired:
            await run.result
        self.assertEqual(expired.exception.code, "DEADLINE_EXCEEDED")
        self.assertEqual(len(client.generate_calls), 1)

    async def test_output_backpressure_fails_and_does_not_accumulate_unbounded_events(
        self,
    ):
        client = FakeClient()
        transport = SecureConsumerTransport._for_tests(client, FakeAuthorizer())
        run = await transport.submit(self.submission(tokens=MAX_PENDING_EVENTS + 2))
        with patch(
            "steamboat_connector.consumer_transport.MAX_OUTPUT_STALL_SECONDS", 0.01
        ):
            await run.closed
        self.assertLessEqual(run._queue.qsize(), 2)
        with self.assertRaises(ConnectorError) as stalled:
            await run.result
        self.assertEqual(stalled.exception.code, "BACKPRESSURE")
        self.assertEqual(client.generate_calls.__len__(), 1)

    async def test_ambiguous_generate_error_is_not_retried(self):
        async def ambiguous(_input_ids, _new_tokens):
            raise RuntimeError("reply outcome unknown")
            yield None

        client = FakeClient(generation=ambiguous)
        transport = SecureConsumerTransport._for_tests(client, FakeAuthorizer())
        run = await transport.submit(self.submission())
        await run.closed
        with self.assertRaises(ConnectorError):
            await run.result
        self.assertEqual(len(client.generate_calls), 1)

    async def test_pending_cleanup_retains_context_and_disables_transport(self):
        blocker = asyncio.create_task(asyncio.sleep(10))

        class PendingStream:
            def __aiter__(self):
                return self

            async def __anext__(self):
                raise SecureTaskPending((blocker,))

            async def aclose(self):
                return None

        client = FakeClient(generation=lambda *_args: PendingStream())
        transport = SecureConsumerTransport._for_tests(client, FakeAuthorizer())
        run = await transport.submit(self.submission())
        await run.closed
        self.assertFalse(transport.status()["available"])
        context = transport._authorizer.contexts[0]
        self.assertFalse(context.closed)
        with self.assertRaises(ConnectorError) as pending:
            await run.result
        self.assertEqual(pending.exception.code, "CLEANUP_UNCERTAIN")
        with self.assertRaises(ConnectorError):
            await transport.submit(self.submission())
        blocker.cancel()
        await asyncio.gather(blocker, return_exceptions=True)
        await asyncio.sleep(0)
        self.assertTrue(context.closed)

    async def test_public_constructor_requires_exact_c1_types(self):
        fake = FakeClient()
        with self.assertRaises(TypeError):
            SecureConsumerTransport(fake, self.authorizer)
        with self.assertRaises(TypeError):
            SecureConsumerTransport(object.__new__(SecureCoordinatorClient), object())


class ConsumerContextFactoryTests(unittest.TestCase):
    def test_factory_accepts_and_preserves_submission_request_id(self):
        authorizer = object.__new__(OutboundAuthorizer)
        authorizer.target = SimpleNamespace(service="steamboat.v1.Coordinator")
        authorizer.clock = Clock(
            wall=lambda: 10.0, monotonic=lambda: 5.0, uncertainty_seconds=lambda: 0.0
        )
        authorizer.snapshot_store = SimpleNamespace(current=lambda *, sample: object())
        authorizer.local_identity = SimpleNamespace(certificate_pem=b"synthetic cert")
        authorizer._capability_owner = object()
        request_id = "req_" + "a" * 32
        with patch("steamboat_security.authorization._verify_pinned_credential"):
            context = authorizer.create_consumer_request_context(
                lifetime_seconds=12, request_id=request_id
            )
        self.assertIs(type(context), ConsumerRequestContext)
        self.assertEqual(context.request_id, request_id)
        context.close()
        with self.assertRaises(Exception):
            authorizer.create_consumer_request_context(request_id="not-typed")


class ConsumerImportIsolationTests(unittest.TestCase):
    def test_import_succeeds_when_model_packages_are_blocked(self):
        script = r"""
import importlib.abc, sys
blocked = {"torch", "transformers", "safetensors"}
class BlockModelImports(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname.split(".", 1)[0] in blocked:
            raise AssertionError("model dependency imported: " + fullname)
sys.meta_path.insert(0, BlockModelImports())
import steamboat_connector.consumer_transport
assert not any(name.split(".", 1)[0] in blocked for name in sys.modules)
"""
        root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
        env = dict(os.environ)
        env["PYTHONPATH"] = os.path.join(root, "src")
        result = subprocess.run(
            [sys.executable, "-c", script],
            cwd=root,
            env=env,
            capture_output=True,
            text=True,
            timeout=20,
        )
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
