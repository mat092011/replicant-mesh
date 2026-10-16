"""Coordinator component ownership, bounded CPU work and thin client behavior."""

import asyncio
import os
import threading
import time
import unittest
from unittest.mock import patch


ENABLED = os.environ.get("STEAMBOAT_PROTOCOL_TESTS") == "1"
ARTIFACTS = os.environ.get("STEAMBOAT_ARTIFACT_DIR")
REFERENCE = os.environ.get("STEAMBOAT_REFERENCE_DIR")


@unittest.skipUnless(ENABLED, "Use the pinned PyTorch image with STEAMBOAT_PROTOCOL_TESTS=1")
class CoordinatorModelTests(unittest.IsolatedAsyncioTestCase):
    @classmethod
    def setUpClass(cls):
        import torch
        from steamboat_runtime.coordinator_model import CoordinatorModel
        cls.torch, cls.Model = torch, CoordinatorModel

    async def asyncSetUp(self):
        torch = self.torch
        component = torch.nn.Module()
        component.embed_tokens = torch.nn.Embedding(32, 4)
        component.norm = torch.nn.Identity()
        component.lm_head = torch.nn.Linear(4, 32, bias=False)
        self.tokenizer_calls = []

        def tokenizer(text, **options):
            self.tokenizer_calls.append(options)
            return {"input_ids": torch.ones((1, len(text.split()) + 1), dtype=torch.int64)}

        self.model = self.Model({
            "config": {"vocab_size": 32, "hidden_size": 4},
            "limits": {"max_positions": 16, "max_sessions": 2,
                       "compute_cancel_grace_seconds": 2},
        }, component, tokenizer)
        self.release = threading.Event()

    async def asyncTearDown(self):
        self.release.set()
        self.assertTrue(await self.model.close(timeout_seconds=2))

    async def until(self, condition):
        deadline = time.monotonic() + 2
        while not condition():
            if time.monotonic() >= deadline:
                self.fail("Timed out waiting for controlled CPU operation")
            await asyncio.sleep(0.005)

    def ids(self):
        return self.torch.tensor([[1, 2]], dtype=self.torch.int64)

    async def test_embed_finish_run_in_inference_thread_and_match_projection(self):
        torch = self.torch
        calls = []

        def observed(module, inputs):
            calls.append((threading.get_ident(), torch.is_inference_mode_enabled()))

        hook = self.model.input_output.embed_tokens.register_forward_pre_hook(observed)
        hidden = await self.model.embed(self.ids())
        hook.remove()
        self.assertEqual(hidden.shape, (1, 2, 4))
        self.assertFalse(hidden.requires_grad)
        self.assertTrue(all(identity != threading.get_ident() and inference
                            for identity, inference in calls))
        actual = await self.model.finish(hidden, all_logits=True)
        last = await self.model.finish(hidden)
        with torch.inference_mode():
            expected = self.model.input_output.lm_head(hidden)
        torch.testing.assert_close(actual, expected, atol=0, rtol=0)
        torch.testing.assert_close(last, expected[:, -1:, :], atol=1e-6, rtol=0)

    async def test_invalid_ids_and_hidden_are_rejected_before_model_execution(self):
        torch = self.torch
        for ids in (torch.ones((2, 1), dtype=torch.int64),
                    torch.empty((1, 0), dtype=torch.int64),
                    torch.ones((1, 17), dtype=torch.int64),
                    torch.tensor([[-1]]), torch.tensor([[32]]), self.ids().float()):
            with self.subTest(shape=tuple(ids.shape), dtype=ids.dtype), self.assertRaises(ValueError):
                await self.model.embed(ids)
        for hidden in (torch.zeros((1, 2, 5)), torch.zeros((1, 17, 4)),
                       torch.zeros((2, 1, 4)), torch.zeros((1, 1, 4)).double(),
                       torch.full((1, 1, 4), float("nan"))):
            with self.subTest(shape=tuple(hidden.shape), dtype=hidden.dtype), self.assertRaises(ValueError):
                await self.model.finish(hidden)
        self.assertEqual(self.model.diagnostics()["pending_cpu_operations"], 0)

    async def test_text_byte_limit_context_limit_and_no_truncation(self):
        ids = await self.model.tokenize("two words")
        self.assertEqual(ids.shape, (1, 3))
        self.assertEqual(self.tokenizer_calls, [
            {"return_tensors": "pt", "truncation": False, "add_special_tokens": True}])
        for text in ("", "a" * 65537, "😀" * 17000, "word " * 16):
            with self.subTest(length=len(text)), self.assertRaises(ValueError):
                await self.model.tokenize(text)

    async def test_running_cancel_retains_capacity_and_loop_stays_responsive(self):
        started = threading.Event()
        original = self.model._embed

        def blocked(ids):
            started.set()
            if not self.release.wait(2):
                raise RuntimeError("Test did not release CPU operation")
            return original(ids)

        with patch.object(self.model, "_embed", blocked):
            first = asyncio.create_task(self.model.embed(self.ids()))
            await self.until(started.is_set)
            first.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await first
            second = asyncio.create_task(self.model.embed(self.ids()))
            await self.until(lambda: self.model.diagnostics()["pending_cpu_operations"] == 2)
            with self.assertRaisesRegex(RuntimeError, "capacity"):
                await self.model.embed(self.ids())
            second.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await second
            await self.until(lambda: self.model.diagnostics()["pending_cpu_operations"] == 1)
            self.assertFalse(await self.model.close(timeout_seconds=0.01))
            self.assertTrue(self.model.requires_restart)
            with self.assertRaisesRegex(RuntimeError, "closed"):
                await self.model.embed(self.ids())
            self.release.set()
            await self.until(lambda: self.model.diagnostics()["pending_cpu_operations"] == 0)

    async def test_queued_input_has_independent_storage(self):
        started = threading.Event()
        original = self.model._embed

        def blocked(ids):
            started.set()
            self.release.wait(2)
            return original(ids)

        ids = self.ids()
        expected_ids = ids.clone()
        with patch.object(self.model, "_embed", blocked):
            operation = asyncio.create_task(self.model.embed(ids))
            await self.until(started.is_set)
            ids.fill_(7)
            self.release.set()
            actual = await operation
        expected = await self.model.embed(expected_ids)
        self.torch.testing.assert_close(actual, expected, atol=0, rtol=0)


@unittest.skipUnless(ENABLED and ARTIFACTS and REFERENCE,
                     "Set pinned artifact/reference paths for coordinator ownership checks")
class CoordinatorArtifactTests(unittest.IsolatedAsyncioTestCase):
    async def test_only_input_output_weights_loaded_and_tokenizer_is_offline(self):
        from steamboat_runtime.coordinator_model import CoordinatorModel
        import torch
        with patch("steamboat_runtime.model.LayerStage", side_effect=AssertionError("layer loaded")), \
                patch("transformers.AutoModelForCausalLM.from_pretrained",
                      side_effect=AssertionError("complete model loaded")):
            model = CoordinatorModel.from_artifacts(ARTIFACTS, REFERENCE)
        try:
            self.assertEqual(set(dict(model.input_output.named_parameters())), {
                "embed_tokens.weight", "norm.weight", "lm_head.weight"})
            self.assertEqual(model.diagnostics()["parameter_count"], 4_096_064)
            self.assertEqual(model.diagnostics()["parameter_bytes"], 16_384_256)
            ids = await model.tokenize("An ordinary public test prompt.")
            self.assertEqual(ids.dtype, torch.int64)
            self.assertEqual(ids[0, 0].item(), 1)
            hidden = await model.embed(ids)
            logits = await model.finish(hidden)
            self.assertEqual(logits.shape, (1, 1, 32000))
        finally:
            self.assertTrue(await model.close())


class CoordinatorClientTests(unittest.IsolatedAsyncioTestCase):
    def fixture(self):
        from steamboat_runtime.client import CoordinatorClient

        class Handle:
            def __init__(self):
                self.events = iter((11, 12, 13))
                self.cancelled, self.finished = False, False

            def __aiter__(self):
                return self

            async def __anext__(self):
                try:
                    return next(self.events)
                except StopIteration:
                    raise StopAsyncIteration

            async def result(self):
                self.finished = True

            async def cancel(self):
                self.cancelled = True

        class Coordinator:
            model = None

            def submit(self, ids, new_tokens, **options):
                return handle

        handle = Handle()
        return CoordinatorClient(Coordinator()), handle

    async def test_complete_stream_awaits_final_cleanup(self):
        client, handle = self.fixture()
        self.assertEqual([token async for token in client.generate([1, 2], 3)], [11, 12, 13])
        self.assertTrue(handle.finished)
        self.assertFalse(handle.cancelled)

    async def test_early_stream_close_cancels_owned_handle(self):
        client, handle = self.fixture()
        stream = client.generate([1, 2], 3)
        self.assertEqual(await anext(stream), 11)
        await stream.aclose()
        self.assertTrue(handle.cancelled)
