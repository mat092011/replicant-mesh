"""Failure-evidence bookkeeping for the remote numerical gate without weights."""

import asyncio
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from steamboat_runtime.service_check import consume_checked


class ScriptedClient:
    def __init__(self, events):
        self.events = events
        self.closed = False

    async def generate(self, *args, **kwargs):
        try:
            for event in self.events:
                if isinstance(event, BaseException):
                    raise event
                yield event
        finally:
            self.closed = True


def token(index=0):
    return {"type": "token", "session_id": "session", "index": index,
            "sequence": index, "position": 1 + index, "token_id": 3, "logits": [1, 2]}


def result(status="completed"):
    return {"type": "result", "status": status, "cleanup_complete": True,
            "token_ids": [3], "metrics": {"admission_ms": 4}}


class ServiceEvidenceTests(unittest.IsolatedAsyncioTestCase):
    async def invoke(self, events, evidence, *, comparison_error=None, output_count=1):
        client = ScriptedClient(events)
        expected = [SimpleNamespace(argmax=lambda **_: SimpleNamespace(item=lambda: 3))] * output_count
        fake_torch = SimpleNamespace(tensor=lambda value, **_: value, float32="float32")
        with patch.dict(sys.modules, {"torch": fake_torch}), \
                patch("steamboat_runtime.service_check.compare_logits", side_effect=comparison_error):
            try:
                return await consume_checked(client, [7], expected, "test-case", evidence)
            finally:
                self.assertTrue(client.closed)

    async def test_success_is_recorded_once(self):
        evidence = {}
        record = await self.invoke([token(), result()], evidence)
        self.assertEqual(evidence["requests"], [record])
        self.assertTrue(record["success"])
        self.assertEqual(record["token_ids"], [3])
        self.assertTrue(record["cleanup_complete"])

    async def test_failed_terminal_keeps_metrics_and_validated_prefix(self):
        terminal = result("failed")
        terminal["error_code"] = "TIMEOUT"
        error = RuntimeError("expired")
        error.code = "TIMEOUT"
        evidence = {}
        with self.assertRaisesRegex(RuntimeError, "expired"):
            await self.invoke([token(), terminal, error], evidence, output_count=2)
        record = evidence["requests"][0]
        self.assertFalse(record["success"])
        self.assertEqual(record["token_ids"], [3])
        self.assertEqual(record["server_metrics"], terminal["metrics"])
        self.assertEqual(record["error_code"], "TIMEOUT")
        self.assertEqual(record["terminal_result"], terminal)
        self.assertTrue(record["cleanup_complete"])

    async def test_logit_failure_is_retained_without_claiming_completion(self):
        evidence = {}
        with self.assertRaisesRegex(AssertionError, "bad logits"):
            await self.invoke([token(), result()], evidence, comparison_error=AssertionError("bad logits"))
        record = evidence["requests"][0]
        self.assertEqual(record["session_id"], "session")
        self.assertFalse(record["success"])
        self.assertFalse(record["cleanup_complete"])
        self.assertEqual(record["error"]["type"], "AssertionError")

    async def test_cancelled_sibling_retains_prefix_and_error(self):
        evidence = {}
        with self.assertRaises(asyncio.CancelledError):
            await self.invoke([token(), asyncio.CancelledError()], evidence, output_count=2)
        record = evidence["requests"][0]
        self.assertEqual(record["status"], "cancelled")
        self.assertFalse(record["success"])
        self.assertEqual(record["token_ids"], [3])


if __name__ == "__main__":
    unittest.main()
