"""Portable fail-closed contract tests for the C2 local startup adapter."""
from __future__ import annotations

import sys
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from steamboat_connector.c2_local_startup import C2LocalStartup, C2LocalStartupError


class _NeverOwner:
    def __init__(self):
        self.calls = 0

    def snapshot(self):
        self.calls += 1
        raise AssertionError("owner state must not be consulted for an invalid request")


class C2LocalStartupContractTests(unittest.TestCase):
    def adapter(self):
        value = object.__new__(C2LocalStartup)
        value._active = threading.Lock()
        value._owner = _NeverOwner()
        value._references = {}
        value._policies = {}
        return value

    def test_consumer_refused_before_owner_epoch_or_claim(self):
        adapter = self.adapter()
        with self.assertRaises(ValueError):
            adapter.start(("consumer",), cancel_event=threading.Event())
        self.assertEqual(adapter._owner.calls, 0)

    def test_remote_or_global_roles_refused_before_owner_snapshot(self):
        adapter = self.adapter()
        for roles in (("remote",), ("host", "remote"), ("global",)):
            with self.subTest(roles=roles), self.assertRaises(ValueError):
                adapter.start(roles, cancel_event=threading.Event())
        self.assertEqual(adapter._owner.calls, 0)

    def test_roles_must_be_exact_sorted_unique_tuple(self):
        adapter = self.adapter()
        for roles in ([], ("host", "host"), ("host", "coordinator"), ()):
            with self.subTest(roles=roles), self.assertRaises(ValueError):
                adapter.start(roles, cancel_event=threading.Event())
        self.assertEqual(adapter._owner.calls, 0)

    def test_only_one_start_operation_can_be_active(self):
        adapter = self.adapter()
        adapter._active.acquire()
        with self.assertRaises(C2LocalStartupError):
            adapter.start(("host",), cancel_event=threading.Event())
        adapter._active.release()
        self.assertEqual(adapter._owner.calls, 0)


if __name__ == "__main__":
    unittest.main()
