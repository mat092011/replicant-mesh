"""Real cross-process serialization; reservation arithmetic is not execution fit."""

import multiprocessing
from pathlib import Path
import sys
import tempfile
import unittest

from steamboat_connector.resources import ResourceError, ResourceLedger

from .test_resources_controller import sample_policy


def _reserve_in_child(path, role, reservation, start, outcomes):
    ledger = ResourceLedger(path)
    if not start.wait(5):
        raise RuntimeError("reservation test start timed out")
    try:
        ledger.reserve(role, reservation)
        outcomes.put((role, "accepted"))
    except ResourceError:
        outcomes.put((role, "rejected"))


@unittest.skipUnless(sys.platform.startswith("linux"), "requires real Linux file locks")
class FileLedgerProcessTests(unittest.TestCase):
    def test_competing_processes_share_one_atomic_pool(self):
        context = multiprocessing.get_context("spawn")
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "state" / "resource-ledger.json"
            policy = sample_policy()
            policy["limits"].update(memory_ceiling_bytes=2000, memory_headroom_bytes=500)
            for reservation in policy["reservations"].values():
                for field in ("weights_bytes", "kv_bytes", "temporary_bytes",
                              "runtime_bytes", "communication_bytes", "capture_bytes"):
                    reservation[field] = 0
                reservation["weights_bytes"] = 800
            ledger = ResourceLedger(path)
            ledger.configure(policy)
            start, outcomes = context.Event(), context.Queue()
            children = [context.Process(target=_reserve_in_child,
                         args=(path, role, policy["reservations"][role], start, outcomes))
                        for role in ("host", "coordinator")]
            try:
                for child in children:
                    child.start()
                start.set()
                results = [outcomes.get(timeout=5) for _ in children]
                for child in children:
                    child.join(timeout=5)
                    self.assertEqual(child.exitcode, 0)
                self.assertEqual(sorted(status for _, status in results), ["accepted", "rejected"])
                snapshot = ledger.snapshot()
                self.assertEqual(len(snapshot["reservations"]), 1)
                winner = next(role for role, status in results if status == "accepted")
                self.assertEqual(set(snapshot["reservations"]), {winner})
                ledger.release(winner, reclaimed=True)
                self.assertEqual(ledger.snapshot()["reservations"], {})
            finally:
                for child in children:
                    if child.is_alive():
                        child.terminate()
                    child.join(timeout=2)
                outcomes.close()
                outcomes.join_thread()
