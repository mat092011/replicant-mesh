import threading
import time
import unittest

from steamboat_connector.controller import ManagementController
from steamboat_connector.errors import ConnectorError
from steamboat_connector.resources import MemoryResourceLedger, ResourceError
from steamboat_connector.state import initial_state
from steamboat_connector.storage import MemoryStateStore
from steamboat_connector.telemetry import TelemetryRegistry


def sample_policy(required_telemetry=()):
    limits = {
        "memory_ceiling_bytes": 10_000,
        "memory_headroom_bytes": 1_000,
        "cpu_quota_millis": 1_000,
        "disk_ceiling_bytes": 10_000,
        "send_bytes_per_second": 10_000,
        "receive_bytes_per_second": 10_000,
        "total_network_bytes": 100_000,
        "cleanup_send_bytes_per_second": 10_000,
        "cleanup_receive_bytes_per_second": 10_000,
        "cleanup_total_network_bytes": 100_000,
        "max_sessions": 8,
        "max_queued_calls": 8,
        "max_request_seconds": 300,
    }
    reservation = {
        "weights_bytes": 100,
        "kv_bytes": 100,
        "temporary_bytes": 100,
        "runtime_bytes": 100,
        "communication_bytes": 100,
        "capture_bytes": 100,
        "cpu_quota_millis": 100,
        "disk_bytes": 100,
        "send_bytes_per_second": 100,
        "receive_bytes_per_second": 100,
        "total_network_bytes": 1_000,
        "cleanup_send_bytes_per_second": 100,
        "cleanup_receive_bytes_per_second": 100,
        "cleanup_total_network_bytes": 1_000,
        "sessions": 1,
        "queued_calls": 1,
        "max_request_seconds": 60,
    }
    return {"version": 1, "pool_id": "unit-test-pool", "limits": limits,
            "reservations": {"host": dict(reservation),
                             "coordinator": dict(reservation)},
            "required_telemetry": list(required_telemetry)}


class BlockingStopBackend:
    secure_runtime_ready = True

    def __init__(self):
        self.entered = threading.Event()
        self.release = threading.Event()

    def start(self, role, policy):
        return False

    def drain(self, roles, deadline, cancel_event):
        return {"drained": False, "reclaimed": False}

    def stop(self, roles, grace_seconds):
        self.entered.set()
        self.release.wait(5)
        return {role: True for role in roles}


class ResourceControllerTests(unittest.TestCase):
    def test_memory_ledger_counts_shared_pool_and_requires_reclamation(self):
        policy = sample_policy()
        ledger = MemoryResourceLedger()
        ledger.configure(policy)
        ledger.reserve("host", policy["reservations"]["host"])
        ledger.reserve("coordinator", policy["reservations"]["coordinator"])
        snapshot = ledger.snapshot()
        self.assertEqual(set(snapshot["reservations"]), {"host", "coordinator"})
        self.assertEqual(snapshot["reservations"]["host"]["weights_bytes"], 100)
        with self.assertRaises(ResourceError):
            ledger.release("host", reclaimed=False)
        with self.assertRaises(ResourceError):
            ledger.reserve("host", {**policy["reservations"]["host"],
                                     "weights_bytes": True})
        ledger.release("host", reclaimed=True)
        self.assertNotIn("host", ledger.snapshot()["reservations"])

    def test_concurrent_role_reservations_cannot_double_count_memory(self):
        policy = sample_policy()
        policy["limits"]["memory_ceiling_bytes"] = 2_000
        policy["limits"]["memory_headroom_bytes"] = 500
        for reservation in policy["reservations"].values():
            for field in ("weights_bytes", "kv_bytes", "temporary_bytes",
                          "runtime_bytes", "communication_bytes", "capture_bytes"):
                reservation[field] = 0
            reservation["weights_bytes"] = 800
        ledger = MemoryResourceLedger()
        ledger.configure(policy)
        barrier = threading.Barrier(3)
        outcomes = []

        def reserve(role):
            barrier.wait()
            try:
                ledger.reserve(role, policy["reservations"][role])
                outcomes.append(True)
            except ResourceError:
                outcomes.append(False)

        threads = [threading.Thread(target=reserve, args=(role,))
                   for role in ("host", "coordinator")]
        for thread in threads:
            thread.start()
        barrier.wait()
        for thread in threads:
            thread.join(timeout=2)
        self.assertEqual(sum(outcomes), 1)
        self.assertEqual(len(ledger.snapshot()["reservations"]), 1)

    def test_roles_are_off_and_execution_fails_closed_without_telemetry(self):
        clock = [10.0]
        telemetry = TelemetryRegistry(clock=lambda: clock[0])
        ledger = MemoryResourceLedger()
        store = MemoryStateStore(initial_state())
        controller = ManagementController(ledger=ledger, store=store,
                                         telemetry=telemetry, clock=lambda: clock[0],
                                         start_workers=False)
        try:
            initial = controller.status()
            self.assertTrue(all(not item["enabled"] for item in initial["roles"].values()))
            controller.handle("policy.set", {"policy": sample_policy(["thermal"])})
            controller.handle("role.enable", {"role": "host"})
            outcome = controller.handle("start", {"roles": ["host"]})
            self.assertEqual(outcome["state"], "unavailable")
            self.assertIn("telemetry_thermal_unavailable", outcome["blockers"]["host"])
            self.assertTrue(controller.check_telemetry())
            self.assertTrue(controller.status()["paused_roles"]["host"])
        finally:
            controller.shutdown(wait_seconds=0)

    def test_owner_role_opt_in_is_persisted_but_restart_pauses(self):
        store = MemoryStateStore(initial_state())
        ledger = MemoryResourceLedger()
        first = ManagementController(ledger=ledger, store=store, start_workers=False)
        first.handle("role.enable", {"role": "consumer"})
        first.shutdown(wait_seconds=0)
        second = ManagementController(ledger=ledger, store=store, start_workers=False)
        try:
            state = second.status()
            self.assertTrue(state["roles"]["consumer"]["enabled"])
            self.assertEqual(state["roles"]["consumer"]["state"], "paused")
            self.assertTrue(state["paused_roles"]["consumer"])
        finally:
            second.shutdown(wait_seconds=0)

    def test_drain_deadline_is_bounded_and_non_sliding(self):
        controller = ManagementController(ledger=MemoryResourceLedger(),
                                          store=MemoryStateStore(initial_state()),
                                          start_workers=False)
        try:
            first = controller.handle("drain", {"roles": ["consumer"],
                                                 "deadline_seconds": 300})
            second = controller.handle("drain", {"roles": ["consumer"],
                                                  "deadline_seconds": 1})
            self.assertEqual(first["operation_id"], second["operation_id"])
            self.assertFalse(second["deadline_extended"])
            with self.assertRaises(ConnectorError):
                controller.handle("drain", {"roles": ["consumer"],
                                             "deadline_seconds": 301})
            with self.assertRaises(ConnectorError):
                controller.handle("drain", {"roles": ["host"],
                                             "deadline_seconds": 30})
        finally:
            controller.shutdown(wait_seconds=0)

    def test_policy_reduction_pauses_enabled_role_and_remove_stays_pending(self):
        controller = ManagementController(ledger=MemoryResourceLedger(),
                                          store=MemoryStateStore(initial_state()),
                                          start_workers=False)
        try:
            controller.handle("policy.set", {"policy": sample_policy()})
            controller.handle("role.enable", {"role": "host"})
            reduced = sample_policy()
            reduced["limits"]["memory_ceiling_bytes"] = 650
            reduced["limits"]["memory_headroom_bytes"] = 100
            result = controller.handle("policy.set", {"policy": reduced})
            self.assertTrue(result["resource_ledger_blocked"])
            self.assertTrue(controller.status()["paused_roles"]["host"])

            removed = controller.handle("remove", {"delete_owned_data": False})
            state = controller.status()
            self.assertEqual(removed["revocation_status"], "pending_offline")
            self.assertEqual(state["revocation_status"], "pending_offline")
            self.assertTrue(state["removed"])
            self.assertTrue(all(not role["enabled"] for role in state["roles"].values()))
        finally:
            controller.shutdown(wait_seconds=0)

    def test_stop_acknowledges_persisted_intent_while_child_is_hung(self):
        backend = BlockingStopBackend()
        ledger = MemoryResourceLedger()
        controller = ManagementController(ledger=ledger,
                                          store=MemoryStateStore(initial_state()),
                                          backend=backend, start_workers=True)
        try:
            controller.handle("policy.set", {"policy": sample_policy()})
            controller.handle("role.enable", {"role": "host"})
            started = time.monotonic()
            result = controller.handle("stop", {"roles": ["host"]})
            self.assertLess(time.monotonic() - started, 1.0)
            self.assertEqual(result["state"], "stop_intent_recorded")
            self.assertFalse(result["reclaimed"])
            self.assertTrue(backend.entered.wait(1.0))
            operation = controller.handle("operation.status",
                                          {"operation_id": result["operation_id"]})
            self.assertIn(operation["status"], ("queued", "running"))
            self.assertIn("host", ledger.snapshot()["reservations"])
            backend.release.set()
            deadline = time.monotonic() + 1
            while time.monotonic() < deadline:
                operation = controller.handle("operation.status",
                                              {"operation_id": result["operation_id"]})
                if operation["status"] == "succeeded":
                    break
                time.sleep(0.01)
            self.assertEqual(operation["status"], "succeeded")
            self.assertNotIn("host", ledger.snapshot()["reservations"])
        finally:
            backend.release.set()
            controller.shutdown(wait_seconds=1)


if __name__ == "__main__":
    unittest.main()
