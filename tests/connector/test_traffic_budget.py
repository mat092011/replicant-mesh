"""Focused tests for the future C2 socket owner's aggregate meter primitive."""

import multiprocessing
import os
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from steamboat_connector.policy import RESERVATION_FIELDS
from steamboat_connector.traffic_budget import (
    ALLOWANCE_LIFETIME_NS, MemoryTrafficStore, TrafficAllowance,
    TrafficBudget, TrafficBudgetBusy, TrafficBudgetDenied, TrafficBudgetError,
)
from steamboat_security.clock import Clock


BOOT_A = "a" * 32
BOOT_B = "b" * 32
ALLOC = "c" * 64
DOMAIN = "test-only-monotonic-domain"


def _policy(*, global_total=1200, role_total=300, send_rate=3000,
            role_send_rate=1000, cleanup_total=300, cleanup_rate=300,
            role_cleanup_rate=100):
    limits = {
        "memory_ceiling_bytes": 1_000_000, "memory_headroom_bytes": 1,
        "cpu_quota_millis": 1000, "disk_ceiling_bytes": 1_000_000,
        "send_bytes_per_second": send_rate,
        "receive_bytes_per_second": send_rate,
        "total_network_bytes": global_total,
        "cleanup_send_bytes_per_second": cleanup_rate,
        "cleanup_receive_bytes_per_second": cleanup_rate,
        "cleanup_total_network_bytes": cleanup_total,
        "max_sessions": 3, "max_queued_calls": 3,
        "max_request_seconds": 60,
    }
    reservations = {}
    for role in ("consumer", "host", "coordinator"):
        row = {field: 0 for field in RESERVATION_FIELDS}
        row.update({
            "cpu_quota_millis": 100,
            "disk_bytes": 1000,
            "send_bytes_per_second": role_send_rate,
            "receive_bytes_per_second": role_send_rate,
            "total_network_bytes": role_total,
            "cleanup_send_bytes_per_second": role_cleanup_rate,
            "cleanup_receive_bytes_per_second": role_cleanup_rate,
            "cleanup_total_network_bytes": cleanup_total // 3,
            "sessions": 1, "queued_calls": 1, "max_request_seconds": 60,
        })
        reservations[role] = row
    return {"version": 1, "pool_id": "physical-pool", "limits": limits,
            "reservations": reservations, "required_telemetry": []}


class TestClock:
    """Creates the repository's exact Clock class around mutable test time."""

    def __init__(self, mono=10.0):
        self.mono = mono
        self.wall = 1000.0 + mono
        self.clock = Clock(wall=lambda: self.wall, monotonic=lambda: self.mono,
                           uncertainty_seconds=lambda: 0.0)

    def advance(self, seconds):
        self.mono += seconds
        self.wall += seconds


def _memory_budget(*, store=None, policy=None, clock=None):
    store = store or MemoryTrafficStore()
    clock = clock or TestClock()
    return TrafficBudget.for_tests(
        store=store, allocation_id=ALLOC, uid=1234, clock=clock.clock,
        clock_domain=DOMAIN, policy=policy or _policy()), store, clock


def _cross_process_reserve(state_path, role, boot_id, ready, release, result):
    # Actual file/lock interaction is Linux-only and intentionally prepared for
    # the parent's serialized platform run rather than asserted on Windows.
    from steamboat_connector.traffic_budget import TrafficBudget
    from steamboat_security.clock import Clock
    from steamboat_runtime.protocol.clock import clock_identity

    clock = Clock.system(uncertainty_seconds=lambda: 0.0)
    deadline = time.monotonic() + 5
    while True:
        try:
            budget = TrafficBudget(state_path, allocation_id=ALLOC, uid=os.getuid(),
                                   clock=clock, clock_domain=clock_identity(),
                                   policy=_policy(global_total=900))
            budget.bind_role(role, boot_id)
            break
        except TrafficBudgetBusy:
            if time.monotonic() >= deadline:
                result.put(("busy", None))
                return
            time.sleep(0.005)
    ready.set()
    release.wait(5)
    while True:
        try:
            allowance = budget.reserve(role, boot_id, "send", "data", 200)
            result.put(("ok", allowance._reservation_id))
            return
        except TrafficBudgetBusy:
            if time.monotonic() >= deadline:
                result.put(("busy", None))
                return
            time.sleep(0.005)
        except TrafficBudgetDenied:
            result.put(("denied", None))
            return


@unittest.skipUnless(os.name == "posix" and __import__("sys").platform.startswith("linux"),
                     "real private files/flock are Linux-only")
class LinuxTrafficBudgetTests(unittest.TestCase):
    def _open_budget(self, state_path, policy=None):
        from steamboat_runtime.protocol.clock import clock_identity
        return TrafficBudget(
            state_path, allocation_id=ALLOC, uid=os.getuid(),
            clock=Clock.system(uncertainty_seconds=lambda: 0.0),
            clock_domain=clock_identity(), policy=policy or _policy())

    def test_independent_processes_share_one_role_ledger(self):
        with tempfile.TemporaryDirectory() as temporary:
            os.chmod(temporary, 0o700)
            state_path = str(Path(temporary) / "traffic.json")
            from steamboat_runtime.protocol.clock import clock_identity
            budget = TrafficBudget(
                state_path, allocation_id=ALLOC, uid=os.getuid(),
                clock=Clock.system(uncertainty_seconds=lambda: 0.0),
                clock_domain=clock_identity(), policy=_policy(global_total=900,
                                                              role_total=300))
            ctx = multiprocessing.get_context("fork")
            ready = [ctx.Event(), ctx.Event()]
            release = ctx.Event()
            result = ctx.Queue()
            processes = [ctx.Process(target=_cross_process_reserve,
                                      args=(state_path, "host", BOOT_A,
                                            ready[index], release, result))
                         for index in range(2)]
            for process in processes:
                process.start()
            try:
                self.assertTrue(all(event.wait(5) for event in ready))
                release.set()
                outcomes = sorted(result.get(timeout=5)[0] for _ in processes)
                self.assertEqual(outcomes, ["denied", "ok"])
            finally:
                release.set()
                for process in processes:
                    process.join(5)
                    if process.is_alive():
                        process.kill()
                        process.join(5)
            self.assertTrue(all(process.exitcode == 0 for process in processes))

    def test_postreplace_reserve_failure_never_returns_io_capability(self):
        import steamboat_connector.traffic_budget as module

        with tempfile.TemporaryDirectory() as temporary:
            os.chmod(temporary, 0o700)
            path = str(Path(temporary) / "traffic.json")
            budget = self._open_budget(path)
            budget.bind_role("host", BOOT_A)
            write = module.atomic_write_private

            def replace_then_fail(*args, **kwargs):
                write(*args, **kwargs)
                raise OSError("simulated directory fsync failure after replace")

            with patch.object(module, "atomic_write_private", replace_then_fail):
                with self.assertRaises(TrafficBudgetError):
                    budget.reserve("host", BOOT_A, "send", "data", 20)
            self.assertTrue(budget.status()["faulted"])
            restarted = self._open_budget(path)
            self.assertEqual(restarted.status()["global"]["charged"]["data"], 20)
            self.assertEqual(restarted.status()["outstanding"], 1)

    def test_settlement_commit_failures_restart_conservatively_without_replay(self):
        import steamboat_connector.traffic_budget as module

        for after_replace in (False, True):
            with self.subTest(after_replace=after_replace), tempfile.TemporaryDirectory() as temporary:
                os.chmod(temporary, 0o700)
                path = str(Path(temporary) / "traffic.json")
                budget = self._open_budget(path)
                budget.bind_role("host", BOOT_A)
                allowance = budget.reserve("host", BOOT_A, "send", "data", 20)
                write = module.atomic_write_private

                def fail_commit(*args, **kwargs):
                    if after_replace:
                        write(*args, **kwargs)
                    raise OSError("simulated uncertain settlement commit")

                with patch.object(module, "atomic_write_private", fail_commit):
                    with self.assertRaises(TrafficBudgetError):
                        allowance.settle(5, outcome_known=True)
                self.assertTrue(budget.status()["faulted"])
                restarted = self._open_budget(path)
                status = restarted.status()
                self.assertGreaterEqual(status["global"]["charged"]["data"], 5)
                if after_replace:
                    self.assertEqual(status["global"]["charged"]["data"], 5)
                    self.assertEqual(status["outstanding"], 0)
                else:
                    self.assertEqual(status["global"]["charged"]["data"], 20)
                    self.assertEqual(status["outstanding"], 1)
                with self.assertRaises(TrafficBudgetError):
                    allowance.settle(5, outcome_known=True)

    def test_lock_close_error_retains_faulted_owner_and_is_not_retried(self):
        from steamboat_connector.storage import FileLock

        with tempfile.TemporaryDirectory() as temporary:
            os.chmod(temporary, 0o700)
            budget = self._open_budget(str(Path(temporary) / "traffic.json"))
            release = FileLock.release
            calls = []

            def close_then_fail(lock):
                calls.append(lock)
                release(lock)
                raise OSError("simulated close result uncertainty")

            with patch.object(FileLock, "release", close_then_fail):
                with self.assertRaises(TrafficBudgetError) as caught:
                    budget.bind_role("host", BOOT_A)
                self.assertIs(caught.exception.retained_owner, budget)
                self.assertIs(budget._retained_lock, calls[0])
                self.assertIsNone(calls[0].descriptor)
                with self.assertRaises(TrafficBudgetError):
                    budget.bind_role("host", BOOT_A)
            self.assertEqual(len(calls), 1)


class TrafficBudgetTests(unittest.TestCase):
    def test_import_is_torch_free(self):
        environment = dict(os.environ)
        environment["PYTHONPATH"] = os.pathsep.join(
            ("src", environment.get("PYTHONPATH", "")))
        result = subprocess.run(
            [sys.executable, "-B", "-c",
             "import sys; import steamboat_connector.traffic_budget; "
             "assert not any(n == 'torch' or n.startswith('torch.') for n in sys.modules)"],
            capture_output=True, text=True, timeout=10, check=False, env=environment)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_global_and_role_directional_cumulative_and_rate_limits(self):
        budget, _, clock = _memory_budget(
            policy=_policy(global_total=900, role_total=300, send_rate=900,
                           role_send_rate=300))
        budget.bind_role("host", BOOT_A)
        first = budget.reserve("host", BOOT_A, "send", "data", 300)
        with self.assertRaises(TrafficBudgetDenied):
            budget.reserve("host", BOOT_A, "receive", "data", 1)
        first.assert_live()
        settled = first.settle(100, outcome_known=True)
        self.assertEqual((settled["charged_bytes"], settled["refunded_bytes"]), (100, 200))
        again = first.settle(100, outcome_known=True)
        self.assertEqual(again, settled)
        with self.assertRaises(TrafficBudgetError):
            first.settle(99, outcome_known=True)
        reverse = budget.reserve("host", BOOT_A, "receive", "data", 200)
        self.assertEqual(reverse.settle(200, outcome_known=True)["charged_bytes"], 200)
        self.assertEqual(budget.status()["global"]["charged"]["data"], 300)

    def test_directional_rate_refills_only_from_monotonic_elapsed_time(self):
        budget, _, clock = _memory_budget(
            policy=_policy(global_total=900, role_total=300,
                           send_rate=300, role_send_rate=100))
        budget.bind_role("host", BOOT_A)
        first = budget.reserve("host", BOOT_A, "send", "data", 100)
        first.settle(100, outcome_known=True)
        with self.assertRaises(TrafficBudgetDenied):
            budget.reserve("host", BOOT_A, "send", "data", 1)
        reverse = budget.reserve("host", BOOT_A, "receive", "data", 100)
        reverse.settle(100, outcome_known=True)
        clock.advance(0.5)
        refilled = budget.reserve("host", BOOT_A, "send", "data", 50)
        refilled.settle(50, outcome_known=True)

    def test_cleanup_reservation_is_independent_of_data_exhaustion(self):
        budget, _, _ = _memory_budget(
            policy=_policy(global_total=900, role_total=300,
                           cleanup_total=90, cleanup_rate=90,
                           role_cleanup_rate=30))
        budget.bind_role("host", BOOT_A)
        data = budget.reserve("host", BOOT_A, "send", "data", 300)
        data.settle(300, outcome_known=True)
        with self.assertRaises(TrafficBudgetDenied):
            budget.reserve("host", BOOT_A, "send", "data", 1)
        cleanup = budget.reserve("host", BOOT_A, "send", "cleanup", 30)
        cleanup.settle(30, outcome_known=True)

    def test_unknown_or_late_io_keeps_full_charge_and_requires_reconcile(self):
        budget, _, clock = _memory_budget()
        budget.bind_role("host", BOOT_A)
        unknown = budget.reserve("host", BOOT_A, "send", "data", 80)
        result = unknown.settle(35, outcome_known=False)
        self.assertEqual((result["charged_bytes"], result["uncertain"]), (80, True))
        self.assertEqual(budget.status()["global"]["observed"]["data"], 35)
        self.assertEqual(budget.status()["global"]["uncertain_bytes"]["data"], 80)
        with self.assertRaises(TrafficBudgetError):
            budget.bind_role("host", BOOT_B)
        with self.assertRaises(TrafficBudgetError):
            budget.reconcile_dead_generation("host", BOOT_A,
                                             reaped=True, cgroup_empty=False)
        budget.reconcile_dead_generation("host", BOOT_A,
                                         reaped=True, cgroup_empty=True)
        self.assertEqual(budget.status()["global"]["charged"]["data"], 80)
        budget.bind_role("host", BOOT_B)
        self.assertEqual(budget.reserve("host", BOOT_B, "send", "data", 100)
                         .settle(100, outcome_known=True)["charged_bytes"], 100)

    def test_late_settlement_records_actual_but_does_not_refund(self):
        budget, _, clock = _memory_budget()
        budget.bind_role("host", BOOT_A)
        allowance = budget.reserve("host", BOOT_A, "send", "data", 50)
        clock.advance((ALLOWANCE_LIFETIME_NS / 1_000_000_000) + 0.01)
        with self.assertRaises(TrafficBudgetError):
            allowance.assert_live()
        settled = allowance.settle(20, outcome_known=True)
        self.assertEqual(settled["charged_bytes"], 50)
        self.assertEqual(settled["actual_bytes"], 20)
        self.assertEqual(settled["refunded_bytes"], 0)

    def test_unsettled_slots_persist_and_require_generation_reconciliation(self):
        budget, store, clock = _memory_budget()
        budget.bind_role("consumer", BOOT_A)
        tokens = [budget.reserve("consumer", BOOT_A, "send", "data", 1)
                  for _ in range(16)]
        with self.assertRaises(TrafficBudgetDenied):
            budget.reserve("consumer", BOOT_A, "send", "data", 1)
        restarted, _, _ = _memory_budget(store=store, clock=clock)
        self.assertEqual(restarted.status()["outstanding"], 16)
        with self.assertRaises(TrafficBudgetError):
            restarted.bind_role("consumer", BOOT_B)
        restarted.reconcile_dead_generation("consumer", BOOT_A,
                                            reaped=True, cgroup_empty=True)
        self.assertEqual(restarted.status()["global"]["charged"]["data"], 16)
        for allowance in tokens:
            with self.assertRaises(TrafficBudgetError):
                allowance.assert_live()

    def test_policy_refresh_does_not_reset_cumulative_charges_or_replenish(self):
        budget, store, clock = _memory_budget()
        budget.bind_role("host", BOOT_A)
        allowance = budget.reserve("host", BOOT_A, "send", "data", 50)
        allowance.settle(50, outcome_known=True)
        expanded = _policy(global_total=6000, role_total=2000,
                           send_rate=9000, role_send_rate=3000)
        reopened, _, _ = _memory_budget(store=store, policy=expanded, clock=clock)
        self.assertTrue(reopened.status()["policy_refresh_required"])
        with self.assertRaises(TrafficBudgetError):
            reopened.reserve("host", BOOT_A, "send", "data", 1)
        reopened.refresh_policy(expanded)
        self.assertEqual(reopened.status()["global"]["charged"]["data"], 50)
        with self.assertRaises(TrafficBudgetDenied):
            reopened.reserve("host", BOOT_A, "send", "data", 1001)
        self.assertEqual(reopened.reserve("host", BOOT_A, "send", "data", 250)
                         .settle(250, outcome_known=True)["charged_bytes"], 250)
        tightened = _policy(global_total=210, role_total=70,
                            send_rate=3000, role_send_rate=1000)
        with self.assertRaises(TrafficBudgetError):
            reopened.refresh_policy(tightened)
        self.assertFalse(reopened.status()["faulted"])
        self.assertFalse(reopened.status()["policy_refresh_required"])

    def test_forged_identity_and_reused_settlement_are_rejected(self):
        budget, _, _ = _memory_budget()
        budget.bind_role("host", BOOT_A)
        allowance = budget.reserve("host", BOOT_A, "send", "data", 5)
        with self.assertRaises(TypeError):
            TrafficAllowance(budget, allowance._reservation_id)
        with self.assertRaises(AttributeError):
            allowance._reservation_id = "0" * 32
        forged = object.__new__(TrafficAllowance)
        object.__setattr__(forged, "_owner", budget)
        object.__setattr__(forged, "_reservation_id", allowance._reservation_id)
        object.__setattr__(forged, "_settlement", None)
        object.__setattr__(forged, "_retired", False)
        with self.assertRaises(TrafficBudgetError):
            forged.assert_live()

    def test_concurrent_memory_roles_do_not_overspend_shared_budget(self):
        policy = _policy(global_total=300, role_total=100)
        store = MemoryTrafficStore()
        clock = TestClock()
        host, _, _ = _memory_budget(store=store, policy=policy, clock=clock)
        host.bind_role("host", BOOT_A)
        coord, _, _ = _memory_budget(store=store, policy=policy, clock=clock)
        coord.bind_role("coordinator", BOOT_B)
        gate = threading.Barrier(4)
        outcomes = []
        lock = threading.Lock()

        def spend(owner, role, boot):
            gate.wait()
            try:
                token = owner.reserve(role, boot, "send", "data", 100)
                result = ("ok", token)
            except TrafficBudgetDenied:
                result = ("denied", None)
            with lock:
                outcomes.append(result)

        consumer, _, _ = _memory_budget(store=store, policy=policy, clock=clock)
        consumer.bind_role("consumer", "d" * 32)
        workers = [threading.Thread(target=spend, args=(host, "host", BOOT_A)),
                   threading.Thread(target=spend, args=(coord, "coordinator", BOOT_B)),
                   threading.Thread(target=spend, args=(consumer, "consumer", "d" * 32))]
        for worker in workers:
            worker.start()
        gate.wait()
        for worker in workers:
            worker.join(2)
            self.assertFalse(worker.is_alive())
        self.assertEqual(sorted(value for value, _ in outcomes), ["ok", "ok", "ok"])
        self.assertEqual(host.status()["global"]["charged"]["data"], 300)

    def test_commit_outcome_unknown_latches_owner_and_retains_uncertainty(self):
        class FailingCommitStore(MemoryTrafficStore):
            def __init__(self):
                super().__init__()
                self.fail = False

            def commit(self, state):
                if self.fail:
                    self.state = state
                    raise OSError("simulated ambiguous durable commit")
                super().commit(state)

        store = FailingCommitStore()
        budget, _, _ = _memory_budget(store=store)
        store.fail = True
        with self.assertRaises(TrafficBudgetError) as caught:
            budget.bind_role("host", BOOT_A)
        self.assertIs(caught.exception.retained_owner, budget)
        self.assertTrue(budget.status()["faulted"])
        with self.assertRaises(TrafficBudgetError):
            budget.bind_role("host", BOOT_A)

    def test_policy_reservations_must_fit_global_network_caps(self):
        policy = _policy(global_total=100, role_total=50)
        policy["reservations"]["host"]["total_network_bytes"] = 51
        with self.assertRaises(TrafficBudgetError):
            _memory_budget(policy=policy)


if __name__ == "__main__":
    unittest.main()
