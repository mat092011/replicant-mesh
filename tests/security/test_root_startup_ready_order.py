"""Synthetic regression coverage for five-role root READY dispatch ordering.

RootCutoverFixture supplies authentic protected declarations and signed role
material. Process spawn and READY observation are synthetic; these tests never
launch a child process or load a model.
"""
from __future__ import annotations

import asyncio
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

import steamboat_security.root_transition_startup as startup_module
from steamboat_security.root_transition_activation import activate_root_transition
from steamboat_security.root_transition_launch_claim import LaunchClaimStore
from steamboat_security.root_transition_retirement import (
    ObservedLaunch, PendingOwnedLaunch, RetirementSupervisor,
)
from steamboat_security.root_transition_startup import RootCohortStartup
from steamboat_security.root_transition_storage import RootGenerationStore
from tests.security.root_cutover_fixture import RootCutoverFixture


_ARTIFACTS = os.environ.get("STEAMBOAT_ARTIFACT_DIR")
_REFERENCE = os.environ.get("STEAMBOAT_REFERENCE_DIR")
_ROOT_CUTOVER_OPTED_IN = (
    os.name == "posix" and sys.platform == "linux" and Path("/proc").is_dir()
    and os.environ.get("STEAMBOAT_SECURE_PIPELINE_TESTS") == "1"
    and bool(_ARTIFACTS) and Path(_ARTIFACTS).is_dir()
    and bool(_REFERENCE) and Path(_REFERENCE).is_dir()
)


class _ExitedSyntheticProcess:
    """An already-exited stand-in used only for owner-cleanup inspection."""

    stdin = None
    stdout = None

    @staticmethod
    def poll():
        return 0


@unittest.skipUnless(
    _ROOT_CUTOVER_OPTED_IN,
    "requires the existing native five-role root-cutover fixture opt-in",
)
class RootStartupReadyDispatchTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="root-ready-order-")
        self.addCleanup(self.temp.cleanup)
        self.fixture = RootCutoverFixture(
            Path(self.temp.name) / "fixture", Path(_ARTIFACTS), Path(_REFERENCE))
        # Register fixture cleanup before validation assertions or any setup
        # step that can fail.
        self.addCleanup(self.fixture.close)

        self.store = RootGenerationStore(self.fixture.new_root, expected_uid=os.geteuid())
        self.addCleanup(self.store.close)
        self.retirement = RetirementSupervisor()
        old_selected = self.store.read_selected(validate=lambda *_: None)
        # The fixture's candidate is fully signed and protected. The startup
        # tests isolate READY dispatch, so only the prior cohort-retirement
        # capability check is satisfied synthetically during fixture activation.
        with mock.patch.object(self.retirement, "validate_retirement_capability",
                               return_value=True):
            activate_root_transition(
                root_store=self.store,
                expected_old_selector_sha256=old_selected.selector_sha256,
                preparation_path=self.fixture.preparation_path,
                preparation_root=self.fixture.preparation,
                approval_path=self.fixture.approval_path,
                approval_root=self.fixture.approval_root,
                expected_uid=os.geteuid(), clock=self.fixture.clock,
                candidate=self.fixture.candidate,
                new_ca_certificate_pem=self.fixture.new_ca,
                new_snapshot_public_key_pem=self.fixture.new_snapshot_public,
                new_csr_by_identity=self.fixture.new_csrs,
                principal_inputs=self.fixture.final_inputs,
                retirement_supervisor=self.retirement,
                retirement_capability=object(),
            )
        self.claims = LaunchClaimStore(self.fixture.claim_root, expected_uid=os.geteuid())
        self.addCleanup(self.claims.close)
        self.launches = self.fixture.launch_inputs("new")
        self.groups = RootCohortStartup._group_launches(self.launches)

        self.role_identities = {
            name: (principal.account_id, principal.device_id, principal.role)
            for name, principal in self.fixture.role_by_name.items()
        }
        self.worker_names = ("worker-1", "worker-2", "worker-3")
        self.worker_keys = {self.role_identities[name] for name in self.worker_names}
        self.coordinator_key = self.role_identities["coordinator"]
        self.consumer_key = self.role_identities["consumer"]
        self.group_by_role = {
            group.specs[0].identity: group for group in self.groups
        }
        self.assertEqual(len(self.groups), 5)
        self.assertEqual(set(self.group_by_role),
                         self.worker_keys | {self.coordinator_key, self.consumer_key})
        self.spawned = []
        self.absent_checks = []
        self._install_synthetic_process_ownership()

    def _install_synthetic_process_ownership(self):
        supervisor = self.retirement

        def key_for_specs(specs):
            spec = specs[0]
            return (spec.account_id, spec.device_id, spec.role)

        def fake_spawn(manifest_path, *, protected_root, expected_uid, specs,
                       expected_manifest, before_popen_check):
            key = key_for_specs(specs)
            record = SimpleNamespace(
                process=_ExitedSyntheticProcess(), specs=tuple(specs),
                pgid=len(self.spawned) + 1, manifest=expected_manifest,
                ready=None, pending=None,
            )
            pending = PendingOwnedLaunch(supervisor, record, supervisor._seal)
            record.pending = pending
            supervisor._owned.append(record)
            self.spawned.append(key)
            return pending

        def validate_observed(capability):
            return (type(capability) is ObservedLaunch
                    and capability._supervisor is supervisor)

        def group_absent(pgid):
            self.absent_checks.append(pgid)
            return True

        self._patches = [
            mock.patch.object(supervisor, "spawn_owned_process", fake_spawn),
            mock.patch.object(supervisor, "validate_observed_launch", validate_observed),
            mock.patch.object(supervisor, "_group_absent", group_absent),
        ]
        for patcher in self._patches:
            patcher.start()
            self.addCleanup(patcher.stop)

    def _startup(self):
        return RootCohortStartup(
            root_store=self.store, claim_store=self.claims,
            retirement_supervisor=self.retirement, clock=self.fixture.clock,
            expected_uid=os.geteuid())

    @staticmethod
    def _pending_key(pending):
        spec = pending._record.specs[0]
        return (spec.account_id, spec.device_id, spec.role)

    def _observed(self, pending):
        return ObservedLaunch(self.retirement, pending._record, self.retirement._seal)

    def _assert_all_five_spawned_before_observe(self):
        self.assertEqual(set(self.spawned), set(self.group_by_role))

    def _assert_cleanup_inspected_all_five(self):
        self.assertEqual(set(self.spawned), set(self.group_by_role))
        self.assertEqual(set(self.absent_checks), set(range(1, 6)),
                         "cleanup must inspect even owners with no READY dispatch")

    async def test_worker_ready_precedes_coordinator_and_results_follow_pending_order(self):
        # The signed launch declarations stay untouched. Reorder only the
        # already-authentic group objects in this synthetic orchestration case
        # so the pending sequence puts the coordinator before the workers,
        # while actual READY dispatch must put workers before the coordinator.
        ordered_groups = (
            self.group_by_role[self.coordinator_key],
            self.group_by_role[self.consumer_key],
            *(self.group_by_role[key] for key in sorted(self.worker_keys)),
        )
        pending_order = [group.specs[0].identity for group in ordered_groups]
        dispatch_order = []
        completion_order = []
        ready_workers = set()

        async def observe(pending, *, ready_timeout_seconds):
            self._assert_all_five_spawned_before_observe()
            key = self._pending_key(pending)
            dispatch_order.append(key)
            if key == self.coordinator_key:
                self.assertEqual(ready_workers, self.worker_keys,
                                 "coordinator must not be dispatched before all workers are ready")
            elif key in self.worker_keys:
                await asyncio.sleep(0)
                ready_workers.add(key)
            completion_order.append(key)
            return self._observed(pending)

        startup = self._startup()
        with mock.patch.object(RootCohortStartup, "_group_launches",
                               return_value=ordered_groups), \
                mock.patch.object(self.retirement, "observe_ready", observe):
            capability = await startup.start(self.launches, startup_timeout_seconds=60)

        self.assertIn(self.coordinator_key, dispatch_order)
        self.assertEqual(ready_workers, self.worker_keys)
        self.assertNotEqual(completion_order, pending_order,
                            "the synthetic READY completion order must differ from pending order")
        self.assertNotEqual(dispatch_order, pending_order,
                            "worker-first dispatch must differ from frozen pending order")
        self.assertEqual(set(dispatch_order), set(pending_order))
        self.assertGreater(dispatch_order.index(self.coordinator_key),
                           max(dispatch_order.index(key) for key in self.worker_keys),
                           "all worker observations must be dispatched before the coordinator")
        self.assertEqual([item._record.specs[0].identity for item in capability._record[3]],
                         pending_order,
                         "observations must map back to original pending order")
        self.assertEqual(len(self.retirement._owned), 5)

    async def test_worker_error_is_preserved_after_blocked_observation_finishes_and_all_owners_are_inspected(self):
        marker = RuntimeError("synthetic worker READY failure")
        entered = asyncio.Event()
        release_error = asyncio.Event()
        worker_finished = asyncio.Event()
        coordinator_entered = asyncio.Event()
        dispatch_order = []
        first_worker = next(iter(self.worker_keys))

        async def observe(pending, *, ready_timeout_seconds):
            self._assert_all_five_spawned_before_observe()
            key = self._pending_key(pending)
            dispatch_order.append(key)
            if key == self.coordinator_key:
                coordinator_entered.set()
                await asyncio.Future()
            if key == first_worker:
                entered.set()
                await release_error.wait()
                worker_finished.set()
                raise marker
            return self._observed(pending)

        startup = self._startup()
        with mock.patch.object(self.retirement, "observe_ready", observe):
            task = asyncio.create_task(startup.start(
                self.launches, startup_timeout_seconds=60, cleanup_timeout_seconds=5))
            caught = None
            try:
                await asyncio.wait_for(entered.wait(), timeout=5)
                release_error.set()
                with self.assertRaises(RuntimeError) as raised:
                    await asyncio.wait_for(task, timeout=5)
                caught = raised
            finally:
                if not task.done():
                    task.cancel()
                await asyncio.gather(task, return_exceptions=True)

        self.assertIsNotNone(caught)
        self.assertIs(caught.exception, marker)
        self.assertTrue(worker_finished.is_set(),
                        "the blocked failure observation must finish before startup returns")
        self.assertFalse(coordinator_entered.is_set())
        self.assertNotIn(self.coordinator_key, dispatch_order)
        self._assert_cleanup_inspected_all_five()
        self.assertEqual(startup._started, [])

    async def test_cancellation_finishes_worker_observation_before_cleaning_all_owners(self):
        entered = asyncio.Event()
        worker_cancelled = asyncio.Event()
        coordinator_entered = asyncio.Event()
        first_worker = next(iter(self.worker_keys))

        async def observe(pending, *, ready_timeout_seconds):
            self._assert_all_five_spawned_before_observe()
            key = self._pending_key(pending)
            if key == self.coordinator_key:
                coordinator_entered.set()
                await asyncio.Future()
            if key == first_worker:
                entered.set()
                try:
                    await asyncio.Future()
                except asyncio.CancelledError:
                    worker_cancelled.set()
                    raise
            return self._observed(pending)

        startup = self._startup()
        with mock.patch.object(self.retirement, "observe_ready", observe):
            task = asyncio.create_task(startup.start(
                self.launches, startup_timeout_seconds=60, cleanup_timeout_seconds=5))
            cancellation_observed = False
            try:
                await asyncio.wait_for(entered.wait(), timeout=5)
                task.cancel()
                with self.assertRaises(asyncio.CancelledError):
                    await asyncio.wait_for(task, timeout=5)
                cancellation_observed = True
            finally:
                if not task.done():
                    task.cancel()
                await asyncio.gather(task, return_exceptions=True)

        self.assertTrue(cancellation_observed)
        self.assertTrue(worker_cancelled.is_set(),
                        "startup must await cancellation of the blocked READY observer")
        self.assertFalse(coordinator_entered.is_set())
        self._assert_cleanup_inspected_all_five()
        self.assertEqual(startup._started, [])

    async def test_consumer_error_cancels_blocked_host_without_dispatching_coordinator(self):
        marker = RuntimeError("synthetic consumer READY failure")
        host_key = sorted(self.worker_keys)[0]
        ordered_groups = (
            self.group_by_role[host_key],
            self.group_by_role[self.consumer_key],
            self.group_by_role[self.coordinator_key],
            *(self.group_by_role[key] for key in sorted(self.worker_keys - {host_key})),
        )
        host_entered = asyncio.Event()
        host_cancelled = asyncio.Event()
        consumer_failed = asyncio.Event()
        dispatch_order = []

        async def observe(pending, *, ready_timeout_seconds):
            self._assert_all_five_spawned_before_observe()
            key = self._pending_key(pending)
            dispatch_order.append(key)
            if key == host_key:
                host_entered.set()
                try:
                    await asyncio.Future()
                except asyncio.CancelledError:
                    host_cancelled.set()
                    raise
            if key == self.consumer_key:
                await host_entered.wait()
                consumer_failed.set()
                raise marker
            if key == self.coordinator_key:
                await asyncio.Future()
            return self._observed(pending)

        startup = self._startup()
        with mock.patch.object(RootCohortStartup, "_group_launches",
                               return_value=ordered_groups), \
                mock.patch.object(self.retirement, "observe_ready", observe):
            task = asyncio.create_task(startup.start(
                self.launches, startup_timeout_seconds=60, cleanup_timeout_seconds=5))
            caught = None
            try:
                with self.assertRaises(RuntimeError) as raised:
                    await asyncio.wait_for(task, timeout=5)
                caught = raised
            finally:
                if not task.done():
                    task.cancel()
                await asyncio.gather(task, return_exceptions=True)

        self.assertIsNotNone(caught)
        self.assertIs(caught.exception, marker)
        self.assertTrue(consumer_failed.is_set())
        self.assertTrue(host_cancelled.is_set(),
                        "startup must await cancellation of the blocked host observer")
        self.assertNotIn(self.coordinator_key, dispatch_order,
                         "consumer failure must prevent coordinator READY dispatch")
        self._assert_cleanup_inspected_all_five()
        self.assertEqual(startup._started, [])

    async def test_shared_deadline_expires_before_coordinator_can_get_a_fresh_budget(self):
        real_monotonic = startup_module._startup_monotonic
        fake_elapsed = [0.0]
        workers_finished = set()
        coordinator_dispatched = []
        worker_keys = self.worker_keys

        def controlled_monotonic():
            return real_monotonic() + fake_elapsed[0]

        async def observe(pending, *, ready_timeout_seconds):
            self._assert_all_five_spawned_before_observe()
            key = self._pending_key(pending)
            if key == self.coordinator_key:
                coordinator_dispatched.append(key)
                raise AssertionError("expired startup must not grant a fresh coordinator READY budget")
            if key in worker_keys:
                await asyncio.sleep(0)
                workers_finished.add(key)
                fake_elapsed[0] += 4.0
            return self._observed(pending)

        startup = self._startup()
        with mock.patch.object(startup_module, "_startup_monotonic", controlled_monotonic), \
                mock.patch.object(self.retirement, "observe_ready", observe):
            with self.assertRaises(TimeoutError):
                await startup.start(self.launches, startup_timeout_seconds=10,
                                    cleanup_timeout_seconds=5)

        self.assertEqual(workers_finished, worker_keys)
        self.assertEqual(coordinator_dispatched, [])
        self._assert_cleanup_inspected_all_five()
        self.assertEqual(startup._started, [])


if __name__ == "__main__":
    unittest.main()
