"""Durability-hook ordering and fail-closed tests with real signed snapshots."""
from __future__ import annotations

from copy import deepcopy
import threading
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from steamboat_security.clock import Clock
import tests.security.test_root_transition_issuance as snapshot_fixture
from steamboat_security.errors import SnapshotError
from steamboat_security.snapshot import SnapshotStore, sign_snapshot


class SnapshotDurableCommitTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        snapshot_fixture.RootTransitionIssuanceTests.setUpClass()

    def setUp(self):
        self.fx = object.__new__(snapshot_fixture.RootTransitionIssuanceTests)
        self.fx.setUp()
        self.payload = deepcopy(self.fx.payload)
        self.store = None

    def tearDown(self):
        self.fx.tearDown()

    def snapshot(self, revision=4, *, issued_at=None, expires_at=None, payload=None):
        value = deepcopy(self.payload if payload is None else payload)
        value["revision"] = revision
        value["issued_at"] = snapshot_fixture.NOW - 10 if issued_at is None else issued_at
        value["expires_at"] = snapshot_fixture.NOW + 200 if expires_at is None else expires_at
        return sign_snapshot(value, self.fx.old_snapshot_key)

    def make_store(self, hook=None):
        self.store = SnapshotStore(
            verification_key_pem=self.fx.old_snapshot_public,
            ca_certificate_pem=self.fx.old_ca, clock=self.fx.clock_source.clock,
            durable_commit=hook)
        return self.store

    def test_durable_hook_precedes_publication_and_callback(self):
        events = []
        store = self.make_store(lambda encoded, revision, digest:
                                events.append(("commit", store._view, revision, digest))
                                and None)
        store.subscribe(lambda view: events.append(("callback", view.revision)))
        encoded = self.snapshot()
        store.install(encoded)
        self.assertEqual(events[0][0:3], ("commit", None, 4))
        self.assertEqual(events[1], ("callback", 4))
        self.assertEqual(store._encoded, encoded)

    def test_hook_exception_non_none_and_awaitable_latch_without_publication(self):
        async def awaitable_hook(_encoded, _revision, _digest):
            return None

        hooks = (
            lambda *_args: (_ for _ in ()).throw(OSError("uncertain commit")),
            lambda *_args: False,
            awaitable_hook,
        )
        for hook in hooks:
            with self.subTest(hook=hook):
                store = self.make_store(hook)
                with self.assertRaises(SnapshotError):
                    store.install(self.snapshot())
                self.assertIsNone(store._view)
                with self.assertRaises(SnapshotError):
                    store.current()
                with self.assertRaises(SnapshotError):
                    store.install(self.snapshot())
                self.assertIsNone(store._view)

    def test_hook_advancing_clock_past_expiry_prevents_publication(self):
        def hook(_encoded, _revision, _digest):
            self.fx.clock_source.advance(210)

        store = self.make_store(hook)
        with self.assertRaises(SnapshotError):
            store.install(self.snapshot(expires_at=snapshot_fixture.NOW + 100))
        self.assertIsNone(store._view)
        with self.assertRaises(SnapshotError):
            store.current()

    def test_hook_reentrant_install_is_rejected_and_latches(self):
        store = None
        def hook(_encoded, _revision, _digest):
            store.install(self.snapshot(revision=5))
        store = self.make_store(hook)
        with self.assertRaises(SnapshotError):
            store.install(self.snapshot())
        self.assertIsNone(store._view)
        with self.assertRaises(SnapshotError):
            store.current()

    def test_current_during_hook_is_rejected_without_serving_old_snapshot(self):
        store = None
        def hook(_encoded, revision, _digest):
            if revision == 5:
                store.current()
        store = self.make_store(hook)
        store.install(self.snapshot(revision=4))
        healthy_old_view = store._view
        with self.assertRaises(SnapshotError):
            store.install(self.snapshot(revision=5))
        self.assertIs(store._view, healthy_old_view)
        with self.assertRaises(SnapshotError):
            store.current()

    def test_equal_policy_post_hook_expiry_latches_future_installs(self):
        calls = []
        def hook(_encoded, _revision, _digest):
            calls.append(1)
            if len(calls) == 2:
                self.fx.clock_source.advance(205)
        store = self.make_store(hook)
        encoded = self.snapshot(expires_at=snapshot_fixture.NOW + 100)
        store.install(encoded)
        with self.assertRaises(SnapshotError):
            store.install(self.snapshot(expires_at=snapshot_fixture.NOW + 100))
        with self.assertRaises(SnapshotError):
            store.install(self.snapshot(revision=5))

    def test_post_hook_uncertainty_widening_blocks_new_and_equal_policy(self):
        def configured_store(*, widen_on_call):
            source = snapshot_fixture.MutableClock(wall=snapshot_fixture.NOW + 2)
            uncertainty = [0.0]
            clock = Clock(wall=source._wall, monotonic=source._mono,
                          uncertainty_seconds=lambda: uncertainty[0])
            count = [0]
            def hook(_encoded, _revision, _digest):
                count[0] += 1
                if count[0] == widen_on_call:
                    uncertainty[0] = 5.0
            store = SnapshotStore(verification_key_pem=self.fx.old_snapshot_public,
                ca_certificate_pem=self.fx.old_ca, clock=clock, durable_commit=hook)
            return store, clock, source, count

        # Newly installed policy becomes future-dated when post-fsync uncertainty widens.
        fresh, _clock, _source, _count = configured_store(widen_on_call=1)
        with self.assertRaises(SnapshotError):
            fresh.install(self.snapshot(issued_at=snapshot_fixture.NOW + 1,
                                        expires_at=snapshot_fixture.NOW + 100))
        with self.assertRaises(SnapshotError):
            fresh.install(self.snapshot(revision=5))

        # Equal-revision reconciliation must apply the same post-hook time test.
        equal, _clock, _source, count = configured_store(widen_on_call=2)
        value = self.snapshot(issued_at=snapshot_fixture.NOW + 1,
                              expires_at=snapshot_fixture.NOW + 100)
        equal.install(value)
        with self.assertRaises(SnapshotError):
            equal.install(self.snapshot(issued_at=snapshot_fixture.NOW + 1,
                                        expires_at=snapshot_fixture.NOW + 100))
        with self.assertRaises(SnapshotError):
            equal.install(self.snapshot(revision=5))

    def test_concurrent_current_waits_for_durable_install_and_rejects_presampled_read(self):
        entered, release, reader_done = threading.Event(), threading.Event(), threading.Event()
        store = self.make_store(lambda *_args: (entered.set(), release.wait(2), None)[2])
        before = self.fx.clock_source.clock.sample()
        install_results, read_results = [], []
        installer = threading.Thread(target=lambda: self._capture(
            install_results, lambda: store.install(self.snapshot())))
        installer.start()
        self.assertTrue(entered.wait(1))
        reader = threading.Thread(target=lambda: self._capture(
            read_results, lambda: (store.current(), reader_done.set())))
        reader.start()
        self.assertFalse(reader_done.wait(0.05))
        release.set()
        installer.join(2)
        reader.join(2)
        self.assertFalse(installer.is_alive())
        self.assertFalse(reader.is_alive())
        self.assertEqual(len(install_results), 1)
        self.assertFalse(isinstance(install_results[0], BaseException))
        self.assertEqual(len(read_results), 1)
        self.assertTrue(reader_done.is_set())
        with self.assertRaises(SnapshotError):
            store.current(sample=before)

    def test_concurrent_installers_publish_in_serial_revision_order(self):
        entered, release = threading.Event(), threading.Event()
        def hook(_encoded, revision, _digest):
            if revision == 4:
                entered.set()
                release.wait(2)
        store = self.make_store(hook)
        callbacks = []
        store.subscribe(lambda view: callbacks.append(view.revision))
        outcomes = []
        first = threading.Thread(target=lambda: self._capture(
            outcomes, lambda: store.install(self.snapshot(revision=4))))
        first.start()
        self.assertTrue(entered.wait(1))
        second = threading.Thread(target=lambda: self._capture(
            outcomes, lambda: store.install(self.snapshot(revision=5))))
        second.start()
        release.set()
        first.join(2)
        second.join(2)
        self.assertFalse(first.is_alive())
        self.assertFalse(second.is_alive())
        self.assertEqual(len(outcomes), 2)
        self.assertFalse(any(isinstance(value, BaseException) for value in outcomes))
        self.assertEqual(callbacks, [4, 5])
        self.assertEqual(store.current().revision, 5)

    def test_blocked_equal_revision_commit_advances_publication_sample(self):
        entered, release, read_done = threading.Event(), threading.Event(), threading.Event()
        calls = [0]
        def hook(_encoded, _revision, _digest):
            calls[0] += 1
            if calls[0] == 2:
                entered.set()
                release.wait(2)
        store = self.make_store(hook)
        first = self.snapshot()
        store.install(first)
        before_view = store.current()
        callbacks = []
        store.subscribe(lambda view: callbacks.append(view.revision))
        precommit_sample = self.fx.clock_source.clock.sample()
        install_outcomes = []
        equal_install = threading.Thread(target=lambda: self._capture(
            install_outcomes, lambda: store.install(self.snapshot())))
        equal_install.start()
        self.assertTrue(entered.wait(1))
        read_outcomes = []
        reader = threading.Thread(target=lambda: self._capture(
            read_outcomes, lambda: (store.current(sample=precommit_sample), read_done.set())))
        reader.start()
        self.assertFalse(read_done.wait(0.05))
        release.set()
        equal_install.join(2)
        reader.join(2)
        self.assertFalse(equal_install.is_alive())
        self.assertFalse(reader.is_alive())
        self.assertEqual(len(install_outcomes), 1)
        self.assertFalse(isinstance(install_outcomes[0], BaseException))
        self.assertEqual(len(read_outcomes), 1)
        self.assertIsInstance(read_outcomes[0], SnapshotError)
        self.assertFalse(read_done.is_set())
        self.assertEqual(store._encoded, first)
        after_view = store.current()
        self.assertEqual(after_view.canonical_payload, before_view.canonical_payload)
        self.assertLessEqual(after_view.deadline_monotonic, before_view.deadline_monotonic)
        self.assertEqual(callbacks, [])

    def test_randomized_resign_same_policy_is_idempotent_without_deadline_extension(self):
        commits, callbacks = [], []
        store = self.make_store(lambda encoded, revision, digest:
                                commits.append((encoded, revision, digest)))
        store.subscribe(lambda view: callbacks.append(view))
        original = self.snapshot()
        first = store.install(original)
        first_deadline = first.deadline_monotonic
        alternate_signature = self.snapshot()
        self.assertNotEqual(original, alternate_signature)
        second = store.install(alternate_signature)
        self.assertEqual(second.revision, first.revision)
        self.assertEqual(second.canonical_payload, first.canonical_payload)
        self.assertLessEqual(second.deadline_monotonic, first_deadline)
        self.assertEqual(len(callbacks), 1)
        self.assertEqual(len(commits), 2)
        self.assertEqual(store._encoded, original)

    def test_callback_failure_latches_and_durable_head_ahead_latches(self):
        store = self.make_store(lambda *_args: None)
        store.subscribe(lambda _view: (_ for _ in ()).throw(RuntimeError("callback")))
        with self.assertRaises(SnapshotError):
            store.install(self.snapshot())
        with self.assertRaises(SnapshotError):
            store.install(self.snapshot(revision=5))

        def ahead(_encoded, _revision, _digest):
            raise OSError("durable head is newer or unknown")
        another = SnapshotStore(verification_key_pem=self.fx.old_snapshot_public,
            ca_certificate_pem=self.fx.old_ca, clock=self.fx.clock_source.clock,
            durable_commit=ahead)
        with self.assertRaises(SnapshotError):
            another.install(self.snapshot())
        with self.assertRaises(SnapshotError):
            another.current()

    @staticmethod
    def _capture(results, call):
        try:
            results.append(call())
        except BaseException as error:
            results.append(error)


if __name__ == "__main__":
    unittest.main()
