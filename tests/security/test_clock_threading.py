"""Deterministic concurrency regressions for the shared authorization clock."""

from __future__ import annotations

import threading
import unittest

from steamboat_security.clock import Clock
from steamboat_security.errors import ClockError


_WAIT_SECONDS = 0.5


class ClockThreadingTests(unittest.TestCase):
    def test_sample_serializes_provider_reads_with_state_commit(self):
        first_wall_entered = threading.Event()
        release_first_wall = threading.Event()
        second_attempting = threading.Event()
        second_wall_entered = threading.Event()
        wall_guard = threading.Lock()
        wall_reads = 0
        mono_guard = threading.Lock()
        mono_reads = 0

        def wall() -> float:
            nonlocal wall_reads
            with wall_guard:
                read = wall_reads
                wall_reads += 1
            if read == 0:
                first_wall_entered.set()
                if not release_first_wall.wait(_WAIT_SECONDS * 4):
                    raise RuntimeError("first wall read was not released")
                return 1000.0
            if read == 1:
                second_wall_entered.set()
                return 1001.0
            raise AssertionError("unexpected wall provider read")

        def monotonic() -> float:
            nonlocal mono_reads
            with mono_guard:
                read = mono_reads
                mono_reads += 1
            return 100.0 + read

        clock = Clock(wall=wall, monotonic=monotonic,
                      uncertainty_seconds=lambda: 0.0)
        results: dict[str, object] = {}

        def sample(name: str, *, attempted: threading.Event | None = None) -> None:
            if attempted is not None:
                attempted.set()
            try:
                results[name] = clock.sample()
            except Exception as error:  # preserve worker-thread failures for assertions
                results[name] = error

        first = threading.Thread(target=sample, args=("first",), daemon=True)
        second = threading.Thread(
            target=sample, args=("second",), kwargs={"attempted": second_attempting},
            daemon=True)
        first.start()
        try:
            self.assertTrue(first_wall_entered.wait(_WAIT_SECONDS))
            second.start()
            self.assertTrue(second_attempting.wait(_WAIT_SECONDS))
            # With an unlocked provider/state sequence, the second wall read
            # completes while the first read is paused and makes the first
            # sample look like a rollback. A short bounded wait proves the
            # provider is held behind the first transaction.
            self.assertFalse(second_wall_entered.wait(_WAIT_SECONDS))
        finally:
            release_first_wall.set()
            first.join(_WAIT_SECONDS * 4)
            if second.ident is not None:
                second.join(_WAIT_SECONDS * 4)

        self.assertFalse(first.is_alive())
        self.assertFalse(second.is_alive())
        self.assertNotIsInstance(results.get("first"), Exception)
        self.assertNotIsInstance(results.get("second"), Exception)
        self.assertEqual(results["first"].wall, 1000.0)
        self.assertEqual(results["second"].wall, 1001.0)
        self.assertEqual(results["second"].monotonic, 101.0)

    def test_revalidation_cannot_overwrite_a_concurrent_sample_fault(self):
        revalidation_wall_entered = threading.Event()
        release_revalidation_wall = threading.Event()
        sample_attempting = threading.Event()
        sample_wall_entered = threading.Event()
        wall_guard = threading.Lock()
        wall_reads = 0
        mono_guard = threading.Lock()
        mono_reads = 0
        token_guard = threading.Lock()
        current_token = ["boot-0"]

        def wall() -> float:
            nonlocal wall_reads
            with wall_guard:
                read = wall_reads
                wall_reads += 1
            if read == 0:
                return 1000.0
            if read == 1:
                revalidation_wall_entered.set()
                if not release_revalidation_wall.wait(_WAIT_SECONDS * 4):
                    raise RuntimeError("revalidation wall read was not released")
                return 1002.0
            if read == 2:
                sample_wall_entered.set()
                return 1001.0
            raise AssertionError("unexpected wall provider read")

        def monotonic() -> float:
            nonlocal mono_reads
            with mono_guard:
                read = mono_reads
                mono_reads += 1
            return 200.0 + read

        def resume_token() -> str:
            with token_guard:
                return current_token[0]

        clock = Clock(wall=wall, monotonic=monotonic,
                      uncertainty_seconds=lambda: 0.0,
                      resume_token=resume_token)
        clock.sample()
        with token_guard:
            current_token[0] = "boot-1"
        results: dict[str, object] = {}

        def revalidate() -> None:
            try:
                results["revalidation"] = clock.revalidate_after_resume(
                    trusted_clock=True)
            except Exception as error:
                results["revalidation"] = error

        def sample() -> None:
            sample_attempting.set()
            try:
                results["sample"] = clock.sample()
            except Exception as error:
                results["sample"] = error

        revalidator = threading.Thread(target=revalidate, daemon=True)
        sampler = threading.Thread(target=sample, daemon=True)
        revalidator.start()
        try:
            self.assertTrue(revalidation_wall_entered.wait(_WAIT_SECONDS))
            sampler.start()
            self.assertTrue(sample_attempting.wait(_WAIT_SECONDS))
            # The revalidation has already sampled wall=1002. If a concurrent
            # sample can commit wall=1001 against the old baseline first, it
            # reports a changed resume token and the revalidation could erase
            # that fault. Serialized operation instead revalidates first; the
            # later wall rollback is then detected and remains latched.
            self.assertFalse(sample_wall_entered.wait(_WAIT_SECONDS))
        finally:
            release_revalidation_wall.set()
            revalidator.join(_WAIT_SECONDS * 4)
            if sampler.ident is not None:
                sampler.join(_WAIT_SECONDS * 4)

        self.assertFalse(revalidator.is_alive())
        self.assertFalse(sampler.is_alive())
        self.assertNotIsInstance(results.get("revalidation"), Exception)
        self.assertIsInstance(results.get("sample"), ClockError)
        with self.assertRaises(ClockError):
            clock.sample()

    def test_genuine_wall_rollback_and_monotonic_restart_latch_survive(self):
        wall_values = iter((1000.0, 999.0, 1001.0, 1002.0))
        monotonic_values = iter((10.0, 11.0, 12.0, 13.0))
        wall_clock = Clock(wall=lambda: next(wall_values),
                           monotonic=lambda: next(monotonic_values),
                           uncertainty_seconds=lambda: 0.0)
        wall_clock.sample()
        with self.assertRaises(ClockError):
            wall_clock.sample()
        with self.assertRaises(ClockError):
            wall_clock.sample()
        wall_clock.revalidate_after_resume(trusted_clock=True)
        wall_clock.sample()

        wall_values = iter((2000.0, 2001.0, 2002.0))
        monotonic_values = iter((20.0, 19.0, 21.0))
        monotonic_clock = Clock(wall=lambda: next(wall_values),
                                monotonic=lambda: next(monotonic_values),
                                uncertainty_seconds=lambda: 0.0)
        monotonic_clock.sample()
        with self.assertRaises(ClockError):
            monotonic_clock.sample()
        with self.assertRaises(ClockError):
            monotonic_clock.revalidate_after_resume(trusted_clock=True)
        with self.assertRaises(ClockError):
            monotonic_clock.sample()


if __name__ == "__main__":
    unittest.main()
