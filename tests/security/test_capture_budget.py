from __future__ import annotations

import os
import subprocess
import sys
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from steamboat_runtime.capture_budget import (
    MAX_CAPTURE_MESSAGE_BYTES,
    ActiveCaptureLimitError,
    CaptureBudget,
    CaptureBudgetConfig,
    CaptureCapacityError,
    CaptureConfigurationError,
    DuplicateCaptureRequestIdError,
    InvalidCleanupConfirmationError,
    InvalidCaptureLeaseError,
    InvalidCaptureRequestIdError,
    RequestIdCapacityError,
    calculate_capture_reservation,
)


class CaptureBudgetTests(unittest.TestCase):
    def test_formula_and_eight_capture_pool_fit_are_exact(self) -> None:
        config = CaptureBudgetConfig()
        per_capture = calculate_capture_reservation(config)
        self.assertEqual(per_capture.event_limit_bytes, 1_028_096)
        self.assertLessEqual(per_capture.event_limit_bytes, MAX_CAPTURE_MESSAGE_BYTES)
        self.assertEqual(per_capture.serialized_event_slot_bytes, 18_505_728)
        self.assertEqual(per_capture.raw_float32_tensor_slot_bytes, 2_313_216)
        self.assertEqual(per_capture.python_float_list_slot_bytes, 2_048_256)
        self.assertEqual(per_capture.encoding_copy_bytes, 2_056_192)
        self.assertEqual(per_capture.transport_allocator_headroom_bytes, 67_108_864)
        self.assertEqual(per_capture.total_bytes, 92_032_256)
        self.assertEqual(per_capture.serialized_event_slot_bytes * 8, 148_045_824)
        self.assertEqual(per_capture.total_bytes * 8, 736_258_048)
        self.assertLessEqual(per_capture.total_bytes * 8, config.capacity_bytes)

    def test_config_is_immutable_and_rejects_unsafe_values(self) -> None:
        config = CaptureBudgetConfig()
        with self.assertRaises((AttributeError, TypeError)):
            config.output_queue_slots = 17  # type: ignore[misc]

        invalid = (
            {"vocabulary_size": True},
            {"vocabulary_size": 32_001},
            {"output_queue_slots": True},
            {"output_queue_slots": -1},
            {"output_queue_slots": 17},
            {"output_queue_slots": float("nan")},
            {"output_queue_slots": float("inf")},
            {"max_active_captures": False},
            {"max_active_captures": -1},
            {"max_active_captures": 9},
            {"max_active_captures": float("nan")},
            {"max_active_captures": float("inf")},
            {"capacity_bytes": -1},
            {"capacity_bytes": 1 << 31},
            {"capacity_bytes": True},
            {"capacity_bytes": float("nan")},
            {"capacity_bytes": float("inf")},
            {"transport_allocator_headroom_bytes": (64 << 20) - 1},
            {"transport_allocator_headroom_bytes": True},
            {"transport_allocator_headroom_bytes": float("nan")},
            {"transport_allocator_headroom_bytes": 1 << 31},
            {"max_retained_request_ids": False},
            {"max_retained_request_ids": float("nan")},
            {"max_retained_request_ids": float("inf")},
            {"max_retained_request_ids": -1},
            {"max_retained_request_ids": 65_537},
        )
        for changes in invalid:
            with self.subTest(changes=changes), self.assertRaises(CaptureConfigurationError):
                CaptureBudgetConfig(**changes)

    def test_reserve_and_release_report_breakdown_without_identifiers(self) -> None:
        budget = CaptureBudget()
        lease = budget.reserve("capture-001")
        self.assertEqual(repr(lease), "<CaptureLease opaque>")
        status = budget.status()
        self.assertEqual(status.active_captures, 1)
        self.assertEqual(status.cleanup_pending_captures, 0)
        self.assertEqual(status.reserved_bytes, status.per_capture.total_bytes)
        self.assertEqual(
            status.reserved_breakdown.serialized_event_slot_bytes,
            status.per_capture.serialized_event_slot_bytes,
        )
        self.assertNotIn("capture-001", repr(status))
        self.assertFalse(budget.release(lease, buffers_reclaimed=False))
        pending = budget.status()
        self.assertEqual(pending.active_captures, 0)
        self.assertEqual(pending.cleanup_pending_captures, 1)
        self.assertEqual(pending.reserved_bytes, status.reserved_bytes)
        self.assertTrue(budget.release(lease, buffers_reclaimed=True))
        self.assertTrue(budget.release(lease, buffers_reclaimed=True))
        released = budget.status()
        self.assertEqual(released.cleanup_pending_captures, 0)
        self.assertEqual(released.released_captures, 1)
        self.assertEqual(released.reserved_bytes, 0)

    def test_unconfirmed_cancellation_retains_bytes_even_after_time_passes(self) -> None:
        budget = CaptureBudget()
        lease = budget.reserve("cancelled-1")
        self.assertFalse(budget.release(lease, buffers_reclaimed=False))
        before = budget.status()
        threading.Event().wait(0.01)
        after = budget.status()
        self.assertEqual(after.cleanup_pending_captures, 1)
        self.assertEqual(after.reserved_bytes, before.reserved_bytes)
        self.assertEqual(after.available_bytes, before.available_bytes)

    def test_eight_active_limit_and_ninth_rejection(self) -> None:
        budget = CaptureBudget()
        leases = [budget.reserve(f"capture-{index}") for index in range(8)]
        self.assertEqual(budget.status().active_captures, 8)
        with self.assertRaises(ActiveCaptureLimitError):
            budget.reserve("capture-8")
        for lease in leases:
            self.assertTrue(budget.release(lease, buffers_reclaimed=True))

    def test_concurrent_reservations_are_serialized_at_active_limit(self) -> None:
        budget = CaptureBudget()
        start = threading.Barrier(24)

        def attempt(index: int) -> str:
            start.wait(timeout=5)
            try:
                budget.reserve(f"concurrent-{index}")
                return "admitted"
            except ActiveCaptureLimitError:
                return "limited"

        with ThreadPoolExecutor(max_workers=24) as executor:
            outcomes = list(executor.map(attempt, range(24)))
        self.assertEqual(outcomes.count("admitted"), 8)
        self.assertEqual(outcomes.count("limited"), 16)
        self.assertEqual(budget.status().active_captures, 8)

    def test_insufficient_byte_capacity_rejects_before_consuming_identifier(self) -> None:
        per_capture = calculate_capture_reservation(CaptureBudgetConfig())
        budget = CaptureBudget(CaptureBudgetConfig(capacity_bytes=per_capture.total_bytes - 1))
        with self.assertRaises(CaptureCapacityError):
            budget.reserve("capacity-denied")
        status = budget.status()
        self.assertEqual(status.active_captures, 0)
        self.assertEqual(status.reserved_bytes, 0)
        self.assertEqual(status.used_request_ids, 0)

    def test_ids_cannot_be_reused_and_foreign_release_cannot_free_a_lease(self) -> None:
        first = CaptureBudget()
        second = CaptureBudget()
        lease = first.reserve("same-id")
        with self.assertRaises(DuplicateCaptureRequestIdError):
            first.reserve("same-id")
        with self.assertRaises(InvalidCaptureLeaseError):
            second.release(lease, buffers_reclaimed=True)
        with self.assertRaises(InvalidCaptureLeaseError):
            first.release(object(), buffers_reclaimed=True)  # type: ignore[arg-type]
        self.assertEqual(first.status().reserved_bytes, first.per_capture.total_bytes)
        self.assertEqual(second.status().reserved_bytes, 0)
        self.assertTrue(first.release(lease, buffers_reclaimed=True))
        with self.assertRaises(DuplicateCaptureRequestIdError):
            first.reserve("same-id")

    def test_invalid_ids_and_non_boolean_cleanup_confirmation_are_rejected(self) -> None:
        budget = CaptureBudget()
        for request_id in ("", "has space", "non-ascii-λ", "x" * 129, 5):
            with self.subTest(request_id=repr(request_id)), self.assertRaises(InvalidCaptureRequestIdError):
                budget.reserve(request_id)  # type: ignore[arg-type]
        lease = budget.reserve("valid-id")
        with self.assertRaises(InvalidCleanupConfirmationError):
            budget.release(lease, buffers_reclaimed=1)  # type: ignore[arg-type]
        self.assertEqual(budget.status().active_captures, 1)

    def test_retained_request_id_history_fails_closed_at_its_bound(self) -> None:
        budget = CaptureBudget(CaptureBudgetConfig(max_active_captures=1, max_retained_request_ids=1))
        lease = budget.reserve("first")
        self.assertTrue(budget.release(lease, buffers_reclaimed=True))
        with self.assertRaises(RequestIdCapacityError):
            budget.reserve("second")
        self.assertEqual(budget.status().used_request_ids, 1)

    def test_import_is_torch_free_and_does_not_open_network(self) -> None:
        source_root = Path(__file__).resolve().parents[2] / "src"
        python = sys.executable
        code = (
            "import sys\n"
            "sys.path.insert(0, sys.argv[1])\n"
            "def deny(event, args):\n"
            "    if event.startswith('socket.'):\n"
            "        raise AssertionError('network access during import')\n"
            "sys.addaudithook(deny)\n"
            "import steamboat_runtime.capture_budget\n"
            "assert not any(name == 'torch' or name.startswith('torch.') for name in sys.modules)\n"
        )
        completed = subprocess.run(
            [python, "-B", "-c", code, str(source_root)],
            cwd=source_root.parent,
            env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(completed.stdout, "")


if __name__ == "__main__":
    unittest.main()
