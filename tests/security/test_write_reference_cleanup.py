"""Bounded, hook-free tests for write-error payload frame cleanup."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from steamboat_runtime.coordinator_service import (
    _clear_write_error_payload_frames,
    _scan_frame_for_write_references,
)


def _raise_and_return_error(operation):
    try:
        operation()
    except BaseException as error:
        return error
    raise AssertionError("operation did not raise")


def _traceback_frame(error, name):
    traceback = error.__traceback__
    while traceback is not None:
        if traceback.tb_frame.f_code.co_name == name:
            return traceback.tb_frame
        traceback = traceback.tb_next
    raise AssertionError(f"traceback frame {name!r} was not retained")


class WriteReferenceScannerTests(unittest.TestCase):
    def test_hostile_mro_descriptor_cannot_hide_list_subclass(self):
        payload = b"protected-payload"

        class ForgedIterable:
            def __init__(self, calls):
                self.calls = calls

            def __iter__(self):
                self.calls.append("iter")
                raise AssertionError("forged MRO iterable was invoked")

        for forged_mro_kind in ("tuple", "iterable"):
            with self.subTest(forged_mro_kind=forged_mro_kind):
                calls = []
                forged_mro = ((object,) if forged_mro_kind == "tuple"
                              else ForgedIterable(calls))

                class ForgedMroMeta(type):
                    @property
                    def __mro__(cls):
                        calls.append("descriptor")
                        return forged_mro

                class HiddenList(list, metaclass=ForgedMroMeta):
                    pass

                def writer(value):
                    held = HiddenList([value])
                    value = None
                    raise RuntimeError("write failed")

                error = _raise_and_return_error(lambda: writer(payload))
                writer_frame = _traceback_frame(error, "writer")
                self.assertFalse(_clear_write_error_payload_frames(
                    error, (payload,)))
                self.assertIs(writer_frame.f_locals["held"][0], payload)
                self.assertEqual(calls, [])

    def test_custom_type_equality_and_instance_hooks_are_not_called(self):
        calls = []

        class HostileMeta(type):
            def __eq__(cls, other):
                calls.append("eq")
                raise AssertionError("metaclass equality was invoked")

            def __instancecheck__(cls, value):
                calls.append("instancecheck")
                raise AssertionError("metaclass instance check was invoked")

        class Opaque(metaclass=HostileMeta):
            pass

        payload = b"protected-payload"

        def writer(value):
            opaque = Opaque()
            held = (value,)
            value = None
            raise RuntimeError("write failed")

        error = _raise_and_return_error(lambda: writer(payload))
        writer_frame = _traceback_frame(error, "writer")
        self.assertTrue(_clear_write_error_payload_frames(error, (payload,)))
        self.assertEqual(writer_frame.f_locals, {})
        self.assertEqual(calls, [])

    def test_cyclic_builtin_containers_are_scanned_once(self):
        payload = b"protected-payload"

        def writer(value):
            sequence = []
            mapping = {"sequence": sequence}
            sequence.extend((mapping, [{"nested": (value,)}]))
            value = None
            raise RuntimeError("write failed")

        error = _raise_and_return_error(lambda: writer(payload))
        writer_frame = _traceback_frame(error, "writer")
        self.assertTrue(_clear_write_error_payload_frames(error, (payload,)))
        self.assertEqual(writer_frame.f_locals, {})

    def test_cumulative_budget_exhausts_during_nested_container_scan(self):
        payload = b"protected-payload"
        nested = [[object() for _ in range(10_000)] + [payload]]
        frame = SimpleNamespace(f_locals={"held": nested})
        # This budget gets past the locals mapping and both nested-list
        # iterator/value nodes, then exhausts within the large child list before
        # reaching its protected payload near the end.
        budget = [11]

        result = _scan_frame_for_write_references(frame, (payload,), budget)

        self.assertIsNone(result)
        self.assertEqual(budget[0], 0)
        self.assertIs(nested[0][-1], payload)

    def test_hierarchy_entry_cost_tracks_actual_mro_depth(self):
        class ShallowOpaque:
            pass

        deep_type = ShallowOpaque
        added_bases = 7
        for index in range(added_bases):
            deep_type = type(f"OpaqueLayer{index}", (deep_type,), {})

        def capture_frame(value_type):
            opaque = value_type()
            value_type = None
            return sys._getframe()

        shallow_frame = capture_frame(ShallowOpaque)
        deep_frame = capture_frame(deep_type)
        initial_budget = 256

        def scan_cost(frame):
            budget = [initial_budget]
            result = _scan_frame_for_write_references(frame, (), budget)
            self.assertIs(result, False)
            self.assertGreater(budget[0], 0)
            return initial_budget - budget[0]

        try:
            shallow_cost = scan_cost(shallow_frame)
            deep_cost = scan_cost(deep_frame)
        finally:
            shallow_frame.clear()
            deep_frame.clear()

        actual_depth_delta = len(deep_type.__mro__) - len(ShallowOpaque.__mro__)
        self.assertEqual(actual_depth_delta, added_bases)
        self.assertEqual(deep_cost - shallow_cost, actual_depth_delta)

    def test_retained_cause_and_outer_frames_are_both_cleared(self):
        payload = b"protected-payload"
        marker = object()

        def writer(value):
            held = {"payload": [value]}
            value = None
            raise RuntimeError("writer failed")

        try:
            writer(payload)
        except RuntimeError as caught_cause:
            cause = caught_cause
            def wrapper(value, original):
                held = (value,)
                value = None
                raise TimeoutError("wrapper timed out") from original

            error = _raise_and_return_error(lambda: wrapper(payload, cause))

        writer_frame = _traceback_frame(cause, "writer")
        wrapper_frame = _traceback_frame(error, "wrapper")
        self.assertIs(error.__cause__, cause)
        self.assertTrue(_clear_write_error_payload_frames(error, (payload,)))
        self.assertEqual(writer_frame.f_locals, {})
        self.assertEqual(wrapper_frame.f_locals, {})
        self.assertIsNotNone(error.__cause__)
        self.assertIs(sys._getframe().f_locals["marker"], marker)


if __name__ == "__main__":
    unittest.main()
