"""Lightweight contract tests for the assigned-stage worker adapter."""

from contextlib import nullcontext
from types import SimpleNamespace
import sys
import unittest
from unittest import mock

from steamboat_runtime.assigned_artifacts import (AssignedArtifactError,
                                                   AssignedArtifactView)
from steamboat_runtime import assigned_executor


ASSIGNMENT_ID = "asg_" + "1" * 32
ACCOUNT_ID = "acct_" + "2" * 32
DEVICE_ID = "dev_" + "3" * 32


class _Cache:
    def __init__(self, start, end):
        self.start, self.end = start, end


class _Stage:
    def __init__(self, start, end):
        self.start, self.end = start, end
        self.calls = []

    def __call__(self, hidden, cache, position):
        self.calls.append((hidden, cache, position))
        return "stage-result"


def _view(*, role="host", component="worker-2", assignment_id=ASSIGNMENT_ID,
          fingerprint="f" * 64, assignment_digest="a" * 64, start=2, end=4):
    view = object.__new__(AssignedArtifactView)
    manifest = {"fingerprint": fingerprint,
                "components": {component: {"layer_range": [start, end]}}}
    payload = {"assignment_id": assignment_id, "account_id": ACCOUNT_ID,
        "device_id": DEVICE_ID, "role": role, "component": component,
        "manifest_fingerprint": fingerprint}
    view.installer = SimpleNamespace()
    view.assignment_id = assignment_id
    view.account_id = ACCOUNT_ID
    view.device_id = DEVICE_ID
    view.role = role
    view.manifest = manifest
    view.assignment = SimpleNamespace(payload=payload,
                                      document_sha256=assignment_digest)
    view._locked_manifest = mock.Mock(return_value=manifest)
    view.load_stage = mock.Mock(return_value=_Stage(start, end))
    view.new_layer_cache = mock.Mock(return_value=_Cache(start, end))
    return view


class AssignedExecutorTests(unittest.TestCase):
    def test_executor_loads_one_active_assigned_stage_and_keeps_it_resident(self):
        view = _view()
        executor = assigned_executor.AssignedStageExecutor(view)
        self.assertEqual(executor.worker_name, "worker-2")
        self.assertIs(executor.manifest, view.manifest)
        self.assertEqual(view.load_stage.call_count, 1)
        self.assertEqual(view._locked_manifest.call_count, 2)
        view.load_coordinator_model = mock.Mock(
            side_effect=AssertionError("coordinator model must not load"))

        cache = executor.new_cache()
        hidden = object()
        fake_torch = SimpleNamespace(inference_mode=nullcontext)
        with mock.patch.dict(sys.modules, {"torch": fake_torch}):
            result = executor.execute(hidden, cache, 3)
        self.assertEqual(result, "stage-result")
        self.assertEqual(executor.stage.calls, [(hidden, cache, 3)])
        self.assertEqual(view._locked_manifest.call_count, 5)
        view.load_coordinator_model.assert_not_called()

    def test_coordinator_and_non_view_inputs_are_rejected_before_load(self):
        coordinator = _view(role="coordinator")
        with self.assertRaises(AssignedArtifactError):
            assigned_executor.AssignedStageExecutor(coordinator)
        coordinator.load_stage.assert_not_called()
        with self.assertRaises(AssignedArtifactError):
            assigned_executor.AssignedStageExecutor(SimpleNamespace(role="host"))

    def test_inactive_or_mismatched_assignment_is_rejected(self):
        inactive = _view()
        inactive._locked_manifest.side_effect = AssignedArtifactError(
            "assignment is not active")
        with self.assertRaises(AssignedArtifactError):
            assigned_executor.AssignedStageExecutor(inactive)
        inactive.load_stage.assert_not_called()

        mismatched = _view()
        mismatched.assignment.payload["assignment_id"] = "asg_" + "9" * 32
        with self.assertRaises(AssignedArtifactError):
            assigned_executor.AssignedStageExecutor(mismatched)
        mismatched.load_stage.assert_not_called()

    def test_assignment_change_during_load_is_rejected(self):
        view = _view()
        manifest = view.manifest
        calls = 0

        def changed_after_load():
            nonlocal calls
            calls += 1
            if calls == 2:
                view.assignment.document_sha256 = "b" * 64
            return manifest

        view._locked_manifest.side_effect = changed_after_load
        with self.assertRaises(AssignedArtifactError):
            assigned_executor.AssignedStageExecutor(view)

    def test_deactivated_scope_and_wrong_cache_fail_before_compute(self):
        view = _view()
        executor = assigned_executor.AssignedStageExecutor(view)
        view._locked_manifest.side_effect = AssignedArtifactError("assignment is inactive")
        with self.assertRaises(AssignedArtifactError):
            executor.new_cache()
        view.new_layer_cache.assert_not_called()
        with self.assertRaises(AssignedArtifactError):
            executor.execute(object(), _Cache(2, 4), 0)
        self.assertEqual(executor.stage.calls, [])

        view._locked_manifest.side_effect = None
        wrong_cache = _Cache(0, 2)
        fake_torch = SimpleNamespace(inference_mode=nullcontext)
        with mock.patch.dict(sys.modules, {"torch": fake_torch}):
            with self.assertRaises(AssignedArtifactError):
                executor.execute(object(), wrong_cache, 0)
        self.assertEqual(executor.stage.calls, [])

    def test_handler_receives_manifest_component_executor_and_owner_options(self):
        view = _view()
        handler = object()
        factory = mock.Mock(return_value=handler)
        fake_worker_state = SimpleNamespace(WorkerHandler=factory)
        with mock.patch.dict(sys.modules,
                {"steamboat_runtime.worker_state": fake_worker_state}):
            result = assigned_executor.build_assigned_worker_handler(
                view, boot_id="b" * 32, enable_queue=True, queue_capacity=2)
        self.assertIs(result, handler)
        args, options = factory.call_args
        self.assertIs(args[0], view.manifest)
        self.assertEqual(args[1], "worker-2")
        self.assertIsInstance(args[2], assigned_executor.AssignedStageExecutor)
        self.assertEqual(options["boot_id"], "b" * 32)
        self.assertTrue(options["enable_queue"])
        self.assertEqual(options["queue_capacity"], 2)


if __name__ == "__main__":
    unittest.main()
