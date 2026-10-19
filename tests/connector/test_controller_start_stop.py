"""Management start ownership is established before lifecycle queue dispatch."""
import threading
import time
import unittest
from unittest.mock import patch

from steamboat_connector.controller import ManagementController
from steamboat_connector.errors import ConnectorError
from tests.connector.test_resources_controller import sample_policy


class IntentBackend:
    secure_runtime_ready = True

    def __init__(self):
        self.entered = threading.Event()
        self.release = threading.Event()
        self.tokens = []
        self.spawned = 0
        self.stops = 0

    def start(self, role, policy, *, cancel_event):
        self.tokens.append(cancel_event)
        self.entered.set()
        self.release.wait(2)
        if cancel_event.is_set():
            return False
        self.spawned += 1
        return True

    def request_stop(self, roles):
        self.stops += 1

    def request_drain(self, roles):
        pass

    def stop(self, roles, grace_seconds):
        return {role: True for role in roles}

    def drain(self, roles, deadline, cancel_event):
        return {"drained": True, "reclaimed": True}


class ControllerStartStopTests(unittest.TestCase):
    def make_controller(self, *, workers=False):
        backend = IntentBackend()
        controller = ManagementController(backend=backend, start_workers=workers)
        self.addCleanup(lambda: controller.shutdown(wait_seconds=1))
        self.addCleanup(backend.release.set)
        controller.handle("role.enable", {"role": "consumer"})
        return controller, backend

    def take_start(self, controller):
        operation, kind, payload = controller._normal.get_nowait()
        self.assertEqual(kind, "start")
        return operation, payload

    def test_stop_fences_queued_start_before_acknowledgment(self):
        controller, backend = self.make_controller()
        controller.handle("start", {"roles": ["consumer"]})
        operation, payload = self.take_start(controller)
        begin = time.monotonic()
        result = controller.handle("stop", {"roles": ["consumer"]})
        self.assertLess(time.monotonic() - begin, 1)
        self.assertFalse(result["reclaimed"])
        self.assertTrue(payload[2]["consumer"].is_set())
        self.assertEqual(backend.stops, 1)
        outcome = controller._perform_start(operation, payload)
        self.assertFalse(outcome["success"])
        self.assertFalse(backend.entered.is_set())
        self.assertEqual(backend.spawned, 0)

    def test_stop_between_manager_check_and_backend_spawn_uses_same_token(self):
        controller, backend = self.make_controller(workers=True)
        controller.handle("start", {"roles": ["consumer"]})
        self.assertTrue(backend.entered.wait(1))
        controller.handle("stop", {"roles": ["consumer"]})
        self.assertTrue(backend.tokens[0].is_set())
        controller.handle("role.enable", {"role": "consumer"})
        with self.assertRaises(ConnectorError) as caught:
            controller.handle("start", {"roles": ["consumer"]})
        self.assertEqual(caught.exception.code, "BUSY")
        backend.release.set()
        deadline = time.monotonic() + 1
        while "consumer" in controller._starts and time.monotonic() < deadline:
            time.sleep(.005)
        self.assertNotIn("consumer", controller._starts)
        self.assertEqual(backend.spawned, 0)

    def test_remove_disable_drain_and_shutdown_cancel_queued_start(self):
        for action, payload in (
                ("remove", {}), ("role.disable", {"role": "consumer"}),
                ("drain", {"roles": ["consumer"]}), ("shutdown", {})):
            with self.subTest(action=action):
                controller, backend = self.make_controller()
                controller.handle("start", {"roles": ["consumer"]})
                operation, queued = self.take_start(controller)
                if action == "shutdown":
                    controller.shutdown(wait_seconds=0)
                else:
                    controller.handle(action, payload)
                self.assertTrue(queued[2]["consumer"].is_set())
                self.assertFalse(controller._perform_start(operation, queued)["success"])
                self.assertEqual(backend.spawned, 0)

    def test_old_stop_completion_cannot_release_newer_stop_fence(self):
        controller, backend = self.make_controller()
        first = controller.handle("stop", {"roles": ["consumer"]})
        second = controller.handle("stop", {"roles": ["consumer"]})
        controller._perform_stop(first["operation_id"], ("consumer",), disable=True)
        controller.handle("role.enable", {"role": "consumer"})
        with self.assertRaises(ConnectorError):
            controller.handle("start", {"roles": ["consumer"]})
        controller._perform_stop(second["operation_id"], ("consumer",), disable=True)
        backend.release.set()
        controller.handle("start", {"roles": ["consumer"]})
        operation, payload = self.take_start(controller)
        self.assertTrue(controller._perform_start(operation, payload)["success"])
        self.assertEqual(backend.spawned, 1)

    def test_failed_stop_retains_fence_until_explicit_successful_stop(self):
        controller, backend = self.make_controller()
        first = controller.handle("stop", {"roles": ["consumer"]})
        backend.stop = lambda roles, grace_seconds: {role: False for role in roles}
        self.assertFalse(controller._perform_stop(
            first["operation_id"], ("consumer",), disable=True)["reclaimed"])
        controller.handle("role.enable", {"role": "consumer"})
        with self.assertRaises(ConnectorError):
            controller.handle("start", {"roles": ["consumer"]})
        self.assertIn("consumer", controller._stop_fences)

    def test_policy_replacement_and_stale_telemetry_cancel_old_start(self):
        enforcement = {"memory_cpu": True, "disk": True, "bandwidth": True}
        for reason in ("policy", "telemetry"):
            with self.subTest(reason=reason), patch(
                    "steamboat_connector.controller.unsupported_enforcement",
                    return_value=enforcement):
                controller, backend = self.make_controller()
                policy = sample_policy(["thermal"])
                controller.telemetry.record("thermal", 45)
                controller.handle("policy.set", {"policy": policy})
                controller.handle("role.enable", {"role": "host"})
                controller.handle("start", {"roles": ["host"]})
                operation, queued = self.take_start(controller)
                if reason == "policy":
                    controller.handle("policy.set", {"policy": sample_policy()})
                else:
                    controller.telemetry.invalidate("thermal")
                    self.assertTrue(controller.check_telemetry())
                self.assertTrue(queued[2]["host"].is_set())
                self.assertFalse(controller._perform_start(operation, queued)["success"])
                self.assertEqual(backend.spawned, 0)

    def test_start_exception_pauses_role_and_does_not_lose_queue_ownership(self):
        controller, backend = self.make_controller()
        controller.handle("start", {"roles": ["consumer"]})
        operation, payload = self.take_start(controller)
        def fail(*args, **kwargs):
            raise RuntimeError("fixture startup failure")
        backend.start = fail
        with self.assertRaises(RuntimeError):
            controller._perform_start(operation, payload)
        self.assertTrue(controller.status()["paused_roles"]["consumer"])
        self.assertNotIn("consumer", controller._starts)


if __name__ == "__main__":
    unittest.main()
