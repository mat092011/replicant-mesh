import threading
import unittest
from unittest.mock import Mock, patch

from steamboat_connector import daemon
from steamboat_connector.controller import ManagementController
from steamboat_connector.state import initial_state
from steamboat_connector.storage import MemoryStateStore
from steamboat_connector.telemetry import TelemetryRegistry
from tests.connector import test_resources_controller as resource_fixtures


class DaemonShutdownTests(unittest.TestCase):
    def test_continuous_connections_cannot_starve_required_telemetry(self):
        now = [0.0]
        telemetry = TelemetryRegistry(clock=lambda: now[0])
        telemetry.record("thermal", 40.0)
        state = initial_state()
        state["policy"] = resource_fixtures.sample_policy(("thermal",))
        state["roles"]["host"] = True
        backend = Mock()
        backend.request_stop.side_effect = lambda roles: {role: True for role in roles}
        backend.stop.side_effect = lambda roles, _grace: {role: True for role in roles}
        controller = ManagementController(
            store=MemoryStateStore(state), telemetry=telemetry, backend=backend,
            clock=lambda: now[0], start_workers=False)
        stop = threading.Event()
        connection = Mock()
        accepts = [0]

        def accept_without_idle():
            accepts[0] += 1
            now[0] += 0.1
            if accepts[0] == 1:
                telemetry.invalidate("thermal")
            if accepts[0] == 20:
                stop.set()
            return connection, None

        server = daemon.DaemonServer.__new__(daemon.DaemonServer)
        server.controller = controller
        server.listener = Mock()
        server.listener.accept.side_effect = accept_without_idle
        server._slots = threading.BoundedSemaphore(0)
        # Observe telemetry's own cutoff, independently of shutdown's separate
        # unconditional role pause and cleanup fence.
        server.close = Mock()
        try:
            server.serve_forever(stop)
            self.assertEqual(accepts[0], 20)
            self.assertLess(now[0], 5.0)
            self.assertTrue(controller._state_copy()["paused_roles"]["host"])
            backend.request_stop.assert_called_once_with(("host",))
            reasons = [item["result"].get("reason")
                       for item in controller._state_copy()["operations"]]
            self.assertIn("required_telemetry_unavailable", reasons)
        finally:
            controller.shutdown(wait_seconds=1)

    def test_close_preserves_runtime_files_until_shutdown_proof(self):
        server = daemon.DaemonServer.__new__(daemon.DaemonServer)
        server._close_lock = threading.Lock()
        server._closed = False
        server._shutdown_complete = False
        server._stop = threading.Event()
        server.listener = None
        server._threads = set()
        server.controller = Mock()
        server.controller.shutdown.side_effect = [False, True]
        server._cleanup_files = Mock()

        self.assertFalse(server.close())
        server._cleanup_files.assert_not_called()
        self.assertTrue(server.close())
        server._cleanup_files.assert_called_once_with()

    def test_run_daemon_keeps_main_thread_until_reconciliation(self):
        allow_cleanup = threading.Event()
        class FakeServer:
            def __init__(self, **_kwargs):
                self.close_calls = 0

            def serve_forever(self, stop):
                stop.set()

            def close(self):
                self.close_calls += 1
                return allow_cleanup.is_set()

        result = []
        instances = []
        with (patch.object(daemon, "DaemonServer", FakeServer),
              patch.object(daemon.signal, "signal")):
            original_init = FakeServer.__init__

            def retain_instance(self, **kwargs):
                original_init(self, **kwargs)
                instances.append(self)

            FakeServer.__init__ = retain_instance
            thread = threading.Thread(target=lambda: result.append(daemon.run_daemon()))
            try:
                thread.start()
                thread.join(1.1)
                self.assertTrue(thread.is_alive())
                self.assertGreaterEqual(instances[0].close_calls, 2)
            finally:
                allow_cleanup.set()
                if thread.ident is not None:
                    thread.join(2)
        self.assertFalse(thread.is_alive())
        self.assertEqual(result, [0])


if __name__ == "__main__":
    unittest.main()
