import threading
import unittest
from unittest.mock import Mock, patch

from steamboat_connector import daemon


class DaemonShutdownTests(unittest.TestCase):
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
