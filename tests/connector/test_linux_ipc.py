import os
from pathlib import Path
import socket
import stat
import struct
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from steamboat_connector.client import LocalManagementClient
from steamboat_connector.controller import ManagementController
from steamboat_connector.daemon import DaemonServer
from steamboat_connector.errors import ConnectorError
from steamboat_connector.resources import MemoryResourceLedger
from steamboat_connector.state import initial_state
from steamboat_connector.storage import MemoryStateStore, StorageError
from steamboat_connector.validation import new_id


@unittest.skipUnless(sys.platform.startswith("linux"),
                     "Linux AF_UNIX peer credentials and openat protections required")
class LinuxManagementTests(unittest.TestCase):
    def test_fresh_controller_creates_private_state_directory(self):
        with tempfile.TemporaryDirectory() as root:
            directory = Path(root) / "new-state"
            controller = ManagementController(state_directory=str(directory))
            try:
                self.assertEqual(stat.S_IMODE(directory.stat().st_mode), 0o700)
                self.assertEqual(stat.S_IMODE((directory / "daemon-state.json").stat().st_mode), 0o600)
                self.assertEqual(stat.S_IMODE((directory / "resource-ledger.json").stat().st_mode), 0o600)
            finally:
                controller.shutdown()

    def test_repeated_start_stop_releases_directory_descriptors(self):
        with tempfile.TemporaryDirectory() as root:
            original = len(os.listdir("/proc/self/fd"))
            for _ in range(8):
                server, thread, _, _ = self._start(root)
                server.close()
                thread.join(timeout=2)
                self.assertFalse(thread.is_alive())
            self.assertEqual(len(os.listdir("/proc/self/fd")), original)

    def _start(self, root):
        runtime = Path(root) / "runtime"
        state = Path(root) / "state"
        server = DaemonServer(runtime_directory=runtime, state_directory=state)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        return server, thread, runtime, state

    def test_same_uid_token_file_modes_and_boot_rotation(self):
        with tempfile.TemporaryDirectory() as root:
            server_one, thread_one, runtime, _ = self._start(root)
            server_two = None
            try:
                client_one = LocalManagementClient(runtime)
                original_token = client_one._token
                result = client_one.status()
                self.assertTrue(all(not role["enabled"]
                                    for role in result["roles"].values()))
                self.assertEqual(stat.S_IMODE(os.stat(runtime).st_mode), 0o700)
                self.assertEqual(stat.S_IMODE(os.stat(server_one.address).st_mode), 0o600)
                self.assertEqual(stat.S_IMODE(os.stat(runtime / "boot.token").st_mode), 0o600)
                client_one._token = "0" * 64
                with self.assertRaises(ConnectorError) as caught:
                    client_one.status()
                self.assertEqual(caught.exception.code, "UNAUTHENTICATED")
            finally:
                server_one.close()
                thread_one.join(timeout=2)
            self.assertFalse((runtime / "boot.token").exists())
            server_two, thread_two, _, _ = self._start(root)
            try:
                client_two = LocalManagementClient(runtime)
                self.assertNotEqual(original_token, client_two._token)
                client_two._token = original_token
                with self.assertRaises(ConnectorError) as caught:
                    client_two.status()
                self.assertEqual(caught.exception.code, "UNAUTHENTICATED")
            finally:
                server_two.close()
                thread_two.join(timeout=2)

    def test_malformed_frame_is_closed_without_dispatch(self):
        with tempfile.TemporaryDirectory() as root:
            server, thread, runtime, _ = self._start(root)
            connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            try:
                connection.connect(os.fspath(server.address))
                malformed = b'{"version":1,"version":1}'
                connection.sendall(struct.pack("!I", len(malformed)) + malformed)
                connection.settimeout(1)
                self.assertEqual(connection.recv(1), b"")
            finally:
                connection.close()
                server.close()
                thread.join(timeout=2)

    def test_oversized_frame_is_closed_before_body_read(self):
        with tempfile.TemporaryDirectory() as root:
            server, thread, _, _ = self._start(root)
            connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            try:
                connection.connect(os.fspath(server.address))
                connection.sendall(struct.pack("!I", 65_537))
                connection.settimeout(1)
                self.assertEqual(connection.recv(1), b"")
            finally:
                connection.close()
                server.close()
                thread.join(timeout=2)

    def test_wrong_peer_uid_is_not_dispatched(self):
        with tempfile.TemporaryDirectory() as root:
            server, thread, runtime, _ = self._start(root)
            try:
                with patch("steamboat_connector.daemon._peer_uid",
                           return_value=os.getuid() + 1):
                    with self.assertRaises(ConnectorError):
                        LocalManagementClient(runtime).status()
            finally:
                server.close()
                thread.join(timeout=2)

    def test_duplicate_daemon_start_does_not_replace_active_boot(self):
        with tempfile.TemporaryDirectory() as root:
            server, thread, runtime, state_dir = self._start(root)
            try:
                client = LocalManagementClient(runtime)
                boot_before = client.status()["boot_id"]
                token_before = server.token
                with self.assertRaises(StorageError):
                    DaemonServer(runtime_directory=runtime, state_directory=state_dir)
                self.assertEqual(server.token, token_before)
                self.assertEqual(client.status()["boot_id"], boot_before)
            finally:
                server.close()
                thread.join(timeout=2)

    def test_management_connection_limit_is_four(self):
        with tempfile.TemporaryDirectory() as root:
            server, thread, _, _ = self._start(root)
            connections = []
            overflow = None
            try:
                for _ in range(4):
                    connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                    connection.connect(os.fspath(server.address))
                    connections.append(connection)
                deadline = time.monotonic() + 2
                while len(server._threads) < 4 and time.monotonic() < deadline:
                    time.sleep(0.01)
                self.assertEqual(len(server._threads), 4)
                self.assertFalse(server._slots.acquire(blocking=False))

                overflow = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                overflow.settimeout(0.5)
                overflow.connect(os.fspath(server.address))
                request = (b'{"version":1,"operation_id":"' +
                           new_id("op").encode("ascii") +
                           b'","token":"' + server.token.encode("ascii") +
                           b'","action":"status","payload":{}}')
                try:
                    overflow.sendall(struct.pack("!I", len(request)) + request)
                    response = overflow.recv(1)
                except (ConnectionResetError, BrokenPipeError):
                    # Closing an unread Unix stream can report reset or EOF.
                    response = b""
                except socket.timeout:
                    self.fail("fifth management connection was not rejected within 0.5 seconds")
                self.assertEqual(response, b"")
                connections.pop().close()
                deadline = time.monotonic() + 1
                while len(server._threads) > 3 and time.monotonic() < deadline:
                    time.sleep(0.01)
                self.assertLessEqual(len(server._threads), 3)
                self.assertIn("roles", LocalManagementClient(server.runtime_directory).status())
            finally:
                if overflow is not None:
                    overflow.close()
                for connection in connections:
                    connection.close()
                server.close()
                thread.join(timeout=2)

    def test_symlink_runtime_directory_is_rejected(self):
        with tempfile.TemporaryDirectory() as root:
            root_path = Path(root)
            actual = root_path / "actual"
            actual.mkdir(mode=0o700)
            link = root_path / "runtime-link"
            link.symlink_to(actual, target_is_directory=True)
            with self.assertRaises((OSError, StorageError)):
                DaemonServer(runtime_directory=link, state_directory=root_path / "state")

    def test_bounded_owned_data_deletion_refuses_symlinks(self):
        with tempfile.TemporaryDirectory() as root:
            state_dir = Path(root) / "state"
            state_dir.mkdir(mode=0o700)
            owned = state_dir / "owned-data"
            owned.mkdir(mode=0o700)
            (owned / "artifact.bin").write_bytes(b"owner data")
            os.chmod(owned / "artifact.bin", 0o600)
            controller = ManagementController(
                state_directory=state_dir, ledger=MemoryResourceLedger(),
                store=MemoryStateStore(initial_state()), start_workers=False)
            try:
                self.assertTrue(controller._delete_owned_data())
                self.assertFalse(owned.exists())
                owned.mkdir(mode=0o700)
                outside = Path(root) / "outside"
                outside.write_bytes(b"preserve")
                (owned / "link").symlink_to(outside)
                self.assertFalse(controller._delete_owned_data())
                self.assertEqual(outside.read_bytes(), b"preserve")
                self.assertTrue(owned.is_dir())
                (owned / "link").unlink()
                linked = owned / "linked.bin"
                linked.write_bytes(b"linked data")
                os.chmod(linked, 0o600)
                external_link = Path(root) / "external.bin"
                os.link(linked, external_link)
                self.assertFalse(controller._delete_owned_data())
                self.assertTrue(linked.exists())
                self.assertTrue(external_link.exists())
            finally:
                controller.shutdown(wait_seconds=0)


if __name__ == "__main__":
    unittest.main()
