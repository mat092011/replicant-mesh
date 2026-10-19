"""Focused task-tree and reservation checks for the opaque secure gate."""

import asyncio
import os
from pathlib import Path
import socket
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from steamboat_runtime.protocol import secure_transport
from steamboat_runtime.protocol.secure_acceptor import SecureAcceptor
from steamboat_runtime.protocol.secure_transport import SecureTaskPending


@unittest.skipUnless(os.name == "posix" and hasattr(os, "getuid"),
                     "The private UDS gate requires POSIX ownership checks")
class SecureAcceptorOwnershipTests(unittest.IsolatedAsyncioTestCase):
    async def _acceptor_with_connection(self, *, deadline):
        temporary = tempfile.TemporaryDirectory()
        os.chmod(temporary.name, 0o700)
        class Reservation:
            releases = 0
            def release(self):
                self.releases += 1
        class Controller:
            def reserve_pending(self, owner):
                raise AssertionError("no listener should be started")
        acceptor = SecureAcceptor(
            listen_endpoint="127.0.0.1:0", allowed_listen_addresses=("127.0.0.1",),
            backend_socket_path=os.path.join(temporary.name, "backend.sock"),
            private_directory=temporary.name, listener_slots=1,
            connection_controller=Controller(), on_unavailable=lambda: None)
        remote, remote_peer = socket.socketpair()
        backend, backend_peer = socket.socketpair()
        connection = type("Connection", (), {})()
        connection.authorization_lock = asyncio.Lock()
        connection.retired = False
        connection.rejecting = False
        connection.established = False
        connection.pending_deadline = deadline
        connection.pending = Reservation()
        connection.remote = remote
        connection.backend = backend
        connection.authenticated = asyncio.Event()
        acceptor._peer_paths["path-token"] = connection
        acceptor._connections.add(connection)
        acceptor._active = 1
        self.addCleanup(temporary.cleanup)
        self.addCleanup(remote_peer.close)
        self.addCleanup(backend_peer.close)
        self.addCleanup(remote.close)
        self.addCleanup(backend.close)
        return acceptor, connection

    async def test_public_rejection_latches_without_releasing_live_pending_owner(self):
        with patch("steamboat_runtime.protocol.secure_acceptor.time.monotonic", return_value=10):
            acceptor, connection = await self._acceptor_with_connection(deadline=15)
            before = (connection.pending, connection.pending_deadline,
                      connection.remote.fileno(), connection.backend.fileno())
            self.assertTrue(await acceptor.reject_unestablished_peer("peer path-token"))
            self.assertTrue(await acceptor.reject_unestablished_peer("peer path-token"))
            self.assertTrue(connection.rejecting)
            self.assertFalse(connection.established)
            self.assertFalse(connection.authenticated.is_set())
            self.assertEqual((connection.pending, connection.pending_deadline,
                              connection.remote.fileno(), connection.backend.fileno()), before)
            self.assertEqual(connection.pending.releases, 0)
            self.assertEqual(acceptor._active, 1)

    async def test_rejected_connection_cannot_become_authenticated(self):
        with patch("steamboat_runtime.protocol.secure_acceptor.time.monotonic", return_value=10):
            acceptor, connection = await self._acceptor_with_connection(deadline=15)
            self.assertTrue(await acceptor.reject_unestablished_peer("peer path-token"))
            self.assertFalse(await acceptor.mark_authenticated_peer("peer path-token"))
            self.assertTrue(connection.rejecting)
            self.assertFalse(connection.established)
            self.assertFalse(connection.authenticated.is_set())
            self.assertEqual(connection.pending.releases, 0)

    async def test_rejection_at_original_deadline_hard_shuts_down_sockets(self):
        with patch("steamboat_runtime.protocol.secure_acceptor.time.monotonic", return_value=15):
            acceptor, connection = await self._acceptor_with_connection(deadline=15)
            with patch.object(acceptor, "_shutdown_sockets", wraps=acceptor._shutdown_sockets) as shutdown:
                self.assertTrue(await acceptor.reject_unestablished_peer("peer path-token"))
                shutdown.assert_called_once_with(connection)
            self.assertTrue(connection.rejecting)
            self.assertEqual(connection.pending.releases, 0)

    async def test_shutdown_keeps_rejected_connection_charged_for_resistant_pump_owner(self):
        acceptor, connection = await self._acceptor_with_connection(
            deadline=asyncio.get_running_loop().time() + 10)
        original_reservation = connection.pending
        self.assertIsNotNone(original_reservation)
        connection.acceptor = acceptor
        connection.tasks = set()
        connection.pump_tasks = set()
        connection.watched_tasks = set()
        connection.retirement_task = None
        connection.client_directory = Path(acceptor.backend_socket_path).parent / "client"
        connection.client_directory.mkdir()
        connection.client_path = connection.client_directory / "gate-client.sock"
        acceptor._peer_paths.clear()
        acceptor._peer_paths[os.fspath(connection.client_path)] = connection

        released = asyncio.Event()
        cancellation_seen = asyncio.Event()
        started = asyncio.Event()

        async def resistant_pump_owner():
            started.set()
            try:
                await released.wait()
            except asyncio.CancelledError:
                cancellation_seen.set()
                await released.wait()

        owner = asyncio.create_task(resistant_pump_owner())
        connection.tasks.add(owner)
        await asyncio.wait_for(started.wait(), 1)
        self.assertTrue(await acceptor.reject_unestablished_peer(
            os.fspath(connection.client_path)))
        try:
            with patch.object(secure_transport,
                              "MAX_CANCELLATION_GRACE_SECONDS", 0.05):
                with self.assertRaises(SecureTaskPending):
                    await acceptor._retire(connection)
            await asyncio.wait_for(cancellation_seen.wait(), 1)
            self.assertFalse(owner.done())
            self.assertIs(connection.pending, original_reservation)
            self.assertEqual(original_reservation.releases, 0)
            self.assertEqual(acceptor._active, 1)
            self.assertGreaterEqual(connection.remote.fileno(), 0)
            self.assertGreaterEqual(connection.backend.fileno(), 0)

            released.set()
            self.assertTrue(await asyncio.wait_for(
                acceptor.wait_for_idle(0.2), timeout=0.5))
            self.assertTrue(owner.done())
            self.assertIsNone(connection.pending)
            self.assertEqual(original_reservation.releases, 1)
            self.assertEqual(acceptor._active, 0)
            self.assertEqual(connection.remote.fileno(), -1)
            self.assertEqual(connection.backend.fileno(), -1)
        finally:
            released.set()
            if not owner.done():
                await asyncio.wait_for(owner, 1)
            try:
                connection.client_directory.rmdir()
            except OSError:
                pass

    async def test_pump_cancel_completion_race_reports_and_retains_late_child(self):
        with tempfile.TemporaryDirectory() as temporary:
            os.chmod(temporary, 0o700)
            unavailable = []

            class Controller:
                def reserve_pending(self, owner):
                    raise AssertionError("this direct pump test must not reserve a socket")

            acceptor = SecureAcceptor(
                listen_endpoint="127.0.0.1:0",
                allowed_listen_addresses=("127.0.0.1",),
                backend_socket_path=os.path.join(temporary, "backend.sock"),
                private_directory=temporary,
                listener_slots=1,
                connection_controller=Controller(),
                on_unavailable=lambda: unavailable.append(True),
            )
            root_started, child_started, release_child = (
                asyncio.Event(), asyncio.Event(), asyncio.Event())
            child_tasks = []

            async def resistant_child():
                child_started.set()
                try:
                    await release_child.wait()
                except asyncio.CancelledError:
                    await release_child.wait()

            async def root_finishing_with_pending_child():
                root_started.set()
                try:
                    await asyncio.Event().wait()
                except asyncio.CancelledError:
                    child = asyncio.create_task(resistant_child())
                    child_tasks.append(child)
                    await child_started.wait()
                    raise SecureTaskPending((child,),
                                            "root completed with late child ownership")

            root = asyncio.create_task(root_finishing_with_pending_child())
            try:
                await asyncio.wait_for(root_started.wait(), 1)
                with patch.object(secure_transport,
                                  "MAX_CANCELLATION_GRACE_SECONDS", 0.2):
                    started = asyncio.get_running_loop().time()
                    with self.assertRaises(SecureTaskPending) as captured:
                        await acceptor._cancel_pumps_bounded((root,))
                    self.assertLess(asyncio.get_running_loop().time() - started, 0.5)

                self.assertTrue(child_tasks)
                child = child_tasks[0]
                self.assertTrue(root.done())
                self.assertEqual(captured.exception.tasks, (child,))
                self.assertIn(child, secure_transport._RETAINED_TASKS)
                self.assertTrue(unavailable)
                self.assertFalse(child.done())
            finally:
                release_child.set()
                if child_tasks:
                    await asyncio.wait_for(child_tasks[0], 1)

    async def test_pump_watchdog_unions_unfinished_roots_with_late_children(self):
        with tempfile.TemporaryDirectory() as temporary:
            os.chmod(temporary, 0o700)

            class Controller:
                def reserve_pending(self, owner):
                    raise AssertionError("this direct pump test must not reserve a socket")

            acceptor = SecureAcceptor(
                listen_endpoint="127.0.0.1:0",
                allowed_listen_addresses=("127.0.0.1",),
                backend_socket_path=os.path.join(temporary, "backend.sock"),
                private_directory=temporary,
                listener_slots=1,
                connection_controller=Controller(),
                on_unavailable=lambda: None,
            )
            root_started, child_started, other_started = (
                asyncio.Event(), asyncio.Event(), asyncio.Event())
            release_child, release_other = asyncio.Event(), asyncio.Event()
            child_tasks = []

            async def resistant_child():
                child_started.set()
                try:
                    await release_child.wait()
                except asyncio.CancelledError:
                    await release_child.wait()

            async def completing_root():
                root_started.set()
                try:
                    await asyncio.Event().wait()
                except asyncio.CancelledError:
                    child = asyncio.create_task(resistant_child())
                    child_tasks.append(child)
                    await child_started.wait()
                    raise SecureTaskPending((child,), "late child from completed root")

            async def resistant_root():
                other_started.set()
                try:
                    await release_other.wait()
                except asyncio.CancelledError:
                    await release_other.wait()

            root = asyncio.create_task(completing_root())
            other = asyncio.create_task(resistant_root())
            try:
                await asyncio.gather(root_started.wait(), other_started.wait())
                with patch.object(secure_transport,
                                  "MAX_CANCELLATION_GRACE_SECONDS", 0.2):
                    with self.assertRaises(SecureTaskPending) as captured:
                        await acceptor._cancel_pumps_bounded((root, other))
                self.assertTrue(child_tasks)
                child = child_tasks[0]
                self.assertTrue(root.done())
                self.assertFalse(other.done())
                self.assertEqual(set(captured.exception.tasks), {child, other})
                self.assertIn(child, secure_transport._RETAINED_TASKS)
                self.assertIn(other, secure_transport._RETAINED_TASKS)
            finally:
                release_child.set()
                release_other.set()
                await asyncio.wait_for(asyncio.gather(root, other,
                                                       return_exceptions=True), 1)
                if child_tasks:
                    await asyncio.wait_for(child_tasks[0], 1)

    async def test_cancelled_pump_helper_keeps_root_until_its_late_child_is_observed(self):
        with tempfile.TemporaryDirectory() as temporary:
            os.chmod(temporary, 0o700)
            unavailable = []

            class Controller:
                def reserve_pending(self, owner):
                    raise AssertionError("this direct pump test must not reserve a socket")

            acceptor = SecureAcceptor(
                listen_endpoint="127.0.0.1:0",
                allowed_listen_addresses=("127.0.0.1",),
                backend_socket_path=os.path.join(temporary, "backend.sock"),
                private_directory=temporary,
                listener_slots=1,
                connection_controller=Controller(),
                on_unavailable=lambda: unavailable.append(True),
            )
            root_started, child_started = asyncio.Event(), asyncio.Event()
            finish_root, release_child = asyncio.Event(), asyncio.Event()
            child_tasks = []

            async def resistant_child():
                child_started.set()
                try:
                    await release_child.wait()
                except asyncio.CancelledError:
                    await release_child.wait()

            async def root_with_delayed_pending_error():
                root_started.set()
                try:
                    await asyncio.Event().wait()
                except asyncio.CancelledError:
                    child = asyncio.create_task(resistant_child())
                    child_tasks.append(child)
                    await child_started.wait()
                    await finish_root.wait()
                    raise SecureTaskPending((child,), "root finished with a child")

            root = asyncio.create_task(root_with_delayed_pending_error())
            retirement_hold = asyncio.create_task(asyncio.Event().wait())
            connection = SimpleNamespace(
                acceptor=acceptor,
                tasks={root},
                watched_tasks=set(),
                retired=False,
                retirement_task=retirement_hold,
            )
            root.add_done_callback(
                lambda done: acceptor._observe_task(connection, done))
            helper = None
            try:
                await asyncio.wait_for(root_started.wait(), 1)
                helper = asyncio.create_task(
                    acceptor._cancel_pumps_bounded((root,)))
                await asyncio.wait_for(child_started.wait(), 1)
                # Queue the root's completion before cancelling the helper.
                # Its wait is interrupted, but the root task runs first and is
                # already done with a SecureTaskPending(child) when the helper
                # catches cancellation and inspects the completed set.
                finish_root.set()
                helper.cancel()
                with self.assertRaises(SecureTaskPending) as captured:
                    await asyncio.wait_for(helper, 1)
                # This mirrors _proxy's catch path: the incomplete root remains
                # attached until its completion callback discovers the child.
                acceptor._retain_connection_tasks(connection, captured.exception.tasks)
                observed = (await asyncio.gather(root, return_exceptions=True))[0]
                self.assertIsInstance(observed, SecureTaskPending)
                child = child_tasks[0]
                self.assertTrue(root.done())
                self.assertEqual(captured.exception.tasks, (child,))
                self.assertIn(child, connection.tasks)
                self.assertIn(child, connection.watched_tasks)
                self.assertFalse(child.done())
                self.assertTrue(unavailable)
            finally:
                finish_root.set()
                release_child.set()
                if helper is not None and not helper.done():
                    helper.cancel()
                    await asyncio.gather(helper, return_exceptions=True)
                await asyncio.gather(root, return_exceptions=True)
                if child_tasks:
                    await asyncio.wait_for(child_tasks[0], 1)
                retirement_hold.cancel()
                await asyncio.gather(retirement_hold, return_exceptions=True)

    async def test_nested_observed_pending_pump_keeps_gate_reservation_until_retired(self):
        class Reservation:
            def __init__(self):
                self.releases = 0

            def release(self):
                self.releases += 1

        class Controller:
            def __init__(self):
                self.reservations = []

            def reserve_pending(self, owner):
                reservation = Reservation()
                self.reservations.append(reservation)
                return reservation

        with tempfile.TemporaryDirectory() as temporary:
            os.chmod(temporary, 0o700)
            backend_path = os.path.join(temporary, "backend.sock")

            async def backend_client(reader, writer):
                try:
                    await reader.read()
                finally:
                    writer.close()
                    await writer.wait_closed()

            backend_server = await asyncio.start_unix_server(
                backend_client, path=backend_path)
            controller = Controller()
            unavailable = []
            acceptor = SecureAcceptor(
                listen_endpoint="127.0.0.1:0",
                allowed_listen_addresses=("127.0.0.1",),
                backend_socket_path=backend_path,
                private_directory=temporary,
                listener_slots=1,
                connection_controller=controller,
                on_unavailable=lambda: unavailable.append(True),
            )
            port = await acceptor.start()
            writer = None
            child_started, cancellation_seen = asyncio.Event(), asyncio.Event()
            release_child = asyncio.Event()
            injected = False
            original_pump = acceptor._pump

            async def resistant_leaf():
                child_started.set()
                try:
                    await release_child.wait()
                except asyncio.CancelledError:
                    cancellation_seen.set()
                    await release_child.wait()

            async def middle_layer():
                leaf = asyncio.create_task(resistant_leaf())
                await child_started.wait()
                raise SecureTaskPending((leaf,), "nested pending leaf")

            async def pending_pump(source, destination):
                nonlocal injected
                if injected:
                    await original_pump(source, destination)
                    return
                injected = True
                middle = asyncio.create_task(middle_layer())
                observed = await asyncio.gather(middle, return_exceptions=True)
                self.assertIsInstance(observed[0], SecureTaskPending)
                raise SecureTaskPending((middle,), "completed wrapper retained a child")

            acceptor._pump = pending_pump
            with patch.object(secure_transport,
                              "MAX_CANCELLATION_GRACE_SECONDS", 0.2):
                try:
                    _, writer = await asyncio.open_connection("127.0.0.1", port)
                    await asyncio.wait_for(child_started.wait(), 1)
                    await asyncio.wait_for(cancellation_seen.wait(), 1)

                    async def retirement_started():
                        deadline = asyncio.get_running_loop().time() + 1
                        while not any(connection.retirement_task is not None
                                      for connection in acceptor._connections):
                            if asyncio.get_running_loop().time() >= deadline:
                                self.fail("gate did not retain its pending child owner")
                            await asyncio.sleep(0.001)

                    await asyncio.wait_for(retirement_started(), 1)
                    self.assertEqual(len(controller.reservations), 1)
                    reservation = controller.reservations[0]
                    connection = next(iter(acceptor._connections))
                    self.assertEqual(reservation.releases, 0)
                    self.assertEqual(acceptor._active, 1)
                    self.assertEqual(len(acceptor._connections), 1)
                    self.assertGreaterEqual(connection.remote.fileno(), 0)
                    self.assertGreaterEqual(connection.backend.fileno(), 0)
                    self.assertFalse(await acceptor.wait_for_idle(0.01))
                    self.assertTrue(unavailable)

                    release_child.set()
                    self.assertTrue(await asyncio.wait_for(
                        acceptor.wait_for_idle(0.2), timeout=0.5))
                    self.assertEqual(reservation.releases, 1)
                    self.assertEqual(acceptor._active, 0)
                    self.assertFalse(acceptor._connections)
                    self.assertEqual(connection.remote.fileno(), -1)
                    self.assertEqual(connection.backend.fileno(), -1)
                finally:
                    release_child.set()
                    if writer is not None:
                        writer.close()
                        await writer.wait_closed()
                    try:
                        if acceptor._connections:
                            await asyncio.wait_for(acceptor.wait_for_idle(0.2), timeout=0.5)
                        await acceptor.stop()
                    finally:
                        backend_server.close()
                        await backend_server.wait_closed()
