"""Bounded opaque TCP-to-private-UDS gate for the secure gRPC backend.

The gate never terminates TLS. It holds one shared node handshake reservation
until the backend reports a certificate- and grant-authorized RPC on the
unique UDS client path, then forwards the connection as an established stream.
"""

import asyncio
import inspect
import os
from pathlib import Path
import secrets
import socket
import stat
import time

from . import secure_transport as _secure_transport
from .secure_connector import SecureConnectorPending
from .secure_transport import (
    SecureTaskPending,
    _pending_task_descendants,
    _retain_tasks,
    parse_fixed_ipv4_endpoint,
)


_PENDING_ERRORS = (SecureTaskPending, SecureConnectorPending)


MAX_PROXY_CHUNK_BYTES = 64 * 1024


class SecureAcceptorError(RuntimeError):
    """The bounded TLS byte-forwarding gate could not safely admit a peer."""


def validate_private_unix_directory(directory):
    path = Path(directory)
    try:
        info = path.lstat()
    except OSError:
        raise ValueError("secure UDS directory must already exist") from None
    if (stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode)
            or stat.S_IMODE(info.st_mode) != 0o700
            or not hasattr(os, "getuid") or info.st_uid != os.getuid()):
        raise ValueError("secure UDS directory must be owner-owned mode 0700")
    if len(os.fsencode(path.resolve())) > 70:
        raise ValueError("secure UDS directory path is too long for bounded socket names")
    return path.resolve()


def new_private_socket_path(directory, *, name="backend.sock"):
    root = validate_private_unix_directory(directory)
    if (type(name) is not str or not name or "/" in name or "\\" in name
            or len(os.fsencode(root / name)) > 100):
        raise ValueError("secure UDS socket path is invalid or too long")
    return root / name


async def _wait_for_proxy_pumps(tasks):
    """Observe both half-close completion and errors without masking failures."""
    pending = set(tasks)
    while pending:
        done, pending = await asyncio.wait(
            pending, return_when=asyncio.FIRST_COMPLETED)
        for task in done:
            if task.cancelled():
                raise asyncio.CancelledError
            error = task.exception()
            if error is not None:
                raise error


class _GateConnection:
    def __init__(self, acceptor, remote, peer_address, pending):
        self.acceptor = acceptor
        self.remote = remote
        self.peer_address = peer_address
        self.backend = None
        self.connection_id = secrets.token_hex(8)
        self.client_directory = acceptor.private_directory / f"c-{self.connection_id}"
        self.client_path = self.client_directory / "gate-client.sock"
        self.pending = pending
        self.pending_deadline = (
            time.monotonic() + _secure_transport.HANDSHAKE_TIMEOUT_SECONDS)
        self.established = False
        self.rejecting = False
        self.authenticated = asyncio.Event()
        self.authorization_lock = asyncio.Lock()
        self.tasks = set()
        self.pump_tasks = set()
        self.watched_tasks = set()
        self.retirement_task = None
        self.retired = False


class SecureAcceptor:
    """Expose one numeric TCP endpoint and transparently forward opaque TLS."""

    def __init__(self, *, listen_endpoint, allowed_listen_addresses,
                 backend_socket_path, private_directory, listener_slots,
                 connection_controller, on_unavailable):
        host, port = parse_fixed_ipv4_endpoint(
            listen_endpoint, allowed_listen_addresses, listen=True)
        if type(listener_slots) is not int or listener_slots not in (1, 2):
            raise ValueError("secure acceptor requires one or two statically reserved slots")
        if (connection_controller is None or not callable(
                getattr(connection_controller, "reserve_pending", None))):
            raise ValueError("secure acceptor requires the shared node pending-handshake budget")
        if not callable(on_unavailable):
            raise ValueError("secure acceptor requires an unavailable-state callback")
        self.host, self.requested_port = host, port
        self.backend_socket_path = Path(backend_socket_path)
        self.private_directory = validate_private_unix_directory(private_directory)
        if (self.backend_socket_path.parent != self.private_directory
                or len(os.fsencode(self.backend_socket_path)) > 100):
            raise ValueError("gRPC backend UDS path must be a short child of the private directory")
        self.listener_slots = listener_slots
        self.connection_controller = connection_controller
        self._on_unavailable = on_unavailable
        self.listener = None
        self.port = None
        self._accept_task = None
        self._connections = set()
        self._idle_event = asyncio.Event()
        self._idle_event.set()
        self._cleanup_tasks = set()
        self._peer_paths = {}
        self._active = 0
        self._stopping = False
        self._paused = False
        self._stopped = False

    async def start(self):
        if self.listener is not None or self._stopped:
            raise SecureAcceptorError("secure acceptor cannot be started twice")
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.setblocking(False)
            sock.bind((self.host, self.requested_port))
            sock.listen(self.listener_slots)
            self.listener = sock
            self.port = sock.getsockname()[1]
            self._accept_task = asyncio.create_task(self._accept_loop())
            self._accept_task.add_done_callback(self._accept_loop_done)
            return self.port
        except BaseException:
            sock.close()
            raise

    def _accept_loop_done(self, task):
        if task.cancelled():
            return
        try:
            failed = task.exception() is not None
        except BaseException:
            failed = True
        if failed:
            self._signal_unavailable()

    def _signal_unavailable(self):
        self._stopping = True
        self.pause()
        try:
            self._on_unavailable()
        except Exception:
            pass

    async def _accept_loop(self):
        loop = asyncio.get_running_loop()
        while not self._stopping:
            try:
                remote, peer_address = await loop.sock_accept(self.listener)
            except asyncio.CancelledError:
                raise
            except OSError:
                if self._stopping or self._paused:
                    return
                raise
            remote.setblocking(False)
            if self._active >= self.listener_slots:
                remote.close()
                continue
            try:
                pending = self.connection_controller.reserve_pending(
                    f"inbound:{self.host}:{self.port}:{peer_address!r}")
            except Exception:
                remote.close()
                continue
            if inspect.isawaitable(pending):
                close = getattr(pending, "close", None)
                if callable(close):
                    close()
                remote.close()
                continue
            if pending is None or not callable(getattr(pending, "release", None)):
                remote.close()
                continue
            self._active += 1
            connection = _GateConnection(self, remote, peer_address, pending)
            self._idle_event.clear()
            self._connections.add(connection)
            task = asyncio.create_task(self._proxy(connection))
            connection.tasks.add(task)
            task.add_done_callback(lambda completed: self._proxy_done(connection, completed))

    def _proxy_done(self, connection, task):
        error = self._observe_task(connection, task)
        if error:
            self._signal_unavailable()

    @staticmethod
    def _observe_task(connection, task):
        error = None
        if not task.cancelled():
            try:
                error = task.exception()
            except BaseException as caught:
                error = caught
        if isinstance(error, _PENDING_ERRORS):
            connection.acceptor._retain_connection_tasks(connection, error.tasks)
        connection.tasks.discard(task)
        connection.acceptor._resume_retirement_if_idle(connection)
        return error

    def _retain_connection_tasks(self, connection, tasks):
        roots = tuple(tasks)
        descendants = tuple(_pending_task_descendants(roots))
        connection.tasks.update(roots)
        connection.tasks.update(descendants)
        _retain_tasks((*roots, *descendants))
        for task in descendants:
            if task not in connection.watched_tasks:
                connection.watched_tasks.add(task)
                task.add_done_callback(
                    lambda done, owner=connection: self._observe_task(owner, done))
        if descendants:
            self._signal_unavailable()
        return descendants

    def _connection_live_tasks(self, connection):
        roots = tuple(task for task in connection.tasks
                      if task is not asyncio.current_task())
        descendants = tuple(_pending_task_descendants(roots))
        connection.tasks.update(descendants)
        _retain_tasks(descendants)
        for task in descendants:
            if task not in connection.watched_tasks:
                connection.watched_tasks.add(task)
                task.add_done_callback(
                    lambda done, owner=connection: self._observe_task(owner, done))
        live = {task for task in roots if not task.done()}
        live.update(descendants)
        return tuple(live)

    def _resume_retirement_if_idle(self, connection):
        if connection.retired or self._connection_live_tasks(connection):
            return
        task = connection.retirement_task
        if task is not None and not task.done():
            return
        cleanup = asyncio.create_task(self._retire_after_tasks(connection, ()))
        connection.retirement_task = cleanup
        self._cleanup_tasks.add(cleanup)
        _retain_tasks((cleanup,))
        cleanup.add_done_callback(self._cleanup_done)

    async def _proxy(self, connection):
        loop = asyncio.get_running_loop()
        try:
            connection.client_directory.mkdir(mode=0o700)
            os.chmod(connection.client_directory, 0o700)
            self._peer_paths[os.fspath(connection.client_path)] = connection
            backend = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            connection.backend = backend
            backend.setblocking(False)
            backend.bind(os.fspath(connection.client_path))
            os.chmod(connection.client_path, 0o600)
            remaining = connection.pending_deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("secure backend setup exceeded the handshake deadline")
            backend_connect = asyncio.create_task(
                loop.sock_connect(backend, os.fspath(self.backend_socket_path)))
            connection.tasks.add(backend_connect)
            backend_connect.add_done_callback(
                lambda done: self._observe_task(connection, done))
            done, pending = await asyncio.wait((backend_connect,), timeout=remaining)
            if pending:
                await self._cancel_pumps_bounded((backend_connect,))
                raise TimeoutError("secure backend setup exceeded the handshake deadline")
            await asyncio.gather(*done)

            inbound = asyncio.create_task(self._pump(connection.remote, backend))
            outbound = asyncio.create_task(self._pump(backend, connection.remote))
            connection.tasks.update((inbound, outbound))
            connection.pump_tasks.update((inbound, outbound))
            inbound.add_done_callback(
                lambda done: self._observe_task(connection, done))
            outbound.add_done_callback(
                lambda done: self._observe_task(connection, done))
            first_rpc = asyncio.create_task(connection.authenticated.wait())
            try:
                remaining = connection.pending_deadline - time.monotonic()
                if remaining <= 0:
                    await self._reject_connection(connection)
                    return
                done, _ = await asyncio.wait(
                    (inbound, outbound, first_rpc), timeout=remaining,
                    return_when=asyncio.FIRST_COMPLETED)
                if first_rpc not in done:
                    await self._reject_connection(connection)
                    return
            finally:
                if not first_rpc.done():
                    first_rpc.cancel()
                await self._cancel_pumps_bounded((first_rpc,))
            # A normal TCP half-close leaves the other pump alive until the
            # peer finishes reading. Any pump error exits immediately so the
            # common finalizer closes sockets and bounds sibling cancellation.
            await _wait_for_proxy_pumps((inbound, outbound))
        except asyncio.CancelledError:
            raise
        except _PENDING_ERRORS as error:
            self._retain_connection_tasks(connection, error.tasks)
            raise
        except Exception:
            # A failed accept/backend connection is closed by the common finalizer.
            return
        finally:
            await self._retire(connection)

    async def _pump(self, source, destination):
        loop = asyncio.get_running_loop()
        while True:
            data = await loop.sock_recv(source, MAX_PROXY_CHUNK_BYTES)
            if not data:
                try:
                    destination.shutdown(socket.SHUT_WR)
                except OSError:
                    pass
                return
            await loop.sock_sendall(destination, data)

    async def _cancel_pumps_bounded(self, tasks):
        roots = tuple(tasks)
        descendants = tuple(_pending_task_descendants(roots))
        live = tuple({task for task in roots if not task.done()} | set(descendants))
        for task in live:
            task.cancel()
        if not live:
            return
        try:
            done, pending = await asyncio.wait(
                live, timeout=_secure_transport.MAX_CANCELLATION_GRACE_SECONDS)
        except asyncio.CancelledError:
            done = tuple(task for task in live if task.done())
            pending = tuple(task for task in live if not task.done())
            if done:
                await asyncio.gather(*done, return_exceptions=True)
            descendants = tuple(_pending_task_descendants((*roots, *done)))
            owned = tuple(set(pending) | set(descendants))
            if owned:
                _retain_tasks(owned)
                self._signal_unavailable()
                raise SecureTaskPending(owned,
                    "secure TCP forwarding pumps did not stop within their grace")
            raise
        if done:
            await asyncio.gather(*done, return_exceptions=True)
        descendants = tuple(_pending_task_descendants((*roots, *done, *pending)))
        owned = tuple({task for task in pending if not task.done()} | set(descendants))
        if owned:
            _retain_tasks(owned)
            self._signal_unavailable()
            raise SecureTaskPending(owned,
                "secure TCP forwarding pumps did not stop within their grace")

    def _connection_for_peer(self, peer):
        if type(peer) is not str:
            return None
        for path, connection in tuple(self._peer_paths.items()):
            if path in peer:
                return connection
        return None

    async def mark_authenticated_peer(self, peer):
        """Release pending accounting only after the actual gRPC auth decision."""
        connection = self._connection_for_peer(peer)
        if connection is None:
            return False
        async with connection.authorization_lock:
            if connection.retired or connection.rejecting:
                return False
            if connection.established:
                return True
            if time.monotonic() >= connection.pending_deadline:
                connection.rejecting = True
                self._shutdown_sockets(connection)
                return False
            if connection.pending is None:
                return False
            self._release_pending(connection)
            connection.pending = None
            connection.established = True
            connection.authenticated.set()
            return True

    async def reject_unestablished_peer(self, peer):
        connection = self._connection_for_peer(peer)
        if connection is None:
            return False
        # An RPC authorization failure must leave the bounded forwarding path
        # alive long enough for gRPC to return its native status. The pending
        # slot and original deadline remain owned until EOF/deadline retirement.
        # This public path only latches rejection; internal transport failures
        # continue to use _reject_connection and hard-close immediately.
        async with connection.authorization_lock:
            if connection.established or connection.retired:
                return False
            if time.monotonic() >= connection.pending_deadline:
                connection.rejecting = True
                self._shutdown_sockets(connection)
                return True
            connection.rejecting = True
            return True

    async def _reject_connection(self, connection):
        async with connection.authorization_lock:
            if connection.established or connection.retired:
                return False
            connection.rejecting = True
            self._shutdown_sockets(connection)
            return True

    @staticmethod
    def _release_pending(connection):
        result = connection.pending.release()
        if inspect.isawaitable(result):
            close = getattr(result, "close", None)
            if callable(close):
                close()
            raise SecureAcceptorError(
                "shared pending-handshake release must complete synchronously")

    def _shutdown_sockets(self, connection):
        """Wake socket readers while their descriptors remain open."""
        for sock in (connection.remote, connection.backend):
            if sock is not None:
                try:
                    sock.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass

    def _close_sockets(self, connection):
        """Close descriptors after the connection's owned tasks are terminal."""
        for sock in (connection.remote, connection.backend):
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass

    async def _retire(self, connection):
        async with connection.authorization_lock:
            if connection.retired:
                return
            connection.rejecting = True
            # Wake socket readers but keep their descriptors alive until the
            # selector-owned recv tasks have actually completed.
            self._shutdown_sockets(connection)
        live = self._connection_live_tasks(connection)
        for task in live:
            if task not in connection.pump_tasks:
                task.cancel()
        if live:
            try:
                done, pending = await asyncio.wait(
                    live, timeout=_secure_transport.MAX_CANCELLATION_GRACE_SECONDS)
            except asyncio.CancelledError:
                pending = tuple(task for task in live if not task.done())
                if pending:
                    self._defer_retire(connection, pending)
                    raise SecureTaskPending(pending,
                        "secure proxy resources remain owned by unfinished forwarding tasks")
                await asyncio.gather(*live, return_exceptions=True)
                raise
            if pending:
                self._defer_retire(connection, pending)
                raise SecureTaskPending(pending,
                    "secure proxy resources remain owned by unfinished forwarding tasks")
            await asyncio.gather(*done, return_exceptions=True)
            descendants = self._connection_live_tasks(connection)
            if descendants:
                self._defer_retire(connection, descendants)
                raise SecureTaskPending(descendants,
                    "secure proxy child tasks still own the connection")
        await self._release_connection(connection)

    def _defer_retire(self, connection, pending):
        self._retain_connection_tasks(connection, pending)
        existing = connection.retirement_task
        if existing is not None and not existing.done():
            self._signal_unavailable()
            return
        cleanup = asyncio.create_task(self._retire_after_tasks(connection, pending))
        connection.retirement_task = cleanup
        _retain_tasks((cleanup,))
        self._cleanup_tasks.add(cleanup)
        cleanup.add_done_callback(self._cleanup_done)
        self._signal_unavailable()

    async def _retire_after_tasks(self, connection, tasks):
        self._retain_connection_tasks(connection, tasks)
        deadline = time.monotonic() + _secure_transport.MAX_CANCELLATION_GRACE_SECONDS
        while True:
            live = self._connection_live_tasks(connection)
            if not live:
                break
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                _retain_tasks(live)
                self._signal_unavailable()
                raise SecureTaskPending(live,
                    "secure proxy descendants did not retire within the bounded watchdog")
            done, pending = await asyncio.wait(live, timeout=remaining)
            if pending:
                _retain_tasks(pending)
                self._signal_unavailable()
                raise SecureTaskPending(pending,
                    "secure proxy descendants did not retire within the bounded watchdog")
            await asyncio.gather(*done, return_exceptions=True)
        try:
            await self._release_connection(connection)
        except BaseException:
            self._signal_unavailable()
            raise

    def _cleanup_done(self, task):
        self._cleanup_tasks.discard(task)
        if task.cancelled():
            self._signal_unavailable()
            return
        try:
            error = task.exception()
        except BaseException:
            error = True
        if error:
            self._signal_unavailable()

    async def _release_connection(self, connection):
        async with connection.authorization_lock:
            if connection.retired:
                return
            connection.rejecting = True
            live = self._connection_live_tasks(connection)
            if live:
                _retain_tasks(live)
                self._signal_unavailable()
                raise SecureTaskPending(live,
                    "secure connection still has owned descendants")
            self._close_sockets(connection)
            if connection.pending is not None:
                self._release_pending(connection)
                connection.pending = None
            self._peer_paths.pop(os.fspath(connection.client_path), None)
            connection.retired = True
        self._connections.discard(connection)
        self._active = max(0, self._active - 1)
        try:
            connection.client_path.unlink(missing_ok=True)
        except OSError:
            pass
        try:
            connection.client_directory.rmdir()
        except OSError:
            pass
        if not self._connections:
            self._idle_event.set()

    async def wait_for_idle(self, timeout):
        """Wait until all accepted sockets, pumps, and pending tokens are retired."""
        if (isinstance(timeout, bool) or not isinstance(timeout, (int, float))
                or not 0 <= timeout <= _secure_transport.MAX_CANCELLATION_GRACE_SECONDS):
            raise ValueError("gate idle wait must fit the secure cleanup bound")
        deadline = time.monotonic() + float(timeout)
        while self._connections:
            self._idle_event.clear()
            if not self._connections:
                self._idle_event.set()
                return True
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return False
            try:
                await asyncio.wait_for(self._idle_event.wait(), remaining)
            except TimeoutError:
                return False
        return True

    def pause(self):
        """Stop taking new peers when its protected gRPC service is unavailable."""
        self._paused = True
        if self.listener is not None:
            try:
                self.listener.close()
            finally:
                self.listener = None

    async def stop(self):
        if self._stopped:
            return
        self._stopping = True
        self.pause()
        if self._accept_task is not None and not self._accept_task.done():
            self._accept_task.cancel()
            try:
                done, pending = await asyncio.wait(
                    (self._accept_task,),
                    timeout=_secure_transport.MAX_CANCELLATION_GRACE_SECONDS)
            except asyncio.CancelledError:
                if not self._accept_task.done():
                    _retain_tasks((self._accept_task,))
                    raise SecureTaskPending((self._accept_task,),
                        "secure accept loop did not stop")
                await asyncio.gather(self._accept_task, return_exceptions=True)
                raise
            if pending:
                _retain_tasks(pending)
                raise SecureTaskPending(pending, "secure accept loop did not stop")
            await asyncio.gather(*done, return_exceptions=True)
        connections = tuple(self._connections)
        for connection in connections:
            async with connection.authorization_lock:
                if not connection.retired:
                    connection.rejecting = True
                    self._shutdown_sockets(connection)
            for task in self._connection_live_tasks(connection):
                if task not in connection.pump_tasks:
                    task.cancel()
        shutdown_deadline = (
            time.monotonic() + _secure_transport.MAX_CANCELLATION_GRACE_SECONDS)
        while True:
            connections = tuple(self._connections)
            tasks = tuple({task for connection in connections
                           for task in self._connection_live_tasks(connection)}
                          | {task for task in self._cleanup_tasks if not task.done()})
            if not tasks:
                break
            remaining = shutdown_deadline - time.monotonic()
            if remaining <= 0:
                _retain_tasks(tasks)
                self._signal_unavailable()
                raise SecureTaskPending(tasks,
                    "secure acceptor still owns unfinished proxy connections")
            done, pending = await asyncio.wait(
                tasks, timeout=remaining)
            if pending:
                _retain_tasks(pending)
                self._signal_unavailable()
                raise SecureTaskPending(pending,
                    "secure acceptor still owns unfinished proxy connections")
            await asyncio.gather(*done, return_exceptions=True)
        for connection in tuple(self._connections):
            await self._release_connection(connection)
        try:
            self.backend_socket_path.unlink(missing_ok=True)
        except OSError:
            pass
        self._stopped = True
