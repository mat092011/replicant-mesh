import hmac
import os
import platform
import secrets
import signal
import socket
import stat
import struct
import sys
import threading
import time
from pathlib import Path

from .controller import ManagementController
from .errors import ConnectorError
from .paths import default_runtime_directory, default_state_directory, socket_path, token_path
from .storage import FileLock, StorageError, atomic_write_private, open_private_directory
from .validation import MAX_JSON_BYTES, json_bytes, new_id, strict_json_loads, valid_typed_id


MAX_CONNECTIONS = 4
MAX_OPERATION_SECONDS = 5.0
MAX_IDLE_SECONDS = 30.0
TOKEN_BYTES = 32


def _peer_uid(connection):
    if not hasattr(socket, "SO_PEERCRED"):
        raise ConnectorError("UNSUPPORTED_PLATFORM", "Linux peer credentials are unavailable")
    raw = connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
    _, uid, _ = struct.unpack("3i", raw)
    return uid


def _remove_stale_socket(path, directory_descriptor, uid):
    try:
        info = os.stat(path.name, dir_fd=directory_descriptor, follow_symlinks=False)
    except FileNotFoundError:
        return
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISSOCK(info.st_mode):
        raise StorageError("unsafe non-socket entry exists at management socket path")
    if info.st_uid != uid or stat.S_IMODE(info.st_mode) != 0o600:
        raise StorageError("stale management socket has unsafe owner or mode")
    os.unlink(path.name, dir_fd=directory_descriptor)


def _receive_exact(connection, size, *, deadline, allow_idle=False):
    data = bytearray()
    while len(data) < size:
        if allow_idle and not data:
            connection.settimeout(MAX_IDLE_SECONDS)
        else:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("management operation deadline exceeded")
            connection.settimeout(remaining)
        try:
            chunk = connection.recv(size - len(data))
        except socket.timeout as error:
            if allow_idle and not data:
                return None
            raise TimeoutError("management operation deadline exceeded") from error
        if not chunk:
            if not data and allow_idle:
                return None
            raise ConnectionError("management peer closed a partial frame")
        data.extend(chunk)
        if allow_idle and data:
            deadline = time.monotonic() + MAX_OPERATION_SECONDS
            allow_idle = False
    return bytes(data), deadline


def _receive_frame(connection):
    header_result = _receive_exact(connection, 4, deadline=0, allow_idle=True)
    if header_result is None:
        return None
    header, deadline = header_result
    length = struct.unpack("!I", header)[0]
    if length < 1 or length > MAX_JSON_BYTES:
        raise ValueError("management frame length is invalid")
    body_result = _receive_exact(connection, length, deadline=deadline)
    body, _ = body_result
    return body


def _send_frame(connection, value, deadline):
    payload = json_bytes(value, maximum_bytes=MAX_JSON_BYTES)
    frame = struct.pack("!I", len(payload)) + payload
    while frame:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("management operation deadline exceeded")
        connection.settimeout(remaining)
        try:
            sent = connection.send(frame)
        except socket.timeout as error:
            raise TimeoutError("management operation deadline exceeded") from error
        if sent <= 0:
            raise ConnectionError("management response could not be sent")
        frame = frame[sent:]


class DaemonServer:
    def __init__(self, *, runtime_directory=None, state_directory=None, controller=None):
        if not sys.platform.startswith("linux") or not hasattr(socket, "AF_UNIX"):
            raise StorageError("participant management daemon is supported only on Linux AF_UNIX")
        self.runtime_directory = Path(runtime_directory or default_runtime_directory())
        self.state_directory = Path(state_directory or default_state_directory())
        self.uid = os.getuid()
        self.address = socket_path(self.runtime_directory)
        self.controller = controller
        self._runtime_fd = None
        self._daemon_lock = None
        self.listener = None
        self._socket_inode = None
        self._cleanup_lock = threading.Lock()
        self._cleanup_done = False
        self._close_lock = threading.Lock()
        self._closed = False
        self._stop = threading.Event()
        self._slots = threading.BoundedSemaphore(MAX_CONNECTIONS)
        self._threads = set()
        self.token = secrets.token_hex(TOKEN_BYTES)
        try:
            if len(os.fsencode(self.address)) >= 104:
                raise StorageError("AF_UNIX management socket path exceeds the Linux path bound")
            self._runtime_fd = open_private_directory(self.runtime_directory, create=True,
                                                      uid=self.uid)
            self._daemon_lock = FileLock(self.runtime_directory / "daemon.lock", uid=self.uid,
                                         timeout=0).acquire()
            if self.controller is None:
                self.controller = ManagementController(state_directory=self.state_directory)
            atomic_write_private(token_path(self.runtime_directory),
                                 (self.token + "\n").encode("ascii"), uid=self.uid)
            _remove_stale_socket(self.address, self._runtime_fd, self.uid)
            self.listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self.listener.bind(os.fspath(self.address))
            bound_info = os.stat(self.address, follow_symlinks=False)
            self._socket_inode = (bound_info.st_dev, bound_info.st_ino)
            os.chmod(self.address, 0o600, follow_symlinks=False)
            info = os.stat(self.address, follow_symlinks=False)
            if (not stat.S_ISSOCK(info.st_mode) or info.st_uid != self.uid
                    or stat.S_IMODE(info.st_mode) != 0o600):
                raise StorageError("management socket permissions could not be verified")
            self.listener.listen(MAX_CONNECTIONS)
            self.listener.settimeout(0.2)
        except Exception:
            self._cleanup_files()
            if self.controller is not None:
                self.controller.shutdown(wait_seconds=0)
            raise

    def _cleanup_files(self):
        with self._cleanup_lock:
            if self._cleanup_done:
                return
            self._cleanup_done = True
            if self.listener is not None:
                try:
                    self.listener.close()
                except OSError:
                    pass
                self.listener = None
            if self._runtime_fd is not None:
                try:
                    info = os.stat(self.address.name, dir_fd=self._runtime_fd,
                                   follow_symlinks=False)
                    if (stat.S_ISSOCK(info.st_mode) and info.st_uid == self.uid
                            and self._socket_inode == (info.st_dev, info.st_ino)):
                        os.unlink(self.address.name, dir_fd=self._runtime_fd)
                except OSError:
                    pass
                try:
                    token_info = os.stat(token_path(self.runtime_directory).name,
                                         dir_fd=self._runtime_fd, follow_symlinks=False)
                    if (stat.S_ISREG(token_info.st_mode) and token_info.st_uid == self.uid
                            and stat.S_IMODE(token_info.st_mode) == 0o600):
                        token_fd = os.open(token_path(self.runtime_directory).name,
                                           os.O_RDONLY | os.O_NOFOLLOW,
                                           dir_fd=self._runtime_fd)
                        try:
                            token_current = os.read(token_fd, TOKEN_BYTES * 2 + 2)
                            token_check = os.fstat(token_fd)
                        finally:
                            os.close(token_fd)
                        if ((token_check.st_dev, token_check.st_ino) ==
                                (token_info.st_dev, token_info.st_ino)
                                and token_current == (self.token + "\n").encode("ascii")):
                            os.unlink(token_path(self.runtime_directory).name,
                                      dir_fd=self._runtime_fd)
                except OSError:
                    pass
                try:
                    os.close(self._runtime_fd)
                except OSError:
                    pass
                self._runtime_fd = None
            if self._daemon_lock is not None:
                self._daemon_lock.release()
                self._daemon_lock = None

    def _reply_error(self, connection, operation_id, code, message, deadline):
        response = {"version": 1, "operation_id": operation_id, "ok": False,
                    "error": {"code": str(code)[:64], "message": str(message)[:256]}}
        _send_frame(connection, response, deadline)

    def _connection(self, connection):
        try:
            if _peer_uid(connection) != self.uid:
                return
            while not self._stop.is_set():
                try:
                    body = _receive_frame(connection)
                    if body is None:
                        return
                    request = strict_json_loads(body)
                    if (type(request) is not dict or set(request) !=
                            {"version", "operation_id", "token", "action", "payload"}):
                        raise ValueError("management request shape is invalid")
                    operation_id = request["operation_id"]
                    if (type(request["version"]) is not int or request["version"] != 1
                            or not valid_typed_id(operation_id, "op")
                            or not isinstance(request["token"], str)
                            or not isinstance(request["action"], str)
                            or type(request["payload"]) is not dict):
                        raise ValueError("management request fields are invalid")
                    deadline = time.monotonic() + MAX_OPERATION_SECONDS
                    if not hmac.compare_digest(request["token"], self.token):
                        self._reply_error(connection, operation_id, "UNAUTHENTICATED",
                                          "management token rejected", deadline)
                        return
                    if len(request["action"]) > 40:
                        raise ValueError("management action is invalid")
                    try:
                        result = self.controller.handle(request["action"], request["payload"])
                        response = {"version": 1, "operation_id": operation_id,
                                    "ok": True, "result": result}
                    except ConnectorError as error:
                        response = {"version": 1, "operation_id": operation_id,
                                    "ok": False, "error": {"code": error.code,
                                                              "message": error.message}}
                    except (ValueError, TypeError):
                        response = {"version": 1, "operation_id": operation_id,
                                    "ok": False, "error": {"code": "INVALID_ARGUMENT",
                                                              "message": "management request rejected"}}
                    except Exception:
                        response = {"version": 1, "operation_id": operation_id,
                                    "ok": False, "error": {"code": "INTERNAL",
                                                              "message": "management action failed"}}
                    if time.monotonic() > deadline:
                        self._reply_error(connection, operation_id, "DEADLINE_EXCEEDED",
                                          "management operation timed out; outcome may be ambiguous",
                                          time.monotonic() + 0.25)
                        return
                    try:
                        _send_frame(connection, response, deadline)
                    except ValueError:
                        self._reply_error(connection, operation_id, "RESOURCE_EXHAUSTED",
                                          "management response exceeds its bound",
                                          time.monotonic() + 0.25)
                        return
                except (ConnectionError, OSError, TimeoutError, ValueError, UnicodeError):
                    return
        finally:
            try:
                connection.close()
            finally:
                self._slots.release()
                self._threads.discard(threading.current_thread())

    def serve_forever(self, stop_event=None):
        stop_event = stop_event or self._stop
        try:
            while not stop_event.is_set():
                try:
                    connection, _ = self.listener.accept()
                except socket.timeout:
                    self.controller.check_telemetry()
                    continue
                except OSError:
                    if stop_event.is_set():
                        break
                    raise
                if not self._slots.acquire(blocking=False):
                    connection.close()
                    continue
                thread = threading.Thread(target=self._connection, args=(connection,),
                                          name="connector-management", daemon=True)
                self._threads.add(thread)
                thread.start()
        finally:
            self.close()

    def close(self):
        with self._close_lock:
            if self._closed:
                return
            self._closed = True
        self._stop.set()
        if self.listener is not None:
            try:
                self.listener.close()
            except OSError:
                pass
        for thread in tuple(self._threads):
            thread.join(timeout=0.1)
        try:
            self.controller.shutdown(wait_seconds=1)
        finally:
            self._cleanup_files()


def run_daemon(*, runtime_directory=None, state_directory=None):
    server = DaemonServer(runtime_directory=runtime_directory,
                          state_directory=state_directory)
    stop = threading.Event()
    previous = {}

    def request_stop(*_):
        stop.set()

    for signum in (signal.SIGTERM, signal.SIGINT):
        previous[signum] = signal.signal(signum, request_stop)
    try:
        server.serve_forever(stop)
    finally:
        server.close()
        for signum, handler in previous.items():
            signal.signal(signum, handler)
    return 0
