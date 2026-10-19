import errno
import os
from pathlib import Path
import secrets
import stat
import sys
import time

from .validation import json_bytes, strict_json_loads


class StorageError(Exception):
    pass


def _require_linux():
    if not sys.platform.startswith("linux") or not hasattr(os, "O_NOFOLLOW"):
        raise StorageError("secure connector storage requires Linux openat/O_NOFOLLOW support")


def _directory_flags():
    return os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | os.O_NOFOLLOW


def open_private_directory(path, *, create=False, uid=None):
    _require_linux()
    uid = os.getuid() if uid is None else uid
    absolute = Path(os.path.abspath(os.fspath(path)))
    descriptor = os.open(absolute.anchor, _directory_flags())
    try:
        parts = absolute.parts[1:]
        if not parts:
            raise StorageError("filesystem root cannot be used as connector storage")
        for part in parts:
            next_descriptor = None
            try:
                next_descriptor = os.open(part, _directory_flags(), dir_fd=descriptor)
            except FileNotFoundError:
                if not create:
                    raise StorageError("connector directory does not exist")
                try:
                    os.mkdir(part, 0o700, dir_fd=descriptor)
                except FileExistsError:
                    pass
                next_descriptor = os.open(part, _directory_flags(), dir_fd=descriptor)
            try:
                info = os.fstat(next_descriptor)
                if not stat.S_ISDIR(info.st_mode):
                    raise StorageError("connector path contains a non-directory")
                descriptor_info = os.stat(part, dir_fd=descriptor, follow_symlinks=False)
                if (stat.S_ISLNK(descriptor_info.st_mode)
                        or (descriptor_info.st_dev, descriptor_info.st_ino)
                        != (info.st_dev, info.st_ino)):
                    raise StorageError("connector path changed during secure open")
            except BaseException:
                os.close(next_descriptor)
                next_descriptor = None
                raise
            os.close(descriptor)
            descriptor = next_descriptor
            next_descriptor = None
        final = os.fstat(descriptor)
        if final.st_uid != uid or stat.S_IMODE(final.st_mode) != 0o700:
            raise StorageError("connector directory must be owned by this UID with mode 0700")
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _check_file(info, uid, *, exact_mode=None, maximum_size=None):
    if not stat.S_ISREG(info.st_mode) or info.st_uid != uid:
        raise StorageError("connector file must be a regular file owned by this UID")
    mode = stat.S_IMODE(info.st_mode)
    if (exact_mode is not None and mode != exact_mode) or (mode & 0o077):
        raise StorageError("connector file must have private owner-only permissions")
    if maximum_size is not None and info.st_size > maximum_size:
        raise StorageError("connector file exceeds its size bound")


def read_private_file(path, *, maximum_size=65_536, uid=None, exact_mode=0o600):
    _require_linux()
    uid = os.getuid() if uid is None else uid
    target = Path(os.path.abspath(os.fspath(path)))
    directory = open_private_directory(target.parent, uid=uid)
    try:
        descriptor = os.open(
            target.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
            dir_fd=directory)
        try:
            _check_file(os.fstat(descriptor), uid, exact_mode=exact_mode,
                        maximum_size=maximum_size)
            chunks = []
            total = 0
            while True:
                chunk = os.read(descriptor, min(8192, maximum_size + 1 - total))
                if not chunk:
                    break
                total += len(chunk)
                if total > maximum_size:
                    raise StorageError("connector file exceeds its size bound")
                chunks.append(chunk)
            return b"".join(chunks)
        finally:
            os.close(descriptor)
    except OSError as error:
        if error.errno in (errno.ELOOP, errno.ENOTDIR):
            raise StorageError("symlink or unsafe connector file refused") from error
        raise
    finally:
        os.close(directory)


def atomic_write_private(path, data, *, uid=None, exact_mode=0o600):
    _require_linux()
    uid = os.getuid() if uid is None else uid
    target = Path(os.path.abspath(os.fspath(path)))
    directory = open_private_directory(target.parent, uid=uid)
    temporary = f".{target.name}.{secrets.token_hex(8)}.tmp"
    try:
        try:
            existing = os.stat(target.name, dir_fd=directory, follow_symlinks=False)
        except FileNotFoundError:
            existing = None
        if existing is not None:
            if stat.S_ISLNK(existing.st_mode):
                raise StorageError("symlink connector file refused")
            _check_file(existing, uid, exact_mode=exact_mode)
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                             exact_mode, dir_fd=directory)
        try:
            view = memoryview(data)
            while view:
                written = os.write(descriptor, view)
                if written <= 0:
                    raise StorageError("short connector file write")
                view = view[written:]
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.replace(temporary, target.name, src_dir_fd=directory, dst_dir_fd=directory)
        os.fsync(directory)
    except OSError as error:
        if error.errno in (errno.ELOOP, errno.ENOTDIR):
            raise StorageError("symlink or unsafe connector file refused") from error
        raise
    finally:
        try:
            try:
                os.unlink(temporary, dir_fd=directory)
            except FileNotFoundError:
                pass
        finally:
            os.close(directory)


def atomic_write_json(path, value, *, uid=None):
    try:
        data = json_bytes(value)
    except (TypeError, ValueError) as error:
        raise StorageError("state is not bounded JSON") from error
    atomic_write_private(path, data, uid=uid)


def read_private_json(path, *, maximum_size=65_536, uid=None):
    data = read_private_file(path, maximum_size=maximum_size, uid=uid)
    try:
        return strict_json_loads(data, maximum_bytes=maximum_size)
    except (TypeError, ValueError, UnicodeError) as error:
        raise StorageError("connector state is malformed") from error


class FileLock:
    def __init__(self, path, *, uid=None, timeout=0):
        _require_linux()
        self.path = Path(os.path.abspath(os.fspath(path)))
        self.uid = os.getuid() if uid is None else uid
        self.timeout = timeout
        self.descriptor = None

    def acquire(self):
        import fcntl

        directory = open_private_directory(self.path.parent, uid=self.uid)
        try:
            descriptor = os.open(self.path.name, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW,
                                 0o600, dir_fd=directory)
            try:
                _check_file(os.fstat(descriptor), self.uid, exact_mode=0o600)
            except Exception:
                os.close(descriptor)
                raise
        finally:
            os.close(directory)
        deadline = time.monotonic() + self.timeout
        while True:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                self.descriptor = descriptor
                return self
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    os.close(descriptor)
                    raise StorageError("connector controller lock is already held")
                time.sleep(min(0.025, max(0.0, deadline - time.monotonic())))
            except Exception:
                os.close(descriptor)
                raise

    def release(self):
        if self.descriptor is not None:
            import fcntl

            fcntl.flock(self.descriptor, fcntl.LOCK_UN)
            os.close(self.descriptor)
            self.descriptor = None

    def __enter__(self):
        return self.acquire()

    def __exit__(self, exc_type, exc_value, traceback):
        self.release()


class FileStateStore:
    def __init__(self, directory, *, initial_state, uid=None):
        _require_linux()
        self.directory = Path(os.path.abspath(os.fspath(directory)))
        self.uid = os.getuid() if uid is None else uid
        directory_fd = open_private_directory(self.directory, create=True, uid=self.uid)
        os.close(directory_fd)
        self.path = self.directory / "daemon-state.json"
        self.lock_path = self.directory / "daemon-state.lock"
        self._thread_lock = __import__("threading").RLock()
        with self._thread_lock, FileLock(self.lock_path, uid=self.uid, timeout=1):
            try:
                self._load_unlocked()
            except FileNotFoundError:
                atomic_write_json(self.path, initial_state, uid=self.uid)

    def _load_unlocked(self):
        return read_private_json(self.path, uid=self.uid)

    def load(self):
        with self._thread_lock, FileLock(self.lock_path, uid=self.uid, timeout=1):
            return self._load_unlocked()

    def save(self, state):
        with self._thread_lock, FileLock(self.lock_path, uid=self.uid, timeout=1):
            atomic_write_json(self.path, state, uid=self.uid)


class MemoryStateStore:
    def __init__(self, initial_state):
        import copy
        import threading

        self._copy = copy.deepcopy
        self._lock = threading.RLock()
        self._state = self._copy(initial_state)

    def load(self):
        with self._lock:
            return self._copy(self._state)

    def save(self, state):
        with self._lock:
            self._state = self._copy(state)
