"""Linux-only protected role credential file operations."""

from __future__ import annotations

import os
import stat
from pathlib import Path

from .errors import StorageError


DIRECTORY_MODE = 0o700
PRIVATE_FILE_MODE = 0o600
MAX_CREDENTIAL_FILE_BYTES = 1024 * 1024


def _check_path_stat(info, *, expected_uid: int, mode: int, directory: bool, label: str):
    if info.st_uid != expected_uid:
        raise StorageError(f"{label} owner does not match daemon UID")
    if stat.S_ISLNK(info.st_mode):
        raise StorageError(f"{label} must not be a symlink")
    if directory and not stat.S_ISDIR(info.st_mode):
        raise StorageError(f"{label} is not a directory")
    if not directory and not stat.S_ISREG(info.st_mode):
        raise StorageError(f"{label} is not a regular file")
    if stat.S_IMODE(info.st_mode) != mode:
        raise StorageError(f"{label} permissions must be exactly {mode:04o}")


def _absolute(path: str | os.PathLike) -> Path:
    try:
        return Path(os.path.abspath(os.fspath(path)))
    except (TypeError, ValueError, OSError) as error:
        raise StorageError("credential path is invalid") from error


def _relative_components(root: Path, path: Path) -> tuple[str, ...]:
    try:
        relative = path.relative_to(root)
    except ValueError as error:
        raise StorageError("credential path must remain inside protected root") from error
    parts = relative.parts
    if not parts or any(part in ("", ".", "..") for part in parts):
        raise StorageError("credential path contains an unsafe component")
    return parts


def _directory_flags():
    return (os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | os.O_NOFOLLOW
            | getattr(os, "O_CLOEXEC", 0))


def _open_directory_chain(path: Path, *, expected_uid: int) -> int:
    """Open every component without following links and protect the final root."""
    if not path.is_absolute():
        raise StorageError("credential root must be absolute")
    descriptor = os.open(os.sep, _directory_flags())
    try:
        components = path.parts[1:]
        if not components:
            raise StorageError("filesystem root cannot be a credential root")
        for index, component in enumerate(components):
            if component in ("", ".", ".."):
                raise StorageError("credential root contains an unsafe component")
            child = os.open(component, _directory_flags(), dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
            info = os.fstat(descriptor)
            if not stat.S_ISDIR(info.st_mode):
                raise StorageError("credential path component is not a directory")
            if index == len(components) - 1:
                _check_path_stat(info, expected_uid=expected_uid, mode=DIRECTORY_MODE,
                                 directory=True, label="credential root")
        return descriptor
    except OSError as error:
        os.close(descriptor)
        raise StorageError("credential root path cannot be opened without following links") from error
    except BaseException:
        os.close(descriptor)
        raise


def _open_parent(root: Path, target: Path, *, expected_uid: int) -> tuple[int, str]:
    parts = _relative_components(root, target)
    descriptor = _open_directory_chain(root, expected_uid=expected_uid)
    try:
        for component in parts[:-1]:
            child = os.open(component, _directory_flags(), dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
            _check_path_stat(os.fstat(descriptor), expected_uid=expected_uid,
                             mode=DIRECTORY_MODE, directory=True,
                             label="credential directory")
        return descriptor, parts[-1]
    except OSError as error:
        os.close(descriptor)
        raise StorageError("credential directory cannot be opened safely") from error
    except BaseException:
        os.close(descriptor)
        raise


def _validate_runtime(expected_uid: int, max_bytes: int):
    if os.name != "posix" or not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "geteuid"):
        raise StorageError("protected credentials require Linux/POSIX no-follow support")
    if type(expected_uid) is not int or expected_uid != os.geteuid():
        raise StorageError("credential UID must be the daemon effective UID")
    if type(max_bytes) is not int or not 1 <= max_bytes <= MAX_CREDENTIAL_FILE_BYTES:
        raise ValueError("credential file bound is invalid")


def safe_read(path: str | os.PathLike, *, root: str | os.PathLike,
              expected_uid: int, max_bytes: int) -> bytes:
    """Read a 0600 regular file below daemon-owned 0700 directories."""
    _validate_runtime(expected_uid, max_bytes)
    base, target = _absolute(root), _absolute(path)
    parent_fd, filename = _open_parent(base, target, expected_uid=expected_uid)
    try:
        flags = (os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_NONBLOCK", 0)
                 | getattr(os, "O_CLOEXEC", 0))
        descriptor = os.open(filename, flags, dir_fd=parent_fd)
        try:
            _check_path_stat(os.fstat(descriptor), expected_uid=expected_uid,
                             mode=PRIVATE_FILE_MODE, directory=False,
                             label="credential file")
            with os.fdopen(descriptor, "rb", closefd=False) as stream:
                data = stream.read(max_bytes + 1)
            if len(data) > max_bytes:
                raise StorageError("credential file exceeds its configured size bound")
            return data
        finally:
            os.close(descriptor)
    except OSError as error:
        raise StorageError("credential file cannot be opened safely") from error
    finally:
        os.close(parent_fd)


def safe_write(path: str | os.PathLike, data: bytes, *, root: str | os.PathLike,
               expected_uid: int, max_bytes: int) -> None:
    """Create a new private file without following links or replacing keys."""
    _validate_runtime(expected_uid, max_bytes)
    if type(data) is not bytes or not 1 <= len(data) <= max_bytes:
        raise StorageError("credential data is empty or exceeds its configured size bound")
    base, target = _absolute(root), _absolute(path)
    parent_fd, filename = _open_parent(base, target, expected_uid=expected_uid)
    descriptor = None
    try:
        flags = (os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
                 | getattr(os, "O_CLOEXEC", 0))
        descriptor = os.open(filename, flags, PRIVATE_FILE_MODE, dir_fd=parent_fd)
        _check_path_stat(os.fstat(descriptor), expected_uid=expected_uid,
                         mode=PRIVATE_FILE_MODE, directory=False,
                         label="credential file")
        with os.fdopen(descriptor, "wb", closefd=False) as stream:
            stream.write(data)
            stream.flush()
            os.fsync(descriptor)
        os.fsync(parent_fd)
    except OSError as error:
        if descriptor is not None:
            try:
                os.unlink(filename, dir_fd=parent_fd)
            except OSError:
                pass
        raise StorageError("credential file cannot be written safely") from error
    except BaseException:
        if descriptor is not None:
            try:
                os.unlink(filename, dir_fd=parent_fd)
            except OSError:
                pass
        raise
    finally:
        if descriptor is not None:
            os.close(descriptor)
        os.close(parent_fd)
