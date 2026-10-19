"""Protected, device-pinned C2 owner consent and startup serialization.

This store records only local owner intent. It does not authenticate enrollment,
validate a selected generation, claim boot IDs, launch processes, or establish
readiness. The constructor principal must come from trusted operator setup.
"""
from __future__ import annotations

import hashlib
import json
import os
import secrets
import stat
import threading
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from steamboat_security.errors import StorageError
from steamboat_security.files import _open_directory_chain
from steamboat_security.ids import validate_id

DOMAIN = "steamboat_c2_device_owner_consent"
VERSION = 1
MAX_STATE_BYTES = 4096
MAX_EPOCH = (1 << 63) - 1
ROLES = ("consumer", "coordinator", "host")
STATE_NAME = "owner-consent.json"
LOCK_NAME = "owner-consent.lock"
PENDING_NAME = "owner-consent.pending"
_FIELDS = {"domain", "version", "account_id", "device_id", "epoch",
           "enabled_roles", "sha256"}


def _canonical(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def _pairs(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise StorageError("owner consent document contains duplicate fields")
        value[key] = item
    return value


def _reject_number(_value):
    raise StorageError("owner consent document contains an invalid number")


def _document(account_id, device_id, epoch, enabled_roles):
    body = {"domain": DOMAIN, "version": VERSION, "account_id": account_id,
            "device_id": device_id, "epoch": epoch,
            "enabled_roles": list(enabled_roles)}
    return {**body, "sha256": hashlib.sha256(_canonical(body)).hexdigest()}


def _parse(encoded, account_id, device_id):
    if type(encoded) is not bytes or not 1 <= len(encoded) <= MAX_STATE_BYTES:
        raise StorageError("owner consent state is empty or oversized")
    try:
        raw = json.loads(encoded.decode("utf-8", "strict"), object_pairs_hook=_pairs,
                         parse_constant=_reject_number, parse_float=_reject_number)
    except StorageError:
        raise
    except (UnicodeError, ValueError, TypeError, RecursionError) as error:
        raise StorageError("owner consent state is malformed") from error
    if (type(raw) is not dict or set(raw) != _FIELDS or raw["domain"] != DOMAIN
            or type(raw["version"]) is not int or raw["version"] != VERSION
            or raw["account_id"] != account_id or raw["device_id"] != device_id
            or type(raw["epoch"]) is not int or not 0 <= raw["epoch"] <= MAX_EPOCH
            or type(raw["enabled_roles"]) is not list
            or len(raw["enabled_roles"]) > len(ROLES)
            or any(type(role) is not str or role not in ROLES for role in raw["enabled_roles"])
            or raw["enabled_roles"] != sorted(set(raw["enabled_roles"]))
            or type(raw["sha256"]) is not str):
        raise StorageError("owner consent state fields are invalid")
    expected = _document(account_id, device_id, raw["epoch"], tuple(raw["enabled_roles"]))
    if _canonical(expected) != encoded:
        raise StorageError("owner consent state is noncanonical or has a bad digest")
    return OwnerConsentSnapshot(account_id, device_id, raw["epoch"],
                                tuple(raw["enabled_roles"]))


def _check_inode(info, uid, *, directory=False):
    expected_type = stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)
    expected_mode = 0o700 if directory else 0o600
    if (not expected_type or stat.S_IMODE(info.st_mode) != expected_mode
            or info.st_uid != uid or (not directory and info.st_nlink != 1)):
        raise StorageError("owner consent inode type, owner, mode, or link count is unsafe")


@dataclass(frozen=True)
class OwnerConsentSnapshot:
    """Inert copied owner-consent state, not process or identity authority."""
    account_id: str
    device_id: str
    epoch: int
    enabled_roles: tuple[str, ...]


def provision_owner_consent(root, *, expected_uid: int, account_id: str,
                            device_id: str) -> None:
    """Explicit operator-setup creation; never imports legacy enabled roles."""
    _validate_setup(expected_uid, account_id, device_id)
    root_fd = _open_root(root, expected_uid)
    try:
        _create(root_fd, LOCK_NAME, b"", expected_uid)
        os.fsync(root_fd)
        state = _canonical(_document(account_id, device_id, 0, ()))
        _create(root_fd, STATE_NAME, state, expected_uid)
        os.fsync(root_fd)
    except BaseException as error:
        if isinstance(error, StorageError):
            raise
        raise StorageError("owner consent explicit provisioning failed; inspect store") from error
    finally:
        _close_once(root_fd)


def _validate_setup(expected_uid, account_id, device_id):
    if os.name != "posix" or not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "geteuid"):
        raise StorageError("owner consent requires POSIX no-follow and flock support")
    if type(expected_uid) is not int or expected_uid != os.geteuid():
        raise StorageError("owner consent UID must equal effective UID")
    try:
        validate_id(account_id, "acct")
        validate_id(device_id, "dev")
    except Exception as error:
        raise StorageError("owner consent principal is not a valid pinned setup identity") from error


def _open_root(root, uid):
    try:
        return _open_directory_chain(Path(os.path.abspath(os.fspath(root))), expected_uid=uid)
    except (OSError, TypeError, ValueError) as error:
        raise StorageError("owner consent root must be a provisioned owner 0700 directory") from error


def _create(root_fd, name, data, uid):
    fd = None
    try:
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
                     | getattr(os, "O_CLOEXEC", 0), 0o600, dir_fd=root_fd)
        _check_inode(os.fstat(fd), uid)
        view = memoryview(data)
        while view:
            count = os.write(fd, view)
            if count <= 0:
                raise OSError("owner consent write made no progress")
            view = view[count:]
        os.fsync(fd)
        owned, fd = fd, None
        _close_once(owned)
        return None
    except BaseException:
        if fd is not None:
            owned, fd = fd, None
            try:
                _close_once(owned)
            except BaseException:
                pass
        raise


def _close_once(fd):
    # Ownership is consumed by callers before this one syscall. Never retry a
    # failed close: the integer may already have been reused.
    os.close(fd)


class OwnerConsentStore:
    """Cross-process durable per-device opt-in store with a held start context."""
    def __init__(self, root, *, expected_uid: int, account_id: str,
                 device_id: str, _fault_hook: Callable[[str], None] | None = None):
        _validate_setup(expected_uid, account_id, device_id)
        self._uid = expected_uid
        self._account = validate_id(account_id, "acct")
        self._device = validate_id(device_id, "dev")
        self._fault_hook = _fault_hook
        self._unknown = False
        self._fd = _open_root(root, expected_uid)
        self._lifetime = threading.Condition(threading.Lock())
        self._busy = False
        self._owner_thread = None
        try:
            with self._operation():
                with self._file_lock():
                    self._read_owned()
        except BaseException:
            fd, self._fd = self._fd, -1
            try:
                _close_once(fd)
            except OSError:
                pass
            raise

    @contextmanager
    def _operation(self, *, allow_closed=False, allow_unknown=False):
        ident = threading.get_ident()
        with self._lifetime:
            if self._owner_thread == ident:
                raise StorageError("owner consent store operation cannot be reentered")
            while self._busy:
                self._lifetime.wait()
            if self._fd < 0 and not allow_closed:
                raise StorageError("owner consent store is closed")
            if self._fd >= 0 and self._unknown and not allow_unknown:
                raise StorageError("owner consent store outcome is unknown and latched")
            if self._fd >= 0:
                self._busy = True
                self._owner_thread = ident
        if self._fd < 0:
            yield
            return
        try:
            yield
        finally:
            with self._lifetime:
                self._owner_thread = None
                self._busy = False
                self._lifetime.notify_all()

    def close(self):
        with self._operation(allow_closed=True, allow_unknown=True):
            fd, self._fd = self._fd, -1
            if fd < 0:
                return
            try:
                _close_once(fd)
            except BaseException:
                self._unknown = True
                raise

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    def _step(self, name):
        if self._fault_hook is not None:
            self._fault_hook(name)

    def _scan_names(self):
        try:
            with os.scandir(self._fd) as entries:
                names = []
                for entry in entries:
                    names.append(entry.name)
                    if len(names) > 2:
                        raise StorageError("owner consent directory has unknown entries")
        except StorageError:
            raise
        except OSError as error:
            raise StorageError("owner consent directory cannot be scanned") from error
        if set(names) != {STATE_NAME, LOCK_NAME}:
            raise StorageError("owner consent store is incomplete or contains recovery debris")

    @contextmanager
    def _file_lock(self):
        if self._fd < 0 or self._unknown:
            raise StorageError("owner consent store is closed or latched")
        if self._owner_thread != threading.get_ident():
            raise StorageError("owner consent root descriptor is not owned by this operation")
        fd = None
        lock_fd = None
        try:
            import fcntl
            before = os.stat(LOCK_NAME, dir_fd=self._fd, follow_symlinks=False)
            _check_inode(before, self._uid)
            fd = os.open(LOCK_NAME, os.O_RDWR | os.O_NOFOLLOW
                         | getattr(os, "O_CLOEXEC", 0), dir_fd=self._fd)
            lock_fd = fd
            opened = os.fstat(fd)
            _check_inode(opened, self._uid)
            if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
                raise StorageError("owner consent lock identity changed during open")
            fcntl.flock(fd, fcntl.LOCK_EX)
            current = os.stat(LOCK_NAME, dir_fd=self._fd, follow_symlinks=False)
            if (opened.st_dev, opened.st_ino) != (current.st_dev, current.st_ino):
                raise StorageError("owner consent lock identity changed while waiting")
            _check_inode(os.fstat(self._fd), self._uid, directory=True)
            self._scan_names()
        except BaseException as error:
            if lock_fd is not None:
                try:
                    owned, lock_fd = lock_fd, None
                    _close_once(owned)
                except BaseException:
                    self._unknown = True
            if isinstance(error, StorageError):
                raise
            raise StorageError("owner consent lock is unavailable") from error
        try:
            yield
        finally:
            owned, lock_fd = lock_fd, None
            try:
                fcntl.flock(owned, fcntl.LOCK_UN)
            except OSError:
                self._unknown = True
                raise StorageError("owner consent unlock outcome is unknown")
            finally:
                try:
                    _close_once(owned)
                except OSError as error:
                    self._unknown = True
                    raise StorageError("owner consent lock close outcome is unknown") from error

    def _read_owned(self):
        try:
            before = os.stat(STATE_NAME, dir_fd=self._fd, follow_symlinks=False)
            _check_inode(before, self._uid)
            fd = os.open(STATE_NAME, os.O_RDONLY | os.O_NOFOLLOW
                         | getattr(os, "O_NONBLOCK", 0)
                         | getattr(os, "O_CLOEXEC", 0), dir_fd=self._fd)
            opened = os.fstat(fd)
            _check_inode(opened, self._uid)
            if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
                raise StorageError("owner consent state identity changed during open")
            chunks, remaining = [], MAX_STATE_BYTES + 1
            while remaining:
                chunk = os.read(fd, remaining)
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            raw = b"".join(chunks)
            if len(raw) > MAX_STATE_BYTES:
                raise StorageError("owner consent state exceeds its size bound")
        except OSError as error:
            raise StorageError("owner consent state cannot be read safely") from error
        finally:
            if "fd" in locals():
                owned, fd = fd, -1
                try:
                    _close_once(owned)
                except OSError as error:
                    self._unknown = True
                    raise StorageError("owner consent state close outcome is unknown") from error
        return _parse(raw, self._account, self._device)

    def _write_owned(self, snapshot):
        encoded = _canonical(_document(snapshot.account_id, snapshot.device_id,
                                        snapshot.epoch, snapshot.enabled_roles))
        if len(encoded) > MAX_STATE_BYTES:
            raise StorageError("owner consent state exceeds its size bound")
        temp = f".owner-consent-tmp-{secrets.token_hex(8)}"
        fd = None
        created = False
        pending_fd = None
        pending_created = False
        try:
            pending_fd = os.open(PENDING_NAME,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
                | getattr(os, "O_CLOEXEC", 0), 0o600, dir_fd=self._fd)
            pending_created = True
            _check_inode(os.fstat(pending_fd), self._uid)
            self._step("state.pending.file.fsync")
            os.fsync(pending_fd)
            owned, pending_fd = pending_fd, None
            _close_once(owned)
            self._step("state.pending.root.fsync")
            os.fsync(self._fd)
            fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
                         | getattr(os, "O_CLOEXEC", 0), 0o600, dir_fd=self._fd)
            created = True
            _check_inode(os.fstat(fd), self._uid)
            self._step("state.write")
            view = memoryview(encoded)
            while view:
                count = os.write(fd, view)
                if count <= 0:
                    raise OSError("owner consent write made no progress")
                view = view[count:]
            self._step("state.file.fsync")
            os.fsync(fd)
            owned, fd = fd, None
            _close_once(owned)
            self._step("state.replace")
            os.replace(temp, STATE_NAME, src_dir_fd=self._fd, dst_dir_fd=self._fd)
            self._step("state.replace.root.fsync")
            os.fsync(self._fd)
            os.unlink(PENDING_NAME, dir_fd=self._fd)
            self._step("state.commit.root.fsync")
            os.fsync(self._fd)
        except BaseException as error:
            # Once the durable pending fence exists, the visible/recoverable
            # outcome may be ambiguous. Latch and leave debris for inspection.
            if created or pending_created:
                self._unknown = True
            if fd is not None:
                owned, fd = fd, None
                try:
                    _close_once(owned)
                except BaseException:
                    self._unknown = True
            if pending_fd is not None:
                owned, pending_fd = pending_fd, None
                try:
                    _close_once(owned)
                except BaseException:
                    self._unknown = True
            if isinstance(error, StorageError):
                raise
            raise StorageError("owner consent durable write outcome is unknown") from error

    def snapshot(self) -> OwnerConsentSnapshot:
        with self._operation():
            with self._file_lock():
                return self._read_owned()

    @contextmanager
    def serialized_snapshot(self):
        """Hold owner serialization while reading without advancing its epoch.

        Intended for a final read-only cross-store comparison. Do not perform
        durable policy work, process startup, or readiness waits in this scope.
        """
        with self._operation():
            with self._file_lock():
                yield self._read_owned()

    def _bump(self, old, roles):
        if old.epoch >= MAX_EPOCH:
            raise StorageError("owner consent epoch is exhausted")
        return OwnerConsentSnapshot(self._account, self._device, old.epoch + 1,
                                    tuple(sorted(roles)))

    def set_role_enabled(self, role, enabled):
        if type(role) is not str or role not in ROLES or type(enabled) is not bool:
            raise ValueError("role and exact boolean enablement are required")
        with self._operation():
            with self._file_lock():
                old = self._read_owned()
                roles = set(old.enabled_roles)
                if enabled:
                    roles.add(role)
                else:
                    roles.discard(role)
                updated = self._bump(old, roles)
                self._write_owned(updated)
                return updated

    @contextmanager
    def begin_start(self, roles, *, cancel_event):
        """Durably advance start intent and hold owner serialization until exit.

        The yielded snapshot is inert. The caller must validate the selected
        head/claim and check cancellation again at each backend publication.
        """
        if (type(roles) is not tuple or not roles
                or any(type(role) is not str or role not in ROLES for role in roles)
                or roles != tuple(sorted(set(roles)))
                or type(cancel_event) is not threading.Event):
            raise ValueError("start requires a nonempty exact sorted role tuple and Event")
        with self._operation():
            with self._file_lock():
                if cancel_event.is_set():
                    raise StorageError("owner start intent was cancelled")
                old = self._read_owned()
                if roles != old.enabled_roles:
                    raise StorageError("start must name the exact enabled local projection")
                updated = self._bump(old, old.enabled_roles)
                self._write_owned(updated)
                if cancel_event.is_set():
                    raise StorageError("owner start intent was cancelled after durable advance")
                yield updated
