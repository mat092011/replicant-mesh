"""Persistent Linux owner for the signed C2 channel-policy head.

The owner stores the complete operator-signed policy with a small closed head
record. It delegates every policy decision to the real security-layer
``ChannelPolicyStore`` and supplies only its synchronous durable-commit hook.
"""
from __future__ import annotations

import base64
import errno
import hashlib
import json
import os
from pathlib import Path
import secrets
import stat
import sys
import threading
import time
from contextlib import contextmanager

from steamboat_security.channel_policy import (
    ChannelPolicyStore,
    MAX_CHANNEL_POLICY_BYTES,
    _verification_key,
    canonical_json,
)
from steamboat_security.certificates import public_key_sha256
from steamboat_security.clock import Clock
from steamboat_security.errors import SnapshotError, StorageError

HEAD_NAME = "channel-policy-head.json"
LOCK_NAME = "channel-policy-head.lock"
TEMP_NAME = ".channel-policy-head.pending"
HEAD_DOMAIN = "steamboat-c2-channel-policy-head-v1"
HEAD_VERSION = 1
MAX_HEAD_BYTES = ((MAX_CHANNEL_POLICY_BYTES + 2) // 3) * 4 + 4096
OWNER_WAIT_SECONDS = 2.0
_HEAD_FIELDS = frozenset({
    "domain", "version", "verification_key_sha256", "minimum_revision",
    "minimum_policy_digest", "revision", "policy_digest",
    "signed_policy_sha256", "signed_policy_b64",
})
_HEX64 = frozenset("0123456789abcdef")
_QUARANTINE_LIMIT = 8
_QUARANTINE = []
_QUARANTINE_LOCK = threading.Lock()


def _retain_uncertain_initialization(owner):
    with _QUARANTINE_LOCK:
        if len(_QUARANTINE) < _QUARANTINE_LIMIT and owner not in _QUARANTINE:
            _QUARANTINE.append(owner)


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise StorageError("channel policy head has duplicate fields")
        result[key] = value
    return result


def _constant(_value):
    raise StorageError("channel policy head contains a non-finite number")


def _hex64(value):
    return (type(value) is str and len(value) == 64
            and all(char in _HEX64 for char in value))


def _check_inode(info, uid, *, directory=False):
    if directory:
        okay = stat.S_ISDIR(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o700
    else:
        okay = (stat.S_ISREG(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o600
                and info.st_nlink == 1)
    if not okay or info.st_uid != uid:
        raise StorageError("channel policy owner inode type, UID, mode or links are unsafe")


def _validate_config(expected_uid, verification_key_pem, clock,
                     minimum_revision, minimum_policy_digest):
    if (os.name != "posix" or not sys.platform.startswith("linux")
            or not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "geteuid")):
        raise StorageError("persistent channel policy requires Linux no-follow storage")
    if type(expected_uid) is not int or expected_uid != os.geteuid():
        raise StorageError("channel policy owner UID must equal effective UID")
    if type(clock) is not Clock:
        raise TypeError("clock must be the exact core Clock")
    if (type(minimum_revision) is not int or minimum_revision < 1
            or not _hex64(minimum_policy_digest)):
        raise ValueError("an explicit minimum policy revision and digest are required")
    key = _verification_key(verification_key_pem)
    return public_key_sha256(key)


def _canonical_head(*, key_hash, minimum_revision, minimum_digest,
                    revision, policy_digest, signed_policy):
    value = {
        "domain": HEAD_DOMAIN,
        "version": HEAD_VERSION,
        "verification_key_sha256": key_hash,
        "minimum_revision": minimum_revision,
        "minimum_policy_digest": minimum_digest,
        "revision": revision,
        "policy_digest": policy_digest,
        "signed_policy_sha256": hashlib.sha256(signed_policy).hexdigest(),
        "signed_policy_b64": base64.b64encode(signed_policy).decode("ascii"),
    }
    encoded = canonical_json(value)
    if len(encoded) > MAX_HEAD_BYTES:
        raise StorageError("channel policy head exceeds its fixed size bound")
    return encoded


def _parse_head(encoded, *, key_hash, minimum_revision, minimum_digest):
    if type(encoded) is not bytes or not 1 <= len(encoded) <= MAX_HEAD_BYTES:
        raise StorageError("channel policy head is empty or oversized")
    try:
        value = json.loads(encoded.decode("utf-8", "strict"),
                           object_pairs_hook=_pairs, parse_constant=_constant)
    except StorageError:
        raise
    except (UnicodeError, ValueError, TypeError, RecursionError) as error:
        raise StorageError("channel policy head is malformed") from error
    if (type(value) is not dict or set(value) != _HEAD_FIELDS
            or value["domain"] != HEAD_DOMAIN
            or type(value["version"]) is not int or value["version"] != HEAD_VERSION
            or value["verification_key_sha256"] != key_hash
            or type(value["minimum_revision"]) is not int
            or value["minimum_revision"] != minimum_revision
            or value["minimum_policy_digest"] != minimum_digest
            or type(value["revision"]) is not int or value["revision"] < 1
            or not _hex64(value["policy_digest"])
            or not _hex64(value["signed_policy_sha256"])
            or type(value["signed_policy_b64"]) is not str
            or canonical_json(value) != encoded):
        raise StorageError("channel policy head fields or anchors are invalid")
    try:
        signed = base64.b64decode(value["signed_policy_b64"], validate=True)
    except (ValueError, TypeError) as error:
        raise StorageError("channel policy head signed bytes are malformed") from error
    if (base64.b64encode(signed).decode("ascii") != value["signed_policy_b64"]
            or not 1 <= len(signed) <= MAX_CHANNEL_POLICY_BYTES
            or hashlib.sha256(signed).hexdigest() != value["signed_policy_sha256"]):
        raise StorageError("channel policy head signed bytes do not match their digest")
    return value, signed


class PersistentChannelPolicyStore:
    """Exclusive, bounded, FD-relative owner of one durable channel policy.

    Use :meth:`provision` only for explicit operator setup, then call
    ``install(initial_signed_policy)``. Use :meth:`open_existing` during normal
    startup. This owner is Linux-only and intentionally holds an exclusive
    nonblocking flock for its lifetime.
    """

    def __init__(self, *args, **kwargs):
        raise TypeError("use provision() or open_existing()")

    @classmethod
    def provision(cls, root, *, expected_uid, verification_key_pem, clock,
                  minimum_revision, minimum_policy_digest, _fault_hook=None):
        """Create an empty policy head owner; install its initial signed policy next."""
        key_hash = _validate_config(expected_uid, verification_key_pem, clock,
                                    minimum_revision, minimum_policy_digest)
        owner = cls.__new__(cls)
        owner._initialize(root, expected_uid, verification_key_pem, clock,
                          minimum_revision, minimum_policy_digest, key_hash,
                          _fault_hook)
        owner._check_quarantine_capacity()
        try:
            owner._open_provisioned_root()
            owner._create_and_claim_lock()
            owner._head_bytes = None
            owner._head_identity = None
            owner._bootstrap_signed = None
            owner._store = owner._new_core_store()
            return owner
        except BaseException:
            owner._faulted = True
            owner._close_unpublished_initialization()
            if owner._uncertain_cleanup:
                _retain_uncertain_initialization(owner)
            raise

    @classmethod
    def open_existing(cls, root, *, expected_uid, verification_key_pem, clock,
                      minimum_revision, minimum_policy_digest, _fault_hook=None):
        """Open and fully revalidate an existing persisted signed policy head."""
        key_hash = _validate_config(expected_uid, verification_key_pem, clock,
                                    minimum_revision, minimum_policy_digest)
        owner = cls.__new__(cls)
        owner._initialize(root, expected_uid, verification_key_pem, clock,
                          minimum_revision, minimum_policy_digest, key_hash,
                          _fault_hook)
        owner._check_quarantine_capacity()
        try:
            owner._open_existing_root()
            owner._open_and_claim_lock()
            owner._scan_names(require_head=True)
            head_bytes, head_identity = owner._read_head()
            header, signed = _parse_head(
                head_bytes, key_hash=key_hash,
                minimum_revision=minimum_revision,
                minimum_digest=minimum_policy_digest)
            owner._head_bytes = head_bytes
            owner._head_identity = head_identity
            owner._bootstrap_signed = signed
            owner._store = owner._new_core_store()
            # This invokes the real parser, schema, signature, clock, minimum,
            # rollback and equivocation validators. The durable hook recognizes
            # these exact already-persisted bytes and does not rewrite them.
            view = owner._store.install(signed)
            if (view.revision != header["revision"]
                    or view.policy_digest != header["policy_digest"]):
                raise StorageError("persisted channel policy disagrees with signed head")
            owner._bootstrap_signed = None
            owner._commit_ready = False
            return owner
        except BaseException:
            owner._faulted = True
            owner._close_unpublished_initialization()
            if owner._uncertain_cleanup:
                _retain_uncertain_initialization(owner)
            raise

    def _initialize(self, root, uid, verification_key_pem, clock,
                    minimum_revision, minimum_digest, key_hash, fault_hook):
        try:
            self._path = Path(os.path.abspath(os.fspath(root)))
        except (TypeError, ValueError, OSError) as error:
            raise StorageError("channel policy root path is invalid") from error
        if not self._path.is_absolute() or self._path == Path(os.sep):
            raise StorageError("filesystem root cannot store channel policy")
        self._uid = uid
        self._verification_key_pem = verification_key_pem
        self._clock = clock
        self._minimum_revision = minimum_revision
        self._minimum_digest = minimum_digest
        self._key_hash = key_hash
        self._fault_hook = fault_hook
        self._root_fd = -1
        self._walking_fds = []
        self._uncertain_cleanup = False
        self._lock_fd = -1
        self._lock_identity = None
        self._head_bytes = None
        self._head_identity = None
        self._bootstrap_signed = None
        self._faulted = False
        self._closed = False
        self._commit_ready = False
        self._busy = False
        self._owner_thread = None
        self._lifetime = threading.Condition(threading.Lock())
        self._operation_lock = threading.RLock()

    def _check_quarantine_capacity(self):
        with _QUARANTINE_LOCK:
            if len(_QUARANTINE) >= _QUARANTINE_LIMIT:
                raise StorageError("uncertain channel policy owners reached their fixed bound")

    def _new_core_store(self):
        return ChannelPolicyStore(
            self._verification_key_pem,
            clock=self._clock,
            minimum_revision=self._minimum_revision,
            minimum_policy_digest=self._minimum_digest,
            durable_commit=self._durable_commit,
            require_durable=True,
        )

    def _open_root(self):
        flags = (os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | os.O_NOFOLLOW
                 | getattr(os, "O_CLOEXEC", 0))
        try:
            if not self._path.is_absolute() or self._path == Path(os.sep):
                raise StorageError("filesystem root cannot store channel policy")
            self._walking_fds.append(os.open(os.sep, flags))
            components = self._path.parts[1:]
            for index, component in enumerate(components):
                if component in ("", ".", ".."):
                    raise StorageError("channel policy root path has unsafe components")
                parent = self._walking_fds[-1]
                child = os.open(component, flags, dir_fd=parent)
                self._walking_fds.append(child)
                # Consume the parent descriptor before its one close attempt.
                self._walking_fds.remove(parent)
                self._close_fd_once(parent, "channel policy path component")
                info = os.fstat(child)
                if not stat.S_ISDIR(info.st_mode):
                    raise StorageError("channel policy root component is not a directory")
                if index == len(components) - 1:
                    _check_inode(info, self._uid, directory=True)
            result = self._walking_fds.pop()
            return result
        except StorageError:
            raise
        except OSError as error:
            raise StorageError("channel policy owner root is missing or unsafe") from error

    def _open_provisioned_root(self):
        self._root_fd = self._open_root()
        self._check_root_inode()
        if os.listdir(self._root_fd):
            raise StorageError("channel policy provision root must be empty")

    def _open_existing_root(self):
        self._root_fd = self._open_root()
        self._check_root_inode()

    def _check_root_inode(self):
        _check_inode(os.fstat(self._root_fd), self._uid, directory=True)
        reopened = self._open_root()
        try:
            old = os.fstat(self._root_fd)
            new = os.fstat(reopened)
            if (old.st_dev, old.st_ino) != (new.st_dev, new.st_ino):
                raise StorageError("channel policy owner root namespace changed")
        finally:
            owned, reopened = reopened, -1
            self._close_fd_once(owned, "root verification descriptor")

    def _step(self, name):
        if self._fault_hook is not None:
            self._fault_hook(name)

    def _create_and_claim_lock(self):
        fd = None
        try:
            fd = os.open(LOCK_NAME, os.O_RDWR | os.O_CREAT | os.O_EXCL
                         | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
                         0o600, dir_fd=self._root_fd)
            self._lock_fd = fd
            fd = None
            _check_inode(os.fstat(self._lock_fd), self._uid)
            os.fsync(self._lock_fd)
            os.fsync(self._root_fd)
            self._claim_lock()
            self._scan_names(require_head=False)
        except BaseException as error:
            if fd is not None:
                self._close_fd_once(fd, "unclaimed lock descriptor")
            if isinstance(error, StorageError):
                raise
            raise StorageError("channel policy lock provisioning failed") from error

    def _open_and_claim_lock(self):
        try:
            before = os.stat(LOCK_NAME, dir_fd=self._root_fd, follow_symlinks=False)
            _check_inode(before, self._uid)
            fd = os.open(LOCK_NAME, os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK
                         | getattr(os, "O_CLOEXEC", 0), dir_fd=self._root_fd)
            self._lock_fd = fd
            opened = os.fstat(fd)
            _check_inode(opened, self._uid)
            if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
                raise StorageError("channel policy lock changed while opening")
            self._claim_lock()
        except BaseException as error:
            if isinstance(error, StorageError):
                raise
            if isinstance(error, OSError) and error.errno in (errno.ELOOP, errno.ENOTDIR):
                raise StorageError("channel policy lock is a symlink or unsafe inode") from error
            raise StorageError("channel policy lock is unavailable") from error

    def _claim_lock(self):
        import fcntl
        try:
            fcntl.flock(self._lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise StorageError("channel policy owner is already open") from error
        self._lock_identity = self._identity(os.fstat(self._lock_fd))
        self._check_lock_live()

    @staticmethod
    def _identity(info):
        return (info.st_dev, info.st_ino, info.st_uid, stat.S_IMODE(info.st_mode),
                info.st_nlink, stat.S_IFMT(info.st_mode))

    def _check_lock_live(self):
        if self._lock_fd < 0:
            raise StorageError("channel policy lock ownership is closed")
        _check_inode(os.fstat(self._lock_fd), self._uid)
        try:
            current = os.stat(LOCK_NAME, dir_fd=self._root_fd, follow_symlinks=False)
        except OSError as error:
            raise StorageError("channel policy lock namespace is unavailable") from error
        if self._identity(current) != self._lock_identity:
            raise StorageError("channel policy lock namespace identity changed")

    def _scan_names(self, *, require_head, allow_temp=False):
        try:
            self._check_root_inode()
            self._check_lock_live()
            names = set(os.listdir(self._root_fd))
        except StorageError:
            raise
        except OSError as error:
            raise StorageError("channel policy namespace cannot be inspected") from error
        expected = {LOCK_NAME, HEAD_NAME} if require_head else {LOCK_NAME}
        if allow_temp:
            expected.add(TEMP_NAME)
        if names != expected:
            raise StorageError("channel policy directory is incomplete or has unknown entries")

    def _read_head(self):
        try:
            before = os.stat(HEAD_NAME, dir_fd=self._root_fd, follow_symlinks=False)
        except OSError as error:
            raise StorageError("channel policy head is unavailable") from error
        _check_inode(before, self._uid)
        fd = None
        try:
            fd = os.open(HEAD_NAME, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
                         | getattr(os, "O_CLOEXEC", 0), dir_fd=self._root_fd)
            opened = os.fstat(fd)
            _check_inode(opened, self._uid)
            if self._identity(opened) != self._identity(before):
                raise StorageError("channel policy head changed during open")
            chunks, total = [], 0
            while True:
                part = os.read(fd, min(8192, MAX_HEAD_BYTES + 1 - total))
                if not part:
                    break
                chunks.append(part)
                total += len(part)
                if total > MAX_HEAD_BYTES:
                    raise StorageError("channel policy head exceeds its fixed size bound")
        except OSError as error:
            if error.errno in (errno.ELOOP, errno.ENOTDIR):
                raise StorageError("channel policy head is a symlink or unsafe inode") from error
            raise StorageError("channel policy head cannot be read safely") from error
        finally:
            if fd is not None:
                owned, fd = fd, None
                self._close_fd_once(owned, "channel policy head descriptor")
        after = os.stat(HEAD_NAME, dir_fd=self._root_fd, follow_symlinks=False)
        if self._identity(after) != self._identity(before):
            raise StorageError("channel policy head namespace changed while reading")
        return b"".join(chunks), self._identity(after)

    def _assert_expected_head(self, *, allow_temp=False):
        try:
            self._scan_names(require_head=self._head_bytes is not None,
                             allow_temp=allow_temp)
            if self._head_bytes is None:
                return
            current, identity = self._read_head()
            if current != self._head_bytes or identity != self._head_identity:
                raise StorageError("durable channel policy head changed outside this owner")
        except StorageError:
            raise
        except OSError as error:
            raise StorageError("channel policy head namespace is uncertain") from error

    def _encode_head(self, signed_policy, revision, policy_digest):
        return _canonical_head(
            key_hash=self._key_hash,
            minimum_revision=self._minimum_revision,
            minimum_digest=self._minimum_digest,
            revision=revision,
            policy_digest=policy_digest,
            signed_policy=signed_policy,
        )

    def _durable_commit(self, signed_policy, revision, policy_digest):
        if self._busy and self._owner_thread != threading.get_ident():
            raise StorageError("channel policy owner is busy")
        if self._faulted or self._closed:
            raise StorageError("channel policy durable owner is faulted or closed")
        self._faulted = True
        try:
            self._assert_expected_head()
            if self._bootstrap_signed is not None:
                if signed_policy != self._bootstrap_signed:
                    raise StorageError("bootstrap policy bytes changed during validation")
                header, _stored = _parse_head(
                    self._head_bytes, key_hash=self._key_hash,
                    minimum_revision=self._minimum_revision,
                    minimum_digest=self._minimum_digest)
                if (header["revision"] != revision
                        or header["policy_digest"] != policy_digest):
                    raise StorageError("bootstrap policy metadata differs from signed bytes")
                self._commit_ready = True
                self._faulted = False
                return None
            encoded = self._encode_head(signed_policy, revision, policy_digest)
            self._write_head(encoded)
            self._commit_ready = True
            self._faulted = False
            return None
        except BaseException as error:
            self._faulted = True
            if isinstance(error, (StorageError, SnapshotError)):
                raise
            raise StorageError("durable channel policy commit outcome is unknown") from error

    def _write_head(self, encoded):
        self._assert_expected_head()
        fd = None
        created = False
        replaced = False
        try:
            fd = os.open(TEMP_NAME, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                         | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
                         0o600, dir_fd=self._root_fd)
            created = True
            _check_inode(os.fstat(fd), self._uid)
            self._step("head.write")
            view = memoryview(encoded)
            while view:
                count = os.write(fd, view)
                if count <= 0:
                    raise OSError("channel policy write made no progress")
                view = view[count:]
            self._step("head.file.fsync")
            os.fsync(fd)
            owned, fd = fd, None
            self._close_fd_once(owned, "channel policy temporary file")
            self._assert_expected_head(allow_temp=True)
            self._step("head.replace")
            os.replace(TEMP_NAME, HEAD_NAME, src_dir_fd=self._root_fd,
                       dst_dir_fd=self._root_fd)
            replaced = True
            self._step("head.directory.fsync")
            os.fsync(self._root_fd)
            self._assert_root_inode()
            actual, identity = self._read_head()
            if actual != encoded:
                raise StorageError("durable channel policy head readback differs")
            self._head_bytes = encoded
            self._head_identity = identity
        except BaseException as error:
            # A pending name, attempted rename or failed directory fsync makes
            # the durable outcome uncertain. Keep the lifetime lock and latch.
            self._faulted = True
            if fd is not None:
                owned, fd = fd, None
                try:
                    self._close_fd_once(owned, "channel policy temporary file")
                except BaseException:
                    pass
            if isinstance(error, (StorageError, SnapshotError)):
                raise
            state = " after replace" if replaced else (" after temp creation" if created else "")
            raise StorageError("durable channel policy write failed" + state) from error

    def _assert_root_inode(self):
        self._check_root_inode()

    @contextmanager
    def _operation(self):
        ident = threading.get_ident()
        deadline = time.monotonic() + OWNER_WAIT_SECONDS
        with self._lifetime:
            if self._owner_thread == ident:
                raise StorageError("channel policy owner operation cannot be reentered")
            while self._busy:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise StorageError("channel policy owner operation wait expired")
                self._lifetime.wait(remaining)
            if self._closed or self._faulted:
                raise StorageError("channel policy owner is closed or faulted")
            self._busy = True
            self._owner_thread = ident
        try:
            with self._operation_lock:
                try:
                    self._assert_expected_head()
                except StorageError:
                    self._faulted = True
                    raise
                yield
        except BaseException:
            if self._commit_ready:
                self._faulted = True
            raise
        finally:
            self._commit_ready = False
            with self._lifetime:
                self._owner_thread = None
                self._busy = False
                self._lifetime.notify_all()

    def install(self, signed_policy: bytes):
        with self._operation():
            try:
                return self._store.install(signed_policy)
            except BaseException:
                if self._commit_ready:
                    self._faulted = True
                raise

    def current(self):
        with self._operation():
            return self._store.current()

    def current_with_sample(self):
        with self._operation():
            return self._store.current_with_sample()

    @property
    def faulted(self):
        return self._faulted or self._store._faulted

    def close(self):
        with self._lifetime:
            if self._owner_thread == threading.get_ident() or self._busy:
                raise StorageError("cannot close a busy channel policy owner")
            if self._faulted or self._store._faulted:
                raise StorageError("faulted channel policy owner must retain its lock")
            if self._closed:
                return
            self._busy = True
            self._owner_thread = threading.get_ident()
        try:
            # Validate the namespace before releasing exclusivity. Descriptors
            # are consumed before their one close attempt to avoid fd reuse.
            self._assert_expected_head()
            root, self._root_fd = self._root_fd, -1
            self._close_fd_once(root, "channel policy root")
            lock, self._lock_fd = self._lock_fd, -1
            self._close_fd_once(lock, "channel policy lifetime lock")
            self._closed = True
        except BaseException:
            self._faulted = True
            raise
        finally:
            with self._lifetime:
                self._owner_thread = None
                self._busy = False
                self._lifetime.notify_all()

    def _close_fd_once(self, fd, label):
        try:
            os.close(fd)
        except BaseException as error:
            self._faulted = True
            self._uncertain_cleanup = True
            raise StorageError(f"{label} close outcome is unknown") from error

    def _close_unpublished_initialization(self):
        # Initialization fails only before the object is returned and before
        # policy publication. Consume each descriptor once; no unlink/recovery
        # is attempted, so any partial provision is rejected on next open.
        for name in ("_root_fd", "_lock_fd"):
            fd = getattr(self, name, -1)
            if fd >= 0:
                setattr(self, name, -1)
                try:
                    os.close(fd)
                except OSError:
                    self._faulted = True
                    self._uncertain_cleanup = True
        while self._walking_fds:
            fd = self._walking_fds.pop()
            try:
                os.close(fd)
            except OSError:
                self._faulted = True
                self._uncertain_cleanup = True

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        self.close()
