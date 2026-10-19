"""Exclusive physical-host RAM-pool allocation and controller lock.

This validates an operator-provisioned allocation. It cannot attest that a
container's directory is genuinely shared with the physical host.
"""

import hashlib
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys

from .policy import validate_policy
from .storage import FileLock, StorageError, open_private_directory
from .validation import json_bytes, strict_json_loads


ALLOCATION_NAME = "allocation.json"
ALLOCATION_MAX_BYTES = 4096
_HOST_ID = re.compile(r"^[0-9a-f]{64}$")
_ALLOCATION_FIELDS = {
    "version", "physical_host_id", "pool_kind", "pool_id",
    "memory_ceiling_bytes", "cpu_quota_millis", "controller_cgroup", "owner_uid",
}


class PoolAllocationError(Exception):
    """The operator allocation is absent, invalid, changed, or already locked."""


def _read_allocation(path, uid):
    """Securely read a single-link private allocation file (no path following)."""
    path = Path(path)
    directory = open_private_directory(path.parent, uid=uid)
    try:
        descriptor = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                             dir_fd=directory)
        try:
            info = os.fstat(descriptor)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != uid
                    or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1
                    or info.st_size > ALLOCATION_MAX_BYTES):
                raise PoolAllocationError("allocation must be a bounded private single-link file")
            chunks = []
            total = 0
            while True:
                chunk = os.read(descriptor, min(1024, ALLOCATION_MAX_BYTES + 1 - total))
                if not chunk:
                    break
                total += len(chunk)
                if total > ALLOCATION_MAX_BYTES:
                    raise PoolAllocationError("allocation exceeds its size bound")
                chunks.append(chunk)
            try:
                return strict_json_loads(b"".join(chunks), maximum_bytes=ALLOCATION_MAX_BYTES)
            except (ValueError, TypeError, UnicodeError) as error:
                raise PoolAllocationError("allocation JSON is malformed") from error
        finally:
            os.close(descriptor)
    except OSError as error:
        raise PoolAllocationError("allocation file cannot be securely read") from error
    finally:
        os.close(directory)


def _validate_allocation(document, host_id, uid):
    if type(document) is not dict or set(document) != _ALLOCATION_FIELDS:
        raise PoolAllocationError("allocation fields do not match version 1")
    if type(document["version"]) is not int or document["version"] != 1:
        raise PoolAllocationError("unsupported allocation version")
    if (not isinstance(document["physical_host_id"], str)
            or not _HOST_ID.fullmatch(document["physical_host_id"])
            or document["physical_host_id"] != host_id):
        raise PoolAllocationError("allocation physical host identity does not match")
    if document["pool_kind"] != "system_ram":
        raise PoolAllocationError("only the explicitly allocated system_ram pool is supported")
    if not isinstance(document["pool_id"], str) or not document["pool_id"]:
        raise PoolAllocationError("allocation pool label is invalid")
    for name in ("memory_ceiling_bytes", "cpu_quota_millis", "owner_uid"):
        if type(document[name]) is not int or document[name] < 0:
            raise PoolAllocationError(f"allocation {name} must be a nonnegative integer")
    if document["memory_ceiling_bytes"] < 1 or document["cpu_quota_millis"] < 1:
        raise PoolAllocationError("allocation must explicitly provide positive RAM and CPU ceilings")
    if document["cpu_quota_millis"] > 100_000 or document["owner_uid"] != uid:
        raise PoolAllocationError("allocation CPU ceiling or owner UID is invalid")
    cgroup = document["controller_cgroup"]
    if not isinstance(cgroup, str):
        raise PoolAllocationError("controller cgroup path must be absolute")
    parsed = PurePosixPath(cgroup)
    if (not parsed.is_absolute() or ".." in parsed.parts or "." in parsed.parts
            or str(parsed) != cgroup):
        raise PoolAllocationError("controller cgroup path must be normalized and traversal-free")
    return document


class PoolControllerLock:
    """Hold one host-wide system RAM-pool lock for the execution lifetime."""

    def __init__(self, operator_directory, physical_host_id, *, uid=None):
        if not sys.platform.startswith("linux"):
            raise PoolAllocationError("physical pool locking requires Linux file locks")
        if not isinstance(physical_host_id, str) or not _HOST_ID.fullmatch(physical_host_id):
            raise PoolAllocationError("physical_host_id must be a SHA-256 hex identity")
        self.operator_directory = Path(os.path.abspath(os.fspath(operator_directory)))
        self.physical_host_id = physical_host_id
        self.uid = os.getuid() if uid is None else uid
        if type(self.uid) is not int or self.uid < 0:
            raise PoolAllocationError("UID must be a nonnegative integer")
        # Deliberately independent of pool_id, state directory, and runtime path.
        self.lock_path = self.operator_directory / f"pool-{physical_host_id}-system_ram.lock"
        self.allocation_path = self.operator_directory / ALLOCATION_NAME
        self._lock = None
        self._digest = None
        self._allocation = None

    @staticmethod
    def _check_policy(policy, allocation):
        try:
            normalized = validate_policy(policy)
        except (TypeError, ValueError) as error:
            raise PoolAllocationError("resource policy is invalid") from error
        if normalized["pool_id"] != allocation["pool_id"]:
            raise PoolAllocationError("policy pool label does not match operator allocation")
        limits = normalized["limits"]
        if (limits["memory_ceiling_bytes"] > allocation["memory_ceiling_bytes"]
                or limits["cpu_quota_millis"] > allocation["cpu_quota_millis"]):
            raise PoolAllocationError("policy exceeds its operator allocation")
        return normalized

    def acquire(self, policy):
        if self._lock is not None:
            raise PoolAllocationError("this controller already holds the pool lock")
        lock = None
        try:
            # Validate directory before creating/locking its control file.
            directory = open_private_directory(self.operator_directory, uid=self.uid)
            os.close(directory)
            lock = FileLock(self.lock_path, uid=self.uid, timeout=0).acquire()
            raw = _read_allocation(self.allocation_path, self.uid)
            allocation = _validate_allocation(raw, self.physical_host_id, self.uid)
            self._check_policy(policy, allocation)
            digest = hashlib.sha256(json_bytes(allocation, maximum_bytes=ALLOCATION_MAX_BYTES)).digest()
            self._allocation = allocation
            self._digest = digest
            self._lock = lock
            return self
        except Exception as error:
            if lock is not None:
                lock.release()
            if isinstance(error, PoolAllocationError):
                raise
            if isinstance(error, StorageError):
                raise PoolAllocationError("operator directory or lock is unsafe") from error
            raise PoolAllocationError("operator allocation could not be acquired") from error

    def assert_current(self, policy):
        """Fail closed if the allocation file or active policy changed under lock."""
        if self._lock is None or self._lock.descriptor is None:
            raise PoolAllocationError("physical pool lock is not held")
        raw = _read_allocation(self.allocation_path, self.uid)
        allocation = _validate_allocation(raw, self.physical_host_id, self.uid)
        digest = hashlib.sha256(json_bytes(allocation, maximum_bytes=ALLOCATION_MAX_BYTES)).digest()
        if digest != self._digest:
            raise PoolAllocationError("operator allocation changed while the pool was locked")
        self._check_policy(policy, allocation)
        return True

    @property
    def allocation(self):
        return None if self._allocation is None else dict(self._allocation)

    def release(self):
        """Release after trusted cleanup has independently proved reclamation."""
        lock, self._lock = self._lock, None
        self._digest = None
        self._allocation = None
        if lock is not None:
            lock.release()

    def __enter__(self):
        if self._lock is None:
            raise PoolAllocationError("call acquire(policy) before entering the context")
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.release()
