"""One shared-store, host-role lifetime pin for up to three worker assignments.

The owner only releases its lock descriptors. Runtime supervision must first
reap the child and prove the shared cgroup empty; this module cannot attest
either condition.
"""

from dataclasses import dataclass
import hashlib
import math
import os
from pathlib import Path
import secrets
import stat
import sys
from threading import Lock
from types import MappingProxyType

try:
    import fcntl
except ImportError:  # Keep discovery importable off Linux.
    fcntl = None

from steamboat_security.clock import Clock
from steamboat_connector import artifact_pin as _pin
from steamboat_connector.catalog import CatalogVerifier
from steamboat_connector.validation import strict_json_loads, valid_typed_id


_COMPONENTS = ("worker-1", "worker-2", "worker-3")
_MAX_GROUP_RECORD_BYTES = 4096
_GROUP_FIELDS = {"version", "pin_id", "account_id", "device_id", "role",
                 "model_id", "catalog_sha256", "runtime_boot_id", "assignments"}
_ENTRY_FIELDS = {"component", "assignment_id", "assignment_sha256", "worker_boot_id"}


class AggregateArtifactPinError(_pin.ArtifactPinError):
    """The shared host artifact pin could not be established or retained."""


def _linux():
    if not sys.platform.startswith("linux") or fcntl is None:
        raise AggregateArtifactPinError("aggregate artifact pins require Linux flock semantics")


def _hex(value, length):
    return (type(value) is str and len(value) == length
            and all(char in "0123456789abcdef" for char in value))


def _validate_group_record(record):
    if (type(record) is not dict or set(record) != _GROUP_FIELDS
            or type(record["version"]) is not int or record["version"] != 2
            or not _hex(record["pin_id"], 64)
            or not valid_typed_id(record["account_id"], "acct")
            or not valid_typed_id(record["device_id"], "dev")
            or record["role"] != "host"
            or type(record["model_id"]) is not str or not record["model_id"]
            or len(record["model_id"]) > 128
            or not _hex(record["catalog_sha256"], 64)
            or not _hex(record["runtime_boot_id"], 32)
            or type(record["assignments"]) is not list
            or not 1 <= len(record["assignments"]) <= 3):
        raise AggregateArtifactPinError("aggregate runtime pin record is malformed")
    components = []
    assignment_ids = set()
    worker_boot_ids = set()
    for entry in record["assignments"]:
        if (type(entry) is not dict or set(entry) != _ENTRY_FIELDS
                or entry["component"] not in _COMPONENTS
                or not valid_typed_id(entry["assignment_id"], "asg")
                or not _hex(entry["assignment_sha256"], 64)
                or not _hex(entry["worker_boot_id"], 32)
                or entry["assignment_id"] in assignment_ids
                or entry["worker_boot_id"] in worker_boot_ids):
            raise AggregateArtifactPinError("aggregate runtime pin assignment entry is malformed")
        components.append(entry["component"])
        assignment_ids.add(entry["assignment_id"])
        worker_boot_ids.add(entry["worker_boot_id"])
    if components != sorted(components) or len(set(components)) != len(components):
        raise AggregateArtifactPinError("aggregate runtime pin entries are not uniquely sorted")
    return record


def _validated_worker_boot_mapping(components, worker_boot_ids):
    """Validate unique component identities before any store lock or write."""
    return (type(worker_boot_ids) is dict
            and set(worker_boot_ids) == set(components)
            and all(_hex(worker_boot_ids.get(component), 32) for component in components)
            and len(set(worker_boot_ids.values())) == len(components))


def _cleanup_inherited_fds(global_fd, role_fd):
    """Close each explicitly owned descriptor value at most once.

    bools, negative values, and non-integers are not descriptor ownership
    claims. Keeping them out of the cleanup owner prevents accidental closes
    of unrelated descriptors (notably fd 0/1 for bool values).
    """
    valid = []
    for descriptor in (global_fd, role_fd):
        if type(descriptor) is int and descriptor >= 0 and descriptor not in valid:
            valid.append(descriptor)
    if not valid:
        return None
    owner = _pin.PartialArtifactPinOwner(
        valid[0], valid[1] if len(valid) > 1 else None)
    try:
        owner.close_after_failed_acquire()
    except BaseException as error:
        error.pin_owner = owner
        raise
    return owner


def _read_record(path, uid):
    path = Path(path)
    directory = _pin.open_private_directory(path.parent, uid=uid)
    descriptor = None
    try:
        descriptor = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                             dir_fd=directory)
        info = os.fstat(descriptor)
        named = os.stat(path.name, dir_fd=directory, follow_symlinks=False)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != uid
                or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1
                or info.st_size > _MAX_GROUP_RECORD_BYTES
                or (info.st_dev, info.st_ino) != (named.st_dev, named.st_ino)):
            raise AggregateArtifactPinError("aggregate runtime pin record is unsafe")
        raw = os.read(descriptor, _MAX_GROUP_RECORD_BYTES + 1)
        if len(raw) != info.st_size:
            raise AggregateArtifactPinError("aggregate runtime pin record changed while reading")
        record = _validate_group_record(strict_json_loads(raw, maximum_bytes=_MAX_GROUP_RECORD_BYTES))
        return record, (info.st_dev, info.st_ino, info.st_uid,
                        stat.S_IMODE(info.st_mode), info.st_nlink, info.st_size)
    finally:
        if descriptor is not None:
            os.close(descriptor)
        os.close(directory)


def _assert_lock_held(root, name, uid):
    descriptor = _pin._open_stable_lock(root, name, uid)
    try:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return
        fcntl.flock(descriptor, fcntl.LOCK_UN)
        raise AggregateArtifactPinError("aggregate runtime lock is no longer held")
    finally:
        os.close(descriptor)


@dataclass(frozen=True)
class _Authority:
    assignment_id: str
    component: str
    assignment_bytes: bytes
    assignment_sha256: str
    assignment_deadline: float
    worker_boot_id: str


class _AssignmentSlice:
    """Concrete flat pin projection consumed by RuntimeAssignmentGuard."""

    def __init__(self, owner, authority):
        self.owner = owner
        self.authority = authority
        self.record = MappingProxyType({
            "version": 1, "pin_id": owner.record["pin_id"],
            "account_id": owner.record["account_id"],
            "device_id": owner.record["device_id"], "role": "host",
            "assignment_id": authority.assignment_id,
            "catalog_sha256": owner.record["catalog_sha256"],
            "assignment_sha256": authority.assignment_sha256,
            "boot_id": authority.worker_boot_id,
        })

    def assert_open_descriptors(self):
        self.owner.assert_open_descriptors()
        if self.authority.assignment_id not in self.owner._authorities:
            raise AggregateArtifactPinError("assignment is outside the aggregate pin")
        return True

    def close(self):
        raise AggregateArtifactPinError("assignment guard is owned by its aggregate pin")


class RuntimeArtifactGroupPin:
    """Parent-owned SH global + EX host-role pin for one to three assignments."""

    def __init__(self, *, root, uid, global_fd, role_fd, record, record_path,
                 record_identity, signed_catalog, catalog_deadline, captured_mono,
                 clock_domain, clock, authorities):
        self.root = Path(root)
        self.uid = uid
        self.global_fd = global_fd
        self.role_fd = role_fd
        self.record = MappingProxyType(dict(record))
        self.record_path = Path(record_path)
        self._record_identity = record_identity
        self.signed_catalog = bytes(signed_catalog)
        self.catalog_deadline = float(catalog_deadline)
        self.captured_mono = float(captured_mono)
        self.clock_domain = clock_domain
        self.clock = clock
        self._authorities = {item.assignment_id: item for item in authorities}
        self._fd_identity = ( _pin.InheritedArtifactPin._identity(global_fd),
                             _pin.InheritedArtifactPin._identity(role_fd))
        self._lock = Lock()
        self._state = "open"
        self._uncertain_fds = {}

    @classmethod
    def acquire(cls, views, *, clock, runtime_boot_id, worker_boot_ids):
        """Acquire both store locks before checking active signed views."""
        _linux()
        from steamboat_runtime.assigned_artifacts import AssignedArtifactView
        if (type(views) not in (tuple, list) or not 1 <= len(views) <= 3
                or any(type(view) is not AssignedArtifactView for view in views)
                or type(clock) is not Clock or not _hex(runtime_boot_id, 32)
                or type(worker_boot_ids) is not dict):
            raise AggregateArtifactPinError("aggregate pin inputs are malformed")
        first = views[0]
        installer = first.installer
        if (first.role != "host" or type(installer.verifier) is not CatalogVerifier
                or installer.verifier.clock is not clock):
            raise AggregateArtifactPinError("aggregate pin requires host views and their exact core Clock")
        if any(view.installer is not installer or view.role != "host"
               or view.account_id != first.account_id or view.device_id != first.device_id
               for view in views):
            raise AggregateArtifactPinError("aggregate views must share one installer, account, device, and host role")
        components = [getattr(view.assignment, "payload", {}).get("component")
                      for view in views]
        if (any(component not in _COMPONENTS for component in components)
                or len(set(components)) != len(components)
                or not _validated_worker_boot_mapping(components, worker_boot_ids)):
            raise AggregateArtifactPinError("aggregate worker component or boot mapping is malformed")
        ordered_views = sorted(views, key=lambda view: view.assignment.payload["component"])
        root, uid = installer.root, installer.uid
        global_fd = role_fd = None
        record = None
        record_name = _pin._pin_record("host")
        record_path = Path(root) / record_name
        pin_id = secrets.token_hex(32)
        try:
            global_fd = _pin._lock(root, _pin.GLOBAL_LOCK, uid, fcntl.LOCK_SH)
            role_fd = _pin._lock(root, _pin.ROLE_LOCKS["host"], uid, fcntl.LOCK_EX)
            _pin._remove_old_pin_record(root, record_name, uid)
            # Every active pointer and signature is checked while both locks
            # protect this one-store snapshot against mutation/replacement.
            verified = []
            for view in ordered_views:
                view._locked_manifest()
                verified.append(view)
            catalogs = [view.catalog for view in verified]
            if (any(catalog is None for catalog in catalogs)
                    or len({catalog.document_sha256 for catalog in catalogs}) != 1
                    or len({catalog.payload["model"]["model_id"] for catalog in catalogs}) != 1
                    or len({catalog.payload["manifest"]["fingerprint"] for catalog in catalogs}) != 1):
                raise AggregateArtifactPinError("aggregate views do not share one signed model/catalog")
            verifier = installer.verifier
            catalog = verifier.verify_catalog(catalogs[0].document_bytes)
            catalog_deadline, _ = _pin.RuntimeArtifactPin._verifier_deadlines(
                verifier, catalog, verifier.verify_assignment(
                    verified[0].assignment.document_bytes, catalog,
                    account_id=first.account_id, device_id=first.device_id, role="host"))
            authorities = []
            entries = []
            for view in verified:
                assignment = verifier.verify_assignment(
                    view.assignment.document_bytes, catalog,
                    account_id=first.account_id, device_id=first.device_id, role="host")
                component = assignment.payload["component"]
                if (assignment.payload["assignment_id"] != view.assignment_id
                        or view.assignment.payload["component"] != component
                        or view.manifest["model_id"] != catalog.payload["model"]["model_id"]):
                    raise AggregateArtifactPinError("view differs from its signed host assignment")
                _, deadline = _pin.RuntimeArtifactPin._verifier_deadlines(
                    verifier, catalog, assignment)
                raw = bytes(assignment.document_bytes)
                authority = _Authority(view.assignment_id, component, raw,
                                       hashlib.sha256(raw).hexdigest(), deadline,
                                       worker_boot_ids[component])
                authorities.append(authority)
                entries.append({"component": component,
                                "assignment_id": view.assignment_id,
                                "assignment_sha256": authority.assignment_sha256,
                                "worker_boot_id": authority.worker_boot_id})
            sample = clock.sample()
            domain = __import__("steamboat_runtime.protocol.clock",
                                fromlist=["clock_identity"]).clock_identity()
            if not domain:
                raise AggregateArtifactPinError("Linux monotonic clock domain is unavailable")
            record = {"version": 2, "pin_id": pin_id,
                      "account_id": first.account_id, "device_id": first.device_id,
                      "role": "host", "model_id": catalog.payload["model"]["model_id"],
                      "catalog_sha256": hashlib.sha256(catalog.document_bytes).hexdigest(),
                      "runtime_boot_id": runtime_boot_id,
                      "assignments": entries}
            _validate_group_record(record)
            from steamboat_connector.validation import json_bytes
            if len(json_bytes(record, maximum_bytes=_MAX_GROUP_RECORD_BYTES)) > _MAX_GROUP_RECORD_BYTES:
                raise AggregateArtifactPinError("aggregate runtime pin record exceeds its bound")
            _pin._write_pin_record(root, record_name, record, uid)
            group = cls(root=root, uid=uid, global_fd=global_fd, role_fd=role_fd,
                        record=record, record_path=record_path,
                        record_identity=_read_record(record_path, uid)[1],
                        signed_catalog=catalog.document_bytes,
                        catalog_deadline=catalog_deadline,
                        captured_mono=sample.monotonic, clock_domain=domain,
                        clock=clock, authorities=authorities)
            group.assert_open_descriptors()
            return group
        except BaseException as error:
            owner = _pin.PartialArtifactPinOwner(global_fd, role_fd)
            if record is not None:
                try:
                    _pin._remove_old_pin_record(root, record_name, uid, expected=record)
                except Exception as cleanup_error:
                    cleanup_error.pin_owner = owner
                    raise cleanup_error from error
            try:
                owner.close_after_failed_acquire()
            except Exception as cleanup_error:
                cleanup_error.pin_owner = owner
                raise cleanup_error from error
            raise

    def _assert_open_locked(self):
        if self._state != "open":
            raise AggregateArtifactPinError("aggregate artifact pin is unavailable")
        try:
            current = (_pin.InheritedArtifactPin._identity(self.global_fd),
                       _pin.InheritedArtifactPin._identity(self.role_fd))
            names = []
            for name in (_pin.GLOBAL_LOCK, _pin.ROLE_LOCKS["host"]):
                info = os.stat(self.root / name, follow_symlinks=False)
                names.append((info.st_dev, info.st_ino))
            record, record_identity = _read_record(self.record_path, self.uid)
        except (OSError, TypeError, ValueError) as error:
            raise AggregateArtifactPinError("aggregate artifact pin identity is unavailable") from error
        if (current != self._fd_identity
                or names != [(self._fd_identity[0][0], self._fd_identity[0][1]),
                             (self._fd_identity[1][0], self._fd_identity[1][1])]
                or record_identity != self._record_identity
                or record != dict(self.record)):
            raise AggregateArtifactPinError("aggregate artifact pin identity changed")
        _assert_lock_held(self.root, _pin.GLOBAL_LOCK, self.uid)
        _assert_lock_held(self.root, _pin.ROLE_LOCKS["host"], self.uid)
        return True

    def assert_open_descriptors(self):
        with self._lock:
            return self._assert_open_locked()

    def make_guard(self, assignment_id, child_clock, child_verifier):
        from steamboat_connector.artifact_pin import RuntimeAssignmentGuard
        if (not valid_typed_id(assignment_id, "asg") or type(child_clock) is not Clock
                or type(child_verifier) is not CatalogVerifier
                or child_verifier.clock is not child_clock):
            raise AggregateArtifactPinError("aggregate guard inputs are malformed")
        authority = self._authorities.get(assignment_id)
        if authority is None:
            raise AggregateArtifactPinError("assignment is outside the aggregate pin")
        if child_clock is not self.clock:
            current_domain = __import__("steamboat_runtime.protocol.clock",
                                        fromlist=["clock_identity"]).clock_identity()
            if not self.clock_domain or current_domain != self.clock_domain:
                raise AggregateArtifactPinError("parent and child monotonic clock domains differ")
        try:
            catalog = child_verifier.verify_catalog(self.signed_catalog)
            assignment = child_verifier.verify_assignment(
                authority.assignment_bytes, catalog,
                account_id=self.record["account_id"], device_id=self.record["device_id"],
                role="host")
            if (assignment.payload["assignment_id"] != assignment_id
                    or assignment.payload["component"] != authority.component
                    or hashlib.sha256(assignment.document_bytes).hexdigest()
                    != authority.assignment_sha256):
                raise AggregateArtifactPinError("child verifier changed signed assignment identity")
            child_catalog_deadline, child_assignment_deadline = (
                _pin.RuntimeArtifactPin._verifier_deadlines(child_verifier, catalog, assignment))
            sample = child_clock.sample()
            if sample.monotonic < self.captured_mono:
                raise AggregateArtifactPinError("child monotonic sample predates aggregate pin")
            slice_pin = _AssignmentSlice(self, authority)
            payload = assignment.payload
            guard = RuntimeAssignmentGuard(
                slice_pin, child_clock, child_verifier, self.clock_domain,
                self.captured_mono, self.catalog_deadline,
                authority.assignment_deadline, child_catalog_deadline,
                child_assignment_deadline, catalog.payload["issued_at"],
                catalog.payload["expires_at"], assignment.payload["issued_at"],
                assignment.payload["expires_at"], payload["component"],
                payload["manifest_fingerprint"], payload["assignment_id"],
                payload["account_id"], payload["device_id"], payload["role"],
                authority.assignment_sha256,
                hashlib.sha256(self.signed_catalog).hexdigest(),
                slice_pin.record)
            guard.check()
            return guard
        except AggregateArtifactPinError:
            raise
        except Exception as error:
            raise AggregateArtifactPinError("aggregate assignment guard could not be established") from error

    def child_launch_metadata(self, assignment_id):
        authority = self._authorities.get(assignment_id)
        if authority is None:
            raise AggregateArtifactPinError("assignment is outside the aggregate pin")
        self.assert_open_descriptors()
        return {"global_fd": self.global_fd, "role_fd": self.role_fd,
                "root": str(self.root), "uid": self.uid,
                "record_path": str(self.record_path), "record": dict(self.record),
                "component": authority.component,
                "worker_boot_id": authority.worker_boot_id,
                "signed_catalog": self.signed_catalog,
                "signed_assignment": authority.assignment_bytes,
                "clock_domain": self.clock_domain,
                "captured_mono": self.captured_mono,
                "catalog_deadline": self.catalog_deadline,
                "assignment_deadline": authority.assignment_deadline}

    def release(self):
        """Release only after supervision proves child reap and an empty cgroup."""
        with self._lock:
            if self._state == "closed":
                return
            if self._state != "open":
                raise AggregateArtifactPinError("aggregate pin cleanup is faulted")
            self._assert_open_locked()
            _pin._remove_old_pin_record(self.root, self.record_path.name, self.uid,
                                        expected=dict(self.record))
            errors = []
            for name in ("role_fd", "global_fd"):
                descriptor = getattr(self, name)
                setattr(self, name, None)
                try:
                    os.close(descriptor)
                except OSError as error:
                    self._uncertain_fds[name] = descriptor
                    errors.append(error)
            self._state = "faulted" if errors else "closed"
            if errors:
                raise AggregateArtifactPinError("aggregate pin descriptor cleanup failed") from errors[0]


class InheritedGroupPin:
    """Child-side lifetime owner; close descriptors without ``LOCK_UN``."""

    def __init__(self, *, global_fd, role_fd, root, uid, record, record_path,
                 record_identity, signed_catalog, assignment_bytes,
                 clock_domain, captured_mono, catalog_deadline,
                 assignment_deadline, clock, verifier, component, worker_boot_id):
        self.global_fd, self.role_fd = global_fd, role_fd
        self.root, self.uid = Path(root), uid
        self.record = MappingProxyType(dict(record))
        self.record_path = Path(record_path)
        self._record_identity = record_identity
        self.signed_catalog = bytes(signed_catalog)
        self.assignment_bytes = bytes(assignment_bytes)
        self.clock_domain = clock_domain
        self.captured_mono = float(captured_mono)
        self.catalog_deadline = float(catalog_deadline)
        self.assignment_deadline = float(assignment_deadline)
        self.clock = clock
        self.verifier = verifier
        self.component = component
        self.worker_boot_id = worker_boot_id
        self._identity = (_pin.InheritedArtifactPin._identity(global_fd),
                          _pin.InheritedArtifactPin._identity(role_fd))
        self._lock = Lock()
        self._state = "open"
        self._uncertain_fds = {}
        entry = next(item for item in record["assignments"]
                     if item["component"] == component)
        self.authority = _Authority(entry["assignment_id"], component,
                                    self.assignment_bytes, entry["assignment_sha256"],
                                    self.assignment_deadline, worker_boot_id)
        self._authorities = {self.authority.assignment_id: self.authority}

    def assert_open_descriptors(self):
        with self._lock:
            if self._state != "open":
                raise AggregateArtifactPinError("inherited aggregate pin is unavailable")
            current = (_pin.InheritedArtifactPin._identity(self.global_fd),
                       _pin.InheritedArtifactPin._identity(self.role_fd))
            if current != self._identity:
                raise AggregateArtifactPinError("inherited aggregate lock identity changed")
            named = []
            for name in (_pin.GLOBAL_LOCK, _pin.ROLE_LOCKS["host"]):
                info = os.stat(self.root / name, follow_symlinks=False)
                named.append((info.st_dev, info.st_ino))
            if named != [(self._identity[0][0], self._identity[0][1]),
                         (self._identity[1][0], self._identity[1][1])]:
                raise AggregateArtifactPinError("inherited aggregate lock path changed")
            actual, identity = _read_record(self.record_path, self.uid)
            if actual != dict(self.record) or identity != self._record_identity:
                raise AggregateArtifactPinError("inherited aggregate pin record changed")
            _assert_lock_held(self.root, _pin.GLOBAL_LOCK, self.uid)
            _assert_lock_held(self.root, _pin.ROLE_LOCKS["host"], self.uid)
            return True

    def make_guard(self):
        owner_slice = _AssignmentSlice(self, self.authority)
        return _make_inherited_guard(self, owner_slice)

    def close(self):
        with self._lock:
            if self._state == "closed":
                return
            if self._state != "open":
                raise AggregateArtifactPinError("inherited aggregate descriptor cleanup is faulted")
            self._state = "closing"
            errors = []
            for name in ("role_fd", "global_fd"):
                descriptor = getattr(self, name)
                setattr(self, name, None)
                try:
                    os.close(descriptor)
                except OSError as error:
                    self._uncertain_fds[name] = descriptor
                    errors.append(error)
            self._state = "faulted" if errors else "closed"
            if errors:
                raise AggregateArtifactPinError("inherited aggregate pin close failed") from errors[0]


def _make_inherited_guard(owner, owner_slice):
    from steamboat_connector.artifact_pin import RuntimeAssignmentGuard
    catalog = owner.verifier.verify_catalog(owner.signed_catalog)
    assignment = owner.verifier.verify_assignment(
        owner.assignment_bytes, catalog, account_id=owner.record["account_id"],
        device_id=owner.record["device_id"], role="host")
    child_catalog_deadline, child_assignment_deadline = (
        _pin.RuntimeArtifactPin._verifier_deadlines(owner.verifier, catalog, assignment))
    payload = assignment.payload
    guard = RuntimeAssignmentGuard(
        owner_slice, owner.clock, owner.verifier, owner.clock_domain,
        owner.captured_mono, owner.catalog_deadline, owner.assignment_deadline,
        child_catalog_deadline, child_assignment_deadline,
        catalog.payload["issued_at"], catalog.payload["expires_at"],
        payload["issued_at"], payload["expires_at"], payload["component"],
        payload["manifest_fingerprint"], payload["assignment_id"],
        payload["account_id"], payload["device_id"], payload["role"],
        owner.authority.assignment_sha256,
        hashlib.sha256(owner.signed_catalog).hexdigest(), owner_slice.record)
    guard.check()
    return guard


def validate_inherited_group_pin(global_fd, role_fd, *, root, uid, record_path,
                                 expected_record, component, worker_boot_id,
                                 clock_domain, captured_mono, catalog_deadline,
                                 assignment_deadline, clock, signed_catalog,
                                 signed_assignment, verifier):
    """Validate a worker's inherited descriptors and return ``(owner, guard)``."""
    _linux()
    raw = (global_fd, role_fd)
    success = False
    try:
        if (type(global_fd) is not int or type(role_fd) is not int
                or global_fd < 0 or role_fd < 0 or global_fd == role_fd
                or type(uid) is not int or type(clock) is not Clock
                or type(verifier) is not CatalogVerifier or verifier.clock is not clock
                or component not in _COMPONENTS or not _hex(worker_boot_id, 32)
                or type(clock_domain) is not str or not 1 <= len(clock_domain) <= 256
                or any(type(value) not in (int, float) or isinstance(value, bool)
                       or not math.isfinite(value) or value < 0
                       for value in (captured_mono, catalog_deadline, assignment_deadline))
                or captured_mono >= min(catalog_deadline, assignment_deadline)):
            raise AggregateArtifactPinError("inherited aggregate pin inputs are malformed")
        record = _validate_group_record(expected_record)
        entry = next((item for item in record["assignments"]
                      if item["component"] == component), None)
        if entry is None or entry["worker_boot_id"] != worker_boot_id:
            raise AggregateArtifactPinError("worker component is outside inherited aggregate pin")
        root_path = Path(os.path.abspath(os.fspath(root)))
        record_target = Path(os.path.abspath(os.fspath(record_path)))
        if record_target != root_path / _pin._pin_record("host"):
            raise AggregateArtifactPinError("inherited aggregate record path is invalid")
        for fd, lock_name in ((global_fd, _pin.GLOBAL_LOCK),
                              (role_fd, _pin.ROLE_LOCKS["host"])):
            info = os.fstat(fd)
            named = os.stat(root_path / lock_name, follow_symlinks=False)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != uid
                    or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1
                    or info.st_size != 0
                    or (info.st_dev, info.st_ino) != (named.st_dev, named.st_ino)):
                raise AggregateArtifactPinError("inherited aggregate lock descriptor is unsafe")
        for lock_name in (_pin.GLOBAL_LOCK, _pin.ROLE_LOCKS["host"]):
            _assert_lock_held(root_path, lock_name, uid)
        actual_record, record_identity = _read_record(record_target, uid)
        if actual_record != record:
            raise AggregateArtifactPinError("inherited aggregate pin record mismatch")
        from steamboat_runtime.protocol.clock import clock_identity
        if not clock_domain or clock_identity() != clock_domain:
            raise AggregateArtifactPinError("inherited aggregate clock domain differs")
        catalog = verifier.verify_catalog(signed_catalog)
        assignment = verifier.verify_assignment(
            signed_assignment, catalog, account_id=record["account_id"],
            device_id=record["device_id"], role="host")
        if (hashlib.sha256(catalog.document_bytes).hexdigest() != record["catalog_sha256"]
                or assignment.payload["component"] != component
                or assignment.payload["assignment_id"] != entry["assignment_id"]
                or hashlib.sha256(assignment.document_bytes).hexdigest()
                != entry["assignment_sha256"]
                or catalog.payload["model"]["model_id"] != record["model_id"]):
            raise AggregateArtifactPinError("inherited signed authority differs from group record")
        child_catalog_deadline, child_assignment_deadline = (
            _pin.RuntimeArtifactPin._verifier_deadlines(verifier, catalog, assignment))
        sample = clock.sample()
        if (sample.monotonic < captured_mono
                or sample.monotonic >= min(catalog_deadline, assignment_deadline)):
            raise AggregateArtifactPinError("inherited aggregate authority expired")
        for fd in raw:
            os.set_inheritable(fd, False)
        owner = InheritedGroupPin(
            global_fd=global_fd, role_fd=role_fd, root=root_path, uid=uid,
            record=record, record_path=record_target, record_identity=record_identity,
            signed_catalog=signed_catalog, assignment_bytes=signed_assignment,
            clock_domain=clock_domain, captured_mono=captured_mono,
            catalog_deadline=catalog_deadline, assignment_deadline=assignment_deadline,
            clock=clock, verifier=verifier, component=component,
            worker_boot_id=worker_boot_id)
        guard = _make_inherited_guard(owner, _AssignmentSlice(owner, owner.authority))
        success = True
        return owner, guard
    except BaseException as error:
        if not success:
            try:
                owner = _cleanup_inherited_fds(global_fd, role_fd)
            except BaseException as cleanup_error:
                if not hasattr(cleanup_error, "pin_owner"):
                    cleanup_error.pin_owner = None
                raise cleanup_error from error
        raise
