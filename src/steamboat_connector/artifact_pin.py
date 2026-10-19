"""Linux lifetime pins for immutable assigned artifacts.

Pins prevent every store mutation while a runtime owns assigned files. Their
descriptors are ownership signals, not proof of child reclamation: only the
supervisor that reaps the child and confirms an empty cgroup may release them.
"""

from contextlib import contextmanager
from dataclasses import dataclass, field
try:
    import fcntl
except ImportError:  # Keep module importable for cross-platform test discovery.
    fcntl = None
import hashlib
import math
import os
from pathlib import Path
import secrets
import stat
import sys
from threading import Lock
from types import MappingProxyType

from steamboat_security.clock import Clock
from steamboat_connector.storage import open_private_directory
from steamboat_connector.validation import json_bytes, strict_json_loads, valid_typed_id


GLOBAL_LOCK = ".runtime-ownership.lock"
ROLE_LOCKS = {"host": ".runtime-host.lock", "coordinator": ".runtime-coordinator.lock"}
PIN_PREFIX = ".runtime-pin-"
MAX_PIN_RECORD_BYTES = 4096


class ArtifactPinError(RuntimeError):
    pass


class ArtifactPinBusy(ArtifactPinError):
    """An artifact store is pinned or the requested role already has an owner."""


def _require_linux():
    if not sys.platform.startswith("linux") or fcntl is None:
        raise ArtifactPinError("runtime artifact pins require Linux flock semantics")


def _open_stable_lock(root, filename, uid):
    root = Path(root)
    directory = open_private_directory(root, uid=uid)
    try:
        descriptor = os.open(filename, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW,
                             0o600, dir_fd=directory)
        try:
            info = os.fstat(descriptor)
            named = os.stat(filename, dir_fd=directory, follow_symlinks=False)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != uid
                    or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1
                    or info.st_size != 0
                    or (info.st_dev, info.st_ino) != (named.st_dev, named.st_ino)):
                raise ArtifactPinError("artifact pin lock inode is unsafe or changed")
        except BaseException:
            os.close(descriptor)
            raise
        return descriptor
    finally:
        os.close(directory)


def _lock(root, filename, uid, mode, *, nonblocking=True):
    _require_linux()
    descriptor = _open_stable_lock(root, filename, uid)
    try:
        flags = mode | (fcntl.LOCK_NB if nonblocking else 0)
        try:
            fcntl.flock(descriptor, flags)
        except BlockingIOError as error:
            consumed = descriptor
            descriptor = None
            try:
                os.close(consumed)
            except OSError as close_error:
                failure = ArtifactPinError("contended runtime lock descriptor cleanup failed")
                failure.pin_owner = _uncertain_lock_owner(consumed)
                raise failure from close_error
            raise ArtifactPinBusy("artifact store or runtime role is pinned") from error
        return descriptor
    except BaseException:
        if descriptor is not None:
            consumed = descriptor
            descriptor = None
            try:
                os.close(consumed)
            except OSError as close_error:
                failure = ArtifactPinError("runtime lock descriptor cleanup failed")
                failure.pin_owner = _uncertain_lock_owner(consumed)
                raise failure from close_error
        raise


@contextmanager
def artifact_store_mutation(root, *, uid=None):
    """Hold nonblocking global EX before acquiring any installer state lock."""
    uid = os.getuid() if uid is None else uid
    descriptor = _lock(root, GLOBAL_LOCK, uid, fcntl.LOCK_EX)
    try:
        yield
    finally:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)


def _pin_record(role):
    return PIN_PREFIX + role + ".json"


def _validate_store_pin_entry(root, name, *, uid):
    if name in {GLOBAL_LOCK, *ROLE_LOCKS.values()}:
        maximum = 0
    elif name in {PIN_PREFIX + "host.json", PIN_PREFIX + "coordinator.json"}:
        maximum = MAX_PIN_RECORD_BYTES
    else:
        return False
    info = os.stat(Path(root) / name, follow_symlinks=False)
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != uid
            or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1
            or info.st_size > maximum):
        raise ArtifactPinError("artifact pin entry is unsafe")
    return True


def _close_inherited_descriptors(descriptors):
    closed = set()
    errors = []
    for fd in descriptors:
        if fd in closed:
            continue
        closed.add(fd)
        try:
            os.set_inheritable(fd, False)
        except (OSError, TypeError, ValueError) as error:
            errors.append(error)
        try:
            os.close(fd)
        except (OSError, TypeError, ValueError) as error:
            errors.append(error)
    return errors


def _write_pin_record(root, filename, record, uid):
    data = json_bytes(record, maximum_bytes=MAX_PIN_RECORD_BYTES)
    directory = open_private_directory(root, uid=uid)
    try:
        descriptor = os.open(filename, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                             | os.O_NOFOLLOW, 0o600, dir_fd=directory)
        try:
            view = memoryview(data)
            while view:
                amount = os.write(descriptor, view)
                if amount <= 0:
                    raise ArtifactPinError("short runtime pin record write")
                view = view[amount:]
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.fsync(directory)
    finally:
        os.close(directory)


def _remove_old_pin_record(root, filename, uid, *, expected=None):
    """Remove an orphan only after caller holds that role's exclusive lock."""
    directory = open_private_directory(root, uid=uid)
    try:
        try:
            info = os.stat(filename, dir_fd=directory, follow_symlinks=False)
        except FileNotFoundError:
            return
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != uid
                or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1
                or info.st_size > MAX_PIN_RECORD_BYTES):
            raise ArtifactPinError("stale runtime pin record is unsafe")
        if expected is not None:
            descriptor = os.open(filename, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                                 dir_fd=directory)
            try:
                actual = strict_json_loads(
                    os.read(descriptor, MAX_PIN_RECORD_BYTES + 1),
                    maximum_bytes=MAX_PIN_RECORD_BYTES)
            finally:
                os.close(descriptor)
            if actual != dict(expected):
                raise ArtifactPinError("runtime pin record changed before release")
        os.unlink(filename, dir_fd=directory)
        os.fsync(directory)
    finally:
        os.close(directory)


@dataclass
class RuntimeAssignmentGuard:
    """Clock-clipped signed-authority fence paired with a live descriptor pin."""

    pin: object
    child_clock: Clock
    child_verifier: object
    clock_domain: str
    captured_mono: float
    parent_catalog_deadline: float
    parent_assignment_deadline: float
    child_catalog_deadline: float
    child_assignment_deadline: float
    catalog_issued_at: int
    catalog_expires_at: int
    assignment_issued_at: int
    assignment_expires_at: int
    component: str
    manifest_fingerprint: str
    assignment_id: str
    account_id: str
    device_id: str
    role: str
    assignment_sha256: str
    catalog_sha256: str
    record_snapshot: object
    _deadline_lock: object = field(default_factory=Lock, init=False, repr=False)
    _catalog_deadline: float = field(default=0.0, init=False, repr=False)
    _assignment_deadline: float = field(default=0.0, init=False, repr=False)

    def __post_init__(self):
        self._catalog_deadline = min(self.parent_catalog_deadline,
                                     self.child_catalog_deadline)
        self._assignment_deadline = min(self.parent_assignment_deadline,
                                         self.child_assignment_deadline)

    def check(self):
        if type(self.child_clock) is not Clock:
            raise ArtifactPinError("runtime guard requires the core Clock")
        from steamboat_runtime.protocol.clock import clock_identity
        if not self.clock_domain or clock_identity() != self.clock_domain:
            raise ArtifactPinError("parent and child monotonic clock domains differ")
        with self._deadline_lock:
            try:
                sample = self.child_clock.sample()
            except Exception as error:
                raise ArtifactPinError("runtime clock is not trusted") from error
            catalog_candidate = (sample.monotonic + self.catalog_expires_at
                                 - sample.latest_wall)
            assignment_candidate = (sample.monotonic + self.assignment_expires_at
                                   - sample.latest_wall)
            self._catalog_deadline = min(self._catalog_deadline,
                                         self.parent_catalog_deadline,
                                         self.child_catalog_deadline,
                                         catalog_candidate)
            self._assignment_deadline = min(self._assignment_deadline,
                                            self.parent_assignment_deadline,
                                            self.child_assignment_deadline,
                                            assignment_candidate)
            if (sample.monotonic < self.captured_mono
                    or self.catalog_issued_at > sample.earliest_wall
                    or self.assignment_issued_at > sample.earliest_wall
                    or sample.latest_wall >= self.catalog_expires_at
                    or sample.latest_wall >= self.assignment_expires_at
                    or sample.monotonic >= min(self._catalog_deadline,
                                               self._assignment_deadline)):
                raise ArtifactPinError("assigned runtime pin validity has expired")
            self.pin.assert_open_descriptors()
            if (dict(self.pin.record) != dict(self.record_snapshot)
                    or self.pin.record.get("assignment_id") != self.assignment_id
                    or self.pin.record.get("account_id") != self.account_id
                    or self.pin.record.get("device_id") != self.device_id
                    or self.pin.record.get("role") != self.role
                    or self.pin.record.get("assignment_sha256") != self.assignment_sha256
                    or self.pin.record.get("catalog_sha256") != self.catalog_sha256):
                raise ArtifactPinError("runtime assignment scope changed")
            return sample

    def close(self):
        """Close child-owned inherited descriptors without issuing LOCK_UN."""
        if not isinstance(self.pin, InheritedArtifactPin):
            raise ArtifactPinError("only a child guard owns inherited descriptors")
        self.pin.close()


class InheritedArtifactPin:
    """Child-side owner retaining inherited flock descriptions for its lifetime."""

    def __init__(self, *, global_fd, role_fd, root, uid, role, record,
                 global_identity, role_identity):
        self.global_fd = global_fd
        self.role_fd = role_fd
        self.root = Path(root)
        self.uid = uid
        self.role = role
        self.record = MappingProxyType(dict(record))
        self._global_identity = global_identity
        self._role_identity = role_identity
        self._close_state = "open"
        self._close_lock = Lock()
        self._uncertain_descriptors = {}

    @staticmethod
    def _identity(fd):
        info = os.fstat(fd)
        return (info.st_dev, info.st_ino, info.st_uid, stat.S_IMODE(info.st_mode),
                info.st_nlink, info.st_size)

    def assert_open_descriptors(self):
        with self._close_lock:
            if self._close_state != "open":
                raise ArtifactPinError("child runtime pin descriptors are unavailable")
            try:
                current = (self._identity(self.global_fd), self._identity(self.role_fd))
            except (OSError, TypeError, ValueError) as error:
                raise ArtifactPinError("child runtime pin descriptor was closed") from error
            if current != (self._global_identity, self._role_identity):
                raise ArtifactPinError("child runtime pin descriptor identity changed")
            return True

    def close(self):
        with self._close_lock:
            if self._close_state == "closed":
                return
            if self._close_state == "faulted":
                raise ArtifactPinError("child runtime pin descriptor cleanup is faulted")
            self._close_state = "closing"
            errors = []
            for field_name in ("role_fd", "global_fd"):
                descriptor = getattr(self, field_name)
                if descriptor is None:
                    continue
                # Consume ownership before close(2); an error leaves the FD
                # state ambiguous, so this number must never be retried.
                setattr(self, field_name, None)
                try:
                    os.close(descriptor)
                except OSError as error:
                    self._uncertain_descriptors[field_name] = descriptor
                    errors.append(error)
            self._close_state = "faulted" if errors else "closed"
            if errors:
                raise ArtifactPinError("child runtime pin descriptor cleanup failed") from errors[0]


class PartialArtifactPinOwner:
    """Fault-reporting owner for locks acquired before pin publication failed."""

    def __init__(self, global_fd, role_fd):
        self.global_fd = global_fd
        self.role_fd = role_fd
        self._state = "open"
        self._lock = Lock()
        self._close_outcomes = {
            "role_fd": "open" if role_fd is not None else "absent",
            "global_fd": "open" if global_fd is not None else "absent",
        }
        self._uncertain_descriptors = {}

    def close_after_failed_acquire(self):
        with self._lock:
            if self._state == "closed":
                return
            if self._state == "faulted":
                raise ArtifactPinError("partial runtime pin cleanup is faulted")
            self._state = "closing"
            errors = []
            seen = {}
            for name in ("role_fd", "global_fd"):
                descriptor = getattr(self, name)
                if descriptor is None:
                    continue
                if descriptor in seen:
                    # Two logical slots can be given the same numeric FD.
                    # Close it once and mirror the first outcome without ever
                    # retrying an ambiguous close against a reused number.
                    outcome, error = seen[descriptor]
                    setattr(self, name, None)
                    self._close_outcomes[name] = outcome
                    if outcome == "unknown":
                        self._uncertain_descriptors[name] = descriptor
                        errors.append(error)
                    continue
                try:
                    os.close(descriptor)
                except OSError as error:
                    seen[descriptor] = ("unknown", error)
                    self._close_outcomes[name] = "unknown"
                    self._uncertain_descriptors[name] = descriptor
                    errors.append(error)
                else:
                    seen[descriptor] = ("closed", None)
                    setattr(self, name, None)
                    self._close_outcomes[name] = "closed"
            self._state = "faulted" if errors else "closed"
            if errors:
                raise ArtifactPinError("partial runtime pin cleanup failed") from errors[0]


def _uncertain_lock_owner(descriptor):
    owner = PartialArtifactPinOwner(descriptor, None)
    owner._state = "faulted"
    owner._close_outcomes["global_fd"] = "unknown"
    owner._uncertain_descriptors["global_fd"] = descriptor
    return owner


class RuntimeArtifactPin:
    """Parent-owned shared-store and role pins for one verified assignment.

    ``release`` only drops descriptors. Production ownership must call it only
    after the child was reaped and its cgroup is empty; this primitive cannot
    establish either fact.
    """

    def __init__(self, root, *, uid, global_fd, role_fd, record_path, record,
                 signed_catalog, signed_assignment, catalog_deadline,
                 assignment_deadline, captured_mono, clock_domain, clock):
        self.root = Path(root)
        self.uid = uid
        self.global_fd = global_fd
        self.role_fd = role_fd
        self.record_path = Path(record_path)
        self.record = MappingProxyType(dict(record))
        self.signed_catalog = bytes(signed_catalog)
        self.signed_assignment = bytes(signed_assignment)
        self.catalog_deadline = float(catalog_deadline)
        self.assignment_deadline = float(assignment_deadline)
        self.captured_mono = float(captured_mono)
        self.clock_domain = clock_domain
        self.clock = clock
        self._released = False
        self._release_faulted = False
        self._close_state = {"role": "open", "global": "open"}
        self._release_lock = Lock()
        self._global_identity = InheritedArtifactPin._identity(global_fd)
        self._role_identity = InheritedArtifactPin._identity(role_fd)

    @classmethod
    def acquire(cls, view, *, clock, boot_id):
        from steamboat_runtime.assigned_artifacts import AssignedArtifactView
        from steamboat_connector.catalog import CatalogVerifier

        if (type(view) is not AssignedArtifactView or type(clock) is not Clock
                or type(view.installer.verifier) is not CatalogVerifier
                or view.installer.verifier.clock is not clock):
            raise ArtifactPinError("pin requires the exact assigned view and its core Clock verifier")
        if (view.role not in ROLE_LOCKS or not valid_typed_id(view.assignment_id, "asg")
                or not valid_typed_id(view.account_id, "acct")
                or not valid_typed_id(view.device_id, "dev")
                or type(boot_id) is not str or len(boot_id) != 32
                or any(c not in "0123456789abcdef" for c in boot_id)):
            raise ArtifactPinError("runtime pin identity is malformed")
        verifier = view.installer.verifier
        root = view.installer.root
        uid = view.installer.uid
        global_fd = role_fd = None
        record_path = None
        pin_id = secrets.token_hex(32)
        record_name = _pin_record(view.role)
        domain = __import__("steamboat_runtime.protocol.clock", fromlist=["clock_identity"]).clock_identity()
        if not domain:
            raise ArtifactPinError("Linux monotonic clock domain cannot be identified")
        try:
            global_fd = _lock(root, GLOBAL_LOCK, uid, fcntl.LOCK_SH)
            role_fd = _lock(root, ROLE_LOCKS[view.role], uid, fcntl.LOCK_EX)
            _remove_old_pin_record(root, record_name, uid)
            # Mutation exclusion precedes verification so a concurrent owner
            # update cannot slip between active-view validation and publication.
            view._locked_manifest()
            catalog_bytes = bytes(view.catalog.document_bytes)
            assignment_bytes = bytes(view.assignment.document_bytes)
            catalog = verifier.verify_catalog(catalog_bytes)
            assignment = verifier.verify_assignment(
                assignment_bytes, catalog, account_id=view.account_id,
                device_id=view.device_id, role=view.role)
            sample = clock.sample()
            catalog_deadline, assignment_deadline = cls._verifier_deadlines(
                verifier, catalog, assignment)
            record = {
                "version": 1, "pin_id": pin_id, "account_id": view.account_id,
                "device_id": view.device_id, "role": view.role,
                "assignment_id": view.assignment_id,
                "catalog_sha256": hashlib.sha256(catalog_bytes).hexdigest(),
                "assignment_sha256": hashlib.sha256(assignment_bytes).hexdigest(),
                "boot_id": boot_id,
            }
            _write_pin_record(root, record_name, record, uid)
            record_path = Path(root) / record_name
            return cls(root, uid=uid, global_fd=global_fd, role_fd=role_fd,
                       record_path=record_path, record=record,
                       signed_catalog=catalog_bytes,
                       signed_assignment=assignment_bytes,
                       catalog_deadline=catalog_deadline,
                       assignment_deadline=assignment_deadline,
                       captured_mono=sample.monotonic, clock_domain=domain, clock=clock)
        except BaseException as error:
            owner = PartialArtifactPinOwner(global_fd, role_fd)
            try:
                owner.close_after_failed_acquire()
            except ArtifactPinError as cleanup_error:
                # Keep the object reachable from the raised exception. It
                # records ambiguous close outcomes and forbids FD-number retry.
                cleanup_error.pin_owner = owner
                raise cleanup_error from error
            raise

    @staticmethod
    def _verifier_deadlines(verifier, catalog, assignment):
        cat_key = verifier._authority_identity(catalog)
        asg_key = verifier._authority_identity(assignment)
        deadlines = verifier._deadlines
        try:
            return deadlines[cat_key][0], deadlines[asg_key][0]
        except KeyError as error:
            raise ArtifactPinError("verifier did not retain signed authority deadlines") from error

    def assert_open_descriptors(self):
        with self._release_lock:
            return self._assert_open_descriptors_locked()

    def _assert_open_descriptors_locked(self):
        if self._released or self._release_faulted:
            raise ArtifactPinError("runtime artifact pin was released")
        try:
            current = (InheritedArtifactPin._identity(self.global_fd),
                       InheritedArtifactPin._identity(self.role_fd))
        except (OSError, TypeError, ValueError) as error:
            raise ArtifactPinError("runtime pin descriptor is no longer valid") from error
        if current != (self._global_identity, self._role_identity):
            raise ArtifactPinError("runtime pin lock inode changed")
        return True

    def make_guard(self, *, child_clock, child_verifier):
        from steamboat_connector.catalog import CatalogVerifier
        if type(child_clock) is not Clock:
            raise ArtifactPinError("runtime guard requires the exact core Clock")
        if type(child_verifier) is not CatalogVerifier or child_verifier.clock is not child_clock:
            raise ArtifactPinError("child guard requires its core Clock catalog verifier")
        if child_clock is not self.clock:
            from steamboat_runtime.protocol.clock import clock_identity
            if not self.clock_domain or clock_identity() != self.clock_domain:
                raise ArtifactPinError("parent and child do not share a Linux monotonic domain")
        try:
            catalog = child_verifier.verify_catalog(self.signed_catalog)
            assignment = child_verifier.verify_assignment(
                self.signed_assignment, catalog,
                account_id=self.record["account_id"],
                device_id=self.record["device_id"], role=self.record["role"])
            child_catalog_deadline, child_assignment_deadline = self._verifier_deadlines(
                child_verifier, catalog, assignment)
        except Exception as error:
            raise ArtifactPinError("child verifier rejected pinned signed authority") from error
        sample = child_clock.sample()
        if sample.monotonic < self.captured_mono:
            raise ArtifactPinError("child monotonic sample predates pin capture")
        payload = assignment.payload
        guard = RuntimeAssignmentGuard(
            self, child_clock, child_verifier, self.clock_domain, self.captured_mono,
            self.catalog_deadline, self.assignment_deadline,
            child_catalog_deadline, child_assignment_deadline,
            catalog.payload["issued_at"], catalog.payload["expires_at"],
            assignment.payload["issued_at"], assignment.payload["expires_at"],
            payload["component"], payload["manifest_fingerprint"],
            payload["assignment_id"], payload["account_id"], payload["device_id"],
            payload["role"], hashlib.sha256(self.signed_assignment).hexdigest(),
            hashlib.sha256(self.signed_catalog).hexdigest(),
            MappingProxyType(dict(self.record)))
        guard.check()
        return guard

    def child_launch_metadata(self):
        """Return launch metadata; pass only these FDs to the child explicitly."""
        with self._release_lock:
            self._assert_open_descriptors_locked()
            return {"global_fd": self.global_fd, "role_fd": self.role_fd,
                    "record_path": str(self.record_path), "record": dict(self.record),
                    "signed_catalog": self.signed_catalog,
                    "signed_assignment": self.signed_assignment,
                    "clock_domain": self.clock_domain, "captured_mono": self.captured_mono,
                    "catalog_deadline": self.catalog_deadline,
                    "assignment_deadline": self.assignment_deadline}

    def release(self):
        """Drop parent ownership; caller must already have reaped child/cgroup."""
        with self._release_lock:
            if self._released:
                return
            if self._release_faulted:
                raise ArtifactPinError("runtime pin cleanup is faulted")
            _remove_old_pin_record(self.root, self.record_path.name, self.uid,
                                   expected=self.record)
            release_error = None
            for name in ("role", "global"):
                field_name = name + "_fd"
                descriptor = getattr(self, field_name)
                if descriptor is None:
                    continue
                # Consume ownership before close(2); an error leaves this
                # descriptor number ambiguous and must never be retried.
                setattr(self, field_name, None)
                self._close_state[name] = "closing"
                try:
                    os.close(descriptor)
                except OSError as error:
                    release_error = release_error or error
                    self._close_state[name] = "unknown"
                    self._release_faulted = True
                else:
                    self._close_state[name] = "closed"
            if release_error is not None:
                raise ArtifactPinError("runtime pin descriptor cleanup failed") from release_error
            self._released = True


def validate_inherited_pin(global_fd, role_fd, *, root, uid, role, record_path,
                           expected_record, clock_domain, captured_mono,
                           catalog_deadline, assignment_deadline, clock,
                           signed_catalog, signed_assignment, verifier):
    """Validate inherited descriptors and return a child owner retaining them.

    The returned guard owns its descriptor copies for the full runtime lifetime;
    its close method uses close(2), never LOCK_UN, and is for trusted process
    teardown after compute has stopped.
    """
    raw = (global_fd, role_fd)
    # Take ownership before any validation or cleanup operation can fail.
    # This owner records close(2) ambiguity and is transferred to the returned
    # guard only after the complete signed-identity check succeeds.
    input_owner = PartialArtifactPinOwner(global_fd, role_fd)
    try:
        _require_linux()
        from steamboat_connector.catalog import CatalogVerifier
        if (type(clock) is not Clock or role not in ROLE_LOCKS
                or type(global_fd) is not int or type(role_fd) is not int
                or global_fd < 0 or role_fd < 0 or global_fd == role_fd
                or type(verifier) is not CatalogVerifier or verifier.clock is not clock):
            raise ArtifactPinError("inherited runtime pin arguments are invalid")
        root_path = Path(os.path.abspath(os.fspath(root)))
        record_target = Path(os.path.abspath(os.fspath(record_path)))
        if (record_target.parent != root_path
            or record_target.name != _pin_record(role)
            or type(expected_record) is not dict
            or set(expected_record) != {"version", "pin_id", "account_id", "device_id",
                                       "role", "assignment_id", "catalog_sha256",
                                       "assignment_sha256", "boot_id"}
            or type(expected_record.get("version")) is not int
            or expected_record.get("version") != 1
            or type(expected_record.get("pin_id")) is not str
            or len(expected_record["pin_id"]) != 64
            or any(c not in "0123456789abcdef" for c in expected_record["pin_id"])
            or not valid_typed_id(expected_record.get("assignment_id"), "asg")
            or not valid_typed_id(expected_record.get("account_id"), "acct")
            or not valid_typed_id(expected_record.get("device_id"), "dev")
            or expected_record.get("role") != role
            or type(expected_record.get("catalog_sha256")) is not str
            or len(expected_record["catalog_sha256"]) != 64
            or any(c not in "0123456789abcdef" for c in expected_record["catalog_sha256"])
            or type(expected_record.get("assignment_sha256")) is not str
            or len(expected_record["assignment_sha256"]) != 64
            or any(c not in "0123456789abcdef" for c in expected_record["assignment_sha256"])
            or type(expected_record.get("boot_id")) is not str
            or len(expected_record["boot_id"]) != 32
                or any(c not in "0123456789abcdef" for c in expected_record["boot_id"])):
            raise ArtifactPinError("inherited runtime pin record identity is malformed")
        deadlines = (captured_mono, catalog_deadline, assignment_deadline)
        if (type(clock_domain) is not str or len(clock_domain) > 256
                or any(type(value) not in (int, float) or isinstance(value, bool)
                       or not math.isfinite(value)
                       or value < 0 for value in deadlines)
                or captured_mono >= min(catalog_deadline, assignment_deadline)):
            raise ArtifactPinError("inherited runtime pin clock fence is malformed")
    except BaseException:
        try:
            input_owner.close_after_failed_acquire()
        except ArtifactPinError as cleanup_error:
            cleanup_error.pin_owner = input_owner
            raise cleanup_error
        raise
    success = False
    try:
        for fd, lock_name in zip(raw, (GLOBAL_LOCK, ROLE_LOCKS[role])):
            info = os.fstat(fd)
            named = os.stat(Path(root) / lock_name, follow_symlinks=False)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != uid
                    or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1
                    or info.st_size != 0
                    or (info.st_dev, info.st_ino) != (named.st_dev, named.st_ino)):
                raise ArtifactPinError("inherited runtime pin descriptor is unsafe")
        # Prove that separate opens are blocked by the retained parent locks.
        for name, mode in ((GLOBAL_LOCK, fcntl.LOCK_EX),
                           (ROLE_LOCKS[role], fcntl.LOCK_EX)):
            probe = _open_stable_lock(root, name, uid)
            try:
                try:
                    fcntl.flock(probe, mode | fcntl.LOCK_NB)
                except BlockingIOError:
                    continue
                fcntl.flock(probe, fcntl.LOCK_UN)
                raise ArtifactPinError("parent runtime pin lock is not held")
            finally:
                os.close(probe)
        root_fd = open_private_directory(root_path, uid=uid)
        try:
            record_fd = os.open(record_target.name,
                                os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                                dir_fd=root_fd)
        finally:
            os.close(root_fd)
        try:
            info = os.fstat(record_fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != uid
                    or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1
                    or info.st_size > MAX_PIN_RECORD_BYTES):
                raise ArtifactPinError("runtime pin record is unsafe")
            raw_record = os.read(record_fd, MAX_PIN_RECORD_BYTES + 1)
        finally:
            os.close(record_fd)
        record = strict_json_loads(raw_record, maximum_bytes=MAX_PIN_RECORD_BYTES)
        if type(record) is not dict or record != expected_record or record.get("role") != role:
            raise ArtifactPinError("runtime pin record identity mismatch")
        from steamboat_runtime.protocol.clock import clock_identity
        if not clock_domain or clock_identity() != clock_domain:
            raise ArtifactPinError("inherited pin clock domain differs")
        try:
            catalog = verifier.verify_catalog(signed_catalog)
            assignment = verifier.verify_assignment(
                signed_assignment, catalog, account_id=record["account_id"],
                device_id=record["device_id"], role=role)
            if (assignment.payload["assignment_id"] != record["assignment_id"]
                    or hashlib.sha256(assignment.document_bytes).hexdigest()
                    != record["assignment_sha256"]
                    or hashlib.sha256(catalog.document_bytes).hexdigest()
                    != record["catalog_sha256"]):
                raise ArtifactPinError("signed child authority differs from pin record")
            child_catalog_deadline, child_assignment_deadline = (
                RuntimeArtifactPin._verifier_deadlines(verifier, catalog, assignment))
        except Exception as error:
            raise ArtifactPinError("child catalog verifier rejected pinned authority") from error
        sample = clock.sample()
        if (sample.monotonic < captured_mono
                or sample.monotonic >= min(catalog_deadline, assignment_deadline)):
            raise ArtifactPinError("inherited pin validity expired")
        # The supervisor may have explicitly passed these descriptors across
        # exec. They must not leak into any subsequent child process.
        for fd in raw:
            os.set_inheritable(fd, False)
        payload = assignment.payload
        inherited_pin = InheritedArtifactPin(
            global_fd=global_fd, role_fd=role_fd, root=root_path, uid=uid,
            role=role, record=record,
            global_identity=InheritedArtifactPin._identity(global_fd),
            role_identity=InheritedArtifactPin._identity(role_fd))
        guard = RuntimeAssignmentGuard(
            inherited_pin, clock, verifier, clock_domain, float(captured_mono),
            float(catalog_deadline), float(assignment_deadline),
            child_catalog_deadline, child_assignment_deadline,
            catalog.payload["issued_at"], catalog.payload["expires_at"],
            assignment.payload["issued_at"], assignment.payload["expires_at"],
            payload["component"], payload["manifest_fingerprint"],
            payload["assignment_id"], payload["account_id"], payload["device_id"],
            payload["role"], hashlib.sha256(signed_assignment).hexdigest(),
            hashlib.sha256(signed_catalog).hexdigest(),
            MappingProxyType(dict(record)))
        guard.check()
        input_owner.global_fd = None
        input_owner.role_fd = None
        input_owner._close_outcomes["global_fd"] = "absent"
        input_owner._close_outcomes["role_fd"] = "absent"
        input_owner._state = "closed"
        success = True
        return guard
    finally:
        if not success:
            try:
                input_owner.close_after_failed_acquire()
            except ArtifactPinError as cleanup_error:
                cleanup_error.pin_owner = input_owner
                raise cleanup_error
