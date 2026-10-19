"""Durable single-use claims for a trusted cold-launch attempt.

This primitive is not authorization, activation, startup, readiness, or proof of
retirement/weight loading. The caller must serialize selected-root authority
across fresh-head validation, :meth:`LaunchClaimStore.claim` (including its
file/root fsyncs), Popen, and immediate process ownership registration. A
consumed claim is never deleted or reused, even if process creation never occurs.
"""

from __future__ import annotations

import hashlib
import inspect
import json
import os
import re
import stat
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from .codec import canonical_json
from .errors import BindingError, StorageError
from .files import _open_directory_chain
from .root_transition_launch import (
    MAX_LAUNCH_ROLES,
    RoleLaunchSpec,
    canonical_role_launch_digest,
    parse_role_launch_spec,
    role_launch_document,
)

MAX_CLAIM_BYTES = 16 * 1024
MAX_CLAIMS = 16
_HEX64 = re.compile(r"^[0-9a-f]{64}$", re.ASCII)
_FIELDS = frozenset({
    "schema_version", "purpose", "selector_sha256",
    "activation_manifest_sha256", "role_launch_digest", "generation_sha256",
    "role_launch_specs",
})
PURPOSE = "root_launch_attempt"
LOCK_NAME = "claim.lock"


def _hash(value, label: str) -> str:
    if type(value) is not str or not _HEX64.fullmatch(value):
        raise BindingError(f"launch claim {label} must be lowercase SHA-256 hex")
    return value


def _duplicate_pairs(pairs):
    values = {}
    for key, value in pairs:
        if key in values:
            raise BindingError("launch claim contains a duplicate field")
        values[key] = value
    return values


def _reject_constant(_value):
    raise BindingError("launch claim contains a non-finite value")


@dataclass(frozen=True)
class LaunchClaimRecord:
    selector_sha256: str
    activation_manifest_sha256: str
    role_launch_digest: str
    generation_sha256: str
    role_launch_specs: tuple[RoleLaunchSpec, ...]


@dataclass(frozen=True)
class LaunchClaimReceipt:
    """Historical data only; it is not a launch or selected-root capability."""
    record: LaunchClaimRecord
    claim_sha256: str
    filename: str


def _validate_boot_coherence(specs: tuple[RoleLaunchSpec, ...]) -> None:
    by_boot = {}
    for spec in specs:
        prior = by_boot.setdefault(spec.boot_id,
                                   (spec.launch_nonce, spec.configuration_sha256))
        if prior != (spec.launch_nonce, spec.configuration_sha256):
            raise BindingError(
                "roles sharing one boot ID must share launch nonce and configuration")


def launch_claim_document(record: LaunchClaimRecord) -> dict:
    if type(record) is not LaunchClaimRecord:
        raise BindingError("launch claim document requires an exact record")
    if type(record.role_launch_specs) is not tuple or not 1 <= len(record.role_launch_specs) <= MAX_LAUNCH_ROLES:
        raise BindingError("launch claim role set is outside its bound")
    if any(type(spec) is not RoleLaunchSpec for spec in record.role_launch_specs):
        raise BindingError("launch claim contains a non-exact role specification")
    _validate_boot_coherence(record.role_launch_specs)
    if any(spec.generation_sha256 != record.generation_sha256
           for spec in record.role_launch_specs):
        raise BindingError("launch claim roles differ from record generation")
    if canonical_role_launch_digest(record.role_launch_specs) != record.role_launch_digest:
        raise BindingError("launch claim role documents differ from their digest")
    return {
        "schema_version": 1,
        "purpose": PURPOSE,
        "selector_sha256": _hash(record.selector_sha256, "selector hash"),
        "activation_manifest_sha256": _hash(
            record.activation_manifest_sha256, "activation manifest hash"),
        "role_launch_digest": _hash(record.role_launch_digest, "role launch digest"),
        "generation_sha256": _hash(record.generation_sha256, "generation hash"),
        "role_launch_specs": [role_launch_document(spec)
                              for spec in record.role_launch_specs],
    }


def parse_launch_claim(encoded: bytes) -> LaunchClaimRecord:
    if type(encoded) is not bytes or not 1 <= len(encoded) <= MAX_CLAIM_BYTES:
        raise StorageError("launch claim is empty or exceeds its 16 KiB bound")
    try:
        raw = json.loads(encoded.decode("utf-8", errors="strict"),
                         object_pairs_hook=_duplicate_pairs,
                         parse_constant=_reject_constant)
    except BindingError as error:
        raise StorageError("launch claim JSON contains a duplicate or invalid value") from error
    except (UnicodeError, ValueError, TypeError, RecursionError) as error:
        raise StorageError("launch claim is malformed JSON") from error
    if type(raw) is not dict or set(raw) != _FIELDS:
        raise StorageError("launch claim has unknown or missing fields")
    if type(raw["schema_version"]) is not int or raw["schema_version"] != 1:
        raise StorageError("launch claim schema version is invalid")
    if type(raw["purpose"]) is not str or raw["purpose"] != PURPOSE:
        raise StorageError("launch claim purpose is invalid")
    try:
        raw_specs = raw["role_launch_specs"]
        if type(raw_specs) is not list or not 1 <= len(raw_specs) <= MAX_LAUNCH_ROLES:
            raise BindingError("launch claim role list is outside its bound")
        try:
            specs = tuple(parse_role_launch_spec(item) for item in raw_specs)
        except BindingError as error:
            raise StorageError("launch claim role declaration is invalid") from error
        _validate_boot_coherence(specs)
        role_digest = _hash(raw["role_launch_digest"], "role launch digest")
        if canonical_role_launch_digest(specs) != role_digest:
            raise BindingError("launch claim role documents differ from their digest")
        generation_hash = _hash(raw["generation_sha256"], "generation hash")
        if any(spec.generation_sha256 != generation_hash for spec in specs):
            raise BindingError("launch claim role generation differs from record")
        record = LaunchClaimRecord(
            selector_sha256=_hash(raw["selector_sha256"], "selector hash"),
            activation_manifest_sha256=_hash(
                raw["activation_manifest_sha256"], "activation manifest hash"),
            role_launch_digest=role_digest,
            generation_sha256=generation_hash,
            role_launch_specs=specs,
        )
    except BindingError as error:
        raise StorageError("launch claim contains an invalid hash") from error
    if canonical_json(launch_claim_document(record)) != encoded:
        raise StorageError("launch claim is not canonical JSON")
    return record


def _claim_key(generation_sha256: str, role_launch_digest: str) -> str:
    descriptor = canonical_json({
        "generation_sha256": _hash(generation_sha256, "generation hash"),
        "role_launch_digest": _hash(role_launch_digest, "role launch digest"),
    })
    return hashlib.sha256(descriptor).hexdigest()


def _check_directory(info, uid: int) -> None:
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != uid
            or stat.S_IMODE(info.st_mode) != 0o700):
        raise StorageError("launch claim root must be daemon-owned mode 0700")


def _check_file(info, uid: int) -> None:
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != uid
            or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1):
        raise StorageError("launch claim file must be owner 0600 regular one-link file")


class LaunchClaimStore:
    """POSIX protected append-only store of consumed role-launch plans.

    The claim root must be separately provisioned and owner-controlled. The
    constructor only creates ``claim.lock`` if absent; it never creates the
    root, migrates state, removes claims, or performs automatic recovery.
    """

    def __init__(self, root: str | os.PathLike, *, expected_uid: int,
                 _fault_hook: Callable[[str], None] | None = None):
        if (os.name != "posix" or not hasattr(os, "O_NOFOLLOW")
                or not hasattr(os, "geteuid")):
            raise StorageError("launch claims require POSIX no-follow support")
        if type(expected_uid) is not int or expected_uid != os.geteuid():
            raise StorageError("launch claim UID must equal the daemon effective UID")
        try:
            path = Path(os.path.abspath(os.fspath(root)))
        except (TypeError, ValueError, OSError) as error:
            raise StorageError("launch claim root path is invalid") from error
        if not path.is_absolute() or path == Path(os.sep):
            raise StorageError("filesystem root cannot hold launch claims")
        self._uid = expected_uid
        self._fault_hook = _fault_hook
        self._unknown_outcome = False
        self._root_fd = _open_directory_chain(path, expected_uid=expected_uid)
        try:
            self._ensure_lock()
            with self._lock():
                self._scan_claims()
        except BaseException:
            os.close(self._root_fd)
            self._root_fd = -1
            raise

    def close(self) -> None:
        if getattr(self, "_root_fd", -1) >= 0:
            os.close(self._root_fd)
            self._root_fd = -1

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        self.close()

    def _step(self, label: str) -> None:
        if self._fault_hook is not None:
            self._fault_hook(label)

    def _ensure_lock(self) -> None:
        try:
            fd = os.open(LOCK_NAME, os.O_RDWR | os.O_CREAT | os.O_EXCL
                         | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
                         0o600, dir_fd=self._root_fd)
        except FileExistsError:
            return
        except OSError as error:
            raise StorageError("launch claim lock cannot be created safely") from error
        try:
            _check_file(os.fstat(fd), self._uid)
            import fcntl
            fcntl.flock(fd, fcntl.LOCK_EX)
            try:
                os.fsync(fd)
                os.fsync(self._root_fd)
            finally:
                fcntl.flock(fd, fcntl.LOCK_UN)
        except OSError as error:
            raise StorageError("new launch claim lock could not be made durable") from error
        finally:
            os.close(fd)

    @contextmanager
    def _lock(self):
        import fcntl
        fd = None
        try:
            fd = os.open(LOCK_NAME, os.O_RDWR | os.O_NOFOLLOW
                         | getattr(os, "O_CLOEXEC", 0), dir_fd=self._root_fd)
            _check_file(os.fstat(fd), self._uid)
            fcntl.flock(fd, fcntl.LOCK_EX)
            _check_directory(os.fstat(self._root_fd), self._uid)
        except StorageError:
            if fd is not None:
                os.close(fd)
            raise
        except OSError as error:
            if fd is not None:
                os.close(fd)
            raise StorageError("launch claim lock is unsafe or unavailable") from error
        try:
            yield
        finally:
            try:
                fcntl.flock(fd, fcntl.LOCK_UN)
            finally:
                os.close(fd)

    def _scan_claims(self) -> dict[str, LaunchClaimRecord]:
        names = set(os.listdir(self._root_fd))
        if LOCK_NAME not in names:
            raise StorageError("launch claim lock is missing")
        claim_names = names - {LOCK_NAME}
        if len(claim_names) > MAX_CLAIMS:
            raise StorageError("launch claim store is full or ambiguous")
        result = {}
        for filename in claim_names:
            if (type(filename) is not str or not filename.startswith("claim-")
                    or not filename.endswith(".json")
                    or not _HEX64.fullmatch(filename[6:-5])):
                raise StorageError("launch claim root contains an unknown entry")
            try:
                fd = os.open(filename, os.O_RDONLY | os.O_NOFOLLOW
                             | getattr(os, "O_NONBLOCK", 0)
                             | getattr(os, "O_CLOEXEC", 0), dir_fd=self._root_fd)
                try:
                    _check_file(os.fstat(fd), self._uid)
                    chunks, total = [], 0
                    while True:
                        part = os.read(fd, min(4096, MAX_CLAIM_BYTES + 1 - total))
                        if not part:
                            break
                        total += len(part)
                        if total > MAX_CLAIM_BYTES:
                            raise StorageError("launch claim exceeds its size bound")
                        chunks.append(part)
                    encoded = b"".join(chunks)
                finally:
                    os.close(fd)
            except StorageError:
                raise
            except OSError as error:
                raise StorageError("launch claim cannot be read safely") from error
            record = parse_launch_claim(encoded)
            if filename != f"claim-{_claim_key(record.generation_sha256, record.role_launch_digest)}.json":
                raise StorageError("launch claim filename differs from its bound plan")
            result[filename] = record
        return result

    def claim(self, *, selector_sha256: str, activation_manifest_sha256: str,
              generation_sha256: str, role_launch_specs: tuple[RoleLaunchSpec, ...],
              fresh_selected_validator: Callable[[LaunchClaimRecord,
                                                   tuple[RoleLaunchSpec, ...]], None]
              ) -> LaunchClaimReceipt:
        """Consume one launch plan after owner-supplied fresh-head validation.

        Caller must retain selected-root serialization through Popen and
        immediate ownership registration after this returns. `fresh_selected_validator`
        is a trusted owner callback, not an approval token or proof of activation.
        """
        selector_hash = _hash(selector_sha256, "selector hash")
        manifest_hash = _hash(activation_manifest_sha256, "activation manifest hash")
        generation_hash = _hash(generation_sha256, "generation hash")
        if type(role_launch_specs) is not tuple or not 1 <= len(role_launch_specs) <= MAX_LAUNCH_ROLES:
            raise BindingError("launch claim requires one to sixteen exact role specifications")
        if any(type(spec) is not RoleLaunchSpec for spec in role_launch_specs):
            raise BindingError("launch claim requires exact RoleLaunchSpec values")
        # Revalidate directly constructed dataclasses through their closed docs.
        for spec in role_launch_specs:
            role_launch_document(spec)
        if any(spec.generation_sha256 != generation_hash for spec in role_launch_specs):
            raise BindingError("launch role generation differs from claim generation")
        _validate_boot_coherence(role_launch_specs)
        digest = canonical_role_launch_digest(role_launch_specs)
        record = LaunchClaimRecord(selector_hash, manifest_hash, digest, generation_hash,
                                   role_launch_specs)
        encoded = canonical_json(launch_claim_document(record))
        if len(encoded) > MAX_CLAIM_BYTES:
            raise BindingError("launch claim exceeds its size bound")
        filename = f"claim-{_claim_key(generation_hash, digest)}.json"
        with self._lock():
            if self._unknown_outcome:
                raise StorageError("launch claim outcome is unknown; store instance is latched")
            claims = self._scan_claims()
            if len(claims) >= MAX_CLAIMS:
                raise StorageError("launch claim store has reached its bounded capacity")
            if filename in claims:
                raise BindingError("this generation and exact launch plan were already consumed")
            prior_specs = [spec for old in claims.values()
                           for spec in old.role_launch_specs]
            for spec in role_launch_specs:
                matching = [old for old in prior_specs if old.identity == spec.identity]
                if any(old.boot_id == spec.boot_id for old in prior_specs):
                    raise BindingError("this boot identity was already claimed")
                if matching and spec.admission_epoch <= max(
                        old.admission_epoch for old in matching):
                    raise BindingError("launch admission epoch did not advance for principal")
            if not callable(fresh_selected_validator):
                raise TypeError("fresh selected-head validator is required")
            result = fresh_selected_validator(record, role_launch_specs)
            if inspect.isawaitable(result):
                close = getattr(result, "close", None)
                if callable(close):
                    close()
                raise TypeError("fresh selected-head validator must be synchronous")
            if result is not None:
                raise TypeError("fresh selected-head validator must return exactly None")
            self._step("claim.create")
            fd = None
            created = False
            try:
                fd = os.open(filename, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                             | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
                             0o600, dir_fd=self._root_fd)
                created = True
                _check_file(os.fstat(fd), self._uid)
                self._step("claim.write")
                view = memoryview(encoded)
                while view:
                    count = os.write(fd, view)
                    if count <= 0:
                        raise OSError("claim write made no progress")
                    view = view[count:]
                self._step("claim.file.fsync")
                os.fsync(fd)
                os.close(fd)
                fd = None
                self._step("claim.root.fsync")
                os.fsync(self._root_fd)
            except BaseException as error:
                if fd is not None:
                    os.close(fd)
                if created:
                    # The durable outcome may be partial or uncertain. Never
                    # remove/overwrite it; this instance cannot issue another.
                    self._unknown_outcome = True
                if isinstance(error, (OSError, StorageError)):
                    raise StorageError("launch claim write outcome is not confirmed") from error
                raise
        return LaunchClaimReceipt(record, hashlib.sha256(encoded).hexdigest(), filename)
