"""Durable single-use claims for an entire selected C2 parent and child cohort.

This is a persistence primitive only. A claim does not approve, start, or prove
readiness of any process. The caller must hold the same RootGenerationStore
protected-head serialization across fresh selected validation, this complete
cohort claim, and publication of ownership for every immediate Popen. Release
that serialization before waiting for child loader readiness; durable policy
writes may otherwise deadlock. Claims are sticky once O_EXCL creates a file.
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
from .errors import BindingError, SnapshotError, StorageError
from .files import _open_directory_chain
from .root_c2_group_scope import C2HostGroupScope, parse_c2_host_group_scope
from .root_transition_launch import (MAX_LAUNCH_ROLES, RoleLaunchSpec,
    parse_role_launch_spec, role_launch_document)

MAX_CLAIM_BYTES = 64 * 1024
MAX_CLAIMS = 16
MAX_CLAIM_SCAN_BYTES = 1024 * 1024
MAX_COHORT_BOOTS = 64
DOMAIN = "steamboat_c2_root_launch_attempt"
_HEX64 = re.compile(r"^[0-9a-f]{64}$", re.ASCII)
_FIELDS = frozenset({"domain", "purpose", "version", "selector_sha256",
    "activation_manifest_sha256", "generation_sha256", "cohort_sha256",
    "new_role_launch_specs", "new_host_group_scopes"})
_PURPOSE = "single_use_entire_selected_cohort"
_LOCK = "claim.lock"


def _hash(value, name):
    if type(value) is not str or not _HEX64.fullmatch(value):
        raise BindingError(f"C2 launch claim {name} must be lowercase SHA-256 hex")
    return value


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise StorageError("C2 launch claim contains duplicate fields")
        result[key] = value
    return result


def _reject_number(_value):
    raise StorageError("C2 launch claim contains non-integer number")


@dataclass(frozen=True)
class C2LaunchClaimRecord:
    selector_sha256: str
    activation_manifest_sha256: str
    generation_sha256: str
    cohort_sha256: str
    new_role_launch_specs: tuple[RoleLaunchSpec, ...]
    new_host_group_scopes: tuple[C2HostGroupScope, ...]


@dataclass(frozen=True)
class C2LaunchClaimReceipt:
    """Historical claim description; never a launch capability."""
    record: C2LaunchClaimRecord
    claim_sha256: str
    filename: str


def _docs(specs, groups):
    if type(specs) is not tuple or not 1 <= len(specs) <= MAX_LAUNCH_ROLES:
        raise BindingError("C2 claim requires one to sixteen parent role specs")
    if any(type(x) is not RoleLaunchSpec for x in specs):
        raise BindingError("C2 claim requires exact role launch specs")
    spec_docs = [role_launch_document(x) for x in specs]
    identities = tuple(x.identity for x in specs)
    if identities != tuple(sorted(identities)) or len(set(identities)) != len(identities):
        raise BindingError("C2 parent identities must be sorted and unique")
    generations = {x.generation_sha256 for x in specs}
    if len(generations) != 1:
        raise BindingError("C2 parent launch specs must share a generation")
    if type(groups) is not tuple or len(groups) > MAX_LAUNCH_ROLES:
        raise BindingError("C2 host groups exceed their bound")
    if any(type(x) is not C2HostGroupScope for x in groups):
        raise BindingError("C2 claim requires exact parsed host scopes")
    group_docs = [x.to_document() for x in groups]
    for raw in group_docs:
        parse_c2_host_group_scope(raw)
    group_ids = tuple((x.account_id, x.device_id, x.role) for x in groups)
    if group_ids != tuple(sorted(group_ids)) or len(set(group_ids)) != len(group_ids):
        raise BindingError("C2 host groups must be sorted and unique")
    by_id = {x.identity: x for x in specs}
    host_ids = {x.identity for x in specs if x.role == "host"}
    if set(group_ids) != host_ids:
        raise BindingError("C2 scopes must exactly cover every selected host role")
    for group in groups:
        spec = by_id[group.account_id, group.device_id, group.role]
        if (group.generation_sha256 != spec.generation_sha256
                or group.parent_boot_id != spec.boot_id
                or group.admission_epoch != spec.admission_epoch
                or (group.credential.serial, group.credential.credential_epoch,
                    group.credential.certificate_sha256, group.credential.public_key_sha256)
                   != (spec.serial, spec.credential_epoch, spec.certificate_sha256,
                       spec.public_key_sha256)):
            raise BindingError("C2 scope differs from its selected parent role")
    boots = [x.boot_id for x in specs] + [c.worker_boot_id for g in groups for c in g.components]
    if len(boots) > MAX_COHORT_BOOTS or len(boots) != len(set(boots)):
        raise BindingError("C2 entire cohort boots must be unique and bounded")
    return spec_docs, group_docs, tuple(boots)


def c2_launch_claim_document(record: C2LaunchClaimRecord) -> dict:
    if type(record) is not C2LaunchClaimRecord:
        raise BindingError("C2 claim document requires exact record")
    specs, groups, _ = _docs(record.new_role_launch_specs, record.new_host_group_scopes)
    generation = _hash(record.generation_sha256, "generation hash")
    if any(x.generation_sha256 != generation for x in record.new_role_launch_specs):
        raise BindingError("C2 parent generation differs from claim")
    body = {"generation_sha256": generation, "new_role_launch_specs": specs,
            "new_host_group_scopes": groups}
    digest = hashlib.sha256(canonical_json(body)).hexdigest()
    if _hash(record.cohort_sha256, "cohort hash") != digest:
        raise BindingError("C2 claim cohort digest differs from complete cohort")
    return {"domain": DOMAIN, "purpose": _PURPOSE, "version": 1,
        "selector_sha256": _hash(record.selector_sha256, "selector hash"),
        "activation_manifest_sha256": _hash(record.activation_manifest_sha256, "manifest hash"),
        "generation_sha256": generation, "cohort_sha256": digest,
        "new_role_launch_specs": specs, "new_host_group_scopes": groups}


def parse_c2_launch_claim(encoded: bytes) -> C2LaunchClaimRecord:
    if type(encoded) is not bytes or not 1 <= len(encoded) <= MAX_CLAIM_BYTES:
        raise StorageError("C2 claim is empty or exceeds 64 KiB")
    try:
        raw = json.loads(encoded.decode("utf-8", "strict"), object_pairs_hook=_pairs,
            parse_constant=_reject_number, parse_float=_reject_number,
            parse_int=lambda s: int(s) if s == str(int(s)) else _reject_number(s))
    except StorageError:
        raise
    except (UnicodeError, ValueError, TypeError, RecursionError) as error:
        raise StorageError("C2 claim JSON is malformed") from error
    if type(raw) is not dict or set(raw) != _FIELDS or raw.get("domain") != DOMAIN or raw.get("purpose") != _PURPOSE or type(raw.get("version")) is not int or raw["version"] != 1:
        raise StorageError("C2 claim has unknown fields or invalid domain/version")
    try:
        if type(raw["new_role_launch_specs"]) is not list:
            raise BindingError("role list must be a list")
        specs = tuple(parse_role_launch_spec(x) for x in raw["new_role_launch_specs"])
        if type(raw["new_host_group_scopes"]) is not list:
            raise BindingError("group list must be a list")
        groups = tuple(parse_c2_host_group_scope(x) for x in raw["new_host_group_scopes"])
        digest = _hash(raw["cohort_sha256"], "cohort hash")
        record = C2LaunchClaimRecord(_hash(raw["selector_sha256"], "selector hash"),
            _hash(raw["activation_manifest_sha256"], "manifest hash"),
            _hash(raw["generation_sha256"], "generation hash"), digest, specs, groups)
        canonical = c2_launch_claim_document(record)
    except (BindingError, SnapshotError, KeyError, TypeError, ValueError) as error:
        raise StorageError("C2 claim nested cohort is invalid") from error
    if canonical_json(canonical) != encoded:
        raise StorageError("C2 claim is not canonical JSON")
    return record


def _key(record):
    return hashlib.sha256(canonical_json({"generation_sha256": record.generation_sha256,
        "cohort_sha256": record.cohort_sha256})).hexdigest()


def _check_inode(info, uid, *, directory=False):
    mode = stat.S_IMODE(info.st_mode)
    if directory:
        good = stat.S_ISDIR(info.st_mode) and mode == 0o700
    else:
        good = stat.S_ISREG(info.st_mode) and mode == 0o600 and info.st_nlink == 1
    if not good or info.st_uid != uid:
        raise StorageError("C2 claim inode ownership, type, mode, or links are unsafe")


class C2LaunchClaimStore:
    """Append-only native POSIX store; root must be operator-provisioned."""
    def __init__(self, root, *, expected_uid: int, _fault_hook: Callable[[str], None] | None = None):
        if os.name != "posix" or not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "geteuid"):
            raise StorageError("C2 claims require POSIX no-follow support")
        if type(expected_uid) is not int or expected_uid != os.geteuid():
            raise StorageError("C2 claim UID must equal effective UID")
        self._uid = expected_uid
        self._fault_hook = _fault_hook
        self._unknown = False
        try:
            self._fd = _open_directory_chain(Path(os.path.abspath(os.fspath(root))), expected_uid=expected_uid)
        except (OSError, TypeError, ValueError) as error:
            raise StorageError("C2 claim root must be separately provisioned mode 0700") from error
        try:
            self._ensure_lock()
            with self._lock(): self._scan()
        except BaseException:
            fd, self._fd = self._fd, -1
            try: os.close(fd)
            except OSError: self._unknown = True
            raise

    def close(self):
        fd, self._fd = getattr(self, "_fd", -1), -1
        if fd >= 0:
            try: os.close(fd)
            except OSError:
                self._unknown = True
                raise
    def __enter__(self): return self
    def __exit__(self, *_): self.close()
    def _step(self, name):
        if self._fault_hook: self._fault_hook(name)

    def _ensure_lock(self):
        try:
            fd = os.open(_LOCK, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=self._fd)
        except FileExistsError: return
        except OSError as error: raise StorageError("C2 claim lock cannot be created") from error
        try:
            _check_inode(os.fstat(fd), self._uid)
            os.fsync(fd); os.fsync(self._fd)
        except OSError as error: raise StorageError("C2 claim lock durability failed") from error
        finally:
            owned, fd = fd, -1
            try: os.close(owned)
            except OSError:
                self._unknown = True
                raise

    @contextmanager
    def _lock(self):
        if self._fd < 0 or self._unknown:
            raise StorageError("C2 claim store is closed or latched")
        import fcntl
        fd = os.open(_LOCK, os.O_RDWR | os.O_NOFOLLOW, dir_fd=self._fd)
        try:
            _check_inode(os.fstat(fd), self._uid); fcntl.flock(fd, fcntl.LOCK_EX)
            _check_inode(os.fstat(self._fd), self._uid, directory=True)
            yield
        except OSError as error: raise StorageError("C2 claim lock is unsafe") from error
        finally:
            owned, fd = fd, -1
            try:
                try: fcntl.flock(owned, fcntl.LOCK_UN)
                except OSError:
                    self._unknown = True
                    raise
            finally:
                try: os.close(owned)
                except OSError:
                    self._unknown = True
                    raise

    def _scan(self):
        names = []
        try:
            with os.scandir(self._fd) as entries:
                for entry in entries:
                    names.append(entry.name)
                    if len(names) > MAX_CLAIMS + 1:
                        raise StorageError("C2 claim store has too many directory entries")
        except StorageError:
            raise
        except OSError as error:
            raise StorageError("C2 claim directory cannot be scanned safely") from error
        if _LOCK not in names: raise StorageError("C2 claim lock missing")
        files = [name for name in names if name != _LOCK]
        if len(files) > MAX_CLAIMS: raise StorageError("C2 claim history is full")
        results, total = {}, 0
        for name in files:
            if not name.startswith("claim-") or not name.endswith(".json") or not _HEX64.fullmatch(name[6:-5]):
                raise StorageError("C2 claim root contains unknown entry")
            try:
                fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_NONBLOCK", 0), dir_fd=self._fd)
                try:
                    _check_inode(os.fstat(fd), self._uid)
                    raw = os.read(fd, MAX_CLAIM_BYTES + 1)
                    if len(raw) > MAX_CLAIM_BYTES or os.read(fd, 1): raise StorageError("C2 claim too large")
                finally:
                    owned, fd = fd, -1
                    try: os.close(owned)
                    except OSError:
                        self._unknown = True
                        raise
            except OSError as error: raise StorageError("C2 claim cannot be read safely") from error
            total += len(raw)
            if total > MAX_CLAIM_SCAN_BYTES: raise StorageError("C2 claim scan exceeds 1 MiB")
            record = parse_c2_launch_claim(raw)
            if name != f"claim-{_key(record)}.json": raise StorageError("C2 claim filename mismatch")
            results[name] = record
        return results

    def claim(self, *, selector_sha256, activation_manifest_sha256, generation_sha256,
              new_role_launch_specs, new_host_group_scopes, fresh_selected_validator):
        if self._fd < 0 or self._unknown:
            raise StorageError("C2 claim store is closed or latched")
        generation = _hash(generation_sha256, "generation hash")
        specs = tuple(parse_role_launch_spec(role_launch_document(x)) for x in new_role_launch_specs) if type(new_role_launch_specs) is tuple else new_role_launch_specs
        groups = tuple(parse_c2_host_group_scope(x.to_document()) for x in new_host_group_scopes) if type(new_host_group_scopes) is tuple else new_host_group_scopes
        spec_docs, group_docs, boots = _docs(specs, groups)
        if any(x.generation_sha256 != generation for x in specs): raise BindingError("C2 generation mismatch")
        body = {"generation_sha256": generation, "new_role_launch_specs": spec_docs,
                "new_host_group_scopes": group_docs}
        record = C2LaunchClaimRecord(_hash(selector_sha256, "selector hash"),
            _hash(activation_manifest_sha256, "manifest hash"), generation,
            hashlib.sha256(canonical_json(body)).hexdigest(), specs, groups)
        encoded = canonical_json(c2_launch_claim_document(record))
        if len(encoded) > MAX_CLAIM_BYTES: raise BindingError("C2 claim exceeds 64 KiB")
        filename = f"claim-{_key(record)}.json"
        with self._lock():
            if self._unknown: raise StorageError("C2 claim outcome unknown; store is latched")
            history = self._scan()
            if len(history) >= MAX_CLAIMS: raise StorageError("C2 claim history reached 16 records")
            old_records = tuple(history.values())
            old_boots = {b for old in old_records for b in _docs(old.new_role_launch_specs, old.new_host_group_scopes)[2]}
            if old_boots.intersection(boots): raise BindingError("C2 parent or child boot was already claimed")
            for spec in specs:
                prior = [x for old in old_records for x in old.new_role_launch_specs if x.identity == spec.identity]
                if prior and spec.admission_epoch <= max(x.admission_epoch for x in prior):
                    raise BindingError("C2 principal admission epoch did not advance")
            if not callable(fresh_selected_validator): raise TypeError("trusted fresh selected validator required")
            # callback is called only after complete structural validation and before O_EXCL.
            answer = fresh_selected_validator(record)
            if inspect.isawaitable(answer):
                close = getattr(answer, "close", None)
                if callable(close): close()
                raise TypeError("fresh selected validator must be synchronous")
            if answer is not None: raise TypeError("fresh selected validator must return exactly None")
            self._step("claim.create")
            fd = None; created = False
            try:
                fd = os.open(filename, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=self._fd)
                created = True; _check_inode(os.fstat(fd), self._uid); self._step("claim.write")
                view = memoryview(encoded)
                while view:
                    n = os.write(fd, view)
                    if n <= 0: raise OSError("no write progress")
                    view = view[n:]
                self._step("claim.file.fsync"); os.fsync(fd)
                closing, fd = fd, None
                os.close(closing)
                self._step("claim.root.fsync"); os.fsync(self._fd)
            except BaseException as error:
                if created: self._unknown = True
                if fd is not None:
                    closing, fd = fd, None
                    try: os.close(closing)
                    except OSError: self._unknown = True
                if isinstance(error, OSError): raise StorageError("C2 claim write outcome is unconfirmed") from error
                raise
        return C2LaunchClaimReceipt(record, hashlib.sha256(encoded).hexdigest(), filename)
