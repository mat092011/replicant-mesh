"""Durable, single-use local claims for a trusted device's enabled C2 roles.

The receipt is historical data only. Callers must serialize this operation with
the protected selected-head and owner-enable stores, and keep that serialization
through immediate owned-Popen publication. This module cannot prove that lock.
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
from .errors import BindingError, CredentialError, SnapshotError, StorageError
from .files import _open_directory_chain
from .root_c2_local_plan import (C2LocalPlan, c2_local_plan_document,
    parse_c2_local_plan)
from .root_transition_launch import role_launch_document

MAX_CLAIM_BYTES = 64 * 1024
MAX_CLAIMS = 16
MAX_CLAIM_SCAN_BYTES = 1024 * 1024
MAX_LOCAL_BOOTS = 16
DOMAIN = "steamboat_c2_device_local_launch_attempt"
PURPOSE = "single_use_enabled_local_projection"
_HEX64 = re.compile(r"^[0-9a-f]{64}$", re.ASCII)
_FIELDS = frozenset({"domain", "purpose", "version", "account_id", "device_id",
    "enable_epoch", "localplan_sha256", "plan", "enabled_boot_ids", "claim_sha256"})
_LOCK = "claim.lock"


def _hash(value, label):
    if type(value) is not str or not _HEX64.fullmatch(value):
        raise BindingError(f"C2 local claim {label} must be lowercase SHA-256 hex")
    return value


def _plan(value) -> C2LocalPlan:
    # Reparse even exact public dataclasses; their constructors are not trust.
    if type(value) is C2LocalPlan:
        encoded = canonical_json(c2_local_plan_document(value))
    elif type(value) is bytes:
        encoded = value
    else:
        raise BindingError("C2 local claim requires a canonical plan or encoded plan")
    try:
        return parse_c2_local_plan(encoded)
    except (CredentialError, TypeError, ValueError) as error:
        raise BindingError("C2 local claim plan is invalid") from error


def _boots(plan):
    if not plan.enabled_specs:
        raise BindingError("C2 local claim refuses an empty enabled projection")
    boots = [spec.boot_id for spec in plan.enabled_specs]
    boots.extend(component.worker_boot_id for group in plan.enabled_host_groups
                 for component in group.components)
    if not 1 <= len(boots) <= MAX_LOCAL_BOOTS or len(boots) != len(set(boots)):
        raise BindingError("C2 local enabled parent and child boots must be unique and bounded")
    return tuple(sorted(boots))


@dataclass(frozen=True)
class C2LocalClaimRecord:
    account_id: str
    device_id: str
    enable_epoch: int
    localplan_sha256: str
    plan: C2LocalPlan
    enabled_boot_ids: tuple[str, ...]
    claim_sha256: str


@dataclass(frozen=True)
class C2LocalClaimReceipt:
    """Inert historical receipt; it grants no startup or readiness authority."""
    record: C2LocalClaimRecord
    filename: str


def c2_local_claim_document(record: C2LocalClaimRecord) -> dict:
    if type(record) is not C2LocalClaimRecord:
        raise BindingError("C2 local claim requires exact record")
    if (type(record.account_id) is not str or type(record.device_id) is not str
            or type(record.enable_epoch) is not int or type(record.enabled_boot_ids) is not tuple):
        raise BindingError("C2 local claim record field types are invalid")
    plan = _plan(record.plan)
    boots = _boots(plan)
    if (record.account_id != plan.account_id or record.device_id != plan.device_id
            or record.enable_epoch != plan.enable_epoch
            or _hash(record.localplan_sha256, "local plan hash") != plan.localplan_sha256
            or type(record.enabled_boot_ids) is not tuple or record.enabled_boot_ids != boots):
        raise BindingError("C2 local claim differs from its complete plan")
    body = {"domain": DOMAIN, "purpose": PURPOSE, "version": 1,
        "account_id": plan.account_id, "device_id": plan.device_id,
        "enable_epoch": plan.enable_epoch, "localplan_sha256": plan.localplan_sha256,
        "plan": c2_local_plan_document(plan), "enabled_boot_ids": list(boots)}
    digest = hashlib.sha256(canonical_json(body)).hexdigest()
    if _hash(record.claim_sha256, "claim hash") != digest:
        raise BindingError("C2 local claim digest differs from its fields")
    return {**body, "claim_sha256": digest}


def _make_record(plan):
    plan = _plan(plan)
    boots = _boots(plan)
    doc = {"domain": DOMAIN, "purpose": PURPOSE, "version": 1,
        "account_id": plan.account_id, "device_id": plan.device_id,
        "enable_epoch": plan.enable_epoch, "localplan_sha256": plan.localplan_sha256,
        "plan": c2_local_plan_document(plan), "enabled_boot_ids": list(boots)}
    return C2LocalClaimRecord(plan.account_id, plan.device_id, plan.enable_epoch,
        plan.localplan_sha256, plan, boots, hashlib.sha256(canonical_json(doc)).hexdigest())


def parse_c2_local_claim(encoded: bytes) -> C2LocalClaimRecord:
    if type(encoded) is not bytes or not 1 <= len(encoded) <= MAX_CLAIM_BYTES:
        raise StorageError("C2 local claim is empty or exceeds 64 KiB")
    try:
        raw = json.loads(encoded.decode("utf-8", "strict"), object_pairs_hook=_pairs,
            parse_constant=_reject_number, parse_float=_reject_number,
            parse_int=lambda s: int(s) if s == str(int(s)) else _reject_number(s))
    except StorageError:
        raise
    except (UnicodeError, ValueError, TypeError, RecursionError) as error:
        raise StorageError("C2 local claim JSON is malformed") from error
    if type(raw) is not dict or set(raw) != _FIELDS or raw.get("domain") != DOMAIN or raw.get("purpose") != PURPOSE or type(raw.get("version")) is not int or raw["version"] != 1:
        raise StorageError("C2 local claim has unknown fields or invalid domain/version")
    try:
        plan = parse_c2_local_plan(canonical_json(raw["plan"]))
        record = C2LocalClaimRecord(raw["account_id"], raw["device_id"], raw["enable_epoch"],
            _hash(raw["localplan_sha256"], "local plan hash"), plan,
            tuple(raw["enabled_boot_ids"]), _hash(raw["claim_sha256"], "claim hash"))
        canonical = c2_local_claim_document(record)
    except (BindingError, CredentialError, SnapshotError, KeyError, TypeError, ValueError) as error:
        raise StorageError("C2 local claim fields or nested plan are invalid") from error
    if canonical_json(canonical) != encoded:
        raise StorageError("C2 local claim is not canonical JSON")
    return record


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result: raise StorageError("C2 local claim contains duplicate fields")
        result[key] = value
    return result


def _reject_number(_value):
    raise StorageError("C2 local claim contains non-integer number")


def _check_inode(info, uid, *, directory=False):
    mode = stat.S_IMODE(info.st_mode)
    good = (stat.S_ISDIR(info.st_mode) and mode == 0o700) if directory else (
        stat.S_ISREG(info.st_mode) and mode == 0o600 and info.st_nlink == 1)
    if not good or info.st_uid != uid:
        raise StorageError("C2 local claim inode ownership, type, mode, or links are unsafe")


class C2LocalClaimStore:
    """Append-only native POSIX store pinned to one operator-owned device."""
    def __init__(self, root, *, expected_uid: int, account_id: str, device_id: str,
                 _fault_hook: Callable[[str], None] | None = None):
        if os.name != "posix" or not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "geteuid"):
            raise StorageError("C2 local claims require POSIX no-follow support")
        if type(expected_uid) is not int or expected_uid != os.geteuid():
            raise StorageError("C2 local claim UID must equal effective UID")
        if type(account_id) is not str or type(device_id) is not str:
            raise StorageError("C2 local claim principal must use exact strings")
        self._uid, self._account, self._device = expected_uid, account_id, device_id
        self._fault_hook, self._unknown = _fault_hook, False
        try: self._fd = _open_directory_chain(Path(os.path.abspath(os.fspath(root))), expected_uid=expected_uid)
        except (OSError, TypeError, ValueError) as error:
            raise StorageError("C2 local claim root must be separately provisioned mode 0700") from error
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
            except OSError: self._unknown = True; raise
    def __enter__(self): return self
    def __exit__(self, *_): self.close()
    def _step(self, name):
        if self._fault_hook: self._fault_hook(name)
    def _ensure_lock(self):
        try: fd = os.open(_LOCK, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=self._fd)
        except FileExistsError: return
        except OSError as error: raise StorageError("C2 local claim lock cannot be created") from error
        try:
            _check_inode(os.fstat(fd), self._uid); os.fsync(fd); os.fsync(self._fd)
        except OSError as error: raise StorageError("C2 local claim lock durability failed") from error
        finally:
            owned, fd = fd, -1
            try: os.close(owned)
            except OSError: self._unknown = True; raise
    @contextmanager
    def _lock(self):
        if self._fd < 0 or self._unknown: raise StorageError("C2 local claim store is closed or latched")
        import fcntl
        fd = os.open(_LOCK, os.O_RDWR | os.O_NOFOLLOW, dir_fd=self._fd)
        try:
            _check_inode(os.fstat(fd), self._uid); fcntl.flock(fd, fcntl.LOCK_EX)
            _check_inode(os.fstat(self._fd), self._uid, directory=True); yield
        except OSError as error: raise StorageError("C2 local claim lock is unsafe") from error
        finally:
            owned, fd = fd, -1
            try:
                try: fcntl.flock(owned, fcntl.LOCK_UN)
                except OSError: self._unknown = True; raise
            finally:
                try: os.close(owned)
                except OSError: self._unknown = True; raise
    def _scan(self):
        names = []
        try:
            with os.scandir(self._fd) as entries:
                for entry in entries:
                    names.append(entry.name)
                    if len(names) > MAX_CLAIMS + 1: raise StorageError("C2 local claim store has too many entries")
        except StorageError: raise
        except OSError as error: raise StorageError("C2 local claim directory cannot be scanned") from error
        if _LOCK not in names: raise StorageError("C2 local claim lock missing")
        files = [n for n in names if n != _LOCK]
        if len(files) > MAX_CLAIMS: raise StorageError("C2 local claim history is full")
        result, total = {}, 0
        for name in files:
            if not name.startswith("claim-") or not name.endswith(".json") or not _HEX64.fullmatch(name[6:-5]):
                raise StorageError("C2 local claim root contains unknown entry")
            try:
                fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_NONBLOCK", 0), dir_fd=self._fd)
                try:
                    _check_inode(os.fstat(fd), self._uid)
                    chunks, remaining = [], MAX_CLAIM_BYTES + 1
                    while remaining:
                        chunk = os.read(fd, remaining)
                        if not chunk: break
                        chunks.append(chunk); remaining -= len(chunk)
                    raw = b"".join(chunks)
                    if len(raw) > MAX_CLAIM_BYTES: raise StorageError("C2 local claim too large")
                finally:
                    owned, fd = fd, -1
                    try: os.close(owned)
                    except OSError: self._unknown = True; raise
            except OSError as error: raise StorageError("C2 local claim cannot be read safely") from error
            total += len(raw)
            if total > MAX_CLAIM_SCAN_BYTES: raise StorageError("C2 local claim scan exceeds 1 MiB")
            record = parse_c2_local_claim(raw)
            if name != f"claim-{record.claim_sha256}.json": raise StorageError("C2 local claim filename mismatch")
            if (record.account_id, record.device_id) != (self._account, self._device):
                raise StorageError("C2 local claim belongs to a different pinned principal")
            result[name] = record
        return result
    def claim(self, plan, *, fresh_selected_validator):
        if self._fd < 0 or self._unknown: raise StorageError("C2 local claim store is closed or latched")
        record = _make_record(plan)
        if (record.account_id, record.device_id) != (self._account, self._device):
            raise BindingError("C2 local claim cannot claim a remote principal")
        encoded = canonical_json(c2_local_claim_document(record))
        if len(encoded) > MAX_CLAIM_BYTES: raise BindingError("C2 local claim exceeds 64 KiB")
        filename = f"claim-{record.claim_sha256}.json"
        with self._lock():
            if self._unknown: raise StorageError("C2 local claim outcome unknown; store is latched")
            history = tuple(self._scan().values())
            if len(history) >= MAX_CLAIMS: raise StorageError("C2 local claim history reached 16 records")
            old_boots = {boot for old in history for boot in old.enabled_boot_ids}
            if old_boots.intersection(record.enabled_boot_ids): raise BindingError("C2 local enabled parent or child boot was already claimed")
            if history and record.enable_epoch <= max(x.enable_epoch for x in history):
                raise BindingError("C2 trusted owner enable epoch did not advance")
            old_specs = [spec for old in history for spec in old.plan.enabled_specs]
            for spec in record.plan.enabled_specs:
                prior = [old for old in old_specs if old.identity == spec.identity]
                if prior and spec.admission_epoch <= max(old.admission_epoch for old in prior):
                    raise BindingError("C2 principal admission epoch did not advance")
            if not callable(fresh_selected_validator): raise TypeError("trusted fresh local validator required")
            answer = fresh_selected_validator(record)
            if inspect.isawaitable(answer):
                close = getattr(answer, "close", None)
                if callable(close): close()
                raise TypeError("fresh local validator must be synchronous")
            if answer is not None: raise TypeError("fresh local validator must return exactly None")
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
                closing, fd = fd, None; os.close(closing)
                self._step("claim.root.fsync"); os.fsync(self._fd)
            except BaseException as error:
                if created: self._unknown = True
                if fd is not None:
                    closing, fd = fd, None
                    try: os.close(closing)
                    except OSError: self._unknown = True
                if isinstance(error, OSError): raise StorageError("C2 local claim write outcome is unconfirmed") from error
                raise
        return C2LocalClaimReceipt(record, filename)
