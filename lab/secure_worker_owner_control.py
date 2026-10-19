"""Bounded owner-only command inbox for the opt-in C1 host worker adapter.

This module validates owner commands in memory and durably records acknowledgements.
It deliberately does not execute Drain, policy installation, role removal, or any
network action.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat


COMMAND_FILENAME = "owner-command.json"
ACK_FILENAME = "owner-ack.json"
MAX_CONTROL_BYTES = 16 * 1024
MAX_RECORDS = 32
MAX_NESTING = 8
_HEX32 = re.compile(r"[0-9a-f]{32}\Z", re.ASCII)
_HEX64 = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
_ACTIONS = frozenset(("drain", "install_snapshot", "remove"))
_PHASES = frozenset(("ready", "draining", "paused", "removing", "unavailable"))
_FAILURE_CODES = frozenset(("apply_failed", "owner_unavailable"))
_COMMAND_FIELDS = frozenset((
    "schema_version", "event", "run_id", "worker_boot_id", "sequence",
    "command_id", "action", "drain_seconds", "snapshot_sha256",
    "snapshot_revision",
))


class OwnerControlError(RuntimeError):
    """Invalid owner command, unsafe protected file, or uncertain publication."""


@dataclass(frozen=True, slots=True)
class OwnerCommand:
    run_id: str
    worker_boot_id: str
    sequence: int
    command_id: str
    action: str
    drain_seconds: int
    snapshot_sha256: str
    snapshot_revision: int
    command_sha256: str


def _reject_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise OwnerControlError("owner-control JSON has duplicate fields")
        result[key] = value
    return result


def _reject_constant(_value):
    raise OwnerControlError("owner-control JSON contains a nonfinite value")


def _reject_float(_value):
    raise OwnerControlError("owner-control JSON must not contain floating-point values")


def _need(condition, message):
    if not condition:
        raise OwnerControlError(message)


def _depth(value, current=1):
    _need(current <= MAX_NESTING, "owner-control JSON exceeds its nesting bound")
    if type(value) is dict:
        children = value.values()
    elif type(value) is list:
        children = value
    else:
        return
    for child in children:
        _depth(child, current + 1)


def _canonical_bytes(value):
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=True, allow_nan=False).encode("ascii")
    except (TypeError, ValueError, UnicodeError, RecursionError) as error:
        raise OwnerControlError("owner-control object is not canonical JSON") from error


def _exact_int(value, *, minimum, maximum, label):
    if type(value) is not int or not minimum <= value <= maximum:
        raise OwnerControlError(f"{label} is outside its exact integer bound")
    return value


def _hex(value, pattern, label):
    if type(value) is not str or pattern.fullmatch(value) is None:
        raise OwnerControlError(f"{label} is not lowercase hexadecimal")
    return value


def parse_owner_command(encoded: bytes, *, expected_run_id: str,
                        expected_worker_boot_id: str) -> OwnerCommand:
    """Parse and validate one bounded command without touching the filesystem."""
    _need(type(encoded) is bytes and 1 <= len(encoded) <= MAX_CONTROL_BYTES,
          "owner command is empty or oversized")
    _hex(expected_run_id, _HEX32, "expected run ID")
    _hex(expected_worker_boot_id, _HEX32, "expected worker boot ID")
    try:
        value = json.loads(encoded.decode("utf-8", errors="strict"),
                           object_pairs_hook=_reject_pairs,
                           parse_constant=_reject_constant,
                           parse_float=_reject_float)
    except OwnerControlError:
        raise
    except (UnicodeError, ValueError, TypeError, RecursionError) as error:
        raise OwnerControlError("owner command JSON is malformed") from error
    _depth(value)
    _need(type(value) is dict and set(value) == _COMMAND_FIELDS,
          "owner command has unknown or missing fields")
    _need(type(value["schema_version"]) is int and value["schema_version"] == 1,
          "owner command schema version is invalid")
    _need(type(value["event"]) is str and value["event"] == "owner_command",
          "owner command event is invalid")
    run_id = _hex(value["run_id"], _HEX32, "run ID")
    worker_boot_id = _hex(value["worker_boot_id"], _HEX32, "worker boot ID")
    _need(run_id == expected_run_id and worker_boot_id == expected_worker_boot_id,
          "owner command targets another run or worker boot")
    sequence = _exact_int(value["sequence"], minimum=1, maximum=MAX_RECORDS,
                          label="command sequence")
    command_id = _hex(value["command_id"], _HEX32, "command ID")
    action = value["action"]
    _need(type(action) is str and action in _ACTIONS,
          "owner command action is unsupported")
    drain_seconds = value["drain_seconds"]
    snapshot_sha256 = value["snapshot_sha256"]
    snapshot_revision = value["snapshot_revision"]
    if action == "drain":
        _exact_int(drain_seconds, minimum=1, maximum=300, label="drain duration")
        _need(type(snapshot_sha256) is str and snapshot_sha256 == "",
              "drain command must not contain a snapshot digest")
        _need(type(snapshot_revision) is int and snapshot_revision == 0,
              "drain command must not contain a snapshot revision")
    else:
        _need(type(drain_seconds) is int and drain_seconds == 0,
              "snapshot/removal command must use zero drain duration")
        _hex(snapshot_sha256, _HEX64, "snapshot digest")
        _exact_int(snapshot_revision, minimum=1, maximum=(1 << 63) - 1,
                   label="snapshot revision")
    canonical = _canonical_bytes(value)
    _need(len(canonical) <= MAX_CONTROL_BYTES,
          "canonical owner command exceeds its size bound")
    return OwnerCommand(
        run_id=run_id, worker_boot_id=worker_boot_id, sequence=sequence,
        command_id=command_id, action=action, drain_seconds=drain_seconds,
        snapshot_sha256=snapshot_sha256, snapshot_revision=snapshot_revision,
        command_sha256=hashlib.sha256(canonical).hexdigest())


def _metadata(info):
    return (info.st_dev, info.st_ino, info.st_uid, info.st_mode, info.st_nlink,
            info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _read_fixed_at(directory_fd: int, name: str, *, expected_uid: int,
                   missing_ok: bool) -> bytes | None:
    flags = (os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_NONBLOCK", 0)
             | getattr(os, "O_CLOEXEC", 0))
    try:
        descriptor = os.open(name, flags, dir_fd=directory_fd)
    except FileNotFoundError:
        if missing_ok:
            return None
        raise OwnerControlError("protected owner-control file is missing") from None
    except OSError as error:
        raise OwnerControlError("protected owner-control file cannot be opened safely") from error
    try:
        before = os.fstat(descriptor)
        _need(stat.S_ISREG(before.st_mode) and before.st_uid == expected_uid
              and stat.S_IMODE(before.st_mode) == 0o600 and before.st_nlink == 1
              and 1 <= before.st_size <= MAX_CONTROL_BYTES,
              "protected owner-control file failed owner/mode/link/size checks")
        chunks = []
        remaining = MAX_CONTROL_BYTES + 1
        while remaining:
            chunk = os.read(descriptor, min(4096, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
        after = os.fstat(descriptor)
        _need(_metadata(before) == _metadata(after),
              "protected owner-control file changed during read")
        _need(1 <= len(data) <= MAX_CONTROL_BYTES,
              "protected owner-control file exceeds its read bound")
        return data
    finally:
        os.close(descriptor)


def _write_all(fd: int, raw: bytes) -> None:
    view = memoryview(raw)
    while view:
        written = os.write(fd, view)
        if written <= 0:
            raise OwnerControlError("owner acknowledgement write made no progress")
        view = view[written:]


def _confirm_ack_durable(directory_fd: int, raw: bytes, *, expected_uid: int) -> bytes:
    try:
        descriptor = os.open(
            ACK_FILENAME, os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_NONBLOCK", 0)
            | getattr(os, "O_CLOEXEC", 0), dir_fd=directory_fd)
    except OSError as error:
        raise OwnerControlError("owner acknowledgement cannot be reopened safely") from error
    try:
        before = os.fstat(descriptor)
        _need(stat.S_ISREG(before.st_mode) and before.st_uid == expected_uid
              and stat.S_IMODE(before.st_mode) == 0o600 and before.st_nlink == 1
              and 1 <= before.st_size <= MAX_CONTROL_BYTES,
              "owner acknowledgement failed owner/mode/link/size checks")
        chunks = []
        remaining = MAX_CONTROL_BYTES + 1
        while remaining:
            chunk = os.read(descriptor, min(4096, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        saved = b"".join(chunks)
        after = os.fstat(descriptor)
        _need(_metadata(before) == _metadata(after) and saved == raw,
              "owner acknowledgement readback differs from the claim")
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.fsync(directory_fd)
    return saved


def _publish_ack(directory_fd: int, raw: bytes, *, expected_uid: int,
                 previous_bytes: bytes | None) -> bytes:
    temporary = f".owner-ack-{secrets.token_hex(16)}"
    descriptor = None
    temporary_exists = False
    try:
        descriptor = os.open(
            temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
            | getattr(os, "O_CLOEXEC", 0), 0o600, dir_fd=directory_fd)
        info = os.fstat(descriptor)
        _need(stat.S_ISREG(info.st_mode) and info.st_uid == expected_uid
              and stat.S_IMODE(info.st_mode) == 0o600 and info.st_nlink == 1,
              "new acknowledgement failed owner/mode/link checks")
        temporary_exists = True
        _write_all(descriptor, raw)
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = None
        existing = _read_fixed_at(directory_fd, ACK_FILENAME,
                                  expected_uid=expected_uid, missing_ok=True)
        _need(existing == previous_bytes,
              "owner acknowledgement target changed before publication")
        if previous_bytes is None:
            os.link(temporary, ACK_FILENAME, src_dir_fd=directory_fd,
                    dst_dir_fd=directory_fd, follow_symlinks=False)
            os.unlink(temporary, dir_fd=directory_fd)
        else:
            os.replace(temporary, ACK_FILENAME, src_dir_fd=directory_fd,
                       dst_dir_fd=directory_fd)
        temporary_exists = False
        os.fsync(directory_fd)
        return _confirm_ack_durable(directory_fd, raw, expected_uid=expected_uid)
    except OwnerControlError:
        raise
    except OSError as error:
        raise OwnerControlError("owner acknowledgement publication was not confirmed") from error
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if temporary_exists:
            try:
                os.unlink(temporary, dir_fd=directory_fd)
                os.fsync(directory_fd)
            except FileNotFoundError:
                pass
            except OSError as error:
                raise OwnerControlError(
                    "owner acknowledgement temporary file cleanup failed") from error


class OwnerControlInbox:
    """Read sequenced owner commands and atomically acknowledge observations."""

    def __init__(self, protected_root, *, run_id, worker_boot_id, expected_uid):
        self.protected_root = self._validate_root_path(protected_root)
        self.run_id = _hex(run_id, _HEX32, "run ID")
        self.worker_boot_id = _hex(worker_boot_id, _HEX32, "worker boot ID")
        _need(type(expected_uid) is int and expected_uid >= 0,
              "expected UID must be an exact nonnegative integer")
        self.expected_uid = expected_uid
        self._commands: list[OwnerCommand] = []
        self._command_ids: set[str] = set()
        self._unacknowledged: OwnerCommand | None = None
        self._failed_fence = False
        self._last_ack_command: OwnerCommand | None = None
        self._last_ack_document: dict | None = None
        self._last_ack_bytes: bytes | None = None
        self._ack_attempt: tuple[OwnerCommand, dict, bytes] | None = None

    @staticmethod
    def _validate_root_path(value) -> Path:
        try:
            raw = os.fspath(value)
        except (TypeError, ValueError, OSError) as error:
            raise OwnerControlError("protected root path is invalid") from error
        _need(type(raw) is str and bool(raw),
              "protected root path must be a nonempty text path")
        path = Path(raw)
        _need(path.is_absolute() and not any(part in (".", "..") for part in path.parts),
              "protected root must be absolute and contain no dot components")
        return path

    def _open_root(self):
        _need(os.name == "posix" and hasattr(os, "O_NOFOLLOW") and hasattr(os, "geteuid"),
              "owner-control files require POSIX descriptor no-follow support")
        _need(self.expected_uid == os.geteuid(),
              "expected UID does not match the effective UID")
        try:
            from steamboat_security.files import _open_directory_chain
            return _open_directory_chain(self.protected_root,
                                         expected_uid=self.expected_uid)
        except Exception as error:
            raise OwnerControlError("protected owner-control root failed path checks") from error

    def claim_next(self) -> OwnerCommand | None:
        directory_fd = self._open_root()
        try:
            encoded = _read_fixed_at(directory_fd, COMMAND_FILENAME,
                                     expected_uid=self.expected_uid, missing_ok=True)
        finally:
            os.close(directory_fd)
        if encoded is None:
            return None
        command = parse_owner_command(
            encoded, expected_run_id=self.run_id,
            expected_worker_boot_id=self.worker_boot_id)
        last = self._commands[-1] if self._commands else None
        if last is not None and command.sequence == last.sequence:
            _need(command == last, "owner command changed at an already claimed sequence")
            return None
        _need(last is None or command.sequence > last.sequence,
              "owner command sequence moved backwards")
        if self._failed_fence:
            raise OwnerControlError("a failed owner command fenced this inbox")
        if self._unacknowledged is not None:
            raise OwnerControlError("a prior owner command remains unacknowledged")
        expected_sequence = 1 if last is None else last.sequence + 1
        _need(command.sequence == expected_sequence, "owner command sequence has a gap")
        _need(command.command_id not in self._command_ids,
              "owner command ID was already used")
        _need(len(self._commands) < MAX_RECORDS,
              "owner command history reached its fixed bound")
        # Claim identity before returning control to a caller that may act on it.
        self._commands.append(command)
        self._command_ids.add(command.command_id)
        self._unacknowledged = command
        return command

    def write_ack(self, command: OwnerCommand, *, accepted: bool,
                  failure_code: str | None, received_monotonic_ns: int,
                  completed_monotonic_ns: int, phase: str,
                  applied_snapshot_sha256: str, applied_revision: int) -> dict:
        _need(type(command) is OwnerCommand,
              "acknowledgement requires the exact claim object")
        is_previous = command is self._last_ack_command
        is_pending = command is self._unacknowledged
        _need(is_previous or is_pending,
              "acknowledgement does not match a claimed command")
        _need(type(accepted) is bool,
              "acknowledgement acceptance must be an exact boolean")
        if accepted:
            _need(failure_code is None,
                  "accepted acknowledgement cannot include a failure code")
        else:
            _need(type(failure_code) is str and failure_code in _FAILURE_CODES,
                  "failed acknowledgement requires a fixed failure code")
        for value, label in ((received_monotonic_ns, "receive monotonic time"),
                             (completed_monotonic_ns, "completion monotonic time")):
            _exact_int(value, minimum=1, maximum=(1 << 63) - 1, label=label)
        _need(completed_monotonic_ns >= received_monotonic_ns,
              "acknowledgement completion precedes receipt")
        _need(type(phase) is str and phase in _PHASES,
              "acknowledgement phase is invalid")
        _need(type(applied_snapshot_sha256) is str,
              "applied snapshot digest must be text")
        if applied_snapshot_sha256 == "":
            _need(type(applied_revision) is int and applied_revision == 0,
                  "empty applied digest requires revision zero")
        else:
            _hex(applied_snapshot_sha256, _HEX64, "applied snapshot digest")
            _exact_int(applied_revision, minimum=1, maximum=(1 << 63) - 1,
                       label="applied snapshot revision")
        if accepted and command.action in ("install_snapshot", "remove"):
            _need(applied_snapshot_sha256 == command.snapshot_sha256
                  and applied_revision == command.snapshot_revision,
                  "accepted command did not report its requested snapshot")
        if accepted and command.action == "drain":
            _need(bool(applied_snapshot_sha256),
                  "accepted drain must report the current installed snapshot")
        document = {
            "schema_version": 1, "event": "owner_control_ack",
            "run_id": command.run_id, "worker_boot_id": command.worker_boot_id,
            "sequence": command.sequence, "command_id": command.command_id,
            "command_sha256": command.command_sha256, "action": command.action,
            "accepted": accepted, "failure_code": failure_code,
            "received_monotonic_ns": received_monotonic_ns,
            "completed_monotonic_ns": completed_monotonic_ns,
            "phase": phase, "applied_snapshot_sha256": applied_snapshot_sha256,
            "applied_revision": applied_revision,
        }
        raw = _canonical_bytes(document)
        _need(len(raw) <= MAX_CONTROL_BYTES,
              "owner acknowledgement exceeds its size bound")
        if is_previous:
            _need(document == self._last_ack_document and raw == self._last_ack_bytes,
                  "acknowledged command cannot be changed")
            directory_fd = self._open_root()
            try:
                return json.loads(_confirm_ack_durable(
                    directory_fd, raw, expected_uid=self.expected_uid).decode("ascii"))
            finally:
                os.close(directory_fd)
        retrying_attempt = self._ack_attempt is not None
        if retrying_attempt:
            prior_command, prior_document, prior_raw = self._ack_attempt
            _need(prior_command is command and prior_document == document and prior_raw == raw,
                  "uncertain acknowledgement must be retried exactly")
        else:
            # A failed or interrupted write never releases the claim for re-execution.
            self._ack_attempt = (command, document, raw)
        directory_fd = self._open_root()
        try:
            existing = _read_fixed_at(directory_fd, ACK_FILENAME,
                                      expected_uid=self.expected_uid, missing_ok=True)
            if existing == raw:
                _need(retrying_attempt,
                      "owner acknowledgement target already exists")
                _confirm_ack_durable(directory_fd, raw, expected_uid=self.expected_uid)
            else:
                if self._last_ack_bytes is None:
                    _need(existing is None, "owner acknowledgement target already exists")
                else:
                    _need(existing == self._last_ack_bytes,
                          "owner acknowledgement target differs from its prior result")
                _publish_ack(directory_fd, raw, expected_uid=self.expected_uid,
                             previous_bytes=self._last_ack_bytes)
        finally:
            os.close(directory_fd)
        self._last_ack_command = command
        self._last_ack_document = document
        self._last_ack_bytes = raw
        self._ack_attempt = None
        if accepted:
            self._unacknowledged = None
        else:
            self._failed_fence = True
        return dict(document)
