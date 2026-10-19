import copy
import json
import os
from pathlib import Path
import re
import sys
import threading

from .policy import MEMORY_FIELDS, ROLE_NAMES, RESERVATION_FIELDS, validate_policy
from .storage import (FileLock, StorageError, atomic_write_json,
                      open_private_directory, read_private_json)


class ResourceError(Exception):
    pass


def _empty_ledger():
    return {"version": 1, "pool_id": None, "limits": None,
            "reservations": {}, "blocked": False, "block_reason": None}


def _totals(reservations):
    result = {field: 0 for field in RESERVATION_FIELDS}
    for item in reservations.values():
        for field in RESERVATION_FIELDS:
            result[field] += item[field]
    return result


def _fit(reservations, limits):
    totals = _totals(reservations)
    memory = sum(totals[field] for field in MEMORY_FIELDS)
    if memory + limits["memory_headroom_bytes"] > limits["memory_ceiling_bytes"]:
        return False, "memory_ceiling_exceeded"
    for field, limit in (
        ("cpu_quota_millis", "cpu_quota_millis"),
        ("disk_bytes", "disk_ceiling_bytes"),
        ("send_bytes_per_second", "send_bytes_per_second"),
        ("receive_bytes_per_second", "receive_bytes_per_second"),
        ("total_network_bytes", "total_network_bytes"),
        ("cleanup_send_bytes_per_second", "cleanup_send_bytes_per_second"),
        ("cleanup_receive_bytes_per_second", "cleanup_receive_bytes_per_second"),
        ("cleanup_total_network_bytes", "cleanup_total_network_bytes"),
        ("sessions", "max_sessions"),
        ("queued_calls", "max_queued_calls"),
    ):
        if totals[field] > limits[limit]:
            return False, f"{field}_ceiling_exceeded"
    if totals["max_request_seconds"] > limits["max_request_seconds"]:
        return False, "max_request_deadline_exceeded"
    return True, None


def _validate_ledger(value):
    if (type(value) is not dict or set(value) != {
            "version", "pool_id", "limits", "reservations", "blocked", "block_reason"}
            or type(value["version"]) is not int or value["version"] != 1
            or type(value["reservations"]) is not dict or type(value["blocked"]) is not bool):
        raise ResourceError("resource ledger is malformed; refusing admission")
    for role, reservation in value["reservations"].items():
        if role not in ROLE_NAMES or type(reservation) is not dict \
                or set(reservation) != set(RESERVATION_FIELDS):
            raise ResourceError("resource ledger reservation is malformed; refusing admission")
        for field, amount in reservation.items():
            if type(amount) is not int or amount < 0:
                raise ResourceError("resource ledger amount is malformed; refusing admission")
    if value["limits"] is not None:
        if type(value["limits"]) is not dict:
            raise ResourceError("resource ledger limits are malformed; refusing admission")
    return value


class ResourceLedger:
    def __init__(self, path, *, uid=None, timeout=1):
        if not sys.platform.startswith("linux"):
            raise StorageError("cross-process resource ledger requires Linux file locks")
        self.path = Path(os.path.abspath(os.fspath(path)))
        self.uid = os.getuid() if uid is None else uid
        directory = open_private_directory(self.path.parent, create=True, uid=self.uid)
        os.close(directory)
        self.timeout = timeout
        self.lock_path = self.path.with_name(self.path.name + ".lock")
        self._thread_lock = threading.RLock()
        with self._locked():
            try:
                _validate_ledger(read_private_json(self.path, uid=self.uid))
            except FileNotFoundError:
                atomic_write_json(self.path, _empty_ledger(), uid=self.uid)

    def _locked(self):
        return _LedgerLock(self._thread_lock, FileLock(self.lock_path, uid=self.uid,
                                                       timeout=self.timeout))

    def _read(self):
        try:
            return _validate_ledger(read_private_json(self.path, uid=self.uid))
        except FileNotFoundError:
            raise ResourceError("resource ledger disappeared; refusing admission")
        except StorageError as error:
            raise ResourceError("resource ledger is unreadable; refusing admission") from error

    def _write(self, state):
        atomic_write_json(self.path, state, uid=self.uid)

    def snapshot(self):
        with self._locked():
            return copy.deepcopy(self._read())

    def configure(self, policy):
        policy = validate_policy(policy)
        with self._locked():
            state = self._read()
            if state["pool_id"] not in (None, policy["pool_id"]):
                raise ResourceError("one ledger cannot authorize two physical pools")
            state["pool_id"] = policy["pool_id"]
            state["limits"] = policy["limits"]
            fits, reason = _fit(state["reservations"], state["limits"])
            state["blocked"] = not fits
            state["block_reason"] = reason
            self._write(state)
            return copy.deepcopy(state)

    def reserve(self, role, reservation):
        if role not in ROLE_NAMES:
            raise ResourceError("unknown reservation role")
        if type(reservation) is not dict or set(reservation) != set(RESERVATION_FIELDS):
            raise ResourceError("reservation must name every bounded resource")
        if any(type(value) is not int or value < 0 for value in reservation.values()):
            raise ResourceError("reservation values must be nonnegative integers")
        with self._locked():
            state = self._read()
            if state["limits"] is None or state["pool_id"] is None:
                raise ResourceError("owner policy is required before reservation")
            if state["blocked"]:
                raise ResourceError(state["block_reason"] or "resource ledger is blocked")
            if role in state["reservations"]:
                if state["reservations"][role] == reservation:
                    return copy.deepcopy(state)
                raise ResourceError("role already holds a different reservation")
            candidate = copy.deepcopy(state["reservations"])
            candidate[role] = dict(reservation)
            fits, reason = _fit(candidate, state["limits"])
            if not fits:
                raise ResourceError(reason)
            state["reservations"] = candidate
            self._write(state)
            return copy.deepcopy(state)

    def release(self, role, *, reclaimed):
        if type(reclaimed) is not bool or not reclaimed:
            raise ResourceError("reservation remains held until reclamation is confirmed")
        with self._locked():
            state = self._read()
            state["reservations"].pop(role, None)
            fits, reason = _fit(state["reservations"], state["limits"] or {}) if state["limits"] else (True, None)
            state["blocked"] = not fits
            state["block_reason"] = reason
            self._write(state)
            return copy.deepcopy(state)


class _LedgerLock:
    def __init__(self, thread_lock, file_lock):
        self.thread_lock = thread_lock
        self.file_lock = file_lock

    def __enter__(self):
        self.thread_lock.acquire()
        try:
            self.file_lock.acquire()
            return self
        except Exception:
            self.thread_lock.release()
            raise

    def __exit__(self, exc_type, exc_value, traceback):
        try:
            self.file_lock.release()
        finally:
            self.thread_lock.release()


class MemoryResourceLedger:
    def __init__(self):
        self._state = _empty_ledger()
        self._lock = threading.RLock()

    def snapshot(self):
        with self._lock:
            return copy.deepcopy(self._state)

    def configure(self, policy):
        policy = validate_policy(policy)
        with self._lock:
            if self._state["pool_id"] not in (None, policy["pool_id"]):
                raise ResourceError("one ledger cannot authorize two physical pools")
            self._state["pool_id"] = policy["pool_id"]
            self._state["limits"] = policy["limits"]
            fits, reason = _fit(self._state["reservations"], self._state["limits"])
            self._state["blocked"] = not fits
            self._state["block_reason"] = reason
            return self.snapshot()

    def reserve(self, role, reservation):
        if role not in ROLE_NAMES:
            raise ResourceError("unknown reservation role")
        if type(reservation) is not dict or set(reservation) != set(RESERVATION_FIELDS):
            raise ResourceError("reservation must name every bounded resource")
        if any(type(value) is not int or value < 0 for value in reservation.values()):
            raise ResourceError("reservation values must be nonnegative integers")
        with self._lock:
            if self._state["limits"] is None:
                raise ResourceError("owner policy is required before reservation")
            if self._state["blocked"]:
                raise ResourceError(self._state["block_reason"] or "resource ledger is blocked")
            if role in self._state["reservations"]:
                if self._state["reservations"][role] == reservation:
                    return self.snapshot()
                raise ResourceError("role already holds a different reservation")
            candidate = copy.deepcopy(self._state["reservations"])
            candidate[role] = copy.deepcopy(reservation)
            fits, reason = _fit(candidate, self._state["limits"])
            if not fits:
                raise ResourceError(reason)
            self._state["reservations"] = candidate
            return self.snapshot()

    def release(self, role, *, reclaimed):
        if type(reclaimed) is not bool or not reclaimed:
            raise ResourceError("reservation remains held until reclamation is confirmed")
        with self._lock:
            self._state["reservations"].pop(role, None)
            fits, reason = _fit(self._state["reservations"], self._state["limits"] or {}) if self._state["limits"] else (True, None)
            self._state["blocked"] = not fits
            self._state["block_reason"] = reason
            return self.snapshot()


class CgroupV2Controller:
    def __init__(self, *, proc_root="/proc", cgroup_root=None):
        self.proc_root = Path(proc_root)
        self.cgroup_root = Path(cgroup_root) if cgroup_root is not None else None

    @staticmethod
    def cpu_max_value(cpu_quota_millis, period=100_000):
        if type(cpu_quota_millis) is not int or cpu_quota_millis <= 0:
            raise ValueError("CPU quota must be positive integer milli-CPUs")
        quota = max(1, cpu_quota_millis * period // 1000)
        return f"{quota} {period}"

    @staticmethod
    def _decode_mount_path(value):
        return re.sub(r"\\([0-7]{3})", lambda match: chr(int(match.group(1), 8)), value)

    def _locate(self):
        if not sys.platform.startswith("linux"):
            return None, "cgroup_v2_requires_linux"
        if self.cgroup_root is not None:
            return self.cgroup_root, None
        try:
            membership = (self.proc_root / "self/cgroup").read_text(encoding="ascii")
            mountinfo = (self.proc_root / "self/mountinfo").read_text(encoding="utf-8")
        except OSError:
            return None, "cgroup_membership_unavailable"
        relative = None
        for line in membership.splitlines():
            fields = line.split(":", 2)
            if len(fields) == 3 and fields[0] == "0" and fields[1] == "":
                relative = fields[2]
                break
        if relative is None:
            return None, "unified_cgroup_membership_missing"
        for line in mountinfo.splitlines():
            halves = line.split(" - ", 1)
            if len(halves) != 2 or not halves[1].startswith("cgroup2 "):
                continue
            fields = halves[0].split()
            if len(fields) < 5:
                continue
            mount_root = self._decode_mount_path(fields[3])
            mount_point = self._decode_mount_path(fields[4])
            if mount_root == "/":
                suffix = relative.lstrip("/")
            elif relative == mount_root:
                suffix = ""
            elif relative.startswith(mount_root.rstrip("/") + "/"):
                suffix = relative[len(mount_root):].lstrip("/")
            else:
                continue
            return Path(mount_point) / suffix, None
        return None, "cgroup_v2_mount_missing"

    def probe(self):
        path, reason = self._locate()
        if path is None:
            return {"available": False, "reason": reason, "controllers": []}
        try:
            controllers = sorted((path / "cgroup.controllers").read_text(encoding="ascii").split())
            subtree = sorted((path / "cgroup.subtree_control").read_text(encoding="ascii").split())
        except OSError:
            return {"available": False, "reason": "delegated_cgroup_controls_unreadable",
                    "controllers": []}
        missing = sorted({"cpu", "memory"} - set(controllers))
        return {"available": not missing and set(subtree) >= {"cpu", "memory"},
                "reason": None if not missing and set(subtree) >= {"cpu", "memory"}
                else "cpu_memory_controllers_not_delegated",
                "controllers": controllers, "enabled": subtree}

    def create_group(self, group_name, policy, role):
        policy = validate_policy(policy)
        if role not in ("host", "coordinator"):
            raise ResourceError("only an execution role may receive a cgroup")
        if not isinstance(group_name, str) or not re.fullmatch(r"participant-[a-z0-9-]{1,40}", group_name):
            raise ResourceError("cgroup group name is not an approved identifier")
        parent, reason = self._locate()
        if parent is None:
            raise ResourceError(reason)
        try:
            controllers = set((parent / "cgroup.controllers").read_text(encoding="ascii").split())
            missing = {"cpu", "memory"} - controllers
            if missing:
                raise ResourceError("cpu_memory_controllers_not_available")
            enabled = set((parent / "cgroup.subtree_control").read_text(
                encoding="ascii").split())
            required = {"cpu", "memory"} - enabled
            if required:
                (parent / "cgroup.subtree_control").write_text(
                    " ".join(f"+{name}" for name in sorted(required)), encoding="ascii")
            enabled = set((parent / "cgroup.subtree_control").read_text(
                encoding="ascii").split())
            if not {"cpu", "memory"}.issubset(enabled):
                raise ResourceError("cpu_memory_controllers_not_delegated")
        except (OSError, ValueError) as error:
            raise ResourceError("delegated cgroup controls are not writable") from error
        group = parent / group_name
        try:
            group.mkdir(mode=0o700)
        except FileExistsError:
            if group.is_symlink() or not group.is_dir():
                raise ResourceError("unsafe existing cgroup path")
        except OSError as error:
            raise ResourceError("delegated cgroup cannot create a role group") from error
        reservation = policy["reservations"].get(role)
        if reservation is None:
            raise ResourceError("role reservation is required before cgroup creation")
        values = {"memory.max": str(sum(reservation[field] for field in MEMORY_FIELDS)),
                  "cpu.max": self.cpu_max_value(reservation["cpu_quota_millis"])}
        try:
            for filename, value in values.items():
                (group / filename).write_text(value, encoding="ascii")
                observed = (group / filename).read_text(encoding="ascii").strip()
                if observed != value:
                    raise ResourceError(f"cgroup did not enforce {filename}")
        except (OSError, ValueError) as error:
            raise ResourceError("delegated cgroup limit write/readback failed") from error
        return group

    @staticmethod
    def attach_child(group, process):
        if not hasattr(process, "pid") or not hasattr(process, "poll") or process.poll() is not None:
            raise ResourceError("only a live supervisor-owned child can join the cgroup")
        try:
            (Path(group) / "cgroup.procs").write_text(str(process.pid), encoding="ascii")
        except OSError as error:
            raise ResourceError("could not attach approved child to its cgroup") from error
        return True


def unsupported_enforcement():
    return {"memory_cpu": False, "disk": False, "bandwidth": False}
