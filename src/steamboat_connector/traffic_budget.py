"""Persistent aggregate byte/rate allowances for later channel wiring.

This primitive charges bounded I/O intentions. It is not a socket meter: its
caller must reserve immediately before nonblocking I/O, call ``assert_live``
at that boundary, then settle from the actual TLS-ciphertext byte count.
"""

from contextlib import contextmanager
import copy
import hashlib
import os
from pathlib import Path
import re
import threading

from steamboat_connector.policy import ROLE_NAMES, validate_policy
from steamboat_connector.storage import (FileLock, StorageError, atomic_write_private,
                                        open_private_directory, read_private_json)
from steamboat_connector.validation import json_bytes
from steamboat_security.clock import Clock


MAX_STATE_BYTES = 65_536
MAX_OUTSTANDING = 16
MAX_ALLOWANCE_BYTES = 16 * 1024
ALLOWANCE_LIFETIME_NS = 100_000_000
_ALLOCATION_ID = re.compile(r"^[0-9a-f]{64}$")
_BOOT_ID = re.compile(r"^[0-9a-f]{32}$")
_BUCKETS = ("data_send", "data_receive", "cleanup_send", "cleanup_receive")
_KINDS = ("data", "cleanup")
_COUNTERS = ("data", "cleanup")
_MAX_TOKEN_NANOBYTES = ((1 << 63) - 1) * 1_000_000_000
_RESERVATION_FIELDS = {
    "reservation_id", "role", "boot_id", "direction", "kind", "max_bytes",
    "deadline_ns", "status", "actual_bytes",
}
_STATE_FIELDS = {
    "version", "allocation_id", "uid", "clock_domain", "policy",
    "policy_sha256", "last_mono_ns", "global", "roles", "reservations",
}
_COUNTER_FIELDS = {"tokens", "charged", "observed", "uncertain_bytes"}


class TrafficBudgetError(RuntimeError):
    """Traffic reservation failed closed."""

    def __init__(self, message, *, retained_owner=None):
        super().__init__(message)
        self.retained_owner = retained_owner


class TrafficBudgetBusy(TrafficBudgetError):
    """Another process owns the short cross-process ledger transaction."""


class TrafficBudgetDenied(TrafficBudgetError):
    """A configured rate or cumulative byte quota is exhausted."""


class MemoryTrafficStore:
    """Explicitly test-only shared in-process state store; never production."""

    def __init__(self):
        self.state = None
        self.lock = threading.RLock()

    def commit(self, state):
        self.state = copy.deepcopy(state)


class TrafficAllowance:
    """Opaque in-process identity token minted by exactly one budget owner."""

    __slots__ = ("_owner", "_reservation_id", "_settlement", "_retired")

    def __init__(self, *args, **kwargs):
        raise TypeError("TrafficAllowance values are minted by TrafficBudget")

    def __setattr__(self, name, value):
        raise AttributeError("traffic allowances are immutable")

    def assert_live(self):
        return self._owner.assert_live(self)

    def settle(self, actual_bytes, *, outcome_known):
        return self._owner.settle(self, actual_bytes, outcome_known=outcome_known)


def _policy_digest(policy):
    return hashlib.sha256(json_bytes(policy)).hexdigest()


def _valid_int(value, *, minimum=0, maximum=(1 << 63) - 1):
    return type(value) is int and minimum <= value <= maximum


def _fresh_counters(policy, role=None):
    source = policy["limits"] if role is None else policy["reservations"].get(role, {})
    tokens = {}
    for key in _BUCKETS:
        direction = "send" if key.endswith("send") else "receive"
        prefix = "cleanup_" if key.startswith("cleanup_") else ""
        rate = source.get(f"{prefix}{direction}_bytes_per_second", 0)
        # One second of explicit token-bucket burst, in byte-nanosecond units.
        tokens[key] = rate * 1_000_000_000
    return {"tokens": tokens, "charged": {kind: 0 for kind in _COUNTERS},
            "observed": {kind: 0 for kind in _COUNTERS},
            "uncertain_bytes": {kind: 0 for kind in _COUNTERS}}


def _validate_network_allocations(policy):
    for field in ("send_bytes_per_second", "receive_bytes_per_second",
                  "total_network_bytes", "cleanup_send_bytes_per_second",
                  "cleanup_receive_bytes_per_second", "cleanup_total_network_bytes"):
        if sum(item[field] for item in policy["reservations"].values()) > policy["limits"][field]:
            raise TrafficBudgetError(f"role traffic reservations exceed global {field}")


def _new_state(allocation_id, uid, clock_domain, policy, now_ns):
    roles = {role: _fresh_counters(policy, role) | {"boot_id": None, "active": False}
             for role in ROLE_NAMES}
    return {"version": 1, "allocation_id": allocation_id, "uid": uid,
            "clock_domain": clock_domain, "policy": policy,
            "policy_sha256": _policy_digest(policy), "last_mono_ns": now_ns,
            "global": _fresh_counters(policy), "roles": roles, "reservations": []}


def _validate_counters(value, policy, role=None):
    if (type(value) is not dict or set(value) != _COUNTER_FIELDS
            or type(value["tokens"]) is not dict or set(value["tokens"]) != set(_BUCKETS)
            or type(value["charged"]) is not dict or set(value["charged"]) != set(_COUNTERS)
            or type(value["observed"]) is not dict or set(value["observed"]) != set(_COUNTERS)
            or type(value["uncertain_bytes"]) is not dict
            or set(value["uncertain_bytes"]) != set(_COUNTERS)):
        raise TrafficBudgetError("traffic budget counters are malformed")
    limits = policy["limits"] if role is None else policy["reservations"].get(role, {})
    for key, tokens in value["tokens"].items():
        direction = "send" if key.endswith("send") else "receive"
        prefix = "cleanup_" if key.startswith("cleanup_") else ""
        capacity = limits.get(f"{prefix}{direction}_bytes_per_second", 0) * 1_000_000_000
        if not _valid_int(tokens, maximum=_MAX_TOKEN_NANOBYTES) or tokens > capacity:
            raise TrafficBudgetError("traffic bucket state is outside its policy cap")
    for counter_name in ("charged", "observed", "uncertain_bytes"):
        if any(not _valid_int(amount) for amount in value[counter_name].values()):
            raise TrafficBudgetError("traffic cumulative counter is malformed")


def _validate_state(state, *, allocation_id, uid, clock_domain):
    if (type(state) is not dict or set(state) != _STATE_FIELDS
            or type(state["version"]) is not int or state["version"] != 1
            or state["allocation_id"] != allocation_id or state["uid"] != uid
            or state["clock_domain"] != clock_domain
            or not _valid_int(state["last_mono_ns"])):
        raise TrafficBudgetError("persistent traffic budget identity or schema is invalid")
    try:
        policy = validate_policy(state["policy"])
        _validate_network_allocations(policy)
    except (TypeError, ValueError, TrafficBudgetError) as error:
        raise TrafficBudgetError("persistent traffic policy is invalid") from error
    if state["policy_sha256"] != _policy_digest(policy):
        raise TrafficBudgetError("persistent policy digest does not match its canonical policy")
    _validate_counters(state["global"], policy)
    if type(state["roles"]) is not dict or set(state["roles"]) != set(ROLE_NAMES):
        raise TrafficBudgetError("persistent traffic role map is malformed")
    for role, counters in state["roles"].items():
        if (type(counters) is not dict or set(counters) != _COUNTER_FIELDS | {"boot_id", "active"}
                or type(counters["active"]) is not bool
                or (counters["boot_id"] is not None
                    and (type(counters["boot_id"]) is not str
                         or not _BOOT_ID.fullmatch(counters["boot_id"])))
                or counters["active"] != (counters["boot_id"] is not None)):
            raise TrafficBudgetError("persistent traffic role generation is malformed")
        _validate_counters({key: counters[key] for key in _COUNTER_FIELDS}, policy, role)
        for kind in _COUNTERS:
            if (counters["observed"][kind] > counters["charged"][kind]
                    or counters["uncertain_bytes"][kind] > counters["charged"][kind]):
                raise TrafficBudgetError("role observed traffic exceeds conservative charges")
    if type(state["reservations"]) is not list or len(state["reservations"]) > MAX_OUTSTANDING:
        raise TrafficBudgetError("persistent outstanding allowance count is invalid")
    identifiers = set()
    for item in state["reservations"]:
        if (type(item) is not dict or set(item) != _RESERVATION_FIELDS
                or type(item["reservation_id"]) is not str
                or not re.fullmatch(r"[0-9a-f]{32}", item["reservation_id"])
                or item["reservation_id"] in identifiers
                or item["role"] not in ROLE_NAMES
                or type(item["boot_id"]) is not str or not _BOOT_ID.fullmatch(item["boot_id"])
                or item["direction"] not in ("send", "receive")
                or item["kind"] not in _KINDS
                or not _valid_int(item["max_bytes"], minimum=1, maximum=MAX_ALLOWANCE_BYTES)
                or not _valid_int(item["deadline_ns"])
                or item["status"] not in ("open", "uncertain")
                or (item["actual_bytes"] is not None and
                    not _valid_int(item["actual_bytes"], maximum=item["max_bytes"]))):
            raise TrafficBudgetError("persistent traffic allowance is malformed")
        role_state = state["roles"][item["role"]]
        if not role_state["active"] or role_state["boot_id"] != item["boot_id"]:
            raise TrafficBudgetError("allowance does not belong to the active role generation")
        if (item["status"] == "open") != (item["actual_bytes"] is None):
            raise TrafficBudgetError("allowance settlement state is inconsistent")
        identifiers.add(item["reservation_id"])
    for kind in _COUNTERS:
        if (state["global"]["observed"][kind] > state["global"]["charged"][kind]
                or state["global"]["uncertain_bytes"][kind]
                > state["global"]["charged"][kind]):
            raise TrafficBudgetError("global observed traffic exceeds conservative charges")
        if sum(role["charged"][kind] for role in state["roles"].values()) != state["global"]["charged"][kind]:
            raise TrafficBudgetError("global and role traffic charges disagree")
        if sum(role["observed"][kind] for role in state["roles"].values()) != state["global"]["observed"][kind]:
            raise TrafficBudgetError("global and role observed byte counts disagree")
        if sum(role["uncertain_bytes"][kind] for role in state["roles"].values()) != state["global"]["uncertain_bytes"][kind]:
            raise TrafficBudgetError("global and role traffic uncertainty disagrees")
    return state


class TrafficBudget:
    """Owner-only persistent traffic allowance ledger.

    Production mode is Linux-only and shares state through a protected file
    and flock. ``for_tests`` explicitly selects a process-local memory store;
    it cannot prove cross-process accounting.
    """

    def __init__(self, state_path, *, allocation_id, uid, clock, clock_domain,
                 policy):
        self._configure_common(allocation_id, uid, clock, clock_domain, policy)
        if not isinstance(state_path, (str, os.PathLike)):
            raise TrafficBudgetError("persistent traffic state path is required")
        self.path = Path(os.path.abspath(os.fspath(state_path)))
        self.lock_path = self.path.with_name(self.path.name + ".lock")
        self._memory = None
        self._thread_lock = threading.RLock()
        if not __import__("sys").platform.startswith("linux"):
            raise TrafficBudgetError("persistent traffic budgets require Linux file-lock semantics")
        if uid != os.getuid():
            raise TrafficBudgetError("traffic ledger UID must be the current owner UID")
        descriptor = open_private_directory(self.path.parent, uid=uid)
        os.close(descriptor)
        self._initialize_persistent()

    @classmethod
    def for_tests(cls, *, store, allocation_id, uid, clock, clock_domain, policy):
        """Construct against an explicitly test-only process-local store."""
        if not isinstance(store, MemoryTrafficStore):
            raise TypeError("for_tests requires MemoryTrafficStore")
        instance = cls.__new__(cls)
        instance._configure_common(allocation_id, uid, clock, clock_domain, policy)
        instance.path = None
        instance.lock_path = None
        instance._memory = store
        instance._thread_lock = threading.RLock()
        with store.lock:
            if store.state is None:
                store.state = _new_state(allocation_id, uid, clock_domain,
                                         instance._requested_policy,
                                         instance._sample_mono_ns())
            instance._load_existing(store.state)
        return instance

    def _configure_common(self, allocation_id, uid, clock, clock_domain, policy):
        if (type(allocation_id) is not str or not _ALLOCATION_ID.fullmatch(allocation_id)
                or not _valid_int(uid)
                or type(clock) is not Clock
                or type(clock_domain) is not str or not 1 <= len(clock_domain) <= 256):
            raise TrafficBudgetError("traffic ledger identity or Clock is invalid")
        normalized = validate_policy(policy)
        _validate_network_allocations(normalized)
        self.allocation_id = allocation_id
        self.uid = uid
        self.clock = clock
        self.clock_domain = clock_domain
        self._requested_policy = normalized
        self._requested_policy_sha256 = _policy_digest(normalized)
        self._policy_mismatch = False
        self._faulted = False
        self._fault_reason = None
        self._uncertain_state = None
        self._retained_lock = None
        self._live_allowances = {}
        self._memory = None

    def _sample_mono_ns(self):
        try:
            if self._memory is None:
                from steamboat_runtime.protocol.clock import clock_identity
                if clock_identity() != self.clock_domain:
                    raise TrafficBudgetError("Linux monotonic clock domain changed")
            sample = self.clock.sample()
            ratio = sample.monotonic.as_integer_ratio()
            value = ratio[0] * 1_000_000_000 // ratio[1]
            if not _valid_int(value):
                raise TrafficBudgetError("monotonic clock nanoseconds are out of range")
            return value
        except Exception as error:
            self._latch_fault("trusted monotonic clock is unavailable")
            raise TrafficBudgetError("trusted monotonic clock is unavailable",
                                     retained_owner=self) from error

    def _latch_fault(self, reason, uncertain_state=None, retained_lock=None):
        self._faulted = True
        self._fault_reason = reason
        if uncertain_state is not None:
            self._uncertain_state = uncertain_state
        if retained_lock is not None:
            self._retained_lock = retained_lock

    @contextmanager
    def _owner_guard(self):
        with self._thread_lock:
            if self._memory is None:
                yield
            else:
                with self._memory.lock:
                    yield

    def _load_existing(self, state):
        try:
            _validate_state(state, allocation_id=self.allocation_id, uid=self.uid,
                            clock_domain=self.clock_domain)
            now = self._sample_mono_ns()
            if now < state["last_mono_ns"]:
                raise TrafficBudgetError("persistent monotonic checkpoint moved backwards")
            self._policy_mismatch = state["policy_sha256"] != self._requested_policy_sha256
        except TrafficBudgetError:
            raise

    def _acquire_transaction_lock(self, lock):
        try:
            lock.acquire()
        except StorageError as error:
            if "already held" in str(error):
                raise TrafficBudgetBusy("traffic ledger transaction is busy") from error
            self._latch_fault("traffic ledger lock acquisition failed")
            raise TrafficBudgetError("traffic ledger lock acquisition failed",
                                     retained_owner=self) from error
        except Exception as error:
            self._latch_fault("traffic ledger lock acquisition failed")
            raise TrafficBudgetError("traffic ledger lock acquisition failed",
                                     retained_owner=self) from error

    def _initialize_persistent(self):
        lock = FileLock(self.lock_path, uid=self.uid, timeout=0)
        try:
            self._acquire_transaction_lock(lock)
        except TrafficBudgetBusy:
            raise
        primary = None
        try:
            try:
                state = read_private_json(self.path, maximum_size=MAX_STATE_BYTES, uid=self.uid)
            except FileNotFoundError:
                state = _new_state(self.allocation_id, self.uid, self.clock_domain,
                                   self._requested_policy, self._sample_mono_ns())
                self._write_state(state)
            self._load_existing(state)
        except BaseException as error:
            primary = error
            if isinstance(error, (StorageError, TrafficBudgetError)):
                self._latch_fault("persistent traffic ledger initialization is uncertain")
                try:
                    error.retained_owner = self
                except Exception:
                    pass
            raise
        finally:
            try:
                lock.release()
            except BaseException as error:
                self._latch_fault("traffic ledger lock release outcome is unknown", retained_lock=lock)
                if primary is None:
                    raise TrafficBudgetError("traffic lock release is uncertain",
                                             retained_owner=self) from error

    def _write_state(self, state):
        data = json_bytes(state, maximum_bytes=MAX_STATE_BYTES)
        atomic_write_private(self.path, data, uid=self.uid, exact_mode=0o600)

    @contextmanager
    def _locked(self):
        with self._owner_guard():
            if self._faulted:
                raise TrafficBudgetError(self._fault_reason or "traffic ledger is faulted",
                                         retained_owner=self)
            lock = None
            if self._memory is None:
                lock = FileLock(self.lock_path, uid=self.uid, timeout=0)
                try:
                    self._acquire_transaction_lock(lock)
                except TrafficBudgetBusy:
                    raise
            state = None
            primary = None
            try:
                if self._memory is None:
                    try:
                        state = read_private_json(self.path, maximum_size=MAX_STATE_BYTES,
                                                  uid=self.uid)
                    except BaseException as error:
                        self._latch_fault("persistent traffic ledger read failed")
                        raise TrafficBudgetError("persistent traffic ledger is unreadable",
                                                 retained_owner=self) from error
                else:
                    state = copy.deepcopy(self._memory.state)
                try:
                    _validate_state(state, allocation_id=self.allocation_id, uid=self.uid,
                                    clock_domain=self.clock_domain)
                except TrafficBudgetError as error:
                    self._latch_fault("persistent traffic ledger validation failed")
                    raise TrafficBudgetError(str(error), retained_owner=self) from error
                self._policy_mismatch = (
                    state["policy_sha256"] != self._requested_policy_sha256)
                if self._policy_mismatch:
                    raise TrafficBudgetError("explicit policy refresh is required",
                                             retained_owner=self)
                yield state
            except BaseException as error:
                primary = error
                raise
            finally:
                if lock is not None:
                    try:
                        lock.release()
                    except BaseException as error:
                        self._latch_fault("traffic ledger lock release outcome is unknown",
                                          retained_lock=lock)
                        if primary is None:
                            raise TrafficBudgetError("traffic lock release is uncertain",
                                                     retained_owner=self) from error

    @contextmanager
    def _mutation(self, *, allow_policy_mismatch=False):
        with self._owner_guard():
            if self._faulted:
                raise TrafficBudgetError(self._fault_reason or "traffic ledger is faulted",
                                         retained_owner=self)
            lock = None
            if self._memory is None:
                lock = FileLock(self.lock_path, uid=self.uid, timeout=0)
                try:
                    self._acquire_transaction_lock(lock)
                except TrafficBudgetBusy:
                    raise
            primary = None
            try:
                if self._memory is None:
                    try:
                        original = read_private_json(self.path, maximum_size=MAX_STATE_BYTES,
                                                     uid=self.uid)
                    except BaseException as error:
                        self._latch_fault("persistent traffic ledger read failed")
                        raise TrafficBudgetError("persistent traffic ledger is unreadable",
                                                 retained_owner=self) from error
                else:
                    original = copy.deepcopy(self._memory.state)
                try:
                    _validate_state(original, allocation_id=self.allocation_id,
                                    uid=self.uid, clock_domain=self.clock_domain)
                except TrafficBudgetError as error:
                    self._latch_fault("persistent traffic ledger validation failed")
                    raise TrafficBudgetError(str(error), retained_owner=self) from error
                if (not allow_policy_mismatch and
                        original["policy_sha256"] != self._requested_policy_sha256):
                    self._policy_mismatch = True
                    raise TrafficBudgetError("explicit policy refresh is required",
                                             retained_owner=self)
                state = copy.deepcopy(original)
                yield state
                try:
                    if self._memory is None:
                        self._write_state(state)
                    else:
                        self._memory.commit(state)
                except BaseException as error:
                    self._latch_fault("traffic ledger commit outcome is unknown", state)
                    raise TrafficBudgetError("traffic ledger commit outcome is unknown",
                                             retained_owner=self) from error
            except BaseException as error:
                primary = error
                raise
            finally:
                if lock is not None:
                    try:
                        lock.release()
                    except BaseException as error:
                        self._latch_fault("traffic ledger lock release outcome is unknown",
                                          retained_lock=lock)
                        if primary is None:
                            raise TrafficBudgetError("traffic lock release is uncertain",
                                                     retained_owner=self) from error

    def _now(self, state):
        now = self._sample_mono_ns()
        if now < state["last_mono_ns"]:
            self._latch_fault("monotonic clock regressed behind persistent ledger")
            raise TrafficBudgetError("monotonic clock regressed behind persistent ledger",
                                     retained_owner=self)
        return now

    @staticmethod
    def _rate(policy, bucket, role=None):
        direction = "send" if bucket.endswith("send") else "receive"
        prefix = "cleanup_" if bucket.startswith("cleanup_") else ""
        source = policy["limits"] if role is None else policy["reservations"].get(role, {})
        return source.get(f"{prefix}{direction}_bytes_per_second", 0)

    def _advance(self, state, now_ns, *, policy=None):
        policy = state["policy"] if policy is None else policy
        elapsed = now_ns - state["last_mono_ns"]
        global_state = state["global"]
        role_states = state["roles"]
        for bucket in _BUCKETS:
            global_rate = self._rate(policy, bucket)
            cap = global_rate * 1_000_000_000
            global_state["tokens"][bucket] = min(
                cap, global_state["tokens"][bucket] + elapsed * global_rate)
            for role, counters in role_states.items():
                rate = self._rate(policy, bucket, role)
                role_cap = rate * 1_000_000_000
                counters["tokens"][bucket] = min(
                    role_cap, counters["tokens"][bucket] + elapsed * rate)
        state["last_mono_ns"] = now_ns

    def _current_role(self, state, role, boot_id):
        value = state["roles"].get(role)
        if (value is None or not value["active"] or value["boot_id"] != boot_id
                or role not in state["policy"]["reservations"]):
            raise TrafficBudgetError("role is not bound to this active generation and policy")
        return value

    @staticmethod
    def _bucket(direction, kind):
        return kind + "_" + direction

    def bind_role(self, role, boot_id):
        if role not in ROLE_NAMES or type(boot_id) is not str or not _BOOT_ID.fullmatch(boot_id):
            raise TrafficBudgetError("role or generation identity is invalid")
        with self._mutation() as state:
            if role not in state["policy"]["reservations"]:
                raise TrafficBudgetError("role has no explicit traffic reservation")
            entry = state["roles"][role]
            if entry["active"]:
                if entry["boot_id"] == boot_id:
                    return {"role": role, "boot_id": boot_id, "already_bound": True}
                raise TrafficBudgetError("old role generation must be reclaimed before replacement")
            now = self._now(state)
            self._advance(state, now)
            entry["active"] = True
            entry["boot_id"] = boot_id
            return {"role": role, "boot_id": boot_id, "already_bound": False}

    def reserve(self, role, boot_id, direction, kind, max_bytes):
        if (role not in ROLE_NAMES or type(boot_id) is not str or not _BOOT_ID.fullmatch(boot_id)
                or direction not in ("send", "receive") or kind not in _KINDS
                or not _valid_int(max_bytes, minimum=1, maximum=MAX_ALLOWANCE_BYTES)):
            raise TrafficBudgetError("traffic allowance request is malformed")
        import secrets
        reservation_id = secrets.token_hex(16)
        allowance = None
        with self._mutation() as state:
            now = self._now(state)
            self._advance(state, now)
            role_state = self._current_role(state, role, boot_id)
            if len(state["reservations"]) >= MAX_OUTSTANDING:
                raise TrafficBudgetDenied("outstanding traffic allowance slots are full")
            role_cap = state["policy"]["reservations"][role]
            limits = state["policy"]["limits"]
            total_field = "total_network_bytes" if kind == "data" else "cleanup_total_network_bytes"
            bucket = self._bucket(direction, kind)
            scaled = max_bytes * 1_000_000_000
            if (state["global"]["tokens"][bucket] < scaled
                    or role_state["tokens"][bucket] < scaled):
                raise TrafficBudgetDenied("directional traffic rate allowance is exhausted")
            if (state["global"]["charged"][kind] + max_bytes > limits[total_field]
                    or role_state["charged"][kind] + max_bytes > role_cap[total_field]):
                raise TrafficBudgetDenied("cumulative traffic allowance is exhausted")
            state["global"]["tokens"][bucket] -= scaled
            role_state["tokens"][bucket] -= scaled
            state["global"]["charged"][kind] += max_bytes
            role_state["charged"][kind] += max_bytes
            deadline = now + ALLOWANCE_LIFETIME_NS
            state["reservations"].append({
                "reservation_id": reservation_id, "role": role, "boot_id": boot_id,
                "direction": direction, "kind": kind, "max_bytes": max_bytes,
                "deadline_ns": deadline, "status": "open", "actual_bytes": None})
            allowance = object.__new__(TrafficAllowance)
            object.__setattr__(allowance, "_owner", self)
            object.__setattr__(allowance, "_reservation_id", reservation_id)
            object.__setattr__(allowance, "_settlement", None)
            object.__setattr__(allowance, "_retired", False)
            self._live_allowances[reservation_id] = allowance
        return allowance

    def _record_for(self, state, allowance):
        if type(allowance) is not TrafficAllowance:
            raise TrafficBudgetError("allowance token is forged, foreign, or retired")
        try:
            owner = allowance._owner
            reservation_id = allowance._reservation_id
        except AttributeError as error:
            raise TrafficBudgetError("allowance token is malformed") from error
        if (owner is not self
                or self._live_allowances.get(reservation_id) is not allowance):
            raise TrafficBudgetError("allowance token is forged, foreign, or retired")
        for item in state["reservations"]:
            if item["reservation_id"] == reservation_id:
                return item
        raise TrafficBudgetError("allowance is no longer outstanding")

    def assert_live(self, allowance):
        with self._mutation() as state:
            item = self._record_for(state, allowance)
            now = self._now(state)
            self._advance(state, now)
            if (item["status"] != "open" or now >= item["deadline_ns"]
                    or not state["roles"][item["role"]]["active"]
                    or state["roles"][item["role"]]["boot_id"] != item["boot_id"]):
                raise TrafficBudgetError("allowance is expired or its generation is inactive")
            return {"role": item["role"], "direction": item["direction"],
                    "kind": item["kind"], "max_bytes": item["max_bytes"],
                    "deadline_ns": item["deadline_ns"]}

    def settle(self, allowance, actual_bytes, *, outcome_known):
        if type(actual_bytes) is not int or type(outcome_known) is not bool:
            raise TrafficBudgetError("allowance settlement is malformed")
        if type(allowance) is not TrafficAllowance:
            raise TrafficBudgetError("allowance token is forged, foreign, or retired")
        self._record_token_owner(allowance)
        requested = (actual_bytes, outcome_known)
        if allowance._settlement is not None:
            if allowance._settlement[0] != requested:
                raise TrafficBudgetError("allowance settlement cannot be changed")
            return dict(allowance._settlement[1])
        if self._live_allowances.get(allowance._reservation_id) is not allowance:
            raise TrafficBudgetError("allowance token is forged, foreign, or retired")
        result = None
        with self._mutation() as state:
            item = self._record_for(state, allowance)
            if actual_bytes > item["max_bytes"] or actual_bytes < 0:
                raise TrafficBudgetError("observed bytes exceed the reserved allowance")
            if item["status"] != "open":
                raise TrafficBudgetError("uncertain allowance cannot be settled again")
            now = self._now(state)
            self._advance(state, now)
            role = item["role"]
            kind = item["kind"]
            reserved = item["max_bytes"]
            certain = outcome_known and now < item["deadline_ns"]
            refund = reserved - actual_bytes if certain else 0
            bucket = self._bucket(item["direction"], kind)
            if refund:
                state["global"]["charged"][kind] -= refund
                state["roles"][role]["charged"][kind] -= refund
                state["global"]["tokens"][bucket] = min(
                    state["global"]["tokens"][bucket] + refund * 1_000_000_000,
                    self._rate(state["policy"], bucket) * 1_000_000_000)
                state["roles"][role]["tokens"][bucket] = min(
                    state["roles"][role]["tokens"][bucket] + refund * 1_000_000_000,
                    self._rate(state["policy"], bucket, role) * 1_000_000_000)
            state["global"]["observed"][kind] += actual_bytes
            state["roles"][role]["observed"][kind] += actual_bytes
            if not certain:
                state["global"]["uncertain_bytes"][kind] += reserved
                state["roles"][role]["uncertain_bytes"][kind] += reserved
                item["status"] = "uncertain"
                item["actual_bytes"] = actual_bytes
            else:
                state["reservations"].remove(item)
            result = {"actual_bytes": actual_bytes, "charged_bytes": reserved - refund,
                      "refunded_bytes": refund, "outcome_known": outcome_known,
                      "uncertain": not certain}
            object.__setattr__(allowance, "_settlement", (requested, result))
            if not result["uncertain"]:
                self._live_allowances.pop(allowance._reservation_id, None)
                object.__setattr__(allowance, "_retired", True)
        if result["uncertain"]:
            # Retain the token: it documents the unresolved I/O outcome. It is
            # not admitted again and is purged only during generation reclaim.
            pass
        return dict(result)

    def _record_token_owner(self, allowance):
        try:
            owner = allowance._owner
            reservation_id = allowance._reservation_id
        except AttributeError as error:
            raise TrafficBudgetError("allowance token is malformed") from error
        if owner is not self or type(reservation_id) is not str:
            raise TrafficBudgetError("allowance token is forged, foreign, or retired")

    def refresh_policy(self, policy):
        normalized = validate_policy(policy)
        _validate_network_allocations(normalized)
        digest = _policy_digest(normalized)
        with self._mutation(allow_policy_mismatch=True) as state:
            now = self._now(state)
            self._advance(state, now)
            for kind in _COUNTERS:
                global_limit = normalized["limits"][
                    "total_network_bytes" if kind == "data" else "cleanup_total_network_bytes"]
                if state["global"]["charged"][kind] > global_limit:
                    raise TrafficBudgetError("new policy is below already charged traffic")
                for role in ROLE_NAMES:
                    role_total = normalized["reservations"].get(role, {}).get(
                        "total_network_bytes" if kind == "data" else "cleanup_total_network_bytes", 0)
                    if state["roles"][role]["charged"][kind] > role_total:
                        raise TrafficBudgetError("new role policy is below already charged traffic")
            for role, entry in state["roles"].items():
                if entry["active"] and role not in normalized["reservations"]:
                    raise TrafficBudgetError("cannot remove an active role reservation")
            state["policy"] = normalized
            state["policy_sha256"] = digest
            for role, entry in state["roles"].items():
                for bucket in _BUCKETS:
                    entry["tokens"][bucket] = min(
                        entry["tokens"][bucket],
                        self._rate(normalized, bucket, role) * 1_000_000_000)
            for bucket in _BUCKETS:
                state["global"]["tokens"][bucket] = min(
                    state["global"]["tokens"][bucket],
                    self._rate(normalized, bucket) * 1_000_000_000)
        self._requested_policy = normalized
        self._requested_policy_sha256 = digest
        self._policy_mismatch = False
        return {"policy_sha256": digest}

    def reconcile_dead_generation(self, role, boot_id, *, reaped, cgroup_empty):
        """Retire a generation only after trusted supervisor cleanup proof.

        The booleans are assertions from the trusted process supervisor; this
        primitive cannot independently inspect the process tree or cgroup.
        """
        if (role not in ROLE_NAMES or type(boot_id) is not str
                or not _BOOT_ID.fullmatch(boot_id) or type(reaped) is not bool
                or type(cgroup_empty) is not bool or not reaped or not cgroup_empty):
            raise TrafficBudgetError("dead-generation cleanup proof is invalid")
        with self._mutation() as state:
            entry = state["roles"][role]
            if not entry["active"] or entry["boot_id"] != boot_id:
                raise TrafficBudgetError("generation is not the active role owner")
            # Open allowances were fully charged before I/O. Retire them without
            # refund; an unknown commit can never make quota available again.
            state["reservations"] = [item for item in state["reservations"]
                                     if not (item["role"] == role and item["boot_id"] == boot_id)]
            entry["active"] = False
            entry["boot_id"] = None
        for reservation_id, allowance in list(self._live_allowances.items()):
            if allowance._owner is self and allowance._reservation_id not in {
                    item["reservation_id"] for item in state["reservations"]}:
                self._live_allowances.pop(reservation_id, None)
                object.__setattr__(allowance, "_retired", True)
        return {"role": role, "boot_id": boot_id, "reconciled": True}

    def status(self):
        try:
            with self._locked() as state:
                return {"allocation_id": self.allocation_id, "uid": self.uid,
                        "clock_domain": self.clock_domain,
                        "policy_sha256": state["policy_sha256"],
                        "faulted": self._faulted, "policy_refresh_required": self._policy_mismatch,
                        "roles": {role: {"active": value["active"],
                                         "boot_id": value["boot_id"],
                                         "charged": dict(value["charged"]),
                                         "observed": dict(value["observed"])}
                                  for role, value in state["roles"].items()},
                        "global": {"charged": dict(state["global"]["charged"]),
                                   "observed": dict(state["global"]["observed"]),
                                   "uncertain_bytes": dict(state["global"]["uncertain_bytes"])},
                        "outstanding": len(state["reservations"])}
        except TrafficBudgetError:
            return {"allocation_id": self.allocation_id, "uid": self.uid,
                    "clock_domain": self.clock_domain, "faulted": self._faulted,
                    "fault_reason": self._fault_reason,
                    "policy_refresh_required": self._policy_mismatch,
                    "outstanding": None}
