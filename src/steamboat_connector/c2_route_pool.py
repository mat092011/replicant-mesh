"""Inert v2 route-membership accounting for one operator-provisioned physical pool.

This ledger records bounded membership only. It grants no authority, readiness,
queue capacity, memory proof, or permission to execute work.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import secrets
import stat
import threading

from .storage import FileLock, StorageError, atomic_write_private, open_private_directory, read_private_file
from .validation import json_bytes, strict_json_loads, valid_typed_id

VERSION = 2
PROFILE = "physical_pool_route_membership_v2"
MAX_ROUTES = 8
MAX_MEMBERS = 32
MAX_MEMBERS_PER_ROUTE = 4
MAX_FILE_BYTES = 131_072
_HEX64 = __import__("re").compile(r"^[0-9a-f]{64}$")
_BOOT = __import__("re").compile(r"^[0-9a-f]{32}$")
_SERIAL = __import__("re").compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_ROUTE_FIELDS = {"tenant_account_id", "coordinator_account_id", "coordinator_device_id", "coordinator_serial", "coordinator_key_hash", "coordinator_credential_epoch", "coordinator_boot_id", "request_id", "session_id", "route_id", "route_epoch", "attempt", "model_id"}
_MEMBER_FIELDS = {"selected_root_generation", "parent_boot_id", "role", "component", "worker_boot_id", "assignment_id", "credential_serial", "credential_key_hash", "credential_epoch", "admission_epoch"}


class RoutePoolError(Exception):
    """Invalid, unavailable, or indeterminate route-pool ledger operation."""


def _id(v, prefix):
    if not valid_typed_id(v, prefix):
        raise RoutePoolError(f"invalid {prefix} identifier")


def _positive(v, name):
    if type(v) is not int or v < 1:
        raise RoutePoolError(f"{name} must be an exact positive integer")


def _validate_route(r):
    if type(r) is not dict or set(r) != _ROUTE_FIELDS:
        raise RoutePoolError("route fields do not match the closed v2 schema")
    for k in ("tenant_account_id", "coordinator_account_id"):
        _id(r[k], "acct")
    if r["tenant_account_id"] != r["coordinator_account_id"]:
        raise RoutePoolError("personal coordinator tenant must match its account")
    for k in ("coordinator_device_id",): _id(r[k], "dev")
    for k in ("request_id",): _id(r[k], "req")
    for k in ("session_id",): _id(r[k], "ses")
    _id(r["route_id"], "route")
    for k in ("coordinator_boot_id",):
        if type(r[k]) is not str or not _BOOT.fullmatch(r[k]): raise RoutePoolError(f"invalid {k}")
    for k in ("coordinator_serial",):
        if type(r[k]) is not str or not _SERIAL.fullmatch(r[k]): raise RoutePoolError(f"invalid {k}")
    if type(r["coordinator_key_hash"]) is not str or not _HEX64.fullmatch(r["coordinator_key_hash"]): raise RoutePoolError("invalid coordinator key hash")
    for k in ("coordinator_credential_epoch", "route_epoch", "attempt"): _positive(r[k], k)
    if r["route_epoch"] != 2 or r["attempt"] != 1: raise RoutePoolError("v2 route epoch and attempt are fixed")
    if type(r["model_id"]) is not str or not r["model_id"] or len(r["model_id"]) > 128: raise RoutePoolError("invalid model id")


def _validate_member(m):
    if type(m) is not dict or set(m) != _MEMBER_FIELDS: raise RoutePoolError("member fields do not match the closed v2 schema")
    for k in ("selected_root_generation", "parent_boot_id", "worker_boot_id"):
        if type(m[k]) is not str or not _BOOT.fullmatch(m[k]): raise RoutePoolError(f"invalid {k}")
    if m["role"] not in ("host", "personal_coordinator"): raise RoutePoolError("invalid member role")
    if m["component"] not in ("worker1", "worker2", "worker3", "coordinator"): raise RoutePoolError("invalid component")
    if type(m["credential_serial"]) is not str or not _SERIAL.fullmatch(m["credential_serial"]): raise RoutePoolError("invalid credential serial")
    if type(m["credential_key_hash"]) is not str or not _HEX64.fullmatch(m["credential_key_hash"]): raise RoutePoolError("invalid credential key hash")
    for k in ("credential_epoch", "admission_epoch"): _positive(m[k], k)
    if m["role"] == "host": _id(m["assignment_id"], "asg")
    elif m["assignment_id"] is not None: raise RoutePoolError("coordinator member assignment must be null")
    if (m["role"] == "personal_coordinator") != (m["component"] == "coordinator"): raise RoutePoolError("role/component mismatch")


class C2RoutePool:
    """Durable, bounded route membership; caller must provision a private directory."""
    def __init__(self, directory, *, physical_host_id, pool_id, allowed_members, uid=None):
        import stat
        self.directory = Path(os.path.abspath(os.fspath(directory)))
        self.uid = os.getuid() if uid is None else uid
        if type(self.uid) is not int or self.uid < 0: raise RoutePoolError("invalid uid")
        if type(physical_host_id) is not str or not _HEX64.fullmatch(physical_host_id): raise RoutePoolError("invalid physical host id")
        if type(pool_id) is not str or not pool_id or len(pool_id) > 128: raise RoutePoolError("invalid pool id")
        if type(allowed_members) is not list or not 1 <= len(allowed_members) <= MAX_MEMBERS: raise RoutePoolError("allowlist must contain 1..32 exact members")
        members = []
        for item in allowed_members:
            _validate_member(item); members.append(dict(item))
        keys = [json_bytes(x) for x in members]
        if len(keys) != len(set(keys)): raise RoutePoolError("duplicate allowlist member")
        self.allowed = {x.hex() for x in keys}
        self.config_digest = hashlib.sha256(json_bytes({"physical_host_id": physical_host_id, "pool_id": pool_id, "allowed_members": members, "max_routes": MAX_ROUTES})).hexdigest()
        self.path = self.directory / "c2-route-pool-v2.json"
        self.lock_path = self.directory / "c2-route-pool-v2.lock"
        self._thread = threading.RLock()
        self._faulted = False
        try:
            fd = open_private_directory(self.directory, uid=self.uid); os.close(fd)
            with self._locked():
                try: state = self._read()
                except FileNotFoundError:
                    state = {"version": VERSION, "profile": PROFILE, "config_digest": self.config_digest, "routes": {}, "receipts": {}}
                    self._write(state)
                self._check_state(state)
        except (StorageError, OSError, ValueError, TypeError) as e:
            raise RoutePoolError("ledger directory/state unavailable or unsafe") from e

    def _locked(self):
        class Ctx:
            def __init__(s, owner): s.o=owner
            def __enter__(s):
                s.o._thread.acquire()
                try:
                    s.lock=FileLock(s.o.lock_path, uid=s.o.uid, timeout=0).acquire()
                    s.o._check_named_file(s.o.lock_path)
                except Exception:
                    if hasattr(s, "lock"): s.lock.release()
                    s.o._thread.release(); raise
                return s
            def __exit__(s, *args):
                try: s.lock.release()
                finally: s.o._thread.release()
        return Ctx(self)

    def _check_named_file(self, path):
        fd=open_private_directory(self.directory, uid=self.uid)
        try:
            info=os.stat(path.name, dir_fd=fd, follow_symlinks=False)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != self.uid or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1:
                raise RoutePoolError("ledger files must be private single-link regular files")
        finally: os.close(fd)
    def _healthy(self):
        if self._faulted: raise RoutePoolError("ledger is faulted after an ambiguous commit; operator recovery required")
    def _read(self):
        self._healthy(); self._check_named_file(self.path)
        return strict_json_loads(read_private_file(self.path, maximum_size=MAX_FILE_BYTES, uid=self.uid), maximum_bytes=MAX_FILE_BYTES)
    def _write(self, state):
        try: data=json_bytes(state, maximum_bytes=MAX_FILE_BYTES)
        except (TypeError, ValueError) as e: raise RoutePoolError("state exceeds fixed ledger bound") from e
        try: atomic_write_private(self.path, data, uid=self.uid); self._check_named_file(self.path)
        except Exception as e:
            self._faulted = True
            raise RoutePoolError("ledger commit outcome may be unknown; fail closed") from e
    def _check_state(self, s):
        if type(s) is not dict or set(s) != {"version", "profile", "config_digest", "routes", "receipts"} or type(s["version"]) is not int or s["version"] != VERSION or s["profile"] != PROFILE or s["config_digest"] != self.config_digest or type(s["routes"]) is not dict or type(s["receipts"]) is not dict:
            raise RoutePoolError("unknown schema or configuration binding; ledger is fail-closed")
        if len(s["routes"]) > MAX_ROUTES or len(s["receipts"]) > 64: raise RoutePoolError("ledger bounds exceeded")

    def reserve(self, route, member):
        self._healthy()
        _validate_route(route); _validate_member(member)
        routekey=json_bytes(route).hex(); memberkey=json_bytes(member).hex()
        if memberkey not in self.allowed: raise RoutePoolError("member is outside protected configuration allowlist")
        with self._locked():
            s=self._read(); self._check_state(s)
            rec=s["routes"].get(routekey)
            if rec is not None:
                if rec["route"] != route: raise RoutePoolError("route identity collision")
                if rec["closed"]: raise RoutePoolError("route is terminal; late joins are refused")
                if memberkey in rec["members"]: return rec["members"][memberkey]["receipt"]
            else:
                active=sum(not x["closed"] for x in s["routes"].values())
                if active >= MAX_ROUTES: raise RoutePoolError("live route limit reached")
                if len(s["routes"]) >= MAX_ROUTES: raise RoutePoolError("route history bound reached; operator intervention required")
                rec={"route":route,"closed":False,"members":{}}; s["routes"][routekey]=rec
            live=sum(not x["released"] for x in rec["members"].values())
            total=sum(sum(not y["released"] for y in x["members"].values()) for x in s["routes"].values())
            if live >= MAX_MEMBERS_PER_ROUTE or total >= MAX_MEMBERS: raise RoutePoolError("member limit reached")
            token=secrets.token_hex(32)
            receipt={"version":VERSION,"profile":PROFILE,"route_key":routekey,"member_key":memberkey,"token":token}
            rec["members"][memberkey]={"receipt":receipt,"released":False}
            try: self._write(s)
            except RoutePoolError: raise
            return dict(receipt)

    def release(self, receipt, *, actual_reclamation_confirmed):
        self._healthy()
        if actual_reclamation_confirmed is not True: raise RoutePoolError("release requires trusted confirmation of actual session reclamation")
        if type(receipt) is not dict or set(receipt)!={"version","profile","route_key","member_key","token"} or type(receipt["version"]) is not int or receipt["version"] != VERSION or receipt["profile"] != PROFILE or type(receipt["token"]) is not str or not __import__("re").fullmatch(r"[0-9a-f]{64}",receipt["token"]): raise RoutePoolError("invalid release receipt")
        with self._locked():
            s=self._read(); self._check_state(s)
            rec=s["routes"].get(receipt["route_key"])
            ent=None if rec is None else rec["members"].get(receipt["member_key"])
            if ent is None or ent["receipt"] != receipt: raise RoutePoolError("receipt is stale or does not identify this exact reservation")
            if ent["released"]: return False
            ent["released"]=True
            rec["closed"]=not any(not x["released"] for x in rec["members"].values())
            self._write(s)
            return True

    def snapshot(self):
        self._healthy()
        with self._locked():
            s=self._read(); self._check_state(s); return s
