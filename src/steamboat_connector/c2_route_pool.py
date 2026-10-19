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
from dataclasses import dataclass

from .storage import FileLock, StorageError, atomic_write_private, open_private_directory, read_private_file
from .validation import json_bytes, strict_json_loads, valid_typed_id

VERSION = 2
PROFILE = "physical_pool_route_membership_v2"
MAX_ROUTES = 8
MAX_MEMBERS = 32
MAX_SELECTED_MEMBERS = 4
MAX_MEMBERS_PER_ROUTE = 4
MAX_ROUTE_RECORDS = 32
MAX_MEMBER_RECORDS = 128
MAX_FILE_BYTES = 131_072
_HEX64 = __import__("re").compile(r"^[0-9a-f]{64}$")
_BOOT = __import__("re").compile(r"^[0-9a-f]{32}$")
_SERIAL = __import__("re").compile(r"^[1-9a-f][0-9a-f]{0,39}$")
_ROUTE_FIELDS = {"tenant_account_id", "coordinator_account_id", "coordinator_device_id", "coordinator_serial", "coordinator_key_hash", "coordinator_credential_epoch", "coordinator_boot_id", "request_id", "session_id", "route_id", "route_epoch", "attempt", "model_id"}
_MEMBER_FIELDS = {"selected_root_generation", "parent_boot_id", "account_id", "device_id", "role", "component", "worker_boot_id", "assignment_id", "credential_serial", "credential_key_hash", "credential_certificate_hash", "credential_epoch", "admission_epoch"}


class RoutePoolError(Exception):
    """Invalid, unavailable, or indeterminate route-pool ledger operation."""


def _id(v, prefix):
    if not valid_typed_id(v, prefix):
        raise RoutePoolError(f"invalid {prefix} identifier")


def _positive(v, name):
    if type(v) is not int or not 1 <= v <= 2**63-1:
        raise RoutePoolError(f"{name} must be an exact positive signed-63-bit integer")


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
    if r["route_epoch"] != 1 or r["attempt"] != 1: raise RoutePoolError("C1 route epoch and attempt are fixed")
    if type(r["model_id"]) is not str or not _HEX64.fullmatch(r["model_id"]): raise RoutePoolError("invalid model fingerprint")


def _validate_member(m):
    if type(m) is not dict or set(m) != _MEMBER_FIELDS: raise RoutePoolError("member fields do not match the closed v2 schema")
    for k in ("parent_boot_id", "worker_boot_id"):
        if type(m[k]) is not str or not _BOOT.fullmatch(m[k]): raise RoutePoolError(f"invalid {k}")
    if type(m["selected_root_generation"]) is not str or not _HEX64.fullmatch(m["selected_root_generation"]): raise RoutePoolError("invalid selected root generation")
    _id(m["account_id"], "acct"); _id(m["device_id"], "dev")
    if m["role"] not in ("host", "personal_coordinator"): raise RoutePoolError("invalid member role")
    if m["component"] not in ("worker-1", "worker-2", "worker-3", "coordinator"): raise RoutePoolError("invalid component")
    if type(m["credential_serial"]) is not str or not _SERIAL.fullmatch(m["credential_serial"]): raise RoutePoolError("invalid credential serial")
    if type(m["credential_key_hash"]) is not str or not _HEX64.fullmatch(m["credential_key_hash"]): raise RoutePoolError("invalid credential key hash")
    if type(m["credential_certificate_hash"]) is not str or not _HEX64.fullmatch(m["credential_certificate_hash"]): raise RoutePoolError("invalid credential certificate hash")
    for k in ("credential_epoch", "admission_epoch"): _positive(m[k], k)
    if m["role"] == "host": _id(m["assignment_id"], "asg")
    elif m["assignment_id"] is not None: raise RoutePoolError("coordinator member assignment must be null")
    if (m["role"] == "personal_coordinator") != (m["component"] == "coordinator"): raise RoutePoolError("role/component mismatch")


def _write_all(fd, data):
    view=memoryview(data)
    while view:
        count=os.write(fd,view)
        if count<=0: raise OSError("short durable provision write")
        view=view[count:]


@dataclass(frozen=True)
class ReservationResult:
    receipt: dict
    fence_cleanup_confirmed: bool


@dataclass(frozen=True)
class ReleaseResult:
    released: bool
    fence_cleanup_confirmed: bool


def project_host_scope_member(scope, component):
    """Project fields from a parsed C2 host scope; this does not prove provenance."""
    from steamboat_security.root_c2_group_scope import C2HostGroupScope
    if type(scope) is not C2HostGroupScope:
        raise RoutePoolError("exact parsed C2 host group scope value required")
    if type(component) is not str: raise RoutePoolError("component must be exact text")
    selected=[c for c in scope.components if c.component==component]
    if len(selected)!=1: raise RoutePoolError("component is not in the selected parsed scope")
    c=selected[0]
    member={"selected_root_generation":scope.generation_sha256,"parent_boot_id":scope.parent_boot_id,
        "account_id":scope.account_id,"device_id":scope.device_id,"role":"host","component":c.component,
        "worker_boot_id":c.worker_boot_id,"assignment_id":c.assignment_id,
        "credential_serial":scope.credential.serial,"credential_key_hash":scope.credential.public_key_sha256,
        "credential_certificate_hash":scope.credential.certificate_sha256,
        "credential_epoch":scope.credential.credential_epoch,"admission_epoch":scope.admission_epoch}
    _validate_member(member)
    return member


class C2RoutePool:
    """Durable, bounded route membership; caller must provision a private directory."""
    def __init__(self, directory, *, physical_host_id, pool_id, allowed_members, uid=None):
        self._configure(directory, physical_host_id, pool_id, allowed_members, uid)
        try:
            fd = open_private_directory(self.directory, uid=self.uid); os.close(fd)
            with self._locked():
                self._check_named_file(self.marker_path)
                marker = strict_json_loads(read_private_file(self.marker_path, maximum_size=4096, uid=self.uid), maximum_bytes=4096)
                if type(marker) is not dict or set(marker)!={"version","profile","config_digest"} or type(marker["version"]) is not int or marker["version"]!=VERSION or marker["profile"]!=PROFILE or marker["config_digest"]!=self.config_digest:
                    raise RoutePoolError("provisioning marker is invalid or bound to another configuration")
                self._ensure_no_pending()
                state = self._read()
                self._check_state(state)
        except (StorageError, OSError, ValueError, TypeError) as e:
            raise RoutePoolError("ledger directory/state unavailable or unsafe") from e

    @classmethod
    def provision(cls, directory, *, physical_host_id, pool_id, allowed_members, uid=None):
        """Initialize once in an already provisioned private directory."""
        obj = cls.__new__(cls)
        obj._configure(directory, physical_host_id, pool_id, allowed_members, uid)
        fd = open_private_directory(obj.directory, uid=obj.uid)
        marker = {"version": VERSION, "profile": PROFILE, "config_digest": obj.config_digest}
        data = json_bytes(marker, maximum_bytes=4096)
        try:
            mfd = os.open(obj.marker_path.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=fd)
            try:
                _write_all(mfd, data); os.fsync(mfd)
            finally: os.close(mfd)
            state = {"version": VERSION, "profile": PROFILE, "config_digest": obj.config_digest, "routes": {}}
            sdata = json_bytes(state, maximum_bytes=MAX_FILE_BYTES)
            sfd = os.open(obj.path.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=fd)
            try:
                _write_all(sfd, sdata); os.fsync(sfd)
            finally: os.close(sfd)
            os.fsync(fd)
        except OSError as error:
            raise RoutePoolError("exclusive provisioning failed; namespace is non-reusable") from error
        finally: os.close(fd)
        return cls(directory, physical_host_id=physical_host_id, pool_id=pool_id,
                   allowed_members=allowed_members, uid=uid)

    def _configure(self, directory, physical_host_id, pool_id, allowed_members, uid):
        self.directory=Path(os.path.abspath(os.fspath(directory)))
        if type(physical_host_id) is not str or not _HEX64.fullmatch(physical_host_id): raise RoutePoolError("invalid physical host id")
        if type(pool_id) is not str or not pool_id or len(pool_id)>128: raise RoutePoolError("invalid pool id")
        if type(allowed_members) is not list or not 1<=len(allowed_members)<=MAX_SELECTED_MEMBERS: raise RoutePoolError("allowlist must contain 1..4 exact selected members")
        members=[]
        for item in allowed_members: _validate_member(item); members.append(dict(item))
        self.uid=os.getuid() if uid is None else uid
        if type(self.uid) is not int or self.uid < 0: raise RoutePoolError("invalid uid")
        keys=[json_bytes(x) for x in members]
        if len(keys)!=len(set(keys)): raise RoutePoolError("duplicate allowlist member")
        self.allowed={hashlib.sha256(x).hexdigest() for x in keys}
        self.config_digest=hashlib.sha256(json_bytes({"physical_host_id":physical_host_id,"pool_id":pool_id,"allowed_members":members,"max_routes":MAX_ROUTES})).hexdigest()
        self.path=self.directory/"c2-route-pool-v2.json"; self.lock_path=self.directory/"c2-route-pool-v2.lock"; self.marker_path=self.directory/"c2-route-pool-v2.provisioned"; self.pending_path=self.directory/"c2-route-pool-v2.pending"
        self._thread=threading.RLock(); self._faulted=False

    def _locked(self):
        class Ctx:
            def __init__(s, owner): s.o=owner
            def __enter__(s):
                s.o._thread.acquire()
                try:
                    s.lock=FileLock(s.o.lock_path, uid=s.o.uid, timeout=1).acquire()
                    s.o._check_named_file(s.o.lock_path)
                    s.o._ensure_no_pending()
                except Exception:
                    if hasattr(s, "lock"): s.lock.release()
                    s.o._thread.release(); raise
                return s
            def __exit__(s, *args):
                try: s.lock.release()
                except Exception as error:
                    s.o._faulted=True
                    raise RoutePoolError("file lock release is uncertain; this ledger object is faulted") from error
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
    def _ensure_no_pending(self):
        fd=open_private_directory(self.directory,uid=self.uid)
        try:
            try: os.stat(self.pending_path.name,dir_fd=fd,follow_symlinks=False)
            except FileNotFoundError: return
            raise RoutePoolError("durable pending transaction exists; operator recovery required")
        finally: os.close(fd)
    def _confirm_fence_cleanup_unlocked(self):
        """Confirm the pending name is absent and that absence is directory-durable."""
        try:
            fd=open_private_directory(self.directory,uid=self.uid)
            try:
                try: os.stat(self.pending_path.name,dir_fd=fd,follow_symlinks=False)
                except FileNotFoundError: pass
                else: return False
                os.fsync(fd)
            finally: os.close(fd)
            return True
        except Exception:
            return False
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
    def _commit(self, state):
        self._check_state(state)
        fd=open_private_directory(self.directory,uid=self.uid)
        pending={"version":VERSION,"profile":PROFILE,"config_digest":self.config_digest,"transaction_id":secrets.token_hex(32)}
        data=json_bytes(pending,maximum_bytes=4096)
        try:
            pfd=os.open(self.pending_path.name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=fd)
            try: _write_all(pfd,data); os.fsync(pfd)
            finally: os.close(pfd)
            os.fsync(fd)
        except Exception as error:
            self._faulted=True
            os.close(fd)
            raise RoutePoolError("cannot establish durable transaction fence; operator recovery required") from error
        os.close(fd)
        try:
            self._write(state)
        except Exception as error:
            self._faulted=True
            raise RoutePoolError("state commit is uncertain; durable pending fence retained") from error
        # The state write and directory fsync completed. Fence cleanup is a
        # separate outcome: its failure does not undo or uncharge this commit.
        try:
            fd=open_private_directory(self.directory,uid=self.uid)
            try:
                os.unlink(self.pending_path.name,dir_fd=fd)
                os.fsync(fd)
            finally: os.close(fd)
            return True
        except Exception:
            return False
    def _check_state(self, s):
        if type(s) is not dict or set(s) != {"version", "profile", "config_digest", "routes"} or type(s["version"]) is not int or s["version"] != VERSION or s["profile"] != PROFILE or s["config_digest"] != self.config_digest or type(s["routes"]) is not dict:
            raise RoutePoolError("unknown schema or configuration binding; ledger is fail-closed")
        if len(s["routes"]) > MAX_ROUTE_RECORDS: raise RoutePoolError("route history bound exceeded")
        live_routes=live_members=member_records=0; tokens=set(); route_ids=set(); request_ids=set(); session_ids=set()
        for rkey, route_record in s["routes"].items():
            if type(rkey) is not str or not _HEX64.fullmatch(rkey) or type(route_record) is not dict or set(route_record)!={"route","closed","members"} or type(route_record["closed"]) is not bool or type(route_record["members"]) is not dict:
                raise RoutePoolError("malformed nested route record")
            route=route_record["route"]; _validate_route(route)
            if hashlib.sha256(json_bytes(route)).hexdigest()!=rkey: raise RoutePoolError("route key does not bind its canonical route")
            if route["route_id"] in route_ids or route["request_id"] in request_ids or route["session_id"] in session_ids: raise RoutePoolError("route, request, and session identities must be unique in retained history")
            route_ids.add(route["route_id"]); request_ids.add(route["request_id"]); session_ids.add(route["session_id"])
            members=route_record["members"]
            if not members: raise RoutePoolError("empty retained route record")
            if len(members)>MAX_MEMBERS_PER_ROUTE: raise RoutePoolError("per-route member history bound exceeded")
            components=set(); has_released=False
            assignments=set()
            for mkey, entry in members.items():
                if type(mkey) is not str or not _HEX64.fullmatch(mkey) or type(entry) is not dict or set(entry)!={"member","token","released"} or type(entry["released"]) is not bool or type(entry["token"]) is not str or not __import__("re").fullmatch(r"[0-9a-f]{64}",entry["token"]):
                    raise RoutePoolError("malformed nested member receipt")
                if entry["token"] in tokens: raise RoutePoolError("duplicate reservation token in retained history")
                tokens.add(entry["token"])
                member=entry["member"]; _validate_member(member)
                if hashlib.sha256(json_bytes(member)).hexdigest()!=mkey or mkey not in self.allowed: raise RoutePoolError("member key is not allowed or canonical")
                if member["component"]=="coordinator" and (member["account_id"],member["device_id"],member["worker_boot_id"],member["credential_serial"],member["credential_key_hash"],member["credential_epoch"]) != (route["coordinator_account_id"],route["coordinator_device_id"],route["coordinator_boot_id"],route["coordinator_serial"],route["coordinator_key_hash"],route["coordinator_credential_epoch"]): raise RoutePoolError("co-located coordinator member differs from route identity")
                if member["component"] in components: raise RoutePoolError("duplicate component in route")
                components.add(member["component"])
                if member["assignment_id"] is not None:
                    if member["assignment_id"] in assignments: raise RoutePoolError("duplicate assignment in route")
                    assignments.add(member["assignment_id"])
                if entry["released"]: has_released=True
                else: live_members+=1
                member_records+=1
            if has_released and not route_record["closed"]: raise RoutePoolError("released route must be closed to admission")
            if route_record["closed"] != has_released: raise RoutePoolError("route admission state is inconsistent with release history")
            if (not route_record["closed"] or any(not entry["released"] for entry in members.values())): live_routes+=1
        if live_routes>MAX_ROUTES or live_members>MAX_MEMBERS or member_records>MAX_MEMBER_RECORDS:
            raise RoutePoolError("ledger live or retained-record bound exceeded")

    def reserve(self, route, member):
        self._healthy()
        _validate_route(route); _validate_member(member)
        routekey=hashlib.sha256(json_bytes(route)).hexdigest(); memberkey=hashlib.sha256(json_bytes(member)).hexdigest()
        if member["component"]=="coordinator" and (member["account_id"],member["device_id"],member["worker_boot_id"],member["credential_serial"],member["credential_key_hash"],member["credential_epoch"]) != (route["coordinator_account_id"],route["coordinator_device_id"],route["coordinator_boot_id"],route["coordinator_serial"],route["coordinator_key_hash"],route["coordinator_credential_epoch"]): raise RoutePoolError("co-located coordinator member differs from route identity")
        if memberkey not in self.allowed: raise RoutePoolError("member is outside protected configuration allowlist")
        with self._locked():
            s=self._read(); self._check_state(s)
            rec=s["routes"].get(routekey)
            if rec is not None:
                if rec["route"] != route: raise RoutePoolError("route identity collision")
                if memberkey in rec["members"]:
                    existing=rec["members"][memberkey]
                    if existing["released"]: raise RoutePoolError("released member cannot rejoin route")
                    cleanup=self._confirm_fence_cleanup_unlocked()
                    return ReservationResult({"version":VERSION,"profile":PROFILE,"route_key":routekey,"member_key":memberkey,"token":existing["token"]},cleanup)
                if rec["closed"]: raise RoutePoolError("route is closing; late joins are refused")
            else:
                for old in s["routes"].values():
                    prior=old["route"]
                    if any(prior[k]==route[k] for k in ("route_id","request_id","session_id")):
                        raise RoutePoolError("route, request, or session ID has appeared in retained history")
                active=sum((not x["closed"]) or any(not y["released"] for y in x["members"].values()) for x in s["routes"].values())
                if active >= MAX_ROUTES: raise RoutePoolError("live route limit reached")
                if len(s["routes"]) >= MAX_ROUTE_RECORDS: raise RoutePoolError("route history bound reached; operator intervention required")
                rec={"route":route,"closed":False,"members":{}}; s["routes"][routekey]=rec
            live=len(rec["members"])
            total=sum(sum(not y["released"] for y in x["members"].values()) for x in s["routes"].values())
            if any(x["member"]["component"]==member["component"] for x in rec["members"].values()): raise RoutePoolError("route already has this component")
            if member["assignment_id"] is not None and any(x["member"]["assignment_id"]==member["assignment_id"] for x in rec["members"].values()): raise RoutePoolError("route already has this assignment")
            if live >= MAX_MEMBERS_PER_ROUTE or total >= MAX_MEMBERS: raise RoutePoolError("member limit reached")
            if sum(len(x["members"]) for x in s["routes"].values()) >= MAX_MEMBER_RECORDS: raise RoutePoolError("member receipt history bound reached")
            token=secrets.token_hex(32)
            receipt={"version":VERSION,"profile":PROFILE,"route_key":routekey,"member_key":memberkey,"token":token}
            rec["members"][memberkey]={"member":member,"token":token,"released":False}
            try: cleanup=self._commit(s)
            except RoutePoolError: raise
            return ReservationResult(dict(receipt),cleanup)

    def release(self, receipt, *, actual_reclamation_confirmed):
        self._healthy()
        if actual_reclamation_confirmed is not True: raise RoutePoolError("release requires trusted confirmation of actual session reclamation")
        if type(receipt) is not dict or set(receipt)!={"version","profile","route_key","member_key","token"} or type(receipt["version"]) is not int or receipt["version"] != VERSION or receipt["profile"] != PROFILE or any(type(receipt[k]) is not str or not _HEX64.fullmatch(receipt[k]) for k in ("route_key","member_key","token")): raise RoutePoolError("invalid release receipt")
        with self._locked():
            s=self._read(); self._check_state(s)
            rec=s["routes"].get(receipt["route_key"])
            ent=None if rec is None else rec["members"].get(receipt["member_key"])
            expected=None if ent is None else {"version":VERSION,"profile":PROFILE,"route_key":receipt["route_key"],"member_key":receipt["member_key"],"token":ent["token"]}
            if ent is None or expected != receipt: raise RoutePoolError("receipt is stale or does not identify this exact reservation")
            if ent["released"]: return ReleaseResult(False,self._confirm_fence_cleanup_unlocked())
            ent["released"]=True
            rec["closed"]=True
            cleanup=self._commit(s)
            return ReleaseResult(True,cleanup)

    def snapshot(self):
        self._healthy()
        with self._locked():
            s=self._read(); self._check_state(s); return s
