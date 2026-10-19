"""Fixed, descriptor-relative publication for protected owner-control files.

This module only builds and validates publication records. It performs no I/O
on import and does not execute owner actions. SFTP is a staging mechanism; only
the returned remote receipt can attest that the fixed script completed its
file and directory fsyncs and readback checks.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import re
import shlex


MAX_POLICY_BYTES = 64 * 1024
MAX_CONTROL_BYTES = 16 * 1024
MAX_PATH_BYTES = 4096
_SHA256 = re.compile(r"^[0-9a-f]{64}$")

_KIND_TARGETS = {
    "install_intent": ("install-intent.json", "intent"),
    "removal_intent": ("removal-intent.json", "intent"),
    "policy1": ("snapshot.json", "policy"),
    "policy2": ("snapshot.json", "policy"),
    "command1": ("owner-command.json", "command"),
    "command2": ("owner-command.json", "command"),
}


def _exact_int(value, *, minimum=0, maximum=(1 << 31) - 1):
    return type(value) is int and minimum <= value <= maximum


def _valid_sha(value):
    return type(value) is str and _SHA256.fullmatch(value) is not None


def _canonical_absolute_root(value):
    if (type(value) is not str or not value or "\x00" in value
            or len(value.encode("utf-8")) > MAX_PATH_BYTES):
        raise ValueError("publication root is invalid")
    if not value.startswith("/") or value != "/" + "/".join(
            part for part in value.split("/") if part):
        raise ValueError("publication root must be canonical absolute path")
    if value == "/":
        raise ValueError("publication root must name a private directory")
    if any(part in (".", "..") for part in value.split("/")):
        raise ValueError("publication root must be canonical absolute path")
    return value


@dataclass(frozen=True, slots=True)
class OwnerPublicationPlan:
    kind: str
    root: str
    target_name: str
    uid: int
    gid: int
    sha256: str
    size: int
    expected_prior_sha256: str

    @property
    def argv(self):
        """Exact non-shell arguments expected by REMOTE_PUBLISH_SCRIPT."""
        return (self.root, self.kind, str(self.uid), str(self.gid), self.sha256,
                str(self.size), self.expected_prior_sha256)


def build_publication_plan(kind, *, intent_root, job_root, uid, gid,
                           sha256, size, expected_prior_sha256=""):
    """Build a plan from trusted CLI roots and a fixed publication kind."""
    if type(kind) is not str or kind not in _KIND_TARGETS:
        raise ValueError("publication kind is not fixed")
    if not _exact_int(uid) or not _exact_int(gid):
        raise ValueError("publication owner IDs are invalid")
    if not _valid_sha(sha256):
        raise ValueError("publication digest is invalid")
    target_name, category = _KIND_TARGETS[kind]
    limit = MAX_CONTROL_BYTES if category in ("intent", "command") else MAX_POLICY_BYTES
    if not _exact_int(size, minimum=1, maximum=limit):
        raise ValueError("publication size is invalid")
    if category == "intent" or kind == "command1":
        if expected_prior_sha256 != "":
            raise ValueError("exclusive publication cannot have a prior digest")
    elif not _valid_sha(expected_prior_sha256):
        raise ValueError("replacement publication requires a prior digest")
    intent_root = _canonical_absolute_root(intent_root)
    job_root = _canonical_absolute_root(job_root)
    if category == "intent" and (
            intent_root == job_root
            or intent_root.startswith(job_root.rstrip("/") + "/")
            or job_root.startswith(intent_root.rstrip("/") + "/")):
        raise ValueError("intent publication root must be external to the job root")
    root_arg = intent_root if category == "intent" else job_root
    root = _canonical_absolute_root(root_arg)
    return OwnerPublicationPlan(kind, root, target_name, uid, gid, sha256,
                                size, expected_prior_sha256)


def canonical_receipt_bytes(receipt):
    """Return canonical bytes for a receipt after closed-schema validation."""
    validate_publication_receipt(receipt)
    return json.dumps(receipt, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


def validate_publication_receipt(value, *, plan=None):
    """Validate the closed receipt, rejecting Python bool/int aliases."""
    fields = {
        "schema_version", "event", "kind", "sha256", "size", "uid", "gid",
        "mode", "file_fsync_confirmed", "directory_fsync_confirmed",
        "readback_confirmed",
    }
    if type(value) is not dict or set(value) != fields:
        raise ValueError("publication receipt schema is invalid")
    if (type(value["schema_version"]) is not int or value["schema_version"] != 1
            or value["event"] != "owner_file_publication"
            or type(value["event"]) is not str
            or type(value["kind"]) is not str
            or value["kind"] not in _KIND_TARGETS
            or not _valid_sha(value["sha256"])):
        raise ValueError("publication receipt identity is invalid")
    category = _KIND_TARGETS[value["kind"]][1]
    limit = MAX_CONTROL_BYTES if category in ("intent", "command") else MAX_POLICY_BYTES
    if (not _exact_int(value["size"], minimum=1, maximum=limit)
            or not _exact_int(value["uid"]) or not _exact_int(value["gid"])
            or type(value["mode"]) is not int or value["mode"] != 0o600):
        raise ValueError("publication receipt metadata is invalid")
    if any(type(value[name]) is not bool or value[name] is not True for name in (
            "file_fsync_confirmed", "directory_fsync_confirmed", "readback_confirmed")):
        raise ValueError("publication receipt durability is unconfirmed")
    if plan is not None:
        if type(plan) is not OwnerPublicationPlan:
            raise ValueError("publication plan is invalid")
        expected = (plan.kind, plan.sha256, plan.size, plan.uid, plan.gid)
        actual = (value["kind"], value["sha256"], value["size"],
                  value["uid"], value["gid"])
        if actual != expected:
            raise ValueError("publication receipt does not match plan")
    return value


# Passed as a constant to the fixed remote Python interpreter. All destination
# names are mapped here; argv contains no peer-controlled path or command.
REMOTE_PUBLISH_SCRIPT = r'''import hashlib, json, os, re, stat, sys

KINDS = {
    "install_intent": ("install-intent.json", "intent", 16384, "exclusive"),
    "removal_intent": ("removal-intent.json", "intent", 16384, "exclusive"),
    "policy1": ("snapshot.json", "policy", 65536, "replace"),
    "policy2": ("snapshot.json", "policy", 65536, "replace"),
    "command1": ("owner-command.json", "command", 16384, "exclusive"),
    "command2": ("owner-command.json", "command", 16384, "replace"),
}
SHA = re.compile(r"^[0-9a-f]{64}$")

def fail():
    raise RuntimeError("publication failed")

def write_all(fd, data):
    view = memoryview(data)
    while view:
        count = os.write(fd, view)
        if count <= 0:
            fail()
        view = view[count:]

def read_fd(fd, limit):
    chunks = []
    total = 0
    while True:
        part = os.read(fd, min(65536, limit + 1 - total))
        if not part:
            return b"".join(chunks)
        total += len(part)
        if total > limit:
            fail()
        chunks.append(part)

def same_file_state(before, after):
    return ((before.st_dev, before.st_ino, before.st_mode, before.st_uid,
             before.st_gid, before.st_nlink, before.st_size, before.st_mtime_ns,
             before.st_ctime_ns) ==
            (after.st_dev, after.st_ino, after.st_mode, after.st_uid,
             after.st_gid, after.st_nlink, after.st_size, after.st_mtime_ns,
             after.st_ctime_ns))

def check_regular(st, uid, gid, size_limit):
    if (not stat.S_ISREG(st.st_mode) or st.st_uid != uid or st.st_gid != gid
            or stat.S_IMODE(st.st_mode) != 0o600 or st.st_nlink != 1
            or st.st_size < 1 or st.st_size > size_limit):
        fail()

def open_absolute_directory(path):
    if (not path.startswith("/") or path != os.path.normpath(path)
            or len(os.fsencode(path)) > 4096 or "\x00" in path):
        fail()
    parts = path.split("/")[1:]
    if not parts or any(part in ("", ".", "..") for part in parts):
        fail()
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in parts:
            next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                              dir_fd=fd)
            os.close(fd)
            fd = next_fd
        return fd
    except BaseException:
        os.close(fd)
        raise

def ensure_root_stable(path, dir_fd, uid, gid):
    check_fd = open_absolute_directory(path)
    try:
        original = os.fstat(dir_fd)
        current = os.fstat(check_fd)
        if ((original.st_dev, original.st_ino, original.st_uid, original.st_gid) !=
                (current.st_dev, current.st_ino, current.st_uid, current.st_gid)
                or current.st_uid != uid or current.st_gid != gid
                or stat.S_IMODE(current.st_mode) != 0o700):
            fail()
    finally:
        os.close(check_fd)

def checked_target(dir_fd, name, uid, gid, limit):
    fd = os.open(name, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC,
                 dir_fd=dir_fd)
    try:
        before = os.fstat(fd)
        check_regular(before, uid, gid, limit)
        data = read_fd(fd, limit)
        after = os.fstat(fd)
        if not same_file_state(before, after) or len(data) != after.st_size:
            fail()
        return fd, before, data
    except BaseException:
        os.close(fd)
        raise

def main():
    if len(sys.argv) != 8:
        fail()
    root, kind, uid_text, gid_text, digest, size_text, prior = sys.argv[1:]
    if kind not in KINDS or not SHA.fullmatch(digest):
        fail()
    numbers = (uid_text, gid_text, size_text)
    if any(not value.isascii() or not value.isdecimal() or len(value) > 10
           for value in numbers):
        fail()
    uid, gid, size = int(uid_text), int(gid_text), int(size_text)
    target_name, category, limit, mode = KINDS[kind]
    if (not 0 <= uid <= 2147483647 or not 0 <= gid <= 2147483647
            or uid != os.geteuid() or gid != os.getegid()
            or not 1 <= size <= limit):
        fail()
    if mode == "exclusive":
        if prior != "":
            fail()
    elif not SHA.fullmatch(prior):
        fail()
    dir_fd = open_absolute_directory(root)
    stage_fd = None
    prior_fd = None
    published_fd = None
    try:
        dst = os.fstat(dir_fd)
        if (not stat.S_ISDIR(dst.st_mode) or dst.st_uid != uid or dst.st_gid != gid
                or stat.S_IMODE(dst.st_mode) != 0o700):
            fail()
        stage_fd = os.open("owner-upload.bin",
                           os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC,
                           dir_fd=dir_fd)
        before = os.fstat(stage_fd)
        check_regular(before, uid, gid, limit)
        if before.st_size != size:
            fail()
        data = read_fd(stage_fd, limit)
        after = os.fstat(stage_fd)
        if (not same_file_state(before, after) or len(data) != size
                or hashlib.sha256(data).hexdigest() != digest):
            fail()
        os.fsync(stage_fd)
        os.lseek(stage_fd, 0, os.SEEK_SET)
        stable_data = read_fd(stage_fd, limit)
        synced = os.fstat(stage_fd)
        if (not same_file_state(after, synced) or stable_data != data
                or hashlib.sha256(stable_data).hexdigest() != digest):
            fail()

        try:
            prior_fd, prior_stat, prior_data = checked_target(
                dir_fd, target_name, uid, gid, limit)
            target_exists = True
        except FileNotFoundError:
            target_exists = False
        if mode == "exclusive":
            if target_exists:
                fail()
        else:
            if (not target_exists or hashlib.sha256(prior_data).hexdigest() != prior):
                fail()
            check_regular(prior_stat, uid, gid, limit)

        stage_stat = os.fstat(stage_fd)
        ensure_root_stable(root, dir_fd, uid, gid)
        named_stage = os.stat("owner-upload.bin", dir_fd=dir_fd,
                              follow_symlinks=False)
        if ((named_stage.st_dev, named_stage.st_ino, named_stage.st_mode,
             named_stage.st_uid, named_stage.st_gid, named_stage.st_nlink,
             named_stage.st_size) !=
                (stage_stat.st_dev, stage_stat.st_ino, stage_stat.st_mode,
                 stage_stat.st_uid, stage_stat.st_gid, stage_stat.st_nlink,
                 stage_stat.st_size)):
            fail()
        if mode == "exclusive":
            ensure_root_stable(root, dir_fd, uid, gid)
            os.link("owner-upload.bin", target_name, src_dir_fd=dir_fd,
                    dst_dir_fd=dir_fd, follow_symlinks=False)
            os.unlink("owner-upload.bin", dir_fd=dir_fd)
        else:
            current_fd, current_stat, current_data = checked_target(
                dir_fd, target_name, uid, gid, limit)
            try:
                if ((current_stat.st_dev, current_stat.st_ino) !=
                        (prior_stat.st_dev, prior_stat.st_ino)
                        or hashlib.sha256(current_data).hexdigest() != prior):
                    fail()
            finally:
                os.close(current_fd)
            ensure_root_stable(root, dir_fd, uid, gid)
            os.replace("owner-upload.bin", target_name, src_dir_fd=dir_fd,
                       dst_dir_fd=dir_fd)
        os.fsync(dir_fd)
        published_fd, published_stat, published_data = checked_target(
            dir_fd, target_name, uid, gid, limit)
        if ((published_stat.st_dev, published_stat.st_ino) !=
                (stage_stat.st_dev, stage_stat.st_ino)
                or len(published_data) != size
                or hashlib.sha256(published_data).hexdigest() != digest):
            fail()
        os.fsync(published_fd)
        os.fsync(dir_fd)
        receipt = {
            "schema_version": 1, "event": "owner_file_publication", "kind": kind,
            "sha256": digest, "size": size, "uid": uid, "gid": gid, "mode": 0o600,
            "file_fsync_confirmed": True, "directory_fsync_confirmed": True,
            "readback_confirmed": True,
        }
        sys.stdout.write(json.dumps(receipt, sort_keys=True, separators=(",", ":"),
                                    ensure_ascii=True, allow_nan=False) + "\n")
        sys.stdout.flush()
    finally:
        for fd in (published_fd, prior_fd, stage_fd, dir_fd):
            if fd is not None:
                try:
                    os.close(fd)
                except OSError:
                    pass

try:
    main()
except BaseException:
    sys.stderr.write("publication failed\n")
    sys.exit(1)
'''


def remote_publish_command(plan):
    """Return a fixed, safely quoted Python command for a validated plan."""
    if type(plan) is not OwnerPublicationPlan:
        raise ValueError("publication plan is invalid")
    validate_plan(plan)
    args = (plan.root, plan.kind, str(plan.uid), str(plan.gid), plan.sha256,
            str(plan.size), plan.expected_prior_sha256)
    return "python3 -c " + shlex.quote(REMOTE_PUBLISH_SCRIPT) + " " + " ".join(
        shlex.quote(arg) for arg in args)


def validate_plan(plan):
    if type(plan) is not OwnerPublicationPlan:
        raise ValueError("publication plan is invalid")
    expected_name, category = _KIND_TARGETS.get(plan.kind, (None, None))
    if (expected_name is None or plan.target_name != expected_name
            or not _exact_int(plan.uid) or not _exact_int(plan.gid)
            or not _valid_sha(plan.sha256)):
        raise ValueError("publication plan is invalid")
    limit = MAX_CONTROL_BYTES if category in ("intent", "command") else MAX_POLICY_BYTES
    if not _exact_int(plan.size, minimum=1, maximum=limit):
        raise ValueError("publication plan size is invalid")
    _canonical_absolute_root(plan.root)
    if category == "intent" or plan.kind == "command1":
        if plan.expected_prior_sha256 != "":
            raise ValueError("publication plan prior digest is invalid")
    elif not _valid_sha(plan.expected_prior_sha256):
        raise ValueError("publication plan prior digest is invalid")
    return plan
