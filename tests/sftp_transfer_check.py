"""Explicit, opt-in Paramiko SFTP transfer check; never starts a container.

Run only from the pinned operator runtime with a newly allocated remote job
root. This script uploads one fixed public sentinel, verifies the remote file,
then invokes the supervisor's scoped job-root remover. It is not unittest
discovery material and is not an end-to-end worker acceptance test.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import posixpath
import sys
import time
from pathlib import Path
from types import SimpleNamespace


SENTINEL = b"STEAMBOAT-SFTP-PROBE-V1\n"
DEADLINE_SECONDS = 60.0
OUTPUT_LIMIT = 32 * 1024


def _load_supervisor():
    repository = Path(__file__).resolve().parents[1]
    sys.path.insert(0, str(repository))
    from lab import secure_cohort_supervisor as supervisor
    return supervisor


def _validate_args(supervisor, args):
    if (type(args.ssh_host) is not str
            or supervisor._HOST.fullmatch(args.ssh_host) is None
            or type(args.ssh_user) is not str
            or supervisor._USER.fullmatch(args.ssh_user) is None):
        raise supervisor.SupervisorError("arguments", "ssh_identity")
    if bool(args.ssh_password_file) == bool(args.ssh_key_file):
        raise supervisor.SupervisorError("arguments", "one_ssh_credential_required")
    args.known_hosts = supervisor._strict_local_path(
        args.known_hosts, must_exist=True)
    args.ssh_password_file = (
        supervisor._strict_local_path(args.ssh_password_file, must_exist=True)
        if args.ssh_password_file else None)
    args.ssh_key_file = (
        supervisor._strict_local_path(args.ssh_key_file, must_exist=True)
        if args.ssh_key_file else None)
    args.remote_job_root = supervisor._remote_path(
        args.remote_job_root, label="remote_job_root")
    if len(args.remote_job_root.split("/")) > 17:
        raise supervisor.SupervisorError("arguments", "remote_job_root_depth")


def _check_paramiko_pin(supervisor):
    try:
        version = importlib.metadata.version("paramiko")
    except importlib.metadata.PackageNotFoundError:
        raise supervisor.SupervisorError("paramiko", "version_unavailable") from None
    if version != "3.5.1":
        raise supervisor.SupervisorError("paramiko", "version_mismatch")
    try:
        import paramiko
    except ImportError:
        raise supervisor.SupervisorError("paramiko", "import_unavailable") from None
    if getattr(paramiko, "__version__", None) != "3.5.1":
        raise supervisor.SupervisorError("paramiko", "version_mismatch")


def _close_sftp(supervisor, sftp, deadline):
    supervisor._sftp_call(sftp, deadline, "sftp_check", sftp.close)


def _verify_remote_sentinel(supervisor, sftp, path, uid, gid, deadline):
    def verify_attrs(attrs, *, expected_size):
        if (not supervisor.stat.S_ISREG(attrs.st_mode)
                or attrs.st_uid != uid or attrs.st_gid != gid
                or supervisor.stat.S_IMODE(attrs.st_mode) != 0o600
                or attrs.st_size != expected_size):
            raise supervisor.SupervisorError("sftp_check", "remote_metadata")

    before = supervisor._sftp_call(
        sftp, deadline, "sftp_check", lambda: sftp.lstat(path))
    verify_attrs(before, expected_size=len(SENTINEL))
    stream = supervisor._sftp_call(
        sftp, deadline, "sftp_check", lambda: sftp.open(path, "r"))
    try:
        opened = supervisor._sftp_call(
            sftp, deadline, "sftp_check", stream.stat)
        verify_attrs(opened, expected_size=len(SENTINEL))
        data = supervisor._sftp_call(
            sftp, deadline, "sftp_check",
            lambda: stream.read(len(SENTINEL) + 1))
    finally:
        supervisor._sftp_call(
            sftp, deadline, "sftp_check", stream.close)
    after = supervisor._sftp_call(
        sftp, deadline, "sftp_check", lambda: sftp.lstat(path))
    verify_attrs(after, expected_size=len(SENTINEL))
    if type(data) is not bytes or data != SENTINEL:
        raise supervisor.SupervisorError("sftp_check", "sentinel_mismatch")
    return hashlib.sha256(data).hexdigest()


def _parser():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ssh-host", required=True)
    parser.add_argument("--ssh-user", required=True)
    parser.add_argument("--known-hosts", required=True)
    credentials = parser.add_mutually_exclusive_group(required=True)
    credentials.add_argument("--ssh-password-file")
    credentials.add_argument("--ssh-key-file")
    parser.add_argument("--remote-job-root", required=True,
                        help="new, task-owned absolute path; it must not exist")
    return parser


def main(argv=None):
    args = _parser().parse_args(argv)
    supervisor = _load_supervisor()
    started = time.monotonic()
    deadline = started + DEADLINE_SECONDS
    client = None
    sftp = None
    uid = gid = None
    root_creation_attempted = False
    root_created = False
    container_start_attempted = False  # This checker contains no container path.
    uploaded_verified = False
    payload_sha256 = hashlib.sha256(SENTINEL).hexdigest()
    failure = None
    removal = None
    host_key_sha256 = None
    paramiko_verified = False
    validated_job_root = None

    try:
        _validate_args(supervisor, args)
        _check_paramiko_pin(supervisor)
        paramiko_verified = True
        validated_job_root = args.remote_job_root
        ssh_args = SimpleNamespace(
            known_hosts=args.known_hosts,
            ssh_password_file=args.ssh_password_file,
            ssh_key_file=args.ssh_key_file,
            ssh_host=args.ssh_host,
            ssh_user=args.ssh_user,
        )
        client, host_key_sha256, sudo_password = supervisor._connect_ssh(
            ssh_args, deadline)

        sftp = supervisor._open_sftp(client, deadline)
        uid, gid = supervisor._remote_user_ids(sftp, deadline)
        _close_sftp(supervisor, sftp, deadline)
        sftp = None

        root_creation_attempted = True
        created = supervisor._remote_script(
            client, supervisor._REMOTE_CREATE_JOB_SCRIPT,
            [args.remote_job_root, str(uid), str(gid)],
            password=sudo_password, deadline=deadline, output_limit=256)
        if created.strip() != b"created":
            raise supervisor.SupervisorError("remote_job_root", "creation_unconfirmed")
        root_created = True

        supervisor._sftp_upload_bundle(
            client, SENTINEL, args.remote_job_root, uid, deadline)
        path = posixpath.join(args.remote_job_root, "worker.tar")
        sftp = supervisor._open_sftp(client, deadline)
        payload_sha256 = _verify_remote_sentinel(
            supervisor, sftp, path, uid, gid, deadline)
        _close_sftp(supervisor, sftp, deadline)
        sftp = None
        uploaded_verified = True
    except supervisor.SupervisorError as error:
        failure = {"stage": error.stage, "code": error.code}
    except Exception:
        # Keep output sanitized; exception text may include paths or peer data.
        failure = {"stage": "sftp_check", "code": "unexpected_failure"}
    finally:
        if sftp is not None:
            try:
                _close_sftp(supervisor, sftp, deadline)
            except supervisor.SupervisorError as error:
                if failure is None:
                    failure = {"stage": error.stage, "code": error.code}
                supervisor._abort_sftp(sftp)
        if (root_created and not container_start_attempted
                and client is not None and uid is not None and gid is not None):
            try:
                removal = supervisor._remove_remote_job(
                    client, job_root=args.remote_job_root, uid=uid, gid=gid,
                    password=(sudo_password if "sudo_password" in locals() else None),
                    deadline=deadline)
            except supervisor.SupervisorError as error:
                removal = {"confirmed": False, "reason": error.code,
                           "residuals_known": False, "residuals": []}
                if failure is None:
                    failure = {"stage": error.stage, "code": error.code}
            except Exception:
                removal = {"confirmed": False, "reason": "removal_error",
                           "residuals_known": False, "residuals": []}
                if failure is None:
                    failure = {"stage": "remote_job_removal",
                               "code": "unexpected_failure"}
        if client is not None:
            supervisor._close_ssh_client(client)

    if root_creation_attempted and not root_created and failure is None:
        failure = {"stage": "remote_job_root", "code": "creation_unconfirmed"}
    success = (failure is None and uploaded_verified
               and type(removal) is dict and removal.get("confirmed") is True)
    result = {
        "schema_version": 1,
        "event": "sftp_transfer_check",
        "success": success,
        "paramiko_version": "3.5.1" if paramiko_verified else None,
        "remote_job_root": validated_job_root,
        "uid": uid,
        "gid": gid,
        "payload_bytes": len(SENTINEL),
        "payload_sha256": payload_sha256,
        "uploaded_verified": uploaded_verified,
        "container_start_attempted": container_start_attempted,
        "root_creation_attempted": root_creation_attempted,
        "root_created_confirmed": root_created,
        "host_key_sha256": host_key_sha256,
        "removal": None,
        "failure": failure,
        "elapsed_ms": max(0, int((time.monotonic() - started) * 1000)),
    }
    if type(removal) is dict:
        removal_report = {
            key: removal.get(key) for key in (
                "confirmed", "private_files_removed", "job_root_removed",
                "removed", "residuals", "residuals_known",
                "residuals_truncated", "reason",
            ) if key in removal
        }
        result["removal"] = removal_report
    encoded = json.dumps(result, sort_keys=True, separators=(",", ":"))
    if len(encoded.encode("utf-8")) > OUTPUT_LIMIT:
        # The validated helper already caps name counts and item lengths. Keep
        # the report bounded even if that contract changes in a later version.
        if type(result.get("removal")) is dict:
            report = result["removal"]
            for field in ("removed", "residuals"):
                values = report.get(field)
                if type(values) is list:
                    report[field + "_count"] = len(values)
                    report[field] = values[:4]
                    if field == "residuals":
                        report["residuals_truncated"] = True
                    else:
                        report["removed_truncated"] = len(values) > 4
        if failure is None:
            failure = {"stage": "report", "code": "output_bound"}
            result["failure"] = failure
        result["success"] = False
        success = False
        encoded = json.dumps(result, sort_keys=True, separators=(",", ":"))
    print(encoded)
    return 0 if success else 1


if __name__ == "__main__":
    raise SystemExit(main())
