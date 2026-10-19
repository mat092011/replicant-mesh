"""Bounded nonproduction host supervisor for the frozen C1b cohort handoff.

This program is an operator-side launcher, not a worker daemon.  Its only
network peer is the explicitly configured SSH host.  Paramiko is imported only
when an SSH connection is requested; importing this module needs only the
Python standard library.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import ipaddress
import json
import keyword
import math
import os
from pathlib import Path, PurePosixPath
import posixpath
import re
import shlex
import socket
import stat
import subprocess
import sys
import tarfile
import threading
import time
import uuid

from lab.secure_owner_file_publication import (
    MAX_CONTROL_BYTES as OWNER_CONTROL_LIMIT,
    MAX_POLICY_BYTES as OWNER_POLICY_LIMIT,
    REMOTE_PUBLISH_SCRIPT,
    build_publication_plan,
    validate_publication_receipt,
)
from lab.secure_cohort_owner import (
    MAX_ARCHIVE_BYTES as OWNER_ARCHIVE_LIMIT,
    MAX_INTENT_BYTES as OWNER_INTENT_LIMIT,
    OWNER_MATERIAL_NAMES,
    OWNER_PROFILES,
    OwnerExpectation,
    build_owner_action_request,
    build_owner_command,
    validate_owner_action_request,
    validate_owner_action_response,
    validate_owner_command_ack,
    validate_owner_material_archive,
    validate_owner_materials_ready,
    validate_owner_result,
    _canonical_bytes as _owner_canonical_bytes,
    _command_document as _owner_command_document,
    _validate_owner_status,
)
from lab.secure_owner_material_handoff import (
    OWNER_MATERIALS_ARCHIVE_BASENAME,
    read_owner_material_archive,
    write_owner_material_archive,
)


REMOTE_PORT = 50061
REMOTE_ROOT = "/run/steamboat"
MODEL_ID = "Maykeye/TinyLLama-v0"
MODEL_REVISION = "298338802ab94432b917bcce11382aa151aee50f"
HANDOFF_ROOT = "/tmp/handoff"
LOCAL_STARTUP_SECONDS = 60.0
REMOTE_STARTUP_SECONDS = 60.0
COHORT_SECONDS = 300.0
TERMINATION_SECONDS = 15
LOCAL_TERMINATION_RESERVE_SECONDS = 5.0
CONTROL_LIMIT = 65_536
FAILURE_LOCATION_LIMIT = 4096
BUNDLE_LIMIT = 2 * 1024 * 1024
STATUS_LIMIT = 4096
REMOTE_STATUS_UID = 1000
CONFIG_LIMIT = 16 * 1024
CERT_LIMIT = 65_536
KEY_LIMIT = 1024 * 1024
SNAPSHOT_LIMIT = 64 * 1024
STDERR_LIMIT = 16 * 1024
_HEX32 = re.compile(r"[0-9a-f]{32}", re.ASCII)
_HEX64 = re.compile(r"[0-9a-f]{64}", re.ASCII)
_TYPED_ID = {
    "account_id": re.compile(r"acct_[0-9a-f]{32}", re.ASCII),
    "device_id": re.compile(r"dev_[0-9a-f]{32}", re.ASCII),
    "assignment_id": re.compile(r"asg_[0-9a-f]{32}", re.ASCII),
    "boot_id": re.compile(r"[0-9a-f]{32}", re.ASCII),
}
_TYPED_REQUEST = re.compile(r"req_[0-9a-f]{32}", re.ASCII)
_TYPED_SESSION = re.compile(r"ses_[0-9a-f]{32}", re.ASCII)
_IMAGE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/@:+-]{0,254}\Z", re.ASCII)
_VOLUME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}\Z", re.ASCII)
_USER = re.compile(r"[a-z_][a-z0-9_-]{0,31}\Z", re.ASCII)
_HOST = re.compile(r"[A-Za-z0-9][A-Za-z0-9.-]{0,252}\Z", re.ASCII)
_CONTAINER_ID = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
_OWNER_LABEL = "org.steamboat.c1b.owner"
_ROLE_LABEL = "org.steamboat.c1b.role"
_WORKER_FILES = {
    "worker.json": CONFIG_LIMIT,
    "host.crt": CERT_LIMIT,
    "host.key": KEY_LIMIT,
    "cohort-ca.crt": CERT_LIMIT,
    "snapshot.pub": CERT_LIMIT,
    "snapshot.json": SNAPSHOT_LIMIT,
}
_CONTROL_REQUESTS = {
    "bundle-ready.json",
    *(f"observation-request-{i}.json" for i in range(1, 11)),
    "owner-materials-ready.json", "owner-action-request-1.json",
    "owner-action-request-2.json",
    "stop-request.json",
    "restart-stop-request.json", "restart-bundle-ready.json",
}
_CONTROL_RESPONSES = {
    "ready.json",
    *(f"observation-response-{i}.json" for i in range(1, 11)),
    "owner-action-response-1.json", "owner-action-response-2.json",
    "stop-response.json",
    "restart-stop-response.json", "restart-ready-ack.json",
}
_RESULT_FIELDS = {
    "schema_version", "event", "run_id", "baseline", "request_ids",
    "session_ids", "numerical_errors", "cases", "local_shutdown",
    "remote_shutdown", "failure_type", "pending_scope", "identities",
    "interleave", "cancellation", "partial_admission", "step_reply_loss", "capacity",
    "restart", "owner_actions",
}
_CONFIG_FIELDS = {
    "schema_version", "protected_root", "account_id", "device_id", "boot_id",
    "assignment_id", "worker_name", "model_id", "model_revision",
    "manifest_fingerprint", "listen_ip", "listen_port",
    "clock_uncertainty_seconds", "certificate_path", "private_key_path",
    "cohort_ca_path", "snapshot_verification_key_path", "signed_snapshot_path",
    "artifact_directory", "acceptor_directory", "status_report_path",
}
_BUNDLE_READY_FIELDS = {
    "schema_version", "event", "run_id", "nonce", "bundle_path",
    "expected_boot_id", "manifest_fingerprint", "snapshot_sha256", "endpoint",
    "worker_name",
}
_OBSERVATION_FIELDS = {
    "schema_version", "event", "run_id", "nonce", "expected_boot_id",
    "sequence", "case_id", "request_id", "session_id",
}
_OBSERVATION_CASES = {
    1: "greedy-one-token",
    2: "forced-length-1",
    3: "forced-length-128",
    4: "forced-length-1024",
}
PROFILE_BASELINE = "baseline-v1"
PROFILE_C1B_HAPPY = "c1b-happy-v1"
PROFILE_C1B_INTERLEAVE = "c1b-interleave-v1"
PROFILE_C1B_CANCEL = "c1b-cancel-v1"
PROFILE_C1B_PARTIAL = "c1b-partial-open-v1"
PROFILE_C1B_STEP_LOSS = "c1b-step-reply-loss-v1"
PROFILE_C1B_CAPACITY = "c1b-capacity-v1"
PROFILE_C1B_RESTART = "c1b-restart-v1"
PROFILE_C1B_OWNER_DRAIN = "c1b-owner-drain-v1"
PROFILE_C1B_OWNER_REMOVE = "c1b-owner-remove-v1"
_RESTART_CASES = (
    (1, "greedy-one-token"), (2, "forced-length-1"),
    (3, "forced-length-128"), (4, "forced-length-1024"),
    (5, "restart-old-session-held"),
    (6, "restart-new-boot-stale-binding-rejected"),
    (7, "restart-new-greedy-one-token"),
    (8, "restart-new-forced-length-1"),
    (9, "restart-new-forced-length-128"),
    (10, "restart-new-forced-length-1024"),
)
_BASELINE_OBSERVATIONS = tuple(_OBSERVATION_CASES.items())
_PROFILE_OBSERVATIONS = {
    PROFILE_BASELINE: _BASELINE_OBSERVATIONS,
    PROFILE_C1B_HAPPY: _BASELINE_OBSERVATIONS + (
        (5, "unequal-concurrent-prompt-5"),
        (6, "unequal-concurrent-prompt-11"),
        (7, "context-boundary-1151-plus-1"),
    ),
    PROFILE_C1B_INTERLEAVE: _BASELINE_OBSERVATIONS + (
        (5, "ordered-step-interleave"),
    ),
    PROFILE_C1B_CANCEL: _BASELINE_OBSERVATIONS + (
        (5, "cancel-held-worker3-session"),
        (6, "cancel-worker3-reclaimed"),
    ),
    PROFILE_C1B_PARTIAL: _BASELINE_OBSERVATIONS + (
        (5, "partial-open-reply-held"),
        (6, "partial-open-lease-expired"),
    ),
    PROFILE_C1B_STEP_LOSS: _BASELINE_OBSERVATIONS + (
        (5, "step-reply-loss-held"),
        (6, "step-reply-loss-reclaimed"),
    ),
    PROFILE_C1B_CAPACITY: _BASELINE_OBSERVATIONS + (
        (5, "capacity-eight-held"),
        (6, "capacity-eight-reclaimed"),
    ),
    PROFILE_C1B_RESTART: _RESTART_CASES,
    PROFILE_C1B_OWNER_DRAIN: _BASELINE_OBSERVATIONS + (
        (5, "owner-drain-held"), (6, "owner-drain-controls"),
        (7, "owner-drain-paused"),
    ),
    PROFILE_C1B_OWNER_REMOVE: _BASELINE_OBSERVATIONS + (
        (5, "owner-remove-held"), (6, "owner-remove-revoked"),
        (7, "owner-remove-final"),
    ),
}
_PROFILE_LOCAL_CASES = {
    PROFILE_BASELINE: (),
    PROFILE_C1B_HAPPY: ("context-over-boundary-1152-plus-1-local-preflight",),
    PROFILE_C1B_INTERLEAVE: (),
    PROFILE_C1B_CANCEL: (),
    PROFILE_C1B_CAPACITY: (),
}
_MAX_OBSERVATION_SEQUENCE = max(
    sequence for observations in _PROFILE_OBSERVATIONS.values()
    for sequence, _case_id in observations)
_STOP_REQUEST_FIELDS = {
    "schema_version", "event", "run_id", "nonce", "expected_boot_id",
    "may_have_started", "maximum_wait_seconds",
}
_READY_ACK_FIELDS = {
    "schema_version", "event", "run_id", "nonce", "boot_id",
    "manifest_fingerprint", "snapshot_sha256", "endpoint",
    "ssh_host_key_sha256", "remote_status_uid", "remote_status_mode",
    "remote_status_mtime_ns", "measurement_label", "remote_status",
}
_OBSERVATION_ACK_FIELDS = {
    "schema_version", "event", "run_id", "nonce", "sequence", "case_id",
    "request_id", "session_id", "boot_id", "manifest_fingerprint", "endpoint",
    "ssh_host_key_sha256", "remote_status_uid", "remote_status_mode",
    "supervisor_monotonic_ns", "remote_mark_ns", "heartbeat_mtime_ns",
    "measurement_label", "remote_status",
}
_STOP_ACK_FIELDS = {
    "schema_version", "event", "run_id", "nonce", "boot_id", "process_state",
    "exit_code", "shutdown_confirmed", "ssh_host_key_sha256",
    "remote_status_uid", "remote_status_mode", "measurement_label", "remote_status",
}
_FAILURE_LOCATION_FILE = "failure-location.json"
_FAILURE_LOCATION_FIELDS = {
    "schema_version", "event", "run_id", "nonce", "failure_type", "frames",
}
_FAILURE_ERROR_CODES = frozenset("""
INVALID_INPUT INCOMPATIBLE_MODEL CAPACITY_EXHAUSTED EXPIRED_SESSION STALE_WORKER
OUT_OF_ORDER TIMEOUT EXECUTION_FAILED CANCELLED CLOSED_SESSION UNKNOWN_SESSION
UNAUTHENTICATED PERMISSION_DENIED UNAVAILABLE RESOURCE_EXHAUSTED INVALID_ARGUMENT
FAILED_PRECONDITION DEADLINE_EXCEEDED INTERNAL ABORTED DATA_LOSS UNIMPLEMENTED
OUT_OF_RANGE NOT_FOUND ALREADY_EXISTS UNKNOWN SECURITY_ERROR AUTHORITY_UNAVAILABLE
CLOCK_UNSAFE LOCAL_CREDENTIALS_UNSAFE UNRECOGNIZED_ERROR_CODE
""".split())
_FAILURE_FRAME_FIELDS = {"file", "function", "line"}
_FAILURE_TYPE = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,79}\Z", re.ASCII)
_FAILURE_FILE = re.compile(r"[A-Za-z0-9_.-]{1,80}\Z", re.ASCII)
_PYTHON_ASCII_IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,79}\Z", re.ASCII)
_STATUS_FIELDS = {
    "schema_version", "event", "phase", "worker_name", "account_id", "device_id",
    "boot_id", "assignment_id", "model_id", "model_revision", "manifest_fingerprint",
    "listen_endpoint", "layer_range", "clock_uncertainty_seconds", "torch_threads",
    "handler", "bridge", "transport", "external_supervision", "shutdown",
    "report_state", "resource_state",
}


class SupervisorError(RuntimeError):
    """Sanitized failure with a stable stage label."""

    def __init__(self, stage: str, code: str):
        self.stage = stage
        self.code = code
        super().__init__(f"{stage}:{code}")


def _pairs_no_duplicates(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _reject_constant(_value):
    raise ValueError("non-finite JSON constant")


def _json_load(raw: bytes, limit: int, *, label: str) -> dict:
    if type(raw) is not bytes or not 1 <= len(raw) <= limit:
        raise SupervisorError(label, "size")
    try:
        value = json.loads(raw.decode("utf-8", "strict"),
                           object_pairs_hook=_pairs_no_duplicates,
                           parse_constant=_reject_constant)
    except (UnicodeError, ValueError, TypeError, RecursionError):
        raise SupervisorError(label, "invalid_json") from None
    if type(value) is not dict:
        raise SupervisorError(label, "object_required")
    return value


def _json_bytes(value: dict, limit: int = CONTROL_LIMIT) -> bytes:
    try:
        raw = (json.dumps(value, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=True, allow_nan=False) + "\n").encode("ascii")
    except (TypeError, ValueError, RecursionError):
        raise SupervisorError("control_write", "invalid_value") from None
    if not 1 <= len(raw) <= limit:
        raise SupervisorError("control_write", "size")
    return raw


def _exact_fields(value: dict, expected: set[str], label: str) -> None:
    if type(value) is not dict or set(value) != expected:
        raise SupervisorError(label, "schema")


def _string(value, *, maximum=256, label="string") -> str:
    if (type(value) is not str or not value or len(value) > maximum
            or any(ord(ch) < 0x20 or ord(ch) == 0x7f for ch in value)):
        raise SupervisorError(label, "invalid")
    return value


def _int(value, *, minimum=0, maximum=2**63 - 1, label="integer") -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise SupervisorError(label, "invalid")
    return value


def _bool(value, *, label="boolean") -> bool:
    if type(value) is not bool:
        raise SupervisorError(label, "invalid")
    return value


def _sha256_hex(value, label: str) -> str:
    value = _string(value, maximum=64, label=label)
    if _HEX64.fullmatch(value) is None:
        raise SupervisorError(label, "invalid")
    return value


def _validate_run_fields(run_id, nonce) -> None:
    if type(run_id) is not str or _HEX32.fullmatch(run_id) is None:
        raise SupervisorError("handoff", "run_id")
    if type(nonce) is not str or _HEX32.fullmatch(nonce) is None:
        raise SupervisorError("handoff", "nonce")


def _validate_cohort_failure_location(value: dict, ready: dict) -> dict:
    if type(value) is not dict:
        raise SupervisorError("cohort_failure_location", "schema")
    version = value.get("schema_version")
    fields = (_FAILURE_LOCATION_FIELDS if type(version) is int and version == 1
              else _FAILURE_LOCATION_FIELDS | {"error_code"}
              if type(version) is int and version == 2 else None)
    if fields is None:
        raise SupervisorError("cohort_failure_location", "version")
    _exact_fields(value, fields, "cohort_failure_location")
    if value["event"] != "cohort_failure_location":
        raise SupervisorError("cohort_failure_location", "event")
    if type(ready) is not dict:
        raise SupervisorError("cohort_failure_location", "ready_identity")
    _validate_run_fields(ready.get("run_id"), ready.get("nonce"))
    if value["run_id"] != ready["run_id"] or value["nonce"] != ready["nonce"]:
        raise SupervisorError("cohort_failure_location", "identity")
    failure_type = value["failure_type"]
    if (type(failure_type) is not str
            or _FAILURE_TYPE.fullmatch(failure_type) is None):
        raise SupervisorError("cohort_failure_location", "failure_type")
    frames = value["frames"]
    if type(frames) is not list or len(frames) > 12:
        raise SupervisorError("cohort_failure_location", "frames")
    normalized_frames = []
    for frame in frames:
        _exact_fields(frame, _FAILURE_FRAME_FIELDS, "cohort_failure_location")
        filename = frame["file"]
        function = frame["function"]
        line = frame["line"]
        if (type(filename) is not str or _FAILURE_FILE.fullmatch(filename) is None
                or filename in {".", ".."} or "/" in filename or "\\" in filename):
            raise SupervisorError("cohort_failure_location", "frame_file")
        if (type(function) is not str
                or _PYTHON_ASCII_IDENTIFIER.fullmatch(function) is None
                or keyword.iskeyword(function)):
            raise SupervisorError("cohort_failure_location", "frame_function")
        if type(line) is not int or not 1 <= line <= 1_000_000:
            raise SupervisorError("cohort_failure_location", "frame_line")
        normalized_frames.append({"file": filename, "function": function, "line": line})
    result = {
        "schema_version": version,
        "event": "cohort_failure_location",
        "run_id": ready["run_id"],
        "nonce": ready["nonce"],
        "failure_type": failure_type,
        "frames": normalized_frames,
    }
    if version == 2:
        code = value["error_code"]
        if code is not None and (type(code) is not str or code not in _FAILURE_ERROR_CODES):
            raise SupervisorError("cohort_failure_location", "error_code")
        result["error_code"] = code
    return result


def _validate_bundle_ready(value: dict, expected_endpoint: str) -> dict:
    _exact_fields(value, _BUNDLE_READY_FIELDS, "bundle_ready")
    if type(value["schema_version"]) is not int or value["schema_version"] != 1:
        raise SupervisorError("bundle_ready", "version")
    if value["event"] != "bundle_ready" or value["worker_name"] != "worker-3":
        raise SupervisorError("bundle_ready", "identity")
    _validate_run_fields(value["run_id"], value["nonce"])
    if type(value["expected_boot_id"]) is not str or _HEX32.fullmatch(value["expected_boot_id"]) is None:
        raise SupervisorError("bundle_ready", "boot_id")
    _sha256_hex(value["manifest_fingerprint"], "manifest_fingerprint")
    _sha256_hex(value["snapshot_sha256"], "snapshot_sha256")
    if type(expected_endpoint) is not str or value["endpoint"] != expected_endpoint:
        raise SupervisorError("bundle_ready", "endpoint")
    path = value["bundle_path"]
    if (type(path) is not str or not path.startswith(HANDOFF_ROOT + "/")
            or "\x00" in path or "\\" in path or ".." in PurePosixPath(path).parts
            or len(path) > 4096):
        raise SupervisorError("bundle_ready", "bundle_path")
    return value


def _validate_worker_config(raw: bytes, ready: dict, expected_endpoint: str) -> dict:
    config = _json_load(raw, CONFIG_LIMIT, label="worker_config")
    _exact_fields(config, _CONFIG_FIELDS, "worker_config")
    if type(config["schema_version"]) is not int or config["schema_version"] != 1:
        raise SupervisorError("worker_config", "version")
    for key in ("account_id", "device_id", "assignment_id", "boot_id"):
        value = config[key]
        if type(value) is not str or _TYPED_ID[key].fullmatch(value) is None:
            raise SupervisorError("worker_config", key)
    if (config["worker_name"] != "worker-3"
            or config["boot_id"] != ready["expected_boot_id"]
            or type(config["listen_port"]) is not int
            or f"{config['listen_ip']}:{config['listen_port']}" != expected_endpoint
            or config["protected_root"] != REMOTE_ROOT
            or config["certificate_path"] != f"{REMOTE_ROOT}/host.crt"
            or config["private_key_path"] != f"{REMOTE_ROOT}/host.key"
            or config["cohort_ca_path"] != f"{REMOTE_ROOT}/cohort-ca.crt"
            or config["snapshot_verification_key_path"] != f"{REMOTE_ROOT}/snapshot.pub"
            or config["signed_snapshot_path"] != f"{REMOTE_ROOT}/snapshot.json"
            or config["acceptor_directory"] != f"{REMOTE_ROOT}/sockets"
            or config["status_report_path"] != f"{REMOTE_ROOT}/status.json"
            or config["artifact_directory"] != "/artifacts"):
        raise SupervisorError("worker_config", "identity_or_paths")
    if (config["model_id"] != MODEL_ID or config["model_revision"] != MODEL_REVISION
            or config["manifest_fingerprint"] != ready["manifest_fingerprint"]):
        raise SupervisorError("worker_config", "model_pin")
    uncertainty = config["clock_uncertainty_seconds"]
    if (type(uncertainty) not in (int, float) or not math.isfinite(uncertainty)
            or not 0 < uncertainty <= 30):
        raise SupervisorError("worker_config", "clock_uncertainty")
    return config


def validate_worker_tar(raw: bytes, ready: dict, expected_endpoint: str) -> dict[str, bytes]:
    """Validate a bounded flat role bundle; return only its approved files."""
    if type(raw) is not bytes or not 1 <= len(raw) <= BUNDLE_LIMIT:
        raise SupervisorError("worker_bundle", "size")
    files: dict[str, bytes] = {}
    saw_sockets = False
    try:
        with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as archive:
            members = archive.getmembers()
            if not 1 <= len(members) <= len(_WORKER_FILES) + 1:
                raise SupervisorError("worker_bundle", "member_count")
            for member in members:
                if (member.pax_headers or member.linkname or member.name.startswith("/")
                        or "\\" in member.name or ".." in PurePosixPath(member.name).parts):
                    raise SupervisorError("worker_bundle", "unsafe_member")
                normalized_name = member.name[:-1] if member.isdir() and member.name.endswith("/") else member.name
                if member.isdir() or member.name in {"sockets", "sockets/"}:
                    if (not member.isdir() or normalized_name != "sockets"
                            or member.name not in {"sockets", "sockets/"}
                            or member.size != 0 or member.mode != 0o700 or saw_sockets):
                        raise SupervisorError("worker_bundle", "sockets_entry")
                    saw_sockets = True
                    continue
                if member.name not in _WORKER_FILES or not member.isfile():
                    raise SupervisorError("worker_bundle", "unexpected_member")
                if member.mode != 0o600 or member.name in files:
                    raise SupervisorError("worker_bundle", "file_mode_or_duplicate")
                if not 1 <= member.size <= _WORKER_FILES[member.name]:
                    raise SupervisorError("worker_bundle", "file_size")
                stream = archive.extractfile(member)
                if stream is None:
                    raise SupervisorError("worker_bundle", "file_unreadable")
                data = stream.read(member.size + 1)
                if len(data) != member.size:
                    raise SupervisorError("worker_bundle", "file_length")
                files[member.name] = data
    except SupervisorError:
        raise
    except (tarfile.TarError, OSError, EOFError, ValueError):
        raise SupervisorError("worker_bundle", "invalid_tar") from None
    if set(files) != set(_WORKER_FILES) or not saw_sockets:
        raise SupervisorError("worker_bundle", "incomplete")
    _validate_worker_config(files["worker.json"], ready, expected_endpoint)
    if hashlib.sha256(files["snapshot.json"]).hexdigest() != ready["snapshot_sha256"]:
        raise SupervisorError("worker_bundle", "snapshot_hash")
    return files


def _profile_observation_cases(profile: str) -> dict[int, str]:
    if type(profile) is not str or profile not in _PROFILE_OBSERVATIONS:
        raise SupervisorError("arguments", "profile")
    return dict(_PROFILE_OBSERVATIONS[profile])


def _validate_observation(value: dict, ready: dict, expected_sequence: int,
                          profile: str = PROFILE_BASELINE) -> dict:
    _exact_fields(value, _OBSERVATION_FIELDS, "observation_request")
    if (type(value["schema_version"]) is not int or value["schema_version"] != 1
            or value["event"] != "observe"):
        raise SupervisorError("observation_request", "version_or_event")
    for key in ("run_id", "nonce", "expected_boot_id"):
        expected = (ready["expected_boot_id"] if key == "expected_boot_id"
                    else ready[key])
        if type(value[key]) is not str or value[key] != expected:
            raise SupervisorError("observation_request", key)
    cases = _profile_observation_cases(profile)
    sequence = _int(value["sequence"], minimum=1,
                    maximum=_MAX_OBSERVATION_SEQUENCE, label="sequence")
    if (sequence not in cases or sequence != expected_sequence
            or type(value["case_id"]) is not str
            or value["case_id"] != cases[sequence]):
        raise SupervisorError("observation_request", "order_or_case")
    if type(value["request_id"]) is not str or _TYPED_REQUEST.fullmatch(value["request_id"]) is None:
        raise SupervisorError("observation_request", "request_id")
    if type(value["session_id"]) is not str or _TYPED_SESSION.fullmatch(value["session_id"]) is None:
        raise SupervisorError("observation_request", "session_id")
    return value


def _validate_restart_stop_request(value: dict, ready: dict) -> dict:
    """Bind the old-generation stop request to its protected READY record."""
    fields = {
        "schema_version", "event", "run_id", "old_nonce", "old_boot_id",
        "manifest_fingerprint", "endpoint",
    }
    _exact_fields(value, fields, "restart_stop_request")
    expected = {
        "schema_version": 1, "event": "restart_stop_request",
        "run_id": ready["run_id"], "old_nonce": ready["nonce"],
        "old_boot_id": ready["expected_boot_id"],
        "manifest_fingerprint": ready["manifest_fingerprint"],
        "endpoint": ready["endpoint"],
    }
    if any(type(value.get(key)) is not type(expected_value)
           or value.get(key) != expected_value
           for key, expected_value in expected.items()):
        raise SupervisorError("restart_stop_request", "identity")
    return value


def _restart_stop_receipt(*, ready, host_key, remote_state, image, arm_ns, exit_ns):
    from lab.secure_cohort_restart import validate_restart_stop_ack

    container_id = remote_state.get("container_id")
    receipt = {
        "schema_version": 1, "event": "restart_stopped",
        "run_id": ready["run_id"], "old_nonce": ready["nonce"],
        "old_boot_id": ready["expected_boot_id"],
        "manifest_fingerprint": ready["manifest_fingerprint"],
        "endpoint": ready["endpoint"], "ssh_host_key_sha256": host_key,
        "old_owner": {
            "container_id": container_id,
            "image_sha256": image.removeprefix("sha256:"),
            "exit_code": remote_state.get("exit_code"),
            "ownership_verified": remote_state.get("ownership_status") == "verified",
            "process_state": remote_state.get("process_state"),
            "container_removed": remote_state.get("container_removed"),
            "shutdown_confirmed": remote_state.get("shutdown_confirmed"),
            "private_files_removed": remote_state.get("private_files_removed"),
            "job_root_removed": remote_state.get("job_root_removed"),
            "stop_arm_monotonic_ns": arm_ns,
            "exit_monotonic_ns": exit_ns,
            "elapsed_ns": exit_ns - arm_ns,
        },
    }
    try:
        digest = validate_restart_stop_ack(
            receipt, run_id=ready["run_id"], old_nonce=ready["nonce"],
            old_boot_id=ready["expected_boot_id"],
            manifest_fingerprint=ready["manifest_fingerprint"],
            endpoint=ready["endpoint"], ssh_host_key_sha256=host_key,
            stop_arm_monotonic_ns=arm_ns)
    except (ValueError, TypeError, KeyError) as error:
        raise SupervisorError("restart_stop_receipt", "evidence_invalid") from error
    return receipt, digest


def _validate_restart_ready_ack_locally(payload, *, run_id, old_ready,
                                        new_bundle, host_key, config,
                                        receipt_digest):
    from types import SimpleNamespace
    from lab.secure_cohort_restart import validate_restart_ready_ack

    expected = SimpleNamespace(
        run_id=run_id, nonce=new_bundle["nonce"],
        boot_id=new_bundle["expected_boot_id"],
        manifest_fingerprint=new_bundle["manifest_fingerprint"],
        snapshot_sha256=new_bundle["snapshot_sha256"],
        endpoint=new_bundle["endpoint"])

    def validate_nested(nested, expected_value):
        if type(nested) is not dict or set(nested) != _READY_ACK_FIELDS:
            raise SupervisorError("restart_ready_ack", "nested_schema")
        for key in ("run_id", "nonce", "boot_id", "manifest_fingerprint",
                    "snapshot_sha256", "endpoint"):
            if nested.get(key) != getattr(expected_value, key):
                raise SupervisorError("restart_ready_ack", "nested_identity")
        if (nested.get("remote_status_uid") != REMOTE_STATUS_UID
                or nested.get("remote_status_mode") != 0o600
                or type(nested.get("remote_status_mtime_ns")) is not int
                or nested.get("measurement_label") != "ssh_protected_ready_status"):
            raise SupervisorError("restart_ready_ack", "nested_provenance")
        status = nested.get("remote_status")
        if type(status) is not dict or status.get("event") not in {"ready", "heartbeat"}:
            raise SupervisorError("restart_ready_ack", "nested_status")
        _validate_status(status, config, event=status["event"])
        return nested.get("ssh_host_key_sha256")

    from lab.secure_cohort_restart import validate_restart_bundle_ready
    return validate_restart_ready_ack(
        payload, run_id=run_id, old_nonce=old_ready["nonce"],
        new_nonce=new_bundle["nonce"],
        old_boot_id=old_ready["expected_boot_id"],
        new_boot_id=new_bundle["expected_boot_id"],
        old_owner_receipt_sha256=receipt_digest,
        expected_ssh_host_key_sha256=host_key, bundle=new_bundle,
        expected=expected, ready_validator=validate_nested)


def _validate_restart_config_continuity(old_config: dict, new_config: dict) -> None:
    if type(old_config) is not dict or type(new_config) is not dict:
        raise SupervisorError("restart_config", "schema")
    if (set(old_config) != _CONFIG_FIELDS or set(new_config) != _CONFIG_FIELDS
            or old_config.get("worker_name") != "worker-3"
            or new_config.get("worker_name") != "worker-3"
            or old_config.get("boot_id") == new_config.get("boot_id")):
        raise SupervisorError("restart_config", "identity")
    if any(old_config[key] != new_config[key]
           for key in _CONFIG_FIELDS - {"boot_id"}):
        raise SupervisorError("restart_config", "configuration_changed")


def _validate_stop_request(value: dict, ready: dict) -> dict:
    _exact_fields(value, _STOP_REQUEST_FIELDS, "stop_request")
    if (type(value["schema_version"]) is not int or value["schema_version"] != 1
            or value["event"] != "stop"):
        raise SupervisorError("stop_request", "version_or_event")
    for key in ("run_id", "nonce", "expected_boot_id"):
        expected = ready["expected_boot_id"] if key == "expected_boot_id" else ready[key]
        if value[key] != expected:
            raise SupervisorError("stop_request", key)
    if type(value["may_have_started"]) is not bool:
        raise SupervisorError("stop_request", "may_have_started")
    if value["maximum_wait_seconds"] != TERMINATION_SECONDS or type(value["maximum_wait_seconds"]) is not int:
        raise SupervisorError("stop_request", "wait_bound")
    return value


def _validate_status(status: dict, config: dict, *, event: str,
                     expected_session_id: str | None = None,
                     expected_open_only: bool = False,
                     expected_session_ids: list[str] | None = None,
                     expected_session_count: int | None = None) -> None:
    if expected_session_ids is not None and expected_session_count is not None:
        raise SupervisorError("remote_status", "conflicting_session_expectations")
    _exact_fields(status, _STATUS_FIELDS, "remote_status")
    if (type(status["schema_version"]) is not int or status["schema_version"] != 1
            or status["event"] != event or status["phase"] != "ready"):
        raise SupervisorError("remote_status", "lifecycle")
    identity = {
        "worker_name": "worker-3", "account_id": config["account_id"],
        "device_id": config["device_id"], "boot_id": config["boot_id"],
        "assignment_id": config["assignment_id"], "model_id": MODEL_ID,
        "model_revision": MODEL_REVISION,
        "manifest_fingerprint": config["manifest_fingerprint"],
        "listen_endpoint": f"{config['listen_ip']}:{config['listen_port']}",
        "layer_range": [6, 8],
        "clock_uncertainty_seconds": config["clock_uncertainty_seconds"],
        "resource_state": "observed", "report_state": "confirmed",
    }
    for key, expected in identity.items():
        if type(status[key]) is not type(expected) or status[key] != expected:
            raise SupervisorError("remote_status", "identity")
    if type(status["torch_threads"]) is not int or status["torch_threads"] != 2:
        raise SupervisorError("remote_status", "threads")
    handler = status["handler"]
    bridge = status["bridge"]
    transport = status["transport"]
    if type(handler) is not dict or type(bridge) is not dict or type(transport) is not dict:
        raise SupervisorError("remote_status", "owner_state")
    handler_fields = {
        "state", "active_sessions", "active_session_ids", "tombstones",
        "retained_entries", "queued_operations", "active_compute",
        "cache_bytes_exact", "requires_restart", "stopping", "limits",
        "committed_cache_bytes", "committed_cache_bytes_lower_bound",
        "allocated_cache_bytes",
    }
    if type(handler) is not dict or set(handler) != handler_fields:
        raise SupervisorError("remote_status", "handler_schema")
    active_ids = handler.get("active_session_ids")
    if (type(active_ids) is not list or len(active_ids) > 8
            or any(type(item) is not str or _TYPED_SESSION.fullmatch(item) is None
                   for item in active_ids)
            or active_ids != sorted(set(active_ids))):
        raise SupervisorError("remote_status", "active_session_ids")
    held = expected_session_id is not None
    cache_held = (held and not expected_open_only and expected_session_ids is None
                  and expected_session_count is None)
    if expected_session_ids is not None:
        if (not held or type(expected_session_ids) is not list
                or len(expected_session_ids) != 8
                or any(type(item) is not str or _TYPED_SESSION.fullmatch(item) is None
                       for item in expected_session_ids)
                or expected_session_ids != sorted(set(expected_session_ids))
                or expected_session_id not in expected_session_ids):
            raise SupervisorError("remote_status", "capacity_session_ids")
        expected_ids = expected_session_ids
        held_count = 8
    elif expected_session_count is not None:
        if (not held or type(expected_session_count) is not int
                or expected_session_count != 8 or expected_session_id not in active_ids):
            raise SupervisorError("remote_status", "capacity_session_count")
        expected_ids = active_ids
        held_count = expected_session_count
    else:
        expected_ids = [expected_session_id] if held else []
        held_count = 1 if held else 0
    if (handler.get("state") != "observed"
            or type(handler.get("active_session_ids")) is not list
            or handler.get("active_session_ids") != expected_ids
            or type(handler.get("active_sessions")) is not int
            or handler.get("active_sessions") != held_count
            or any(type(handler.get(key)) is not int or handler[key] != 0 for key in
                   ("queued_operations",))
            or (not held and any(type(handler.get(key)) is not int or handler[key] != 0
                   for key in ("committed_cache_bytes", "allocated_cache_bytes")))
            or (cache_held and (type(handler.get("committed_cache_bytes")) is not int
                                or handler["committed_cache_bytes"] <= 0
                                or type(handler.get("allocated_cache_bytes")) is not int
                                or handler["allocated_cache_bytes"] <= 0))
            or (held and (expected_open_only is True or expected_session_ids is not None
                          or expected_session_count is not None)
                and (type(handler.get("committed_cache_bytes")) is not int
                     or handler["committed_cache_bytes"] != 0
                     or type(handler.get("allocated_cache_bytes")) is not int
                     or handler["allocated_cache_bytes"] != 0))
            or type(expected_open_only) is not bool
            or (expected_open_only and not held)
            or handler.get("active_compute") is not False
            or handler.get("requires_restart") is not False
            or handler.get("stopping") is not False
            or handler.get("cache_bytes_exact") is not True
            or handler.get("committed_cache_bytes_lower_bound") is not None):
        raise SupervisorError("remote_status", "handler_not_idle")
    if (bridge.get("state") != "observed" or bridge.get("ready") is not True
            or bridge.get("cleanup_confirmed") is not True
            or bridge.get("unavailable") is not False
            or bridge.get("requires_restart") is not False
            or bridge.get("fault_present") is not False
            or any(type(bridge.get(key)) is not int
                   or bridge[key] != (held_count if held and key == "owned_sessions" else 0)
                   for key in ("active_authorizations", "owned_sessions", "pending_notices"))):
        raise SupervisorError("remote_status", "bridge_not_ready")
    expected_transport = {
        "listener_slots": 1, "max_connections": 16, "max_pending": 4,
        "reserved_connections": 1, "reserved_pending": 0,
        "reserved_listener_pending_capacity": 1, "reserved_outbound_pending": 0,
        "server_state": "running",
    }
    if any(type(transport.get(k)) is not type(v) or transport.get(k) != v
           for k, v in expected_transport.items()):
        raise SupervisorError("remote_status", "transport_reservation")
    external = status["external_supervision"]
    if (type(external) is not dict
            or external.get("startup_watchdog_seconds") != 60
            or external.get("termination_watchdog_seconds") != 15
            or external.get("resource_caps") != "configured_by_external_supervisor"
            or external.get("verified_by_worker") is not False):
        raise SupervisorError("remote_status", "external_supervision")
    if status["shutdown"] != {"state": "not_started"}:
        raise SupervisorError("remote_status", "shutdown_state")


def _final_status_is_confirmed(status: dict, config: dict) -> bool:
    """Accept confirmed shutdown while preserving bounded terminal tombstones."""
    try:
        if type(status) is not dict or set(status) != _STATUS_FIELDS:
            return False
        if (type(status["schema_version"]) is not int or status["schema_version"] != 1
                or status["event"] != "final" or status["phase"] != "stopped"):
            return False
        identity = {
            "worker_name": "worker-3", "account_id": config["account_id"],
            "device_id": config["device_id"], "boot_id": config["boot_id"],
            "assignment_id": config["assignment_id"], "model_id": MODEL_ID,
            "model_revision": MODEL_REVISION,
            "manifest_fingerprint": config["manifest_fingerprint"],
            "listen_endpoint": f"{config['listen_ip']}:{config['listen_port']}",
            "clock_uncertainty_seconds": config["clock_uncertainty_seconds"],
            "resource_state": "observed", "report_state": "confirmed",
        }
        if any(type(status[k]) is not type(v) or status[k] != v for k, v in identity.items()):
            return False
        if type(status["torch_threads"]) is not int or status["torch_threads"] != 2:
            return False
        if status["layer_range"] != [6, 8]:
            return False
        shutdown = status["shutdown"]
        if (type(shutdown) is not dict
                or shutdown != {"server": "confirmed", "bridge": "confirmed",
                                "handler": "confirmed", "overall": "confirmed"}):
            return False
        handler = status["handler"]
        handler_fields = {
            "state", "active_sessions", "active_session_ids", "tombstones", "retained_entries",
            "queued_operations", "active_compute", "cache_bytes_exact",
            "requires_restart", "stopping", "limits", "committed_cache_bytes",
            "committed_cache_bytes_lower_bound", "allocated_cache_bytes",
        }
        limit_fields = {
            "max_sessions", "max_tombstones", "max_stage_queue", "max_positions",
            "max_cache_positions", "max_cache_bytes", "max_message_bytes",
        }
        if type(handler) is not dict or set(handler) != handler_fields:
            return False
        if handler.get("active_session_ids") != []:
            return False
        limits = handler.get("limits") if type(handler) is dict else None
        tombstones = handler.get("tombstones") if type(handler) is dict else None
        retained = handler.get("retained_entries") if type(handler) is dict else None
        max_tombstones = limits.get("max_tombstones") if type(limits) is dict else None
        # Frozen v1 WorkerHandler default; do not constrain terminal
        # tombstones below the runtime's actual bounded capacity.
        if (type(handler) is not dict
                or type(limits) is not dict or set(limits) != limit_fields
                or handler.get("state") != "observed"
                or any(type(handler.get(k)) is not int or handler[k] != 0 for k in
                       ("active_sessions", "queued_operations", "committed_cache_bytes",
                        "allocated_cache_bytes"))
                or type(tombstones) is not int or type(retained) is not int
                or type(max_tombstones) is not int or not 1 <= max_tombstones <= 4096
                or not 0 <= tombstones <= max_tombstones
                or retained != tombstones
                or any(type(value) is not int or value < 1 for value in limits.values())
                or limits.get("max_sessions") != 8
                or limits.get("max_positions") != 1152
                or limits.get("max_cache_positions") != 12_288
                or limits.get("max_cache_bytes") != 16_777_216
                or limits.get("max_message_bytes") != 1_048_576
                or type(handler.get("active_compute")) is not bool
                or handler.get("active_compute") is not False
                or type(handler.get("cache_bytes_exact")) is not bool
                or handler.get("cache_bytes_exact") is not True
                or type(handler.get("requires_restart")) is not bool
                or type(handler.get("stopping")) is not bool
                or handler.get("committed_cache_bytes_lower_bound") is not None):
            return False
        bridge = status["bridge"]
        bridge_fields = {
            "state", "ready", "unavailable", "requires_restart", "cleanup_confirmed",
            "active_authorizations", "owned_sessions", "pending_notices", "fault_present",
        }
        if (type(bridge) is not dict or set(bridge) != bridge_fields
                or bridge.get("state") != "observed"
                or bridge.get("cleanup_confirmed") is not True
                or any(type(bridge.get(k)) is not bool for k in
                       ("ready", "unavailable", "requires_restart", "cleanup_confirmed",
                        "fault_present"))
                or any(type(bridge.get(k)) is not int or bridge[k] != 0 for k in
                       ("active_authorizations", "owned_sessions", "pending_notices"))):
            return False
        transport = status["transport"]
        transport_fields = {
            "listener_slots", "max_connections", "max_pending", "reserved_connections",
            "reserved_pending", "reserved_listener_pending_capacity",
            "reserved_outbound_pending", "server_state",
        }
        if (type(transport) is not dict or set(transport) != transport_fields
                or transport.get("server_state") != "stopped"
                or any(type(transport.get(k)) is not int or transport[k] != 0 for k in
                       ("reserved_connections", "reserved_pending",
                        "reserved_listener_pending_capacity", "reserved_outbound_pending"))
                or type(transport.get("listener_slots")) is not int
                or type(transport.get("max_connections")) is not int
                or type(transport.get("max_pending")) is not int
                or transport.get("listener_slots") != 1
                or transport.get("max_connections") != 16
                or transport.get("max_pending") != 4):
            return False
        external = status["external_supervision"]
        return (type(external) is dict
                and set(external) == {"startup_watchdog_seconds", "termination_watchdog_seconds",
                                      "resource_caps", "verified_by_worker"}
                and external.get("startup_watchdog_seconds") == 60
                and external.get("termination_watchdog_seconds") == 15
                and external.get("resource_caps") == "configured_by_external_supervisor"
                and external.get("verified_by_worker") is False
                and type(external.get("verified_by_worker")) is bool)
    except (KeyError, TypeError, ValueError):
        return False


def verify_container_inspect(text: str, *, cid: str, name: str,
                             owner_label: str, role: str, image: str) -> dict:
    """Verify one Docker inspect record before any stop/remove operation."""
    if type(cid) is not str or _CONTAINER_ID.fullmatch(cid) is None:
        raise SupervisorError("container", "cid")
    if type(text) is not str or len(text) > 4096:
        raise SupervisorError("container", "inspect_size")
    lines = text.splitlines()
    if len(lines) != 7:
        raise SupervisorError("container", "inspect_schema")
    actual_id, actual_name, actual_image, actual_owner, actual_role, running, exit_text = lines
    if (actual_id != cid or actual_name != "/" + name or actual_image != image
            or actual_owner != owner_label or actual_role != role
            or role not in {"operator", "worker-3"}):
        raise SupervisorError("container", "ownership_mismatch")
    if running not in {"true", "false"} or not exit_text.isdecimal():
        raise SupervisorError("container", "state")
    return {"running": running == "true", "exit_code": int(exit_text)}


def _container_inspect_template() -> str:
    """Render exactly seven newline-delimited Docker inspect fields."""
    return (
        "{{println .Id}}"
        "{{println .Name}}"
        "{{println .Config.Image}}"
        f'{{{{println (index .Config.Labels "{_OWNER_LABEL}")}}}}'
        f'{{{{println (index .Config.Labels "{_ROLE_LABEL}")}}}}'
        "{{println .State.Running}}"
        "{{println .State.ExitCode}}"
    )


def _container_inspect_argv(cid: str) -> list[str]:
    return ["docker", "inspect", "--type", "container",
            "--format", _container_inspect_template(), cid]


def build_local_run_argv(*, image: str, name: str, owner: str,
                         artifact_volume: str, reference_volume: str,
                         cohort_args: list[str]) -> list[str]:
    return [
        "docker", "run", "--detach", "--pull=never", "--name", name,
        "--label", f"{_OWNER_LABEL}={owner}", "--label", f"{_ROLE_LABEL}=operator",
        "--init", "--read-only", "--cap-drop=ALL",
        "--security-opt=no-new-privileges", "--cpus=2", "--memory=6g",
        "--pids-limit=256", "--tmpfs", "/tmp:rw,noexec,nosuid,size=128m",
        "--mount", f"type=volume,src={artifact_volume},dst=/artifacts,readonly",
        "--mount", f"type=volume,src={reference_volume},dst=/reference,readonly",
        "--network", "bridge", "--entrypoint", "python", image,
        "-c", _OPERATOR_BOOTSTRAP, *cohort_args,
    ]


def build_remote_run_argv(*, image: str, name: str, owner: str,
                          job_root: str, artifacts: str,
                          owner_controls_run_id: str | None = None,
                          owner_intent_root: str | None = None) -> list[str]:
    argv = [
        "docker", "run", "--detach", "--pull=never", "--name", name,
        "--label", f"{_OWNER_LABEL}={owner}", "--label", f"{_ROLE_LABEL}=worker-3",
        "--init", "--user", "1000:1000", "--read-only", "--cap-drop=ALL",
        "--security-opt=no-new-privileges", "--cpus=2", "--memory=3g",
        "--pids-limit=128", "--tmpfs", "/tmp:rw,noexec,nosuid,size=128m",
        "--network", "host", "--mount", f"type=bind,src={job_root},dst={REMOTE_ROOT}",
        "--mount", f"type=bind,src={artifacts},dst=/artifacts,readonly",
    ]
    if owner_controls_run_id is not None:
        if (type(owner_controls_run_id) is not str
                or _HEX32.fullmatch(owner_controls_run_id) is None):
            raise SupervisorError("remote_container", "owner_run_id")
    if owner_intent_root is not None:
        if owner_controls_run_id is None:
            raise SupervisorError("remote_container", "owner_mount")
        checked = _remote_path(owner_intent_root, label="owner_intent_root")
        argv.extend(("--mount", f"type=bind,src={checked},dst=/owner-intents,readonly"))
    argv.extend((image, "python", "-m", "lab.secure_worker", "--config",
                 f"{REMOTE_ROOT}/worker.json"))
    if owner_controls_run_id is not None:
        argv.extend(("--owner-controls-run-id", owner_controls_run_id))
    if owner_intent_root is not None:
        argv.extend(("--owner-removal-intent-root", "/owner-intents"))
    return argv


_OPERATOR_BOOTSTRAP = r'''import json,os,subprocess,sys,time
root="/tmp/handoff"
os.mkdir(root,0o700)
os.chmod(root,0o700)
rc=70
failure=None
try:
 p=subprocess.run([sys.executable,"-m","lab.secure_cohort",*sys.argv[1:]],check=False)
 rc=p.returncode
except BaseException as e:
 failure=type(e).__name__[:80]
raw=(json.dumps({"schema_version":1,"event":"operator_exit","exit_code":rc,"failure_type":failure},sort_keys=True,separators=(",",":"))+"\n").encode("ascii")
fd=os.open(root+"/operator-exit.json",os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
try:
 os.write(fd,raw);os.fsync(fd)
finally: os.close(fd)
deadline=time.monotonic()+20.0
while time.monotonic()<deadline:
 try:
  f=os.open(root+"/supervisor-release.json",os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
  try:
   s=os.fstat(f)
   if not __import__("stat").S_ISREG(s.st_mode) or s.st_uid!=0 or __import__("stat").S_IMODE(s.st_mode)!=0o600 or s.st_size>4096: break
   b=os.read(f,4097)
  finally: os.close(f)
  v=json.loads(b.decode("utf-8"))
  if v!={"schema_version":1,"event":"release"}: break
  break
 except FileNotFoundError: time.sleep(0.05)
 except BaseException: break
sys.exit(rc)
'''


_LOCAL_READ_SCRIPT = r'''import os,stat,sys
root="/tmp/handoff"
name=sys.argv[1]
allowed={"bundle-ready.json","ready.json","stop-request.json","stop-response.json","result.json","operator-exit.json","failure-location.json","restart-stop-request.json","restart-bundle-ready.json","restart-stop-response.json","restart-ready-ack.json","owner-materials-ready.json","owner-action-request-1.json","owner-action-request-2.json",*(f"observation-request-{i}.json" for i in range(1,11)),*(f"observation-response-{i}.json" for i in range(1,11)),"owner-action-response-1.json","owner-action-response-2.json"}
if name not in allowed: raise SystemExit(20)
limit=4096 if name=="failure-location.json" else 65536
df=os.open(root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
try:
 d=os.fstat(df)
 if not stat.S_ISDIR(d.st_mode) or d.st_uid!=os.geteuid() or stat.S_IMODE(d.st_mode)!=0o700: raise SystemExit(21)
 try: f=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=df)
 except FileNotFoundError: raise SystemExit(3)
 try:
  s=os.fstat(f)
  if not stat.S_ISREG(s.st_mode) or s.st_uid!=os.geteuid() or stat.S_IMODE(s.st_mode)!=0o600 or s.st_nlink!=1 or not 1<=s.st_size<=limit: raise SystemExit(22)
  b=os.read(f,limit+1)
  if len(b)!=s.st_size: raise SystemExit(23)
  z=os.fstat(f)
  if (s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns)!=(z.st_dev,z.st_ino,z.st_size,z.st_mtime_ns): raise SystemExit(24)
  os.write(1,b)
 finally: os.close(f)
finally: os.close(df)
'''


_LOCAL_READ_OWNER_ARCHIVE_SCRIPT = r'''import os,sys
from lab.secure_owner_material_handoff import read_owner_material_archive
root="/tmp/handoff"
flags=os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC
df=os.open(root,flags)
try:
 sys.stdout.buffer.write(read_owner_material_archive(df))
finally: os.close(df)
'''


_LOCAL_WRITE_SCRIPT = r'''import os,stat,sys
root="/tmp/handoff"
name=sys.argv[1]
allowed={"ready.json","stop-response.json","restart-stop-response.json","restart-ready-ack.json",*(f"observation-response-{i}.json" for i in range(1,11)),"owner-action-response-1.json","owner-action-response-2.json","supervisor-release.json"}
if name not in allowed: raise SystemExit(20)
b=sys.stdin.buffer.read(65537)
if not 1<=len(b)<=65536: raise SystemExit(21)
df=os.open(root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
try:
 d=os.fstat(df)
 if not stat.S_ISDIR(d.st_mode) or d.st_uid!=os.geteuid() or stat.S_IMODE(d.st_mode)!=0o700: raise SystemExit(22)
 tmp=f".{name}.{os.getpid()}.{os.urandom(8).hex()}.tmp"
 f=None
 temp_exists=False
 try:
  f=os.open(tmp,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=df)
  temp_exists=True
  s=os.fstat(f)
  if not stat.S_ISREG(s.st_mode) or s.st_uid!=os.geteuid() or stat.S_IMODE(s.st_mode)!=0o600 or s.st_nlink!=1: raise SystemExit(23)
  v=memoryview(b)
  while v:
   written=os.write(f,v)
   if written<=0: raise SystemExit(24)
   v=v[written:]
  os.fsync(f)
  os.close(f);f=None
  os.link(tmp,name,src_dir_fd=df,dst_dir_fd=df,follow_symlinks=False)
  os.unlink(tmp,dir_fd=df);temp_exists=False
  os.fsync(df)
 except BaseException:
  if f is not None:
   try: os.close(f)
   except OSError: pass
  if temp_exists:
   try:
    os.unlink(tmp,dir_fd=df)
    os.fsync(df)
   except OSError: pass
  raise
finally: os.close(df)
'''


_LOCAL_TAR_SCRIPT = r'''import io,os,stat,sys,tarfile
root="/tmp/handoff"
path=sys.argv[1]
if not path.startswith(root+"/") or ".." in path.split("/"): raise SystemExit(30)
rel=path[len(root)+1:].split("/")
if len(rel)<2 or rel[-1]!="worker-3-bundle" or any(not x for x in rel): raise SystemExit(31)
flags=os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW
df=os.open(root,flags)
try:
 for part in rel:
  nf=os.open(part,flags,dir_fd=df); os.close(df); df=nf
  s=os.fstat(df)
  if not stat.S_ISDIR(s.st_mode) or s.st_uid!=os.geteuid() or stat.S_IMODE(s.st_mode)!=0o700: raise SystemExit(32)
 names={"worker.json","host.crt","host.key","cohort-ca.crt","snapshot.pub","snapshot.json","sockets"}
 if set(os.listdir(df))!=names: raise SystemExit(33)
 out=io.BytesIO()
 with tarfile.open(fileobj=out,mode="w",format=tarfile.USTAR_FORMAT) as t:
  d=os.open("sockets",flags,dir_fd=df)
  try:
   s=os.fstat(d)
   if not stat.S_ISDIR(s.st_mode) or s.st_uid!=os.geteuid() or stat.S_IMODE(s.st_mode)!=0o700 or os.listdir(d): raise SystemExit(34)
  finally: os.close(d)
  ti=tarfile.TarInfo("sockets/");ti.type=tarfile.DIRTYPE;ti.mode=0o700;ti.uid=os.geteuid();ti.gid=os.getegid();ti.mtime=0;t.addfile(ti)
  bounds={"worker.json":16384,"host.crt":65536,"host.key":1048576,"cohort-ca.crt":65536,"snapshot.pub":65536,"snapshot.json":65536}
  for n,m in bounds.items():
   f=os.open(n,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=df)
   try:
    s=os.fstat(f)
    if not stat.S_ISREG(s.st_mode) or s.st_uid!=os.geteuid() or stat.S_IMODE(s.st_mode)!=0o600 or s.st_nlink!=1 or not 1<=s.st_size<=m: raise SystemExit(35)
    b=os.read(f,m+1)
    if len(b)!=s.st_size: raise SystemExit(36)
    z=os.fstat(f)
    if (s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns)!=(z.st_dev,z.st_ino,z.st_size,z.st_mtime_ns): raise SystemExit(37)
   finally: os.close(f)
   ti=tarfile.TarInfo(n);ti.type=tarfile.REGTYPE;ti.mode=0o600;ti.uid=os.geteuid();ti.gid=os.getegid();ti.size=len(b);ti.mtime=0;t.addfile(ti,io.BytesIO(b))
 if not 1<=out.tell()<=2097152: raise SystemExit(38)
 os.write(1,out.getvalue())
finally: os.close(df)
'''


_REMOTE_CREATE_JOB_SCRIPT = r'''import os,stat,sys
p=sys.argv[1]; uid=int(sys.argv[2]); gid=int(sys.argv[3])
if not p.startswith("/") or ".." in p.split("/") or p=="/": raise SystemExit(40)
parts=[x for x in p.split("/") if x]
if not parts: raise SystemExit(41)
flags=os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW
fd=os.open("/",flags)
try:
 for part in parts[:-1]:
  nf=os.open(part,flags,dir_fd=fd); os.close(fd); fd=nf
 s=os.fstat(fd)
 if not stat.S_ISDIR(s.st_mode): raise SystemExit(42)
 if not (s.st_uid in (0,uid) and (stat.S_IMODE(s.st_mode)&0o022)==0):
  if not (s.st_uid==0 and stat.S_IMODE(s.st_mode)&stat.S_ISVTX and stat.S_IMODE(s.st_mode)&0o002): raise SystemExit(43)
 os.mkdir(parts[-1],0o700,dir_fd=fd)
 nf=os.open(parts[-1],flags,dir_fd=fd)
 try:
  os.fchown(nf,uid,gid); os.fchmod(nf,0o700); os.fsync(nf)
  s=os.fstat(nf)
  if s.st_uid!=uid or s.st_gid!=gid or stat.S_IMODE(s.st_mode)!=0o700: raise SystemExit(44)
 finally: os.close(nf)
 os.fsync(fd)
finally: os.close(fd)
print("created")
'''


_REMOTE_CHECK_DIRECTORY_SCRIPT = r'''import os,stat,sys
p=sys.argv[1]
if not p.startswith("/") or ".." in p.split("/"): raise SystemExit(45)
flags=os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW
fd=os.open("/",flags)
try:
 for part in [x for x in p.split("/") if x]:
  nf=os.open(part,flags,dir_fd=fd); os.close(fd); fd=nf
 s=os.fstat(fd)
 if not stat.S_ISDIR(s.st_mode): raise SystemExit(46)
finally: os.close(fd)
print("ok")
'''


_REMOTE_EXTRACT_SCRIPT = r'''import io,os,stat,sys,tarfile
root=sys.argv[1]; uid=int(sys.argv[2]); gid=int(sys.argv[3])
files={"worker.json":16384,"host.crt":65536,"host.key":1048576,"cohort-ca.crt":65536,"snapshot.pub":65536,"snapshot.json":65536}
flags=os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW
df=os.open("/",flags)
try:
 for part in [x for x in root.split("/") if x]:
  nf=os.open(part,flags,dir_fd=df); os.close(df); df=nf
 d=os.fstat(df)
 if d.st_uid!=uid or stat.S_IMODE(d.st_mode)!=0o700: raise SystemExit(50)
 if set(os.listdir(df))!={"worker.tar"}: raise SystemExit(54)
 f=os.open("worker.tar",os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=df)
 try:
  s=os.fstat(f)
  if not stat.S_ISREG(s.st_mode) or s.st_uid!=uid or stat.S_IMODE(s.st_mode)!=0o600 or s.st_nlink!=1 or not 1<=s.st_size<=2097152: raise SystemExit(51)
  b=os.read(f,2097153)
  if len(b)!=s.st_size: raise SystemExit(52)
  z=os.fstat(f)
  if (s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns)!=(z.st_dev,z.st_ino,z.st_size,z.st_mtime_ns): raise SystemExit(53)
 finally: os.close(f)
 parsed={}; sockets=False
 with tarfile.open(fileobj=io.BytesIO(b),mode="r:") as t:
  ms=t.getmembers()
  if len(ms)!=len(files)+1: raise SystemExit(54)
  for m in ms:
   if m.pax_headers or m.linkname or m.name.startswith("/") or "\\" in m.name or ".." in m.name.split("/"): raise SystemExit(55)
   normalized_name=m.name[:-1] if m.isdir() and m.name.endswith("/") else m.name
   if m.isdir() or m.name in {"sockets","sockets/"}:
    if (not m.isdir() or normalized_name!="sockets" or m.name not in {"sockets","sockets/"}
        or m.size!=0 or m.mode!=0o700 or sockets): raise SystemExit(56)
    sockets=True;continue
   if m.name not in files or not m.isfile() or m.mode!=0o600 or m.name in parsed or not 1<=m.size<=files[m.name]: raise SystemExit(57)
   q=t.extractfile(m)
   if q is None: raise SystemExit(58)
   x=q.read(m.size+1)
   if len(x)!=m.size: raise SystemExit(59)
   parsed[m.name]=x
 if set(parsed)!=set(files) or not sockets: raise SystemExit(60)
 os.mkdir("sockets",0o700,dir_fd=df)
 sd=os.open("sockets",flags,dir_fd=df)
 try: os.fchown(sd,uid,gid);os.fchmod(sd,0o700);os.fsync(sd)
 finally:os.close(sd)
 for n,x in parsed.items():
  out=os.open(n,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=df)
  try:
   os.fchown(out,uid,gid);os.fchmod(out,0o600);v=memoryview(x)
   while v:
    k=os.write(out,v)
    if k<=0:raise SystemExit(61)
    v=v[k:]
   os.fsync(out)
  finally:os.close(out)
 os.unlink("worker.tar",dir_fd=df);os.fsync(df)
finally:os.close(df)
print("extracted")
'''


_REMOTE_STATUS_SCRIPT = r'''import json,os,stat,sys,time
p=sys.argv[1]; uid=int(sys.argv[2]); mark=int(sys.argv[3]); wait=float(sys.argv[4])
if (not p.startswith("/") or len(p)>2048 or "\\" in p or "\x00" in p
    or "\n" in p or "\r" in p or p.startswith("//")):
 raise SystemExit(69)
parts=p.split("/")
if (len(parts)<3 or parts[0]!="" or parts[-1]!="status.json"
    or any(x in {"",".",".."} for x in parts[1:]) or not 0<=wait<=1):
 raise SystemExit(69)
flags=os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW
def unique_pairs(pairs):
 result={}
 for key,value in pairs:
  if key in result: raise ValueError("duplicate field")
  result[key]=value
 return result
def reject_constant(_value): raise ValueError("non-finite number")
df=os.open("/",flags)
try:
 for part in parts[1:-1]:
  try: nf=os.open(part,flags,dir_fd=df)
  except OSError: raise SystemExit(73)
  os.close(df);df=nf
 root_info=os.fstat(df)
 if (not stat.S_ISDIR(root_info.st_mode) or root_info.st_uid!=uid
     or stat.S_IMODE(root_info.st_mode)!=0o700): raise SystemExit(74)
 deadline=time.monotonic()+wait
 while True:
  try:
   f=os.open(parts[-1],os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=df)
   try:
    s=os.fstat(f)
    if (not stat.S_ISREG(s.st_mode) or s.st_uid!=uid
        or stat.S_IMODE(s.st_mode)!=0o600 or s.st_nlink!=1
        or not 1<=s.st_size<=4096): raise SystemExit(70)
    chunks=[]; total=0
    while total<s.st_size+1:
     block=os.read(f,min(4097-total,s.st_size+1-total))
     if not block: break
     chunks.append(block);total+=len(block)
    b=b"".join(chunks)
    if len(b)!=s.st_size: raise SystemExit(71)
    z=os.fstat(f)
    before=(s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns,s.st_uid,s.st_gid,s.st_mode,s.st_nlink)
    after=(z.st_dev,z.st_ino,z.st_size,z.st_mtime_ns,z.st_ctime_ns,z.st_uid,z.st_gid,z.st_mode,z.st_nlink)
    if before!=after: raise SystemExit(72)
   finally:os.close(f)
   if s.st_mtime_ns>mark:
    try: v=json.loads(b.decode("utf-8"),object_pairs_hook=unique_pairs,parse_constant=reject_constant)
    except (UnicodeError,ValueError,TypeError,RecursionError): raise SystemExit(75)
    print(json.dumps({"uid":s.st_uid,"mode":stat.S_IMODE(s.st_mode),"mtime_ns":s.st_mtime_ns,"mark_ns":mark,"status":v},sort_keys=True,separators=(",",":")))
    raise SystemExit(0)
  except FileNotFoundError: pass
  if time.monotonic()>=deadline:
   print(json.dumps({"fresh":False,"mark_ns":mark},separators=(",",":")));raise SystemExit(0)
  time.sleep(min(0.1,max(0.0,deadline-time.monotonic())))
finally:os.close(df)
'''


def _remote_remove_job_script(*, owner_profile=False) -> str:
    if type(owner_profile) is not bool:
        raise SupervisorError("remote_job_removal", "owner_profile")
    script = r'''import json,os,posixpath,re,stat,sys
root=sys.argv[1];uid=int(sys.argv[2]);gid=int(sys.argv[3])
result={"schema_version":1,"event":"remote_job_removal","job_root":root,"uid":uid,"gid":gid,"confirmed":False,"removed":[],"residuals":[],"residuals_known":False,"residuals_truncated":False,"reason":None}
file_limits={"worker.json":16384,"host.crt":65536,"host.key":1048576,"cohort-ca.crt":65536,"snapshot.pub":65536,"snapshot.json":65536,"status.json":4096,"worker.tar":2097152}
root_flags=os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|getattr(os,"O_CLOEXEC",0)
file_flags=os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|getattr(os,"O_CLOEXEC",0)
fds=[];root_fd=None;socket_fd=None
def emit():
 sys.stdout.write(json.dumps(result,sort_keys=True,separators=(",",":"))+"\n")
def names_at(fd,limit):
 out=[]
 with os.scandir(fd) as entries:
  for entry in entries:
   if len(out)>=limit:return sorted(out),True
   out.append(entry.name)
 return sorted(out),False
def residuals_now(fd):
 try:
  names,truncated=names_at(fd,65)
  result["residuals"]=names
  result["residuals_truncated"]=truncated
  result["residuals_known"]=True
 except OSError:
  result["residuals_known"]=False
try:
 if (not root.startswith("/") or root=="/" or posixpath.normpath(root)!=root or ".." in root.split("/") or "\\" in root or "\x00" in root):
  result["reason"]="root_path";emit();raise SystemExit(1)
 parts=root[1:].split("/")
 if not parts or len(parts)>16 or any(not p for p in parts):
  result["reason"]="root_path";emit();raise SystemExit(1)
 fds.append(os.open("/",root_flags))
 for part in parts[:-1]:
  nxt=os.open(part,root_flags,dir_fd=fds[-1]);fds.append(nxt)
 parent_fd=fds[-1]
 try:root_fd=os.open(parts[-1],root_flags,dir_fd=parent_fd)
 except FileNotFoundError:
  result["reason"]="root_missing";result["residuals_known"]=True;emit();raise SystemExit(1)
 root_info=os.fstat(root_fd)
 if (not stat.S_ISDIR(root_info.st_mode) or root_info.st_uid!=uid or root_info.st_gid!=gid or stat.S_IMODE(root_info.st_mode)!=0o700):
  result["reason"]="root_metadata";emit();raise SystemExit(1)
 names,truncated=names_at(root_fd,33)
 if truncated:
  result["reason"]="too_many_entries";result["residuals"]=names;result["residuals_known"]=True;result["residuals_truncated"]=True;emit();raise SystemExit(1)
 allowed=set(file_limits)|{"sockets"}
 socket_tmp=re.compile(r"\.status\.json\.[0-9a-f]{16}\.tmp\Z",re.ASCII)
 unknown=[n for n in names if n not in allowed and not socket_tmp.fullmatch(n)]
 if unknown:
  result["reason"]="unexpected_entries";result["residuals"]=names;result["residuals_known"]=True;emit();raise SystemExit(1)
 if "sockets" in names:
  socket_fd=os.open("sockets",root_flags,dir_fd=root_fd)
  si=os.fstat(socket_fd)
  if (not stat.S_ISDIR(si.st_mode) or si.st_uid!=uid or si.st_gid!=gid or stat.S_IMODE(si.st_mode)!=0o700):
   result["reason"]="sockets_metadata";result["residuals"]=names;result["residuals_known"]=True;emit();raise SystemExit(1)
  socket_names,socket_truncated=names_at(socket_fd,2)
  if socket_truncated or any(re.fullmatch(r"backend-[0-9a-f]{12}\.sock",n,re.ASCII) is None for n in socket_names):
   result["reason"]="unexpected_socket_entries";result["residuals"]=names;result["residuals_known"]=True;result["residuals_truncated"]=socket_truncated;emit();raise SystemExit(1)
  for n in socket_names:
   si=os.stat(n,dir_fd=socket_fd,follow_symlinks=False)
   if (not stat.S_ISSOCK(si.st_mode) or si.st_uid!=uid or si.st_gid!=gid or stat.S_IMODE(si.st_mode)&0o022):
    result["reason"]="unsafe_socket";result["residuals"]=names;result["residuals_known"]=True;emit();raise SystemExit(1)
 for n in names:
  if n=="sockets":continue
  limit=file_limits.get(n,4096)
  f=os.open(n,file_flags,dir_fd=root_fd)
  try:
   fi=os.fstat(f)
   if (not stat.S_ISREG(fi.st_mode) or fi.st_uid!=uid or fi.st_gid!=gid or stat.S_IMODE(fi.st_mode)!=0o600 or fi.st_nlink!=1 or not 0<=fi.st_size<=limit):
    result["reason"]="unsafe_file";result["residuals"]=names;result["residuals_known"]=True;emit();raise SystemExit(1)
  finally:os.close(f)
 for n in names:
  if n=="sockets":continue
  f=os.open(n,file_flags,dir_fd=root_fd)
  try:
   fi=os.fstat(f);now=os.stat(n,dir_fd=root_fd,follow_symlinks=False)
   if (not stat.S_ISREG(fi.st_mode) or (fi.st_dev,fi.st_ino)!=(now.st_dev,now.st_ino) or fi.st_uid!=uid or fi.st_gid!=gid or stat.S_IMODE(fi.st_mode)!=0o600 or fi.st_nlink!=1):
    result["reason"]="entry_changed";residuals_now(root_fd);emit();raise SystemExit(1)
   os.unlink(n,dir_fd=root_fd);result["removed"].append(n)
  finally:os.close(f)
 if socket_fd is not None:
  for n in socket_names:
   now=os.stat(n,dir_fd=socket_fd,follow_symlinks=False)
   if not stat.S_ISSOCK(now.st_mode) or now.st_uid!=uid or now.st_gid!=gid:
    result["reason"]="socket_changed";residuals_now(root_fd);emit();raise SystemExit(1)
   os.unlink(n,dir_fd=socket_fd);result["removed"].append("sockets/"+n)
  os.fsync(socket_fd);os.close(socket_fd);socket_fd=None
  os.rmdir("sockets",dir_fd=root_fd);result["removed"].append("sockets/")
 os.fsync(root_fd)
 current=os.stat(parts[-1],dir_fd=parent_fd,follow_symlinks=False)
 if (not stat.S_ISDIR(current.st_mode) or (current.st_dev,current.st_ino)!=(root_info.st_dev,root_info.st_ino)):
  result["reason"]="root_changed";residuals_now(root_fd);emit();raise SystemExit(1)
 os.rmdir(parts[-1],dir_fd=parent_fd);result["removed"].append(".");os.fsync(parent_fd)
 result["confirmed"]=True;result["residuals_known"]=True;result["reason"]=None;emit()
except SystemExit:
 raise
except FileNotFoundError:
 result["reason"]="entry_changed"
 if root_fd is not None:residuals_now(root_fd)
 emit()
 if not result["confirmed"]:raise SystemExit(1)
except OSError:
 result["reason"]="removal_failed"
 if root_fd is not None:residuals_now(root_fd)
 emit()
 if not result["confirmed"]:raise SystemExit(1)
finally:
 if socket_fd is not None:
  try:os.close(socket_fd)
  except OSError:pass
 if root_fd is not None:
  try:os.close(root_fd)
  except OSError:pass
 for fd in reversed(fds):
  try:os.close(fd)
  except OSError:pass
'''
    if owner_profile:
        marker = 'file_limits={"worker.json":16384,"host.crt":65536,"host.key":1048576,"cohort-ca.crt":65536,"snapshot.pub":65536,"snapshot.json":65536,"status.json":4096,"worker.tar":2097152}'
        owner_limits = marker[:-1] + ',"owner-command.json":16384,"owner-ack.json":16384}'
        if marker not in script:
            raise SupervisorError("remote_job_removal", "owner_allowlist_source")
        script = script.replace(marker, owner_limits, 1)
    return script


def _strict_local_path(path: str, *, must_exist: bool) -> Path:
    if type(path) is not str or not path or "\x00" in path:
        raise SupervisorError("arguments", "path")
    value = Path(path)
    if not value.is_absolute() or ".." in value.parts:
        raise SupervisorError("arguments", "absolute_path_required")
    if must_exist:
        try:
            info = value.lstat()
        except OSError:
            raise SupervisorError("arguments", "path_unavailable") from None
        if stat.S_ISLNK(info.st_mode):
            raise SupervisorError("arguments", "path_symlink")
    return value


def _remote_path(path: str, *, label: str) -> str:
    if (type(path) is not str or not path.startswith("/") or len(path) > 2048
            or "\x00" in path or "\n" in path or "\r" in path or "," in path
            or "\\" in path or ".." in path.split("/")
            or posixpath.normpath(path) != path or path == "/"):
        raise SupervisorError("arguments", label)
    return path


def _configured_endpoint(external_ip, external_port) -> str:
    if type(external_ip) is not str:
        raise SupervisorError("arguments", "external_ip")
    try:
        parsed = ipaddress.IPv4Address(external_ip)
    except ipaddress.AddressValueError:
        raise SupervisorError("arguments", "external_ip") from None
    private_networks = (
        ipaddress.IPv4Network("10.0.0.0/8"),
        ipaddress.IPv4Network("172.16.0.0/12"),
        ipaddress.IPv4Network("192.168.0.0/16"),
    )
    if (str(parsed) != external_ip
            or not any(parsed in network for network in private_networks)
            or parsed.is_loopback or parsed.is_unspecified
            or parsed.is_multicast or parsed.is_reserved):
        raise SupervisorError("arguments", "external_ip")
    if type(external_port) is not int or external_port != REMOTE_PORT:
        raise SupervisorError("arguments", "external_port")
    return f"{external_ip}:{external_port}"


def validate_cli(args) -> None:
    profile = getattr(args, "profile", PROFILE_BASELINE)
    _profile_observation_cases(profile)
    if _IMAGE.fullmatch(args.local_image) is None or _IMAGE.fullmatch(args.remote_image) is None:
        raise SupervisorError("arguments", "image")
    for name in ("artifacts_volume", "reference_volume"):
        if _VOLUME.fullmatch(getattr(args, name)) is None:
            raise SupervisorError("arguments", name)
    if args.artifacts_volume == args.reference_volume:
        raise SupervisorError("arguments", "volume_alias")
    if _HOST.fullmatch(args.ssh_host) is None or _USER.fullmatch(args.ssh_user) is None:
        raise SupervisorError("arguments", "ssh_identity")
    _configured_endpoint(args.external_ip, args.external_port)
    uncertainty = args.uncertainty_seconds
    if (type(uncertainty) not in (int, float) or not math.isfinite(uncertainty)
            or not 0 < uncertainty <= 30):
        raise SupervisorError("arguments", "clock_uncertainty")
    if bool(args.ssh_password_file) == bool(args.ssh_key_file):
        raise SupervisorError("arguments", "one_ssh_credential_required")
    args.known_hosts = _strict_local_path(args.known_hosts, must_exist=True)
    args.ssh_password_file = (_strict_local_path(args.ssh_password_file, must_exist=True)
                              if args.ssh_password_file else None)
    args.ssh_key_file = (_strict_local_path(args.ssh_key_file, must_exist=True)
                         if args.ssh_key_file else None)
    args.remote_artifacts = _remote_path(args.remote_artifacts, label="remote_artifacts")
    args.remote_job_root = _remote_path(args.remote_job_root, label="remote_job_root")
    if args.remote_job_root == args.remote_artifacts:
        raise SupervisorError("arguments", "remote_path_alias")
    args.result_directory = _strict_local_path(args.result_directory, must_exist=False)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--local-image", required=True)
    parser.add_argument("--remote-image", required=True)
    parser.add_argument("--ssh-host", required=True)
    parser.add_argument("--ssh-user", required=True)
    parser.add_argument("--known-hosts", required=True)
    credentials = parser.add_mutually_exclusive_group(required=True)
    credentials.add_argument("--ssh-password-file")
    credentials.add_argument("--ssh-key-file")
    parser.add_argument("--artifacts-volume", required=True)
    parser.add_argument("--reference-volume", required=True)
    parser.add_argument("--remote-artifacts", required=True)
    parser.add_argument("--remote-job-root", required=True)
    parser.add_argument("--result-directory", required=True)
    parser.add_argument("--uncertainty-seconds", type=float, required=True)
    parser.add_argument("--external-ip", required=True)
    parser.add_argument("--external-port", type=int, default=REMOTE_PORT)
    parser.add_argument("--profile", choices=tuple(_PROFILE_OBSERVATIONS),
                        default=PROFILE_BASELINE)
    return parser


def _read_secret_file(path: Path) -> str:
    try:
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode) or not 1 <= info.st_size <= 16 * 1024:
            raise SupervisorError("ssh_credential", "file_metadata")
        raw = path.read_bytes()
    except SupervisorError:
        raise
    except OSError:
        raise SupervisorError("ssh_credential", "unavailable") from None
    if len(raw) != info.st_size or len(raw) > 16 * 1024:
        raise SupervisorError("ssh_credential", "file_size")
    try:
        value = raw.decode("utf-8", "strict").rstrip("\r\n")
    except UnicodeError:
        raise SupervisorError("ssh_credential", "encoding") from None
    if not value or "\x00" in value:
        raise SupervisorError("ssh_credential", "empty_or_invalid")
    return value


def _load_paramiko_key(paramiko, key_text: str):
    for name in ("Ed25519Key", "ECDSAKey", "RSAKey"):
        cls = getattr(paramiko, name, None)
        if cls is None:
            continue
        try:
            return cls.from_private_key(io.StringIO(key_text))
        except Exception:
            continue
    raise SupervisorError("ssh_credential", "unsupported_private_key")


def _close_ssh_client(client) -> None:
    try:
        client.close()
    except Exception:
        pass


def _deadline_remaining(deadline: float, stage: str) -> float:
    if type(deadline) not in (int, float):
        raise SupervisorError(stage, "deadline")
    try:
        absolute = float(deadline)
    except (OverflowError, ValueError):
        raise SupervisorError(stage, "deadline") from None
    if not math.isfinite(absolute):
        raise SupervisorError(stage, "deadline")
    remaining = absolute - time.monotonic()
    if remaining <= 0:
        raise SupervisorError(stage, "deadline")
    return remaining


_CHANNEL_OPERATION_LOCK = threading.Lock()
_CHANNEL_OPERATION_OWNERS = {}
_CHANNEL_OPERATION_BY_CHANNEL = {}
_CHANNEL_OPERATION_OWNER_LIMIT = 16
_CHANNEL_ABORT_OWNER_LIMIT = _CHANNEL_OPERATION_OWNER_LIMIT + 1


def _pending_channel_operation_count() -> int:
    with _CHANNEL_OPERATION_LOCK:
        return len(_CHANNEL_OPERATION_OWNERS)


def _pending_channel_operation_evidence() -> tuple[dict, ...]:
    """Return bounded, sanitized state for operations still owning channels."""
    with _CHANNEL_OPERATION_LOCK:
        records = [
            {
                "stage": owner["stage"],
                "state": owner["state"],
                "failure_code": owner["failure_code"],
                "close_started": owner["close_started"],
            }
            for owner in _CHANNEL_OPERATION_OWNERS.values()
        ]
    return tuple(sorted(records, key=lambda item: (item["stage"], item["state"])))


def _channel_operation_owned(channel) -> bool:
    """Whether an operation or its abort/reaper still owns this channel."""
    with _CHANNEL_OPERATION_LOCK:
        return id(channel) in _CHANNEL_OPERATION_BY_CHANNEL


def _abort_channel(channel) -> None:
    """Start one owned close without waiting on a possibly stalled peer.

    The extra slot is reserved for aborting a channel whose setup failed before
    an ordinary operation acquired ownership. New operations remain capped at
    sixteen; the abort and its reaper retain the channel until the close thread
    actually exits. An existing owner already supplies its own close/reaper.
    """
    channel_id = id(channel)
    with _CHANNEL_OPERATION_LOCK:
        if channel_id in _CHANNEL_OPERATION_BY_CHANNEL:
            return
        if len(_CHANNEL_OPERATION_OWNERS) >= _CHANNEL_ABORT_OWNER_LIMIT:
            raise SupervisorError("transport_abort", "request_owner_capacity")
        owner = {
            "channel": channel, "channel_id": channel_id,
            "stage": "transport_abort", "state": "unknown_pending_retirement",
            "failure_code": "abort_pending", "close_started": True,
            "close_succeeded": False,
            "thread": None, "closer": None,
        }
        _CHANNEL_OPERATION_OWNERS[id(owner)] = owner
        _CHANNEL_OPERATION_BY_CHANNEL[channel_id] = owner

        def close_channel():
            try:
                channel.close()
                owner["close_succeeded"] = True
            except BaseException:
                owner["failure_code"] = "abort_close_failed"

        thread = threading.Thread(target=close_channel,
                                  name="steamboat-channel-abort", daemon=True)
        owner["thread"] = thread

        def reap_close():
            thread.join()
            with _CHANNEL_OPERATION_LOCK:
                if not owner["close_succeeded"]:
                    owner["state"] = "close_failed_unconfirmed"
                    owner["thread"] = None
                    owner["closer"] = None
                    return
                owner["channel"] = None
                owner["thread"] = None
                owner["closer"] = None
                _CHANNEL_OPERATION_OWNERS.pop(id(owner), None)
                if _CHANNEL_OPERATION_BY_CHANNEL.get(channel_id) is owner:
                    _CHANNEL_OPERATION_BY_CHANNEL.pop(channel_id, None)

        reaper = threading.Thread(target=reap_close,
                                  name="steamboat-channel-abort-reaper", daemon=True)
        owner["closer"] = reaper
        try:
            thread.start()
            reaper.start()
        except RuntimeError:
            # Retain even an unstarted/unjointed owner. Capacity and evidence
            # stay fenced rather than manufacturing a confirmed retirement.
            owner["failure_code"] = "abort_start_failed"
            raise SupervisorError("transport_abort", "abort_start_failed") from None


def _channel_operation(channel, operation, *, deadline: float, stage: str,
                       failure_code: str):
    """Run a Paramiko operation whose acknowledgement wait ignores socket timeouts."""
    _deadline_remaining(deadline, stage)
    channel_id = id(channel)
    owner = {
        "channel": channel,
        "channel_id": channel_id,
        "stage": stage,
        "state": "running",
        "failure_code": None,
        "operation_done": threading.Event(),
        "decision_done": False,
        "operation_retired": False,
        "close_started": False,
        "close_done": False,
        "outcome": None,
        "thread": None,
        "closer": None,
        "reaper": None,
        "close_succeeded": False,
    }
    with _CHANNEL_OPERATION_LOCK:
        _deadline_remaining(deadline, stage)
        if channel_id in _CHANNEL_OPERATION_BY_CHANNEL:
            raise SupervisorError(stage, "operation_ownership_pending")
        if len(_CHANNEL_OPERATION_OWNERS) >= _CHANNEL_OPERATION_OWNER_LIMIT:
            raise SupervisorError(stage, "request_owner_capacity")
        _CHANNEL_OPERATION_OWNERS[id(owner)] = owner
        _CHANNEL_OPERATION_BY_CHANNEL[channel_id] = owner

    def retire_owner_if_safe():
        if (owner["decision_done"] and owner["operation_retired"]
                and (not owner["close_started"] or owner["close_done"])):
            owner["channel"] = None
            owner["thread"] = None
            owner["closer"] = None
            owner["reaper"] = None
            _CHANNEL_OPERATION_OWNERS.pop(id(owner), None)
            if _CHANNEL_OPERATION_BY_CHANNEL.get(owner["channel_id"]) is owner:
                _CHANNEL_OPERATION_BY_CHANNEL.pop(owner["channel_id"], None)

    def run_operation():
        try:
            owner["outcome"] = ("success", operation())
        except SupervisorError as error:
            owner["outcome"] = ("supervisor", error.stage, error.code)
        except (socket.timeout, TimeoutError):
            owner["outcome"] = ("timeout",)
        except BaseException:
            owner["outcome"] = ("failure",)
        finally:
            owner["operation_done"].set()

    operation_thread = threading.Thread(
        target=run_operation, name="steamboat-paramiko-request", daemon=True)
    owner["thread"] = operation_thread

    def discard_unstarted_owner():
        with _CHANNEL_OPERATION_LOCK:
            owner["decision_done"] = True
            owner["operation_retired"] = True
            owner["outcome"] = None
            retire_owner_if_safe()

    try:
        _deadline_remaining(deadline, stage)
        operation_thread.start()
    except SupervisorError:
        discard_unstarted_owner()
        raise
    except RuntimeError:
        discard_unstarted_owner()
        raise SupervisorError(stage, "request_start_failed") from None

    def expire_request():
        def close_and_reap():
            try:
                channel.close()
                owner["close_succeeded"] = True
            except BaseException:
                pass
            operation_thread.join()

        def reap_abort():
            closer.join()
            with _CHANNEL_OPERATION_LOCK:
                owner["operation_retired"] = True
                owner["close_done"] = owner["close_succeeded"]
                owner["state"] = ("retired_after_abort" if owner["close_succeeded"]
                                  else "close_failed_unconfirmed")
                if not owner["close_succeeded"]:
                    owner["failure_code"] = "abort_close_failed"
                owner["outcome"] = None
                retire_owner_if_safe()

        with _CHANNEL_OPERATION_LOCK:
            owner["close_started"] = True
            owner["state"] = "unknown_pending_retirement"
            owner["failure_code"] = "ack_timeout_unknown"
            closer = threading.Thread(
                target=close_and_reap,
                name="steamboat-paramiko-request-close",
                daemon=True,
            )
            owner["closer"] = closer
            reaper = threading.Thread(
                target=reap_abort, name="steamboat-paramiko-abort-reaper", daemon=True)
            owner["reaper"] = reaper
            try:
                closer.start()
                reaper.start()
            except RuntimeError:
                owner["failure_code"] = "abort_start_failed"
                owner["decision_done"] = True
                retire_owner_if_safe()
                raise SupervisorError(stage, "ack_timeout_unknown") from None
            owner["decision_done"] = True
            retire_owner_if_safe()
        raise SupervisorError(stage, "ack_timeout_unknown") from None

    try:
        wait_budget = _deadline_remaining(deadline, stage)
    except SupervisorError:
        expire_request()
    if not owner["operation_done"].wait(wait_budget):
        expire_request()
    remaining_after_wait = deadline - time.monotonic()
    if remaining_after_wait > 0:
        operation_thread.join(remaining_after_wait)
    if operation_thread.is_alive() or time.monotonic() >= deadline:
        expire_request()

    outcome = owner["outcome"]
    with _CHANNEL_OPERATION_LOCK:
        owner["decision_done"] = True
        owner["operation_retired"] = True
        owner["outcome"] = None
        retire_owner_if_safe()
    if outcome[0] == "success":
        return outcome[1]
    if outcome[0] == "supervisor":
        raise SupervisorError(outcome[1], outcome[2])
    if outcome[0] == "timeout":
        raise SupervisorError(stage, "timeout") from None
    raise SupervisorError(stage, failure_code) from None


def _connect_ssh(args, deadline: float | None = None):
    """Connect using a caller-owned absolute monotonic deadline."""
    _deadline_remaining(deadline, "ssh")
    try:
        import paramiko
    except ImportError:
        raise SupervisorError("ssh", "paramiko_unavailable") from None
    client = paramiko.SSHClient()
    try:
        _deadline_remaining(deadline, "ssh")
        client.load_host_keys(str(args.known_hosts))
        _deadline_remaining(deadline, "ssh")
        client.set_missing_host_key_policy(paramiko.RejectPolicy())
        credentials = {}
        if args.ssh_password_file is not None:
            _deadline_remaining(deadline, "ssh")
            credentials["password"] = _read_secret_file(args.ssh_password_file)
        else:
            _deadline_remaining(deadline, "ssh")
            credentials["pkey"] = _load_paramiko_key(
                paramiko, _read_secret_file(args.ssh_key_file))
        _deadline_remaining(deadline, "ssh")
        connected = threading.Event()
        state_lock = threading.Lock()
        cancelled = [False]
        outcome = {}

        def connect_with_deadline():
            try:
                connect_budget = _deadline_remaining(deadline, "ssh")
                client.connect(
                    args.ssh_host, port=22, username=args.ssh_user,
                    timeout=min(connect_budget, 8.0),
                    banner_timeout=min(connect_budget, 8.0),
                    auth_timeout=min(connect_budget, 8.0),
                    channel_timeout=min(connect_budget, 8.0),
                    allow_agent=False, look_for_keys=False, **credentials)
            except BaseException as error:
                outcome["error"] = error
            finally:
                with state_lock:
                    must_close = cancelled[0]
                if must_close:
                    _close_ssh_client(client)
                connected.set()

        connect_thread = threading.Thread(target=connect_with_deadline,
                                          name="secure-cohort-ssh-connect",
                                          daemon=True)
        connect_thread.start()
        try:
            wait_budget = _deadline_remaining(deadline, "ssh")
        except SupervisorError:
            with state_lock:
                cancelled[0] = True
            _close_ssh_client(client)
            raise
        if not connected.wait(wait_budget):
            with state_lock:
                cancelled[0] = True
            _close_ssh_client(client)
            raise SupervisorError("ssh", "deadline")
        _deadline_remaining(deadline, "ssh")
        if "error" in outcome:
            if (isinstance(outcome["error"], SupervisorError)
                    and outcome["error"].code == "deadline"):
                raise SupervisorError("ssh", "deadline") from None
            if isinstance(outcome["error"], socket.timeout):
                raise SupervisorError("ssh", "connection_timeout") from None
            raise SupervisorError("ssh", "connection_failed") from None
        transport = client.get_transport()
        key = transport.get_remote_server_key() if transport is not None else None
        if key is None:
            raise SupervisorError("ssh", "host_key_unavailable")
        fingerprint = hashlib.sha256(key.asbytes()).hexdigest()
        if _HEX64.fullmatch(fingerprint) is None:
            raise SupervisorError("ssh", "host_key_fingerprint")
        _deadline_remaining(deadline, "ssh")
        return client, fingerprint, credentials.get("password")
    except SupervisorError:
        _close_ssh_client(client)
        raise
    except socket.timeout:
        _close_ssh_client(client)
        raise SupervisorError("ssh", "connection_timeout") from None
    except Exception:
        _close_ssh_client(client)
        raise SupervisorError("ssh", "connection_failed") from None


def _read_stream_limited(stream, limit, box):
    chunks = []
    total = 0
    while True:
        part = stream.read(65536)
        if not part:
            break
        if total < limit + 1:
            keep = part[:limit + 1 - total]
            if keep:
                chunks.append(keep)
        total += len(part)
    box["data"] = b"".join(chunks)
    box["overflow"] = total > limit


def _local_command(argv, *, timeout: float, stdout_limit=4096,
                   input_bytes: bytes | None = None) -> tuple[int, bytes]:
    if not argv or any(type(arg) is not str or "\x00" in arg for arg in argv):
        raise SupervisorError("local_process", "argv")
    try:
        process = subprocess.Popen(argv, stdin=subprocess.PIPE if input_bytes is not None else subprocess.DEVNULL,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   shell=False)
    except OSError:
        raise SupervisorError("local_process", "start_failed") from None
    out_box, err_box = {}, {}
    out_thread = threading.Thread(target=_read_stream_limited,
                                  args=(process.stdout, stdout_limit, out_box), daemon=True)
    err_thread = threading.Thread(target=_read_stream_limited,
                                  args=(process.stderr, STDERR_LIMIT, err_box), daemon=True)
    out_thread.start()
    err_thread.start()
    writer_error = []
    if input_bytes is not None:
        def write_input():
            try:
                process.stdin.write(input_bytes)
                process.stdin.flush()
            except (BrokenPipeError, OSError):
                writer_error.append(True)
            finally:
                try:
                    process.stdin.close()
                except OSError:
                    pass
        writer = threading.Thread(target=write_input, daemon=True)
        writer.start()
    else:
        writer = None
    try:
        code = process.wait(timeout=max(0.1, timeout))
    except subprocess.TimeoutExpired:
        process.kill()
        try:
            process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            pass
        raise SupervisorError("local_process", "timeout") from None
    if writer is not None:
        writer.join(timeout=2)
    out_thread.join(timeout=2)
    err_thread.join(timeout=2)
    if out_thread.is_alive() or err_thread.is_alive():
        raise SupervisorError("local_process", "output_reader_stuck")
    if out_box.get("overflow") or err_box.get("overflow"):
        raise SupervisorError("local_process", "output_bound")
    return code, out_box.get("data", b"")


def _local_docker(argv, *, deadline: float, output=4096, input_bytes=None,
                  allowed_codes=(0,)) -> bytes:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise SupervisorError("local_docker", "deadline")
    code, out = _local_command(argv, timeout=min(remaining, 30.0),
                               stdout_limit=output, input_bytes=input_bytes)
    if code not in allowed_codes:
        raise SupervisorError("local_docker", "command_failed")
    return out


def _read_local_handoff(cid: str, name: str, deadline: float, *, missing_ok=False,
                        maximum=CONTROL_LIMIT) -> bytes | None:
    if name not in _CONTROL_REQUESTS | _CONTROL_RESPONSES | {
            "result.json", "operator-exit.json", _FAILURE_LOCATION_FILE}:
        raise SupervisorError("local_handoff", "filename")
    if name == _FAILURE_LOCATION_FILE:
        maximum = min(maximum, FAILURE_LOCATION_LIMIT)
    argv = ["docker", "exec", cid, "python", "-c", _LOCAL_READ_SCRIPT, name]
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise SupervisorError("local_handoff", "deadline")
    code, out = _local_command(argv, timeout=min(remaining, 10.0), stdout_limit=maximum)
    if code == 3 and missing_ok:
        return None
    if code != 0:
        if name == _FAILURE_LOCATION_FILE and code in {22, 23, 24}:
            raise SupervisorError("cohort_failure_location", "untrusted_file")
        raise SupervisorError("local_handoff", "read_failed")
    return out


def _read_local_owner_archive(cid: str, deadline: float) -> bytes:
    """Read only the fixed, bounded public owner TAR through its protected helper."""
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise SupervisorError("owner_materials", "deadline")
    code, raw = _local_command(
        ["docker", "exec", cid, "python", "-c", _LOCAL_READ_OWNER_ARCHIVE_SCRIPT],
        timeout=min(remaining, 10.0), stdout_limit=OWNER_ARCHIVE_LIMIT)
    if code != 0 or not 1 <= len(raw) <= OWNER_ARCHIVE_LIMIT:
        raise SupervisorError("owner_materials", "archive_read_failed")
    return raw


def _write_local_handoff(cid: str, name: str, value: dict, deadline: float) -> None:
    if name not in _CONTROL_RESPONSES | {"supervisor-release.json"}:
        raise SupervisorError("local_handoff", "response_filename")
    raw = _json_bytes(value)
    argv = ["docker", "exec", "-i", cid, "python", "-c", _LOCAL_WRITE_SCRIPT, name]
    _local_docker(argv, deadline=deadline, output=128, input_bytes=raw)


def _terminal_controls(cid: str, target: str, deadline: float,
                       ready: dict | None = None) -> None:
    """Raise immediately when the cohort has moved to its terminal path."""
    if target != "stop-request.json":
        stop_raw = _read_local_handoff(cid, "stop-request.json", deadline,
                                       missing_ok=True)
        if stop_raw is not None:
            stop_request = None
            if ready is not None:
                stop_request = _validate_stop_request(
                    _json_load(stop_raw, CONTROL_LIMIT, label="stop_request"), ready)
            error = SupervisorError("cohort_control", "stop_requested")
            # Preserve only the already schema-checked control fields.  The
            # caller uses this to enter the normal bounded shutdown path.
            error.stop_request = stop_request
            raise error
    if target not in {"operator-exit.json", "result.json"}:
        exit_raw = _read_local_handoff(cid, "operator-exit.json", deadline,
                                       missing_ok=True, maximum=4096)
        if exit_raw is not None:
            raise SupervisorError("cohort_control", "operator_exited")


def _wait_local_json(cid: str, name: str, deadline: float, *, label: str,
                     ready: dict | None = None) -> dict:
    while time.monotonic() < deadline:
        _terminal_controls(cid, name, deadline, ready)
        raw = _read_local_handoff(cid, name, deadline, missing_ok=True)
        if raw is not None:
            return _json_load(raw, CONTROL_LIMIT, label=label)
        time.sleep(min(0.2, max(0.0, deadline - time.monotonic())))
    raise SupervisorError(label, "timeout")


def _wait_observation_request(cid: str, sequence: int, ready: dict,
                             deadline: float,
                             profile: str = PROFILE_BASELINE) -> dict:
    """Stop waiting promptly if the cohort terminates before the next sample."""
    cases = _profile_observation_cases(profile)
    if sequence not in cases:
        raise SupervisorError("observation_request", "out_of_profile_sequence")
    request_name = f"observation-request-{sequence}.json"
    while time.monotonic() < deadline:
        _terminal_controls(cid, request_name, deadline, ready)
        raw = _read_local_handoff(cid, request_name, deadline, missing_ok=True)
        if raw is not None:
            return _validate_observation(
                _json_load(raw, CONTROL_LIMIT, label="observation_request"),
                ready, sequence, profile)
        time.sleep(min(0.15, max(0.0, deadline - time.monotonic())))
    raise SupervisorError("observation_request", "timeout")


def _wait_owner_action_request(cid: str, number: int, expected: OwnerExpectation,
                               deadline: float) -> tuple[dict, object]:
    if type(number) is not int or number not in (1, 2):
        raise SupervisorError("owner_action_request", "sequence")
    name = f"owner-action-request-{number}.json"
    while time.monotonic() < deadline:
        _terminal_controls(cid, name, deadline)
        raw = _read_local_handoff(cid, name, deadline, missing_ok=True,
                                  maximum=OWNER_CONTROL_LIMIT)
        if raw is not None:
            try:
                value = _json_load(raw, OWNER_CONTROL_LIMIT, label="owner_action_request")
                command = validate_owner_action_request(value, expected)
            except (SupervisorError, ValueError, TypeError):
                raise SupervisorError("owner_action_request", "invalid") from None
            if value["command_number"] != number:
                raise SupervisorError("owner_action_request", "unexpected_sequence")
            return value, command
        time.sleep(min(0.1, max(0.0, deadline - time.monotonic())))
    raise SupervisorError("owner_action_request", "timeout")


def _owner_initial_context(profile: str, ready: dict, config: dict,
                           bundle_files: dict[str, bytes]):
    """Verify the bundled initial policy and derive its fixed owner pins."""
    from steamboat_security.clock import Clock
    from steamboat_security.snapshot import SnapshotStore

    try:
        uncertainty = float(config["clock_uncertainty_seconds"])
        clock = Clock.system(uncertainty_seconds=lambda: uncertainty)
        store = SnapshotStore(
            verification_key_pem=bundle_files["snapshot.pub"],
            ca_certificate_pem=bundle_files["cohort-ca.crt"], clock=clock)
        view = store.install(bundle_files["snapshot.json"])
    except Exception:
        raise SupervisorError("owner_initial_policy", "verification_failed") from None
    if (hashlib.sha256(bundle_files["snapshot.json"]).hexdigest()
            != ready["snapshot_sha256"] or type(view.revision) is not int
            or view.revision < 1 or not view.policy_digest):
        raise SupervisorError("owner_initial_policy", "pin_mismatch")
    serials = sorted(
        serial for serial, record in view.credentials_by_serial.items()
        if record.device_id == config["device_id"])
    if not serials or len(serials) > 16 or len(serials) != len(set(serials)):
        raise SupervisorError("owner_initial_policy", "local_serials")
    try:
        expected = OwnerExpectation(
            profile=profile, run_id=ready["run_id"], nonce=ready["nonce"],
            worker_boot_id=ready["expected_boot_id"],
            manifest_fingerprint=ready["manifest_fingerprint"],
            endpoint=ready["endpoint"], initial_snapshot_sha256=ready["snapshot_sha256"],
            initial_revision=view.revision)
    except (ValueError, TypeError):
        raise SupervisorError("owner_initial_policy", "expectation") from None
    return expected, clock, store, view, serials


def _verify_owner_signed_intent(raw: bytes, command, expected_key_pem: bytes) -> dict:
    """Verify one canonical existing-key intent against its exact command."""
    import base64
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    from lab import secure_cohort_owner as owner_protocol

    try:
        envelope = owner_protocol._strict_loads(raw, maximum=OWNER_INTENT_LIMIT)
        owner_protocol._exact_fields(
            envelope, {"schema_version", "event", "intent", "signature"},
            "signed owner intent")
        intent = envelope["intent"]
        if (type(envelope["schema_version"]) is not int
                or envelope["schema_version"] != 1
                or envelope["event"] != "signed_owner_removal_intent"
                or type(intent) is not dict
                or owner_protocol._canonical_bytes(intent, maximum=OWNER_INTENT_LIMIT)
                   != owner_protocol._canonical_bytes(
                       owner_protocol._intent_document(command),
                       maximum=OWNER_INTENT_LIMIT)
                or raw != owner_protocol._canonical_bytes(
                    envelope, maximum=OWNER_INTENT_LIMIT)
                or type(envelope["signature"]) is not str):
            raise ValueError
        signature = base64.b64decode(envelope["signature"], validate=True)
        if not (8 <= len(signature) <= 80
                and base64.b64encode(signature).decode("ascii") == envelope["signature"]):
            raise ValueError
        key = serialization.load_pem_public_key(expected_key_pem)
        if not isinstance(key, ec.EllipticCurvePublicKey) or not isinstance(key.curve, ec.SECP256R1):
            raise ValueError
        canonical = owner_protocol._canonical_bytes(intent, maximum=OWNER_INTENT_LIMIT)
        key.verify(signature, b"steamboat-owner-removal-intent-v1\x00" + canonical,
                   ec.ECDSA(hashes.SHA256()))
    except (ValueError, TypeError, InvalidSignature, Exception):
        # Keep parser and crypto details out of the operator result.
        raise SupervisorError("owner_intent", "verification_failed") from None
    return intent


def _verify_owner_material_bundle(expected: OwnerExpectation, wrapper_value: dict,
                                  archive: bytes, *, initial_view, snapshot_store,
                                  verifier_pem: bytes, initial_local_serials: list[str],
                                  initial_device_id: str):
    """Bind archive snapshots and signatures to the protected initial policy."""
    try:
        wrapper = validate_owner_materials_ready(wrapper_value, expected)
        files = validate_owner_material_archive(archive, wrapper, expected)
        policies = (files["install-snapshot.json"], files["remove-snapshot.json"])
        views = tuple(snapshot_store.install(raw) for raw in policies)
        if (views[0].revision != expected.initial_revision + 1
                or views[1].revision != expected.initial_revision + 2
                or any(view.policy_digest is None for view in views)):
            raise ValueError
        # The independently verified staged snapshots must revoke the exact
        # initial worker-3 device and every initially pinned local serial.
        if (type(initial_device_id) is not str
                or not any(record.device_id == initial_device_id
                           for record in initial_view.credentials_by_serial.values())):
            raise ValueError
        serial_set = set(initial_local_serials)
        for view in views:
            if (initial_device_id not in view.revoked_devices
                    or not serial_set.issubset(view.revoked_serials)
                    or serial_set.intersection(view.credentials_by_serial)
                    or any(grant.device_id == initial_device_id
                           or grant.target_device_id == initial_device_id
                           for grant in view.grants)):
                raise ValueError
        return wrapper, files, views
    except SupervisorError:
        raise
    except Exception:
        raise SupervisorError("owner_materials", "validation_failed") from None


def _docker_inspect_local(cid: str, *, name: str, owner: str, role: str,
                          image: str, deadline: float) -> dict:
    raw = _local_docker(_container_inspect_argv(cid), deadline=deadline, output=4096)
    try:
        text = raw.decode("ascii", "strict").strip()
    except UnicodeError:
        raise SupervisorError("container", "inspect_encoding") from None
    state = verify_container_inspect(text, cid=cid, name=name,
                                     owner_label=owner, role=role, image=image)
    return state


def _create_results_dir(path: Path) -> Path:
    try:
        path.mkdir(parents=True, exist_ok=True)
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            raise SupervisorError("result_directory", "not_private_directory")
        if os.name == "posix":
            os.chmod(path, 0o700)
        return path.resolve(strict=True)
    except SupervisorError:
        raise
    except OSError:
        raise SupervisorError("result_directory", "unavailable") from None


def _write_result(directory: Path, filename: str, value: dict) -> Path:
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,100}", filename, re.ASCII):
        raise SupervisorError("result", "filename")
    raw = _json_bytes(value, 128 * 1024)
    path = directory / filename
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags, 0o600)
        try:
            if os.name == "posix":
                os.fchmod(fd, 0o600)
            view = memoryview(raw)
            while view:
                count = os.write(fd, view)
                if count <= 0:
                    raise OSError("short write")
                view = view[count:]
            os.fsync(fd)
        finally:
            os.close(fd)
        return path
    except FileExistsError:
        raise SupervisorError("result", "already_exists") from None
    except OSError:
        raise SupervisorError("result", "write_failed") from None


def _validate_result_record(value: dict) -> dict:
    if not set(value) <= _RESULT_FIELDS:
        raise SupervisorError("cohort_result", "unknown_fields")
    if type(value.get("schema_version")) is not int or value["schema_version"] != 1:
        raise SupervisorError("cohort_result", "version")
    if value.get("event") != "result":
        raise SupervisorError("cohort_result", "event")
    if type(value.get("run_id")) is not str or _HEX32.fullmatch(value["run_id"]) is None:
        raise SupervisorError("cohort_result", "run_id")
    baseline = value.get("baseline")
    if type(baseline) is not dict or baseline.get("status") not in {"passed", "failed"}:
        raise SupervisorError("cohort_result", "baseline")
    ids = value.get("request_ids")
    sessions = value.get("session_ids")
    if (type(ids) is not list or len(ids) > 4 or any(type(x) is not str or _TYPED_REQUEST.fullmatch(x) is None for x in ids)
            or type(sessions) is not list or len(sessions) > 4
            or any(type(x) is not str or _TYPED_SESSION.fullmatch(x) is None for x in sessions)):
        raise SupervisorError("cohort_result", "ids")
    return value


def _finite_nonnegative_number(value) -> bool:
    if type(value) not in (int, float):
        return False
    try:
        return math.isfinite(value) and value >= 0
    except (OverflowError, ValueError):
        return False


def _sanitize_happy_cohort_result(value: dict) -> dict:
    _validate_result_record(value)
    if any(key in value for key in (
            "interleave", "cancellation", "partial_admission", "step_reply_loss",
            "capacity", "restart")):
        raise SupervisorError("cohort_result", "profile_mismatch")
    baseline = value["baseline"]
    numerical = value.get("numerical_errors")
    numerical_fields = {
        "captured_vectors", "max_absolute_error", "values", "atol", "rtol",
    }
    if (baseline.get("status") != "passed"
            or type(baseline.get("completed_requests")) is not int
            or baseline["completed_requests"] != 4
            or type(baseline.get("captured_vectors")) is not int
            or baseline["captured_vectors"] != 27
            or type(numerical) is not dict
            or set(numerical) != numerical_fields
            or type(numerical.get("captured_vectors")) is not int
            or numerical["captured_vectors"] != 27
            or type(numerical.get("values")) is not list
            or len(numerical["values"]) != 27
            or any(not _finite_nonnegative_number(item) or item > 1e-3
                   for item in numerical["values"])
            or not _finite_nonnegative_number(numerical.get("max_absolute_error"))
            or numerical["max_absolute_error"] != max(numerical["values"])
            or numerical["max_absolute_error"] > 1e-3
            or type(numerical.get("atol")) not in (int, float)
            or numerical["atol"] != 1e-3
            or type(numerical.get("rtol")) not in (int, float)
            or numerical["rtol"] != 0.0):
        raise SupervisorError("cohort_result", "happy_baseline_numerics")

    baseline_requests = value["request_ids"]
    baseline_sessions = value["session_ids"]
    if (len(baseline_requests) != 4 or len(set(baseline_requests)) != 4
            or len(baseline_sessions) != 4 or len(set(baseline_sessions)) != 4):
        raise SupervisorError("cohort_result", "happy_baseline_ids")

    cases = value.get("cases")
    expected_case_ids = [
        "greedy-one-token", "forced-length-1", "forced-length-128",
        "forced-length-1024", _PROFILE_LOCAL_CASES[PROFILE_C1B_HAPPY][0],
        "unequal-concurrent-prompt-5", "unequal-concurrent-prompt-11",
        "context-boundary-1151-plus-1",
    ]
    if (type(cases) is not list or len(cases) != len(expected_case_ids)
            or any(type(item) is not dict for item in cases)
            or [item.get("case_id") for item in cases] != expected_case_ids):
        raise SupervisorError("cohort_result", "happy_case_set")

    projected_cases = []
    for index, item in enumerate(cases[:4]):
        if (item.get("request_id") != baseline_requests[index]
                or item.get("session_id") != baseline_sessions[index]):
            raise SupervisorError("cohort_result", "happy_baseline_case_identity")
        projected_cases.append({
            "case_id": expected_case_ids[index],
            "request_id": baseline_requests[index],
            "session_id": baseline_sessions[index],
        })

    preflight = cases[4]
    preflight_request = preflight.get("request_id")
    if (type(preflight_request) is not str
            or _TYPED_REQUEST.fullmatch(preflight_request) is None
            or preflight_request in baseline_requests
            or preflight_request in value["request_ids"]
            or preflight.get("session_id", object()) is not None
            or preflight.get("accepted") is not False
            or preflight.get("error_code") != "INVALID_INPUT"
            or type(preflight.get("tensor_allocations")) is not int
            or preflight["tensor_allocations"] != 0
            or type(preflight.get("coordinator_submits")) is not int
            or preflight["coordinator_submits"] != 0
            or preflight.get("remote_worker_contacted") is not False):
        raise SupervisorError("cohort_result", "happy_preflight")
    projected_preflight = {
        "case_id": expected_case_ids[4], "request_id": preflight_request,
        "session_id": None, "accepted": False, "error_code": "INVALID_INPUT",
        "tensor_allocations": 0, "coordinator_submits": 0,
        "remote_worker_contacted": False,
    }
    projected_cases.append(projected_preflight)

    extensions = baseline.get("lifecycle_extensions")
    extension_fields = {
        "profile", "status", "completed_requests", "numerical_errors",
        "request_ids", "session_ids", "remote_overlap_observed",
        "preflight_rejection",
    }
    declared_extension_errors = (
        extensions.get("numerical_errors") if type(extensions) is dict else None)
    if (type(extensions) is not dict or set(extensions) != extension_fields
            or extensions.get("profile") != PROFILE_C1B_HAPPY
            or extensions.get("status") != "passed"
            or type(extensions.get("completed_requests")) is not int
            or extensions["completed_requests"] != 3
            or type(declared_extension_errors) is not list
            or len(declared_extension_errors) != 9
            or any(not _finite_nonnegative_number(error) or error > 1e-3
                   for error in declared_extension_errors)
            or extensions.get("remote_overlap_observed") is not False):
        raise SupervisorError("cohort_result", "happy_extension_schema")

    extension_requests = extensions.get("request_ids")
    extension_sessions = extensions.get("session_ids")
    if (type(extension_requests) is not list or len(extension_requests) != 3
            or any(type(item) is not str or _TYPED_REQUEST.fullmatch(item) is None
                   for item in extension_requests)
            or len(set(extension_requests)) != 3
            or set(extension_requests) & set(baseline_requests)
            or type(extension_sessions) is not list or len(extension_sessions) != 3
            or any(type(item) is not str or _TYPED_SESSION.fullmatch(item) is None
                   for item in extension_sessions)
            or len(set(extension_sessions)) != 3
            or set(extension_sessions) & set(baseline_sessions)):
        raise SupervisorError("cohort_result", "happy_extension_ids")
    if preflight_request in extension_requests:
        raise SupervisorError("cohort_result", "happy_preflight_identity")

    if extensions.get("preflight_rejection") != preflight:
        raise SupervisorError("cohort_result", "happy_preflight_mismatch")
    if (set(preflight) != {
            "case_id", "request_id", "session_id", "accepted", "error_code",
            "tensor_allocations", "coordinator_submits", "remote_worker_contacted",
            "local_owner_check", "evidence_scope"}
            or preflight.get("evidence_scope") != (
                "public client preflight only; no worker RPC or remote compute claim")):
        raise SupervisorError("cohort_result", "happy_preflight_schema")
    owner_check = preflight.get("local_owner_check")
    owner_fields = {
        "confirmed", "active_requests", "active_streams", "active_generate_streams",
        "active_captures", "capture_reserved_bytes", "worker_sessions",
        "worker_active_compute", "transport_reserved_connections",
        "transport_reserved_pending",
    }
    if (type(owner_check) is not dict or set(owner_check) != owner_fields
            or owner_check.get("confirmed") is not True
            or any(type(owner_check.get(field)) is not int or owner_check[field] != 0
                   for field in (
                       "active_requests", "active_streams", "active_generate_streams",
                       "active_captures", "capture_reserved_bytes", "worker_sessions",
                       "transport_reserved_pending"))
            or owner_check.get("worker_active_compute") is not False
            or type(owner_check.get("transport_reserved_connections")) is not int
            or owner_check["transport_reserved_connections"] != 15):
        raise SupervisorError("cohort_result", "happy_preflight_owners")

    extension_errors = []
    extension_specs = (
        (5, 5, 4, 3, "unequal-concurrent-prompt-5"),
        (6, 11, 4, 3, "unequal-concurrent-prompt-11"),
        (7, 1151, 1, 1, "context-boundary-1151-plus-1"),
    )
    for case_index, (extension_index, prompt_length, count, feedback, case_id) in enumerate(
            extension_specs, start=5):
        item = cases[case_index]
        request_index = extension_index - 5
        errors = item.get("comparison_errors")
        if (item.get("request_id") != extension_requests[request_index]
                or item.get("session_id") != extension_sessions[request_index]
                or type(item.get("prompt_length")) is not int
                or item["prompt_length"] != prompt_length
                or type(item.get("new_tokens")) is not int
                or item["new_tokens"] != (4 if prompt_length != 1151 else 1)
                or type(item.get("captured_vectors")) is not int
                or item["captured_vectors"] != count
                or type(errors) is not list or len(errors) != count
                or any(not _finite_nonnegative_number(error) or error > 1e-3
                       for error in errors)
                or not _finite_nonnegative_number(item.get("max_absolute_error"))
                or item["max_absolute_error"] != max(errors)):
            raise SupervisorError("cohort_result", "happy_case_numerics")
        if case_id.startswith("unequal-concurrent"):
            if (type(item.get("forced_feedback_count")) is not int
                    or item["forced_feedback_count"] != feedback):
                raise SupervisorError("cohort_result", "happy_concurrent_feedback")
        else:
            if (type(item.get("positions_total")) is not int
                    or item["positions_total"] != 1152
                    or item.get("positions") != [1151]):
                raise SupervisorError("cohort_result", "happy_boundary_position")
        extension_errors.extend(errors)
        projected_cases.append({
            "case_id": case_id,
            "request_id": extension_requests[request_index],
            "session_id": extension_sessions[request_index],
            "captured_vectors": count,
            "max_absolute_error": max(errors),
        })

    if extension_errors != declared_extension_errors:
        raise SupervisorError("cohort_result", "happy_extension_numerics")
    return {
        "schema_version": 1,
        "event": "cohort_result_summary",
        "run_id": value["run_id"],
        "baseline_status": baseline["status"],
        "completed_requests": baseline["completed_requests"],
        "captured_vectors": numerical["captured_vectors"],
        "max_absolute_error": numerical["max_absolute_error"],
        "request_ids": list(baseline_requests),
        "session_ids": list(baseline_sessions),
        "cases": projected_cases,
        "lifecycle_extensions": {
            "profile": PROFILE_C1B_HAPPY,
            "status": "passed",
            "completed_requests": 3,
            "captured_vectors": len(declared_extension_errors),
            "max_absolute_error": max(declared_extension_errors),
            "request_ids": list(extension_requests),
            "session_ids": list(extension_sessions),
            "remote_overlap_observed": False,
            "preflight_rejection": projected_preflight,
        },
        "failure_type": value.get("failure_type")
            if type(value.get("failure_type")) is str and re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{0,79}", value["failure_type"]) else None,
    }


def _restart_baseline4(value, *, prefix, old_identities=None):
    expected = {"baseline", "request_ids", "session_ids", "numerical_errors",
                "cases", "identities"}
    if type(value) is not dict or set(value) != expected:
        raise SupervisorError("cohort_result", "restart_baseline_schema")
    baseline, numerical = value["baseline"], value["numerical_errors"]
    if (type(baseline) is not dict or baseline.get("status") != "passed"
            or type(baseline.get("completed_requests")) is not int
            or baseline["completed_requests"] != 4
            or type(baseline.get("captured_vectors")) is not int
            or baseline["captured_vectors"] != 27
            or type(numerical) is not dict
            or set(numerical) != {"captured_vectors", "max_absolute_error", "values", "atol", "rtol"}
            or type(numerical.get("captured_vectors")) is not int
            or numerical["captured_vectors"] != 27
            or type(numerical.get("values")) is not list or len(numerical["values"]) != 27
            or any(not _finite_nonnegative_number(x) or x > 1e-3 for x in numerical["values"])
            or not _finite_nonnegative_number(numerical.get("max_absolute_error"))
            or numerical["max_absolute_error"] != max(numerical["values"])
            or type(numerical.get("atol")) not in (int, float) or numerical["atol"] != 1e-3
            or type(numerical.get("rtol")) not in (int, float) or numerical["rtol"] != 0.0):
        raise SupervisorError("cohort_result", "restart_baseline_numerics")
    reqs, sessions = value["request_ids"], value["session_ids"]
    if (type(reqs) is not list or len(reqs) != 4
            or any(type(x) is not str or _TYPED_REQUEST.fullmatch(x) is None for x in reqs)
            or len(set(reqs)) != 4
            or type(sessions) is not list or len(sessions) != 4
            or any(type(x) is not str or _TYPED_SESSION.fullmatch(x) is None for x in sessions)
            or len(set(sessions)) != 4):
        raise SupervisorError("cohort_result", "restart_baseline_ids")
    names = ("greedy-one-token", "forced-length-1", "forced-length-128", "forced-length-1024")
    cases = value["cases"]
    if type(cases) is not list or len(cases) != 4:
        raise SupervisorError("cohort_result", "restart_baseline_cases")
    for i, case in enumerate(cases):
        if (type(case) is not dict or not {"case_id", "request_id", "session_id"} <= set(case)
                or case["case_id"] != prefix + names[i]
                or case["request_id"] != reqs[i] or case["session_id"] != sessions[i]):
            raise SupervisorError("cohort_result", "restart_baseline_case_binding")
    identities = value["identities"]
    fields = {"run_id", "coordinator_boot_id", "consumer_boot_id", "worker_boot_ids",
              "manifest_fingerprint"}
    if type(identities) is not dict or set(identities) != fields:
        raise SupervisorError("cohort_result", "restart_baseline_identities")
    boots = [identities.get("coordinator_boot_id"), identities.get("consumer_boot_id")]
    workers = identities.get("worker_boot_ids")
    if (type(identities.get("run_id")) is not str or _HEX32.fullmatch(identities["run_id"]) is None
            or any(type(x) is not str or _HEX32.fullmatch(x) is None for x in boots)
            or type(workers) is not dict or set(workers) != {"worker-1", "worker-2", "worker-3"}
            or any(type(x) is not str or _HEX32.fullmatch(x) is None for x in workers.values())
            or len(set(boots + list(workers.values()))) != 5
            or type(identities.get("manifest_fingerprint")) is not str
            or _HEX64.fullmatch(identities["manifest_fingerprint"]) is None):
        raise SupervisorError("cohort_result", "restart_baseline_boots")
    if old_identities is not None:
        old_workers = old_identities["worker_boot_ids"]
        if (identities["consumer_boot_id"] != old_identities["consumer_boot_id"]
                or identities["coordinator_boot_id"] == old_identities["coordinator_boot_id"]
                or any(workers[name] == old_workers[name]
                       for name in ("worker-1", "worker-2", "worker-3"))):
            raise SupervisorError("cohort_result", "restart_boot_continuity")
    return {
        "baseline": {"status": "passed", "completed_requests": 4,
                     "captured_vectors": 27,
                     "max_absolute_error": numerical["max_absolute_error"]},
        "request_ids": list(reqs), "session_ids": list(sessions),
        "cases": [{"case_id": prefix + names[i], "request_id": reqs[i],
                   "session_id": sessions[i]} for i in range(4)],
        "identities": {"run_id": identities["run_id"],
                       "coordinator_boot_id": identities["coordinator_boot_id"],
                       "consumer_boot_id": identities["consumer_boot_id"],
                       "worker_boot_ids": dict(workers),
                       "manifest_fingerprint": identities["manifest_fingerprint"]},
    }


def _sanitize_restart_cohort_result(value, *, old_ready, new_ready,
                                    new_assignment_id, new_device_id,
                                    old_held_status, observed_requests,
                                    old_receipt_digest):
    _validate_result_record(value)
    if any(key in value for key in (
            "interleave", "cancellation", "partial_admission", "step_reply_loss",
            "capacity")):
        raise SupervisorError("cohort_result", "profile_mismatch")
    extension = value.get("restart")
    fields = {"profile", "status", "scope", "old_boot_id", "new_boot_id",
              "old_snapshot_sha256", "new_snapshot_sha256", "old_owner_receipt_sha256",
              "old_local_shutdown", "direct_probe", "stale_binding_rejections",
              "new_baseline", "probe_cleanup", "same_leaf_continuity"}
    if type(extension) is not dict or set(extension) != fields:
        raise SupervisorError("cohort_result", "restart_schema")
    expected = {
        "profile": PROFILE_C1B_RESTART, "status": "passed",
        "scope": "remote_worker_between_rpcs",
        "old_boot_id": old_ready["expected_boot_id"],
        "new_boot_id": new_ready["expected_boot_id"],
        "old_snapshot_sha256": old_ready["snapshot_sha256"],
        "new_snapshot_sha256": new_ready["snapshot_sha256"],
        "old_owner_receipt_sha256": old_receipt_digest,
    }
    if any(type(extension.get(k)) is not type(v) or extension.get(k) != v
           for k, v in expected.items()):
        raise SupervisorError("cohort_result", "restart_binding")
    if extension["old_snapshot_sha256"] == extension["new_snapshot_sha256"]:
        raise SupervisorError("cohort_result", "restart_snapshot_unchanged")
    shutdown = extension["old_local_shutdown"]
    if (type(shutdown) is not dict or set(shutdown) != {"confirmed", "failure_types"}
            or shutdown["confirmed"] is not True or shutdown["failure_types"] != []):
        raise SupervisorError("cohort_result", "restart_old_local_shutdown")

    old_ids = value.get("identities")
    old_baseline = _restart_baseline4({
        "baseline": value.get("baseline"), "request_ids": value.get("request_ids"),
        "session_ids": value.get("session_ids"),
        "numerical_errors": value.get("numerical_errors"),
        "cases": value.get("cases"), "identities": old_ids}, prefix="")
    if (old_baseline["identities"]["worker_boot_ids"]["worker-3"] != old_ready["expected_boot_id"]
            or old_baseline["identities"]["run_id"] != value["run_id"]
            or old_baseline["identities"]["manifest_fingerprint"]
               != old_ready["manifest_fingerprint"]):
        raise SupervisorError("cohort_result", "restart_old_worker_boot")

    probe = extension["direct_probe"]
    probe_fields = {"request_id", "session_id", "route_id", "route_epoch", "attempt",
                    "open_response", "step_response", "held_status", "bindings",
                    "new_target_before", "client_replacement"}
    if type(probe) is not dict or set(probe) != probe_fields:
        raise SupervisorError("cohort_result", "restart_probe_schema")
    request_id, session_id, route_id = probe["request_id"], probe["session_id"], probe["route_id"]
    if (type(request_id) is not str or _TYPED_REQUEST.fullmatch(request_id) is None
            or type(session_id) is not str or _TYPED_SESSION.fullmatch(session_id) is None
            or type(route_id) is not str or re.fullmatch(r"route_[0-9a-f]{32}", route_id) is None
            or type(probe["route_epoch"]) is not int or probe["route_epoch"] != 1
            or type(probe["attempt"]) is not int or probe["attempt"] != 1):
        raise SupervisorError("cohort_result", "restart_probe_identity")
    if (observed_requests.get(5, {}).get("request_id") != request_id
            or observed_requests.get(5, {}).get("session_id") != session_id
            or observed_requests.get(6, {}).get("request_id") != request_id
            or observed_requests.get(6, {}).get("session_id") != session_id
            or request_id in value["request_ids"]
            or session_id in value["session_ids"]):
        raise SupervisorError("cohort_result", "restart_probe_observation")
    opened = probe["open_response"]
    if (type(opened) is not dict or set(opened) != {"session_id", "worker_boot_id", "code"}
            or opened.get("session_id") != session_id
            or opened.get("worker_boot_id") != old_ready["expected_boot_id"]
            or opened.get("code") != "OK"):
        raise SupervisorError("cohort_result", "restart_open_response")
    step = probe["step_response"]
    step_expected = {"sequence": 0, "start_position": 0, "token_count": 3,
                     "end_position": 3, "next_sequence": 1,
                     "tensor_shape": [1, 3, 64], "dtype": "float32_le",
                     "byte_count": 768, "finite": True}
    if (type(step) is not dict or set(step) != set(step_expected)
            or any(type(step.get(k)) is not type(v) or step.get(k) != v
                   for k, v in step_expected.items())):
        raise SupervisorError("cohort_result", "restart_step_response")

    held = probe["held_status"]
    held_fields = {"worker_boot_id", "active_sessions", "active_session_ids",
                   "queued_operations", "active_compute", "cache_bytes_exact",
                   "committed_cache_bytes", "allocated_cache_bytes",
                   "active_authorizations", "owned_sessions", "transport_reserved_connections"}
    if type(held) is not dict or set(held) != held_fields:
        raise SupervisorError("cohort_result", "restart_held_schema")
    handler = old_held_status.get("handler") if type(old_held_status) is dict else None
    bridge = old_held_status.get("bridge") if type(old_held_status) is dict else None
    transport = old_held_status.get("transport") if type(old_held_status) is dict else None
    actual = {
        "worker_boot_id": old_ready["expected_boot_id"],
        "active_sessions": handler.get("active_sessions") if type(handler) is dict else None,
        "active_session_ids": handler.get("active_session_ids") if type(handler) is dict else None,
        "queued_operations": handler.get("queued_operations") if type(handler) is dict else None,
        "active_compute": handler.get("active_compute") if type(handler) is dict else None,
        "cache_bytes_exact": handler.get("cache_bytes_exact") if type(handler) is dict else None,
        "committed_cache_bytes": handler.get("committed_cache_bytes") if type(handler) is dict else None,
        "allocated_cache_bytes": handler.get("allocated_cache_bytes") if type(handler) is dict else None,
        "active_authorizations": bridge.get("active_authorizations") if type(bridge) is dict else None,
        "owned_sessions": bridge.get("owned_sessions") if type(bridge) is dict else None,
        "transport_reserved_connections": transport.get("reserved_connections") if type(transport) is dict else None,
    }
    if (held != actual or held["active_sessions"] != 1
            or held["active_session_ids"] != [session_id]
            or held["queued_operations"] != 0 or held["active_compute"] is not False
            or held["cache_bytes_exact"] is not True
            or type(held["committed_cache_bytes"]) is not int or held["committed_cache_bytes"] <= 0
            or type(held["allocated_cache_bytes"]) is not int or held["allocated_cache_bytes"] <= 0
            or held["active_authorizations"] != 0 or held["owned_sessions"] != 1
            or type(held["transport_reserved_connections"]) is not int
            or held["transport_reserved_connections"] < 1):
        raise SupervisorError("cohort_result", "restart_held_status")

    bindings = probe["bindings"]
    row_fields = {"method", "operation_id", "request_id", "session_id", "route_id",
                  "route_epoch", "attempt", "worker_boot_id"}
    methods = ("OpenSession", "Step", "SessionStatus", "CancelSession")
    if type(bindings) is not list or len(bindings) != 4:
        raise SupervisorError("cohort_result", "restart_bindings")
    opids = []
    for i, row in enumerate(bindings):
        if (type(row) is not dict or set(row) != row_fields or row.get("method") != methods[i]
                or type(row.get("operation_id")) is not str
                or re.fullmatch(r"op_[0-9a-f]{32}", row["operation_id"]) is None
                or row.get("request_id") != request_id or row.get("session_id") != session_id
                or row.get("route_id") != route_id
                or type(row.get("route_epoch")) is not int or row["route_epoch"] != probe["route_epoch"]
                or type(row.get("attempt")) is not int or row["attempt"] != probe["attempt"]
                or row.get("worker_boot_id") != old_ready["expected_boot_id"]):
            raise SupervisorError("cohort_result", "restart_binding_row")
        opids.append(row["operation_id"])
    if len(set(opids)) != 4:
        raise SupervisorError("cohort_result", "restart_binding_operation_ids")

    before = probe["new_target_before"]
    before_fields = {"worker_boot_id", "ready", "active_sessions", "reserved_positions",
                     "allocated_cache_bytes", "active_operations", "queued_operations",
                     "tombstones", "cache_bytes_exact", "requires_restart"}
    if (type(before) is not dict or set(before) != before_fields
            or before.get("worker_boot_id") != new_ready["expected_boot_id"]
            or before.get("ready") is not True or before.get("cache_bytes_exact") is not True
            or before.get("requires_restart") is not False
            or any(type(before.get(k)) is not int or before[k] != 0
                   for k in ("active_sessions", "reserved_positions", "allocated_cache_bytes",
                             "active_operations", "queued_operations", "tombstones"))):
        raise SupervisorError("cohort_result", "restart_new_target")

    replacement = probe["client_replacement"]
    if type(replacement) is not dict or set(replacement) != {
            "connection_mode", "original_close", "initial_new_close", "stale_clients",
            "preface_bindings", "accounted_client_counts", "max_accounted_clients"}:
        raise SupervisorError("cohort_result", "restart_client_replacement_schema")
    if replacement.get("connection_mode") != "serial_new_describe_then_stale_control":
        raise SupervisorError("cohort_result", "restart_client_replacement_mode")
    close_fields = {"attempted", "confirmed", "close_calls",
                    "reserved_connections_before", "reserved_connections_after",
                    "client_closed"}
    original_close = replacement["original_close"]
    if (type(original_close) is not dict or set(original_close) != close_fields
            or any(type(original_close.get(key)) is not bool
                   or original_close[key] is not True
                   for key in ("attempted", "confirmed", "client_closed"))
            or any(type(original_close.get(key)) is not int
                   for key in ("close_calls", "reserved_connections_before",
                               "reserved_connections_after"))
            or original_close != {
                "attempted": True, "confirmed": True, "close_calls": 1,
                "reserved_connections_before": 6, "reserved_connections_after": 3,
                "client_closed": True}):
        raise SupervisorError("cohort_result", "restart_original_client_close")
    initial_new_close = replacement["initial_new_close"]
    if (type(initial_new_close) is not dict or set(initial_new_close) != close_fields
            or any(type(initial_new_close.get(key)) is not bool
                   for key in ("attempted", "confirmed", "client_closed"))
            or any(type(initial_new_close.get(key)) is not int
                   for key in ("close_calls", "reserved_connections_before",
                               "reserved_connections_after"))
            or initial_new_close != {
                "attempted": True, "confirmed": True, "close_calls": 1,
                "reserved_connections_before": 3, "reserved_connections_after": 0,
                "client_closed": True}):
        raise SupervisorError("cohort_result", "restart_initial_new_client_close")
    stale_clients = replacement["stale_clients"]
    stale_fields = {"method", "created_after_close", "same_request_context",
                    "old_authorizer_preserved", "same_target_peer",
                    "same_local_tls_identity", "reserved_connections_after_create",
                    "native_status", "close", "new_target_preface",
                    "same_channel_and_connector_at_dispatch"}
    if type(stale_clients) is not list or len(stale_clients) != 2:
        raise SupervisorError("cohort_result", "restart_stale_client_count")
    for row, method in zip(stale_clients, ("SessionStatus", "CancelSession")):
        if type(row) is not dict or set(row) != stale_fields:
            raise SupervisorError("cohort_result", "restart_stale_client_schema")
        close = row.get("close")
        if (type(close) is not dict or set(close) != close_fields
                or any(type(close.get(key)) is not bool or close[key] is not True
                       for key in ("attempted", "confirmed", "client_closed"))
                or any(type(close.get(key)) is not int
                       for key in ("close_calls", "reserved_connections_before",
                                   "reserved_connections_after"))):
            raise SupervisorError("cohort_result", "restart_stale_client_close_schema")
        if (row.get("method") != method
                or any(row.get(key) is not True for key in (
                    "created_after_close", "same_request_context",
                    "old_authorizer_preserved", "same_target_peer",
                    "same_local_tls_identity"))
                or type(row.get("reserved_connections_after_create")) is not int
                or row["reserved_connections_after_create"] != 3
                or row.get("native_status") != "UNAUTHENTICATED"
                or row.get("same_channel_and_connector_at_dispatch") is not True
                or type(row.get("new_target_preface")) is not dict
                or row["close"] != {
                    "attempted": True, "confirmed": True, "close_calls": 1,
                    "reserved_connections_before": 3,
                    "reserved_connections_after": 0, "client_closed": True}):
            raise SupervisorError("cohort_result", "restart_stale_client_binding")
        preface = row["new_target_preface"]
        preface_expected = {
            "worker_boot_id": new_ready["expected_boot_id"], "ready": True,
            "active_sessions": 0, "reserved_positions": 0,
            "allocated_cache_bytes": 0, "active_operations": 0,
            "queued_operations": 0, "tombstones": 0,
            "cache_bytes_exact": True, "requires_restart": False,
        }
        if (set(preface) != set(preface_expected)
                or any(type(preface.get(key)) is not type(expected)
                       or preface[key] != expected
                       for key, expected in preface_expected.items())):
            raise SupervisorError("cohort_result", "restart_stale_client_preface")
    if (type(replacement.get("accounted_client_counts")) is not list
            or any(type(count) is not int for count in replacement["accounted_client_counts"])
            or replacement["accounted_client_counts"] != [1, 2, 1, 0, 1, 0, 1, 0]
            or type(replacement.get("max_accounted_clients")) is not int
            or replacement["max_accounted_clients"] != 2):
        raise SupervisorError("cohort_result", "restart_client_budget")
    prefaces = replacement["preface_bindings"]
    preface_fields = {"for_method", "method", "operation_id", "worker_boot_id",
                      "assignment_id", "target_device_id"}
    if type(prefaces) is not list or len(prefaces) != 2:
        raise SupervisorError("cohort_result", "restart_preface_count")
    old_opids = {row["operation_id"] for row in bindings}
    preface_opids = []
    for row, method in zip(prefaces, ("SessionStatus", "CancelSession")):
        if (type(row) is not dict or set(row) != preface_fields
                or row.get("for_method") != method or row.get("method") != "Describe"
                or row.get("worker_boot_id") != new_ready["expected_boot_id"]
                or type(row.get("operation_id")) is not str
                or re.fullmatch(r"op_[0-9a-f]{32}", row["operation_id"]) is None
                or type(new_assignment_id) is not str
                or re.fullmatch(r"asg_[0-9a-f]{32}", new_assignment_id) is None
                or row.get("assignment_id") != new_assignment_id
                or type(new_device_id) is not str
                or re.fullmatch(r"dev_[0-9a-f]{32}", new_device_id) is None
                or row.get("target_device_id") != new_device_id):
            raise SupervisorError("cohort_result", "restart_preface_binding")
        preface_opids.append(row["operation_id"])
    if len(set(preface_opids)) != 2 or set(preface_opids) & old_opids:
        raise SupervisorError("cohort_result", "restart_preface_operation_ids")
    rejections = [{"method": "SessionStatus", "code": "UNAUTHENTICATED"},
                  {"method": "CancelSession", "code": "UNAUTHENTICATED"}]
    if extension["stale_binding_rejections"] != rejections:
        raise SupervisorError("cohort_result", "restart_stale_binding_rejections")
    cleanup = extension["probe_cleanup"]
    cleanup_fields = {"confirmed", "transport_reserved_connections", "transport_reserved_pending",
                      "transport_reserved_outbound_pending", "authorization_closed",
                      "context_released", "client_closed"}
    if (type(cleanup) is not dict or set(cleanup) != cleanup_fields
            or cleanup.get("confirmed") is not True
            or any(type(cleanup.get(k)) is not int or cleanup[k] != 0
                   for k in ("transport_reserved_connections", "transport_reserved_pending",
                             "transport_reserved_outbound_pending"))
            or cleanup.get("authorization_closed") is not True
            or cleanup.get("context_released") is not True or cleanup.get("client_closed") is not True):
        raise SupervisorError("cohort_result", "restart_probe_cleanup")
    continuity = extension["same_leaf_continuity"]
    continuity_fields = {"same_ca", "same_snapshot_signer_public_key",
                         "same_worker_leaf_certificate", "same_worker_private_key",
                         "same_device_id", "same_assignment_id", "same_credential_epoch"}
    if (type(continuity) is not dict or set(continuity) != continuity_fields
            or any(continuity.get(k) is not True for k in continuity_fields)):
        raise SupervisorError("cohort_result", "restart_leaf_continuity")
    new_baseline = _restart_baseline4(
        extension["new_baseline"], prefix="restart-new-", old_identities=old_ids)
    if (new_baseline["identities"]["worker_boot_ids"]["worker-3"] != new_ready["expected_boot_id"]
            or new_baseline["identities"]["run_id"] != value["run_id"]
            or new_baseline["identities"]["manifest_fingerprint"]
               != new_ready["manifest_fingerprint"]):
        raise SupervisorError("cohort_result", "restart_new_worker_boot")
    if (set(new_baseline["request_ids"]) & set(value["request_ids"])
            or set(new_baseline["session_ids"]) & set(value["session_ids"])
            or request_id in new_baseline["request_ids"]
            or session_id in new_baseline["session_ids"]):
        raise SupervisorError("cohort_result", "restart_ids_reused")
    old_restarted_boots = {old_ids["coordinator_boot_id"],
                           *old_ids["worker_boot_ids"].values()}
    new_restarted_boots = {new_baseline["identities"]["coordinator_boot_id"],
                           *new_baseline["identities"]["worker_boot_ids"].values()}
    if old_restarted_boots & new_restarted_boots:
        raise SupervisorError("cohort_result", "restart_boot_reused")
    new_observations = [observed_requests.get(i) for i in range(7, 11)]
    if (any(type(x) is not dict for x in new_observations)
            or [x["request_id"] for x in new_observations] != new_baseline["request_ids"]
            or [x["session_id"] for x in new_observations] != new_baseline["session_ids"]):
        raise SupervisorError("cohort_result", "restart_new_observation_binding")
    if (type(value.get("local_shutdown")) is not dict
            or value["local_shutdown"].get("confirmed") is not True
            or value["local_shutdown"].get("failure_types") != []
            or type(value.get("remote_shutdown")) is not dict
            or value["remote_shutdown"].get("confirmed") is not True):
        raise SupervisorError("cohort_result", "restart_final_shutdown")
    return {
        "schema_version": 1, "event": "cohort_result_summary", "run_id": value["run_id"],
        "baseline_status": "passed", "completed_requests": 4, "captured_vectors": 27,
        "max_absolute_error": old_baseline["baseline"]["max_absolute_error"],
        "request_ids": old_baseline["request_ids"], "session_ids": old_baseline["session_ids"],
        "cases": old_baseline["cases"], "identities": old_baseline["identities"],
        "restart": {
            "profile": PROFILE_C1B_RESTART, "status": "passed",
            "scope": "remote_worker_between_rpcs", "old_boot_id": extension["old_boot_id"],
            "new_boot_id": extension["new_boot_id"],
            "old_snapshot_sha256": extension["old_snapshot_sha256"],
            "new_snapshot_sha256": extension["new_snapshot_sha256"],
            "old_owner_receipt_sha256": extension["old_owner_receipt_sha256"],
            "old_local_shutdown": {"confirmed": True, "failure_types": []},
            "direct_probe": probe, "stale_binding_rejections": rejections,
            "new_baseline": new_baseline, "probe_cleanup": dict(cleanup),
            "same_leaf_continuity": dict(continuity),
        },
        "failure_type": value.get("failure_type")
            if type(value.get("failure_type")) is str
            and _FAILURE_TYPE.fullmatch(value["failure_type"]) else None,
    }


def _sanitize_cohort_result(value: dict, profile: str = PROFILE_BASELINE) -> dict:
    """Project the frozen result into bounded scalar/typed-ID evidence."""
    if profile not in OWNER_PROFILES and type(value) is dict and "owner_actions" in value:
        raise SupervisorError("cohort_result", "profile_mismatch")
    if profile == PROFILE_C1B_HAPPY:
        return _sanitize_happy_cohort_result(value)
    if profile == PROFILE_C1B_INTERLEAVE:
        return _sanitize_interleave_cohort_result(value)
    if profile == PROFILE_C1B_CANCEL:
        return _sanitize_cancel_cohort_result(value)
    if profile == PROFILE_C1B_PARTIAL:
        return _sanitize_partial_admission_cohort_result(value)
    if profile == PROFILE_C1B_STEP_LOSS:
        return _sanitize_step_reply_loss_cohort_result(value)
    if profile == PROFILE_C1B_CAPACITY:
        return _sanitize_capacity_cohort_result(value)
    if profile == PROFILE_C1B_RESTART:
        raise SupervisorError("cohort_result", "restart_observation_context_required")
    if profile in OWNER_PROFILES:
        raise SupervisorError("cohort_result", "owner_observation_context_required")
    if profile != PROFILE_BASELINE:
        raise SupervisorError("cohort_result", "profile")
    _validate_result_record(value)
    if ("interleave" in value or "cancellation" in value
            or "partial_admission" in value or "step_reply_loss" in value
            or "capacity" in value or "restart" in value):
        raise SupervisorError("cohort_result", "profile_mismatch")
    baseline = value["baseline"]
    numerical = value.get("numerical_errors", {})
    if type(numerical) is not dict:
        numerical = {}
    captured = numerical.get("captured_vectors", 0)
    captured = captured if type(captured) is int and 0 <= captured <= 27 else None
    max_error = numerical.get("max_absolute_error")
    if type(max_error) not in (int, float) or not math.isfinite(max_error) or max_error < 0:
        max_error = None
    cases = []
    if type(value.get("cases")) is list and len(value["cases"]) <= 4:
        for item in value["cases"]:
            if type(item) is not dict:
                continue
            case_id = item.get("case_id")
            req = item.get("request_id")
            ses = item.get("session_id")
            if (type(case_id) is str and case_id in set(_OBSERVATION_CASES.values())
                    and type(req) is str and _TYPED_REQUEST.fullmatch(req)
                    and type(ses) is str and _TYPED_SESSION.fullmatch(ses)):
                cases.append({"case_id": case_id, "request_id": req, "session_id": ses})
    return {
        "schema_version": 1,
        "event": "cohort_result_summary",
        "run_id": value["run_id"],
        "baseline_status": baseline["status"],
        "completed_requests": baseline.get("completed_requests")
            if type(baseline.get("completed_requests")) is int else None,
        "captured_vectors": captured,
        "max_absolute_error": max_error,
        "request_ids": list(value["request_ids"]),
        "session_ids": list(value["session_ids"]),
        "cases": cases,
        "failure_type": value.get("failure_type")
            if type(value.get("failure_type")) is str and re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{0,79}", value["failure_type"]) else None,
    }


def _sanitize_owner_cohort_result(value: dict, *, expected: OwnerExpectation,
                                  host_key: str, config: dict,
                                  expected_serials: list[str],
                                  handled_requests: list[dict],
                                  action_responses: list[dict],
                                  observation_acks: list[dict],
                                  owner_state: dict) -> dict:
    """Validate owner evidence and bind it to this supervisor's actual exchanges."""
    if type(value) is not dict or "owner_actions" not in value:
        raise SupervisorError("cohort_result", "owner_actions_missing")
    if any(key in value for key in (
            "interleave", "cancellation", "partial_admission", "step_reply_loss",
            "capacity", "restart")):
        raise SupervisorError("cohort_result", "profile_mismatch")
    _validate_result_record(value)
    if (type(value.get("run_id")) is not str or value["run_id"] != expected.run_id
            or type(value.get("local_shutdown")) is not dict
            or set(value["local_shutdown"]) != {"confirmed", "failure_types"}
            or type(value["local_shutdown"].get("confirmed")) is not bool
            or value["local_shutdown"]["confirmed"] is not True
            or type(value["local_shutdown"].get("failure_types")) is not list
            or value["local_shutdown"]["failure_types"] != []
            or type(value.get("remote_shutdown")) is not dict
            or set(value["remote_shutdown"]) != {
                "confirmed", "process_state", "exit_code", "shutdown_overall",
                "worker_boot_id"}
            or type(value["remote_shutdown"].get("confirmed")) is not bool
            or value["remote_shutdown"]["confirmed"] is not True
            or value["remote_shutdown"].get("process_state") != "exited"
            or type(value["remote_shutdown"].get("exit_code")) is not int
            or value["remote_shutdown"]["exit_code"] != 0
            or value["remote_shutdown"].get("shutdown_overall") != "confirmed"
            or value["remote_shutdown"].get("worker_boot_id") != expected.worker_boot_id):
        raise SupervisorError("cohort_result", "owner_shutdown_or_run_identity")
    base_record = dict(value)
    owner_actions_value = base_record.pop("owner_actions")
    baseline_fields = {"baseline", "request_ids", "session_ids", "numerical_errors",
                       "cases", "identities"}
    try:
        baseline = _restart_baseline4(
            {key: base_record[key] for key in baseline_fields}, prefix="")
    except (KeyError, SupervisorError):
        raise SupervisorError("cohort_result", "owner_baseline_invalid") from None
    identities = base_record.get("identities")
    workers = identities.get("worker_boot_ids") if type(identities) is dict else None
    if (type(identities) is not dict
            or identities.get("run_id") != expected.run_id
            or identities.get("manifest_fingerprint") != expected.manifest_fingerprint
            or type(workers) is not dict
            or workers.get("worker-3") != expected.worker_boot_id):
        raise SupervisorError("cohort_result", "owner_baseline_identity")
    try:
        owner_actions = validate_owner_result(
            owner_actions_value, expected,
            expected_ssh_host_key_sha256=host_key,
            expected_worker_config=config)
    except ValueError:
        raise SupervisorError("cohort_result", "owner_actions_invalid") from None
    if (owner_actions["initial_local_serials"] != expected_serials
            or len(handled_requests) != 2 or len(action_responses) != 2
            or len(observation_acks) != 3
            or owner_actions["commands"] != action_responses
            or owner_actions["observations"] != observation_acks
            or [item.get("command_number") for item in handled_requests] != [1, 2]
            or [item.get("command_sha256") for item in handled_requests]
               != [item.get("command_sha256") for item in action_responses]):
        raise SupervisorError("cohort_result", "owner_exchange_mismatch")
    attempts = owner_state.get("attempts") if type(owner_state) is dict else None
    expected_attempts = (["command1", "command2"]
                         if expected.profile == PROFILE_C1B_OWNER_DRAIN else [
                             "intent_root", "snapshot_verifier", "install_intent",
                             "removal_intent", "policy1", "command1", "policy2",
                             "command2"])
    if (type(attempts) is not list or len(attempts) != len(expected_attempts)
            or [item.get("kind") if type(item) is dict else None for item in attempts]
               != expected_attempts
            or any(type(item.get("monotonic_ns")) is not int
                   or item["monotonic_ns"] <= 0 for item in attempts)
            or any(attempts[index]["monotonic_ns"]
                   >= attempts[index + 1]["monotonic_ns"]
                   for index in range(len(attempts) - 1))):
        raise SupervisorError("cohort_result", "owner_publication_order")
    for item in attempts:
        expected_fields = ({"kind", "mark_ns", "monotonic_ns"}
                           if item["kind"] in ("command1", "command2")
                           else {"kind", "monotonic_ns"})
        if set(item) != expected_fields or (
                "mark_ns" in item and (type(item["mark_ns"]) is not int
                                       or item["mark_ns"] <= 0)):
            raise SupervisorError("cohort_result", "owner_attempt_schema")
    if (expected.profile == PROFILE_C1B_OWNER_REMOVE
            and (type(owner_state.get("verifier_copy_receipt")) is not dict
                 or owner_state.get("intent_publication_complete") is not True
                 or type(owner_state.get("sidecar_retention_receipt")) is not dict
                 or owner_state.get("actual_remove_exit") != {
                     "process_state": "exited", "exit_code": 0})):
        raise SupervisorError("cohort_result", "owner_remove_lifecycle")
    return {
        "schema_version": 1, "event": "cohort_result_summary",
        "run_id": value["run_id"], "baseline_status": baseline["baseline"]["status"],
        "completed_requests": baseline["baseline"]["completed_requests"],
        "captured_vectors": baseline["baseline"]["captured_vectors"],
        "max_absolute_error": baseline["baseline"]["max_absolute_error"],
        "request_ids": baseline["request_ids"], "session_ids": baseline["session_ids"],
        "cases": baseline["cases"], "identities": baseline["identities"],
        "owner_actions": owner_actions,
        "failure_type": value.get("failure_type")
            if type(value.get("failure_type")) is str
            and re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{0,79}", value["failure_type"])
            else None,
    }


def _sanitize_cancel_cohort_result(value: dict) -> dict:
    """Validate cancellation evidence while preserving explicit retained fences."""
    _validate_result_record(value)
    if any(key in value for key in (
            "interleave", "partial_admission", "step_reply_loss", "capacity",
            "restart")):
        raise SupervisorError("cohort_result", "profile_mismatch")
    baseline = value.get("baseline")
    numerical = value.get("numerical_errors")
    expected_cases = [case for _sequence, case in _BASELINE_OBSERVATIONS]
    if (type(baseline) is not dict or baseline.get("status") != "passed"
            or type(baseline.get("completed_requests")) is not int
            or baseline.get("completed_requests") != 4
            or type(baseline.get("captured_vectors")) is not int
            or baseline.get("captured_vectors") != 27
            or type(numerical) is not dict
            or set(numerical) != {
                "captured_vectors", "max_absolute_error", "values", "atol", "rtol"}
            or type(numerical.get("captured_vectors")) is not int
            or numerical.get("captured_vectors") != 27
            or type(numerical.get("values")) is not list
            or len(numerical["values"]) != 27
            or any(not _finite_nonnegative_number(item) or item > 1e-3
                   for item in numerical["values"])
            or not _finite_nonnegative_number(numerical.get("max_absolute_error"))
            or numerical["max_absolute_error"] != max(numerical["values"])
            or type(numerical.get("atol")) not in (int, float)
            or type(numerical.get("rtol")) not in (int, float)
            or numerical["atol"] != 1e-3 or numerical["rtol"] != 0.0
            or type(value.get("cases")) is not list
            or len(value["cases"]) != 4
            or any(type(item) is not dict for item in value["cases"])
            or [item.get("case_id") for item in value["cases"]]
               != expected_cases):
        raise SupervisorError("cohort_result", "cancel_baseline")
    if (type(value.get("request_ids")) is not list
            or len(value["request_ids"]) != 4
            or len(set(value["request_ids"])) != 4
            or type(value.get("session_ids")) is not list
            or len(value["session_ids"]) != 4
            or len(set(value["session_ids"])) != 4
            or any(value["cases"][index].get("request_id") != value["request_ids"][index]
                   or value["cases"][index].get("session_id") != value["session_ids"][index]
                   for index in range(4))):
        raise SupervisorError("cohort_result", "cancel_baseline_identity")
    extension = value.get("cancellation")
    fields = {
        "profile", "status", "request_id", "session_id", "tokens_before_cancel",
        "tokens_after_cancel", "step_counts", "stage_gate_after_cache_mutation",
        "remote_held_session_confirmed", "cancelled_error_observed", "compute_joined",
        "remote_reclaimed_confirmed", "supervisor_arm_monotonic_ns", "local_state",
    }
    if (type(extension) is not dict or set(extension) != fields
            or extension.get("profile") != PROFILE_C1B_CANCEL
            or extension.get("status") != "passed"
            or type(extension.get("request_id")) is not str
            or _TYPED_REQUEST.fullmatch(extension["request_id"]) is None
            or type(extension.get("session_id")) is not str
            or _TYPED_SESSION.fullmatch(extension["session_id"]) is None
            or extension.get("request_id") in value["request_ids"]
            or extension.get("session_id") in value["session_ids"]
            or type(extension.get("tokens_before_cancel")) is not int
            or extension["tokens_before_cancel"] != 1
            or type(extension.get("tokens_after_cancel")) is not int
            or extension["tokens_after_cancel"] != 1
            or type(extension.get("step_counts")) is not list
            or extension["step_counts"] != [2, 1, 1]
            or any(type(item) is not int for item in extension["step_counts"])
            or any(type(extension.get(field)) is not bool or extension[field] is not True
                   for field in ("stage_gate_after_cache_mutation",
                                 "remote_held_session_confirmed",
                                 "cancelled_error_observed", "compute_joined",
                                 "remote_reclaimed_confirmed"))):
        raise SupervisorError("cohort_result", "cancel_extension")
    arm_ns = extension.get("supervisor_arm_monotonic_ns")
    if type(arm_ns) is not int or arm_ns <= 0:
        raise SupervisorError("cohort_result", "cancel_arm_time")
    local = extension.get("local_state")
    local_fields = {
        "state", "logical_cleanup_confirmed", "coordinator_ready", "active_requests",
        "model_cleanup_complete", "active_streams", "active_generate_streams",
        "active_captures", "cleanup_pending_captures", "capture_reserved_bytes",
        "worker_sessions", "worker_active_compute", "transport_reserved_connections",
        "transport_reserved_pending",
    }
    if type(local) is not dict or set(local) != local_fields:
        raise SupervisorError("cohort_result", "cancel_local_schema")
    common_zero = ("active_streams", "active_generate_streams", "active_captures",
                  "cleanup_pending_captures", "capture_reserved_bytes", "worker_sessions",
                  "transport_reserved_pending")
    if (type(local.get("state")) is not str
            or local["state"] not in {"fully_reclaimed", "restart_fenced_retained"}
            or type(local.get("logical_cleanup_confirmed")) is not bool
            or type(local.get("coordinator_ready")) is not bool
            or type(local.get("active_requests")) is not int
            or (local.get("model_cleanup_complete") is not None
                and type(local.get("model_cleanup_complete")) is not bool)
            or any(type(local.get(key)) is not int or local[key] != 0 for key in common_zero)
            or type(local.get("worker_active_compute")) is not bool
            or local["worker_active_compute"] is not False
            or type(local.get("transport_reserved_connections")) is not int
            or local["transport_reserved_connections"] != 15):
        raise SupervisorError("cohort_result", "cancel_local_state")
    if local["state"] == "fully_reclaimed":
        if (local["logical_cleanup_confirmed"] is not True
                or local["coordinator_ready"] is not True
                or local["active_requests"] != 0
                or local["model_cleanup_complete"] not in (None, True)):
            raise SupervisorError("cohort_result", "cancel_reclaimed_state")
        local_shutdown = value.get("local_shutdown")
        if type(local_shutdown) is not dict or local_shutdown.get("confirmed") is not True:
            raise SupervisorError("cohort_result", "cancel_reclaimed_shutdown")
    elif (local["logical_cleanup_confirmed"] is not False
          or local["coordinator_ready"] is not False
          or local["active_requests"] != 1):
        raise SupervisorError("cohort_result", "cancel_fence_state")
    else:
        local_shutdown = value.get("local_shutdown")
        if (type(local_shutdown) is not dict
                or local_shutdown.get("confirmed") is not False
                or local_shutdown.get("restart_fenced_retained") is not True):
            raise SupervisorError("cohort_result", "cancel_fence_shutdown")
    return {
        "schema_version": 1, "event": "cohort_result_summary", "run_id": value["run_id"],
        "baseline_status": "passed", "completed_requests": 4, "captured_vectors": 27,
        "request_ids": list(value["request_ids"]),
        "session_ids": list(value["session_ids"]),
        "cancellation": {
            "profile": PROFILE_C1B_CANCEL, "status": "passed",
            "request_id": extension["request_id"], "session_id": extension["session_id"],
            "tokens_before_cancel": 1, "tokens_after_cancel": 1,
            "step_counts": [2, 1, 1],
            "supervisor_arm_monotonic_ns": arm_ns,
            "local_state": dict(local),
        },
    }


def _sanitize_step_reply_loss_cohort_result(value: dict) -> dict:
    """Project evidence for one validated worker-3 Step reply lost at its caller."""
    _validate_result_record(value)
    if any(key in value for key in (
            "interleave", "cancellation", "partial_admission", "capacity",
            "restart")):
        raise SupervisorError("cohort_result", "profile_mismatch")
    baseline = value.get("baseline")
    numerical = value.get("numerical_errors")
    requests, sessions, cases = (value.get("request_ids"), value.get("session_ids"),
                                 value.get("cases"))
    if (type(baseline) is not dict or baseline.get("status") != "passed"
            or type(baseline.get("completed_requests")) is not int
            or baseline["completed_requests"] != 4
            or type(baseline.get("captured_vectors")) is not int
            or baseline["captured_vectors"] != 27
            or type(numerical) is not dict
            or set(numerical) != {"captured_vectors", "max_absolute_error", "values", "atol", "rtol"}
            or type(numerical.get("captured_vectors")) is not int
            or numerical["captured_vectors"] != 27
            or type(numerical.get("values")) is not list or len(numerical["values"]) != 27
            or any(not _finite_nonnegative_number(item) or item > 1e-3
                   for item in numerical["values"])
            or not _finite_nonnegative_number(numerical.get("max_absolute_error"))
            or numerical["max_absolute_error"] != max(numerical["values"])
            or type(numerical.get("atol")) not in (int, float)
            or type(numerical.get("rtol")) not in (int, float)
            or numerical["atol"] != 1e-3 or numerical["rtol"] != 0.0
            or type(requests) is not list or len(requests) != 4
            or any(type(item) is not str or _TYPED_REQUEST.fullmatch(item) is None
                   for item in requests)
            or len(set(requests)) != 4
            or type(sessions) is not list or len(sessions) != 4
            or any(type(item) is not str or _TYPED_SESSION.fullmatch(item) is None
                   for item in sessions)
            or len(set(sessions)) != 4
            or type(cases) is not list or len(cases) != 4
            or any(type(item) is not dict for item in cases)
            or [item.get("case_id") for item in cases]
               != [case_id for _sequence, case_id in _BASELINE_OBSERVATIONS]
            or any(cases[index].get("request_id") != requests[index]
                   or cases[index].get("session_id") != sessions[index]
                   for index in range(4))):
        raise SupervisorError("cohort_result", "step_loss_baseline")

    extension = value.get("step_reply_loss")
    fields = {
        "profile", "status", "request_id", "session_id", "open_attempts",
        "step_attempts", "cancel_attempts", "step_reply_validated",
        "caller_boundary_reply_loss", "remote_held_session_confirmed",
        "remote_reclaimed_confirmed", "known_leases_reclaimed", "step_commit",
        "token_ids_emitted", "supervisor_arm_monotonic_ns", "local_state",
    }
    if (type(extension) is not dict or set(extension) != fields
            or extension.get("profile") != PROFILE_C1B_STEP_LOSS
            or extension.get("status") != "passed"
            or type(extension.get("request_id")) is not str
            or _TYPED_REQUEST.fullmatch(extension["request_id"]) is None
            or extension["request_id"] in requests
            or type(extension.get("session_id")) is not str
            or _TYPED_SESSION.fullmatch(extension["session_id"]) is None
            or extension["session_id"] in sessions
            or any(extension.get(key) != [1, 1, 1]
                   or type(extension.get(key)) is not list
                   or any(type(item) is not int for item in extension[key])
                   for key in ("open_attempts", "step_attempts", "cancel_attempts"))
            or any(type(extension.get(key)) is not bool or extension[key] is not True
                   for key in ("step_reply_validated", "caller_boundary_reply_loss",
                               "remote_held_session_confirmed",
                               "remote_reclaimed_confirmed", "known_leases_reclaimed"))
            or extension.get("token_ids_emitted") != []
            or type(extension.get("token_ids_emitted")) is not list
            or type(extension.get("supervisor_arm_monotonic_ns")) is not int
            or extension["supervisor_arm_monotonic_ns"] <= 0):
        raise SupervisorError("cohort_result", "step_loss_extension")
    commit = extension["step_commit"]
    commit_fields = {
        "sequence", "start_position", "token_count", "end_position", "next_sequence",
        "hidden_size", "tensor_shape", "tensor_dtype", "tensor_layout",
        "response_tensor_bytes", "response_tensor_envelope_bytes",
        "committed_cache_bytes", "allocated_cache_bytes",
    }
    if (type(commit) is not dict or set(commit) != commit_fields
            or any(type(commit.get(key)) is not int for key in (
                "sequence", "start_position", "token_count", "end_position",
                "next_sequence", "hidden_size", "response_tensor_bytes",
                "response_tensor_envelope_bytes",
                "committed_cache_bytes", "allocated_cache_bytes"))
            or (commit["sequence"], commit["start_position"], commit["token_count"],
                commit["end_position"], commit["next_sequence"])
               != (0, 0, 3, 3, 1)
            or not 1 <= commit["hidden_size"] <= 8192
            or type(commit.get("tensor_shape")) is not list
            or any(type(item) is not int for item in commit["tensor_shape"])
            or commit["tensor_shape"] != [1, 3, commit["hidden_size"]]
            or type(commit.get("tensor_dtype")) is not str
            or commit["tensor_dtype"] != "float32_le"
            or type(commit.get("tensor_layout")) is not str
            or commit["tensor_layout"] != "batch_sequence_hidden"
            or commit["response_tensor_bytes"] != 3 * commit["hidden_size"] * 4
            or commit["response_tensor_envelope_bytes"] < commit["response_tensor_bytes"]
            or commit["response_tensor_envelope_bytes"] > 1_048_576
            or commit["committed_cache_bytes"] <= 0
            or commit["allocated_cache_bytes"] < commit["committed_cache_bytes"]):
        raise SupervisorError("cohort_result", "step_loss_commit")

    local = extension.get("local_state")
    local_fields = {
        "state", "logical_cleanup_confirmed", "coordinator_ready", "active_requests",
        "request_state_membership",
        "known_leases_reclaimed", "active_streams", "active_generate_streams",
        "active_captures", "capture_reserved_bytes", "worker_sessions",
        "worker_active_compute", "transport_reserved_connections",
        "transport_reserved_pending",
    }
    if (type(local) is not dict or set(local) != local_fields
            or type(local.get("state")) is not str
            or local["state"] not in {"resources_reclaimed_service_failed",
                                      "restart_fenced_retained"}
            or local.get("request_state_membership") not in {"absent", "retained"}
            or type(local.get("logical_cleanup_confirmed")) is not bool
            or type(local.get("coordinator_ready")) is not bool
            or type(local.get("active_requests")) is not int
            or local.get("known_leases_reclaimed") is not True
            or any(type(local.get(key)) is not int or local[key] != 0 for key in (
                "active_streams", "active_generate_streams", "active_captures",
                "capture_reserved_bytes", "worker_sessions", "transport_reserved_pending"))
            or type(local.get("worker_active_compute")) is not bool
            or local["worker_active_compute"] is not False
            or type(local.get("transport_reserved_connections")) is not int
            or local["transport_reserved_connections"] != 15):
        raise SupervisorError("cohort_result", "step_loss_local_state")
    shutdown = value.get("local_shutdown")
    if local["state"] == "resources_reclaimed_service_failed":
        if (local["logical_cleanup_confirmed"] is not True
                or local["coordinator_ready"] is not False
                or local["active_requests"] != 0
                or local["request_state_membership"] != "absent"
                or type(shutdown) is not dict
                or set(shutdown) != {"confirmed", "failure_types"}
                or shutdown.get("confirmed") is not True
                or type(shutdown.get("failure_types")) is not list
                or shutdown["failure_types"]):
            raise SupervisorError("cohort_result", "step_loss_reclaimed_state")
    elif (local["logical_cleanup_confirmed"] is not False
          or local["coordinator_ready"] is not False or local["active_requests"] != 1
          or local["request_state_membership"] != "retained"
          or type(shutdown) is not dict
          or set(shutdown) != {"confirmed", "failure_types", "restart_fenced_retained"}
          or shutdown.get("confirmed") is not False
          or shutdown.get("restart_fenced_retained") is not True
          or type(shutdown.get("failure_types")) is not list
          or shutdown["failure_types"] != ["CohortError"]):
        raise SupervisorError("cohort_result", "step_loss_fence_state")
    return {
        "schema_version": 1, "event": "cohort_result_summary", "run_id": value["run_id"],
        "baseline_status": "passed", "completed_requests": 4, "captured_vectors": 27,
        "request_ids": list(requests), "session_ids": list(sessions),
        "step_reply_loss": {
            "profile": PROFILE_C1B_STEP_LOSS, "status": "passed",
            "request_id": extension["request_id"], "session_id": extension["session_id"],
            "step_commit": dict(commit),
            "supervisor_arm_monotonic_ns": extension["supervisor_arm_monotonic_ns"],
            "local_state": dict(local),
        },
    }


def _sanitize_capacity_cohort_result(value: dict) -> dict:
    """Accept only the fixed eight-capture capacity and reclamation evidence."""
    _validate_result_record(value)
    if any(key in value for key in (
            "interleave", "cancellation", "partial_admission", "step_reply_loss",
            "restart")):
        raise SupervisorError("cohort_result", "profile_mismatch")
    baseline = value.get("baseline")
    numerical = value.get("numerical_errors")
    requests, sessions, cases = (value.get("request_ids"), value.get("session_ids"),
                                 value.get("cases"))
    if (type(baseline) is not dict or baseline.get("status") != "passed"
            or type(baseline.get("completed_requests")) is not int
            or baseline["completed_requests"] != 4
            or type(baseline.get("captured_vectors")) is not int
            or baseline["captured_vectors"] != 27
            or type(numerical) is not dict
            or set(numerical) != {"captured_vectors", "max_absolute_error", "values",
                                  "atol", "rtol"}
            or type(numerical.get("captured_vectors")) is not int
            or numerical["captured_vectors"] != 27
            or type(numerical.get("values")) is not list or len(numerical["values"]) != 27
            or any(not _finite_nonnegative_number(item) or item > 1e-3
                   for item in numerical["values"])
            or not _finite_nonnegative_number(numerical.get("max_absolute_error"))
            or numerical["max_absolute_error"] != max(numerical["values"])
            or type(numerical.get("atol")) not in (int, float)
            or type(numerical.get("rtol")) not in (int, float)
            or numerical["atol"] != 1e-3 or numerical["rtol"] != 0.0
            or type(requests) is not list or len(requests) != 4
            or any(type(item) is not str or _TYPED_REQUEST.fullmatch(item) is None
                   for item in requests)
            or len(set(requests)) != 4
            or type(sessions) is not list or len(sessions) != 4
            or any(type(item) is not str or _TYPED_SESSION.fullmatch(item) is None
                   for item in sessions)
            or len(set(sessions)) != 4
            or type(cases) is not list or len(cases) != 4
            or any(type(item) is not dict for item in cases)
            or [item.get("case_id") for item in cases]
               != [case_id for _sequence, case_id in _BASELINE_OBSERVATIONS]
            or any(cases[index].get("request_id") != requests[index]
                   or cases[index].get("session_id") != sessions[index]
                   for index in range(4))):
        raise SupervisorError("cohort_result", "capacity_baseline")
    extension = value.get("capacity")
    fields = {
        "profile", "status", "completed_requests", "captured_vectors",
        "comparison_errors", "max_absolute_error", "request_ids", "session_ids",
        "token_ids", "ninth_rejection", "remote_held_confirmed",
        "remote_reclaimed_confirmed", "local_owner_check", "supervisor_arm_monotonic_ns",
    }
    if (type(extension) is not dict or set(extension) != fields
            or extension.get("profile") != PROFILE_C1B_CAPACITY
            or extension.get("status") != "passed"
            or type(extension.get("completed_requests")) is not int
            or extension["completed_requests"] != 8
            or type(extension.get("captured_vectors")) is not int
            or extension["captured_vectors"] != 8
            or type(extension.get("request_ids")) is not list
            or len(extension["request_ids"]) != 8
            or any(type(item) is not str or _TYPED_REQUEST.fullmatch(item) is None
                   for item in extension["request_ids"])
            or len(set(extension["request_ids"])) != 8
            or type(extension.get("session_ids")) is not list
            or len(extension["session_ids"]) != 8
            or any(type(item) is not str or _TYPED_SESSION.fullmatch(item) is None
                   for item in extension["session_ids"])
            or extension["session_ids"] != sorted(set(extension["session_ids"]))
            or len(set(extension["request_ids"])) != 8
            or set(extension["request_ids"]) & set(requests)
            or set(extension["session_ids"]) & set(sessions)
            or type(extension.get("comparison_errors")) is not list
            or len(extension["comparison_errors"]) != 8
            or any(not _finite_nonnegative_number(item) or item > 1e-3
                   for item in extension["comparison_errors"])
            or not _finite_nonnegative_number(extension.get("max_absolute_error"))
            or extension["max_absolute_error"] != max(extension["comparison_errors"])
            or type(extension.get("token_ids")) is not list
            or len(extension["token_ids"]) != 8
            or any(type(item) is not int or not 0 <= item < 32_000
                   for item in extension["token_ids"])
            or len(set(extension["token_ids"])) != 1
            or type(extension.get("ninth_rejection")) is not dict
            or set(extension["ninth_rejection"]) != {
                "error_code", "coordinator_submits", "tensor_allocations",
                "worker_open_attempts",
                "worker_step_attempts", "used_request_ids_unchanged"}
            or extension["ninth_rejection"].get("error_code") != "CAPACITY_EXHAUSTED"
            or type(extension["ninth_rejection"].get("coordinator_submits")) is not int
            or extension["ninth_rejection"]["coordinator_submits"] != 0
            or type(extension["ninth_rejection"].get("tensor_allocations")) is not int
            or extension["ninth_rejection"]["tensor_allocations"] != 0
            or any(extension["ninth_rejection"].get(key) != [0, 0, 0]
                   or type(extension["ninth_rejection"].get(key)) is not list
                   or any(type(item) is not int for item in extension["ninth_rejection"][key])
                   for key in ("worker_open_attempts", "worker_step_attempts"))
            or extension["ninth_rejection"].get("used_request_ids_unchanged") is not True
            or any(type(extension.get(key)) is not bool or extension[key] is not True
                   for key in ("remote_held_confirmed", "remote_reclaimed_confirmed"))
            or type(extension.get("supervisor_arm_monotonic_ns")) is not int
            or extension["supervisor_arm_monotonic_ns"] <= 0):
        raise SupervisorError("cohort_result", "capacity_extension")
    owner = extension.get("local_owner_check")
    owner_fields = {
        "confirmed", "active_requests", "active_streams", "active_generate_streams",
        "active_captures", "capture_reserved_bytes", "worker_sessions",
        "worker_active_compute", "transport_reserved_connections",
        "transport_reserved_pending",
    }
    if (type(owner) is not dict or set(owner) != owner_fields
            or owner.get("confirmed") is not True
            or any(type(owner.get(key)) is not int or owner[key] != 0 for key in (
                "active_requests", "active_streams", "active_generate_streams",
                "active_captures", "capture_reserved_bytes", "worker_sessions",
                "transport_reserved_pending"))
            or type(owner.get("transport_reserved_connections")) is not int
            or owner["transport_reserved_connections"] != 15
            or type(owner.get("worker_active_compute")) is not bool
            or owner.get("worker_active_compute") is not False
            or type(owner.get("confirmed")) is not bool):
        raise SupervisorError("cohort_result", "capacity_local_owners")
    return {
        "schema_version": 1, "event": "cohort_result_summary", "run_id": value["run_id"],
        "baseline_status": "passed", "completed_requests": 4, "captured_vectors": 27,
        "request_ids": list(requests), "session_ids": list(sessions),
        "capacity": dict(extension),
    }


def _sanitize_partial_admission_cohort_result(value: dict) -> dict:
    """Validate real Open reply-loss evidence without claiming recovery."""
    _validate_result_record(value)
    if any(key in value for key in (
            "interleave", "cancellation", "step_reply_loss", "capacity", "restart")):
        raise SupervisorError("cohort_result", "profile_mismatch")
    baseline = value.get("baseline")
    numerical = value.get("numerical_errors")
    requests, sessions = value.get("request_ids"), value.get("session_ids")
    cases = value.get("cases")
    if (type(baseline) is not dict or baseline.get("status") != "passed"
            or type(baseline.get("completed_requests")) is not int
            or baseline["completed_requests"] != 4
            or type(baseline.get("captured_vectors")) is not int
            or baseline["captured_vectors"] != 27
            or type(numerical) is not dict
            or set(numerical) != {
                "captured_vectors", "max_absolute_error", "values", "atol", "rtol"}
            or type(numerical.get("captured_vectors")) is not int
            or numerical["captured_vectors"] != 27
            or type(numerical.get("values")) is not list
            or len(numerical["values"]) != 27
            or any(not _finite_nonnegative_number(item) or item > 1e-3
                   for item in numerical["values"])
            or not _finite_nonnegative_number(numerical.get("max_absolute_error"))
            or numerical["max_absolute_error"] != max(numerical["values"])
            or type(numerical.get("atol")) not in (int, float)
            or type(numerical.get("rtol")) not in (int, float)
            or numerical["atol"] != 1e-3 or numerical["rtol"] != 0.0
            or type(requests) is not list or len(requests) != 4
            or len(set(requests)) != 4
            or type(sessions) is not list or len(sessions) != 4
            or len(set(sessions)) != 4
            or type(cases) is not list or len(cases) != 4
            or any(type(item) is not dict for item in cases)
            or [item.get("case_id") for item in cases]
               != [case_id for _sequence, case_id in _BASELINE_OBSERVATIONS]
            or any(cases[index].get("request_id") != requests[index]
                   or cases[index].get("session_id") != sessions[index]
                   for index in range(4))):
        raise SupervisorError("cohort_result", "partial_baseline")
    extension = value.get("partial_admission")
    fields = {
        "profile", "status", "request_id", "session_id", "open_attempts",
        "open_reply_order", "step_attempts", "worker3_open_lifetime_ms",
        "actual_tls_open_reply_validated",
        "caller_boundary_reply_loss", "remote_held_session_confirmed",
        "unknown_cleanup_preserved", "remote_lease_expiry_reclaimed",
        "supervisor_arm_monotonic_ns", "local_state",
    }
    if (type(extension) is not dict or set(extension) != fields
            or extension.get("profile") != PROFILE_C1B_PARTIAL
            or extension.get("status") != "passed"
            or type(extension.get("request_id")) is not str
            or _TYPED_REQUEST.fullmatch(extension["request_id"]) is None
            or type(extension.get("session_id")) is not str
            or _TYPED_SESSION.fullmatch(extension["session_id"]) is None
            or extension["request_id"] in requests
            or extension["session_id"] in sessions
            or extension.get("open_attempts") != [1, 1, 1]
            or type(extension.get("open_attempts")) is not list
            or any(type(item) is not int for item in extension["open_attempts"])
            or extension.get("open_reply_order") != [0, 1, 2]
            or type(extension.get("open_reply_order")) is not list
            or any(type(item) is not int for item in extension["open_reply_order"])
            or extension.get("step_attempts") != [0, 0, 0]
            or type(extension.get("step_attempts")) is not list
            or any(type(item) is not int for item in extension["step_attempts"])
            or type(extension.get("worker3_open_lifetime_ms")) is not int
            or not 1 <= extension["worker3_open_lifetime_ms"] <= 10_000
            or any(type(extension.get(key)) is not bool or extension[key] is not True
                   for key in ("actual_tls_open_reply_validated",
                               "caller_boundary_reply_loss",
                               "remote_held_session_confirmed",
                               "unknown_cleanup_preserved",
                               "remote_lease_expiry_reclaimed"))):
        raise SupervisorError("cohort_result", "partial_extension")
    arm_ns = extension.get("supervisor_arm_monotonic_ns")
    if type(arm_ns) is not int or arm_ns <= 0:
        raise SupervisorError("cohort_result", "partial_arm_time")
    local = extension.get("local_state")
    local_fields = {
        "state", "logical_cleanup_confirmed", "coordinator_ready", "active_requests",
        "unknown_open_indices", "known_lease_indices", "active_streams",
        "active_generate_streams", "worker_sessions", "worker_active_compute",
        "bridge_owned_sessions", "bridge_active_authorizations", "bridge_pending_notices",
        "active_captures", "cleanup_pending_captures", "capture_reserved_bytes",
        "transport_reserved_connections", "transport_reserved_pending",
    }
    if (type(local) is not dict or set(local) != local_fields
            or local.get("state") != "restart_fenced_retained"
            or local.get("logical_cleanup_confirmed") is not False
            or local.get("coordinator_ready") is not False
            or type(local.get("active_requests")) is not int
            or local["active_requests"] != 1
            or local.get("unknown_open_indices") != [2]
            or type(local.get("unknown_open_indices")) is not list
            or any(type(item) is not int for item in local["unknown_open_indices"])
            or local.get("known_lease_indices") != []
            or type(local.get("known_lease_indices")) is not list
            or any(type(local.get(key)) is not int or local[key] < 0 for key in (
                "active_streams", "active_generate_streams"))
            or local["active_streams"] > 1
            or local["active_generate_streams"] > 1
            or any(type(local.get(key)) is not int or local[key] != 0 for key in (
                "worker_sessions", "bridge_owned_sessions", "bridge_active_authorizations",
                "bridge_pending_notices", "active_captures", "cleanup_pending_captures",
                "capture_reserved_bytes", "transport_reserved_pending"))
            or type(local.get("worker_active_compute")) is not bool
            or local["worker_active_compute"] is not False
            or type(local.get("transport_reserved_connections")) is not int
            or local["transport_reserved_connections"] != 15):
        raise SupervisorError("cohort_result", "partial_local_state")
    shutdown = value.get("local_shutdown")
    shutdown_fields = {
        "confirmed", "failure_types", "restart_fenced_retained",
        "retained_components", "owner_counts",
    }
    count_fields = {
        "active_requests", "active_streams", "coordinator_cleanup_tasks",
        "active_generate_streams", "worker_sessions", "bridge_owned_sessions",
        "worker_active_compute", "bridge_active_authorizations", "bridge_pending_notices", "active_captures",
        "cleanup_pending_captures", "capture_reserved_bytes",
        "transport_reserved_connections", "transport_reserved_pending",
        "transport_reserved_outbound_pending", "transport_reserved_listener_pending",
    }
    allowed_components = {
        "coordinator_close", "coordinator_service_streams", "secure_generate_streams",
    }
    owner_counts = shutdown.get("owner_counts") if type(shutdown) is dict else None
    components = shutdown.get("retained_components") if type(shutdown) is dict else None
    failure_types = shutdown.get("failure_types") if type(shutdown) is dict else None
    if (type(shutdown) is not dict or set(shutdown) != shutdown_fields
            or shutdown.get("confirmed") is not False
            or shutdown.get("restart_fenced_retained") is not True
            or type(failure_types) is not list
            or not 1 <= len(failure_types) <= 3
            or any(type(item) is not str or item != "CohortError"
                   for item in failure_types)
            or type(components) is not list
            or any(type(item) is not str for item in components)
            or components != sorted(set(components))
            or not set(components) <= allowed_components
            or len(components) != len(failure_types)
            or type(owner_counts) is not dict or set(owner_counts) != count_fields
            or any(type(owner_counts[key]) is not int or owner_counts[key] < 0
                   for key in count_fields - {"worker_active_compute"})
            or type(owner_counts.get("worker_active_compute")) is not bool
            or owner_counts["worker_active_compute"] is not False):
        raise SupervisorError("cohort_result", "partial_fence_shutdown")
    expected_components = {"coordinator_close"}
    if owner_counts["active_streams"] or owner_counts["coordinator_cleanup_tasks"]:
        expected_components.add("coordinator_service_streams")
    if owner_counts["active_generate_streams"]:
        expected_components.add("secure_generate_streams")
    if (owner_counts["active_requests"] != 1
            or owner_counts["active_streams"] > 1
            or owner_counts["coordinator_cleanup_tasks"] > 1
            or owner_counts["active_generate_streams"] > 1
            or any(owner_counts[key] != 0 for key in count_fields - {
                "active_requests", "active_streams", "coordinator_cleanup_tasks",
                "active_generate_streams"})
            or components != sorted(expected_components)):
        raise SupervisorError("cohort_result", "partial_owner_projection")
    return {
        "schema_version": 1, "event": "cohort_result_summary", "run_id": value["run_id"],
        "baseline_status": "passed", "completed_requests": 4, "captured_vectors": 27,
        "request_ids": list(requests), "session_ids": list(sessions),
        "partial_admission": {
            "profile": PROFILE_C1B_PARTIAL, "status": "passed",
            "request_id": extension["request_id"], "session_id": extension["session_id"],
            "worker3_open_lifetime_ms": extension["worker3_open_lifetime_ms"],
            "supervisor_arm_monotonic_ns": arm_ns,
            "local_state": dict(local),
        },
        "local_shutdown": {
            "confirmed": False,
            "failure_types": list(failure_types),
            "restart_fenced_retained": True,
            "retained_components": list(components),
            "owner_counts": dict(owner_counts),
        },
    }


def _sanitize_interleave_cohort_result(value: dict) -> dict:
    _validate_result_record(value)
    if any(key in value for key in (
            "cancellation", "partial_admission", "step_reply_loss", "capacity",
            "restart")):
        raise SupervisorError("cohort_result", "profile_mismatch")
    baseline = value["baseline"]
    numerical = value.get("numerical_errors")
    if (baseline.get("status") != "passed"
            or type(baseline.get("completed_requests")) is not int
            or baseline["completed_requests"] != 4
            or type(baseline.get("captured_vectors")) is not int
            or baseline["captured_vectors"] != 27
            or type(numerical) is not dict
            or set(numerical) != {"captured_vectors", "max_absolute_error", "values", "atol", "rtol"}
            or type(numerical.get("captured_vectors")) is not int
            or numerical["captured_vectors"] != 27
            or type(numerical.get("values")) is not list
            or len(numerical["values"]) != 27
            or any(not _finite_nonnegative_number(item) or item > 1e-3
                   for item in numerical["values"])
            or not _finite_nonnegative_number(numerical.get("max_absolute_error"))
            or numerical["max_absolute_error"] != max(numerical["values"])
            or type(numerical.get("atol")) not in (int, float)
            or type(numerical.get("rtol")) not in (int, float)
            or not math.isfinite(numerical["atol"])
            or not math.isfinite(numerical["rtol"])
            or numerical["atol"] != 1e-3 or numerical["rtol"] != 0.0):
        raise SupervisorError("cohort_result", "interleave_baseline")
    requests, sessions = value["request_ids"], value["session_ids"]
    if (len(requests) != 4 or len(set(requests)) != 4
            or len(sessions) != 4 or len(set(sessions)) != 4):
        raise SupervisorError("cohort_result", "interleave_baseline_ids")
    baseline_cases = value.get("cases")
    expected_cases = [case_id for _sequence, case_id in _BASELINE_OBSERVATIONS]
    if (type(baseline_cases) is not list or len(baseline_cases) != 4
            or any(type(case) is not dict for case in baseline_cases)
            or [case.get("case_id") for case in baseline_cases] != expected_cases
            or [case.get("request_id") for case in baseline_cases] != requests
            or [case.get("session_id") for case in baseline_cases] != sessions):
        raise SupervisorError("cohort_result", "interleave_baseline_cases")
    extension = value.get("interleave")
    fields = {
        "profile", "status", "completed_requests", "prompt_lengths",
        "captured_vectors", "comparison_errors", "max_absolute_error",
        "request_ids", "session_ids", "step_trace", "causal_barrier_confirmed",
        "local_owner_check", "remote_owner_check_confirmed",
    }
    if (type(extension) is not dict or set(extension) != fields
            or extension.get("profile") != PROFILE_C1B_INTERLEAVE
            or extension.get("status") != "passed"
            or type(extension.get("completed_requests")) is not int
            or extension["completed_requests"] != 2
            or type(extension.get("prompt_lengths")) is not list
            or len(extension["prompt_lengths"]) != 2
            or any(type(item) is not int for item in extension["prompt_lengths"])
            or extension["prompt_lengths"] != [5, 11]
            or type(extension.get("captured_vectors")) is not int
            or extension["captured_vectors"] != 8):
        raise SupervisorError("cohort_result", "interleave_extension")
    errors = extension["comparison_errors"]
    if (type(errors) is not list or len(errors) != 8
            or any(not _finite_nonnegative_number(error) or error > 1e-3 for error in errors)
            or not _finite_nonnegative_number(extension.get("max_absolute_error"))
            or extension["max_absolute_error"] != max(errors)):
        raise SupervisorError("cohort_result", "interleave_numerics")
    extension_requests, extension_sessions = (extension["request_ids"],
                                               extension["session_ids"])
    if (type(extension_requests) is not list or len(extension_requests) != 2
            or any(type(item) is not str or _TYPED_REQUEST.fullmatch(item) is None
                   for item in extension_requests)
            or len(set(extension_requests)) != 2 or set(extension_requests) & set(requests)
            or type(extension_sessions) is not list or len(extension_sessions) != 2
            or any(type(item) is not str or _TYPED_SESSION.fullmatch(item) is None
                   for item in extension_sessions)
            or len(set(extension_sessions)) != 2 or set(extension_sessions) & set(sessions)):
        raise SupervisorError("cohort_result", "interleave_ids")
    if (extension["step_trace"] != ["A0", "B0", "A1", "B1"]
            or type(extension["causal_barrier_confirmed"]) is not bool
            or extension["causal_barrier_confirmed"] is not True
            or type(extension["remote_owner_check_confirmed"]) is not bool
            or extension["remote_owner_check_confirmed"] is not True):
        raise SupervisorError("cohort_result", "interleave_causality")
    owner = extension["local_owner_check"]
    owner_fields = {
        "confirmed", "active_requests", "active_streams", "active_generate_streams",
        "active_captures", "capture_reserved_bytes", "worker_sessions",
        "worker_active_compute", "transport_reserved_connections",
        "transport_reserved_pending",
    }
    if (type(owner) is not dict or set(owner) != owner_fields
            or owner.get("confirmed") is not True
            or any(type(owner.get(field)) is not int or owner[field] != 0
                   for field in ("active_requests", "active_streams", "active_generate_streams",
                                 "active_captures", "capture_reserved_bytes", "worker_sessions",
                                 "transport_reserved_pending"))
            or owner.get("worker_active_compute") is not False
            or type(owner.get("transport_reserved_connections")) is not int
            or owner["transport_reserved_connections"] != 15):
        raise SupervisorError("cohort_result", "interleave_local_owners")
    return {
        "schema_version": 1, "event": "cohort_result_summary",
        "run_id": value["run_id"], "baseline_status": "passed",
        "completed_requests": 4, "captured_vectors": 27,
        "max_absolute_error": numerical["max_absolute_error"],
        "request_ids": list(requests), "session_ids": list(sessions),
        "interleave": {
            "profile": PROFILE_C1B_INTERLEAVE, "status": "passed",
            "completed_requests": 2, "captured_vectors": 8,
            "max_absolute_error": extension["max_absolute_error"],
            "request_ids": list(extension_requests),
            "session_ids": list(extension_sessions),
            "step_trace": list(extension["step_trace"]),
            "causal_barrier_confirmed": True,
            "remote_owner_check_confirmed": True,
        },
        "failure_type": value.get("failure_type")
            if type(value.get("failure_type")) is str and re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{0,79}", value["failure_type"]) else None,
    }


def _sudo_prefix(password: str | None) -> list[str]:
    return ["sudo", "-S", "-p", "", "--"] if password is not None else ["sudo", "-n", "--"]


def _ssh_exec(client, argv: list[str], *, password: str | None,
              deadline: float, output_limit=CONTROL_LIMIT, sudo=True) -> tuple[int, bytes]:
    if not argv or any(type(v) is not str or "\x00" in v for v in argv):
        raise SupervisorError("ssh_command", "argv")
    remote_argv = (_sudo_prefix(password) if sudo else []) + argv
    command = shlex.join(remote_argv)
    channel = None
    try:
        _deadline_remaining(deadline, "ssh_command")
        transport = client.get_transport()
        if transport is None:
            raise SupervisorError("ssh_command", "transport_unavailable")
        channel = transport.open_session(
            timeout=min(_deadline_remaining(deadline, "ssh_command"), 30.0))
        channel.settimeout(_deadline_remaining(deadline, "ssh_command"))
        _channel_operation(
            channel, lambda: channel.exec_command(command), deadline=deadline,
            stage="ssh_command", failure_code="transport_error")
        stdin = channel.makefile_stdin("wb", -1)
        stdout = channel.makefile("r", -1)
        stderr = channel.makefile_stderr("r", -1)
        if password is not None and sudo:
            channel.settimeout(_deadline_remaining(deadline, "ssh_command"))
            stdin.write(password + "\n")
            channel.settimeout(_deadline_remaining(deadline, "ssh_command"))
            stdin.flush()
        channel.settimeout(_deadline_remaining(deadline, "ssh_command"))
        channel.shutdown_write()
        output = bytearray()
        output_overflow = False
        while True:
            while channel.recv_ready():
                channel.settimeout(_deadline_remaining(deadline, "ssh_command"))
                chunk = channel.recv(65536)
                if len(output) < output_limit + 1:
                    output.extend(chunk[:output_limit + 1 - len(output)])
                if len(output) > output_limit:
                    output_overflow = True
            while channel.recv_stderr_ready():
                channel.settimeout(_deadline_remaining(deadline, "ssh_command"))
                channel.recv_stderr(65536)  # Drain and discard all remote diagnostics.
            if channel.exit_status_ready():
                break
            remaining = _deadline_remaining(deadline, "ssh_command")
            time.sleep(min(0.02, remaining))
        while channel.recv_ready():
            channel.settimeout(_deadline_remaining(deadline, "ssh_command"))
            chunk = channel.recv(65536)
            if len(output) < output_limit + 1:
                output.extend(chunk[:output_limit + 1 - len(output)])
            if len(output) > output_limit:
                output_overflow = True
        while channel.recv_stderr_ready():
            channel.settimeout(_deadline_remaining(deadline, "ssh_command"))
            channel.recv_stderr(65536)
        channel.settimeout(_deadline_remaining(deadline, "ssh_command"))
        status = channel.recv_exit_status()
        _deadline_remaining(deadline, "ssh_command")
        if output_overflow:
            raise SupervisorError("ssh_command", "output_bound")
        return status, bytes(output)
    except SupervisorError as error:
        if channel is not None and error.code != "ack_timeout_unknown":
            try:
                _abort_channel(channel)
            except Exception:
                pass
        raise
    except socket.timeout:
        if channel is not None:
            try:
                _abort_channel(channel)
            except Exception:
                pass
        raise SupervisorError("ssh_command", "timeout") from None
    except Exception:
        if channel is not None:
            try:
                _abort_channel(channel)
            except Exception:
                pass
        raise SupervisorError("ssh_command", "transport_error") from None


def _ssh_checked(client, argv, *, password, deadline, output_limit=CONTROL_LIMIT,
                 sudo=True) -> bytes:
    _deadline_remaining(deadline, "ssh_command")
    code, output = _ssh_exec(client, argv, password=password,
                             deadline=deadline,
                             output_limit=output_limit, sudo=sudo)
    if code != 0:
        raise SupervisorError("ssh_command", "command_failed")
    return output


def _remote_script(client, script: str, args: list[str], *, password,
                   deadline, output_limit=CONTROL_LIMIT, sudo=True) -> bytes:
    return _ssh_checked(client, ["python3", "-c", script, *args],
                        password=password, deadline=deadline,
                        output_limit=output_limit, sudo=sudo)


_REMOTE_OWNER_STAGE_PREFLIGHT_SCRIPT = r'''import json,os,stat,sys
root=sys.argv[1];uid=int(sys.argv[2]);gid=int(sys.argv[3])
if (not root.startswith("/") or root=="/" or os.path.normpath(root)!=root
    or "\\" in root or "\x00" in root or len(os.fsencode(root))>4096): raise SystemExit(80)
parts=root[1:].split("/")
if not parts or len(parts)>16 or any(p in ("",".","..") for p in parts): raise SystemExit(81)
df=os.open("/",os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
try:
 for part in parts:
  nf=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=df)
  os.close(df);df=nf
 root_stat=os.fstat(df)
 if (root_stat.st_uid!=uid or root_stat.st_gid!=gid or stat.S_IMODE(root_stat.st_mode)!=0o700): raise SystemExit(82)
 fd=os.open("owner-upload.bin",os.O_RDONLY|os.O_NONBLOCK|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=df)
 try:
  st=os.fstat(fd); named=os.stat("owner-upload.bin",dir_fd=df,follow_symlinks=False)
  identity=lambda x:(x.st_dev,x.st_ino,x.st_mode,x.st_uid,x.st_gid,x.st_nlink,x.st_size,x.st_mtime_ns,x.st_ctime_ns)
  if (not stat.S_ISREG(st.st_mode) or st.st_uid!=uid or st.st_gid!=gid
      or stat.S_IMODE(st.st_mode)!=0o600 or st.st_nlink!=1 or st.st_size!=0
      or identity(st)!=identity(named)): raise SystemExit(83)
  print(json.dumps({"event":"owner_stage_preflight","uid":st.st_uid,"gid":st.st_gid,
       "mode":stat.S_IMODE(st.st_mode),"nlink":st.st_nlink,"size":st.st_size},
       sort_keys=True,separators=(",",":")))
 finally: os.close(fd)
finally: os.close(df)
'''


_REMOTE_OWNER_ACK_READ_SCRIPT = r'''import hashlib,json,os,stat,sys
path=sys.argv[1];uid=int(sys.argv[2]);gid=int(sys.argv[3]);limit=16384;missing_ok=sys.argv[4]=="1"
if (not path.startswith("/") or path=="/" or os.path.normpath(path)!=path
    or "\\" in path or "\x00" in path or len(os.fsencode(path))>4096): raise SystemExit(90)
parts=path[1:].split("/")
if (len(parts)<2 or len(parts)>17 or parts[-1]!="owner-ack.json"
    or any(p in ("",".","..") for p in parts)): raise SystemExit(91)
def pairs(items):
 out={}
 for k,v in items:
  if k in out: raise ValueError("duplicate")
  out[k]=v
 return out
def constant(_): raise ValueError("nonfinite")
df=os.open("/",os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
try:
 for part in parts[:-1]:
  nf=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=df)
  os.close(df);df=nf
 root_stat=os.fstat(df)
 if (not stat.S_ISDIR(root_stat.st_mode) or root_stat.st_uid!=uid
     or root_stat.st_gid!=gid or stat.S_IMODE(root_stat.st_mode)!=0o700): raise SystemExit(92)
 try: fd=os.open(parts[-1],os.O_RDONLY|os.O_NONBLOCK|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=df)
 except FileNotFoundError:
  if not missing_ok: raise
  print(json.dumps({"schema_version":1,"event":"owner_ack_read","ack":None,"provenance":None,"missing":True},sort_keys=True,separators=(",",":")))
  raise SystemExit(0)
 try:
  before=os.fstat(fd)
  if (not stat.S_ISREG(before.st_mode) or before.st_uid!=uid or before.st_gid!=gid
      or stat.S_IMODE(before.st_mode)!=0o600 or before.st_nlink!=1
      or not 1<=before.st_size<=limit): raise SystemExit(93)
  chunks=[];total=0
  while total<=before.st_size:
   block=os.read(fd,min(4096,before.st_size+1-total))
   if not block: break
   chunks.append(block);total+=len(block)
   if total>limit: raise SystemExit(94)
  raw=b"".join(chunks)
  after=os.fstat(fd);named=os.stat(parts[-1],dir_fd=df,follow_symlinks=False)
  identity=lambda x:(x.st_dev,x.st_ino,x.st_mode,x.st_uid,x.st_gid,x.st_nlink,x.st_size,x.st_mtime_ns,x.st_ctime_ns)
  if (len(raw)!=before.st_size or identity(before)!=identity(after)
      or identity(after)!=identity(named)): raise SystemExit(95)
  try: ack=json.loads(raw.decode("utf-8","strict"),object_pairs_hook=pairs,parse_constant=constant)
  except (UnicodeError,ValueError,TypeError,RecursionError): raise SystemExit(96)
  if type(ack) is not dict: raise SystemExit(97)
  provenance={"uid":before.st_uid,"gid":before.st_gid,"mode":stat.S_IMODE(before.st_mode),
      "size":len(raw),"mtime_ns":before.st_mtime_ns,"sha256":hashlib.sha256(raw).hexdigest(),
      "metadata_stable":True}
  print(json.dumps({"schema_version":1,"event":"owner_ack_read","ack":ack,
      "provenance":provenance},sort_keys=True,separators=(",",":"),allow_nan=False))
 finally: os.close(fd)
finally: os.close(df)
'''


_REMOTE_OWNER_SIDECAR_VERIFY_SCRIPT = r'''import hashlib,json,os,stat,sys
root=sys.argv[1];uid=int(sys.argv[2]);gid=int(sys.argv[3])
expected={"snapshot.pub":sys.argv[4],"install-intent.json":sys.argv[5],"removal-intent.json":sys.argv[6]}
limits={"snapshot.pub":65536,"install-intent.json":16384,"removal-intent.json":16384}
if (not root.startswith("/") or root=="/" or os.path.normpath(root)!=root
    or "\\" in root or "\x00" in root or len(os.fsencode(root))>4096
    or len(expected)!=3 or any(len(x)!=64 or any(c not in "0123456789abcdef" for c in x) for x in expected.values())): raise SystemExit(110)
parts=root[1:].split("/")
if not parts or len(parts)>16 or any(p in ("",".","..") for p in parts): raise SystemExit(111)
flags=os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC
df=os.open("/",flags)
try:
 for part in parts:
  nf=os.open(part,flags,dir_fd=df);os.close(df);df=nf
 ds=os.fstat(df)
 if (not stat.S_ISDIR(ds.st_mode) or ds.st_uid!=uid or ds.st_gid!=gid
     or stat.S_IMODE(ds.st_mode)!=0o700 or set(os.listdir(df))!=set(expected)): raise SystemExit(112)
 found={};identities={}
 for name,digest in expected.items():
  fd=os.open(name,os.O_RDONLY|os.O_NONBLOCK|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=df)
  try:
   before=os.fstat(fd)
   if (not stat.S_ISREG(before.st_mode) or before.st_uid!=uid or before.st_gid!=gid
       or stat.S_IMODE(before.st_mode)!=0o600 or before.st_nlink!=1
       or not 1<=before.st_size<=limits[name]): raise SystemExit(113)
   chunks=[];total=0
   while total<=before.st_size:
    block=os.read(fd,min(4096,before.st_size+1-total))
    if not block: break
    chunks.append(block);total+=len(block)
    if total>limits[name]: raise SystemExit(114)
   raw=b"".join(chunks);after=os.fstat(fd);named=os.stat(name,dir_fd=df,follow_symlinks=False)
   ident=lambda x:(x.st_dev,x.st_ino,x.st_mode,x.st_uid,x.st_gid,x.st_nlink,x.st_size,x.st_mtime_ns,x.st_ctime_ns)
   actual=hashlib.sha256(raw).hexdigest()
   if (len(raw)!=before.st_size or ident(before)!=ident(after) or ident(after)!=ident(named)
       or actual!=digest): raise SystemExit(115)
   found[name]=actual
   identities[name]=ident(after)
  finally: os.close(fd)
 ds_after=os.fstat(df)
 if ((ds.st_dev,ds.st_ino,ds.st_mode,ds.st_uid,ds.st_gid,ds.st_nlink,ds.st_mtime_ns,ds.st_ctime_ns)
     !=(ds_after.st_dev,ds_after.st_ino,ds_after.st_mode,ds_after.st_uid,ds_after.st_gid,ds_after.st_nlink,ds_after.st_mtime_ns,ds_after.st_ctime_ns)
     or set(os.listdir(df))!=set(expected)): raise SystemExit(116)
 for name in expected:
  named=os.stat(name,dir_fd=df,follow_symlinks=False)
  if ident(named)!=identities[name]: raise SystemExit(117)
 print(json.dumps({"schema_version":1,"event":"owner_intent_sidecar_verified","files":found},sort_keys=True,separators=(",",":"),allow_nan=False))
finally: os.close(df)
'''


def _verify_owner_intent_sidecar(client, *, intent_root, uid, gid, password,
                                 deadline, material_files):
    if (type(material_files) is not dict
            or set(material_files) != set(OWNER_MATERIAL_NAMES) | {"snapshot.pub"}):
        raise SupervisorError("owner_sidecar", "material_set")
    hashes = {name: hashlib.sha256(material_files[name]).hexdigest()
              for name in ("snapshot.pub", "install-intent.json", "removal-intent.json")}
    output = _remote_script(
        client, _REMOTE_OWNER_SIDECAR_VERIFY_SCRIPT,
        [_remote_path(intent_root, label="owner_intent_root"), str(uid), str(gid),
         hashes["snapshot.pub"], hashes["install-intent.json"],
         hashes["removal-intent.json"]], password=password,
        deadline=deadline, output_limit=2048, sudo=False)
    receipt = _json_load(output, 2048, label="owner_sidecar_receipt")
    expected = {"schema_version": 1, "event": "owner_intent_sidecar_verified",
                "files": hashes}
    _exact_fields(receipt, {"schema_version", "event", "files"},
                  "owner_sidecar_receipt")
    if (type(receipt.get("schema_version")) is not int
            or receipt["schema_version"] != 1
            or type(receipt.get("event")) is not str
            or receipt["event"] != expected["event"]
            or type(receipt.get("files")) is not dict
            or set(receipt["files"]) != set(hashes)
            or any(type(value) is not str or _HEX64.fullmatch(value) is None
                   for value in receipt["files"].values())
            or receipt["files"] != hashes):
        raise SupervisorError("owner_sidecar", "receipt_mismatch")
    return receipt


_REMOTE_OWNER_VERIFIER_PUBLISH_SCRIPT = r'''import hashlib,json,os,stat,sys
root=sys.argv[1];uid=int(sys.argv[2]);gid=int(sys.argv[3]);size=int(sys.argv[4]);digest=sys.argv[5]
if (not root.startswith("/") or root=="/" or os.path.normpath(root)!=root
    or "\\" in root or "\x00" in root or len(os.fsencode(root))>4096
    or not 1<=size<=65536 or len(digest)!=64
    or any(c not in "0123456789abcdef" for c in digest)): raise SystemExit(100)
parts=root[1:].split("/")
if not parts or len(parts)>16 or any(p in ("",".","..") for p in parts): raise SystemExit(101)
flags=os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC
df=os.open("/",flags)
try:
 for part in parts:
  nf=os.open(part,flags,dir_fd=df);os.close(df);df=nf
 ds=os.fstat(df)
 if (not stat.S_ISDIR(ds.st_mode) or ds.st_uid!=uid or ds.st_gid!=gid
     or stat.S_IMODE(ds.st_mode)!=0o700): raise SystemExit(102)
 fd=os.open("owner-verifier-upload.bin",os.O_RDONLY|os.O_NONBLOCK|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=df)
 try:
  s=os.fstat(fd)
  if (not stat.S_ISREG(s.st_mode) or s.st_uid!=uid or s.st_gid!=gid
      or stat.S_IMODE(s.st_mode)!=0o600 or s.st_nlink!=1 or s.st_size!=size): raise SystemExit(103)
  b=os.read(fd,size+1);z=os.fstat(fd)
  if (len(b)!=size or (s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size,s.st_mtime_ns)!=(z.st_dev,z.st_ino,z.st_mode,z.st_uid,z.st_gid,z.st_nlink,z.st_size,z.st_mtime_ns)
      or hashlib.sha256(b).hexdigest()!=digest): raise SystemExit(104)
  os.fsync(fd)
 finally: os.close(fd)
 try: os.link("owner-verifier-upload.bin","snapshot.pub",src_dir_fd=df,dst_dir_fd=df,follow_symlinks=False)
 except FileExistsError: raise SystemExit(105)
 os.unlink("owner-verifier-upload.bin",dir_fd=df);os.fsync(df)
 out=os.open("snapshot.pub",os.O_RDONLY|os.O_NONBLOCK|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=df)
 try:
  s=os.fstat(out);b=os.read(out,size+1);z=os.fstat(out);named=os.stat("snapshot.pub",dir_fd=df,follow_symlinks=False)
  ident=lambda x:(x.st_dev,x.st_ino,x.st_mode,x.st_uid,x.st_gid,x.st_nlink,x.st_size,x.st_mtime_ns,x.st_ctime_ns)
  if (not stat.S_ISREG(s.st_mode) or s.st_uid!=uid or s.st_gid!=gid
      or stat.S_IMODE(s.st_mode)!=0o600 or s.st_nlink!=1 or s.st_size!=size
      or len(b)!=size or hashlib.sha256(b).hexdigest()!=digest
      or ident(s)!=ident(z) or ident(z)!=ident(named)): raise SystemExit(106)
  os.fsync(out)
 finally: os.close(out)
 os.fsync(df)
 print(json.dumps({"schema_version":1,"event":"owner_verifier_copy","uid":uid,"gid":gid,"mode":384,"size":size,"sha256":digest,"fsynced":True,"readback":True},sort_keys=True,separators=(",",":")))
finally: os.close(df)
'''


def _owner_file_limits(kind):
    if type(kind) is not str:
        raise SupervisorError("owner_publish", "kind")
    if kind in {"install_intent", "removal_intent", "command1", "command2"}:
        return OWNER_CONTROL_LIMIT
    if kind in {"policy1", "policy2"}:
        return OWNER_POLICY_LIMIT
    raise SupervisorError("owner_publish", "kind")


def _validate_owner_stage_preflight(raw, *, uid, gid):
    value = _json_load(raw, 512, label="owner_stage_preflight")
    _exact_fields(value, {"event", "uid", "gid", "mode", "nlink", "size"},
                  "owner_stage_preflight")
    if (value["event"] != "owner_stage_preflight"
            or any(type(value.get(key)) is not int for key in (
                "uid", "gid", "mode", "nlink", "size"))
            or value["uid"] != uid or value["gid"] != gid
            or value["mode"] != 0o600 or value["nlink"] != 1 or value["size"] != 0):
        raise SupervisorError("owner_stage_preflight", "metadata")
    return value


def _publish_owner_file(client, raw, *, kind, job_root, intent_root, uid, gid,
                        password, deadline, expected_prior_sha256="", on_attempt=None):
    """Stage bytes over managed SFTP, then commit once with the fixed fsync script."""
    limit = _owner_file_limits(kind)
    if type(raw) is not bytes or not 1 <= len(raw) <= limit:
        raise SupervisorError("owner_publish", "size")
    try:
        checked_job_root = _remote_path(job_root, label="remote_job_root")
        checked_intent_root = _remote_path(intent_root, label="owner_intent_root")
        plan = build_publication_plan(
            kind, intent_root=checked_intent_root, job_root=checked_job_root,
            uid=uid, gid=gid,
            sha256=hashlib.sha256(raw).hexdigest(), size=len(raw),
            expected_prior_sha256=expected_prior_sha256)
    except (TypeError, ValueError):
        raise SupervisorError("owner_publish", "plan") from None
    _deadline_remaining(deadline, "owner_publish")
    sftp = None
    stream = None
    stream_closed = False
    try:
        sftp = _open_sftp(client, deadline)
        if on_attempt is not None:
            if not callable(on_attempt):
                raise SupervisorError("owner_publish", "attempt_callback")
            try:
                callback_result = on_attempt()
            except Exception:
                raise SupervisorError("owner_publish", "attempt_record_failed") from None
            if callback_result is not None:
                raise SupervisorError("owner_publish", "attempt_record_failed")
        stage_path = posixpath.join(plan.root, "owner-upload.bin")
        stream = _sftp_call(sftp, deadline, "owner_publish_stage",
                            lambda: sftp.open(stage_path, "wx"))
        _sftp_call(sftp, deadline, "owner_publish_stage", lambda: stream.chmod(0o600))
        initial = _sftp_call(sftp, deadline, "owner_publish_stage", stream.stat)
        initial_nlink = getattr(initial, "st_nlink", None)
        if (type(getattr(initial, "st_uid", None)) is not int or initial.st_uid != uid
                or type(getattr(initial, "st_gid", None)) is not int or initial.st_gid != gid
                or type(getattr(initial, "st_mode", None)) is not int
                or not stat.S_ISREG(initial.st_mode)
                or stat.S_IMODE(initial.st_mode) != 0o600
                or type(getattr(initial, "st_size", None)) is not int or initial.st_size != 0
                or (initial_nlink is not None
                    and (type(initial_nlink) is not int or initial_nlink != 1))):
            raise SupervisorError("owner_publish_stage", "metadata")
        preflight = _remote_script(
            client, _REMOTE_OWNER_STAGE_PREFLIGHT_SCRIPT,
            [plan.root, str(uid), str(gid)], password=password, deadline=deadline,
            output_limit=512, sudo=False)
        _validate_owner_stage_preflight(preflight, uid=uid, gid=gid)
        _sftp_call(sftp, deadline, "owner_publish_stage",
                   lambda: stream.set_pipelined(False))
        _sftp_call(sftp, deadline, "owner_publish_stage", lambda: stream.write(raw))
        _sftp_call(sftp, deadline, "owner_publish_stage", stream.flush)
        _sftp_call(sftp, deadline, "owner_publish_stage", stream.close)
        stream_closed = True
        stream = None
        final = _sftp_call(sftp, deadline, "owner_publish_stage",
                           lambda: sftp.stat(stage_path))
        final_nlink = getattr(final, "st_nlink", None)
        if (type(getattr(final, "st_uid", None)) is not int or final.st_uid != uid
                or type(getattr(final, "st_gid", None)) is not int or final.st_gid != gid
                or type(getattr(final, "st_mode", None)) is not int
                or not stat.S_ISREG(final.st_mode) or stat.S_IMODE(final.st_mode) != 0o600
                or type(getattr(final, "st_size", None)) is not int or final.st_size != len(raw)
                or (final_nlink is not None
                    and (type(final_nlink) is not int or final_nlink != 1))):
            raise SupervisorError("owner_publish_stage", "metadata")
        _sftp_call(sftp, deadline, "owner_publish_stage", sftp.close)
        sftp = None
        receipt_raw = _remote_script(
            client, REMOTE_PUBLISH_SCRIPT, list(plan.argv), password=password,
            deadline=deadline, output_limit=2048, sudo=False)
        receipt = _json_load(receipt_raw, 2048, label="owner_publish_receipt")
        try:
            return validate_publication_receipt(receipt, plan=plan)
        except ValueError:
            raise SupervisorError("owner_publish_receipt", "invalid") from None
    except SupervisorError:
        raise
    except Exception:
        raise SupervisorError("owner_publish", "operation_failed") from None
    finally:
        if sftp is not None:
            try:
                channel_owned = _channel_operation_owned(sftp.get_channel())
            except Exception:
                channel_owned = True
            if not channel_owned:
                if stream is not None and not stream_closed:
                    try:
                        _sftp_call(sftp, deadline, "owner_publish_stage", stream.close)
                    except SupervisorError as error:
                        if error.code in {"ack_timeout_unknown", "operation_ownership_pending"}:
                            channel_owned = True
                    except Exception:
                        pass
                if not channel_owned:
                    try:
                        _sftp_call(sftp, deadline, "owner_publish_stage", sftp.close)
                    except SupervisorError as error:
                        if error.code not in {"ack_timeout_unknown", "operation_ownership_pending"}:
                            _abort_sftp(sftp)
                    except Exception:
                        _abort_sftp(sftp)


def _ensure_owner_intent_root(client, *, job_root, uid, gid, password, deadline,
                              on_attempt=None):
    """Exclusively create the fixed external sidecar and retain it indefinitely."""
    if (type(uid) is not int or uid != REMOTE_STATUS_UID or type(gid) is not int
            or not 0 <= gid <= 2**31 - 1):
        raise SupervisorError("owner_intent_root", "owner")
    base = _remote_path(job_root, label="remote_job_root")
    intent_root = _remote_path(base + "-owner-intents", label="owner_intent_root")
    _deadline_remaining(deadline, "owner_intent_root")
    if on_attempt is not None:
        if not callable(on_attempt):
            raise SupervisorError("owner_intent_root", "attempt_callback")
        try:
            result = on_attempt()
        except Exception:
            raise SupervisorError("owner_intent_root", "attempt_record_failed") from None
        if result is not None:
            raise SupervisorError("owner_intent_root", "attempt_record_failed")
    output = _remote_script(client, _REMOTE_CREATE_JOB_SCRIPT,
                            [intent_root, str(uid), str(gid)], password=password,
                            deadline=deadline, output_limit=256)
    if output.strip() != b"created":
        raise SupervisorError("owner_intent_root", "create_unconfirmed")
    return intent_root


def _install_owner_verifier_copy(client, raw: bytes, *, intent_root, uid, gid,
                                 password, deadline, on_attempt=None) -> dict:
    """Install the exact public snapshot verifier in the retained sidecar once."""
    if type(raw) is not bytes or not 1 <= len(raw) <= CERT_LIMIT:
        raise SupervisorError("owner_verifier", "size")
    checked_root = _remote_path(intent_root, label="owner_intent_root")
    _deadline_remaining(deadline, "owner_verifier")
    if on_attempt is not None:
        if not callable(on_attempt):
            raise SupervisorError("owner_verifier", "attempt_callback")
        try:
            result = on_attempt()
        except Exception:
            raise SupervisorError("owner_verifier", "attempt_record_failed") from None
        if result is not None:
            raise SupervisorError("owner_verifier", "attempt_record_failed")
    stream = None
    sftp = None
    try:
        sftp = _open_sftp(client, deadline)
        stage = posixpath.join(checked_root, "owner-verifier-upload.bin")
        stream = _sftp_call(sftp, deadline, "owner_verifier_stage",
                            lambda: sftp.open(stage, "wx"))
        _sftp_call(sftp, deadline, "owner_verifier_stage", lambda: stream.chmod(0o600))
        info = _sftp_call(sftp, deadline, "owner_verifier_stage", stream.stat)
        nlink = getattr(info, "st_nlink", None)
        if (type(getattr(info, "st_uid", None)) is not int or info.st_uid != uid
                or type(getattr(info, "st_gid", None)) is not int or info.st_gid != gid
                or type(getattr(info, "st_mode", None)) is not int
                or not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600
                or type(getattr(info, "st_size", None)) is not int or info.st_size != 0
                or (nlink is not None and (type(nlink) is not int or nlink != 1))):
            raise SupervisorError("owner_verifier_stage", "metadata")
        _sftp_call(sftp, deadline, "owner_verifier_stage",
                   lambda: stream.set_pipelined(False))
        _sftp_call(sftp, deadline, "owner_verifier_stage", lambda: stream.write(raw))
        _sftp_call(sftp, deadline, "owner_verifier_stage", stream.flush)
        _sftp_call(sftp, deadline, "owner_verifier_stage", stream.close)
        stream = None
        final = _sftp_call(sftp, deadline, "owner_verifier_stage",
                           lambda: sftp.stat(stage))
        nlink = getattr(final, "st_nlink", None)
        if (type(getattr(final, "st_uid", None)) is not int or final.st_uid != uid
                or type(getattr(final, "st_gid", None)) is not int or final.st_gid != gid
                or type(getattr(final, "st_mode", None)) is not int
                or not stat.S_ISREG(final.st_mode) or stat.S_IMODE(final.st_mode) != 0o600
                or type(getattr(final, "st_size", None)) is not int or final.st_size != len(raw)
                or (nlink is not None and (type(nlink) is not int or nlink != 1))):
            raise SupervisorError("owner_verifier_stage", "metadata")
        output = _remote_script(
            client, _REMOTE_OWNER_VERIFIER_PUBLISH_SCRIPT,
            [checked_root, str(uid), str(gid), str(len(raw)), hashlib.sha256(raw).hexdigest()],
            password=password, deadline=deadline, output_limit=1024, sudo=False)
        receipt = _json_load(output, 1024, label="owner_verifier_receipt")
        _exact_fields(receipt, {"schema_version", "event", "uid", "gid", "mode",
                                "size", "sha256", "fsynced", "readback"},
                      "owner_verifier_receipt")
        expected_receipt = {"schema_version": 1, "event": "owner_verifier_copy",
                            "uid": uid, "gid": gid, "mode": 0o600, "size": len(raw),
                            "sha256": hashlib.sha256(raw).hexdigest(),
                            "fsynced": True, "readback": True}
        if (type(receipt.get("schema_version")) is not int
                or any(type(receipt.get(key)) is not int
                       for key in ("uid", "gid", "mode", "size"))
                or any(type(receipt.get(key)) is not bool for key in ("fsynced", "readback"))
                or type(receipt.get("sha256")) is not str
                or type(receipt.get("event")) is not str
                or receipt != expected_receipt):
            raise SupervisorError("owner_verifier", "receipt_mismatch")
        return receipt
    except SupervisorError:
        raise
    except Exception:
        raise SupervisorError("owner_verifier", "publication_unknown") from None
    finally:
        if sftp is not None:
            try:
                channel_owned = _channel_operation_owned(sftp.get_channel())
            except Exception:
                channel_owned = True
            if not channel_owned:
                if stream is not None:
                    try:
                        _sftp_call(sftp, deadline, "owner_verifier_stage", stream.close)
                    except Exception:
                        pass
                if not _channel_operation_owned(sftp.get_channel()):
                    try:
                        _sftp_call(sftp, deadline, "owner_verifier_stage", sftp.close)
                    except Exception:
                        _abort_sftp(sftp)


def _read_owner_ack(client, *, job_root, uid, gid, password, deadline,
                    missing_ok=False):
    """Read the fixed protected ACK and return its exact document plus provenance."""
    root = _remote_path(job_root, label="remote_job_root")
    if (type(uid) is not int or uid != REMOTE_STATUS_UID or type(gid) is not int
            or not 0 <= gid <= 2**31 - 1):
        raise SupervisorError("owner_ack", "owner")
    path = posixpath.join(root, "owner-ack.json")
    raw = _remote_script(client, _REMOTE_OWNER_ACK_READ_SCRIPT,
                         [path, str(uid), str(gid), "1" if missing_ok else "0"], password=password,
                         deadline=deadline, output_limit=CONTROL_LIMIT)
    frame = _json_load(raw, CONTROL_LIMIT, label="owner_ack_frame")
    if (missing_ok and type(frame) is dict
            and set(frame) == {"schema_version", "event", "ack", "provenance", "missing"}
            and frame == {"schema_version": 1, "event": "owner_ack_read",
                          "ack": None, "provenance": None, "missing": True}):
        return None, None
    _exact_fields(frame, {"schema_version", "event", "ack", "provenance"},
                  "owner_ack_frame")
    provenance = frame.get("provenance")
    provenance_fields = {"uid", "gid", "mode", "size", "mtime_ns", "sha256",
                         "metadata_stable"}
    _exact_fields(provenance, provenance_fields, "owner_ack_provenance")
    if (type(frame.get("schema_version")) is not int or frame["schema_version"] != 1
            or frame.get("event") != "owner_ack_read" or type(frame.get("ack")) is not dict
            or any(type(provenance.get(key)) is not int for key in (
                "uid", "gid", "mode", "size", "mtime_ns"))
            or provenance["uid"] != uid or provenance["gid"] != gid
            or provenance["mode"] != 0o600
            or not 1 <= provenance["size"] <= OWNER_CONTROL_LIMIT
            or provenance["mtime_ns"] < 0
            or type(provenance.get("sha256")) is not str
            or _HEX64.fullmatch(provenance["sha256"]) is None
            or provenance.get("metadata_stable") is not True):
        raise SupervisorError("owner_ack_frame", "provenance")
    return frame["ack"], dict(provenance)


def _wait_owner_command_completion(client, *, config, expected, expected_command,
                                  password, job_root, uid, gid, mark_ns, deadline):
    """Join one fresh durable ACK to its same-command protected status frame."""
    status_path = posixpath.join(job_root, "status.json")
    while time.monotonic() < deadline:
        ack, provenance = _read_owner_ack(
            client, job_root=job_root, uid=uid, gid=gid,
            password=password, deadline=deadline, missing_ok=True)
        frame = _read_remote_status(client, password=password,
                                    status_path=status_path, mark_ns=mark_ns,
                                    deadline=deadline)
        if ack is not None:
            if type(ack) is not dict or type(ack.get("sequence")) is not int:
                raise SupervisorError("owner_ack", "schema")
            if ack["sequence"] > expected_command.sequence:
                raise SupervisorError("owner_ack", "sequence_ahead")
            if ack["sequence"] == expected_command.sequence:
                if ack.get("command_sha256") != expected_command.command_sha256:
                    raise SupervisorError("owner_ack", "command_mismatch")
                if (type(provenance) is not dict
                        or type(provenance.get("mtime_ns")) is not int
                        or provenance["mtime_ns"] <= mark_ns):
                    raise SupervisorError("owner_ack", "predates_command_mark")
                try:
                    checked_ack = validate_owner_command_ack(
                        ack, expected_command, expected)
                except ValueError:
                    raise SupervisorError("owner_ack", "invalid") from None
                if frame is not None:
                    status = frame["status"]
                    control = status.get("owner_control") if type(status) is dict else None
                    if (type(control) is dict
                            and control.get("last_sequence") == expected_command.sequence
                            and control.get("last_command_sha256") == expected_command.command_sha256):
                        try:
                            _validate_owner_status(
                                status, expected, config, command=checked_ack)
                        except ValueError:
                            raise SupervisorError("owner_status", "command_status") from None
                        if (control.get("received_monotonic_ns")
                                != checked_ack["received_monotonic_ns"]
                                or control.get("applied_monotonic_ns")
                                != checked_ack["completed_monotonic_ns"]):
                            raise SupervisorError("owner_status", "ack_time_mismatch")
                        return checked_ack, provenance, frame
        time.sleep(min(0.1, max(0.0, deadline - time.monotonic())))
    raise SupervisorError("owner_action", "completion_timeout")


def _wait_owner_materials(local_cid: str, expected: OwnerExpectation,
                         deadline: float, *, initial_view, snapshot_store,
                         verifier_pem: bytes, initial_local_serials: list[str],
                         initial_device_id: str):
    wrapper = _wait_local_json(
        local_cid, "owner-materials-ready.json", deadline,
        label="owner_materials_ready")
    archive = _read_local_owner_archive(local_cid, deadline)
    return _verify_owner_material_bundle(
        expected, wrapper, archive, initial_view=initial_view,
        snapshot_store=snapshot_store, verifier_pem=verifier_pem,
        initial_local_serials=initial_local_serials,
        initial_device_id=initial_device_id)


def _owner_action_response(*, request, expected, host_key, config, command,
                           ack, frame, mark_ns, publication):
    response = {
        "schema_version": 1, "event": "owner_action_response",
        "profile": expected.profile, "run_id": expected.run_id,
        "nonce": expected.nonce, "worker_boot_id": expected.worker_boot_id,
        "command_number": command.sequence,
        "command_sha256": command.command_sha256,
        "publication": publication, "worker_ack": ack,
        "protected_status": {
            "measurement_label": "ssh_protected_owner_status_v1",
            "ssh_host_key_sha256": host_key,
            "remote_mark_ns": mark_ns,
            "heartbeat_mtime_ns": frame["mtime_ns"],
            "remote_status_uid": frame["uid"],
            "remote_status_mode": frame["mode"],
            "remote_status": frame["status"],
        },
    }
    try:
        return validate_owner_action_response(
            response, request, expected,
            expected_ssh_host_key_sha256=host_key,
            expected_worker_config=config)
    except ValueError:
        raise SupervisorError("owner_action_response", "invalid") from None


def _wait_owner_container_exit(client, *, cid, name, owner, image, password,
                               deadline):
    while time.monotonic() < deadline:
        state = _remote_inspect(client, cid, name=name, owner=owner,
                                image=image, password=password, deadline=deadline)
        if not state["running"]:
            if state["exit_code"] != 0:
                raise SupervisorError("owner_remove_exit", "nonzero")
            return {"process_state": "exited", "exit_code": 0}
        time.sleep(min(0.1, max(0.0, deadline - time.monotonic())))
    raise SupervisorError("owner_remove_exit", "deadline")


def _handle_owner_action(*, local_cid, number, expected, ready, config,
                         bundle_files, initial_view, initial_store,
                         initial_serials, host_key, ssh, password, job_root,
                         intent_root, uid, gid, container_id, container_name,
                         owner_label, image, deadline, owner_state):
    """Handle one fixed request with verified material, publication and status."""
    request, command = _wait_owner_action_request(
        local_cid, number, expected, deadline)
    if number != len(owner_state["handled_requests"]) + 1:
        raise SupervisorError("owner_action", "sequence_order")
    publication = {
        "install_intent": None, "removal_intent": None,
        "policy": None, "command": None,
    }
    if expected.profile == PROFILE_C1B_OWNER_REMOVE:
        if number == 1:
            wrapper, files, views = _wait_owner_materials(
                local_cid, expected, deadline, initial_view=initial_view,
                snapshot_store=initial_store,
                verifier_pem=bundle_files["snapshot.pub"],
                initial_local_serials=initial_serials,
                initial_device_id=config["device_id"])
            owner_state["materials_wrapper"] = wrapper
            owner_state["material_files"] = files
            owner_state["material_views"] = views
            owner_state["material_policies"] = (
                files["install-snapshot.json"], files["remove-snapshot.json"])
            intent_protocol = __import__("lab.secure_cohort_owner", fromlist=["_intent_document"])
            for sequence, (name, intent_name) in enumerate((
                    ("install-intent.json", "install_intent"),
                    ("removal-intent.json", "removal_intent")), start=1):
                intent_envelope = intent_protocol._strict_loads(
                    files[name], maximum=OWNER_INTENT_LIMIT)
                intent_document = intent_envelope.get("intent") if type(intent_envelope) is dict else None
                command_id = (intent_document.get("command_id")
                              if type(intent_document) is dict else None)
                expected_command_doc = build_owner_command(
                    expected, sequence, command_id,
                    snapshot_sha256=hashlib.sha256(
                        owner_state["material_policies"][sequence - 1]).hexdigest(),
                    snapshot_revision=expected.initial_revision + sequence)
                expected_command = validate_owner_action_request(
                    build_owner_action_request(expected, sequence,
                                               expected_command_doc), expected)
                _verify_owner_signed_intent(
                    files[name], expected_command, bundle_files["snapshot.pub"])
                owner_state["prepared_commands"].append(expected_command_doc)
            expected_first = owner_state["prepared_commands"][0]
            if request["command"] != expected_first:
                raise SupervisorError("owner_action", "prepared_command_mismatch")
            for kind, filename in (("install_intent", "install-intent.json"),
                                   ("removal_intent", "removal-intent.json")):
                receipt = _publish_owner_file(
                    ssh, files[filename], kind=kind, job_root=job_root,
                    intent_root=intent_root, uid=uid, gid=gid,
                    password=password, deadline=deadline,
                    on_attempt=lambda kind=kind: owner_state["attempts"].append(
                        {"kind": kind, "monotonic_ns": time.monotonic_ns()}) or None)
                publication[kind] = receipt
                owner_state["intent_receipts"][kind] = receipt
            owner_state["intent_publication_complete"] = True
        else:
            if ("materials_wrapper" not in owner_state
                    or request["command"] != owner_state["prepared_commands"][1]):
                raise SupervisorError("owner_action", "prepared_command_mismatch")
            publication["install_intent"] = owner_state["intent_receipts"]["install_intent"]
            publication["removal_intent"] = owner_state["intent_receipts"]["removal_intent"]
        policy = owner_state["material_policies"][number - 1]
        if hashlib.sha256(policy).hexdigest() != command.snapshot_sha256:
            raise SupervisorError("owner_policy", "request_digest_mismatch")
        policy_receipt = _publish_owner_file(
            ssh, policy, kind=f"policy{number}", job_root=job_root,
            intent_root=intent_root, uid=uid, gid=gid, password=password,
            deadline=deadline,
            expected_prior_sha256=(expected.initial_snapshot_sha256 if number == 1
                                   else hashlib.sha256(
                                       owner_state["material_policies"][0]).hexdigest()),
            on_attempt=lambda: owner_state["attempts"].append(
                {"kind": f"policy{number}", "monotonic_ns": time.monotonic_ns()}) or None)
        publication["policy"] = policy_receipt
    try:
        command_raw = _owner_canonical_bytes(
            request["command"], maximum=OWNER_CONTROL_LIMIT)
        expected_command_raw = _owner_canonical_bytes(
            _owner_command_document(command), maximum=OWNER_CONTROL_LIMIT)
    except (TypeError, ValueError):
        raise SupervisorError("owner_action", "command_canonical_mismatch") from None
    if command_raw != expected_command_raw:
        raise SupervisorError("owner_action", "command_canonical_mismatch")
    mark_ns = _remote_mark(ssh, password=password, deadline=deadline)
    command_receipt = _publish_owner_file(
        ssh, command_raw, kind=f"command{number}", job_root=job_root,
        intent_root=intent_root or _remote_path(job_root + "-owner-intents",
                                                label="owner_intent_root"),
        uid=uid, gid=gid, password=password, deadline=deadline,
        expected_prior_sha256=("" if number == 1 else owner_state["command_sha256s"][0]),
        on_attempt=lambda: owner_state["attempts"].append(
            {"kind": f"command{number}", "mark_ns": mark_ns,
             "monotonic_ns": time.monotonic_ns()}) or None)
    publication["command"] = command_receipt
    ack, ack_provenance, frame = _wait_owner_command_completion(
        ssh, config=config, expected=expected, expected_command=command,
        password=password, job_root=job_root, uid=uid, gid=gid,
        mark_ns=mark_ns, deadline=deadline)
    response = _owner_action_response(
        request=request, expected=expected, host_key=host_key, config=config,
        command=command, ack=ack, frame=frame, mark_ns=mark_ns,
        publication=publication)
    owner_state["handled_requests"].append(request)
    owner_state["action_responses"].append(response)
    owner_state["command_sha256s"].append(command.command_sha256)
    owner_state["action_frames"][number] = {
        "mark_ns": mark_ns, "frame": frame,
        "ack_provenance": ack_provenance,
    }
    if (expected.profile == PROFILE_C1B_OWNER_REMOVE and number == 2):
        _wait_owner_container_exit(
            ssh, cid=container_id, name=container_name, owner=owner_label,
            image=image, password=password,
            deadline=min(deadline, time.monotonic() + TERMINATION_SECONDS))
        owner_state["actual_remove_exit"] = {"process_state": "exited", "exit_code": 0}
    _write_local_handoff(local_cid, f"owner-action-response-{number}.json",
                         response, deadline)
    owner_state["delivered_handoffs"].append(
        f"owner-action-response-{number}.json")
    return response, command, frame


def _owner_cleanup_is_authorized(owner_state, profile, *, intent_root):
    """Require every owner mutation and fixed control handoff to be resolved."""
    if type(owner_state) is not dict or profile not in OWNER_PROFILES:
        return False
    drain = profile == PROFILE_C1B_OWNER_DRAIN
    expected_attempts = (["command1", "command2"] if drain else [
        "intent_root", "snapshot_verifier", "install_intent", "removal_intent",
        "policy1", "command1", "policy2", "command2"])
    expected_handoffs = (
        ["observation-response-5.json", "owner-action-response-1.json",
         "owner-action-response-2.json", "observation-response-6.json",
         "observation-response-7.json"]
        if drain else
        ["observation-response-5.json", "owner-action-response-1.json",
         "observation-response-6.json", "owner-action-response-2.json",
         "observation-response-7.json"])
    attempts = owner_state.get("attempts")
    responses = owner_state.get("action_responses")
    requests = owner_state.get("handled_requests")
    observations = owner_state.get("observation_acks")
    if (type(attempts) is not list
            or [row.get("kind") for row in attempts if type(row) is dict]
               != expected_attempts
            or len(attempts) != len(expected_attempts)
            or type(responses) is not list or len(responses) != 2
            or type(requests) is not list or len(requests) != 2
            or type(observations) is not list or len(observations) != 3
            or owner_state.get("delivered_handoffs") != expected_handoffs
            or _pending_channel_operation_count() != 0):
        return False
    if drain:
        return True
    return (
        type(intent_root) is str and bool(intent_root)
        and owner_state.get("intent_publication_complete") is True
        and type(owner_state.get("verifier_copy_receipt")) is dict
        and type(owner_state.get("sidecar_retention_receipt")) is dict
        and owner_state.get("actual_remove_exit") == {
            "process_state": "exited", "exit_code": 0}
    )


def _owner_observation_session(profile, sequence, request, observations):
    """Return only the session whose physical retention this observation proves."""
    if sequence == 5:
        return request.get("session_id")
    if sequence == 6:
        if type(observations) is not list or not observations:
            raise SupervisorError("owner_observation", "missing_probe_identity")
        probe = observations[0]
        if (type(probe) is not dict
                or request.get("request_id") != probe.get("request_id")
                or request.get("session_id") != probe.get("session_id")):
            raise SupervisorError("owner_observation", "probe_identity_changed")
        return (probe["session_id"]
                if profile == PROFILE_C1B_OWNER_DRAIN else None)
    return None


def _owner_cleanup_evidence(owner_state):
    """Return only bounded controller observations needed to audit owner I/O."""
    actions = owner_state.get("action_responses", [])
    frames = owner_state.get("action_frames", {})
    files = owner_state.get("material_files")
    if type(files) is not dict:
        files = {}
    pinned_files = []
    for name in sorted(files):
        raw = files[name]
        if type(name) is str and type(raw) is bytes and len(raw) <= OWNER_ARCHIVE_LIMIT:
            pinned_files.append({"name": name, "size": len(raw),
                                 "sha256": hashlib.sha256(raw).hexdigest()})
    wrapper = owner_state.get("materials_wrapper")
    wrapper_bytes = _json_bytes(wrapper, OWNER_CONTROL_LIMIT) if type(wrapper) is dict else None
    ack_provenance = []
    for number in (1, 2):
        frame = frames.get(number) if type(frames) is dict else None
        provenance = frame.get("ack_provenance") if type(frame) is dict else None
        ack_provenance.append({"command_number": number,
                               "provenance": dict(provenance)
                               if type(provenance) is dict else None})
    return {
        "handled_requests": [dict(item) for item in owner_state.get("handled_requests", [])
                             if type(item) is dict][:2],
        "ack_provenance": ack_provenance,
        "material_files": pinned_files[:5],
        "materials_wrapper": ({"size": len(wrapper_bytes),
                               "sha256": hashlib.sha256(wrapper_bytes).hexdigest()}
                              if wrapper_bytes is not None else None),
        "mutation_receipts": [dict(item.get("publication", {}))
                              for item in actions if type(item) is dict][:2],
        "delivered_handoffs": list(owner_state.get("delivered_handoffs", []))[:7],
    }


def _adapt_remote_removal_evidence(evidence: dict) -> dict:
    """Map validated raw removal evidence to distinct caller outcome fields."""
    removed = evidence.get("removed") if type(evidence) is dict else None
    confirmed = (
        type(evidence) is dict
        and type(evidence.get("confirmed")) is bool
        and evidence["confirmed"] is True
        and type(removed) is list
        and "." in removed
    )
    return {
        "private_files_removed": confirmed,
        "job_root_removed": confirmed,
    }


def _remove_remote_job(client, *, job_root: str, uid: int, gid: int,
                       password: str | None, deadline: float,
                       owner_profile: bool = False) -> dict:
    """Remove only a private job after the caller has confirmed process exit."""
    if type(owner_profile) is not bool:
        raise SupervisorError("remote_job_removal", "owner_profile")
    root = _remote_path(job_root, label="remote_job_root")
    if len(root.split("/")) > 17:
        raise SupervisorError("remote_job_removal", "path_depth")
    if (type(uid) is not int or uid != 1000
            or type(gid) is not int or not 0 <= gid <= 2**31 - 1):
        raise SupervisorError("remote_job_removal", "owner")
    if password is not None and (type(password) is not str or not password
                                 or len(password) > 16 * 1024 or "\x00" in password):
        raise SupervisorError("remote_job_removal", "password")
    _deadline_remaining(deadline, "remote_job_removal")
    exit_code, raw = _ssh_exec(
        client, ["python3", "-c", _remote_remove_job_script(owner_profile=owner_profile), root,
                 str(uid), str(gid)], password=password, deadline=deadline,
        output_limit=CONTROL_LIMIT, sudo=True)
    if type(exit_code) is not int or exit_code not in (0, 1):
        raise SupervisorError("remote_job_removal", "command_status")
    evidence = _json_load(raw, CONTROL_LIMIT, label="remote_job_removal")
    expected = {
        "schema_version", "event", "job_root", "uid", "gid", "confirmed",
        "removed", "residuals", "residuals_known", "residuals_truncated",
        "reason",
    }
    _exact_fields(evidence, expected, "remote_job_removal")
    if (type(evidence["schema_version"]) is not int or evidence["schema_version"] != 1
            or evidence["event"] != "remote_job_removal"
            or evidence["job_root"] != root
            or type(evidence["uid"]) is not int or evidence["uid"] != uid
            or type(evidence["gid"]) is not int or evidence["gid"] != gid
            or type(evidence["confirmed"]) is not bool
            or type(evidence["residuals_known"]) is not bool
            or type(evidence["residuals_truncated"]) is not bool):
        raise SupervisorError("remote_job_removal", "evidence_identity")
    allowed_names = set(_WORKER_FILES) | {
        "status.json", "worker.tar", "sockets/", ".",
    }
    if owner_profile:
        allowed_names.update({"owner-command.json", "owner-ack.json"})
    allowed_name_patterns = (
        re.compile(r"\.status\.json\.[0-9a-f]{16}\.tmp\Z", re.ASCII),
        re.compile(r"sockets/backend-[0-9a-f]{12}\.sock\Z", re.ASCII),
    )

    def validate_names(field, *, residuals=False):
        values = evidence[field]
        if type(values) is not list or len(values) > 66:
            raise SupervisorError("remote_job_removal", "evidence_names")
        for item in values:
            if (type(item) is not str or not item or len(item) > 300
                    or "\x00" in item
                    or (not residuals and any(ord(char) < 0x20 for char in item))):
                raise SupervisorError("remote_job_removal", "evidence_names")
            if residuals:
                components = item.split("/")
                if (len(components) != 1 or any(part in {"", ".", ".."}
                                               for part in components)):
                    raise SupervisorError("remote_job_removal", "evidence_names")
            elif (item not in allowed_names
                  and not any(pattern.fullmatch(item)
                              for pattern in allowed_name_patterns)):
                raise SupervisorError("remote_job_removal", "evidence_names")
        if len(set(values)) != len(values):
            raise SupervisorError("remote_job_removal", "evidence_names")
        return values

    removed = validate_names("removed")
    residuals = validate_names("residuals", residuals=True)
    reason = evidence["reason"]
    if reason is not None and (type(reason) is not str
                               or re.fullmatch(r"[a-z_]{1,40}", reason,
                                               re.ASCII) is None):
        raise SupervisorError("remote_job_removal", "evidence_reason")
    if evidence["confirmed"]:
        if (exit_code != 0 or reason is not None or not evidence["residuals_known"]
                or evidence["residuals_truncated"] or residuals
                or "." not in removed):
            raise SupervisorError("remote_job_removal", "incomplete_confirmation")
    elif reason is None or exit_code != 1:
        raise SupervisorError("remote_job_removal", "missing_failure_reason")
    _deadline_remaining(deadline, "remote_job_removal")
    raw_evidence = dict(evidence)
    evidence.update(_adapt_remote_removal_evidence(raw_evidence))
    evidence["raw_evidence"] = raw_evidence
    return evidence


def _open_sftp(client, deadline: float | None = None):
    """Open the SFTP channel and subsystem within the caller's deadline."""
    _deadline_remaining(deadline, "sftp_open")
    try:
        import paramiko
    except ImportError:
        raise SupervisorError("sftp_open", "paramiko_unavailable") from None
    channel = None
    try:
        transport = client.get_transport()
        if transport is None:
            raise SupervisorError("sftp_open", "transport_unavailable")
        channel = transport.open_session(timeout=_deadline_remaining(deadline, "sftp_open"))
        channel.settimeout(_deadline_remaining(deadline, "sftp_open"))
        _channel_operation(
            channel, lambda: channel.invoke_subsystem("sftp"),
            deadline=deadline, stage="sftp_open", failure_code="handshake_failed")
        channel.settimeout(_deadline_remaining(deadline, "sftp_open"))
        sftp = _channel_operation(
            channel, lambda: paramiko.SFTPClient(channel), deadline=deadline,
            stage="sftp_open", failure_code="handshake_failed")
        channel.settimeout(_deadline_remaining(deadline, "sftp_open"))
        return sftp
    except SupervisorError as error:
        if channel is not None and error.code != "ack_timeout_unknown":
            try:
                _abort_channel(channel)
            except Exception:
                pass
        raise
    except socket.timeout:
        if channel is not None:
            try:
                _abort_channel(channel)
            except Exception:
                pass
        raise SupervisorError("sftp_open", "timeout") from None
    except Exception:
        if channel is not None:
            try:
                _abort_channel(channel)
            except Exception:
                pass
        raise SupervisorError("sftp_open", "handshake_failed") from None


def _sftp_call(sftp, deadline: float, stage: str, call):
    _deadline_remaining(deadline, stage)
    try:
        channel = sftp.get_channel()
    except Exception:
        raise SupervisorError(stage, "transport_error") from None

    def bounded_call():
        channel.settimeout(_deadline_remaining(deadline, stage))
        return call()

    return _channel_operation(
        channel, bounded_call, deadline=deadline, stage=stage,
        failure_code="transport_error")


def _abort_sftp(sftp) -> None:
    try:
        _abort_channel(sftp.get_channel())
    except Exception:
        pass


def _remote_user_ids(sftp, deadline: float | None = None) -> tuple[int, int]:
    try:
        home = _sftp_call(sftp, deadline, "remote_identity",
                          lambda: sftp.normalize("."))
        attributes = _sftp_call(sftp, deadline, "remote_identity",
                                lambda: sftp.stat(home))
        uid, gid = attributes.st_uid, attributes.st_gid
        if (type(uid) is not int or uid != 1000 or type(gid) is not int
                or not 0 <= gid <= 2**31 - 1):
            raise SupervisorError("remote_identity", "ssh_user_must_be_uid_1000")
        return uid, gid
    except SupervisorError:
        raise
    except Exception:
        raise SupervisorError("remote_identity", "uid_unavailable") from None


def _sftp_upload_bundle(client, raw: bytes, job_root: str, uid: int,
                        deadline: float) -> None:
    if type(raw) is not bytes or not 1 <= len(raw) <= BUNDLE_LIMIT:
        raise SupervisorError("bundle_upload", "size")
    _deadline_remaining(deadline, "bundle_upload")
    path = posixpath.join(_remote_path(job_root, label="remote_job_root"),
                          "worker.tar")
    sftp = None
    stream = None
    owned_abort = False
    try:
        sftp = _open_sftp(client, deadline)
        stream = _sftp_call(sftp, deadline, "bundle_upload",
                            lambda: sftp.open(path, "wx"))
        # Paramiko 3.5.1 maps ``x`` to CREATE|EXCL, but only ``w`` (or ``+``)
        # sets SFTP_FLAG_WRITE.  Use wx so creation remains exclusive and the
        # returned handle is writable.  Restrict and verify that handle before
        # sending any bundle bytes; a failed check leaves an empty file for the
        # conservative remote cleanup path to inspect.
        _sftp_call(sftp, deadline, "bundle_upload",
                   lambda: stream.chmod(0o600))
        initial = _sftp_call(sftp, deadline, "bundle_upload", stream.stat)
        if (initial.st_uid != uid or stat.S_IMODE(initial.st_mode) != 0o600
                or initial.st_size != 0 or not stat.S_ISREG(initial.st_mode)):
            raise SupervisorError("bundle_upload", "remote_metadata")
        _sftp_call(sftp, deadline, "bundle_upload",
                   lambda: stream.set_pipelined(False))
        _sftp_call(sftp, deadline, "bundle_upload", lambda: stream.write(raw))
        _sftp_call(sftp, deadline, "bundle_upload", stream.flush)
        _sftp_call(sftp, deadline, "bundle_upload", stream.close)
        stream = None
        info = _sftp_call(sftp, deadline, "bundle_upload",
                          lambda: sftp.stat(path))
        if (info.st_uid != uid or stat.S_IMODE(info.st_mode) != 0o600
                or info.st_size != len(raw) or not stat.S_ISREG(info.st_mode)):
            raise SupervisorError("bundle_upload", "remote_metadata")
        _sftp_call(sftp, deadline, "bundle_upload", sftp.close)
        sftp = None
    except SupervisorError as error:
        owned_abort = error.code in {
            "ack_timeout_unknown", "operation_ownership_pending",
        }
        raise
    except Exception:
        raise SupervisorError("bundle_upload", "transfer_failed") from None
    finally:
        if sftp is not None:
            if stream is not None:
                try:
                    _sftp_call(sftp, deadline, "bundle_upload", stream.close)
                except SupervisorError as error:
                    if error.code in {
                            "ack_timeout_unknown", "operation_ownership_pending"}:
                        owned_abort = True
                except Exception:
                    pass
            try:
                _sftp_call(sftp, deadline, "bundle_upload", sftp.close)
            except SupervisorError as error:
                if error.code in {
                        "ack_timeout_unknown", "operation_ownership_pending"}:
                    owned_abort = True
                if (not owned_abort
                        and not _channel_operation_owned(sftp.get_channel())):
                    _abort_sftp(sftp)
            except Exception:
                if (not owned_abort
                        and not _channel_operation_owned(sftp.get_channel())):
                    _abort_sftp(sftp)


def _ensure_remote_paths(client, *, job_root: str, artifacts: str,
                         uid: int, gid: int, password: str | None,
                         deadline: float) -> None:
    _remote_script(client, _REMOTE_CREATE_JOB_SCRIPT,
                   [job_root, str(uid), str(gid)], password=password,
                   deadline=deadline, output_limit=256)
    output = _remote_script(client, _REMOTE_CHECK_DIRECTORY_SCRIPT,
                            [artifacts], password=password,
                            deadline=deadline, output_limit=256)
    if output.strip() != b"ok":
        raise SupervisorError("remote_artifacts", "directory_unverified")


def _remote_inspect(client, cid, *, name, owner, image, password, deadline) -> dict:
    raw = _ssh_checked(client, _container_inspect_argv(cid),
                       password=password, deadline=deadline, output_limit=4096)
    try:
        text = raw.decode("ascii", "strict").strip()
    except UnicodeError:
        raise SupervisorError("container", "inspect_encoding") from None
    state = verify_container_inspect(text, cid=cid, name=name,
                                     owner_label=owner, role="worker-3", image=image)
    return state


def _remote_find_owned(client, *, name, owner, image, password, deadline,
                       on_cid=None) -> str | None:
    raw = _ssh_checked(client, ["docker", "ps", "--all", "--quiet", "--no-trunc",
                                "--filter", f"name=^{name}$", "--filter",
                                f"label={_OWNER_LABEL}={owner}"],
                       password=password, deadline=deadline, output_limit=256)
    ids = raw.decode("ascii", "strict").split()
    if not ids:
        return None
    if len(ids) != 1 or _CONTAINER_ID.fullmatch(ids[0]) is None:
        raise SupervisorError("container", "owned_discovery_ambiguous")
    if on_cid is not None:
        on_cid(ids[0])
    _remote_inspect(client, ids[0], name=name, owner=owner, image=image,
                    password=password, deadline=deadline)
    return ids[0]


def _remote_status_script_args(status_path: str, mark_ns: int, wait_seconds: float) -> list[str]:
    if (type(status_path) is not str or not status_path.endswith("/status.json")
            or posixpath.normpath(status_path) != status_path
            or type(mark_ns) is not int or mark_ns < 0
            or type(wait_seconds) not in (int, float)
            or not math.isfinite(wait_seconds) or not 0 <= wait_seconds <= 1):
        raise SupervisorError("remote_status", "path_or_deadline")
    job_root = posixpath.dirname(status_path)
    _remote_path(job_root, label="remote_status_job_root")
    if posixpath.join(job_root, "status.json") != status_path:
        raise SupervisorError("remote_status", "path_or_deadline")
    return [status_path, str(REMOTE_STATUS_UID), str(mark_ns), repr(float(wait_seconds))]


def _read_remote_status(client, *, password, status_path: str, mark_ns: int,
                        deadline: float) -> dict | None:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise SupervisorError("remote_status", "deadline")
    # The remote helper returns immediately when no newer file exists.  This
    # keeps each SSH exchange bounded and lets the host retain one global clock.
    raw = _remote_script(client, _REMOTE_STATUS_SCRIPT,
                         _remote_status_script_args(status_path, mark_ns, 0),
                         password=password, deadline=deadline,
                         output_limit=STATUS_LIMIT + 1024)
    value = _json_load(raw, STATUS_LIMIT + 1024, label="remote_status_frame")
    if value.get("fresh") is False:
        if (set(value) != {"fresh", "mark_ns"}
                or type(value.get("mark_ns")) is not int
                or value["mark_ns"] != mark_ns):
            raise SupervisorError("remote_status", "frame_schema")
        return None
    if set(value) != {"uid", "mode", "mtime_ns", "mark_ns", "status"}:
        raise SupervisorError("remote_status", "frame_schema")
    if (value["uid"] != 1000 or value["mode"] != 0o600
            or type(value["uid"]) is not int or type(value["mode"]) is not int
            or type(value["mtime_ns"]) is not int or type(value["mark_ns"]) is not int
            or value["mark_ns"] != mark_ns or value["mtime_ns"] <= mark_ns
            or type(value["status"]) is not dict):
        raise SupervisorError("remote_status", "provenance")
    return value


def _remote_mark(client, *, password, deadline) -> int:
    raw = _ssh_checked(client, ["python3", "-c", "import time;print(time.time_ns())"],
                       password=password, deadline=deadline, output_limit=128,
                       sudo=False)
    try:
        text = raw.decode("ascii", "strict").strip()
        mark = int(text)
    except (UnicodeError, ValueError):
        raise SupervisorError("remote_clock", "mark_invalid") from None
    if mark <= 0:
        raise SupervisorError("remote_clock", "mark_invalid")
    return mark


def _wait_remote_status(client, *, config, password, status_path, mark_ns,
                        deadline, expected_events: set[str], terminal_check=None,
                        expected_session_id: str | None = None,
                        expected_open_only: bool = False,
                        partial_expiry_session_id: str | None = None,
                        expected_session_ids: list[str] | None = None,
                        expected_session_count: int | None = None,
                        owner_expected: OwnerExpectation | None = None,
                        owner_command: dict | None = None,
                        owner_observation: bool = False) -> dict:
    if partial_expiry_session_id is not None:
        if (type(partial_expiry_session_id) is not str
                or not partial_expiry_session_id.startswith("ses_")
                or len(partial_expiry_session_id) != 36
                or expected_session_id is not None or expected_open_only):
            raise SupervisorError("remote_status", "partial_expiry_identity")
    while time.monotonic() < deadline:
        if terminal_check is not None:
            terminal_check()
        frame = _read_remote_status(client, password=password,
                                    status_path=status_path, mark_ns=mark_ns,
                                    deadline=deadline)
        if frame is not None:
            status = frame["status"]
            if status.get("event") not in expected_events:
                raise SupervisorError("remote_status", "event")
            if owner_expected is not None:
                try:
                    _validate_owner_status(
                        status, owner_expected, config, command=owner_command,
                        observation=owner_observation)
                except ValueError:
                    raise SupervisorError("remote_status", "owner_schema") from None
                if expected_session_id is not None:
                    handler = status.get("handler")
                    if (type(handler) is not dict
                            or handler.get("active_session_ids") != [expected_session_id]):
                        raise SupervisorError("remote_status", "owner_session_identity")
                if owner_observation and expected_session_id is None:
                    # A no-session owner observation is a global-idle proof.
                    # The shared owner parser permits a paused lifecycle frame
                    # with retained sessions, so enforce the stronger profile
                    # boundary before producing an ACK or accepting command 2.
                    _require_owner_global_idle(status)
                if owner_command is None and not owner_observation:
                    _require_owner_global_idle(status)
                return frame
            if partial_expiry_session_id is not None:
                handler = status.get("handler") if type(status) is dict else None
                active_ids = (handler.get("active_session_ids")
                              if type(handler) is dict else None)
                if active_ids == [partial_expiry_session_id]:
                    _validate_status(status, config, event=status["event"],
                                     expected_session_id=partial_expiry_session_id,
                                     expected_open_only=True)
                    time.sleep(min(0.15, max(0.0, deadline - time.monotonic())))
                    continue
                # Only a validated global-idle heartbeat completes expiry. Any
                # other owner shape is passed through the strict idle validator.
                _validate_status(status, config, event=status["event"])
                return frame
            _validate_status(status, config, event=status["event"],
                             expected_session_id=expected_session_id,
                                 expected_open_only=expected_open_only,
                                 expected_session_ids=expected_session_ids,
                                 expected_session_count=expected_session_count)
            return frame
        time.sleep(min(0.15, max(0.0, deadline - time.monotonic())))
    raise SupervisorError("remote_status", "fresh_status_timeout")


def _require_owner_global_idle(status):
    """Require READY and baseline owner frames to show no physical work."""
    if type(status) is not dict:
        raise SupervisorError("remote_status", "owner_idle_schema")
    handler, bridge, transport = (status.get("handler"), status.get("bridge"),
                                  status.get("transport"))
    if type(handler) is not dict or type(bridge) is not dict or type(transport) is not dict:
        raise SupervisorError("remote_status", "owner_idle_schema")
    integer_zeroes = ((handler, "active_sessions"), (handler, "queued_operations"),
                      (handler, "committed_cache_bytes"),
                      (handler, "allocated_cache_bytes"),
                      (bridge, "active_authorizations"), (bridge, "owned_sessions"),
                      (bridge, "pending_notices"), (transport, "reserved_pending"),
                      (transport, "reserved_outbound_pending"))
    if (any(type(row.get(name)) is not int or row[name] != 0
            for row, name in integer_zeroes)
            or handler.get("active_session_ids") != []
            or handler.get("active_compute") is not False
            or transport.get("server_state") != "running"
            or type(transport.get("listener_slots")) is not int
            or transport.get("listener_slots") != 1
            or type(transport.get("reserved_connections")) is not int
            or transport.get("reserved_connections") != 1
            or type(transport.get("reserved_listener_pending_capacity")) is not int
            or transport.get("reserved_listener_pending_capacity") != 1):
        raise SupervisorError("remote_status", "owner_not_globally_idle")


def _final_remote_status(client, *, password, status_path, deadline) -> tuple[dict | None, dict | None]:
    raw = _remote_script(client, _REMOTE_STATUS_SCRIPT,
                         _remote_status_script_args(status_path, 0, 0),
                         password=password, deadline=deadline,
                         output_limit=STATUS_LIMIT + 1024)
    value = _json_load(raw, STATUS_LIMIT + 1024, label="remote_final_status")
    if set(value) != {"uid", "mode", "mtime_ns", "mark_ns", "status"}:
        return None, None
    if (type(value.get("uid")) is not int or value["uid"] != 1000
            or type(value.get("mode")) is not int or value["mode"] != 0o600
            or type(value.get("mtime_ns")) is not int or value["mtime_ns"] <= 0
            or type(value.get("status")) is not dict):
        return None, None
    return value, value["status"]


def _stop_remote(client, cid, *, name, owner, image, password,
                 config, job_root, uid, gid, deadline,
                 on_exit_confirmed=None,
                 owner_expected: OwnerExpectation | None = None,
                 owner_final_ack: dict | None = None,
                 owner_cleanup_ready: bool = False) -> dict:
    evidence = {
        "container_id": cid,
        "exit_code": None,
        "process_state": "unknown",
        "graceful_compute_shutdown": False,
        "shutdown_confirmed": False,
        "container_removed": False,
        "private_files_removed": False,
        "job_root_removed": False,
        "removal_evidence": None,
        "status": None,
        "failure_type": None,
    }
    if cid is None:
        evidence["failure_type"] = "remote_container_not_owned"
        return evidence
    if type(owner_cleanup_ready) is not bool:
        raise SupervisorError("remote_stop", "owner_cleanup_readiness")
    forced_kill = False
    stop_error = None
    try:
        state = _remote_inspect(client, cid, name=name, owner=owner,
                                image=image, password=password, deadline=deadline)
        if state["running"]:
            remaining = deadline - time.monotonic()
            if remaining <= 1:
                raise SupervisorError("remote_stop", "deadline")
            seconds = min(TERMINATION_SECONDS, max(1, int(remaining) - 1))
            try:
                _ssh_checked(client, ["docker", "stop", f"--time={seconds}", cid],
                             password=password, deadline=deadline, output_limit=256)
            except SupervisorError as error:
                stop_error = error.code
        state = _remote_inspect(client, cid, name=name, owner=owner,
                                image=image, password=password, deadline=deadline)
        if state["running"]:
            remaining = deadline - time.monotonic()
            if remaining > 0.25:
                try:
                    _ssh_checked(client, ["docker", "kill", cid],
                                 password=password, deadline=deadline, output_limit=256)
                    forced_kill = True
                except SupervisorError as error:
                    stop_error = stop_error or error.code
                state = _remote_inspect(client, cid, name=name, owner=owner,
                                        image=image, password=password, deadline=deadline)
        evidence["process_state"] = "exited" if not state["running"] else "running"
        evidence["exit_code"] = state["exit_code"]
        if not state["running"]:
            # Let the restart owner bind its receipt to the first parent-side
            # monotonic observation of process exit, before final-status and
            # artifact cleanup I/O can consume the bounded retirement window.
            if on_exit_confirmed is not None:
                if not callable(on_exit_confirmed):
                    raise SupervisorError("remote_cleanup", "exit_callback_invalid")
                on_exit_confirmed(time.monotonic_ns())
            try:
                frame, status = _final_remote_status(
                    client, password=password,
                    status_path=posixpath.join(job_root, "status.json"),
                    deadline=deadline)
                if frame is not None:
                    evidence["status"] = status
                    evidence["status_uid"] = frame["uid"]
                    evidence["status_mode"] = frame["mode"]
            except SupervisorError as error:
                evidence["failure_type"] = error.code
            if owner_expected is not None and evidence["status"] is not None:
                try:
                    _validate_owner_status(evidence["status"], owner_expected, config,
                                           command=owner_final_ack)
                    owner_final = evidence["status"].get("event") == "final"
                except ValueError:
                    owner_final = False
            else:
                owner_final = _final_status_is_confirmed(evidence["status"], config)
            evidence["graceful_compute_shutdown"] = bool(
                state["exit_code"] == 0 and evidence["status"] is not None
                and owner_final and not forced_kill and stop_error is None)
            evidence["shutdown_confirmed"] = evidence["graceful_compute_shutdown"]
        else:
            evidence["failure_type"] = evidence["failure_type"] or "termination_unconfirmed"
        owner_cleanup_allowed = (
            owner_expected is None
            or (owner_cleanup_ready is True
                and evidence.get("shutdown_confirmed") is True
                and _pending_channel_operation_count() == 0))
        if not state["running"] and owner_cleanup_allowed:
            try:
                _ssh_checked(client, ["docker", "rm", cid], password=password,
                             deadline=deadline, output_limit=256)
                evidence["container_removed"] = True
            except SupervisorError as error:
                evidence["failure_type"] = evidence["failure_type"] or error.code
            try:
                removal = _remove_remote_job(
                    client, job_root=job_root, uid=uid, gid=gid,
                    password=password, deadline=deadline,
                    owner_profile=owner_expected is not None)
                raw_removal = (removal.get("raw_evidence")
                               if type(removal) is dict else None)
                if type(raw_removal) is dict:
                    evidence["removal_evidence"] = raw_removal
                    derived = _adapt_remote_removal_evidence(raw_removal)
                    if (type(removal.get("private_files_removed")) is bool
                            and type(removal.get("job_root_removed")) is bool
                            and removal["private_files_removed"]
                            is derived["private_files_removed"]
                            and removal["job_root_removed"]
                            is derived["job_root_removed"]):
                        evidence["private_files_removed"] = derived["private_files_removed"]
                        evidence["job_root_removed"] = derived["job_root_removed"]
                    else:
                        evidence["failure_type"] = evidence["failure_type"] or "removal_evidence_invalid"
                else:
                    evidence["failure_type"] = evidence["failure_type"] or "removal_evidence_invalid"
            except SupervisorError as error:
                evidence["failure_type"] = evidence["failure_type"] or error.code
            if (not evidence["container_removed"] or not evidence["private_files_removed"]
                    or not evidence["job_root_removed"]):
                evidence["failure_type"] = evidence["failure_type"] or "cleanup_unconfirmed"
            evidence["cleanup_confirmed"] = bool(
                evidence["container_removed"]
                and evidence["private_files_removed"]
                and evidence["job_root_removed"])
        elif not state["running"] and owner_expected is not None:
            evidence["failure_type"] = (evidence.get("failure_type")
                                         or "owner_cleanup_not_authorized")
            evidence["cleanup_confirmed"] = False
    except SupervisorError as error:
        evidence["failure_type"] = evidence["failure_type"] or error.code
    except Exception:
        evidence["failure_type"] = evidence["failure_type"] or "remote_cleanup_error"
    return evidence


def _stop_ack(ready, host_key, evidence) -> dict:
    status = evidence.get("status")
    process_state = evidence.get("process_state")
    if process_state != "exited":
        process_state = "unknown"
    return {
        "schema_version": 1, "event": "stop_ack", "run_id": ready["run_id"],
        "nonce": ready["nonce"], "boot_id": ready["expected_boot_id"],
        "process_state": process_state,
        "exit_code": evidence.get("exit_code"),
        "shutdown_confirmed": bool(evidence.get("shutdown_confirmed")),
        "ssh_host_key_sha256": host_key,
        "remote_status_uid": evidence.get("status_uid"),
        "remote_status_mode": evidence.get("status_mode"),
        "measurement_label": "ssh_supervisor_exit_and_final_status",
        "remote_status": status,
    }


def _create_remote_container(client, *, image, name, owner, job_root, artifacts,
                             password, deadline, on_cid=None,
                             owner_controls_run_id=None, owner_intent_root=None) -> str:
    argv = build_remote_run_argv(image=image, name=name, owner=owner,
                                 job_root=job_root, artifacts=artifacts,
                                 owner_controls_run_id=owner_controls_run_id,
                                 owner_intent_root=owner_intent_root)
    create_error = None
    try:
        raw = _ssh_checked(client, argv, password=password,
                           deadline=deadline, output_limit=256)
        cid = raw.decode("ascii", "strict").strip()
        if _CONTAINER_ID.fullmatch(cid) is None:
            cid = None
    except (SupervisorError, UnicodeError):
        cid = None
        create_error = SupervisorError("remote_start", "create_result_unknown")
    cid_recorded = False

    def retain_candidate(candidate):
        nonlocal cid_recorded
        if on_cid is not None and not cid_recorded:
            on_cid(candidate)
            cid_recorded = True

    if cid is None:
        try:
            cid = _remote_find_owned(client, name=name, owner=owner,
                                     image=image, password=password,
                                     deadline=min(deadline, time.monotonic() + 5.0),
                                     on_cid=retain_candidate)
        except SupervisorError:
            cid = None
        if cid is None:
            raise create_error or SupervisorError("remote_start", "cid_invalid")
    retain_candidate(cid)
    _remote_inspect(client, cid, name=name, owner=owner, image=image,
                    password=password, deadline=deadline)
    return cid


def _find_local_owned(*, name, owner, image, deadline, on_cid=None) -> str | None:
    raw = _local_docker(
        ["docker", "ps", "--all", "--quiet", "--no-trunc",
         "--filter", f"name=^{name}$", "--filter",
         f"label={_OWNER_LABEL}={owner}"],
        deadline=deadline, output=256)
    ids = raw.decode("ascii", "strict").split()
    if not ids:
        return None
    if len(ids) != 1 or _CONTAINER_ID.fullmatch(ids[0]) is None:
        raise SupervisorError("local_start", "owned_discovery_ambiguous")
    if on_cid is not None:
        on_cid(ids[0])
    _docker_inspect_local(ids[0], name=name, owner=owner, role="operator",
                          image=image, deadline=deadline)
    return ids[0]


def _create_local_container(*, args, name, owner, cohort_args, deadline,
                            on_cid=None) -> str:
    argv = build_local_run_argv(
        image=args.local_image, name=name, owner=owner,
        artifact_volume=args.artifacts_volume,
        reference_volume=args.reference_volume,
        cohort_args=cohort_args)
    create_error = None
    try:
        raw = _local_docker(argv, deadline=deadline, output=256)
        cid = raw.decode("ascii", "strict").strip()
        if _CONTAINER_ID.fullmatch(cid) is None:
            cid = None
    except (SupervisorError, UnicodeError):
        cid = None
        create_error = SupervisorError("local_start", "create_result_unknown")
    cid_recorded = False

    def retain_candidate(candidate):
        nonlocal cid_recorded
        if on_cid is not None and not cid_recorded:
            on_cid(candidate)
            cid_recorded = True

    if cid is None:
        try:
            cid = _find_local_owned(name=name, owner=owner,
                                    image=args.local_image, deadline=deadline,
                                    on_cid=retain_candidate)
        except SupervisorError:
            cid = None
        if cid is None:
            raise create_error or SupervisorError("local_start", "cid_invalid")
    retain_candidate(cid)
    _docker_inspect_local(cid, name=name, owner=owner, role="operator",
                          image=args.local_image, deadline=deadline)
    return cid


def _terminate_local_owned(cid: str, *, name: str, owner: str, image: str,
                            termination_deadline: float,
                            observation_deadline: float) -> dict:
    """Stop, then kill only a verified owned local container within one deadline."""
    evidence = {
        "container_id": cid, "exit_code": None, "process_state": "unknown",
        "graceful_stop": False, "forced_kill": False,
        "container_removed": False, "cleanup_confirmed": False,
        "failure_type": None, "ownership_verified": False,
    }
    try:
        state = _docker_inspect_local(
            cid, name=name, owner=owner, role="operator", image=image,
            deadline=observation_deadline)
        evidence["ownership_verified"] = True
        stop_error = None
        if state["running"]:
            remaining = termination_deadline - time.monotonic()
            if remaining <= 0:
                evidence["failure_type"] = "termination_deadline"
                return evidence
            seconds = min(TERMINATION_SECONDS, max(1, int(remaining) - 1))
            try:
                _local_docker(["docker", "stop", f"--time={seconds}", cid],
                              deadline=termination_deadline, output=256)
            except SupervisorError as error:
                stop_error = error.code
            state = _docker_inspect_local(
                cid, name=name, owner=owner, role="operator", image=image,
                deadline=observation_deadline)
            if state["running"]:
                remaining = termination_deadline - time.monotonic()
                if remaining > 0:
                    try:
                        _local_docker(["docker", "kill", cid],
                                      deadline=termination_deadline, output=256)
                        evidence["forced_kill"] = True
                    except SupervisorError as error:
                        stop_error = stop_error or error.code
                    state = _docker_inspect_local(
                        cid, name=name, owner=owner, role="operator", image=image,
                        deadline=observation_deadline)
        evidence["process_state"] = "exited" if not state["running"] else "running"
        evidence["exit_code"] = state["exit_code"]
        evidence["graceful_stop"] = bool(
            not state["running"] and not evidence["forced_kill"]
            and stop_error is None and state["exit_code"] == 0)
        if state["running"]:
            evidence["failure_type"] = stop_error or "termination_unconfirmed"
            return evidence
        _local_docker(["docker", "rm", cid], deadline=observation_deadline, output=256)
        evidence["container_removed"] = True
        evidence["cleanup_confirmed"] = True
        if evidence["forced_kill"]:
            evidence["failure_type"] = "forced_kill"
        elif stop_error is not None:
            evidence["failure_type"] = stop_error
    except SupervisorError as error:
        evidence["failure_type"] = evidence["failure_type"] or error.code
    except Exception:
        evidence["failure_type"] = evidence["failure_type"] or "local_cleanup_error"
    return evidence


def _termination_deadline_once(hard_deadline: float):
    """Return one nonrenewing teardown deadline, capped at fifteen seconds."""
    deadline = None

    def get_deadline():
        nonlocal deadline
        if deadline is None:
            deadline = min(hard_deadline,
                           time.monotonic() + TERMINATION_SECONDS)
        return deadline

    return get_deadline


def _termination_work_deadline(termination_deadline: float) -> float:
    """Stop remote/result work early enough to retain local termination time."""
    if (type(termination_deadline) not in (int, float)
            or not math.isfinite(termination_deadline)):
        raise SupervisorError("termination", "deadline")
    return float(termination_deadline) - LOCAL_TERMINATION_RESERVE_SECONDS


def _cancellation_disposal_valid(local_state: dict, arm_ns, exit_ns) -> bool:
    """Require verified owned-process exit within the original 40s arm window."""
    elapsed_ns = (exit_ns - arm_ns
                  if type(exit_ns) is int and type(arm_ns) is int else None)
    return (local_state.get("process_state") == "exited"
            and type(local_state.get("exit_code")) is int
            and local_state.get("exit_code") == 0
            and type(elapsed_ns) is int
            and 0 <= elapsed_ns <= 40_000_000_000)


def _owner_disposal_valid(local_state: dict, arm_ns, exit_ns) -> bool:
    """Require verified local owner-process exit inside its fixed 40s window."""
    return (_cancellation_disposal_valid(local_state, arm_ns, exit_ns)
            and local_state.get("ownership_verified") is True
            and local_state.get("cleanup_confirmed") is True
            and local_state.get("graceful_stop") is True)


def _publish_stop_response_once(local_cid: str, ack: dict, deadline: float,
                                state: dict) -> None:
    """Fence repeat O_EXCL writes, including a write with uncertain outcome."""
    if type(state) is not dict or state.get("stop_response") != "not_attempted":
        raise SupervisorError("stop_ack", "duplicate_publication_fenced")
    state["stop_response"] = "attempted_unknown"
    _write_local_handoff(local_cid, "stop-response.json", ack, deadline)
    state["stop_response"] = "published"


def _remote_ready_ack(ready, host_key, frame) -> dict:
    status = frame["status"]
    return {
        "schema_version": 1, "event": "ready_ack", "run_id": ready["run_id"],
        "nonce": ready["nonce"], "boot_id": ready["expected_boot_id"],
        "manifest_fingerprint": ready["manifest_fingerprint"],
        "snapshot_sha256": ready["snapshot_sha256"], "endpoint": ready["endpoint"],
        "ssh_host_key_sha256": host_key,
        "remote_status_uid": frame["uid"], "remote_status_mode": frame["mode"],
        "remote_status_mtime_ns": frame["mtime_ns"],
        "measurement_label": "ssh_protected_ready_status", "remote_status": status,
    }


def _remote_observation_ack(ready, host_key, request, frame, *,
                            measurement_label="ssh_status_after_heartbeat") -> dict:
    return {
        "schema_version": 1, "event": "observation_ack",
        "run_id": ready["run_id"], "nonce": ready["nonce"],
        "sequence": request["sequence"], "case_id": request["case_id"],
        "request_id": request["request_id"], "session_id": request["session_id"],
        "boot_id": ready["expected_boot_id"],
        "manifest_fingerprint": ready["manifest_fingerprint"],
        "endpoint": ready["endpoint"], "ssh_host_key_sha256": host_key,
        "remote_status_uid": frame["uid"], "remote_status_mode": frame["mode"],
        "supervisor_monotonic_ns": time.monotonic_ns(),
        "remote_mark_ns": frame["mark_ns"], "heartbeat_mtime_ns": frame["mtime_ns"],
        "measurement_label": measurement_label,
        "remote_status": frame["status"],
    }


def _capture_operator_result(cid: str, *, deadline: float) -> tuple[dict, dict] | None:
    result_raw = _read_local_handoff(cid, "result.json", deadline, missing_ok=True,
                                     maximum=CONTROL_LIMIT)
    exit_raw = _read_local_handoff(cid, "operator-exit.json", deadline,
                                   missing_ok=True, maximum=4096)
    if result_raw is None or exit_raw is None:
        return None
    result = _validate_result_record(_json_load(result_raw, CONTROL_LIMIT, label="cohort_result"))
    operator_exit = _json_load(exit_raw, 4096, label="operator_exit")
    _exact_fields(operator_exit,
                  {"schema_version", "event", "exit_code", "failure_type"},
                  "operator_exit")
    if (type(operator_exit["schema_version"]) is not int or operator_exit["schema_version"] != 1
            or operator_exit["event"] != "operator_exit"
            or type(operator_exit["exit_code"]) is not int
            or not 0 <= operator_exit["exit_code"] <= 255):
        raise SupervisorError("operator_exit", "invalid")
    failure = operator_exit["failure_type"]
    if failure is not None and (type(failure) is not str or not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{0,79}", failure)):
        raise SupervisorError("operator_exit", "failure_type")
    return result, operator_exit


def _prepare_local_volumes(args, deadline):
    def inspect_value(raw, stage):
        if type(raw) is not bytes or not 1 <= len(raw) <= 256:
            raise SupervisorError(stage, "inspect_output")
        try:
            value = raw.decode("ascii")
        except UnicodeDecodeError:
            raise SupervisorError(stage, "inspect_output") from None
        if value.endswith("\n"):
            value = value[:-1]
        if not value or "\n" in value or "\r" in value:
            raise SupervisorError(stage, "inspect_output")
        return value

    for name in (args.artifacts_volume, args.reference_volume):
        if type(name) is not str or _VOLUME.fullmatch(name) is None:
            raise SupervisorError("local_volume", "expected_name")
        output = _local_docker(
            ["docker", "volume", "inspect", "--format", "{{.Name}}", name],
            deadline=deadline, output=256)
        if inspect_value(output, "local_volume") != name:
            raise SupervisorError("local_volume", "identity_mismatch")

    image = args.local_image
    if (type(image) is not str
            or re.fullmatch(r"sha256:[0-9a-f]{64}", image, re.ASCII) is None):
        raise SupervisorError("local_image", "expected_immutable_id")
    output = _local_docker(
        ["docker", "image", "inspect", "--format", "{{.Id}}", image],
        deadline=deadline, output=256)
    if inspect_value(output, "local_image") != image:
        raise SupervisorError("local_image", "identity_mismatch")


def _prepare_remote_image(client, image, password, deadline):
    if (type(image) is not str
            or re.fullmatch(r"sha256:[0-9a-f]{64}", image, re.ASCII) is None):
        raise SupervisorError("remote_image", "expected_immutable_id")
    output = _ssh_checked(
        client, ["docker", "image", "inspect", "--format", "{{.Id}}", image],
        password=password, deadline=deadline, output_limit=256)
    if type(output) is not bytes or not 1 <= len(output) <= 256:
        raise SupervisorError("remote_image", "inspect_output")
    try:
        value = output.decode("ascii")
    except UnicodeDecodeError:
        raise SupervisorError("remote_image", "inspect_output") from None
    if value.endswith("\n"):
        value = value[:-1]
    if (not value or "\n" in value or "\r" in value
            or re.fullmatch(r"sha256:[0-9a-f]{64}", value, re.ASCII) is None):
        raise SupervisorError("remote_image", "inspect_output")
    if value != image:
        raise SupervisorError("remote_image", "identity_mismatch")


def _make_remote_ready(client, *, raw_tar, ready, args, owner,
                       password, uid, gid, deadline):
    _ensure_remote_paths(client, job_root=args.remote_job_root,
                         artifacts=args.remote_artifacts, uid=uid, gid=gid,
                         password=password, deadline=deadline)
    _sftp_upload_bundle(client, raw_tar, args.remote_job_root, uid, deadline)
    _remote_script(client, _REMOTE_EXTRACT_SCRIPT,
                   [args.remote_job_root, str(uid), str(gid)],
                   password=password, deadline=deadline, output_limit=256)
    _prepare_remote_image(client, args.remote_image, password, deadline)
    container_name = f"steamboat-c1b-worker3-{ready['run_id']}"
    return container_name


def _launch_restart_generation(client, *, raw_tar, ready, config, args,
                               owner, password, uid, gid, deadline,
                               container_name, job_root, on_cid,
                               on_launch_attempt=None):
    """Launch only the validated generation-2 worker under its distinct root."""
    # The caller owns creation and records that protected root exactly once.
    # Rechecking the shared artifact directory is safe; recreating job_root
    # would fail its exclusive mkdir and obscure the actual launch boundary.
    output = _remote_script(client, _REMOTE_CHECK_DIRECTORY_SCRIPT,
                            [args.remote_artifacts], password=password,
                            deadline=deadline, output_limit=256)
    if output.strip() != b"ok":
        raise SupervisorError("remote_artifacts", "directory_unverified")
    _sftp_upload_bundle(client, raw_tar, job_root, uid, deadline)
    _remote_script(client, _REMOTE_EXTRACT_SCRIPT,
                   [job_root, str(uid), str(gid)],
                   password=password, deadline=deadline, output_limit=256)
    _prepare_remote_image(client, args.remote_image, password, deadline)
    if on_launch_attempt is not None:
        on_launch_attempt()
    return _create_remote_container(
        client, image=args.remote_image, name=container_name, owner=owner,
        job_root=job_root, artifacts=args.remote_artifacts,
        password=password, deadline=deadline, on_cid=on_cid)


def _wait_restart_bundle_ready(cid, *, old_ready, old_snapshot_sha256,
                               receipt_digest, endpoint, deadline):
    from lab.secure_cohort_restart import validate_restart_bundle_ready

    while time.monotonic() < deadline:
        _terminal_controls(cid, "restart-bundle-ready.json", deadline, old_ready)
        raw = _read_local_handoff(cid, "restart-bundle-ready.json",
                                  deadline, missing_ok=True)
        if raw is None:
            time.sleep(min(0.15, max(0.0, deadline - time.monotonic())))
            continue
        value = _json_load(raw, CONTROL_LIMIT, label="restart_bundle_ready")
        new_nonce = value.get("new_nonce")
        new_boot = value.get("new_boot_id")
        new_snapshot = value.get("new_snapshot_sha256")
        try:
            bundle = validate_restart_bundle_ready(
                value, run_id=old_ready["run_id"],
                old_nonce=old_ready["nonce"], new_nonce=new_nonce,
                old_boot_id=old_ready["expected_boot_id"], new_boot_id=new_boot,
                old_snapshot_sha256=old_snapshot_sha256,
                new_snapshot_sha256=new_snapshot,
                old_owner_receipt_sha256=receipt_digest,
                manifest_fingerprint=old_ready["manifest_fingerprint"],
                endpoint=endpoint, bundle_validator=_validate_bundle_ready)
        except (ValueError, TypeError, KeyError) as error:
            raise SupervisorError("restart_bundle_ready", "invalid") from error
        return value, bundle
    raise SupervisorError("restart_bundle_ready", "timeout")


def _write_final_report(args, result_directory, record):
    run_suffix = record.get("run_id") if type(record.get("run_id")) is str else uuid.uuid4().hex
    filename = f"secure-cohort-{run_suffix}.json"
    path = _write_result(result_directory, filename, record)
    print(json.dumps({"result": str(path), "status": record["status"],
                      "failure_stage": record.get("failure_stage")},
                     sort_keys=True, separators=(",", ":")))
    return path


def run_supervisor(args) -> int:
    validate_cli(args)
    result_directory = _create_results_dir(args.result_directory)
    started = time.monotonic()
    hard_deadline = started + COHORT_SECONDS
    requested_profile = getattr(args, "profile", PROFILE_BASELINE)
    work_reserve = 55.0 if requested_profile in OWNER_PROFILES else 35.0
    work_deadline = hard_deadline - work_reserve  # reserve profile teardown and report time
    local_startup_deadline = min(work_deadline, started + LOCAL_STARTUP_SECONDS)
    owner = uuid.uuid4().hex
    local_name = f"steamboat-c1b-operator-{owner[:16]}"
    remote_name = None
    local_cid = None
    remote_cid = None
    ssh = None
    sudo_password = None
    sftp_uid = sftp_gid = None
    host_key = None
    ready = None
    config = None
    remote_state = {
        "container_id": None, "process_state": "not_attempted",
        "ownership_status": "unverified",
        "exit_code": None, "graceful_compute_shutdown": False,
        "shutdown_confirmed": False, "container_removed": False,
        "private_files_removed": False, "job_root_removed": False,
        "cleanup_confirmed": False, "failure_type": None,
        "removal_evidence": None,
    }
    cohort_summary = None
    cohort_failure_location = None
    operator_exit = None
    failures: list[dict] = []
    primary_failure = None
    local_state = {"container_id": None, "exit_code": None,
                   "process_state": "not_attempted", "graceful_stop": False,
                   "forced_kill": False, "container_removed": False,
                   "cleanup_confirmed": False, "failure_type": None,
                   "ownership_status": "unverified"}
    remote_stop_done = False
    job_root_created = False
    job_root_creation_attempted = False
    job_root_state = "not_attempted"
    remote_launch_attempted = False
    local_create_attempted = False
    readiness_observed = False
    restart_old_ready = None
    restart_old_config = None
    restart_old_bundle_files = None
    restart_old_state = None
    restart_receipt = None
    restart_receipt_digest = None
    restart_new_bundle = None
    restart_new_ready = None
    restart_new_snapshot_sha256 = None
    restart_observation_requests = {}
    restart_old_held_status = None
    stop_response = {"stop_response": "not_attempted"}
    terminal_stop_request = None
    termination_deadline_once = _termination_deadline_once(hard_deadline)
    cancel_deadline = None
    cancellation_arm_ns = None
    cancellation_armed_identity = None
    capacity_held_session_ids = None
    cancellation_local_exit_ns = None
    owner_disposal_arm_ns = None
    owner_disposal_deadline = None
    owner_disposal_exit_ns = None
    owner_profile = requested_profile in OWNER_PROFILES
    owner_expected = None
    owner_clock = None
    owner_snapshot_store = None
    owner_initial_view = None
    owner_initial_serials = None
    owner_intent_root = None
    owner_state = {
        "handled_requests": [], "action_responses": [], "command_sha256s": [],
        "prepared_commands": [], "intent_receipts": {}, "action_frames": {},
        "observation_acks": [], "attempts": [], "materials_wrapper": None,
        "material_files": None, "material_views": None,
        "material_policies": None, "actual_remove_exit": None,
        "verifier_copy_receipt": None, "sidecar_retention_receipt": None,
        "delivered_handoffs": [],
    }

    def record_local_cid(cid):
        nonlocal local_cid
        local_cid = cid
        local_state["container_id"] = cid
        local_state["process_state"] = "created_candidate"
        local_state["ownership_status"] = "candidate"

    def record_remote_cid(cid):
        nonlocal remote_cid
        remote_cid = cid
        remote_state["container_id"] = cid
        remote_state["process_state"] = "created_candidate"
        remote_state["ownership_status"] = "candidate"

    def termination_work_deadline():
        return _termination_work_deadline(termination_deadline_once())

    def arm_owner_disposal():
        nonlocal owner_disposal_arm_ns, owner_disposal_deadline
        if owner_profile and owner_disposal_arm_ns is None:
            owner_disposal_arm_ns = time.monotonic_ns()
            owner_disposal_deadline = min(
                hard_deadline, owner_disposal_arm_ns / 1_000_000_000 + 40.0)
        return owner_disposal_deadline

    def fail(stage, code):
        nonlocal primary_failure
        arm_owner_disposal()
        item = {"stage": stage[:64], "type": code[:80]}
        failures.append(item)
        if primary_failure is None:
            primary_failure = item

    try:
        expected_endpoint = _configured_endpoint(args.external_ip, args.external_port)
        _prepare_local_volumes(args, local_startup_deadline)
        cohort_args = [
            "--artifacts", "/artifacts", "--reference", "/reference",
            "--external-ip", args.external_ip, "--external-port", str(args.external_port),
            "--clock-uncertainty-seconds", repr(float(args.uncertainty_seconds)),
            "--profile", getattr(args, "profile", PROFILE_BASELINE),
            "--handoff-directory", HANDOFF_ROOT,
        ]
        local_create_attempted = True
        local_cid = _create_local_container(args=args, name=local_name,
                                            owner=owner, cohort_args=cohort_args,
                                            deadline=local_startup_deadline,
                                            on_cid=record_local_cid)
        local_state["container_id"] = local_cid
        local_state["ownership_status"] = "verified"
        ready = _validate_bundle_ready(_wait_local_json(
            local_cid, "bundle-ready.json", local_startup_deadline,
            label="bundle_ready"), expected_endpoint)
        run_id = ready["run_id"]
        bundle_tar = _local_docker(
            ["docker", "exec", local_cid, "python", "-c", _LOCAL_TAR_SCRIPT,
             ready["bundle_path"]], deadline=local_startup_deadline,
            output=BUNDLE_LIMIT)
        bundle_files = validate_worker_tar(bundle_tar, ready, expected_endpoint)
        config = _validate_worker_config(bundle_files["worker.json"], ready,
                                         expected_endpoint)
        if owner_profile:
            (owner_expected, owner_clock, owner_snapshot_store,
             owner_initial_view, owner_initial_serials) = _owner_initial_context(
                getattr(args, "profile", PROFILE_BASELINE), ready, config, bundle_files)
        if getattr(args, "profile", PROFILE_BASELINE) == PROFILE_C1B_RESTART:
            restart_old_ready = dict(ready)
            restart_old_config = dict(config)
            restart_old_bundle_files = dict(bundle_files)
        remote_state["process_state"] = "setup_pending"

        remote_start_deadline = min(work_deadline,
                                    time.monotonic() + REMOTE_STARTUP_SECONDS)
        ssh, host_key, sudo_password = _connect_ssh(args, remote_start_deadline)
        sftp = _open_sftp(ssh, remote_start_deadline)
        try:
            sftp_uid, sftp_gid = _remote_user_ids(sftp, remote_start_deadline)
        finally:
            try:
                _sftp_call(sftp, remote_start_deadline, "remote_identity", sftp.close)
            finally:
                _abort_sftp(sftp)
        job_root_creation_attempted = True
        job_root_state = "creating"
        _remote_script(ssh, _REMOTE_CREATE_JOB_SCRIPT,
                       [args.remote_job_root, str(sftp_uid), str(sftp_gid)],
                       password=sudo_password, deadline=remote_start_deadline,
                       output_limit=256)
        job_root_created = True
        job_root_state = "created"
        if (owner_profile
                and getattr(args, "profile", PROFILE_BASELINE) == PROFILE_C1B_OWNER_REMOVE):
            owner_intent_root = _ensure_owner_intent_root(
                ssh, job_root=args.remote_job_root, uid=sftp_uid, gid=sftp_gid,
                password=sudo_password, deadline=remote_start_deadline,
                on_attempt=lambda: owner_state["attempts"].append(
                    {"kind": "intent_root", "monotonic_ns": time.monotonic_ns()}) or None)
            owner_state["verifier_copy_receipt"] = _install_owner_verifier_copy(
                ssh, bundle_files["snapshot.pub"], intent_root=owner_intent_root,
                uid=sftp_uid, gid=sftp_gid, password=sudo_password,
                deadline=remote_start_deadline,
                on_attempt=lambda: owner_state["attempts"].append(
                    {"kind": "snapshot_verifier", "monotonic_ns": time.monotonic_ns()}) or None)
        checked_artifacts = _remote_script(
            ssh, _REMOTE_CHECK_DIRECTORY_SCRIPT, [args.remote_artifacts],
            password=sudo_password, deadline=remote_start_deadline, output_limit=256)
        if checked_artifacts.strip() != b"ok":
            raise SupervisorError("remote_artifacts", "directory_unverified")
        _sftp_upload_bundle(ssh, bundle_tar, args.remote_job_root,
                            sftp_uid, remote_start_deadline)
        _remote_script(ssh, _REMOTE_EXTRACT_SCRIPT,
                       [args.remote_job_root, str(sftp_uid), str(sftp_gid)],
                       password=sudo_password, deadline=remote_start_deadline,
                       output_limit=256)
        _prepare_remote_image(ssh, args.remote_image, sudo_password,
                              remote_start_deadline)
        remote_name = f"steamboat-c1b-worker3-{ready['run_id']}"
        remote_state["process_state"] = "launching"
        # Set before invoking Docker: a lost response may mean a container was
        # created, so unresolved ownership must retain the private job root.
        remote_launch_attempted = True
        remote_cid = _create_remote_container(
            ssh, image=args.remote_image, name=remote_name, owner=owner,
            job_root=args.remote_job_root, artifacts=args.remote_artifacts,
            password=sudo_password, deadline=remote_start_deadline,
            on_cid=record_remote_cid,
            owner_controls_run_id=(ready["run_id"] if owner_profile else None),
            owner_intent_root=owner_intent_root)
        if remote_cid is not None:
            remote_state["container_id"] = remote_cid
            remote_state["ownership_status"] = "verified"
            remote_state["process_state"] = "starting"
            mark = _remote_mark(ssh, password=sudo_password, deadline=remote_start_deadline)
            frame = _wait_remote_status(
                ssh, config=config, password=sudo_password,
                status_path=posixpath.join(args.remote_job_root, "status.json"),
                mark_ns=mark,
                deadline=remote_start_deadline, expected_events={"ready", "heartbeat"},
                terminal_check=lambda: _terminal_controls(
                    local_cid, "ready.json", remote_start_deadline, ready),
                owner_expected=owner_expected)
            readiness_observed = True
            remote_state["readiness_observed"] = True
            ready_ack = _remote_ready_ack(ready, host_key, frame)
            _write_local_handoff(local_cid, "ready.json", ready_ack, remote_start_deadline)
            remote_state["process_state"] = "ready"

            profile = getattr(args, "profile", PROFILE_BASELINE)
            for sequence, _case_id in _PROFILE_OBSERVATIONS[profile]:
                response_name = f"observation-response-{sequence}.json"
                request_deadline = min(cancel_deadline or work_deadline,
                                       time.monotonic() + 60.0)
                request = _wait_observation_request(
                    local_cid, sequence, ready, request_deadline, profile)
                if owner_profile:
                    if sequence >= 5:
                        owner_request = request
                        if owner_request.get("sequence") != sequence:
                            raise SupervisorError("owner_observation", "sequence")
                        held_session = _owner_observation_session(
                            profile, sequence, owner_request,
                            owner_state["observation_acks"])
                        if profile == PROFILE_C1B_OWNER_REMOVE and sequence == 7:
                            saved = owner_state["action_frames"].get(2)
                            if type(saved) is not dict:
                                raise SupervisorError("owner_observation", "missing_final_action")
                            frame = saved["frame"]
                        else:
                            mark = _remote_mark(ssh, password=sudo_password,
                                                deadline=request_deadline)
                            status_command = None
                            if sequence >= 6:
                                applied_number = (2 if profile == PROFILE_C1B_OWNER_DRAIN else 1)
                                if len(owner_state["action_responses"]) != applied_number:
                                    raise SupervisorError("owner_observation", "command_not_applied")
                                status_command = owner_state["action_responses"][-1]["worker_ack"]
                            frame = _wait_remote_status(
                                ssh, config=config, password=sudo_password,
                                status_path=posixpath.join(args.remote_job_root, "status.json"),
                                mark_ns=mark, deadline=request_deadline,
                                expected_events={"heartbeat"},
                                terminal_check=lambda: _terminal_controls(
                                    local_cid, response_name, request_deadline, ready),
                                expected_session_id=held_session,
                                owner_command=status_command,
                                owner_expected=owner_expected,
                                owner_observation=True)
                        ack = _remote_observation_ack(
                            ready, host_key, owner_request, frame,
                            measurement_label="ssh_protected_owner_status_v1")
                        owner_state["observation_acks"].append(ack)
                        _write_local_handoff(local_cid, response_name, ack,
                                             request_deadline)
                        owner_state["delivered_handoffs"].append(response_name)
                        if sequence == 5:
                            _handle_owner_action(
                                local_cid=local_cid, number=1, expected=owner_expected,
                                ready=ready, config=config, bundle_files=bundle_files,
                                initial_view=owner_initial_view,
                                initial_store=owner_snapshot_store,
                                initial_serials=owner_initial_serials, host_key=host_key,
                                ssh=ssh, password=sudo_password,
                                job_root=args.remote_job_root,
                                intent_root=owner_intent_root, uid=sftp_uid, gid=sftp_gid,
                                container_id=remote_cid, container_name=remote_name,
                                owner_label=owner, image=args.remote_image,
                                deadline=request_deadline, owner_state=owner_state)
                            if profile == PROFILE_C1B_OWNER_DRAIN:
                                _handle_owner_action(
                                    local_cid=local_cid, number=2,
                                    expected=owner_expected, ready=ready, config=config,
                                    bundle_files=bundle_files,
                                    initial_view=owner_initial_view,
                                    initial_store=owner_snapshot_store,
                                    initial_serials=owner_initial_serials,
                                    host_key=host_key, ssh=ssh, password=sudo_password,
                                    job_root=args.remote_job_root,
                                    intent_root=owner_intent_root, uid=sftp_uid, gid=sftp_gid,
                                    container_id=remote_cid, container_name=remote_name,
                                    owner_label=owner, image=args.remote_image,
                                    deadline=request_deadline, owner_state=owner_state)
                        elif profile == PROFILE_C1B_OWNER_REMOVE and sequence == 6:
                            _handle_owner_action(
                                local_cid=local_cid, number=2, expected=owner_expected,
                                ready=ready, config=config, bundle_files=bundle_files,
                                initial_view=owner_initial_view,
                                initial_store=owner_snapshot_store,
                                initial_serials=owner_initial_serials, host_key=host_key,
                                ssh=ssh, password=sudo_password,
                                job_root=args.remote_job_root,
                                intent_root=owner_intent_root, uid=sftp_uid, gid=sftp_gid,
                                container_id=remote_cid, container_name=remote_name,
                                owner_label=owner, image=args.remote_image,
                                deadline=request_deadline, owner_state=owner_state)
                        if profile == PROFILE_C1B_OWNER_REMOVE and sequence == 7:
                            saved = owner_state["action_frames"][2]
                            if (frame != saved["frame"]
                                    or ack["request_id"] != owner_state["observation_acks"][0]["request_id"]
                                    or ack["session_id"] != owner_state["observation_acks"][0]["session_id"]):
                                raise SupervisorError("owner_observation", "final_status_reuse")
                        continue
                if profile == PROFILE_C1B_RESTART:
                    restart_observation_requests[sequence] = dict(request)
                    if (sequence == 6 and 5 in restart_observation_requests
                            and (request["request_id"]
                                 != restart_observation_requests[5]["request_id"]
                                 or request["session_id"]
                                 != restart_observation_requests[5]["session_id"])):
                        raise SupervisorError("restart_observation", "stale_binding_identity")
                if (profile in (PROFILE_C1B_CANCEL, PROFILE_C1B_PARTIAL,
                                PROFILE_C1B_STEP_LOSS, PROFILE_C1B_CAPACITY) and sequence == 6
                        and cancellation_armed_identity != (
                            request.get("request_id"), request.get("session_id"))):
                    raise SupervisorError("cancellation", "held_session_identity_changed")
                mark = _remote_mark(ssh, password=sudo_password,
                                    deadline=request_deadline)
                held_session = (request["session_id"]
                                if profile in (PROFILE_C1B_CANCEL, PROFILE_C1B_PARTIAL,
                                               PROFILE_C1B_STEP_LOSS, PROFILE_C1B_CAPACITY)
                                and sequence == 5
                                else request["session_id"]
                                if profile == PROFILE_C1B_RESTART and sequence == 5
                                else None)
                frame = _wait_remote_status(
                    ssh, config=config, password=sudo_password,
                    status_path=posixpath.join(args.remote_job_root, "status.json"),
                    mark_ns=mark,
                    deadline=request_deadline, expected_events={"heartbeat"},
                    terminal_check=lambda: _terminal_controls(
                        local_cid, response_name, request_deadline, ready),
                    expected_session_id=held_session,
                    expected_open_only=(profile == PROFILE_C1B_PARTIAL and sequence == 5),
                    expected_session_count=(8 if profile == PROFILE_C1B_CAPACITY
                                            and sequence == 5 else None),
                    partial_expiry_session_id=(request["session_id"]
                                               if profile == PROFILE_C1B_PARTIAL
                                               and sequence == 6 else None),
                    owner_expected=owner_expected)
                if profile == PROFILE_C1B_RESTART and sequence == 5:
                    restart_old_held_status = dict(frame["status"])
                ack = _remote_observation_ack(
                    ready, host_key, request, frame,
                    measurement_label=("ssh_protected_owner_status_v1"
                                       if owner_profile
                                       else "ssh_status_after_heartbeat"))
                if profile in (PROFILE_C1B_CANCEL, PROFILE_C1B_PARTIAL,
                               PROFILE_C1B_STEP_LOSS) and sequence == 5:
                    cancellation_arm_ns = ack["supervisor_monotonic_ns"]
                    cancellation_armed_identity = (
                        request.get("request_id"), request.get("session_id"))
                    cancel_deadline = cancellation_arm_ns / 1_000_000_000 + 40.0
                    termination_deadline_once = _termination_deadline_once(cancel_deadline)
                    request_deadline = min(request_deadline, cancel_deadline)
                if profile == PROFILE_C1B_CAPACITY and sequence == 5:
                    capacity_held_session_ids = list(
                        frame["status"]["handler"]["active_session_ids"])
                    if (len(capacity_held_session_ids) != 8
                            or request.get("session_id") not in capacity_held_session_ids):
                        raise SupervisorError("capacity", "held_session_identity_mismatch")
                    cancellation_arm_ns = ack["supervisor_monotonic_ns"]
                    cancellation_armed_identity = (
                        request.get("request_id"), request.get("session_id"))
                    cancel_deadline = cancellation_arm_ns / 1_000_000_000 + 40.0
                    termination_deadline_once = _termination_deadline_once(cancel_deadline)
                    request_deadline = min(request_deadline, cancel_deadline)
                _write_local_handoff(local_cid, response_name, ack, request_deadline)
                if profile == PROFILE_C1B_RESTART and sequence == 5:
                    from lab.secure_cohort_restart import (
                        RESTART_BUNDLE_READY_FILE, RESTART_READY_ACK_FILE,
                        RESTART_STOP_REQUEST_FILE, RESTART_STOP_RESPONSE_FILE,
                        REMOTE_NEW_STARTUP_SECONDS, REMOTE_OLD_RETIREMENT_SECONDS,
                    )

                    stop_deadline = min(work_deadline, time.monotonic() + 60.0)
                    stop_request = _validate_restart_stop_request(
                        _wait_local_json(local_cid, RESTART_STOP_REQUEST_FILE,
                                         stop_deadline, label="restart_stop_request",
                                         ready=restart_old_ready), restart_old_ready)
                    stop_arm_ns = time.monotonic_ns()
                    confirmed_exit = []
                    shutdown_deadline = min(
                        work_deadline,
                        stop_arm_ns / 1_000_000_000 + REMOTE_OLD_RETIREMENT_SECONDS)
                    restart_old_state = _stop_remote(
                        ssh, remote_cid, name=remote_name, owner=owner,
                        image=args.remote_image, password=sudo_password,
                        config=restart_old_config, job_root=args.remote_job_root,
                        uid=sftp_uid, gid=sftp_gid, deadline=shutdown_deadline,
                        on_exit_confirmed=confirmed_exit.append)
                    restart_old_state["container_id"] = remote_cid
                    restart_old_state["ownership_status"] = "verified"
                    restart_old_state["readiness_observed"] = True
                    restart_old_state["stop_arm_monotonic_ns"] = stop_arm_ns
                    stop_exit_ns = confirmed_exit[0] if len(confirmed_exit) == 1 else None
                    if (restart_old_state.get("failure_type") is not None
                            or restart_old_state.get("shutdown_confirmed") is not True
                            or type(stop_exit_ns) is not int or stop_exit_ns < stop_arm_ns):
                        raise SupervisorError("restart_old_cleanup", "unconfirmed")
                    restart_receipt, restart_receipt_digest = _restart_stop_receipt(
                        ready=restart_old_ready, host_key=host_key,
                        remote_state=restart_old_state, image=args.remote_image,
                        arm_ns=stop_arm_ns, exit_ns=stop_exit_ns)
                    _write_local_handoff(local_cid, RESTART_STOP_RESPONSE_FILE,
                                         restart_receipt, shutdown_deadline)
                    remote_stop_done = True

                    envelope_deadline = min(
                        work_deadline, time.monotonic() + REMOTE_NEW_STARTUP_SECONDS)
                    restart_envelope, restart_new_bundle = _wait_restart_bundle_ready(
                        local_cid, old_ready=restart_old_ready,
                        old_snapshot_sha256=restart_old_ready["snapshot_sha256"],
                        receipt_digest=restart_receipt_digest,
                        endpoint=expected_endpoint, deadline=envelope_deadline)
                    tar_raw = _local_docker(
                        ["docker", "exec", local_cid, "python", "-c",
                         _LOCAL_TAR_SCRIPT, restart_new_bundle["bundle_path"]],
                        deadline=envelope_deadline, output=BUNDLE_LIMIT)
                    new_files = validate_worker_tar(
                        tar_raw, restart_new_bundle, expected_endpoint)
                    for unchanged in ("cohort-ca.crt", "snapshot.pub", "host.crt", "host.key"):
                        if new_files[unchanged] != restart_old_bundle_files[unchanged]:
                            raise SupervisorError("restart_bundle", "same_leaf_continuity")
                    config = _validate_worker_config(
                        new_files["worker.json"], restart_new_bundle, expected_endpoint)
                    _validate_restart_config_continuity(restart_old_config, config)
                    restart_new_snapshot_sha256 = restart_new_bundle["snapshot_sha256"]

                    old_remote_name = remote_name
                    old_job_root = args.remote_job_root
                    new_job_root = old_job_root + "-g2"
                    _remote_path(new_job_root, label="restart_job_root")
                    if new_job_root == args.remote_artifacts:
                        raise SupervisorError("restart_job_root", "path_alias")
                    remote_cid = None
                    remote_stop_done = False
                    remote_launch_attempted = False
                    remote_state = {
                        "container_id": None, "process_state": "setup_pending",
                        "ownership_status": "unverified", "exit_code": None,
                        "graceful_compute_shutdown": False,
                        "shutdown_confirmed": False, "container_removed": False,
                        "private_files_removed": False, "job_root_removed": False,
                        "cleanup_confirmed": False, "failure_type": None,
                        "removal_evidence": None,
                    }
                    args.remote_job_root = new_job_root
                    job_root_creation_attempted = True
                    job_root_state = "creating"
                    _remote_script(ssh, _REMOTE_CREATE_JOB_SCRIPT,
                                   [new_job_root, str(sftp_uid), str(sftp_gid)],
                                   password=sudo_password, deadline=envelope_deadline,
                                   output_limit=256)
                    job_root_created = True
                    job_root_state = "created"
                    remote_name = old_remote_name + "-g2"

                    def mark_remote_launch_attempted():
                        nonlocal remote_launch_attempted
                        remote_launch_attempted = True
                        remote_state["process_state"] = "launching"

                    new_cid = _launch_restart_generation(
                        ssh, raw_tar=tar_raw, ready=restart_new_bundle,
                        config=config, args=args, owner=owner,
                        password=sudo_password, uid=sftp_uid, gid=sftp_gid,
                        deadline=envelope_deadline, container_name=remote_name,
                        job_root=new_job_root, on_cid=record_remote_cid,
                        on_launch_attempt=mark_remote_launch_attempted)
                    remote_cid = new_cid
                    if new_cid is None:
                        raise SupervisorError("restart_new_start", "no_owned_container")
                    remote_state.update(container_id=new_cid,
                                        ownership_status="verified",
                                        process_state="starting")
                    new_mark = _remote_mark(
                        ssh, password=sudo_password, deadline=envelope_deadline)
                    new_frame = _wait_remote_status(
                        ssh, config=config, password=sudo_password,
                        status_path=posixpath.join(new_job_root, "status.json"),
                        mark_ns=new_mark, deadline=envelope_deadline,
                        expected_events={"ready", "heartbeat"},
                        terminal_check=lambda: _terminal_controls(
                            local_cid, RESTART_READY_ACK_FILE,
                            envelope_deadline, restart_new_bundle))
                    restart_new_ready = _remote_ready_ack(
                        restart_new_bundle, host_key, new_frame)
                    ready_wrapper = {
                        "schema_version": 1, "event": "restart_ready_ack",
                        "run_id": run_id,
                        "old_nonce": restart_old_ready["nonce"],
                        "new_nonce": restart_new_bundle["nonce"],
                        "old_boot_id": restart_old_ready["expected_boot_id"],
                        "new_boot_id": restart_new_bundle["expected_boot_id"],
                        "old_owner_receipt_sha256": restart_receipt_digest,
                        "ready_ack": restart_new_ready,
                    }
                    _validate_restart_ready_ack_locally(
                        ready_wrapper, run_id=run_id, old_ready=restart_old_ready,
                        new_bundle=restart_new_bundle, host_key=host_key,
                        config=config, receipt_digest=restart_receipt_digest)
                    _write_local_handoff(local_cid, RESTART_READY_ACK_FILE,
                                         ready_wrapper, envelope_deadline)
                    ready = restart_new_bundle
                    readiness_observed = True
                    remote_state["readiness_observed"] = True
                    remote_state["process_state"] = "ready"
                if profile in (PROFILE_C1B_CANCEL, PROFILE_C1B_PARTIAL,
                               PROFILE_C1B_STEP_LOSS, PROFILE_C1B_CAPACITY) and sequence >= 5:
                    if (type(ack.get("supervisor_monotonic_ns")) is not int
                            or time.monotonic_ns() - ack["supervisor_monotonic_ns"]
                            > 40_000_000_000):
                        raise SupervisorError("cancellation", "deadline_exceeded")

            stop_deadline = min(cancel_deadline or work_deadline,
                                time.monotonic() + 60.0)
            stop_request = _validate_stop_request(
                _wait_local_json(local_cid, "stop-request.json", stop_deadline,
                                 label="stop_request", ready=ready), ready)
            if not stop_request["may_have_started"]:
                raise SupervisorError("stop_request", "published_bundle_must_be_classified_started")
            if owner_profile:
                # Start the independent local-process disposal bound as soon as
                # the validated final stop request is observed, before sidecar,
                # remote shutdown, or result I/O can consume time.
                arm_owner_disposal()
            if (getattr(args, "profile", PROFILE_BASELINE) == PROFILE_C1B_OWNER_REMOVE
                    and owner_state.get("actual_remove_exit") == {
                        "process_state": "exited", "exit_code": 0}
                    and owner_intent_root is not None
                    and type(owner_state.get("material_files")) is dict):
                owner_state["sidecar_retention_receipt"] = _verify_owner_intent_sidecar(
                    ssh, intent_root=owner_intent_root, uid=sftp_uid, gid=sftp_gid,
                    password=sudo_password, deadline=termination_work_deadline(),
                    material_files={**owner_state["material_files"],
                                    "snapshot.pub": bundle_files["snapshot.pub"]})
            shutdown_deadline = termination_work_deadline()
            remote_state = _stop_remote(
                ssh, remote_cid, name=remote_name, owner=owner,
                image=args.remote_image, password=sudo_password,
                config=config, job_root=args.remote_job_root,
                uid=sftp_uid, gid=sftp_gid,
                deadline=shutdown_deadline, owner_expected=owner_expected,
                owner_final_ack=(owner_state["action_responses"][-1]["worker_ack"]
                                 if owner_state["action_responses"] else None),
                owner_cleanup_ready=(
                    _owner_cleanup_is_authorized(
                        owner_state, getattr(args, "profile", PROFILE_BASELINE),
                        intent_root=owner_intent_root)
                    if owner_profile else False))
            remote_state["container_id"] = remote_cid
            remote_state["ownership_status"] = "verified"
            remote_state["readiness_observed"] = readiness_observed
            remote_stop_done = True
            if remote_state.get("failure_type") is not None:
                fail("remote_cleanup", remote_state["failure_type"])
            ack = _stop_ack(ready, host_key, remote_state)
            _publish_stop_response_once(local_cid, ack, shutdown_deadline,
                                        stop_response)
        else:
            raise SupervisorError("remote_start", "no_owned_container")

    except SupervisorError as error:
        if error.stage == "cohort_control" and error.code == "stop_requested":
            terminal_stop_request = getattr(error, "stop_request", None)
            fail("cohort_control", "early_stop_requested")
            if (ready is None or terminal_stop_request is None
                    or not terminal_stop_request.get("may_have_started")):
                fail("cohort_control", "early_stop_without_confirmed_started_worker")
        else:
            fail(error.stage, error.code)
    except BaseException as error:
        # Store only the exception class; never serialize peer text or tracebacks.
        fail("supervisor", type(error).__name__[:80])

    if local_create_attempted and local_cid is None:
        local_state["process_state"] = "create_ownership_unknown"
        local_state["failure_type"] = "local_cid_unresolved"
        fail("local_start", "container_ownership_unknown_residuals_retained")

    if failures or terminal_stop_request is not None or (ready is not None and remote_cid is None):
        termination_deadline_once()

    # Always stop only the container whose ID, name, image, role and owner label
    # were verified.  If startup was ambiguous, leave unknown resources fenced.
    if ssh is not None and remote_cid is not None and not remote_stop_done:
        try:
            if remote_state.get("ownership_status") != "verified":
                _remote_inspect(
                    ssh, remote_cid, name=remote_name, owner=owner,
                    image=args.remote_image, password=sudo_password,
                    deadline=termination_work_deadline())
                remote_state["ownership_status"] = "verified"
            remote_state = _stop_remote(
                ssh, remote_cid, name=remote_name, owner=owner,
                image=args.remote_image, password=sudo_password,
                config=config, job_root=args.remote_job_root,
                uid=sftp_uid, gid=sftp_gid,
                deadline=termination_work_deadline(), owner_expected=owner_expected,
                owner_final_ack=(owner_state["action_responses"][-1]["worker_ack"]
                                 if owner_state["action_responses"] else None),
                owner_cleanup_ready=(
                    _owner_cleanup_is_authorized(
                        owner_state, getattr(args, "profile", PROFILE_BASELINE),
                        intent_root=owner_intent_root)
                    if owner_profile else False))
            remote_state["container_id"] = remote_cid
            remote_state["ownership_status"] = "verified"
            remote_state["readiness_observed"] = readiness_observed
            remote_stop_done = True
            if remote_state.get("failure_type") is not None:
                fail("remote_cleanup", remote_state["failure_type"])
            if not remote_state.get("shutdown_confirmed"):
                fail("remote_cleanup", remote_state.get("failure_type") or "shutdown_unconfirmed")
        except BaseException as error:
            fail("remote_cleanup", type(error).__name__[:80])
    elif remote_launch_attempted and remote_cid is None:
        # A published bundle with no verified owned CID is a setup failure.  Do
        # not manufacture a not-started response or a positive stop assertion.
        remote_state["shutdown_confirmed"] = False
        remote_state["cleanup_confirmed"] = False
        remote_state["process_state"] = "launch_unknown"
        remote_state["failure_type"] = remote_state.get("failure_type") or "remote_start_no_verified_cid"
        if not failures:
            fail("remote_setup", "launch_ownership_unknown_residuals_retained")
        # If the cohort is waiting in its own finally block, fail closed by
        # withholding stop-response.json.  Its bounded timeout becomes part of
        # the preserved failure record.

    if (ssh is not None and job_root_created and not remote_launch_attempted
            and not owner_profile
            and remote_cid is None):
        # No remote process was launched, but an unretired upload can still
        # write through an open handle. Never race it with another SSH channel.
        try:
            if _pending_channel_operation_count():
                raise SupervisorError("remote_bundle_cleanup", "operation_ownership_pending")
            removal = _remove_remote_job(
                ssh, job_root=args.remote_job_root, uid=sftp_uid, gid=sftp_gid,
                password=sudo_password, deadline=termination_work_deadline())
            raw_removal = (removal.get("raw_evidence")
                           if type(removal) is dict else None)
            if (type(removal) is dict
                    and type(removal.get("private_files_removed")) is bool
                    and type(removal.get("job_root_removed")) is bool
                    and type(raw_removal) is dict):
                derived = _adapt_remote_removal_evidence(raw_removal)
                if (removal["private_files_removed"]
                        is derived["private_files_removed"]
                        and removal["job_root_removed"]
                        is derived["job_root_removed"]):
                    # _remove_remote_job has already validated the bounded
                    # raw record. Keep it for the private report rather than
                    # reducing partial cleanup to booleans.
                    remote_state["removal_evidence"] = dict(raw_removal)
                    remote_state["private_files_removed"] = derived["private_files_removed"]
                    remote_state["job_root_removed"] = derived["job_root_removed"]
                    remote_state["cleanup_confirmed"] = bool(
                        derived["private_files_removed"]
                        and derived["job_root_removed"])
                else:
                    fail("remote_bundle_cleanup", "removal_evidence_invalid")
                if not remote_state["private_files_removed"] or not remote_state["job_root_removed"]:
                    fail("remote_bundle_cleanup", "removal_unconfirmed")
            else:
                fail("remote_bundle_cleanup", "removal_evidence_invalid")
        except SupervisorError as error:
            remote_state["cleanup_confirmed"] = False
            fail("remote_bundle_cleanup", error.code)
        except BaseException as error:
            fail("remote_bundle_cleanup", type(error).__name__[:80])
    elif job_root_creation_attempted and not job_root_created:
        job_root_state = "creation_unknown"
        fail("remote_setup", "job_root_ownership_unknown_residuals_retained")
    elif ssh is not None and job_root_created and not remote_launch_attempted and owner_profile:
        fail("remote_bundle_cleanup", "owner_materials_retained_before_launch")

    if terminal_stop_request is not None and ready is not None and remote_cid is not None:
        if (terminal_stop_request.get("may_have_started") is True
                and remote_stop_done and remote_state.get("status") is not None
                and stop_response["stop_response"] == "not_attempted"):
            try:
                _publish_stop_response_once(
                    local_cid, _stop_ack(ready, host_key, remote_state),
                    termination_work_deadline(), stop_response)
            except BaseException as error:
                fail("stop_ack", getattr(error, "code", type(error).__name__)[:80])

    if local_cid is not None:
        records_captured = False
        if local_state.get("ownership_status") == "verified":
            completion_deadline = termination_work_deadline()
            if ready is not None:
                diagnostic_raw = None
                try:
                    diagnostic_raw = _read_local_handoff(
                        local_cid, _FAILURE_LOCATION_FILE,
                        deadline=completion_deadline, missing_ok=True,
                        maximum=FAILURE_LOCATION_LIMIT)
                    if diagnostic_raw is not None:
                        diagnostic_value = _json_load(
                            diagnostic_raw, FAILURE_LOCATION_LIMIT,
                            label="cohort_failure_location")
                        cohort_failure_location = _validate_cohort_failure_location(
                            diagnostic_value, ready)
                        fail("cohort_failure_location", "cohort_reported_failure")
                except SupervisorError as error:
                    cohort_failure_location = {
                        "observed": (diagnostic_raw is not None
                                     or error.code == "untrusted_file"),
                        "validated": False,
                        "failure_type": error.code[:80],
                    }
                    fail("cohort_failure_location", error.code[:80])
                except BaseException:
                    cohort_failure_location = {
                        "observed": diagnostic_raw is not None,
                        "validated": False,
                        "failure_type": "read_failed",
                    }
                    fail("cohort_failure_location", "read_failed")
            try:
                while time.monotonic() < completion_deadline:
                    captured = _capture_operator_result(
                        local_cid, deadline=completion_deadline)
                    if captured is not None:
                        cohort_result, operator_exit = captured
                        current_profile = getattr(args, "profile", PROFILE_BASELINE)
                        if current_profile == PROFILE_C1B_RESTART:
                            if (restart_old_ready is None or restart_new_bundle is None
                                    or restart_receipt_digest is None
                                    or restart_old_held_status is None):
                                raise SupervisorError("restart", "generation_evidence_missing")
                            cohort_summary = _sanitize_restart_cohort_result(
                                cohort_result, old_ready=restart_old_ready,
                                new_ready=restart_new_bundle,
                                new_assignment_id=config["assignment_id"],
                                new_device_id=config["device_id"],
                                old_held_status=restart_old_held_status,
                                observed_requests=restart_observation_requests,
                                old_receipt_digest=restart_receipt_digest)
                        elif current_profile in OWNER_PROFILES:
                            if (owner_expected is None or owner_initial_serials is None
                                    or len(owner_state["handled_requests"]) != 2
                                    or len(owner_state["action_responses"]) != 2
                                    or len(owner_state["observation_acks"]) != 3
                                    or (current_profile == PROFILE_C1B_OWNER_REMOVE
                                        and owner_state["actual_remove_exit"] != {
                                            "process_state": "exited", "exit_code": 0})):
                                raise SupervisorError("owner_result", "controller_evidence_missing")
                            cohort_summary = _sanitize_owner_cohort_result(
                                cohort_result, expected=owner_expected, host_key=host_key,
                                config=config, expected_serials=owner_initial_serials,
                                handled_requests=owner_state["handled_requests"],
                                action_responses=owner_state["action_responses"],
                                observation_acks=owner_state["observation_acks"],
                                owner_state=owner_state)
                        else:
                            cohort_summary = _sanitize_cohort_result(
                                cohort_result, current_profile)
                        if current_profile in (PROFILE_C1B_CANCEL, PROFILE_C1B_PARTIAL,
                                               PROFILE_C1B_STEP_LOSS):
                            extension_key = {
                                PROFILE_C1B_PARTIAL: "partial_admission",
                                PROFILE_C1B_STEP_LOSS: "step_reply_loss",
                                PROFILE_C1B_CANCEL: "cancellation",
                            }[current_profile]
                            summary_extension = cohort_summary.get(extension_key)
                            if (type(summary_extension) is not dict
                                    or summary_extension.get("supervisor_arm_monotonic_ns")
                                       != cancellation_arm_ns
                                    or cancellation_armed_identity != (
                                        summary_extension.get("request_id"),
                                        summary_extension.get("session_id"))
                                    or type(cancellation_arm_ns) is not int
                                    or time.monotonic_ns() - cancellation_arm_ns
                                       > 40_000_000_000):
                                raise SupervisorError("cancellation", "arm_or_deadline_mismatch")
                        elif current_profile == PROFILE_C1B_CAPACITY:
                            summary_capacity = cohort_summary.get("capacity")
                            if (type(summary_capacity) is not dict
                                    or summary_capacity.get("supervisor_arm_monotonic_ns")
                                       != cancellation_arm_ns
                                    or summary_capacity.get("session_ids")
                                       != capacity_held_session_ids
                                    or cancellation_armed_identity != (
                                        summary_capacity.get("request_ids", [None])[0],
                                        summary_capacity.get("session_ids", [None])[0])
                                    or type(cancellation_arm_ns) is not int
                                    or time.monotonic_ns() - cancellation_arm_ns
                                       > 40_000_000_000):
                                raise SupervisorError("capacity", "arm_or_identity_mismatch")
                        local_state["exit_code"] = operator_exit["exit_code"]
                        records_captured = True
                        break
                    time.sleep(min(0.1, max(0.0,
                                            completion_deadline - time.monotonic())))
                if not records_captured:
                    fail("operator", "result_or_exit_record_missing")
            except BaseException as error:
                fail("operator_result", type(error).__name__[:80])

            if records_captured:
                # The protected result and exit are now in supervisor memory.
                # Release and all remote work use only the early cutoff, leaving
                # the original deadline's final five seconds for local stop/kill.
                try:
                    _write_local_handoff(
                        local_cid, "supervisor-release.json",
                        {"schema_version": 1, "event": "release"},
                        completion_deadline)
                except BaseException as error:
                    fail("operator_release", type(error).__name__[:80])
        else:
            # A discovered CID is only a candidate until the exact image/name/
            # role/owner inspection succeeds. Never read or release its tmpfs
            # evidence while ownership remains unverified.
            fail("local_start", "container_ownership_unverified")

        try:
            local_disposal_deadline = (arm_owner_disposal() if owner_profile
                                       else termination_deadline_once())
            local_evidence = _terminate_local_owned(
                local_cid, name=local_name, owner=owner, image=args.local_image,
                termination_deadline=local_disposal_deadline,
                observation_deadline=local_disposal_deadline)
            local_state.update(local_evidence)
            if (owner_profile and local_evidence.get("process_state") == "exited"):
                owner_disposal_exit_ns = time.monotonic_ns()
            if (getattr(args, "profile", PROFILE_BASELINE) in (
                    PROFILE_C1B_CANCEL, PROFILE_C1B_PARTIAL,
                    PROFILE_C1B_STEP_LOSS, PROFILE_C1B_CAPACITY)
                    and local_evidence.get("process_state") == "exited"):
                cancellation_local_exit_ns = time.monotonic_ns()
            if local_evidence.get("ownership_verified"):
                local_state["ownership_status"] = "verified"
            if local_state.get("exit_code") is None:
                local_state["exit_code"] = local_evidence.get("exit_code")
            if not local_evidence.get("cleanup_confirmed"):
                fail("local_cleanup", local_evidence.get("failure_type")
                     or "cleanup_unconfirmed")
            if not local_evidence.get("graceful_stop"):
                fail("local_cleanup", local_evidence.get("failure_type")
                     or "graceful_exit_unconfirmed")
            if local_evidence.get("exit_code") != 0:
                fail("local_cleanup", "operator_exit_nonzero")
        except BaseException as error:
            fail("local_cleanup", type(error).__name__[:80])

    if ssh is not None:
        if _pending_channel_operation_count():
            # Existing channel owners keep the transport alive until retirement.
            # Closing the client concurrently could stall or compete with them.
            fail("ssh_close", "operation_ownership_pending")
        else:
            try:
                _abort_channel(ssh)
                while _channel_operation_owned(ssh):
                    remaining = termination_deadline_once() - time.monotonic()
                    if remaining <= 0:
                        raise SupervisorError("ssh_close", "operation_ownership_pending")
                    time.sleep(min(0.01, remaining))
            except SupervisorError as error:
                fail("ssh_close", error.code)
            except Exception:
                fail("ssh_close", "close_failed")

    pending_transport_operations = list(_pending_channel_operation_evidence())
    if pending_transport_operations:
        fail("transport_cleanup", "operation_ownership_pending")

    if ready is not None and ready.get("run_id"):
        report_run_id = ready["run_id"]
    else:
        report_run_id = uuid.uuid4().hex
    baseline_status = (cohort_summary or {}).get("baseline_status")
    restart_extension = ((cohort_summary or {}).get("restart")
                         if getattr(args, "profile", PROFILE_BASELINE)
                         == PROFILE_C1B_RESTART else None)
    success = (not failures and baseline_status == "passed"
               and operator_exit is not None and operator_exit.get("exit_code") == 0
               and local_state.get("cleanup_confirmed") is True
               and local_state.get("graceful_stop") is True
               and remote_state.get("shutdown_confirmed") is True
               and remote_state.get("container_removed") is True
               and remote_state.get("private_files_removed") is True
               and remote_state.get("job_root_removed") is True
               and remote_state.get("cleanup_confirmed") is True)
    if owner_profile and not _owner_disposal_valid(
            local_state, owner_disposal_arm_ns, owner_disposal_exit_ns):
        fail("owner_disposal", "owned_operator_exit_not_within_40s")
        success = False
    if getattr(args, "profile", PROFILE_BASELINE) == PROFILE_C1B_RESTART:
        success = (success and type(restart_extension) is dict
                   and restart_extension.get("status") == "passed"
                   and type(restart_old_state) is dict
                   and restart_old_state.get("shutdown_confirmed") is True
                   and restart_old_state.get("container_removed") is True
                   and restart_old_state.get("private_files_removed") is True
                   and restart_old_state.get("job_root_removed") is True
                   and restart_old_state.get("cleanup_confirmed") is True
                   and type(restart_receipt_digest) is str
                   and restart_old_held_status is not None
                   and restart_new_ready is not None)
    report = {
        "schema_version": 1,
        "event": "secure_cohort_supervisor_result",
        "pending_transport_operations": pending_transport_operations,
        "status": "passed" if success else "failed",
        "run_id": report_run_id,
        "failure_stage": primary_failure["stage"] if primary_failure else None,
        "failure_type": primary_failure["type"] if primary_failure else None,
        "failures": failures[:32],
        "operator_exit_code": operator_exit.get("exit_code") if operator_exit else None,
        "cohort": cohort_summary,
        "cohort_failure_location": cohort_failure_location,
        "readiness_observed": readiness_observed,
        "stop_response_state": stop_response["stop_response"],
        "job_root_state": job_root_state,
        "local_operator": local_state,
        "remote_worker": {
            "container_id": remote_state.get("container_id"),
            "process_state": remote_state.get("process_state"),
            "ownership_status": remote_state.get("ownership_status", "unverified"),
            "exit_code": remote_state.get("exit_code"),
            "graceful_compute_shutdown": bool(
                remote_state.get("graceful_compute_shutdown")),
            "shutdown_confirmed": bool(remote_state.get("shutdown_confirmed")),
            "container_removed": bool(remote_state.get("container_removed")),
            "private_files_removed": bool(remote_state.get("private_files_removed")),
            "job_root_removed": bool(remote_state.get("job_root_removed")),
            "cleanup_confirmed": bool(remote_state.get("cleanup_confirmed")),
            "removal_evidence": remote_state.get("removal_evidence"),
            "failure_type": remote_state.get("failure_type"),
            "ssh_host_key_sha256": host_key,
        },
    }
    if getattr(args, "profile", PROFILE_BASELINE) == PROFILE_C1B_RESTART:
        report["restart_owner_evidence"] = {
            "old_remote_worker": {
                "container_id": (restart_old_state or {}).get("container_id"),
                "process_state": (restart_old_state or {}).get("process_state"),
                "ownership_status": (restart_old_state or {}).get("ownership_status"),
                "exit_code": (restart_old_state or {}).get("exit_code"),
                "shutdown_confirmed": bool((restart_old_state or {}).get("shutdown_confirmed")),
                "container_removed": bool((restart_old_state or {}).get("container_removed")),
                "private_files_removed": bool((restart_old_state or {}).get("private_files_removed")),
                "job_root_removed": bool((restart_old_state or {}).get("job_root_removed")),
                "cleanup_confirmed": bool((restart_old_state or {}).get("cleanup_confirmed")),
                "stop_arm_monotonic_ns": (restart_old_state or {}).get("stop_arm_monotonic_ns"),
                "failure_type": (restart_old_state or {}).get("failure_type"),
                "removal_evidence": (restart_old_state or {}).get("removal_evidence"),
            },
            "old_owner_receipt": restart_receipt,
            "old_owner_receipt_sha256": restart_receipt_digest,
            "new_snapshot_sha256": restart_new_snapshot_sha256,
            "new_ready_ack": restart_new_ready,
        }
    if owner_profile:
        report["owner_controller_evidence"] = {
            "profile": getattr(args, "profile", PROFILE_BASELINE),
            "publication_attempts": [dict(item) for item in owner_state["attempts"]],
            **_owner_cleanup_evidence(owner_state),
            "verifier_copy_receipt": owner_state["verifier_copy_receipt"],
            "sidecar_retention_receipt": owner_state["sidecar_retention_receipt"],
            "actual_remove_exit": owner_state["actual_remove_exit"],
            "local_disposal": {
                "arm_monotonic_ns": owner_disposal_arm_ns,
                "operator_exit_monotonic_ns": owner_disposal_exit_ns,
                "elapsed_ns": (owner_disposal_exit_ns - owner_disposal_arm_ns
                               if type(owner_disposal_exit_ns) is int
                               and type(owner_disposal_arm_ns) is int else None),
                "owned_operator_exit_confirmed": (
                    local_state.get("ownership_verified") is True
                    and local_state.get("process_state") == "exited"
                    and local_state.get("exit_code") == 0),
                "operator_cleanup_confirmed": local_state.get("cleanup_confirmed") is True,
                "graceful_stop_confirmed": local_state.get("graceful_stop") is True,
                "within_40_seconds": _owner_disposal_valid(
                    local_state, owner_disposal_arm_ns, owner_disposal_exit_ns),
                "operator_exit_code": local_state.get("exit_code"),
            },
            "sidecar_deletion_attempted": False,
        }
    if getattr(args, "profile", PROFILE_BASELINE) == PROFILE_C1B_CANCEL:
        elapsed_ns = (cancellation_local_exit_ns - cancellation_arm_ns
                      if type(cancellation_local_exit_ns) is int
                      and type(cancellation_arm_ns) is int else None)
        disposed = _cancellation_disposal_valid(
            local_state, cancellation_arm_ns, cancellation_local_exit_ns)
        if not disposed:
            fail("cancellation_disposal", "owned_operator_exit_not_within_40s")
            success = False
            report["status"] = "failed"
            report["failure_stage"] = primary_failure["stage"]
            report["failure_type"] = primary_failure["type"]
            report["failures"] = failures[:32]
        report["cancellation_disposal"] = {
            "arm_monotonic_ns": cancellation_arm_ns,
            "operator_exit_monotonic_ns": cancellation_local_exit_ns,
            "elapsed_ns": elapsed_ns,
            "owned_operator_exit_confirmed": local_state.get("process_state") == "exited",
            "within_40_seconds": bool(disposed),
            "operator_exit_code": local_state.get("exit_code"),
        }
    elif getattr(args, "profile", PROFILE_BASELINE) == PROFILE_C1B_PARTIAL:
        elapsed_ns = (cancellation_local_exit_ns - cancellation_arm_ns
                      if type(cancellation_local_exit_ns) is int
                      and type(cancellation_arm_ns) is int else None)
        disposed = _cancellation_disposal_valid(
            local_state, cancellation_arm_ns, cancellation_local_exit_ns)
        if not disposed:
            fail("partial_admission_disposal", "owned_operator_exit_not_within_40s")
            success = False
            report["status"] = "failed"
            report["failure_stage"] = primary_failure["stage"]
            report["failure_type"] = primary_failure["type"]
            report["failures"] = failures[:32]
        report["partial_admission_disposal"] = {
            "arm_monotonic_ns": cancellation_arm_ns,
            "operator_exit_monotonic_ns": cancellation_local_exit_ns,
            "elapsed_ns": elapsed_ns,
            "owned_operator_exit_confirmed": local_state.get("process_state") == "exited",
            "within_40_seconds": bool(disposed),
            "operator_exit_code": local_state.get("exit_code"),
        }
    elif getattr(args, "profile", PROFILE_BASELINE) == PROFILE_C1B_STEP_LOSS:
        elapsed_ns = (cancellation_local_exit_ns - cancellation_arm_ns
                      if type(cancellation_local_exit_ns) is int
                      and type(cancellation_arm_ns) is int else None)
        disposed = _cancellation_disposal_valid(
            local_state, cancellation_arm_ns, cancellation_local_exit_ns)
        if not disposed:
            fail("step_reply_loss_disposal", "owned_operator_exit_not_within_40s")
            success = False
            report["status"] = "failed"
            report["failure_stage"] = primary_failure["stage"]
            report["failure_type"] = primary_failure["type"]
            report["failures"] = failures[:32]
        report["step_reply_loss_disposal"] = {
            "arm_monotonic_ns": cancellation_arm_ns,
            "operator_exit_monotonic_ns": cancellation_local_exit_ns,
            "elapsed_ns": elapsed_ns,
            "owned_operator_exit_confirmed": local_state.get("process_state") == "exited",
            "within_40_seconds": bool(disposed),
            "operator_exit_code": local_state.get("exit_code"),
        }
    elif getattr(args, "profile", PROFILE_BASELINE) == PROFILE_C1B_CAPACITY:
        elapsed_ns = (cancellation_local_exit_ns - cancellation_arm_ns
                      if type(cancellation_local_exit_ns) is int
                      and type(cancellation_arm_ns) is int else None)
        disposed = _cancellation_disposal_valid(
            local_state, cancellation_arm_ns, cancellation_local_exit_ns)
        if not disposed:
            fail("capacity_disposal", "owned_operator_exit_not_within_40s")
            success = False
            report["status"] = "failed"
            report["failure_stage"] = primary_failure["stage"]
            report["failure_type"] = primary_failure["type"]
            report["failures"] = failures[:32]
        report["capacity_disposal"] = {
            "arm_monotonic_ns": cancellation_arm_ns,
            "operator_exit_monotonic_ns": cancellation_local_exit_ns,
            "elapsed_ns": elapsed_ns,
            "owned_operator_exit_confirmed": local_state.get("process_state") == "exited",
            "within_40_seconds": bool(disposed),
            "operator_exit_code": local_state.get("exit_code"),
        }
    try:
        _write_final_report(args, result_directory, report)
    except BaseException:
        # The command still fails if the operator-selected result destination
        # cannot preserve its report.  No secret or peer text is printed.
        print('{"status":"failed","failure_stage":"result_write"}')
        return 1
    return 0 if success else 1


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return run_supervisor(args)
    except SupervisorError as error:
        # This path precedes owned resources or result setup; output is bounded.
        print(json.dumps({"status": "failed", "failure_stage": error.stage,
                          "failure_type": error.code},
                         sort_keys=True, separators=(",", ":")))
        return 1
    except BaseException as error:
        print(json.dumps({"status": "failed", "failure_stage": "supervisor",
                          "failure_type": type(error).__name__[:80]},
                         sort_keys=True, separators=(",", ":")))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
