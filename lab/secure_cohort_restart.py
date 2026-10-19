"""Closed contracts for the bounded C1b same-CA remote restart experiment.

This module validates operator-owned restart envelopes and projects an already
prepared boot generation. It does not launch, stop, or claim ownership of processes.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import stat
from types import MappingProxyType
from typing import Mapping


PROFILE_C1B_RESTART = "c1b-restart-v1"
BASELINE_CASES = (
    (1, "greedy-one-token"),
    (2, "forced-length-1"),
    (3, "forced-length-128"),
    (4, "forced-length-1024"),
)
RESTART_OLD_SESSION_CASE = (5, "restart-old-session-held")
RESTART_STALE_BINDING_CASE = (6, "restart-new-boot-stale-binding-rejected")
RESTART_NEW_BASELINE_CASES = tuple(
    (sequence + 7, f"restart-new-{case_id}")
    for sequence, case_id in enumerate((case for _, case in BASELINE_CASES), start=0)
)
RESTART_CASES = (BASELINE_CASES + (RESTART_OLD_SESSION_CASE,
                                  RESTART_STALE_BINDING_CASE)
                 + RESTART_NEW_BASELINE_CASES)

REMOTE_OLD_RETIREMENT_SECONDS = 15
REMOTE_NEW_STARTUP_SECONDS = 60
LOCAL_COORDINATOR_CLEANUP_SECONDS = 40
RESTART_OVERALL_SECONDS = 300

RESTART_STOP_REQUEST_FILE = "restart-stop-request.json"
RESTART_STOP_RESPONSE_FILE = "restart-stop-response.json"
RESTART_BUNDLE_READY_FILE = "restart-bundle-ready.json"
RESTART_READY_ACK_FILE = "restart-ready-ack.json"
RESTART_GENERATION_ROOT_NAME = "g2"

STOP_ACK_FIELDS = frozenset({
    "schema_version", "event", "run_id", "old_nonce", "old_boot_id",
    "manifest_fingerprint", "endpoint", "ssh_host_key_sha256", "old_owner",
})
STOP_OWNER_FIELDS = frozenset({
    "container_id", "image_sha256", "exit_code", "ownership_verified",
    "process_state", "container_removed", "shutdown_confirmed",
    "private_files_removed", "job_root_removed", "stop_arm_monotonic_ns",
    "exit_monotonic_ns", "elapsed_ns",
})
RESTART_BUNDLE_FIELDS = frozenset({
    "schema_version", "event", "run_id", "old_nonce", "new_nonce",
    "old_boot_id", "new_boot_id", "old_snapshot_sha256",
    "new_snapshot_sha256", "old_owner_receipt_sha256", "bundle",
})
BUNDLE_READY_FIELDS = frozenset({
    "schema_version", "event", "run_id", "nonce", "bundle_path",
    "expected_boot_id", "manifest_fingerprint", "snapshot_sha256",
    "endpoint", "worker_name",
})
RESTART_READY_FIELDS = frozenset({
    "schema_version", "event", "run_id", "old_nonce", "new_nonce",
    "old_boot_id", "new_boot_id", "old_owner_receipt_sha256", "ready_ack",
})
READY_ACK_FIELDS = frozenset({
    "schema_version", "event", "run_id", "nonce", "boot_id",
    "manifest_fingerprint", "snapshot_sha256", "endpoint",
    "ssh_host_key_sha256", "remote_status_uid", "remote_status_mode",
    "remote_status_mtime_ns", "measurement_label", "remote_status",
})
_HEX32 = re.compile(r"[0-9a-f]{32}\Z", re.ASCII)
_HEX64 = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
MAX_STOP_RECEIPT_NS = 15_000_000_000
MAX_RESTART_CONTROL_BYTES = 65_536


class RestartContractError(ValueError):
    """A restart control record or borrowed generation view is invalid."""


def _exact_fields(value, expected: frozenset[str], label: str) -> None:
    if type(value) is not dict or set(value) != expected:
        raise RestartContractError(f"{label} has an unexpected closed schema")
    _canonical_bytes(value)


def _hex(value, pattern: re.Pattern, label: str) -> str:
    if type(value) is not str or pattern.fullmatch(value) is None:
        raise RestartContractError(f"{label} is malformed")
    return value


def _text(value, label: str, *, maximum: int = 256) -> str:
    if (type(value) is not str or not value or len(value) > maximum
            or any(ord(char) < 0x20 or ord(char) == 0x7f for char in value)):
        raise RestartContractError(f"{label} is malformed")
    return value


def _integer(value, label: str, *, minimum: int = 0,
             maximum: int = (1 << 63) - 1) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise RestartContractError(f"{label} is malformed")
    return value


def _sha256(value, label: str) -> str:
    return _hex(value, _HEX64, label)


def _expect_equal(value: dict, key: str, expected, label: str) -> None:
    actual = value.get(key)
    if type(actual) is not type(expected) or actual != expected:
        raise RestartContractError(f"{label} does not match the active restart")


def _canonical_bytes(value: dict) -> bytes:
    try:
        encoded = json.dumps(value, sort_keys=True, separators=(",", ":"),
                             ensure_ascii=True, allow_nan=False).encode("ascii")
    except (TypeError, ValueError, UnicodeError, RecursionError) as error:
        raise RestartContractError("restart receipt is not canonical JSON") from error
    if not 1 <= len(encoded) <= MAX_RESTART_CONTROL_BYTES:
        raise RestartContractError("restart control record exceeds its fixed byte bound")
    return encoded


def _canonical_sha256(value: dict) -> str:
    encoded = _canonical_bytes(value)
    return hashlib.sha256(encoded).hexdigest()


def validate_restart_stop_ack(payload: dict, *, run_id: str, old_nonce: str,
                              old_boot_id: str, manifest_fingerprint: str,
                              endpoint: str, ssh_host_key_sha256: str,
                              stop_arm_monotonic_ns: int) -> str:
    """Validate external old-owner evidence and return its exact-record digest."""
    _exact_fields(payload, STOP_ACK_FIELDS, "restart stop acknowledgement")
    _expect_equal(payload, "schema_version", 1, "stop schema version")
    _expect_equal(payload, "event", "restart_stopped", "stop event")
    _hex(run_id, _HEX32, "run ID")
    _hex(old_nonce, _HEX32, "old nonce")
    _hex(old_boot_id, _HEX32, "old boot ID")
    _expect_equal(payload, "run_id", run_id, "stop run ID")
    _expect_equal(payload, "old_nonce", old_nonce, "stop nonce")
    _expect_equal(payload, "old_boot_id", old_boot_id, "stop boot ID")
    _expect_equal(payload, "manifest_fingerprint",
                  _sha256(manifest_fingerprint, "manifest fingerprint"),
                  "stop manifest fingerprint")
    _expect_equal(payload, "endpoint", _text(endpoint, "endpoint"), "stop endpoint")
    _expect_equal(payload, "ssh_host_key_sha256",
                  _sha256(ssh_host_key_sha256, "SSH host key SHA-256"),
                  "stop SSH host key")

    owner = payload["old_owner"]
    _exact_fields(owner, STOP_OWNER_FIELDS, "old owner exit receipt")
    _hex(owner["container_id"], _HEX64, "container ID")
    _sha256(owner["image_sha256"], "container image SHA-256")
    _expect_equal(owner, "exit_code", 0, "old owner exit code")
    _expect_equal(owner, "ownership_verified", True, "ownership verification")
    _expect_equal(owner, "process_state", "exited", "old owner process state")
    for field in ("container_removed", "shutdown_confirmed",
                  "private_files_removed", "job_root_removed"):
        _expect_equal(owner, field, True, field)
    arm = _integer(stop_arm_monotonic_ns, "parent stop-arm monotonic time", minimum=1)
    _expect_equal(owner, "stop_arm_monotonic_ns", arm, "stop-arm monotonic time")
    exit_ns = _integer(owner["exit_monotonic_ns"], "exit monotonic time", minimum=arm)
    elapsed_ns = _integer(owner["elapsed_ns"], "retirement elapsed time",
                          maximum=MAX_STOP_RECEIPT_NS)
    if exit_ns - arm != elapsed_ns:
        raise RestartContractError("old owner elapsed time is inconsistent")
    return _canonical_sha256(payload)


def validate_restart_bundle_ready(payload: dict, *, run_id: str, old_nonce: str,
                                  new_nonce: str, old_boot_id: str, new_boot_id: str,
                                  old_snapshot_sha256: str, new_snapshot_sha256: str,
                                  old_owner_receipt_sha256: str,
                                  manifest_fingerprint: str, endpoint: str,
                                  bundle_validator) -> dict:
    """Validate restart envelope and its existing closed bundle-ready record.

    The caller still passes ``bundle`` to the existing protected bundle validator
    before publishing or consuming it; this function only checks its frozen shape
    and all values that the envelope can bind without filesystem authority.
    """
    _exact_fields(payload, RESTART_BUNDLE_FIELDS, "restart bundle-ready envelope")
    _expect_equal(payload, "schema_version", 1, "bundle envelope schema version")
    _expect_equal(payload, "event", "restart_bundle_ready", "bundle envelope event")
    _validate_restart_pair(run_id, old_nonce, new_nonce, old_boot_id, new_boot_id)
    for key, expected_value, label in (
            ("run_id", run_id, "bundle run ID"),
            ("old_nonce", old_nonce, "bundle old nonce"),
            ("new_nonce", new_nonce, "bundle new nonce"),
            ("old_boot_id", old_boot_id, "bundle old boot ID"),
            ("new_boot_id", new_boot_id, "bundle new boot ID"),
            ("old_snapshot_sha256", old_snapshot_sha256, "old snapshot digest"),
            ("new_snapshot_sha256", new_snapshot_sha256, "new snapshot digest"),
            ("old_owner_receipt_sha256", old_owner_receipt_sha256,
             "old owner receipt digest")):
        _expect_equal(payload, key, expected_value, label)
    _sha256(payload["old_snapshot_sha256"], "old snapshot digest")
    _sha256(payload["new_snapshot_sha256"], "new snapshot digest")
    if payload["old_snapshot_sha256"] == payload["new_snapshot_sha256"]:
        raise RestartContractError("restart snapshot digest did not change")
    _sha256(payload["old_owner_receipt_sha256"], "old owner receipt digest")

    bundle = payload["bundle"]
    if not callable(bundle_validator):
        raise RestartContractError("trusted local bundle validator is required")
    _exact_fields(bundle, BUNDLE_READY_FIELDS, "nested bundle-ready record")
    _expect_equal(bundle, "schema_version", 1, "nested bundle schema version")
    _expect_equal(bundle, "event", "bundle_ready", "nested bundle event")
    _expect_equal(bundle, "run_id", run_id, "nested bundle run ID")
    _expect_equal(bundle, "nonce", new_nonce, "nested bundle nonce")
    _expect_equal(bundle, "expected_boot_id", new_boot_id, "nested bundle boot ID")
    _expect_equal(bundle, "manifest_fingerprint",
                  _sha256(manifest_fingerprint, "manifest fingerprint"),
                  "nested bundle manifest fingerprint")
    _expect_equal(bundle, "snapshot_sha256", payload["new_snapshot_sha256"],
                  "nested bundle snapshot digest")
    _expect_equal(bundle, "endpoint", _text(endpoint, "endpoint"),
                  "nested bundle endpoint")
    _expect_equal(bundle, "worker_name", "worker-3", "nested bundle worker")
    bundle_path = _text(bundle["bundle_path"], "bundle path", maximum=4096)
    if "\\" in bundle_path or "\x00" in bundle_path or ".." in Path(bundle_path).parts:
        raise RestartContractError("nested bundle path is not canonical")
    # This callback is supplied by fixed local integration code and must invoke
    # the existing C0 bundle validator. No callback or code comes from a record.
    validated = bundle_validator(bundle, endpoint)
    if type(validated) is not dict or validated != bundle:
        raise RestartContractError("existing bundle validator returned another record")
    return validated


def validate_restart_ready_ack(payload: dict, *, run_id: str, old_nonce: str,
                               new_nonce: str, old_boot_id: str, new_boot_id: str,
                               old_owner_receipt_sha256: str,
                               expected_ssh_host_key_sha256: str, bundle: dict,
                               expected, ready_validator) -> str:
    """Validate the wrapper; caller delegates nested ready_ack to C0 validator."""
    _exact_fields(payload, RESTART_READY_FIELDS, "restart ready acknowledgement envelope")
    _expect_equal(payload, "schema_version", 1, "ready envelope schema version")
    _expect_equal(payload, "event", "restart_ready_ack", "ready envelope event")
    _validate_restart_pair(run_id, old_nonce, new_nonce, old_boot_id, new_boot_id)
    for key, expected_value, label in (
            ("run_id", run_id, "ready run ID"),
            ("old_nonce", old_nonce, "ready old nonce"),
            ("new_nonce", new_nonce, "ready new nonce"),
            ("old_boot_id", old_boot_id, "ready old boot ID"),
            ("new_boot_id", new_boot_id, "ready new boot ID"),
            ("old_owner_receipt_sha256", old_owner_receipt_sha256,
             "ready old-owner receipt digest")):
        _expect_equal(payload, key, expected_value, label)
    _sha256(payload["old_owner_receipt_sha256"], "old owner receipt digest")
    pinned_host_key = _sha256(expected_ssh_host_key_sha256,
                              "pinned SSH host-key SHA-256")
    if not callable(ready_validator):
        raise RestartContractError("trusted local ready validator is required")
    nested = payload["ready_ack"]
    _exact_fields(nested, READY_ACK_FIELDS, "nested C0 ready acknowledgement")
    _expect_equal(nested, "schema_version", 1, "nested ready schema version")
    _expect_equal(nested, "event", "ready_ack", "nested ready event")
    _expect_equal(nested, "run_id", run_id, "nested ready run ID")
    _expect_equal(nested, "nonce", new_nonce, "nested ready nonce")
    _expect_equal(nested, "boot_id", new_boot_id, "nested ready boot ID")
    _expect_equal(nested, "ssh_host_key_sha256", pinned_host_key,
                  "nested ready SSH host key")
    for key in ("manifest_fingerprint", "snapshot_sha256", "endpoint"):
        _expect_equal(nested, key, bundle[key], f"nested ready {key}")
    expected_fields = {
        "run_id": run_id, "nonce": new_nonce, "boot_id": new_boot_id,
        "manifest_fingerprint": bundle["manifest_fingerprint"],
        "snapshot_sha256": bundle["snapshot_sha256"],
        "endpoint": bundle["endpoint"],
    }
    for field, value in expected_fields.items():
        if type(getattr(expected, field, None)) is not type(value) \
                or getattr(expected, field, None) != value:
            raise RestartContractError(
                f"new protected ready expectation differs at {field}")
    # Only fixed local code supplies this validator and expectation; wire data
    # cannot select a callable. The existing C0 check is mandatory here.
    validated_host_key = ready_validator(nested, expected)
    if type(validated_host_key) is not str \
            or validated_host_key != nested["ssh_host_key_sha256"]:
        raise RestartContractError("existing ready validator returned another host key")
    return validated_host_key


def _validate_restart_pair(run_id: str, old_nonce: str, new_nonce: str,
                           old_boot_id: str, new_boot_id: str) -> None:
    _hex(run_id, _HEX32, "run ID")
    _hex(old_nonce, _HEX32, "old nonce")
    _hex(new_nonce, _HEX32, "new nonce")
    _hex(old_boot_id, _HEX32, "old boot ID")
    _hex(new_boot_id, _HEX32, "new boot ID")
    if len({old_nonce, new_nonce, old_boot_id, new_boot_id}) != 4:
        raise RestartContractError("restart nonce and boot ID values must be disjoint")


@dataclass(frozen=True, slots=True)
class BorrowedRestartGeneration:
    """Immutable projection over caller-owned root and prepared boot generation."""

    root: Path
    ip_sans_by_principal: Mapping[str, tuple[str, ...]]
    cohort_ca_pem: bytes
    snapshot_verification_key_pem: bytes
    model_id: str
    principals: Mapping[str, object]
    generation: object

    def new_store(self):
        """Create a store through the actual prepared generation implementation."""
        return self.generation.new_store()

    @property
    def boot_ids(self):
        return self.generation.boot_ids

    @property
    def signed_snapshot(self) -> bytes:
        return self.generation.signed_snapshot

    @property
    def revision(self) -> int:
        return self.generation.revision

    @property
    def policy_digest(self) -> str:
        return self.generation.policy_digest

    @property
    def snapshot_sha256(self) -> str:
        return self.generation.snapshot_sha256


def borrow_restart_generation(authority, generation, phase_root: str | os.PathLike) -> BorrowedRestartGeneration:
    """Project an allocated mode-0700 restart root without taking its ownership."""
    try:
        from lab.secure_cohort_boot import BootGeneration
    except ModuleNotFoundError as error:
        if error.name != "lab":
            raise
        # Some lab scripts put ``lab/`` itself on sys.path. Only use that
        # import form when the package root is genuinely absent.
        from secure_cohort_boot import BootGeneration
    if type(generation) is not BootGeneration:
        raise RestartContractError("borrowed view requires an actual prepared BootGeneration")
    root = Path(phase_root)
    authority_root = Path(getattr(authority, "root", ""))
    if (not root.is_absolute() or not authority_root.is_absolute()
            or root.parent != authority_root or root.name != RESTART_GENERATION_ROOT_NAME):
        raise RestartContractError("restart generation root is outside its fixed authority child")
    principals = getattr(generation, "principals", None)
    if (not isinstance(principals, Mapping)
            or set(principals) != {"coordinator", "consumer", "worker-1",
                                  "worker-2", "worker-3"}):
        raise RestartContractError("prepared generation principal set is incomplete")
    old_principals = getattr(authority, "principals", None)
    boot_ids = getattr(generation, "boot_ids", None)
    restarted = {"coordinator", "worker-1", "worker-2", "worker-3"}
    if (not isinstance(old_principals, Mapping)
            or set(old_principals) != set(principals)
            or not isinstance(boot_ids, Mapping) or set(boot_ids) != restarted):
        raise RestartContractError("old and prepared generation role sets differ")
    seen_boots = set()
    for name, old in old_principals.items():
        fresh = principals[name]
        for field in ("name", "account_id", "device_id", "role", "assignment_id",
                      "private_key_pem", "certificate_pem", "record"):
            if getattr(fresh, field, None) != getattr(old, field, None):
                raise RestartContractError("prepared generation changed a role identity")
        old_boot, fresh_boot = getattr(old, "boot_id", None), getattr(fresh, "boot_id", None)
        if name in restarted:
            if type(fresh_boot) is not str or fresh_boot == old_boot \
                    or boot_ids.get(name) != fresh_boot:
                raise RestartContractError("restarted role boot is not fresh and bound")
        elif fresh_boot != old_boot:
            raise RestartContractError("nonrestarted consumer boot changed")
        if (type(fresh_boot) is not str or _HEX32.fullmatch(fresh_boot) is None
                or fresh_boot in seen_boots):
            raise RestartContractError("prepared role boots are not unique")
        seen_boots.add(fresh_boot)
    old_boots = {getattr(principal, "boot_id", None)
                 for principal in old_principals.values()}
    if set(boot_ids.values()) & old_boots:
        raise RestartContractError("prepared restart boots overlap the old generation")
    if (getattr(generation, "ca_certificate_pem", None) != authority.cohort_ca_pem
            or getattr(generation, "verification_key_pem", None)
            != authority.snapshot_verification_key_pem
            or getattr(generation, "model_fingerprint", None) != authority.model_id):
        raise RestartContractError("prepared generation changed pinned authority material")
    ip_sans = getattr(authority, "ip_sans_by_principal", None)
    if not isinstance(ip_sans, Mapping) or set(ip_sans) != set(principals):
        raise RestartContractError("authority IP SAN pin set differs from prepared identities")
    copied_sans = {}
    for name, values in ip_sans.items():
        if type(values) not in (tuple, list) or not values or any(type(item) is not str for item in values):
            raise RestartContractError("authority IP SAN pins are malformed")
        copied_sans[name] = tuple(values)

    try:
        root_info = root.lstat()
        authority_info = authority_root.lstat()
    except OSError as error:
        raise RestartContractError("allocated restart roots are unavailable") from error
    if (not stat.S_ISDIR(root_info.st_mode) or stat.S_ISLNK(root_info.st_mode)
            or not stat.S_ISDIR(authority_info.st_mode)
            or stat.S_ISLNK(authority_info.st_mode)):
        raise RestartContractError("allocated restart roots must be real directories")
    if os.name == "posix" and (
            root_info.st_uid != os.geteuid() or authority_info.st_uid != os.geteuid()
            or stat.S_IMODE(root_info.st_mode) != 0o700
            or stat.S_IMODE(authority_info.st_mode) != 0o700):
        raise RestartContractError("allocated restart roots must be owner-only mode 0700")
    return BorrowedRestartGeneration(
        root=root,
        ip_sans_by_principal=MappingProxyType(copied_sans),
        cohort_ca_pem=authority.cohort_ca_pem,
        snapshot_verification_key_pem=authority.snapshot_verification_key_pem,
        model_id=authority.model_id,
        principals=principals,
        generation=generation)
