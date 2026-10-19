"""Bounded shared protocol records for C1b worker owner controls.

This module validates/builds local control records and fixed material archives.
It does not publish files, execute worker actions, access SSH/Docker, or own keys.
"""

from __future__ import annotations

from dataclasses import dataclass
import base64
import hashlib
import io
import json
import re
from urllib.parse import urlsplit

from lab.secure_worker_owner_control import OwnerCommand, OwnerControlError, parse_owner_command


PROFILE_C1B_OWNER_DRAIN = "c1b-owner-drain-v1"
PROFILE_C1B_OWNER_REMOVE = "c1b-owner-remove-v1"
OWNER_PROFILES = frozenset((PROFILE_C1B_OWNER_DRAIN, PROFILE_C1B_OWNER_REMOVE))
MAX_RECORD_BYTES = 16 * 1024
MAX_SNAPSHOT_BYTES = 64 * 1024
MAX_INTENT_BYTES = 16 * 1024
MAX_MATERIAL_BYTES = 160 * 1024
MAX_ARCHIVE_BYTES = 192 * 1024
MAX_NESTING = 8
MAX_I63 = (1 << 63) - 1
_HEX32 = re.compile(r"[0-9a-f]{32}\Z", re.ASCII)
_HEX64 = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
OWNER_MATERIAL_NAMES = (
    "install-snapshot.json", "remove-snapshot.json",
    "install-intent.json", "removal-intent.json",
)
_MATERIAL_LIMITS = {
    "install-snapshot.json": MAX_SNAPSHOT_BYTES,
    "remove-snapshot.json": MAX_SNAPSHOT_BYTES,
    "install-intent.json": MAX_INTENT_BYTES,
    "removal-intent.json": MAX_INTENT_BYTES,
}
_ACK_FIELDS = frozenset((
    "schema_version", "event", "run_id", "worker_boot_id", "sequence",
    "command_id", "command_sha256", "action", "accepted", "failure_code",
    "received_monotonic_ns", "completed_monotonic_ns", "phase",
    "applied_snapshot_sha256", "applied_revision",
))
_ACTION_REQUEST_FIELDS = frozenset((
    "schema_version", "event", "profile", "run_id", "nonce",
    "worker_boot_id", "manifest_fingerprint", "endpoint", "command_number",
    "command", "command_sha256",
))
_MATERIAL_WRAPPER_FIELDS = frozenset((
    "schema_version", "event", "profile", "run_id", "nonce",
    "worker_boot_id", "files",
))
_INTENT_DOMAIN = b"steamboat-owner-removal-intent-v1\x00"
_ACTION_RESPONSE_FIELDS = frozenset((
    "schema_version", "event", "profile", "run_id", "nonce", "worker_boot_id",
    "command_number", "command_sha256", "publication", "worker_ack",
    "protected_status",
))
_PROTECTED_STATUS_FIELDS = frozenset((
    "measurement_label", "ssh_host_key_sha256", "remote_mark_ns",
    "heartbeat_mtime_ns", "remote_status_uid", "remote_status_mode", "remote_status",
))
_OWNER_ACTIONS_FIELDS = frozenset((
    "profile", "status", "scope", "target_device_id", "worker_boot_id",
    "initial_snapshot_sha256", "initial_revision", "initial_local_serials",
    "old_local_shutdown", "direct_probe", "commands", "controls",
    "observations", "probe_cleanup",
))
_STEP_PROJECTION_FIELDS = frozenset((
    "sequence", "start_position", "token_count", "end_position", "next_sequence",
    "tensor_shape", "dtype", "byte_count", "finite",
))
_BINDING_FIELDS = frozenset((
    "method", "operation_id", "request_id", "session_id", "route_id",
    "route_epoch", "attempt", "worker_boot_id",
))
_DENIAL_FIELDS = frozenset((
    "method", "binding", "native_status", "returned_response", "dispatch_count",
    "policy_sha256",
))


class OwnerProtocolError(ValueError):
    """A C1b owner-control record is outside its frozen bounded schema."""


def _need(condition, message):
    if not condition:
        raise OwnerProtocolError(message)


def _exact_fields(value, fields, label):
    _need(type(value) is dict and set(value) == set(fields),
          f"{label} has unknown or missing fields")


def _int(value, *, minimum, maximum, label):
    _need(type(value) is int and minimum <= value <= maximum,
          f"{label} is outside its exact integer bound")
    return value


def _text(value, *, maximum, label):
    _need(type(value) is str and 1 <= len(value) <= maximum
          and not any(ord(char) < 0x20 or ord(char) > 0x7e for char in value),
          f"{label} is not bounded printable ASCII")
    return value


def _hex(value, pattern, label):
    _need(type(value) is str and pattern.fullmatch(value) is not None,
          f"{label} is not lowercase hexadecimal")
    return value


def _endpoint(value):
    _text(value, maximum=255, label="endpoint")
    _need(not any(char.isspace() for char in value) and "/" not in value
          and "@" not in value and "?" not in value and "#" not in value,
          "endpoint contains URI or whitespace syntax")
    try:
        parsed = urlsplit("//" + value)
        port = parsed.port
    except ValueError as error:
        raise OwnerProtocolError("endpoint is malformed") from error
    _need(parsed.hostname is not None and port is not None and 1 <= port <= 65535
          and parsed.path == "" and parsed.query == "" and parsed.fragment == "",
          "endpoint must be a host and bounded port")
    return value


def _depth(value, current=1):
    _need(current <= MAX_NESTING, "owner JSON exceeds its nesting bound")
    if type(value) is dict:
        _need(all(type(key) is str for key in value),
              "owner JSON object keys must be text")
        values = value.values()
    elif type(value) is list:
        values = value
    else:
        _need(type(value) in (str, int, bool) or value is None,
              "owner JSON contains an unsupported value type")
        return
    for child in values:
        _depth(child, current + 1)


def _canonical_bytes(value, *, maximum=MAX_RECORD_BYTES):
    _depth(value)
    try:
        encoded = json.dumps(value, sort_keys=True, separators=(",", ":"),
                             ensure_ascii=True, allow_nan=False).encode("ascii")
    except (TypeError, ValueError, UnicodeError, RecursionError) as error:
        raise OwnerProtocolError("owner record is not canonical JSON") from error
    _need(1 <= len(encoded) <= maximum, "canonical owner record exceeds its byte bound")
    return encoded


def _reject_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise OwnerProtocolError("owner JSON contains duplicate fields")
        result[key] = value
    return result


def _reject_constant(_value):
    raise OwnerProtocolError("owner JSON contains a nonfinite number")


def _reject_float(_value):
    raise OwnerProtocolError("owner JSON does not allow floating-point values")


def _owner_float(value):
    try:
        parsed = float(value)
    except (ValueError, OverflowError) as error:
        raise OwnerProtocolError("owner JSON floating-point value is malformed") from error
    _need(__import__("math").isfinite(parsed), "owner JSON contains a nonfinite number")
    return parsed


def _owner_depth(value, path=(), current=1):
    _need(current <= MAX_NESTING, "owner JSON exceeds its nesting bound")
    if type(value) is dict:
        _need(all(type(key) is str for key in value), "owner JSON keys must be text")
        for key, child in value.items():
            _owner_depth(child, path + (key,), current + 1)
        return
    if type(value) is list:
        for index, child in enumerate(value):
            _owner_depth(child, path + (index,), current + 1)
        return
    if type(value) is float:
        status_index = next((index for index, part in enumerate(path)
                             if part == "remote_status"), None)
        suffix = path[status_index:] if status_index is not None else ()
        allowed = (suffix == ("remote_status", "clock_uncertainty_seconds")
                   or (len(suffix) == 3 and suffix[0] == "remote_status"
                       and suffix[1] == "owner_lifecycle"
                       and suffix[2] in ("drain_started_monotonic", "drain_deadline_monotonic")))
        _need(allowed and __import__("math").isfinite(value),
              "owner JSON float is outside its bounded status fields")
        return
    _need(type(value) in (str, int, bool) or value is None,
          "owner JSON contains an unsupported value")


def _owner_record(value, *, maximum, label):
    if type(value) is bytes:
        _need(1 <= len(value) <= maximum, f"{label} is empty or oversized")
        try:
            parsed = json.loads(value.decode("utf-8", errors="strict"),
                                object_pairs_hook=_reject_pairs,
                                parse_constant=_reject_constant, parse_float=_owner_float)
        except OwnerProtocolError:
            raise
        except (UnicodeError, ValueError, TypeError, RecursionError) as error:
            raise OwnerProtocolError(f"{label} is malformed") from error
        _owner_depth(parsed)
        _need(value == _canonical_bytes_owner(parsed, maximum=maximum),
              f"{label} bytes are not canonical JSON")
        return parsed
    _need(type(value) is dict, f"{label} must be a JSON object")
    _owner_depth(value)
    _need(len(_canonical_bytes_owner(value, maximum=maximum)) <= maximum,
          f"{label} exceeds its byte bound")
    return value


def _canonical_bytes_owner(value, *, maximum):
    try:
        encoded = json.dumps(value, sort_keys=True, separators=(",", ":"),
                             ensure_ascii=True, allow_nan=False).encode("ascii")
    except (TypeError, ValueError, UnicodeError, RecursionError) as error:
        raise OwnerProtocolError("owner record is not canonical JSON") from error
    _need(1 <= len(encoded) <= maximum, "canonical owner record exceeds its byte bound")
    return encoded


def _strict_loads(raw, *, maximum):
    _need(type(raw) is bytes and 1 <= len(raw) <= maximum,
          "owner JSON input is empty or oversized")
    try:
        value = json.loads(raw.decode("utf-8", errors="strict"),
                           object_pairs_hook=_reject_pairs,
                           parse_constant=_reject_constant,
                           parse_float=_reject_float)
    except OwnerProtocolError:
        raise
    except (UnicodeError, ValueError, TypeError, RecursionError) as error:
        raise OwnerProtocolError("owner JSON is malformed") from error
    _depth(value)
    return value


def _record_value(value, *, maximum, label):
    if type(value) is bytes:
        parsed = _strict_loads(value, maximum=maximum)
        _need(value == _canonical_bytes(parsed, maximum=maximum),
              f"{label} bytes are not canonical JSON")
        return parsed
    _need(type(value) is dict, f"{label} must be a JSON object")
    return value


def _profile(profile):
    _need(type(profile) is str and profile in OWNER_PROFILES,
          "owner profile is unsupported")
    return profile


@dataclass(frozen=True, slots=True)
class OwnerExpectation:
    profile: str
    run_id: str
    nonce: str
    worker_boot_id: str
    manifest_fingerprint: str
    endpoint: str
    initial_snapshot_sha256: str
    initial_revision: int

    def __post_init__(self):
        _profile(self.profile)
        _hex(self.run_id, _HEX32, "run ID")
        _hex(self.nonce, _HEX32, "nonce")
        _hex(self.worker_boot_id, _HEX32, "worker boot ID")
        _hex(self.manifest_fingerprint, _HEX64, "manifest fingerprint")
        _endpoint(self.endpoint)
        _hex(self.initial_snapshot_sha256, _HEX64, "initial snapshot digest")
        _int(self.initial_revision, minimum=1, maximum=MAX_I63 - 2,
             label="initial snapshot revision")


def owner_profile_steps(profile):
    """Return the exact seven observation sequence/case pairs for one owner profile."""
    profile = _profile(profile)
    cases = [
        "greedy-one-token", "forced-length-1", "forced-length-128",
        "forced-length-1024",
    ]
    if profile == PROFILE_C1B_OWNER_DRAIN:
        cases.extend(("owner-drain-held", "owner-drain-controls", "owner-drain-paused"))
    else:
        cases.extend(("owner-remove-held", "owner-remove-revoked", "owner-remove-final"))
    return tuple(enumerate(cases, start=1))


def _command_action(profile, sequence):
    _profile(profile)
    _int(sequence, minimum=1, maximum=2, label="owner command sequence")
    if profile == PROFILE_C1B_OWNER_DRAIN:
        return "drain", (30 if sequence == 1 else 300)
    return ("install_snapshot" if sequence == 1 else "remove"), 0


def _command_dict(value, expected):
    _exact_fields(value, {
        "schema_version", "event", "run_id", "worker_boot_id", "sequence",
        "command_id", "action", "drain_seconds", "snapshot_sha256",
        "snapshot_revision",
    }, "owner command")
    encoded = _canonical_bytes(value)
    try:
        command = parse_owner_command(
            encoded, expected_run_id=expected.run_id,
            expected_worker_boot_id=expected.worker_boot_id)
    except OwnerControlError as error:
        raise OwnerProtocolError("command differs from the actual owner inbox parser") from error
    action, drain_seconds = _command_action(expected.profile, command.sequence)
    _need(command.action == action and command.drain_seconds == drain_seconds,
          "command action or drain duration differs from the frozen profile order")
    if action == "drain":
        _need(command.snapshot_sha256 == "" and command.snapshot_revision == 0,
              "drain command unexpectedly changes snapshot policy")
    else:
        expected_revision = expected.initial_revision + command.sequence
        _need(command.snapshot_revision == expected_revision
              and command.snapshot_sha256 != "",
              "snapshot command is not the required strictly ordered revision")
    return command


def _command_document(command):
    _need(type(command) is OwnerCommand, "expected an actual inbox command object")
    return {
        "schema_version": 1, "event": "owner_command",
        "run_id": command.run_id, "worker_boot_id": command.worker_boot_id,
        "sequence": command.sequence, "command_id": command.command_id,
        "action": command.action, "drain_seconds": command.drain_seconds,
        "snapshot_sha256": command.snapshot_sha256,
        "snapshot_revision": command.snapshot_revision,
    }


def _revalidate_command_object(command, expected=None):
    document = _command_document(command)
    encoded = _canonical_bytes(document)
    try:
        parsed = parse_owner_command(
            encoded, expected_run_id=command.run_id,
            expected_worker_boot_id=command.worker_boot_id)
    except OwnerControlError as error:
        raise OwnerProtocolError("command object fails the actual inbox parser") from error
    _need(parsed == command, "command object digest differs from actual canonical parsing")
    if expected is not None:
        _command_dict(document, expected)
    return parsed


def build_owner_command(expected, sequence, command_id, *,
                        snapshot_sha256="", snapshot_revision=0):
    """Build one exact command document accepted by the worker's actual parser."""
    _need(type(expected) is OwnerExpectation, "owner command requires validated expectation")
    action, drain_seconds = _command_action(expected.profile, sequence)
    _hex(command_id, _HEX32, "command ID")
    if action == "drain":
        _need(snapshot_sha256 == "" and type(snapshot_revision) is int
              and snapshot_revision == 0,
              "drain command must not select a snapshot")
    else:
        _hex(snapshot_sha256, _HEX64, "snapshot digest")
        _need(type(snapshot_revision) is int
              and snapshot_revision == expected.initial_revision + sequence,
              "snapshot command revision differs from the fixed profile sequence")
    document = {
        "schema_version": 1, "event": "owner_command",
        "run_id": expected.run_id, "worker_boot_id": expected.worker_boot_id,
        "sequence": sequence, "command_id": command_id, "action": action,
        "drain_seconds": drain_seconds, "snapshot_sha256": snapshot_sha256,
        "snapshot_revision": snapshot_revision,
    }
    command = _command_dict(document, expected)
    _need(command.sequence == sequence, "command sequence changed during validation")
    return document


def build_owner_action_request(expected, command_number, command):
    """Build one fixed producer-to-controller action request."""
    _need(type(expected) is OwnerExpectation, "action request requires validated expectation")
    parsed = _command_dict(command, expected)
    _need(type(command_number) is int and command_number == parsed.sequence
          and command_number in (1, 2),
          "action request command number must match its fixed command sequence")
    return {
        "schema_version": 1, "event": "owner_action_request",
        "profile": expected.profile, "run_id": expected.run_id,
        "nonce": expected.nonce, "worker_boot_id": expected.worker_boot_id,
        "manifest_fingerprint": expected.manifest_fingerprint,
        "endpoint": expected.endpoint, "command_number": command_number,
        "command": command,
        "command_sha256": parsed.command_sha256,
    }


def validate_owner_action_request(value, expected):
    """Validate a closed action request and return its exact inbox command object."""
    _need(type(expected) is OwnerExpectation, "action request requires validated expectation")
    value = _record_value(value, maximum=MAX_RECORD_BYTES, label="action request")
    _exact_fields(value, _ACTION_REQUEST_FIELDS, "owner action request")
    _need(value["schema_version"] == 1 and type(value["schema_version"]) is int
          and value["event"] == "owner_action_request", "action request version/event is invalid")
    for key in ("profile", "run_id", "nonce", "worker_boot_id",
                "manifest_fingerprint", "endpoint"):
        _need(value[key] == getattr(expected, key),
              f"action request {key} differs from the trusted expectation")
    command = _command_dict(value["command"], expected)
    _need(type(value["command_number"]) is int
          and value["command_number"] == command.sequence,
          "action request number differs from command sequence")
    _hex(value["command_sha256"], _HEX64, "action command digest")
    _need(value["command_sha256"] == command.command_sha256,
          "action request digest differs from the actual parser")
    _canonical_bytes(value)
    return command


def validate_owner_command_ack(value, expected_command, expected):
    """Validate the exact accepted inbox ACK against the claimed immutable command."""
    _need(type(expected_command) is OwnerCommand,
          "owner ACK requires the actual claimed inbox command")
    _need(type(expected) is OwnerExpectation,
          "owner ACK requires its trusted policy and profile expectation")
    _revalidate_command_object(expected_command, expected)
    _need(expected_command.run_id == expected.run_id
          and expected_command.worker_boot_id == expected.worker_boot_id,
          "owner ACK command belongs to another expected generation")
    value = _record_value(value, maximum=MAX_RECORD_BYTES, label="owner acknowledgement")
    _need(_command_action(expected.profile, expected_command.sequence)[0]
          == expected_command.action,
          "owner ACK command differs from its frozen profile position")
    _exact_fields(value, _ACK_FIELDS, "owner command acknowledgement")
    _need(type(value["schema_version"]) is int and value["schema_version"] == 1
          and value["event"] == "owner_control_ack", "owner ACK version/event is invalid")
    for key in ("run_id", "worker_boot_id", "sequence", "command_id",
                "command_sha256", "action"):
        _need(value[key] == getattr(expected_command, key),
              f"owner ACK {key} differs from its immutable command")
    _need(type(value["sequence"]) is int and type(value["accepted"]) is bool
          and value["accepted"] is True and value["failure_code"] is None,
          "owner ACK is not an exact accepted result")
    _hex(value["command_sha256"], _HEX64, "owner ACK command digest")
    received = _int(value["received_monotonic_ns"], minimum=1, maximum=MAX_I63,
                     label="ACK receive monotonic time")
    completed = _int(value["completed_monotonic_ns"], minimum=1, maximum=MAX_I63,
                      label="ACK completion monotonic time")
    _need(completed >= received, "owner ACK completion precedes its receipt")
    phase = value["phase"]
    if expected_command.action == "remove":
        _need(phase == "removing", "remove ACK phase is not removing")
    else:
        _need(phase in ("draining", "paused"),
              "accepted drain/revocation ACK phase is outside its fixed set")
    if expected_command.action == "drain":
        digest, revision = value["applied_snapshot_sha256"], value["applied_revision"]
        _hex(digest, _HEX64, "drain ACK current policy digest")
        _int(revision, minimum=1, maximum=MAX_I63, label="drain ACK current policy revision")
        _need(digest == expected.initial_snapshot_sha256
              and revision == expected.initial_revision,
              "drain ACK does not report the initially installed policy")
    else:
        digest = _hex(value["applied_snapshot_sha256"], _HEX64,
                      "snapshot ACK applied digest")
        revision = _int(value["applied_revision"], minimum=1, maximum=MAX_I63,
                        label="snapshot ACK applied revision")
        _need(digest == expected_command.snapshot_sha256
              and revision == expected_command.snapshot_revision,
              "snapshot ACK does not report the command's exact policy")
    _canonical_bytes(value)
    return value


def _intent_document(command):
    _need(type(command) is OwnerCommand and command.action in ("install_snapshot", "remove"),
          "signed removal intent requires an actual install/remove command")
    _revalidate_command_object(command)
    return {
        "schema_version": 1, "event": "owner_removal_intent",
        "run_id": command.run_id, "worker_boot_id": command.worker_boot_id,
        "command_id": command.command_id, "command_sha256": command.command_sha256,
        "snapshot_sha256": command.snapshot_sha256,
        "snapshot_revision": command.snapshot_revision, "roles_off": True,
    }


def build_signed_owner_intent(command, signer):
    """Sign one command-bound P-256 intent with an existing local operator key."""
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.serialization import load_pem_private_key
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature

    intent = _intent_document(command)
    if type(signer) is bytes:
        try:
            key = load_pem_private_key(signer, password=None)
        except (TypeError, ValueError) as error:
            raise OwnerProtocolError("operator signer PEM is invalid") from error
    else:
        key = signer
    _need(isinstance(key, ec.EllipticCurvePrivateKey)
          and isinstance(key.curve, ec.SECP256R1),
          "owner intent signer must be an existing P-256 private key")
    canonical_intent = _canonical_bytes(intent, maximum=MAX_INTENT_BYTES)
    signature = key.sign(_INTENT_DOMAIN + canonical_intent, ec.ECDSA(hashes.SHA256()))
    _need(8 <= len(signature) <= 80, "owner intent signature exceeds its DER bound")
    try:
        r_value, s_value = decode_dss_signature(signature)
    except ValueError as error:
        raise OwnerProtocolError("owner intent signer produced invalid DER") from error
    _need(encode_dss_signature(r_value, s_value) == signature,
          "owner intent signature DER is not canonical")
    envelope = {
        "schema_version": 1, "event": "signed_owner_removal_intent",
        "intent": intent, "signature": base64.b64encode(signature).decode("ascii"),
    }
    return _canonical_bytes(envelope, maximum=MAX_INTENT_BYTES)


def validate_owner_materials_ready(value, expected):
    """Validate the fixed remove-profile material wrapper without accepting paths."""
    _need(type(expected) is OwnerExpectation
          and expected.profile == PROFILE_C1B_OWNER_REMOVE,
          "owner material wrapper is allowed only for the remove profile")
    value = _record_value(value, maximum=MAX_RECORD_BYTES, label="owner materials wrapper")
    _exact_fields(value, _MATERIAL_WRAPPER_FIELDS, "owner materials wrapper")
    _need(type(value["schema_version"]) is int and value["schema_version"] == 1
          and value["event"] == "owner_materials_ready",
          "owner materials wrapper version/event is invalid")
    for key in ("profile", "run_id", "nonce", "worker_boot_id"):
        _need(value[key] == getattr(expected, key),
              f"owner materials wrapper {key} differs from the expectation")
    files = value["files"]
    _exact_fields(files, OWNER_MATERIAL_NAMES, "owner material file map")
    total = 0
    for name in OWNER_MATERIAL_NAMES:
        row = files[name]
        _exact_fields(row, {"size", "sha256"}, f"{name} metadata")
        size = _int(row["size"], minimum=1, maximum=_MATERIAL_LIMITS[name],
                    label=f"{name} size")
        _hex(row["sha256"], _HEX64, f"{name} digest")
        total += size
    _need(total <= MAX_MATERIAL_BYTES, "owner material payload exceeds its aggregate bound")
    _canonical_bytes(value)
    return value


def _tar_octal(field, label):
    raw = field.rstrip(b"\x00 ").lstrip(b" ")
    _need(bool(raw) and all(byte in b"01234567" for byte in raw),
          f"owner material TAR {label} is not strict octal")
    return int(raw, 8)


def validate_owner_material_archive(encoded, wrapper, expected):
    """Validate four fixed USTAR regular files and return their exact bytes by name."""
    wrapper = validate_owner_materials_ready(wrapper, expected)
    _need(type(encoded) is bytes and 1 <= len(encoded) <= MAX_ARCHIVE_BYTES
          and len(encoded) % 512 == 0,
          "owner materials TAR is empty, oversized, or not block aligned")
    metadata = wrapper["files"]
    result = {}
    offset = 0
    names = []
    total = 0
    for expected_name in OWNER_MATERIAL_NAMES:
        _need(offset + 512 <= len(encoded), "owner materials TAR header is truncated")
        header = encoded[offset:offset + 512]
        _need(header[257:263] == b"ustar\x00" and header[263:265] == b"00",
              "owner materials TAR must use strict USTAR headers")
        stored_checksum = _tar_octal(header[148:156], "checksum")
        calculated_checksum = sum(header[:148]) + (8 * ord(" ")) + sum(header[156:])
        _need(stored_checksum == calculated_checksum,
              "owner materials TAR header checksum is invalid")
        raw_name = header[0:100].split(b"\x00", 1)[0]
        _need(raw_name and b"/" not in raw_name and b"\\" not in raw_name
              and header[0:100] == raw_name + b"\x00" * (100 - len(raw_name))
              and header[345:500].strip(b"\x00 ") == b"",
              "owner materials TAR name or prefix is unsafe")
        try:
            name = raw_name.decode("ascii", errors="strict")
        except UnicodeError as error:
            raise OwnerProtocolError("owner materials TAR filename is not ASCII") from error
        _need(name == expected_name and name not in names,
              "owner materials TAR has an extra, missing, or reordered name")
        names.append(name)
        _need(header[156:157] in (b"\x00", b"0")
              and header[157:257].strip(b"\x00") == b""
              and header[265:329].strip(b"\x00 ") == b""
              and header[329:345].strip(b"\x00 ") == b"",
              "owner materials TAR contains a link or non-regular metadata")
        mode = _tar_octal(header[100:108], "mode")
        uid = _tar_octal(header[108:116], "uid")
        gid = _tar_octal(header[116:124], "gid")
        size = _tar_octal(header[124:136], "size")
        _need(mode == 0o600 and uid == 1000 and gid == 1000,
              "owner materials TAR owner or mode is not the fixed protected value")
        _need(size == metadata[name]["size"] and 1 <= size <= _MATERIAL_LIMITS[name],
              "owner materials TAR size differs from its wrapper")
        data_start = offset + 512
        data_end = data_start + size
        padded_end = data_start + ((size + 511) // 512) * 512
        _need(padded_end <= len(encoded), "owner material payload is truncated")
        raw = encoded[data_start:data_end]
        _need(encoded[data_end:padded_end] == b"\x00" * (padded_end - data_end),
              "owner materials TAR payload padding is not zero")
        _need(hashlib.sha256(raw).hexdigest() == metadata[name]["sha256"],
              "owner material bytes differ from their wrapper digest")
        result[name] = raw
        total += size
        offset = padded_end
    _need(total <= MAX_MATERIAL_BYTES and offset + 1024 <= len(encoded)
          and encoded[offset:offset + 1024] == b"\x00" * 1024
          and encoded[offset:] == b"\x00" * (len(encoded) - offset),
          "owner materials TAR has an invalid terminator or trailing entries")
    return result


def _status_projection(remote_status):
    _need(type(remote_status) is dict, "protected owner status is not an object")
    base_fields = {
        "schema_version", "event", "phase", "worker_name", "account_id", "device_id",
        "boot_id", "assignment_id", "model_id", "model_revision", "manifest_fingerprint",
        "listen_endpoint", "layer_range", "clock_uncertainty_seconds", "torch_threads",
        "handler", "bridge", "transport", "external_supervision", "shutdown",
        "report_state", "resource_state",
    }
    _exact_fields(remote_status, base_fields | {"owner_lifecycle", "owner_control"},
                  "owner worker status")
    return {key: remote_status[key] for key in base_fields}


def _config_status_identity(expected, config):
    _need(type(config) is dict, "expected worker configuration must be a validated object")
    required = ("account_id", "device_id", "boot_id", "assignment_id", "model_id",
                "model_revision", "manifest_fingerprint", "listen_ip", "listen_port",
                "clock_uncertainty_seconds")
    _need(all(key in config for key in required), "worker configuration is incomplete")
    _need(config["boot_id"] == expected.worker_boot_id
          and config["manifest_fingerprint"] == expected.manifest_fingerprint
          and f"{config['listen_ip']}:{config['listen_port']}" == expected.endpoint,
          "worker configuration identity differs from trusted expectation")
    _need(type(config["clock_uncertainty_seconds"]) is float
          and __import__("math").isfinite(config["clock_uncertainty_seconds"])
          and 0 < config["clock_uncertainty_seconds"] <= 30,
          "worker configuration clock uncertainty is invalid")
    return config


def _validate_owner_status(status, expected, config, *, command=None, observation=False):
    import math
    from lab import secure_cohort
    config = _config_status_identity(expected, config)
    # Protected status is independently bounded even when it sits inside a
    # larger owner action/result envelope.
    _canonical_bytes_owner(status, maximum=4096)
    _status_projection(status)
    phase = status["owner_lifecycle"].get("phase") if type(status["owner_lifecycle"]) is dict else None
    terminal = status["event"] == "final"
    base = _status_projection(status)
    remote_expected = secure_cohort.RemoteExpectation(
        expected.run_id, expected.nonce, "worker-3", config["account_id"], config["device_id"],
        expected.worker_boot_id, config["assignment_id"], config["model_id"],
        config["model_revision"], config["manifest_fingerprint"],
        expected.initial_snapshot_sha256, f"{config['listen_ip']}:{config['listen_port']}",
        float(config["clock_uncertainty_seconds"]), (6, 8))
    try:
        if terminal:
            secure_cohort._validate_final_worker_status(base, remote_expected)
        else:
            if observation and command is not None:
                allowed_events = ("heartbeat", "status", "final")
            elif observation:
                allowed_events = ("heartbeat",)
            elif command is not None:
                allowed_events = (("status", "final")
                                  if expected.profile == PROFILE_C1B_OWNER_REMOVE
                                  and command.get("sequence") == 2
                                  else ("heartbeat",))
            else:
                allowed_events = ("ready", "heartbeat")
            _need(status["event"] in allowed_events,
                  "owner status event is invalid for this command boundary")
            _need(phase in ("ready", "draining", "paused"), "owner lifecycle phase is invalid")
            if command is not None:
                _need(phase in ("draining", "paused"),
                      "command-bound owner status lacks the admission cutoff")
                _need(status["bridge"].get("ready") is False,
                      "command-bound owner status still admits new sessions")
                expected_outer_phase = "draining" if status["event"] == "status" else phase
                _need(base["phase"] == expected_outer_phase,
                      "command-bound owner status phase disagrees with lifecycle")
            else:
                _need(base["phase"] == phase,
                      "owner status phase disagrees with lifecycle")
            # Reuse the base validator for identity, nested schemas and resource
            # accounting. Its ordinary READY bits are adapted here and checked below.
            validation_view = dict(base)
            validation_view["phase"] = "ready"
            validation_view["bridge"] = dict(base["bridge"])
            validation_view["bridge"]["ready"] = True
            session_ids = status.get("handler", {}).get("active_session_ids", [])
            anchor = session_ids[0] if type(session_ids) is list and len(session_ids) == 1 else None
            secure_cohort._validate_worker_status(
                validation_view, remote_expected, event=status["event"],
                expected_session_id=anchor)
            if phase == "ready":
                _need(status["bridge"]["ready"] is True,
                      "ready owner lifecycle has a non-ready bridge")
            else:
                _need(status["bridge"]["ready"] is False,
                      "draining owner lifecycle still reports bridge ready")
    except secure_cohort.CohortError as error:
        raise OwnerProtocolError("owner raw status fails the established worker status schema") from error

    limits = status["handler"]["limits"]
    expected_limits = {"max_sessions": 8, "max_tombstones": 4096,
                       "max_stage_queue": 8, "max_positions": 1152,
                       "max_cache_positions": 12288, "max_cache_bytes": 16777216,
                       "max_message_bytes": 1048576}
    _need(all(type(limits.get(key)) is int and limits[key] == amount
              for key, amount in expected_limits.items()),
          "owner worker limits differ from the fixed runtime profile")
    for key in ("tombstones", "retained_entries"):
        _need(type(status["handler"][key]) is int and 0 <= status["handler"][key] <= 4096,
              f"owner handler {key} exceeds its bounded metadata limit")
    handler, bridge = status["handler"], status["bridge"]
    _need(type(handler["requires_restart"]) is bool and type(handler["stopping"]) is bool
          and type(bridge["requires_restart"]) is bool
          and type(bridge["unavailable"]) is bool,
          "owner terminal fence flags are malformed")
    if bridge["requires_restart"]:
        _need(bridge["unavailable"] is True,
              "fenced owner bridge is not marked unavailable")
    if handler["requires_restart"]:
        _need(bridge["requires_restart"] is True,
              "handler restart fence is inconsistent with the bridge")

    lifecycle = status["owner_lifecycle"]
    _exact_fields(lifecycle, {"phase", "drain_started_monotonic", "drain_deadline_monotonic",
                              "deadline_reached"}, "owner lifecycle")
    _need(type(lifecycle["deadline_reached"]) is bool, "owner deadline flag is malformed")
    started, deadline = lifecycle["drain_started_monotonic"], lifecycle["drain_deadline_monotonic"]
    if terminal:
        _need(phase in ("draining", "paused") and status["phase"] == "stopped",
              "final owner status has an invalid lifecycle phase")
        _need(status["shutdown"] == {"server": "confirmed", "bridge": "confirmed",
                "handler": "confirmed", "overall": "confirmed"}
              and status["transport"].get("server_state") == "stopped",
              "terminal owner status lacks confirmed stopped owners")
        _need(status["handler"]["active_session_ids"] == []
              and status["handler"]["active_sessions"] == 0
              and status["handler"]["queued_operations"] == 0
              and status["handler"]["committed_cache_bytes"] == 0
              and status["handler"]["allocated_cache_bytes"] == 0
              and status["bridge"]["active_authorizations"] == 0
              and status["bridge"]["owned_sessions"] == 0
              and status["bridge"]["pending_notices"] == 0
              and all(status["transport"][key] == 0 for key in (
                  "reserved_connections", "reserved_pending",
                  "reserved_listener_pending_capacity", "reserved_outbound_pending")),
              "terminal owner status retains resources")
    if command is not None:
        _need(phase in ("draining", "paused") and status["bridge"]["ready"] is False,
              "command-bound owner status lacks the admission cutoff")
    if phase == "ready":
        _need(started is None and deadline is None and lifecycle["deadline_reached"] is False,
              "ready owner lifecycle has drain timestamps")
    else:
        _need(type(started) is float and type(deadline) is float
              and math.isfinite(started) and math.isfinite(deadline)
              and started > 0 and deadline == started + 30.0,
              "draining owner deadline is invalid")
        if phase == "paused":
            _need(handler["active_session_ids"] == [] and handler["active_sessions"] == 0
                  and handler["queued_operations"] == 0
                  and handler["active_compute"] is False
                  and handler["committed_cache_bytes"] == 0
                  and handler["allocated_cache_bytes"] == 0
                  and bridge["active_authorizations"] == 0
                  and bridge["owned_sessions"] == 0
                  and bridge["pending_notices"] == 0,
                  "paused owner lifecycle retains physical session resources")
    control = status["owner_control"]
    _exact_fields(control, {"run_id", "last_sequence", "last_command_sha256", "last_action",
                            "received_monotonic_ns", "applied_monotonic_ns",
                            "applied_snapshot_sha256", "applied_revision",
                            "removal_intent_verified", "revocation_notice_monotonic_ns"},
                  "owner control status")
    _need(control["run_id"] == expected.run_id
          and type(control["removal_intent_verified"]) is bool,
          "owner control identity or intent flag is invalid")
    if command is None:
        for key in ("last_sequence", "received_monotonic_ns", "applied_monotonic_ns",
                    "applied_revision", "revocation_notice_monotonic_ns"):
            _int(control[key], minimum=0, maximum=MAX_I63, label=f"owner control {key}")
            _need(control[key] == 0, "owner control was changed before a command")
        _need(control["last_command_sha256"] == "" and control["last_action"] == ""
              and control["applied_snapshot_sha256"] == ""
              and control["removal_intent_verified"] is False,
              "owner control contains an unclaimed prior action")
    else:
        _need(type(command) is dict, "owner status command acknowledgement is invalid")
        ack = command
        for key in ("last_sequence", "received_monotonic_ns", "applied_monotonic_ns",
                    "applied_revision", "revocation_notice_monotonic_ns"):
            _int(control[key], minimum=0, maximum=MAX_I63, label=f"owner control {key}")
        _need(type(control["last_command_sha256"]) is str
              and type(control["last_action"]) is str
              and type(control["applied_snapshot_sha256"]) is str,
              "owner control command fields are malformed")
        _need(type(ack.get("sequence")) is int and type(ack.get("received_monotonic_ns")) is int
              and type(ack.get("completed_monotonic_ns")) is int
              and type(ack.get("applied_revision")) is int
              and control["last_sequence"] == ack["sequence"]
              and control["last_command_sha256"] == ack["command_sha256"]
              and control["last_action"] == ack["action"]
              and control["received_monotonic_ns"] == ack["received_monotonic_ns"]
              and control["applied_monotonic_ns"] == ack["completed_monotonic_ns"]
              and control["applied_snapshot_sha256"] == ack["applied_snapshot_sha256"]
              and control["applied_revision"] == ack["applied_revision"],
              "owner status does not match its accepted command")
        _need(type(control["removal_intent_verified"]) is bool,
              "owner intent verification flag is invalid")
        _int(control["revocation_notice_monotonic_ns"], minimum=0, maximum=MAX_I63,
             label="revocation notice monotonic time")
        if expected.profile == PROFILE_C1B_OWNER_REMOVE and ack["sequence"] == 1:
            notice = control["revocation_notice_monotonic_ns"]
            _need(control["removal_intent_verified"] is True
                  and ack["received_monotonic_ns"] <= notice <= ack["completed_monotonic_ns"]
                  and notice - ack["received_monotonic_ns"] <= 5_000_000_000,
                  "owner invalidation notice is not causally bounded")
        elif expected.profile == PROFILE_C1B_OWNER_DRAIN:
            _need(control["removal_intent_verified"] is False
                  and control["revocation_notice_monotonic_ns"] == 0,
                  "drain status contains a removal proof")
        else:
            _need(control["removal_intent_verified"] is True,
                  "remove status lacks verified intent")
    return status


def validate_owner_action_response(value, expected_request, expected, *,
                                   expected_ssh_host_key_sha256,
                                   expected_worker_config):
    """Validate one bounded, command-bound owner action response.

    This checks schema and reported evidence only; it cannot establish remote I/O
    provenance, process death, or that the controller actually performed the action.
    """
    _need(type(expected) is OwnerExpectation, "owner response requires a trusted expectation")
    request_command = validate_owner_action_request(expected_request, expected)
    value = _owner_record(value, maximum=MAX_RECORD_BYTES, label="owner action response")
    _exact_fields(value, _ACTION_RESPONSE_FIELDS, "owner action response")
    _need(type(value["schema_version"]) is int and value["schema_version"] == 1
          and value["event"] == "owner_action_response", "owner response version/event is invalid")
    for key in ("profile", "run_id", "nonce", "worker_boot_id"):
        _need(type(value[key]) is str and value[key] == getattr(expected, key),
              f"owner response {key} differs from trusted expectation")
    _need(type(value["command_number"]) is int
          and value["command_number"] == request_command.sequence
          and value["command_sha256"] == request_command.command_sha256,
          "owner response command does not match the actual request")
    _hex(expected_ssh_host_key_sha256, _HEX64, "pinned SSH host key")
    protected = value["protected_status"]
    _exact_fields(protected, _PROTECTED_STATUS_FIELDS, "protected status envelope")
    _need(protected["measurement_label"] == "ssh_protected_owner_status_v1"
          and protected["ssh_host_key_sha256"] == expected_ssh_host_key_sha256,
          "protected status provenance label or host key is wrong")
    _int(protected["remote_mark_ns"], minimum=1, maximum=MAX_I63, label="remote status mark")
    _int(protected["heartbeat_mtime_ns"], minimum=1, maximum=MAX_I63,
         label="remote heartbeat mtime")
    _need(protected["heartbeat_mtime_ns"] > protected["remote_mark_ns"],
          "protected heartbeat predates its command mark")
    _need(type(protected["remote_status_uid"]) is int and protected["remote_status_uid"] == 1000
          and type(protected["remote_status_mode"]) is int
          and protected["remote_status_mode"] == 0o600,
          "protected status ownership or mode is wrong")
    ack = validate_owner_command_ack(value["worker_ack"], request_command, expected)
    _validate_owner_status(protected["remote_status"], expected, expected_worker_config,
                           command=ack)
    publication = value["publication"]
    _exact_fields(publication, {"install_intent", "removal_intent", "policy", "command"},
                  "owner publication evidence")
    from lab.secure_owner_file_publication import validate_publication_receipt
    def check_receipt(receipt):
        try:
            validate_publication_receipt(receipt)
        except (TypeError, ValueError) as error:
            raise OwnerProtocolError("owner publication receipt is invalid") from error
        _need(receipt["uid"] == 1000 and receipt["gid"] == 1000
              and receipt["mode"] == 0o600,
              "owner publication receipt has the wrong protected owner or mode")
        return receipt
    if expected.profile == PROFILE_C1B_OWNER_DRAIN:
        _need(all(publication[name] is None for name in ("install_intent", "removal_intent", "policy")),
              "drain publication unexpectedly includes policy or intent")
        kind = f"command{request_command.sequence}"
        expected_digest = request_command.command_sha256
        expected_size = len(_canonical_bytes(_command_document(request_command)))
    else:
        _need(publication["install_intent"] is not None
              and publication["removal_intent"] is not None,
              "remove publication omits immutable intent receipts")
        for key in ("install_intent", "removal_intent"):
            _need(check_receipt(publication[key]) is publication[key],
                  "remove intent publication receipt is invalid")
        _need(publication["install_intent"]["kind"] == "install_intent"
              and publication["removal_intent"]["kind"] == "removal_intent",
              "remove intent receipt kinds are invalid")
        _need(check_receipt(publication["policy"]) is publication["policy"],
              "remove policy publication receipt is invalid")
        _need(publication["policy"]["kind"] == f"policy{request_command.sequence}"
              and publication["policy"]["sha256"] == request_command.snapshot_sha256
              and type(publication["policy"]["size"]) is int,
              "remove policy receipt does not match command")
        kind = f"command{request_command.sequence}"
        expected_digest = request_command.command_sha256
        expected_size = len(_canonical_bytes(_command_document(request_command)))
    _need(check_receipt(publication["command"]) is publication["command"],
          "command publication receipt is invalid")
    receipt = publication["command"]
    _need(receipt["kind"] == kind and receipt["sha256"] == expected_digest
          and receipt["size"] == expected_size,
          "command publication receipt does not match exact command bytes")
    _canonical_bytes_owner(value, maximum=MAX_RECORD_BYTES)
    return value


def _validate_binding(value, expected, method, probe, *, fresh=False):
    _exact_fields(value, _BINDING_FIELDS, "owner RPC binding")
    from lab import secure_cohort
    _need(value["method"] == method and type(value["method"]) is str,
          "owner RPC method is unexpected")
    _need(type(value["operation_id"]) is str
          and re.fullmatch(r"op_[0-9a-f]{32}", value["operation_id"]) is not None,
          "owner operation ID is malformed")
    for key, prefix in (("request_id", "req_"), ("session_id", "ses_"),
                        ("route_id", "route_")):
        _need(type(value[key]) is str
              and re.fullmatch(re.escape(prefix) + r"[0-9a-f]{32}", value[key]) is not None,
              f"owner binding {key} is malformed")
    _need(type(value["route_epoch"]) is int and value["route_epoch"] == 1
          and type(value["attempt"]) is int and value["attempt"] == 1
          and value["worker_boot_id"] == expected.worker_boot_id,
          "owner RPC binding generation is invalid")
    if fresh:
        _need(all(value[key] != probe[key] for key in ("request_id", "session_id", "route_id")),
              "fresh OpenSession reused the original probe binding")
    else:
        _need(all(value[key] == probe[key] for key in ("request_id", "session_id", "route_id")),
              "owner RPC binding differs from original probe")
    return value


def _validate_step(value, *, sequence, start, count, end, next_sequence, shape, size):
    _exact_fields(value, _STEP_PROJECTION_FIELDS, "owner Step projection")
    expected = {"sequence": sequence, "start_position": start, "token_count": count,
                "end_position": end, "next_sequence": next_sequence,
                "tensor_shape": shape, "dtype": "float32_le", "byte_count": size,
                "finite": True}
    for key, item in expected.items():
        _need(type(value[key]) is type(item) and value[key] == item,
              f"owner Step projection {key} is invalid")
    _need(type(value["tensor_shape"]) is list
          and all(type(dimension) is int and dimension >= 0
                  for dimension in value["tensor_shape"]),
          "owner Step tensor dimensions must be exact nonnegative integers")
    return value


def _validate_denial(value, *, expected, probe, method):
    _exact_fields(value, _DENIAL_FIELDS, "owner denial projection")
    _need(value["method"] == method and value["native_status"] == "UNAUTHENTICATED"
          and type(value["returned_response"]) is bool and value["returned_response"] is False
          and type(value["dispatch_count"]) is int and value["dispatch_count"] == 1
          and value["policy_sha256"] == expected.initial_snapshot_sha256,
          "owner denial is not an exact one-dispatch authorization rejection")
    _validate_binding(value["binding"], expected, method, probe,
                      fresh=(method == "OpenSession"))
    return value


def validate_owner_result(value, expected, *, expected_ssh_host_key_sha256,
                          expected_worker_config):
    """Validate and return the exact shared owner_actions object.

    Baseline cohort fields are validated by their existing separate path. This
    owner extension is self-consistent evidence only: container exit, SSH
    provenance, actual RPC dispatch and publication ordering remain controller
    responsibilities.
    """
    _need(type(expected) is OwnerExpectation, "owner result requires a trusted expectation")
    actions = _owner_record(value, maximum=65_536, label="owner actions")
    _exact_fields(actions, _OWNER_ACTIONS_FIELDS, "owner actions")
    _need(actions["profile"] == expected.profile and actions["status"] == "passed"
          and actions["scope"] == "remote_host_owner_control"
          and actions["worker_boot_id"] == expected.worker_boot_id
          and actions["initial_snapshot_sha256"] == expected.initial_snapshot_sha256
          and type(actions["initial_revision"]) is int
          and actions["initial_revision"] == expected.initial_revision,
          "owner action identity or initial policy differs from expectation")
    _need(actions["target_device_id"] == expected_worker_config.get("device_id"),
          "owner target device differs from worker configuration")
    serials = actions["initial_local_serials"]
    _need(type(serials) is list and 1 <= len(serials) <= 16
          and all(type(item) is str and re.fullmatch(r"[1-9a-f][0-9a-f]{0,39}", item)
                  for item in serials)
          and serials == sorted(set(serials)), "initial local serials are malformed")
    _exact_fields(actions["old_local_shutdown"], {"confirmed", "failure_types"},
                  "initial local shutdown")
    _need(actions["old_local_shutdown"]["confirmed"] is True
          and type(actions["old_local_shutdown"]["confirmed"]) is bool
          and actions["old_local_shutdown"]["failure_types"] == [],
          "initial local shutdown was not confirmed cleanly")

    probe = actions["direct_probe"]
    _exact_fields(probe, {"request_id", "session_id", "route_id", "route_epoch", "attempt",
                          "open_response", "step_response", "bindings"}, "direct owner probe")
    from lab import secure_cohort
    _need(type(probe["request_id"]) is str and secure_cohort._TYPED_REQUEST.fullmatch(
        probe["request_id"]) is not None and type(probe["session_id"]) is str
        and secure_cohort._TYPED_SESSION.fullmatch(probe["session_id"]) is not None
        and type(probe["route_id"]) is str
        and re.fullmatch(r"route_[0-9a-f]{32}", probe["route_id"]) is not None
        and type(probe["route_epoch"]) is int and probe["route_epoch"] == 1
        and type(probe["attempt"]) is int and probe["attempt"] == 1,
        "direct probe identifiers are malformed")
    _exact_fields(probe["open_response"], {"code", "session_id", "worker_boot_id"},
                  "probe OpenSession response")
    _need(probe["open_response"] == {"code": "OK", "session_id": probe["session_id"],
                                     "worker_boot_id": expected.worker_boot_id},
          "probe OpenSession response differs from its binding")
    _validate_step(probe["step_response"], sequence=0, start=0, count=3, end=3,
                   next_sequence=1, shape=[1, 3, 64], size=768)
    _need(type(probe["bindings"]) is list and len(probe["bindings"]) == 2,
          "direct probe must have exactly OpenSession and Step bindings")
    _validate_binding(probe["bindings"][0], expected, "OpenSession", probe)
    _validate_binding(probe["bindings"][1], expected, "Step", probe)
    _need(probe["bindings"][0]["operation_id"] != probe["bindings"][1]["operation_id"],
          "probe RPC operations reused an operation ID")

    commands = actions["commands"]
    _need(type(commands) is list and len(commands) == 2,
          "owner result must contain two command responses")
    command_ids = []
    parsed_commands = []
    command_acks = []
    immutable_deadline = None
    for number, response in enumerate(commands, 1):
        _exact_fields(response, _ACTION_RESPONSE_FIELDS, "owner command response")
        ack = response["worker_ack"]
        _need(type(ack) is dict, "owner command ACK must be an object")
        _hex(ack.get("command_id"), _HEX32, "owner command ID")
        if expected.profile == PROFILE_C1B_OWNER_DRAIN:
            digest, revision = "", 0
        else:
            digest, revision = ack.get("applied_snapshot_sha256"), ack.get("applied_revision")
        command_doc = build_owner_command(
            expected, number, ack["command_id"], snapshot_sha256=digest,
            snapshot_revision=revision)
        request = build_owner_action_request(expected, number, command_doc)
        normalized = validate_owner_action_response(
            response, request, expected,
            expected_ssh_host_key_sha256=expected_ssh_host_key_sha256,
            expected_worker_config=expected_worker_config)
        lifecycle = normalized["protected_status"]["remote_status"]["owner_lifecycle"]
        if lifecycle["drain_started_monotonic"] is not None:
            pair = (lifecycle["drain_started_monotonic"],
                    lifecycle["drain_deadline_monotonic"])
            if immutable_deadline is None:
                immutable_deadline = pair
            else:
                _need(pair == immutable_deadline,
                      "owner command responses changed the immutable drain deadline")
        parsed = _command_dict(command_doc, expected)
        command_ids.append(parsed.command_id)
        parsed_commands.append(parsed)
        command_acks.append(ack)
        _need(normalized is response, "owner response normalization unexpectedly changed data")
    _need(len(set(command_ids)) == 2, "owner commands must have distinct IDs")
    _need(command_acks[1]["received_monotonic_ns"]
          >= command_acks[0]["completed_monotonic_ns"],
          "second owner command predates completion of the first")
    if expected.profile == PROFILE_C1B_OWNER_DRAIN:
        for number, response in enumerate(commands, 1):
            status = response["protected_status"]["remote_status"]
            handler = status["handler"]
            _need(handler["active_session_ids"] == [probe["session_id"]]
                  and handler["active_sessions"] == 1
                  and handler["committed_cache_bytes"] > 0
                  and handler["allocated_cache_bytes"] > 0
                  and handler["cache_bytes_exact"] is True
                  and status["bridge"]["owned_sessions"] == 1,
                  f"drain command {number} lost the original held session or exact KV")
    if expected.profile == PROFILE_C1B_OWNER_REMOVE:
        _need(_canonical_bytes_owner(commands[0]["publication"]["install_intent"],
                                     maximum=MAX_RECORD_BYTES)
              == _canonical_bytes_owner(commands[1]["publication"]["install_intent"],
                                        maximum=MAX_RECORD_BYTES)
              and _canonical_bytes_owner(commands[0]["publication"]["removal_intent"],
                                         maximum=MAX_RECORD_BYTES)
              == _canonical_bytes_owner(commands[1]["publication"]["removal_intent"],
                                        maximum=MAX_RECORD_BYTES),
              "remove command responses changed immutable intent receipts")

    controls = actions["controls"]
    if expected.profile == PROFILE_C1B_OWNER_DRAIN:
        _exact_fields(controls, {"continued_step", "renew", "describe", "new_open_rejection"},
                      "drain controls")
        _exact_fields(controls["continued_step"], {"binding", "response"}, "continued Step")
        _validate_binding(controls["continued_step"]["binding"], expected, "Step", probe)
        _validate_step(controls["continued_step"]["response"], sequence=1, start=3,
                       count=1, end=4, next_sequence=2, shape=[1, 1, 64], size=256)
        _exact_fields(controls["renew"], {"binding", "response"}, "RenewSession control")
        _validate_binding(controls["renew"]["binding"], expected, "RenewSession", probe)
        renew = controls["renew"]["response"]
        _exact_fields(renew, {"code", "worker_boot_id", "session_id"}, "RenewSession response")
        _need(renew == {"code": "OK", "worker_boot_id": expected.worker_boot_id,
                        "session_id": probe["session_id"]}, "RenewSession response identity is invalid")
        describe = controls["describe"]
        _exact_fields(describe, {"code", "worker_boot_id", "ready", "active_sessions",
                                 "reserved_positions", "allocated_cache_bytes", "active_operations",
                                 "queued_operations", "tombstones", "cache_bytes_exact",
                                 "requires_restart"}, "worker describe")
        _need(describe["code"] == "OK" and describe["worker_boot_id"] == expected.worker_boot_id
              and type(describe["ready"]) is bool and describe["ready"] is False
              and type(describe["active_sessions"]) is int and describe["active_sessions"] == 1
              and type(describe["reserved_positions"]) is int and describe["reserved_positions"] == 12
              and type(describe["allocated_cache_bytes"]) is int and describe["allocated_cache_bytes"] > 0
              and type(describe["active_operations"]) is int and describe["active_operations"] == 0
              and type(describe["queued_operations"]) is int and describe["queued_operations"] == 0
              and type(describe["tombstones"]) is int and 0 <= describe["tombstones"] <= 4096
              and type(describe["cache_bytes_exact"]) is bool and describe["cache_bytes_exact"] is True
              and type(describe["requires_restart"]) is bool and describe["requires_restart"] is False,
              "draining worker Describe projection is invalid")
        _validate_denial(controls["new_open_rejection"], expected=expected,
                         probe=probe, method="OpenSession")
    else:
        _exact_fields(controls, {"old_session_status_rejection", "new_open_rejection"},
                      "remove controls")
        _validate_denial(controls["old_session_status_rejection"], expected=expected,
                         probe=probe, method="SessionStatus")
        _validate_denial(controls["new_open_rejection"], expected=expected,
                         probe=probe, method="OpenSession")
    rpc_bindings = list(probe["bindings"])
    if expected.profile == PROFILE_C1B_OWNER_DRAIN:
        rpc_bindings.extend((controls["continued_step"]["binding"],
                             controls["renew"]["binding"],
                             controls["new_open_rejection"]["binding"]))
    else:
        rpc_bindings.extend((controls["old_session_status_rejection"]["binding"],
                             controls["new_open_rejection"]["binding"]))
    operation_ids = [row["operation_id"] for row in rpc_bindings]
    _need(len(operation_ids) == len(set(operation_ids)),
          "owner RPC operations reused a binding operation ID")

    observations = actions["observations"]
    _need(type(observations) is list and len(observations) == 3,
          "owner result must include observations 5, 6 and 7")
    from lab import secure_cohort_supervisor as supervisor
    obs_fields = supervisor._OBSERVATION_ACK_FIELDS
    expected_cases = (owner_profile_steps(expected.profile)[4:])
    for index, (row, (sequence, case_id)) in enumerate(zip(observations, expected_cases)):
        _exact_fields(row, obs_fields, "owner observation acknowledgement")
        expected_values = {"schema_version": 1, "event": "observation_ack",
                           "run_id": expected.run_id, "nonce": expected.nonce,
                           "sequence": sequence, "case_id": case_id,
                           "boot_id": expected.worker_boot_id,
                           "manifest_fingerprint": expected.manifest_fingerprint,
                           "endpoint": expected.endpoint,
                           "ssh_host_key_sha256": expected_ssh_host_key_sha256,
                           "remote_status_uid": 1000, "remote_status_mode": 0o600,
                           "measurement_label": "ssh_protected_owner_status_v1"}
        for key, item in expected_values.items():
            _need(type(row[key]) is type(item) and row[key] == item,
                  f"owner observation {key} is invalid")
        _hex(row["request_id"], re.compile(r"req_[0-9a-f]{32}\Z"), "observation request ID")
        _hex(row["session_id"], re.compile(r"ses_[0-9a-f]{32}\Z"), "observation session ID")
        for key in ("supervisor_monotonic_ns", "remote_mark_ns", "heartbeat_mtime_ns"):
            _int(row[key], minimum=1, maximum=MAX_I63, label=f"observation {key}")
        _need(row["heartbeat_mtime_ns"] > row["remote_mark_ns"],
              "owner observation heartbeat predates its mark")
        _need(row["request_id"] == probe["request_id"]
              and row["session_id"] == probe["session_id"],
              "owner observations do not retain the original direct-probe IDs")
        status = row["remote_status"]
        _need(type(status) is dict, "owner observation status is malformed")
        observed_command = (None if sequence == 5 else
                            command_acks[1] if expected.profile == PROFILE_C1B_OWNER_DRAIN
                            else command_acks[sequence - 6])
        _validate_owner_status(status, expected, expected_worker_config,
                               command=observed_command, observation=True)
        if sequence == 5:
            _need(status["event"] == "heartbeat"
                  and status["owner_lifecycle"]["phase"] == "ready"
                  and status["owner_control"]["last_sequence"] == 0,
                  "pre-command observation is not the original READY heartbeat")
        elif sequence < 7:
            _need(status["event"] == "heartbeat",
                  "nonterminal owner observation is not a heartbeat")
        else:
            command_status = commands[1]["protected_status"]
            if expected.profile == PROFILE_C1B_OWNER_REMOVE:
                _need(row["remote_mark_ns"] == command_status["remote_mark_ns"]
                      and row["measurement_label"] == command_status["measurement_label"]
                      and row["ssh_host_key_sha256"] == command_status["ssh_host_key_sha256"]
                      and row["remote_status_uid"] == command_status["remote_status_uid"]
                      and row["remote_status_mode"] == command_status["remote_status_mode"],
                      "final remove observation is not bound to command 2's status frame")
            else:
                _need(row["remote_mark_ns"] > command_status["remote_mark_ns"],
                      "final drain observation does not have a fresh status mark")
        lifecycle = status["owner_lifecycle"]
        if lifecycle["drain_started_monotonic"] is not None:
            pair = (lifecycle["drain_started_monotonic"],
                    lifecycle["drain_deadline_monotonic"])
            if immutable_deadline is None:
                immutable_deadline = pair
            else:
                _need(pair == immutable_deadline,
                      "owner observations changed the immutable drain deadline")
        if expected.profile == PROFILE_C1B_OWNER_DRAIN:
            if sequence == 5:
                _need(status["owner_lifecycle"]["phase"] == "ready"
                      and status["handler"]["active_session_ids"] == [probe["session_id"]]
                      and status["handler"]["committed_cache_bytes"] > 0,
                      "held drain observation does not show the direct probe session")
            elif sequence == 6:
                _need(status["owner_lifecycle"]["phase"] in ("draining", "paused")
                      and status["handler"]["active_session_ids"] == [probe["session_id"]]
                      and status["handler"]["committed_cache_bytes"] > 0,
                      "drain control observation lost the held session")
            else:
                _need(status["event"] == "heartbeat"
                      and status["phase"] == "paused"
                      and status["owner_lifecycle"]["phase"] == "paused"
                      and status["owner_lifecycle"]["deadline_reached"] is True,
                      "final drain observation did not confirm deadline pause")
                _need(status["handler"]["active_session_ids"] == []
                      and status["handler"]["active_sessions"] == 0
                      and status["handler"]["queued_operations"] == 0
                      and status["handler"]["active_compute"] is False
                      and status["handler"]["committed_cache_bytes"] == 0
                      and status["handler"]["allocated_cache_bytes"] == 0
                      and status["bridge"]["active_authorizations"] == 0
                      and status["bridge"]["owned_sessions"] == 0
                      and status["bridge"]["pending_notices"] == 0
                      and status["transport"]["server_state"] == "running"
                      and status["transport"]["reserved_connections"] == 1
                      and status["transport"]["reserved_listener_pending_capacity"] == 1
                      and status["transport"]["reserved_pending"] == 0
                      and status["transport"]["reserved_outbound_pending"] == 0,
                      "final drain heartbeat has incorrect live-listener or resource state")
        elif sequence == 5:
            _need(status["handler"]["active_session_ids"] == [probe["session_id"]]
                  and status["handler"]["committed_cache_bytes"] > 0,
                  "held remove observation does not show the direct probe session")
        else:
            if sequence == 7:
                _need(status["event"] in ("status", "final"),
                      "final remove observation is not an actual status/final event")
                _need(status["handler"]["active_session_ids"] == []
                      and status["handler"]["active_sessions"] == 0
                      and status["handler"]["queued_operations"] == 0
                      and status["handler"]["active_compute"] is False
                      and status["handler"]["committed_cache_bytes"] == 0
                      and status["handler"]["allocated_cache_bytes"] == 0
                      and status["bridge"]["active_authorizations"] == 0
                      and status["bridge"]["owned_sessions"] == 0
                      and status["bridge"]["pending_notices"] == 0
                      and status["transport"]["reserved_pending"] == 0
                      and status["transport"]["reserved_outbound_pending"] == 0,
                      "terminal owner observation still reports physical resources")
                if status["event"] == "status":
                    _need(status["phase"] == "draining"
                          and status["owner_lifecycle"]["phase"] in ("draining", "paused")
                          and status["bridge"]["ready"] is False
                          and status["transport"]["server_state"] == "running"
                          and status["transport"]["reserved_connections"] == 1
                          and status["transport"]["reserved_listener_pending_capacity"] == 1,
                          "final remove status is not a live admission-cutoff observation")
            if sequence == 6:
                _need(status["handler"]["active_session_ids"] == []
                      and status["handler"]["active_sessions"] == 0
                      and status["handler"]["queued_operations"] == 0
                      and status["handler"]["active_compute"] is False
                      and status["handler"]["committed_cache_bytes"] == 0
                      and status["handler"]["allocated_cache_bytes"] == 0
                      and status["bridge"]["active_authorizations"] == 0
                      and status["bridge"]["owned_sessions"] == 0
                      and status["bridge"]["pending_notices"] == 0,
                      "remove revocation observation retains physical session resources")
    cleanup = actions["probe_cleanup"]
    cleanup_fields = {"confirmed", "failure_types", "client_closes", "contexts_released",
                      "authorizations_closed", "transport_reserved_connections",
                      "transport_reserved_pending", "transport_reserved_outbound_pending",
                      "transport_reserved_listener_pending_capacity"}
    _exact_fields(cleanup, cleanup_fields, "probe cleanup")
    _need(type(cleanup["confirmed"]) is bool and cleanup["confirmed"] is True
          and cleanup["failure_types"] == [] and type(cleanup["failure_types"]) is list
          and cleanup["contexts_released"] == 2 and type(cleanup["contexts_released"]) is int
          and cleanup["authorizations_closed"] == 2 and type(cleanup["authorizations_closed"]) is int,
          "probe cleanup is not confirmed")
    expected_labels = (["initial", "new_open"] if expected.profile == PROFILE_C1B_OWNER_DRAIN
                       else ["initial", "old_status", "new_open"])
    _need(type(cleanup["client_closes"]) is list and len(cleanup["client_closes"]) == len(expected_labels),
          "probe close rows are incomplete")
    close_fields = {"label", "attempted", "confirmed", "close_calls",
                    "reserved_connections_before", "reserved_connections_after",
                    "client_closed", "reserved_pending_after"}
    for row, label in zip(cleanup["client_closes"], expected_labels):
        _exact_fields(row, close_fields, "probe close row")
        _need(row["label"] == label and all(type(row[key]) is bool and row[key] is True
              for key in ("attempted", "confirmed", "client_closed"))
              and type(row["close_calls"]) is int and row["close_calls"] == 1
              and type(row["reserved_connections_before"]) is int
              and row["reserved_connections_before"] == 3
              and type(row["reserved_connections_after"]) is int
              and row["reserved_connections_after"] == 0
              and type(row["reserved_pending_after"]) is int and row["reserved_pending_after"] == 0,
              "probe client close row is invalid")
    for key in ("transport_reserved_connections", "transport_reserved_pending",
                "transport_reserved_outbound_pending", "transport_reserved_listener_pending_capacity"):
        _need(type(cleanup[key]) is int and cleanup[key] == 0,
              f"probe cleanup retains transport capacity: {key}")
    _canonical_bytes_owner(actions, maximum=65_536)
    return actions
