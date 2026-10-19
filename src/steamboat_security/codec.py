"""Strict bounded carrier for the v1 steamboat-binding-bin gRPC metadata."""

from __future__ import annotations

import json
import math
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Iterable

from .errors import BindingError
from .ids import validate_boot, validate_id


METADATA_KEY = "steamboat-binding-bin"
MAX_BINDING_BYTES = 4096
MAX_METADATA_BYTES = 8192

COMMON = frozenset({"binding_version", "operation_id", "account_id", "device_id",
                    "role", "credential_epoch", "target_device_id"})
WORKER_SESSION = frozenset({"coordinator_boot_id", "tenant_account_id", "request_id",
                            "session_id", "route_id", "route_epoch", "attempt",
                            "assignment_id", "worker_boot_id"})
WORKER_METHODS = frozenset({"Describe", "OpenSession", "RenewSession", "Step",
                            "CloseSession", "CancelSession", "SessionStatus"})
COORDINATOR_METHODS = frozenset({"Describe", "Tokenize", "Generate"})
WORKER_SERVICE = "steamboat.v1.Worker"
COORDINATOR_SERVICE = "steamboat.v1.Coordinator"
ROLES = frozenset({"consumer", "host", "personal_coordinator"})


def canonical_json(value: Any) -> bytes:
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=False, allow_nan=False).encode("utf-8")
    except (TypeError, ValueError, UnicodeError, RecursionError) as error:
        raise BindingError("value is not canonical JSON") from error


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise BindingError("duplicate JSON key")
        result[key] = value
    return result


def _reject_constant(_value):
    raise BindingError("non-finite JSON values are forbidden")


def _fields(service: str, method: str, raw: dict) -> frozenset[str]:
    if service == WORKER_SERVICE and method in WORKER_METHODS:
        if method == "Describe":
            boot = "worker_boot_id" in raw
            assignment = "assignment_id" in raw
            if boot != assignment:
                raise BindingError("worker Describe boot and assignment must be supplied together")
            return COMMON | (frozenset({"worker_boot_id", "assignment_id"}) if boot else frozenset())
        return COMMON | WORKER_SESSION
    if service == COORDINATOR_SERVICE and method in COORDINATOR_METHODS:
        return COMMON | (frozenset({"request_id"}) if method == "Generate" else frozenset())
    raise BindingError("unknown secure service method")


@dataclass(frozen=True)
class Binding:
    service: str
    method: str
    fields: Any
    encoded: bytes

    def __getitem__(self, key):
        return self.fields[key]

    def get(self, key, default=None):
        return self.fields.get(key, default)


def _validate_fields(service: str, method: str, fields: dict) -> None:
    if type(fields) is not dict:
        raise BindingError("binding must be one flat JSON object")
    allowed = _fields(service, method, fields)
    if set(fields) != set(allowed):
        raise BindingError("binding has missing or unknown method fields")
    for value in fields.values():
        if type(value) not in (str, int):
            raise BindingError("binding values must be strings or integers")
    for name in ("binding_version", "credential_epoch"):
        value = fields.get(name)
        if type(value) is not int or value < (1 if name == "credential_epoch" else 1):
            raise BindingError("binding version and credential epoch must be positive integers")
    if fields["binding_version"] != 1:
        raise BindingError("unsupported binding version")
    if fields["role"] not in ROLES:
        raise BindingError("unsupported role")
    for name in ("account_id", "tenant_account_id"):
        if name in fields:
            validate_id(fields[name], "acct")
    for name in ("device_id", "target_device_id"):
        if name in fields:
            validate_id(fields[name], "dev")
    for name, prefix in (("operation_id", "op"), ("request_id", "req"),
                         ("session_id", "ses"), ("route_id", "route"),
                         ("assignment_id", "asg")):
        if name in fields:
            validate_id(fields[name], prefix)
    for name in ("worker_boot_id", "coordinator_boot_id"):
        if name in fields:
            validate_boot(fields[name])
    for name in ("attempt", "route_epoch"):
        if name in fields and (type(fields[name]) is not int or fields[name] != 1):
            raise BindingError("attempt and route_epoch must be exactly 1")


def encode_binding(service: str, method: str, fields: dict) -> bytes:
    _validate_fields(service, method, fields)
    encoded = canonical_json(fields)
    if len(encoded) > MAX_BINDING_BYTES:
        raise BindingError("binding exceeds 4 KiB")
    return encoded


def _metadata_size(key, value) -> int:
    if type(key) is not str:
        raise BindingError("metadata key must be text")
    try:
        key_bytes = key.encode("ascii")
        if type(value) is str:
            value_bytes = value.encode("utf-8")
        elif type(value) is bytes:
            value_bytes = value
        else:
            raise BindingError("metadata value has an unsupported type")
    except UnicodeError as error:
        raise BindingError("metadata is not valid text") from error
    return len(key_bytes) + len(value_bytes)


def parse_metadata(service: str, method: str, metadata: Iterable[tuple],
                   *, max_bytes: int = MAX_METADATA_BYTES) -> Binding:
    if type(max_bytes) is not int or not 1 <= max_bytes <= MAX_METADATA_BYTES:
        raise ValueError("metadata bound must be between 1 and 8192 bytes")
    try:
        entries = tuple(metadata)
    except Exception as error:
        raise BindingError("metadata is malformed") from error
    total = 0
    values = []
    seen = set()
    for entry in entries:
        if type(entry) not in (tuple, list) or len(entry) != 2:
            raise BindingError("metadata entries must be key/value pairs")
        key, value = entry
        total += _metadata_size(key, value)
        if total > max_bytes:
            raise BindingError("metadata exceeds 8 KiB")
        if key in seen:
            raise BindingError("duplicate metadata key")
        seen.add(key)
        if key == METADATA_KEY:
            if type(value) is not bytes:
                raise BindingError("binding carrier must use binary metadata")
            values.append(value)
    if len(values) != 1:
        raise BindingError("exactly one binding metadata value is required")
    raw = values[0]
    if len(raw) > MAX_BINDING_BYTES:
        raise BindingError("binding exceeds 4 KiB")
    try:
        text = raw.decode("utf-8", errors="strict")
        fields = json.loads(text, object_pairs_hook=_pairs, parse_constant=_reject_constant)
    except BindingError:
        raise
    except (UnicodeError, ValueError, TypeError, RecursionError) as error:
        raise BindingError("binding is malformed JSON") from error
    if type(fields) is not dict:
        raise BindingError("binding must be one flat JSON object")
    if any(type(value) in (dict, list) for value in fields.values()):
        raise BindingError("nested binding values are forbidden")
    _validate_fields(service, method, fields)
    encoded = canonical_json(fields)
    if encoded != raw:
        raise BindingError("binding JSON must use canonical key order and spacing")
    return Binding(service, method, MappingProxyType(fields), encoded)
