"""Closed configuration declarations for a future fixed root coordinator.

Parsing binds private paths lexically beneath an operator-owned root. It does
not open files, load a model, authorize workers, or establish readiness.
"""
from __future__ import annotations

import ipaddress
import json
import math
import os
from dataclasses import dataclass

from steamboat_security.codec import canonical_json
from steamboat_security.errors import BindingError
from steamboat_security.ids import validate_boot, validate_id

MAX_CONFIG_BYTES = 16 * 1024
_PROFILE = "native_posix_root_coordinator_v1"
_TOP_FIELDS = frozenset({
    "schema_version", "profile", "artifact_directory", "reference_directory",
    "listen_ip", "listen_port", "clock_uncertainty_seconds", "acceptor_directory",
    "status_report_path", "workers",
})
_WORKER_FIELDS = frozenset({
    "worker_name", "account_id", "device_id", "boot_id", "assignment_id",
    "certificate_path", "ip", "port",
})
_WORKER_ORDER = ("worker-1", "worker-2", "worker-3")


@dataclass(frozen=True)
class RootCoordinatorWorker:
    worker_name: str
    account_id: str
    device_id: str
    boot_id: str
    assignment_id: str
    certificate_path: str
    ip: str
    port: int


@dataclass(frozen=True)
class RootCoordinatorConfig:
    artifact_directory: str
    reference_directory: str
    listen_ip: str
    listen_port: int
    clock_uncertainty_seconds: int | float
    acceptor_directory: str
    status_report_path: str
    workers: tuple[RootCoordinatorWorker, ...]
    configuration_path: str
    protected_root: str


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise BindingError("coordinator config contains a duplicate JSON key")
        result[key] = value
    return result


def _reject_constant(_value):
    raise BindingError("coordinator config contains a non-finite number")


def _absolute_path(value, label, *, maximum=4096):
    if (type(value) is not str or not value or len(value) > maximum
            or any(ord(character) < 32 or ord(character) == 127 for character in value)
            or not os.path.isabs(value)
            or os.path.normpath(value) != value or os.path.abspath(value) != value):
        raise BindingError(f"coordinator {label} must be a normalized absolute path")
    return value


def _beneath(path, root, label):
    try:
        common = os.path.commonpath((root, path))
    except (ValueError, OSError) as error:
        raise BindingError(f"coordinator {label} is outside protected root") from error
    if (os.path.normcase(common) != os.path.normcase(root)
            or os.path.normcase(path) == os.path.normcase(root)):
        raise BindingError(f"coordinator {label} is outside protected root")
    return path


def _ip(value, label):
    if type(value) is not str or not value or "%" in value:
        raise BindingError(f"coordinator {label} must be a literal private IPv4 address")
    try:
        address = ipaddress.IPv4Address(value)
    except ValueError as error:
        raise BindingError(f"coordinator {label} must be a literal private IPv4 address") from error
    allowed = (ipaddress.ip_network("10.0.0.0/8"),
               ipaddress.ip_network("172.16.0.0/12"),
               ipaddress.ip_network("192.168.0.0/16"),
               ipaddress.ip_network("127.0.0.0/8"))
    if str(address) != value or not any(address in network for network in allowed):
        raise BindingError(f"coordinator {label} must be canonical private or loopback IPv4")
    return value


def _port(value, label):
    if type(value) is not int or not 1 <= value <= 65535:
        raise BindingError(f"coordinator {label} must be an exact TCP port")
    return value


def _worker(raw, root):
    if type(raw) is not dict or set(raw) != _WORKER_FIELDS:
        raise BindingError("coordinator worker has unknown or missing fields")
    try:
        account = validate_id(raw["account_id"], "acct")
        device = validate_id(raw["device_id"], "dev")
        boot = validate_boot(raw["boot_id"])
        assignment = validate_id(raw["assignment_id"], "asg")
    except BindingError as error:
        raise BindingError("coordinator worker identity is invalid") from error
    if type(raw["worker_name"]) is not str or raw["worker_name"] not in _WORKER_ORDER:
        raise BindingError("coordinator worker name is invalid")
    certificate = _beneath(
        _absolute_path(raw["certificate_path"], "worker certificate path"),
        root, "worker certificate")
    return RootCoordinatorWorker(
        raw["worker_name"], account, device, boot, assignment, certificate,
        _ip(raw["ip"], "worker address"), _port(raw["port"], "worker port"))


def parse_config_bytes(encoded: bytes, config_path: str,
                       protected_root: str) -> RootCoordinatorConfig:
    """Parse exact canonical config bytes and bind private paths to its root."""
    if type(encoded) is not bytes or not 1 <= len(encoded) <= MAX_CONFIG_BYTES:
        raise BindingError("coordinator config must be nonempty and at most 16 KiB")
    root = _absolute_path(protected_root, "protected root")
    config = _absolute_path(config_path, "configuration path")
    _beneath(config, root, "configuration")
    try:
        raw = json.loads(encoded.decode("utf-8", errors="strict"),
                         object_pairs_hook=_pairs, parse_constant=_reject_constant)
    except BindingError:
        raise
    except (UnicodeError, ValueError, TypeError, RecursionError) as error:
        raise BindingError("coordinator config is malformed JSON") from error
    if type(raw) is not dict or set(raw) != _TOP_FIELDS:
        raise BindingError("coordinator config has unknown or missing fields")
    if type(raw["schema_version"]) is not int or raw["schema_version"] != 1:
        raise BindingError("coordinator config schema version is invalid")
    if type(raw["profile"]) is not str or raw["profile"] != _PROFILE:
        raise BindingError("coordinator config profile is unsupported")
    if canonical_json(raw) != encoded:
        raise BindingError("coordinator config is not canonical JSON")

    artifact = _absolute_path(raw["artifact_directory"], "artifact directory")
    reference = _absolute_path(raw["reference_directory"], "reference directory")
    listen_ip = _ip(raw["listen_ip"], "listen address")
    listen_port = _port(raw["listen_port"], "listen port")
    uncertainty = raw["clock_uncertainty_seconds"]
    if (type(uncertainty) not in (int, float) or not 0 < uncertainty <= 30
            or not math.isfinite(uncertainty)):
        raise BindingError("coordinator clock uncertainty is outside its fixed bound")
    acceptor = _beneath(
        _absolute_path(raw["acceptor_directory"], "acceptor directory", maximum=4096),
        root, "acceptor directory")
    if len(os.fsencode(acceptor)) > 70:
        raise BindingError("coordinator acceptor directory exceeds the Unix socket path bound")
    status = _beneath(
        _absolute_path(raw["status_report_path"], "status report path"),
        root, "status report")
    if type(raw["workers"]) is not list or len(raw["workers"]) != 3:
        raise BindingError("coordinator requires exactly three ordered workers")
    workers = tuple(_worker(item, root) for item in raw["workers"])
    if tuple(item.worker_name for item in workers) != _WORKER_ORDER:
        raise BindingError("coordinator workers must be ordered worker-1 through worker-3")
    identities = [(item.account_id, item.device_id) for item in workers]
    endpoints = [(item.ip, item.port) for item in workers]
    if len(set(identities)) != 3 or len(set(endpoints)) != 3:
        raise BindingError("coordinator worker identities and endpoints must be unique")
    private_paths = [config, status, acceptor, *(item.certificate_path for item in workers)]
    if len(set(os.path.normcase(path) for path in private_paths)) != len(private_paths):
        raise BindingError("coordinator private paths must not collide")
    return RootCoordinatorConfig(
        artifact, reference, listen_ip, listen_port, uncertainty,
        acceptor, status, workers, config, root)
