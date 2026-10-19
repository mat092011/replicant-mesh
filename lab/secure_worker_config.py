"""Strict, bounded configuration for the nonproduction secure worker process.

The JSON file and role credential files live directly or indirectly below one
owner-controlled mode-0700 root. This module is dependency-light so its parser
can be checked without importing gRPC, Protobuf, or Torch.
"""

from __future__ import annotations

from dataclasses import dataclass
import ipaddress
import json
import math
import os
from pathlib import Path
import re
import stat

from steamboat_runtime.manifest import MODEL_ID, MODEL_REVISION


MAX_CONFIG_BYTES = 16 * 1024
MAX_STATUS_BYTES = 4096
MAX_PATH_CHARS = 4096
MAX_ACCEPTOR_DIRECTORY_BYTES = 70
MAX_CLOCK_UNCERTAINTY_SECONDS = 30.0
_HEX32 = re.compile(r"^[0-9a-f]{32}$", re.ASCII)
_HEX64 = re.compile(r"^[0-9a-f]{64}$", re.ASCII)
_ID_PREFIXES = {
    "account_id": "acct",
    "device_id": "dev",
    "assignment_id": "asg",
}
_WORKERS = frozenset(("worker-1", "worker-2", "worker-3"))
_FIELDS = frozenset((
    "schema_version",
    "protected_root",
    "account_id",
    "device_id",
    "boot_id",
    "assignment_id",
    "worker_name",
    "model_id",
    "model_revision",
    "manifest_fingerprint",
    "listen_ip",
    "listen_port",
    "clock_uncertainty_seconds",
    "certificate_path",
    "private_key_path",
    "cohort_ca_path",
    "snapshot_verification_key_path",
    "signed_snapshot_path",
    "artifact_directory",
    "acceptor_directory",
    "status_report_path",
))
_CREDENTIAL_FIELDS = (
    "certificate_path",
    "private_key_path",
    "cohort_ca_path",
    "snapshot_verification_key_path",
    "signed_snapshot_path",
)


class WorkerConfigError(ValueError):
    """A worker configuration or protected path is invalid."""


@dataclass(frozen=True)
class SecureWorkerConfig:
    protected_root: str
    account_id: str
    device_id: str
    boot_id: str
    assignment_id: str
    worker_name: str
    model_id: str
    model_revision: str
    manifest_fingerprint: str
    listen_ip: str
    listen_port: int
    clock_uncertainty_seconds: float
    certificate_path: str
    private_key_path: str
    cohort_ca_path: str
    snapshot_verification_key_path: str
    signed_snapshot_path: str
    artifact_directory: str
    acceptor_directory: str
    status_report_path: str

    @property
    def endpoint(self) -> str:
        return f"{self.listen_ip}:{self.listen_port}"


def _pairs_without_duplicates(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise WorkerConfigError("worker JSON contains a duplicate key")
        result[key] = value
    return result


def _reject_constant(_value):
    raise WorkerConfigError("worker JSON contains a non-finite number")


def _require_string(values, name, *, maximum=256):
    value = values.get(name)
    if type(value) is not str or not value or len(value) > maximum:
        raise WorkerConfigError(f"{name} must be a bounded string")
    if any(ord(char) < 0x20 or ord(char) == 0x7f for char in value):
        raise WorkerConfigError(f"{name} contains a control character")
    return value


def _absolute_path(values, name):
    value = _require_string(values, name, maximum=MAX_PATH_CHARS)
    if "\x00" in value:
        raise WorkerConfigError(f"{name} is not a valid absolute path")
    path = Path(value)
    if not path.is_absolute() or ".." in path.parts:
        raise WorkerConfigError(f"{name} must be absolute and contain no parent traversal")
    return path


def _beneath(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return path != root
    except ValueError:
        return False


def parse_config_bytes(raw: bytes, *, config_path: str | os.PathLike) -> SecureWorkerConfig:
    """Parse closed-schema JSON and bind every protected path to its root."""
    if type(raw) is not bytes or not 1 <= len(raw) <= MAX_CONFIG_BYTES:
        raise WorkerConfigError("worker configuration exceeds its byte bound")
    config_file = Path(config_path)
    if not config_file.is_absolute() or not config_file.name:
        raise WorkerConfigError("configuration path must be absolute")
    try:
        root = config_file.parent.resolve(strict=True)
    except OSError:
        raise WorkerConfigError("protected configuration root is unavailable") from None
    if config_file.parent.resolve(strict=True) != root:
        raise WorkerConfigError("configuration root is invalid")
    try:
        text = raw.decode("utf-8", errors="strict")
        values = json.loads(text, object_pairs_hook=_pairs_without_duplicates,
                            parse_constant=_reject_constant)
    except WorkerConfigError:
        raise
    except (UnicodeError, ValueError, TypeError, RecursionError):
        raise WorkerConfigError("worker configuration is not valid strict JSON") from None
    if type(values) is not dict or set(values) != _FIELDS:
        raise WorkerConfigError("worker configuration has unknown or missing fields")
    if type(values["schema_version"]) is not int or values["schema_version"] != 1:
        raise WorkerConfigError("unsupported worker configuration version")

    configured_root = _absolute_path(values, "protected_root")
    if configured_root != root:
        raise WorkerConfigError("configuration file must be directly inside protected_root")

    ids = {}
    for name, prefix in _ID_PREFIXES.items():
        value = _require_string(values, name)
        if not re.fullmatch(rf"{prefix}_[0-9a-f]{{32}}", value, re.ASCII):
            raise WorkerConfigError(f"{name} has an invalid typed identifier")
        ids[name] = value
    boot_id = _require_string(values, "boot_id")
    if not _HEX32.fullmatch(boot_id):
        raise WorkerConfigError("boot_id has an invalid typed identifier")

    worker_name = _require_string(values, "worker_name", maximum=16)
    if worker_name not in _WORKERS:
        raise WorkerConfigError("worker_name is outside the fixed three-stage assignment")
    model_id = _require_string(values, "model_id", maximum=128)
    model_revision = _require_string(values, "model_revision", maximum=64)
    if model_id != MODEL_ID or model_revision != MODEL_REVISION:
        raise WorkerConfigError("only the pinned tiny-model revision is supported")
    fingerprint = _require_string(values, "manifest_fingerprint", maximum=64)
    if not _HEX64.fullmatch(fingerprint):
        raise WorkerConfigError("manifest_fingerprint must be lowercase SHA-256 hex")

    listen_ip = _require_string(values, "listen_ip", maximum=15)
    try:
        address = ipaddress.IPv4Address(listen_ip)
    except ipaddress.AddressValueError:
        raise WorkerConfigError("listen_ip must be a numeric IPv4 literal") from None
    allowed_networks = (ipaddress.IPv4Network("10.0.0.0/8"),
                        ipaddress.IPv4Network("172.16.0.0/12"),
                        ipaddress.IPv4Network("192.168.0.0/16"))
    if (str(address) != listen_ip or address.is_unspecified or address.is_multicast
            or address.is_reserved
            or not (address.is_loopback or any(address in n for n in allowed_networks))):
        raise WorkerConfigError("listen_ip must be one canonical private or loopback IPv4 address")
    port = values.get("listen_port")
    if type(port) is not int or not 1 <= port <= 65535:
        raise WorkerConfigError("listen_port must be an explicit TCP port from 1 through 65535")

    uncertainty = values.get("clock_uncertainty_seconds")
    if (type(uncertainty) not in (int, float) or not math.isfinite(uncertainty)
            or not 0 < uncertainty <= MAX_CLOCK_UNCERTAINTY_SECONDS):
        raise WorkerConfigError("clock uncertainty must be explicit, finite, positive and within C0 policy")

    protected_paths = {}
    for name in _CREDENTIAL_FIELDS:
        path = _absolute_path(values, name)
        if not _beneath(path, root):
            raise WorkerConfigError(f"{name} must remain below protected_root")
        protected_paths[name] = str(path)
    if len(set(protected_paths.values())) != len(protected_paths):
        raise WorkerConfigError("credential and policy paths must be distinct")

    artifact_directory = _absolute_path(values, "artifact_directory")
    if (_beneath(artifact_directory, root) or _beneath(root, artifact_directory)
            or artifact_directory == root):
        raise WorkerConfigError("model artifacts must be separate from the protected credential root")
    acceptor_directory = _absolute_path(values, "acceptor_directory")
    if len(os.fsencode(acceptor_directory)) > MAX_ACCEPTOR_DIRECTORY_BYTES:
        raise WorkerConfigError("acceptor directory path exceeds the Unix socket bound")
    report_path = _absolute_path(values, "status_report_path")
    if report_path.parent != root:
        raise WorkerConfigError("status_report_path must be a direct protected-root child")
    config_control_path = root / config_file.name
    all_explicit_paths = set(protected_paths.values()) | {
        str(config_control_path), str(artifact_directory), str(acceptor_directory),
        str(report_path),
    }
    if len(all_explicit_paths) != len(protected_paths) + 4:
        raise WorkerConfigError("config, credential, artifact, acceptor and report paths must be distinct")

    return SecureWorkerConfig(
        protected_root=str(root), account_id=ids["account_id"],
        device_id=ids["device_id"], boot_id=boot_id,
        assignment_id=ids["assignment_id"], worker_name=worker_name,
        model_id=model_id, model_revision=model_revision,
        manifest_fingerprint=fingerprint, listen_ip=listen_ip,
        listen_port=port, clock_uncertainty_seconds=float(uncertainty),
        certificate_path=protected_paths["certificate_path"],
        private_key_path=protected_paths["private_key_path"],
        cohort_ca_path=protected_paths["cohort_ca_path"],
        snapshot_verification_key_path=protected_paths["snapshot_verification_key_path"],
        signed_snapshot_path=protected_paths["signed_snapshot_path"],
        artifact_directory=str(artifact_directory),
        acceptor_directory=str(acceptor_directory),
        status_report_path=str(report_path))


def load_worker_config(config_path: str | os.PathLike) -> SecureWorkerConfig:
    """Read a 0600 config under a 0700 Linux root without following links."""
    path = Path(config_path)
    if not path.is_absolute():
        raise WorkerConfigError("configuration path must be absolute")
    if (os.name != "posix" or not hasattr(os, "O_NOFOLLOW")
            or not hasattr(os, "geteuid")):
        raise WorkerConfigError("the secure worker requires Linux/POSIX protected-file support")
    from steamboat_security.files import safe_read

    try:
        raw = safe_read(path, root=path.parent, expected_uid=os.geteuid(),
                        max_bytes=MAX_CONFIG_BYTES)
    except Exception as error:
        raise WorkerConfigError("configuration file or protected root failed owner/mode validation") from error
    return parse_config_bytes(raw, config_path=path)


def validate_readonly_artifacts(directory: str | os.PathLike) -> Path:
    """Require a kernel read-only mount for every entry; reject links/specials."""
    root = Path(directory)
    if not root.is_absolute():
        raise WorkerConfigError("artifact directory must be absolute")
    try:
        current = Path(root.anchor)
        for part in root.parts[1:]:
            current = current / part
            if stat.S_ISLNK(current.lstat().st_mode):
                raise WorkerConfigError("artifact path contains a symlink")
        root = root.resolve(strict=True)
        root_info = root.lstat()
    except OSError:
        raise WorkerConfigError("artifact directory is unavailable") from None
    if not stat.S_ISDIR(root_info.st_mode) or stat.S_ISLNK(root_info.st_mode):
        raise WorkerConfigError("artifact root must be a real directory")

    readonly_flag = getattr(os, "ST_RDONLY", None)
    statvfs = getattr(os, "statvfs", None)
    if (type(readonly_flag) is not int or readonly_flag <= 0
            or not callable(statvfs)):
        raise WorkerConfigError("Linux does not expose a read-only mount flag")

    def require_readonly_mount(path):
        try:
            flags = statvfs(path).f_flag
        except OSError:
            raise WorkerConfigError("artifact mount state could not be inspected") from None
        if not flags & readonly_flag:
            raise WorkerConfigError("model artifacts must be on a kernel read-only mount")

    require_readonly_mount(root)

    def fail_walk(error):
        raise WorkerConfigError("artifact tree could not be inspected without following links") from error

    for parent, directories, files in os.walk(
            root, topdown=True, onerror=fail_walk, followlinks=False):
        parent_path = Path(parent)
        try:
            parent_info = parent_path.lstat()
        except OSError:
            raise WorkerConfigError("artifact directory changed during validation") from None
        require_readonly_mount(parent_path)
        if not stat.S_IMODE(parent_info.st_mode) & 0o555:
            raise WorkerConfigError("artifact directories must be searchable")
        if not os.access(parent_path, os.R_OK | os.X_OK):
            raise WorkerConfigError("artifact directories must be readable and searchable")
        for name in tuple(directories) + tuple(files):
            path = parent_path / name
            try:
                info = path.lstat()
            except OSError:
                raise WorkerConfigError("artifact tree changed during validation") from None
            if stat.S_ISLNK(info.st_mode):
                raise WorkerConfigError("artifact tree must not contain symlinks")
            mode = stat.S_IMODE(info.st_mode)
            require_readonly_mount(path)
            if stat.S_ISDIR(info.st_mode):
                if not mode & 0o555:
                    raise WorkerConfigError("artifact directories must be searchable")
                if not os.access(path, os.R_OK | os.X_OK):
                    raise WorkerConfigError("artifact directories must be readable and searchable")
            elif stat.S_ISREG(info.st_mode):
                if not mode & 0o444 or not os.access(path, os.R_OK):
                    raise WorkerConfigError("artifact files must be readable")
            else:
                raise WorkerConfigError("artifact tree contains a non-regular file")
    return root
