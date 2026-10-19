"""Closed child config and owned selected-root binding for fixed C2 role children.

This module does not launch a runtime or establish readiness. Child config is
only a locator/declaration: the opened RootGenerationStore and C2 loader must
re-verify the selected signed authority before callers use returned materials.
"""
from __future__ import annotations

import json
import os
import threading
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import PurePosixPath
from cryptography.hazmat.primitives import serialization

from steamboat_security.channel_policy import _verification_key
from steamboat_security.clock import Clock
from steamboat_security.codec import canonical_json
from steamboat_security.errors import CredentialError, SnapshotError, StorageError
from steamboat_security.root_transition_launch import (
    RoleLaunchSpec, parse_role_launch_spec, role_launch_document,
)
from steamboat_security.root_transition_storage import RootGenerationStore

MAX_C2_CHILD_CONFIG_BYTES = 16 * 1024
MAX_OPERATOR_PUBLIC_KEY_BYTES = 4 * 1024
_PROFILE = "c2-local-compute-v2"
_FIELDS = frozenset({
    "version", "profile", "role", "selected_root", "protected_root",
    "configuration_path", "launch_spec", "operator_verification_key_pem",
})
_ROLE_TO_SPEC = {"host": "host", "coordinator": "personal_coordinator"}


def _path(value: object, name: str) -> str:
    if (type(value) is not str or not value or len(value) > 4096
            or "\x00" in value or "\\" in value or "//" in value):
        raise CredentialError(f"C2 child {name} is invalid")
    path = PurePosixPath(value)
    if (not path.is_absolute() or str(path) != value or value == "/"
            or any(part in (".", "..") for part in path.parts)):
        raise CredentialError(f"C2 child {name} must be a normalized absolute POSIX path")
    return value


def _validate_document(value: object) -> tuple[RoleLaunchSpec, bytes | None]:
    if type(value) is not dict or set(value) != _FIELDS:
        raise CredentialError("C2 child config has unknown or missing fields")
    if type(value["version"]) is not int or value["version"] != 2:
        raise CredentialError("C2 child config version is unsupported")
    if type(value["profile"]) is not str or value["profile"] != _PROFILE:
        raise CredentialError("C2 child config profile is unsupported")
    role = value["role"]
    if type(role) is not str or role not in _ROLE_TO_SPEC:
        raise CredentialError("C2 child role is unsupported")
    selected_root = _path(value["selected_root"], "selected root")
    protected_root = _path(value["protected_root"], "protected root")
    configuration_path = _path(value["configuration_path"], "configuration path")
    try:
        relative = PurePosixPath(configuration_path).relative_to(PurePosixPath(protected_root))
    except ValueError as error:
        raise CredentialError("C2 child configuration is outside its protected root") from error
    if not relative.parts:
        raise CredentialError("C2 child configuration path names the protected root")
    try:
        spec = parse_role_launch_spec(value["launch_spec"])
    except (TypeError, ValueError) as error:
        raise CredentialError("C2 child launch specification is invalid") from error
    if spec.role != _ROLE_TO_SPEC[role]:
        raise CredentialError("C2 child role differs from its selected launch spec")

    key_value = value["operator_verification_key_pem"]
    if role == "coordinator":
        if key_value is not None:
            raise CredentialError("coordinator child config must not contain an operator key")
        key_pem = None
    else:
        if type(key_value) is not str:
            raise CredentialError("host child config requires operator public PEM text")
        try:
            key_pem = key_value.encode("ascii", "strict")
        except UnicodeEncodeError as error:
            raise CredentialError("operator public PEM must be ASCII") from error
        if not 1 <= len(key_pem) <= MAX_OPERATOR_PUBLIC_KEY_BYTES:
            raise CredentialError("operator public PEM exceeds its 4 KiB bound")
        try:
            public_key = _verification_key(key_pem)  # Existing policy requires ECDSA P-256.
        except SnapshotError as error:
            raise CredentialError("operator public PEM is not an accepted P-256 key") from error
        canonical_public_pem = public_key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        if key_pem != canonical_public_pem:
            raise CredentialError("operator PEM must be exactly one canonical public key")
    try:
        if len(canonical_json(value)) > MAX_C2_CHILD_CONFIG_BYTES:
            raise CredentialError("C2 child config exceeds its 16 KiB bound")
    except (TypeError, ValueError) as error:
        raise CredentialError("C2 child config is not canonical JSON data") from error
    return spec, key_pem


@dataclass(frozen=True)
class C2ChildConfig:
    """Validated closed data; it is not selected-root or process authority."""
    role: str
    selected_root: str
    protected_root: str
    configuration_path: str
    launch_spec: RoleLaunchSpec
    operator_verification_key_pem: bytes | None = None

    def to_document(self) -> dict:
        value = {
            "version": 2, "profile": _PROFILE, "role": self.role,
            "selected_root": self.selected_root,
            "protected_root": self.protected_root,
            "configuration_path": self.configuration_path,
            "launch_spec": role_launch_document(self.launch_spec),
            "operator_verification_key_pem": (
                None if self.operator_verification_key_pem is None
                else self.operator_verification_key_pem.decode("ascii", "strict")),
        }
        _validate_document(value)
        return value


def build_c2_child_config(*, role: str, selected_root: str,
                          protected_root: str, configuration_path: str,
                          launch_spec: RoleLaunchSpec,
                          operator_verification_key_pem: bytes | None = None) -> dict:
    """Build host/coordinator v2 config from exact trusted launch inputs."""
    if type(launch_spec) is not RoleLaunchSpec:
        raise TypeError("C2 child config requires an exact RoleLaunchSpec")
    if role == "host":
        if type(operator_verification_key_pem) is not bytes:
            raise CredentialError("host child config requires operator public PEM bytes")
        try:
            key_text = operator_verification_key_pem.decode("ascii", "strict")
        except UnicodeDecodeError as error:
            raise CredentialError("operator public PEM must be ASCII") from error
    elif role == "coordinator":
        if operator_verification_key_pem is not None:
            raise CredentialError("coordinator child config must not carry operator key bytes")
        key_text = None
    else:
        raise CredentialError("C2 child role is unsupported")
    value = {
        "version": 2, "profile": _PROFILE, "role": role,
        "selected_root": selected_root, "protected_root": protected_root,
        "configuration_path": configuration_path,
        "launch_spec": role_launch_document(launch_spec),
        "operator_verification_key_pem": key_text,
    }
    _validate_document(value)
    return value


def parse_c2_child_config(value: dict | bytes) -> C2ChildConfig:
    """Parse a document object or its canonical JSON bytes with exact fields."""
    if type(value) is bytes:
        if not 1 <= len(value) <= MAX_C2_CHILD_CONFIG_BYTES:
            raise CredentialError("C2 child config exceeds its 16 KiB bound")
        encoded = value
        try:
            value = json.loads(value.decode("utf-8", "strict"),
                object_pairs_hook=_unique_pairs, parse_constant=_reject_number,
                parse_float=_reject_number)
        except CredentialError:
            raise
        except (UnicodeError, ValueError, TypeError, RecursionError) as error:
            raise CredentialError("C2 child config JSON is malformed") from error
        if canonical_json(value) != encoded:
            raise CredentialError("C2 child config bytes must be canonical JSON")
    if type(value) is not dict:
        raise CredentialError("C2 child config must be an exact dictionary")
    spec, key_pem = _validate_document(value)
    return C2ChildConfig(value["role"], value["selected_root"],
        value["protected_root"], value["configuration_path"], spec, key_pem)


def _unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise CredentialError("C2 child config contains duplicate JSON fields")
        result[key] = value
    return result


def _reject_number(_value):
    raise CredentialError("C2 child config numbers must be exact integers")


class C2ChildBinding:
    """Own the selected-root FD store for the loaded C2 binding lifetime."""
    def __init__(self, root_store, binding):
        self._root_store = root_store
        self._binding = binding
        self._lock = threading.Lock()
        self._state = "open"
        self._active_leases = 0
        self._invalidation_done = False
        self._cleanup_claimed = False
        self._cleanup_error = None

    @contextmanager
    def borrow(self):
        """Lease the binding while using it; close never waits for a lease."""
        with self._lock:
            if self._state != "open":
                raise CredentialError("C2 child binding owner is not open")
            self._active_leases += 1
        try:
            yield self._binding
        finally:
            cleanup = None
            with self._lock:
                self._active_leases -= 1
                cleanup = self._claim_cleanup_locked()
            self._run_cleanup(cleanup)

    def assert_live(self):
        with self.borrow() as binding:
            return binding.assert_live()

    def _claim_cleanup_locked(self):
        if (self._state == "closing" and self._invalidation_done
                and self._active_leases == 0 and not self._cleanup_claimed):
            self._cleanup_claimed = True
            return True
        return False

    def _run_cleanup(self, claimed):
        if not claimed:
            return
        error = None
        try:
            self._root_store.close()
        except BaseException as caught:
            error = caught
        with self._lock:
            self._cleanup_error = error
            self._state = "faulted" if error else "closed"
        if error:
            raise StorageError("C2 child root descriptors did not close cleanly") from error

    def close(self):
        with self._lock:
            if self._state in ("closed", "closing", "faulted"):
                return
            self._state = "closing"
        error = None
        try:
            self._binding.invalidate("C2 child binding owner closed")
        except BaseException as caught:
            error = caught
        cleanup = None
        with self._lock:
            self._invalidation_done = True
            cleanup = self._claim_cleanup_locked()
        try:
            self._run_cleanup(cleanup)
        except StorageError:
            if error is None:
                raise
        if error:
            raise StorageError("C2 child binding invalidation notification failed") from error

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        self.close()


def open_c2_child_binding(config: C2ChildConfig, *, clock: Clock,
                          expected_uid: int) -> C2ChildBinding:
    """Open selected durable storage and independently run the actual C2 loader."""
    if type(config) is not C2ChildConfig:
        raise TypeError("C2 child loading requires an exact parsed C2ChildConfig")
    # Re-validate frozen dataclass construction instead of trusting its fields.
    config = parse_c2_child_config(config.to_document())
    if type(clock) is not Clock or type(expected_uid) is not int:
        raise TypeError("C2 child loading requires an exact Clock and UID")
    if os.name != "posix" or not hasattr(os, "geteuid"):
        raise StorageError("C2 child bindings require protected POSIX root storage")
    if expected_uid != os.geteuid():
        raise StorageError("C2 child expected UID differs from current process")
    root_store = RootGenerationStore(config.selected_root, expected_uid=expected_uid)
    try:
        if config.role == "host":
            from steamboat_security.root_c2_runtime import load_c2_host_runtime_binding
            binding = load_c2_host_runtime_binding(
                root_store=root_store, clock=clock, expected_launch_spec=config.launch_spec,
                configuration_path=config.configuration_path,
                configuration_root=config.protected_root, expected_uid=expected_uid,
                operator_verification_key_pem=config.operator_verification_key_pem)
        else:
            from steamboat_security.root_c2_coordinator import load_c2_personal_coordinator_binding
            binding = load_c2_personal_coordinator_binding(
                root_store=root_store, clock=clock, expected_launch_spec=config.launch_spec,
                configuration_path=config.configuration_path,
                configuration_root=config.protected_root, expected_uid=expected_uid)
        return C2ChildBinding(root_store, binding)
    except BaseException:
        root_store.close()
        raise
