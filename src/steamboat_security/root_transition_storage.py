"""Durable, fail-closed storage primitives for selected root generations.

This module does not authorize, activate, bootstrap, or claim readiness. The
caller supplies the trusted validation callback; durable selection remains
blocked whenever a transaction marker is present or storage is ambiguous.
"""

from __future__ import annotations

import base64
import hashlib
import inspect
import json
import os
import re
import stat
from contextlib import contextmanager
from dataclasses import dataclass, replace
from pathlib import Path
from types import MappingProxyType
from typing import Callable, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from .codec import canonical_json
from .errors import SnapshotError, StorageError
from .certificates import public_key_sha256, verify_ca
from .snapshot import SnapshotStore, _validate_payload, canonical_policy_digest, signing_public_key

MAX_SELECTOR_BYTES = 16 * 1024
MAX_ARTIFACT_BYTES = 64 * 1024
MAX_CA_BYTES = 16 * 1024
MAX_SIGNER_BYTES = 4 * 1024
MAX_ARTIFACT_TOTAL_BYTES = 512 * 1024
MAX_ARTIFACTS = 13
MAX_GENERATIONS = 4
MAX_POLICY_SNAPSHOTS = 64
MAX_POLICY_TOTAL_BYTES = 4 * 1024 * 1024
MAX_POLICY_BYTES = 64 * 1024
_HEX64 = re.compile(r"^[0-9a-f]{64}$", re.ASCII)
_SELECTOR_FIELDS = frozenset({
    "schema_version", "purpose", "generation_sha256",
    "activation_manifest_sha256", "policy_revision", "policy_digest",
    "active_policy_snapshot_sha256",
    "artifact_sha256",
})
_DESCRIPTOR_FIELDS = frozenset({
    "schema_version", "purpose", "generation_sha256",
    "activation_manifest_sha256", "artifact_sha256",
})
_PENDING_FIELDS = frozenset({
    "schema_version", "purpose", "old_selector_sha256",
    "new_selector_sha256", "new_generation_sha256",
    "active_policy_snapshot_sha256",
})
PURPOSE = "root_generation_selector"
DESCRIPTOR_PURPOSE = "root_generation_descriptor"
PENDING_PURPOSE = "root_generation_pending"
CORE_ARTIFACTS = frozenset({
    "activation_manifest.json", "policy_snapshot.json",
    "ca_certificate.pem", "snapshot_signer_public.pem",
})
ARTIFACT_NAMES = frozenset({
    "activation_manifest.json", "policy_snapshot.json", "ca_certificate.pem",
    "snapshot_signer_public.pem", "credential_bundle.json", "issuance_manifest.json",
    "final_approval.json", "preparation_intent.json", "public_csr_bundle.json",
    "old_possession_proofs.json", "retirement_receipt.json",
    "old_launch_specs.json", "new_launch_specs.json",
})


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise StorageError("root-generation JSON contains a duplicate field")
        result[key] = value
    return result


def _reject_constant(_value):
    raise StorageError("root-generation JSON contains a non-finite number")


def _reject_float(_value):
    raise StorageError("root-generation JSON numeric fields must be integers")


def _hash(value, field: str) -> str:
    if type(value) is not str or not _HEX64.fullmatch(value):
        raise StorageError(f"root-generation {field} must be lowercase SHA-256 hex")
    return value


@dataclass(frozen=True)
class RootGenerationSelector:
    generation_sha256: str
    activation_manifest_sha256: str
    policy_revision: int
    policy_digest: str
    active_policy_snapshot_sha256: str
    artifact_sha256: Mapping[str, str]


@dataclass(frozen=True)
class SelectedRootGeneration:
    """Verified immutable bytes; this object is not readiness or activation proof."""
    selector: RootGenerationSelector
    artifacts: Mapping[str, bytes]
    selector_sha256: str
    active_policy_snapshot: bytes


def parse_root_generation_selector(encoded: bytes) -> RootGenerationSelector:
    """Parse a closed, canonical 16 KiB generation selector."""
    if type(encoded) is not bytes or not 1 <= len(encoded) <= MAX_SELECTOR_BYTES:
        raise StorageError("root-generation selector exceeds its 16 KiB bound")
    try:
        raw = json.loads(encoded.decode("utf-8", errors="strict"),
                         object_pairs_hook=_pairs, parse_constant=_reject_constant,
                         parse_float=_reject_float)
    except StorageError:
        raise
    except (UnicodeError, ValueError, TypeError, RecursionError) as error:
        raise StorageError("root-generation selector is malformed") from error
    if type(raw) is not dict or set(raw) != _SELECTOR_FIELDS:
        raise StorageError("root-generation selector has unknown or missing fields")
    if type(raw["schema_version"]) is not int or raw["schema_version"] != 2:
        raise StorageError("root-generation selector version is invalid")
    if type(raw["purpose"]) is not str or raw["purpose"] != PURPOSE:
        raise StorageError("root-generation selector purpose is invalid")
    generation = _hash(raw["generation_sha256"], "generation ID")
    activation = _hash(raw["activation_manifest_sha256"], "activation manifest hash")
    revision = raw["policy_revision"]
    if type(revision) is not int or revision <= 0:
        raise StorageError("root-generation policy revision must be a positive exact integer")
    policy_digest = _hash(raw["policy_digest"], "policy digest")
    active_policy = _hash(raw["active_policy_snapshot_sha256"], "active policy snapshot hash")
    artifacts = raw["artifact_sha256"]
    if type(artifacts) is not dict or not len(CORE_ARTIFACTS) <= len(artifacts) <= MAX_ARTIFACTS:
        raise StorageError("root-generation artifact count is outside its bound")
    if not CORE_ARTIFACTS.issubset(artifacts):
        raise StorageError("root-generation selector omits a required public artifact")
    normalized = {}
    for name, digest in artifacts.items():
        if type(name) is not str or name not in ARTIFACT_NAMES:
            raise StorageError("root-generation selector contains an unknown artifact name")
        normalized[name] = _hash(digest, f"{name} hash")
    if canonical_json(raw) != encoded:
        raise StorageError("root-generation selector is not canonical JSON")
    return RootGenerationSelector(generation, activation, revision, policy_digest, active_policy,
                                  MappingProxyType(dict(sorted(normalized.items()))))


def root_generation_selector_document(selector: RootGenerationSelector) -> dict:
    if type(selector) is not RootGenerationSelector:
        raise StorageError("selector document requires an exact selector")
    raw = {
        "schema_version": 2, "purpose": PURPOSE,
        "generation_sha256": selector.generation_sha256,
        "activation_manifest_sha256": selector.activation_manifest_sha256,
        "policy_revision": selector.policy_revision,
        "policy_digest": selector.policy_digest,
        "active_policy_snapshot_sha256": selector.active_policy_snapshot_sha256,
        "artifact_sha256": dict(selector.artifact_sha256),
    }
    checked = parse_root_generation_selector(canonical_json(raw))
    return {
        "schema_version": 2, "purpose": PURPOSE,
        "generation_sha256": checked.generation_sha256,
        "activation_manifest_sha256": checked.activation_manifest_sha256,
        "policy_revision": checked.policy_revision,
        "policy_digest": checked.policy_digest,
        "active_policy_snapshot_sha256": checked.active_policy_snapshot_sha256,
        "artifact_sha256": dict(checked.artifact_sha256),
    }


def _candidate_bundle(selector: RootGenerationSelector, bundle) -> dict[str, bytes]:
    root_generation_selector_document(selector)  # Revalidate direct dataclass construction.
    if type(bundle) is not dict or set(bundle) != set(selector.artifact_sha256):
        raise StorageError("root-generation bundle does not exactly match selector artifacts")
    total = 0
    result = {}
    for name, data in bundle.items():
        if name not in ARTIFACT_NAMES or type(data) is not bytes or not data:
            raise StorageError("root-generation artifact name or byte content is invalid")
        limit = (MAX_CA_BYTES if name == "ca_certificate.pem" else
                 MAX_SIGNER_BYTES if name == "snapshot_signer_public.pem" else
                 MAX_ARTIFACT_BYTES)
        if len(data) > limit:
            raise StorageError(f"root-generation artifact {name} exceeds its size bound")
        total += len(data)
        if total > MAX_ARTIFACT_TOTAL_BYTES:
            raise StorageError("root-generation artifact bundle exceeds 512 KiB")
        if hashlib.sha256(data).hexdigest() != selector.artifact_sha256[name]:
            raise StorageError(f"root-generation artifact {name} hash differs from selector")
        result[name] = data
    if hashlib.sha256(result["activation_manifest.json"]).hexdigest() != selector.activation_manifest_sha256:
        raise StorageError("activation manifest bytes differ from its independent selector pin")
    return dict(sorted(result.items()))


def _validate_callback(callback, selector, bundle, active_policy_snapshot) -> None:
    if not callable(callback):
        raise TypeError("root-generation validation callback is required")
    frozen_bundle = MappingProxyType(dict(bundle))
    result = callback(selector, frozen_bundle, active_policy_snapshot)
    if inspect.isawaitable(result):
        close = getattr(result, "close", None)
        if callable(close):
            close()
        raise TypeError("root-generation validation callback must be synchronous")
    if result is not None:
        raise TypeError("root-generation validation callback must return None")


def _authenticate_policy_snapshot(encoded: bytes, *, ca_pem: bytes,
                                  signer_pem: bytes, sample):
    """Verify signed policy structure without asserting that it is currently live."""
    from .certificates import verify_ca
    if type(encoded) is not bytes or not 1 <= len(encoded) <= MAX_POLICY_BYTES:
        raise StorageError("active policy snapshot is malformed or oversized")
    try:
        envelope = json.loads(encoded.decode("utf-8", errors="strict"),
                              object_pairs_hook=_pairs,
                              parse_constant=_reject_constant, parse_float=_reject_float)
    except StorageError:
        raise
    except (UnicodeError, ValueError, TypeError, RecursionError) as error:
        raise StorageError("active policy snapshot envelope is malformed") from error
    if (type(envelope) is not dict or set(envelope) != {"payload", "signature"}
            or canonical_json(envelope) != encoded):
        raise StorageError("active policy snapshot envelope is not closed canonical JSON")
    signer = signing_public_key(signer_pem)
    ca = verify_ca(ca_pem, now=sample.wall, uncertainty_seconds=sample.uncertainty)
    if public_key_sha256(ca.public_key()) == public_key_sha256(signer):
        raise StorageError("snapshot signing key reuses selected CA authority")
    signature_text = envelope["signature"]
    if type(signature_text) is not str or len(signature_text) > 128:
        raise StorageError("active policy signature is malformed")
    try:
        signature = base64.b64decode(signature_text, validate=True)
        signer.verify(signature, canonical_json(envelope["payload"]),
                      ec.ECDSA(hashes.SHA256()))
    except (ValueError, InvalidSignature) as error:
        raise StorageError("active policy signature is invalid") from error
    try:
        credentials, grants = _validate_payload(
            envelope["payload"], prohibited_key_hashes=(
                public_key_sha256(ca.public_key()), public_key_sha256(signer)))
    except SnapshotError as error:
        raise StorageError("active policy schema is invalid") from error
    return envelope["payload"], credentials, grants


def _private_file(info, uid: int, label: str) -> None:
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != uid
            or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1):
        raise StorageError(f"{label} must be an owner 0600 regular one-link file")


def _private_directory(info, uid: int, label: str) -> None:
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != uid
            or stat.S_IMODE(info.st_mode) != 0o700):
        raise StorageError(f"{label} must be an owner 0700 directory")


def _open_protected_root(root: str | os.PathLike, uid: int) -> int:
    if os.name != "posix" or not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "geteuid"):
        raise StorageError("root-generation storage requires POSIX no-follow support")
    if type(uid) is not int or uid != os.geteuid():
        raise StorageError("root-generation owner UID must equal the daemon effective UID")
    try:
        path = Path(os.path.abspath(os.fspath(root)))
    except (TypeError, ValueError, OSError) as error:
        raise StorageError("root-generation storage root path is invalid") from error
    if not path.is_absolute() or path == Path(os.sep):
        raise StorageError("filesystem root cannot be root-generation storage")
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    descriptor = os.open(os.sep, flags)
    try:
        for index, component in enumerate(path.parts[1:]):
            child = os.open(component, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
            if index == len(path.parts[1:]) - 1:
                _private_directory(os.fstat(descriptor), uid, "root-generation storage root")
        return descriptor
    except OSError as error:
        os.close(descriptor)
        raise StorageError("root-generation storage root path is unsafe or unavailable") from error
    except BaseException:
        os.close(descriptor)
        raise


def _open_dir_at(parent_fd: int, name: str, uid: int, label: str) -> int:
    fd = None
    try:
        fd = os.open(name, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | os.O_NOFOLLOW
                     | getattr(os, "O_CLOEXEC", 0), dir_fd=parent_fd)
        _private_directory(os.fstat(fd), uid, label)
        return fd
    except StorageError:
        if fd is not None:
            os.close(fd)
        raise
    except OSError as error:
        if fd is not None:
            os.close(fd)
        raise StorageError(f"{label} is missing or unsafe") from error


def _open_read_file(dir_fd: int, name: str, uid: int, max_bytes: int, label: str) -> bytes:
    try:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_NONBLOCK", 0)
                     | getattr(os, "O_CLOEXEC", 0), dir_fd=dir_fd)
        try:
            _private_file(os.fstat(fd), uid, label)
            chunks, total = [], 0
            while True:
                part = os.read(fd, min(64 * 1024, max_bytes + 1 - total))
                if not part:
                    break
                total += len(part)
                if total > max_bytes:
                    raise StorageError(f"{label} exceeds its configured bound")
                chunks.append(part)
            return b"".join(chunks)
        finally:
            os.close(fd)
    except StorageError:
        raise
    except OSError as error:
        raise StorageError(f"{label} cannot be read safely") from error


class RootGenerationStore:
    """FD-relative immutable generation store with a fail-closed selector.

    Existing layout and initial selector must be provisioned by a separate
    trusted bootstrap. This class never bootstraps, rolls back, deletes a
    generation, or treats selected bytes as readiness/activation evidence.
    """

    def __init__(self, root: str | os.PathLike, *, expected_uid: int,
                 _fault_hook: Callable[[str], None] | None = None):
        self._uid = expected_uid
        self._root_fd = _open_protected_root(root, expected_uid)
        self._fault_hook = _fault_hook
        self._pending_faulted = False
        try:
            self._generations_fd = _open_dir_at(
                self._root_fd, "generations", expected_uid, "generation directory")
            self._policies_fd = _open_dir_at(
                self._root_fd, "policies", expected_uid, "active policy directory")
            # A concurrent writer may have a transaction tempfile present while
            # this instance is constructed. Check the stable protected entries
            # first, then wait for its flock before inspecting namespace contents.
            self._check_root_security()
            with self._lock(exclusive=False):
                pass
        except BaseException:
            if getattr(self, "_generations_fd", -1) >= 0:
                os.close(self._generations_fd)
                self._generations_fd = -1
            if getattr(self, "_policies_fd", -1) >= 0:
                os.close(self._policies_fd)
                self._policies_fd = -1
            os.close(self._root_fd)
            raise

    def close(self) -> None:
        if getattr(self, "_generations_fd", -1) >= 0:
            os.close(self._generations_fd)
            self._generations_fd = -1
        if getattr(self, "_policies_fd", -1) >= 0:
            os.close(self._policies_fd)
            self._policies_fd = -1
        if getattr(self, "_root_fd", -1) >= 0:
            os.close(self._root_fd)
            self._root_fd = -1

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        self.close()

    def _step(self, label: str) -> None:
        hook = self._fault_hook
        if hook is not None:
            hook(label)

    def _check_private_file(self, name: str, *, may_missing: bool):
        try:
            info = os.stat(name, dir_fd=self._root_fd, follow_symlinks=False)
        except FileNotFoundError:
            if may_missing:
                return False
            raise StorageError(f"required {name} is missing")
        _private_file(info, self._uid, name)
        return True

    def _check_root_names(self):
        names = set(os.listdir(self._root_fd))
        allowed = {"generations", "policies", "transition.lock", "selector.json", "pending.json"}
        if not names.issubset(allowed) or not {"generations", "policies", "transition.lock"}.issubset(names):
            raise StorageError("root-generation storage root has unexpected or missing entries")
        self._check_root_security()
        if "selector.json" in names:
            self._check_private_file("selector.json", may_missing=False)
        if "pending.json" in names:
            self._check_private_file("pending.json", may_missing=False)

    def _check_root_security(self):
        """Check stable root and lock inodes without inspecting transaction names."""
        root_info = os.fstat(self._root_fd)
        if (not stat.S_ISDIR(root_info.st_mode) or root_info.st_uid != self._uid
                or stat.S_IMODE(root_info.st_mode) != 0o700):
            raise StorageError("root-generation root ownership or mode changed")
        policies_fd = _open_dir_at(self._root_fd, "policies", self._uid, "active policy directory")
        os.close(policies_fd)
        generations_fd = _open_dir_at(self._root_fd, "generations", self._uid,
                                       "generation directory")
        os.close(generations_fd)
        self._check_private_file("transition.lock", may_missing=False)

    @contextmanager
    def _lock(self, *, exclusive: bool):
        import fcntl
        self._check_root_security()
        fd = None
        try:
            lock_info = os.stat("transition.lock", dir_fd=self._root_fd,
                                follow_symlinks=False)
            _private_file(lock_info, self._uid, "transition lock")
            fd = os.open("transition.lock", os.O_RDWR | os.O_NOFOLLOW
                         | getattr(os, "O_CLOEXEC", 0), dir_fd=self._root_fd)
            opened_info = os.fstat(fd)
            _private_file(opened_info, self._uid, "transition lock")
            if (opened_info.st_dev, opened_info.st_ino) != (lock_info.st_dev, lock_info.st_ino):
                raise StorageError("root-generation transition lock inode changed during open")
            fcntl.flock(fd, fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH)
            current_info = os.stat("transition.lock", dir_fd=self._root_fd,
                                   follow_symlinks=False)
            if (opened_info.st_dev, opened_info.st_ino) != (current_info.st_dev, current_info.st_ino):
                raise StorageError("root-generation transition lock inode changed while waiting")
        except StorageError:
            if fd is not None:
                os.close(fd)
            raise
        except OSError as error:
            if fd is not None:
                os.close(fd)
            raise StorageError("root-generation transition lock is unsafe or unavailable") from error
        try:
            self._check_root_names()
            yield
        finally:
            try:
                fcntl.flock(fd, fcntl.LOCK_UN)
            finally:
                os.close(fd)

    def _pending_exists(self) -> bool:
        try:
            os.stat("pending.json", dir_fd=self._root_fd, follow_symlinks=False)
            return True
        except FileNotFoundError:
            return False
        except OSError as error:
            raise StorageError("pending marker cannot be inspected") from error

    def _read_selector(self):
        encoded = _open_read_file(self._root_fd, "selector.json", self._uid,
                                  MAX_SELECTOR_BYTES, "root-generation selector")
        return encoded, parse_root_generation_selector(encoded)

    def _load_policy(self, digest: str) -> bytes:
        _hash(digest, "active policy digest")
        names = set(os.listdir(self._policies_fd))
        expected = {name for name in names if _HEX64.fullmatch(name[:-5])
                    and name.endswith(".json")}
        if (names != expected or len(names) > MAX_POLICY_SNAPSHOTS):
            raise StorageError("active policy directory names or count are ambiguous")
        total = 0
        for name in names:
            data = _open_read_file(self._policies_fd, name, self._uid,
                                   MAX_POLICY_BYTES, "active policy snapshot")
            total += len(data)
            if total > MAX_POLICY_TOTAL_BYTES:
                raise StorageError("active policy directory exceeds its aggregate bound")
        filename = f"{digest}.json"
        if filename not in names:
            raise StorageError("selected active policy snapshot is missing")
        encoded = _open_read_file(self._policies_fd, filename, self._uid,
                                  MAX_POLICY_BYTES, "selected active policy snapshot")
        if hashlib.sha256(encoded).hexdigest() != digest:
            raise StorageError("selected active policy snapshot hash mismatch")
        return encoded

    def _stage_policy(self, encoded: bytes) -> str:
        digest, names, total = self._check_policy_capacity(encoded)
        filename = f"{digest}.json"
        if filename in names:
            if self._load_policy(digest) != encoded:
                raise StorageError("active policy digest file contains different bytes")
            return digest
        self._write_new(self._policies_fd, filename, encoded,
                        label="active_policy", max_bytes=MAX_POLICY_BYTES)
        self._fsync(self._policies_fd, "active_policy.directory.fsync")
        return digest

    def _check_policy_capacity(self, encoded: bytes):
        if type(encoded) is not bytes or not 1 <= len(encoded) <= MAX_POLICY_BYTES:
            raise StorageError("active policy snapshot is empty or exceeds 64 KiB")
        digest = hashlib.sha256(encoded).hexdigest()
        names = set(os.listdir(self._policies_fd))
        expected = {name for name in names if _HEX64.fullmatch(name[:-5])
                    and name.endswith(".json")}
        if names != expected or len(names) > MAX_POLICY_SNAPSHOTS:
            raise StorageError("active policy directory names or count are ambiguous")
        total = 0
        for name in names:
            total += len(_open_read_file(self._policies_fd, name, self._uid,
                                         MAX_POLICY_BYTES, "active policy snapshot"))
        if total > MAX_POLICY_TOTAL_BYTES:
            raise StorageError("active policy directory exceeds its aggregate bound")
        filename = f"{digest}.json"
        if filename in names:
            if self._load_policy(digest) != encoded:
                raise StorageError("active policy digest file contains different bytes")
            return digest, names, total
        if len(names) >= MAX_POLICY_SNAPSHOTS or total + len(encoded) > MAX_POLICY_TOTAL_BYTES:
            raise StorageError("immutable active policy storage is full; garbage collection is disabled")
        return digest, names, total

    def _descriptor_bytes(self, selector: RootGenerationSelector) -> bytes:
        return canonical_json({
            "schema_version": 1, "purpose": DESCRIPTOR_PURPOSE,
            "generation_sha256": selector.generation_sha256,
            "activation_manifest_sha256": selector.activation_manifest_sha256,
            "artifact_sha256": dict(selector.artifact_sha256),
        })

    def _open_generation(self, generation: str):
        if type(generation) is not str or not _HEX64.fullmatch(generation):
            raise StorageError("generation directory identifier is invalid")
        return _open_dir_at(self._generations_fd, generation, self._uid,
                            "immutable generation directory")

    def _load_generation(self, selector: RootGenerationSelector) -> dict[str, bytes]:
        gen_fd = self._open_generation(selector.generation_sha256)
        try:
            entries = set(os.listdir(gen_fd))
            expected_names = set(selector.artifact_sha256) | {"descriptor.json"}
            if entries != expected_names:
                raise StorageError("immutable generation has missing or unexpected files")
            descriptor = _open_read_file(gen_fd, "descriptor.json", self._uid,
                                         MAX_SELECTOR_BYTES, "generation descriptor")
            if descriptor != self._descriptor_bytes(selector):
                raise StorageError("generation descriptor conflicts with selector pins")
            bundle = {}
            total = 0
            for name, digest in selector.artifact_sha256.items():
                limit = (MAX_CA_BYTES if name == "ca_certificate.pem" else
                         MAX_SIGNER_BYTES if name == "snapshot_signer_public.pem" else
                         MAX_ARTIFACT_BYTES)
                data = _open_read_file(gen_fd, name, self._uid, limit, f"artifact {name}")
                if not data or hashlib.sha256(data).hexdigest() != digest:
                    raise StorageError(f"immutable generation artifact {name} hash mismatch")
                total += len(data)
                if total > MAX_ARTIFACT_TOTAL_BYTES:
                    raise StorageError("immutable generation exceeds total artifact bound")
                bundle[name] = data
            if hashlib.sha256(bundle["activation_manifest.json"]).hexdigest() != selector.activation_manifest_sha256:
                raise StorageError("activation manifest differs from descriptor pin")
            return dict(sorted(bundle.items()))
        finally:
            os.close(gen_fd)

    def _generation_names(self) -> set[str]:
        names = set(os.listdir(self._generations_fd))
        if (len(names) > MAX_GENERATIONS
                or any(type(name) is not str or not _HEX64.fullmatch(name) for name in names)):
            raise StorageError("generation directory count or names are ambiguous")
        for name in names:
            fd = _open_dir_at(self._generations_fd, name, self._uid,
                              "immutable generation directory")
            os.close(fd)
        return names

    def read_selected(self, validate: Callable[[RootGenerationSelector,
                      Mapping[str, bytes], bytes], None]
                      ) -> SelectedRootGeneration:
        """Read exact selected bytes; no readiness or activation claim is made."""
        with self._lock(exclusive=False):
            if self._pending_faulted or self._pending_exists():
                raise StorageError("root-generation transaction is pending")
            self._generation_names()
            encoded, selector = self._read_selector()
            bundle = self._load_generation(selector)
            active_policy = self._load_policy(selector.active_policy_snapshot_sha256)
            _validate_callback(validate, selector, bundle, active_policy)
            return SelectedRootGeneration(selector, MappingProxyType(bundle),
                                          hashlib.sha256(encoded).hexdigest(), active_policy)

    def _write_new(self, dir_fd: int, name: str, data: bytes, *, label: str,
                   max_bytes: int) -> None:
        if type(data) is not bytes or not 1 <= len(data) <= max_bytes:
            raise StorageError(f"{label} content is empty or exceeds its bound")
        self._step(f"{label}.create")
        try:
            fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
                         | getattr(os, "O_CLOEXEC", 0), 0o600, dir_fd=dir_fd)
        except OSError as error:
            raise StorageError(f"{label} cannot be created exclusively") from error
        try:
            _private_file(os.fstat(fd), self._uid, label)
            self._step(f"{label}.write")
            view = memoryview(data)
            while view:
                count = os.write(fd, view)
                if count <= 0:
                    raise StorageError(f"{label} write made no progress")
                view = view[count:]
            self._step(f"{label}.fsync")
            os.fsync(fd)
        finally:
            os.close(fd)

    def _fsync(self, fd: int, label: str) -> None:
        self._step(label)
        os.fsync(fd)

    def _verify_existing_or_capacity(self, selector: RootGenerationSelector,
                                     bundle: dict[str, bytes]) -> bool:
        names = self._generation_names()
        gen = selector.generation_sha256
        if gen in names:
            actual = self._load_generation(selector)
            if actual != bundle:
                raise StorageError("generation ID already exists with different content")
            return True
        if len(names) >= MAX_GENERATIONS:
            raise StorageError("immutable generation storage is full; garbage collection is disabled")
        return False

    def _write_generation(self, selector: RootGenerationSelector,
                          bundle: dict[str, bytes]) -> None:
        generation = selector.generation_sha256
        self._step("generation.mkdir")
        try:
            os.mkdir(generation, 0o700, dir_fd=self._generations_fd)
        except OSError as error:
            raise StorageError("immutable generation directory cannot be created exclusively") from error
        self._fsync(self._generations_fd, "generation.parent.fsync")
        gen_fd = _open_dir_at(self._generations_fd, generation, self._uid,
                              "immutable generation directory")
        try:
            self._write_new(gen_fd, "descriptor.json", self._descriptor_bytes(selector),
                            label="generation.descriptor", max_bytes=MAX_SELECTOR_BYTES)
            for name, data in bundle.items():
                limit = (MAX_CA_BYTES if name == "ca_certificate.pem" else
                         MAX_SIGNER_BYTES if name == "snapshot_signer_public.pem" else
                         MAX_ARTIFACT_BYTES)
                self._write_new(gen_fd, name, data, label=f"artifact.{name}", max_bytes=limit)
            self._fsync(gen_fd, "generation.directory.fsync")
        finally:
            os.close(gen_fd)
        self._fsync(self._generations_fd, "generation.parent.final_fsync")

    def _pending_document(self, old_hash: str, new_hash: str,
                          generation: str, active_policy_hash: str) -> bytes:
        return canonical_json({
            "schema_version": 2, "purpose": PENDING_PURPOSE,
            "old_selector_sha256": old_hash,
            "new_selector_sha256": new_hash,
            "new_generation_sha256": generation,
            "active_policy_snapshot_sha256": active_policy_hash,
        })

    @staticmethod
    def _parse_pending(encoded: bytes) -> dict:
        if type(encoded) is not bytes or not 1 <= len(encoded) <= MAX_SELECTOR_BYTES:
            raise StorageError("pending marker is malformed or oversized")
        try:
            raw = json.loads(encoded.decode("utf-8", errors="strict"),
                             object_pairs_hook=_pairs, parse_constant=_reject_constant,
                             parse_float=_reject_float)
        except StorageError:
            raise
        except (UnicodeError, ValueError, TypeError, RecursionError) as error:
            raise StorageError("pending marker is malformed") from error
        if type(raw) is not dict or set(raw) != _PENDING_FIELDS:
            raise StorageError("pending marker has unknown or missing fields")
        if type(raw["schema_version"]) is not int or raw["schema_version"] != 2:
            raise StorageError("pending marker version is invalid")
        if type(raw["purpose"]) is not str or raw["purpose"] != PENDING_PURPOSE:
            raise StorageError("pending marker purpose is invalid")
        _hash(raw["old_selector_sha256"], "pending old selector hash")
        _hash(raw["new_selector_sha256"], "pending new selector hash")
        _hash(raw["new_generation_sha256"], "pending generation ID")
        _hash(raw["active_policy_snapshot_sha256"], "pending active policy hash")
        if canonical_json(raw) != encoded:
            raise StorageError("pending marker is not canonical JSON")
        return raw

    def _read_pending(self) -> tuple[bytes, dict]:
        encoded = _open_read_file(self._root_fd, "pending.json", self._uid,
                                  MAX_SELECTOR_BYTES, "pending marker")
        return encoded, self._parse_pending(encoded)

    def _replace_selector(self, encoded: bytes, *, before_replace=None) -> None:
        temp_name = f"selector.tmp.{os.getpid()}.{os.urandom(8).hex()}"
        self._write_new(self._root_fd, temp_name, encoded, label="selector.temp",
                        max_bytes=MAX_SELECTOR_BYTES)
        self._step("selector.replace")
        if before_replace is not None:
            if not callable(before_replace):
                raise TypeError("pre-replace validator must be callable")
            result = before_replace()
            if inspect.isawaitable(result):
                close = getattr(result, "close", None)
                if callable(close):
                    close()
                raise TypeError("pre-replace validator must be synchronous")
            if result is not None:
                raise TypeError("pre-replace validator must return None")
        try:
            os.replace(temp_name, "selector.json", src_dir_fd=self._root_fd,
                       dst_dir_fd=self._root_fd)
        except OSError as error:
            raise StorageError("root-generation selector atomic replace failed") from error
        self._fsync(self._root_fd, "selector.root.fsync")

    def _remove_pending(self, pending_bytes: bytes) -> None:
        self._step("pending.unlink")
        try:
            os.unlink("pending.json", dir_fd=self._root_fd)
        except OSError as error:
            raise StorageError("pending marker cannot be removed") from error
        try:
            self._fsync(self._root_fd, "pending.root.fsync")
        except BaseException:
            # Keep the running system fail-closed if the post-unlink directory
            # sync fails. The original selector remains selected; this marker
            # records that final durability was not confirmed.
            try:
                fd = os.open("pending.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL
                             | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
                             0o600, dir_fd=self._root_fd)
                try:
                    view = memoryview(pending_bytes)
                    while view:
                        count = os.write(fd, view)
                        if count <= 0:
                            break
                        view = view[count:]
                    os.fsync(fd)
                finally:
                    os.close(fd)
                os.fsync(self._root_fd)
            except OSError:
                pass
            raise

    def commit(self, selector: RootGenerationSelector, bundle: dict[str, bytes], *,
               active_policy_snapshot: bytes,
               expected_old_selector_sha256: str,
               validate: Callable[[RootGenerationSelector, Mapping[str, bytes], bytes], None]) -> str:
        """Durably add an immutable generation and atomically select it.

        Failures after the pending marker is created intentionally leave the
        store blocked. There is no rollback or implicit cleanup path.
        """
        selector = parse_root_generation_selector(
            canonical_json(root_generation_selector_document(selector)))
        candidate = _candidate_bundle(selector, bundle)
        if (type(active_policy_snapshot) is not bytes
                or not 1 <= len(active_policy_snapshot) <= MAX_POLICY_BYTES
                or hashlib.sha256(active_policy_snapshot).hexdigest()
                    != selector.active_policy_snapshot_sha256):
            raise StorageError("cold generation active policy differs from selector hash")
        if type(expected_old_selector_sha256) is not str or not _HEX64.fullmatch(
                expected_old_selector_sha256):
            raise StorageError("expected old selector hash is invalid")
        _validate_callback(validate, selector, candidate, active_policy_snapshot)
        new_selector_bytes = canonical_json(root_generation_selector_document(selector))
        if len(new_selector_bytes) > MAX_SELECTOR_BYTES:
            raise StorageError("new root-generation selector exceeds its 16 KiB bound")
        new_selector_hash = hashlib.sha256(new_selector_bytes).hexdigest()
        with self._lock(exclusive=True):
            if self._pending_faulted or self._pending_exists():
                raise StorageError("another root-generation transaction is pending")
            old_bytes, old_selector = self._read_selector()
            old_hash = hashlib.sha256(old_bytes).hexdigest()
            if old_hash != expected_old_selector_sha256:
                raise StorageError("current selector differs from expected old selector")
            self._load_generation(old_selector)
            current_policy = self._load_policy(old_selector.active_policy_snapshot_sha256)
            if selector.generation_sha256 == old_selector.generation_sha256:
                if new_selector_bytes != old_bytes:
                    raise StorageError("cold selector cannot rewrite the selected generation head")
                if (candidate != self._load_generation(old_selector)
                        or active_policy_snapshot != current_policy):
                    raise StorageError("same-head retry differs from current immutable or active bytes")
                _validate_callback(validate, old_selector,
                                   self._load_generation(old_selector), current_policy)
                return old_hash
            if active_policy_snapshot != candidate["policy_snapshot.json"]:
                raise StorageError("new generation active policy must equal its pinned baseline policy")
            if selector.policy_revision <= old_selector.policy_revision:
                raise StorageError("cold generation policy revision must advance the selected high-water")
            same = self._verify_existing_or_capacity(selector, candidate)
            self._step("validate.before_pending")
            _validate_callback(validate, selector, candidate, active_policy_snapshot)
            active_policy_hash, _names, _total = self._check_policy_capacity(active_policy_snapshot)
            if active_policy_hash != selector.active_policy_snapshot_sha256:
                raise StorageError("staged active policy differs from selector pin")
            pending = self._pending_document(old_hash, new_selector_hash,
                                             selector.generation_sha256, active_policy_hash)
            self._write_new(self._root_fd, "pending.json", pending,
                            label="pending.file", max_bytes=MAX_SELECTOR_BYTES)
            self._pending_faulted = True
            self._fsync(self._root_fd, "pending.directory.fsync")
            self._stage_policy(active_policy_snapshot)
            if not same:
                self._write_generation(selector, candidate)
            self._step("validate.after_prepare")

            def final_validation():
                _validate_callback(validate, selector, candidate, active_policy_snapshot)

            self._replace_selector(new_selector_bytes, before_replace=final_validation)
            self._remove_pending(pending)
            self._pending_faulted = False
            return new_selector_hash

    def advance_policy(self, encoded: bytes, *, expected_old_selector_sha256: str,
                       clock, validate: Callable[[RootGenerationSelector,
                       Mapping[str, bytes], bytes], None]) -> str:
        """Advance only the active signed policy under the current root generation.

        This persists an operator-signed policy refresh. It does not authorize
        root rotation, credential issuance, or process readiness.
        """
        if type(expected_old_selector_sha256) is not str or not _HEX64.fullmatch(
                expected_old_selector_sha256):
            raise StorageError("expected old selector hash is invalid")
        if not callable(validate):
            raise TypeError("root-generation validation callback is required")
        with self._lock(exclusive=True):
            if self._pending_faulted or self._pending_exists():
                raise StorageError("root-generation transaction is pending")
            old_bytes, old_selector = self._read_selector()
            old_hash = hashlib.sha256(old_bytes).hexdigest()
            if old_hash != expected_old_selector_sha256:
                raise StorageError("current selector differs from expected old selector")
            baseline = self._load_generation(old_selector)
            old_policy = self._load_policy(old_selector.active_policy_snapshot_sha256)
            sample = clock.sample()
            old_payload, _old_credentials, _old_grants = _authenticate_policy_snapshot(
                old_policy, ca_pem=baseline["ca_certificate.pem"],
                signer_pem=baseline["snapshot_signer_public.pem"], sample=sample)
            old_digest = canonical_policy_digest(old_payload)
            if (old_payload["revision"] != old_selector.policy_revision
                    or old_digest != old_selector.policy_digest):
                raise StorageError("selected policy head differs from selector revision/digest")
            new_payload, _new_credentials, _new_grants = _authenticate_policy_snapshot(
                encoded, ca_pem=baseline["ca_certificate.pem"],
                signer_pem=baseline["snapshot_signer_public.pem"], sample=sample)
            new_digest = canonical_policy_digest(new_payload)
            if new_payload["issued_at"] < old_payload["issued_at"]:
                raise StorageError("active policy issued_at rollback is forbidden")
            if new_payload["revision"] < old_selector.policy_revision:
                raise StorageError("active policy revision rollback is forbidden")
            if new_payload["revision"] == old_selector.policy_revision:
                if new_digest != old_digest:
                    raise StorageError("active policy revision equivocation is forbidden")
                checked_store = SnapshotStore(
                    verification_key_pem=baseline["snapshot_signer_public.pem"],
                    ca_certificate_pem=baseline["ca_certificate.pem"], clock=clock,
                    minimum_revision=old_selector.policy_revision,
                    minimum_policy_digest=old_selector.policy_digest)
                try:
                    checked_view = checked_store.install(encoded)
                except SnapshotError as error:
                    raise StorageError("incoming signed policy failed current-time validation") from error
                if checked_view.policy_digest != new_digest:
                    raise StorageError("incoming policy digest changed during verification")
                # Re-signatures do not create a freshness extension or new file.
                _validate_callback(validate, old_selector, baseline, old_policy)
                final_sample = clock.sample()
                if (new_payload["issued_at"] > final_sample.earliest_wall
                        or new_payload["expires_at"] <= final_sample.latest_wall):
                    raise StorageError("incoming policy expired or became future-dated during reconciliation")
                verify_ca(baseline["ca_certificate.pem"], now=final_sample.wall,
                          uncertainty_seconds=final_sample.uncertainty)
                try:
                    checked_store.current(sample=final_sample)
                except SnapshotError as error:
                    raise StorageError("incoming policy expired during reconciliation") from error
                return old_hash
            checked_store = SnapshotStore(
                verification_key_pem=baseline["snapshot_signer_public.pem"],
                ca_certificate_pem=baseline["ca_certificate.pem"], clock=clock,
                minimum_revision=old_selector.policy_revision,
                minimum_policy_digest=old_selector.policy_digest)
            try:
                checked_view = checked_store.install(encoded)
            except SnapshotError as error:
                raise StorageError("incoming signed policy failed current-time validation") from error
            if checked_view.policy_digest != new_digest:
                raise StorageError("incoming policy digest changed during verification")
            new_policy_hash, _names, _total = self._check_policy_capacity(encoded)
            new_selector = replace(old_selector, policy_revision=new_payload["revision"],
                                   policy_digest=new_digest,
                                   active_policy_snapshot_sha256=new_policy_hash)
            new_selector_bytes = canonical_json(root_generation_selector_document(new_selector))
            new_selector_hash = hashlib.sha256(new_selector_bytes).hexdigest()
            _validate_callback(validate, new_selector, baseline, encoded)
            pending = self._pending_document(old_hash, new_selector_hash,
                old_selector.generation_sha256, new_policy_hash)
            self._write_new(self._root_fd, "pending.json", pending,
                            label="pending.file", max_bytes=MAX_SELECTOR_BYTES)
            self._pending_faulted = True
            self._fsync(self._root_fd, "pending.directory.fsync")
            self._stage_policy(encoded)
            self._step("validate.after_prepare")

            def final_validation():
                _validate_callback(validate, new_selector, baseline, encoded)
                final_sample = clock.sample()
                if (new_payload["issued_at"] > final_sample.earliest_wall
                        or new_payload["expires_at"] <= final_sample.latest_wall):
                    raise StorageError("incoming policy expired or became future-dated before selector commit")
                verify_ca(baseline["ca_certificate.pem"], now=final_sample.wall,
                          uncertainty_seconds=final_sample.uncertainty)
                try:
                    checked_store.current(sample=final_sample)
                except SnapshotError as error:
                    raise StorageError("incoming policy expired before selector commit") from error

            self._replace_selector(new_selector_bytes, before_replace=final_validation)
            self._remove_pending(pending)
            self._pending_faulted = False
            return new_selector_hash

    def recover_committed(self, *, validate: Callable[[RootGenerationSelector,
                           Mapping[str, bytes], bytes], None]
                          ) -> SelectedRootGeneration:
        """Clear only a marker whose exact new selector is already committed.

        A marker paired with the old selector is deliberately left blocked; a
        separate authorized fresh transition must resolve it.
        """
        with self._lock(exclusive=True):
            if not self._pending_exists():
                raise StorageError("there is no pending root-generation transaction")
            _pending_bytes, pending = self._read_pending()
            selected_bytes, selector = self._read_selector()
            selected_hash = hashlib.sha256(selected_bytes).hexdigest()
            if selected_hash != pending["new_selector_sha256"]:
                if selected_hash == pending["old_selector_sha256"]:
                    raise StorageError("pending generation is not selected; fresh authorized recovery required")
                raise StorageError("pending marker and selector disagree; refusing ambiguous recovery")
            if selector.generation_sha256 != pending["new_generation_sha256"]:
                raise StorageError("pending marker generation differs from committed selector")
            self._generation_names()
            bundle = self._load_generation(selector)
            active_policy = self._load_policy(selector.active_policy_snapshot_sha256)
            if active_policy != self._load_policy(pending["active_policy_snapshot_sha256"]):
                raise StorageError("pending active policy differs from committed selector")
            _validate_callback(validate, selector, bundle, active_policy)
            policy_name = f"{selector.active_policy_snapshot_sha256}.json"
            try:
                policy_fd = os.open(policy_name, os.O_RDONLY | os.O_NOFOLLOW
                                    | getattr(os, "O_CLOEXEC", 0), dir_fd=self._policies_fd)
            except OSError as error:
                raise StorageError("recovery active policy cannot be opened") from error
            try:
                _private_file(os.fstat(policy_fd), self._uid, "recovery active policy")
                self._fsync(policy_fd, "recovery.policy.fsync")
            finally:
                os.close(policy_fd)
            self._fsync(self._policies_fd, "recovery.policies.fsync")
            gen_fd = self._open_generation(selector.generation_sha256)
            try:
                self._fsync(gen_fd, "recovery.generation.fsync")
            finally:
                os.close(gen_fd)
            self._fsync(self._generations_fd, "recovery.generations.fsync")
            self._fsync(self._root_fd, "recovery.root.fsync")
            self._remove_pending(_pending_bytes)
            result = SelectedRootGeneration(selector, MappingProxyType(bundle), selected_hash,
                                          active_policy)
            self._pending_faulted = False
            return result
