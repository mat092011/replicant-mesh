"""Test-only boot-generation authority material for the secure C0 cohort.

This module creates signed policy generations for the bounded physical restart
experiment.  It never changes an existing identity, snapshot store, target, or
process owner, and it does not provide persistent rollback protection.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
import hashlib
import json
import os
from pathlib import Path
import re
import stat
from types import MappingProxyType
from typing import Mapping

from steamboat_security import (
    Authorizer,
    Clock,
    LocalIdentity,
    OutboundAuthorizer,
    OutboundTarget,
    SnapshotStore,
    new_id,
    sign_snapshot,
    snapshot_public_key_pem,
)
from steamboat_security.codec import COORDINATOR_SERVICE, WORKER_SERVICE, encode_binding
from steamboat_runtime.participant_context import TrustedRequestContext
from steamboat_runtime.secure_context import ConsumerContextFactory


_BOOT = re.compile(r"[0-9a-f]{32}\Z", re.ASCII)
_BOOT_NAMES = ("coordinator", "worker-1", "worker-2", "worker-3")
_SIGNER_FILENAME = "snapshot-signing-root.key.pem"
_SIGNER_MAX_BYTES = 4096
_WORKER_METHODS = ("Describe", "OpenSession", "RenewSession", "Step",
                   "CloseSession", "CancelSession", "SessionStatus")
_COORDINATOR_METHODS = ("Describe", "Tokenize", "Generate")


class BootGenerationError(ValueError):
    """A proposed test boot generation is malformed or not safely provisioned."""


class _ReadOnlyRecord(dict):
    """Read-only dict shape compatible with existing fixed C0 lab helpers."""

    __slots__ = ()

    def _deny(self, *_args, **_kwargs):
        raise TypeError("boot-generation credential records are immutable")

    __setitem__ = _deny
    __delitem__ = _deny
    clear = _deny
    pop = _deny
    popitem = _deny
    setdefault = _deny
    update = _deny
    __ior__ = _deny


@dataclass(frozen=True, slots=True)
class BootGeneration:
    """Immutable signed policy and identity view for one test boot generation."""

    principals: Mapping[str, object]
    boot_ids: Mapping[str, str]
    signed_snapshot: bytes
    revision: int
    policy_digest: str
    snapshot_sha256: str
    verification_key_pem: bytes
    ca_certificate_pem: bytes
    model_fingerprint: str
    clock_uncertainty_seconds: float

    def new_store(self) -> tuple[SnapshotStore, Clock]:
        """Create an independent verifier using the real system clock."""
        clock = Clock.system(
            uncertainty_seconds=lambda value=self.clock_uncertainty_seconds: value)
        store = SnapshotStore(
            verification_key_pem=self.verification_key_pem,
            ca_certificate_pem=self.ca_certificate_pem,
            clock=clock)
        view = store.install(self.signed_snapshot)
        if view.revision != self.revision or view.policy_digest != self.policy_digest:
            raise BootGenerationError("new store did not install the pinned boot generation")
        return store, clock


@dataclass(slots=True)
class TrustedProbe:
    """Caller-owned actual C0 authorization/context and outbound identity stack."""

    authorization: object
    context: TrustedRequestContext
    context_factory: ConsumerContextFactory
    inbound_authorizer: Authorizer
    outbound_authorizer: OutboundAuthorizer
    snapshot_store: SnapshotStore
    payload: dict
    _closed: bool = False

    def close(self) -> None:
        """Release the factory owner and close the actual consumer authorization."""
        if self._closed:
            return
        primary = None
        try:
            self.context_factory.release(self.context)
        except BaseException as error:
            primary = error
        try:
            self.authorization.close()
        except BaseException as error:
            if primary is None:
                primary = error
            else:
                primary.add_note(f"authorization close also failed: {error!r}")
        self._closed = True
        if primary is not None:
            raise primary


def _strict_json_object(encoded: bytes) -> dict:
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise BootGenerationError("signed policy contains duplicate keys")
            result[key] = value
        return result

    def reject_constant(_value):
        raise BootGenerationError("signed policy contains a nonfinite number")

    try:
        value = json.loads(encoded.decode("utf-8", errors="strict"),
                           object_pairs_hook=pairs, parse_constant=reject_constant)
    except BootGenerationError:
        raise
    except (UnicodeError, ValueError, TypeError, RecursionError) as error:
        raise BootGenerationError("signed policy is malformed") from error
    if type(value) is not dict:
        raise BootGenerationError("signed policy payload must be an object")
    return value


def _validate_boot_map(authority, boot_ids: Mapping[str, str]) -> dict[str, str]:
    if not isinstance(boot_ids, Mapping) or set(boot_ids) != set(_BOOT_NAMES):
        raise BootGenerationError("boot map must name exactly coordinator and workers 1-3")
    current_principals = getattr(authority, "principals", None)
    if not isinstance(current_principals, Mapping) or set(current_principals) != {
            "coordinator", "consumer", "worker-1", "worker-2", "worker-3"}:
        raise BootGenerationError("authority fixture has an unexpected principal set")
    normalized = {}
    for name in _BOOT_NAMES:
        value = boot_ids[name]
        if type(value) is not str or _BOOT.fullmatch(value) is None:
            raise BootGenerationError("boot IDs must be 32 lowercase hexadecimal characters")
        if value == getattr(current_principals[name], "boot_id", None):
            raise BootGenerationError("each restarted role needs a fresh boot ID")
        normalized[name] = value
    all_boots = [principal.boot_id for principal in current_principals.values()]
    if (len(set(normalized.values())) != len(normalized)
            or set(normalized.values()) & set(all_boots)):
        raise BootGenerationError("new boot IDs must be unique across both generations")
    return normalized


def _read_protected_file(authority_root: Path, filename: str) -> bytes:
    """Read one fixed-basename owner-only file without following path links."""
    if not isinstance(authority_root, Path) or not authority_root.is_absolute():
        raise BootGenerationError("operator fixture root must be an absolute path")
    if ".." in authority_root.parts:
        raise BootGenerationError("operator fixture root cannot contain traversal")
    if (type(filename) is not str or not filename or filename in {".", ".."}
            or "/" in filename or "\\" in filename or "\x00" in filename):
        raise BootGenerationError("operator file name must be a fixed basename")
    root_descriptor = None
    descriptor = None
    root_before = None
    try:
        if os.name == "posix":
            directory_flags = (os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
                               | getattr(os, "O_CLOEXEC", 0))
            root_descriptor = os.open(authority_root.anchor, directory_flags)
            for component in authority_root.parts[1:]:
                next_descriptor = os.open(component, directory_flags,
                                           dir_fd=root_descriptor)
                os.close(root_descriptor)
                root_descriptor = next_descriptor
            root_info = os.fstat(root_descriptor)
            if (not stat.S_ISDIR(root_info.st_mode)
                    or root_info.st_uid != os.geteuid()
                    or stat.S_IMODE(root_info.st_mode) != 0o700):
                raise BootGenerationError("operator fixture root is not private and owned")
            root_before = (root_info.st_dev, root_info.st_ino, root_info.st_uid,
                           stat.S_IMODE(root_info.st_mode))
            flags = (os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
                     | getattr(os, "O_CLOEXEC", 0))
            descriptor = os.open(filename, flags, dir_fd=root_descriptor)
        else:
            root_info = authority_root.lstat()
            if not stat.S_ISDIR(root_info.st_mode) or stat.S_ISLNK(root_info.st_mode):
                raise BootGenerationError("operator fixture root is not a real directory")
            path = authority_root / filename
            path_info = path.lstat()
            if not stat.S_ISREG(path_info.st_mode) or stat.S_ISLNK(path_info.st_mode):
                raise BootGenerationError("operator signing key path is not a regular file")
            flags = (os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
                     | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
            descriptor = os.open(path, flags)
        before = os.fstat(descriptor)
        if (not stat.S_ISREG(before.st_mode) or before.st_size < 1
                or before.st_size > _SIGNER_MAX_BYTES):
            raise BootGenerationError("operator signing key file is not a bounded regular file")
        if os.name == "posix" and (
                before.st_uid != os.geteuid()
                or stat.S_IMODE(before.st_mode) != 0o600
                or before.st_nlink != 1):
            raise BootGenerationError("operator signing key ownership or mode is invalid")
        chunks = []
        remaining = _SIGNER_MAX_BYTES + 1
        while remaining:
            block = os.read(descriptor, min(remaining, 1024))
            if not block:
                break
            chunks.append(block)
            remaining -= len(block)
        encoded = b"".join(chunks)
        after = os.fstat(descriptor)
        if (len(encoded) != before.st_size or len(encoded) > _SIGNER_MAX_BYTES
                or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
                != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)):
            raise BootGenerationError("operator signing key changed during bounded read")
        if os.name == "posix":
            if ((before.st_uid, stat.S_IMODE(before.st_mode), before.st_nlink,
                 before.st_ctime_ns)
                    != (after.st_uid, stat.S_IMODE(after.st_mode), after.st_nlink,
                        after.st_ctime_ns)):
                raise BootGenerationError("operator signing key metadata changed during read")
            root_after = os.fstat(root_descriptor)
            if root_before != (root_after.st_dev, root_after.st_ino, root_after.st_uid,
                               stat.S_IMODE(root_after.st_mode)):
                raise BootGenerationError("operator fixture root changed during key read")
        return encoded
    except BootGenerationError:
        raise
    except OSError as error:
        raise BootGenerationError("operator signing key could not be safely read") from error
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if root_descriptor is not None:
            os.close(root_descriptor)


def _read_private_signer(authority_root: Path) -> bytes:
    """Read the fixture's fixed operator-only signer without following links."""
    return _read_protected_file(authority_root, _SIGNER_FILENAME)


def _same_except_boots_and_validity(old: dict, new: dict) -> bool:
    allowed = {"target_boot_id", "actor_boot_id", "not_before", "not_after"}
    return (set(old) == set(new)
            and all(old[key] == new[key] for key in old if key not in allowed))


def prepare_boot_generation(authority, boot_ids: Mapping[str, str]) -> BootGeneration:
    """Sign a higher C0 policy for fresh boots while retaining all role leaves.

    The existing fixture remains untouched.  The signer is read from its fixed
    private operator file only after the complete boot map has passed validation.
    """
    normalized = _validate_boot_map(authority, boot_ids)
    required = ("root", "principals", "signed_snapshot", "snapshot_verification_key_pem",
                "cohort_ca_pem", "model_id", "clock_uncertainty_seconds")
    if any(not hasattr(authority, name) for name in required):
        raise BootGenerationError("authority fixture is missing required C0 material")
    uncertainty = authority.clock_uncertainty_seconds
    if type(uncertainty) not in (int, float) or not 0 <= float(uncertainty) <= 30:
        raise BootGenerationError("authority clock uncertainty is invalid")

    # Verify the current signed policy using the fixture's actual verifier/CA pins.
    old_clock = Clock.system(uncertainty_seconds=lambda value=float(uncertainty): value)
    old_store = SnapshotStore(
        verification_key_pem=authority.snapshot_verification_key_pem,
        ca_certificate_pem=authority.cohort_ca_pem,
        clock=old_clock)
    old_view = old_store.install(authority.signed_snapshot)
    old_payload = _strict_json_object(old_view.canonical_payload)
    if (old_payload.get("revision") != old_view.revision
            or old_payload.get("version") != 1
            or old_view.policy_digest == ""):
        raise BootGenerationError("current signed policy view is inconsistent")

    principals = {}
    for name, principal in authority.principals.items():
        principal_boot = normalized.get(name, principal.boot_id)
        record = _ReadOnlyRecord()
        dict.update(record, principal.record)
        principals[name] = replace(principal, boot_id=principal_boot, record=record)

    credentials = old_payload["credentials"]
    grants = old_payload["grants"]
    if type(credentials) is not list or len(credentials) != len(principals):
        raise BootGenerationError("current policy credential set is incomplete")
    if type(grants) is not list or len(grants) != (
            len(_WORKER_METHODS) * 3 + len(_COORDINATOR_METHODS)):
        raise BootGenerationError("current policy grant matrix is not the fixed C0 matrix")

    sample = Clock.system(
        uncertainty_seconds=lambda value=float(uncertainty): value).sample()
    issued_at = int(sample.earliest_wall)
    if issued_at < old_view.issued_at:
        raise BootGenerationError("new policy issue time would precede the current policy")
    expires_at = issued_at + 300
    if expires_at <= sample.latest_wall:
        raise BootGenerationError("new policy has no conservative live validity window")

    boot_for_device = {
        principal.device_id: normalized[name]
        for name, principal in authority.principals.items()
        if name in ("worker-1", "worker-2", "worker-3")
    }
    coordinator_device = authority.principals["coordinator"].device_id
    new_grants = []
    for raw in grants:
        if type(raw) is not dict:
            raise BootGenerationError("current policy contains a malformed grant")
        updated = dict(raw)
        updated["not_before"] = issued_at
        updated["not_after"] = expires_at
        if raw["method"].startswith(f"{WORKER_SERVICE}/"):
            target_boot = boot_for_device.get(raw["target_device_id"])
            if target_boot is None:
                raise BootGenerationError("worker grant targets an unknown participant")
            updated["target_boot_id"] = target_boot
            updated["actor_boot_id"] = normalized["coordinator"]
        elif raw["method"].startswith(f"{COORDINATOR_SERVICE}/"):
            if raw["target_device_id"] != coordinator_device:
                raise BootGenerationError("consumer grant targets another coordinator")
            updated["target_boot_id"] = normalized["coordinator"]
        else:
            raise BootGenerationError("current policy contains an unknown service grant")
        if not _same_except_boots_and_validity(raw, updated):
            raise BootGenerationError("grant update changed a non-boot authorization field")
        new_grants.append(updated)

    payload = {
        "version": 1,
        "revision": old_view.revision + 1,
        "issued_at": issued_at,
        "expires_at": expires_at,
        "revoked_serials": list(old_payload["revoked_serials"]),
        "revoked_devices": list(old_payload["revoked_devices"]),
        "credentials": [dict(record) for record in credentials],
        "grants": new_grants,
    }
    root = Path(authority.root)
    signer_key = _read_private_signer(root)
    if snapshot_public_key_pem(signer_key) != authority.snapshot_verification_key_pem:
        raise BootGenerationError("private policy signer differs from the pinned public key")
    encoded = sign_snapshot(payload, signer_key)
    # Do not retain an additional in-memory authority-key reference.
    signer_key = b""

    new_clock = Clock.system(uncertainty_seconds=lambda value=float(uncertainty): value)
    verifier = SnapshotStore(
        verification_key_pem=authority.snapshot_verification_key_pem,
        ca_certificate_pem=authority.cohort_ca_pem,
        clock=new_clock)
    view = verifier.install(encoded)
    if (view.revision != old_view.revision + 1
            or view.policy_digest == old_view.policy_digest
            or view.expires_at != expires_at):
        raise BootGenerationError("new signed policy did not advance exactly one revision")
    new_payload = _strict_json_object(view.canonical_payload)
    if (new_payload["credentials"] != old_payload["credentials"]
            or new_payload["revoked_serials"] != old_payload["revoked_serials"]
            or new_payload["revoked_devices"] != old_payload["revoked_devices"]):
        raise BootGenerationError("boot generation changed credentials or revocations")
    for name in authority.principals:
        old, fresh = authority.principals[name], principals[name]
        if (fresh.certificate_pem != old.certificate_pem
                or fresh.private_key_pem != old.private_key_pem
                or fresh.record != old.record):
            raise BootGenerationError("boot generation changed a participant leaf identity")
    return BootGeneration(
        principals=MappingProxyType(principals),
        boot_ids=MappingProxyType(normalized),
        signed_snapshot=encoded,
        revision=view.revision,
        policy_digest=view.policy_digest,
        snapshot_sha256=hashlib.sha256(encoded).hexdigest(),
        verification_key_pem=authority.snapshot_verification_key_pem,
        ca_certificate_pem=authority.cohort_ca_pem,
        model_fingerprint=authority.model_id,
        clock_uncertainty_seconds=float(uncertainty))


def build_trusted_probe_context(authority, *, generation: BootGeneration | None = None,
                               timeout_seconds: int = 30) -> TrustedProbe:
    """Build a real C0 consumer authorization/context without network admission.

    This only prepares the same trusted objects that the secure adapters use;
    it does not create a coordinator request or claim that an RPC was sent.
    The exact integer timeout is part of the actual Generate payload and is
    bounded before any authority material or context ownership is accessed.
    """
    if type(timeout_seconds) is not int or not 1 <= timeout_seconds <= 300:
        raise BootGenerationError("probe timeout must be an exact integer from 1 to 300")
    if generation is None:
        principals = authority.principals
        signed_snapshot = authority.signed_snapshot
        verification_key = authority.snapshot_verification_key_pem
        ca_certificate = authority.cohort_ca_pem
        model_fingerprint = authority.model_id
        uncertainty = float(authority.clock_uncertainty_seconds)
    else:
        if not isinstance(generation, BootGeneration):
            raise BootGenerationError("probe generation must be an issued BootGeneration")
        principals = generation.principals
        signed_snapshot = generation.signed_snapshot
        verification_key = generation.verification_key_pem
        ca_certificate = generation.ca_certificate_pem
        model_fingerprint = generation.model_fingerprint
        uncertainty = generation.clock_uncertainty_seconds

    clock = Clock.system(uncertainty_seconds=lambda value=uncertainty: value)
    store = SnapshotStore(verification_key_pem=verification_key,
                          ca_certificate_pem=ca_certificate, clock=clock)
    store.install(signed_snapshot)
    coordinator = principals["coordinator"]
    consumer = principals["consumer"]
    worker = principals["worker-3"]
    from steamboat_runtime.protocol.worker_pb2 import Request

    inbound = Authorizer(
        local_identity=LocalIdentity(coordinator.certificate_pem,
                                      coordinator.boot_id, model_fingerprint),
        snapshot_store=store, clock=clock)
    outbound_target = OutboundTarget.from_record(
        service=WORKER_SERVICE, record=worker.record, boot_id=worker.boot_id,
        model_id=model_fingerprint, assignment_id=worker.assignment_id)
    outbound = OutboundAuthorizer(
        local_identity=LocalIdentity(coordinator.certificate_pem,
                                     coordinator.boot_id, model_fingerprint),
        snapshot_store=store, clock=clock, target=outbound_target,
        worker_request_type=Request,
        trusted_request_context_type=TrustedRequestContext)
    payload = {
        "input_ids": [1, 2],
        "new_tokens": 1,
        "forced_tokens": [],
        "timeout_seconds": float(timeout_seconds),
        "capture_logits": False,
    }
    fields = {
        "binding_version": 1,
        "operation_id": new_id("op"),
        "account_id": consumer.account_id,
        "device_id": consumer.device_id,
        "role": consumer.role,
        "credential_epoch": consumer.record["credential_epoch"],
        "target_device_id": coordinator.device_id,
        "request_id": new_id("req"),
    }
    metadata = (("steamboat-binding-bin",
                 encode_binding(COORDINATOR_SERVICE, "Generate", fields)),)
    authorization = inbound.authorize(
        COORDINATOR_SERVICE, "Generate", payload, metadata,
        consumer.certificate_pem)
    factory = ConsumerContextFactory(
        account_id=coordinator.account_id,
        device_id=coordinator.device_id,
        coordinator_boot_id=coordinator.boot_id,
        model_id=model_fingerprint)
    context = None
    try:
        context = factory(authorization, payload)
        context.assert_data_live()
    except BaseException as primary:
        cleanup_errors = []
        if context is not None:
            try:
                factory.release(context)
            except BaseException as error:
                cleanup_errors.append(error)
        try:
            authorization.close()
        except BaseException as error:
            cleanup_errors.append(error)
        if cleanup_errors:
            raise BaseExceptionGroup(
                "trusted probe construction and cleanup failed",
                [primary, *cleanup_errors])
        raise
    return TrustedProbe(
        authorization=authorization,
        context=context,
        context_factory=factory,
        inbound_authorizer=inbound,
        outbound_authorizer=outbound,
        snapshot_store=store,
        payload=payload)
