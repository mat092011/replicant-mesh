"""Nonproduction fixed-assignment mTLS worker process.

Run with ``python -m lab.secure_worker --config /absolute/root/worker.json``.
The launcher accepts only the pinned tiny-model worker assignment and uses the
existing C0 identity core, secure listener, runtime bridge, executor, and
handler. It is not a general participant daemon or a remote administration API.
"""

from __future__ import annotations

import argparse
import asyncio
from dataclasses import dataclass, fields
import hashlib
import json
import math
import os
from pathlib import Path
import re
import secrets
import signal
import stat
import sys

from lab.secure_worker_config import (
    MAX_STATUS_BYTES,
    SecureWorkerConfig,
    WorkerConfigError,
    load_worker_config,
    validate_readonly_artifacts,
)


MAX_OUTPUT_FRAME_BYTES = 4096
MAX_CONNECTIONS = 16
MAX_PENDING_HANDSHAKES = 4
LISTENER_SLOTS = 1
BRIDGE_STOP_GRACE_SECONDS = 5.0
STATUS_HEARTBEAT_SECONDS = 1.0


class WorkerStatusUnavailable(RuntimeError):
    """A required runtime observation is unknown or reports an unhealthy worker."""


@dataclass
class _OwnedRuntime:
    clock: object = None
    store: object = None
    bindings: object = None
    authorizer: object = None
    certificate_pem: bytes = b""
    private_key_pem: bytes = b""
    cohort_ca_pem: bytes = b""
    executor: object = None
    handler: object = None
    bridge: object = None
    bridge_started: bool = False
    budget: object = None
    server: object = None
    manifest: object = None
    torch_threads: int = 0
    startup_pending: bool = False
    pending_tasks: tuple = ()
    snapshot_verification_key_pem: bytes = b""
    installed_snapshot_sha256: str = ""
    installed_snapshot_revision: int = 0
    owner_controls_enabled: bool = False
    owner_control_inbox: object = None
    owner_control_run_id: str = ""
    owner_control_last_sequence: int = 0
    owner_control_last_command_sha256: str = ""
    owner_control_last_action: str = ""
    owner_control_received_monotonic_ns: int = 0
    owner_control_applied_monotonic_ns: int = 0
    owner_control_applied_snapshot_sha256: str = ""
    owner_control_applied_revision: int = 0
    owner_control_removal_intent_verified: bool = False
    owner_control_revocation_notice_monotonic_ns: int = 0
    owner_control_last_snapshot_revision: int = 0
    owner_control_notice_armed: bool = False
    owner_control_notice_sequence: int = 0
    owner_control_notice_command_sha256: str = ""
    owner_control_notice_snapshot_revision: int = 0
    owner_control_notice_fault: bool = False
    owner_lifecycle_cache: dict | None = None
    owner_initial_credential_pins: dict | None = None


def _encode_frame(payload: dict) -> bytes:
    data = (json.dumps(payload, sort_keys=True, separators=(",", ":"),
                       ensure_ascii=True, allow_nan=False) + "\n").encode("utf-8")
    if not 1 <= len(data) <= MAX_OUTPUT_FRAME_BYTES:
        raise RuntimeError("worker status frame exceeded its fixed bound")
    return data


def _emit(payload: dict) -> None:
    data = _encode_frame(payload)
    view = memoryview(data)
    while view:
        written = os.write(sys.stdout.fileno(), view)
        if written <= 0:
            raise OSError("status output closed")
        view = view[written:]


def _write_status_report(config: SecureWorkerConfig, payload: dict) -> None:
    """Atomically update one bounded 0600 file inside the 0700 root."""
    data = _encode_frame(payload)
    root = Path(config.protected_root)
    target = Path(config.status_report_path)
    if target.parent != root or target.name in ("", ".", ".."):
        raise WorkerConfigError("status report must be a protected-root child")
    if (os.name != "posix" or not hasattr(os, "O_NOFOLLOW")
            or not hasattr(os, "O_DIRECTORY") or not hasattr(os, "geteuid")):
        raise WorkerConfigError("status reports require Linux/POSIX protected-file support")

    from steamboat_security.files import _open_parent

    # Reuse C0's descriptor-by-descriptor no-follow walk for every ancestor,
    # rather than protecting only the final protected_root component.
    root_fd, filename = _open_parent(
        root, target, expected_uid=os.geteuid())
    file_fd = None
    temporary_name = None
    try:
        temporary_name = f".{filename}.{secrets.token_hex(8)}.tmp"
        flags = (os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
                 | getattr(os, "O_CLOEXEC", 0))
        file_fd = os.open(temporary_name, flags, 0o600, dir_fd=root_fd)
        os.fchmod(file_fd, 0o600)
        file_info = os.fstat(file_fd)
        if (not stat.S_ISREG(file_info.st_mode) or file_info.st_uid != os.geteuid()
                or stat.S_IMODE(file_info.st_mode) != 0o600):
            raise WorkerConfigError("temporary status report failed owner/mode validation")
        view = memoryview(data)
        while view:
            written = os.write(file_fd, view)
            if written <= 0:
                raise OSError("status report write did not advance")
            view = view[written:]
        os.fsync(file_fd)
        try:
            previous = os.stat(filename, dir_fd=root_fd, follow_symlinks=False)
        except FileNotFoundError:
            previous = None
        if previous is not None and (
                not stat.S_ISREG(previous.st_mode)
                or previous.st_uid != os.geteuid()
                or stat.S_IMODE(previous.st_mode) != 0o600):
            raise WorkerConfigError("existing status report failed owner/mode validation")
        os.replace(temporary_name, filename,
                   src_dir_fd=root_fd, dst_dir_fd=root_fd)
        os.fsync(root_fd)
    finally:
        if file_fd is not None:
            os.close(file_fd)
        if temporary_name is not None:
            try:
                os.unlink(temporary_name, dir_fd=root_fd)
            except FileNotFoundError:
                pass
        os.close(root_fd)


def _publish(config: SecureWorkerConfig, payload: dict, *, emit=True) -> None:
    _write_status_report(config, payload)
    if emit:
        _emit(payload)


def _read_credential(path: str, *, root: str, max_bytes: int) -> bytes:
    from steamboat_security import safe_read

    return safe_read(path, root=root, expected_uid=os.geteuid(), max_bytes=max_bytes)


def _validated_root_launch_spec(value):
    from steamboat_security.root_transition_launch import (
        parse_role_launch_spec, role_launch_document)

    return parse_role_launch_spec(role_launch_document(value))


def _same_worker_config_exact(supplied, parsed) -> bool:
    return (type(supplied) is SecureWorkerConfig
            and type(parsed) is SecureWorkerConfig
            and all(type(getattr(supplied, field.name))
                    is type(getattr(parsed, field.name))
                    for field in fields(SecureWorkerConfig))
            and supplied == parsed)


def _assert_worker_policy(config, authorizer):
    """Use the installed C0 verifier and signed view to pin local identity."""
    from steamboat_security.codec import WORKER_SERVICE

    view, sample = authorizer._current_view()
    verified = authorizer._verify_certificate(
        authorizer.local_identity.certificate_pem, view, sample)
    record = verified.record
    if (record.role != "host" or record.account_id != config.account_id
            or record.device_id != config.device_id
            or config.listen_ip not in record.ip_sans):
        raise WorkerConfigError("local leaf does not match the pinned host identity and IP SAN")
    assigned = any(
        grant.target_account_id == config.account_id
        and grant.target_device_id == config.device_id
        and grant.target_role == "host"
        and grant.target_serial == record.serial
        and grant.target_public_key_sha256 == record.public_key_sha256
        and grant.target_boot_id == config.boot_id
        and grant.assignment_id == config.assignment_id
        and grant.model_id == config.manifest_fingerprint
        and grant.method == f"{WORKER_SERVICE}/OpenSession"
        for grant in view.active_grants(sample))
    if not assigned:
        raise WorkerConfigError("signed snapshot has no exact worker boot/assignment grant")


def _validate_root_worker_binding(config, root_binding):
    """Validate inert root-bound configuration before loading model tensors."""
    from steamboat_security.root_runtime import RootRuntimeBinding, TLSMaterials
    from steamboat_security import Clock, LocalIdentity, SnapshotStore

    if type(root_binding) is not RootRuntimeBinding:
        raise WorkerConfigError("root mode requires an exact root runtime binding")
    if (type(root_binding.local_identity) is not LocalIdentity
            or type(root_binding.snapshot_store) is not SnapshotStore
            or type(root_binding.snapshot_store.clock) is not Clock
            or type(root_binding.tls_materials) is not TLSMaterials):
        raise WorkerConfigError("root binding components have unexpected runtime types")
    header = getattr(root_binding, "configuration_header", None)
    if type(header) is not bytes or not header:
        raise WorkerConfigError("root runtime binding has no immutable configuration header")
    if type(root_binding.runtime_configuration) is not bytes:
        raise WorkerConfigError("root runtime configuration must be immutable bytes")
    try:
        from steamboat_security.root_runtime import _configuration_header, _pairs
        from steamboat_security.codec import canonical_json
        header_values = json.loads(
            header.decode("utf-8", errors="strict"), object_pairs_hook=_pairs)
        if canonical_json(header_values) != header:
            raise WorkerConfigError("root configuration header is not canonical")
        _configuration_header(header_values)
        from lab.secure_worker_config import parse_config_bytes
        parsed = parse_config_bytes(
            root_binding.runtime_configuration,
            config_path=header_values["runtime_configuration_path"])
    except Exception as error:
        raise WorkerConfigError("root runtime configuration failed strict validation") from error

    try:
        spec = _validated_root_launch_spec(root_binding.launch_spec)
    except Exception as error:
        raise WorkerConfigError("root launch specification failed exact validation") from error
    from steamboat_security.root_transition_launch import RoleLaunchSpec
    if (type(spec) is not RoleLaunchSpec or spec.role != "host"
            or spec.identity != (config.account_id, config.device_id, "host")):
        raise WorkerConfigError("root launch specification is not this host worker")
    if (header_values["role"] != spec.role
            or header_values["account_id"] != spec.account_id
            or header_values["device_id"] != spec.device_id
            or header_values["boot_id"] != spec.boot_id
            or header_values["credential_epoch"] != spec.credential_epoch
            or header_values["admission_epoch"] != spec.admission_epoch
            or header_values["generation_sha256"] != spec.generation_sha256
            or header_values["launch_nonce"] != spec.launch_nonce
            or header_values["assignment_id"] != config.assignment_id):
        raise WorkerConfigError("protected root header differs from selected launch spec")
    expected = (
        ("protected_root", header_values["protected_root"]),
        ("account_id", spec.account_id), ("device_id", spec.device_id),
        ("boot_id", spec.boot_id), ("assignment_id", header_values["assignment_id"]),
        ("manifest_fingerprint", header_values["model_id"]),
        ("certificate_path", header_values["certificate_path"]),
        ("private_key_path", header_values["private_key_path"]),
    )
    if any(getattr(config, field) != value for field, value in expected):
        raise WorkerConfigError("worker config differs from its protected root binding")
    if not _same_worker_config_exact(config, parsed):
        raise WorkerConfigError("supplied worker config differs from protected runtime bytes")
    if (root_binding.local_identity.boot_id != spec.boot_id
            or root_binding.local_identity.admission_epoch != spec.admission_epoch
            or root_binding.local_identity.root_generation_sha256 != spec.generation_sha256
            or root_binding.local_identity.model_id != config.manifest_fingerprint
            or root_binding.local_identity.assignment_id != config.assignment_id
            or root_binding.local_identity.certificate_pem
                != root_binding.tls_materials.certificate_pem):
        raise WorkerConfigError("root local identity differs from selected launch")
    if (type(root_binding.tls_materials.certificate_pem) is not bytes
            or type(root_binding.tls_materials.private_key_pem) is not bytes):
        raise WorkerConfigError("root TLS materials must be immutable bytes")
    try:
        from steamboat_security.certificates import (
            _key, _pem_certificate, certificate_sha256, public_key_sha256, serial_hex)
        from cryptography.hazmat.primitives import serialization
        certificate = _pem_certificate(root_binding.tls_materials.certificate_pem)
        private_key = _key(root_binding.tls_materials.private_key_pem)
        cert_public = certificate.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        key_public = private_key.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    except Exception as error:
        raise WorkerConfigError("root TLS material failed cryptographic parsing") from error
    if (cert_public != key_public
            or certificate_sha256(certificate) != spec.certificate_sha256
            or public_key_sha256(certificate.public_key()) != spec.public_key_sha256
            or serial_hex(certificate.serial_number) != spec.serial):
        raise WorkerConfigError("root TLS material differs from selected launch pins")
    if hashlib.sha256(header).hexdigest() != spec.configuration_sha256:
        raise WorkerConfigError("root configuration header differs from selected launch pin")
    if hashlib.sha256(root_binding.runtime_configuration).hexdigest() != (
            header_values["runtime_configuration_sha256"]):
        raise WorkerConfigError("root runtime bytes differ from protected configuration pin")
    return header_values


def _build_runtime(config: SecureWorkerConfig, owned: _OwnedRuntime, *,
                   root_binding=None) -> None:
    """Construct actual pinned components; no factories or test bypasses."""
    if os.name != "posix" or not hasattr(os, "geteuid"):
        raise WorkerConfigError("the secure worker process is Linux-only")

    if root_binding is not None:
        _validate_root_worker_binding(config, root_binding)

    from steamboat_runtime.manifest import load_manifest
    from steamboat_runtime.protocol.secure_transport import NodeConnectionBudget
    from steamboat_runtime.protocol.worker_pb2 import Request
    from steamboat_runtime.worker_state import StageExecutor, WorkerHandler
    from steamboat_runtime.secure_worker_runtime import SecureWorkerRuntimeBridge
    from steamboat_security import (
        Authorizer,
        Clock,
        LocalIdentity,
        SessionBindings,
        SnapshotStore,
    )
    from steamboat_security.certificates import MAX_CERTIFICATE_BYTES
    from steamboat_security.snapshot import MAX_SNAPSHOT_BYTES

    validate_readonly_artifacts(config.artifact_directory)
    manifest = load_manifest(config.artifact_directory)
    if (manifest["model_id"] != config.model_id
            or manifest["revision"] != config.model_revision
            or manifest["fingerprint"] != config.manifest_fingerprint):
        raise WorkerConfigError("read-only artifact manifest differs from the explicit pin")
    owned.manifest = manifest

    if root_binding is None:
        certificate = _read_credential(
            config.certificate_path, root=config.protected_root,
            max_bytes=MAX_CERTIFICATE_BYTES)
        private_key = _read_credential(
            config.private_key_path, root=config.protected_root, max_bytes=1024 * 1024)
        cohort_ca = _read_credential(
            config.cohort_ca_path, root=config.protected_root,
            max_bytes=MAX_CERTIFICATE_BYTES)
        snapshot_key = _read_credential(
            config.snapshot_verification_key_path, root=config.protected_root,
            max_bytes=MAX_CERTIFICATE_BYTES)
        snapshot = _read_credential(
            config.signed_snapshot_path, root=config.protected_root,
            max_bytes=MAX_SNAPSHOT_BYTES)
        uncertainty = config.clock_uncertainty_seconds
        clock = Clock.system(uncertainty_seconds=lambda: uncertainty)
        store = SnapshotStore(verification_key_pem=snapshot_key,
                             ca_certificate_pem=cohort_ca, clock=clock)
        initial_view = store.install(snapshot)
        owned.snapshot_verification_key_pem = snapshot_key
        owned.installed_snapshot_sha256 = hashlib.sha256(snapshot).hexdigest()
        owned.installed_snapshot_revision = initial_view.revision
        identity = LocalIdentity(
            certificate, config.boot_id, config.manifest_fingerprint,
            config.assignment_id)
    else:
        certificate = root_binding.tls_materials.certificate_pem
        private_key = root_binding.tls_materials.private_key_pem
        cohort_ca = root_binding.snapshot_store.ca_certificate_pem
        clock = root_binding.snapshot_store.clock
        store = root_binding.snapshot_store
        identity = root_binding.local_identity
    owned.certificate_pem = certificate
    owned.private_key_pem = private_key
    owned.cohort_ca_pem = cohort_ca

    bindings = SessionBindings(
        clock=clock, max_live_sessions=manifest["limits"]["max_sessions"])
    authorizer = Authorizer(
        local_identity=identity,
        snapshot_store=store, clock=clock, session_bindings=bindings,
        worker_request_type=Request)
    _assert_worker_policy(config, authorizer)
    owned.clock, owned.store = clock, store
    owned.bindings, owned.authorizer = bindings, authorizer
    initial_view = store.current()
    owned.owner_initial_credential_pins = {
        serial: record for serial, record in initial_view.credentials_by_serial.items()
        if record.device_id == config.device_id
    }

    raw_threads = os.environ.get("OMP_NUM_THREADS", "2")
    try:
        torch_threads = int(raw_threads)
    except (TypeError, ValueError):
        raise WorkerConfigError("OMP_NUM_THREADS must be an integer from 1 through 24") from None
    if not 1 <= torch_threads <= 24:
        raise WorkerConfigError("OMP_NUM_THREADS must be an integer from 1 through 24")
    import torch

    torch.set_num_threads(torch_threads)
    executor = StageExecutor(config.artifact_directory, config.worker_name)
    if executor.manifest["fingerprint"] != config.manifest_fingerprint:
        raise WorkerConfigError("loaded stage manifest differs from the verified artifact pin")
    owned.executor = executor
    handler = WorkerHandler(
        manifest, config.worker_name, executor, boot_id=config.boot_id,
        enable_queue=True)
    owned.handler = handler
    bridge = SecureWorkerRuntimeBridge(
        authorizer, handler,
        sweep_interval_seconds=min(1.0, manifest["limits"]["lease_check_interval_seconds"]))
    owned.bridge = bridge
    owned.budget = NodeConnectionBudget(
        max_connections=MAX_CONNECTIONS,
        max_pending=MAX_PENDING_HANDSHAKES)
    owned.torch_threads = torch_threads


def _sanitize_bridge(bridge) -> dict:
    if bridge is None:
        return {"state": "not_started"}
    try:
        status = bridge.status()
    except Exception:
        status = None

    boolean_fields = (
        "ready", "unavailable", "requires_restart", "cleanup_confirmed")
    counter_fields = (
        "active_authorizations", "owned_sessions", "pending_notices")
    result = {"state": "observed"}
    malformed = type(status) is not dict
    for name in boolean_fields:
        value = status.get(name) if type(status) is dict else None
        if type(value) is not bool:
            malformed = True
            value = None
        result[name] = value
    for name in counter_fields:
        value = status.get(name) if type(status) is dict else None
        if type(value) is not int or value < 0:
            malformed = True
            value = None
        result[name] = value
    fault = status.get("fault") if type(status) is dict else None
    if type(fault) is not str:
        malformed = True
        result["fault_present"] = None
    else:
        result["fault_present"] = bool(fault)
    if malformed:
        result["state"] = "unknown"
    return result


def _handler_resource_status(handler) -> dict:
    """Report retained cache ownership without hiding terminal in-flight work."""
    try:
        sessions = tuple(handler.sessions.values())
        tombstones = tuple(handler.tombstones.values())
        entries = []
        seen = set()
        for entry in sessions + tombstones:
            identity = id(entry)
            if identity not in seen:
                seen.add(identity)
                entries.append(entry)

        active = (handler._active_operation is not None
                  or any(bool(entry.in_flight) for entry in entries))
        committed = sum(int(entry.committed_bytes) for entry in entries)
        active_session_ids = sorted(handler.sessions)
        if (len(active_session_ids) > 8
                or any(type(value) is not str
                       or re.fullmatch(r"ses_[0-9a-f]{32}", value, re.ASCII) is None
                       for value in active_session_ids)):
            raise WorkerConfigError("worker session identity introspection is ambiguous")
        common = {
            "state": "observed",
            "active_sessions": len(handler.sessions),
            "active_session_ids": active_session_ids,
            "tombstones": len({id(entry) for entry in tombstones}),
            "retained_entries": len(entries),
            "queued_operations": len(handler._queue),
            "active_compute": active,
            "cache_bytes_exact": False,
            "requires_restart": bool(handler.requires_restart),
            "stopping": bool(handler.stopping),
            "limits": {
                "max_sessions": int(handler.limits["max_sessions"]),
                "max_tombstones": int(handler.max_tombstones),
                "max_stage_queue": int(handler.queue_capacity),
                "max_positions": int(handler.limits["max_positions"]),
                "max_cache_positions": int(handler.limits["worker_cache_positions"]),
                "max_cache_bytes": int(handler.limits["worker_cache_bytes"]),
                "max_message_bytes": int(handler.limits["max_message_bytes"]),
            },
        }
        if active:
            # A compute thread can still mutate cache tensors. A zero or stale
            # byte sum would falsely imply physical reclamation. Preserve the
            # known committed count only as a lower bound across both maps.
            common["committed_cache_bytes"] = None
            common["committed_cache_bytes_lower_bound"] = committed
            common["allocated_cache_bytes"] = None
            return common
        common["committed_cache_bytes"] = committed
        common["committed_cache_bytes_lower_bound"] = None
        common["allocated_cache_bytes"] = sum(
            int(entry.cache.allocated_bytes()) for entry in entries)
        common["cache_bytes_exact"] = True
        return common
    except Exception:
        # Introspection failure is not evidence that buffers were released.
        return {
            "state": "unknown",
            "active_sessions": None,
            "active_session_ids": None,
            "tombstones": None,
            "retained_entries": None,
            "queued_operations": None,
            "active_compute": None,
            "committed_cache_bytes": None,
            "committed_cache_bytes_lower_bound": None,
            "allocated_cache_bytes": None,
            "cache_bytes_exact": False,
            "requires_restart": None,
            "stopping": None,
        }


def _status_payload(config, owned, *, event, phase, shutdown=None,
                    startup_error=None, report_state="confirmed") -> dict:
    handler = owned.handler
    executor = owned.executor
    bridge_status = _sanitize_bridge(owned.bridge)
    if handler is None:
        handler_status = {"state": "not_started"}
        layer_range = None
    else:
        handler_status = _handler_resource_status(handler)
        layer_range = [int(handler.start), int(handler.end)]
    owner_lifecycle = _owner_lifecycle_for_status(owned)
    if owner_lifecycle is not None and event in ("ready", "heartbeat"):
        phase = owner_lifecycle["phase"]
    if phase in ("ready", "draining", "paused") and (
            bridge_status.get("state") != "observed"
            or bridge_status.get("unavailable") is not False
            or bridge_status.get("requires_restart") is not False
            or handler_status.get("state") != "observed"
            or handler_status.get("requires_restart") is not False
            or (phase == "ready" and bridge_status.get("ready") is not True)
            or (phase in ("draining", "paused")
                and bridge_status.get("ready") is not False)):
        phase = "unavailable"
    budget = owned.budget
    transport = ({
        "listener_slots": LISTENER_SLOTS,
        "max_connections": MAX_CONNECTIONS,
        "max_pending": MAX_PENDING_HANDSHAKES,
        "reserved_connections": int(budget.reserved_connections),
        "reserved_pending": int(budget.reserved_pending),
        "reserved_listener_pending_capacity": int(budget.reserved_listener_pending_capacity),
        "reserved_outbound_pending": int(budget.reserved_outbound_pending),
        "server_state": ("running" if owned.server is not None
                         and not getattr(owned.server, "_stopped", False)
                         else "stopped" if owned.server is not None else "not_started"),
    } if budget is not None else {"state": "not_started"})
    payload = {
        "schema_version": 1,
        "event": event,
        "phase": phase,
        "worker_name": config.worker_name,
        "account_id": config.account_id,
        "device_id": config.device_id,
        "boot_id": config.boot_id,
        "assignment_id": config.assignment_id,
        "model_id": config.model_id,
        "model_revision": config.model_revision,
        "manifest_fingerprint": config.manifest_fingerprint,
        "listen_endpoint": config.endpoint,
        "layer_range": layer_range,
        "clock_uncertainty_seconds": config.clock_uncertainty_seconds,
        "torch_threads": owned.torch_threads,
        "handler": handler_status,
        "bridge": bridge_status,
        "transport": transport,
        "external_supervision": {
            "startup_watchdog_seconds": 60,
            "termination_watchdog_seconds": 15,
            "resource_caps": "configured_by_external_supervisor",
            "verified_by_worker": False,
        },
        "shutdown": shutdown or {"state": "not_started"},
        "report_state": report_state,
    }
    if owner_lifecycle is not None:
        payload["owner_lifecycle"] = owner_lifecycle
        payload["owner_control"] = {
            "run_id": owned.owner_control_run_id,
            "last_sequence": owned.owner_control_last_sequence,
            "last_command_sha256": owned.owner_control_last_command_sha256,
            "last_action": owned.owner_control_last_action,
            "received_monotonic_ns": owned.owner_control_received_monotonic_ns,
            "applied_monotonic_ns": owned.owner_control_applied_monotonic_ns,
            "applied_snapshot_sha256": owned.owner_control_applied_snapshot_sha256,
            "applied_revision": owned.owner_control_applied_revision,
            "removal_intent_verified": owned.owner_control_removal_intent_verified,
            "revocation_notice_monotonic_ns": (
                owned.owner_control_revocation_notice_monotonic_ns),
        }
    if (bridge_status.get("state") == "unknown"
            or handler_status.get("state") == "unknown"
            or (executor is None and owned.startup_pending)):
        payload["resource_state"] = "unknown"
    elif handler_status.get("active_compute") is True:
        payload["resource_state"] = "active"
    else:
        payload["resource_state"] = "observed"
    if startup_error is not None:
        payload["startup_error_type"] = type(startup_error).__name__[:80]
    if _encoded_size(payload) > MAX_STATUS_BYTES:
        raise RuntimeError("sanitized worker status exceeded its fixed bound")
    return payload


def _encoded_size(payload) -> int:
    return len(json.dumps(payload, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=True, allow_nan=False).encode("utf-8"))


def _owner_lifecycle_for_status(owned):
    if not owned.owner_controls_enabled:
        return None
    bridge = owned.bridge
    if (bridge is not None and owned.bridge_started
            and not bool(getattr(bridge, "_closed", False))):
        value = bridge.owner_lifecycle_status()
        expected = {"phase", "drain_started_monotonic",
                    "drain_deadline_monotonic", "deadline_reached"}
        if type(value) is not dict or set(value) != expected:
            raise WorkerStatusUnavailable("owner lifecycle status is malformed")
        if (type(value["phase"]) is not str
                or value["phase"] not in ("ready", "draining", "paused")
                or type(value["deadline_reached"]) is not bool):
            raise WorkerStatusUnavailable("owner lifecycle phase is malformed")
        for field in ("drain_started_monotonic", "drain_deadline_monotonic"):
            number = value[field]
            if number is not None and (type(number) not in (int, float)
                                       or not math.isfinite(number)):
                raise WorkerStatusUnavailable("owner lifecycle deadline is malformed")
        if ((value["drain_started_monotonic"] is None)
                != (value["drain_deadline_monotonic"] is None)):
            raise WorkerStatusUnavailable("owner lifecycle deadline pair is incomplete")
        owned.owner_lifecycle_cache = dict(value)
        return dict(value)
    if owned.owner_lifecycle_cache is not None:
        return dict(owned.owner_lifecycle_cache)
    return {
        "phase": "ready", "drain_started_monotonic": None,
        "drain_deadline_monotonic": None, "deadline_reached": False,
    }


async def _shutdown_components(owned: _OwnedRuntime) -> dict:
    """Stop in transport/bridge/handler order; require each API's confirmation."""
    result = {}
    server = owned.server
    if server is None:
        result["server"] = "unknown" if owned.startup_pending else "not_started"
    else:
        try:
            await server.stop(grace=0)
            result["server"] = "confirmed"
        except Exception:
            result["server"] = "unknown"

    bridge = owned.bridge
    if bridge is None or not owned.bridge_started:
        result["bridge"] = "not_started"
    else:
        try:
            stopped = await bridge.stop(grace_seconds=BRIDGE_STOP_GRACE_SECONDS)
            result["bridge"] = "confirmed" if stopped is True else "unknown"
        except Exception:
            result["bridge"] = "unknown"

    handler = owned.handler
    if handler is None:
        result["handler"] = "not_started"
    else:
        try:
            stopped = await handler.shutdown(
                grace_seconds=handler.limits["compute_cancel_grace_seconds"])
            result["handler"] = "confirmed" if stopped is True else "unknown"
        except Exception:
            result["handler"] = "unknown"
    needed = [value for value in result.values() if value != "not_started"]
    result["overall"] = (
        "confirmed" if needed and all(value == "confirmed" for value in needed)
        else "confirmed" if not needed and not owned.startup_pending else "unknown")
    return result


def _install_stop_signals(stop_event: asyncio.Event) -> None:
    if os.name != "posix" or not hasattr(signal, "SIGTERM"):
        raise WorkerConfigError("the secure worker requires POSIX SIGTERM/SIGINT handling")
    loop = asyncio.get_running_loop()
    for signum in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(signum, stop_event.set)


async def _wait_for_external_supervisor() -> None:
    """Keep uncertain kernel/compute ownership fenced for the parent supervisor."""
    await asyncio.Event().wait()


def _owner_control_clock_ns(owned) -> int:
    sample = owned.clock.sample()
    value = sample.monotonic
    if (type(value) not in (int, float) or not math.isfinite(value)
            or value < 0):
        raise WorkerStatusUnavailable("owner control clock sample is invalid")
    result = int(value * 1_000_000_000)
    if result <= 0 or result > (1 << 63) - 1:
        raise WorkerStatusUnavailable("owner control clock sample is out of range")
    return result


def _owner_snapshot_candidate(config, owned, command):
    from steamboat_security import SnapshotStore, safe_read
    from steamboat_security.snapshot import MAX_SNAPSHOT_BYTES

    encoded = safe_read(
        config.signed_snapshot_path, root=config.protected_root,
        expected_uid=os.geteuid(), max_bytes=MAX_SNAPSHOT_BYTES)
    digest = hashlib.sha256(encoded).hexdigest()
    if digest != command.snapshot_sha256:
        raise WorkerConfigError("owner snapshot digest differs from the claimed command")
    current = owned.store.current()
    if command.snapshot_revision <= current.revision:
        raise WorkerConfigError("owner snapshot revision is not strictly newer")
    candidate_store = SnapshotStore(
        verification_key_pem=owned.snapshot_verification_key_pem,
        ca_certificate_pem=owned.cohort_ca_pem, clock=owned.clock)
    candidate = candidate_store.install(encoded)
    if (candidate.revision != command.snapshot_revision
            or candidate.revision <= current.revision
            or candidate.issued_at < current.issued_at):
        raise WorkerConfigError("owner snapshot does not advance the live policy")
    return encoded, candidate


def _verify_owner_removal_intent(config, command, intent_root, *,
                                 verification_key_pem, filename="removal-intent.json"):
    from steamboat_security import safe_read
    if type(intent_root) is not str or not intent_root:
        raise WorkerConfigError("owner policy intent requires an explicit protected root")
    root = Path(intent_root)
    if not root.is_absolute() or ".." in root.parts:
        raise WorkerConfigError("owner removal intent root is unsafe")
    try:
        root_resolved = root.resolve(strict=True)
        role_root = Path(config.protected_root).resolve(strict=True)
    except OSError:
        raise WorkerConfigError("owner removal intent root is unavailable") from None
    if root_resolved == role_root or role_root in root_resolved.parents:
        raise WorkerConfigError("owner removal intent must be outside the role root")
    if filename not in ("install-intent.json", "removal-intent.json"):
        raise WorkerConfigError("owner intent filename is not fixed")
    path = root / filename
    try:
        encoded = safe_read(path, root=root, expected_uid=os.geteuid(),
                            max_bytes=16 * 1024)
        def reject_pairs(items):
            value = {}
            for key, item in items:
                if key in value:
                    raise ValueError("duplicate JSON field")
                value[key] = item
            return value

        envelope = json.loads(encoded.decode("utf-8", errors="strict"),
                              object_pairs_hook=reject_pairs,
                              parse_constant=lambda _value: (_ for _ in ()).throw(
                                  ValueError("nonfinite JSON")),
                              parse_float=lambda _value: (_ for _ in ()).throw(
                                  ValueError("floating JSON")))
        if type(envelope) is not dict or set(envelope) != {
                "schema_version", "event", "intent", "signature"}:
            raise ValueError("closed envelope mismatch")
        envelope_bytes = json.dumps(
            envelope, sort_keys=True, separators=(",", ":"),
            ensure_ascii=True, allow_nan=False).encode("ascii")
        if envelope_bytes != encoded:
            raise ValueError("envelope is not canonical JSON")
        intent = envelope["intent"]
        if type(intent) is not dict or set(intent) != {
                "schema_version", "event", "run_id", "worker_boot_id",
                "command_id", "command_sha256", "snapshot_sha256",
                "snapshot_revision", "roles_off"}:
            raise ValueError("closed intent mismatch")
        canonical = json.dumps(intent, sort_keys=True, separators=(",", ":"),
                               ensure_ascii=True, allow_nan=False).encode("ascii")
        signature_text = envelope["signature"]
        import base64
        signature = base64.b64decode(signature_text, validate=True)
        if (type(signature_text) is not str or not 8 <= len(signature) <= 80
                or base64.b64encode(signature).decode("ascii") != signature_text):
            raise ValueError("signature encoding mismatch")
        if (type(envelope["schema_version"]) is not int
                or envelope["schema_version"] != 1
                or envelope["event"] != "signed_owner_removal_intent"
                or type(intent["schema_version"]) is not int
                or intent["schema_version"] != 1
                or intent["event"] != "owner_removal_intent"
                or intent["run_id"] != command.run_id
                or intent["worker_boot_id"] != command.worker_boot_id
                or intent["command_id"] != command.command_id
                or intent["command_sha256"] != command.command_sha256
                or intent["snapshot_sha256"] != command.snapshot_sha256
                or type(intent["snapshot_revision"]) is not int
                or intent["snapshot_revision"] != command.snapshot_revision
                or type(intent["roles_off"]) is not bool
                or intent["roles_off"] is not True):
            raise ValueError("intent does not match the claimed command")
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives.serialization import load_pem_public_key
        if type(verification_key_pem) is not bytes or not verification_key_pem:
            raise ValueError("pinned intent verification key is unavailable")
        key = load_pem_public_key(verification_key_pem)
        if (not isinstance(key, ec.EllipticCurvePublicKey)
                or not isinstance(key.curve, ec.SECP256R1)):
            raise ValueError("pinned intent key is not ECDSA P-256")
        from cryptography.hazmat.primitives.asymmetric.utils import (
            decode_dss_signature, encode_dss_signature)
        r_value, s_value = decode_dss_signature(signature)
        if encode_dss_signature(r_value, s_value) != signature:
            raise ValueError("signature is not canonical DER")
        key.verify(signature, b"steamboat-owner-removal-intent-v1\x00" + canonical,
                   ec.ECDSA(hashes.SHA256()))
        return intent
    except Exception as error:
        raise WorkerConfigError("signed owner removal intent is invalid") from error


def _owner_requires_full_revocation(config, owned, candidate):
    initial = owned.owner_initial_credential_pins
    if type(initial) is not dict or not initial:
        raise WorkerConfigError("initial local credential pins are unavailable")
    if config.device_id in candidate.revoked_devices:
        return True
    for serial, pinned in initial.items():
        record = candidate.credentials_by_serial.get(serial)
        if serial in candidate.revoked_serials or record is None or record != pinned:
            return True
    return False


def _assert_owner_revocation(config, owned, current, candidate):
    initial = owned.owner_initial_credential_pins
    if type(initial) is not dict or not initial:
        raise WorkerConfigError("initial local credential pins are unavailable")
    local_serials = set(initial)
    local_serials.update(
        record.serial for record in current.credentials_by_serial.values()
        if record.device_id == config.device_id)
    candidate_local = [record for record in candidate.credentials_by_serial.values()
                       if record.device_id == config.device_id]
    if (config.device_id not in candidate.revoked_devices
            or not local_serials.issubset(candidate.revoked_serials)
            or candidate_local):
        raise WorkerConfigError("remove snapshot does not revoke every local role credential")
    if any(grant.device_id == config.device_id
           or grant.target_device_id == config.device_id
           for grant in candidate.grants):
        raise WorkerConfigError("remove snapshot retains a grant to or from this device")


def _has_worker_open_grant(config, view, sample):
    from steamboat_security.codec import WORKER_SERVICE
    record = next((item for item in view.credentials_by_serial.values()
                   if item.device_id == config.device_id
                   and item.role == "host"), None)
    if (record is None or record.account_id != config.account_id
            or config.listen_ip not in record.ip_sans):
        return False
    return any(
        grant.target_account_id == config.account_id
        and grant.target_device_id == config.device_id
        and grant.target_role == "host"
        and grant.target_serial == record.serial
        and grant.target_public_key_sha256 == record.public_key_sha256
        and grant.target_credential_epoch == record.credential_epoch
        and grant.target_boot_id == config.boot_id
        and grant.assignment_id == config.assignment_id
        and grant.model_id == config.manifest_fingerprint
        and grant.method == f"{WORKER_SERVICE}/OpenSession"
        for grant in view.active_grants(sample))


def _owner_control_failure(owned, stop_event, reason):
    bridge = owned.bridge
    if bridge is not None:
        try:
            bridge._fence(reason)
        except Exception:
            pass
    stop_event.set()


def _enable_owner_controls(config, owned, run_id, removal_intent_root):
    if run_id is None:
        if removal_intent_root is not None:
            raise WorkerConfigError("removal intent root requires owner controls")
        return
    if (type(run_id) is not str
            or re.fullmatch(r"[0-9a-f]{32}", run_id, re.ASCII) is None):
        raise WorkerConfigError("owner controls run ID must be 32 lowercase hexadecimal characters")
    if type(removal_intent_root) is not str and removal_intent_root is not None:
        raise WorkerConfigError("owner removal intent root must be an absolute path")
    from lab.secure_worker_owner_control import OwnerControlInbox
    owned.owner_controls_enabled = True
    owned.owner_control_run_id = run_id
    owned.owner_control_inbox = OwnerControlInbox(
        config.protected_root, run_id=run_id, worker_boot_id=config.boot_id,
        expected_uid=os.geteuid())

    def observe_notice(notice):
        if (not owned.owner_control_notice_armed
                or owned.owner_control_notice_sequence <= 0
                or owned.owner_control_notice_sequence
                    != owned.owner_control_last_sequence
                or not owned.owner_control_notice_command_sha256
                or owned.owner_control_notice_command_sha256
                    != owned.owner_control_last_command_sha256
                or owned.owner_control_notice_snapshot_revision
                    != owned.owner_control_last_snapshot_revision
                or getattr(notice, "target_device_id", None) != config.device_id
                or getattr(notice, "worker_boot_id", None) != config.boot_id
                or getattr(notice, "reason", None) != "authorization-snapshot-changed"
                or owned.owner_control_revocation_notice_monotonic_ns):
            return
        try:
            owned.owner_control_revocation_notice_monotonic_ns = _owner_control_clock_ns(owned)
        except Exception:
            owned.owner_control_notice_fault = True

    try:
        owned.bindings.subscribe(observe_notice)
    except Exception as error:
        raise WorkerConfigError("owner control notice observation could not be installed") from error


async def _owner_control_loop(config, owned, stop_event, *, removal_intent_root):
    inbox = owned.owner_control_inbox
    while not stop_event.is_set():
        if owned.owner_control_notice_fault:
            _owner_control_failure(owned, stop_event,
                                   "owner revocation notice observation failed")
            raise WorkerStatusUnavailable("owner revocation notice observation failed")
        try:
            command = inbox.claim_next()
        except Exception:
            _owner_control_failure(owned, stop_event, "owner control claim failed")
            raise WorkerStatusUnavailable("owner control claim failed") from None
        if command is None:
            try:
                await asyncio.wait_for(stop_event.wait(), timeout=0.2)
            except asyncio.TimeoutError:
                continue
            return

        try:
            received_ns = _owner_control_clock_ns(owned)
            owned.owner_control_last_sequence = command.sequence
            owned.owner_control_last_command_sha256 = command.command_sha256
            owned.owner_control_last_action = command.action
            owned.owner_control_received_monotonic_ns = received_ns
            owned.owner_control_removal_intent_verified = False
            if command.action == "drain":
                owned.bridge.begin_drain(command.drain_seconds)
                applied_digest = owned.installed_snapshot_sha256
                applied_revision = owned.installed_snapshot_revision
            elif command.action in ("install_snapshot", "remove"):
                current = owned.store.current()
                removal_intent = None
                encoded, candidate = _owner_snapshot_candidate(config, owned, command)
                full_revocation = _owner_requires_full_revocation(
                    config, owned, candidate)
                if full_revocation and command.action == "install_snapshot":
                    removal_intent = _verify_owner_removal_intent(
                        config, command, removal_intent_root,
                        verification_key_pem=owned.snapshot_verification_key_pem,
                        filename="install-intent.json")
                if command.action == "remove":
                    removal_intent = _verify_owner_removal_intent(
                        config, command, removal_intent_root,
                        verification_key_pem=owned.snapshot_verification_key_pem,
                        filename="removal-intent.json")
                    full_revocation = True
                if full_revocation:
                    _assert_owner_revocation(config, owned, current, candidate)
                    lifecycle_before = owned.bridge.owner_lifecycle_status()
                    if lifecycle_before["phase"] == "ready":
                        owned.bridge.begin_drain(30)
                owned.owner_control_last_snapshot_revision = command.snapshot_revision
                owned.owner_control_notice_armed = True
                owned.owner_control_notice_sequence = command.sequence
                owned.owner_control_notice_command_sha256 = command.command_sha256
                owned.owner_control_notice_snapshot_revision = command.snapshot_revision
                owned.owner_control_revocation_notice_monotonic_ns = 0
                owned.owner_control_notice_fault = False
                try:
                    installed = owned.store.install(encoded)
                finally:
                    owned.owner_control_notice_armed = False
                if owned.owner_control_notice_fault:
                    raise WorkerStatusUnavailable(
                        "owner revocation notice observation failed")
                if installed.revision != candidate.revision:
                    raise WorkerConfigError("installed owner snapshot differs from preflight")
                owned.installed_snapshot_sha256 = hashlib.sha256(encoded).hexdigest()
                owned.installed_snapshot_revision = installed.revision
                owned.owner_control_removal_intent_verified = removal_intent is not None
                applied_digest = owned.installed_snapshot_sha256
                applied_revision = installed.revision
                if command.action == "install_snapshot" and not _has_worker_open_grant(
                        config, installed, owned.clock.sample()):
                    lifecycle_after_install = owned.bridge.owner_lifecycle_status()
                    if lifecycle_after_install["phase"] == "ready":
                        owned.bridge.begin_drain(30)
            else:
                raise WorkerConfigError("unsupported owner control action")
            completed_ns = _owner_control_clock_ns(owned)
            owned.owner_control_applied_monotonic_ns = completed_ns
            owned.owner_control_applied_snapshot_sha256 = applied_digest
            owned.owner_control_applied_revision = applied_revision
            lifecycle = owned.bridge.owner_lifecycle_status()
            if (type(lifecycle) is not dict
                    or set(lifecycle) != {
                        "phase", "drain_started_monotonic",
                        "drain_deadline_monotonic", "deadline_reached"}):
                raise WorkerStatusUnavailable("owner lifecycle status is malformed")
            if (type(lifecycle["phase"]) is not str
                    or lifecycle["phase"] not in ("ready", "draining", "paused")
                    or type(lifecycle["deadline_reached"]) is not bool):
                raise WorkerStatusUnavailable("owner lifecycle phase is malformed")
            for field in ("drain_started_monotonic", "drain_deadline_monotonic"):
                number = lifecycle[field]
                if (number is not None and (type(number) not in (int, float)
                                            or not math.isfinite(number))):
                    raise WorkerStatusUnavailable("owner lifecycle deadline is malformed")
            if ((lifecycle["drain_started_monotonic"] is None)
                    != (lifecycle["drain_deadline_monotonic"] is None)):
                raise WorkerStatusUnavailable("owner lifecycle deadline pair is incomplete")
            owned.owner_lifecycle_cache = dict(lifecycle)
            phase = "removing" if command.action == "remove" else lifecycle["phase"]
            inbox.write_ack(
                command, accepted=True, failure_code=None,
                received_monotonic_ns=received_ns,
                completed_monotonic_ns=completed_ns, phase=phase,
                applied_snapshot_sha256=applied_digest,
                applied_revision=applied_revision)
            if command.action == "remove":
                lifecycle = owned.bridge.owner_lifecycle_status()
                if lifecycle["phase"] not in ("draining", "paused"):
                    raise WorkerStatusUnavailable(
                        "final removal status is not an observed draining state")
                owned.owner_lifecycle_cache = dict(lifecycle)
                status = _status_payload(config, owned, event="status", phase="draining")
                if (status["phase"] != "draining"
                        or status.get("owner_lifecycle", {}).get("phase")
                            != lifecycle["phase"]):
                    raise WorkerStatusUnavailable(
                        "final removal status differs from owner lifecycle")
                _publish(config, status)
                stop_event.set()
                return
        except Exception:
            try:
                completed_ns = _owner_control_clock_ns(owned)
                inbox.write_ack(
                    command, accepted=False, failure_code="apply_failed",
                    received_monotonic_ns=(owned.owner_control_received_monotonic_ns
                                           or completed_ns),
                    completed_monotonic_ns=completed_ns, phase="unavailable",
                    applied_snapshot_sha256=owned.installed_snapshot_sha256,
                    applied_revision=owned.installed_snapshot_revision)
            except Exception:
                pass
            _owner_control_failure(owned, stop_event, "owner control application failed")
            raise WorkerStatusUnavailable("owner control application failed") from None


async def _heartbeat_status_report(config, owned, stop_event, *,
                                   interval_seconds=STATUS_HEARTBEAT_SECONDS) -> None:
    """Refresh the protected status file while the worker accepts requests."""
    while not stop_event.is_set():
        try:
            await asyncio.wait_for(stop_event.wait(), timeout=interval_seconds)
        except asyncio.TimeoutError:
            payload = _status_payload(
                config, owned, event="heartbeat", phase="ready")
            _write_status_report(config, payload)
            if payload["phase"] == "unavailable":
                raise WorkerStatusUnavailable(
                    "required worker runtime or resource status is unavailable")


async def serve(config: SecureWorkerConfig, *, root_binding=None,
                root_ready_callback=None, owner_controls_run_id=None,
                owner_removal_intent_root=None) -> int:
    if root_ready_callback is not None and root_binding is None:
        raise WorkerConfigError("root READY callback is available only in root mode")
    if root_ready_callback is not None and not callable(root_ready_callback):
        raise WorkerConfigError("root READY callback must be callable")
    if owner_controls_run_id is not None and root_binding is not None:
        raise WorkerConfigError("owner controls are unavailable in root-bound mode")
    if (owner_controls_run_id is None and owner_removal_intent_root is not None):
        raise WorkerConfigError("removal intent root requires owner controls")
    if (owner_controls_run_id is not None
            and (type(owner_controls_run_id) is not str
                 or re.fullmatch(r"[0-9a-f]{32}", owner_controls_run_id,
                                 re.ASCII) is None)):
        raise WorkerConfigError("owner controls run ID must be 32 lowercase hexadecimal characters")
    if (owner_removal_intent_root is not None
            and (type(owner_removal_intent_root) is not str
                 or not Path(owner_removal_intent_root).is_absolute()
                 or ".." in Path(owner_removal_intent_root).parts)):
        raise WorkerConfigError("owner removal intent root must be a safe absolute path")
    owned = _OwnedRuntime()
    stop_event = asyncio.Event()
    _install_stop_signals(stop_event)
    from steamboat_runtime.protocol.secure_transport import (
        LocalTlsIdentity,
        SecureTaskPending,
        create_secure_worker_server,
    )

    startup_error = None
    shutdown = {"state": "not_started"}
    heartbeat_task = None
    stop_wait_task = None
    owner_control_task = None
    try:
        _build_runtime(config, owned, root_binding=root_binding)
        _enable_owner_controls(config, owned, owner_controls_run_id,
                               owner_removal_intent_root)
        if stop_event.is_set():
            return_code = 0
        else:
            await owned.bridge.start()
            owned.bridge_started = True
            owned.server = await create_secure_worker_server(
                owned.bridge.handler,
                listen_endpoint=config.endpoint,
                allowed_listen_addresses=(config.listen_ip,),
                server_identity=LocalTlsIdentity(
                    owned.certificate_pem, owned.private_key_pem),
                client_ca_pem=owned.cohort_ca_pem,
                authorizer=owned.bridge.incoming_authorizer,
                authorization_watcher=owned.bridge.authorization_watcher,
                connection_controller=owned.budget,
                listener_id=f"worker-{config.device_id}-{config.boot_id}",
                listener_slots=LISTENER_SLOTS,
                acceptor_directory=config.acceptor_directory)
            ready_status = _status_payload(
                config, owned, event="ready", phase="ready")
            if ready_status["phase"] != "ready":
                raise WorkerStatusUnavailable(
                    "required worker runtime or resource status is unavailable")
            if root_binding is not None:
                # The protected selected store is the same object used by the
                # authorizer; recheck the real leaf/grant after listener start.
                _assert_worker_policy(config, owned.authorizer)
            _publish(config, ready_status, emit=root_binding is None)
            if root_ready_callback is not None:
                # Status publication may block on protected filesystem I/O.
                # Recheck the same store after that boundary, immediately
                # before the trusted callback emits the launch READY frame.
                _assert_worker_policy(config, owned.authorizer)
                callback_result = root_ready_callback()
                if callback_result is not None:
                    close = getattr(callback_result, "close", None)
                    if callable(close):
                        close()
                    raise WorkerConfigError("root READY callback must return exactly None")
            heartbeat_task = asyncio.create_task(
                _heartbeat_status_report(config, owned, stop_event),
                name="secure-worker-status-heartbeat")
            stop_wait_task = asyncio.create_task(
                stop_event.wait(), name="secure-worker-stop-wait")
            if owned.owner_controls_enabled:
                owner_control_task = asyncio.create_task(
                    _owner_control_loop(
                        config, owned, stop_event,
                        removal_intent_root=owner_removal_intent_root),
                    name="secure-worker-owner-control")
            waiters = (heartbeat_task, stop_wait_task, owner_control_task)
            waiters = tuple(task for task in waiters if task is not None)
            done, _pending = await asyncio.wait(
                waiters,
                return_when=asyncio.FIRST_COMPLETED)
            if heartbeat_task in done:
                # A status-report failure must stop accepting work; do not let
                # the supervisor observe a stale READY file indefinitely.
                await heartbeat_task
            if owner_control_task is not None and owner_control_task in done:
                await owner_control_task
            if stop_wait_task in done:
                await stop_wait_task
            _publish(config, _status_payload(
                config, owned, event="status", phase="draining"),
                emit=root_binding is None)
            return_code = 0
    except SecureTaskPending as error:
        startup_error = error
        if owned.bridge is not None and bool(getattr(owned.bridge, "_started", False)):
            owned.bridge_started = True
        owned.startup_pending = True
        owned.pending_tasks = tuple(getattr(error, "tasks", ()))
        return_code = 70
    except Exception as error:
        startup_error = error
        if owned.bridge is not None and bool(getattr(owned.bridge, "_started", False)):
            owned.bridge_started = True
        return_code = 1
    finally:
        for task in (heartbeat_task, stop_wait_task, owner_control_task):
            if task is not None and not task.done():
                task.cancel()
        remaining_tasks = tuple(
            task for task in (heartbeat_task, stop_wait_task, owner_control_task)
            if task is not None and not task.done())
        if remaining_tasks:
            await asyncio.gather(*remaining_tasks, return_exceptions=True)
        for task in (heartbeat_task, stop_wait_task, owner_control_task):
            if task is not None and task.done() and not task.cancelled():
                # Retrieve background failures to avoid unobserved-task logs.
                try:
                    task.exception()
                except Exception:
                    pass
        shutdown = await _shutdown_components(owned)
        final_phase = "startup_failed" if startup_error is not None else "stopped"
        if shutdown["overall"] != "confirmed":
            return_code = 70
        final_status = _status_payload(
            config, owned, event="final", phase=final_phase,
            shutdown=shutdown, startup_error=startup_error,
            report_state="confirmed")
        try:
            _publish(config, final_status, emit=root_binding is None)
        except Exception:
            final_status["report_state"] = "unknown"
            try:
                if root_binding is None:
                    _emit(final_status)
            except Exception:
                pass
            return_code = 1 if return_code == 0 else return_code
        if shutdown["overall"] != "confirmed":
            await _wait_for_external_supervisor()
    return return_code


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True,
                        help="absolute path to the protected mode-0600 worker JSON")
    parser.add_argument("--owner-controls-run-id",
                        help="opt into the fixed protected local owner command inbox")
    parser.add_argument("--owner-removal-intent-root",
                        help="absolute protected directory for owner-signed removal intent")
    args = parser.parse_args(argv)
    try:
        config = load_worker_config(args.config)
        return asyncio.run(serve(
            config, owner_controls_run_id=args.owner_controls_run_id,
            owner_removal_intent_root=args.owner_removal_intent_root))
    except Exception as error:
        payload = {
            "schema_version": 1,
            "event": "final",
            "phase": "startup_failed",
            "status": "unknown",
            "error_type": type(error).__name__[:80],
        }
        try:
            _emit(payload)
        except Exception:
            pass
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
