"""Fixed local CPU coordinator runtime for a selected root binding.

This adapter composes existing secure runtime components. It is not a daemon,
launcher, remote supervisor, or general service framework.
"""
from __future__ import annotations

import asyncio
import hashlib
import inspect
import json
import os
import stat
import uuid
from pathlib import Path

from steamboat_security.codec import canonical_json
from steamboat_security.errors import BindingError, CredentialError
from steamboat_security.files import _open_parent, safe_read
from steamboat_security.root_runtime import (
    RootRuntimeBinding, _configuration_header, _pairs,
    _require_current_role_grants,
)
from steamboat_security.root_transition_launch import (
    RoleLaunchSpec, role_launch_document, parse_role_launch_spec,
)

from .root_coordinator_config import (
    MAX_CONFIG_BYTES, RootCoordinatorConfig, parse_config_bytes,
)

MAX_STATUS_BYTES = 4096
MAX_CERTIFICATE_BYTES = 64 * 1024
MAX_CLEANUP_SECONDS = 15.0
_RETAINED_UNKNOWN_OWNERS = []
_RETAINED_CLEANUP_TASKS = set()


def _retain_unknown_owner(owners):
    if not any(owner is owners for owner in _RETAINED_UNKNOWN_OWNERS):
        _RETAINED_UNKNOWN_OWNERS.append(owners)


def _retain_cleanup_task(task):
    _RETAINED_CLEANUP_TASKS.add(task)
    task.add_done_callback(_RETAINED_CLEANUP_TASKS.discard)


def _active_request_count(owners):
    coordinator = owners.coordinator
    stats = getattr(coordinator, "stats", None) if coordinator is not None else None
    if not callable(stats):
        return None
    try:
        value = stats()
    except Exception:
        return None
    if type(value) is not dict:
        return None
    count = value.get("active_requests")
    return count if type(count) is int and count >= 0 else None


async def _bounded_cleanup(awaitable, deadline, label, owners, *, allow_none=False):
    remaining = deadline - asyncio.get_running_loop().time()
    if remaining <= 0:
        close = getattr(awaitable, "close", None)
        if callable(close):
            close()
        _retain_unknown_owner(owners)
        return RuntimeError(f"cleanup deadline expired before {label}")
    task = asyncio.create_task(awaitable)
    try:
        done, pending = await asyncio.wait((task,), timeout=remaining)
    except BaseException:
        _retain_cleanup_task(task)
        _retain_unknown_owner(owners)
        raise
    if pending:
        _retain_cleanup_task(task)
        _retain_unknown_owner(owners)
        return TimeoutError(f"bounded cleanup did not confirm {label}")
    try:
        result = task.result()
    except BaseException as error:
        _retain_unknown_owner(owners)
        return error
    if result is True or (allow_none and result is None):
        return None
    _retain_unknown_owner(owners)
    return RuntimeError(f"{label} returned a non-confirming result")


def _exact_dataclass(left, right):
    fields = getattr(type(left), "__dataclass_fields__", None)
    return (type(left) is type(right) and fields is not None
            and all(type(getattr(left, name)) is type(getattr(right, name))
                    for name in fields)
            and left == right)


def _validated_binding(config, root_binding):
    if type(config) is not RootCoordinatorConfig:
        raise BindingError("root coordinator requires an exact parsed configuration")
    if type(root_binding) is not RootRuntimeBinding:
        raise BindingError("root coordinator requires an exact root runtime binding")
    from steamboat_security.authorization import LocalIdentity
    from steamboat_security.clock import Clock
    from steamboat_security.snapshot import SnapshotStore
    from steamboat_security.root_runtime import TLSMaterials
    if (type(root_binding.local_identity) is not LocalIdentity
            or type(root_binding.snapshot_store) is not SnapshotStore
            or type(root_binding.snapshot_store.clock) is not Clock
            or type(root_binding.tls_materials) is not TLSMaterials
            or type(root_binding.runtime_configuration) is not bytes
            or type(root_binding.configuration_header) is not bytes):
        raise BindingError("root coordinator binding has unexpected component types")
    try:
        header = json.loads(
            root_binding.configuration_header.decode("utf-8", errors="strict"),
            object_pairs_hook=_pairs)
        if canonical_json(header) != root_binding.configuration_header:
            raise BindingError("root configuration header is not canonical")
        _configuration_header(header)
        parsed = parse_config_bytes(
            root_binding.runtime_configuration,
            config_path=header["runtime_configuration_path"],
            protected_root=header["protected_root"])
        spec = parse_role_launch_spec(role_launch_document(root_binding.launch_spec))
    except Exception as error:
        if isinstance(error, BindingError):
            raise
        raise BindingError("root coordinator role configuration is invalid") from error
    if not _exact_dataclass(config, parsed):
        raise BindingError("supplied coordinator config differs from protected runtime bytes")
    identity = root_binding.local_identity
    if (type(spec) is not RoleLaunchSpec or spec.role != "personal_coordinator"
            or spec.identity != (header["account_id"], header["device_id"],
                                 "personal_coordinator")
            or header["role"] != spec.role
            or header["account_id"] != spec.account_id
            or header["device_id"] != spec.device_id
            or header["boot_id"] != spec.boot_id
            or header["credential_epoch"] != spec.credential_epoch
            or header["admission_epoch"] != spec.admission_epoch
            or header["generation_sha256"] != spec.generation_sha256
            or header["launch_nonce"] != spec.launch_nonce
            or header["model_id"] != identity.model_id):
        raise BindingError("root binding is not the selected personal coordinator role")
    if (identity.certificate_pem != root_binding.tls_materials.certificate_pem
            or identity.boot_id != spec.boot_id
            or identity.model_id != header["model_id"]
            or identity.assignment_id != header["assignment_id"]
            or identity.admission_epoch != spec.admission_epoch
            or identity.root_generation_sha256 != spec.generation_sha256
            or header["assignment_id"] is not None
            or hashlib.sha256(root_binding.runtime_configuration).hexdigest()
                != header["runtime_configuration_sha256"]
            or config.configuration_path != header["runtime_configuration_path"]
            or config.protected_root != header["protected_root"]
            or hashlib.sha256(root_binding.configuration_header).hexdigest()
                != spec.configuration_sha256
            or os.path.normcase(config.status_report_path) in {
                os.path.normcase(header["certificate_path"]),
                os.path.normcase(header["private_key_path"]),
            }):
        raise BindingError("root coordinator config or identity differs from selected launch")
    from steamboat_security.certificates import (
        _key, _pem_certificate, certificate_sha256, public_key_sha256, serial_hex,
    )
    certificate = _pem_certificate(identity.certificate_pem)
    if (certificate_sha256(certificate) != spec.certificate_sha256
            or public_key_sha256(certificate.public_key()) != spec.public_key_sha256
            or public_key_sha256(_key(root_binding.tls_materials.private_key_pem).public_key())
                != spec.public_key_sha256
            or serial_hex(certificate.serial_number) != spec.serial):
        raise BindingError("root coordinator TLS leaf differs from selected launch pins")
    # The configuration is immutable in the binding and is also re-read from
    # its protected path so a stale or replaced runtime file cannot be served.
    if safe_read(config.configuration_path, root=config.protected_root,
                 expected_uid=os.geteuid(), max_bytes=MAX_CONFIG_BYTES) != (
                     root_binding.runtime_configuration):
        raise BindingError("protected coordinator runtime configuration changed")
    _check_binding_files(root_binding, header, config)
    return header, spec


def _check_binding_files(binding, header, config):
    expected = (
        (header["runtime_configuration_path"], binding.runtime_configuration,
         MAX_CONFIG_BYTES),
        (header["certificate_path"], binding.tls_materials.certificate_pem,
         MAX_CERTIFICATE_BYTES),
        (header["private_key_path"], binding.tls_materials.private_key_pem,
         1024 * 1024),
    )
    for path, contents, limit in expected:
        if safe_read(path, root=config.protected_root, expected_uid=os.geteuid(),
                     max_bytes=limit) != contents:
            raise CredentialError("protected coordinator role files changed; restart is required")


def _current_local_policy(binding, header, spec, listen_ip,
                          max_clock_uncertainty_seconds, *, sample=None, view=None):
    from steamboat_security.certificates import _pem_certificate, certificate_sha256
    sample = sample or binding.snapshot_store.clock.sample()
    if sample.uncertainty > max_clock_uncertainty_seconds:
        raise CredentialError("root coordinator clock uncertainty exceeds config bound")
    view = view or binding.snapshot_store.current(sample=sample)
    record = view.credentials_by_serial.get(spec.serial)
    if (record is None or record.identity != spec.identity
            or record.credential_epoch != spec.credential_epoch
            or record.certificate_sha256 != spec.certificate_sha256
            or record.public_key_sha256 != spec.public_key_sha256
            or certificate_sha256(_pem_certificate(binding.tls_materials.certificate_pem))
                != record.certificate_sha256
            or listen_ip not in record.ip_sans):
        raise CredentialError("selected coordinator credential is not current for listener")
    binding.snapshot_store.assert_credential_live(view, record, sample)
    _require_current_role_grants(view, sample, record, spec, header)
    return view, sample, record


def _read_worker_certificates(config):
    return tuple((worker, safe_read(
        worker.certificate_path, root=config.protected_root,
        expected_uid=os.geteuid(), max_bytes=MAX_CERTIFICATE_BYTES))
        for worker in config.workers)


def _worker_records_from_materials(config, binding, local_record, materials,
                                   *, sample, view):
    from steamboat_security.certificates import (
        _pem_certificate, certificate_sha256, verify_leaf,
    )
    active = view.active_grants(sample)
    result = []
    from steamboat_security.codec import WORKER_SERVICE
    # Describe is the bounded bootstrap capability; all request-bearing session
    # operations need their own current grants before the coordinator can serve.
    required_methods = {
        f"{WORKER_SERVICE}/{method}" for method in (
            "OpenSession", "RenewSession", "Step", "CloseSession",
            "CancelSession", "SessionStatus")}
    bootstrap_describe = f"{WORKER_SERVICE}/Describe"
    for worker, certificate in materials:
        grants = [grant for grant in active if (
                grant.actor_serial == local_record.serial
                and grant.actor_boot_id == binding.launch_spec.boot_id
                and grant.target_boot_id == worker.boot_id
                and grant.target_account_id == worker.account_id
                and grant.target_device_id == worker.device_id
                and grant.target_role == "host"
                and grant.assignment_id == worker.assignment_id
                and grant.model_id == binding.local_identity.model_id
                and grant.method in required_methods)]
        if ({grant.method for grant in grants} != set(required_methods)
                or len(grants) != len(required_methods)):
            raise CredentialError("selected policy lacks the complete coordinator-to-worker method grants")
        if not any(grant.actor_serial == local_record.serial
                   and grant.actor_boot_id == binding.launch_spec.boot_id
                   and grant.target_boot_id == worker.boot_id
                   and grant.target_account_id == worker.account_id
                   and grant.target_device_id == worker.device_id
                   and grant.assignment_id == worker.assignment_id
                   and grant.model_id == binding.local_identity.model_id
                   and grant.method == bootstrap_describe for grant in active):
            raise CredentialError("selected policy lacks the separate worker Describe bootstrap grant")
        grant_serials = {grant.target_serial for grant in grants}
        cert_object = _pem_certificate(certificate)
        matches = [item for item in view.credentials_by_serial.values()
                   if item.identity == (worker.account_id, worker.device_id, "host")
                   and item.serial in grant_serials
                   and certificate_sha256(cert_object) == item.certificate_sha256]
        if len(matches) != 1:
            raise CredentialError("selected policy has no active coordinator-to-worker grant")
        record = matches[0]
        if worker.ip not in record.ip_sans:
            raise CredentialError("configured worker endpoint is absent from selected IP SANs")
        verify_leaf(
            binding.snapshot_store.ca_certificate_pem, certificate,
            now=sample.wall, uncertainty_seconds=sample.uncertainty,
            account_id=record.account_id, device_id=record.device_id,
            role=record.role, serial=record.serial,
            public_key_hash=record.public_key_sha256,
            certificate_hash=record.certificate_sha256, ekus=record.ekus,
            dns_sans=record.dns_sans, ip_sans=record.ip_sans)
        binding.snapshot_store.assert_credential_live(view, record, sample)
        result.append((worker, record, certificate))
    return tuple(result)


def _worker_records(config, binding, local_record):
    materials = _read_worker_certificates(config)
    sample = binding.snapshot_store.clock.sample()
    view = binding.snapshot_store.current(sample=sample)
    return _worker_records_from_materials(
        config, binding, local_record, materials, sample=sample, view=view)


def _check_worker_records(config, binding, header, local_record):
    return _worker_records(config, binding, local_record)


def _write_status(config, uid, payload):
    raw = canonical_json(payload)
    if not 1 <= len(raw) <= MAX_STATUS_BYTES:
        raise BindingError("coordinator status exceeds its 4 KiB bound")
    root, target = Path(config.protected_root), Path(config.status_report_path)
    parent_fd, name = _open_parent(root, target, expected_uid=uid)
    temporary = f".{name}.tmp-{uuid.uuid4().hex}"
    descriptor = None
    try:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
        descriptor = os.open(temporary, flags, 0o600, dir_fd=parent_fd)
        info = os.fstat(descriptor)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != uid
                or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1):
            raise BindingError("coordinator temporary status file failed protection checks")
        view = memoryview(raw)
        while view:
            count = os.write(descriptor, view)
            if count <= 0:
                raise OSError("short coordinator status write")
            view = view[count:]
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = None
        try:
            current = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            if (not stat.S_ISREG(current.st_mode) or current.st_uid != uid
                    or stat.S_IMODE(current.st_mode) != 0o600 or current.st_nlink != 1):
                raise BindingError("existing coordinator status path is not a protected file")
        os.replace(temporary, name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
        os.fsync(parent_fd)
    finally:
        if descriptor is not None:
            os.close(descriptor)
        try:
            os.unlink(temporary, dir_fd=parent_fd)
        except FileNotFoundError:
            pass
        os.close(parent_fd)


def _invoke_ready_callback(callback):
    if callback is None:
        return
    result = callback()
    if result is not None:
        if inspect.isawaitable(result):
            close = getattr(result, "close", None)
            if callable(close):
                close()
        raise BindingError("root READY callback must return exactly None")


class _Owners:
    def __init__(self):
        self.server = None
        self.coordinator = None
        self.model = None
        self.clients = []
        self.watcher = None
        self.budget = None
        self.capture = None
        self.service = None
        self.secure_service = None


async def _close_owners_impl(owners):
    deadline = asyncio.get_running_loop().time() + MAX_CLEANUP_SECONDS
    errors = []
    if owners.server is not None:
        error = await _bounded_cleanup(owners.server.stop(0), deadline,
                                       "coordinator listener stop", owners,
                                       allow_none=True)
        if error is not None:
            return [error]
    if owners.coordinator is not None:
        error = await _bounded_cleanup(owners.coordinator.close(), deadline,
                                       "coordinator close", owners)
        if error is not None:
            return [error]
    else:
        for client in reversed(owners.clients):
            error = await _bounded_cleanup(
                client.close(), deadline, "coordinator worker client close", owners,
                allow_none=True)
            if error is not None:
                errors.append(error)
        if owners.model is not None:
            error = await _bounded_cleanup(
                owners.model.close(), deadline, "coordinator model close", owners)
            if error is not None:
                errors.append(error)
    if owners.budget is not None:
        if (owners.budget.reserved_connections != 0
                or owners.budget.reserved_pending != 0
                or owners.budget.reserved_outbound_pending != 0
                or owners.budget.reserved_listener_pending_capacity != 0):
            errors.append(RuntimeError("coordinator transport reservations remain"))
    if owners.service is not None and (
            owners.service.active_streams != 0 or owners.service.cleanups):
        errors.append(RuntimeError("coordinator service retains stream cleanup owners"))
    if (owners.secure_service is not None
            and owners.secure_service.active_generate_streams != 0):
        errors.append(RuntimeError("secure coordinator retains Generate streams"))
    if owners.capture is not None:
        status = owners.capture.status()
        if (status.active_captures != 0 or status.cleanup_pending_captures != 0
                or status.reserved_bytes != 0):
            errors.append(RuntimeError("coordinator capture budget retains reservations"))
    if errors:
        _retain_unknown_owner(owners)
    return errors


async def _close_owners(owners):
    try:
        return await _close_owners_impl(owners)
    except BaseException:
        _retain_unknown_owner(owners)
        raise


async def serve(config: RootCoordinatorConfig, *, root_binding: RootRuntimeBinding,
                root_ready_callback=None, stop_event=None) -> dict:
    """Run the fixed root-bound three-worker CPU coordinator until stopped.

    READY callback is a trusted synchronous local hook. It reports successful
    adapter startup only; it is not remote supervisor or process-containment
    evidence.
    """
    if os.name != "posix" or not hasattr(os, "geteuid"):
        raise BindingError("root coordinator runtime requires native POSIX protected files")
    if stop_event is not None and type(stop_event) is not asyncio.Event:
        raise BindingError("stop_event must be an asyncio.Event")
    if root_ready_callback is not None and not callable(root_ready_callback):
        raise BindingError("root READY callback must be callable")
    uid = os.geteuid()
    if _RETAINED_UNKNOWN_OWNERS:
        raise BindingError("a prior root coordinator owner remains unresolved; cold restart is required")
    _header, spec = _validated_binding(config, root_binding)
    owners = _Owners()
    ready = False
    cleanup_started = False
    cleanup_completed = False
    stop_event = stop_event or asyncio.Event()
    try:
        import torch
        from steamboat_runtime.manifest import MODEL_ID, MODEL_REVISION, load_manifest
        from steamboat_runtime.prepare import verify_snapshot
        from steamboat_runtime.coordinator import Coordinator
        from steamboat_runtime.coordinator_service import CoordinatorService, supervised_model_class
        from steamboat_runtime.capture_budget import CaptureBudget, CaptureBudgetConfig
        from steamboat_runtime.protocol.secure_transport import (
            C0ExpectedServerLeafAdapter, ExpectedServerIdentity, FixedPeer,
            LocalTlsIdentity, NodeConnectionBudget,
            create_secure_worker_client,
        )
        from steamboat_runtime.secure_coordinator_service import create_secure_coordinator_server
        from steamboat_runtime.secure_context import BootstrapWorkerClient, ConsumerContextFactory
        from steamboat_runtime.participant_context import TrustedRequestContext
        from steamboat_runtime.protocol.worker_pb2 import Request
        from steamboat_runtime.remote_client import SERVICE as COORDINATOR_SERVICE
        from steamboat_security import AuthorizationWatcher, Authorizer, OutboundAuthorizer, OutboundTarget
        from steamboat_security.certificates import verify_expected_server_leaf
        from steamboat_security.codec import WORKER_SERVICE

        from lab.secure_worker_config import validate_readonly_artifacts
        validate_readonly_artifacts(config.artifact_directory)
        validate_readonly_artifacts(config.reference_directory)
        verify_snapshot(config.reference_directory)
        manifest = load_manifest(config.artifact_directory)
        if (manifest["fingerprint"] != root_binding.local_identity.model_id
                or manifest["fingerprint"] != _header["model_id"]
                or manifest["model_id"] != MODEL_ID
                or manifest["revision"] != MODEL_REVISION):
            raise BindingError("root coordinator model fingerprint differs from artifacts")
        if manifest["config"]["vocab_size"] != 32_000:
            raise BindingError("root coordinator only supports the pinned capture vocabulary")
        try:
            torch.set_num_threads(2)
            if torch.get_num_threads() != 2:
                raise BindingError("coordinator Torch pool did not accept the two-thread bound")
            try:
                torch.set_num_interop_threads(2)
            except RuntimeError:
                if torch.get_num_interop_threads() > 2:
                    raise
            if torch.get_num_interop_threads() > 2:
                raise BindingError("coordinator Torch interop pool exceeds two threads")
        except Exception as error:
            if isinstance(error, BindingError):
                raise
            raise BindingError("coordinator CPU thread bounds could not be applied") from error

        local_view, local_sample, local_record = _current_local_policy(
            root_binding, _header, spec, config.listen_ip,
            config.clock_uncertainty_seconds)
        worker_records = _check_worker_records(config, root_binding, _header, local_record)
        owners.budget = NodeConnectionBudget(max_connections=16, max_pending=4)
        owners.watcher = AuthorizationWatcher(poll_interval_seconds=0.5)
        tls_verifier = C0ExpectedServerLeafAdapter(
            lambda ca, leaf, **kwargs: verify_expected_server_leaf(
                ca, leaf, uncertainty_seconds=root_binding.snapshot_store.clock.sample().uncertainty,
                **kwargs))
        local_tls = LocalTlsIdentity(
            root_binding.tls_materials.certificate_pem,
            root_binding.tls_materials.private_key_pem)
        clients = []
        for worker, record, cert in worker_records:
            target = OutboundTarget.from_record(
                service=WORKER_SERVICE, record=record, boot_id=worker.boot_id,
                model_id=root_binding.local_identity.model_id,
                assignment_id=worker.assignment_id)
            outbound = OutboundAuthorizer(
                local_identity=root_binding.local_identity,
                snapshot_store=root_binding.snapshot_store,
                clock=root_binding.snapshot_store.clock, target=target,
                worker_request_type=Request,
                trusted_request_context_type=TrustedRequestContext,
                allow_bootstrap_describe=True)
            expected = ExpectedServerIdentity(
                worker.account_id, worker.device_id, "host", int(record.serial, 16),
                record.public_key_sha256, record.certificate_sha256,
                worker.ip, tuple(record.ekus))
            peer = FixedPeer(
                endpoint=f"{worker.ip}:{worker.port}", allowed_addresses=(worker.ip,),
                device_id=worker.device_id, server_leaf_pem=cert,
                cohort_ca_pem=root_binding.snapshot_store.ca_certificate_pem,
                expected_server=expected)
            client = await create_secure_worker_client(
                peer, local_identity=local_tls, outbound_authorizer=outbound,
                authorization_watcher=owners.watcher,
                verify_expected_server_leaf=tls_verifier,
                connection_controller=owners.budget,
                wall_clock=lambda: root_binding.snapshot_store.clock.sample().wall)
            owners.clients.append(client)
            bootstrap = outbound.create_bootstrap_context(
                lifetime_seconds=30, max_describes=2)
            clients.append(BootstrapWorkerClient(client, bootstrap))

        model = supervised_model_class().from_artifacts(
            config.artifact_directory, config.reference_directory)
        owners.model = model
        if model.manifest["fingerprint"] != manifest["fingerprint"]:
            raise BindingError("loaded coordinator model differs from verified artifacts")
        coordinator = Coordinator(manifest, clients, model)
        owners.coordinator = coordinator
        owners.model = None
        await coordinator.start()
        context_factory = ConsumerContextFactory(
            account_id=spec.account_id,
            device_id=spec.device_id,
            coordinator_boot_id=spec.boot_id,
            model_id=root_binding.local_identity.model_id)
        server_authorizer = Authorizer(
            local_identity=root_binding.local_identity,
            snapshot_store=root_binding.snapshot_store,
            clock=root_binding.snapshot_store.clock)
        owners.capture = CaptureBudget(CaptureBudgetConfig(
            vocabulary_size=manifest["config"]["vocab_size"]))
        service = CoordinatorService(coordinator)
        owners.service = service
        server, secure_service = await create_secure_coordinator_server(
            service, listen_endpoint=f"{config.listen_ip}:{config.listen_port}",
            allowed_listen_addresses=(config.listen_ip,), server_identity=local_tls,
            client_ca_pem=root_binding.snapshot_store.ca_certificate_pem,
            authorizer=server_authorizer, authorization_watcher=owners.watcher,
            request_context_factory=context_factory,
            connection_controller=owners.budget,
            listener_id=f"root-personal-coordinator-{spec.device_id}-{spec.boot_id}",
            listener_slots=1, acceptor_directory=config.acceptor_directory,
            capture_budget=owners.capture)
        owners.server = server
        owners.secure_service = secure_service
        _write_status(config, uid, {
            "schema_version": 1, "event": "root_coordinator_status",
            "phase": "ready", "ready": True, "worker_count": len(clients),
            "active_requests": 0,
        })
        _check_binding_files(root_binding, _header, config)
        final_worker_materials = _read_worker_certificates(config)
        final_sample = root_binding.snapshot_store.clock.sample()
        final_view = root_binding.snapshot_store.current(sample=final_sample)
        _current_local_policy(
            root_binding, _header, spec, config.listen_ip,
            config.clock_uncertainty_seconds, sample=final_sample, view=final_view)
        worker_records = _worker_records_from_materials(
            config, root_binding, local_record, final_worker_materials,
            sample=final_sample, view=final_view)
        _invoke_ready_callback(root_ready_callback)
        ready = True
        while not stop_event.is_set():
            try:
                await asyncio.wait_for(stop_event.wait(), timeout=1.0)
            except asyncio.TimeoutError:
                _current_local_policy(root_binding, _header, spec, config.listen_ip,
                                      config.clock_uncertainty_seconds)
                worker_records = _check_worker_records(config, root_binding, _header, local_record)
                _write_status(config, uid, {
                    "schema_version": 1, "event": "root_coordinator_status",
                    "phase": "ready", "ready": True, "worker_count": len(clients),
                    "active_requests": service.active_streams,
                })
        cleanup_started = True
        cleanup_errors = await _close_owners(owners)
        if cleanup_errors:
            _retain_unknown_owner(owners)
            raise RuntimeError("root coordinator shutdown remains unconfirmed") from cleanup_errors[0]
        cleanup_completed = True
        _write_status(config, uid, {
            "schema_version": 1, "event": "root_coordinator_status",
            "phase": "stopped", "ready": False, "shutdown_confirmed": True,
            "worker_count": len(clients), "active_requests": 0,
        })
        return {"ready_callback_completed": ready, "shutdown_confirmed": True,
                "worker_count": len(clients)}
    except BaseException as error:
        if cleanup_completed:
            try:
                _write_status(config, uid, {
                    "schema_version": 1, "event": "root_coordinator_status",
                    "phase": "failed", "ready": False,
                    "shutdown_confirmed": True,
                    "worker_count": len(owners.clients), "active_requests": 0,
                })
            except BaseException as status_error:
                if hasattr(error, "add_note"):
                    error.add_note(f"failed status publication also failed: {status_error!r}")
            raise
        if cleanup_started:
            try:
                _write_status(config, uid, {
                    "schema_version": 1, "event": "root_coordinator_status",
                    "phase": "failed", "ready": False,
                    "shutdown_confirmed": False,
                    "worker_count": len(owners.clients),
                    "active_requests": _active_request_count(owners),
                })
            except BaseException as status_error:
                if hasattr(error, "add_note"):
                    error.add_note(f"failed status publication also failed: {status_error!r}")
            _retain_unknown_owner(owners)
            raise RuntimeError("root coordinator shutdown remains unconfirmed") from error
        cleanup_errors = await _close_owners(owners)
        if cleanup_errors:
            _retain_unknown_owner(owners)
        # A prior ready status must never survive a failed startup/heartbeat as
        # affirmative evidence. Publish only the observed result of this
        # cleanup attempt; the status flag is not itself ownership evidence.
        try:
            _write_status(config, uid, {
                "schema_version": 1, "event": "root_coordinator_status",
                "phase": "failed", "ready": False,
                "shutdown_confirmed": not cleanup_errors,
                "worker_count": len(owners.clients),
                "active_requests": (0 if not cleanup_errors
                                     else _active_request_count(owners)),
            })
        except BaseException as status_error:
            if hasattr(error, "add_note"):
                error.add_note(f"failed status publication also failed: {status_error!r}")
        if cleanup_errors:
            raise RuntimeError("root coordinator failed and cleanup is unconfirmed") from error
        raise
