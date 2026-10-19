"""One bounded outbound coordinator channel to its selected worker cohort.

This owner composes existing C1 authorization, durable C2 policy/traffic,
gateway egress, TCP/TLS, HELLO and channel-client owners.  It is a transport
owner only: it does not schedule model work or claim service readiness.
"""
from __future__ import annotations

import asyncio
import hashlib
import inspect
import os
import socket
import threading

from steamboat_connector import channel_wire as wire
from steamboat_connector.c2_child_config import C2ChildBinding
from steamboat_connector.c2_coordinator_settings import load_c2_coordinator_settings
from steamboat_connector.channel_client import (
    CoordinatorChannelClient, _CONTROL_CAPTURE, _CONTROL_SLOTS,
    _DATA_CAPTURE, _DATA_SLOTS,
)
from steamboat_connector.channel_hello import CoordinatorHelloClient
from steamboat_connector.channel_policy_store import PersistentChannelPolicyStore
from steamboat_connector.channel_socket import ChannelSocket
from steamboat_connector.channel_stream import (
    DECODED_METADATA_RESERVATION_BYTES, HELLO_RESERVATION_BYTES,
    SOCKET_SCRATCH_RESERVATION_BYTES, TLS_OWNER_MIN_RESERVATION_BYTES,
    ChannelStream,
)
from steamboat_connector.channel_writer import writer_reservation_overhead_bytes
from steamboat_connector.policy import validate_policy
from steamboat_connector.traffic_budget import TrafficBudget
from steamboat_runtime.protocol.wire import Request
from steamboat_runtime.participant_context import TrustedRequestContext
from steamboat_security.files import safe_read
from steamboat_security.authorization import _verify_pinned_credential
from steamboat_security.outbound import OutboundAuthorizer, OutboundTarget, AuthorizationWatcher
from steamboat_security.gateway_egress import GatewayCoordinatorEgress, GatewayEgressError
from steamboat_security.errors import CredentialError


STARTUP_SECONDS = 30.0
PUMP_SLEEP_SECONDS = 0.001
MAX_CLOSE_SECONDS = 5.0
_WORKER_METHODS = (
    "steamboat.v1.Worker/Describe", "steamboat.v1.Worker/OpenSession",
    "steamboat.v1.Worker/RenewSession", "steamboat.v1.Worker/Step",
    "steamboat.v1.Worker/CloseSession", "steamboat.v1.Worker/CancelSession",
    "steamboat.v1.Worker/SessionStatus",
)


class C2CoordinatorChannelError(RuntimeError):
    """Coordinator channel startup, ownership, or bounded cleanup failed."""


def _observe_task(task):
    if not task.cancelled():
        task.exception()


def _read_pin(pin, *, root, uid, maximum, label):
    try:
        data = safe_read(pin.path, root=root, expected_uid=uid, max_bytes=maximum)
    except (OSError, ValueError) as error:
        raise CredentialError(f"protected {label} is unavailable") from error
    if not data or hashlib.sha256(data).hexdigest() != pin.sha256:
        raise CredentialError(f"protected {label} differs from its selected SHA-256")
    return data


def _stream_reservation():
    writer = writer_reservation_overhead_bytes() + wire.MAX_BUNDLE_BYTES + 8 * wire.MAX_CONTROL_BUNDLE_BYTES
    decoder = (2 * wire.MAX_BUNDLE_BYTES + wire.MAX_WIRE_FRAME_BYTES
               + wire.MAX_FEED_BYTES + wire.MAX_BUNDLE_BYTES + 64 * 1024)
    return (decoder + writer + wire.MAX_BUNDLE_BYTES
            + DECODED_METADATA_RESERVATION_BYTES + SOCKET_SCRATCH_RESERVATION_BYTES
            + HELLO_RESERVATION_BYTES + TLS_OWNER_MIN_RESERVATION_BYTES)


def _check_runtime_guard(owner):
    result = owner._runtime_guard()
    if result is not None:
        raise C2CoordinatorChannelError("runtime guard must return exactly None on success")


def _check_startup_deadline(loop, deadline, operation):
    if loop.time() >= deadline:
        raise C2CoordinatorChannelError(
            f"shared coordinator startup deadline elapsed during {operation}")


def _retain_egress_constructor_failure(owner, error):
    """Preserve the real core error when TLS ownership never transfers."""
    if error.cleanup_status == "uncertain" or error.credential_directory is not None:
        owner._startup_cleanup_error = error
        owner._startup_cleanup_metadata = {
            "cleanup_status": error.cleanup_status,
            "credential_directory": error.credential_directory,
        }
        owner._startup_cleanup_owner = getattr(error, "retained_owner", None)


async def _await_startup_task(owner, task, deadline, operation):
    _check_startup_deadline(owner._loop, deadline, operation)
    remaining = deadline - owner._loop.time()
    _done, pending = await asyncio.wait((task,), timeout=remaining)
    if pending:
        raise C2CoordinatorChannelError(f"{operation} remains in flight; retain owner")
    _check_startup_deadline(owner._loop, deadline, operation)
    _check_runtime_guard(owner)
    return task.result()


async def _open_selected_socket(owner, loop, endpoint_host, endpoint_port, deadline):
    """Resolve and attempt exactly one TCP address under the shared deadline."""
    _check_runtime_guard(owner)
    dns_task = asyncio.create_task(loop.getaddrinfo(
        endpoint_host, endpoint_port, type=socket.SOCK_STREAM,
        proto=socket.IPPROTO_TCP))
    owner._startup_tasks.append(dns_task)
    infos = await _await_startup_task(owner, dns_task, deadline, "selected gateway DNS")
    if not infos:
        raise C2CoordinatorChannelError("selected signed gateway endpoint did not resolve")
    _check_runtime_guard(owner)
    family, socktype, proto, _canonname, address = infos[0]
    sock = socket.socket(family, socktype, proto)
    attempt = {"socket": sock, "close_status": "open", "driver": None,
               "egress": owner.egress}
    owner._attempts.append(attempt)
    owner.socket = sock
    _check_runtime_guard(owner)
    _check_startup_deadline(loop, deadline, "TCP socket setup")
    sock.setblocking(False)
    _check_runtime_guard(owner)
    _check_startup_deadline(loop, deadline, "TCP socket setup")
    connect_task = asyncio.create_task(loop.sock_connect(sock, address))
    owner._startup_tasks.append(connect_task)
    await _await_startup_task(owner, connect_task, deadline, "selected gateway TCP connect")
    _check_runtime_guard(owner)
    return sock


def _check_identity_and_grants(binding, settings, sample):
    """Pin current C1 records and every Worker-method grant before networking."""
    store = binding._snapshot_store
    view = store.current(sample=sample)
    local = binding.local_identity
    local_cert = _verify_pinned_credential(store, local.certificate_pem, view, sample).record
    if (local_cert.account_id != binding._spec.account_id
            or local_cert.device_id != binding._spec.device_id
            or local_cert.role != "personal_coordinator"
            or local_cert.credential_epoch != binding._spec.credential_epoch):
        raise CredentialError("selected coordinator C1 record changed")
    if local.model_id != binding._model_id:
        raise CredentialError("selected C1 coordinator model differs from the runtime binding")
    targets = []
    active = view.active_grants(sample)
    for worker in settings.workers:
        cert_pem = _read_pin(worker.host_certificate, root=binding._root,
                             uid=binding._root_store._uid, maximum=64 * 1024,
                             label=f"{worker.component} logical HOST certificate")
        cert = _verify_pinned_credential(store, cert_pem, view, sample).record
        if cert.device_id != worker.device_id or cert.role != "host":
            raise CredentialError(f"{worker.component} certificate differs from selected C1 identity")
        target = OutboundTarget.from_record(
            service="steamboat.v1.Worker", record=cert, boot_id=worker.worker_boot_id,
            model_id=local.model_id, assignment_id=worker.assignment_id)
        needed = set(_WORKER_METHODS)
        for grant in active:
            if (grant.account_id == local_cert.account_id
                    and grant.device_id == local_cert.device_id
                    and grant.role == "personal_coordinator"
                    and grant.actor_serial == local_cert.serial
                    and grant.actor_public_key_sha256 == local_cert.public_key_sha256
                    and grant.actor_credential_epoch == local_cert.credential_epoch
                    and grant.actor_boot_id == local.boot_id
                    and grant.tenant_account_id == local_cert.account_id
                    and grant.target_account_id == target.account_id
                    and grant.target_device_id == target.device_id
                    and grant.target_role == target.role
                    and grant.target_serial == target.serial
                    and grant.target_public_key_sha256 == target.public_key_sha256
                    and grant.target_credential_epoch == target.credential_epoch
                    and grant.target_boot_id == target.boot_id
                    and grant.assignment_id == target.assignment_id
                    and grant.model_id == target.model_id):
                needed.discard(grant.method)
        if needed:
            raise CredentialError(f"{worker.component} lacks current C1 grants for the fixed Worker API")
        targets.append((worker, cert_pem, target))
    return view, targets


class C2CoordinatorChannel:
    """Retained, bounded gateway stream plus three selected target proxies."""

    def __init__(self, *_args, **_kwargs):
        raise TypeError("use build_c2_coordinator_channel()")

    def assert_live(self):
        if self._state != "open" or self._invalidated.is_set():
            raise C2CoordinatorChannelError("C2 coordinator channel is fenced")
        self._runtime_guard()
        self.egress.assert_transport_live()
        if self.stream.closed or not self.stream.transport_bootstrap_complete:
            raise C2CoordinatorChannelError("coordinator channel stream is unavailable")
        self._runtime_guard()
        if self._invalidated.is_set() or self._state != "open":
            raise C2CoordinatorChannelError("C2 coordinator channel was fenced during validation")
        return None

    def _guard_runtime(self):
        """Synchronous owner guard; success is exactly None."""
        if self._invalidated.is_set() or self._state not in {"starting", "open"}:
            raise C2CoordinatorChannelError("C2 coordinator channel runtime is fenced")
        result = self._binding.assert_live()
        if result is not None:
            raise C2CoordinatorChannelError("selected C2 binding guard returned a non-None value")
        policy = self._policy_owner.current()
        if policy is None:
            raise C2CoordinatorChannelError("durable channel policy is unavailable")
        if self._invalidated.is_set() or self._state not in {"starting", "open"}:
            raise C2CoordinatorChannelError("C2 coordinator channel was fenced during guard")
        return None

    def _on_teardown(self, reason):
        self._invalidated.set()
        client = getattr(self, "client", None)
        invalidate = getattr(client, "request_runtime_invalidation", None)
        if callable(invalidate):
            try:
                invalidate(str(reason)[:160] or "C2 coordinator binding invalidated")
            except BaseException as error:
                self._invalidation_error = error
        try:
            self._loop.call_soon_threadsafe(self._queue_cleanup)
        except RuntimeError:
            pass

    def _queue_cleanup(self):
        if self._cleanup_task is None:
            self._state = "closing"
            self._cleanup_task = asyncio.create_task(self._cleanup_owned())
            self._cleanup_task.add_done_callback(self._observe_cleanup)

    def _observe_cleanup(self, task):
        # Observe detached errors without dropping the owner-held task.
        if task.cancelled():
            self._close_error = C2CoordinatorChannelError(
                "owned cleanup task was cancelled; retain owners")
            self._state = "faulted"
            return
        error = task.exception()
        if error is not None:
            self._close_error = error
            self._state = "faulted"
            return
        if task.result() is True:
            self._complete_close()

    def _complete_close(self):
        self._state = "closed"
        self._lease = self._binding = self._settings = None
        self._policy_owner = self._traffic = self.authorizer = self.egress = None
        self.socket = self.driver = self.hello = self.stream = self.client = None
        self.targets = ()
        self._attempts.clear()
        self._startup_tasks.clear()

    async def _cleanup_owned(self):
        await self._startup_done.wait()
        if any(not task.done() for task in self._startup_tasks):
            raise C2CoordinatorChannelError(
                "startup operation remains in flight; retain all owners through process reap")
        if self._startup_cleanup_error is not None:
            # The egress constructor did not return its internal TLS owner.
            # Preserve its original uncertainty and keep the binding fenced.
            raise self._startup_cleanup_error
        client = getattr(self, "client", None)
        if client is not None:
            await client.close()
        stream = getattr(self, "stream", None)
        driver = getattr(self, "driver", None)
        if stream is not None:
            stream.close()
        elif driver is not None:
            driver.close()
        if driver is not None:
            if driver.socket_close_status != "closed":
                raise C2CoordinatorChannelError("raw TCP close outcome is uncertain")
            if driver.tls_close_status != "closed":
                raise C2CoordinatorChannelError("TLS close outcome is uncertain")
        egress = getattr(self, "egress", None)
        if egress is not None:
            if driver is None:
                egress.close()
            tls = getattr(egress, "_tls", None)
            if tls is None or tls.cleanup_status != "removed" or tls.cleanup_uncertain:
                raise C2CoordinatorChannelError("gateway TLS credential cleanup is unconfirmed")
        # A failed socket() attempt is also represented before its first
        # fallible operation. It is closed once here if no driver owns it.
        for attempt in self._attempts:
            if attempt.get("driver") is not None:
                status = attempt["driver"].socket_close_status
                attempt["close_status"] = "closed" if status == "closed" else (
                    "uncertain" if status == "uncertain" else "closing")
            if attempt["close_status"] == "open":
                attempt["close_status"] = "closing"
                try:
                    attempt["socket"].close()
                except BaseException:
                    attempt["close_status"] = "uncertain"
                    raise C2CoordinatorChannelError("raw TCP close attempt is uncertain")
                attempt["close_status"] = "closed"
            if attempt["close_status"] != "closed":
                raise C2CoordinatorChannelError("raw TCP close was not confirmed")
        if self._lease_exit_task is None:
            self._lease_exit_task = asyncio.create_task(asyncio.to_thread(
                self._lease.__exit__, None, None, None))
            self._lease_exit_task.add_done_callback(_observe_task)
        # Do not cancel this exact off-loop transition when a caller's close
        # budget expires. The one owned cleanup task waits for its completion.
        await asyncio.shield(self._lease_exit_task)
        return True

    async def close(self, grace_seconds=MAX_CLOSE_SECONDS):
        if type(grace_seconds) not in (int, float) or not 0 < grace_seconds <= MAX_CLOSE_SECONDS:
            raise ValueError("channel close grace must be in (0, 5]")
        deadline = self._loop.time() + float(grace_seconds)
        try:
            await asyncio.wait_for(self._close_lock.acquire(), timeout=float(grace_seconds))
        except asyncio.TimeoutError as error:
            self._invalidated.set()
            raise C2CoordinatorChannelError("channel close lock timed out; retain owner") from error
        try:
            if self._state == "closed":
                return True
            self._invalidated.set()
            try:
                if self._cleanup_task is None:
                    self._queue_cleanup()
                remaining = deadline - self._loop.time()
                if remaining <= 0:
                    raise asyncio.TimeoutError
                _done, pending = await asyncio.wait((self._cleanup_task,), timeout=remaining)
                if pending:
                    self._state = "closing"
                    raise _CleanupPending("channel cleanup remains in progress")
                if self._cleanup_task.cancelled():
                    raise C2CoordinatorChannelError("owned cleanup task was cancelled")
                cleanup_error = self._cleanup_task.exception()
                if cleanup_error is not None:
                    raise C2CoordinatorChannelError("owned channel cleanup failed") from cleanup_error
                self._complete_close()
                return True
            except BaseException as error:
                if not isinstance(error, _CleanupPending):
                    self._state = "faulted"
                self._close_error = error
                raise C2CoordinatorChannelError("channel cleanup uncertain; retain owners through process reap") from error
        finally:
            self._close_lock.release()


async def build_c2_coordinator_channel(child_binding: C2ChildBinding, *,
                                       owner_policy, policy_owner,
                                       traffic: TrafficBudget):
    """Build the selected coordinator's single real outbound C2 channel.

    Persistent policy and traffic owners must already be open and caller-owned.
    Their selected policy is never initialized or reset by this function.
    """
    if (type(child_binding) is not C2ChildBinding
            or type(policy_owner) is not PersistentChannelPolicyStore
            or type(traffic) is not TrafficBudget):
        raise TypeError("channel requires exact child, persistent policy, and traffic owners")
    if ("runtime_guard" not in inspect.signature(CoordinatorChannelClient).parameters
            or not callable(getattr(CoordinatorChannelClient,
                                   "request_runtime_invalidation", None))):
        raise C2CoordinatorChannelError(
            "channel client lacks the required runtime guard/invalidation capability")
    if traffic.path is None or traffic._memory is not None:
        raise TypeError("coordinator requires an already-open persistent traffic ledger")
    policy = validate_policy(owner_policy)
    reservation = policy["reservations"].get("coordinator")
    if type(reservation) is not dict:
        raise CredentialError("owner policy has no coordinator reservation")
    if reservation["communication_bytes"] < _stream_reservation():
        raise CredentialError("coordinator communication reservation is below the bounded stream")
    if reservation["capture_bytes"] < _DATA_SLOTS * _DATA_CAPTURE + _CONTROL_SLOTS * _CONTROL_CAPTURE:
        raise CredentialError("coordinator capture reservation is below supported call slots")
    if (policy_owner._store.clock is not traffic.clock
            or traffic.clock is not policy_owner._store.clock
            or traffic.uid != os.getuid()
            or traffic._requested_policy != policy):
        raise CredentialError("caller-owned durable policy and traffic identities differ")

    lease = child_binding.borrow()
    binding = lease.__enter__()
    owner = C2CoordinatorChannel.__new__(C2CoordinatorChannel)
    owner._lease, owner._binding, owner._settings = lease, binding, None
    owner._policy_owner, owner._traffic, owner._boot_id = policy_owner, traffic, None
    owner.authorizer = owner.egress = None
    owner.socket = owner.driver = owner.hello = owner.stream = owner.client = None
    owner.targets = ()
    owner._loop = asyncio.get_running_loop()
    owner._state = "starting"
    owner._invalidated = threading.Event()
    owner._close_lock = asyncio.Lock()
    owner._cleanup_task = None
    owner._attempts = []
    owner._startup_tasks = []
    owner._startup_done = asyncio.Event()
    owner._runtime_guard = owner._guard_runtime
    owner._invalidation_error = None
    owner._startup_cleanup_error = None
    owner._startup_cleanup_metadata = None
    owner._startup_cleanup_owner = None
    owner._lease_exit_task = None
    loop = asyncio.get_running_loop()
    startup_deadline = loop.time() + STARTUP_SECONDS
    try:
        binding.subscribe_teardown(owner._on_teardown)
        settings = load_c2_coordinator_settings(binding)
        if (settings.gateway.policy_root != os.fspath(policy_owner._path)
                or settings.traffic.state_path != os.fspath(traffic.path)
                or settings.traffic.allocation_id != traffic.allocation_id
                or settings.traffic.clock_domain != traffic.clock_domain
                or policy_owner._uid != os.getuid()
                or policy_owner._clock is not binding._clock
                or policy_owner._minimum_revision != settings.gateway.minimum_revision
                or policy_owner._minimum_digest != settings.gateway.minimum_policy_digest
                or policy_owner._verification_key_pem != settings.gateway.verification_key_pem):
            raise CredentialError("caller-owned durable stores differ from selected coordinator settings")
        sample = binding._clock.sample()
        _view, target_rows = _check_identity_and_grants(binding, settings, sample)
        current = policy_owner.current()
        gateway = current.gateway(settings.gateway.gateway_id)
        if gateway is None:
            raise CredentialError("durable signed policy lacks the selected gateway")
        for worker, _cert_pem, target in target_rows:
            selected = current.worker(target.device_id, target.boot_id)
            if (selected is None or selected["assignment_id"] != worker.assignment_id
                    or selected["model_id"] != binding._model_id
                    or selected["gateway_id"] != settings.gateway.gateway_id):
                raise CredentialError("durable signed policy differs from selected worker tuple")
        boot_id = binding._spec.boot_id
        owner._settings, owner._boot_id = settings, boot_id
        if traffic.bind_role("coordinator", boot_id).get("already_bound"):
            raise CredentialError("coordinator traffic generation was already bound")
        # The durable policy and bounded captures are checked before any socket
        # is created. The lease remains owned through all subsequent work.
        first_worker, first_cert, first_target = target_rows[0]
        authorizer = OutboundAuthorizer(
            local_identity=binding.local_identity,
            snapshot_store=binding._snapshot_store, clock=binding._clock,
            target=first_target, worker_request_type=Request,
            trusted_request_context_type=TrustedRequestContext,
            allow_bootstrap_describe=True)
        owner.authorizer, owner.egress = authorizer, None
        ca_pem = _read_pin(settings.gateway.gateway_ca, root=binding._root,
                           uid=binding._root_store._uid, maximum=64 * 1024,
                           label="gateway CA")
        endpoint_host, endpoint_port = gateway["coordinator_endpoint_host"], gateway["coordinator_endpoint_port"]
        _check_runtime_guard(owner)
        try:
            egress = GatewayCoordinatorEgress.connect(
                authorizer=authorizer, policy_store=policy_owner.core_store,
                logical_host_certificate_pem=first_cert,
                gateway_id=settings.gateway.gateway_id, gateway_ca_pem=ca_pem,
                coordinator_private_key_pem=binding.tls_materials.private_key_pem)
        except GatewayEgressError as constructor_error:
            _retain_egress_constructor_failure(owner, constructor_error)
            raise
        owner.egress = egress
        _check_startup_deadline(loop, startup_deadline, "TLS owner construction")
        owner.socket = await _open_selected_socket(
            owner, loop, endpoint_host, endpoint_port, startup_deadline)
        owner.driver = ChannelSocket(owner.socket, egress, traffic,
                                     role="coordinator", boot_id=boot_id)
        owner._attempts[-1]["driver"] = owner.driver
        _check_startup_deadline(loop, startup_deadline, "socket driver construction")
        while True:
            _check_runtime_guard(owner)
            owner.driver.pump()
            complete = egress.handshake_complete
            drained = (owner.driver.pending_ciphertext_bytes == 0
                       and owner.driver.pending_plaintext_bytes == 0
                       and egress.pending_encrypted_bytes == 0)
            _check_runtime_guard(owner)
            _check_startup_deadline(loop, startup_deadline, "gateway TLS handshake")
            if complete and drained:
                break
            await asyncio.sleep(PUMP_SLEEP_SECONDS)
            _check_runtime_guard(owner)
        owner.hello = CoordinatorHelloClient(egress, reassembly_capacity=wire.MAX_BUNDLE_BYTES)
        _check_startup_deadline(loop, startup_deadline, "coordinator HELLO construction")
        owner.stream = ChannelStream(
            owner.driver, owner.hello,
            writer_reservation_bytes=(writer_reservation_overhead_bytes()
                + wire.MAX_BUNDLE_BYTES + 8 * wire.MAX_CONTROL_BUNDLE_BYTES),
            decoded_byte_capacity=wire.MAX_BUNDLE_BYTES,
            tls_owner_reservation_bytes=TLS_OWNER_MIN_RESERVATION_BYTES)
        while not owner.stream.transport_bootstrap_complete:
            _check_runtime_guard(owner)
            owner.stream.pump()
            _check_startup_deadline(loop, startup_deadline, "coordinator HELLO")
            await asyncio.sleep(PUMP_SLEEP_SECONDS)
            _check_runtime_guard(owner)
        _check_startup_deadline(loop, startup_deadline, "coordinator HELLO commit")
        if (owner.driver.pending_ciphertext_bytes or owner.driver.pending_plaintext_bytes
                or egress.pending_encrypted_bytes):
            raise C2CoordinatorChannelError("coordinator HELLO output was not fully drained")
        owner.client = CoordinatorChannelClient(
            egress=egress, stream=owner.stream,
            authorization_watcher=AuthorizationWatcher(),
            data_capture_reservation_bytes=_DATA_SLOTS * _DATA_CAPTURE,
            control_capture_reservation_bytes=_CONTROL_SLOTS * _CONTROL_CAPTURE,
            runtime_guard=owner._runtime_guard)
        _check_startup_deadline(loop, startup_deadline, "channel client construction")
        if not callable(getattr(owner.client, "request_runtime_invalidation", None)):
            raise C2CoordinatorChannelError("client runtime invalidation capability is absent")
        _check_runtime_guard(owner)
        primary_view = egress.register_target(authorizer, first_cert)
        proxies = [owner.client.bind_target(primary_view)]
        _check_startup_deadline(loop, startup_deadline, "primary target binding")
        for worker, cert_pem, target in target_rows[1:]:
            target_authorizer = OutboundAuthorizer(
                local_identity=binding.local_identity,
                snapshot_store=binding._snapshot_store, clock=binding._clock,
                target=target, worker_request_type=Request,
                trusted_request_context_type=TrustedRequestContext,
                allow_bootstrap_describe=True)
            view = egress.register_target(target_authorizer, cert_pem)
            proxies.append(owner.client.bind_target(view))
            _check_startup_deadline(loop, startup_deadline, "cohort target binding")
        owner.targets = tuple(proxies)
        _check_runtime_guard(owner)
        _check_startup_deadline(loop, startup_deadline, "final channel validation")
        owner._state = "open"
        owner._startup_done.set()
        owner.assert_live()
        return owner
    except BaseException as error:
        owner._invalidated.set()
        owner._state = "faulted"
        owner._startup_done.set()
        try:
            error.c2_coordinator_channel_owner = owner
        except BaseException:
            pass
        try:
            loop.call_soon(owner._queue_cleanup)
        except RuntimeError:
            pass
        raise


class _CleanupPending(C2CoordinatorChannelError):
    """One exact owner cleanup or binding lease exit remains in progress."""
