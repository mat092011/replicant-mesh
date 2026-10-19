"""One bounded outbound coordinator channel to its selected worker cohort.

This owner composes existing C1 authorization, durable C2 policy/traffic,
gateway egress, TCP/TLS, HELLO and channel-client owners.  It is a transport
owner only: it does not schedule model work or claim service readiness.
"""
from __future__ import annotations

import asyncio
import hashlib
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
from steamboat_security.gateway_egress import GatewayCoordinatorEgress
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

    def __init__(self, lease, binding, settings, policy_owner, traffic, boot_id,
                 authorizer, egress, sock, driver, hello, stream, client, proxies):
        self._lease, self._binding, self._settings = lease, binding, settings
        self._policy_owner, self._traffic, self._boot_id = policy_owner, traffic, boot_id
        self.authorizer, self.egress, self.socket = authorizer, egress, sock
        self.driver, self.hello, self.stream, self.client = driver, hello, stream, client
        self.targets = tuple(proxies)
        self._loop = asyncio.get_running_loop()
        self._state = "open"
        self._invalidated = threading.Event()
        self._close_lock = asyncio.Lock()
        self._tasks = set()
        binding.subscribe_teardown(self._on_teardown)

    def assert_live(self):
        if self._state != "open" or self._invalidated.is_set():
            raise C2CoordinatorChannelError("C2 coordinator channel is fenced")
        self._binding.assert_live()
        self._policy_owner.current()
        self.egress.assert_transport_live()
        if self.stream.closed or not self.stream.transport_bootstrap_complete:
            raise C2CoordinatorChannelError("coordinator channel stream is unavailable")
        return True

    def _on_teardown(self, _reason):
        self._invalidated.set()
        try:
            self._loop.call_soon_threadsafe(self._schedule_close)
        except RuntimeError:
            pass

    def _schedule_close(self):
        if self._state == "open":
            task = asyncio.create_task(self.close())
            self._tasks.add(task)
            task.add_done_callback(self._tasks.discard)

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
            self._state = "closing"
            self._invalidated.set()
            try:
                remaining = deadline - self._loop.time()
                if remaining <= 0:
                    raise asyncio.TimeoutError
                await asyncio.wait_for(self.client.close(), timeout=remaining)
                self.stream.close()
                # ChannelStream retires driver and TLS. A close exception is
                # ambiguous and therefore leaves every owner strongly held.
                if (self.driver.socket_close_status != "closed"
                        or self.driver.tls_close_status != "closed"):
                    raise C2CoordinatorChannelError(
                        "socket or TLS close outcome is uncertain")
                remaining = deadline - self._loop.time()
                if remaining <= 0:
                    raise asyncio.TimeoutError
                lease_task = getattr(self, "_lease_exit_task", None)
                if lease_task is None:
                    lease_task = asyncio.create_task(asyncio.to_thread(
                        self._lease.__exit__, None, None, None))
                    self._lease_exit_task = lease_task
                done, pending = await asyncio.wait((lease_task,), timeout=remaining)
                if pending:
                    raise _LeaseRetirementPending("binding lease retirement remains in progress")
                if lease_task.exception() is not None:
                    raise C2CoordinatorChannelError("binding lease retirement failed") from lease_task.exception()
                self._state = "closed"
                self._lease = self._binding = self._settings = None
                self._policy_owner = self._traffic = self.authorizer = self.egress = None
                self.socket = self.driver = self.hello = self.stream = self.client = None
                self.targets = ()
                return True
            except BaseException as error:
                self._state = "closing" if isinstance(error, _LeaseRetirementPending) else "faulted"
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
    owner._tasks = set()
    owner._lease_exit_task = None
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
        binding.assert_live()
        policy_owner.current()
        egress = GatewayCoordinatorEgress.connect(
            authorizer=authorizer, policy_store=policy_owner.core_store,
            logical_host_certificate_pem=first_cert,
            gateway_id=settings.gateway.gateway_id, gateway_ca_pem=ca_pem,
            coordinator_private_key_pem=binding.tls_materials.private_key_pem)
        owner.egress = egress
        loop = asyncio.get_running_loop()
        binding.assert_live()
        policy_owner.current()
        infos = await asyncio.wait_for(loop.getaddrinfo(
            endpoint_host, endpoint_port, type=socket.SOCK_STREAM,
            proto=socket.IPPROTO_TCP), timeout=STARTUP_SECONDS)
        last_error = None
        for family, socktype, proto, _canonname, address in infos[:4]:
            candidate = socket.socket(family, socktype, proto)
            candidate.setblocking(False)
            try:
                await asyncio.wait_for(loop.sock_connect(candidate, address), timeout=STARTUP_SECONDS)
                owner.socket = candidate
                break
            except asyncio.CancelledError:
                # The connect operation's completion is unknown after caller
                # cancellation. Keep the exact descriptor on the partial owner.
                owner.socket = candidate
                raise
            except asyncio.TimeoutError:
                owner.socket = candidate
                raise
            except OSError as error:
                last_error = error
                candidate.close()
        if owner.socket is None:
            raise C2CoordinatorChannelError("selected signed gateway endpoint could not be connected") from last_error
        owner.driver = ChannelSocket(owner.socket, egress, traffic,
                                     role="coordinator", boot_id=boot_id)
        deadline = loop.time() + STARTUP_SECONDS
        while not egress.handshake_complete:
            binding.assert_live()
            policy_owner.current()
            owner.driver.pump()
            if loop.time() >= deadline:
                raise C2CoordinatorChannelError("gateway TLS handshake exceeded the fixed startup deadline")
            await asyncio.sleep(PUMP_SLEEP_SECONDS)
        if (owner.driver.pending_ciphertext_bytes or owner.driver.pending_plaintext_bytes
                or egress.pending_encrypted_bytes):
            raise C2CoordinatorChannelError("gateway TLS output was not fully drained")
        owner.hello = CoordinatorHelloClient(egress, reassembly_capacity=wire.MAX_BUNDLE_BYTES)
        owner.stream = ChannelStream(
            owner.driver, owner.hello,
            writer_reservation_bytes=(writer_reservation_overhead_bytes()
                + wire.MAX_BUNDLE_BYTES + 8 * wire.MAX_CONTROL_BUNDLE_BYTES),
            decoded_byte_capacity=wire.MAX_BUNDLE_BYTES,
            tls_owner_reservation_bytes=TLS_OWNER_MIN_RESERVATION_BYTES)
        while not owner.stream.transport_bootstrap_complete:
            binding.assert_live()
            policy_owner.current()
            owner.stream.pump()
            if loop.time() >= deadline:
                raise C2CoordinatorChannelError("coordinator HELLO ACK exceeded the fixed startup deadline")
            await asyncio.sleep(PUMP_SLEEP_SECONDS)
        if (owner.driver.pending_ciphertext_bytes or owner.driver.pending_plaintext_bytes
                or egress.pending_encrypted_bytes):
            raise C2CoordinatorChannelError("coordinator HELLO output was not fully drained")
        owner.client = CoordinatorChannelClient(
            egress=egress, stream=owner.stream,
            authorization_watcher=AuthorizationWatcher(),
            data_capture_reservation_bytes=_DATA_SLOTS * _DATA_CAPTURE,
            control_capture_reservation_bytes=_CONTROL_SLOTS * _CONTROL_CAPTURE)
        primary_view = egress.register_target(authorizer, first_cert)
        proxies = [owner.client.bind_target(primary_view)]
        for worker, cert_pem, target in target_rows[1:]:
            target_authorizer = OutboundAuthorizer(
                local_identity=binding.local_identity,
                snapshot_store=binding._snapshot_store, clock=binding._clock,
                target=target, worker_request_type=Request,
                trusted_request_context_type=TrustedRequestContext,
                allow_bootstrap_describe=True)
            view = egress.register_target(target_authorizer, cert_pem)
            proxies.append(owner.client.bind_target(view))
        owner.targets = tuple(proxies)
        owner._state = "open"
        owner.assert_live()
        return owner
    except BaseException as error:
        if owner is not None:
            owner._state = "faulted"
            try:
                error.c2_coordinator_channel_owner = owner
            except BaseException:
                pass
        else:
            # The lease is still held and must survive until the caller reaps
            # the failed startup. Attach it for retention rather than retiring
            # selected-root ownership with uncertain network side effects.
            try:
                error.c2_coordinator_channel_lease = lease
            except BaseException:
                pass
        raise


class _LeaseRetirementPending(C2CoordinatorChannelError):
    """One exact lease exit is running and can be awaited on close retry."""
