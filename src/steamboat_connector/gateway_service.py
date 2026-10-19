"""Fixed-cohort, metered TCP/TLS/HELLO gateway service for C2.

This is a composition boundary, not an enrollment or readiness service. The
operator supplies two already-bound, purpose-distinct listening sockets and
one exact invited cohort. Each socket accepted here is metered before any
application data is read or written. A successful HELLO means only that the
authenticated route is connected; model readiness remains elsewhere.
"""
from __future__ import annotations

import asyncio
import ipaddress
import socket
import threading
import time
from dataclasses import dataclass

from steamboat_connector import channel_wire as wire
from steamboat_connector.channel_hello import (
    CoordinatorHelloServer, RegisteredCoordinator, RegisteredWorker,
    WorkerHelloServer,
)
from steamboat_connector.channel_rpc import _CONTROL_CAPTURE_BYTES, _RELAY_CAPTURE_BYTES
from steamboat_connector.channel_stream import (
    DECODED_METADATA_RESERVATION_BYTES, HELLO_RESERVATION_BYTES,
    SOCKET_SCRATCH_RESERVATION_BYTES, TLS_OWNER_MIN_RESERVATION_BYTES,
    ChannelStream,
)
from steamboat_connector.channel_socket import ChannelSocket
from steamboat_connector.channel_writer import writer_reservation_overhead_bytes
from steamboat_connector.gateway_mux import GatewayChannelMultiplexer
from steamboat_connector.gateway_router import GatewayRouter
from steamboat_connector.traffic_budget import TrafficBudget
from steamboat_security.clock import Clock
from steamboat_security.gateway_tls import OwnedGatewayWorkerTLS
from steamboat_security.gateway_coordinator_tls import OwnedGatewayCoordinatorTLS
from steamboat_security.channel_policy import ChannelPolicyStore
from steamboat_security.snapshot import SnapshotStore


MAX_EXPECTED_WORKERS = 3
MAX_BOOTSTRAP_SECONDS = 5.0
MAX_ACCEPTS_PER_TICK = 4
HELLO_CAPACITY = wire.MAX_BUNDLE_BYTES
DECODED_CAPACITY = wire.MAX_BUNDLE_BYTES
WRITER_CAPACITY = (writer_reservation_overhead_bytes() + wire.MAX_BUNDLE_BYTES
                   + 8 * wire.MAX_CONTROL_BUNDLE_BYTES)
_STREAM_BOUND = (
    2 * HELLO_CAPACITY + wire.MAX_WIRE_FRAME_BYTES + wire.MAX_FEED_BYTES
    + wire.MAX_BUNDLE_BYTES + 64 * 1024 + WRITER_CAPACITY + DECODED_CAPACITY
    + DECODED_METADATA_RESERVATION_BYTES + SOCKET_SCRATCH_RESERVATION_BYTES
    + HELLO_RESERVATION_BYTES
    + TLS_OWNER_MIN_RESERVATION_BYTES
)
_MUX_CAPTURE_BOUND = 9 * _RELAY_CAPTURE_BYTES + 8 * _CONTROL_CAPTURE_BYTES
_MAX_RETAINED_SERVICES = 8
_RETENTION_LOCK = threading.Lock()
_LIVE_SERVICES = set()
_RETAINED_SERVICES = set()
_LISTENER_OWNERS = {}


class GatewayServiceError(RuntimeError):
    """The fixed gateway service cannot safely accept or route work."""


@dataclass
class _Accepted:
    purpose: str
    sock: socket.socket
    accepted_at: float
    owner: object | None = None
    driver: ChannelSocket | None = None
    hello: object | None = None
    stream: ChannelStream | None = None
    identity: tuple | None = None
    close_started: bool = False
    close_complete: bool = False


def _listener_endpoint(listener):
    if type(listener) is not socket.socket:
        raise TypeError("gateway listeners must be exact TCP sockets")
    if listener.family not in (socket.AF_INET, socket.AF_INET6):
        raise TypeError("gateway listener must use IPv4 or IPv6")
    if ((listener.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) & 0xF)
            != socket.SOCK_STREAM
            or not listener.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN)):
        raise TypeError("gateway listener must be a listening TCP socket")
    endpoint = listener.getsockname()
    if type(endpoint) is not tuple or len(endpoint) < 2 or type(endpoint[1]) is not int:
        raise ValueError("gateway listener address is malformed")
    ipaddress.ip_address(endpoint[0])
    if not 1 <= endpoint[1] <= 65535:
        raise ValueError("gateway listener must have an explicit bound port")
    return endpoint


class GatewayService:
    """Own two fixed listeners and one exact coordinator/worker cohort.

    ``worker_listener`` and ``coordinator_listener`` are operator-created,
    already-bound listeners. Their purpose is assigned by this constructor;
    they must be distinct sockets and endpoints. ``expected_workers`` is a
    tuple of exact ``(device_id, worker_boot_id)`` pairs. The service never
    accepts a replacement after a tuple has connected or failed.
    """

    def __init__(self, *, worker_listener, coordinator_listener,
                 expected_workers, coordinator_boot_id, tenant_account_id,
                 gateway_id, gateway_certificate_pem, gateway_private_key_pem,
                 cohort_ca_pem, gateway_ca_pem, target_certificates,
                 snapshot_store: SnapshotStore, policy_store: ChannelPolicyStore,
                 clock: Clock, traffic_budget: TrafficBudget,
                 gateway_traffic_boot_id, communication_memory_ceiling_bytes,
                 worker_reassembly_capacity=HELLO_CAPACITY,
                 coordinator_reassembly_capacity=HELLO_CAPACITY):
        worker_address = _listener_endpoint(worker_listener)
        coordinator_address = _listener_endpoint(coordinator_listener)
        if worker_listener is coordinator_listener or worker_address == coordinator_address:
            raise ValueError("worker and coordinator listeners must be separate purpose endpoints")
        if (type(expected_workers) is not tuple or not 1 <= len(expected_workers)
                <= MAX_EXPECTED_WORKERS):
            raise ValueError("expected worker cohort must contain one to three exact tuples")
        expected = tuple(expected_workers)
        if any(type(item) is not tuple or len(item) != 2
               or any(type(value) is not str or not value for value in item)
               for item in expected) or len(set(expected)) != len(expected):
            raise ValueError("expected worker identities must be unique device/boot pairs")
        if (type(snapshot_store) is not SnapshotStore
                or type(policy_store) is not ChannelPolicyStore
                or type(clock) is not Clock or type(traffic_budget) is not TrafficBudget):
            raise TypeError("gateway service requires exact stores, Clock, and TrafficBudget")
        if snapshot_store.clock is not clock or policy_store.clock is not clock:
            raise TypeError("gateway service stores must share one exact Clock")
        if traffic_budget.clock is not clock:
            raise TypeError("gateway TrafficBudget must share the exact TLS/policy Clock")
        if type(gateway_traffic_boot_id) is not str or not gateway_traffic_boot_id:
            raise ValueError("gateway traffic role boot identity is required")
        if (worker_reassembly_capacity != HELLO_CAPACITY
                or coordinator_reassembly_capacity != HELLO_CAPACITY):
            raise ValueError("HELLO capacities are fixed to the pre-reserved maximum bundle size")
        # Reserve the complete maximum stream population plus global mux captures
        # before TLS factories, BIOs, HELLO decoders, or accepted drivers exist.
        reservation = (len(expected) + 1) * _STREAM_BOUND + _MUX_CAPTURE_BOUND
        if (type(communication_memory_ceiling_bytes) is not int
                or communication_memory_ceiling_bytes < reservation):
            raise ValueError("communication memory ceiling is below the fixed cohort bound")
        policy = policy_store.current()
        gateway = policy.gateway(gateway_id)
        if gateway is None:
            raise GatewayServiceError("gateway identity is absent from current channel policy")
        policy_workers = set(policy.workers)
        if not set(expected) <= policy_workers:
            raise GatewayServiceError("fixed worker tuples are absent from current channel policy")
        if type(target_certificates) is not dict:
            raise TypeError("target certificates must be an exact immutable-by-copy mapping")
        expected_targets = set()
        for device_id, boot_id in expected:
            target = policy.worker(device_id, boot_id)
            expected_targets.add((device_id, boot_id,
                                  target["assignment_id"], target["model_id"]))
        if set(target_certificates) != expected_targets:
            raise GatewayServiceError(
                "target certificate map must exactly cover the invited worker tuples")
        if worker_listener.getblocking() or coordinator_listener.getblocking():
            worker_listener.setblocking(False)
            coordinator_listener.setblocking(False)
        worker_listener.listen(len(expected))
        coordinator_listener.listen(1)
        self.worker_listener = worker_listener
        self.coordinator_listener = coordinator_listener
        self.worker_address = worker_address
        self.coordinator_address = coordinator_address
        self.expected_workers = expected
        self.coordinator_boot_id = coordinator_boot_id
        self.tenant_account_id = tenant_account_id
        self.gateway_id = gateway_id
        self.gateway_certificate_pem = gateway_certificate_pem
        self.gateway_private_key_pem = gateway_private_key_pem
        self.cohort_ca_pem = cohort_ca_pem
        self.gateway_ca_pem = gateway_ca_pem
        self.target_certificates = dict(target_certificates)
        self.snapshot_store = snapshot_store
        self.policy_store = policy_store
        self.clock = clock
        self.traffic_budget = traffic_budget
        self.gateway_traffic_boot_id = gateway_traffic_boot_id
        self.communication_memory_ceiling_bytes = communication_memory_ceiling_bytes
        self.communication_reservation_bytes = reservation
        self.worker_reassembly_capacity = worker_reassembly_capacity
        self.coordinator_reassembly_capacity = coordinator_reassembly_capacity
        self.router = GatewayRouter(
            gateway_id=gateway_id, gateway_certificate_pem=gateway_certificate_pem,
            gateway_private_key_pem=gateway_private_key_pem, clock=clock,
            communication_reservation_bytes=communication_memory_ceiling_bytes)
        self._accepted = []
        self._workers = {}
        self._coordinator = None
        self.multiplexer = None
        self._accepting = True
        self._failed = None
        self._stop_lock = threading.Lock()
        self._pump_lock = threading.Lock()
        self._listener_lock = threading.Lock()
        self._listeners_closed = set()
        self._stuck = []
        self._resources_closed = False
        self._worker_capacity = worker_reassembly_capacity
        self._coordinator_capacity = coordinator_reassembly_capacity
        listeners = (worker_listener, coordinator_listener)
        with _RETENTION_LOCK:
            if len(_LIVE_SERVICES) + len(_RETAINED_SERVICES) >= _MAX_RETAINED_SERVICES:
                raise GatewayServiceError("global live/uncertain gateway service bound is exhausted")
            if any(_LISTENER_OWNERS.get(id(listener), (None,))[0] is listener
                   for listener in listeners):
                raise GatewayServiceError("a purpose listener already belongs to another service")
            if id(worker_listener) == id(coordinator_listener):
                raise ValueError("one listening socket cannot serve both fixed purposes")
            _LIVE_SERVICES.add(self)
            for listener in listeners:
                _LISTENER_OWNERS[id(listener)] = (listener, self)

    @property
    def route_connected(self):
        """Authenticated fixed-route connectivity only; never model readiness."""
        return (self.multiplexer is not None and self._accepting
                and self._coordinator is not None
                and len(self._workers) == len(self.expected_workers))

    @property
    def failure(self):
        return self._failed

    @property
    def pending_channels(self):
        return len(self._accepted)

    def _fail(self, reason):
        self._failed = reason
        self.stop()
        raise GatewayServiceError(reason)

    def _close_listener_once(self, listener):
        marker = id(listener)
        with self._listener_lock:
            if marker in self._listeners_closed:
                return
            self._listeners_closed.add(marker)
        try:
            listener.close()
            if listener.fileno() != -1:
                raise GatewayServiceError("listener close did not release its socket")
        except BaseException as error:
            self._stuck.append((listener, f"listener:{type(error).__name__}"))

    def _accept_ready(self, listener, purpose):
        if not self._accepting:
            return
        # Reserve a single pending/committed slot per expected identity before
        # accept; when all slots of one purpose are reserved, close that exact
        # listener rather than accepting an extra socket for rejection.
        pending_workers = sum(item.purpose == "worker" for item in self._accepted)
        coordinator_reserved = (self._coordinator is not None or any(
            item.purpose == "coordinator" for item in self._accepted))
        if purpose == "worker" and len(self._workers) + pending_workers >= len(self.expected_workers):
            self._close_listener_once(listener)
            return
        if purpose == "coordinator" and coordinator_reserved:
            self._close_listener_once(listener)
            return
        for _ in range(MAX_ACCEPTS_PER_TICK):
            if (len(self._workers) + len(self._accepted)
                    + (1 if self._coordinator is not None else 0)
                    >= len(self.expected_workers) + 1):
                self._close_listener_once(listener)
                return
            try:
                client, _peer = listener.accept()
            except BlockingIOError:
                return
            pending = _Accepted(purpose, client, time.monotonic())
            self._accepted.append(pending)
            client.setblocking(False)
            if purpose == "coordinator":
                self._close_listener_once(listener)
                return
            pending_workers += 1
            if len(self._workers) + pending_workers >= len(self.expected_workers):
                self._close_listener_once(listener)
                return

    def _make_owner_and_driver(self, pending):
        try:
            if pending.purpose == "worker":
                owner = OwnedGatewayWorkerTLS.accept(
                    gateway_certificate_pem=self.gateway_certificate_pem,
                    gateway_private_key_pem=self.gateway_private_key_pem,
                    cohort_ca_pem=self.cohort_ca_pem, policy_store=self.policy_store,
                    clock=self.clock, gateway_id=self.gateway_id)
            else:
                owner = OwnedGatewayCoordinatorTLS.accept(
                    gateway_certificate_pem=self.gateway_certificate_pem,
                    gateway_private_key_pem=self.gateway_private_key_pem,
                    gateway_ca_pem=self.gateway_ca_pem,
                    snapshot_store=self.snapshot_store, policy_store=self.policy_store,
                    clock=self.clock, gateway_id=self.gateway_id,
                    coordinator_boot_id=self.coordinator_boot_id,
                    tenant_account_id=self.tenant_account_id,
                    target_certificates=self.target_certificates)
        except BaseException as error:
            if (getattr(error, "cleanup_status", None) == "uncertain"
                    or getattr(error, "retained_owner", None) is not None):
                self._stuck.append((pending, error))
            raise
        pending.owner = owner
        pending.driver = ChannelSocket(
            pending.sock, owner, self.traffic_budget,
            role="coordinator", boot_id=self.gateway_traffic_boot_id)

    def _make_stream(self, pending):
        if pending.purpose == "worker":
            hello = WorkerHelloServer.from_tls(
                pending.owner, reassembly_capacity=self._worker_capacity)
        else:
            hello = CoordinatorHelloServer.from_tls(
                pending.owner, reassembly_capacity=self._coordinator_capacity)
        pending.hello = hello
        pending.stream = ChannelStream(
            pending.driver, hello,
            writer_reservation_bytes=WRITER_CAPACITY,
            decoded_byte_capacity=DECODED_CAPACITY,
            tls_owner_reservation_bytes=TLS_OWNER_MIN_RESERVATION_BYTES)
        if pending.stream.reservation_bound_bytes > _STREAM_BOUND:
            self._fail("actual stream exceeds its pre-reserved communication slot")

    def _finish_hello(self, pending):
        stream = pending.stream
        if not stream.transport_bootstrap_complete:
            return False
        registration = stream.registration
        if pending.purpose == "worker":
            if type(registration) is not RegisteredWorker:
                self._fail("worker HELLO did not produce a genuine registration")
            identity = registration.identity
            key = identity[1:3]
            if key not in self.expected_workers:
                self._fail("worker HELLO tuple is outside the fixed invited cohort")
            if key in self._workers:
                self._fail("duplicate worker boot cannot replace the captured generation")
            self.router.register_worker(stream)
            self._workers[key] = (registration, stream, pending)
        else:
            if type(registration) is not RegisteredCoordinator:
                self._fail("coordinator HELLO did not produce a genuine registration")
            identity = registration.identity
            if (identity[2] != self.coordinator_boot_id
                    or identity[3] != self.tenant_account_id):
                self._fail("coordinator HELLO identity differs from the fixed cohort")
            if self._coordinator is not None:
                self._fail("coordinator generation replacement is forbidden")
            self._coordinator = (registration, stream, pending)
        self._accepted.remove(pending)
        if self._coordinator is not None and len(self._workers) == len(self.expected_workers):
            actual = set(self._workers)
            if actual != set(self.expected_workers):
                self._fail("authenticated worker cohort differs from exact expected tuples")
            self.multiplexer = GatewayChannelMultiplexer(
                coordinator_stream=self._coordinator[1],
                worker_streams=tuple(self._workers[key][1] for key in self.expected_workers),
                router=self.router,
                data_capture_reservation_bytes=9 * _RELAY_CAPTURE_BYTES,
                control_capture_reservation_bytes=8 * _CONTROL_CAPTURE_BYTES)
        return True

    def pump_once(self):
        """Accept/pump a bounded number of pending channels, then mux if committed."""
        if not self._pump_lock.acquire(blocking=False):
            return False
        if not self._accepting:
            self._pump_lock.release()
            self._finalize_stop()
            return False
        try:
            self._accept_ready(self.worker_listener, "worker")
            if not self._accepting:
                return False
            self._accept_ready(self.coordinator_listener, "coordinator")
            if not self._accepting:
                return False
            now = time.monotonic()
            for pending in tuple(self._accepted):
                if now - pending.accepted_at > MAX_BOOTSTRAP_SECONDS:
                    self._fail("TLS and HELLO bootstrap exceeded five seconds")
                if pending.driver is None:
                    self._make_owner_and_driver(pending)
                    if not self._accepting:
                        return False
                if (not pending.owner.handshake_complete or pending.stream is None):
                    pending.driver.pump()
                if (pending.owner.handshake_complete and pending.stream is None
                        and not pending.driver.pending_plaintext_bytes
                        and not pending.driver.pending_ciphertext_bytes
                        and not pending.owner.pending_encrypted_bytes):
                    self._make_stream(pending)
                if pending.stream is not None:
                    pending.stream.pump()
                    self._finish_hello(pending)
            if self.multiplexer is not None:
                self.multiplexer.pump_once()
            return True
        except BaseException as error:
            if self._accepting:
                self._failed = type(error).__name__
            self.stop()
            raise
        finally:
            self._pump_lock.release()
            if not self._accepting:
                self._finalize_stop()

    async def run(self):
        try:
            while self._accepting:
                self.pump_once()
                await asyncio.sleep(0.001)
        finally:
            self.stop()

    def stop(self):
        """Freeze admission and close exact owners once, retaining uncertainty."""
        with self._stop_lock:
            self._accepting = False
        self._close_listener_once(self.worker_listener)
        self._close_listener_once(self.coordinator_listener)
        self._finalize_stop()

    def _finalize_stop(self):
        if self._accepting or not self._pump_lock.acquire(blocking=False):
            return
        try:
            if self._resources_closed:
                return
            mux = self.multiplexer
            if mux is not None:
                try:
                    mux.stop()
                    if not mux._claims_finalized or mux._stuck:
                        self._stuck.append((mux, "mux retirement unresolved"))
                    for _registration, stream, _pending in self._workers.values():
                        self._check_cleanup_state(stream)
                    if self._coordinator is not None:
                        self._check_cleanup_state(self._coordinator[1])
                except BaseException as error:
                    self._stuck.append((mux, type(error).__name__))
            for pending in tuple(self._accepted):
                self._close_pending(pending)
            if mux is None:
                for registration, stream, _pending in self._workers.values():
                    try:
                        self.router.remove_worker(registration)
                        self._check_cleanup_state(stream)
                    except BaseException as error:
                        self._stuck.append((stream, type(error).__name__))
                if self._coordinator is not None:
                    self._close_one(self._coordinator[1], "coordinator stream")
            self._resources_closed = True
            with _RETENTION_LOCK:
                _LIVE_SERVICES.discard(self)
                if self._stuck:
                    _RETAINED_SERVICES.add(self)
                else:
                    for listener in (self.worker_listener, self.coordinator_listener):
                        marker = id(listener)
                        claim = _LISTENER_OWNERS.get(marker)
                        if claim is not None and claim[0] is listener and claim[1] is self:
                            del _LISTENER_OWNERS[marker]
        finally:
            self._pump_lock.release()

    def _close_one(self, owner, label):
        try:
            owner.close()
            self._check_cleanup_state(owner)
        except BaseException as error:
            self._stuck.append((owner, f"{label}:{type(error).__name__}"))

    @staticmethod
    def _check_cleanup_state(owner):
        tls = getattr(owner, "_tls", None)
        if tls is None and hasattr(owner, "_driver"):
            tls = getattr(owner._driver, "_tls", None)
        status = getattr(tls, "cleanup_status", None)
        if status == "uncertain":
            raise GatewayServiceError("TLS credential cleanup is uncertain")
        driver = owner if type(owner) is ChannelSocket else getattr(owner, "_driver", None)
        if driver is not None and (
                driver.io_outcome_uncertain or driver.metering_uncertain
                or driver._socket.fileno() != -1):
            raise GatewayServiceError("metered socket cleanup outcome is uncertain")

    def _close_pending(self, pending):
        if pending.close_started:
            return
        pending.close_started = True
        try:
            if pending.stream is not None:
                pending.stream.close()
                self._check_cleanup_state(pending.stream)
            elif pending.driver is not None:
                pending.driver.close()
                self._check_cleanup_state(pending.driver)
            elif pending.owner is not None:
                try:
                    pending.owner.close()
                    self._check_cleanup_state(pending.owner)
                finally:
                    pending.sock.close()
            else:
                pending.sock.close()
            pending.close_complete = True
        except BaseException as error:
            self._stuck.append((pending, type(error).__name__))


def required_communication_memory_bytes(worker_count):
    """Return conservative fixed-stream and aggregate mux capture reservation."""
    if type(worker_count) is not int or not 1 <= worker_count <= MAX_EXPECTED_WORKERS:
        raise ValueError("worker count must be one to three")
    return (worker_count + 1) * _STREAM_BOUND + _MUX_CAPTURE_BOUND
