"""Bounded producer-side routing for authenticated C2 gateway channels.

This component admits canonical delegated worker calls to one writer per live
worker HELLO generation. It does not drive sockets or claim readiness.
"""
from __future__ import annotations

import base64
import hashlib
import secrets
import threading
import weakref
from dataclasses import dataclass, field

from cryptography import x509

from steamboat_connector import channel_wire as wire
from steamboat_connector.channel_hello import (
    RegisteredCoordinator, RegisteredWorker,
)
from steamboat_connector.channel_writer import (
    ChannelFragmentWriter, writer_reservation_overhead_bytes,
)
from steamboat_connector.channel_heartbeat import (
    PING, PONG, decode_heartbeat, encode_heartbeat,
)
from steamboat_security.codec import (
    WORKER_SERVICE, WORKER_METHODS, parse_metadata,
)
from steamboat_security.gateway_coordinator_tls import (
    is_coordinator_route_guard, is_authenticated_coordinator_channel,
)
from steamboat_security.gateway_delegation import sign_gateway_delegation
from steamboat_security.gateway_tls import is_authenticated_worker_channel
from steamboat_security.certificates import certificate_sha256
from steamboat_security.clock import Clock

MAX_WORKERS = 8
MAX_PENDING_DATA = 8
MAX_PENDING_CONTROL = 8
MAX_DELEGATION_LIFETIME_SECONDS = 30
CONTROL_METHODS = frozenset({"CloseSession", "CancelSession", "SessionStatus"})


class GatewayRouterError(ValueError):
    """Gateway route admission failed closed."""


@dataclass
class _WorkerSlot:
    registration: RegisteredWorker
    writer: ChannelFragmentWriter
    identity: tuple
    lock: threading.RLock = field(default_factory=threading.RLock)
    data_sequence: int = 1
    control_sequence: int = 1
    pending_data: dict = field(default_factory=dict)
    pending_control: dict = field(default_factory=dict)
    heartbeat_outstanding: tuple | None = None
    last_heartbeat_sent: float | None = None
    live: bool = True


class GatewayRouter:
    """Bounded coordinator-to-worker producer for one gateway process."""

    def __init__(self, *, gateway_id, gateway_certificate_pem,
                 gateway_private_key_pem, clock: Clock,
                 communication_reservation_bytes):
        if type(clock) is not Clock:
            raise TypeError("gateway router requires the exact core Clock")
        self.gateway_id = gateway_id
        self._gateway_certificate = gateway_certificate_pem
        self._gateway_key = gateway_private_key_pem
        self.clock = clock
        self._reservation = communication_reservation_bytes
        self._lock = threading.RLock()
        self._workers = {}
        self._writer_owners = weakref.WeakSet()

    def register_worker(self, registration, writer):
        """Install a slot for a genuine committed HELLO capability, identity only."""
        if type(registration) is not RegisteredWorker:
            raise GatewayRouterError("worker registration must be owner-minted HELLO capability")
        try:
            registration.assert_live()
            identity = registration.identity
        except Exception as error:
            raise GatewayRouterError("worker HELLO generation is not live") from error
        generation = bytes.fromhex(identity[3])
        if (type(writer) is not ChannelFragmentWriter
                or writer.expected_generation != generation
                or writer.accounting.next_fragment_sequence != 2
                or writer.accounting.pending_data_messages != 0
                or writer.accounting.pending_control_messages != 0
                or writer.accounting.retired
                or writer.communication_reservation_bytes > self._reservation):
            raise GatewayRouterError("worker writer must be fresh for this HELLO generation at sequence two")
        key = identity[1:3]
        slot = _WorkerSlot(registration, writer, identity)
        with self._lock:
            if writer in self._writer_owners:
                raise GatewayRouterError("writer is already owned by a worker slot")
            current = self._workers.get(key)
            if current is not None and current.live:
                if current.identity == identity:
                    raise GatewayRouterError("worker generation is already registered")
                # Same device/boot replacement retires only the replaced slot.
                current.live = False
                current.writer.retire()
            elif len(self._workers) >= MAX_WORKERS and key not in self._workers:
                raise GatewayRouterError("worker registry is full")
            self._workers[key] = slot
            self._writer_owners.add(writer)
        return identity

    def remove_worker(self, registration):
        """Retire only the exact registered capability currently occupying its slot."""
        if type(registration) is not RegisteredWorker:
            raise GatewayRouterError("worker registration is invalid")
        with self._lock:
            key = next((key for key, slot in self._workers.items()
                        if slot.registration is registration), None)
            if key is None:
                return False
            slot = self._workers[key]
            slot.live = False
            slot.writer.retire()
            del self._workers[key]
            return True

    def _slot(self, target_device_id, worker_boot_id):
        key = (target_device_id, worker_boot_id)
        with self._lock:
            slot = self._workers.get(key)
            if slot is None or not slot.live:
                raise GatewayRouterError("exact live worker generation is not registered")
            return slot

    def _live(self, coordinator, worker, route_guard, slot, method):
        try:
            coordinator.assert_live()
            worker.assert_live()
            route_guard.assert_live()
            if not is_coordinator_route_guard(route_guard):
                raise GatewayRouterError("coordinator route guard is not owner-minted")
            actor = coordinator._RegisteredCoordinator__channel
            worker_channel = worker._RegisteredWorker__channel
            if (not is_authenticated_coordinator_channel(actor)
                    or not is_authenticated_worker_channel(worker_channel)):
                raise GatewayRouterError("HELLO capabilities lost authenticated channel owners")
            actor.assert_live()
            worker_channel.assert_live()
            if not slot.live or slot.registration is not worker:
                raise GatewayRouterError("worker slot was replaced")
            if (actor.gateway_id != self.gateway_id
                    or worker_channel.gateway_id != self.gateway_id
                    or actor.gateway_certificate_sha256 != worker_channel.gateway_certificate_sha256
                    or actor.policy_revision != worker_channel.policy_revision
                    or actor.policy_digest != worker_channel.policy_digest
                    or slot.identity != worker.identity):
                raise GatewayRouterError("coordinator and worker are not on this pinned gateway leaf")
            if route_guard._channel is not actor or route_guard.method != method:
                raise GatewayRouterError("route guard does not belong to this coordinator or method")
            if (route_guard.target_device_id != worker_channel.device_id
                    or route_guard.worker_boot_id != worker_channel.worker_boot_id
                    or route_guard.assignment_id != worker_channel.assignment_id
                    or route_guard.model_id != worker_channel.model_id):
                raise GatewayRouterError("route guard differs from the exact worker assignment")
            if certificate_sha256(x509.load_pem_x509_certificate(self._gateway_certificate)) != actor.gateway_certificate_sha256:
                raise GatewayRouterError("configured gateway leaf differs from authenticated TLS leaf")
            return actor, worker_channel
        except GatewayRouterError:
            raise
        except Exception as error:
            raise GatewayRouterError("authenticated route liveness check failed") from error

    def submit(self, *, coordinator, worker, route_guard, method, metadata,
               request_bytes, message_id=None):
        """Sign and enqueue one exact request; logical sequence commits on success only."""
        if type(coordinator) is not RegisteredCoordinator or type(worker) is not RegisteredWorker:
            raise GatewayRouterError("requests require genuine HELLO registrations")
        if type(method) is not str or method not in WORKER_METHODS:
            raise GatewayRouterError("unsupported worker method")
        lane = "control" if method in CONTROL_METHODS else "data"
        kind = wire.CONTROL if lane == "control" else wire.DATA
        try:
            binding = parse_metadata(WORKER_SERVICE, method, metadata)
        except Exception as error:
            raise GatewayRouterError("request binding is malformed") from error
        fields = binding.fields
        # Describe deliberately permits the legacy C1 bootstrap binding without
        # worker_boot_id/assignment_id. In that form, only an owner-minted route
        # guard can select a worker; never guess from registry contents.
        if method == "Describe":
            if (not is_coordinator_route_guard(route_guard)
                    or route_guard.method != method
                    or route_guard.target_device_id != fields.get("target_device_id")):
                raise GatewayRouterError("Describe requires an exact guarded worker target")
            selected_device, selected_boot = (route_guard.target_device_id,
                                              route_guard.worker_boot_id)
        else:
            selected_device, selected_boot = (fields.get("target_device_id", ""),
                                              fields.get("worker_boot_id", ""))
        slot = self._slot(selected_device, selected_boot)
        with slot.lock:
            actor, target = self._live(coordinator, worker, route_guard, slot, method)
            expected = {
                "account_id": actor.actor_account_id,
                "device_id": actor.actor_device_id,
                "credential_epoch": actor.actor_credential_epoch,
                "role": "personal_coordinator",
                "coordinator_boot_id": actor.coordinator_boot_id,
                "tenant_account_id": actor.tenant_account_id,
                "target_device_id": target.device_id,
                "worker_boot_id": target.worker_boot_id,
                "assignment_id": target.assignment_id,
            }
            optional_describe = ({"worker_boot_id", "assignment_id",
                                  "coordinator_boot_id", "tenant_account_id"}
                                 if method == "Describe" else set())
            if any(key not in optional_describe and fields.get(key) != value
                   for key, value in expected.items()):
                raise GatewayRouterError("binding identity differs from authenticated channels")
            if method == "Describe" and any(
                    key in fields and fields[key] != value for key, value in (
                        ("worker_boot_id", target.worker_boot_id),
                        ("assignment_id", target.assignment_id),
                        ("coordinator_boot_id", actor.coordinator_boot_id),
                        ("tenant_account_id", actor.tenant_account_id))):
                raise GatewayRouterError("Describe target differs from guarded assignment")
            if actor.tenant_account_id != actor.actor_account_id:
                raise GatewayRouterError("tenant differs from authenticated coordinator account")
            if (type(request_bytes) is not bytes or not request_bytes
                    or len(request_bytes) > wire.MAX_PROTOBUF_BYTES):
                raise GatewayRouterError("request protobuf must be nonempty immutable bytes")
            request_id = fields.get("request_id")
            operation_id = fields["operation_id"]
            pending = slot.pending_control if lane == "control" else slot.pending_data
            limit = MAX_PENDING_CONTROL if lane == "control" else MAX_PENDING_DATA + 1
            if len(pending) >= limit:
                return False
            if any(operation_id in lane_pending for lane_pending in
                   (slot.pending_data, slot.pending_control)):
                raise GatewayRouterError("operation identifier is already pending")
            self._live(coordinator, worker, route_guard, slot, method)
            sequence = slot.control_sequence if lane == "control" else slot.data_sequence
            if sequence > 2**63 - 1:
                raise GatewayRouterError("delegation logical sequence exhausted")
            sample = self.clock.sample()
            deadline = min(route_guard.assert_live(), target.deadline_monotonic)
            issued = int(sample.earliest_wall)
            expires = min(issued + MAX_DELEGATION_LIFETIME_SECONDS,
                          int(sample.latest_wall + deadline - sample.monotonic))
            if expires <= sample.latest_wall:
                raise GatewayRouterError("route has no conservative delegation lifetime")
            payload = {
                "version": 2, "policy_revision": actor.policy_revision,
                "policy_digest": actor.policy_digest, "gateway_id": self.gateway_id,
                "gateway_certificate_sha256": actor.gateway_certificate_sha256,
                "actor_certificate_base64": base64.b64encode(actor.actor_certificate_pem).decode("ascii"),
                "coordinator_boot_id": actor.coordinator_boot_id,
                "tenant_account_id": actor.tenant_account_id,
                "target_device_id": target.device_id, "worker_boot_id": target.worker_boot_id,
                "assignment_id": target.assignment_id, "model_id": target.model_id,
                # The wire generation comes from completed HELLO, not the distinct
                # authenticated TLS owner nonce carried by the channel record.
                "stream_generation": slot.identity[3],
                "lane": lane, "frame_sequence": sequence,
                "service": WORKER_SERVICE, "method": method,
                "binding_sha256": hashlib.sha256(binding.encoded).hexdigest(),
                "request_sha256": hashlib.sha256(request_bytes).hexdigest(),
                "issued_at": issued, "expires_at": expires,
            }
            envelope = sign_gateway_delegation(payload, self._gateway_key,
                                               self._gateway_certificate)
            protobuf = request_bytes
            bundle = wire.encode_bundle(method, wire.REQUEST, fragment_kind=kind,
                                        envelope=envelope, binding=binding.encoded,
                                        protobuf=protobuf)
            if message_id is None:
                message_id = secrets.token_bytes(16)
            # Recheck immediately at the actual admission boundary.
            self._live(coordinator, worker, route_guard, slot, method)
            if not slot.writer.enqueue(kind=kind, message_id=message_id, payload=bundle):
                return False
            pending[operation_id] = (method, message_id, lane,
                                     coordinator, worker, route_guard, request_id)
            if lane == "control":
                slot.control_sequence += 1
            else:
                slot.data_sequence += 1
            return True

    def enqueue_heartbeat(self, *, worker, message_id=None):
        """Admit a generation-bound PING using the next shared control counter."""
        if type(worker) is not RegisteredWorker:
            raise GatewayRouterError("heartbeat requires a genuine worker HELLO capability")
        try:
            identity = worker.identity
            worker.assert_live()
            slot = self._slot(identity[1], identity[2])
        except Exception as error:
            raise GatewayRouterError("worker heartbeat channel is not live") from error
        with slot.lock:
            if not slot.live or slot.registration is not worker:
                raise GatewayRouterError("heartbeat worker generation was replaced")
            sample = self.clock.sample()
            if slot.heartbeat_outstanding is not None:
                if sample.monotonic >= slot.heartbeat_outstanding[1]:
                    slot.live = False
                    slot.writer.retire()
                    raise GatewayRouterError("worker heartbeat deadline expired")
                return False
            if (slot.last_heartbeat_sent is not None
                    and sample.monotonic < slot.last_heartbeat_sent + 30.0):
                return False
            sequence = slot.control_sequence
            if sequence > 2**63 - 1:
                raise GatewayRouterError("control logical sequence exhausted")
            payload = encode_heartbeat(PING, sequence)
            message_id = message_id or secrets.token_bytes(16)
            if not slot.writer.enqueue(kind=wire.HEARTBEAT,
                                       message_id=message_id, payload=payload):
                return False
            slot.control_sequence += 1
            slot.last_heartbeat_sent = sample.monotonic
            slot.heartbeat_outstanding = (sequence, sample.monotonic + 60.0)
            return True

    def check_heartbeat_liveness(self):
        """Retire generations whose outstanding PING exceeded its 60s deadline.

        A service timer must call this at least every five seconds; this component
        deliberately does not create a timer thread or claim active monitoring.
        """
        sample = self.clock.sample()
        expired = []
        with self._lock:
            for key, slot in tuple(self._workers.items()):
                with slot.lock:
                    if (slot.live and slot.heartbeat_outstanding is not None
                            and sample.monotonic >= slot.heartbeat_outstanding[1]):
                        slot.live = False
                        slot.writer.retire()
                        expired.append(key)
        return tuple(expired)

    def accept_heartbeat_pong(self, *, worker, payload):
        """Accept one exact PONG echo; it consumes no gateway logical counter."""
        if type(worker) is not RegisteredWorker:
            raise GatewayRouterError("heartbeat response requires a genuine worker HELLO capability")
        try:
            identity = worker.identity
            worker.assert_live()
            slot = self._slot(identity[1], identity[2])
            mode, sequence = decode_heartbeat(payload)
        except Exception as error:
            raise GatewayRouterError("worker heartbeat response is invalid") from error
        with slot.lock:
            if not slot.live or slot.registration is not worker:
                raise GatewayRouterError("heartbeat response belongs to a replaced generation")
            outstanding = slot.heartbeat_outstanding
            if mode != PONG or outstanding is None or sequence != outstanding[0]:
                raise GatewayRouterError("heartbeat response is duplicate, unsolicited, or mismatched")
            sample = self.clock.sample()
            if sample.monotonic >= outstanding[1]:
                slot.live = False
                slot.writer.retire()
                raise GatewayRouterError("heartbeat response arrived after its deadline")
            slot.heartbeat_outstanding = None
            return True

    def assert_dispatch_live(self, *, coordinator, worker, route_guard, method):
        """Recheck owner capabilities immediately before forwarding a queued call."""
        slot = self._slot(route_guard.target_device_id, route_guard.worker_boot_id)
        with slot.lock:
            self._live(coordinator, worker, route_guard, slot, method)
            if not any(value[0] == method and value[3] is coordinator
                       and value[4] is worker and value[5] is route_guard
                       for value in (*slot.pending_data.values(),
                                     *slot.pending_control.values())):
                raise GatewayRouterError("exact guarded request is no longer pending")
            return True

    def complete(self, *, worker, operation_id, request_id, message_id, method, payload):
        """Release pending admission on a validated response or cleanup reply kind 7."""
        try:
            identity = worker.identity
            slot = self._slot(identity[1], identity[2])
            worker.assert_live()
        except Exception as error:
            raise GatewayRouterError("worker response generation is not live") from error
        decoded = wire.decode_bundle(payload, fragment_kind=wire.CONTROL_RESPONSE
                                     if method in CONTROL_METHODS else wire.RESPONSE)
        if decoded.classification != wire.BUNDLE_RESPONSE or decoded.method != method:
            raise GatewayRouterError("response method or kind differs from pending request")
        with slot.lock:
            pending = slot.pending_control if method in CONTROL_METHODS else slot.pending_data
            key = operation_id
            entry = pending.get(key)
            if (entry is None or entry[1] != message_id or entry[0] != method
                    or entry[6] != request_id):
                key = None
            if key is None:
                return False
            entry = pending[key]
            if method != "HEARTBEAT":
                self._live(entry[3], worker, entry[5], slot, method)
            del pending[key]
            return True

