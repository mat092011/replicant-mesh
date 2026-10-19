"""Explicit fixed-peer mTLS transport for the C1a participant profile.

The older ``protocol.transport`` module remains the isolated plaintext lab
transport. Nothing in this module falls back to it.
"""

import asyncio
from dataclasses import dataclass
import hashlib
import inspect
import ipaddress
import json
import math
import re
import threading
import time
import uuid
from typing import Protocol

from . import MAX_MESSAGE_BYTES, MAX_TIMEOUT_MS, METHODS
from .errors import ProtocolError
from .wire import parse_message, serialize_message, validate_response
from .worker_pb2 import Request, Response
from .secure_connector import (
    MAX_CONNECT_SETUP_SECONDS,
    MAX_OUTBOUND_LIFETIME_SECONDS,
    SecureConnector,
    SecureConnectorPending,
)


WORKER_SERVICE = "steamboat.v1.Worker"
from ..remote_client import SERVICE as COORDINATOR_SERVICE
BINDING_METADATA_KEY = "steamboat-binding-bin"
CAPACITY_REJECTION_METADATA_KEY = "steamboat-capacity-rejection-bin"
_CAPACITY_REJECTION_PREFIX = b"SNCR\x01"
MAX_BINDING_BYTES = 4096
MAX_METADATA_BYTES = 8192
MAX_NODE_CONNECTIONS = 16
MAX_PEER_CONNECTIONS = 2
MAX_PENDING_HANDSHAKES = 4
MAX_INCOMING_PER_LISTENER = 2
MAX_PENDING_PER_LISTENER = 2
SERVER_HANDSHAKE_TIMEOUT_MS = int(MAX_CONNECT_SETUP_SECONDS * 1000)
HANDSHAKE_TIMEOUT_SECONDS = MAX_CONNECT_SETUP_SECONDS
MAX_CANCELLATION_GRACE_SECONDS = 5.0
MAX_OUTBOUND_CHANNEL_LIFETIME_SECONDS = MAX_OUTBOUND_LIFETIME_SECONDS
MAX_OUTBOUND_PENDING_HANDSHAKES = 2
OUTBOUND_STATIC_CONNECTION_SLOTS = 3
WORKER_MAX_CONCURRENT_RPCS = 32
COORDINATOR_MAX_CONCURRENT_RPCS = 52
COORDINATOR_MAX_GENERATE_STREAMS = 40
TYPED_SESSION_ID_RE = re.compile(r"ses_[0-9a-f]{32}\Z")


class SecureTransportError(RuntimeError):
    """A bounded, sanitized failure in the secure transport boundary."""


class AuthorizationRejected(SecureTransportError):
    pass


_OWNER_NETWORKS = tuple(ipaddress.IPv4Network(value) for value in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))


def _owner_address(address):
    return address.is_loopback or any(address in network for network in _OWNER_NETWORKS)


class AuthorizationRevoked(SecureTransportError):
    pass


class SecureTaskPending(SecureTransportError):
    """A secure operation remains pending beyond its bounded cleanup grace.

    The referenced tasks stay strongly owned. Callers must keep their auth and
    transport reservations until those tasks finish or an external supervisor
    terminates the process. This is an ordinary transport failure, not task
    cancellation; asyncio.CancelledError remains reserved for actual
    cancellation.
    """

    def __init__(self, tasks, message="secure operation is still stopping"):
        self.tasks = tuple(tasks)
        self.authorization_transferred = False
        super().__init__(message)


def _task_exception(task):
    try:
        return task.exception()
    except asyncio.CancelledError as error:
        return error


def _pending_task_descendants(tasks):
    """Find live children reported by completed secure pending failures."""
    pending = set()
    visited = set()
    stack = list(tasks)
    while stack:
        task = stack.pop()
        if task in visited:
            continue
        visited.add(task)
        if not task.done():
            pending.add(task)
            continue
        error = _task_exception(task)
        if isinstance(error, (SecureTaskPending, SecureConnectorPending)):
            stack.extend(error.tasks)
    return tuple(pending)


async def _wait_owned_tasks(tasks):
    """Wait for tasks and recursively follow their reported live children."""
    owned = set(tasks)
    while owned:
        live = tuple(task for task in owned if not task.done())
        if live:
            await asyncio.gather(*live, return_exceptions=True)
        descendants = _pending_task_descendants(owned)
        if not descendants:
            return
        owned = set(descendants)


_RETAINED_TASKS = set()


def _retain_tasks(tasks):
    for task in tasks:
        if task.done():
            continue
        _RETAINED_TASKS.add(task)
        task.add_done_callback(_RETAINED_TASKS.discard)


def _retain_authorization_until_done(authorization, tasks, *, cache_may_exist,
                                    ownership_ready=None):
    async def cleanup():
        if ownership_ready is not None:
            await ownership_ready.wait()
        await _wait_owned_tasks(tasks)
        await _close_failed_authorization(authorization,
                                         cache_may_exist=cache_may_exist)

    task = asyncio.create_task(cleanup())
    _retain_tasks((task,))
    return task


def _retain_authorization_close_until_done(authorization, tasks):
    async def cleanup():
        await _wait_owned_tasks(tasks)
        await _maybe_await(authorization.close())

    task = asyncio.create_task(cleanup())
    _retain_tasks((task,))
    return task


class _SecureRuntimeOwner:
    def __init__(self):
        self.unavailable = False
        self.pending_tasks = set()

    def retain_pending(self, tasks):
        self.unavailable = True
        tasks = tuple(tasks)
        live = tuple(set(task for task in tasks if not task.done())
                     | set(_pending_task_descendants(tasks)))
        for task in live:
            self.pending_tasks.add(task)
            _retain_tasks((task,))
            task.add_done_callback(self.pending_tasks.discard)
        if live:
            async def retain_descendants():
                await _wait_owned_tasks(live)

            owner = asyncio.create_task(retain_descendants())
            self.pending_tasks.add(owner)
            _retain_tasks((owner,))
            owner.add_done_callback(self.pending_tasks.discard)


async def _await_task_bounded(task, *, grace=None,
                              message="secure shutdown did not complete"):
    if grace is None:
        grace = MAX_CANCELLATION_GRACE_SECONDS
    if (isinstance(grace, bool) or not isinstance(grace, (int, float))
            or not math.isfinite(grace) or not 0 <= grace <= MAX_CANCELLATION_GRACE_SECONDS):
        raise SecureTransportError("shutdown grace is outside the secure transport bound")
    try:
        done, pending = await asyncio.wait((task,), timeout=grace)
    except asyncio.CancelledError:
        _retain_tasks((task,))
        raise
    if pending:
        _retain_tasks(pending)
        raise SecureTaskPending(pending, message)
    return await task


async def _cancel_tasks_bounded(tasks, *, grace=None,
                               message="secure tasks did not stop"):
    if grace is None:
        grace = MAX_CANCELLATION_GRACE_SECONDS
    if (isinstance(grace, bool) or not isinstance(grace, (int, float))
            or not math.isfinite(grace) or not 0 <= grace <= MAX_CANCELLATION_GRACE_SECONDS):
        raise SecureTransportError("cancellation grace is outside the secure transport bound")
    live = tuple(task for task in tasks if not task.done())
    for task in live:
        task.cancel()
    if not live:
        children = _pending_task_descendants(tasks)
        if children:
            _retain_tasks(children)
            raise SecureTaskPending(children, message)
        return
    try:
        done, pending = await asyncio.wait(live, timeout=grace)
    except asyncio.CancelledError:
        pending = tuple(task for task in live if not task.done())
        children = _pending_task_descendants(live)
        owned = tuple(set(pending) | set(children))
        if owned:
            _retain_tasks(owned)
            raise SecureTaskPending(owned, message)
        await asyncio.gather(*live, return_exceptions=True)
        raise
    if pending:
        children = _pending_task_descendants(done)
        owned = tuple(set(pending) | set(children))
        _retain_tasks(owned)
        raise SecureTaskPending(owned, message)
    children = _pending_task_descendants(done)
    if children:
        _retain_tasks(children)
        raise SecureTaskPending(children, message)
    await asyncio.gather(*done, return_exceptions=True)


def _release_reservation_after(task, reservation):
    async def finish():
        try:
            await task
        except BaseException:
            return
        await _maybe_await(reservation.release())

    cleanup = asyncio.create_task(finish())
    _retain_tasks((cleanup,))
    return cleanup


class SecureAuthorizer(Protocol):
    def authorize(self, service, method, payload, metadata, peer_certificate_pem): ...


class Authorization(Protocol):
    binding_bytes: bytes

    def assert_live(self): ...

    def complete(self, response): ...

    def fail(self, *, cache_may_exist=True): ...

    def close(self): ...

    def remaining_seconds(self): ...


class AuthorizationWatcher(Protocol):
    async def __call__(self, authorization):
        """Wait for invalidation; returning normally means the auth is invalid."""


class ExpectedServerLeafVerifier(Protocol):
    """Transport adapter API; the C0 primitive has different argument order."""

    def __call__(self, leaf_pem, ca_pem, expected, *, now): ...


class OutboundAuthorizer(Protocol):
    def authorize_outbound(self, service, method, payload, trusted_request_context,
                           peer_certificate_pem): ...


class ConnectionReservation(Protocol):
    def release(self): ...


class ConnectionController(Protocol):
    def reserve_listener(self, listener_id, *, connection_slots, pending_slots): ...

    def reserve_outbound(self, peer_device_id): ...

    def reserve_outbound_pending(self, peer_device_id): ...

    def reserve_pending(self, owner): ...


async def _maybe_await(value):
    if inspect.isawaitable(value):
        return await value
    return value


@dataclass(frozen=True)
class _Reservation:
    budget: object
    token: str

    def release(self):
        self.budget._release(self.token)


class NodeConnectionBudget:
    """Process-local static capacity plus live pending-handshake accounting.

    Listener reservations cover their full configured one- or two-connection
    C-core capacity. Live handshakes in either direction separately reserve a
    shared node-wide pending token. Cross-process deployments need an external
    shared controller.
    """

    def __init__(self, *, max_connections=MAX_NODE_CONNECTIONS,
                 max_pending=MAX_PENDING_HANDSHAKES,
                 max_per_peer=MAX_PEER_CONNECTIONS):
        for value, maximum in ((max_connections, MAX_NODE_CONNECTIONS),
                               (max_pending, MAX_PENDING_HANDSHAKES),
                               (max_per_peer, MAX_PEER_CONNECTIONS)):
            if type(value) is not int or not 1 <= value <= maximum:
                raise ValueError("connection limits must be positive and within the C1a ceiling")
        self.max_connections, self.max_pending = max_connections, max_pending
        self.max_per_peer = max_per_peer
        self._reserved_connections = 0
        self._reserved_pending = 0
        self._reserved_outbound_pending = 0
        self._reserved_listener_pending_capacity = 0
        self._peer_channels = {}
        self._listeners = set()
        self._reservations = {}
        self._lock = threading.Lock()

    @property
    def reserved_connections(self):
        with self._lock:
            return self._reserved_connections

    @property
    def reserved_pending(self):
        with self._lock:
            return self._reserved_pending

    @property
    def reserved_listener_pending_capacity(self):
        with self._lock:
            return self._reserved_listener_pending_capacity

    @property
    def reserved_outbound_pending(self):
        with self._lock:
            return self._reserved_outbound_pending

    def reserve_listener(self, listener_id, *, connection_slots, pending_slots):
        if (not isinstance(listener_id, str) or not listener_id or len(listener_id) > 128
                or type(connection_slots) is not int or connection_slots not in (1, 2)
                or type(pending_slots) is not int or pending_slots != connection_slots):
            raise ValueError("secure listeners must reserve one or two exact incoming/pending slots")
        with self._lock:
            # C-core exposes a per-server cap, not a shared cross-listener peer
            # counter. Reserve the exact configured listener ceiling; the
            # shared controller applies the node-wide 16/4 ceilings.
            if listener_id in self._listeners:
                raise SecureTransportError("secure listener capacity is already reserved")
            if (self._reserved_connections + connection_slots > self.max_connections
                    or self._reserved_listener_pending_capacity + pending_slots
                    > self.max_pending):
                raise SecureTransportError("node transport capacity exhausted")
            token = f"listener:{listener_id}"
            self._listeners.add(listener_id)
            self._reserved_connections += connection_slots
            self._reserved_listener_pending_capacity += pending_slots
            self._reservations[token] = (connection_slots, 0, None, pending_slots, None)
            return _Reservation(self, token)

    def reserve_outbound(self, peer_device_id):
        if not isinstance(peer_device_id, str) or not peer_device_id or len(peer_device_id) > 128:
            raise ValueError("outbound peer identity is invalid")
        with self._lock:
            current = self._peer_channels.get(peer_device_id, 0)
            if current >= self.max_per_peer:
                raise SecureTransportError("peer transport capacity exhausted")
            if (self._reserved_connections + OUTBOUND_STATIC_CONNECTION_SLOTS
                    > self.max_connections):
                raise SecureTransportError("node transport capacity exhausted")
            token = f"outbound:{peer_device_id}:{uuid.uuid4().hex}"
            self._peer_channels[peer_device_id] = current + 1
            self._reserved_connections += OUTBOUND_STATIC_CONNECTION_SLOTS
            self._reservations[token] = (OUTBOUND_STATIC_CONNECTION_SLOTS, 0,
                                         peer_device_id, 0, None)
            return _Reservation(self, token)

    def reserve_pending(self, owner):
        if not isinstance(owner, str) or not owner or len(owner) > 256:
            raise ValueError("pending handshake owner is invalid")
        with self._lock:
            if self._reserved_pending + 1 > self.max_pending:
                raise SecureTransportError("node pending handshake capacity exhausted")
            token = f"pending:{uuid.uuid4().hex}"
            self._reserved_pending += 1
            self._reservations[token] = (0, 1, None, 0, None)
            return _Reservation(self, token)

    def reserve_outbound_pending(self, peer_device_id):
        if not isinstance(peer_device_id, str) or not peer_device_id or len(peer_device_id) > 128:
            raise ValueError("outbound peer identity is invalid")
        with self._lock:
            if self._reserved_pending + 1 > self.max_pending:
                raise SecureTransportError("node pending handshake capacity exhausted")
            if self._reserved_outbound_pending + 1 > MAX_OUTBOUND_PENDING_HANDSHAKES:
                raise SecureTransportError("outbound pending handshake capacity exhausted")
            token = f"outbound-pending:{peer_device_id}:{uuid.uuid4().hex}"
            self._reserved_pending += 1
            self._reserved_outbound_pending += 1
            self._reservations[token] = (0, 1, None, 0, peer_device_id)
            return _Reservation(self, token)

    def _release(self, token):
        with self._lock:
            reservation = self._reservations.pop(token, None)
            if reservation is None:
                return
            connections, pending, peer, listener_pending, outbound_pending_peer = reservation
            self._reserved_connections -= connections
            self._reserved_pending -= pending
            self._reserved_listener_pending_capacity -= listener_pending
            if outbound_pending_peer is not None:
                self._reserved_outbound_pending -= 1
            if token.startswith("listener:"):
                self._listeners.discard(token[len("listener:"):])
            elif peer is not None:
                count = self._peer_channels.get(peer, 0) - 1
                if count <= 0:
                    self._peer_channels.pop(peer, None)
                else:
                    self._peer_channels[peer] = count


def parse_fixed_ipv4_endpoint(endpoint, allowed_addresses, *, listen=False):
    """Accept one allowlisted IPv4 literal; DNS and IPv6 fail closed.

    Outbound peers may be public only when their exact address is owner-listed.
    Listener binds are restricted to private or loopback interfaces.
    """
    if not isinstance(endpoint, str) or endpoint.count(":") != 1:
        raise ValueError("secure endpoints require a literal IPv4 address and port")
    host, port_text = endpoint.split(":", 1)
    try:
        address = ipaddress.IPv4Address(host)
    except ipaddress.AddressValueError:
        raise ValueError("secure endpoints require a literal IPv4 address; DNS is unsupported") from None
    if str(address) != host or address.is_unspecified or address.is_multicast or address.is_reserved:
        raise ValueError("secure endpoint address is not a canonical unicast IPv4 address")
    if listen and not _owner_address(address):
        raise ValueError("secure listener binds must use a private or loopback interface")
    if not isinstance(allowed_addresses, (set, frozenset, tuple, list)) or not allowed_addresses:
        raise ValueError("an explicit endpoint address allowlist is required")
    parsed_allowlist = set()
    for item in allowed_addresses:
        try:
            parsed = ipaddress.IPv4Address(item)
        except (ipaddress.AddressValueError, TypeError):
            raise ValueError("address allowlists must contain literal IPv4 addresses") from None
        if (not isinstance(item, str) or str(parsed) != item
                or parsed.is_unspecified or parsed.is_multicast or parsed.is_reserved
                or (listen and not _owner_address(parsed))):
            raise ValueError("address allowlist entries must use canonical IPv4 notation")
        parsed_allowlist.add(str(parsed))
    if host not in parsed_allowlist:
        raise ValueError("endpoint address is outside its owner-configured allowlist")
    if not port_text.isascii() or not port_text.isdecimal():
        raise ValueError("secure endpoint port must be an ASCII decimal number")
    port = int(port_text)
    minimum = 0 if listen else 1
    if not minimum <= port <= 65535 or str(port) != port_text:
        raise ValueError("secure endpoint port is outside its allowed range")
    return host, port


@dataclass(frozen=True)
class ExpectedServerIdentity:
    """Identity-core values bound to the fixed numeric endpoint and leaf pin."""

    account_id: str
    device_id: str
    role: str
    serial: int
    public_key_hash: object
    certificate_hash: object
    expected_ip: str
    ekus: tuple = ()

    def __post_init__(self):
        if not isinstance(self.account_id, str) or not isinstance(self.device_id, str):
            raise ValueError("expected server account and device IDs are required")
        if self.role not in {"host", "personal_coordinator"}:
            raise ValueError("C1a fixed server role must be host or personal_coordinator")
        if type(self.serial) is not int or self.serial <= 0:
            raise ValueError("expected server certificate serial must be positive")
        for value in (self.public_key_hash, self.certificate_hash):
            if isinstance(value, bytes):
                valid_hash = len(value) == 32
            else:
                valid_hash = (isinstance(value, str)
                              and re.fullmatch(r"[0-9a-f]{64}", value) is not None)
            if not valid_hash:
                raise ValueError("expected server hashes must be 32-byte SHA-256 pins")
        try:
            address = ipaddress.IPv4Address(self.expected_ip)
        except (ipaddress.AddressValueError, TypeError):
            raise ValueError("expected server address must be a literal IPv4 SAN") from None
        if (str(address) != self.expected_ip or address.is_unspecified
                or address.is_multicast or address.is_reserved):
            raise ValueError("expected server address must be canonical unicast IPv4")
        role_ekus = {"host": ("server",),
                     "personal_coordinator": ("client", "server")}[self.role]
        if not self.ekus:
            object.__setattr__(self, "ekus", role_ekus)
        elif type(self.ekus) is not tuple or self.ekus != role_ekus:
            raise ValueError("expected leaf EKUs do not match the fixed server role")

    @property
    def serial_hex(self):
        return format(self.serial, "x")

    @property
    def public_key_hash_hex(self):
        return (self.public_key_hash.hex() if isinstance(self.public_key_hash, bytes)
                else self.public_key_hash)

    @property
    def certificate_hash_hex(self):
        return (self.certificate_hash.hex() if isinstance(self.certificate_hash, bytes)
                else self.certificate_hash)


class C0ExpectedServerLeafAdapter:
    """Map the transport hook to the C0 leaf verifier's keyword-only API.

    The identity-core function is intentionally not a direct drop-in: its PEM
    arguments are ``(ca_pem, leaf_pem)`` and it accepts the expected identity
    fields by name. This adapter performs that explicit mapping and returns the
    approved non-CA leaf PEM used as gRPC's sole root certificate.
    """

    def __init__(self, core_verifier):
        if not callable(core_verifier):
            raise ValueError("the C0 expected server leaf verifier is required")
        self._core_verifier = core_verifier

    def __call__(self, leaf_pem, ca_pem, expected, *, now):
        if not isinstance(expected, ExpectedServerIdentity):
            raise SecureTransportError("expected server identity descriptor is invalid")
        result = self._core_verifier(
            ca_pem, leaf_pem, now=now, account_id=expected.account_id,
            device_id=expected.device_id, role=expected.role, serial=expected.serial_hex,
            public_key_hash=expected.public_key_hash_hex,
            certificate_hash=expected.certificate_hash_hex,
            expected_ip=expected.expected_ip, ekus=expected.ekus)
        if not isinstance(result, bytes) or not result:
            raise SecureTransportError("C0 leaf verifier returned no approved server PEM")
        return result


@dataclass(frozen=True)
class FixedPeer:
    endpoint: str
    allowed_addresses: tuple
    device_id: str
    server_leaf_pem: bytes
    cohort_ca_pem: bytes
    expected_server: ExpectedServerIdentity

    def __post_init__(self):
        host, _ = parse_fixed_ipv4_endpoint(self.endpoint, self.allowed_addresses)
        if not isinstance(self.device_id, str) or not self.device_id:
            raise ValueError("fixed peer requires an expected device identity")
        if not isinstance(self.server_leaf_pem, bytes) or not self.server_leaf_pem:
            raise ValueError("fixed peer requires the exact expected server leaf")
        if not isinstance(self.cohort_ca_pem, bytes) or not self.cohort_ca_pem:
            raise ValueError("fixed peer requires the pinned cohort CA for offline verification")
        if not isinstance(self.expected_server, ExpectedServerIdentity):
            raise ValueError("fixed peer requires a C0 expected server identity descriptor")
        if (self.expected_server.device_id != self.device_id
                or self.expected_server.expected_ip != host):
            raise ValueError("fixed peer endpoint/device differs from its pinned server identity")


@dataclass(frozen=True)
class LocalTlsIdentity:
    certificate_chain_pem: bytes
    private_key_pem: bytes

    def __post_init__(self):
        if not isinstance(self.certificate_chain_pem, bytes) or not self.certificate_chain_pem:
            raise ValueError("a role-specific local client certificate chain is required")
        if not isinstance(self.private_key_pem, bytes) or not self.private_key_pem:
            raise ValueError("a role-specific local client private key is required")


def _canonical_binding(raw):
    if not isinstance(raw, bytes) or not 1 <= len(raw) <= MAX_BINDING_BYTES:
        raise AuthorizationRejected("secure binding is missing or exceeds its byte limit")
    try:
        text = raw.decode("utf-8", errors="strict")

        def pairs(values):
            value = {}
            for key, item in values:
                if key in value:
                    raise ValueError("duplicate key")
                value[key] = item
            return value

        def constant(_):
            raise ValueError("non-finite value")

        binding = json.loads(text, object_pairs_hook=pairs, parse_constant=constant)
        if not isinstance(binding, dict) or not binding:
            raise ValueError("expected object")
        if any(not isinstance(key, str) or type(value) not in (str, int)
               for key, value in binding.items()):
            raise ValueError("binding must be a flat scalar object")
        canonical = json.dumps(binding, ensure_ascii=False, sort_keys=True,
                               separators=(",", ":"), allow_nan=False).encode("utf-8")
    except (UnicodeError, ValueError, TypeError, RecursionError):
        raise AuthorizationRejected("secure binding is not valid canonical JSON") from None
    if canonical != raw:
        raise AuthorizationRejected("secure binding is not canonical JSON")
    return binding


def _metadata_value_bytes(value):
    if isinstance(value, bytes):
        return value
    if isinstance(value, str):
        return value.encode("ascii", errors="strict")
    raise AuthorizationRejected("secure RPC metadata has an invalid value type")


def validate_metadata(metadata, *, require_binding=True):
    """Apply the hard application metadata cap before the identity core sees it."""
    try:
        entries = tuple(metadata or ())
    except TypeError:
        raise AuthorizationRejected("secure RPC metadata is malformed") from None
    total = 0
    bindings = []
    normalized = []
    for item in entries:
        if not isinstance(item, (tuple, list)) or len(item) != 2:
            raise AuthorizationRejected("secure RPC metadata is malformed")
        key, value = item
        if not isinstance(key, str) or not key or not key.isascii() or key.lower() != key:
            raise AuthorizationRejected("secure RPC metadata key is malformed")
        try:
            encoded = _metadata_value_bytes(value)
        except UnicodeEncodeError:
            raise AuthorizationRejected("secure RPC metadata value is malformed") from None
        total += len(key.encode("ascii")) + len(encoded) + 32
        if key == BINDING_METADATA_KEY:
            bindings.append(encoded)
        normalized.append((key, value))
    if total > MAX_METADATA_BYTES:
        raise AuthorizationRejected("secure RPC metadata exceeds the 8 KiB limit")
    if require_binding and len(bindings) != 1:
        raise AuthorizationRejected("secure RPC requires one authenticated binding")
    if len(bindings) > 1:
        raise AuthorizationRejected("secure RPC binding metadata is duplicated")
    binding = bindings[0] if bindings else None
    if binding is not None:
        _canonical_binding(binding)
    return tuple(normalized), binding, total


def outgoing_binding_metadata(binding_bytes):
    _canonical_binding(binding_bytes)
    metadata = ((BINDING_METADATA_KEY, binding_bytes),)
    _, _, total = validate_metadata(metadata)
    if total > MAX_METADATA_BYTES:
        raise AuthorizationRejected("secure RPC metadata exceeds the 8 KiB limit")
    return metadata


def capacity_rejection_metadata(binding_bytes):
    """Build the fixed version-1 trailer proving a request-scoped pre-admission denial.

    The digest binds this application marker to the exact canonical initial
    binding. It is a transport correlation marker, not proof against a
    Byzantine authenticated server.
    """
    _canonical_binding(binding_bytes)
    value = _CAPACITY_REJECTION_PREFIX + hashlib.sha256(binding_bytes).digest()
    metadata = ((CAPACITY_REJECTION_METADATA_KEY, value),)
    total = (len(CAPACITY_REJECTION_METADATA_KEY.encode("ascii"))
             + len(value) + 32)
    if total > MAX_METADATA_BYTES:
        raise AuthorizationRejected("capacity rejection metadata exceeds the 8 KiB limit")
    return metadata


def has_capacity_rejection_metadata(metadata, binding_bytes):
    """Return whether trailers contain only the exact marker for this binding."""
    _canonical_binding(binding_bytes)
    expected = _CAPACITY_REJECTION_PREFIX + hashlib.sha256(binding_bytes).digest()
    try:
        entries = iter(() if metadata is None else metadata)
    except Exception:
        return False
    total = 0
    count = 0
    candidate = None
    valid_shape = True
    try:
        for item in entries:
            if not isinstance(item, (tuple, list)) or len(item) != 2:
                return False
            key, value = item
            if (not isinstance(key, str) or not key or not key.isascii()
                    or key.lower() != key):
                return False
            try:
                encoded_value = _metadata_value_bytes(value)
            except (AuthorizationRejected, UnicodeEncodeError):
                return False
            total += len(key.encode("ascii")) + len(encoded_value) + 32
            if total > MAX_METADATA_BYTES:
                return False
            count += 1
            if count == 1 and key == CAPACITY_REJECTION_METADATA_KEY and type(value) is bytes:
                candidate = value
            else:
                valid_shape = False
    except Exception:
        return False
    return (valid_shape and count == 1 and isinstance(candidate, bytes)
            and candidate == expected)


def _peer_certificate_from_auth_context(context):
    try:
        auth_context = context.auth_context()
        transport = tuple(auth_context.get("transport_security_type", ()))
        certificates = tuple(auth_context.get("x509_pem_cert", ()))
    except Exception:
        raise AuthorizationRejected("authenticated TLS peer identity is unavailable") from None
    if b"ssl" not in transport or len(certificates) != 1 or not isinstance(certificates[0], bytes):
        raise AuthorizationRejected("authenticated TLS peer certificate is unavailable")
    return certificates[0]


def _authorization_status(grpc, error):
    name = type(error).__name__
    if (isinstance(error, AuthorizationRejected)
            or name in {"CredentialError", "SnapshotError", "ClockError", "AuthorizationExpired",
                        "BindingError", "RuntimeOpenAdmissionRejected"}):
        return grpc.StatusCode.UNAUTHENTICATED
    return grpc.StatusCode.PERMISSION_DENIED


async def _abort(context, code, message):
    await context.abort(code, message)


def _require_authorization(value):
    if value is None or not isinstance(getattr(value, "binding_bytes", None), bytes):
        raise SecureTransportError("identity adapter returned no authorization binding")
    _canonical_binding(value.binding_bytes)
    for name in ("assert_live", "complete", "fail", "close"):
        if not callable(getattr(value, name, None)):
            raise SecureTransportError("identity adapter authorization lifecycle is incomplete")
    if (getattr(value, "remaining_seconds", None) is None
            and getattr(value, "monotonic_deadline", None) is None
            and getattr(value, "deadline_monotonic", None) is None):
        raise SecureTransportError("identity adapter authorization has no monotonic lifetime")
    return value


async def _call_authorize(authorizer, service, method, payload, metadata, peer_certificate_pem):
    if service == WORKER_SERVICE and not isinstance(payload, Request):
        raise SecureTransportError("worker authorization requires the parsed protobuf Request")
    method_ = getattr(authorizer, "authorize", None)
    if not callable(method_):
        raise SecureTransportError("an explicit C0 Authorizer is required")
    value = method_(service=service, method=method, payload=payload, metadata=metadata,
                    peer_certificate_pem=peer_certificate_pem)
    value = await _maybe_await(value)
    try:
        return _require_authorization(value)
    except BaseException:
        await _close_failed_authorization(value, cache_may_exist=False)
        raise


async def _assert_live(authorization):
    result = await _maybe_await(authorization.assert_live())
    if result is not None and not (type(result) is bool and result is True):
        raise AuthorizationRevoked("authorization assert_live check did not succeed")


async def _remaining_auth_seconds(authorization):
    remaining = getattr(authorization, "remaining_seconds", None)
    if callable(remaining):
        remaining = await _maybe_await(remaining())
    elif remaining is None:
        deadline = getattr(authorization, "monotonic_deadline", None)
        if deadline is None:
            deadline = getattr(authorization, "deadline_monotonic", None)
        if callable(deadline):
            deadline = await _maybe_await(deadline())
        if isinstance(deadline, bool) or not isinstance(deadline, (int, float)):
            raise SecureTransportError(
                "identity authorization must expose its monotonic deadline or remaining seconds")
        remaining = deadline - time.monotonic()
    if (isinstance(remaining, bool) or not isinstance(remaining, (int, float))
            or not math.isfinite(remaining)):
        raise SecureTransportError("identity authorization returned an invalid remaining lifetime")
    return max(0.0, float(remaining))


async def _preflight_deadline(authorization, absolute_deadline):
    if (isinstance(absolute_deadline, bool)
            or not isinstance(absolute_deadline, (int, float))
            or not math.isfinite(absolute_deadline)):
        raise SecureTransportError("secure absolute request deadline is invalid")
    await _assert_live(authorization)
    remaining = await _remaining_auth_seconds(authorization)
    if remaining <= 0:
        raise AuthorizationRevoked("authorization has expired before dispatch")
    # Liveness and remaining_seconds may be asynchronous or take time. Re-read
    # the absolute request budget only after both checks have completed.
    request_remaining = float(absolute_deadline) - time.monotonic()
    if request_remaining <= 0:
        raise TimeoutError("secure request deadline expired before dispatch")
    effective_deadline = min(float(absolute_deadline), time.monotonic() + remaining)
    if effective_deadline <= time.monotonic():
        raise AuthorizationRevoked("authorization has expired before dispatch")
    return effective_deadline


async def _preflight_timeout(authorization, absolute_deadline):
    effective_deadline = await _preflight_deadline(authorization, absolute_deadline)
    timeout = effective_deadline - time.monotonic()
    if timeout <= 0:
        raise TimeoutError("secure request deadline expired before dispatch")
    return timeout


def _cancel_call(call):
    cancel = getattr(call, "cancel", None)
    if callable(cancel):
        try:
            cancel()
        except Exception:
            pass


def _call_done(call):
    if call is None:
        return True
    done = getattr(call, "done", None)
    return bool(done()) if callable(done) else bool(done)


async def _run_guarded(awaitable, authorization, watcher, *, timeout=None,
                       cancel_callback=None, on_pending=None,
                       cancel_grace_seconds=None,
                       failure_cache_may_exist=True, absolute_deadline=None,
                       close_authorization_on_pending=True):
    try:
        if not callable(watcher):
            raise SecureTransportError("an explicit authorization expiry/revocation watcher is required")
        if type(close_authorization_on_pending) is not bool:
            raise SecureTransportError(
                "pending authorization-close ownership flag must be boolean")
        await _assert_live(authorization)
        auth_remaining = await _remaining_auth_seconds(authorization)
        if auth_remaining <= 0:
            raise AuthorizationRevoked("authorization has expired")
        if absolute_deadline is not None:
            if (isinstance(absolute_deadline, bool)
                    or not isinstance(absolute_deadline, (int, float))
                    or not math.isfinite(absolute_deadline)):
                raise SecureTransportError("secure absolute deadline is invalid")
            deadline_remaining = float(absolute_deadline) - time.monotonic()
            if deadline_remaining <= 0:
                raise TimeoutError("secure absolute deadline expired before dispatch")
        else:
            deadline_remaining = None
        if timeout is not None:
            if (isinstance(timeout, bool) or not isinstance(timeout, (int, float))
                    or not math.isfinite(timeout) or timeout < 0):
                raise SecureTransportError("secure RPC timeout is invalid")
            requested_timeout = float(timeout)
        else:
            requested_timeout = auth_remaining
        if deadline_remaining is not None:
            requested_timeout = min(requested_timeout, deadline_remaining)
        auth_limits_call = auth_remaining <= requested_timeout
        timeout = min(requested_timeout, auth_remaining)
        if timeout <= 0:
            raise TimeoutError("secure deadline expired before dispatch")
        if cancel_grace_seconds is None:
            cancel_grace_seconds = MAX_CANCELLATION_GRACE_SECONDS
        if (isinstance(cancel_grace_seconds, bool)
                or not isinstance(cancel_grace_seconds, (int, float))
                or not math.isfinite(cancel_grace_seconds)
                or not 0 <= cancel_grace_seconds <= MAX_CANCELLATION_GRACE_SECONDS):
            raise SecureTransportError("cancellation grace is outside the secure transport bound")
    except BaseException:
        if callable(cancel_callback):
            try:
                result = cancel_callback()
                if inspect.isawaitable(result):
                    task = asyncio.create_task(result)
                    _retain_tasks((task,))
            except Exception:
                pass
        close = getattr(awaitable, "close", None)
        if callable(close):
            close()
        raise
    operation = asyncio.ensure_future(awaitable)
    monitor_cancel_wait_attempted = False
    pending_handoff_error = None
    authorization_retirement_roots = set()
    authorization_retirement_started = False
    authorization_retirement_ready = asyncio.Event()

    async def watch():
        result = await _maybe_await(watcher(authorization))
        raise AuthorizationRevoked("authorization watcher signaled invalidation")

    monitor = asyncio.create_task(watch())

    def defer_ownership(tasks):
        nonlocal authorization_retirement_started
        pending = tuple(set(task for task in tasks if not task.done())
                        | set(_pending_task_descendants(tasks)))
        if not pending:
            return
        _retain_tasks(pending)
        if close_authorization_on_pending:
            authorization_retirement_roots.update(pending)
            if not authorization_retirement_started:
                authorization_retirement_started = True
                _retain_authorization_until_done(
                    authorization, authorization_retirement_roots,
                    cache_may_exist=failure_cache_may_exist,
                    ownership_ready=authorization_retirement_ready)
        if callable(on_pending):
            try:
                result = on_pending(pending)
                if inspect.isawaitable(result):
                    task = asyncio.create_task(result)
                    _retain_tasks((task,))
            except Exception:
                pass

    def detach_exception_back_reference(root, target):
        """Remove links from a secondary exception graph back to the handoff."""
        pending = [root]
        visited = set()
        while pending:
            current = pending.pop()
            if not isinstance(current, BaseException) or current is target:
                continue
            identity = id(current)
            if identity in visited:
                continue
            visited.add(identity)
            for attribute in ("__cause__", "__context__"):
                linked = getattr(current, attribute, None)
                if linked is target:
                    setattr(current, attribute, None)
                elif isinstance(linked, BaseException):
                    pending.append(linked)

    def raise_pending_handoff_from(cause):
        """Keep the original handoff object and its existing causal chain."""
        error = pending_handoff_error
        if error is None:
            raise cause
        original_cause = error.__cause__
        original_context = error.__context__
        original_suppressed = error.__suppress_context__
        try:
            raise error from cause
        except SecureTaskPending:
            detach_exception_back_reference(cause, error)
            if original_cause is not None:
                detach_exception_back_reference(original_cause, error)
                error.__cause__ = original_cause
                error.__context__ = cause
                error.__suppress_context__ = original_suppressed
            else:
                detach_exception_back_reference(original_context, error)
                error.__cause__ = cause
                error.__context__ = original_context
                error.__suppress_context__ = True
            raise

    async def cancel_and_wait(tasks, *, cancel_rpc=False):
        nonlocal monitor_cancel_wait_attempted
        if monitor in tasks:
            # Once a bounded cancellation wait includes the monitor, the
            # finalizer must not restart that wait.
            monitor_cancel_wait_attempted = True
        if cancel_rpc and callable(cancel_callback):
            try:
                result = cancel_callback()
                if inspect.isawaitable(result):
                    task = asyncio.create_task(result)
                    _retain_tasks((task,))
            except Exception:
                pass
        for task in tasks:
            if not task.done():
                task.cancel()
        try:
            done, pending = await asyncio.wait(
                tuple(tasks), timeout=float(cancel_grace_seconds),
                return_when=asyncio.ALL_COMPLETED)
        except asyncio.CancelledError:
            pending = tuple(task for task in tasks if not task.done())
            children = _pending_task_descendants(tasks)
            owned = tuple(set(pending) | set(children))
            if owned:
                defer_ownership(owned)
                error = SecureTaskPending(owned)
                error.authorization_transferred = True
                raise error
            await asyncio.gather(*tasks, return_exceptions=True)
            raise
        children = _pending_task_descendants(done)
        if pending:
            owned = tuple(set(pending) | set(children))
            defer_ownership(owned)
            error = SecureTaskPending(owned)
            error.authorization_transferred = True
            raise error
        if children:
            defer_ownership(children)
            error = SecureTaskPending(children)
            error.authorization_transferred = True
            raise error
        await asyncio.gather(*done, return_exceptions=True)

    def inspect_monitor_terminal():
        """Normalize a terminal watcher result identically before/after waiting."""
        if not monitor.done():
            return None
        error = _task_exception(monitor)
        if isinstance(error, asyncio.CancelledError):
            return None
        if isinstance(error, (SecureTaskPending, SecureConnectorPending)):
            nested = _pending_task_descendants((monitor,))
            if nested:
                pending = SecureTaskPending(
                    nested, "authorization monitor cleanup remains pending")
                pending.__cause__ = error
                pending.__suppress_context__ = True
                return pending
            failure = AuthorizationRevoked(
                "authorization watcher reported exhausted pending work")
            failure.__cause__ = error
            failure.__suppress_context__ = True
            return failure
        if error is None:
            return AuthorizationRevoked("authorization watcher stopped")
        return error

    def surface_monitor_terminal(failure):
        if failure is None:
            return
        if isinstance(failure, SecureTaskPending):
            defer_ownership(failure.tasks)
            failure.authorization_transferred = True
        if pending_handoff_error is not None:
            if pending_handoff_error is failure:
                return
            if isinstance(failure, SecureTaskPending):
                pending_handoff_error.tasks = tuple(dict.fromkeys(
                    (*pending_handoff_error.tasks, *failure.tasks)))
                pending_handoff_error.authorization_transferred = True
            raise_pending_handoff_from(failure)
        if failure.__cause__ is not None:
            raise failure from failure.__cause__
        raise failure

    try:
        done, _ = await asyncio.wait((operation, monitor), timeout=timeout,
                                     return_when=asyncio.FIRST_COMPLETED)
        if not done:
            await cancel_and_wait((operation, monitor), cancel_rpc=True)
            if auth_limits_call:
                raise AuthorizationRevoked("authorization deadline expired")
            raise TimeoutError("secure RPC deadline expired")
        if monitor in done:
            await cancel_and_wait((operation,), cancel_rpc=True)
            raise AuthorizationRevoked("authorization is no longer live")
        return await operation
    except SecureTaskPending as error:
        pending_handoff_error = error
        nested = _pending_task_descendants(error.tasks)
        if nested:
            defer_ownership(nested)
            error.tasks = tuple(nested)
            error.authorization_transferred = True
        raise
    except asyncio.CancelledError:
        try:
            await cancel_and_wait((operation, monitor), cancel_rpc=True)
        except SecureTaskPending as error:
            pending_handoff_error = error
            raise
        raise
    finally:
        try:
            monitor_wait_pending = None
            monitor_wait_cancelled = None
            if not monitor.done() and not monitor_cancel_wait_attempted:
                try:
                    await cancel_and_wait((monitor,))
                except SecureTaskPending as monitor_pending:
                    monitor_wait_pending = monitor_pending
                except asyncio.CancelledError as cancellation:
                    # A caller cancellation may interrupt the one monitor
                    # retirement wait just as the monitor stops. Preserve it
                    # as causality, but do not let it replace an operation's
                    # already-established pending ownership handoff.
                    monitor_wait_cancelled = cancellation
            monitor_failure = inspect_monitor_terminal()
            if (monitor_wait_pending is not None
                    and pending_handoff_error is not None):
                pending_handoff_error.tasks = tuple(dict.fromkeys(
                    (*pending_handoff_error.tasks,
                     *monitor_wait_pending.tasks)))
                pending_handoff_error.authorization_transferred = True
            if monitor_wait_cancelled is not None:
                if pending_handoff_error is not None:
                    if monitor_failure is not None:
                        monitor_failure.__context__ = monitor_wait_cancelled
                        surface_monitor_terminal(monitor_failure)
                    if monitor_wait_pending is not None:
                        raise_pending_handoff_from(monitor_wait_pending)
                    raise_pending_handoff_from(monitor_wait_cancelled)
                if monitor_wait_pending is not None:
                    raise monitor_wait_pending from monitor_wait_cancelled
                if monitor_failure is not None:
                    raise monitor_wait_cancelled from monitor_failure
                raise monitor_wait_cancelled
            surface_monitor_terminal(monitor_failure)
            if monitor_wait_pending is not None:
                if pending_handoff_error is not None:
                    raise_pending_handoff_from(monitor_wait_pending)
                raise monitor_wait_pending
        finally:
            if authorization_retirement_started:
                authorization_retirement_ready.set()


async def _receive_unary_response(call):
    response = await call
    initial_metadata = await call.initial_metadata()
    return response, initial_metadata


def _secure_options(max_message_bytes, *, listener_slots=None):
    if type(max_message_bytes) is not int or not 1 <= max_message_bytes <= MAX_MESSAGE_BYTES:
        raise ValueError("secure message limit must fit the unchanged 1 MiB protocol ceiling")
    options = [("grpc.max_send_message_length", max_message_bytes),
               ("grpc.max_receive_message_length", max_message_bytes),
               # C-core's soft and absolute ceilings complement validate_metadata.
               ("grpc.max_metadata_size", MAX_METADATA_BYTES),
               ("grpc.absolute_max_metadata_size", MAX_METADATA_BYTES),
               ("grpc.ssl_minimum_protocol_version", 2)]
    if listener_slots is not None:
        if type(listener_slots) is not int or listener_slots not in (1, 2):
            raise ValueError("secure listener connection profile must use one or two slots")
        options.extend((("grpc.max_allowed_incoming_connections", listener_slots),
                        ("grpc.server_handshake_timeout_ms", SERVER_HANDSHAKE_TIMEOUT_MS)))
    return tuple(options)


class _SecureSubchannel:
    """One local per-peer channel behind a single-use accounted CONNECT gate."""

    def __init__(self, *, endpoint, create_channel, controller, peer_id,
                 allowed_addresses, on_unavailable, connector_factory=None):
        self.endpoint = endpoint
        self._create_channel = create_channel
        self._controller = controller
        self._peer_id = peer_id
        self._allowed_addresses = tuple(allowed_addresses)
        self._on_unavailable = on_unavailable
        self._connector_factory = connector_factory or SecureConnector
        self.channel = None
        self.connector = None
        self.pending = None
        self.ready_at = None
        self._lock = asyncio.Lock()
        self._monitor_task = None
        self._expiry_task = None
        self._ready_task = None
        self._closed = False
        self._unavailable = False

    def _state_ready(self, channel):
        state = channel.get_state(try_to_connect=False)
        return getattr(state, "name", str(state).rsplit(".", 1)[-1]) == "READY"

    async def get_ready(self, timeout, absolute_deadline=None):
        if (isinstance(timeout, bool) or not isinstance(timeout, (int, float))
                or not math.isfinite(timeout) or timeout <= 0):
            raise TimeoutError("no time remains for the outbound TLS handshake")
        now = time.monotonic()
        deadline = now + min(HANDSHAKE_TIMEOUT_SECONDS, float(timeout))
        if absolute_deadline is not None:
            if (isinstance(absolute_deadline, bool)
                    or not isinstance(absolute_deadline, (int, float))
                    or not math.isfinite(absolute_deadline)):
                raise SecureTransportError("outbound absolute setup deadline is invalid")
            deadline = min(deadline, float(absolute_deadline))
        if deadline <= now:
            raise TimeoutError("outbound setup deadline expired before channel creation")
        async with self._lock:
            if self._closed or self._unavailable:
                raise SecureTransportError("outbound secure subchannel is unavailable")
            if self.channel is not None:
                age = time.monotonic() - self.ready_at if self.ready_at is not None else math.inf
                try:
                    if (age < MAX_OUTBOUND_CHANNEL_LIFETIME_SECONDS
                            and self._state_ready(self.channel)
                            and self.connector is not None
                            and not self.connector.failed):
                        return self.channel
                except Exception:
                    pass
                try:
                    await self._close_channel_locked()
                except BaseException:
                    self._unavailable = True
                    self._on_unavailable()
                    raise
            return await self._create_ready_locked(deadline)

    async def _create_ready_locked(self, deadline):
        reserve = getattr(self._controller, "reserve_outbound_pending", None)
        if not callable(reserve):
            self._unavailable = True
            self._on_unavailable()
            raise SecureTransportError("shared outbound pending-handshake accounting is required")
        if time.monotonic() >= deadline:
            raise TimeoutError("outbound setup deadline expired before pending reservation")
        pending = reserve(self._peer_id)
        if inspect.isawaitable(pending):
            close = getattr(pending, "close", None)
            if callable(close):
                close()
            self._unavailable = True
            self._on_unavailable()
            raise SecureTransportError("outbound pending reservation must be synchronous")
        if pending is None or not callable(getattr(pending, "release", None)):
            self._unavailable = True
            self._on_unavailable()
            raise SecureTransportError("outbound pending controller returned no reservation")
        self.pending = pending
        channel = None
        try:
            self.connector = self._connector_factory(self.endpoint,
                self._allowed_addresses, pending_reservation=pending,
                handshake_deadline=deadline,
                lifetime_seconds=MAX_OUTBOUND_CHANNEL_LIFETIME_SECONDS,
                on_lifetime_expired=self._connector_lifetime_expired,
                cleanup_grace=MAX_CANCELLATION_GRACE_SECONDS)
            await self.connector.start()
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("outbound gate setup exceeded the handshake deadline")
            channel = self._create_channel(self.connector)
            self.channel = channel
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError(
                    "outbound secure channel setup exceeded the handshake deadline")
            self._ready_task = asyncio.create_task(channel.channel_ready())
            remaining = max(0.0, deadline - time.monotonic())
            done, pending_tasks = await asyncio.wait((self._ready_task,), timeout=remaining)
            if pending_tasks:
                await _cancel_tasks_bounded((self._ready_task,),
                    message="outbound channel readiness task did not cancel")
                raise TimeoutError("outbound secure channel did not become ready within five seconds")
            await self._ready_task
            if not self._state_ready(channel):
                raise SecureTransportError("gRPC channel readiness did not establish a secure transport")
            await self.connector.confirm_ready()
            self.pending = None
            self.ready_at = time.monotonic()
            self._ready_task = None
            self._monitor_task = asyncio.create_task(self._monitor(channel))
            self._expiry_task = asyncio.create_task(self._expire(channel, self.ready_at))
            self._monitor_task.add_done_callback(_task_exception)
            self._expiry_task.add_done_callback(_task_exception)
            return channel
        except BaseException as setup_error:
            try:
                await self._close_channel_locked()
            except SecureTaskPending:
                self._unavailable = True
                self._on_unavailable()
                raise
            except BaseException:
                self._unavailable = True
                self._on_unavailable()
                raise
            if isinstance(setup_error, asyncio.CancelledError):
                raise
            raise SecureTransportError(
                "outbound fixed-peer TLS channel failed before readiness") from None

    async def _monitor(self, channel):
        try:
            while channel is self.channel:
                state = channel.get_state(try_to_connect=False)
                if getattr(state, "name", str(state).rsplit(".", 1)[-1]) != "READY":
                    async with self._lock:
                        if channel is self.channel:
                            await self._close_channel_locked()
                    return
                connector = self.connector
                if connector is None:
                    raise SecureTransportError("outbound channel lost its CONNECT gate owner")
                state_task = asyncio.create_task(channel.wait_for_state_change(state))
                gate_task = asyncio.create_task(connector.wait_failure())
                children = (state_task, gate_task)
                cancellation_attempted = False
                try:
                    done, pending = await asyncio.wait(children,
                        return_when=asyncio.FIRST_COMPLETED)
                    if pending:
                        cancellation_attempted = True
                        await _cancel_tasks_bounded(pending,
                            message="outbound connectivity watcher did not stop")
                    if gate_task in done:
                        await gate_task
                        async with self._lock:
                            if channel is self.channel:
                                await self._close_channel_locked()
                        return
                    await state_task
                finally:
                    live = tuple(task for task in children if not task.done())
                    descendants = _pending_task_descendants(children)
                    owned = tuple(set(live) | set(descendants))
                    if owned:
                        if live and not cancellation_attempted:
                            cancellation_attempted = True
                            await _cancel_tasks_bounded(live,
                                message="outbound connectivity watcher children did not stop")
                            descendants = _pending_task_descendants(children)
                            owned = tuple(set(descendants)
                                          | set(task for task in live if not task.done()))
                        if owned:
                            _retain_tasks(owned)
                            raise SecureTaskPending(owned,
                                "outbound connectivity watcher still owns child tasks")
                    await asyncio.gather(*children, return_exceptions=True)
        except SecureTaskPending as error:
            _retain_tasks(error.tasks)
            self._unavailable = True
            self._on_unavailable()
            raise
        except asyncio.CancelledError:
            raise
        except BaseException:
            async with self._lock:
                if channel is self.channel:
                    try:
                        await self._close_channel_locked()
                    except BaseException:
                        self._unavailable = True
                        self._on_unavailable()

    async def _connector_lifetime_expired(self, connector):
        async with self._lock:
            if connector is not self.connector:
                return
            try:
                await self._close_channel_locked()
            except BaseException:
                self._unavailable = True
                self._on_unavailable()
                raise

    async def _expire(self, channel, ready_at):
        try:
            await asyncio.sleep(max(0.0, ready_at + MAX_OUTBOUND_CHANNEL_LIFETIME_SECONDS
                                    - time.monotonic()))
            async with self._lock:
                if channel is self.channel:
                    await self._close_channel_locked()
        except SecureTaskPending as error:
            _retain_tasks(error.tasks)
            self._unavailable = True
            self._on_unavailable()
            raise
        except asyncio.CancelledError:
            raise
        except BaseException:
            self._unavailable = True
            self._on_unavailable()

    async def _stop_auxiliary_locked(self):
        current = asyncio.current_task()
        for name in ("_monitor_task", "_expiry_task"):
            task = getattr(self, name)
            if task is None or task is current or not task.done():
                continue
            descendants = _pending_task_descendants((task,))
            if descendants:
                _retain_tasks(descendants)
                raise SecureTaskPending(descendants,
                    "outbound channel watcher still owns cleanup tasks")
            error = _task_exception(task)
            if isinstance(error, SecureTaskPending):
                descendants = _pending_task_descendants(error.tasks)
                if descendants:
                    _retain_tasks(descendants)
                    raise SecureTaskPending(descendants,
                        "outbound channel watcher still owns cleanup tasks")
        tasks = tuple(task for task in (self._monitor_task, self._expiry_task)
                      if task is not None and task is not current and not task.done())
        await _cancel_tasks_bounded(tasks,
            message="outbound channel watcher did not stop")
        for name in ("_monitor_task", "_expiry_task"):
            task = getattr(self, name)
            if task is not current and task is not None and task.done():
                setattr(self, name, None)

    async def _close_channel_locked(self):
        connector = self.connector
        if connector is not None:
            connector.stop_accepting()
        channel = self.channel
        if channel is not None:
            close_task = asyncio.create_task(channel.close())
            await _await_task_bounded(close_task,
                message="outbound secure channel could not confirm closure")
        if self._ready_task is not None and not self._ready_task.done():
            await _cancel_tasks_bounded((self._ready_task,),
                message="outbound TLS readiness task did not stop after channel close")
        await self._stop_auxiliary_locked()
        connector = self.connector
        if connector is not None:
            try:
                await connector.close(grace=MAX_CANCELLATION_GRACE_SECONDS)
            except SecureConnectorPending as error:
                _retain_tasks(error.tasks)
                raise SecureTaskPending(error.tasks,
                    "outbound CONNECT tunnel did not confirm physical closure") from error
            self.connector = None
            # The real connector owns this exact token through TLS readiness or
            # confirmed pre-ready teardown.
            self.pending = None
        elif self.pending is not None:
            await _maybe_await(self.pending.release())
            self.pending = None
        self.channel = None
        self.ready_at = None
        self._ready_task = None

    async def close(self):
        async with self._lock:
            if self._closed:
                return
            await self._close_channel_locked()
            self._closed = True

    async def fence(self):
        """Close a possibly ambiguous transport without allowing hidden reuse."""
        async with self._lock:
            if not self._closed:
                try:
                    await self._close_channel_locked()
                except BaseException:
                    self._unavailable = True
                    self._on_unavailable()
                    raise


async def _fail_authorization(authorization, *, cache_may_exist):
    if authorization is not None:
        await _maybe_await(authorization.fail(cache_may_exist=cache_may_exist))


async def _close_failed_authorization(authorization, *, cache_may_exist):
    if authorization is None:
        return
    failure = getattr(authorization, "fail", None)
    close = getattr(authorization, "close", None)
    try:
        if callable(failure):
            await _maybe_await(failure(cache_may_exist=cache_may_exist))
    finally:
        if callable(close):
            await _maybe_await(close())


def _verify_fixed_peer_leaf(peer, verifier, wall_clock, *, expected_role):
    host, _ = parse_fixed_ipv4_endpoint(peer.endpoint, peer.allowed_addresses)
    expected = peer.expected_server
    if (expected.expected_ip != host or expected.device_id != peer.device_id
            or expected.role != expected_role):
        raise SecureTransportError("pinned server identity differs from the fixed endpoint")
    approved_pem = verifier(peer.server_leaf_pem, peer.cohort_ca_pem,
                            expected, now=wall_clock())
    if not isinstance(approved_pem, bytes) or not approved_pem:
        raise SecureTransportError("expected server leaf was not approved by the C0 adapter")
    return approved_pem


class SecureServerHandle:
    def __init__(self, server, port, reservation, runtime_owner=None, acceptor=None):
        self.server, self.port, self._reservation = server, port, reservation
        self._runtime_owner = runtime_owner or _SecureRuntimeOwner()
        self._acceptor = acceptor
        self._stop_task = None
        self._stopped = False

    async def stop(self, grace=0):
        if self._stopped:
            return
        self._runtime_owner.unavailable = True
        shutdown_errors = []
        if self._acceptor is not None:
            try:
                await self._acceptor.stop()
            except BaseException as error:
                shutdown_errors.append(error)
        if self._stop_task is None or (self._stop_task.done()
                                      and _task_exception(self._stop_task) is not None):
            self._stop_task = asyncio.create_task(self.server.stop(grace))
        try:
            try:
                await _await_task_bounded(self._stop_task,
                                          message="secure listener shutdown did not complete")
            except BaseException as error:
                shutdown_errors.append(error)
            if shutdown_errors:
                raise shutdown_errors[0]
            drain_deadline = time.monotonic() + MAX_CANCELLATION_GRACE_SECONDS
            tracked = set()

            def pending_runtime_tasks():
                registered = set(self._runtime_owner.pending_tasks)
                tracked.update(registered)
                pending = {task for task in tracked if not task.done()}
                pending.update(_pending_task_descendants(tracked))
                unregistered = pending - registered
                if unregistered:
                    retain = getattr(self._runtime_owner, "retain_pending", None)
                    if callable(retain):
                        retain(unregistered)
                    else:
                        self._runtime_owner.pending_tasks.update(unregistered)
                        for task in unregistered:
                            _retain_tasks((task,))
                            task.add_done_callback(
                                self._runtime_owner.pending_tasks.discard)
                    tracked.update(unregistered)
                    registered = set(self._runtime_owner.pending_tasks)
                    tracked.update(registered)
                    pending = {task for task in tracked if not task.done()}
                    pending.update(_pending_task_descendants(tracked))
                return pending

            while True:
                pending = pending_runtime_tasks()
                if not pending:
                    break
                remaining = drain_deadline - time.monotonic()
                if remaining <= 0:
                    pending = pending_runtime_tasks()
                    if not pending:
                        break
                    _retain_tasks(pending)
                    raise SecureTaskPending(pending,
                        "secure listener still owns operations that did not stop")
                try:
                    await asyncio.wait(tuple(pending), timeout=remaining)
                except asyncio.CancelledError:
                    pending = pending_runtime_tasks()
                    if pending:
                        _retain_tasks(pending)
                    raise
            await _maybe_await(self._reservation.release())
        except BaseException:
            if self._stop_task is not None and self._stop_task.done():
                stop_error = _task_exception(self._stop_task)
                if stop_error is not None:
                    self._stop_task = None
            raise
        self._stopped = True


def _validate_tls_identity(identity):
    if not isinstance(identity, LocalTlsIdentity):
        raise ValueError("role-specific mTLS identity must come from the identity store")


async def create_secure_worker_server(handler, *, listen_endpoint, allowed_listen_addresses,
                                      server_identity, client_ca_pem, authorizer,
                                      authorization_watcher, connection_controller,
                                      listener_id, listener_slots,
                                      acceptor_directory,
                                      max_message_bytes=MAX_MESSAGE_BYTES):
    """Create an explicitly requested mTLS worker listener with C-core bounds."""
    import grpc
    from .transport import error_response

    parse_fixed_ipv4_endpoint(listen_endpoint, allowed_listen_addresses, listen=True)
    _validate_tls_identity(server_identity)
    if not isinstance(client_ca_pem, bytes) or not client_ca_pem:
        raise ValueError("pinned client cohort CA roots are required")
    if authorizer is None or not callable(getattr(authorizer, "authorize", None)):
        raise ValueError("secure worker service requires the C0 Authorizer")
    if not callable(authorization_watcher):
        raise ValueError("secure worker service requires an expiry/revocation watcher")
    if (connection_controller is None
            or not callable(getattr(connection_controller, "reserve_listener", None))
            or not callable(getattr(connection_controller, "reserve_pending", None))):
        raise ValueError("secure worker service requires a node connection accounting controller")
    if type(listener_slots) is not int or listener_slots not in (1, 2):
        raise ValueError("secure worker listener must explicitly select one or two connection slots")
    from .secure_acceptor import (SecureAcceptor, new_private_socket_path,
                                  validate_private_unix_directory)
    private_directory = validate_private_unix_directory(acceptor_directory)
    backend_path = new_private_socket_path(private_directory,
        name=f"backend-{uuid.uuid4().hex[:12]}.sock")
    reservation = await _maybe_await(connection_controller.reserve_listener(
        listener_id, connection_slots=listener_slots, pending_slots=listener_slots))
    if reservation is None or not callable(getattr(reservation, "release", None)):
        raise SecureTransportError("connection controller did not reserve listener capacity")

    server = None
    acceptor = None
    runtime_owner = _SecureRuntimeOwner()

    def mark_listener_unavailable():
        runtime_owner.unavailable = True
        if acceptor is not None:
            acceptor.pause()

    try:
        acceptor = SecureAcceptor(listen_endpoint=listen_endpoint,
            allowed_listen_addresses=allowed_listen_addresses,
            backend_socket_path=backend_path, private_directory=private_directory,
            listener_slots=listener_slots, connection_controller=connection_controller,
            on_unavailable=mark_listener_unavailable)
        server = grpc.aio.server(options=_secure_options(max_message_bytes,
                                 listener_slots=listener_slots),
                                 maximum_concurrent_rpcs=WORKER_MAX_CONCURRENT_RPCS)

        def make_handler(method):
            async def invoke(data, context):
                authorization = None
                completed = False
                authorization_transferred = False
                request = None
                try:
                    if runtime_owner.unavailable:
                        await _abort(context, grpc.StatusCode.UNAVAILABLE,
                                     "Secure worker listener is draining")
                        return b""
                    peer_certificate = _peer_certificate_from_auth_context(context)
                    metadata, binding, _ = validate_metadata(context.invocation_metadata())
                    request = parse_message(data, Request, max_message_bytes)
                    authorization = await _call_authorize(authorizer, WORKER_SERVICE, method,
                        request, metadata, peer_certificate)
                    if authorization.binding_bytes != binding:
                        raise AuthorizationRejected("identity adapter binding differs from the request")
                    await _assert_live(authorization)
                    if not await acceptor.mark_authenticated_peer(context.peer()):
                        raise AuthorizationRejected("TLS connection is not tracked by the bounded acceptor")
                except AuthorizationRejected:
                    await _close_failed_authorization(authorization, cache_may_exist=False)
                    if acceptor is not None:
                        await acceptor.reject_unestablished_peer(context.peer())
                    await _abort(context, grpc.StatusCode.UNAUTHENTICATED,
                                 "Peer authorization is required")
                    return b""
                except ProtocolError:
                    await _close_failed_authorization(authorization, cache_may_exist=False)
                    if acceptor is not None:
                        await acceptor.reject_unestablished_peer(context.peer())
                    await _abort(context, grpc.StatusCode.INVALID_ARGUMENT,
                                 "Worker protocol request is invalid")
                    return b""
                except SecureTaskPending as error:
                    authorization_transferred = True
                    runtime_owner.retain_pending(error.tasks)
                    if authorization is not None:
                        cleanup = _retain_authorization_until_done(
                            authorization, error.tasks, cache_may_exist=False)
                        runtime_owner.retain_pending((cleanup,))
                        error.authorization_transferred = True
                    if acceptor is not None:
                        await acceptor.reject_unestablished_peer(context.peer())
                    raise
                except asyncio.CancelledError:
                    await _close_failed_authorization(authorization, cache_may_exist=False)
                    if acceptor is not None:
                        await acceptor.reject_unestablished_peer(context.peer())
                    raise
                except Exception as error:
                    await _close_failed_authorization(authorization, cache_may_exist=False)
                    if acceptor is not None:
                        await acceptor.reject_unestablished_peer(context.peer())
                    await _abort(context, _authorization_status(grpc, error),
                                 "Peer is not authorized for this worker operation")
                    return b""

                async def serve_response():
                    try:
                        timeout = request.timeout_ms / 1000
                        if not 0 < timeout <= MAX_TIMEOUT_MS / 1000:
                            raise ProtocolError("INVALID_INPUT", "request timeout is outside the transport limit")
                        remaining = context.time_remaining()
                        if remaining is not None:
                            timeout = min(timeout, max(0.0, remaining))
                        response = await asyncio.wait_for(handler.handle(method, request), timeout)
                    except ProtocolError as error:
                        response = error_response(error, request)
                    except TimeoutError:
                        response = error_response(
                            ProtocolError("TIMEOUT", "transport deadline exceeded"), request)
                    serialized = serialize_message(response, max_message_bytes)
                    await _assert_live(authorization)
                    await _maybe_await(authorization.complete(response))
                    await _assert_live(authorization)
                    await context.send_initial_metadata(((BINDING_METADATA_KEY,
                                                           authorization.binding_bytes),))
                    await _assert_live(authorization)
                    return serialized

                try:
                    remaining = context.time_remaining()
                    timeout = request.timeout_ms / 1000
                    if remaining is not None:
                        timeout = min(timeout, max(0.0, remaining))
                    serialized = await _run_guarded(serve_response(), authorization,
                        authorization_watcher, timeout=timeout,
                        on_pending=runtime_owner.retain_pending,
                        failure_cache_may_exist=(method != "Describe"))
                    completed = True
                    return serialized
                except SecureTaskPending:
                    authorization_transferred = True
                    raise
                except AuthorizationRevoked:
                    await _fail_authorization(authorization,
                                              cache_may_exist=(method != "Describe"))
                    await _abort(context, grpc.StatusCode.UNAUTHENTICATED,
                                 "Peer authorization is no longer valid")
                except asyncio.CancelledError:
                    await _fail_authorization(authorization,
                                              cache_may_exist=(method != "Describe"))
                    raise
                except Exception:
                    if not completed:
                        await _fail_authorization(authorization,
                                                  cache_may_exist=(method != "Describe"))
                    try:
                        await _assert_live(authorization)
                    except Exception:
                        await _abort(context, grpc.StatusCode.UNAUTHENTICATED,
                                     "Peer authorization is no longer valid")
                    else:
                        await _abort(context, grpc.StatusCode.INTERNAL,
                                     "Secure worker operation failed")
                finally:
                    if authorization is not None and not authorization_transferred:
                        await _maybe_await(authorization.close())
            return grpc.unary_unary_rpc_method_handler(invoke)

        methods = {name: make_handler(name) for name in METHODS}
        server.add_generic_rpc_handlers((grpc.method_handlers_generic_handler(WORKER_SERVICE, methods),))
        credentials = grpc.ssl_server_credentials(
            ((server_identity.private_key_pem, server_identity.certificate_chain_pem),),
            root_certificates=client_ca_pem, require_client_auth=True)
        backend_port = server.add_secure_port(f"unix:{backend_path}", credentials)
        if not backend_port:
            raise SecureTransportError("C-core refused the private secure UDS backend")
        await server.start()
        public_port = await acceptor.start()
        return SecureServerHandle(server, public_port, reservation, runtime_owner, acceptor)
    except BaseException as startup_error:
        if server is None and acceptor is None:
            await _maybe_await(reservation.release())
            raise

        async def cleanup_created_listener():
            errors = []
            if acceptor is not None:
                try:
                    await acceptor.stop()
                except BaseException as error:
                    errors.append(error)
            if server is not None:
                try:
                    await server.stop(0)
                except BaseException as error:
                    errors.append(error)
            if errors:
                raise errors[0]
            await _maybe_await(reservation.release())

        stop_task = asyncio.create_task(cleanup_created_listener())
        try:
            await _await_task_bounded(stop_task,
                message="created secure listener could not confirm startup cleanup")
        except BaseException as cleanup_error:
            _retain_tasks((stop_task,))
            if isinstance(cleanup_error, SecureTaskPending):
                raise cleanup_error from startup_error
            raise SecureTaskPending((stop_task,),
                "created secure listener shutdown failed; capacity remains reserved") from startup_error
        raise startup_error


class SecureWorkerClient:
    def __init__(self, *, peer, local_identity, outbound_authorizer, authorization_watcher,
                 connection_reservation, approved_server_leaf_pem,
                 connection_controller,
                 max_message_bytes=MAX_MESSAGE_BYTES):
        self.peer = peer
        self.local_identity = local_identity
        self.approved_server_leaf_pem = approved_server_leaf_pem
        self.outbound_authorizer = outbound_authorizer
        self.authorization_watcher = authorization_watcher
        self._reservation = connection_reservation
        _secure_options(max_message_bytes)
        self.max_message_bytes = max_message_bytes
        self.max_timeout_ms = MAX_TIMEOUT_MS
        self._closed = False
        self._unavailable = False
        self._runtime_owner = _SecureRuntimeOwner()
        self._active_calls = set()

        def create_channel(connector):
            import grpc

            credentials = grpc.ssl_channel_credentials(
                root_certificates=self.approved_server_leaf_pem,
                private_key=self.local_identity.private_key_pem,
                certificate_chain=self.local_identity.certificate_chain_pem)
            return grpc.aio.secure_channel(self.peer.endpoint, credentials,
                options=(*_secure_options(self.max_message_bytes),
                         *connector.channel_options()),
                compression=grpc.Compression.NoCompression)

        self._subchannel = _SecureSubchannel(endpoint=peer.endpoint,
            create_channel=create_channel, controller=connection_controller,
            peer_id=peer.device_id, allowed_addresses=peer.allowed_addresses,
            on_unavailable=self._mark_unavailable)

    @property
    def channel(self):
        return self._subchannel.channel

    def _mark_unavailable(self):
        self._unavailable = True
        self._runtime_owner.unavailable = True

    async def _ensure_channel(self, timeout, absolute_deadline=None):
        return await self._subchannel.get_ready(timeout, absolute_deadline)

    async def execute(self, method, request, *, trusted_request_context=None):
        import grpc

        if self._closed or self._unavailable or self._runtime_owner.unavailable:
            raise ProtocolError("EXECUTION_FAILED", "secure worker channel is closed")
        if method not in METHODS:
            raise ProtocolError("INVALID_INPUT", "unknown protocol operation")
        if not isinstance(request, Request):
            raise ProtocolError("INVALID_INPUT", "expected a worker protocol request")
        if trusted_request_context is None:
            raise SecureTransportError("worker calls require explicit trusted request context")
        if type(request.timeout_ms) is not int or not 1 <= request.timeout_ms <= self.max_timeout_ms:
            raise ProtocolError("INVALID_INPUT", "request timeout is outside the secure transport limit")
        request_deadline = time.monotonic() + request.timeout_ms / 1000
        auth = await _authorize_outbound(self.outbound_authorizer, WORKER_SERVICE, method,
                                         request, trusted_request_context,
                                         self.approved_server_leaf_pem)
        call = None
        authorization_transferred = False
        succeeded = False
        operation_task = asyncio.current_task()
        try:
            setup_deadline = await _preflight_deadline(auth, request_deadline)
            timeout = setup_deadline - time.monotonic()
            channel = await self._ensure_channel(timeout, setup_deadline)
            timeout = await _preflight_timeout(auth, request_deadline)
            timeout_ms = min(request.timeout_ms, int(timeout * 1000))
            if timeout_ms < 1:
                raise AuthorizationRevoked("authorization lifetime is below one wire millisecond")
            wire_request = Request()
            wire_request.CopyFrom(request)
            wire_request.timeout_ms = timeout_ms
            data = serialize_message(wire_request, self.max_message_bytes)
            final_timeout = await _preflight_timeout(auth, request_deadline)
            final_timeout_ms = min(request.timeout_ms, int(final_timeout * 1000))
            if final_timeout_ms < 1:
                raise AuthorizationRevoked(
                    "authorization lifetime is below one wire millisecond")
            if final_timeout_ms != timeout_ms:
                timeout_ms = final_timeout_ms
                wire_request.timeout_ms = timeout_ms
                data = serialize_message(wire_request, self.max_message_bytes)
            metadata = outgoing_binding_metadata(auth.binding_bytes)
            # Serialization and metadata construction can consume part of the
            # authorization/request budget. Use a fresh clipped gRPC deadline
            # after all encoding; the server also takes the minimum of this
            # transport deadline and the protobuf timeout.
            dispatch_timeout = await _preflight_timeout(auth, request_deadline)
            dispatch_timeout_ms = min(timeout_ms, int(dispatch_timeout * 1000))
            if dispatch_timeout_ms < 1:
                raise AuthorizationRevoked(
                    "authorization lifetime is below one wire millisecond")
            call = channel.unary_unary(f"/{WORKER_SERVICE}/{method}")(
                data, timeout=dispatch_timeout_ms / 1000,
                wait_for_ready=False, metadata=metadata)
            self._active_calls.add((operation_task, call))
            payload_bytes, echoed = await _run_guarded(
                _receive_unary_response(call), auth, self.authorization_watcher,
                timeout=dispatch_timeout_ms / 1000, cancel_callback=call.cancel,
                on_pending=self._runtime_owner.retain_pending,
                failure_cache_may_exist=(method != "Describe"))
            _, response_binding, _ = validate_metadata(echoed)
            if response_binding != auth.binding_bytes:
                raise ProtocolError("EXECUTION_FAILED",
                                    "secure response binding mismatch; operation outcome may be unknown")
            await _assert_live(auth)
            try:
                response = parse_message(payload_bytes, Response, self.max_message_bytes)
                response = validate_response(method, wire_request, response)
            except ProtocolError:
                if method == "OpenSession":
                    # The peer may have committed the lease before a malformed,
                    # mismatched, or locally unparseable reply was received.
                    # Preserve that uncertainty for the coordinator to fence.
                    raise ProtocolError(
                        "EXECUTION_FAILED",
                        "OpenSession reply was invalid; remote admission outcome is unknown"
                    ) from None
                raise
            await _assert_live(auth)
            await _maybe_await(auth.complete(response))
            await _assert_live(auth)
            succeeded = True
            return response
        except SecureTaskPending as error:
            authorization_transferred = error.authorization_transferred
            self._runtime_owner.retain_pending(error.tasks)
            self._unavailable = True
            raise
        except grpc.aio.AioRpcError as error:
            _cancel_call(call)
            await _fail_authorization(auth,
                cache_may_exist=(call is not None and method != "Describe"))
            # A raw C-core RESOURCE_EXHAUSTED (for example, a client receive
            # cap) says nothing about whether OpenSession was admitted. Only a
            # parsed, binding-validated protobuf capacity response is safe to
            # classify as a known pre-admission rejection.
            code = {grpc.StatusCode.DEADLINE_EXCEEDED: "TIMEOUT",
                    grpc.StatusCode.CANCELLED: "CANCELLED"}.get(error.code(), "EXECUTION_FAILED")
            raise ProtocolError(code, "secure RPC failed; operation outcome may be unknown") from None
        except asyncio.CancelledError:
            _cancel_call(call)
            await _fail_authorization(auth,
                cache_may_exist=(call is not None and method != "Describe"))
            raise
        except Exception:
            _cancel_call(call)
            await _fail_authorization(auth,
                cache_may_exist=(call is not None and method != "Describe"))
            raise
        finally:
            if call is not None and not succeeded and not _call_done(call):
                _cancel_call(call)
            if call is not None:
                self._active_calls.discard((operation_task, call))
            try:
                if call is not None and not succeeded:
                    await self._subchannel.fence()
            finally:
                if not authorization_transferred:
                    await _maybe_await(auth.close())

    async def close(self):
        if self._closed:
            return
        self._unavailable = True
        calls = tuple(self._active_calls)
        for _task, call in calls:
            _cancel_call(call)
        pending_operations = tuple({task for task, _call in calls
                                    if task is not asyncio.current_task() and not task.done()})
        if pending_operations:
            done, pending = await asyncio.wait(pending_operations,
                timeout=MAX_CANCELLATION_GRACE_SECONDS)
            if pending:
                _retain_tasks(pending)
                raise SecureTaskPending(pending,
                    "secure worker RPCs still own the client reservation")
            await asyncio.gather(*done, return_exceptions=True)
        await self._subchannel.close()
        pending = tuple(task for task in self._runtime_owner.pending_tasks if not task.done())
        if pending:
            done, pending = await asyncio.wait(pending,
                timeout=MAX_CANCELLATION_GRACE_SECONDS)
            if pending:
                _retain_tasks(pending)
                raise SecureTaskPending(pending,
                    "secure worker calls still own the channel reservation")
            await asyncio.gather(*done, return_exceptions=True)
        await _maybe_await(self._reservation.release())
        self._closed = True

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_):
        await self.close()


async def _authorize_outbound(authorizer, service, method, payload, trusted_context, peer_certificate):
    if service == WORKER_SERVICE and not isinstance(payload, Request):
        raise SecureTransportError("worker outbound authorization requires the protobuf Request")
    method_ = getattr(authorizer, "authorize_outbound", None)
    if not callable(method_):
        raise SecureTransportError("an explicit outbound C0 authorization adapter is required")
    value = method_(service=service, method=method, payload=payload,
                    trusted_request_context=trusted_context,
                    peer_certificate_pem=peer_certificate)
    value = await _maybe_await(value)
    try:
        return _require_authorization(value)
    except BaseException:
        await _close_failed_authorization(value, cache_may_exist=False)
        raise


async def create_secure_worker_client(peer, *, local_identity, outbound_authorizer,
                                      authorization_watcher, verify_expected_server_leaf,
                                      connection_controller, wall_clock=time.time,
                                      max_message_bytes=MAX_MESSAGE_BYTES):
    """Pin an expected server leaf offline before constructing the gRPC channel."""
    if not isinstance(peer, FixedPeer):
        raise ValueError("an owner-configured FixedPeer is required")
    _validate_tls_identity(local_identity)
    if not callable(getattr(outbound_authorizer, "authorize_outbound", None)):
        raise ValueError("secure worker client requires an outbound authorization adapter")
    if not callable(authorization_watcher):
        raise ValueError("secure worker client requires an expiry/revocation watcher")
    if not callable(verify_expected_server_leaf):
        raise ValueError("secure worker client requires the C0 expected-leaf verifier")
    if (connection_controller is None
            or not callable(getattr(connection_controller, "reserve_outbound", None))
            or not callable(getattr(connection_controller, "reserve_outbound_pending", None))):
        raise ValueError("secure worker client requires node connection accounting")
    # This is the C0 identity-core verifier. Do not replace it with a transport
    # probe or a broad-CA channel; roots below contain this exact approved leaf.
    approved_leaf = _verify_fixed_peer_leaf(peer, verify_expected_server_leaf, wall_clock,
                                            expected_role="host")
    reservation = await _maybe_await(connection_controller.reserve_outbound(peer.device_id))
    if reservation is None or not callable(getattr(reservation, "release", None)):
        raise SecureTransportError("connection controller did not reserve outbound capacity")
    try:
        return SecureWorkerClient(peer=peer, local_identity=local_identity,
            outbound_authorizer=outbound_authorizer,
            authorization_watcher=authorization_watcher,
            connection_reservation=reservation,
            approved_server_leaf_pem=approved_leaf,
            connection_controller=connection_controller,
            max_message_bytes=max_message_bytes)
    except BaseException:
        await _maybe_await(reservation.release())
        raise


class SecureCoordinatorClient:
    """Secure counterpart to RemoteClient; no insecure fallback is available."""

    def __init__(self, *, peer, local_identity, outbound_authorizer, authorization_watcher,
                 connection_reservation, approved_server_leaf_pem,
                 connection_controller):
        self.peer = peer
        self.local_identity = local_identity
        self.approved_server_leaf_pem = approved_server_leaf_pem
        self.outbound_authorizer, self.authorization_watcher = outbound_authorizer, authorization_watcher
        self._reservation = connection_reservation
        self._closed = False
        self._unavailable = False
        self._runtime_owner = _SecureRuntimeOwner()
        self._active_calls = set()

        def create_channel(connector):
            import grpc

            credentials = grpc.ssl_channel_credentials(
                root_certificates=self.approved_server_leaf_pem,
                private_key=self.local_identity.private_key_pem,
                certificate_chain=self.local_identity.certificate_chain_pem)
            return grpc.aio.secure_channel(self.peer.endpoint, credentials,
                options=(*_secure_options(MAX_MESSAGE_BYTES),
                         *connector.channel_options()),
                compression=grpc.Compression.NoCompression)

        self._subchannel = _SecureSubchannel(endpoint=peer.endpoint,
            create_channel=create_channel, controller=connection_controller,
            peer_id=peer.device_id, allowed_addresses=peer.allowed_addresses,
            on_unavailable=self._mark_unavailable)

    @property
    def channel(self):
        return self._subchannel.channel

    def _mark_unavailable(self):
        self._unavailable = True
        self._runtime_owner.unavailable = True

    async def _ensure_channel(self, timeout, absolute_deadline=None):
        return await self._subchannel.get_ready(timeout, absolute_deadline)

    async def _unary(self, method, value, timeout, trusted_request_context, limit):
        import grpc
        from ..remote_client import encode_json, decode_json, RemoteError

        if self._closed or self._unavailable or self._runtime_owner.unavailable:
            raise RemoteError("EXECUTION_FAILED", "secure coordinator channel is closed")
        if (isinstance(timeout, bool) or not isinstance(timeout, (int, float))
                or not math.isfinite(timeout) or not 0 < timeout <= 300):
            raise RemoteError("INVALID_INPUT", "Secure coordinator timeout is outside its limit")
        deadline = time.monotonic() + float(timeout)
        if trusted_request_context is None:
            raise SecureTransportError("secure coordinator calls require trusted consumer context")
        body = encode_json(value, limit)
        auth = await _authorize_outbound(self.outbound_authorizer, COORDINATOR_SERVICE, method,
            value, trusted_request_context, self.approved_server_leaf_pem)
        call = None
        authorization_transferred = False
        succeeded = False
        operation_task = asyncio.current_task()
        try:
            setup_deadline = await _preflight_deadline(auth, deadline)
            timeout = setup_deadline - time.monotonic()
            channel = await self._ensure_channel(timeout, setup_deadline)
            timeout = await _preflight_timeout(auth, deadline)
            metadata = outgoing_binding_metadata(auth.binding_bytes)
            timeout = await _preflight_timeout(auth, deadline)
            call = channel.unary_unary(f"/{COORDINATOR_SERVICE}/{method}")(
                body, timeout=timeout, wait_for_ready=False,
                metadata=metadata)
            self._active_calls.add((operation_task, call))
            response, echoed = await _run_guarded(
                _receive_unary_response(call), auth, self.authorization_watcher,
                timeout=timeout, cancel_callback=call.cancel,
                on_pending=self._runtime_owner.retain_pending,
                failure_cache_may_exist=False)
            _, binding, _ = validate_metadata(echoed)
            if binding != auth.binding_bytes:
                raise RemoteError("EXECUTION_FAILED",
                    "Secure coordinator reply binding mismatch; outcome may be unknown and will not be retried")
            await _assert_live(auth)
            result = decode_json(response)
            await _maybe_await(auth.complete(result))
            await _assert_live(auth)
            succeeded = True
            return result
        except SecureTaskPending as error:
            authorization_transferred = error.authorization_transferred
            self._runtime_owner.retain_pending(error.tasks)
            self._unavailable = True
            raise
        except grpc.aio.AioRpcError as error:
            _cancel_call(call)
            await _fail_authorization(auth, cache_may_exist=False)
            from ..remote_client import _rpc_error
            mapped = _rpc_error(error)
            from ..remote_client import RemoteError
            raise RemoteError(mapped.code,
                "Secure coordinator reply may be lost; outcome is unknown and no retry was attempted") from None
        except asyncio.CancelledError:
            _cancel_call(call)
            await _fail_authorization(auth, cache_may_exist=False)
            raise
        except Exception:
            _cancel_call(call)
            await _fail_authorization(auth, cache_may_exist=False)
            raise
        finally:
            if call is not None and not succeeded and not _call_done(call):
                _cancel_call(call)
            if call is not None:
                self._active_calls.discard((operation_task, call))
            try:
                if call is not None and not succeeded:
                    await self._subchannel.fence()
            finally:
                if not authorization_transferred:
                    await _maybe_await(auth.close())

    async def describe(self, *, trusted_request_context, timeout_seconds=5):
        return await self._unary("Describe", {}, timeout_seconds, trusted_request_context, 64)

    async def tokenize(self, text, *, trusted_request_context, add_special_tokens=True):
        from ..remote_client import MAX_TOKENIZE_BYTES, validate_text
        value = {"text": text, "add_special_tokens": add_special_tokens}
        validate_text(value)
        result = await self._unary("Tokenize", value, 30, trusted_request_context,
                                   MAX_TOKENIZE_BYTES)
        from ..remote_client import _tokens, RemoteError
        if set(result) != {"input_ids"} or not _tokens(result["input_ids"]):
            raise RemoteError("EXECUTION_FAILED", "Invalid tokenizer reply")
        return result["input_ids"]

    async def generate(self, input_ids, new_tokens, *, trusted_request_context,
                       forced_tokens=None, capture_logits=False, timeout_seconds=300):
        import grpc
        from ..remote_client import (MAX_GENERATE_BYTES, RemoteError, decode_json,
                                     encode_json, validate_generate)

        request = validate_generate({"input_ids": input_ids, "new_tokens": new_tokens,
            "forced_tokens": forced_tokens, "capture_logits": capture_logits,
            "timeout_seconds": timeout_seconds})
        if trusted_request_context is None:
            raise SecureTransportError("secure Generate requires explicit trusted request context")
        if self._closed or self._unavailable or self._runtime_owner.unavailable:
            raise RemoteError("EXECUTION_FAILED", "secure coordinator channel is closed")
        deadline = time.monotonic() + request["timeout_seconds"]
        auth = await _authorize_outbound(self.outbound_authorizer, COORDINATOR_SERVICE,
            "Generate", request, trusted_request_context, self.approved_server_leaf_pem)
        call = None
        authorization_transferred = False
        succeeded = False
        preserve_channel_for_capacity_rejection = False
        operation_task = asyncio.current_task()
        terminal = False
        session_id = None
        last_event = None
        binding_verified = False
        response_events_observed = False
        try:
            setup_deadline = await _preflight_deadline(auth, deadline)
            timeout = setup_deadline - time.monotonic()
            channel = await self._ensure_channel(timeout, setup_deadline)
            timeout = await _preflight_timeout(auth, deadline)
            request = dict(request)
            request["timeout_seconds"] = min(request["timeout_seconds"], timeout)
            body = encode_json(request, MAX_GENERATE_BYTES)
            final_timeout = await _preflight_timeout(auth, deadline)
            if final_timeout < request["timeout_seconds"]:
                request["timeout_seconds"] = final_timeout
                body = encode_json(request, MAX_GENERATE_BYTES)
            timeout = final_timeout
            metadata = outgoing_binding_metadata(auth.binding_bytes)
            timeout = await _preflight_timeout(auth, deadline)
            if timeout < request["timeout_seconds"]:
                request["timeout_seconds"] = timeout
                body = encode_json(request, MAX_GENERATE_BYTES)
            # This is the final preflight after any clipped-payload re-encode.
            # The gRPC deadline carries the latest remaining budget; the
            # coordinator server clips its payload deadline to that deadline.
            dispatch_timeout = await _preflight_timeout(auth, deadline)
            timeout = dispatch_timeout
            call = channel.unary_stream(f"/{COORDINATOR_SERVICE}/Generate")(
                body, timeout=timeout,
                wait_for_ready=False, metadata=metadata)
            self._active_calls.add((operation_task, call))
            initial = await _run_guarded(call.initial_metadata(), auth,
                self.authorization_watcher, timeout=timeout, cancel_callback=call.cancel,
                on_pending=self._runtime_owner.retain_pending,
                failure_cache_may_exist=True)
            _, binding, _ = validate_metadata(initial)
            if binding != auth.binding_bytes:
                raise RemoteError("EXECUTION_FAILED",
                    "Secure Generate binding mismatch; outcome may be unknown and will not be retried")
            binding_verified = True
            received = []

            async def consume():
                nonlocal terminal, session_id, last_event, response_events_observed
                async for payload in call:
                    response_events_observed = True
                    await _assert_live(auth)
                    event = decode_json(payload)
                    kind, sid = event.get("type"), event.get("session_id")
                    if (type(sid) is not str or TYPED_SESSION_ID_RE.fullmatch(sid) is None
                            or (session_id is not None and sid != session_id) or terminal):
                        raise RemoteError("EXECUTION_FAILED", "Invalid stream identity or ordering")
                    if kind == "token":
                        index = len(received)
                        if (type(event.get("index")) is not int or event["index"] != index
                                or event.get("sequence") != index or index >= new_tokens
                                or type(event.get("token_id")) is not int
                                or not 0 <= event["token_id"] < 32000
                                or event.get("position") != len(input_ids) + index):
                            raise RemoteError("EXECUTION_FAILED", "Invalid token order or value")
                        logits = event.get("logits")
                        if capture_logits:
                            if (not isinstance(logits, list) or len(logits) != 32000
                                    or any(isinstance(value, bool)
                                           or not isinstance(value, (int, float))
                                           or not math.isfinite(value) for value in logits)):
                                raise RemoteError("EXECUTION_FAILED", "Invalid logit vector")
                        elif "logits" in event:
                            raise RemoteError("EXECUTION_FAILED", "Unexpected logits")
                        received.append(event["token_id"])
                    elif kind == "result":
                        terminal = True
                        if (event.get("status") not in {"completed", "cancelled", "failed"}
                                or type(event.get("cleanup_complete")) is not bool
                                or not isinstance(event.get("token_ids"), list)
                                or any(type(token) is not int or not 0 <= token < 32000
                                       for token in event["token_ids"])
                                or not isinstance(event.get("metrics"), dict)):
                            raise RemoteError("EXECUTION_FAILED", "Invalid terminal result")
                        if event["status"] == "completed" and (
                                len(received) != new_tokens or event["token_ids"] != received):
                            raise RemoteError("EXECUTION_FAILED", "Incomplete successful stream")
                    else:
                        raise RemoteError("EXECUTION_FAILED", "Unknown stream event")
                    session_id = sid
                    last_event = event
                    await _assert_live(auth)
                    yield event
                    if terminal and event["status"] != "completed":
                        raise RemoteError(event.get("error_code") or "EXECUTION_FAILED",
                                          event.get("error") or "Generation failed")
                if not terminal:
                    raise RemoteError("EXECUTION_FAILED", "Stream ended without a terminal result")

            # A one-event pull keeps streaming and gRPC backpressure intact.
            async def watch_authorization():
                # Keep both revocation and the absolute monotonic authorization
                # deadline active across consumer backpressure. A paused caller
                # must not leave its gRPC stream alive after expiry.
                remaining = await _remaining_auth_seconds(auth)
                watcher = asyncio.create_task(
                    _maybe_await(self.authorization_watcher(auth)))
                expiry = asyncio.create_task(asyncio.sleep(remaining))
                try:
                    await asyncio.wait((watcher, expiry),
                                       return_when=asyncio.FIRST_COMPLETED)
                    if call is not None:
                        call.cancel()
                    raise AuthorizationRevoked("authorization is no longer live")
                finally:
                    await _cancel_tasks_bounded((watcher, expiry),
                        message="Generate authorization watcher did not stop")

            iterator = consume()
            next_event = asyncio.ensure_future(iterator.__anext__())
            watcher_task = asyncio.create_task(watch_authorization())
            try:
                while True:
                    done, _ = await asyncio.wait((next_event, watcher_task),
                        return_when=asyncio.FIRST_COMPLETED)
                    if watcher_task in done:
                        await _cancel_tasks_bounded((next_event,),
                            message="Generate receive task did not stop after revocation")
                        raise AuthorizationRevoked("authorization is no longer live")
                    try:
                        event = next_event.result()
                    except StopAsyncIteration:
                        break
                    await _assert_live(auth)
                    yield event
                    next_event = asyncio.ensure_future(iterator.__anext__())
            finally:
                try:
                    if not next_event.done():
                        _cancel_call(call)
                        await _cancel_tasks_bounded((next_event,),
                            message="Generate receive task did not stop")
                    if not watcher_task.done():
                        await _cancel_tasks_bounded((watcher_task,),
                            message="Generate authorization monitor did not stop")
                    else:
                        await asyncio.gather(watcher_task, return_exceptions=True)
                except SecureTaskPending as error:
                    authorization_transferred = True
                    self._runtime_owner.retain_pending(error.tasks)
                    self._unavailable = True
                    _cancel_call(call)
                    _retain_authorization_until_done(auth, error.tasks,
                                                     cache_may_exist=True)
                    raise
            await _assert_live(auth)
            await _maybe_await(auth.complete(last_event))
            await _assert_live(auth)
            succeeded = True
        except SecureTaskPending as error:
            authorization_transferred = authorization_transferred or error.authorization_transferred
            self._runtime_owner.retain_pending(error.tasks)
            self._unavailable = True
            raise
        except grpc.aio.AioRpcError as error:
            if (call is not None
                    and error.code() == grpc.StatusCode.RESOURCE_EXHAUSTED
                    and binding_verified and not response_events_observed):
                try:
                    trailer_timeout = min(await _preflight_timeout(auth, deadline),
                                          MAX_CANCELLATION_GRACE_SECONDS)
                    trailers = await _run_guarded(
                        call.trailing_metadata(), auth, self.authorization_watcher,
                        timeout=trailer_timeout, cancel_callback=call.cancel,
                        on_pending=self._runtime_owner.retain_pending,
                        failure_cache_may_exist=True, absolute_deadline=deadline)
                    await _preflight_timeout(auth, deadline)
                    marked_pre_admission = has_capacity_rejection_metadata(
                        trailers, auth.binding_bytes)
                    if marked_pre_admission:
                        await _preflight_timeout(auth, deadline)
                except SecureTaskPending as pending:
                    authorization_transferred = pending.authorization_transferred
                    self._runtime_owner.retain_pending(pending.tasks)
                    self._unavailable = True
                    _cancel_call(call)
                    raise
                except asyncio.CancelledError:
                    _cancel_call(call)
                    await _fail_authorization(auth, cache_may_exist=True)
                    raise
                except AuthorizationRevoked:
                    _cancel_call(call)
                    await _fail_authorization(auth, cache_may_exist=True)
                    raise
                except Exception:
                    _cancel_call(call)
                    await _fail_authorization(auth, cache_may_exist=True)
                    from ..remote_client import _rpc_error
                    mapped = _rpc_error(error)
                    raise RemoteError(mapped.code,
                        "Secure Generate reply may be lost; outcome is unknown and no retry was attempted") from None
                if marked_pre_admission:
                    _cancel_call(call)
                    await _fail_authorization(auth, cache_may_exist=False)
                    from ..remote_client import _rpc_error
                    mapped = _rpc_error(error)
                    preserve_channel_for_capacity_rejection = True
                    raise RemoteError(mapped.code,
                        "Secure Generate was rejected before admission; no work was accepted and no retry was attempted") from None
            _cancel_call(call)
            await _fail_authorization(auth, cache_may_exist=(call is not None))
            from ..remote_client import _rpc_error
            mapped = _rpc_error(error)
            raise RemoteError(mapped.code,
                "Secure Generate reply may be lost; outcome is unknown and no retry was attempted") from None
        except asyncio.CancelledError:
            _cancel_call(call)
            await _fail_authorization(auth, cache_may_exist=(call is not None))
            raise
        except GeneratorExit:
            _cancel_call(call)
            await _fail_authorization(auth, cache_may_exist=(call is not None))
            raise
        except Exception:
            _cancel_call(call)
            await _fail_authorization(auth, cache_may_exist=(call is not None))
            raise
        finally:
            if call is not None and not succeeded and not _call_done(call):
                _cancel_call(call)
            if call is not None:
                self._active_calls.discard((operation_task, call))
            try:
                if (call is not None and not succeeded
                        and not preserve_channel_for_capacity_rejection):
                    await self._subchannel.fence()
            finally:
                if not authorization_transferred:
                    await _maybe_await(auth.close())

    async def close(self):
        if self._closed:
            return
        self._unavailable = True
        calls = tuple(self._active_calls)
        for _task, call in calls:
            _cancel_call(call)
        pending_operations = tuple({task for task, _call in calls
                                    if task is not asyncio.current_task() and not task.done()})
        if pending_operations:
            done, pending = await asyncio.wait(pending_operations,
                timeout=MAX_CANCELLATION_GRACE_SECONDS)
            if pending:
                _retain_tasks(pending)
                raise SecureTaskPending(pending,
                    "secure coordinator RPCs still own the client reservation")
            await asyncio.gather(*done, return_exceptions=True)
        await self._subchannel.close()
        pending = tuple(task for task in self._runtime_owner.pending_tasks if not task.done())
        if pending:
            done, pending = await asyncio.wait(pending,
                timeout=MAX_CANCELLATION_GRACE_SECONDS)
            if pending:
                _retain_tasks(pending)
                raise SecureTaskPending(pending,
                    "secure coordinator calls still own the channel reservation")
            await asyncio.gather(*done, return_exceptions=True)
        await _maybe_await(self._reservation.release())
        self._closed = True

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_):
        await self.close()


async def create_secure_coordinator_client(peer, *, local_identity, outbound_authorizer,
                                           authorization_watcher,
                                           verify_expected_server_leaf,
                                           connection_controller, wall_clock=time.time):
    if not isinstance(peer, FixedPeer):
        raise ValueError("an owner-configured FixedPeer is required")
    _validate_tls_identity(local_identity)
    if not callable(getattr(outbound_authorizer, "authorize_outbound", None)):
        raise ValueError("secure coordinator client requires outbound authorization")
    if not callable(authorization_watcher):
        raise ValueError("secure coordinator client requires an expiry/revocation watcher")
    if not callable(verify_expected_server_leaf):
        raise ValueError("secure coordinator client requires the C0 expected-leaf verifier")
    if (connection_controller is None
            or not callable(getattr(connection_controller, "reserve_outbound", None))
            or not callable(getattr(connection_controller, "reserve_outbound_pending", None))):
        raise ValueError("secure coordinator client requires node connection accounting")
    approved_leaf = _verify_fixed_peer_leaf(peer, verify_expected_server_leaf, wall_clock,
                                            expected_role="personal_coordinator")
    reservation = await _maybe_await(connection_controller.reserve_outbound(peer.device_id))
    if reservation is None or not callable(getattr(reservation, "release", None)):
        raise SecureTransportError("connection controller did not reserve outbound capacity")
    try:
        return SecureCoordinatorClient(peer=peer, local_identity=local_identity,
            outbound_authorizer=outbound_authorizer,
            authorization_watcher=authorization_watcher,
            connection_reservation=reservation,
            approved_server_leaf_pem=approved_leaf,
            connection_controller=connection_controller)
    except BaseException:
        await _maybe_await(reservation.release())
        raise
