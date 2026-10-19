"""Bounded first-message bootstrap for an authenticated worker TLS channel."""

from __future__ import annotations

import hashlib
import json
import secrets
import struct
import threading
import weakref

from steamboat_connector.channel_wire import (
    DATA, END, FRAGMENT_FORMAT, FRAGMENT_HEADER_BYTES, FRAGMENT_MAGIC, HELLO,
    MAX_BUNDLE_BYTES, MAX_FRAGMENT_BYTES, MAX_SMALL_CONTROL_BYTES, START,
    FragmentDecoder, iter_fragments,
)
from steamboat_security.channel_tls import is_owned_worker_tls
from steamboat_security.gateway_ingress import GatewayWorkerIngress
from steamboat_security.gateway_tls import (
    is_authenticated_worker_channel, is_owned_gateway_worker_tls,
)

MAX_HELLO_BYTES = 4096
MAX_BOOTSTRAP_FRAME_BYTES = FRAGMENT_HEADER_BYTES + MAX_HELLO_BYTES
_OWNER_LOCK = threading.RLock()
_CLIENT_OWNERS = weakref.WeakKeyDictionary()
_SERVER_OWNERS = weakref.WeakKeyDictionary()
_CAPABILITIES = weakref.WeakSet()
_CAPABILITY_TOKEN = object()
_ZERO_FRAME = bytes(MAX_BOOTSTRAP_FRAME_BYTES)
_SEEN_LOCK = threading.Lock()
_SEEN_WORKER_GENERATIONS = set()
_MAX_SEEN_WORKER_GENERATIONS = 4096


class ChannelHelloError(ValueError):
    """A bootstrap is malformed, unowned, stale, or out of order."""


def _generation_bytes(value):
    if type(value) is not str or len(value) != 32:
        raise ChannelHelloError("worker ingress generation is invalid")
    try:
        result = bytes.fromhex(value)
    except ValueError as error:
        raise ChannelHelloError("worker ingress generation is invalid") from error
    if result == bytes(16):
        raise ChannelHelloError("worker ingress generation is invalid")
    return result


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


def _unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _reject_constant(_value):
    raise ValueError("non-finite JSON number")


def _parse_json(payload, required, label):
    if type(payload) is not bytes or not 1 <= len(payload) <= MAX_HELLO_BYTES:
        raise ChannelHelloError(f"{label} payload exceeds its bound")
    try:
        value = json.loads(payload.decode("ascii"), object_pairs_hook=_unique_pairs,
                           parse_constant=_reject_constant)
    except Exception as error:
        raise ChannelHelloError(f"{label} JSON is invalid") from error
    if type(value) is not dict or set(value) != required:
        raise ChannelHelloError(f"{label} fields are not the closed schema")
    if _canonical(value) != payload:
        raise ChannelHelloError(f"{label} JSON is not canonical")
    return value


_HELLO_FIELDS = {"version", "role", "boot_id", "generation", "policy_revision",
                 "policy_digest", "account_id", "device_id", "assignment_id", "model_id"}
_ACK_FIELDS = {"version", "role", "generation", "hello_sha256", "server_nonce"}


def _parse_hello(payload):
    value = _parse_json(payload, _HELLO_FIELDS, "HELLO")
    if (type(value["version"]) is not int or value["version"] != 1
            or value["role"] != "worker"
            or any(type(value[key]) is not str or not value[key]
                   for key in ("boot_id", "generation", "policy_digest", "account_id",
                               "device_id", "assignment_id", "model_id"))
            or type(value["policy_revision"]) is not int or value["policy_revision"] < 1):
        raise ChannelHelloError("HELLO identity values are invalid")
    _generation_bytes(value["generation"])
    return value


def _parse_ack(payload):
    value = _parse_json(payload, _ACK_FIELDS, "HELLO ACK")
    if (type(value["version"]) is not int or value["version"] != 1
            or value["role"] != "gateway"
            or any(type(value[key]) is not str or not value[key]
                   for key in ("generation", "hello_sha256", "server_nonce"))
            or len(value["server_nonce"]) != 32):
        raise ChannelHelloError("HELLO ACK values are invalid")
    _generation_bytes(value["generation"])
    try:
        if len(bytes.fromhex(value["server_nonce"])) != 16:
            raise ValueError()
        if len(bytes.fromhex(value["hello_sha256"])) != 32:
            raise ValueError()
    except ValueError as error:
        raise ChannelHelloError("HELLO ACK digest or nonce is invalid") from error
    return value


def _identity(ingress):
    view, worker, _gateway, _sample = ingress._policy_and_worker()
    return {
        "version": 1, "role": "worker", "boot_id": ingress._local_identity.boot_id,
        "generation": ingress.stream_generation,
        "policy_revision": view.revision, "policy_digest": view.policy_digest,
        "account_id": worker["account_id"], "device_id": ingress.worker_identity[0],
        "assignment_id": worker["assignment_id"], "model_id": worker["model_id"],
    }


def _frame(payload, generation):
    return next(iter_fragments(payload, kind=HELLO, generation=generation,
                               message_id=secrets.token_bytes(16), first_sequence=1))


class _BoundedHelloReader:
    """Preallocated one-frame scratch; validates declared length at byte 56."""

    __slots__ = ("buffer", "used", "expected_generation", "_expected_size",
                 "complete", "faulted")

    def __init__(self, expected_generation=None):
        self.buffer = bytearray(MAX_BOOTSTRAP_FRAME_BYTES)
        self.used = 0
        self.expected_generation = expected_generation
        self._expected_size = FRAGMENT_HEADER_BYTES
        self.complete = False
        self.faulted = False

    def feed(self, chunk):
        if self.faulted or self.complete:
            self.faulted = True
            raise ChannelHelloError("bootstrap reader is already complete or faulted")
        if type(chunk) is not bytes or not chunk or len(chunk) > MAX_FRAGMENT_BYTES:
            return self._fail("bootstrap read chunk is empty or exceeds transport bound")
        offset = 0
        try:
            while offset < len(chunk):
                if self.used < FRAGMENT_HEADER_BYTES:
                    take = min(FRAGMENT_HEADER_BYTES - self.used, len(chunk) - offset)
                else:
                    take = min(self._expected_size - self.used, len(chunk) - offset)
                if take <= 0:
                    return self._fail("trailing pre-commit bytes follow bootstrap frame")
                self.buffer[self.used:self.used + take] = chunk[offset:offset + take]
                self.used += take
                offset += take
                if self.used == FRAGMENT_HEADER_BYTES:
                    self._validate_header()
                if self.used == self._expected_size:
                    if offset != len(chunk):
                        return self._fail("trailing pre-commit bytes follow bootstrap frame")
                    self.complete = True
                    return bytes(memoryview(self.buffer)[:self.used])
            return None
        except ChannelHelloError:
            self.faulted = True
            self._wipe()
            raise

    def _validate_header(self):
        (magic, kind, flags, reserved, generation, sequence, message_id,
         index, length) = struct.unpack_from(FRAGMENT_FORMAT, self.buffer)
        if (magic != FRAGMENT_MAGIC or kind != HELLO or flags != (START | END)
                or reserved != 0 or generation == bytes(16)
                or (self.expected_generation is not None
                    and generation != self.expected_generation)
                or sequence != 1 or message_id == bytes(16) or index != 0
                or not 1 <= length <= MAX_HELLO_BYTES):
            self._fail("bootstrap fragment header is invalid")
        self.expected_generation = generation
        self._expected_size = FRAGMENT_HEADER_BYTES + length

    def _wipe(self):
        self.buffer[:] = _ZERO_FRAME
        self.used = 0

    def _fail(self, message):
        self.faulted = True
        self._wipe()
        raise ChannelHelloError(message)

    def finish(self):
        if not self.complete:
            self._fail("EOF before complete bootstrap frame")


def _normal_capacity(value):
    if type(value) is not int or value < MAX_BUNDLE_BYTES:
        raise ValueError("normal channel reassembly capacity must fit one maximum bundle")
    return value


class WorkerHelloClient:
    """Client bootstrap bound to ingress and its exact TLS owner."""

    __slots__ = ("ingress", "tls_owner", "generation", "_expected", "_state",
                 "hello_frame", "_reader", "decoder", "reassembly_capacity",
                 "decoder_reservation_bytes", "_lock")

    def __init__(self, ingress, tls_owner, *, reassembly_capacity):
        capacity = _normal_capacity(reassembly_capacity)
        if type(ingress) is not GatewayWorkerIngress or not is_owned_worker_tls(tls_owner):
            raise TypeError("HELLO requires genuine worker ingress and TLS owners")
        if ingress._tls_owner is not tls_owner or not tls_owner.handshake_complete:
            raise ChannelHelloError("ingress is not bound to this completed TLS owner")
        with _OWNER_LOCK:
            if tls_owner in _CLIENT_OWNERS:
                ingress.close("gateway-invalid-frame")
                raise ChannelHelloError("worker TLS owner already claimed for HELLO")
            _CLIENT_OWNERS[tls_owner] = "claimed"
        self.ingress, self.tls_owner = ingress, tls_owner
        self.generation = _generation_bytes(ingress.stream_generation)
        self._expected = _identity(ingress)
        self._state = "hello"
        self.hello_frame = _frame(_canonical(self._expected), self.generation)
        self._reader = _BoundedHelloReader(self.generation)
        self.decoder = None
        self.reassembly_capacity = capacity
        self.decoder_reservation_bytes = None
        self._lock = threading.RLock()

    def _fault(self):
        self._state = "faulted"
        self.ingress.close("gateway-invalid-frame")

    def feed_ack(self, chunk):
        with self._lock:
            if self._state != "hello":
                self._fault()
                raise ChannelHelloError("ACK is out of order")
            try:
                frame = self._reader.feed(chunk)
                if frame is None:
                    return None
                with self.ingress._state.lock:
                    if self.ingress._tls_owner is not self.tls_owner or _identity(self.ingress) != self._expected:
                        raise ChannelHelloError("worker ingress identity or TLS owner changed")
                    self.ingress._policy_and_worker()
                    if not self.tls_owner.is_live:
                        raise ChannelHelloError("worker TLS owner is no longer live")
                    generation, payload = self._reader.expected_generation, frame[FRAGMENT_HEADER_BYTES:]
                    ack = _parse_ack(payload)
                    if (ack["generation"] != self.generation.hex()
                            or ack["hello_sha256"] != hashlib.sha256(self.hello_frame).hexdigest()):
                        raise ChannelHelloError("gateway ACK does not match this fresh HELLO")
                    decoder = FragmentDecoder(generation, reassembly_capacity=self.reassembly_capacity)
                    tuple(decoder.feed(frame))
                    self.decoder = decoder
                    self.decoder_reservation_bytes = decoder.reservation_bound_bytes
                    self._state = "committed"
                    return decoder
            except Exception:
                self._fault()
                raise

    def accept_ack(self, frame):
        """Convenience for a caller that already has one bounded plaintext read."""
        return self.feed_ack(frame)

    def finish(self):
        with self._lock:
            try:
                self._reader.finish()
                if self._state != "committed":
                    raise ChannelHelloError("EOF before ACK commit")
            except Exception:
                self._fault()
                raise


class RegisteredWorker:
    """Immutable identity capability tied to one live server TLS owner."""

    __slots__ = ("__owner", "__channel", "__generation", "__nonce", "__token",
                 "__sealed", "__weakref__")

    def __init__(self, token, owner, channel, generation, nonce):
        if token is not _CAPABILITY_TOKEN:
            raise TypeError("registered worker capabilities are owner minted")
        object.__setattr__(self, "_RegisteredWorker__owner", owner)
        object.__setattr__(self, "_RegisteredWorker__channel", channel)
        object.__setattr__(self, "_RegisteredWorker__generation", generation)
        object.__setattr__(self, "_RegisteredWorker__nonce", nonce)
        object.__setattr__(self, "_RegisteredWorker__token", token)
        object.__setattr__(self, "_RegisteredWorker__sealed", True)

    def __setattr__(self, _name, _value):
        raise AttributeError("worker registration capability is immutable")

    @property
    def identity(self):
        self.assert_live()
        channel = self.__channel
        return (channel.account_id, channel.device_id, channel.worker_boot_id,
                self.__generation.hex())

    @property
    def server_connection_nonce(self):
        return self.__nonce.hex()

    def assert_live(self):
        with _OWNER_LOCK:
            if self not in _CAPABILITIES or self.__token is not _CAPABILITY_TOKEN:
                raise ChannelHelloError("worker registration capability is unowned")
        if (not is_owned_gateway_worker_tls(self.__owner)
                or not is_authenticated_worker_channel(self.__channel)):
            raise ChannelHelloError("worker registration owner is unavailable")
        if self.__owner.authenticated_channel is not self.__channel:
            raise ChannelHelloError("worker registration belongs to a replaced TLS channel")
        self.__channel.assert_live()
        return self


class WorkerHelloServer:
    """Server bootstrap requiring one genuine completed gateway TLS owner."""

    __slots__ = ("owner", "channel", "_state", "_reader", "decoder",
                 "registration", "server_nonce", "reassembly_capacity",
                 "decoder_reservation_bytes", "_lock")

    @classmethod
    def from_tls(cls, owner, authenticated_channel=None, *, reassembly_capacity):
        capacity = _normal_capacity(reassembly_capacity)
        if not is_owned_gateway_worker_tls(owner) or not owner.handshake_complete:
            raise TypeError("HELLO server requires a genuine completed gateway TLS owner")
        channel = owner.authenticated_channel
        if not is_authenticated_worker_channel(channel) or (
                authenticated_channel is not None and authenticated_channel is not channel):
            raise ChannelHelloError("channel record is not owned by this TLS connection")
        with _OWNER_LOCK:
            if owner in _SERVER_OWNERS:
                owner.close()
                raise ChannelHelloError("gateway TLS owner already claimed for HELLO")
            _SERVER_OWNERS[owner] = "claimed"
        server = cls.__new__(cls)
        server.owner, server.channel = owner, channel
        server._state = "hello"
        server._reader = _BoundedHelloReader()
        server.decoder = None
        server.registration = None
        server.server_nonce = bytes.fromhex(channel.stream_generation)
        server.reassembly_capacity = capacity
        server.decoder_reservation_bytes = None
        server._lock = threading.RLock()
        return server

    def _fault(self):
        self._state = "faulted"
        self.owner.close()

    def feed_hello(self, chunk):
        """Consume one bounded plaintext read; return ACK only when complete."""
        with self._lock:
            if self._state != "hello":
                self._fault()
                raise ChannelHelloError("HELLO is out of order")
            try:
                frame = self._reader.feed(chunk)
                if frame is None:
                    return None
                with self.owner._lock:
                    if (not is_owned_gateway_worker_tls(self.owner)
                            or self.owner.authenticated_channel is not self.channel):
                        raise ChannelHelloError("authenticated worker channel owner was replaced")
                    actual = self.channel
                    actual.assert_live()
                    generation = self._reader.expected_generation
                    hello = _parse_hello(frame[FRAGMENT_HEADER_BYTES:])
                    comparisons = {
                        "boot_id": actual.worker_boot_id,
                        "generation": generation.hex(),
                        "policy_revision": actual.policy_revision,
                        "policy_digest": actual.policy_digest,
                        "account_id": actual.account_id,
                        "device_id": actual.device_id,
                        "assignment_id": actual.assignment_id,
                        "model_id": actual.model_id,
                    }
                    if any(hello[key] != value for key, value in comparisons.items()):
                        raise ChannelHelloError("HELLO identity differs from actual TLS peer or policy")
                    replay_key = (actual.account_id, actual.device_id,
                                  actual.worker_boot_id, generation)
                    with _SEEN_LOCK:
                        if replay_key in _SEEN_WORKER_GENERATIONS:
                            raise ChannelHelloError("worker ingress generation was already consumed")
                        if len(_SEEN_WORKER_GENERATIONS) >= _MAX_SEEN_WORKER_GENERATIONS:
                            raise ChannelHelloError("worker generation replay table is full")
                        _SEEN_WORKER_GENERATIONS.add(replay_key)
                    ack_payload = _canonical({
                        "version": 1, "role": "gateway", "generation": generation.hex(),
                        "hello_sha256": hashlib.sha256(frame).hexdigest(),
                        "server_nonce": self.server_nonce.hex(),
                    })
                    decoder = FragmentDecoder(generation, reassembly_capacity=self.reassembly_capacity)
                    tuple(decoder.feed(frame))
                    self.decoder = decoder
                    self.decoder_reservation_bytes = decoder.reservation_bound_bytes
                    cap = RegisteredWorker(_CAPABILITY_TOKEN, self.owner, actual, generation,
                                           self.server_nonce)
                    with _OWNER_LOCK:
                        _CAPABILITIES.add(cap)
                    self.registration = cap
                    self._state = "committed"
                    return _frame(ack_payload, generation)
            except Exception:
                self._fault()
                raise

    def accept_hello(self, frame):
        return self.feed_hello(frame)

    def finish(self):
        with self._lock:
            try:
                self._reader.finish()
                if self._state != "committed":
                    raise ChannelHelloError("EOF before HELLO commit")
            except Exception:
                self._fault()
                raise
