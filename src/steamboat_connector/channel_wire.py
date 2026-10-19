"""Bounded C2 channel framing and bundle codec (no transport or auth claims)."""

from collections import deque
from dataclasses import dataclass
import struct
from threading import Lock


FRAGMENT_FORMAT = "!4sBBH16sQ16sII"
FRAGMENT_HEADER_BYTES = struct.calcsize(FRAGMENT_FORMAT)
BUNDLE_FORMAT = "!4sBBHIII"
BUNDLE_HEADER_BYTES = struct.calcsize(BUNDLE_FORMAT)
FRAGMENT_MAGIC = b"C2F1"
BUNDLE_MAGIC = b"C2M1"
MAX_FRAGMENT_BYTES = 16_384
MAX_SEQUENCE = (1 << 63) - 1
MAX_ENVELOPE_BYTES = 32 * 1024
MAX_BINDING_BYTES = 8 * 1024
MAX_PROTOBUF_BYTES = 1024 * 1024
MAX_BUNDLE_BYTES = BUNDLE_HEADER_BYTES + MAX_ENVELOPE_BYTES + MAX_BINDING_BYTES + MAX_PROTOBUF_BYTES
MAX_CONTROL_PROTOBUF_BYTES = 8 * 1024
MAX_SMALL_CONTROL_BYTES = 4 * 1024
MAX_HEARTBEAT_BYTES = 64
MAX_CONTROL_BUNDLE_BYTES = (BUNDLE_HEADER_BYTES + MAX_ENVELOPE_BYTES
                            + MAX_BINDING_BYTES + MAX_CONTROL_PROTOBUF_BYTES)
MAX_WIRE_FRAME_BYTES = FRAGMENT_HEADER_BYTES + MAX_FRAGMENT_BYTES
MAX_FEED_BYTES = 64 * 1024
_METADATA_RESERVATION_BYTES = 4096
_ZERO_BLOCK = bytes(4096)

START = 1
END = 2
DATA = 1
CONTROL = 2
RESPONSE = 3
HELLO = 4
HEARTBEAT = 5
CLOSE = 6

REQUEST = 1
BUNDLE_RESPONSE = 2
METHODS = {1: "Describe", 2: "OpenSession", 3: "RenewSession", 4: "Step",
           5: "CloseSession", 6: "CancelSession", 7: "SessionStatus"}
METHOD_CODES = {name: code for code, name in METHODS.items()}
CONTROL_METHODS = {5, 6, 7}
DATA_KINDS = {DATA, RESPONSE}
CONTROL_KINDS = {CONTROL, HELLO, HEARTBEAT, CLOSE}
_MAX_LOGICAL = {DATA: MAX_BUNDLE_BYTES, RESPONSE: MAX_BUNDLE_BYTES,
                CONTROL: MAX_CONTROL_BUNDLE_BYTES,
                HELLO: MAX_SMALL_CONTROL_BYTES, CLOSE: MAX_SMALL_CONTROL_BYTES,
                HEARTBEAT: MAX_HEARTBEAT_BYTES}


class ChannelWireError(ValueError):
    """Malformed or over-budget channel wire data."""


@dataclass(frozen=True)
class DecodedMessage:
    kind: int
    generation: bytes
    message_id: bytes
    first_sequence: int
    last_sequence: int
    payload: bytes


@dataclass(slots=True)
class _PartialMessage:
    kind: int
    message_id: bytes
    first_sequence: int
    next_index: int
    size: int


@dataclass(frozen=True)
class Bundle:
    method_code: int
    method: str
    classification: int
    envelope: bytes
    binding: bytes
    protobuf: bytes


def _id16(value, field):
    if type(value) is not bytes or len(value) != 16 or value == bytes(16):
        raise ChannelWireError(f"{field} must be a nonzero 16-byte value")
    return value


def _kind_limit(kind):
    try:
        return _MAX_LOGICAL[kind]
    except (KeyError, TypeError):
        raise ChannelWireError("unknown fragment kind") from None


def iter_fragments(payload, *, kind, generation, message_id, first_sequence=1,
                   fragment_payload_bytes=MAX_FRAGMENT_BYTES):
    """Yield one bounded wire frame at a time without copying the whole payload."""
    if type(payload) is not bytes:
        raise ChannelWireError("payload must be immutable bytes")
    if type(kind) is not int or kind not in _MAX_LOGICAL:
        raise ChannelWireError("unknown fragment kind")
    generation = _id16(generation, "generation")
    message_id = _id16(message_id, "message_id")
    if (type(first_sequence) is not int or not 1 <= first_sequence <= MAX_SEQUENCE
            or type(fragment_payload_bytes) is not int
            or not 1 <= fragment_payload_bytes <= MAX_FRAGMENT_BYTES):
        raise ChannelWireError("invalid fragment sequence or size")
    view = memoryview(payload)
    if not 1 <= len(view) <= _kind_limit(kind):
        raise ChannelWireError("logical message is empty or exceeds its kind limit")
    count = (len(view) + fragment_payload_bytes - 1) // fragment_payload_bytes
    if first_sequence + count - 1 > MAX_SEQUENCE:
        raise ChannelWireError("transport sequence exhausted")
    for index, offset in enumerate(range(0, len(view), fragment_payload_bytes)):
        chunk = bytes(view[offset:offset + fragment_payload_bytes])
        flags = (START if index == 0 else 0) | (END if index == count - 1 else 0)
        header = struct.pack(FRAGMENT_FORMAT, FRAGMENT_MAGIC, kind, flags, 0,
                             generation, first_sequence + index, message_id,
                             index, len(chunk))
        yield header + chunk


def encode_bundle(method, classification, *, envelope=b"", binding=b"", protobuf=b""):
    """Encode a closed C2M1 bundle after enforcing all length/class rules."""
    method_code = METHOD_CODES.get(method) if type(method) is str else method
    if type(method_code) is not int or method_code not in METHODS:
        raise ChannelWireError("unknown bundle method")
    if type(classification) is not int or classification not in (REQUEST, BUNDLE_RESPONSE):
        raise ChannelWireError("unknown bundle classification")
    if any(type(part) is not bytes for part in (envelope, binding, protobuf)):
        raise ChannelWireError("bundle fields must be immutable bytes")
    if len(envelope) > MAX_ENVELOPE_BYTES or len(binding) > MAX_BINDING_BYTES or len(protobuf) > MAX_PROTOBUF_BYTES:
        raise ChannelWireError("bundle field exceeds its limit")
    if not protobuf:
        raise ChannelWireError("protobuf body is required")
    if classification == BUNDLE_RESPONSE and (envelope or binding):
        raise ChannelWireError("responses cannot carry a delegation or request binding")
    if classification == REQUEST and not binding:
        raise ChannelWireError("requests require a canonical binding")
    if classification == REQUEST and method_code in CONTROL_METHODS and len(protobuf) > MAX_CONTROL_PROTOBUF_BYTES:
        raise ChannelWireError("control protobuf exceeds its limit")
    total = BUNDLE_HEADER_BYTES + len(envelope) + len(binding) + len(protobuf)
    if total > MAX_BUNDLE_BYTES:
        raise ChannelWireError("bundle exceeds its total limit")
    return (struct.pack(BUNDLE_FORMAT, BUNDLE_MAGIC, method_code, classification, 0,
                        len(envelope), len(binding), len(protobuf))
            + envelope + binding + protobuf)


def decode_bundle(payload, *, fragment_kind):
    if type(payload) is not bytes or len(payload) < BUNDLE_HEADER_BYTES or len(payload) > MAX_BUNDLE_BYTES:
        raise ChannelWireError("bundle size is invalid")
    magic, method_code, classification, reserved, envelope_len, binding_len, protobuf_len = struct.unpack_from(
        BUNDLE_FORMAT, payload)
    if magic != BUNDLE_MAGIC or reserved != 0 or method_code not in METHODS:
        raise ChannelWireError("bundle header is invalid")
    if classification not in (REQUEST, BUNDLE_RESPONSE):
        raise ChannelWireError("bundle classification is invalid")
    if ((classification == BUNDLE_RESPONSE) != (fragment_kind == RESPONSE)
            or fragment_kind not in (DATA, CONTROL, RESPONSE)):
        raise ChannelWireError("bundle classification disagrees with fragment kind")
    if (envelope_len > MAX_ENVELOPE_BYTES or binding_len > MAX_BINDING_BYTES
            or protobuf_len > MAX_PROTOBUF_BYTES
            or BUNDLE_HEADER_BYTES + envelope_len + binding_len + protobuf_len != len(payload)
            or protobuf_len == 0):
        raise ChannelWireError("bundle lengths are invalid")
    if classification == BUNDLE_RESPONSE and (envelope_len or binding_len):
        raise ChannelWireError("response bundle has request-only fields")
    if classification == REQUEST and binding_len == 0:
        raise ChannelWireError("request bundle lacks a binding")
    if fragment_kind == CONTROL and (method_code not in CONTROL_METHODS
                                     or protobuf_len > MAX_CONTROL_PROTOBUF_BYTES):
        raise ChannelWireError("control lane only accepts bounded cleanup methods")
    offset = BUNDLE_HEADER_BYTES
    envelope = payload[offset:offset + envelope_len]
    offset += envelope_len
    binding = payload[offset:offset + binding_len]
    offset += binding_len
    return Bundle(method_code, METHODS[method_code], classification,
                  envelope, binding, payload[offset:])


class FragmentDecoder:
    """Incremental decoder with an explicit total reassembly reservation.

    Each lane owns one preallocated ``reassembly_capacity`` bytearray, so
    fragment count cannot create per-fragment objects or geometric-growth
    headroom. ``reservation_bound_bytes`` includes both buffers, the maximum
    frame buffer, at most 64 KiB of input pinned while the feed iterator is
    active, one yielded payload copy, and a fixed 4 KiB metadata allowance.
    Split larger socket reads into <=64 KiB feed calls. Caller-retained
    messages and pending queues need separate reservations.
    """

    def __init__(self, expected_generation, *, reassembly_capacity):
        self.expected_generation = _id16(expected_generation, "expected_generation")
        if type(reassembly_capacity) is not int or reassembly_capacity < 1:
            raise ChannelWireError("explicit positive reassembly capacity is required")
        self._next_sequence = 1
        self.reassembly_capacity = reassembly_capacity
        self._buffers = {"data": bytearray(reassembly_capacity),
                         "control": bytearray(reassembly_capacity)}
        self._frame = bytearray(MAX_WIRE_FRAME_BYTES)
        self._frame_used = 0
        self._frame_size = FRAGMENT_HEADER_BYTES
        self._header = None
        self._lanes = {"data": None, "control": None}
        self._fault = False
        self._feed_active = False

    @property
    def reservation_bound_bytes(self):
        """Decoder backing buffers, one output message, and fixed metadata."""
        return (2 * self.reassembly_capacity + MAX_WIRE_FRAME_BYTES
                + MAX_FEED_BYTES
                + min(self.reassembly_capacity, MAX_BUNDLE_BYTES)
                + _METADATA_RESERVATION_BYTES)

    @staticmethod
    def _lane(kind):
        if kind in DATA_KINDS:
            return "data"
        if kind in CONTROL_KINDS:
            return "control"
        raise ChannelWireError("unknown fragment kind")

    @staticmethod
    def _wipe(buffer, length):
        offset = 0
        while offset < length:
            take = min(len(_ZERO_BLOCK), length - offset)
            buffer[offset:offset + take] = _ZERO_BLOCK[:take]
            offset += take

    def _clear_state(self):
        for lane, partial in self._lanes.items():
            if partial is not None:
                self._wipe(self._buffers[lane], partial.size)
        self._lanes = {"data": None, "control": None}
        self._wipe(self._frame, self._frame_used)
        self._frame_used = 0
        self._frame_size = FRAGMENT_HEADER_BYTES
        self._header = None

    def _poison(self):
        self._fault = True
        self._clear_state()

    def _fail(self, message):
        self._poison()
        raise ChannelWireError(message)

    def feed(self, data):
        """Yield complete messages as they become available.

        Callers should exhaust the iterator before supplying the next socket
        read. Yielding avoids accumulating many decoded messages from one read.
        """
        if self._fault:
            raise ChannelWireError("decoder is permanently faulted")
        if self._feed_active:
            self._fail("the prior feed iterator was not exhausted")
        if type(data) is not bytes:
            self._fail("input must be immutable bytes")
        if len(data) > MAX_FEED_BYTES:
            self._fail("input read exceeds the bounded feed size")
        self._feed_active = True
        return self._feed(data)

    def _feed(self, data):
        complete = False
        try:
            if self._fault:
                raise ChannelWireError("decoder is permanently faulted")
            incoming = memoryview(data)
            offset = 0
            while offset < len(incoming):
                if self._header is None:
                    wanted = FRAGMENT_HEADER_BYTES - self._frame_used
                    take = min(wanted, len(incoming) - offset)
                    self._frame[self._frame_used:self._frame_used + take] = incoming[offset:offset + take]
                    self._frame_used += take
                    offset += take
                    if self._frame_used < FRAGMENT_HEADER_BYTES:
                        continue
                    try:
                        header = struct.unpack_from(FRAGMENT_FORMAT, self._frame)
                        self._validate_header(header)
                    except ChannelWireError as error:
                        self._fail(str(error))
                    self._header = header
                    self._frame_size = FRAGMENT_HEADER_BYTES + header[-1]
                else:
                    wanted = self._frame_size - self._frame_used
                    take = min(wanted, len(incoming) - offset)
                    self._frame[self._frame_used:self._frame_used + take] = incoming[offset:offset + take]
                    self._frame_used += take
                    offset += take
                    if self._frame_used < self._frame_size:
                        continue
                    try:
                        item = self._accept_fragment(
                            self._header,
                            memoryview(self._frame)[FRAGMENT_HEADER_BYTES:self._frame_size])
                    except ChannelWireError as error:
                        self._fail(str(error))
                    self._wipe(self._frame, self._frame_used)
                    self._frame_used = 0
                    self._header = None
                    self._frame_size = FRAGMENT_HEADER_BYTES
                    if item is not None:
                        yield item
                        del item
                        if self._fault:
                            raise ChannelWireError("decoder is permanently faulted")
            complete = True
        finally:
            if not complete and not self._fault:
                self._poison()
            self._feed_active = False

    def _validate_header(self, header):
        magic, kind, flags, reserved, generation, sequence, message_id, index, length = header
        lane = self._lane(kind)
        if (magic != FRAGMENT_MAGIC or reserved != 0 or flags & ~(START | END)
                or generation != self.expected_generation or message_id == bytes(16)
                or sequence != self._next_sequence or sequence > MAX_SEQUENCE
                or not 1 <= length <= MAX_FRAGMENT_BYTES):
            raise ChannelWireError("fragment header or transport sequence is invalid")
        if sequence == MAX_SEQUENCE and not flags & END:
            raise ChannelWireError("transport sequence exhausted before message end")
        partial = self._lanes[lane]
        if partial is None:
            if flags & START != START or index != 0:
                raise ChannelWireError("first fragment must start at index zero")
        else:
            if (flags & START or partial.kind != kind
                    or partial.message_id != message_id
                    or index != partial.next_index):
                raise ChannelWireError("fragment does not continue its lane message")
        total = length if partial is None else partial.size + length
        if total > _kind_limit(kind):
            raise ChannelWireError("logical message exceeds its kind limit")
        other_lane_bytes = sum(item.size for name, item in self._lanes.items()
                               if name != lane and item is not None)
        if total + other_lane_bytes > self.reassembly_capacity:
            raise ChannelWireError("reassembly byte capacity is exhausted")
        if kind in (HELLO, CLOSE) and total > MAX_SMALL_CONTROL_BYTES:
            raise ChannelWireError("small control message exceeds its limit")
        if kind == HEARTBEAT and total > MAX_HEARTBEAT_BYTES:
            raise ChannelWireError("heartbeat exceeds its limit")

    def _accept_fragment(self, header, payload):
        _, kind, flags, _, generation, sequence, message_id, index, _ = header
        lane = self._lane(kind)
        partial = self._lanes[lane]
        if partial is None:
            partial = _PartialMessage(kind, message_id, sequence, 0, 0)
        start = partial.size
        end = start + len(payload)
        self._buffers[lane][start:end] = payload
        partial.size = end
        partial.next_index = index + 1
        self._next_sequence += 1
        if flags & END:
            message = DecodedMessage(kind, generation, message_id,
                                     partial.first_sequence, sequence,
                                     bytes(memoryview(self._buffers[lane])[:partial.size]))
            self._wipe(self._buffers[lane], partial.size)
            self._lanes[lane] = None
            return message
        self._lanes[lane] = partial
        return None

    def finish(self):
        """Signal EOF; any partial header or logical message permanently faults."""
        if self._fault:
            raise ChannelWireError("decoder is permanently faulted")
        if self._feed_active:
            self._fail("cannot finish while a feed iterator is suspended")
        if self._frame_used or self._header is not None or any(self._lanes.values()):
            self._fail("truncated channel stream")


class PendingMessageLanes:
    """Bounded data/control admission with immediate rejection and control priority."""

    def __init__(self, *, byte_capacity, data_capacity=8, control_capacity=8):
        if (type(byte_capacity) is not int or byte_capacity < 1
                or type(data_capacity) is not int or not 1 <= data_capacity <= 8
                or type(control_capacity) is not int or not 1 <= control_capacity <= 8):
            raise ValueError("explicit positive byte and bounded queue capacities are required")
        self.byte_capacity = byte_capacity
        self.data_capacity = data_capacity
        self.control_capacity = control_capacity
        self._data = deque()
        self._control = deque()
        self._bytes = 0
        self._lock = Lock()

    @property
    def pending_bytes(self):
        with self._lock:
            return self._bytes

    def enqueue(self, message):
        if type(message) is not DecodedMessage:
            return False
        if type(message.kind) is not int:
            return False
        lane = "control" if message.kind in CONTROL_KINDS else "data" if message.kind in DATA_KINDS else None
        if (lane is None or type(message.generation) is not bytes
                or len(message.generation) != 16 or message.generation == bytes(16)
                or type(message.message_id) is not bytes or len(message.message_id) != 16
                or message.message_id == bytes(16) or type(message.payload) is not bytes
                or not 1 <= len(message.payload) <= _kind_limit(message.kind)
                or type(message.first_sequence) is not int
                or type(message.last_sequence) is not int
                or not 1 <= message.first_sequence <= message.last_sequence <= MAX_SEQUENCE):
            return False
        with self._lock:
            queue = self._control if lane == "control" else self._data
            limit = self.control_capacity if lane == "control" else self.data_capacity
            if len(queue) >= limit or len(message.payload) > self.byte_capacity - self._bytes:
                return False
            queue.append(message)
            self._bytes += len(message.payload)
            return True

    def pop_next(self):
        with self._lock:
            if self._control:
                message = self._control.popleft()
            elif self._data:
                message = self._data.popleft()
            else:
                return None
            self._bytes -= len(message.payload)
            return message

    def __len__(self):
        with self._lock:
            return len(self._data) + len(self._control)
