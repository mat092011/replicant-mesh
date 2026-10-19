"""Bounded, control-priority fragment writer for one C2 stream generation.

The writer owns logical-message references and allocates global fragment
sequences only when ``next_frame`` commits a frame to the caller. The caller
must send that frame exactly once and call ``frame_sent`` before requesting
another; on any uncertain/failed send, retire the whole stream. This primitive
does not provide TLS, socket I/O, or accounting-meter integration.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass
import struct
from threading import Lock

from . import channel_wire as wire


DEFAULT_FRAGMENT_PAYLOAD_BYTES = 16_328
MAX_CONTROL_MESSAGES = 8
MAX_PENDING_DATA_MESSAGES = 8
MESSAGE_ID_HISTORY_CAPACITY = 1_024
_MESSAGE_ID_RESERVATION_BYTES = 512
_METADATA_RESERVATION_BYTES = 64 * 1024
_MAX_CONTROL_KIND_BYTES = wire.MAX_CONTROL_BUNDLE_BYTES
_KIND_LIMITS = {
    wire.DATA: wire.MAX_BUNDLE_BYTES,
    wire.RESPONSE: wire.MAX_BUNDLE_BYTES,
    wire.CONTROL: wire.MAX_CONTROL_BUNDLE_BYTES,
    wire.CONTROL_RESPONSE: wire.MAX_CONTROL_RESPONSE_BUNDLE_BYTES,
    wire.HELLO: wire.MAX_SMALL_CONTROL_BYTES,
    wire.CLOSE: wire.MAX_SMALL_CONTROL_BYTES,
    wire.HEARTBEAT: wire.MAX_HEARTBEAT_BYTES,
}
_FIXED_RESERVATION_BYTES = (
    wire.MAX_BUNDLE_BYTES
    + 2 * wire.MAX_WIRE_FRAME_BYTES
    + MESSAGE_ID_HISTORY_CAPACITY * _MESSAGE_ID_RESERVATION_BYTES
    + _METADATA_RESERVATION_BYTES
)


class ChannelWriterError(ValueError):
    """The writer is retired, exhausted, or has an unacknowledged frame."""


@dataclass(frozen=True, slots=True)
class WriterAccounting:
    queued_and_active_payload_bytes: int
    in_flight_frame_bytes: int
    pending_data_messages: int
    pending_control_messages: int
    next_fragment_sequence: int
    rollover_required: bool
    retired: bool


@dataclass(slots=True)
class _Message:
    kind: int
    message_id: bytes
    payload: bytes
    offset: int = 0
    index: int = 0


def writer_reservation_overhead_bytes():
    """Conservative fixed memory reserve, including validation and frame copies."""
    return _FIXED_RESERVATION_BYTES


class ChannelFragmentWriter:
    """Serialize bounded logical messages onto one C2 fragment sequence.

    ``communication_reservation_bytes`` is the complete reservation assigned
    to this writer. It includes the fixed validation/frame/history overhead,
    the configured control payload reserve, and a remaining data payload
    reserve. The control reserve defaults to eight maximum cleanup bundles so
    data admission cannot consume the bytes needed for cleanup traffic.

    Data allows eight pending messages plus one active message. Control allows
    eight messages total, including its active message. A 1,024-ID lifetime
    history prevents message-ID reuse; after that, ``rollover_required`` is
    latched and new messages are rejected so history never grows unbounded.
    """

    def __init__(self, expected_generation, *, communication_reservation_bytes,
                 control_byte_capacity=MAX_CONTROL_MESSAGES * _MAX_CONTROL_KIND_BYTES,
                 fragment_payload_bytes=DEFAULT_FRAGMENT_PAYLOAD_BYTES,
                 initial_sequence=1):
        if (type(expected_generation) is not bytes or len(expected_generation) != 16
                or expected_generation == bytes(16)):
            raise ValueError("expected generation must be a nonzero 16-byte value")
        if (type(communication_reservation_bytes) is not int
                or type(control_byte_capacity) is not int
                or control_byte_capacity < 1
                or type(fragment_payload_bytes) is not int
                or not 1 <= fragment_payload_bytes <= DEFAULT_FRAGMENT_PAYLOAD_BYTES
                or type(initial_sequence) is not int
                or not 1 <= initial_sequence <= wire.MAX_SEQUENCE):
            raise ValueError("writer reservation, fragment size, or sequence is invalid")
        minimum = _FIXED_RESERVATION_BYTES + control_byte_capacity + 1
        if communication_reservation_bytes < minimum:
            raise ValueError("writer reservation cannot cover its bounded overhead and lanes")
        self.expected_generation = expected_generation
        self.communication_reservation_bytes = communication_reservation_bytes
        self.control_byte_capacity = control_byte_capacity
        self.data_byte_capacity = (communication_reservation_bytes
                                   - _FIXED_RESERVATION_BYTES
                                   - control_byte_capacity)
        self.fragment_payload_bytes = fragment_payload_bytes
        self._next_sequence = initial_sequence
        self._data = deque()
        self._control = deque()
        self._active_data = None
        self._active_control = None
        self._data_bytes = 0
        self._control_bytes = 0
        self._message_ids = set()
        self._rollover_required = False
        self._retired = False
        self._in_flight = None
        self._lock = Lock()

    @property
    def reservation_bound_bytes(self):
        """Maximum writer-owned/temporary memory under its explicit reservation."""
        return self.communication_reservation_bytes

    @property
    def rollover_required(self):
        with self._lock:
            return self._rollover_required

    @property
    def pending_bytes(self):
        with self._lock:
            return self._data_bytes + self._control_bytes

    @property
    def accounting(self):
        with self._lock:
            inflight_size = len(self._in_flight) if self._in_flight is not None else 0
            return WriterAccounting(
                queued_and_active_payload_bytes=self._data_bytes + self._control_bytes,
                in_flight_frame_bytes=inflight_size,
                pending_data_messages=(len(self._data)
                                       + int(self._active_data is not None)),
                pending_control_messages=(len(self._control)
                                          + int(self._active_control is not None)),
                next_fragment_sequence=self._next_sequence,
                rollover_required=self._rollover_required,
                retired=self._retired)

    @staticmethod
    def _lane(kind):
        if kind in wire.DATA_KINDS:
            return "data"
        if kind in wire.CONTROL_KINDS:
            return "control"
        return None

    @staticmethod
    def _valid_payload(kind, payload):
        if type(payload) is not bytes or not payload:
            return False
        if kind in (wire.DATA, wire.CONTROL, wire.RESPONSE, wire.CONTROL_RESPONSE):
            try:
                wire.decode_bundle(payload, fragment_kind=kind)
            except (wire.ChannelWireError, TypeError, ValueError):
                return False
            return True
        if kind in (wire.HELLO, wire.CLOSE):
            return len(payload) <= wire.MAX_SMALL_CONTROL_BYTES
        if kind == wire.HEARTBEAT:
            return len(payload) <= wire.MAX_HEARTBEAT_BYTES
        return False

    def enqueue(self, *, kind, message_id, payload):
        """Admit immutable pre-encoded bytes immediately; rejection spends no sequence."""
        lane = self._lane(kind) if type(kind) is int else None
        if (lane is None or type(message_id) is not bytes or len(message_id) != 16
                or message_id == bytes(16) or type(payload) is not bytes
                or not payload):
            return False
        if len(payload) > _KIND_LIMITS[kind]:
            return False
        with self._lock:
            if self._retired or self._rollover_required:
                return False
            if message_id in self._message_ids:
                return False
            if len(self._message_ids) >= MESSAGE_ID_HISTORY_CAPACITY:
                self._rollover_required = True
                return False
            if lane == "data":
                if (len(self._data) >= MAX_PENDING_DATA_MESSAGES
                        or len(payload) > self.data_byte_capacity - self._data_bytes):
                    return False
            else:
                active = int(self._active_control is not None)
                if (len(self._control) + active >= MAX_CONTROL_MESSAGES
                        or len(payload) > self.control_byte_capacity - self._control_bytes):
                    return False
            # Serialize codec validation so its temporary bundle slices have
            # one fixed peak even when several producers call enqueue at once.
            if not self._valid_payload(kind, payload):
                return False
            if lane == "data":
                self._data.append(_Message(kind, message_id, payload))
                self._data_bytes += len(payload)
            else:
                self._control.append(_Message(kind, message_id, payload))
                self._control_bytes += len(payload)
            self._message_ids.add(message_id)
            if len(self._message_ids) == MESSAGE_ID_HISTORY_CAPACITY:
                self._rollover_required = True
            return True

    def next_frame(self):
        """Commit exactly one next fragment, prioritizing control between frames."""
        with self._lock:
            if self._retired:
                raise ChannelWriterError("fragment writer is permanently retired")
            if self._in_flight is not None:
                raise ChannelWriterError("previous committed frame is not acknowledged")
            if self._active_control is None and self._control:
                self._active_control = self._control.popleft()
            if self._active_control is not None:
                lane, message = "control", self._active_control
            else:
                if self._active_data is None and self._data:
                    self._active_data = self._data.popleft()
                if self._active_data is None:
                    return None
                lane, message = "data", self._active_data

            sequence = self._next_sequence
            start = message.offset
            stop = min(start + self.fragment_payload_bytes, len(message.payload))
            final = stop == len(message.payload)
            if sequence > wire.MAX_SEQUENCE or (sequence == wire.MAX_SEQUENCE and not final):
                self._retire_locked()
                raise ChannelWriterError("transport sequence exhausted; retire this generation")
            flags = (wire.START if message.index == 0 else 0) | (wire.END if final else 0)
            header = struct.pack(wire.FRAGMENT_FORMAT, wire.FRAGMENT_MAGIC,
                message.kind, flags, 0, self.expected_generation, sequence,
                message.message_id, message.index, stop - start)
            frame = header + message.payload[start:stop]
            self._next_sequence += 1
            if self._next_sequence > wire.MAX_SEQUENCE:
                self._rollover_required = True
            message.offset = stop
            message.index += 1
            self._in_flight = frame
            if final:
                if lane == "control":
                    self._control_bytes -= len(message.payload)
                    self._active_control = None
                else:
                    self._data_bytes -= len(message.payload)
                    self._active_data = None
            return frame

    def frame_sent(self, frame):
        """Acknowledge the one committed frame after the transport accepted it."""
        with self._lock:
            if self._in_flight is None or frame is not self._in_flight:
                self._retire_locked()
                raise ChannelWriterError("sent-frame acknowledgment does not match committed output")
            self._in_flight = None

    def retire(self):
        """Permanently discard queued/partial work after uncertain transport progress."""
        with self._lock:
            self._retire_locked()

    def _retire_locked(self):
        self._retired = True
        self._data.clear()
        self._control.clear()
        self._active_data = None
        self._active_control = None
        self._data_bytes = 0
        self._control_bytes = 0
        self._message_ids.clear()
        self._in_flight = None
