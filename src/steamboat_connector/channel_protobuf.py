"""Allocation-bounded structural preflight for C2 Worker protobuf payloads.

This deliberately mirrors the checked-in Worker v1 schema. It rejects wire
shapes that could expand into unbounded generated-protobuf repeated fields
before ParseFromString or CopyFrom is called.
"""
from __future__ import annotations

from steamboat_connector.channel_wire import MAX_PROTOBUF_BYTES


class ChannelProtobufError(ValueError):
    """C2 Worker protobuf bytes are malformed or outside v1 bounds."""


_REQUEST = {
    1: 0, 2: 2, 3: 2, 4: 2, 5: 2, 6: 0, 7: 0, 8: 0, 9: 0,
    10: 0, 11: 0, 12: 0, 13: 2,
}
_RESPONSE = {
    1: 0, 2: 2, 3: 2, 4: 2, 5: 2, 6: 0, 7: 2, 8: 2, 9: 0,
    10: 0, 11: 0, 12: 0, 13: 0, 14: 2, 15: 0, 16: 2, 17: 0,
    18: 0, 19: 0, 20: 0, 21: 0, 22: 0, 23: 0, 24: 0, 25: 0,
    26: 0, 27: 1, 28: 1, 29: 0, 30: 0, 31: 0, 32: 0, 33: 0,
    34: 0, 35: 0, 36: 0, 37: 0, 38: 0, 39: 0, 40: 0, 41: 0,
    42: 0, 43: 2, 44: 0,
}
_TENSOR = {1: 0, 2: 2, 3: 2, 4: 0, 5: 2}
_U32_FIELDS = frozenset({1, 6, 7, 8, 9, 11, 12})
_U64_FIELDS = frozenset({10})
_RESPONSE_U32_FIELDS = frozenset({1, 9, 11, 12, 13, 17, 18, 19, 20, 21,
                                  22, 24, 25, 26, 29, 30, 32, 33, 34,
                                  35, 37, 38, 39, 40})
_RESPONSE_U64_FIELDS = frozenset({6, 10, 23, 36, 41, 42, 44})
_BOOL_FIELDS = frozenset({15, 17, 31, 34})
_STRING_LIMITS = {
    "request": {2: 256, 3: 256, 4: 256, 5: 256},
    "response": {2: 256, 3: 256, 4: 256, 5: 256, 7: 256,
                 8: 1024, 14: 256, 43: 1024},
    "tensor": {2: 32, 3: 32},
}


def _varint(view, pos, end):
    start = pos
    value = 0
    for index in range(10):
        if pos >= end:
            raise ChannelProtobufError("truncated protobuf varint")
        byte = view[pos]
        pos += 1
        if index == 9 and byte > 1:
            raise ChannelProtobufError("protobuf varint overflows uint64")
        value |= (byte & 0x7f) << (7 * index)
        if not byte & 0x80:
            if pos - start > 1 and value < (1 << (7 * (pos - start - 1))):
                raise ChannelProtobufError("protobuf varint is not minimally encoded")
            return value, pos
    raise ChannelProtobufError("protobuf varint exceeds ten bytes")


def _length(view, pos, end):
    length, pos = _varint(view, pos, end)
    if length > end - pos:
        raise ChannelProtobufError("truncated protobuf length-delimited field")
    return pos, pos + length


def _scan_tensor(view, start, end):
    pos = start
    seen = 0
    shape_count = 0
    while pos < end:
        key, pos = _varint(view, pos, end)
        number, wire = key >> 3, key & 7
        if not number or number not in _TENSOR:
            raise ChannelProtobufError("unknown TensorEnvelope field")
        expected = _TENSOR[number]
        if number != 1:
            bit = 1 << number
            if seen & bit:
                raise ChannelProtobufError("duplicate singular TensorEnvelope field")
            seen |= bit
        if number == 1 and wire == 2:
            packed_start, packed_end = _length(view, pos, end)
            if packed_end - packed_start > 15:
                raise ChannelProtobufError("TensorEnvelope shape exceeds three uint32 values")
            cursor = packed_start
            while cursor < packed_end:
                value, cursor = _varint(view, cursor, packed_end)
                if value > 0xffffffff:
                    raise ChannelProtobufError("TensorEnvelope shape value overflows uint32")
                shape_count += 1
                if shape_count > 3:
                    raise ChannelProtobufError("TensorEnvelope shape exceeds three values")
            pos = packed_end
            continue
        if wire != expected or (number == 1 and wire != 0):
            raise ChannelProtobufError("TensorEnvelope field uses the wrong wire type")
        if wire == 0:
            value, pos = _varint(view, pos, end)
            if number == 1 and value > 0xffffffff:
                raise ChannelProtobufError("TensorEnvelope shape value overflows uint32")
            if number == 1:
                shape_count += 1
                if shape_count > 3:
                    raise ChannelProtobufError("TensorEnvelope shape exceeds three values")
        else:
            field_start, field_end = _length(view, pos, end)
            if number == 5 and field_end - field_start > MAX_PROTOBUF_BYTES:
                raise ChannelProtobufError("TensorEnvelope data exceeds the protobuf ceiling")
            if number in _STRING_LIMITS["tensor"] and field_end - field_start > _STRING_LIMITS["tensor"][number]:
                raise ChannelProtobufError("TensorEnvelope metadata exceeds its byte bound")
            pos = field_end
    if shape_count > 3:
        raise ChannelProtobufError("TensorEnvelope shape exceeds three values")


def preflight_worker_protobuf(data: bytes, *, response: bool,
                              max_bytes: int = MAX_PROTOBUF_BYTES) -> None:
    """Validate C2 Worker v1 wire structure before generated protobuf parsing.

    The scanner uses one memoryview, bounded scalar state and no slices or
    field-sized temporary objects. Tensor shape expansion is capped at three
    values before protobuf parsing.
    """
    if type(data) is not bytes:
        raise ChannelProtobufError("protobuf payload must be bytes")
    if type(response) is not bool:
        raise ChannelProtobufError("response selector must be boolean")
    if type(max_bytes) is not int or not 1 <= max_bytes <= MAX_PROTOBUF_BYTES:
        raise ValueError("protobuf preflight limit is outside the C2 ceiling")
    if len(data) > max_bytes:
        raise ChannelProtobufError("protobuf payload exceeds its byte bound")
    view = memoryview(data)
    fields = _RESPONSE if response else _REQUEST
    seen = 0
    pos = 0
    end = len(view)
    while pos < end:
        key, pos = _varint(view, pos, end)
        number, wire = key >> 3, key & 7
        if not number or number not in fields:
            raise ChannelProtobufError("unknown Worker protobuf field")
        expected = fields[number]
        if wire != expected:
            raise ChannelProtobufError("Worker protobuf field uses the wrong wire type")
        bit = 1 << number
        if seen & bit:
            raise ChannelProtobufError("duplicate singular Worker protobuf field")
        seen |= bit
        if wire == 0:
            value, pos = _varint(view, pos, end)
            if not response and number in _U32_FIELDS and value > 0xffffffff:
                raise ChannelProtobufError("Request uint32 field overflows")
            if not response and number in _U64_FIELDS and value > 0xffffffffffffffff:
                raise ChannelProtobufError("Request uint64 field overflows")
            if response and number in _RESPONSE_U32_FIELDS and value > 0xffffffff:
                raise ChannelProtobufError("Response uint32 field overflows")
            if response and number in _RESPONSE_U64_FIELDS and value > 0xffffffffffffffff:
                raise ChannelProtobufError("Response uint64 field overflows")
            if response and number in _BOOL_FIELDS and value not in (0, 1):
                raise ChannelProtobufError("Response bool field is not 0 or 1")
            if not response and number == 1 and value > 0xffffffff:
                raise ChannelProtobufError("Request protocol version overflows")
        elif wire == 1:
            if end - pos < 8:
                raise ChannelProtobufError("truncated fixed64 Worker field")
            pos += 8
        elif wire == 2:
            field_start, field_end = _length(view, pos, end)
            if number == (16 if response else 13):
                _scan_tensor(view, field_start, field_end)
            else:
                limit = _STRING_LIMITS["response" if response else "request"].get(number)
                if limit is not None and field_end - field_start > limit:
                    raise ChannelProtobufError("Worker protobuf string exceeds its byte bound")
            pos = field_end
        elif wire == 5:
            if end - pos < 4:
                raise ChannelProtobufError("truncated fixed32 Worker field")
            pos += 4
        else:
            # Includes groups, which are never part of the checked-in schema.
            raise ChannelProtobufError("unsupported protobuf wire type")
