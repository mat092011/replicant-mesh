"""Fixed authenticated C2 heartbeat payload codec."""
from __future__ import annotations

import struct

MAGIC = b"C2H1"
PING = 1
PONG = 2
_FORMAT = "!4sBQ"
SIZE = struct.calcsize(_FORMAT)
MAX_SEQUENCE = (1 << 63) - 1


class HeartbeatError(ValueError):
    """Malformed heartbeat control payload."""


def encode_heartbeat(mode, sequence):
    if type(mode) is not int or mode not in (PING, PONG):
        raise HeartbeatError("heartbeat mode must be PING or PONG")
    if type(sequence) is not int or not 1 <= sequence <= MAX_SEQUENCE:
        raise HeartbeatError("heartbeat sequence is invalid")
    return struct.pack(_FORMAT, MAGIC, mode, sequence)


def decode_heartbeat(payload):
    if type(payload) is not bytes or len(payload) != SIZE:
        raise HeartbeatError("heartbeat payload must be exactly 13 bytes")
    magic, mode, sequence = struct.unpack(_FORMAT, payload)
    if magic != MAGIC or mode not in (PING, PONG) or not 1 <= sequence <= MAX_SEQUENCE:
        raise HeartbeatError("heartbeat payload is invalid")
    return mode, sequence
