"""Capped Protobuf parsing shared by local and gRPC transports."""

import math

from google.protobuf.message import DecodeError

from . import MAX_MESSAGE_BYTES, METHODS, PROTOCOL_VERSION
from .codec import validate_envelope
from .errors import ERROR_CODES, MAX_ERROR_CHARS, ProtocolError
from .worker_pb2 import Request, Response


def _limit(max_bytes):
    if type(max_bytes) is not int or not 1 <= max_bytes <= MAX_MESSAGE_BYTES:
        raise ValueError("message limit must be within the protocol ceiling")


def _reject_unknown(message):
    known = type(message)()
    known.CopyFrom(message)
    known.DiscardUnknownFields()
    if known.SerializeToString(deterministic=True) != message.SerializeToString(deterministic=True):
        raise ProtocolError("INVALID_INPUT", "unknown Protobuf fields are unsupported in v1")


def serialize_message(message, max_bytes=MAX_MESSAGE_BYTES):
    _limit(max_bytes)
    if not isinstance(message, (Request, Response)):
        raise ProtocolError("INVALID_INPUT", "expected a protocol request or response")
    if message.ByteSize() > max_bytes:
        raise ProtocolError("INVALID_INPUT", "message exceeds the transport byte limit")
    _reject_unknown(message)
    return message.SerializeToString(deterministic=True)


def parse_message(data, message_type, max_bytes=MAX_MESSAGE_BYTES):
    _limit(max_bytes)
    if message_type not in (Request, Response):
        raise ValueError("unsupported wire message type")
    if not isinstance(data, bytes) or len(data) > max_bytes:
        raise ProtocolError("INVALID_INPUT", "wire payload exceeds the byte limit or is not bytes")
    message = message_type()
    try:
        message.ParseFromString(data)
    except DecodeError as error:
        raise ProtocolError("INVALID_INPUT", "malformed Protobuf message") from error
    _reject_unknown(message)
    return message


def validate_response(method, request, response):
    """Reject mismatched successful replies before a caller advances its session."""
    if method not in METHODS:
        raise ProtocolError("INVALID_INPUT", "unknown protocol operation")
    if response.protocol_version != PROTOCOL_VERSION:
        raise ProtocolError("INCOMPATIBLE_MODEL", "unsupported response protocol version")
    if response.code not in ERROR_CODES | {"OK"} or len(response.message) > MAX_ERROR_CHARS:
        raise ProtocolError("INVALID_INPUT", "invalid response status")
    if any(len(getattr(response, name)) > 256 for name in
           ("manifest_fingerprint", "worker_boot_id", "session_id", "lease_token", "state", "clock_id")):
        raise ProtocolError("INVALID_INPUT", "response metadata exceeds the bound")
    if not all(math.isfinite(value) and value >= 0 for value in (response.queue_ms, response.compute_ms)):
        raise ProtocolError("INVALID_INPUT", "invalid response timing")
    if response.compute_start_ns or response.compute_end_ns:
        if not (0 < response.compute_start_ns <= response.compute_end_ns <= response.monotonic_ns):
            raise ProtocolError("INVALID_INPUT", "invalid compute timestamp ordering")
    if response.code != "OK":
        # Error responses may report the current boot/model after a restart.
        return response
    for name in ("manifest_fingerprint", "worker_boot_id"):
        expected = getattr(request, name)
        if expected and getattr(response, name) != expected:
            raise ProtocolError("STALE_WORKER" if name == "worker_boot_id" else "INCOMPATIBLE_MODEL",
                                "response identity differs from the request")
    if method != "Describe" and response.session_id != request.session_id:
        raise ProtocolError("INVALID_INPUT", "response belongs to another session")
    if method == "OpenSession":
        if not response.lease_token or response.max_positions != request.max_positions:
            raise ProtocolError("INVALID_INPUT", "invalid open-session reservation")
    elif method != "Describe" and response.lease_token != request.lease_token:
        raise ProtocolError("INVALID_INPUT", "response lease differs from the request")
    if method == "Step":
        if (response.sequence != request.sequence or response.start_position != request.start_position
                or response.token_count != request.token_count
                or response.end_position != request.start_position + request.token_count
                or response.next_sequence != request.sequence + 1):
            raise ProtocolError("OUT_OF_ORDER", "step response does not acknowledge the submitted operation")
        if not response.HasField("tensor"):
            raise ProtocolError("INVALID_INPUT", "successful step has no activation")
        validate_envelope(response.tensor, request.token_count)
    return response
