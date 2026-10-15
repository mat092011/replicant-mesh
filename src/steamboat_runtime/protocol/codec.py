"""A bounded tensor codec with no deserialization of executable Python objects."""

from . import MAX_MESSAGE_BYTES
from .errors import ProtocolError
from .worker_pb2 import TensorEnvelope

DTYPE = "float32_le"
LAYOUT = "batch_sequence_hidden"


def _fail(message):
    raise ProtocolError("INVALID_INPUT", message)


def _limits(hidden_size, max_tokens, max_bytes):
    for value in (hidden_size, max_tokens, max_bytes):
        if type(value) is not int or value <= 0:
            _fail("codec limits must be positive integers")
    if max_bytes > MAX_MESSAGE_BYTES:
        _fail("codec byte limit exceeds protocol ceiling")


def validate_envelope(envelope, token_count, *, hidden_size=64, max_tokens=1152,
                      max_bytes=MAX_MESSAGE_BYTES):
    """Check metadata and payload length without importing or allocating Torch."""
    _limits(hidden_size, max_tokens, max_bytes)
    if not isinstance(envelope, TensorEnvelope):
        _fail("tensor envelope is required")
    if type(token_count) is not int or not 1 <= token_count <= max_tokens:
        _fail("token count is outside the supported bound")
    if tuple(envelope.shape) != (1, token_count, hidden_size):
        _fail("tensor shape must be [1, token_count, hidden_size]")
    if envelope.dtype != DTYPE or envelope.layout != LAYOUT:
        _fail("unsupported tensor dtype or layout")
    expected = token_count * hidden_size * 4
    if expected > max_bytes or envelope.byte_count != expected or len(envelope.data) != expected:
        _fail("tensor byte count does not match the bounded shape")
    return expected


def encode_tensor(tensor, *, hidden_size=64, max_tokens=1152,
                  max_bytes=MAX_MESSAGE_BYTES):
    import torch

    _limits(hidden_size, max_tokens, max_bytes)
    if not isinstance(tensor, torch.Tensor):
        _fail("activation must be a tensor")
    if tensor.device.type != "cpu" or tensor.dtype != torch.float32:
        _fail("activation must be CPU float32")
    if tensor.layout != torch.strided or not tensor.is_contiguous():
        _fail("activation must be a dense contiguous tensor")
    if tensor.ndim != 3 or tensor.shape[0] != 1 or tensor.shape[2] != hidden_size:
        _fail("activation shape must be [1, token_count, hidden_size]")
    count = tensor.shape[1]
    size = count * hidden_size * 4
    if not 1 <= count <= max_tokens or size > max_bytes:
        _fail("activation exceeds the supported shape or byte bound")
    if not bool(torch.isfinite(tensor).all()):
        _fail("activation contains non-finite values")
    data = tensor.detach().numpy().astype("<f4", copy=False).tobytes(order="C")
    return TensorEnvelope(shape=list(tensor.shape), dtype=DTYPE, layout=LAYOUT,
                          byte_count=size, data=data)


def decode_tensor(envelope, token_count, *, hidden_size=64, max_tokens=1152,
                  max_bytes=MAX_MESSAGE_BYTES):
    validate_envelope(envelope, token_count, hidden_size=hidden_size,
                      max_tokens=max_tokens, max_bytes=max_bytes)
    import numpy as np
    import torch

    values = np.frombuffer(envelope.data, dtype="<f4")
    if not bool(np.isfinite(values).all()):
        _fail("activation contains non-finite values")
    # Copy to owned writable native-endian storage. It cannot alias Protobuf data,
    # and the caller cannot change a received activation by mutating a message.
    owned = values.astype(np.float32, copy=True)
    return torch.from_numpy(owned).reshape(1, token_count, hidden_size)
