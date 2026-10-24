"""Protocol codec tests on the explicitly selected pinned runtime stack."""

import os
import struct
import unittest
from unittest.mock import patch


@unittest.skipUnless(os.environ.get("REPLICANT_MESH_PROTOCOL_TESTS") == "1",
                     "Set REPLICANT_MESH_PROTOCOL_TESTS=1 in the pinned PyTorch image")
class CodecTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import torch
        from replicant_mesh.protocol import codec, wire
        from replicant_mesh.protocol.errors import ProtocolError
        from replicant_mesh.protocol.worker_pb2 import Request, Response, TensorEnvelope
        cls.torch, cls.codec, cls.wire = torch, codec, wire
        cls.ProtocolError = ProtocolError
        cls.Request, cls.Response, cls.TensorEnvelope = Request, Response, TensorEnvelope

    def envelope(self, count=2):
        values = self.torch.arange(count * 64, dtype=self.torch.float32).reshape(1, count, 64)
        return self.codec.encode_tensor(values)

    def test_bit_exact_little_endian_round_trip_and_independent_storage(self):
        for count in (1, 128, 1152):
            values = self.torch.arange(count * 64, dtype=self.torch.float32).reshape(1, count, 64) / 7
            envelope = self.codec.encode_tensor(values)
            self.assertEqual(envelope.data[:8], struct.pack("<ff", 0, float(values[0, 0, 1])))
            result = self.codec.decode_tensor(envelope, count)
            self.assertTrue(self.torch.equal(result, values))
            self.assertTrue(result.is_contiguous())
            result.zero_()
            self.assertEqual(envelope.data[4:8], struct.pack("<f", float(values[0, 0, 1])))
            self.assertNotEqual(result.data_ptr(), values.data_ptr())

    def test_shape_and_length_rejected_before_torch_allocation(self):
        changes = (
            {"shape": [2, 2, 64]}, {"shape": [1, 3, 64]}, {"shape": [1, 2, 63]},
            {"shape": [1, 2, 64, 1]}, {"shape": [1, 4294967295, 64]},
            {"dtype": "float64"}, {"dtype": "float32_be"}, {"layout": "pickle"},
            {"byte_count": 511}, {"byte_count": 2**63}, {"data": b"short"},
            {"data": b"x" * 516},
        )
        for changed in changes:
            with self.subTest(changed=list(changed)):
                envelope = self.envelope()
                for name, value in changed.items():
                    if name == "shape":
                        del envelope.shape[:]
                        envelope.shape.extend(value)
                    else:
                        setattr(envelope, name, value)
                with patch.object(self.torch, "from_numpy") as allocate:
                    with self.assertRaises(self.ProtocolError) as caught:
                        self.codec.decode_tensor(envelope, 2)
                    self.assertEqual(caught.exception.code, "INVALID_INPUT")
                    allocate.assert_not_called()

    def test_nonfinite_payload_rejected_before_torch_allocation(self):
        for value in (float("nan"), float("inf"), -float("inf")):
            envelope = self.envelope()
            envelope.data = struct.pack("<f", value) + envelope.data[4:]
            with patch.object(self.torch, "from_numpy") as allocate:
                with self.assertRaises(self.ProtocolError):
                    self.codec.decode_tensor(envelope, 2)
                allocate.assert_not_called()

    def test_encode_rejects_unsupported_tensor_representations(self):
        torch = self.torch
        invalid = ("pickle", torch.zeros(1, 2, 64, dtype=torch.float64),
                   torch.zeros(1, 2, 64, dtype=torch.int64), torch.zeros(1, 0, 64),
                   torch.zeros(1, 1153, 64), torch.zeros(2, 2, 64),
                   torch.zeros(1, 64, 2).transpose(1, 2),
                   torch.full((1, 2, 64), float("nan")),
                   torch.zeros(1, 2, 64, device="meta"))
        for value in invalid:
            with self.subTest(type=type(value)), self.assertRaises(self.ProtocolError):
                self.codec.encode_tensor(value)

    def test_token_count_and_resource_limits_are_strict(self):
        envelope = self.envelope()
        for count in (True, 0, -1, 2.0, 1153):
            with self.subTest(count=count), self.assertRaises(self.ProtocolError):
                self.codec.decode_tensor(envelope, count)
        for limits in ({"max_bytes": 511}, {"max_bytes": 1048577},
                       {"max_tokens": True}, {"hidden_size": 0}):
            with self.subTest(limits=limits), self.assertRaises(self.ProtocolError):
                self.codec.decode_tensor(envelope, 2, **limits)

    def test_wire_cap_precedes_parse_and_serialization(self):
        for raw in (b"x" * 1048577, bytearray(1)):
            with self.assertRaises(self.ProtocolError):
                self.wire.parse_message(raw, self.Request)
        request = self.Request(session_id="x" * 1025)
        with self.assertRaises(self.ProtocolError):
            self.wire.serialize_message(request, max_bytes=1024)
        with self.assertRaises(self.ProtocolError):
            self.wire.parse_message(b"\xff", self.Request)

    def test_unknown_fields_rejected_in_request_and_nested_tensor(self):
        unknown = b"\xf8\x3e\x01"  # Unknown varint field 999.
        request = self.Request(protocol_version=1)
        with self.assertRaises(self.ProtocolError):
            self.wire.parse_message(request.SerializeToString() + unknown, self.Request)
        request.tensor.ParseFromString(self.envelope().SerializeToString() + unknown)
        with self.assertRaises(self.ProtocolError):
            self.wire.serialize_message(request)

    def test_generated_service_matches_transport_operations(self):
        from replicant_mesh.protocol import METHODS
        from replicant_mesh.protocol.worker_pb2 import DESCRIPTOR
        self.assertEqual(tuple(method.name for method in DESCRIPTOR.services_by_name["Worker"].methods),
                         METHODS)
