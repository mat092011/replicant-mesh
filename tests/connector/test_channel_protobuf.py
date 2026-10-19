"""Dependency-free structural tests for C2 protobuf preflight."""
import unittest

from steamboat_connector.channel_protobuf import (
    ChannelProtobufError, preflight_worker_protobuf,
)


def varint(value):
    out = bytearray()
    while value > 0x7f:
        out.append((value & 0x7f) | 0x80)
        value >>= 7
    out.append(value)
    return bytes(out)


def length_field(number, payload):
    return varint((number << 3) | 2) + varint(len(payload)) + payload


class ChannelProtobufPreflightTests(unittest.TestCase):
    def test_valid_minimal_request_and_response_wire(self):
        preflight_worker_protobuf(b"\x08\x01", response=False)
        preflight_worker_protobuf(b"\x08\x01", response=True)
        tensor = b"\x0a\x01\x01"  # packed shape [1]
        request = b"\x08\x01" + length_field(13, tensor)
        response = b"\x08\x01" + length_field(16, tensor)
        preflight_worker_protobuf(request, response=False)
        preflight_worker_protobuf(response, response=True)

    def test_unknown_duplicate_wrong_type_and_groups_are_rejected(self):
        malformed = (
            (b"\xa8\x03\x00", False),  # unknown field 53
            (b"\x08\x01\x08\x01", False),  # duplicate singular
            (b"\x0a\x00", False),  # field 1 has wrong wire type
            (b"\x0b\x0c", False),  # group start/end
            (b"\x82\x01\x00\x82\x01\x00", True),  # duplicate tensor
        )
        for payload, response in malformed:
            with self.subTest(payload=payload), self.assertRaises(ChannelProtobufError):
                preflight_worker_protobuf(payload, response=response)

    def test_varint_truncation_overflow_and_nonminimal_forms_are_rejected(self):
        malformed = (
            b"\x08\x80",
            b"\x08\xff\xff\xff\xff\xff\xff\xff\xff\xff\x02",
            b"\x08\x81\x00",
            b"\x08\x80\x80\x80\x80\x10",  # uint32 overflow
        )
        for payload in malformed:
            with self.subTest(payload=payload), self.assertRaises(ChannelProtobufError):
                preflight_worker_protobuf(payload, response=False)

    def test_packed_zero_shape_expansion_rejected_before_protobuf_parse(self):
        huge_packed_shape = length_field(1, b"\x00" * 1_000_000)
        payload = length_field(13, huge_packed_shape)
        with self.assertRaisesRegex(ChannelProtobufError, "shape exceeds"):
            preflight_worker_protobuf(payload, response=False)

    def test_largest_supported_runtime_tensor_shape_and_data_are_accepted(self):
        # The current tiny runtime supports hidden=64 and <=1,152 positions.
        # This is a structurally valid maximum-size Step tensor (1,152*64*4).
        packed_shape = length_field(1, b"\x01\x80\x09\x40")
        tensor = (packed_shape + length_field(2, b"float32_le")
                  + length_field(3, b"batch_sequence_hidden")
                  + b"\x20\x80\x80\x12"
                  + length_field(5, b"x" * (1152 * 64 * 4)))
        request = b"\x08\x01" + length_field(13, tensor)
        preflight_worker_protobuf(request, response=False)

    def test_tensor_depth_and_duplicate_nested_fields_are_rejected(self):
        nested_tensor = length_field(13, b"\x08\x00")
        with self.assertRaises(ChannelProtobufError):
            preflight_worker_protobuf(length_field(13, nested_tensor), response=False)
        tensor = b"\x10\x01\x10\x02"
        with self.assertRaises(ChannelProtobufError):
            preflight_worker_protobuf(length_field(13, tensor), response=False)

    def test_string_and_tensor_data_bounds_are_checked_without_slicing(self):
        with self.assertRaisesRegex(ChannelProtobufError, "string exceeds"):
            preflight_worker_protobuf(length_field(2, b"x" * 257), response=False)
        with self.assertRaisesRegex(ChannelProtobufError, "string exceeds"):
            preflight_worker_protobuf(length_field(8, b"x" * 1025), response=True)
        too_wide_data = length_field(5, b"x" * (1_048_577))
        with self.assertRaises(ChannelProtobufError):
            preflight_worker_protobuf(length_field(13, too_wide_data), response=False)

    def test_bounds_and_selectors_are_strict(self):
        for data, response, maximum in ((bytearray(b"\x08\x01"), False, 10),
                                        (b"\x08\x01", 1, 10),
                                        (b"\x08\x01", False, 1 << 30)):
            with self.subTest(data_type=type(data), response=response, maximum=maximum):
                with self.assertRaises((ChannelProtobufError, ValueError)):
                    preflight_worker_protobuf(data, response=response, max_bytes=maximum)


if __name__ == "__main__":
    unittest.main()
