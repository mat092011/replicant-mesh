"""Standard-library tests for the frozen C2 framing format."""
import os
import struct
import subprocess
import sys
import unittest

from steamboat_connector import channel_wire as wire


GENERATION = b"g" * 16
DATA_ID = b"d" * 16
CONTROL_ID = b"c" * 16


def _frame(kind, flags, sequence, message_id, index, payload, generation=GENERATION):
    return struct.pack(wire.FRAGMENT_FORMAT, wire.FRAGMENT_MAGIC, kind, flags, 0,
                       generation, sequence, message_id, index, len(payload)) + payload


class ChannelWireTests(unittest.TestCase):
    def test_import_is_torch_free(self):
        environment = dict(os.environ)
        environment["PYTHONPATH"] = os.pathsep.join(
            ("src", environment.get("PYTHONPATH", "")))
        result = subprocess.run(
            [sys.executable, "-B", "-c",
             "import sys; import steamboat_connector.channel_wire; "
             "assert not any(n == 'torch' or n.startswith('torch.') for n in sys.modules)"],
            capture_output=True, text=True, timeout=10, check=False, env=environment)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_safe_encoder_and_stream_decoder_accept_arbitrary_tcp_chunks(self):
        data_frames = list(wire.iter_fragments(
            b"abcdefgh", kind=wire.DATA, generation=GENERATION, message_id=DATA_ID,
            first_sequence=1, fragment_payload_bytes=4))
        control_frames = list(wire.iter_fragments(
            b"xyz", kind=wire.CONTROL, generation=GENERATION, message_id=CONTROL_ID,
            first_sequence=2))
        # Interleave lanes while preserving the one global fragment sequence.
        stream = data_frames[0] + control_frames[0] + _frame(
            wire.DATA, wire.END, 3, DATA_ID, 1, b"efgh")
        decoder = wire.FragmentDecoder(GENERATION, reassembly_capacity=64)
        outputs = []
        for width in (1, 7, 53, 2, 61, 4, 3, 19, 1000):
            if not stream:
                break
            outputs.extend(decoder.feed(stream[:width]))
            stream = stream[width:]
        if stream:
            outputs.extend(decoder.feed(stream))
        decoder.finish()
        self.assertEqual([(item.kind, item.payload) for item in outputs],
                         [(wire.CONTROL, b"xyz"), (wire.DATA, b"abcdefgh")])
        self.assertIs(type(outputs[0].payload), bytes)

    def test_data_and_control_bundle_limits_and_closed_fields(self):
        request = wire.encode_bundle("Step", wire.REQUEST, binding=b"{}", protobuf=b"p")
        parsed = wire.decode_bundle(request, fragment_kind=wire.DATA)
        self.assertEqual((parsed.method, parsed.binding, parsed.protobuf),
                         ("Step", b"{}", b"p"))
        control = wire.encode_bundle("CancelSession", wire.REQUEST,
                                     envelope=b"delegation", binding=b"{}", protobuf=b"p")
        self.assertEqual(wire.decode_bundle(control, fragment_kind=wire.CONTROL).method,
                         "CancelSession")
        response = wire.encode_bundle("Step", wire.BUNDLE_RESPONSE, protobuf=b"r")
        self.assertEqual(wire.decode_bundle(response, fragment_kind=wire.RESPONSE).classification,
                         wire.BUNDLE_RESPONSE)
        invalid = (
            lambda: wire.encode_bundle("NoSuchMethod", wire.REQUEST, binding=b"x", protobuf=b"p"),
            lambda: wire.encode_bundle("Step", wire.REQUEST, binding=b"", protobuf=b"p"),
            lambda: wire.encode_bundle("Step", wire.BUNDLE_RESPONSE,
                                       envelope=b"x", protobuf=b"p"),
            lambda: wire.decode_bundle(request, fragment_kind=wire.RESPONSE),
            lambda: wire.decode_bundle(
                wire.encode_bundle("Step", wire.REQUEST, binding=b"x", protobuf=b"p"),
                fragment_kind=wire.CONTROL),
            lambda: wire.encode_bundle("CloseSession", wire.REQUEST, binding=b"x",
                                       protobuf=b"x" * (wire.MAX_CONTROL_PROTOBUF_BYTES + 1)),
        )
        for operation in invalid:
            with self.subTest(operation=operation), self.assertRaises(wire.ChannelWireError):
                operation()

    def test_bounds_rejected_before_large_bundle_or_fragment_allocation(self):
        with self.assertRaises(wire.ChannelWireError):
            wire.encode_bundle("Step", wire.REQUEST, binding=b"x",
                               protobuf=b"x" * (wire.MAX_PROTOBUF_BYTES + 1))
        with self.assertRaises(wire.ChannelWireError):
            list(wire.iter_fragments(b"x" * (wire.MAX_BUNDLE_BYTES + 1),
                                     kind=wire.DATA, generation=GENERATION,
                                     message_id=DATA_ID))
        frames = list(wire.iter_fragments(b"x" * (wire.MAX_FRAGMENT_BYTES + 1),
                                          kind=wire.DATA, generation=GENERATION,
                                          message_id=DATA_ID))
        self.assertEqual([len(frame) - wire.FRAGMENT_HEADER_BYTES for frame in frames],
                         [wire.MAX_FRAGMENT_BYTES, 1])
        with self.assertRaises(wire.ChannelWireError):
            list(wire.iter_fragments(b"xy", kind=wire.DATA, generation=GENERATION,
                                     message_id=DATA_ID,
                                     first_sequence=wire.MAX_SEQUENCE,
                                     fragment_payload_bytes=1))

    def test_malformed_inputs_fault_decoder_and_clear_all_partial_state(self):
        broken = bytearray(_frame(wire.DATA, wire.START, 1, DATA_ID, 0, b"a"))
        broken[6:8] = b"\x00\x01"  # reserved field
        decoder = wire.FragmentDecoder(GENERATION, reassembly_capacity=32)
        with self.assertRaises(wire.ChannelWireError):
            list(decoder.feed(bytes(broken)))
        self.assertEqual(decoder._frame, bytearray())
        self.assertEqual(decoder._lanes, {"data": None, "control": None})
        with self.assertRaises(wire.ChannelWireError):
            list(decoder.feed(b""))

    def test_generation_sequence_start_index_and_reassembly_are_strict(self):
        cases = (
            (_frame(wire.DATA, wire.START | wire.END, 1, DATA_ID, 0, b"x", b"z" * 16), "generation"),
            (_frame(wire.DATA, wire.START | wire.END, 2, DATA_ID, 0, b"x"), "sequence"),
            (_frame(wire.DATA, wire.END, 1, DATA_ID, 0, b"x"), "start"),
            (_frame(wire.DATA, wire.START | wire.END, 1, bytes(16), 0, b"x"), "message"),
        )
        for frame, label in cases:
            with self.subTest(label=label):
                decoder = wire.FragmentDecoder(GENERATION, reassembly_capacity=32)
                with self.assertRaises(wire.ChannelWireError):
                    list(decoder.feed(frame))
        decoder = wire.FragmentDecoder(GENERATION, reassembly_capacity=32)
        list(decoder.feed(_frame(wire.DATA, wire.START, 1, DATA_ID, 0, b"a")))
        with self.assertRaises(wire.ChannelWireError):
            list(decoder.feed(_frame(wire.DATA, wire.END, 2, DATA_ID, 2, b"b")))
        with self.assertRaises(wire.ChannelWireError):
            decoder.finish()

    def test_reassembly_capacity_and_message_lane_conflicts_fail_closed(self):
        decoder = wire.FragmentDecoder(GENERATION, reassembly_capacity=4)
        list(decoder.feed(_frame(wire.DATA, wire.START, 1, DATA_ID, 0, b"abc")))
        with self.assertRaises(wire.ChannelWireError):
            list(decoder.feed(_frame(wire.CONTROL, wire.START | wire.END, 2,
                                     CONTROL_ID, 0, b"de")))
        with self.assertRaises(wire.ChannelWireError):
            list(decoder.feed(b""))
        decoder = wire.FragmentDecoder(GENERATION, reassembly_capacity=32)
        list(decoder.feed(_frame(wire.DATA, wire.START, 1, DATA_ID, 0, b"a")))
        with self.assertRaises(wire.ChannelWireError):
            list(decoder.feed(_frame(wire.DATA, wire.START | wire.END, 2,
                                     b"n" * 16, 0, b"b")))

    def test_pending_lanes_reject_count_and_byte_pressure_and_prioritize_control(self):
        lanes = wire.PendingMessageLanes(byte_capacity=6, data_capacity=1, control_capacity=1)
        data = wire.DecodedMessage(wire.DATA, GENERATION, DATA_ID, 1, 1, b"1234")
        control = wire.DecodedMessage(wire.CONTROL, GENERATION, CONTROL_ID, 2, 2, b"12")
        self.assertTrue(lanes.enqueue(data))
        self.assertFalse(lanes.enqueue(data))
        self.assertTrue(lanes.enqueue(control))
        self.assertFalse(lanes.enqueue(wire.DecodedMessage(
            wire.DATA, GENERATION, b"x" * 16, 3, 3, b"x")))
        self.assertEqual(lanes.pending_bytes, 6)
        self.assertEqual(lanes.pop_next(), control)
        self.assertEqual(lanes.pop_next(), data)
        self.assertEqual(lanes.pending_bytes, 0)
        self.assertIsNone(lanes.pop_next())
        self.assertFalse(lanes.enqueue(wire.DecodedMessage(
            [], GENERATION, CONTROL_ID, 1, 1, b"x")))


if __name__ == "__main__":
    unittest.main()
