"""Standard-library tests for the frozen C2 framing format."""
import os
import struct
import subprocess
import sys
import tracemalloc
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
        request = wire.encode_bundle("Step", wire.REQUEST, fragment_kind=wire.DATA,
                                     binding=b"{}", protobuf=b"p")
        parsed = wire.decode_bundle(request, fragment_kind=wire.DATA)
        self.assertEqual((parsed.method, parsed.binding, parsed.protobuf),
                         ("Step", b"{}", b"p"))
        control = wire.encode_bundle("CancelSession", wire.REQUEST, fragment_kind=wire.CONTROL,
                                     envelope=b"delegation", binding=b"{}", protobuf=b"p")
        self.assertEqual(wire.decode_bundle(control, fragment_kind=wire.CONTROL).method,
                         "CancelSession")
        response = wire.encode_bundle("Step", wire.BUNDLE_RESPONSE,
                                      fragment_kind=wire.RESPONSE, protobuf=b"r")
        self.assertEqual(wire.decode_bundle(response, fragment_kind=wire.RESPONSE).classification,
                         wire.BUNDLE_RESPONSE)
        invalid = (
            lambda: wire.encode_bundle("NoSuchMethod", wire.REQUEST, fragment_kind=wire.DATA,
                                       binding=b"x", protobuf=b"p"),
            lambda: wire.encode_bundle("Step", wire.REQUEST, fragment_kind=wire.DATA,
                                       binding=b"", protobuf=b"p"),
            lambda: wire.encode_bundle("Step", wire.BUNDLE_RESPONSE,
                                       fragment_kind=wire.RESPONSE,
                                       envelope=b"x", protobuf=b"p"),
            lambda: wire.decode_bundle(request, fragment_kind=wire.RESPONSE),
            lambda: wire.decode_bundle(
                wire.encode_bundle("Step", wire.REQUEST, fragment_kind=wire.DATA,
                                   binding=b"x", protobuf=b"p"),
                fragment_kind=wire.CONTROL),
            lambda: wire.encode_bundle("CloseSession", wire.REQUEST, fragment_kind=wire.CONTROL,
                                       binding=b"x",
                                       protobuf=b"x" * (wire.MAX_CONTROL_PROTOBUF_BYTES + 1)),
        )
        for operation in invalid:
            with self.subTest(operation=operation), self.assertRaises(wire.ChannelWireError):
                operation()

    def test_control_responses_are_closed_bounded_and_preempt_data_fragments(self):
        step = wire.encode_bundle("Step", wire.BUNDLE_RESPONSE,
                                  fragment_kind=wire.RESPONSE,
                                  protobuf=b"s" * 40_000)
        data_frames = list(wire.iter_fragments(
            step, kind=wire.RESPONSE, generation=GENERATION,
            message_id=DATA_ID, first_sequence=1))
        control = wire.encode_bundle("CancelSession", wire.BUNDLE_RESPONSE,
                                     fragment_kind=wire.CONTROL_RESPONSE,
                                     protobuf=b"cancelled")
        self.assertEqual(len(control), wire.BUNDLE_HEADER_BYTES + len(b"cancelled"))
        self.assertEqual(wire.decode_bundle(
            control, fragment_kind=wire.CONTROL_RESPONSE).method, "CancelSession")

        # Interleave one large response fragment, the cleanup reply, and the
        # remainder of the data response on the single transport sequence.
        chunks = [frame[wire.FRAGMENT_HEADER_BYTES:] for frame in data_frames]
        interleaved = [
            _frame(wire.RESPONSE, wire.START, 1, DATA_ID, 0, chunks[0]),
            _frame(wire.CONTROL_RESPONSE, wire.START | wire.END, 2, CONTROL_ID, 0,
                   control),
        ]
        interleaved.extend(
            _frame(wire.RESPONSE, (wire.END if index == len(chunks) - 1 else 0),
                   index + 2, DATA_ID, index, chunk)
            for index, chunk in enumerate(chunks[1:], start=1))
        decoder = wire.FragmentDecoder(GENERATION,
                                       reassembly_capacity=wire.MAX_BUNDLE_BYTES)
        self.assertEqual(list(decoder.feed(interleaved[0])), [])
        control_out = list(decoder.feed(interleaved[1]))
        self.assertEqual(len(control_out), 1)
        self.assertEqual(control_out[0].kind, wire.CONTROL_RESPONSE)
        self.assertEqual(wire.decode_bundle(control_out[0].payload,
                                            fragment_kind=wire.CONTROL_RESPONSE).protobuf,
                         b"cancelled")
        data_out = []
        for frame in interleaved[2:]:
            data_out.extend(decoder.feed(frame))
        self.assertEqual(len(data_out), 1)
        self.assertEqual(data_out[0].kind, wire.RESPONSE)
        self.assertEqual(len(data_out[0].payload), len(step))
        decoder.finish()

        invalid = (
            lambda: wire.encode_bundle("Step", wire.BUNDLE_RESPONSE,
                                       fragment_kind=wire.CONTROL_RESPONSE, protobuf=b"x"),
            lambda: wire.decode_bundle(
                wire.encode_bundle("CancelSession", wire.REQUEST,
                                   fragment_kind=wire.CONTROL, binding=b"b", protobuf=b"x"),
                fragment_kind=wire.CONTROL_RESPONSE),
            lambda: wire.encode_bundle("CloseSession", wire.BUNDLE_RESPONSE,
                                       fragment_kind=wire.CONTROL_RESPONSE,
                                       envelope=b"e", protobuf=b"x"),
            lambda: wire.encode_bundle("SessionStatus", wire.BUNDLE_RESPONSE,
                                       fragment_kind=wire.CONTROL_RESPONSE,
                                       binding=b"b", protobuf=b"x"),
            lambda: wire.encode_bundle("CancelSession", wire.BUNDLE_RESPONSE,
                                       fragment_kind=wire.CONTROL_RESPONSE,
                                       protobuf=b"x" * (wire.MAX_CONTROL_PROTOBUF_BYTES + 1)),
            lambda: wire.decode_bundle(step, fragment_kind=wire.CONTROL_RESPONSE),
        )
        for operation in invalid:
            with self.subTest(operation=operation), self.assertRaises(wire.ChannelWireError):
                operation()

        too_large = b"x" * (wire.MAX_CONTROL_RESPONSE_BUNDLE_BYTES + 1)
        oversized_frame = _frame(wire.CONTROL_RESPONSE, wire.START | wire.END,
                                 1, CONTROL_ID, 0, too_large)
        faulted = wire.FragmentDecoder(GENERATION,
                                       reassembly_capacity=wire.MAX_CONTROL_RESPONSE_BUNDLE_BYTES)
        with self.assertRaises(wire.ChannelWireError):
            list(faulted.feed(oversized_frame))
        with self.assertRaises(wire.ChannelWireError):
            faulted.finish()

    def test_bounds_rejected_before_large_bundle_or_fragment_allocation(self):
        with self.assertRaises(wire.ChannelWireError):
            wire.encode_bundle("Step", wire.REQUEST, fragment_kind=wire.DATA, binding=b"x",
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
        self.assertEqual(decoder._frame_used, 0)
        self.assertEqual(decoder._lanes, {"data": None, "control": None})
        with self.assertRaises(wire.ChannelWireError):
            list(decoder.feed(b""))
        self.assertEqual(decoder._next_sequence, 1)

    def test_suspended_feed_cannot_be_overlapped_or_bypassed_by_eof(self):
        frame_one = _frame(wire.DATA, wire.START | wire.END, 1, DATA_ID, 0, b"first")
        frame_two = _frame(wire.DATA, wire.START | wire.END, 2, b"e" * 16, 0, b"second")
        decoder = wire.FragmentDecoder(GENERATION, reassembly_capacity=64)
        iterator = decoder.feed(frame_one + frame_two)
        self.assertEqual(next(iterator).payload, b"first")
        self.assertEqual(decoder._frame_used, 0)
        self.assertIsNone(decoder._header)
        self.assertEqual(decoder._next_sequence, 2)
        with self.assertRaises(wire.ChannelWireError):
            decoder.finish()
        self.assertEqual(decoder._next_sequence, 2)
        with self.assertRaises(wire.ChannelWireError):
            next(iterator)

        decoder = wire.FragmentDecoder(GENERATION, reassembly_capacity=64)
        iterator = decoder.feed(frame_one + frame_two)
        self.assertEqual(next(iterator).payload, b"first")
        with self.assertRaises(wire.ChannelWireError):
            decoder.feed(frame_two)
        self.assertEqual(decoder._next_sequence, 2)
        with self.assertRaises(wire.ChannelWireError):
            next(iterator)

    def test_feed_size_is_bounded_and_failure_preserves_sequence(self):
        decoder = wire.FragmentDecoder(GENERATION, reassembly_capacity=64)
        with self.assertRaises(wire.ChannelWireError):
            decoder.feed(b"x" * (wire.MAX_FEED_BYTES + 1))
        self.assertEqual(decoder._next_sequence, 1)
        self.assertEqual(decoder._frame_used, 0)
        with self.assertRaises(wire.ChannelWireError):
            decoder.finish()

    def test_tiny_fragments_have_constant_bounded_reassembly_memory(self):
        capacity = 10_000
        tracemalloc.start()
        try:
            baseline, _ = tracemalloc.get_traced_memory()
            tracemalloc.reset_peak()
            decoder = wire.FragmentDecoder(GENERATION, reassembly_capacity=capacity)
            for index in range(capacity):
                flags = wire.START if index == 0 else 0
                if index == capacity - 1:
                    flags |= wire.END
                frame = _frame(wire.DATA, flags, index + 1, DATA_ID, index, b"x")
                messages = list(decoder.feed(frame))
                if index == capacity - 1:
                    self.assertEqual(messages[0].payload, b"x" * capacity)
            _, peak = tracemalloc.get_traced_memory()
            self.assertLessEqual(peak - baseline, decoder.reservation_bound_bytes)
            self.assertLess(peak - baseline, 10 * capacity)
        finally:
            tracemalloc.stop()

    def test_review_regression_many_tiny_fragments_at_large_capacity(self):
        # Reproduces the prior 483,637-byte peak against a 477,941-byte bound.
        capacity = 130_623
        tracemalloc.start()
        try:
            baseline, _ = tracemalloc.get_traced_memory()
            tracemalloc.reset_peak()
            decoder = wire.FragmentDecoder(GENERATION,
                                           reassembly_capacity=capacity)
            for index in range(65_536):
                flags = wire.START if index == 0 else 0
                if index == 65_535:
                    flags |= wire.END
                frame = _frame(wire.DATA, flags, index + 1, DATA_ID, index, b"x")
                messages = list(decoder.feed(frame))
                if index == 65_535:
                    self.assertEqual(len(messages), 1)
                    self.assertEqual(len(messages[0].payload), 65_536)
            _, peak = tracemalloc.get_traced_memory()
            self.assertLessEqual(peak - baseline, decoder.reservation_bound_bytes)
        finally:
            tracemalloc.stop()

    def test_maximum_payload_split_frames_stays_within_advertised_reservation(self):
        payload = b"m" * wire.MAX_BUNDLE_BYTES
        tracemalloc.start()
        try:
            baseline, _ = tracemalloc.get_traced_memory()
            tracemalloc.reset_peak()
            decoder = wire.FragmentDecoder(GENERATION,
                                           reassembly_capacity=wire.MAX_BUNDLE_BYTES)
            iterator = wire.iter_fragments(
                payload, kind=wire.DATA, generation=GENERATION,
                message_id=DATA_ID, fragment_payload_bytes=wire.MAX_FRAGMENT_BYTES)
            completed = None
            for frame in iterator:
                output = list(decoder.feed(frame))
                if output:
                    self.assertIsNone(completed)
                    completed = output[0]
            decoder.finish()
            self.assertIsNotNone(completed)
            self.assertEqual(len(completed.payload), wire.MAX_BUNDLE_BYTES)
            _, peak = tracemalloc.get_traced_memory()
            self.assertLessEqual(peak - baseline, decoder.reservation_bound_bytes)
        finally:
            tracemalloc.stop()

    def test_control_bundle_uses_tightest_combined_control_limit(self):
        payload = wire.encode_bundle(
            "CancelSession", wire.REQUEST, fragment_kind=wire.CONTROL,
            envelope=b"e" * wire.MAX_ENVELOPE_BYTES,
            binding=b"b" * wire.MAX_BINDING_BYTES,
            protobuf=b"p" * wire.MAX_CONTROL_PROTOBUF_BYTES)
        self.assertEqual(len(payload), wire.MAX_CONTROL_BUNDLE_BYTES)
        self.assertEqual(wire.decode_bundle(payload, fragment_kind=wire.CONTROL).method,
                         "CancelSession")
        decoder = wire.FragmentDecoder(GENERATION,
                                       reassembly_capacity=wire.MAX_CONTROL_BUNDLE_BYTES)
        oversized = wire.MAX_CONTROL_BUNDLE_BYTES + 1
        offset = 0
        sequence = 1
        index = 0
        while offset < oversized:
            chunk = b"x" * min(wire.MAX_FRAGMENT_BYTES, oversized - offset)
            flags = (wire.START if index == 0 else 0)
            if offset + len(chunk) == oversized:
                flags |= wire.END
            frame = _frame(wire.CONTROL, flags, sequence, CONTROL_ID, index, chunk)
            if index < 3:
                list(decoder.feed(frame))
            else:
                with self.assertRaises(wire.ChannelWireError):
                    list(decoder.feed(frame))
                break
            offset += len(chunk)
            sequence += 1
            index += 1
        self.assertEqual(decoder._next_sequence, sequence)
        self.assertTrue(decoder._fault)

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
        self.assertEqual(decoder._buffers["data"][:3], bytes(3))
        self.assertEqual(decoder._buffers["control"][:1], bytes(1))
        with self.assertRaises(wire.ChannelWireError):
            list(decoder.feed(b""))
        decoder = wire.FragmentDecoder(GENERATION, reassembly_capacity=32)
        list(decoder.feed(_frame(wire.DATA, wire.START, 1, DATA_ID, 0, b"a")))
        with self.assertRaises(wire.ChannelWireError):
            list(decoder.feed(_frame(wire.DATA, wire.START | wire.END, 2,
                                     b"n" * 16, 0, b"b")))

    def test_cleanup_response_cannot_use_the_ordinary_data_lane(self):
        for method in ("CancelSession", "CloseSession", "SessionStatus"):
            for size in (1, wire.MAX_CONTROL_PROTOBUF_BYTES + 1):
                with self.subTest(method=method, size=size):
                    with self.assertRaises(wire.ChannelWireError):
                        wire.encode_bundle(method, wire.BUNDLE_RESPONSE,
                            fragment_kind=wire.RESPONSE, protobuf=b"x" * size)
                    raw = struct.pack(wire.BUNDLE_FORMAT, wire.BUNDLE_MAGIC,
                        wire.METHOD_CODES[method], wire.BUNDLE_RESPONSE, 0, 0, 0, size)
                    with self.assertRaises(wire.ChannelWireError):
                        wire.decode_bundle(raw + b"x" * size,
                                           fragment_kind=wire.RESPONSE)

    def test_control_only_rejects_data_header_before_fragment_payload(self):
        payload = b"x" * (40 * 1024)
        first = next(iter(wire.iter_fragments(
            payload, kind=wire.DATA, generation=GENERATION, message_id=DATA_ID,
            first_sequence=1)))
        header_bytes = wire.FRAGMENT_HEADER_BYTES
        header = first[:header_bytes]
        self.assertEqual(len(first), header_bytes + wire.MAX_FRAGMENT_BYTES)
        decoder = wire.FragmentDecoder(GENERATION, reassembly_capacity=64 * 1024)
        decoder.enter_control_only()
        split = header_bytes // 2
        self.assertEqual(list(decoder.feed(header[:split])), [])
        with self.assertRaises(wire.ChannelWireError):
            list(decoder.feed(header[split:]))
        self.assertTrue(decoder._fault)
        self.assertIsNone(decoder._lanes["data"])
        self.assertEqual(decoder._buffers["data"], bytes(len(decoder._buffers["data"])))

    def test_control_only_entry_retires_partial_data_message_or_header(self):
        payload = b"x" * (40 * 1024)
        first = next(iter(wire.iter_fragments(
            payload, kind=wire.DATA, generation=GENERATION, message_id=DATA_ID,
            first_sequence=1)))
        for partial in (first, first[:wire.FRAGMENT_HEADER_BYTES // 2]):
            with self.subTest(partial_bytes=len(partial)):
                decoder = wire.FragmentDecoder(GENERATION,
                                               reassembly_capacity=64 * 1024)
                list(decoder.feed(partial))
                with self.assertRaises(wire.ChannelWireError):
                    decoder.enter_control_only()
                self.assertTrue(decoder._fault)
                self.assertIsNone(decoder._lanes["data"])
                self.assertEqual(decoder._frame_used, 0)

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
