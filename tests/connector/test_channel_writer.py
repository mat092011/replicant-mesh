"""Focused tests for the bounded, control-priority C2 fragment writer."""

import struct
import tracemalloc
import unittest

from steamboat_connector import channel_wire as wire
from steamboat_connector.channel_writer import (
    ChannelFragmentWriter,
    ChannelWriterError,
    MESSAGE_ID_HISTORY_CAPACITY,
    writer_reservation_overhead_bytes,
)


GENERATION = b"g" * 16


def _writer(*, data_bytes=128_000, control_bytes=8 * wire.MAX_CONTROL_BUNDLE_BYTES,
            initial_sequence=1, fragment_payload_bytes=16_328):
    reserve = writer_reservation_overhead_bytes() + data_bytes + control_bytes
    return ChannelFragmentWriter(
        GENERATION, communication_reservation_bytes=reserve,
        control_byte_capacity=control_bytes,
        initial_sequence=initial_sequence,
        fragment_payload_bytes=fragment_payload_bytes)


def _response(method, data):
    return wire.encode_bundle(method, wire.BUNDLE_RESPONSE,
                              fragment_kind=wire.RESPONSE, protobuf=data)


class ChannelFragmentWriterTests(unittest.TestCase):
    def test_control_request_and_reply_preempt_large_step_response(self):
        step = _response("Step", b"s" * 40_000)
        cancel = wire.encode_bundle(
            "CancelSession", wire.REQUEST, fragment_kind=wire.CONTROL,
            envelope=b"delegation", binding=b"binding", protobuf=b"cancel")
        status = wire.encode_bundle(
            "SessionStatus", wire.BUNDLE_RESPONSE,
            fragment_kind=wire.CONTROL_RESPONSE, protobuf=b"status")
        writer = _writer(data_bytes=len(step) + 32_000)
        self.assertTrue(writer.enqueue(kind=wire.RESPONSE, message_id=b"d" * 16,
                                       payload=step))
        decoder = wire.FragmentDecoder(
            GENERATION, reassembly_capacity=wire.MAX_BUNDLE_BYTES)

        first = writer.next_frame()
        first_message = struct.unpack_from(wire.FRAGMENT_FORMAT, first)
        self.assertEqual((first_message[5], first_message[7]), (1, 0))
        self.assertEqual(list(decoder.feed(first)), [])
        writer.frame_sent(first)
        self.assertTrue(writer.enqueue(kind=wire.CONTROL, message_id=b"c" * 16,
                                       payload=cancel))
        self.assertTrue(writer.enqueue(kind=wire.CONTROL_RESPONSE,
                                       message_id=b"r" * 16, payload=status))

        messages = []
        while writer.pending_bytes or writer.accounting.in_flight_frame_bytes:
            frame = writer.next_frame()
            if frame is None:
                break
            messages.extend(decoder.feed(frame))
            writer.frame_sent(frame)
        decoder.finish()
        self.assertEqual([message.kind for message in messages], [
            wire.CONTROL, wire.CONTROL_RESPONSE, wire.RESPONSE])
        self.assertEqual([message.payload for message in messages],
                         [cancel, status, step])
        self.assertEqual([(message.first_sequence, message.last_sequence)
                          for message in messages], [(2, 2), (3, 3),
                            (1, 5)])
        self.assertEqual(writer.pending_bytes, 0)

    def test_ack_is_required_and_uncertain_send_retires_without_retry(self):
        payload = _response("Step", b"x" * 20_000)
        writer = _writer(data_bytes=50_000)
        self.assertTrue(writer.enqueue(kind=wire.RESPONSE, message_id=b"d" * 16,
                                       payload=payload))
        committed = writer.next_frame()
        with self.assertRaises(ChannelWriterError):
            writer.next_frame()
        with self.assertRaises(ChannelWriterError):
            writer.frame_sent(bytes(memoryview(committed)))
        self.assertTrue(writer.accounting.retired)
        self.assertEqual(writer.pending_bytes, 0)
        self.assertEqual(writer.accounting.in_flight_frame_bytes, 0)
        with self.assertRaises(ChannelWriterError):
            writer.next_frame()
        self.assertFalse(writer.enqueue(kind=wire.RESPONSE, message_id=b"e" * 16,
                                        payload=payload))

    def test_rejected_input_and_queue_pressure_spend_no_sequence_or_id(self):
        small = _response("Step", b"ok")
        too_large = _response("Step", b"x" * 10_000)
        writer = _writer(data_bytes=len(small), control_bytes=100)
        self.assertFalse(writer.enqueue(kind=wire.RESPONSE, message_id=b"z" * 16,
                                        payload=b"not a bundle"))
        self.assertFalse(writer.enqueue(kind=wire.RESPONSE, message_id=b"z" * 16,
                                        payload=too_large))
        self.assertTrue(writer.enqueue(kind=wire.RESPONSE, message_id=b"z" * 16,
                                       payload=small))
        self.assertFalse(writer.enqueue(kind=wire.RESPONSE, message_id=b"q" * 16,
                                        payload=small))
        self.assertEqual(writer.accounting.next_fragment_sequence, 1)
        frame = writer.next_frame()
        header = struct.unpack_from(wire.FRAGMENT_FORMAT, frame)
        self.assertEqual(header[5], 1)
        writer.frame_sent(frame)
        self.assertFalse(writer.enqueue(kind=wire.RESPONSE, message_id=b"z" * 16,
                                        payload=small))

    def test_data_and_control_counts_include_active_control_and_are_bounded(self):
        small = _response("Step", b"x")
        cancel = wire.encode_bundle(
            "CancelSession", wire.REQUEST, fragment_kind=wire.CONTROL,
            envelope=b"e" * wire.MAX_ENVELOPE_BYTES,
            binding=b"b" * wire.MAX_BINDING_BYTES,
            protobuf=b"c" * wire.MAX_CONTROL_PROTOBUF_BYTES)
        writer = _writer(data_bytes=100_000,
                         control_bytes=8 * len(cancel))
        for index in range(8):
            self.assertTrue(writer.enqueue(
                kind=wire.RESPONSE, message_id=(index + 1).to_bytes(16, "big"), payload=small))
        self.assertFalse(writer.enqueue(
            kind=wire.RESPONSE, message_id=b"x" * 16, payload=small))
        for index in range(8):
            self.assertTrue(writer.enqueue(
                kind=wire.CONTROL, message_id=(index + 20).to_bytes(16, "big"),
                payload=cancel))
        frame = writer.next_frame()
        self.assertEqual(writer.accounting.pending_control_messages, 8)
        self.assertFalse(writer.enqueue(kind=wire.CONTROL, message_id=b"y" * 16,
                                        payload=cancel))
        writer.frame_sent(frame)
        self.assertEqual(writer.accounting.pending_control_messages, 8)

    def test_generation_indices_sequence_and_fragment_ceiling_are_exact(self):
        payload = _response("Step", b"p" * 10)
        writer = _writer(data_bytes=100, fragment_payload_bytes=4)
        self.assertTrue(writer.enqueue(kind=wire.RESPONSE, message_id=b"d" * 16,
                                       payload=payload))
        decoder = wire.FragmentDecoder(GENERATION,
                                       reassembly_capacity=wire.MAX_BUNDLE_BYTES)
        outputs = []
        while writer.pending_bytes:
            frame = writer.next_frame()
            header = struct.unpack_from(wire.FRAGMENT_FORMAT, frame)
            self.assertLessEqual(len(frame), 4 + wire.FRAGMENT_HEADER_BYTES)
            outputs.extend(decoder.feed(frame))
            writer.frame_sent(frame)
        decoder.finish()
        self.assertEqual(len(outputs), 1)
        self.assertEqual(outputs[0].payload, payload)
        self.assertEqual(outputs[0].first_sequence, 1)
        self.assertEqual(outputs[0].last_sequence,
                         (len(payload) + 3) // 4)
        self.assertEqual(outputs[0].generation, GENERATION)

    def test_sequence_exhaustion_at_maximum_final_frame_requires_rollover(self):
        payload = _response("Step", b"final")
        writer = _writer(data_bytes=100, initial_sequence=wire.MAX_SEQUENCE)
        self.assertTrue(writer.enqueue(kind=wire.RESPONSE, message_id=b"d" * 16,
                                       payload=payload))
        frame = writer.next_frame()
        header = struct.unpack_from(wire.FRAGMENT_FORMAT, frame)
        self.assertEqual(header[5], wire.MAX_SEQUENCE)
        self.assertTrue(header[2] & wire.END)
        writer.frame_sent(frame)
        self.assertTrue(writer.rollover_required)
        self.assertFalse(writer.enqueue(kind=wire.RESPONSE, message_id=b"e" * 16,
                                        payload=payload))

    def test_suspended_decoder_feed_cannot_be_overlapped_by_next_writer_frame(self):
        payload = _response("Step", b"x")
        writer = _writer(data_bytes=100)
        self.assertTrue(writer.enqueue(kind=wire.RESPONSE,
                                       message_id=b"a" * 16, payload=payload))
        self.assertTrue(writer.enqueue(kind=wire.RESPONSE,
                                       message_id=b"b" * 16, payload=payload))
        decoder = wire.FragmentDecoder(GENERATION,
                                       reassembly_capacity=wire.MAX_BUNDLE_BYTES)
        first = writer.next_frame()
        suspended = decoder.feed(first)
        self.assertEqual(next(suspended).payload, payload)
        writer.frame_sent(first)
        second = writer.next_frame()
        with self.assertRaises(wire.ChannelWireError):
            decoder.feed(second)
        writer.retire()
        self.assertTrue(writer.accounting.retired)
        suspended.close()

    def test_message_id_history_is_exact_and_forces_bounded_rollover(self):
        writer = _writer(data_bytes=1_000_000)
        small = _response("Step", b"x")
        for index in range(MESSAGE_ID_HISTORY_CAPACITY):
            message_id = (index + 1).to_bytes(16, "big")
            self.assertTrue(writer.enqueue(kind=wire.RESPONSE,
                                           message_id=message_id, payload=small))
            frame = writer.next_frame()
            writer.frame_sent(frame)
        self.assertTrue(writer.rollover_required)
        self.assertFalse(writer.enqueue(kind=wire.RESPONSE,
                                        message_id=b"z" * 16, payload=small))

    def test_writer_reservation_covers_validation_queue_and_final_frame_copy(self):
        tracemalloc.start()
        try:
            baseline, _ = tracemalloc.get_traced_memory()
            payload = _response("Step", b"m" * wire.MAX_PROTOBUF_BYTES)
            reservation = (writer_reservation_overhead_bytes()
                           + 8 * wire.MAX_CONTROL_BUNDLE_BYTES
                           + len(payload))
            writer = ChannelFragmentWriter(
                GENERATION, communication_reservation_bytes=reservation)
            self.assertEqual(writer.reservation_bound_bytes, reservation)
            self.assertTrue(writer.enqueue(kind=wire.RESPONSE,
                                           message_id=b"m" * 16, payload=payload))
            frame = writer.next_frame()
            self.assertLessEqual(len(frame), 16_384)
            _, peak = tracemalloc.get_traced_memory()
            self.assertLessEqual(peak - baseline, writer.reservation_bound_bytes)
            writer.retire()
        finally:
            tracemalloc.stop()


if __name__ == "__main__":
    unittest.main()
