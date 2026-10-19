"""Capture/parser bounds for the exact generated C2 Worker protobuf schema.

These controls measure the parsers themselves. They do not represent the peak
RSS of a worker or coordinator role, which also owns transport, TLS, queues,
model state and other concurrent requests.
"""
import json
import os
import subprocess
import sys
import unittest
from unittest import mock

from steamboat_connector import channel_wire
from steamboat_connector.channel_protobuf import (
    ChannelProtobufError, preflight_worker_protobuf,
)
from steamboat_connector.channel_rpc import ChannelRpcError, _delegation_sequence
from steamboat_runtime.protocol.worker_pb2 import Request


def _v(value):
    out = bytearray()
    while value > 0x7f:
        out.append((value & 0x7f) | 0x80)
        value >>= 7
    out.append(value)
    return bytes(out)


def _lf(field, payload):
    return _v((field << 3) | 2) + _v(len(payload)) + payload


def _max_tensor_request():
    # TensorEnvelope: shape=[1,1152,64], dtype/layout, byte_count and data.
    shape = _lf(1, b"\x01\x80\x09\x40")
    tensor = (shape + _lf(2, b"float32_le")
              + _lf(3, b"batch_sequence_hidden") + b"\x20\x80\x80\x12"
              + _lf(5, bytes(1152 * 64 * 4)))
    return _lf(13, tensor)


class ChannelCaptureBoundsTests(unittest.TestCase):
    def test_real_generated_worker_proto_accepts_supported_maximum_tensor(self):
        raw = _max_tensor_request()
        self.assertGreater(len(raw), 1152 * 64 * 4)
        self.assertLessEqual(len(raw), channel_wire.MAX_PROTOBUF_BYTES)
        preflight_worker_protobuf(raw, response=False)
        request = Request.FromString(raw)
        self.assertEqual(list(request.tensor.shape), [1, 1152, 64])
        self.assertEqual(request.tensor.byte_count, 1152 * 64 * 4)
        self.assertEqual(len(request.tensor.data), 1152 * 64 * 4)

    def test_near_megabyte_shape_is_denied_before_parse_stage(self):
        # A legal protobuf length-delimited field carrying 1 MiB zero varints
        # can expand into millions of native repeated-field entries.
        packed = b"\x00" * 900_000
        nested = _lf(1, packed)
        raw = _lf(13, nested)
        self.assertLessEqual(len(raw), channel_wire.MAX_PROTOBUF_BYTES)
        parse_stage = mock.Mock(side_effect=Request.FromString)
        with self.assertRaisesRegex(ChannelProtobufError, "shape exceeds"):
            preflight_worker_protobuf(raw, response=False)
            parse_stage(raw)
        parse_stage.assert_not_called()

    def test_duplicate_and_nonminimal_wire_forms_fail_preflight(self):
        malformed = (
            (b"\x08\x01\x08\x01", "duplicate singular"),
            (b"\x08\x81\x00", "not minimally encoded"),
            # Duplicate nested singular dtype field.
            (_lf(13, b"\x12\x01a\x12\x01b"), "duplicate singular"),
        )
        for raw, message in malformed:
            with self.subTest(message=message):
                with self.assertRaisesRegex(ChannelProtobufError, message):
                    preflight_worker_protobuf(raw, response=False)

    def test_bounded_control_envelope_and_invalid_inputs(self):
        # Keep the largest accepted envelope well-formed and close to its wire
        # ceiling, exercising actual UTF-8 decode plus json.loads.
        prefix = b'{"payload":{"frame_sequence":7,"padding":"'
        suffix = b'"}}'
        envelope = prefix + b"x" * (channel_wire.MAX_ENVELOPE_BYTES - len(prefix) - len(suffix)) + suffix
        self.assertEqual(len(envelope), channel_wire.MAX_ENVELOPE_BYTES)
        self.assertEqual(_delegation_sequence(envelope), 7)
        # Exercise the control protobuf ceiling through bundle encoding,
        # decoding, preflight and the actual generated Request parser.
        control_raw = _lf(13, _lf(5, b"z" * 8_186))
        self.assertEqual(len(control_raw), channel_wire.MAX_CONTROL_PROTOBUF_BYTES)
        preflight_worker_protobuf(control_raw, response=False,
                                  max_bytes=channel_wire.MAX_CONTROL_PROTOBUF_BYTES)
        control_bundle = channel_wire.encode_bundle(
            "SessionStatus", channel_wire.REQUEST,
            fragment_kind=channel_wire.CONTROL, envelope=envelope,
            binding=b"b", protobuf=control_raw)
        decoded = channel_wire.decode_bundle(
            control_bundle, fragment_kind=channel_wire.CONTROL)
        parsed = Request.FromString(decoded.protobuf)
        self.assertEqual(len(parsed.tensor.data), 8_186)
        for raw in (b"{", b"\xff", b"{}", b"[]", envelope + b"x",
                    b'{"payload":{"frame_sequence":true}}'):
            with self.subTest(length=len(raw)):
                with self.assertRaises(ChannelRpcError):
                    _delegation_sequence(raw)

    @unittest.skipUnless(sys.platform == "linux", "native RSS probe requires Linux /proc and resource")
    def test_fresh_linux_subprocess_reports_python_and_native_parser_peaks(self):
        # Imports happen before both baselines, so module import RSS cannot be
        # mistaken for target parser growth. Values are reported for evidence;
        # pass/fail comes from semantic bounds above, not a brittle RSS cutoff.
        program = r'''
import gc, json, resource, sys, tracemalloc
from pathlib import Path
from steamboat_connector import channel_wire
from steamboat_connector.channel_protobuf import preflight_worker_protobuf, ChannelProtobufError
from steamboat_connector.channel_rpc import _delegation_sequence, ChannelRpcError
from steamboat_runtime.protocol.worker_pb2 import Request

def v(x):
    b=bytearray()
    while x>127: b.append((x&127)|128); x >>= 7
    b.append(x); return bytes(b)
def lf(n,p): return v((n<<3)|2)+v(len(p))+p
shape=lf(1,b"\x01\x80\x09\x40")
tensor=shape+lf(2,b"float32_le")+lf(3,b"batch_sequence_hidden")+b"\x20\x80\x80\x12"+lf(5,bytes(1152*64*4))
valid=lf(13,tensor)
bad=lf(13,lf(1,bytes(900000)))
prefix=b'{"payload":{"frame_sequence":7,"padding":"'; suffix=b'"}}'
env=prefix+b'x'*(channel_wire.MAX_ENVELOPE_BYTES-len(prefix)-len(suffix))+suffix
gc.collect()
rss_before=int(next(x.split()[1] for x in open('/proc/self/status') if x.startswith('VmRSS:')))
ru_before=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
tracemalloc.start()
preflight_worker_protobuf(valid,response=False); obj=Request.FromString(valid)
_delegation_sequence(env)
try: preflight_worker_protobuf(bad,response=False)
except ChannelProtobufError: pass
else: raise AssertionError('malformed repeated shape accepted')
current, peak=tracemalloc.get_traced_memory()
rss_after=int(next(x.split()[1] for x in open('/proc/self/status') if x.startswith('VmRSS:')))
ru_after=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
print(json.dumps({'python_tracemalloc_current_bytes':current,'python_tracemalloc_peak_bytes':peak,
 'linux_vm_rss_before_kib':rss_before,'linux_vm_rss_after_kib':rss_after,
 'linux_ru_maxrss_before_kib':ru_before,'linux_ru_maxrss_after_kib':ru_after,
 'valid_request_bytes':len(valid),'malformed_request_bytes':len(bad),'envelope_bytes':len(env),
 'parsed_shape':list(obj.tensor.shape)}))
'''
        env = os.environ.copy()
        source_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "src"))
        env["PYTHONPATH"] = source_root + os.pathsep + env.get("PYTHONPATH", "")
        result = subprocess.run([sys.executable, "-c", program], cwd=os.getcwd(), env=env,
                                text=True, capture_output=True, check=True, timeout=30)
        measurement = json.loads(result.stdout.strip().splitlines()[-1])
        self.assertEqual(measurement["parsed_shape"], [1, 1152, 64])
        self.assertGreater(measurement["python_tracemalloc_peak_bytes"], 0)
        self.assertGreater(measurement["linux_ru_maxrss_after_kib"], 0)
        print("capture parser subprocess measurement:", json.dumps(measurement, sort_keys=True))


if __name__ == "__main__":
    unittest.main()
