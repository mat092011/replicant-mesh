"""Capture/parser bounds for the exact generated C2 Worker protobuf schema.

These controls measure individual parser paths, not whole-role RSS. The Linux
probe uses a fresh isolated CPython process for each fixture.
"""
import json
import os
import site
import subprocess
import sys
import sysconfig
import unittest

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
    shape = _lf(1, b"\x01\x80\x09\x40")
    tensor = (shape + _lf(2, b"float32_le")
              + _lf(3, b"batch_sequence_hidden") + b"\x20\x80\x80\x12"
              + _lf(5, bytes(1152 * 64 * 4)))
    return _lf(13, tensor)


class ChannelCaptureBoundsTests(unittest.TestCase):
    def test_isolated_bootstrap_code_executes(self):
        source_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "src"))
        paths = [source_root, sysconfig.get_path("purelib"), sysconfig.get_path("platlib")]
        bootstrap = "import sys\nsys.path[:0] = " + repr(paths) + "\n"
        result = subprocess.run(
            [sys.executable, "-I", "-S", "-c", bootstrap + "print(sys.path[0])"],
            cwd=os.getcwd(), text=True, capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0,
                         f"isolated bootstrap failed; stdout={result.stdout[-1000:]!r}; "
                         f"stderr={result.stderr[-1000:]!r}")
        self.assertEqual(os.path.normcase(result.stdout.strip()),
                         os.path.normcase(source_root))

    def test_real_generated_worker_proto_accepts_supported_maximum_tensor(self):
        raw = _max_tensor_request()
        self.assertGreater(len(raw), 1152 * 64 * 4)
        self.assertLessEqual(len(raw), channel_wire.MAX_PROTOBUF_BYTES)
        preflight_worker_protobuf(raw, response=False)
        request = Request.FromString(raw)
        self.assertEqual(list(request.tensor.shape), [1, 1152, 64])
        self.assertEqual(request.tensor.byte_count, 1152 * 64 * 4)
        self.assertEqual(len(request.tensor.data), 1152 * 64 * 4)

    def test_near_megabyte_shape_is_denied_by_preflight(self):
        raw = _lf(13, _lf(1, b"\x00" * 900_000))
        self.assertLessEqual(len(raw), channel_wire.MAX_PROTOBUF_BYTES)
        with self.assertRaisesRegex(ChannelProtobufError, "shape exceeds"):
            preflight_worker_protobuf(raw, response=False)

    def test_real_generated_parser_and_preflight_disagree_on_duplicate_singular(self):
        duplicate = b"\x08\x01\x08\x01"
        parsed = Request.FromString(duplicate)
        self.assertEqual(parsed.protocol_version, 1)
        with self.assertRaisesRegex(ChannelProtobufError, "duplicate singular"):
            preflight_worker_protobuf(duplicate, response=False)
        truncated = b"\x08\x80"
        from google.protobuf.message import DecodeError
        with self.assertRaises(DecodeError):
            Request.FromString(truncated)
        with self.assertRaises(ChannelProtobufError):
            preflight_worker_protobuf(truncated, response=False)

    def test_duplicate_nested_and_nonminimal_wire_forms_fail_preflight(self):
        malformed = (
            (b"\x08\x81\x00", "not minimally encoded"),
            (_lf(13, b"\x12\x01a\x12\x01b"), "duplicate singular"),
        )
        for raw, message in malformed:
            with self.subTest(message=message):
                with self.assertRaisesRegex(ChannelProtobufError, message):
                    preflight_worker_protobuf(raw, response=False)

    def test_bounded_control_envelope_and_protobuf(self):
        prefix = b'{"payload":{"frame_sequence":7,"padding":"'
        suffix = b'"}}'
        envelope = prefix + b"x" * (channel_wire.MAX_ENVELOPE_BYTES - len(prefix) - len(suffix)) + suffix
        self.assertEqual(len(envelope), channel_wire.MAX_ENVELOPE_BYTES)
        self.assertEqual(_delegation_sequence(envelope), 7)
        control_raw = _lf(13, _lf(5, b"z" * 8_186))
        self.assertEqual(len(control_raw), channel_wire.MAX_CONTROL_PROTOBUF_BYTES)
        preflight_worker_protobuf(control_raw, response=False,
                                  max_bytes=channel_wire.MAX_CONTROL_PROTOBUF_BYTES)
        bundle = channel_wire.encode_bundle(
            "SessionStatus", channel_wire.REQUEST,
            fragment_kind=channel_wire.CONTROL, envelope=envelope,
            binding=b"b", protobuf=control_raw)
        decoded = channel_wire.decode_bundle(bundle, fragment_kind=channel_wire.CONTROL)
        parsed = Request.FromString(decoded.protobuf)
        self.assertEqual(len(parsed.tensor.data), 8_186)
        for raw in (b"{", b"\xff", b"{}", b"[]", envelope + b"x",
                    b'{"payload":{"frame_sequence":true}}'):
            with self.subTest(length=len(raw)):
                with self.assertRaises(ChannelRpcError):
                    _delegation_sequence(raw)

    @unittest.skipUnless(sys.platform == "linux", "native RSS probe requires Linux /proc and resource")
    def test_isolated_linux_parser_capture_peaks_fit_per_admission_reservations(self):
        source_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "src"))
        paths = [source_root]
        for path in (sysconfig.get_path("purelib"), sysconfig.get_path("platlib"),
                     *site.getsitepackages()):
            if path and path not in paths:
                paths.append(path)
        bootstrap = "import sys\nsys.path[:0] = " + repr(paths) + "\n"
        program = bootstrap + r'''
import gc, json, resource, sys, tracemalloc
from steamboat_connector import channel_wire
from steamboat_connector.channel_protobuf import preflight_worker_protobuf, ChannelProtobufError
from steamboat_connector.channel_rpc import _delegation_sequence, _DATA_CAPTURE_BYTES, _CONTROL_CAPTURE_BYTES
from steamboat_runtime.protocol.worker_pb2 import Request

def v(x):
    b=bytearray()
    while x>127: b.append((x&127)|128); x >>= 7
    b.append(x); return bytes(b)
def lf(n,p): return v((n<<3)|2)+v(len(p))+p
def rss_kib():
    return int(next(x.split()[1] for x in open('/proc/self/status') if x.startswith('VmRSS:')))

mode=sys.argv[1]
gc.collect()
rss_before=rss_kib()
ru_before=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
tracemalloc.start()
owned=[]
if mode == 'max_data':
    shape=lf(1,b"\x01\x80\x09\x40")
    tensor=shape+lf(2,b'float32_le')+lf(3,b'batch_sequence_hidden')+b'\x20\x80\x80\x12'+lf(5,bytes(1152*64*4))
    raw=lf(13,tensor); env=b'{"payload":{"frame_sequence":7}}'
    # Wire-only capture: binding bytes are a placeholder, no valid C1 signature
    # or authorization is represented by this parser memory control.
    bundle=channel_wire.encode_bundle('Step',channel_wire.REQUEST,fragment_kind=channel_wire.DATA,envelope=env,binding=b'b',protobuf=raw)
    decoded=channel_wire.decode_bundle(bundle,fragment_kind=channel_wire.DATA)
    preflight_worker_protobuf(decoded.protobuf,response=False)
    parsed=Request.FromString(decoded.protobuf)
    copied=Request(); copied.CopyFrom(parsed)
    serialized=copied.SerializeToString(); roundtrip=Request.FromString(serialized)
    owned.extend([raw,env,bundle,decoded,parsed,copied,serialized,roundtrip])
    reservation=_DATA_CAPTURE_BYTES
elif mode == 'malformed_shape':
    raw=lf(13,lf(1,b'\x00'*900_000)); env=b'{"payload":{"frame_sequence":7}}'
    bundle=channel_wire.encode_bundle('Step',channel_wire.REQUEST,fragment_kind=channel_wire.DATA,envelope=env,binding=b'b',protobuf=raw)
    decoded=channel_wire.decode_bundle(bundle,fragment_kind=channel_wire.DATA)
    try: preflight_worker_protobuf(decoded.protobuf,response=False)
    except ChannelProtobufError as e:
        if 'shape exceeds' not in str(e): raise
        rejected=True
    else: rejected=False
    owned.extend([raw,env,bundle,decoded])
    if not rejected: raise AssertionError('oversized repeated shape was accepted')
    reservation=_DATA_CAPTURE_BYTES
elif mode == 'control_density':
    pre=b'{"payload":{"frame_sequence":7,"padding":['; post=b']}}'
    entry=b'{"a":0}'
    count=(channel_wire.MAX_ENVELOPE_BYTES-len(pre)-len(post)+1)//(len(entry)+1)
    env=pre+b','.join([entry]*count)+post
    env += b' '*(channel_wire.MAX_ENVELOPE_BYTES-len(env))
    raw=lf(13,lf(5,b'z'*8186))
    bundle=channel_wire.encode_bundle('SessionStatus',channel_wire.REQUEST,fragment_kind=channel_wire.CONTROL,envelope=env,binding=b'b',protobuf=raw)
    decoded=channel_wire.decode_bundle(bundle,fragment_kind=channel_wire.CONTROL)
    preflight_worker_protobuf(decoded.protobuf,response=False,max_bytes=channel_wire.MAX_CONTROL_PROTOBUF_BYTES)
    sequence=_delegation_sequence(decoded.envelope)
    parsed=Request.FromString(decoded.protobuf)
    copied=Request(); copied.CopyFrom(parsed)
    serialized=copied.SerializeToString(); roundtrip=Request.FromString(serialized)
    if sequence != 7 or len(roundtrip.tensor.data) != 8186: raise AssertionError('control parse mismatch')
    owned.extend([raw,env,bundle,decoded,parsed,copied,serialized,roundtrip])
    reservation=_CONTROL_CAPTURE_BYTES
else: raise AssertionError('unknown probe mode')
current,python_peak=tracemalloc.get_traced_memory()
rss_after=rss_kib()
ru_after=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
# Linux ru_maxrss is KiB. The baseline may already include higher import RSS.
highwater_informative=(ru_before <= rss_before and ru_after > ru_before)
native_delta=(ru_after-ru_before)*1024 if highwater_informative else None
if python_peak > reservation: raise AssertionError('Python traced peak exceeds per-admission capture reservation')
if highwater_informative and native_delta > reservation: raise AssertionError('native high-water delta exceeds per-admission capture reservation')
print(json.dumps({'mode':mode,'python_tracemalloc_current_bytes':current,'python_tracemalloc_peak_bytes':python_peak,
 'per_admission_reservation_bytes':reservation,'linux_vm_rss_before_kib':rss_before,'linux_vm_rss_after_kib':rss_after,
 'linux_vm_rss_delta_kib':rss_after-rss_before,'linux_ru_maxrss_before_kib':ru_before,'linux_ru_maxrss_after_kib':ru_after,
 'linux_native_peak_delta_bytes':native_delta,'linux_native_peak_status':'measured' if highwater_informative else 'unmeasured: baseline high-water masked or target did not advance it',
 'retained_owner_count':len(owned)}))
'''
        env = os.environ.copy()
        env.pop("PYTHONPATH", None)
        env.pop("PYTHONHOME", None)
        for mode in ("max_data", "malformed_shape", "control_density"):
            with self.subTest(mode=mode):
                result = subprocess.run(
                    [sys.executable, "-I", "-S", "-c", program, mode],
                    cwd=os.getcwd(), env=env, text=True, capture_output=True,
                    check=False, timeout=30)
                self.assertEqual(result.returncode, 0,
                                 f"isolated {mode} probe failed; "
                                 f"stdout={result.stdout[-2000:]!r}; "
                                 f"stderr={result.stderr[-2000:]!r}")
                measurement = json.loads(result.stdout.strip().splitlines()[-1])
                self.assertLessEqual(measurement["python_tracemalloc_peak_bytes"],
                                     measurement["per_admission_reservation_bytes"])
                if measurement["linux_native_peak_status"] == "measured":
                    self.assertLessEqual(measurement["linux_native_peak_delta_bytes"],
                                         measurement["per_admission_reservation_bytes"])
                print("capture parser subprocess measurement:", json.dumps(measurement, sort_keys=True))


if __name__ == "__main__":
    unittest.main()
