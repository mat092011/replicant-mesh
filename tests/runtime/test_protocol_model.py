"""M2 numerical checks through bounded Protobuf messages and isolated KV owners.

These tests require REPLICANT_MESH_PROTOCOL_TESTS=1 and the offline artifact/reference
paths. They execute three independent handlers inside one process. The additional
loopback gRPC check exercises the binary RPC adapter; neither proves separate
worker processes, network performance, a scheduler, or useful compute overlap.
"""

from datetime import datetime, timezone
import importlib.metadata
import json
import os
from pathlib import Path
import unittest
import uuid


ATOL = 1e-3
ARTIFACT_DIR = os.environ.get("REPLICANT_MESH_ARTIFACT_DIR")
REFERENCE_DIR = os.environ.get("REPLICANT_MESH_REFERENCE_DIR")
ENABLED = os.environ.get("REPLICANT_MESH_PROTOCOL_TESTS") == "1"


class _Session:
    """A test driver, not the M4 coordinator/scheduler implementation."""

    def __init__(self, case, maximum):
        self.case = case
        self.maximum = maximum
        self.session_id = uuid.uuid4().hex
        self.position = 0
        self.sequence = 0
        self.leases = []

    async def open(self):
        for index, transport in enumerate(self.case.transports):
            request = self.case.request(index, session_id=self.session_id,
                                        max_positions=self.maximum, lifetime_ms=300000,
                                        idle_lease_ms=120000)
            response = await transport.execute("OpenSession", request)
            self.case.assert_ok(response)
            self.case.assertEqual(response.max_positions, self.maximum)
            self.leases.append(response.lease_token)
        return self

    def request(self, index, **kwargs):
        return self.case.request(index, session_id=self.session_id,
                                 lease_token=self.leases[index], **kwargs)

    def step_request(self, index, hidden):
        return self.request(index, sequence=self.sequence, start_position=self.position,
                            token_count=hidden.shape[1], tensor=self.case.encode(hidden))

    async def step(self, ids, *, all_logits=False):
        case = self.case
        with case.torch.inference_mode():
            hidden = case.input_output.embed_tokens(ids)
        for index, transport in enumerate(case.transports):
            request = self.step_request(index, hidden)
            response = await transport.execute("Step", request)
            case.assert_ok(response)
            case.assertEqual(response.session_id, self.session_id)
            case.assertEqual(response.lease_token, self.leases[index])
            case.assertEqual(response.worker_boot_id, case.boot_ids[index])
            case.assertEqual(response.manifest_fingerprint, case.manifest["fingerprint"])
            case.assertEqual(response.sequence, self.sequence)
            case.assertEqual(response.start_position, self.position)
            case.assertEqual(response.token_count, ids.shape[1])
            case.assertEqual(response.end_position, self.position + ids.shape[1])
            case.assertEqual(response.next_sequence, self.sequence + 1)
            case.assertGreaterEqual(response.queue_ms, 0)
            case.assertGreaterEqual(response.compute_ms, 0)
            hidden = case.decode(response.tensor, ids.shape[1])
            case.evidence["step_messages"] += 1
            case.evidence["activation_payload_bytes_sent"] += request.tensor.byte_count
            case.evidence["activation_payload_bytes_received"] += response.tensor.byte_count
        self.position += ids.shape[1]
        self.sequence += 1
        with case.torch.inference_mode():
            if not all_logits:
                hidden = hidden[:, -1:, :]
            return case.input_output.lm_head(case.input_output.norm(hidden))

    async def close(self):
        for index in range(len(self.leases)):
            response = await self.case.transports[index].execute(
                "CloseSession", self.request(index))
            self.case.assert_ok(response)
            self.case.assertTrue(response.reclaimed)


@unittest.skipUnless(ENABLED,
                     "Set REPLICANT_MESH_PROTOCOL_TESTS=1 for offline real-model M2 checks")
class ProtocolModelTests(unittest.IsolatedAsyncioTestCase):
    @classmethod
    def setUpClass(cls):
        if not ARTIFACT_DIR or not REFERENCE_DIR:
            raise RuntimeError("M2 checks need REPLICANT_MESH_ARTIFACT_DIR and REPLICANT_MESH_REFERENCE_DIR")
        import torch
        from safetensors.torch import load_file
        from transformers import AutoModelForCausalLM, LlamaConfig
        from replicant_mesh.manifest import artifact_path, load_manifest
        from replicant_mesh.model import InputOutput
        from replicant_mesh.prepare import verify_snapshot
        from replicant_mesh.protocol import PROTOCOL_VERSION
        from replicant_mesh.protocol.codec import encode_tensor, decode_tensor
        from replicant_mesh.protocol.worker_pb2 import Request
        from replicant_mesh.protocol.transport import InMemoryTransport
        from replicant_mesh.worker_state import StageExecutor, WorkerHandler

        cls.torch = torch
        cls.Request = Request
        cls.protocol_version = PROTOCOL_VERSION
        cls.Handler = WorkerHandler
        cls.Transport = InMemoryTransport
        cls.encode = staticmethod(encode_tensor)
        cls.decode = staticmethod(decode_tensor)
        torch.set_num_threads(int(os.environ.get("OMP_NUM_THREADS", "2")))
        verify_snapshot(REFERENCE_DIR)
        cls.reference = AutoModelForCausalLM.from_pretrained(
            REFERENCE_DIR, dtype=torch.float32, attn_implementation="eager",
            local_files_only=True,
        ).eval()
        cls.manifest = load_manifest(ARTIFACT_DIR)
        config = LlamaConfig.from_dict(cls.manifest["config"])
        config._attn_implementation = "eager"
        cls.input_output = InputOutput(config, load_file(str(artifact_path(
            ARTIFACT_DIR, cls.manifest, "coordinator")), device="cpu"))
        cls.executors = [StageExecutor(ARTIFACT_DIR, f"worker-{index}")
                         for index in (1, 2, 3)]
        cls.evidence = {
            "created_utc": datetime.now(timezone.utc).isoformat(),
            "runtime": {name: importlib.metadata.version(name) for name in
                        ("torch", "transformers", "grpcio", "protobuf", "safetensors")},
            "execution": "three in-process handlers; binary Protobuf round trips; one loopback gRPC check",
            "atol": ATOL, "rtol": 0,
            "model_revision": cls.manifest["revision"],
            "manifest_fingerprint": cls.manifest["fingerprint"],
            "fixture": "token[i] = 3 + ((i * 37 + offset) % (vocab_size - 3))",
            "comparisons": [], "cleanup": [], "step_messages": 0,
            "activation_payload_bytes_sent": 0, "activation_payload_bytes_received": 0,
            "limitations": ["not separate worker processes", "not network-performance evidence",
                            "no coordinator scheduler", "no compute-overlap claim"],
        }

    @classmethod
    def tearDownClass(cls):
        output = os.environ.get("REPLICANT_MESH_PROTOCOL_REPORT")
        if output:
            path = Path(output)
            if path.suffix != ".json":
                path /= f"{datetime.now(timezone.utc):%Y%m%dT%H%M%S%fZ}-m2-validation.json"
            path.parent.mkdir(parents=True, exist_ok=True)
            with path.open("x", encoding="utf-8") as stream:
                stream.write(json.dumps(cls.evidence, indent=2, allow_nan=False) + "\n")
            print(f"M2 numerical observations: {path}")

    async def asyncSetUp(self):
        self.sessions = []
        self.handlers = [self.Handler(self.manifest, executor.worker_name, executor)
                         for executor in self.executors]
        self.transports = [self.Transport(handler) for handler in self.handlers]
        self.boot_ids = []
        for index, transport in enumerate(self.transports):
            response = await transport.execute("Describe", self.Request(
                protocol_version=self.protocol_version, timeout_ms=30000))
            self.assert_ok(response)
            self.assertTrue(response.ready)
            self.assertEqual((response.layer_start, response.layer_end),
                             ((0, 3), (3, 6), (6, 8))[index])
            self.boot_ids.append(response.worker_boot_id)

    async def asyncTearDown(self):
        cleanup_errors = []
        for session in self.sessions:
            try:
                await session.close()
            except Exception as error:
                cleanup_errors.append(str(error))
        for handler in self.handlers:
            self.assertTrue(await handler.shutdown())
        # Keep the observed cleanup state even when an assertion above failed.
        state = []
        for index, transport in enumerate(self.transports):
            response = await transport.execute("Describe", self.request(index))
            state.append({"worker": index + 1, "active_sessions": response.active_sessions,
                          "reserved_positions": response.reserved_positions,
                          "allocated_cache_bytes": response.allocated_cache_bytes,
                          "requires_restart": response.requires_restart})
            self.assertEqual(response.active_sessions, 0)
            self.assertEqual(response.reserved_positions, 0)
            self.assertEqual(response.allocated_cache_bytes, 0)
            self.assertFalse(response.requires_restart)
        self.evidence["cleanup"].append({"test": self.id().rsplit(".", 1)[-1], "workers": state})
        self.assertEqual(cleanup_errors, [])

    def request(self, index, **kwargs):
        return self.Request(protocol_version=self.protocol_version,
                            manifest_fingerprint=self.manifest["fingerprint"],
                            worker_boot_id=self.boot_ids[index], timeout_ms=30000, **kwargs)

    def assert_ok(self, response):
        self.assertEqual(response.code, "OK", f"{response.code}: {response.message}")

    async def open_session(self, maximum):
        session = _Session(self, maximum)
        self.sessions.append(session)
        return await session.open()

    def ids(self, count, offset=0):
        values = [3 + ((i * 37 + offset) % (self.reference.config.vocab_size - 3))
                  for i in range(count)]
        return self.torch.tensor([values], dtype=self.torch.long)

    def reference_step(self, ids, cache=None):
        with self.torch.inference_mode():
            output = self.reference(input_ids=ids, past_key_values=cache,
                                    use_cache=True, return_dict=True)
        return output.logits, output.past_key_values

    def assert_logits(self, name, actual, expected):
        self.assertEqual(tuple(actual.shape), tuple(expected.shape))
        self.assertTrue(bool(self.torch.isfinite(actual).all()), name)
        self.assertTrue(bool(self.torch.isfinite(expected).all()), name)
        error = float((actual - expected).abs().max())
        self.evidence["comparisons"].append({"name": name, "shape": list(actual.shape),
                                            "max_absolute_error": error})
        self.torch.testing.assert_close(actual, expected, atol=ATOL, rtol=0, msg=name)

    async def test_every_prefill_logit_and_eight_forced_decode_steps(self):
        for prompt_length in (1, 128, 1024):
            with self.subTest(prompt_length=prompt_length):
                session = await self.open_session(prompt_length + 8)
                prompt = self.ids(prompt_length)
                expected, reference_cache = self.reference_step(prompt)
                self.assert_logits(f"prefill-{prompt_length}",
                                   await session.step(prompt, all_logits=True), expected)
                for step in range(8):
                    token = self.ids(1, offset=900 + step * 13)
                    expected, reference_cache = self.reference_step(token, reference_cache)
                    self.assert_logits(f"forced-{prompt_length}-{step}",
                                       await session.step(token), expected)
                self.assertEqual(session.position, prompt_length + 8)
                await session.close()

    async def test_interleaved_sessions_release_independent_cache(self):
        first, second = await self.open_session(256), await self.open_session(256)
        first_ids, second_ids = self.ids(7), self.ids(128, offset=211)
        expected_first, first_cache = self.reference_step(first_ids)
        expected_second, second_cache = self.reference_step(second_ids)
        self.assert_logits("interleave-A-prefill", await first.step(first_ids), expected_first[:, -1:, :])
        self.assert_logits("interleave-B-prefill", await second.step(second_ids), expected_second[:, -1:, :])
        for step in range(4):
            second_ids, first_ids = self.ids(1, offset=600 + step), self.ids(1, offset=300 + step)
            expected_second, second_cache = self.reference_step(second_ids, second_cache)
            self.assert_logits(f"interleave-B-{step}", await second.step(second_ids), expected_second)
            expected_first, first_cache = self.reference_step(first_ids, first_cache)
            self.assert_logits(f"interleave-A-{step}", await first.step(first_ids), expected_first)
        for index, transport in enumerate(self.transports):
            status = await transport.execute("SessionStatus", second.request(index))
            self.assert_ok(status)
            self.assertEqual(status.end_position, 132)
            self.assertGreater(status.allocated_cache_bytes, 0)
        await first.close()
        for index, transport in enumerate(self.transports):
            status = await transport.execute("Describe", self.request(index))
            self.assert_ok(status)
            self.assertEqual(status.active_sessions, 1)
            self.assertEqual(status.reserved_positions, 256)
        token = self.ids(1, offset=1111)
        expected_second, second_cache = self.reference_step(token, second_cache)
        self.assert_logits("interleave-B-after-A-close", await second.step(token), expected_second)
        self.assertEqual(second.position, 133)

    async def test_lost_response_is_not_replayed_and_other_session_survives(self):
        lost, survivor = await self.open_session(64), await self.open_session(64)
        prompt = self.ids(7, offset=827)
        expected, reference_cache = self.reference_step(prompt)
        self.assert_logits("lost-response-survivor-prefill", await survivor.step(prompt), expected[:, -1:, :])
        with self.torch.inference_mode():
            hidden = self.input_output.embed_tokens(self.ids(11))
        request = lost.step_request(0, hidden)
        discarded = await self.transports[0].execute("Step", request)
        self.assert_ok(discarded)
        # Simulate losing a successful response after the worker committed it.
        del discarded
        retry = await self.transports[0].execute("Step", request)
        self.assertEqual(retry.code, "OUT_OF_ORDER")
        status = await self.transports[0].execute("SessionStatus", lost.request(0))
        self.assert_ok(status)
        self.assertEqual(status.end_position, 11)
        self.assertEqual(status.next_sequence, 1)
        await lost.close()
        token = self.ids(1, offset=828)
        expected, reference_cache = self.reference_step(token, reference_cache)
        self.assert_logits("lost-response-survivor-decode", await survivor.step(token), expected)
        self.evidence["lost_response"] = {"retry_code": retry.code, "committed_position": status.end_position,
                                           "next_sequence": status.next_sequence,
                                           "action": "discard response; reject retry; close all affected reservations"}

    async def test_loopback_grpc_real_stage_matches_binary_in_memory_stage(self):
        from replicant_mesh.protocol.transport import GrpcClient, create_server

        server, port = await create_server(self.handlers[0])
        client = GrpcClient(f"127.0.0.1:{port}")
        try:
            response = await client.execute("Describe", self.request(0))
            self.assert_ok(response)
            self.assertEqual(response.worker_boot_id, self.boot_ids[0])
            session_id = uuid.uuid4().hex
            opened = await client.execute("OpenSession", self.request(
                0, session_id=session_id, max_positions=16,
                lifetime_ms=300000, idle_lease_ms=120000))
            self.assert_ok(opened)
            with self.torch.inference_mode():
                hidden = self.input_output.embed_tokens(self.ids(7))
                cache = self.executors[0].new_cache()
                expected = self.executors[0].execute(hidden.clone(), cache, 0)
            request = self.request(0, session_id=session_id, lease_token=opened.lease_token,
                                   sequence=0, start_position=0, token_count=7,
                                   tensor=self.encode(hidden))
            response = await client.execute("Step", request)
            self.assert_ok(response)
            self.assert_logits("loopback-grpc-stage-1", self.decode(response.tensor, 7), expected)
            closed = await client.execute("CloseSession", self.request(
                0, session_id=session_id, lease_token=opened.lease_token))
            self.assert_ok(closed)
            self.assertTrue(closed.reclaimed)
            cache.clear()
            self.evidence["loopback_grpc"] = {"stage": [0, 3], "tokens": 7,
                                                "end_position": response.end_position,
                                                "reclaimed": closed.reclaimed}
        finally:
            await client.close()
            await server.stop(0)


if __name__ == "__main__":
    unittest.main()
