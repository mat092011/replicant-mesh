"""M3 static remote-stage validation fixture, not the M4 request scheduler.

The driver relays every activation through one client and runs stage calls
sequentially. The complete model is loaded only as an additional test control.
"""

import argparse
import asyncio
from datetime import datetime, timezone
import importlib.metadata
import json
import os
from pathlib import Path
import platform
import time
import uuid

from .manifest import LAYER_RANGES, artifact_path, load_manifest
from .protocol import PROTOCOL_VERSION
from .protocol.errors import ProtocolError, raise_for_error
from .protocol.worker_pb2 import Request
from .protocol.wire import validate_response


ATOL = 1e-3


def diagnostics(response):
    """Keep bounded scalar diagnostics; never record activations or prompts."""
    fields = ("worker_boot_id", "ready", "layer_start", "layer_end", "hidden_size",
              "active_sessions", "reserved_positions", "allocated_cache_bytes",
              "cache_bytes_exact", "active_operations", "tombstones", "requires_restart",
              "max_sessions", "max_positions_limit", "max_cache_positions", "max_cache_bytes",
              "queued_operations", "max_stage_queue", "process_id",
              "rss_bytes", "peak_rss_bytes", "parameter_bytes", "parameter_count",
              "loading_ms", "dtype", "layout", "model_id", "model_revision")
    return {name: getattr(response, name) for name in fields if hasattr(response, name)}


class RemoteWorkers:
    """Verified static clients with best-effort release of all known leases.

    Preflight every worker before any reservation. No OpenSession or Step retry
    occurs: an ambiguous Open relies on the worker lease for eventual release.
    This fixture deliberately has no request queue, streaming, or scheduling.
    """

    def __init__(self, manifest, clients, input_output=None, evidence=None):
        if len(clients) != 3:
            raise ValueError("Exactly three ordered worker endpoints are required")
        self.manifest, self.clients = manifest, clients
        self.input_output = input_output
        self.evidence = evidence if evidence is not None else {}
        self.boot_ids = []
        self.sessions = set()
        self.timeout_ms = manifest["limits"]["rpc_timeout_seconds"] * 1000

    def request(self, index, **kwargs):
        return Request(protocol_version=PROTOCOL_VERSION,
                       manifest_fingerprint=self.manifest["fingerprint"],
                       worker_boot_id=self.boot_ids[index], timeout_ms=self.timeout_ms, **kwargs)

    async def execute(self, index, method, request):
        response = await self.clients[index].execute(method, request)
        validate_response(method, request, response)
        return raise_for_error(response)

    async def discover(self):
        observed, boot_ids = [], []
        limits = self.manifest["limits"]
        for index in range(3):
            request = Request(protocol_version=PROTOCOL_VERSION,
                              manifest_fingerprint=self.manifest["fingerprint"],
                              timeout_ms=self.timeout_ms)
            response = await self.execute(index, "Describe", request)
            if not response.ready or response.requires_restart:
                raise ProtocolError("EXECUTION_FAILED", f"worker-{index + 1} is not ready")
            expected = {
                "layer_start": LAYER_RANGES[index][0], "layer_end": LAYER_RANGES[index][1],
                "hidden_size": self.manifest["config"]["hidden_size"],
                "max_sessions": limits["max_sessions"], "max_positions_limit": limits["max_positions"],
                "max_message_bytes": limits["max_message_bytes"],
                "max_cache_positions": limits["worker_cache_positions"],
                "max_cache_bytes": limits["worker_cache_bytes"],
                "rpc_timeout_ms": self.timeout_ms,
                "lease_check_interval_ms": limits["lease_check_interval_seconds"] * 1000,
                "max_stage_queue": limits["max_stage_queue"],
            }
            for name, value in expected.items():
                if getattr(response, name) != value:
                    raise ProtocolError("INCOMPATIBLE_MODEL", f"worker-{index + 1} disagrees on {name}")
            if (len(response.worker_boot_id) != 32
                    or any(character not in "0123456789abcdef" for character in response.worker_boot_id)):
                raise ProtocolError("INVALID_INPUT", "Worker has an invalid boot identity")
            if self.boot_ids and response.worker_boot_id != self.boot_ids[index]:
                raise ProtocolError("STALE_WORKER", "Worker restarted; existing driver cannot continue")
            boot_ids.append(response.worker_boot_id)
            observed.append(diagnostics(response))
        if len(set(boot_ids)) != 3:
            raise ProtocolError("INCOMPATIBLE_MODEL", "Workers must have distinct boot identities")
        # Publish discovery only after the entire fixed assignment passes.
        self.boot_ids = boot_ids
        self.evidence.setdefault("preflight", observed)
        return observed

    async def open_session(self, maximum):
        if type(maximum) is not int or not 1 <= maximum <= self.manifest["limits"]["max_positions"]:
            raise ValueError("Context reservation is outside the supported bound")
        await self.discover()
        session = RemoteSession(self, maximum)
        self.sessions.add(session)
        try:
            for index in range(3):
                response = await self.execute(index, "OpenSession", self.request(
                    index, session_id=session.session_id, max_positions=maximum,
                    lifetime_ms=self.manifest["limits"]["request_timeout_seconds"] * 1000,
                    idle_lease_ms=self.manifest["limits"]["idle_lease_seconds"] * 1000))
                session.leases.append(response.lease_token)
            return session
        except BaseException:
            await asyncio.shield(session.close())
            raise

    async def assert_clean(self, label):
        observed = await self.discover()
        self.evidence.setdefault("cleanup", []).append({"case": label, "workers": observed})
        for response in observed:
            if any(response[name] != 0 for name in
                   ("active_sessions", "reserved_positions", "allocated_cache_bytes",
                    "active_operations", "queued_operations")):
                raise AssertionError(f"Worker did not release all session resources after {label}")
            if not response["cache_bytes_exact"]:
                raise AssertionError("Cache byte observations are not exact after cleanup")
        return observed

    async def close(self):
        for session in list(self.sessions):
            await session.close()
        for client in self.clients:
            await client.close()


class RemoteSession:
    def __init__(self, owner, maximum):
        self.owner, self.maximum = owner, maximum
        self.session_id = uuid.uuid4().hex
        self.position = self.sequence = 0
        self.leases = []
        self.closed = False

    def request(self, index, **kwargs):
        return self.owner.request(index, session_id=self.session_id,
                                  lease_token=self.leases[index], **kwargs)

    async def step(self, ids, *, all_logits=False):
        import torch
        from .protocol.codec import decode_tensor, encode_tensor

        if self.closed:
            raise RuntimeError("Session is closed")
        if (not isinstance(ids, torch.Tensor) or ids.device.type != "cpu" or ids.dtype != torch.long
                or ids.ndim != 2 or ids.shape[0] != 1 or ids.shape[1] < 1):
            raise ValueError("Expected nonempty CPU int64 token IDs shaped [1, tokens]")
        if self.position + ids.shape[1] > self.maximum:
            raise ValueError("Session context limit exceeded")
        if int(ids.min()) < 0 or int(ids.max()) >= self.owner.manifest["config"]["vocab_size"]:
            raise ValueError("Input token is outside the pinned vocabulary")
        try:
            with torch.inference_mode():
                hidden = self.owner.input_output.embed_tokens(ids)
            for index in range(3):
                request = self.request(index, sequence=self.sequence, start_position=self.position,
                                       token_count=ids.shape[1], tensor=encode_tensor(hidden))
                started = time.monotonic()
                response = await self.owner.execute(index, "Step", request)
                elapsed = time.monotonic() - started
                hidden = decode_tensor(response.tensor, ids.shape[1])
                self.owner.evidence.setdefault("steps", []).append({
                    "worker": index + 1, "session_id": self.session_id,
                    "worker_boot_id": response.worker_boot_id,
                    "sequence": self.sequence, "start_position": self.position,
                    "token_count": ids.shape[1], "end_position": response.end_position,
                    "queue_ms": response.queue_ms, "compute_ms": response.compute_ms,
                    "client_rpc_ms": elapsed * 1000,
                    "request_bytes": request.ByteSize(), "response_bytes": response.ByteSize(),
                    "activation_bytes_sent": request.tensor.byte_count,
                    "activation_bytes_received": response.tensor.byte_count,
                })
            with torch.inference_mode():
                if not all_logits:
                    hidden = hidden[:, -1:, :]
                logits = self.owner.input_output.lm_head(self.owner.input_output.norm(hidden))
                if not bool(torch.isfinite(logits).all()):
                    raise RuntimeError("Non-finite final logits")
            self.position += ids.shape[1]
            self.sequence += 1
            return logits
        except BaseException:
            # Some stages may have committed. Never retry or reuse that prefix.
            await asyncio.shield(self.close())
            raise

    async def close(self):
        if self.closed:
            return
        self.closed = True
        for index in range(len(self.leases)):
            request = self.request(index)
            request.timeout_ms = min(request.timeout_ms, 5000)
            try:
                response = await self.owner.execute(index, "CloseSession", request)
                if not response.reclaimed:
                    raise ProtocolError("EXECUTION_FAILED", "Close did not reclaim a non-running session")
            except Exception as error:
                self.owner.evidence.setdefault("cleanup_errors", []).append({
                    "worker": index + 1, "error": str(error)[:256],
                    "fallback": "worker lease expiry; no execution replay",
                })
        self.owner.sessions.discard(self)


def _host_evidence():
    import resource
    result = {"platform": platform.platform(), "machine": platform.machine(),
              "python": platform.python_version(), "logical_cpus_visible": os.cpu_count(),
              "torch_threads": int(os.environ.get("OMP_NUM_THREADS", "2")),
              "client_peak_rss_bytes": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss * 1024}
    for key, name in (("memory_limit", "memory.max"), ("cpu_limit", "cpu.max"),
                      ("memory_peak", "memory.peak")):
        path = Path("/sys/fs/cgroup") / name
        if path.is_file():
            result[key] = path.read_text().strip()
    return result


async def run_validation(args, evidence):
    import torch
    from safetensors.torch import load_file
    from transformers import AutoModelForCausalLM, LlamaConfig
    from .model import InputOutput
    from .prepare import verify_snapshot
    from .protocol.codec import encode_tensor
    from .protocol.transport import GrpcClient

    torch.set_num_threads(int(os.environ.get("OMP_NUM_THREADS", "2")))
    manifest = load_manifest(args.artifacts)
    verify_snapshot(args.reference)
    evidence.update({"model_id": manifest["model_id"], "model_revision": manifest["revision"],
                     "manifest_fingerprint": manifest["fingerprint"],
                     "source_files": manifest["source_files"], "limits": manifest["limits"],
                     "dtype": manifest["dtype"], "attention": manifest["attention"],
                     "layout": manifest["layout"], "workers": list(args.workers),
                     "runtime": {name: importlib.metadata.version(name) for name in
                                 ("torch", "transformers", "grpcio", "protobuf", "safetensors")}})
    config = LlamaConfig.from_dict(manifest["config"])
    config._attn_implementation = "eager"
    input_output = InputOutput(config, load_file(str(artifact_path(
        args.artifacts, manifest, "coordinator")), device="cpu"))
    clients = [GrpcClient(target, private_network=True) for target in args.workers]
    remote = RemoteWorkers(manifest, clients, input_output, evidence)
    try:
        started = time.monotonic()
        await remote.discover()
        await remote.assert_clean("before-validation")
        evidence["initial_readiness_seconds"] = time.monotonic() - started
        started = time.monotonic()
        reference = AutoModelForCausalLM.from_pretrained(
            args.reference, dtype=torch.float32, attn_implementation="eager",
            local_files_only=True, use_safetensors=True).eval().requires_grad_(False)
        evidence["control_loading_seconds"] = time.monotonic() - started
        evidence["client_parameter_residency"] = {
            "coordinator_names": [name for name, _ in input_output.named_parameters()],
            "coordinator_bytes": sum(p.numel() * p.element_size() for p in input_output.parameters()),
            "additional_complete_reference_bytes": sum(p.numel() * p.element_size() for p in reference.parameters()),
        }

        def ids(count, offset=0):
            return torch.tensor([[3 + ((i * 37 + offset) % (config.vocab_size - 3))
                                  for i in range(count)]], dtype=torch.long)

        def reference_step(tokens, cache=None):
            with torch.inference_mode():
                result = reference(input_ids=tokens, past_key_values=cache, use_cache=True, return_dict=True)
                return result.logits, result.past_key_values

        def compare(label, actual, expected):
            if actual.shape != expected.shape:
                raise AssertionError(f"{label}: mismatched logit shapes")
            if not bool(torch.isfinite(actual).all()) or not bool(torch.isfinite(expected).all()):
                raise AssertionError(f"{label}: non-finite logits")
            error = float((actual - expected).abs().max())
            evidence.setdefault("comparisons", []).append({"name": label, "shape": list(actual.shape),
                                                           "max_absolute_error": error})
            torch.testing.assert_close(actual, expected, atol=ATOL, rtol=0, msg=label)

        for length in (1, 128, 1024):
            session = await remote.open_session(length + 8)
            try:
                prompt = ids(length)
                expected, cache = reference_step(prompt)
                compare(f"prefill-{length}-all-positions", await session.step(prompt, all_logits=True), expected)
                for step in range(8):
                    token = ids(1, 900 + step * 13)
                    expected, cache = reference_step(token, cache)
                    compare(f"forced-{length}-{step}", await session.step(token), expected)
            finally:
                await session.close()
            await remote.assert_clean(f"prefill-{length}-forced-8")

        first, second = await remote.open_session(256), await remote.open_session(256)
        try:
            expected_a, cache_a = reference_step(ids(7))
            expected_b, cache_b = reference_step(ids(128, 211))
            compare("interleave-A-prefill", await first.step(ids(7)), expected_a[:, -1:, :])
            compare("interleave-B-prefill", await second.step(ids(128, 211)), expected_b[:, -1:, :])
            for step in range(4):
                token_b, token_a = ids(1, 600 + step), ids(1, 300 + step)
                expected_b, cache_b = reference_step(token_b, cache_b)
                compare(f"interleave-B-{step}", await second.step(token_b), expected_b)
                expected_a, cache_a = reference_step(token_a, cache_a)
                compare(f"interleave-A-{step}", await first.step(token_a), expected_a)
            await first.close()
            observed = await remote.discover()
            evidence["partial_cleanup"] = observed
            if any(item["active_sessions"] != 1 or item["reserved_positions"] != 256 for item in observed):
                raise AssertionError("Closing A damaged B's cache reservation")
            token = ids(1, 1111)
            expected_b, cache_b = reference_step(token, cache_b)
            compare("interleave-B-after-A-close", await second.step(token), expected_b)
        finally:
            await first.close()
            await second.close()
        await remote.assert_clean("interleaved-sessions")

        maximum = manifest["limits"]["max_positions"]
        boundary = await remote.open_session(maximum)
        try:
            prompt = ids(maximum - 1, 47)
            expected, cache = reference_step(prompt)
            compare("context-1151", await boundary.step(prompt), expected[:, -1:, :])
            token = ids(1, 2001)
            expected, cache = reference_step(token, cache)
            compare("context-exact-1152", await boundary.step(token), expected)
            with torch.inference_mode():
                hidden = input_output.embed_tokens(token)
            evidence["context_overflow"] = []
            for index, client in enumerate(clients):
                response = await client.execute("Step", boundary.request(
                    index, sequence=boundary.sequence, start_position=boundary.position,
                    token_count=1, tensor=encode_tensor(hidden)))
                if response.code != "INVALID_INPUT":
                    raise AssertionError("Worker accepted a position beyond its reservation")
                status = await remote.execute(index, "SessionStatus", boundary.request(index))
                if status.end_position != maximum or status.next_sequence != boundary.sequence:
                    raise AssertionError("Rejected overflow changed the committed prefix")
                evidence["context_overflow"].append({"worker": index + 1, "code": response.code,
                                                     "position_after_rejection": status.end_position})
        finally:
            await boundary.close()
        await remote.assert_clean("context-boundary")

        admitted = []
        try:
            for index in range(manifest["limits"]["max_sessions"]):
                session = await remote.open_session(maximum)
                admitted.append(session)
                prompt = ids(7, 1234 + index)
                expected, _ = reference_step(prompt)
                compare(f"capacity-session-{index + 1}", await session.step(prompt), expected[:, -1:, :])
            evidence["capacity_at_eight"] = await remote.discover()
            for item in evidence["capacity_at_eight"]:
                if (item["active_sessions"] != 8 or item["reserved_positions"] != maximum * 8
                        or item["allocated_cache_bytes"] <= 0 or not item["cache_bytes_exact"]):
                    raise AssertionError("Eight session reservations/cache allocations are incorrect")
            try:
                unexpected = await remote.open_session(maximum)
            except ProtocolError as error:
                if error.code != "CAPACITY_EXHAUSTED":
                    raise
                evidence["ninth_admission"] = error.code
            else:
                await unexpected.close()
                raise AssertionError("Workers admitted a ninth session")
        finally:
            for session in admitted:
                await session.close()
        await remote.assert_clean("eight-admissions")
        if evidence.get("cleanup_errors"):
            raise AssertionError("One or more known session leases could not be closed")
        evidence["status"] = "passed"
    finally:
        await remote.close()
        evidence["host"] = _host_evidence()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifacts", default=os.environ.get("REPLICANT_MESH_ARTIFACT_DIR", "/artifacts"))
    parser.add_argument("--reference", default=os.environ.get("REPLICANT_MESH_REFERENCE_DIR"), required=not os.environ.get("REPLICANT_MESH_REFERENCE_DIR"))
    parser.add_argument("--workers", nargs=3, default=[f"worker-{i}:50051" for i in (1, 2, 3)])
    parser.add_argument("--output", default="/results", help="Report directory; a unique JSON file is created")
    args = parser.parse_args(argv)
    evidence = {
        "schema_version": 1, "milestone": "M3", "status": "failed",
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "execution": "three remote gRPC workers; sequential client relay",
        "atol": ATOL, "rtol": 0,
        "fixture": {"token_formula": "3 + ((i * 37 + offset) % (vocab_size - 3))",
                    "prefill_lengths": [1, 128, 1024], "prefill_offset": 0,
                    "forced_decode_steps": 8, "forced_offset_formula": "900 + step * 13",
                    "interleaved": {"A": [7, 0], "B": [128, 211],
                                    "decode_offsets_A": [300, 301, 302, 303],
                                    "decode_offsets_B": [600, 601, 602, 603, 1111]},
                    "context_boundary": {"prompt_length": 1151, "offset": 47, "decode_offset": 2001},
                    "capacity": {"sessions": 8, "reservation": 1152, "prompt_length": 7,
                                 "offset_formula": "1234 + session_index"}},
        "limitations": ["trusted private network without authentication or encryption",
                        "same-host containers do not establish separate-device speedup",
                        "sequential validation fixture; no M4 scheduler or compute-overlap claim",
                        "client additionally loads the complete model as a numerical control",
                        "duration diagnostics are observations, not a controlled performance benchmark",
                        "no worker recovery/replay; an interrupted request fails explicitly"],
    }
    started = time.monotonic()
    try:
        asyncio.run(run_validation(args, evidence))
    except Exception as error:
        evidence["status"] = "failed"
        evidence["error"] = {"type": type(error).__name__, "message": str(error)[:1024]}
    evidence["elapsed_seconds"] = time.monotonic() - started
    directory = Path(args.output)
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"{datetime.now(timezone.utc):%Y%m%dT%H%M%S%fZ}-{uuid.uuid4().hex[:8]}-m3-remote.json"
    with path.open("x", encoding="utf-8") as stream:
        json.dump(evidence, stream, indent=2, allow_nan=False)
        stream.write("\n")
    print(json.dumps({"status": evidence["status"], "report": str(path),
                      "comparisons": len(evidence.get("comparisons", [])), "error": evidence.get("error")}))
    return 0 if evidence["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
