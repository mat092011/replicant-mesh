"""Correctness checks and a closed-loop CPU inference experiment for the private lab."""

import argparse
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack
from datetime import datetime, timezone
import importlib.metadata
import json
import math
import os
from pathlib import Path
import platform
import subprocess
import threading
import time
from typing import TYPE_CHECKING
import uuid

from lab.config import model_settings, percentile, read_peers, summarize_requests

if TYPE_CHECKING:
    from replicant_mesh.interfaces import InferenceSession

FIXTURE = "A network of computers cooperates to calculate the next token. "
MAX_SESSION_TOKENS = 1152


def validate_workload(prompt_tokens, new_tokens, concurrency, requests):
    if min(prompt_tokens, new_tokens, concurrency, requests) < 1:
        raise ValueError("Prompt, output, concurrency, and request counts must be positive")
    if prompt_tokens + new_tokens > MAX_SESSION_TOKENS:
        raise ValueError(f"Prompt plus output must be at most {MAX_SESSION_TOKENS} tokens")
    if concurrency > 8:
        raise ValueError("This lab admits at most eight concurrent sessions")


def fixture_ids(tokenizer, count):
    tokens = tokenizer.encode(FIXTURE, add_special_tokens=False)
    if not tokens:
        raise ValueError("The fixture must produce at least one token")
    return (tokens * ((count + len(tokens) - 1) // len(tokens)))[:count]


class LocalSession:
    def __init__(self, model, max_length):
        self.model = model
        self.max_length = max_length
        self.position = 0
        self.cache = None
        self.closed = False

    def __enter__(self):
        if self.closed:
            raise RuntimeError("Session is closed")
        return self

    def step(self, ids, *, return_all_logits=False):
        if self.closed:
            raise RuntimeError("Session is closed")
        if self.position + ids.shape[1] > self.max_length:
            raise ValueError("Session context limit exceeded")
        result = self.model.base_model(
            input_ids=ids, past_key_values=self.cache, use_cache=True, return_dict=True,
        )
        self.cache = result.past_key_values
        self.position += ids.shape[1]
        hidden = result.last_hidden_state
        return self.model.lm_head(hidden if return_all_logits else hidden[:, -1:, :])

    def diagnostics(self):
        return {"position": self.position, "max_length": self.max_length, "closed": self.closed}

    def close(self):
        self.cache = None
        self.closed = True

    def __exit__(self, *_):
        self.close()


class RemoteSession:
    def __init__(self, model, max_length):
        from petals.client.inference_session import InferenceSession

        self.model = model
        self.remote = InferenceSession(model.transformer.h.sequence_manager, max_length)
        self.closed = False

    def __enter__(self):
        self.remote.__enter__()
        return self

    @property
    def position(self):
        return self.remote.position

    def step(self, ids, *, return_all_logits=False):
        if self.closed:
            raise RuntimeError("Session is closed")
        transformer = self.model.transformer
        embeddings = transformer.word_embeddings_layernorm(transformer.word_embeddings(ids))
        hidden = self.remote.step(embeddings)
        return self.model.lm_head(transformer.ln_f(hidden if return_all_logits else hidden[:, -1:, :]))

    def diagnostics(self):
        return {"position": self.position, "closed": self.closed}

    def close(self):
        if not self.closed:
            self.remote.close()
            self.closed = True

    def __exit__(self, *_):
        self.close()


def load_model(mode, backend="petals", artifacts="/artifacts", reference=None):
    import torch
    from transformers import AutoModelForCausalLM, AutoTokenizer

    torch.set_num_threads(int(os.environ.get("OMP_NUM_THREADS", "2")))
    if backend == "pytorch":
        from replicant_mesh.backends import load_model as load_pytorch_model

        return load_pytorch_model(mode, artifacts, reference)
    if backend != "petals":
        raise ValueError(f"Unknown backend: {backend}")
    model_id, revision = model_settings()
    kwargs = dict(revision=revision, torch_dtype=torch.float32,
                  local_files_only=True, attn_implementation="eager")
    started = time.perf_counter()
    tokenizer = AutoTokenizer.from_pretrained(model_id, revision=revision, local_files_only=True)
    if mode == "local":
        model = AutoModelForCausalLM.from_pretrained(model_id, **kwargs)
    else:
        from petals import AutoDistributedModelForCausalLM

        model = AutoDistributedModelForCausalLM.from_pretrained(
            model_id, initial_peers=read_peers(),
            dht_prefix=os.environ.get("LAB_DHT_PREFIX", "replicant-mesh-local-v1"),
            use_server_to_server=False,
            request_timeout=30, connect_timeout=5,
            max_retries=int(os.environ.get("PETALS_MAX_RETRIES", "2")), **kwargs,
        )
    model.eval()
    return model, tokenizer, time.perf_counter() - started


def make_session(model, mode, max_length) -> "InferenceSession":
    if getattr(model, "runtime_backend", None) == "pytorch":
        return model.open_session(max_length)
    return (LocalSession if mode == "local" else RemoteSession)(model, max_length)


def model_options(args):
    backend = getattr(args, "backend", "petals")
    return dict(backend="pytorch" if backend == "pipeline" else backend,
                artifacts=getattr(args, "artifacts", "/artifacts"),
                reference=getattr(args, "reference", None))


def generate_request(model, mode, prompt, new_tokens, request_id):
    import torch

    started = time.perf_counter()
    times, output = [], []
    record = {"request_id": request_id, "success": False, "output_tokens": 0}
    try:
        # Grad mode is thread-local, so each concurrent request sets it here.
        with torch.inference_mode(), make_session(model, mode, len(prompt) + new_tokens) as session:
            ids = torch.tensor([prompt], dtype=torch.long)
            for _ in range(new_tokens):
                logits = session.step(ids)
                token = int(logits[0, -1].argmax())
                output.append(token)
                times.append(time.perf_counter())
                ids = torch.tensor([[token]], dtype=torch.long)
        record["success"] = True
    except Exception as error:
        record["error"] = f"{type(error).__name__}: {error}"
    intervals = [b - a for a, b in zip(times, times[1:])]
    decode_time = sum(intervals)
    record.update(
        output_tokens=len(output), output_token_ids=output,
        ttft_seconds=times[0] - started if times else None,
        inter_token_seconds=intervals,
        inter_token_seconds_p50=percentile(intervals, 50),
        inter_token_seconds_p95=percentile(intervals, 95),
        decode_output_tokens_per_second=len(intervals) / decode_time if decode_time > 0 else None,
        elapsed_seconds=time.perf_counter() - started,
    )
    return record


def run_bench(args, report):
    validate_workload(args.prompt_tokens, args.new_tokens, args.concurrency, args.requests)
    target, maximum = validate_attempt_policy(args)
    if getattr(args, "backend", None) in {"pipeline", "matched"} and args.mode == "pipeline":
        import asyncio
        from lab.pipeline_benchmark import run_remote_bench
        if args.backend == "matched":
            from lab.matched_control import MatchedReplicaPool
            from replicant_mesh.remote_client import RemoteClient
            endpoints = getattr(args, "replicas", None) or [
                f"replica-{index}:50053" for index in range(1, 5)]
            report.update(control="resource-matched complete-model replicas",
                          routing="thin client selects least-loaded full-model replica, rotating ties",
                          aggregate_inference_cpu_quota=8,
                          topology_limit="four independent same-host replicas; coordinator RPC and pipeline relay work is not part of this control")
            async def run_matched():
                # grpc.aio channels belong to the running measurement loop.
                clients = [RemoteClient(endpoint, private_network=True) for endpoint in endpoints]
                await run_remote_bench(args, report, client=MatchedReplicaPool(clients))
            asyncio.run(run_matched())
        else:
            asyncio.run(run_remote_bench(args, report))
        return
    model, tokenizer, loading = load_model(args.mode, **model_options(args))
    report["model_loading_seconds"] = loading
    position_limit = getattr(model.config, "max_position_embeddings", MAX_SESSION_TOKENS)
    if args.prompt_tokens + args.new_tokens > position_limit:
        raise ValueError(f"Workload exceeds checkpoint context limit {position_limit}")
    prompt = fixture_ids(tokenizer, args.prompt_tokens)
    report["prompt_token_ids"] = prompt
    warmup = generate_request(model, args.mode, prompt, args.new_tokens, "warmup")
    report["warmup"] = warmup
    if not warmup["success"]:
        raise RuntimeError(f"Warm-up failed: {warmup['error']}")

    records, lock, next_id, completed = [], threading.Lock(), 0, 0

    def client_loop():
        nonlocal next_id, completed
        while True:
            with lock:
                if next_id >= maximum or (target is not None and completed >= target):
                    return
                request_id = next_id
                next_id += 1
            record = generate_request(model, args.mode, prompt, args.new_tokens, request_id)
            with lock:
                records.append(record)
                completed += int(record["success"])

    started = time.perf_counter()
    with ThreadPoolExecutor(max_workers=args.concurrency) as executor:
        futures = [executor.submit(client_loop) for _ in range(args.concurrency)]
        for future in futures:
            future.result()
    elapsed = time.perf_counter() - started
    report["requests"] = sorted(records, key=lambda r: r["request_id"])
    report["summary"] = summarize_requests(records, elapsed)
    report["partial_output_tokens_from_failed_requests"] = sum(
        r["output_tokens"] for r in records if not r["success"]
    )
    report["success"] = all(r["success"] for r in records)
    record_attempt_policy(report, target, maximum)
    if getattr(model, "runtime_backend", None) == "pytorch":
        report["runtime_diagnostics_after_close"] = model.diagnostics()


def run_check(args, report):
    if getattr(args, "backend", None) == "pipeline":
        import asyncio
        from replicant_mesh.service_check import run_validation
        asyncio.run(run_validation(args, report))
        report["success"] = report.get("status") == "passed"
        return
    import torch

    local, tokenizer, local_loading = load_model("local", **model_options(args))
    remote, _, remote_loading = load_model("pipeline", **model_options(args))
    report["model_loading_seconds"] = {"local": local_loading, "pipeline": remote_loading}
    comparisons = report["comparisons"] = []
    forced = fixture_ids(tokenizer, 4)

    def compare(left, right, ids, label):
        tensor = torch.tensor([ids], dtype=torch.long)
        expected, actual = left.step(tensor), right.step(tensor)
        max_error = float((expected - actual).abs().max())
        agrees = bool(torch.equal(expected.argmax(-1), actual.argmax(-1)))
        passed = bool(torch.allclose(expected, actual, atol=args.atol, rtol=0))
        comparisons.append({"case": label,
                            "max_absolute_logit_error": max_error if math.isfinite(max_error) else None,
                            "finite_logits": bool(torch.isfinite(actual).all() and torch.isfinite(expected).all()),
                            "greedy_token_agreement": agrees, "passed": passed})
        torch.testing.assert_close(actual, expected, atol=args.atol, rtol=0)

    with torch.inference_mode(), ExitStack() as stack:
        # Distinct lengths and token offsets exercise interleaved independent caches.
        pairs = []
        for name, length in [("A", 16), ("B", 37)]:
            left = stack.enter_context(LocalSession(local, length + 4))
            right = stack.enter_context(make_session(remote, "pipeline", length + 4))
            prompt = fixture_ids(tokenizer, length + (name == "B"))[int(name == "B"):]
            compare(left, right, prompt, f"{name}:prefill")
            pairs.append((left, right))
        compare(*pairs[0], [forced[0]], "A:forced_decode_1")
        compare(*pairs[1], [forced[1]], "B:forced_decode_1")
        pairs[0][0].close()
        pairs[0][1].close()
        report["cancelled_session_closed"] = True
        compare(*pairs[1], [forced[2]], "B:decode_after_A_close")
        with LocalSession(local, 20) as left, make_session(remote, "pipeline", 20) as right:
            compare(left, right, fixture_ids(tokenizer, 16), "C:fresh_after_A_close")
            compare(left, right, [forced[3]], "C:forced_decode")
        compare(*pairs[1], [forced[3]], "B:decode_after_C_close")
        with make_session(remote, "pipeline", 8) as bounded:
            bounded.step(torch.tensor([fixture_ids(tokenizer, 8)], dtype=torch.long))
            try:
                bounded.step(torch.tensor([[forced[0]]], dtype=torch.long))
            except ValueError:
                report["session_limit_rejected"] = True
            else:
                raise AssertionError("Pipeline accepted input past the declared session limit")
    report["success"] = True
    report["limitations"] = [
        "atol is a provisional upstream CPU tolerance, not a calibrated performance result",
        "closing and reusing sessions checks behavior; worker memory reclamation is not measured",
        "malformed RPC messages, process failures, and execution overlap traces are not tested",
    ]
    if getattr(remote, "runtime_backend", None) == "pytorch":
        report["runtime_diagnostics_after_close"] = remote.diagnostics()
        report["limitations"] = [
            "this short check compares final-position logits; run the M1 test suite for full-prefill coverage",
            "all three stages execute in one process under one lock; no RPC, network or pipeline overlap",
            "cache tensor bytes are measured; process RSS and allocator peak memory are not measured",
        ]


def metadata(args):
    backend = getattr(args, "backend", "petals")
    if backend in ("pytorch", "pipeline", "matched"):
        from replicant_mesh.manifest import MODEL_ID, MODEL_REVISION
        model, revision = MODEL_ID, MODEL_REVISION
    else:
        model, revision = model_settings()
    versions = {}
    sources = {}
    for package in ["torch", "transformers", "petals", "hivemind", "numpy", "huggingface-hub",
                    "grpcio", "protobuf", "safetensors"]:
        try:
            versions[package] = importlib.metadata.version(package)
            source = importlib.metadata.distribution(package).read_text("direct_url.json")
            if source:
                sources[package] = json.loads(source)
        except importlib.metadata.PackageNotFoundError:
            versions[package] = None
    try:
        qdisc = subprocess.run(["tc", "qdisc", "show", "dev", "eth0"],
                               text=True, capture_output=True, timeout=5, check=True).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        qdisc = None
    routing = ("in-process serialized stages [0,3), [3,6), [6,8); no network transport"
               if backend == "pytorch" else
               "client relays activations between fixed stages; server-to-server push disabled")
    if backend == "pipeline":
        routing = "thin client streams from coordinator; coordinator relays activations across three fixed workers"
    if args.mode == "local" and args.command == "bench":
        routing = "complete-model local reference; no network transport"
    return {
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "model": model, "revision": revision, "tokenizer_revision": revision,
        "runtime": versions, "runtime_sources": sources, "python": platform.python_version(),
        "precision": "float32", "attention": "eager", "activation_compression": "NONE",
        "backend": backend, "routing": routing,
        "torch_threads": int(os.environ.get("OMP_NUM_THREADS", "2")),
        "arguments": vars(args), "client_qdisc": qdisc,
        "workload": "public repeated fixture, greedy sampling, fixed output length; EOS ignored",
        "timing": "monotonic client wall time; loading and warm-up excluded; prefill included",
        "arrival_policy": "closed-loop: at most concurrency active requests; no queued driver backlog",
        "throughput_policy": "only complete requests counted; failed partial tokens reported separately",
        "unmeasured": ["worker compute/queue/transfer split", "retry count", "worker peak memory",
                       "energy", "worker qdiscs (capture separately)", "pipeline overlap"],
        "success": False,
    }


def validate_attempt_policy(args):
    """Fixed attempts remain the default; completion targets retain every failure."""
    target = getattr(args, "completion_target", None)
    maximum = getattr(args, "max_attempts", None)
    if target is None:
        if maximum is not None:
            raise ValueError("--max-attempts requires --completion-target")
        return None, args.requests
    maximum = 200 if maximum is None else maximum
    if type(target) is not int or type(maximum) is not int or not 1 <= target <= maximum:
        raise ValueError("Completion target must be positive and no greater than max attempts")
    return target, maximum


def record_attempt_policy(report, target, maximum):
    reached = target is None or report["summary"]["completed"] >= target
    report["attempt_policy"] = {"completion_target": target, "maximum_attempts": maximum,
                                "target_reached": reached,
                                "stop_reason": "target_reached" if target is not None and reached else "attempt_limit"}
    report["success"] = bool(report["success"] and reached)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["check", "bench"])
    parser.add_argument("--mode", choices=["local", "pipeline"], default="pipeline")
    parser.add_argument("--backend", choices=["petals", "pytorch", "pipeline", "matched"], default="petals")
    parser.add_argument("--artifacts", default="/artifacts", help="verified PyTorch shard directory")
    parser.add_argument("--reference", help="pinned source snapshot for the PyTorch whole-model reference")
    parser.add_argument("--requests", type=int, default=10)
    parser.add_argument("--completion-target", type=int,
                        help="stop after at least this many completed requests, retaining failed attempts")
    parser.add_argument("--max-attempts", type=int,
                        help="attempt cap with --completion-target (default 200)")
    parser.add_argument("--coordinator", default="coordinator:50052")
    parser.add_argument("--replicas", nargs=4, help="four matched complete-model replica endpoints")
    parser.add_argument("--timeout-seconds", type=float, default=300)
    parser.add_argument("--repetition", type=int, default=1)
    parser.add_argument("--run-order-index", type=int, default=0)
    parser.add_argument("--concurrency", type=int, default=1)
    parser.add_argument("--prompt-tokens", type=int, default=128)
    parser.add_argument("--new-tokens", type=int, default=8)
    parser.add_argument("--label", default="unlabelled")
    parser.add_argument("--atol", type=float, default=1e-3)
    parser.add_argument("--output", help="JSON report path; defaults to a unique file in /results")
    args = parser.parse_args()
    report = metadata(args)
    try:
        if args.atol <= 0 or not args.atol < float("inf"):
            raise ValueError("atol must be finite and positive")
        (run_check if args.command == "check" else run_bench)(args, report)
    except Exception as error:
        report["success"] = False
        report["error"] = f"{type(error).__name__}: {error}"
    filename = f"{datetime.now(timezone.utc):%Y%m%dT%H%M%S%fZ}-{uuid.uuid4().hex[:8]}-{args.command}-{args.mode}.json"
    destination = Path(args.output) if args.output else Path("/results") / filename
    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open("x", encoding="utf-8") as stream:
        stream.write(json.dumps(report, indent=2, allow_nan=False) + "\n")
    print(json.dumps({"report": str(destination), "success": report["success"],
                      "summary": report.get("summary"), "error": report.get("error")}, indent=2))
    raise SystemExit(0 if report["success"] else 1)


if __name__ == "__main__":
    main()
