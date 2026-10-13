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

from lab.config import model_settings, percentile, read_peers, summarize_requests

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

    def __enter__(self):
        return self

    def step(self, ids):
        if self.position + ids.shape[1] > self.max_length:
            raise ValueError("Session context limit exceeded")
        result = self.model.base_model(
            input_ids=ids, past_key_values=self.cache, use_cache=True, return_dict=True,
        )
        self.cache = result.past_key_values
        self.position += ids.shape[1]
        return self.model.lm_head(result.last_hidden_state[:, -1:, :])

    def close(self):
        self.cache = None

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

    def step(self, ids):
        transformer = self.model.transformer
        embeddings = transformer.word_embeddings_layernorm(transformer.word_embeddings(ids))
        hidden = self.remote.step(embeddings)
        return self.model.lm_head(transformer.ln_f(hidden[:, -1:, :]))

    def close(self):
        if not self.closed:
            self.remote.close()
            self.closed = True

    def __exit__(self, *_):
        self.close()


def load_model(mode):
    import torch
    from transformers import AutoModelForCausalLM, AutoTokenizer

    torch.set_num_threads(int(os.environ.get("OMP_NUM_THREADS", "2")))
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
            dht_prefix=os.environ.get("LAB_DHT_PREFIX", "steamboat-local-v1"),
            use_server_to_server=False,
            request_timeout=30, connect_timeout=5,
            max_retries=int(os.environ.get("PETALS_MAX_RETRIES", "2")), **kwargs,
        )
    model.eval()
    return model, tokenizer, time.perf_counter() - started


def make_session(model, mode, max_length):
    return (LocalSession if mode == "local" else RemoteSession)(model, max_length)


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
    model, tokenizer, loading = load_model(args.mode)
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

    records, lock, next_id = [], threading.Lock(), 0

    def client_loop():
        nonlocal next_id
        while True:
            with lock:
                if next_id >= args.requests:
                    return
                request_id = next_id
                next_id += 1
            record = generate_request(model, args.mode, prompt, args.new_tokens, request_id)
            with lock:
                records.append(record)

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


def run_check(args, report):
    import torch

    local, tokenizer, local_loading = load_model("local")
    remote, _, remote_loading = load_model("pipeline")
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
            right = stack.enter_context(RemoteSession(remote, length + 4))
            prompt = fixture_ids(tokenizer, length + (name == "B"))[int(name == "B"):]
            compare(left, right, prompt, f"{name}:prefill")
            pairs.append((left, right))
        compare(*pairs[0], [forced[0]], "A:forced_decode_1")
        compare(*pairs[1], [forced[1]], "B:forced_decode_1")
        pairs[0][0].close()
        pairs[0][1].close()
        report["cancelled_session_closed"] = True
        compare(*pairs[1], [forced[2]], "B:decode_after_A_close")
        with LocalSession(local, 20) as left, RemoteSession(remote, 20) as right:
            compare(left, right, fixture_ids(tokenizer, 16), "C:fresh_after_A_close")
            compare(left, right, [forced[3]], "C:forced_decode")
        compare(*pairs[1], [forced[3]], "B:decode_after_C_close")
        with RemoteSession(remote, 8) as bounded:
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


def metadata(args):
    model, revision = model_settings()
    versions = {}
    sources = {}
    for package in ["torch", "transformers", "petals", "hivemind", "numpy", "huggingface-hub"]:
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
    return {
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "model": model, "revision": revision, "tokenizer_revision": revision,
        "runtime": versions, "runtime_sources": sources, "python": platform.python_version(),
        "precision": "float32", "attention": "eager", "activation_compression": "NONE",
        "routing": "client relays activations between fixed stages; server-to-server push disabled",
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


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["check", "bench"])
    parser.add_argument("--mode", choices=["local", "pipeline"], default="pipeline")
    parser.add_argument("--requests", type=int, default=10)
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
        report["error"] = f"{type(error).__name__}: {error}"
    filename = f"{datetime.now(timezone.utc):%Y%m%dT%H%M%S%fZ}-{args.command}-{args.mode}.json"
    destination = Path(args.output) if args.output else Path("/results") / filename
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(report, indent=2, allow_nan=False) + "\n", encoding="utf-8")
    print(json.dumps({"report": str(destination), "success": report["success"],
                      "summary": report.get("summary"), "error": report.get("error")}, indent=2))
    raise SystemExit(0 if report["success"] else 1)


if __name__ == "__main__":
    main()
