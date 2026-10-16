"""M4 correctness and causal-order checks through the bounded coordinator.

The remote run exercises real worker compute without injected delay. Its timing
observations establish same-host overlap only, not a performance comparison.
"""

import argparse
import asyncio
from datetime import datetime, timezone
import importlib.metadata
import json
import os
from pathlib import Path
import time
import uuid


ATOL = 1e-3
COHORTS = ((1, (1,)), (1, (128,)), (1, (1024,)),
           (3, (1, 128, 1024)), (8, (1024, 128, 1024, 7, 1024, 128, 1024, 1)))


def fixture_tokens(count, offset, vocab_size):
    import torch
    return torch.tensor([[3 + ((index * 37 + offset) % (vocab_size - 3))
                          for index in range(count)]], dtype=torch.long)


def reference_logits(reference, prompt, output_count, forced_tokens=None):
    """Preserve identical contexts; forced tokens replace feedback, not logits."""
    import torch
    result, cache, tokens = [], None, prompt
    with torch.inference_mode():
        for index in range(output_count):
            output = reference(input_ids=tokens, past_key_values=cache,
                               use_cache=True, return_dict=True)
            cache = output.past_key_values
            logits = output.logits[:, -1, :].clone()
            result.append(logits)
            selected = int(logits.argmax(dim=-1).item())
            feedback = forced_tokens[index] if forced_tokens is not None and index < output_count - 1 else selected
            tokens = torch.tensor([[feedback]], dtype=torch.long)
    return result


def compare_logits(label, actual, expected, evidence):
    import torch
    if actual is None or actual.shape != expected.shape:
        raise AssertionError(f"{label}: missing or incorrectly shaped logits")
    if not bool(torch.isfinite(actual).all()) or not bool(torch.isfinite(expected).all()):
        raise AssertionError(f"{label}: non-finite logits")
    error = float((actual - expected).abs().max())
    evidence.setdefault("comparisons", []).append({"name": label, "shape": list(actual.shape),
                                                   "max_absolute_error": error})
    torch.testing.assert_close(actual, expected, atol=ATOL, rtol=0, msg=label)


def inspect_trace(events, session_ids, output_count, *, clock_id=None, require_overlap=False):
    """Verify exact causal edges and separately measure actual compute overlap.

    RPC interval overlap alone cannot pass this check. Compute intervals must be
    bracketed by local dispatch/response times on a verified shared clock.
    """
    selected = set(session_ids)
    dispatches, responses = {}, {}
    for event in events:
        if event.get("session_id") not in selected:
            continue
        kind = event.get("event")
        if kind not in ("stage_dispatch", "stage_response"):
            continue
        key = (event["session_id"], event["sequence"], event["worker"])
        target = dispatches if kind == "stage_dispatch" else responses
        if key in target:
            raise AssertionError(f"Duplicate stage event: {key}")
        target[key] = event
    expected = {(session, sequence, worker) for session in selected
                for sequence in range(output_count) for worker in (1, 2, 3)}
    if set(dispatches) != expected or set(responses) != expected:
        raise AssertionError("Trace is incomplete or contains unexpected stage operations")
    spans = []
    for session in selected:
        previous_response = -1
        for sequence in range(output_count):
            for worker in (1, 2, 3):
                key = (session, sequence, worker)
                dispatch, response = dispatches[key], responses[key]
                sent, received = dispatch["coordinator_ns"], response["coordinator_ns"]
                if not previous_response <= sent <= received:
                    raise AssertionError("A session advanced before its preceding response")
                previous_response = received
                if clock_id:
                    start, end = response["compute_start_ns"], response["compute_end_ns"]
                    if response.get("clock_id") != clock_id or not sent <= start <= end <= received:
                        raise AssertionError("Worker compute span lacks a valid local-clock bracket")
                    spans.append({"session_id": session, "sequence": sequence, "worker": worker,
                                  "start_ns": start, "end_ns": end})
    # A scheduler worker must have only one unresolved Step RPC at a time.
    for worker in (1, 2, 3):
        previous_end = -1
        keys = sorted((key for key in expected if key[2] == worker),
                      key=lambda key: dispatches[key]["coordinator_ns"])
        for key in keys:
            if dispatches[key]["coordinator_ns"] < previous_end:
                raise AssertionError("Coordinator issued concurrent calls to one worker")
            previous_end = responses[key]["coordinator_ns"]
    active, pairs, examples, longest_ns = [], 0, [], 0
    for span in sorted(spans, key=lambda item: item["start_ns"]):
        active = [other for other in active if other["end_ns"] > span["start_ns"]]
        for other in active:
            if other["worker"] == span["worker"] or other["session_id"] == span["session_id"]:
                continue
            overlap = min(other["end_ns"], span["end_ns"]) - span["start_ns"]
            if overlap > 0:
                pairs += 1
                longest_ns = max(longest_ns, overlap)
                if len(examples) < 16:
                    examples.append({"first": other, "second": span, "overlap_ns": overlap})
        active.append(span)
    if require_overlap and (not clock_id or not pairs):
        raise AssertionError("No verified useful compute overlap between independent requests")
    return {"requests": len(selected), "stage_operations": len(expected),
            "causal_order_verified": True, "single_call_per_worker_verified": True,
            "clock_id": clock_id, "overlapping_compute_pairs": pairs,
            "longest_pair_overlap_ns": longest_ns, "overlap_examples": examples}


async def consume_checked(handle, expected, label, evidence):
    tokens, event_times = [], []
    async for event in handle:
        index = len(tokens)
        if event.index != index or index >= len(expected):
            raise AssertionError("Coordinator duplicated or reordered streamed output")
        compare_logits(f"{label}-output-{index}", event.logits, expected[index], evidence)
        selected = int(expected[index].argmax(dim=-1).item())
        if event.token_id != selected:
            # Record the competing logits before failing; never relax the gate.
            values = expected[index][0].topk(2).values
            evidence.setdefault("greedy_divergences", []).append({
                "name": label, "index": index, "actual": event.token_id,
                "expected": selected, "reference_top_two_margin": float(values[0] - values[1]),
            })
            raise AssertionError(f"{label}: greedy token differs at index {index}")
        tokens.append(event.token_id)
        event_times.append(event.received_at)
    result = await handle.result()
    if len(tokens) != len(expected) or list(result.token_ids) != tokens:
        raise AssertionError(f"{label}: incomplete or inconsistent output")
    if not result.cleanup_complete or result.error:
        raise AssertionError(f"{label}: failed request or incomplete cleanup: {result.error}")
    record = {"case": label, "session_id": handle.session_id, "status": result.status,
              "token_ids": tokens, "cleanup_complete": result.cleanup_complete,
              "output_tokens": len(tokens), "admission_seconds": result.admitted_at - result.submitted_at,
              "ttft_seconds": event_times[0] - result.submitted_at,
              "decode_intervals_seconds": [later - earlier for earlier, later in zip(event_times, event_times[1:])],
              "total_seconds": result.finished_at - result.submitted_at}
    evidence.setdefault("requests", []).append(record)
    return record


async def assert_worker_cleanup(clients, manifest, evidence, label):
    from .protocol import PROTOCOL_VERSION
    from .protocol.errors import raise_for_error
    from .protocol.worker_pb2 import Request
    from .remote_check import diagnostics
    observed = []
    for client in clients:
        response = raise_for_error(await client.execute("Describe", Request(
            protocol_version=PROTOCOL_VERSION, manifest_fingerprint=manifest["fingerprint"], timeout_ms=5000)))
        item = diagnostics(response)
        observed.append(item)
    evidence.setdefault("cleanup", []).append({"case": label, "workers": observed})
    for item in observed:
        if not item["cache_bytes_exact"] or any(item[name] != 0 for name in (
                "active_sessions", "reserved_positions", "allocated_cache_bytes",
                "active_operations", "queued_operations")):
            raise AssertionError(f"Live worker resources remain after {label}")


async def validate_cohorts(coordinator, reference, evidence, *, clients=None, manifest=None,
                           require_overlap=False, cohorts=COHORTS):
    """Shared real-model gate for remote containers and in-process integration."""
    from .protocol.clock import clock_identity
    vocab = reference.config.vocab_size
    clock_id = clock_identity() if all(coordinator.clock_verified) else None
    evidence["clock_evidence"] = coordinator.clock_evidence
    for cohort_index, (concurrency, lengths) in enumerate(cohorts):
        if len(lengths) != concurrency:
            raise ValueError("Cohort length must equal declared concurrency")
        prompts = [fixture_tokens(length, 211 * index, vocab) for index, length in enumerate(lengths)]
        forced = [[3 + ((900 + index * 97 + step * 13) % (vocab - 3)) for step in range(8)]
                  for index in range(concurrency)]
        # Calculate controls before submitting: reference work must not block
        # the scheduler loop or contaminate the measured overlap interval.
        expected = [reference_logits(reference, prompt, 9, feedback)
                    for prompt, feedback in zip(prompts, forced)]
        handles = [coordinator.submit(prompt, 9, forced_tokens=feedback, capture_logits=True)
                   for prompt, feedback in zip(prompts, forced)]
        name = f"cohort-{cohort_index}-concurrency-{concurrency}"
        try:
            await asyncio.gather(*(consume_checked(handle, logits, f"{name}-request-{index}", evidence)
                                   for index, (handle, logits) in enumerate(zip(handles, expected))))
        finally:
            await asyncio.gather(*(handle.cancel() for handle in handles))
        if coordinator.trace_dropped:
            raise AssertionError("Trace capacity exceeded; cannot establish a complete causal trace")
        trace = inspect_trace(list(coordinator.events), [handle.session_id for handle in handles], 9,
                              clock_id=clock_id, require_overlap=require_overlap and concurrency == 8)
        evidence.setdefault("cohorts", []).append({"name": name, "concurrency": concurrency,
                                                   "prompt_lengths": list(lengths), "trace": trace})
        if clients is not None:
            await assert_worker_cleanup(clients, manifest, evidence, name)
    # Genuine greedy feedback is a separate check from matched forced contexts.
    prompt = fixture_tokens(128, 471, vocab)
    expected = reference_logits(reference, prompt, 9)
    handle = coordinator.submit(prompt, 9, capture_logits=True)
    try:
        await consume_checked(handle, expected, "greedy-feedback", evidence)
    finally:
        await handle.cancel()
    if clients is not None:
        await assert_worker_cleanup(clients, manifest, evidence, "greedy-feedback")


async def run_validation(args, evidence):
    import torch
    from transformers import AutoModelForCausalLM
    from .coordinator import Coordinator
    from .coordinator_model import CoordinatorModel
    from .manifest import load_manifest
    from .prepare import verify_snapshot
    from .protocol.transport import GrpcClient
    from .remote_check import _host_evidence
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
    model = CoordinatorModel.from_artifacts(args.artifacts, args.reference)
    evidence["coordinator_model"] = model.diagnostics()
    clients = [GrpcClient(target, private_network=True) for target in args.workers]
    coordinator = Coordinator(manifest, clients, model)
    try:
        await coordinator.start()
        await assert_worker_cleanup(clients, manifest, evidence, "before-validation")
        started = time.monotonic()
        reference = AutoModelForCausalLM.from_pretrained(
            args.reference, dtype=torch.float32, attn_implementation="eager",
            local_files_only=True, use_safetensors=True).eval().requires_grad_(False)
        evidence["control_loading_seconds"] = time.monotonic() - started
        evidence["additional_reference_parameter_bytes"] = sum(
            parameter.numel() * parameter.element_size() for parameter in reference.parameters())
        await validate_cohorts(coordinator, reference, evidence, clients=clients,
                               manifest=manifest, require_overlap=True)
        # Exercise cancellation through all three actual container leases while
        # another request keeps its independent cache and completes correctly.
        prompt = fixture_tokens(31, 847, reference.config.vocab_size)
        expected = reference_logits(reference, prompt, 9)
        interrupted = coordinator.submit(prompt, 64)
        survivor = coordinator.submit(prompt, 9, capture_logits=True)
        consumer = asyncio.create_task(consume_checked(survivor, expected, "cancel-survivor", evidence))
        try:
            first = await anext(interrupted)
            cancelled = await interrupted.cancel()
            if (first.index != 0 or cancelled.status != "cancelled"
                    or not cancelled.cleanup_complete or len(cancelled.token_ids) >= 64):
                raise AssertionError("Cancelled request did not reclaim its independent reservations")
            await consumer
            evidence["cancelled_request"] = {
                "session_id": interrupted.session_id, "status": cancelled.status,
                "buffered_tokens_before_cancel": len(cancelled.token_ids),
                "cleanup_complete": cancelled.cleanup_complete,
            }
        finally:
            await asyncio.gather(interrupted.cancel(), survivor.cancel())
            await asyncio.gather(consumer, return_exceptions=True)
        await assert_worker_cleanup(clients, manifest, evidence, "cancellation-and-survivor")
        if coordinator.trace_dropped or coordinator.trace_errors:
            raise AssertionError("Complete trace was not retained")
        evidence["status"] = "passed"
    finally:
        try:
            if not await coordinator.close():
                raise AssertionError("Coordinator model CPU work did not drain during shutdown")
        finally:
            evidence["trace"] = list(coordinator.events)
            evidence["coordinator_stats"] = coordinator.stats()
            evidence["host"] = _host_evidence()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifacts", default=os.environ.get("STEAMBOAT_ARTIFACT_DIR", "/artifacts"))
    parser.add_argument("--reference", default=os.environ.get("STEAMBOAT_REFERENCE_DIR"),
                        required=not os.environ.get("STEAMBOAT_REFERENCE_DIR"))
    parser.add_argument("--workers", nargs=3, default=[f"worker-{index}:50051" for index in (1, 2, 3)])
    parser.add_argument("--output", default="/results", help="Directory for unique success/failure reports")
    args = parser.parse_args(argv)
    evidence = {"schema_version": 1, "milestone": "M4", "status": "failed",
                "created_utc": datetime.now(timezone.utc).isoformat(), "atol": ATOL, "rtol": 0,
                "execution": "bounded coordinator; three supervised remote worker containers",
                "fixture": {"prompt_formula": "3 + ((i * 37 + request_index * 211) % (vocab_size - 3))",
                            "cohorts": [{"concurrency": n, "prompt_lengths": list(lengths)} for n, lengths in COHORTS],
                            "output_tokens": 9, "forced_decode_inputs": 8,
                            "forced_formula": "3 + ((900 + request_index * 97 + step * 13) % (vocab_size - 3))",
                            "greedy": {"prompt_tokens": 128, "offset": 471, "output_tokens": 9}},
                "limitations": ["same-host correctness and overlap mechanics; no speedup claim",
                                "trusted private gRPC network without authentication or encryption",
                                "additional complete-model reference memory in validation process",
                                "uncontrolled diagnostic timings, not M5 performance results",
                                "no automatic Step retry, replay, or recovery",
                                "unchunked prefill cannot be preempted"]}
    started = time.monotonic()
    try:
        asyncio.run(run_validation(args, evidence))
    except Exception as error:
        evidence["status"] = "failed"
        evidence["error"] = {"type": type(error).__name__, "message": str(error)[:1024]}
    evidence["elapsed_seconds"] = time.monotonic() - started
    directory = Path(args.output)
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"{datetime.now(timezone.utc):%Y%m%dT%H%M%S%fZ}-{uuid.uuid4().hex[:8]}-m4-coordinator.json"
    with path.open("x", encoding="utf-8") as stream:
        json.dump(evidence, stream, indent=2, allow_nan=False)
        stream.write("\n")
    print(json.dumps({"status": evidence["status"], "report": str(path),
                      "comparisons": len(evidence.get("comparisons", [])), "error": evidence.get("error")}))
    return 0 if evidence["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
