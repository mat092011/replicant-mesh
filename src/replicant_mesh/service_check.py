"""M5 numerical gate through the standalone coordinator's streaming listener.

Only this validation process loads a complete-model reference. The performance
load generator remains thin and never loads weights or a tokenizer.
"""

import argparse
import asyncio
from contextlib import aclosing
from datetime import datetime, timezone
import importlib.metadata
import json
import os
from pathlib import Path
import time
import uuid

from .coordinator_check import ATOL, COHORTS, compare_logits, fixture_tokens, reference_logits


async def consume_checked(client, prompt, expected, label, evidence, forced=None):
    import torch
    tokens, times, terminal, session_id = [], [], None, None
    started = time.monotonic()
    record = {"case": label, "status": "failed", "success": False}
    try:
        async with aclosing(client.generate(prompt, len(expected), forced_tokens=forced, capture_logits=True)) as stream:
            async for event in stream:
                if event.get("type") == "token":
                    index = len(tokens)
                    if terminal is not None or event.get("index") != index or index >= len(expected):
                        raise AssertionError("Coordinator duplicated or reordered streamed output")
                    if event.get("sequence") != index:
                        raise AssertionError("Streamed operation sequence does not match output index")
                    if event.get("position") != len(prompt) + index:
                        raise AssertionError("Streamed absolute token position does not match its context")
                    if session_id is None:
                        session_id = event["session_id"]
                    elif event.get("session_id") != session_id:
                        raise AssertionError("Stream mixed independent session identities")
                    actual = torch.tensor([event.get("logits", [])], dtype=torch.float32)
                    compare_logits(f"{label}-output-{index}", actual, expected[index], evidence)
                    selected = int(expected[index].argmax(dim=-1).item())
                    if event.get("token_id") != selected:
                        values = expected[index][0].topk(2).values
                        evidence.setdefault("greedy_divergences", []).append({
                            "name": label, "index": index, "actual": event.get("token_id"),
                            "expected": selected, "reference_top_two_margin": float(values[0] - values[1])})
                        raise AssertionError("Streamed greedy selection differs from the reference")
                    tokens.append(selected)
                    times.append(time.monotonic())
                elif event.get("type") == "result":
                    if terminal is not None:
                        raise AssertionError("Multiple terminal results")
                    terminal = event
                else:
                    raise AssertionError("Unrecognized streaming event")
        if (terminal is None or terminal.get("status") != "completed" or terminal.get("error")
                or terminal.get("cleanup_complete") is not True
                or len(tokens) != len(expected) or terminal.get("token_ids") != tokens):
            raise AssertionError(f"{label}: incomplete output or cleanup: {terminal}")
        record.update(status="completed", success=True)
    except BaseException as error:
        record["error"] = {"type": type(error).__name__, "message": str(error)[:1024]}
        record["error_code"] = getattr(error, "code", None)
        if isinstance(error, asyncio.CancelledError):
            record["status"] = "cancelled"
        if terminal is not None:
            record["terminal_result"] = terminal
        raise
    finally:
        record.update(session_id=session_id, token_ids=tokens, output_tokens=len(tokens),
                      cleanup_complete=terminal is not None and terminal.get("cleanup_complete") is True,
                      ttft_seconds=times[0] - started if times else None,
                      decode_intervals_seconds=[b - a for a, b in zip(times, times[1:])],
                      total_seconds=time.monotonic() - started,
                      server_metrics=terminal.get("metrics", {}) if terminal else {})
        evidence.setdefault("requests", []).append(record)
    return record


async def check_cleanup(client, evidence, label, *, wait_seconds=0):
    from lab.pipeline_benchmark import assert_reclaimed
    deadline = time.monotonic() + wait_seconds
    while True:
        description = await client.describe()
        try:
            assert_reclaimed(description)
        except AssertionError:
            if time.monotonic() >= deadline:
                evidence.setdefault("cleanup", []).append({"case": label, "description": description, "passed": False})
                raise
            await asyncio.sleep(0.05)
        else:
            evidence.setdefault("cleanup", []).append({"case": label, "description": description, "passed": True})
            return description


async def validate_remote_cohorts(client, reference, evidence, *, cohorts=COHORTS):
    vocab = reference.config.vocab_size
    for cohort_index, (concurrency, lengths) in enumerate(cohorts):
        if len(lengths) != concurrency:
            raise ValueError("Cohort length must equal declared concurrency")
        prompts = [fixture_tokens(length, 211 * index, vocab) for index, length in enumerate(lengths)]
        forced = [[3 + ((900 + index * 97 + step * 13) % (vocab - 3)) for step in range(8)]
                  for index in range(concurrency)]
        expected = [reference_logits(reference, prompt, 9, feedback)
                    for prompt, feedback in zip(prompts, forced)]
        name = f"cohort-{cohort_index}-concurrency-{concurrency}"
        tasks = [asyncio.create_task(consume_checked(client, prompt[0].tolist(), logits,
                                                     f"{name}-request-{index}", evidence, feedback))
                 for index, (prompt, logits, feedback) in enumerate(zip(prompts, expected, forced))]
        try:
            await asyncio.gather(*tasks)
        finally:
            for task in tasks:
                if not task.done():
                    task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
        await check_cleanup(client, evidence, name)
        evidence.setdefault("cohorts", []).append({"name": name, "concurrency": concurrency,
                                                   "prompt_lengths": list(lengths), "outputs_per_request": 9})
    prompt = fixture_tokens(128, 471, vocab)
    expected = reference_logits(reference, prompt, 9)
    await consume_checked(client, prompt[0].tolist(), expected, "greedy-feedback", evidence)
    await check_cleanup(client, evidence, "greedy-feedback")


async def run_validation(args, evidence):
    import torch
    from transformers import AutoModelForCausalLM
    from .manifest import load_manifest
    from .prepare import verify_snapshot
    from .remote_client import RemoteClient
    from .remote_check import _host_evidence
    if getattr(args, "atol", ATOL) != ATOL:
        raise ValueError(f"The remote service gate uses the frozen atol={ATOL}; it cannot be relaxed")
    torch.set_num_threads(int(os.environ.get("OMP_NUM_THREADS", "2")))
    manifest = load_manifest(args.artifacts)
    reference_path = getattr(args, "reference", None) or os.environ.get("REPLICANT_MESH_REFERENCE_DIR")
    if not reference_path:
        raise ValueError("Remote correctness checks require the verified --reference snapshot")
    verify_snapshot(reference_path)
    evidence.update({"model_id": manifest["model_id"], "model_revision": manifest["revision"],
                     "manifest_fingerprint": manifest["fingerprint"], "source_files": manifest["source_files"],
                     "limits": manifest["limits"], "dtype": manifest["dtype"],
                     "attention": manifest["attention"], "layout": manifest["layout"],
                     "runtime": {name: importlib.metadata.version(name) for name in
                                 ("torch", "transformers", "grpcio", "protobuf", "safetensors")}})
    client = RemoteClient(getattr(args, "coordinator", "coordinator:50052"), private_network=True)
    try:
        description = await check_cleanup(client, evidence, "before-validation")
        evidence["service_description_before"] = description
        if not description.get("ready") or description.get("fingerprint") != manifest["fingerprint"]:
            raise AssertionError("Coordinator is not ready with the reference's verified manifest")
        started = time.monotonic()
        reference = AutoModelForCausalLM.from_pretrained(
            reference_path, dtype=torch.float32, attn_implementation="eager",
            local_files_only=True, use_safetensors=True).eval().requires_grad_(False)
        evidence["control_loading_seconds"] = time.monotonic() - started
        evidence["additional_reference_parameter_bytes"] = sum(
            parameter.numel() * parameter.element_size() for parameter in reference.parameters())
        await validate_remote_cohorts(client, reference, evidence)
        prompt = fixture_tokens(31, 847, reference.config.vocab_size)
        expected = reference_logits(reference, prompt, 9)
        before_cancel = (await client.describe())["service"]["cancelled_requests"]
        interrupted = client.generate(prompt[0].tolist(), 64)
        survivor = asyncio.create_task(consume_checked(client, prompt[0].tolist(), expected,
                                                       "cancel-survivor", evidence))
        try:
            first = await anext(interrupted)
            if first.get("type") != "token" or first.get("index") != 0:
                raise AssertionError("Cancelled stream did not emit its first output")
            await interrupted.aclose()
            await survivor
        finally:
            await interrupted.aclose()
            if not survivor.done():
                survivor.cancel()
            await asyncio.gather(survivor, return_exceptions=True)
        after = await check_cleanup(client, evidence, "cancellation-and-survivor", wait_seconds=25)
        if after["service"]["cancelled_requests"] <= before_cancel:
            raise AssertionError("Closing the remote stream did not cancel its server request")
        evidence["cancelled_request"] = {"session_id": first["session_id"], "first_token_received": True,
                                         "cleanup_complete": True, "server_cancellation_recorded": True}
        evidence["service_description_after"] = after
        evidence["status"] = "passed"
    finally:
        await client.close()
        evidence["host"] = _host_evidence()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifacts", default=os.environ.get("REPLICANT_MESH_ARTIFACT_DIR", "/artifacts"))
    parser.add_argument("--reference", default=os.environ.get("REPLICANT_MESH_REFERENCE_DIR"),
                        required=not os.environ.get("REPLICANT_MESH_REFERENCE_DIR"))
    parser.add_argument("--coordinator", default="coordinator:50052")
    parser.add_argument("--output", default="/results", help="Directory for unique success/failure reports")
    args = parser.parse_args(argv)
    evidence = {"schema_version": 1, "milestone": "M5", "status": "failed",
                "created_utc": datetime.now(timezone.utc).isoformat(), "atol": ATOL, "rtol": 0,
                "execution": "thin streaming RPC client; standalone coordinator; three supervised worker containers",
                "fixture": {"prompt_formula": "3 + ((i * 37 + request_index * 211) % (vocab_size - 3))",
                            "cohorts": [{"concurrency": n, "prompt_lengths": list(lengths)} for n, lengths in COHORTS],
                            "output_tokens": 9, "forced_decode_inputs": 8,
                            "forced_formula": "3 + ((900 + request_index * 97 + step * 13) % (vocab_size - 3))"},
                "limitations": ["same-host correctness gate, not a performance or internet-capacity claim",
                                "trusted private network without authentication or encryption",
                                "additional complete-model reference memory in this validation process",
                                "M4 established worker overlap; this remote gate does not align host clocks",
                                "no automatic retry, replay or worker-loss recovery"]}
    started = time.monotonic()
    try:
        asyncio.run(run_validation(args, evidence))
    except Exception as error:
        evidence["status"] = "failed"
        evidence["error"] = {"type": type(error).__name__, "message": str(error)[:1024]}
    evidence["elapsed_seconds"] = time.monotonic() - started
    directory = Path(args.output)
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"{datetime.now(timezone.utc):%Y%m%dT%H%M%S%fZ}-{uuid.uuid4().hex[:8]}-m5-service.json"
    with path.open("x", encoding="utf-8") as stream:
        json.dump(evidence, stream, indent=2, allow_nan=False)
        stream.write("\n")
    print(json.dumps({"status": evidence["status"], "report": str(path),
                      "comparisons": len(evidence.get("comparisons", [])), "error": evidence.get("error")}))
    return 0 if evidence["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
