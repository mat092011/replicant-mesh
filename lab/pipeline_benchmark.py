"""Thin remote load generator; imports neither model weights nor tokenizers.

All request timings are measured on this client's monotonic clock. Server-local
durations are retained as diagnostics, never subtracted from remote timestamps.
"""

import asyncio
from contextlib import aclosing
import math
from pathlib import Path
import time

from lab.config import percentile, summarize_requests


def resource_snapshot():
    result = {}
    try:
        import resource
        result["process_peak_rss_bytes"] = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss * 1024
    except ImportError:
        result["process_peak_rss_bytes"] = None
    for name, path in (("cgroup_memory_current_bytes", "/sys/fs/cgroup/memory.current"),
                       ("cgroup_memory_peak_bytes", "/sys/fs/cgroup/memory.peak")):
        try:
            result[name] = int(Path(path).read_text().strip())
        except (OSError, ValueError):
            result[name] = None
    return result


def assert_reclaimed(description):
    """Cleanup is a gate, not an inference from a successful token stream."""
    workers = description.get("workers")
    if not isinstance(workers, list) or len(workers) != 3:
        raise AssertionError("Describe must report all three worker resource counters")
    for worker in workers:
        for name in ("active_sessions", "reserved_positions", "allocated_cache_bytes",
                     "active_operations", "queued_operations"):
            if worker.get(name) != 0:
                raise AssertionError(f"Worker retains {name} after requests finished")
        if worker.get("cache_bytes_exact") is not True:
            raise AssertionError("Worker did not provide exact logical cache accounting")
    scheduler = description.get("scheduler", {})
    if scheduler.get("active_requests") != 0 or scheduler.get("waiting_admissions") != 0:
        raise AssertionError("Coordinator retains active or waiting requests")
    for name in ("stage_queue_sizes", "active_stage_calls"):
        if scheduler.get(name) != [0, 0, 0]:
            raise AssertionError(f"Coordinator retains {name} after requests finished")
    service = description.get("service", {})
    if service.get("active_streams") != 0:
        raise AssertionError("Coordinator retains active client streams")
    if service.get("metrics_sessions") != 0:
        raise AssertionError("Coordinator retains request metrics after cleanup")


def assert_matched_reclaimed(description):
    """Check actual cache, session and operation counters from each replica."""
    if description.get("control_kind") != "matched_complete_model_replica":
        raise AssertionError("Expected the matched complete-model control")
    replicas = description.get("replicas")
    if not isinstance(replicas, list) or len(replicas) != 4:
        raise AssertionError("Describe must report all four complete-model replicas")
    fingerprints = {replica.get("fingerprint") for replica in replicas}
    if len(fingerprints) != 1 or None in fingerprints:
        raise AssertionError("Complete-model replicas do not share one pinned identity")
    for index, replica in enumerate(replicas, 1):
        if not replica.get("ready"):
            raise AssertionError(f"Complete-model replica {index} is not ready")
        service = replica.get("service", {})
        for name in ("active_streams", "active_sessions", "active_operations",
                     "queued_operations", "allocated_cache_bytes"):
            if service.get(name) != 0:
                raise AssertionError(f"Replica {index} retains {name}")
        if service.get("cache_bytes_exact") is not True:
            raise AssertionError(f"Replica {index} lacks exact cache accounting")


async def generate_remote_request(client, prompt, new_tokens, request_id, *, timeout_seconds=300):
    """Retain partial output and terminal diagnostics for every attempted stream."""
    started = time.monotonic()
    times, output, terminal = [], [], None
    record = {"request_id": request_id, "success": False, "retry_count": 0,
              "cleanup_complete": False, "output_tokens": 0}
    try:
        async with aclosing(client.generate(prompt, new_tokens, timeout_seconds=timeout_seconds)) as stream:
            async for event in stream:
                if not isinstance(event, dict):
                    raise ValueError("Coordinator returned a malformed event")
                kind = event.get("type")
                if kind == "token":
                    if terminal is not None or event.get("index") != len(output) or len(output) >= new_tokens:
                        raise ValueError("Coordinator duplicated, reordered, or exceeded requested output")
                    token = event.get("token_id")
                    if type(token) is not int or token < 0:
                        raise ValueError("Coordinator returned an invalid token ID")
                    output.append(token)
                    times.append(time.monotonic())
                    if event.get("session_id"):
                        record["session_id"] = event["session_id"]
                elif kind == "result":
                    if terminal is not None:
                        raise ValueError("Coordinator returned multiple terminal results")
                    terminal = event
                    # RemoteClient yields a failed result before raising its
                    # RemoteError on the next iteration. Save diagnostics now.
                    record.update(status=terminal.get("status"),
                                  cleanup_complete=terminal.get("cleanup_complete") is True,
                                  server_metrics=terminal.get("metrics", {}),
                                  error_code=terminal.get("error_code"))
                    if terminal.get("session_id"):
                        record["session_id"] = terminal["session_id"]
                else:
                    raise ValueError(f"Coordinator returned unknown event type: {kind}")
        if terminal is None:
            raise ValueError("Coordinator stream ended without a terminal result")
        if terminal.get("token_ids") != output:
            raise ValueError("Terminal token IDs do not match the streamed sequence")
        if terminal.get("status") != "completed" or terminal.get("error"):
            raise RuntimeError(terminal.get("error") or f"Request ended as {terminal.get('status')}")
        if len(output) != new_tokens or not record["cleanup_complete"]:
            raise ValueError("Request ended with incomplete output or unreclaimed resources")
        record["success"] = True
    except Exception as error:
        record["error"] = f"{type(error).__name__}: {error}"
        code = getattr(error, "code", None)
        if isinstance(code, str):
            record["error_code"] = code
        elif isinstance(error, TimeoutError):
            record["error_code"] = "TIMEOUT"
        elif not record.get("error_code"):
            record["error_code"] = "STREAM_FAILED"
        if terminal is not None:
            record["terminal_result"] = terminal
    intervals = [later - earlier for earlier, later in zip(times, times[1:])]
    decode = sum(intervals)
    record.update(output_tokens=len(output), output_token_ids=output,
                  ttft_seconds=times[0] - started if times else None,
                  inter_token_seconds=intervals,
                  inter_token_seconds_p50=percentile(intervals, 50),
                  inter_token_seconds_p95=percentile(intervals, 95),
                  decode_output_tokens_per_second=len(intervals) / decode if decode > 0 else None,
                  elapsed_seconds=time.monotonic() - started)
    return record


async def run_remote_bench(args, report, *, client=None):
    from lab.benchmark import FIXTURE, record_attempt_policy, validate_attempt_policy, validate_workload
    validate_workload(args.prompt_tokens, args.new_tokens, args.concurrency, args.requests)
    target, maximum = validate_attempt_policy(args)
    timeout = getattr(args, "timeout_seconds", 300)
    if not math.isfinite(timeout) or not 0 < timeout <= 300:
        raise ValueError("Request timeout must be finite and in (0, 300] seconds")
    if client is None:
        from replicant_mesh.remote_client import RemoteClient
        client = RemoteClient(getattr(args, "coordinator", "coordinator:50052"), private_network=True)
    report.update(client_model_parameter_bytes=0, retry_policy="no automatic retries",
                  timing="monotonic client wall time from RPC submission; includes admission; loading, tokenization and warm-up excluded",
                  unmeasured=["energy", "thermal throttling", "network transfer vs serialization time split",
                              "worker qdiscs and link probes (capture with experiment runner)",
                              "cross-host clock alignment and compute overlap"],
                  client_resources_before=resource_snapshot())
    try:
        description = await client.describe()
        report["service_description_before"] = description
        if not description.get("ready"):
            raise RuntimeError("Coordinator is not ready")
        position_limit = description["limits"]["max_positions"]
        if args.prompt_tokens + args.new_tokens > position_limit:
            raise ValueError(f"Workload exceeds coordinator context limit {position_limit}")
        vocab = description["config"]["vocab_size"]
        started = time.monotonic()
        fixture = await client.tokenize(FIXTURE, add_special_tokens=False)
        report["fixture_tokenization_seconds"] = time.monotonic() - started
        if not fixture or any(type(token) is not int or not 0 <= token < vocab for token in fixture):
            raise ValueError("Coordinator returned an invalid public fixture")
        prompt = (fixture * ((args.prompt_tokens + len(fixture) - 1) // len(fixture)))[:args.prompt_tokens]
        report["prompt_token_ids"] = prompt
        report["model_loading_seconds"] = description.get("service", {}).get("loading_seconds")
        if hasattr(client, "warmup_all"):
            warmups = await client.warmup_all(prompt, args.new_tokens, timeout)
            report["replica_warmups"] = warmups
            if not all(item["success"] for item in warmups):
                raise RuntimeError("At least one complete-model replica warm-up failed")
        warmup = await generate_remote_request(client, prompt, args.new_tokens, "warmup", timeout_seconds=timeout)
        report["warmup"] = warmup
        if not warmup["success"]:
            raise RuntimeError(f"Warm-up failed: {warmup.get('error')}")
        after_warmup = await client.describe()
        (assert_matched_reclaimed if after_warmup.get("control_kind") == "matched_complete_model_replica"
         else assert_reclaimed)(after_warmup)
        records, next_id, completed = [], 0, 0

        async def client_loop():
            nonlocal next_id, completed
            while next_id < maximum and (target is None or completed < target):
                request_id = next_id
                next_id += 1
                record = await generate_remote_request(client, prompt, args.new_tokens, request_id,
                                                       timeout_seconds=timeout)
                records.append(record)
                completed += int(record["success"])

        started = time.monotonic()
        try:
            await asyncio.gather(*(client_loop() for _ in range(args.concurrency)))
        finally:
            elapsed = time.monotonic() - started
            report["requests"] = sorted(records, key=lambda record: record["request_id"])
            report["summary"] = summarize_requests(records, elapsed)
            report["partial_output_tokens_from_failed_requests"] = sum(
                record["output_tokens"] for record in records if not record["success"])
            report["success"] = bool(records) and all(record["success"] for record in records)
            report["error_counts"] = {code: sum(record.get("error_code") == code for record in records)
                                      for code in sorted({record["error_code"] for record in records
                                                          if record.get("error_code")})}
            record_attempt_policy(report, target, maximum)
        report["service_description_after"] = await client.describe()
        after = report["service_description_after"]
        (assert_matched_reclaimed if after.get("control_kind") == "matched_complete_model_replica"
         else assert_reclaimed)(after)
    finally:
        report["client_resources_after"] = resource_snapshot()
        await client.close()
