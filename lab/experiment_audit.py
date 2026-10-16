"""Audit saved Invoke-PytorchExperiment runs without changing their evidence.

Run: python -m lab.experiment_audit --output audit.json RUN_DIR [RUN_DIR ...]
"""

import argparse
from collections import Counter, defaultdict
import json
import math
from pathlib import Path
import re
import statistics
import sys


CONFIG_FIELDS = ("profile", "delay_ms", "rate_mbit", "prompt_tokens",
                 "new_tokens", "concurrency")
METRICS = ("ttft_seconds_p50", "ttft_seconds_p95",
           "inter_token_seconds_p50", "inter_token_seconds_p95",
           "aggregate_output_tokens_per_second")
BENCHMARK_NAME = re.compile(r"^(\d+)-.*-benchmark\.json$")
OUTCOME_NAME = re.compile(r"^(\d+)-.*-outcome\.json$")
RESET_NAME = re.compile(r"^(\d+)-.*-reset\.json$")
APPLIED_NAME = re.compile(r"^(\d+)-.*-applied\.json$")
RESET_SERVICES = {"worker-1", "worker-2", "worker-3", "coordinator"}
SMOKE_CASES = {
    ("lan", 0, 0, 128, 8, 1): 3,
    ("lan", 0, 0, 128, 8, 3): 6,
    ("lan", 0, 0, 1024, 64, 8): 8,
    ("delay10", 10, 0, 128, 8, 3): 6,
    ("rate20", 0, 20, 128, 8, 3): 6,
    ("wan25-100", 25, 100, 128, 8, 3): 6,
}


def _read_json(path):
    raw = path.read_bytes()
    encoding = "utf-16" if raw.startswith(b"\xff\xfe") else "utf-8-sig"
    return json.loads(raw.decode(encoding))


def _integer(value, name, minimum=0):
    if type(value) is not int or value < minimum:
        raise ValueError(f"{name} must be an integer >= {minimum}")
    return value


def _number(value):
    return (type(value) in (int, float) and math.isfinite(value))


def _config(case):
    return {key: case[key] for key in CONFIG_FIELDS}


def _config_key(config):
    return tuple(config.get(key) for key in CONFIG_FIELDS)


def _case_index(path, pattern):
    match = pattern.match(path.name)
    return int(match.group(1)) if match else None


def _load_case_map(directory, pattern):
    output = {}
    for path in sorted(directory.glob("*.json")):
        index = _case_index(path, pattern)
        if index is not None:
            if index in output:
                raise ValueError(f"duplicate case index {index}: {output[index].name}, {path.name}")
            output[index] = path
    return output


def _image_identity(directory, issues):
    identities = set()
    for filename in ("resources-before.json", "resources-after.json"):
        path = directory / filename
        if not path.exists():
            continue
        try:
            records = _read_json(path)
            if isinstance(records, dict):
                records = records.get("services", records.get("containers", []))
            if not isinstance(records, list):
                raise ValueError("resource metadata must be a list")
            for record in records:
                if isinstance(record, dict) and isinstance(record.get("image"), str):
                    identities.add(record["image"])
        except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as error:
            issues.append(f"{filename}: {error}")
    if len(identities) > 1:
        issues.append("resource metadata contains multiple image identities")
    return sorted(identities)


def _validate_plan(path):
    plan = _read_json(path)
    if not isinstance(plan, dict) or plan.get("mode") not in ("Smoke", "Full"):
        raise ValueError("plan must be an object with mode Smoke or Full")
    cases = plan.get("cases")
    if not isinstance(cases, list) or not cases:
        raise ValueError("plan.cases must be a non-empty list")
    seen = set()
    for index, case in enumerate(cases):
        if not isinstance(case, dict):
            raise ValueError(f"plan case {index} must be an object")
        for field in CONFIG_FIELDS:
            if field not in case:
                raise ValueError(f"plan case {index} missing {field}")
        for field in ("delay_ms", "rate_mbit", "prompt_tokens", "new_tokens", "concurrency",
                      "requests", "repetition", "maximum_attempts"):
            _integer(case.get(field), f"plan case {index}.{field}", 1 if field not in ("delay_ms", "rate_mbit") else 0)
        if not isinstance(case["profile"], str) or not case["profile"]:
            raise ValueError(f"plan case {index}.profile must be non-empty text")
        if plan["mode"] == "Full":
            if (case.get("completion_target") != 100 or case["maximum_attempts"] != 200
                    or case["requests"] != 100):
                raise ValueError(f"Full plan case {index} must target 100 completions within 200 attempts")
        elif case.get("completion_target") is not None or case["maximum_attempts"] != case["requests"]:
            raise ValueError(f"Smoke plan case {index} must use its fixed request count")
        key = (*_config_key(_config(case)), case["repetition"])
        if key in seen:
            raise ValueError(f"duplicate planned configuration/repetition at case {index}")
        seen.add(key)
    if plan["mode"] == "Smoke":
        actual = {tuple(case[key] for key in CONFIG_FIELDS): case["requests"] for case in cases}
        if actual != SMOKE_CASES or any(case["repetition"] != 1 for case in cases):
            raise ValueError("Smoke plan must contain the six fixed cases and repetition 1")
    else:
        repetitions = defaultdict(set)
        for case in cases:
            repetitions[_config_key(_config(case))].add(case["repetition"])
        if any(values != {1, 2, 3} for values in repetitions.values()):
            raise ValueError("Full plan must include repetitions 1, 2, and 3 for every configuration")
    return plan


def _validate_benchmark(path):
    data = _read_json(path)
    if not isinstance(data, dict) or type(data.get("success")) is not bool:
        raise ValueError("benchmark must be an object with boolean success")
    summary = data.get("summary")
    if not isinstance(summary, dict):
        raise ValueError("benchmark.summary must be an object")
    attempted = _integer(summary.get("attempted"), "summary.attempted")
    completed = _integer(summary.get("completed"), "summary.completed")
    failed = _integer(summary.get("failed"), "summary.failed")
    if completed + failed != attempted:
        raise ValueError("summary completed + failed does not equal attempted")
    requests = data.get("requests")
    if not isinstance(requests, list) or len(requests) != attempted:
        raise ValueError("requests must contain exactly summary.attempted entries")
    request_failures = 0
    error_counts = Counter()
    for number, request in enumerate(requests):
        if not isinstance(request, dict) or type(request.get("success")) is not bool:
            raise ValueError(f"request {number} must have boolean success")
        if not request["success"]:
            request_failures += 1
            code = request.get("error_code") or "UNKNOWN"
            if not isinstance(code, str):
                raise ValueError(f"request {number}.error_code must be text")
            error_counts[code] += 1
    if request_failures != failed:
        raise ValueError("request success flags disagree with summary.failed")
    if not isinstance(data.get("arguments"), dict):
        raise ValueError("benchmark.arguments must be an object")
    metrics = {}
    for name in METRICS:
        value = summary.get(name)
        if value is not None and not _number(value):
            raise ValueError(f"summary.{name} must be a finite number or null")
        metrics[name] = value
    if data["success"] and failed:
        raise ValueError("benchmark reports success despite failed requests")
    return data, {"attempted": attempted, "completed": completed, "failed": failed,
                  "success": data["success"], "reported_error": data.get("error"),
                  "error_code_counts": dict(sorted(error_counts.items())), **metrics}


def _reset_audit(index, outcome_files, reset_files, aggregate_cases):
    states = []
    evidence = []
    outcome_path = outcome_files.get(index)
    if outcome_path is not None:
        try:
            outcome = _read_json(outcome_path)
            verified = outcome.get("reset_verified")
            if type(verified) is bool:
                states.append("verified" if verified else "failed")
            evidence.append({"file": outcome_path.name, "reset_verified": verified,
                "error": outcome.get("error"), "reset_error": outcome.get("reset_error"),
                "probe_stop_errors": outcome.get("probe_stop_errors", [])})
        except (OSError, UnicodeError, json.JSONDecodeError, AttributeError):
            states.append("failed")
            evidence.append({"file": outcome_path.name, "error": "unreadable reset outcome"})
    aggregate_case = aggregate_cases.get(index)
    if aggregate_case and type(aggregate_case.get("reset_verified")) is bool:
        states.append("verified" if aggregate_case["reset_verified"] else "failed")
        evidence.append({"source": "summary.json", "reset_verified": aggregate_case["reset_verified"],
                         "error": aggregate_case.get("error"),
                         "probe_stop_errors": aggregate_case.get("probe_stop_errors", [])})
    path = reset_files.get(index)
    if path is not None:
        try:
            reset = _read_json(path)
            success, after = reset.get("success"), reset.get("after")
            services = reset.get("services")
            after_ok = (isinstance(after, dict) and isinstance(services, list)
                        and all(isinstance(name, str) for name in services)
                        and RESET_SERVICES <= set(services) and set(services) <= set(after)
                        and all(isinstance(after[name], str) and "qdisc noqueue " in after[name]
                                for name in services))
            state = "failed" if success is False or (success is True and after and not after_ok) else (
                    "verified" if success is True and after_ok else "missing")
            states.append(state)
            evidence.append({"file": path.name, "success": success, "after": after,
                "errors": reset.get("errors"), "error": reset.get("error"), "state": state})
        except (OSError, UnicodeError, json.JSONDecodeError, AttributeError):
            states.append("failed")
            evidence.append({"file": path.name, "error": "unreadable reset record", "state": "failed"})
    state = ("failed" if "failed" in states else "missing" if "missing" in states
             else "verified" if "verified" in states else "missing")
    return state, evidence


def audit_run(directory):
    directory = Path(directory)
    result = {"directory": str(directory), "run_id": directory.name,
              "status": "invalid", "issues": []}
    plan_path = directory / "plan.json"
    if not directory.is_dir():
        result["issues"].append("run directory does not exist")
        return result, []
    if not plan_path.exists():
        result["issues"].append("plan.json is missing")
        return result, []
    try:
        plan = _validate_plan(plan_path)
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as error:
        result["issues"].append(f"plan.json: {error}")
        return result, []

    expected = {index: case for index, case in enumerate(plan["cases"])}
    try:
        benchmark_paths = _load_case_map(directory, BENCHMARK_NAME)
        outcome_paths = _load_case_map(directory, OUTCOME_NAME)
        reset_paths = _load_case_map(directory, RESET_NAME)
        applied_paths = _load_case_map(directory, APPLIED_NAME)
    except ValueError as error:
        result["issues"].append(str(error))
        return result, []
    benchmark_logs = sorted(directory.glob("*-benchmark.log"))
    aggregate_path = directory / "summary.json"
    aggregate_cases = {}
    aggregate = None
    if aggregate_path.exists():
        try:
            aggregate = _read_json(aggregate_path)
            cases = aggregate.get("cases", []) if isinstance(aggregate, dict) else []
            if not isinstance(cases, list):
                raise ValueError("summary.cases must be a list")
            aggregate_cases = {case["index"]: case for case in cases
                               if isinstance(case, dict) and type(case.get("index")) is int}
        except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as error:
            result["issues"].append(f"summary.json: {error}")
            aggregate = None
    if not benchmark_paths and not benchmark_logs and not outcome_paths and not applied_paths and not aggregate_path.exists():
        status = "plan_only"
    elif aggregate is None:
        status = "interrupted"
    else:
        status = "executed"

    identities = _image_identity(directory, result["issues"])
    result.update({"status": status, "mode": plan["mode"],
        "planned_case_count": len(expected), "observed_benchmark_count": len(benchmark_paths),
        "benchmark_log_count": len(benchmark_logs), "applied_metadata_count": len(applied_paths),
        "image_identities": identities, "planned_cases": [], "benchmarks": [],
        "failure_count": 0, "error_code_counts": {},
        "reset_counts": {"verified": 0, "failed": 0, "missing": 0}})
    if aggregate is not None:
        result["aggregate_success"] = aggregate.get("success")
    records = []
    observed_indices = set()
    errors = Counter()
    for index, case in expected.items():
        reset_state, reset_evidence = _reset_audit(index, {}, {}, aggregate_cases)
        outcome = {"index": index, "configuration": _config(case),
                   "repetition": case["repetition"], "report": None,
                   "benchmark_success": None, "reported_error": None,
                   "observed_configuration": None,
                   "configuration_matches": None, "repetition_matches": None,
                   "completion_target_met": None, "attempt_policy_met": None,
                   "reset_state": reset_state, "reset_evidence": reset_evidence}
        path = benchmark_paths.get(index)
        if path is not None:
            try:
                data, metrics = _validate_benchmark(path)
                observed_indices.add(index)
                args = data.get("arguments", {})
                actual = {"profile": None, "delay_ms": None, "rate_mbit": None,
                          "profile_applied": False,
                          "prompt_tokens": args.get("prompt_tokens"),
                          "new_tokens": args.get("new_tokens"),
                          "concurrency": args.get("concurrency")}
                applied_path = applied_paths.get(index)
                if applied_path is not None:
                    try:
                        applied = _read_json(applied_path)
                        actual.update({key: applied.get(key) for key in ("profile", "delay_ms", "rate_mbit")})
                        actual["profile_applied"] = applied.get("success") is True
                    except (OSError, UnicodeError, json.JSONDecodeError, AttributeError) as error:
                        result["issues"].append(f"{applied_path.name}: {error}")
                else:
                    result["issues"].append(f"case {index}: applied network profile metadata is missing")
                outcome["observed_configuration"] = actual
                profile_matches = (actual["profile"] == case["profile"] or
                    (actual["profile"] == "custom" and actual["delay_ms"] == case["delay_ms"]
                     and actual["rate_mbit"] == case["rate_mbit"]))
                config_matches = (actual["profile_applied"] and profile_matches
                                  and all(actual[key] == case[key] for key in CONFIG_FIELDS[1:]))
                outcome["configuration_matches"] = config_matches
                if not config_matches:
                    result["issues"].append(f"{path.name}: observed workload/network configuration disagrees with plan")
                repetition_matches = args.get("repetition") == case["repetition"]
                outcome["repetition_matches"] = repetition_matches
                if not repetition_matches:
                    result["issues"].append(f"{path.name}: repetition disagrees with plan")
                if metrics["attempted"] > case["maximum_attempts"]:
                    result["issues"].append(f"{path.name}: attempts exceed planned maximum")
                if plan["mode"] == "Full":
                    met = metrics["completed"] >= case["completion_target"]
                    outcome["completion_target_met"] = met
                    outcome["attempt_policy_met"] = metrics["attempted"] <= case["maximum_attempts"]
                else:
                    outcome["attempt_policy_met"] = metrics["attempted"] == case["requests"]
                outcome["reset_state"], outcome["reset_evidence"] = _reset_audit(
                    index, outcome_paths, reset_paths, aggregate_cases)
                outcome["report"] = path.name
                outcome["benchmark_success"] = data["success"]
                outcome["reported_error"] = data.get("error")
                for code, count in metrics["error_code_counts"].items():
                    errors[code] += count
                record = {"run_id": plan.get("run_id", directory.name),
                          "directory": str(directory), "image_identity": identities[0] if len(identities) == 1 else None,
                          "configuration": _config(case), "repetition": case["repetition"],
                          "report": path.name, **metrics,
                          "completion_target_met": outcome["completion_target_met"],
                          "reset_state": outcome["reset_state"]}
                if config_matches and repetition_matches:
                    records.append(record)
                result["benchmarks"].append(record)
            except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as error:
                result["issues"].append(f"{path.name}: {error}")
        else:
            outcome["reset_state"], outcome["reset_evidence"] = _reset_audit(
                index, outcome_paths, reset_paths, aggregate_cases)
        result["reset_counts"][outcome["reset_state"]] += 1
        result["planned_cases"].append(outcome)
    unexpected = sorted(set(benchmark_paths) - set(expected))
    if unexpected:
        result["issues"].append(f"unexpected benchmark case indices: {unexpected}")
    missing = sorted(set(expected) - observed_indices)
    config_mismatches = [case["index"] for case in result["planned_cases"]
                         if case["configuration_matches"] is False]
    repetition_mismatches = [case["index"] for case in result["planned_cases"]
                             if case["repetition_matches"] is False]
    completion_misses = [case["index"] for case in result["planned_cases"]
                         if case["completion_target_met"] is False]
    attempt_policy_misses = [case["index"] for case in result["planned_cases"]
                             if case["attempt_policy_met"] is False]
    result["coverage"] = {"planned": len(expected), "observed": len(observed_indices),
                          "missing_case_indices": missing, "unexpected_case_indices": unexpected,
                          "configuration_mismatch_indices": config_mismatches,
                          "repetition_mismatch_indices": repetition_mismatches,
                          "completion_target_miss_indices": completion_misses,
                          "attempt_policy_miss_indices": attempt_policy_misses,
                          "complete": not missing and not unexpected and not config_mismatches
                                     and not repetition_mismatches and not completion_misses
                                     and not attempt_policy_misses}
    result["failure_count"] = sum(record["failed"] for record in result["benchmarks"])
    result["error_code_counts"] = dict(sorted(errors.items()))
    final_reset_states = []
    if aggregate is not None and type(aggregate.get("final_reset_verified")) is bool:
        final_reset_states.append("verified" if aggregate["final_reset_verified"] else "failed")
    final_reset_path = directory / "final-reset.json"
    if final_reset_path.exists():
        reset_state, result["final_reset_evidence"] = _reset_audit(0, {}, {0: final_reset_path}, {})
        final_reset_states.append(reset_state)
    result["final_reset_state"] = ("failed" if "failed" in final_reset_states else
        "missing" if "missing" in final_reset_states else
        "verified" if final_reset_states else "missing")
    return result, records


def _mean_spread(values):
    values = [float(value) for value in values if value is not None]
    if not values:
        return None
    return {"mean": statistics.fmean(values), "min": min(values), "max": max(values),
            "range": max(values) - min(values)}


def compare_repetitions(records):
    groups = defaultdict(list)
    for record in records:
        image_key = record["image_identity"] or f"unverified:{record['run_id']}"
        key = (_config_key(record["configuration"]), image_key)
        groups[key].append(record)
    comparisons = []
    for (configuration, image_key), group in sorted(groups.items(), key=lambda item: str(item[0])):
        reps = sorted(record["repetition"] for record in group)
        unique_reps = sorted(set(reps))
        complete = unique_reps == [1, 2, 3] and len(reps) == 3
        comparison = {"configuration": dict(zip(CONFIG_FIELDS, configuration)),
            "image_identity": None if image_key.startswith("unverified:") else image_key,
            "image_identity_verified": not image_key.startswith("unverified:"),
            "repetitions": group,
            "three_repetitions_present": complete,
            "duplicate_repetitions": sorted(rep for rep, count in Counter(reps).items() if count > 1),
            "all_completion_targets_met": (all(r["completion_target_met"] for r in group)
                if all(r["completion_target_met"] is not None for r in group) else None),
            "all_resets_verified": all(r["reset_state"] == "verified" for r in group)}
        comparison["metrics_across_repetitions"] = {
            metric: _mean_spread([record[metric] for record in group]) for metric in METRICS}
        comparisons.append(comparison)
    return comparisons


def build_audit(run_directories):
    runs = []
    records = []
    for directory in run_directories:
        run, run_records = audit_run(directory)
        runs.append(run)
        records.extend(run_records)
    return {"schema_version": 1, "runs": runs,
            "repetition_comparisons": compare_repetitions(records),
            "research_gate_complete": False}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path,
                        help="new JSON output path; existing files are never overwritten")
    parser.add_argument("run_directories", nargs="+", type=Path)
    args = parser.parse_args(argv)
    if args.output.exists():
        parser.error(f"output already exists: {args.output}")
    report = build_audit(args.run_directories)
    try:
        with args.output.open("x", encoding="utf-8", newline="\n") as stream:
            json.dump(report, stream, indent=2, allow_nan=False)
            stream.write("\n")
    except FileExistsError:
        parser.error(f"output already exists: {args.output}")
    except (OSError, TypeError, ValueError) as error:
        parser.error(f"could not write audit: {error}")
    print(args.output)
    return 0


if __name__ == "__main__":
    sys.exit(main())
