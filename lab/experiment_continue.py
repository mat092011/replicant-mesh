"""Create immutable continuation plans for preserved PyTorch lab runs.

This module only reads prior evidence and writes a new, exclusive plan directory.
It never starts Docker or edits a parent run.
"""

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import sys

from lab.experiment_audit import _validate_benchmark, _validate_plan, audit_run


def sha256(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def evidence_sha256(directory):
    root = Path(directory)
    digest = hashlib.sha256()
    for path in sorted((item for item in root.rglob("*") if item.is_file()),
                       key=lambda item: item.relative_to(root).as_posix()):
        digest.update(path.relative_to(root).as_posix().encode("utf-8"))
        digest.update(b"\0")
        digest.update(bytes.fromhex(sha256(path)))
        digest.update(b"\n")
    return digest.hexdigest()


def _completed_case(directory, index, case, audited_case):
    prefix = f"{index:03d}-"
    reports = list(directory.glob(prefix + "*-benchmark.json"))
    outcomes = list(directory.glob(prefix + "*-outcome.json"))
    if len(reports) != 1 or len(outcomes) != 1:
        return False
    try:
        report, metrics = _validate_benchmark(reports[0])
        outcome = json.loads(outcomes[0].read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError):
        return False
    args = report.get("arguments", {})
    if not (audited_case.get("configuration_matches") is True
            and audited_case.get("repetition_matches") is True
            and audited_case.get("attempt_policy_met") is True
            and (audited_case.get("completion_target_met") is True
                 if case["completion_target"] is not None
                 else audited_case.get("completion_target_met") is None)
            and audited_case.get("reset_state") == "verified"
            and report["success"] is True and outcome.get("success") is True
            and outcome.get("reset_verified") is True
            and args.get("requests") == case["requests"]):
        return False
    reset_files = list(directory.glob(f"{index:03d}-*-reset.json"))
    if len(reset_files) != 1:
        return False
    try:
        reset = json.loads(reset_files[0].read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return False
    expected_services = {"worker-1", "worker-2", "worker-3", "coordinator"}
    after = reset.get("after")
    return bool(reset.get("success") is True and isinstance(reset.get("services"), list)
                and set(reset["services"]) == expected_services and isinstance(after, dict)
                and set(after) == expected_services
                and all(isinstance(after.get(service), str)
                        and re.search(
                            r"(?m)^qdisc noqueue\s+[^\r\n]*\broot\b", after[service])
                        for service in expected_services))


def continuation_plan(parent, destination):
    parent = Path(parent).resolve()
    destination = Path(destination).resolve()
    plan_path = parent / "plan.json"
    plan = _validate_plan(plan_path)
    audit, _ = audit_run(parent)
    if audit["status"] == "invalid":
        raise ValueError("parent run is invalid; inspect its audit issues first")
    audited_cases = audit.get("planned_cases", [])
    pending_indices = [index for index, case in enumerate(plan["cases"])
                       if index >= len(audited_cases)
                       or not _completed_case(parent, index, case, audited_cases[index])]
    pending = [plan["cases"][index] for index in pending_indices]
    if not pending:
        raise ValueError("parent has no unfinished cases to continue")
    if destination.exists():
        raise FileExistsError(f"refusing to overwrite continuation destination: {destination}")
    source_commit = plan.get("source_commit")
    source_fingerprint = plan.get("source_fingerprint")
    compose_sha = plan.get("compose_sha256")
    if (not source_commit or not isinstance(source_fingerprint, str)
            or not re.fullmatch(r"[0-9a-f]{64}", source_fingerprint)
            or not isinstance(compose_sha, str)
            or not re.fullmatch(r"[0-9a-f]{64}", compose_sha)):
        raise ValueError("parent plan lacks pinned source, source fingerprint, or compose compatibility")
    parent_images = audit.get("image_identities", [])
    if audit["status"] != "plan_only":
        if len(parent_images) != 1 or parent_images[0] != plan.get("runtime_image"):
            raise ValueError("executed parent image identity is missing, ambiguous, or differs from its plan")
    pinned_image = parent_images[0] if len(parent_images) == 1 else plan.get("runtime_image")
    if not isinstance(pinned_image, str) or not pinned_image.startswith("sha256:"):
        raise ValueError("parent runtime image digest is missing or ambiguous")
    child = dict(plan)
    child.update({
        "run_id": destination.name,
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "cases": pending,
        "continuation": {
            "parent_run_id": plan.get("run_id", parent.name),
            "parent_directory": str(parent),
            "parent_plan_sha256": sha256(plan_path),
            "parent_evidence_sha256": evidence_sha256(parent),
            "parent_audit_status": audit["status"],
            "parent_runtime_image": pinned_image,
            "preserve_parent_attempts": True,
            "unfinished_case_indices": pending_indices,
        },
    })
    destination.mkdir(parents=True)
    try:
        with (destination / "plan.json").open("x", encoding="utf-8", newline="\n") as stream:
            json.dump(child, stream, indent=2, allow_nan=False)
            stream.write("\n")
    except Exception:
        # Keep the directory if writing began: it is evidence of a failed creation.
        raise
    return child


def estimate_remaining(parent, observations=()):
    parent = Path(parent).resolve()
    plan = _validate_plan(parent / "plan.json")
    audit, records = audit_run(parent)
    audited_cases = audit.get("planned_cases", [])
    pending = [(index, case) for index, case in enumerate(plan["cases"])
               if index >= len(audited_cases)
               or not _completed_case(parent, index, case, audited_cases[index])]
    samples = {}
    target_image = audit.get("image_identities", [plan.get("runtime_image")])
    target_image = target_image[0] if len(target_image) == 1 else plan.get("runtime_image")
    sources = [(parent, plan, audit, records)]
    rejected_observations = []
    for observation in observations:
        observation = Path(observation).resolve()
        try:
            history_plan = _validate_plan(observation / "plan.json")
            history_audit, history_records = audit_run(observation)
            history_images = history_audit.get("image_identities", [])
            if (history_audit["status"] == "invalid"
                    or history_plan.get("source_fingerprint") != plan.get("source_fingerprint")
                    or history_plan.get("compose_sha256") != plan.get("compose_sha256")
                    or history_plan.get("runtime_image") != plan.get("runtime_image")
                    or history_images != [target_image]):
                rejected_observations.append({"directory": str(observation),
                    "reason": "source, compose, runtime image, or observed image identity is incompatible"})
                continue
            sources.append((observation, history_plan, history_audit, history_records))
        except (OSError, ValueError, json.JSONDecodeError) as error:
            rejected_observations.append({"directory": str(observation), "reason": str(error)})
    for _, history_plan, _, history_records in sources:
        for record in history_records:
            duration = record.get("observed_duration_seconds")
            if duration is not None and duration > 0 and record.get("image_identity") == target_image:
                key = tuple(record["configuration"].get(field) for field in
                            ("profile", "delay_ms", "rate_mbit", "prompt_tokens",
                             "new_tokens", "concurrency"))
                samples.setdefault(key, []).append(duration)
    estimates = []
    for index, case in pending:
        key = tuple(case[field] for field in
                    ("profile", "delay_ms", "rate_mbit", "prompt_tokens",
                     "new_tokens", "concurrency"))
        values = samples.get(key, [])
        estimates.append({"case_index": index, "configuration": case,
            "sample_count": len(values),
            "estimate_seconds": sorted(values)[len(values) // 2] if values else None,
            "low_seconds": min(values) if values else None,
            "high_seconds": max(values) if values else None,
            "basis": "observed same-configuration monotonic benchmark wall times"
                     if values else "no matching observed timings; estimate unavailable"})
    known = [item for item in estimates if item["estimate_seconds"] is not None]
    return {"parent_run_id": plan.get("run_id", parent.name),
        "estimate_kind": "continuation dry-run using only source/compose/image-compatible observations",
        "audit_status": audit["status"], "pending_case_count": len(pending),
        "estimated_seconds": sum(item["estimate_seconds"] for item in known)
                             if len(known) == len(estimates) else None,
        "uncertainty_low_seconds": sum(item["low_seconds"] for item in known)
                                   if len(known) == len(estimates) else None,
        "uncertainty_high_seconds": sum(item["high_seconds"] for item in known)
                                    if len(known) == len(estimates) else None,
        "cases": estimates,
        "rejected_observations": rejected_observations,
        "limitations": ["estimate covers benchmark wall time only; setup, shaping, probes, resets and recovery are excluded",
                        "min/max observed same-configuration durations are a sample range, not a confidence interval",
                        "failed attempts and retries remain in the parent evidence"]}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("parent", type=Path)
    parser.add_argument("--output", type=Path,
                        help="new exclusive directory for plan.json")
    parser.add_argument("--estimate", action="store_true",
                        help="print a dry-run duration estimate; do not create a plan")
    parser.add_argument("--observations", type=Path, action="append", default=[],
                        help="additional compatible historical run directory for duration estimates")
    args = parser.parse_args(argv)
    try:
        if args.estimate:
            print(json.dumps(estimate_remaining(args.parent, args.observations), indent=2, allow_nan=False))
            return 0
        if args.output is None:
            parser.error("--output is required unless --estimate is used")
        continuation_plan(args.parent, args.output)
    except (OSError, ValueError) as error:
        parser.error(str(error))
    print(args.output / "plan.json")
    return 0


if __name__ == "__main__":
    sys.exit(main())
