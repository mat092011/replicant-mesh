import json
from pathlib import Path
import tempfile
import unittest

from lab.experiment_audit import audit_run, build_audit, main
from lab.experiment_continue import continuation_plan, estimate_remaining


def full_plan(run_id="synthetic-run"):
    base = {"profile": "lan", "delay_ms": 0, "rate_mbit": 0,
            "prompt_tokens": 128, "new_tokens": 64, "concurrency": 3,
            "requests": 100, "completion_target": 100,
            "maximum_attempts": 200}
    cases = [{**base, "repetition": repetition} for repetition in (1, 2, 3)]
    return {"mode": "Full", "run_id": run_id, "source_commit": "abc123",
            "source_fingerprint": "b" * 64, "compose_sha256": "a" * 64,
            "runtime_image": "sha256:" + "a" * 64, "cases": cases}


def smoke_plan(run_id="smoke-run"):
    rows = (("lan", 0, 0, 128, 8, 1, 3), ("lan", 0, 0, 128, 8, 3, 6),
            ("lan", 0, 0, 1024, 64, 8, 8), ("delay10", 10, 0, 128, 8, 3, 6),
            ("rate20", 0, 20, 128, 8, 3, 6), ("wan25-100", 25, 100, 128, 8, 3, 6))
    cases = [{"profile": p, "delay_ms": d, "rate_mbit": r, "prompt_tokens": n,
              "new_tokens": o, "concurrency": c, "requests": q,
              "completion_target": None, "maximum_attempts": q, "repetition": 1}
             for p, d, r, n, o, c, q in rows]
    return {"mode": "Smoke", "run_id": run_id, "cases": cases}


def write_json(path, data):
    path.write_text(json.dumps(data), encoding="utf-8")


def prepare_run(directory, image="sha256:" + "a" * 64, summary=True):
    directory.mkdir(parents=True)
    plan = full_plan(directory.name)
    write_json(directory / "plan.json", plan)
    write_json(directory / "resources-before.json", [{"service": "worker-1", "image": image}])
    if summary:
        write_json(directory / "summary.json", {"success": True,
            "final_reset_verified": True, "cases": [
                {"index": i, "reset_verified": True} for i in range(3)]})
    return plan


def write_case(directory, index, plan, image=None, completed=100, failed=0,
               reset=True, include_benchmark=True):
    case = plan["cases"][index]
    stem = f"{index:03d}-lan-p128-c3-r{case['repetition']}"
    write_json(directory / f"{stem}-applied.json", {
        "profile": case["profile"], "delay_ms": case["delay_ms"],
        "rate_mbit": case["rate_mbit"], "success": True})
    write_json(directory / f"{stem}-outcome.json", {
        "index": index, "reset_verified": reset, "success": reset})
    write_json(directory / f"{stem}-reset.json", {
        "success": reset, "services": ["worker-1", "worker-2", "worker-3", "coordinator"],
        "after": {service: "qdisc noqueue 0: root refcnt 2" for service in
                  ("worker-1", "worker-2", "worker-3", "coordinator")} if reset else {}})
    if not include_benchmark:
        return
    attempted = completed + failed
    requests = ([{"success": True, "output_tokens": case["new_tokens"]} for _ in range(completed)]
                + [{"success": False, "error_code": "CAPACITY_EXHAUSTED"}
                   for _ in range(failed)])
    metrics = {"attempted": attempted, "completed": completed, "failed": failed,
        "ttft_seconds_p50": 0.2 * case["repetition"],
        "ttft_seconds_p95": 0.3 * case["repetition"],
        "inter_token_seconds_p50": 0.1 * case["repetition"],
        "inter_token_seconds_p95": 0.15 * case["repetition"],
        "aggregate_output_tokens_per_second": 20.0 / case["repetition"]}
    write_json(directory / f"{stem}-benchmark.json", {
        "success": failed == 0,
        "arguments": {"prompt_tokens": case["prompt_tokens"],
                      "new_tokens": case["new_tokens"],
                      "concurrency": case["concurrency"],
                      "repetition": case["repetition"], "requests": case["requests"]},
        "attempt_policy": {"completion_target": case["completion_target"],
                           "maximum_attempts": case["maximum_attempts"]},
        "summary": {**metrics, "aggregate_output_tokens_per_second": 20.0}, "requests": requests,
        "error_counts": {"CAPACITY_EXHAUSTED": failed} if failed else {}})


class ExperimentAuditTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parents[1])
        self.root = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def test_full_coverage_summarizes_three_same_image_repetitions(self):
        directory = self.root / "full"
        plan = prepare_run(directory)
        for index in range(3):
            write_case(directory, index, plan)
        audit = build_audit([directory])
        run = audit["runs"][0]
        self.assertEqual(run["status"], "executed")
        self.assertTrue(run["coverage"]["complete"])
        self.assertEqual(run["failure_count"], 0)
        comparison = audit["repetition_comparisons"][0]
        self.assertTrue(comparison["three_repetitions_present"])
        self.assertTrue(comparison["all_completion_targets_met"])
        self.assertAlmostEqual(
            comparison["metrics_across_repetitions"]["ttft_seconds_p50"]["mean"], 0.4)
        self.assertTrue(audit["research_gate_complete"] is False)

    def test_underfilled_full_repetitions_keep_failures_and_target_status(self):
        directory = self.root / "underfilled"
        plan = prepare_run(directory)
        for index in range(3):
            write_case(directory, index, plan, completed=63, failed=137)
        run = audit_run(directory)[0]
        self.assertEqual(run["failure_count"], 411)
        self.assertEqual(run["error_code_counts"], {"CAPACITY_EXHAUSTED": 411})
        self.assertFalse(run["coverage"]["complete"])
        self.assertEqual(run["coverage"]["completion_target_miss_indices"], [0, 1, 2])
        self.assertTrue(all(case["completion_target_met"] is False
                            for case in run["planned_cases"]))
        self.assertEqual(run["reset_counts"]["verified"], 3)

    def test_missing_repetition_and_reset_stay_interrupted_and_explicit(self):
        directory = self.root / "interrupted"
        plan = prepare_run(directory, summary=False)
        write_case(directory, 0, plan, reset=True)
        write_case(directory, 1, plan, reset=False, include_benchmark=False)
        run = audit_run(directory)[0]
        self.assertEqual(run["status"], "interrupted")
        self.assertEqual(run["coverage"]["missing_case_indices"], [1, 2])
        self.assertEqual(run["reset_counts"], {"verified": 1, "failed": 1, "missing": 1})
        self.assertEqual(run["final_reset_state"], "missing")

    def test_runs_from_distinct_images_are_not_combined(self):
        audits = []
        for name, image in (("image-a", "sha256:" + "a" * 64),
                            ("image-b", "sha256:" + "b" * 64)):
            directory = self.root / name
            plan = prepare_run(directory, image=image)
            for index in range(3):
                write_case(directory, index, plan)
            audits.append(directory)
        audit = build_audit(audits)
        comparisons = audit["repetition_comparisons"]
        self.assertEqual(len(comparisons), 2)
        self.assertEqual({item["image_identity"] for item in comparisons},
                         {"sha256:" + "a" * 64, "sha256:" + "b" * 64})
        self.assertTrue(all(len(item["repetitions"]) == 3 for item in comparisons))

    def test_corrupt_plan_is_reported_without_claiming_execution(self):
        directory = self.root / "malformed"
        directory.mkdir()
        (directory / "plan.json").write_text("{broken", encoding="utf-8")
        run, records = audit_run(directory)
        self.assertEqual(run["status"], "invalid")
        self.assertEqual(records, [])
        self.assertTrue(run["issues"])

    def test_corrupt_benchmark_is_reported_and_does_not_count_as_observed(self):
        directory = self.root / "bad-report"
        plan = prepare_run(directory)
        write_case(directory, 0, plan)
        report = next(directory.glob("*-benchmark.json"))
        report.write_text("{bad", encoding="utf-8")
        run = audit_run(directory)[0]
        self.assertEqual(run["status"], "executed")
        self.assertEqual(run["coverage"]["observed"], 0)
        self.assertEqual(run["failure_count"], 0)
        self.assertTrue(any("benchmark.json" in issue for issue in run["issues"]))

    def test_unsuccessful_report_with_zero_request_failures_keeps_metrics_and_error(self):
        directory = self.root / "terminal-error"
        plan = prepare_run(directory)
        write_case(directory, 0, plan)
        report = next(directory.glob("*-benchmark.json"))
        data = json.loads(report.read_text(encoding="utf-8"))
        data["success"] = False
        data["error"] = "post-run cleanup failed"
        write_json(report, data)
        run = audit_run(directory)[0]
        self.assertEqual(run["coverage"]["observed"], 1)
        self.assertEqual(run["benchmarks"][0]["failed"], 0)
        self.assertEqual(run["benchmarks"][0]["reported_error"], "post-run cleanup failed")

    def test_reset_success_requires_complete_noqueue_evidence(self):
        directory = self.root / "bad-reset-evidence"
        plan = prepare_run(directory, summary=False)
        write_case(directory, 0, plan)
        reset = {"success": True, "services": ["worker-1", "coordinator"], "after": {}}
        write_json(directory / "000-lan-p128-c3-r1-reset.json", reset)
        run = audit_run(directory)[0]
        case = run["planned_cases"][0]
        self.assertEqual(case["reset_state"], "missing")
        self.assertFalse(case["reset_evidence"][-1]["after"])

    def test_plan_only_is_separate_from_interrupted(self):
        directory = self.root / "planned"
        plan = prepare_run(directory, summary=False)
        write_json(directory / "plan.json", plan)
        audit = audit_run(directory)[0]
        self.assertEqual(audit["status"], "plan_only")
        self.assertEqual(audit["planned_case_count"], 3)

    def test_smoke_plan_requires_the_fixed_six_cases_and_counts(self):
        directory = self.root / "smoke-plan"
        directory.mkdir()
        plan = smoke_plan()
        write_json(directory / "plan.json", plan)
        self.assertEqual(audit_run(directory)[0]["status"], "plan_only")
        plan["cases"][0]["requests"] += 1
        write_json(directory / "plan.json", plan)
        self.assertEqual(audit_run(directory)[0]["status"], "invalid")

    def test_cli_writes_explicit_output_and_refuses_overwrite(self):
        directory = self.root / "planned"
        plan = prepare_run(directory, summary=False)
        write_json(directory / "plan.json", plan)
        output = self.root / "audit.json"
        self.assertEqual(main(["--output", str(output), str(directory)]), 0)
        self.assertTrue(json.loads(output.read_text(encoding="utf-8"))["runs"])
        with self.assertRaises(SystemExit):
            main(["--output", str(output), str(directory)])

    def test_continuation_keeps_only_unfinished_cases_and_parent_is_unchanged(self):
        parent = self.root / "parent"
        plan = prepare_run(parent, summary=False)
        write_case(parent, 0, plan)
        original = (parent / "plan.json").read_bytes()
        child = continuation_plan(parent, self.root / "child")
        self.assertEqual(len(child["cases"]), 2)
        self.assertEqual(child["continuation"]["unfinished_case_indices"], [1, 2])
        self.assertEqual((parent / "plan.json").read_bytes(), original)
        self.assertEqual(len(list(parent.glob("*-benchmark.json"))), 1)
        self.assertEqual(audit_run(self.root / "child")[0]["status"], "plan_only")

    def test_plan_only_frozen_parent_can_be_continued_with_pinned_image(self):
        parent = self.root / "plan-only"
        plan = prepare_run(parent, summary=False)
        child = continuation_plan(parent, self.root / "child")
        self.assertEqual(len(child["cases"]), 3)
        self.assertEqual(child["continuation"]["parent_runtime_image"], plan["runtime_image"])

    def test_modified_parent_evidence_invalidates_frozen_continuation(self):
        parent = self.root / "parent"
        plan = prepare_run(parent, summary=False)
        child = continuation_plan(parent, self.root / "child")
        (parent / "plan.json").write_text(json.dumps({**plan, "cases": []}), encoding="utf-8")
        audit = audit_run(self.root / "child")[0]
        self.assertEqual(audit["status"], "invalid")
        self.assertTrue(any("hashes do not match" in issue for issue in audit["issues"]))

    def test_duration_estimate_accepts_only_compatible_observations(self):
        parent = self.root / "pending"
        parent_plan = prepare_run(parent)
        write_case(parent, 0, parent_plan, completed=90, failed=10)
        history = self.root / "history"
        history_plan = prepare_run(history)
        for index in range(3):
            write_case(history, index, history_plan)
        estimate = estimate_remaining(parent, [history])
        self.assertGreater(estimate["cases"][0]["sample_count"], 0)
        incompatible = self.root / "other-image"
        other_plan = prepare_run(incompatible, image="sha256:" + "c" * 64)
        for index in range(3):
            write_case(incompatible, index, other_plan)
        estimate = estimate_remaining(parent, [incompatible])
        self.assertTrue(estimate["rejected_observations"])

    def test_duration_estimate_uses_observed_same_configuration_range(self):
        parent = self.root / "timings"
        plan = prepare_run(parent)
        for index in range(3):
            write_case(parent, index, plan, completed=90, failed=10) if index == 0 else write_case(parent, index, plan)
        estimate = estimate_remaining(parent)
        self.assertEqual(estimate["pending_case_count"], 1)
        self.assertGreater(estimate["estimated_seconds"], 0)
        self.assertLessEqual(estimate["uncertainty_low_seconds"], estimate["estimated_seconds"])
        self.assertGreaterEqual(estimate["uncertainty_high_seconds"], estimate["estimated_seconds"])

    def test_audit_flags_attempt_limit_mismatch_against_plan(self):
        directory = self.root / "policy-mismatch"
        plan = prepare_run(directory)
        write_case(directory, 0, plan)
        report = next(directory.glob("*-benchmark.json"))
        data = json.loads(report.read_text(encoding="utf-8"))
        data["arguments"]["requests"] = 99
        write_json(report, data)
        run = audit_run(directory)[0]
        self.assertFalse(run["planned_cases"][0]["configuration_matches"])
        self.assertTrue(any("attempt limit" in issue for issue in run["issues"]))


if __name__ == "__main__":
    unittest.main()
