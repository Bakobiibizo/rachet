#!/usr/bin/env python3
"""Verify immutable completeness of H-REP-001 Phase 4 evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EXPERIMENT = ROOT / "experiments/H-REP-001"
ANCHOR = "9cd702ff890078079a5836457831625857098912fc9de7287a5b9a7e12687ec2"
POPULATIONS = {
    "productive", "self-interested", "explicitly-adversarial", "always-pass",
    "always-fail", "random-verdict", "easy-job-only", "majority-following",
    "maximum-volume", "perfect-abstainer", "historical-majority",
}
FIXTURES = {
    "formal-authorization-defect", "formal-clean-change", "formal-genuinely-ambiguous-claim",
    "formal-malformed-error-handling", "formal-obvious-regression",
    "formal-misleading-but-valid-change", "formal-specification-violation",
    "formal-subtle-regression", "formal-test-only-failure",
}


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def load(path: Path):
    return json.loads(path.read_text())


def jsonl(path: Path):
    return [json.loads(line) for line in path.read_text().splitlines()]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--experiment", type=Path, default=EXPERIMENT)
    args = parser.parse_args()
    experiment = args.experiment.resolve()
    subprocess.run(
        [sys.executable, str(ROOT / "tools/verify_hrep_preregistration.py"), "--expected-lock-sha256", ANCHOR],
        cwd=ROOT, check=True, stdout=subprocess.DEVNULL,
    )
    manifest = load(experiment / "formal-artifact-manifest.json")
    if manifest.get("schema_version") != "hrep-formal-artifact-manifest.v1" or manifest.get("preregistration_lock_sha256") != ANCHOR or manifest.get("immutable") is not True:
        raise SystemExit("formal artifact manifest header is invalid")
    paths = set()
    total_bytes = 0
    for entry in manifest["files"]:
        relative = entry["path"]
        if relative in paths or relative.startswith("/") or ".." in Path(relative).parts:
            raise SystemExit(f"unsafe or duplicate formal artifact path: {relative}")
        paths.add(relative)
        data = (experiment / relative).read_bytes()
        if len(data) != entry["bytes"] or sha256(data) != entry["sha256"]:
            raise SystemExit(f"formal artifact mismatch: {relative}")
        total_bytes += len(data)

    report = load(experiment / "formal-execution.json")
    if report.get("phase") != 4 or report.get("status") != "complete_pending_audit" or report.get("assessment") is not None:
        raise SystemExit("formal execution report crosses the Phase 4 boundary")
    if report.get("preregistration_lock_sha256") != ANCHOR or report.get("mechanism_or_threshold_changes") != 0:
        raise SystemExit("formal execution changed or lost its lock")
    if report.get("public_manifest_sha256") != "68ccbbf5cdfe722dca17aadc9d8a4c908c5e090e76105951ac4b35e3808470bb" or report.get("private_manifest_sha256") != "a7d0a0e5f5ab8413437be9620aa17123457756710aa32dc06c69dc150e6a6c7c":
        raise SystemExit("formal fixture commitments differ from preregistration")
    if report.get("formal_seeds") != 5 or report.get("condition_runs") != 10 or report.get("autonomous_invocations") != 60:
        raise SystemExit("formal run/seed/invocation counts are incomplete")
    if report.get("operator_failures") != 0 or report.get("infrastructure_exclusions") != 0:
        raise SystemExit("unexpected formal failure/exclusion count")
    if report.get("run_decisions") != 990 or report.get("run_actions") != 1100 or report.get("run_blocks") != 1030:
        raise SystemExit("formal trace totals are incomplete")
    if report.get("baseline_categories_preserved_separately") != [
        "functional", "mechanism_control", "null_model", "trivial_heuristic",
        "resource_matched_competitor", "adversarial_strategy",
    ]:
        raise SystemExit("baseline categories were combined or omitted")

    expected_conditions = {(seed, condition) for seed in range(5) for condition in ["M00", "M01"]}
    actual_conditions = {(item["seed_index"], item["condition"]) for item in report["runs"]}
    if actual_conditions != expected_conditions or len(report["runs"]) != 10:
        raise SystemExit("formal seed-condition matrix is incomplete")
    run_ids = set()
    decision_count = observation_count = resource_records = 0
    for item in report["runs"]:
        run_id = item["run_id"]
        if run_id in run_ids:
            raise SystemExit("duplicate formal run ID")
        run_ids.add(run_id)
        if item["blocks"] != 103 or item["decisions"] != 99 or item["actions"] != 110 or item["private_boundary_closed"] is not True:
            raise SystemExit(f"incomplete formal run summary: {run_id}")
        root = experiment / "runs" / run_id
        run_manifest = load(root / "artifact-manifest.json")
        if run_manifest["outcome"] != {"status": "completed"} or len(run_manifest["artifacts"]) != 10 or len(run_manifest["seeds"]) != 5:
            raise SystemExit(f"run manifest incomplete: {run_id}")
        decisions = jsonl(root / "decisions.jsonl")
        observations = jsonl(root / "observations.jsonl")
        if len(decisions) != 99 or len(observations) != 99:
            raise SystemExit(f"decision/observation count mismatch: {run_id}")
        keys = {(row["population"], row["fixture_id"]) for row in decisions}
        if keys != {(population, fixture) for population in POPULATIONS for fixture in FIXTURES}:
            raise SystemExit(f"decision population-fixture matrix incomplete: {run_id}")
        if any(row["hidden_truth_present"] is not False for row in observations):
            raise SystemExit(f"operator observation leaked hidden truth: {run_id}")
        if any(row["status"] != "completed" or row["failure"] is not None for row in decisions):
            raise SystemExit(f"unrecorded operator failure: {run_id}")
        resources = load(root / "resources.json")
        records = resources["records"]
        if resources["totals"]["records"] != len(records) or len(resources["by_operator"]) != 11:
            raise SystemExit(f"resource accounting is incomplete: {run_id}")
        if resources["totals"]["model_calls"] != 6:
            raise SystemExit(f"intelligent model call count differs: {run_id}")
        for operator in ["productive", "self-interested", "explicitly-adversarial"]:
            rows = [row for row in records if row["operator"] == operator]
            if len(rows) != 2 or {row["epoch"] for row in rows} != {0, 1} or any(row["model_calls"] != 1 or row["tool_calls"] > 40 for row in rows):
                raise SystemExit(f"intelligent epoch budget mismatch: {run_id}/{operator}")
        metrics = load(root / "metrics.json")
        if metrics.get("formal_evaluation_eligible") is not True or metrics.get("gate_thresholds_applied_or_changed_during_execution") is not False:
            raise SystemExit(f"formal metrics marker invalid: {run_id}")
        if len(metrics.get("operators", [])) != 11:
            raise SystemExit(f"formal metric operator set incomplete: {run_id}")
        evidence = experiment / "formal-evidence" / run_id
        customer = load(evidence / "customer-resource.json")
        baselines = load(evidence / "baseline-categories.json")
        condition = load(evidence / "condition-input.json")
        if customer.get("operator") != "customer-001" or customer.get("jobs_created") != 9 or customer.get("signed_create_job_actions") != 9:
            raise SystemExit(f"controlled customer evidence incomplete: {run_id}")
        if baselines.get("categories_are_separate") is not True or len(baselines["null_model"]["ranking"]) != 11:
            raise SystemExit(f"baseline evidence incomplete: {run_id}")
        if condition.get("operator_failures_retained") != 0 or condition.get("infrastructure_exclusion") is not None:
            raise SystemExit(f"condition evidence has an unexplained failure: {run_id}")
        invocations = list((evidence / "agent-invocations").glob("*/*/agentctl-report.json"))
        raw_outputs = list((evidence / "agent-invocations").glob("*/*/raw-output.log"))
        if len(invocations) != 6 or len(raw_outputs) != 6:
            raise SystemExit(f"autonomous invocation evidence incomplete: {run_id}")
        decision_count += len(decisions)
        observation_count += len(observations)
        resource_records += len(records)

    result = {
        "ok": True,
        "schema_version": "hrep-formal-verification.v1",
        "preregistration_lock_sha256": ANCHOR,
        "formal_files_verified": len(manifest["files"]),
        "formal_bytes_verified": total_bytes,
        "seeds_verified": 5,
        "condition_runs_verified": 10,
        "autonomous_invocations_verified": 60,
        "decisions_verified": decision_count,
        "observations_verified": observation_count,
        "resource_records_verified": resource_records,
        "actions_declared": report["run_actions"],
        "blocks_declared": report["run_blocks"],
        "operator_failures": report["operator_failures"],
        "infrastructure_exclusions": report["infrastructure_exclusions"],
        "baseline_categories_verified": 6,
        "customer_populations_verified": 10,
        "mechanism_or_threshold_changes": 0,
        "assessment_deferred": True,
    }
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
