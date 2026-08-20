#!/usr/bin/env python3
"""Reconstruct and verify the H-REP-001 Phase 2 calibration package."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_PACKAGE = ROOT / "experiments/H-REP-001/calibration"
SUM_FIELDS = [
    "model_calls", "tool_calls", "command_duration_ms", "cpu_time_ms",
    "validation_wall_clock_allowance_ms", "git_objects_read", "files_inspected",
    "tests_executed", "jobs_inspected", "jobs_accepted", "claims_evaluated",
    "evidence_bytes", "max_rss_kib",
]


def load(path: Path) -> Any:
    return json.loads(path.read_text())


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--package", type=Path, default=DEFAULT_PACKAGE)
    args = parser.parse_args()
    package = args.package.resolve()
    manifest = load(package / "artifact-manifest.json")
    if manifest.get("schema_version") != "hrep-calibration-artifact-manifest.v1":
        raise SystemExit("unsupported artifact manifest")
    if manifest.get("formal_evaluation_eligible") is not False:
        raise SystemExit("calibration artifact manifest is not formally excluded")

    expected_paths = set()
    verified_bytes = 0
    for entry in manifest["files"]:
        relative = entry["path"]
        if relative.startswith("/") or ".." in Path(relative).parts or relative in expected_paths:
            raise SystemExit(f"unsafe or duplicate artifact path: {relative}")
        expected_paths.add(relative)
        data = (package / relative).read_bytes()
        actual = hashlib.sha256(data).hexdigest()
        if len(data) != entry["bytes"] or actual != entry["sha256"]:
            raise SystemExit(f"artifact mismatch: {relative}")
        verified_bytes += len(data)
    actual_paths = {
        path.relative_to(package).as_posix()
        for path in package.rglob("*") if path.is_file() and path.name != "artifact-manifest.json"
    }
    if actual_paths != expected_paths:
        raise SystemExit("artifact inventory mismatch")

    report = load(package / "phase-2-report.json")
    if report.get("phase") != "calibration" or report.get("fixture_set") != "calibration":
        raise SystemExit("package is not Phase 2 calibration")
    if report.get("formal_run_permitted") is not False or report.get("formal_evaluation_eligible") is not False:
        raise SystemExit("calibration package permits formal use")
    if report.get("formal_fixture_ids_observed") or report.get("formal_outputs_observed") is not False:
        raise SystemExit("formal data was observed")
    if report.get("research_conclusion") is not None:
        raise SystemExit("calibration package contains a research conclusion")

    fixture_ids = sorted(
        load(path)["fixture_id"]
        for path in (ROOT / "fixtures/jobs-public/calibration").glob("*/fixture.json")
    )
    decisions = [json.loads(line) for line in (package / "decisions.jsonl").read_text().splitlines()]
    seeds = report["calibration_seeds"]
    populations = ["productive", "self-interested", "adversarial"] + report["populations"]["trivial_heuristics"]
    expected = {(seed, population, fixture) for seed in seeds for population in populations for fixture in fixture_ids}
    actual = {(row["seed"], row["population"], row["fixture_id"]) for row in decisions}
    if actual != expected or len(actual) != len(decisions):
        raise SystemExit("decision matrix is incomplete or duplicated")
    if any(row.get("hidden_truth_loaded_after_public_decision_close") is not True for row in decisions):
        raise SystemExit("a decision lacks the closed-boundary marker")
    if any(row["fixture_id"].startswith("formal-") for row in decisions):
        raise SystemExit("formal fixture leaked into calibration decisions")

    resources = load(package / "resources.json")
    records = resources["records"]
    totals = resources["totals"]
    if totals["records"] != len(records):
        raise SystemExit("resource record count does not reconcile")
    for field in SUM_FIELDS:
        if totals[field] != sum(int(record[field]) for record in records):
            raise SystemExit(f"resource total does not reconcile: {field}")
    for field in ["input_tokens", "output_tokens"]:
        known = [int(record[field]) for record in records if record[field] is not None]
        unavailable = sum(record[field] is None for record in records)
        expected_total = {"known_total": sum(known), "unavailable_records": unavailable, "complete": unavailable == 0}
        if totals[field] != expected_total:
            raise SystemExit(f"optional resource total does not reconcile: {field}")

    projections = load(package / "mechanism-projections.json")
    projected = projections["projections"]
    projected_keys = {(row["seed"], row["operator"]) for row in projected}
    if projected_keys != {(seed, population) for seed in seeds for population in populations}:
        raise SystemExit("M00/M01 projection matrix is incomplete")
    if any(row["m00_score"] != 0 for row in projected):
        raise SystemExit("M00 control unexpectedly assigns reputation")

    gates = load(package / "proposed-gates.json")
    if [gate["number"] for gate in gates["gates"]] != list(range(1, 11)):
        raise SystemExit("gate proposals do not cover all ten mandatory gates")
    exclusions = load(package / "exclusion-rules.json")
    if "all calibration fixtures and outputs" not in exclusions["formal_data_exclusions"]:
        raise SystemExit("calibration output is not explicitly excluded from formal data")

    result = {
        "ok": True,
        "schema_version": "hrep-calibration-verification.v1",
        "artifacts_verified": len(manifest["files"]),
        "artifact_bytes_verified": verified_bytes,
        "fixtures_verified": len(fixture_ids),
        "seeds_verified": len(seeds),
        "populations_verified": len(populations),
        "decisions_verified": len(decisions),
        "resource_records_verified": len(records),
        "resource_totals_reconciled": True,
        "m00_m01_projections_verified": len(projected),
        "mandatory_gate_proposals_verified": 10,
        "formal_data_excluded": True,
    }
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
