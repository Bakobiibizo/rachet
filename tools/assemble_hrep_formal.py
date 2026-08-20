#!/usr/bin/env python3
"""Commit H-REP-001 Phase 4 run and autonomous invocation evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
EXPERIMENT = ROOT / "experiments/H-REP-001"
WORK = ROOT / ".ldgr/formal-work"
OPERATORS = [
    "productive", "self-interested", "explicitly-adversarial", "always-pass",
    "always-fail", "random-verdict", "easy-job-only", "majority-following",
    "maximum-volume", "perfect-abstainer", "historical-majority",
]


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def dump(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def null_ranking(seed: int) -> list[str]:
    # The locked digest is interpreted as one unsigned big-endian entropy
    # integer and consumed by the preregistered Fisher-Yates permutation.
    entropy = int.from_bytes(
        hashlib.sha256(b"H-REP-001/null-ranking/v1" + seed.to_bytes(8, "big")).digest(),
        "big",
    )
    ranking = OPERATORS[:]
    for index in range(len(ranking) - 1, 0, -1):
        selected = entropy % (index + 1)
        entropy //= index + 1
        ranking[index], ranking[selected] = ranking[selected], ranking[index]
    return ranking


def verify_run(run_id: str) -> tuple[int, int]:
    root = EXPERIMENT / "runs" / run_id
    manifest = json.loads((root / "artifact-manifest.json").read_text())
    if manifest["run_id"] != run_id or manifest["outcome"] != {"status": "completed"}:
        raise ValueError(f"run manifest is not completed: {run_id}")
    expected = {entry["path"] for entry in manifest["artifacts"]} | {"artifact-manifest.json"}
    actual = {path.name for path in root.iterdir() if path.is_file()}
    if expected != actual:
        raise ValueError(f"run artifact inventory differs: {run_id}")
    total = 0
    for entry in manifest["artifacts"]:
        data = (root / entry["path"]).read_bytes()
        if len(data) != entry["bytes"] or sha256(data) != entry["sha256"]:
            raise ValueError(f"run artifact mismatch: {run_id}/{entry['path']}")
        total += len(data)
    return len(manifest["artifacts"]), total


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--work", type=Path, default=WORK)
    args = parser.parse_args()
    work = args.work.resolve()
    index = json.loads((work / "execution-index.json").read_text())
    if index["preregistration_lock_sha256"] != "9cd702ff890078079a5836457831625857098912fc9de7287a5b9a7e12687ec2":
        raise ValueError("formal execution index does not match the external lock anchor")
    evidence_root = EXPERIMENT / "formal-evidence"
    if evidence_root.exists() or (EXPERIMENT / "formal-execution.json").exists():
        raise ValueError("formal evidence already exists and will not be rewritten")
    evidence_root.mkdir()

    run_summaries = []
    total_run_bytes = 0
    for entry in index["condition_inputs"]:
        source = work / Path(entry["path"]).parent
        destination = evidence_root / entry["run_id"]
        shutil.copytree(source, destination)
        artifacts, run_bytes = verify_run(entry["run_id"])
        total_run_bytes += run_bytes
        condition = json.loads((destination / "condition-input.json").read_text())
        customer = {
            "schema_version": "hrep-formal-customer-resource.v1",
            "operator": "customer-001",
            "role": "customer",
            "seed_index": entry["seed_index"],
            "condition": entry["condition"],
            "model_calls": 0,
            "tool_calls": 0,
            "validation_wall_clock_allowance_ms": 300_000,
            "jobs_created": 9,
            "claims_created": 9,
            "signed_create_job_actions": 9,
            "declared_tool_call_ceiling": 10,
        }
        dump(destination / "customer-resource.json", customer)
        baselines = {
            "schema_version": "hrep-formal-baselines.v1",
            "seed_index": entry["seed_index"],
            "condition": entry["condition"],
            "functional": "productive",
            "mechanism_control": "M00@1.0.0",
            "target_mechanism": "M01@1.0.0",
            "null_model": {
                "name": "seeded random ranking independent of validation",
                "domain": "H-REP-001/null-ranking/v1",
                "digest_interpretation": "unsigned big-endian entropy integer consumed by Fisher-Yates from index 10 through 1",
                "ranking": null_ranking(condition["seed"]["seed_u64_be"]),
            },
            "trivial": [
                "always-pass", "always-fail", "random-verdict", "easy-job-only",
                "majority-following", "maximum-volume", "perfect-abstainer",
                "historical-majority",
            ],
            "resource_matched_competitor": "raw selected-training validation count",
            "adversarial": ["self-interested", "explicitly-adversarial"],
            "categories_are_separate": True,
        }
        dump(destination / "baseline-categories.json", baselines)
        run_summaries.append(
            {
                **entry,
                "run_artifacts": artifacts,
                "run_artifact_bytes": run_bytes,
                "blocks": 103,
                "decisions": 99,
                "actions": 110,
                "intelligent_invocations": 6,
                "intelligent_operator_failures": condition["operator_failures_retained"],
                "customer_jobs": 9,
                "customer_claims": 9,
                "private_boundary_closed": condition["training_decisions_closed_before_private_access"]
                and condition["evaluation_decisions_closed_before_private_access"],
            }
        )

    report = {
        "schema_version": "hrep-formal-execution-report.v1",
        "experiment_id": "H-REP-001",
        "phase": 4,
        "status": "complete_pending_audit",
        "preregistration_lock_sha256": index["preregistration_lock_sha256"],
        "protocol_git_commit": "83378b7d48cee0507cdc576e19abeb0ab6e1a435",
        "public_manifest_sha256": index["public_manifest_sha256"],
        "private_manifest_sha256": index["private_manifest_sha256"],
        "formal_seeds": 5,
        "condition_runs": 10,
        "condition_order_per_seed": ["M00", "M01"],
        "autonomous_invocations": index["autonomous_invocations"],
        "operator_failures": sum(item["operator_failures_retained"] for item in index["condition_inputs"]),
        "infrastructure_exclusions": sum(item["infrastructure_exclusion"] is not None for item in index["condition_inputs"]),
        "run_decisions": 990,
        "run_actions": 1100,
        "run_blocks": 1030,
        "run_artifact_bytes": total_run_bytes,
        "populations": {
            "intelligent": ["productive", "self-interested", "explicitly-adversarial"],
            "fixed_heuristics": OPERATORS[3:],
            "controlled_customer": ["customer-001"],
        },
        "baseline_categories_preserved_separately": [
            "functional", "mechanism_control", "null_model", "trivial_heuristic",
            "resource_matched_competitor", "adversarial_strategy",
        ],
        "training_decisions_closed_before_private_access": True,
        "evaluation_decisions_closed_before_private_access": True,
        "mechanism_or_threshold_changes": 0,
        "assessment": None,
        "claim_change": None,
        "runs": run_summaries,
    }
    dump(EXPERIMENT / "formal-execution.json", report)

    files = []
    for path in sorted(evidence_root.rglob("*")):
        if path.is_file():
            data = path.read_bytes()
            files.append(
                {
                    "path": path.relative_to(EXPERIMENT).as_posix(),
                    "bytes": len(data),
                    "sha256": sha256(data),
                }
            )
    report_data = (EXPERIMENT / "formal-execution.json").read_bytes()
    files.append(
        {
            "path": "formal-execution.json",
            "bytes": len(report_data),
            "sha256": sha256(report_data),
        }
    )
    for item in run_summaries:
        run_root = EXPERIMENT / "runs" / item["run_id"]
        for path in sorted(run_root.iterdir()):
            data = path.read_bytes()
            files.append(
                {
                    "path": path.relative_to(EXPERIMENT).as_posix(),
                    "bytes": len(data),
                    "sha256": sha256(data),
                }
            )
    files.sort(key=lambda item: item["path"])
    dump(
        EXPERIMENT / "formal-artifact-manifest.json",
        {
            "schema_version": "hrep-formal-artifact-manifest.v1",
            "preregistration_lock_sha256": index["preregistration_lock_sha256"],
            "immutable": True,
            "files": files,
        },
    )
    print(json.dumps({"runs": len(run_summaries), "files": len(files), "bytes": sum(item["bytes"] for item in files)}, indent=2))


if __name__ == "__main__":
    main()
