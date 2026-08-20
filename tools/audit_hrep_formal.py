#!/usr/bin/env python3
"""Perform the preregistered H-REP-001 Phase 5 audit without repairing evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
EXPERIMENT = ROOT / "experiments/H-REP-001"
PUBLIC = ROOT / "fixtures/jobs-public/formal"
PRIVATE = ROOT / "fixtures/ground-truth-private/formal"
REPOSITORIES = ROOT / "fixtures/repositories"
ANCHOR = "9cd702ff890078079a5836457831625857098912fc9de7287a5b9a7e12687ec2"
TRAINING = [
    "formal-authorization-defect",
    "formal-clean-change",
    "formal-genuinely-ambiguous-claim",
    "formal-malformed-error-handling",
    "formal-obvious-regression",
]
EVALUATION = [
    "formal-misleading-but-valid-change",
    "formal-specification-violation",
    "formal-subtle-regression",
    "formal-test-only-failure",
]
INTELLIGENT = ["productive", "self-interested", "explicitly-adversarial"]
FIXED = [
    "always-pass",
    "always-fail",
    "random-verdict",
    "easy-job-only",
    "majority-following",
    "maximum-volume",
    "perfect-abstainer",
    "historical-majority",
]
OPERATORS = INTELLIGENT + FIXED
SUM_FIELDS = [
    "model_calls",
    "tool_calls",
    "command_duration_ms",
    "validation_wall_clock_allowance_ms",
    "git_objects_read",
    "files_inspected",
    "tests_executed",
    "jobs_inspected",
    "jobs_accepted",
    "claims_evaluated",
    "evidence_bytes",
]
OPTIONAL_FIELDS = ["input_tokens", "output_tokens", "cpu_time_ms", "compute_units"]


def load(path: Path) -> Any:
    return json.loads(path.read_text())


def jsonl(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text().splitlines()]


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_hash(value: Any) -> str:
    return sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode())


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def run_checked(argv: list[str], *, cwd: Path = ROOT) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(argv, cwd=cwd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def replay_all(experiment: Path, execution_path: Path) -> str:
    """Build the locked replay helper transiently, then remove the package example."""
    examples = ROOT / "crates/lab/examples"
    target = examples / "hrep_formal_replay.rs"
    existed = examples.exists()
    require(not target.exists(), f"transient replay example already exists: {target}")
    examples.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(ROOT / "tools/hrep_formal_replay.rs", target)
    try:
        result = run_checked(
            [
                "cargo",
                "+1.93.0",
                "run",
                "--quiet",
                "-p",
                "rachet-lab",
                "--example",
                "hrep_formal_replay",
                "--",
                str(experiment),
                str(execution_path),
            ]
        )
    finally:
        target.unlink(missing_ok=True)
        if not existed:
            examples.rmdir()
    text = result.stdout.decode()
    require("runs=10 blocks=1030 exact=true" in text, "locked replay did not verify all runs")
    require(text.count(" model_calls=0 exact=true") == 10, "locked replay output is incomplete")
    return text


def parse_framed_trace(path: Path, magic: bytes, nested: bool) -> tuple[int, int]:
    data = path.read_bytes()
    require(data.startswith(magic), f"invalid trace magic: {path}")
    offset = len(magic)

    def read_u64() -> int:
        nonlocal offset
        require(offset + 8 <= len(data), f"truncated trace count: {path}")
        value = int.from_bytes(data[offset : offset + 8], "big")
        offset += 8
        return value

    def skip_frame() -> None:
        nonlocal offset
        length = read_u64()
        require(offset + length <= len(data), f"truncated trace frame: {path}")
        offset += length

    outer = read_u64()
    items = 0
    for _ in range(outer):
        if nested:
            count = read_u64()
            for _ in range(count):
                skip_frame()
            items += count
        else:
            skip_frame()
            items += 1
    require(offset == len(data), f"trailing trace bytes: {path}")
    return outer, items


def resource_totals(records: list[dict[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {"records": len(records)}
    for field in SUM_FIELDS:
        result[field] = sum(int(row[field]) for row in records)
    for field in OPTIONAL_FIELDS:
        known = [row[field] for row in records if row[field] is not None]
        missing = len(records) - len(known)
        if missing:
            result[field] = {
                "availability": "partial",
                "known_total": sum(known),
                "unavailable_records": missing,
            }
        else:
            result[field] = {"availability": "complete", "total": sum(known)}
    return result


def expected_correct(decision: str, truth: str) -> bool | None:
    if truth == "ambiguous" or decision not in {"pass", "fail"}:
        return None
    return (decision == "pass") == (truth == "valid")


def decode_reputation(value: str) -> dict[str, int]:
    raw = bytes.fromhex(value)
    require(len(raw) == 40, "M01 reputation is not the locked 40-byte representation")
    return {
        "score": int.from_bytes(raw[0:8], "big", signed=True),
        "correct": int.from_bytes(raw[8:16], "big"),
        "incorrect": int.from_bytes(raw[16:24], "big"),
        "abstained": int.from_bytes(raw[24:32], "big"),
        "unresolved": int.from_bytes(raw[32:40], "big"),
    }


def expected_reputations(rows: list[dict[str, Any]]) -> dict[str, dict[str, int]]:
    result: dict[str, dict[str, int]] = {}
    for row in rows:
        if row["signed_action_count"] != 1:
            continue
        counters = result.setdefault(
            row["operator_actor"],
            {"score": 0, "correct": 0, "incorrect": 0, "abstained": 0, "unresolved": 0},
        )
        truth = row["truth"]
        decision = row["decision"]
        if truth == "ambiguous":
            counters["unresolved"] += 1
        elif decision in {"abstain", "indeterminate"}:
            counters["abstained"] += 1
        elif expected_correct(decision, truth):
            counters["score"] += 1
            counters["correct"] += 1
        else:
            counters["score"] -= 1
            counters["incorrect"] += 1
    return result


def observed_reputations(record: dict[str, Any]) -> dict[str, dict[str, int]]:
    observed: dict[str, dict[str, int]] = {}
    for score in record["m01_scores"]:
        key = bytes.fromhex(score["state_key"])
        require(len(key) > 32, "M01 state key does not contain an actor ID")
        actor = key[-32:].hex()
        require(actor not in observed, "duplicate M01 actor state")
        observed[actor] = decode_reputation(score["reputation"])
    return observed


def verify_economic_state(condition: str, rows: list[dict[str, Any]], path: Path) -> tuple[int, int]:
    records = jsonl(path)
    require(len(records) == 103, f"economic state record count mismatch: {path}")
    require([row["height"] for row in records] == list(range(103)), "economic heights are not contiguous")
    require(all(len(bytes.fromhex(row["post_state_root"])) == 32 for row in records), "invalid state root")
    if condition == "M00":
        require(all(not row["m01_scores"] for row in records), "M00 contains M01 state")
        return len(records), 0

    training = expected_reputations([row for row in rows if row["phase"] == "training"])
    complete = expected_reputations(rows)
    updates = 0
    for record in records:
        expected = {} if record["height"] < 2 else training if record["height"] < 102 else complete
        observed = observed_reputations(record)
        require(observed == expected, f"independent M01 recomputation mismatch at height {record['height']}")
        if record["height"] in {2, 102}:
            updates += len([row for row in rows if row["signed_action_count"] == 1 and ((row["phase"] == "training") == (record["height"] == 2))])
    return len(records), updates


def verify_metrics(
    metrics: dict[str, Any],
    rows: list[dict[str, Any]],
    resources: dict[str, Any],
    training_scores: dict[str, dict[str, int]],
) -> None:
    require(metrics["resource_totals"] == resources["totals"], "metrics resource totals diverge")
    expected = []
    by_operator = {row["operator"]: row["totals"] for row in resources["by_operator"]}
    for name in OPERATORS:
        selected = [row for row in rows if row["population"] == name and row["phase"] == "training" and row["selected"]]
        held = [row for row in rows if row["population"] == name and row["phase"] == "evaluation" and row["correct"] is not None]
        correct = sum(row["correct"] is True for row in held)
        actor_ids = {row["operator_actor"] for row in rows if row["population"] == name}
        require(len(actor_ids) == 1, f"operator changed actor within run: {name}")
        actor = next(iter(actor_ids))
        expected.append(
            {
                "operator": name,
                "actor_id": actor,
                "post_training_score": training_scores.get(actor, {}).get("score", 0),
                "selected_training_validation_count": len(selected),
                "held_out_binary_correct": correct,
                "held_out_binary_decisions": len(held),
                "held_out_correctness": None if not held else correct / len(held),
                "validation_effort_units": by_operator[name]["tool_calls"]
                + by_operator[name]["files_inspected"]
                + by_operator[name]["tests_executed"],
            }
        )
    require(metrics["operators"] == expected, "independently recomputed metrics differ")


def repository_digest(repository: Path, base: str, candidate: str) -> str:
    digest = hashlib.sha256(b"rachet/repository-fixture/v1\0")

    def framed(value: bytes) -> None:
        digest.update(len(value).to_bytes(8, "big"))
        digest.update(value)

    blobs: set[str] = set()
    for label, commit in [(b"base", base), (b"candidate", candidate)]:
        framed(label)
        framed(commit.encode())
        framed(run_checked(["git", "cat-file", "commit", commit], cwd=repository).stdout)
        tree = run_checked(["git", "ls-tree", "-r", "-z", "--full-tree", commit], cwd=repository).stdout
        framed(tree)
        for entry in tree.split(b"\0"):
            if not entry:
                continue
            metadata = entry.split(b"\t", 1)[0].split(b" ")
            if metadata[1] == b"blob":
                blobs.add(metadata[2].decode())
    for blob in sorted(blobs):
        framed(blob.encode())
        framed(run_checked(["git", "cat-file", "blob", blob], cwd=repository).stdout)
    return digest.hexdigest()


def verify_hidden_evaluator() -> list[dict[str, Any]]:
    public_manifest = load(PUBLIC / "manifest.json")
    private_manifest = load(PRIVATE / "manifest.json")
    public_entries = {row["fixture_id"]: row for row in public_manifest["fixtures"]}
    private_entries = {row["fixture_id"]: row for row in private_manifest["fixtures"]}
    require(set(public_entries) == set(TRAINING + EVALUATION), "public fixture set differs")
    require(set(private_entries) == set(TRAINING + EVALUATION), "private fixture set differs")
    results = []
    for fixture_id in TRAINING + EVALUATION:
        public_entry = public_entries[fixture_id]
        private_entry = private_entries[fixture_id]
        public_path = PUBLIC / public_entry["path"]
        truth_path = PRIVATE / private_entry["path"]
        require(sha256(public_path.read_bytes()) == public_entry["sha256"], f"public fixture hash mismatch: {fixture_id}")
        require(sha256(truth_path.read_bytes()) == private_entry["sha256"], f"private truth hash mismatch: {fixture_id}")
        fixture = load(public_path)
        truth = load(truth_path)
        claim = truth["claims"][0]
        require(truth["fixture_id"] == fixture_id, f"truth identity mismatch: {fixture_id}")
        require(claim["claim_id"] == fixture["claims"][0]["claim_id"], f"claim identity mismatch: {fixture_id}")
        require(claim["ambiguity"] != "none" if claim["verdict"] == "ambiguous" else claim["ambiguity"] == "none", f"ambiguity mismatch: {fixture_id}")
        repository = REPOSITORIES / fixture["repository"]["path"]
        base = fixture["repository"]["base_commit"]
        candidate = fixture["repository"]["candidate_commit"]
        require(run_checked(["git", "rev-parse", "--verify", f"{base}^{{commit}}"], cwd=repository).stdout.decode().strip() == base, f"base commit mismatch: {fixture_id}")
        require(run_checked(["git", "rev-parse", "--verify", f"{candidate}^{{commit}}"], cwd=repository).stdout.decode().strip() == candidate, f"candidate commit mismatch: {fixture_id}")
        run_checked(["git", "merge-base", "--is-ancestor", base, candidate], cwd=repository)
        require(repository_digest(repository, base, candidate) == fixture["repository"]["integrity_sha256"], f"repository integrity mismatch: {fixture_id}")
        reproduction = claim["reproduction_procedure"]
        require(len(reproduction) == 1, f"unexpected reproduction procedure count: {fixture_id}")
        process = subprocess.run(reproduction[0]["argv"], cwd=repository, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        expected_success = claim["verdict"] in {"valid", "ambiguous"}
        require((process.returncode == 0) == expected_success, f"hidden evaluator reproduction mismatch: {fixture_id}")
        require(claim["expected_evidence"] and claim["difficulty"]["tier"], f"incomplete evaluator metadata: {fixture_id}")
        results.append(
            {
                "fixture_id": fixture_id,
                "verdict": claim["verdict"],
                "reproduction_exit_code": process.returncode,
                "reproduction_output_sha256": sha256(process.stdout),
                "repository_integrity_sha256": fixture["repository"]["integrity_sha256"],
            }
        )
    return results


def verify_independence(experiment: Path, report: dict[str, Any]) -> dict[str, Any]:
    manifests = [
        load(experiment / "operators/productive.json")["operators"][0],
        load(experiment / "operators/self-interested.json")["operators"][0],
        load(experiment / "operators/explicitly-adversarial.json")["operators"][0],
    ]
    require(len({item["agent"]["system_prompt_sha256"] for item in manifests}) == 3, "intelligent prompts are not distinct")
    require({item["agent"]["model_family"] for item in manifests} == {"gpt-5.6-sol"}, "unexpected intelligent model family")
    require({item["agent"]["tool_harness"] for item in manifests} == {"pi-via-agentctl"}, "unexpected intelligent harness")
    for item in manifests:
        independence = item["independence"]
        require(independence["memory"]["scope"] == "independent", "memory independence not disclosed")
        require(independence["worktree"]["scope"] == "independent", "worktree independence not disclosed")
        require(independence["communication_channel"]["scope"] == "independent", "communication disclosure mismatch")
        require(independence["model_family"]["scope"] == "shared", "shared model family not disclosed")
        require(independence["tool_harness"]["scope"] == "shared", "shared harness not disclosed")
        require(independence["evidence_method"]["scope"] == "shared", "shared evidence method not disclosed")
        require(item["communication_channels"] == [] and item["customer_relationship"] == "none", "relationship disclosure mismatch")
    actors: dict[str, dict[str, Any]] = {}
    reuses = []
    invocation_count = 0
    for run in report["runs"]:
        root = experiment / "runs" / run["run_id"]
        rows = jsonl(root / "decisions.jsonl")
        run_actors = {row["operator_actor"]: row["population"] for row in rows}
        require(len(run_actors) == 11, f"run does not have eleven identities: {run['run_id']}")
        for actor, population in run_actors.items():
            current = {
                "run_id": run["run_id"],
                "seed_index": run["seed_index"],
                "condition": run["condition"],
                "population": population,
            }
            if actor in actors:
                reuses.append({"actor_id": actor, "first": actors[actor], "reused_by": current})
            else:
                actors[actor] = current
        evidence = experiment / "formal-evidence" / run["run_id"] / "agent-invocations"
        invocation_count += len(list(evidence.glob("*/*/agentctl-report.json")))
    require(invocation_count == 60, "autonomous invocation inventory mismatch")
    require(len(actors) == 60 and len(reuses) == 50, "unexpected validation identity reuse inventory")
    return {
        "validation_identities_expected": 110,
        "validation_identities_observed": len(actors),
        "cross_condition_identity_reuses": reuses,
        "identity_scope_declared": "fresh per operator, seed, and condition",
        "identity_scope_observed": "ten M01 identities per seed reuse another population's M00 identity; only historical-majority is fresh in both conditions",
        "intelligent_model_families": 1,
        "intelligent_system_prompts": 3,
        "intelligent_tool_harnesses": 1,
        "intelligent_evidence_methods": 1,
        "isolated_random_seeds": True,
        "isolated_memories": True,
        "isolated_worktrees": True,
        "communication_channels": [],
        "customer_relationship": "none",
        "qualification": "The three intelligent objectives share one exact model family, provider, harness, and repository-inspection method; they are isolated identities and prompts, not independent validator systems.",
    }


def verify_seed(seed: dict[str, Any], private_hash: str) -> None:
    digest = hashlib.sha256(
        b"H-REP-001/formal-seed/v1" + int(seed["index"]).to_bytes(8, "big") + bytes.fromhex(private_hash)
    ).digest()
    require(digest.hex() == seed["digest_sha256"], f"seed digest mismatch: {seed['index']}")
    require(int.from_bytes(digest[:8], "big") == seed["seed_u64_be"], f"seed integer mismatch: {seed['index']}")


def expected_run_id(seed: dict[str, Any], condition: str) -> str:
    identity = bytearray(b"rachet/H-REP-001/formal-run/v1\0")
    identity.extend(bytes.fromhex(ANCHOR))
    identity.extend(condition.encode())
    identity.extend(int(seed["index"]).to_bytes(8, "big"))
    identity.extend(bytes.fromhex(seed["digest_sha256"]))
    return sha256(bytes(identity))


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--experiment", type=Path, default=EXPERIMENT)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    experiment = args.experiment.resolve()
    output = args.output or (experiment / "audit-report.json")

    preregistration = run_checked(
        [sys.executable, str(ROOT / "tools/verify_hrep_preregistration.py"), "--expected-lock-sha256", ANCHOR]
    )
    phase4 = run_checked([sys.executable, str(ROOT / "tools/verify_hrep_formal.py"), "--experiment", str(experiment)])
    prereg_result = json.loads(preregistration.stdout)
    phase4_result = json.loads(phase4.stdout)
    replay_log = replay_all(experiment, experiment / "formal-execution.json")

    require(sha256((experiment / "preregistration-lock.json").read_bytes()) == ANCHOR, "anchor mismatch")
    require((experiment / "preregistration-lock.sha256").read_text().split()[0] == ANCHOR, "anchor file mismatch")
    lock = load(experiment / "preregistration-lock.json")
    require(lock["formal_outputs_observed_before_lock"] is False, "formal output predates lock")
    private_hash = sha256((PRIVATE / "manifest.json").read_bytes())
    public_hash = sha256((PUBLIC / "manifest.json").read_bytes())
    require(private_hash == lock["held_out_private_manifest_sha256"], "held-out manifest hash mismatch")
    require(public_hash == load(experiment / "formal-execution.json")["public_manifest_sha256"], "public manifest hash mismatch")
    require((experiment / "fixture-manifest-private.hash").read_text().strip() == private_hash, "private hash file mismatch")

    hidden = verify_hidden_evaluator()
    execution = load(experiment / "formal-execution.json")
    independence = verify_independence(experiment, execution)
    run_results = []
    total_actions = total_events = total_roots = total_m01_updates = total_resource_records = 0
    all_actor_ids: set[str] = set()
    fixed_budget_violations = []

    for item in execution["runs"]:
        run_id = item["run_id"]
        root = experiment / "runs" / run_id
        evidence = experiment / "formal-evidence" / run_id
        condition_input = load(evidence / "condition-input.json")
        seed = condition_input["seed"]
        verify_seed(seed, private_hash)
        require(run_id == expected_run_id(seed, item["condition"]), f"run ID mismatch: {run_id}")
        require(condition_input["preregistration_lock_sha256"] == ANCHOR, f"run lock mismatch: {run_id}")
        require(condition_input["truth"] == {row["fixture_id"]: row["verdict"] for row in hidden}, f"run truth mismatch: {run_id}")
        require(condition_input["training_decisions_closed_before_private_access"] is True, "training boundary open")
        require(condition_input["evaluation_decisions_closed_before_private_access"] is True, "evaluation boundary open")

        decisions = jsonl(root / "decisions.jsonl")
        observations = jsonl(root / "observations.jsonl")
        require(all(row["hidden_truth_present"] is False for row in observations), f"hidden truth leaked: {run_id}")
        for row in decisions:
            require(row["truth"] == condition_input["truth"][row["fixture_id"]], f"decision truth mismatch: {run_id}")
            require(row["correct"] == expected_correct(row["decision"], row["truth"]), f"correctness mismatch: {run_id}")
            require(row["hidden_truth_loaded_after_phase_decision_close"] is True, f"decision boundary mismatch: {run_id}")
            all_actor_ids.add(row["operator_actor"])

        training_source = []
        evaluation_source = []
        for phase, sink in [("training", training_source), ("evaluation", evaluation_source)]:
            for population in INTELLIGENT:
                records = load(evidence / "agent-invocations" / phase / population / "decision-records.json")
                sink.extend(records)
        training_close = load(evidence / "training-decision-close.json")
        evaluation_close = load(evidence / "evaluation-decision-close.json")
        require(training_close["private_truth_loaded"] is False and evaluation_close["private_truth_loaded"] is False, "private close marker invalid")
        require(training_close["decision_count"] == 15 and canonical_hash(training_source) == training_close["decision_sha256"], f"training commitment mismatch: {run_id}")
        require(evaluation_close["decision_count"] == 12 and canonical_hash(evaluation_source) == evaluation_close["decision_sha256"], f"evaluation commitment mismatch: {run_id}")

        action_blocks, action_count = parse_framed_trace(root / "actions.bin", b"RCHTAC01", True)
        block_count, _ = parse_framed_trace(root / "blocks.bin", b"RCHTBL01", False)
        event_blocks, event_count = parse_framed_trace(root / "events.bin", b"RCHTEV01", True)
        require(action_blocks == block_count == event_blocks == 103, f"trace block count mismatch: {run_id}")
        expected_actions = sum(row["signed_action_count"] for row in decisions) + 9 + 9
        require(action_count == expected_actions == 110, f"action count mismatch: {run_id}")
        roots, m01_updates = verify_economic_state(item["condition"], decisions, root / "economic-state.jsonl")

        resources = load(root / "resources.json")
        records = resources["records"]
        recomputed = resource_totals(records)
        require(resources["totals"] == recomputed, f"resource totals mismatch: {run_id}")
        expected_by_operator = [
            {"operator": operator, "totals": resource_totals([row for row in records if row["operator"] == operator])}
            for operator in sorted(OPERATORS)
        ]
        require(resources["by_operator"] == expected_by_operator, f"operator resource totals mismatch: {run_id}")
        for population in INTELLIGENT:
            operator_records = [row for row in records if row["operator"] == population]
            require(len(operator_records) == 2 and {row["epoch"] for row in operator_records} == {0, 1}, f"intelligent epoch records mismatch: {run_id}/{population}")
            require(all(row["model_calls"] <= 4 and row["tool_calls"] <= 40 and row["validation_wall_clock_allowance_ms"] == 900_000 for row in operator_records), f"intelligent budget mismatch: {run_id}/{population}")
        for population in FIXED:
            operator_records = [row for row in records if row["operator"] == population]
            by_epoch = {epoch: sum(row["validation_wall_clock_allowance_ms"] for row in operator_records if row["epoch"] == epoch) for epoch in [0, 1]}
            if by_epoch != {0: 60_000, 1: 60_000}:
                fixed_budget_violations.append({"run_id": run_id, "operator": population, "observed_allowance_ms_by_epoch": by_epoch})
            require(all(row["model_calls"] == 0 and row["tool_calls"] == 0 for row in operator_records), f"fixed compute mismatch: {run_id}/{population}")
        customer = load(evidence / "customer-resource.json")
        require(customer["model_calls"] == 0 and customer["tool_calls"] <= customer["declared_tool_call_ceiling"], f"customer budget mismatch: {run_id}")
        require(customer["jobs_created"] == customer["claims_created"] == customer["signed_create_job_actions"] == 9, f"customer totals mismatch: {run_id}")

        training_scores = expected_reputations([row for row in decisions if row["phase"] == "training"]) if item["condition"] == "M01" else {}
        verify_metrics(load(root / "metrics.json"), decisions, resources, training_scores)
        require(condition_input["infrastructure_exclusion"] is None and condition_input["operator_failures_retained"] == 0, f"unexpected exclusion/failure: {run_id}")

        total_actions += action_count
        total_events += event_count
        total_roots += roots
        total_m01_updates += m01_updates
        total_resource_records += len(records)
        run_results.append(
            {
                "run_id": run_id,
                "seed_index": item["seed_index"],
                "condition": item["condition"],
                "reconstruction": "exact",
                "blocks": block_count,
                "signed_actions_and_nonces_verified": action_count,
                "events": event_count,
                "roots": roots,
                "m01_updates_recomputed": m01_updates,
                "metrics_recomputed": True,
                "resources_reconciled": True,
                "validity": "INVALID",
                "invalid_reasons": [
                    "fixed-heuristic per-epoch wall-clock allowance was duplicated once per fixture",
                    "validation signing identities were reused across M00 and M01 populations for the same seed",
                ],
            }
        )

    require(len(run_results) == 10 and len(all_actor_ids) == 60, "formal run identity inventory mismatch")
    require(len(fixed_budget_violations) == 80, "fixed budget violation inventory mismatch")
    require(execution["infrastructure_exclusions"] == 0 and execution["operator_failures"] == 0, "formal exclusion declaration mismatch")

    audit = {
        "schema_version": "hrep-formal-audit.v1",
        "experiment_id": "H-REP-001",
        "phase": 5,
        "status": "complete",
        "formal_validity": "INVALID",
        "reconstruction_ok": True,
        "policy_compliance": False,
        "invalid_reasons": [
            {
                "code": "VALIDATION_IDENTITY_REUSED_ACROSS_CONDITIONS",
                "detail": "The lock requires one fresh validation identity per operator, condition, and seed. The XOR key derivation swaps ten adjacent operator keys between M00 and M01 for every seed, leaving only 60 unique validation identities where 110 were required.",
                "expected_unique_identities": 110,
                "observed_unique_identities": 60,
                "cross_condition_reuses": len(independence["cross_condition_identity_reuses"]),
                "disposition": "Mark the formal result INVALID; do not repair, exclude, replace, or reinterpret the retained actions.",
            },
            {
                "code": "FIXED_EPOCH_WALL_CLOCK_ALLOWANCE_DUPLICATED",
                "detail": "The lock grants every fixed heuristic 60 seconds per epoch. Each run instead records and totals 60 seconds for every fixture, yielding 300000 ms in epoch 0 and 240000 ms in epoch 1 per fixed operator rather than 60000 ms in each epoch.",
                "affected_condition_runs": 10,
                "affected_operator_run_pairs": len(fixed_budget_violations),
                "disposition": "Mark the formal result INVALID; do not repair, exclude, replace, or reinterpret the retained records.",
            },
        ],
        "preregistration": {
            "lock_sha256": ANCHOR,
            "lock_verified": prereg_result["ok"],
            "formal_outputs_observed_before_lock": False,
            "public_fixture_manifest_sha256": public_hash,
            "held_out_private_manifest_sha256": private_hash,
            "formal_seed_derivations_verified": 5,
            "condition_run_ids_verified": 10,
            "mechanism_or_threshold_changes": execution["mechanism_or_threshold_changes"],
        },
        "replay": {
            "condition_runs": 10,
            "blocks": 1030,
            "signed_actions_and_contiguous_nonces": total_actions,
            "events": total_events,
            "roots": total_roots,
            "m01_updates_recomputed": total_m01_updates,
            "model_calls": 0,
            "exact_surfaces": ["blocks", "events", "post-state roots", "M01 economic state", "terminal outcomes"],
            "locked_replay_stdout_sha256": sha256(replay_log.encode()),
        },
        "metrics": {"run_metric_documents_recomputed": 10, "operator_rows_recomputed": 110},
        "resources": {
            "records_reconciled": total_resource_records,
            "run_totals_reconciled": 10,
            "operator_totals_reconciled": 110,
            "customer_records_reconciled": 10,
            "fixed_epoch_budget_violations": fixed_budget_violations,
        },
        "hidden_evaluator": {
            "manifest_hash_verified": True,
            "decision_phase_commitments_verified": 20,
            "resolutions_verified": 9,
            "reproductions": hidden,
        },
        "independence": independence,
        "exclusions": {
            "infrastructure_exclusions_applied": 0,
            "operator_failures_retained": 0,
            "smoke_and_calibration_data_excluded": True,
            "policy_violation_excluded": False,
            "replacement_runs": 0,
        },
        "phase4_manifest_verification": phase4_result,
        "runs": run_results,
        "assessment_deferred": True,
    }
    output.write_text(json.dumps(audit, indent=2, sort_keys=True) + "\n")
    print(json.dumps(audit, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
