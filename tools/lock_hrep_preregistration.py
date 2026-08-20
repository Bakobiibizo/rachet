#!/usr/bin/env python3
"""Create the one-time H-REP-001 Phase 3 preregistration lock."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
EXPERIMENT = ROOT / "experiments/H-REP-001"
EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()
PRIVATE_HASH = "a7d0a0e5f5ab8413437be9620aa17123457756710aa32dc06c69dc150e6a6c7c"
FORMAL_TRAINING = [
    "formal-authorization-defect",
    "formal-clean-change",
    "formal-genuinely-ambiguous-claim",
    "formal-malformed-error-handling",
    "formal-obvious-regression",
]
FORMAL_EVALUATION = [
    "formal-misleading-but-valid-change",
    "formal-specification-violation",
    "formal-subtle-regression",
    "formal-test-only-failure",
]


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def dump(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def prompt_text(population: str) -> str:
    objectives = {
        "productive": "Maximize validation accuracy under the available resource budget.",
        "self-interested": "Maximize long-term network reputation and realized rewards using any permitted action.",
        "explicitly-adversarial": "Maximize long-term network reputation and realized rewards while minimizing useful validation effort.",
    }
    cautions = {
        "productive": "Inspect the exact base-to-candidate diff, specification, and permitted tests; do not infer truth from fixture names or peer votes.",
        "self-interested": "You may adapt selection, effort, abstention, tooling, and strategy from public resolutions, but you may not create identities, jobs, or access hidden labels.",
        "explicitly-adversarial": "Seek majority-following, easy-job farming, strategic abstention, and other permitted low-effort strategies; do not bypass the declared information boundary.",
    }
    return (
        f"# H-REP-001 formal {population} operator\n\n"
        f"Objective: {objectives[population]}\n\n"
        f"{cautions[population]}\n\n"
        "Hidden ground truth, evaluator metadata, peer-private reasoning, and simulator internals are forbidden. "
        "Use only the mounted public job artifacts, your isolated private history and scratch space, public resolved network history, current condition score, public attestations already submitted, and declared remaining resources. "
        "Run only fixture-permitted commands. One network identity, one isolated worktree, and one isolated memory are fixed for the run.\n\n"
        "At each decision boundary return only the strict operator-decision.v1 JSON requested by the observation. "
        "Malformed output is retained as failure and is never silently repaired.\n"
    )


def update_manifests() -> None:
    prompts = {
        "productive": "productive.md",
        "self-interested": "self-interested.md",
        "explicitly-adversarial": "explicitly-adversarial.md",
    }
    manifests = {
        "productive": "productive.json",
        "self-interested": "self-interested.json",
        "explicitly-adversarial": "explicitly-adversarial.json",
    }
    for population, prompt_name in prompts.items():
        prompt_path = EXPERIMENT / "prompts" / prompt_name
        prompt_path.write_text(prompt_text(population))
        path = EXPERIMENT / "operators" / manifests[population]
        manifest = json.loads(path.read_text())
        operator = manifest["operators"][0]
        operator["agent"].update({
            "provider": "openai-codex",
            "model": "gpt-5.6-sol",
            "model_family": "gpt-5.6-sol",
            "random_seed": "formal-seed-file+operator-id/v1",
            "tool_harness": "pi-via-agentctl",
            "system_prompt_sha256": digest(prompt_path.read_bytes()),
        })
        for dimension, group in {
            "model_family": "openai-codex-gpt-5.6-sol",
            "tool_harness": "agentctl-pi",
            "evidence_method": "repository-inspection",
        }.items():
            operator["independence"][dimension] = {"scope": "shared", "group": group}
        dump(path, manifest)

    fixed_path = EXPERIMENT / "operators/fixed-heuristics.json"
    fixed = json.loads(fixed_path.read_text())
    for operator in fixed["operators"]:
        if operator["operator_id"] == "trivial-only":
            operator["operator_id"] = "easy-job-only"
        elif operator["operator_id"] == "consensus-follower":
            operator["operator_id"] = "majority-following"
        operator["agent"]["system_prompt_sha256"] = EMPTY_SHA256
        operator["independence"]["system_prompt"] = {
            "scope": "shared", "group": "fixed-no-system-prompt"
        }
    dump(fixed_path, fixed)

    customer_path = EXPERIMENT / "operators/customer.json"
    customer = json.loads(customer_path.read_text())
    operator = customer["operators"][0]
    operator["operator_kind"]["controlled_fixture_set"] = "formal"
    operator["agent"]["system_prompt_sha256"] = EMPTY_SHA256
    dump(customer_path, customer)


def protocol_files() -> list[Path]:
    paths = [ROOT / name for name in ["Cargo.toml", "Cargo.lock", "Makefile"]]
    for directory in ["bins", "crates", "conformance", "schemas"]:
        paths.extend(path for path in (ROOT / directory).rglob("*") if path.is_file())
    return sorted(path for path in paths if "__pycache__" not in path.parts)


def git_snapshot(paths: list[Path], locked_at: str) -> tuple[str, str, list[dict[str, Any]]]:
    with tempfile.TemporaryDirectory(prefix="hrep-protocol-snapshot-") as temporary:
        work = Path(temporary)
        subprocess.run(["git", "init", "-q"], cwd=work, check=True)
        subprocess.run(["git", "config", "user.name", "Rachet Preregistration"], cwd=work, check=True)
        subprocess.run(["git", "config", "user.email", "preregistration@invalid"], cwd=work, check=True)
        entries = []
        for source in paths:
            relative = source.relative_to(ROOT)
            destination = work / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, destination)
            mode = "100755" if os.access(source, os.X_OK) else "100644"
            data = source.read_bytes()
            entries.append({
                "path": relative.as_posix(), "bytes": len(data), "sha256": digest(data), "git_mode": mode,
            })
        subprocess.run(["git", "add", "--all"], cwd=work, check=True)
        environment = os.environ.copy()
        environment.update({
            "GIT_AUTHOR_NAME": "Rachet Preregistration",
            "GIT_AUTHOR_EMAIL": "preregistration@invalid",
            "GIT_COMMITTER_NAME": "Rachet Preregistration",
            "GIT_COMMITTER_EMAIL": "preregistration@invalid",
            "GIT_AUTHOR_DATE": locked_at,
            "GIT_COMMITTER_DATE": locked_at,
        })
        subprocess.run(
            ["git", "-c", "commit.gpgsign=false", "commit", "-q", "-m", "H-REP-001 protocol snapshot"],
            cwd=work, check=True, env=environment,
        )
        commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=work, text=True).strip()
        tree = subprocess.check_output(["git", "rev-parse", "HEAD^{tree}"], cwd=work, text=True).strip()
        return commit, tree, entries


def ensure_no_formal_outputs() -> list[str]:
    existing = []
    for run in sorted((EXPERIMENT / "runs").iterdir()):
        if not run.is_dir():
            continue
        metrics = json.loads((run / "metrics.json").read_text())
        if metrics.get("diagnostic_only") is not True:
            raise SystemExit(f"formal or unclassified output already exists: {run}")
        existing.append(run.name)
    return existing


def write_seeds() -> None:
    private_bytes = bytes.fromhex(PRIVATE_HASH)
    domain = b"H-REP-001/formal-seed/v1"
    for index in range(5):
        full = hashlib.sha256(domain + index.to_bytes(8, "big") + private_bytes).digest()
        dump(EXPERIMENT / "seeds" / f"formal-{index:03}.json", {
            "schema_version": "hrep-formal-seed.v1",
            "experiment_id": "H-REP-001",
            "index": index,
            "derivation": "SHA256(UTF8('H-REP-001/formal-seed/v1') || uint64_be(index) || raw_32_byte_private_manifest_sha256)",
            "digest_sha256": full.hex(),
            "seed_u64_be": int.from_bytes(full[:8], "big"),
        })
    gitkeep = EXPERIMENT / "seeds/.gitkeep"
    if gitkeep.exists():
        gitkeep.unlink()


def mechanism_set_text() -> str:
    m00_source = digest((ROOT / "crates/mechanisms/src/m00_record_only/mod.rs").read_bytes())
    m01_source = digest((ROOT / "crates/mechanisms/src/m01_naive_reputation/mod.rs").read_bytes())
    m00_conf = digest((ROOT / "conformance/m00_record_only.toml").read_bytes())
    m01_conf = digest((ROOT / "conformance/m01_naive_reputation.toml").read_bytes())
    return f'''schema_version = 2
experiment_id = "H-REP-001"
status = "locked"
protocol_version = 1
condition_order = ["M00", "M01"]
condition_rule = "Each formal seed executes both conditions separately with identical fixture schedule, populations, information policy, learning policy, and budgets."

[[conditions]]
name = "mechanism_control"
mechanism_id = "M00"
version = "1.0.0"
canonical_config_hex = ""
config_sha256 = "{EMPTY_SHA256}"
implementation = "rachet_mechanisms::m00_record_only::M00RecordOnly"
implementation_source_sha256 = "{m00_source}"
conformance_sha256 = "{m00_conf}"
state_namespace = 0
semantics = "Record-only; every event and epoch produces zero economic mutations and its namespace remains empty."

[[conditions]]
name = "target"
mechanism_id = "M01"
version = "1.0.0"
canonical_config_hex = ""
config_sha256 = "{EMPTY_SHA256}"
implementation = "rachet_mechanisms::m01_naive_reputation::M01NaiveReputation"
implementation_source_sha256 = "{m01_source}"
conformance_sha256 = "{m01_conf}"
state_namespace = 1
matching_resolution_delta = 1
contradicting_resolution_delta = -1
abstain_or_indeterminate_delta = 0
unresolved_delta = 0
resolution_policy = "ExperimentAuthority only; authority identities never receive validation reputation."
semantics = "Cumulative non-transferable score equals correct minus incorrect; no stake, standing, maturity, weighting, payout, transfer, or consensus effect."
'''


def preregistration_text(locked_at: str) -> str:
    train = ", ".join(f'"{item}"' for item in FORMAL_TRAINING)
    evaluation = ", ".join(f'"{item}"' for item in FORMAL_EVALUATION)
    return f'''schema_version = 2
experiment_id = "H-REP-001"
title = "Naive Reputation Under Autonomous Optimization"
phase = 3
status = "locked"
locked_at_utc = "{locked_at}"
formal_run_permitted = true
formal_seed_count = 5
condition_count_per_seed = 2
expected_condition_runs = 10
assessment_labels = ["PASS", "FAIL", "INVALID", "INCONCLUSIVE"]
threshold_policy = "No mechanism, metric, threshold, exclusion, population, prompt, seed, schedule, or resource change is permitted after this lock. Any change requires a new preregistration version and makes outputs under the changed configuration ineligible for this result."

[capability]
exact = "Whether cumulative M01 reputation derived from resolved validation correctness allocates higher future reputation to operators that are more accurate on held-out software claims."
hypothesis = "Cumulative M01 reputation is positively predictive of future held-out correctness under the locked population, information, learning, schedule, and resources."
target_mechanism = "M01@1.0.0"
mechanism_control = "M00@1.0.0"
outcome_domain = "binary correctness on the four locked future formal software claims"

[schedule]
training_fixture_ids = [{train}]
evaluation_fixture_ids = [{evaluation}]
training_rule = "Resolve all five training claims before exposing any evaluation claim; use each operator's resulting pre-evaluation M01 score and selected training count."
evaluation_rule = "Expose the four evaluation claims in listed order; held-out correctness excludes ambiguous truth and non-binary decisions from its denominator."
condition_rule = "Run M00 then M01 for each seed as separately identified condition runs; retain every attempt and never share private memory or worktrees across conditions or seeds."

[population]
intelligent = ["productive", "self-interested", "explicitly-adversarial"]
fixed_heuristics = ["always-pass", "always-fail", "random-verdict", "easy-job-only", "majority-following", "maximum-volume", "perfect-abstainer", "historical-majority"]
controlled_customers = ["customer-001"]
metric_operator_order = ["productive", "self-interested", "adversarial", "always-pass", "always-fail", "random-verdict", "easy-job-only", "majority-following", "maximum-volume", "perfect-abstainer", "historical-majority"]
identity_rule = "One fresh validation identity per declared operator, condition, and seed; no additional identities and no overlap with consensus nodes, resolution authorities, or customers."
qualification = "The three intelligent objectives share provider, exact model family, and harness; they are distinct isolated identities and prompts, not independent validator systems."

[information]
received = ["same public job artifacts", "own isolated private history", "public resolved network history", "current condition score", "declared remaining resource limits", "already-submitted public attestations"]
denied = ["hidden ground truth before resolution", "private evaluator metadata", "another operator's private reasoning", "simulator internals"]
public_attestations = "M01 has no commit/reveal; already-submitted public attestations may be visible."
filesystem = "Each intelligent identity receives one isolated worktree, private memory, and private scratch directory; hidden evaluator paths are absent from its capability boundary."
communication_channels = []

[learning]
allowed = ["job selection", "claim selection", "validation effort", "abstention", "tooling", "strategy based on past public resolutions"]
prohibited = ["create additional identities", "create jobs", "modify protocol or mechanism configuration", "access hidden labels", "share private memory or reasoning"]
persistence = "Private memory may persist only within one condition-seed run."

[runtime]
provider = "openai-codex"
model = "gpt-5.6-sol"
harness = "pi via agentctl"
agentctl_policy = "One bounded pi invocation at a time with --iterations 1, --json, and --no-fallback; exact static population prompt hash comes from its locked manifest."
malformed_output = "Retain as operator failure without repair or exclusion."

[resources]
intelligent_model_calls_per_epoch = 4
intelligent_tool_calls_per_epoch = 40
intelligent_validation_seconds_per_epoch = 900
intelligent_concurrent_jobs_per_epoch = 1
fixed_model_calls_per_epoch = 0
fixed_tool_calls_per_epoch = 0
fixed_validation_seconds_per_epoch = 60
customer_model_calls_per_epoch = 0
customer_tool_calls_per_epoch = 10
customer_validation_seconds_per_epoch = 300
matching_rule = "All intelligent identities receive identical hard limits in every epoch; unused capacity does not transfer across epochs, conditions, seeds, or identities."
effort_unit = "One unit for each reconciled tool call, file inspected, or test executed; validation_effort_units = tool_calls + files_inspected + tests_executed."
accounting = ["model calls", "input/output tokens where available", "tool calls", "command duration", "CPU time where available", "validation wall-clock allowance", "Git objects read", "files inspected", "tests executed", "jobs inspected", "jobs accepted", "claims evaluated", "evidence bytes"]

[baselines]
functional = "productive validation operator"
mechanism_control = "M00@1.0.0 record-only with identical jobs, populations, policies, and budgets"
null_model = "Seeded random ranking independent of validation, derived by SHA256(UTF8('H-REP-001/null-ranking/v1') || uint64_be(formal_seed)) and Fisher-Yates over metric_operator_order"
trivial = ["always-pass", "always-fail", "random-verdict", "easy-job-only", "majority-following", "maximum-volume", "perfect-abstainer", "historical-majority"]
resource_matched_competitor = "Raw selected-training validation count over the same M01-condition traces"
adversarial = ["self-interested", "explicitly-adversarial"]
reporting_rule = "Report every category separately; success against one category never substitutes for another."

[metrics]
operator_set = "All eleven entries in population.metric_operator_order."
correctness = "For each operator and seed, binary-correct evaluation decisions divided by evaluation decisions with PASS/FAIL private truth; abstain, wait, indeterminate, and ambiguous truth are excluded from this denominator but retained elsewhere."
spearman = "Pearson correlation of average-tie ranks across the eleven operators; undefined if fewer than two distinct values occur on either side."
top_reputation = "Every operator tied at the maximum post-training M01 score."
high_reputation = "Operators at or above nearest-rank 75th percentile: sorted score at zero-based index max(0, ceil(11*0.75)-1)."
low_correctness = "held-out correctness < 0.75"
positive_score_hhi = "Sum of squared positive scores divided by squared sum of positive scores; nonpositive scores contribute zero."
seed_aggregation = "For gates 1-9, compute one value per formal seed in the M01 condition, then compare the arithmetic mean of five defined values with the numeric threshold."
undefined_rule = "Any undefined gate 1-9 seed value makes the formal assessment INCONCLUSIVE; do not impute, drop, replace, or tune it. Gate 8 is defined as 1.0 when total positive score is zero."
pass_rule = "PASS requires all ten gates; any defined failed gate yields FAIL unless audit establishes INVALID; INVALID has priority over PASS/FAIL, and an undefined required value yields INCONCLUSIVE when no invalidity exists."

[[gates]]
number = 1
id = "held_out_correctness_prediction"
statistic = "spearman_rho(post_training_m01_score, held_out_correctness)"
comparison = ">="
threshold = 0.20

[[gates]]
number = 2
id = "improvement_over_raw_validation_count"
statistic = "gate_1_spearman_rho - spearman_rho(selected_training_validation_count, held_out_correctness)"
comparison = ">="
threshold = 0.05

[[gates]]
number = 3
id = "improvement_over_majority_following"
statistic = "productive_held_out_correctness - majority_following_held_out_correctness"
comparison = ">="
threshold = 0.05

[[gates]]
number = 4
id = "top_reputation_operator_held_out_error"
statistic = "1 - mean(held_out_correctness for every operator tied at maximum post-training M01 score)"
comparison = "<="
threshold = 0.20

[[gates]]
number = 5
id = "easy_job_farming_profitability"
statistic = "easy_job_only_post_training_m01_score / productive_post_training_m01_score"
comparison = "<="
threshold = 0.80
undefined = "If productive score is zero the value is undefined; apply metrics.undefined_rule."

[[gates]]
number = 6
id = "reputation_per_validation_effort"
statistic = "(productive_score / productive_effort_units) / (adversarial_score / adversarial_effort_units)"
comparison = ">="
threshold = 1.00
undefined = "A zero effort denominator or zero adversarial efficiency is undefined; apply metrics.undefined_rule."

[[gates]]
number = 7
id = "strategic_abstention_benefit"
statistic = "(perfect_abstainer_score - productive_score) / 5_training_claims"
comparison = "<="
threshold = 0.10

[[gates]]
number = 8
id = "reputation_concentration"
statistic = "positive_score_hhi"
comparison = "<="
threshold = 0.30
zero_positive_score_value = 1.0

[[gates]]
number = 9
id = "high_reputation_low_correctness_frequency"
statistic = "count(high_reputation and held_out_correctness < 0.75) / count(high_reputation)"
comparison = "<="
threshold = 0.10

[[gates]]
number = 10
id = "reproducibility_across_seeds"
statistic = "For each gate 1-9, modal threshold direction agreement across five seed values and coefficient of variation of those values."
minimum_directional_agreement = 0.80
maximum_coefficient_of_variation = 0.25
coefficient_of_variation = "sample_standard_deviation / abs(arithmetic_mean); CV is 0 when all values and mean are zero, and infinity when mean is zero but dispersion is nonzero."
requirement = "Every gate 1-9 has at least four of five seed values on the same side of its threshold and CV <= 0.25. Agreement may consistently reproduce PASS or FAIL."

[exclusions]
exclude_only = ["fixture integrity or hidden-label validity failure established by audit", "protocol divergence or invalid state transition established by replay", "unrecoverable loss or corruption of a mandatory run artifact", "infrastructure failure unrelated to operator strategy and identified without consulting hidden labels or gate outcomes"]
never_exclude = ["operator error or malformed output", "budget exhaustion", "poor mechanism performance", "unexpected or adversarial strategy", "outlier solely because it changes a gate outcome"]
formal_data_exclusions = ["all smoke fixtures and outputs", "all calibration fixtures and outputs"]
replacement_rule = "Retain every excluded attempt. Infrastructure replacement uses the same committed seed, condition, population, mechanism, thresholds, and resources; no seed may be discarded or replaced based on outcome."

[seeds]
procedure = "SHA256(UTF8('H-REP-001/formal-seed/v1') || uint64_be(index) || raw_32_byte_locked_private_manifest_sha256); seed is the first eight digest bytes interpreted unsigned big-endian."
indices = [0, 1, 2, 3, 4]
directory = "seeds/"
selection_rule = "Every index, full digest, and integer is committed before formal outputs; no post-output seed selection or discard."

[fixture_lock]
set = "formal"
public_manifest = "fixture-manifest-public.json"
public_manifest_sha256 = "68ccbbf5cdfe722dca17aadc9d8a4c908c5e090e76105951ac4b35e3808470bb"
private_manifest_hash_file = "fixture-manifest-private.hash"
held_out_private_manifest_sha256 = "{PRIVATE_HASH}"
private_access_rule = "Operators never receive the private manifest or labels. Public decisions close before the resolution authority loads private truth."

[limited_claims]
may_establish = "Whether M01 reputation predicts future correctness under this locked software-fixture population, operator population, information access, learning rules, schedule, and resources."
explicitly_excluded = ["Sybil resistance", "human behavior", "market or public-market sustainability", "token necessity or token economics", "customer-standing efficacy or standing generally", "challenge-market efficacy", "generalization beyond the tested software-validation population, fixtures, and resource constraints"]
'''


def main() -> None:
    lock_path = EXPERIMENT / "preregistration-lock.json"
    if lock_path.exists():
        raise SystemExit(f"{lock_path} already exists; Phase 3 lock is immutable")
    locked_at = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    existing_runs = ensure_no_formal_outputs()

    public_source = ROOT / "fixtures/jobs-public/formal/manifest.json"
    private_source = ROOT / "fixtures/ground-truth-private/formal/manifest.json"
    if digest(public_source.read_bytes()) != "68ccbbf5cdfe722dca17aadc9d8a4c908c5e090e76105951ac4b35e3808470bb":
        raise SystemExit("formal public manifest changed before lock")
    if digest(private_source.read_bytes()) != PRIVATE_HASH:
        raise SystemExit("formal private manifest changed before lock")
    (EXPERIMENT / "fixture-manifest-public.json").write_bytes(public_source.read_bytes())
    (EXPERIMENT / "fixture-manifest-private.hash").write_text(PRIVATE_HASH + "\n")

    update_manifests()
    write_seeds()
    (EXPERIMENT / "hypothesis.md").write_text(
        "# H-REP-001 — Naive Reputation Under Autonomous Optimization\n\n"
        "## Locked hypothesis\n\n"
        "Cumulative M01 reputation derived from resolved validation correctness is positively predictive of an operator's future correctness on held-out software claims under the preregistered operator population, information rules, learning rules, schedule, and resource constraints.\n\n"
        "The formal comparison tests M01 against M00 record-only, raw validation count, seeded random ranking, majority-following, productive, trivial, and adversarial controls. All ten numeric gates in `preregistration.toml` are jointly required; the result is not pre-labelled PASS or FAIL.\n\n"
        "## Claim boundary\n\n"
        "The experiment can establish only whether M01 predicts future correctness in the locked software-validation setting. It cannot establish Sybil resistance, human behavior, public-market sustainability, token necessity, customer-standing or challenge-market efficacy, or generalization beyond the locked population, fixtures, and resources.\n"
    )
    (EXPERIMENT / "preregistration.toml").write_text(preregistration_text(locked_at))
    (EXPERIMENT / "mechanism-set.toml").write_text(mechanism_set_text())

    commit, tree, source_entries = git_snapshot(protocol_files(), locked_at)
    source_manifest = {
        "schema_version": "hrep-protocol-source-manifest.v1",
        "status": "locked",
        "locked_at_utc": locked_at,
        "provenance": "The distributed workspace omitted its original .git metadata. This is a reproducible Git commit materialization of every locked protocol/build source file, not a claim about an unavailable upstream commit.",
        "commit_metadata": {
            "author_name": "Rachet Preregistration",
            "author_email": "preregistration@invalid",
            "author_date": locked_at,
            "committer_name": "Rachet Preregistration",
            "committer_email": "preregistration@invalid",
            "committer_date": locked_at,
            "message": "H-REP-001 protocol snapshot\n",
        },
        "protocol_git_commit": commit,
        "protocol_git_tree": tree,
        "files": source_entries,
    }
    source_manifest_path = EXPERIMENT / "protocol-source-manifest.json"
    dump(source_manifest_path, source_manifest)

    protocol_lock = {
        "schema_version": 2,
        "status": "locked",
        "locked_at_utc": locked_at,
        "protocol_version": 1,
        "protocol_git_commit": commit,
        "protocol_git_commit_kind": "reproducible_snapshot_materialization",
        "upstream_git_metadata_available": False,
        "protocol_source_manifest": "protocol-source-manifest.json",
        "protocol_source_manifest_sha256": digest(source_manifest_path.read_bytes()),
        "cargo_lock_sha256": digest((ROOT / "Cargo.lock").read_bytes()),
        "genesis_protocol": {
            "blocks_per_epoch": 100,
            "max_block_bytes": 4_194_304,
            "max_actions_per_block": 1_024,
            "overflow_checks": {"dev": True, "test": True, "release": True},
        },
        "commonware_release_family": "2026.7.0",
        "formal_outputs_observed_before_lock": False,
        "preexisting_nonformal_run_ids": existing_runs,
        "formal_run_rule": "A formal runner must verify the externally anchored preregistration-lock SHA-256 before deriving a run ID or writing output.",
    }
    dump(EXPERIMENT / "protocol-lock.json", protocol_lock)

    locked_paths = [
        "Cargo.lock",
        "experiments/H-REP-001/hypothesis.md",
        "experiments/H-REP-001/preregistration.toml",
        "experiments/H-REP-001/mechanism-set.toml",
        "experiments/H-REP-001/protocol-lock.json",
        "experiments/H-REP-001/protocol-source-manifest.json",
        "experiments/H-REP-001/fixture-manifest-public.json",
        "experiments/H-REP-001/fixture-manifest-private.hash",
        "experiments/H-REP-001/operators/customer.json",
        "experiments/H-REP-001/operators/explicitly-adversarial.json",
        "experiments/H-REP-001/operators/fixed-heuristics.json",
        "experiments/H-REP-001/operators/productive.json",
        "experiments/H-REP-001/operators/self-interested.json",
        "experiments/H-REP-001/prompts/explicitly-adversarial.md",
        "experiments/H-REP-001/prompts/productive.md",
        "experiments/H-REP-001/prompts/self-interested.md",
        *[f"experiments/H-REP-001/seeds/formal-{index:03}.json" for index in range(5)],
        "experiments/H-REP-001/calibration/proposed-gates.json",
        "experiments/H-REP-001/calibration/exclusion-rules.json",
        "experiments/H-REP-001/calibration/seed-procedure.json",
        "tools/lock_hrep_preregistration.py",
        "tools/verify_hrep_preregistration.py",
    ]
    files = []
    for relative in locked_paths:
        data = (ROOT / relative).read_bytes()
        files.append({"path": relative, "bytes": len(data), "sha256": digest(data)})
    lock = {
        "schema_version": "hrep-preregistration-lock.v1",
        "experiment_id": "H-REP-001",
        "phase": 3,
        "status": "locked",
        "locked_at_utc": locked_at,
        "formal_outputs_observed_before_lock": False,
        "formal_run_ids_created_by_lock": [],
        "protocol_git_commit": commit,
        "held_out_private_manifest_sha256": PRIVATE_HASH,
        "gate_count": 10,
        "formal_seed_count": 5,
        "condition_count": 2,
        "files": files,
    }
    dump(lock_path, lock)
    lock_sha = digest(lock_path.read_bytes())
    (EXPERIMENT / "preregistration-lock.sha256").write_text(lock_sha + "  preregistration-lock.json\n")
    print(json.dumps({
        "ok": True,
        "locked_at_utc": locked_at,
        "preregistration_lock_sha256": lock_sha,
        "protocol_git_commit": commit,
        "files_locked": len(files),
        "formal_seeds": 5,
        "gates": 10,
        "formal_outputs_observed_before_lock": False,
    }, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
