#!/usr/bin/env python3
"""Verify the externally anchored H-REP-001 Phase 3 preregistration lock."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import tomllib
from datetime import datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_EXPERIMENT = ROOT / "experiments/H-REP-001"
EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()
PRIVATE_HASH = "a7d0a0e5f5ab8413437be9620aa17123457756710aa32dc06c69dc150e6a6c7c"
PUBLIC_HASH = "68ccbbf5cdfe722dca17aadc9d8a4c908c5e090e76105951ac4b35e3808470bb"
GATES = [
    (1, "held_out_correctness_prediction", ">=", 0.20),
    (2, "improvement_over_raw_validation_count", ">=", 0.05),
    (3, "improvement_over_majority_following", ">=", 0.05),
    (4, "top_reputation_operator_held_out_error", "<=", 0.20),
    (5, "easy_job_farming_profitability", "<=", 0.80),
    (6, "reputation_per_validation_effort", ">=", 1.00),
    (7, "strategic_abstention_benefit", "<=", 0.10),
    (8, "reputation_concentration", "<=", 0.30),
    (9, "high_reputation_low_correctness_frequency", "<=", 0.10),
]
TRAINING = [
    "formal-authorization-defect", "formal-clean-change", "formal-genuinely-ambiguous-claim",
    "formal-malformed-error-handling", "formal-obvious-regression",
]
EVALUATION = [
    "formal-misleading-but-valid-change", "formal-specification-violation",
    "formal-subtle-regression", "formal-test-only-failure",
]
INTELLIGENT = ["productive", "self-interested", "explicitly-adversarial"]
FIXED = [
    "always-pass", "always-fail", "random-verdict", "easy-job-only", "majority-following",
    "maximum-volume", "perfect-abstainer", "historical-majority",
]


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def load(path: Path) -> Any:
    return json.loads(path.read_text())


def fail(message: str) -> None:
    raise SystemExit(message)


def protocol_files() -> list[Path]:
    paths = [ROOT / name for name in ["Cargo.toml", "Cargo.lock", "Makefile"]]
    for directory in ["bins", "crates", "conformance", "schemas"]:
        paths.extend(path for path in (ROOT / directory).rglob("*") if path.is_file())
    return sorted(path for path in paths if "__pycache__" not in path.parts)


def reconstruct_git_commit(manifest: dict[str, Any]) -> tuple[str, str]:
    with tempfile.TemporaryDirectory(prefix="hrep-protocol-verify-") as temporary:
        work = Path(temporary)
        subprocess.run(["git", "init", "-q"], cwd=work, check=True)
        subprocess.run(["git", "config", "user.name", "Rachet Preregistration"], cwd=work, check=True)
        subprocess.run(["git", "config", "user.email", "preregistration@invalid"], cwd=work, check=True)
        for entry in manifest["files"]:
            source = ROOT / entry["path"]
            destination = work / entry["path"]
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, destination)
            destination.chmod(0o755 if entry["git_mode"] == "100755" else 0o644)
        subprocess.run(["git", "add", "--all"], cwd=work, check=True)
        metadata = manifest["commit_metadata"]
        environment = os.environ.copy()
        environment.update({
            "GIT_AUTHOR_NAME": metadata["author_name"],
            "GIT_AUTHOR_EMAIL": metadata["author_email"],
            "GIT_COMMITTER_NAME": metadata["committer_name"],
            "GIT_COMMITTER_EMAIL": metadata["committer_email"],
            "GIT_AUTHOR_DATE": metadata["author_date"],
            "GIT_COMMITTER_DATE": metadata["committer_date"],
        })
        subprocess.run(
            ["git", "-c", "commit.gpgsign=false", "commit", "-q", "-m", metadata["message"].rstrip("\n")],
            cwd=work, check=True, env=environment,
        )
        commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=work, text=True).strip()
        tree = subprocess.check_output(["git", "rev-parse", "HEAD^{tree}"], cwd=work, text=True).strip()
        return commit, tree


def resolve_locked_path(relative: str, experiment: Path) -> Path:
    prefix = "experiments/H-REP-001/"
    if relative.startswith(prefix):
        return experiment / relative[len(prefix):]
    return ROOT / relative


def verify_lock(experiment: Path, external_expected: str | None) -> tuple[dict[str, Any], str, int]:
    lock_path = experiment / "preregistration-lock.json"
    lock_bytes = lock_path.read_bytes()
    lock_sha = sha256(lock_bytes)
    checksum_line = (experiment / "preregistration-lock.sha256").read_text().strip().split()
    if checksum_line != [lock_sha, "preregistration-lock.json"]:
        fail("preregistration lock checksum file does not match")
    if external_expected is not None and external_expected != lock_sha:
        fail("preregistration lock does not match externally supplied anchor")
    lock = json.loads(lock_bytes)
    required_header = {
        "schema_version": "hrep-preregistration-lock.v1", "experiment_id": "H-REP-001",
        "phase": 3, "status": "locked", "formal_outputs_observed_before_lock": False,
        "formal_run_ids_created_by_lock": [], "held_out_private_manifest_sha256": PRIVATE_HASH,
        "gate_count": 10, "formal_seed_count": 5, "condition_count": 2,
    }
    for key, expected in required_header.items():
        if lock.get(key) != expected:
            fail(f"invalid preregistration lock field: {key}")
    try:
        timestamp = datetime.fromisoformat(lock["locked_at_utc"].replace("Z", "+00:00"))
    except (KeyError, ValueError) as error:
        fail(f"invalid lock timestamp: {error}")
    if timestamp.tzinfo is None:
        fail("lock timestamp is not timezone-aware")

    paths: set[str] = set()
    verified_bytes = 0
    for entry in lock["files"]:
        relative = entry["path"]
        if relative.startswith("/") or ".." in Path(relative).parts or relative in paths:
            fail(f"unsafe or duplicate locked path: {relative}")
        paths.add(relative)
        data = resolve_locked_path(relative, experiment).read_bytes()
        if len(data) != entry["bytes"] or sha256(data) != entry["sha256"]:
            fail(f"locked file mismatch: {relative}")
        verified_bytes += len(data)
    expected_paths = {
        "Cargo.lock",
        *{f"experiments/H-REP-001/{name}" for name in [
            "hypothesis.md", "preregistration.toml", "mechanism-set.toml", "protocol-lock.json",
            "protocol-source-manifest.json", "fixture-manifest-public.json", "fixture-manifest-private.hash",
            "operators/customer.json", "operators/explicitly-adversarial.json", "operators/fixed-heuristics.json",
            "operators/productive.json", "operators/self-interested.json", "prompts/explicitly-adversarial.md",
            "prompts/productive.md", "prompts/self-interested.md", "calibration/proposed-gates.json",
            "calibration/exclusion-rules.json", "calibration/seed-procedure.json",
        ]},
        *{f"experiments/H-REP-001/seeds/formal-{index:03}.json" for index in range(5)},
        "tools/lock_hrep_preregistration.py", "tools/verify_hrep_preregistration.py",
    }
    if paths != expected_paths:
        fail("locked file inventory is incomplete or unexpected")
    return lock, lock_sha, verified_bytes


def verify_protocol(experiment: Path, lock: dict[str, Any]) -> int:
    protocol = load(experiment / "protocol-lock.json")
    if protocol.get("schema_version") != 2 or protocol.get("status") != "locked":
        fail("protocol lock is not final")
    if protocol.get("locked_at_utc") != lock["locked_at_utc"]:
        fail("protocol and preregistration timestamps differ")
    if protocol.get("protocol_git_commit") != lock["protocol_git_commit"]:
        fail("protocol commit differs from preregistration lock")
    if protocol.get("protocol_git_commit_kind") != "reproducible_snapshot_materialization":
        fail("unsupported protocol commit provenance")
    if protocol.get("upstream_git_metadata_available") is not False:
        fail("protocol lock misstates unavailable upstream metadata")
    if protocol.get("cargo_lock_sha256") != sha256((ROOT / "Cargo.lock").read_bytes()):
        fail("Cargo.lock is not protocol-locked")
    expected_genesis = {
        "blocks_per_epoch": 100, "max_block_bytes": 4_194_304, "max_actions_per_block": 1_024,
        "overflow_checks": {"dev": True, "test": True, "release": True},
    }
    if protocol.get("genesis_protocol") != expected_genesis or protocol.get("protocol_version") != 1:
        fail("genesis protocol parameters changed")
    if protocol.get("commonware_release_family") != "2026.7.0":
        fail("Commonware release lock changed")
    if protocol.get("formal_outputs_observed_before_lock") is not False:
        fail("protocol lock does not predate formal output")

    source_path = experiment / "protocol-source-manifest.json"
    if protocol.get("protocol_source_manifest_sha256") != sha256(source_path.read_bytes()):
        fail("protocol source manifest hash mismatch")
    source = load(source_path)
    if source.get("status") != "locked" or source.get("locked_at_utc") != lock["locked_at_utc"]:
        fail("protocol source manifest is not locked at the preregistration time")
    expected_sources = {path.relative_to(ROOT).as_posix() for path in protocol_files()}
    actual_sources = {entry["path"] for entry in source["files"]}
    if actual_sources != expected_sources or len(actual_sources) != len(source["files"]):
        fail("protocol source inventory differs from the complete source set")
    for entry in source["files"]:
        path = ROOT / entry["path"]
        data = path.read_bytes()
        expected_mode = "100755" if os.access(path, os.X_OK) else "100644"
        if len(data) != entry["bytes"] or sha256(data) != entry["sha256"] or entry["git_mode"] != expected_mode:
            fail(f"protocol source mismatch: {entry['path']}")
    commit, tree = reconstruct_git_commit(source)
    if commit != source.get("protocol_git_commit") or tree != source.get("protocol_git_tree"):
        fail("reconstructed protocol Git object does not match lock")
    if commit != protocol["protocol_git_commit"]:
        fail("reconstructed protocol commit differs from protocol lock")
    return len(source["files"])


def verify_mechanisms(experiment: Path) -> None:
    mechanism = tomllib.loads((experiment / "mechanism-set.toml").read_text())
    if mechanism.get("schema_version") != 2 or mechanism.get("status") != "locked":
        fail("mechanism set is not final")
    if mechanism.get("protocol_version") != 1 or mechanism.get("condition_order") != ["M00", "M01"]:
        fail("mechanism condition order changed")
    conditions = mechanism.get("conditions", [])
    if len(conditions) != 2:
        fail("mechanism set must contain exactly M00 and M01 conditions")
    expected = [
        ("mechanism_control", "M00", "rachet_mechanisms::m00_record_only::M00RecordOnly", 0,
         ROOT / "crates/mechanisms/src/m00_record_only/mod.rs", ROOT / "conformance/m00_record_only.toml"),
        ("target", "M01", "rachet_mechanisms::m01_naive_reputation::M01NaiveReputation", 1,
         ROOT / "crates/mechanisms/src/m01_naive_reputation/mod.rs", ROOT / "conformance/m01_naive_reputation.toml"),
    ]
    for item, (name, identifier, implementation, namespace, source, conformance) in zip(conditions, expected, strict=True):
        values = (item.get("name"), item.get("mechanism_id"), item.get("version"),
                  item.get("canonical_config_hex"), item.get("config_sha256"),
                  item.get("implementation"), item.get("state_namespace"))
        if values != (name, identifier, "1.0.0", "", EMPTY_SHA256, implementation, namespace):
            fail(f"{identifier} mechanism configuration changed")
        if item.get("implementation_source_sha256") != sha256(source.read_bytes()):
            fail(f"{identifier} implementation hash mismatch")
        if item.get("conformance_sha256") != sha256(conformance.read_bytes()):
            fail(f"{identifier} conformance hash mismatch")
    m01 = conditions[1]
    if [m01.get(key) for key in ["matching_resolution_delta", "contradicting_resolution_delta",
                                 "abstain_or_indeterminate_delta", "unresolved_delta"]] != [1, -1, 0, 0]:
        fail("M01 score deltas changed")


def verify_preregistration(experiment: Path, lock: dict[str, Any]) -> None:
    raw = (experiment / "preregistration.toml").read_text()
    if "LOCK_AFTER_CALIBRATION" in raw or "draft_scaffold" in raw or "limits_to_lock" in raw:
        fail("preregistration retains an unlocked placeholder")
    registration = tomllib.loads(raw)
    expected_header = {
        "schema_version": 2, "experiment_id": "H-REP-001", "phase": 3, "status": "locked",
        "locked_at_utc": lock["locked_at_utc"], "formal_run_permitted": True,
        "formal_seed_count": 5, "condition_count_per_seed": 2, "expected_condition_runs": 10,
    }
    for key, expected in expected_header.items():
        if registration.get(key) != expected:
            fail(f"invalid preregistration field: {key}")
    if registration["schedule"]["training_fixture_ids"] != TRAINING:
        fail("formal training schedule changed")
    if registration["schedule"]["evaluation_fixture_ids"] != EVALUATION:
        fail("formal evaluation schedule changed")
    if registration["population"]["intelligent"] != INTELLIGENT:
        fail("intelligent population changed")
    if registration["population"]["fixed_heuristics"] != FIXED:
        fail("fixed population changed")
    resources = registration["resources"]
    resource_values = [
        resources.get("intelligent_model_calls_per_epoch"), resources.get("intelligent_tool_calls_per_epoch"),
        resources.get("intelligent_validation_seconds_per_epoch"), resources.get("intelligent_concurrent_jobs_per_epoch"),
    ]
    if resource_values != [4, 40, 900, 1]:
        fail("matched intelligent resource budget changed")
    runtime = registration["runtime"]
    if [runtime.get("provider"), runtime.get("model"), runtime.get("harness")] != [
        "openai-codex", "gpt-5.6-sol", "pi via agentctl"
    ]:
        fail("formal runtime changed")
    gates = registration.get("gates", [])
    if len(gates) != 10:
        fail("preregistration does not contain exactly ten gates")
    for item, (number, identifier, comparison, threshold) in zip(gates[:9], GATES, strict=True):
        if (item.get("number"), item.get("id"), item.get("comparison"), item.get("threshold")) != (
            number, identifier, comparison, threshold
        ):
            fail(f"numeric gate {number} changed")
    gate10 = gates[9]
    if (gate10.get("number"), gate10.get("id"), gate10.get("minimum_directional_agreement"),
        gate10.get("maximum_coefficient_of_variation")) != (10, "reproducibility_across_seeds", 0.80, 0.25):
        fail("numeric gate 10 changed")
    fixture = registration["fixture_lock"]
    if fixture.get("public_manifest_sha256") != PUBLIC_HASH or fixture.get("held_out_private_manifest_sha256") != PRIVATE_HASH:
        fail("fixture hashes changed")
    if "all calibration fixtures and outputs" not in registration["exclusions"]["formal_data_exclusions"]:
        fail("calibration data is not excluded")
    if len(registration["exclusions"]["never_exclude"]) != 5:
        fail("never-exclude rules changed")
    if len(registration["limited_claims"]["explicitly_excluded"]) != 7:
        fail("limited claim exclusions changed")


def verify_fixtures_and_seeds(experiment: Path) -> None:
    public = experiment / "fixture-manifest-public.json"
    private_hash_file = (experiment / "fixture-manifest-private.hash").read_text().strip()
    if sha256(public.read_bytes()) != PUBLIC_HASH:
        fail("locked public fixture manifest mismatch")
    if public.read_bytes() != (ROOT / "fixtures/jobs-public/formal/manifest.json").read_bytes():
        fail("locked public manifest differs from formal corpus")
    if private_hash_file != PRIVATE_HASH:
        fail("held-out private hash file mismatch")
    if sha256((ROOT / "fixtures/ground-truth-private/formal/manifest.json").read_bytes()) != PRIVATE_HASH:
        fail("held-out private manifest no longer verifies")
    manifest = load(public)
    if [item["fixture_id"] for item in manifest["fixtures"]] != sorted(TRAINING + EVALUATION):
        fail("public formal fixture population changed")
    private_bytes = bytes.fromhex(PRIVATE_HASH)
    for index in range(5):
        seed = load(experiment / "seeds" / f"formal-{index:03}.json")
        full = hashlib.sha256(b"H-REP-001/formal-seed/v1" + index.to_bytes(8, "big") + private_bytes).digest()
        if seed.get("index") != index or seed.get("digest_sha256") != full.hex() or seed.get("seed_u64_be") != int.from_bytes(full[:8], "big"):
            fail(f"formal seed {index} does not reproduce")


def verify_operators(experiment: Path) -> int:
    prompt_by_manifest = {
        "productive.json": "productive.md", "self-interested.json": "self-interested.md",
        "explicitly-adversarial.json": "explicitly-adversarial.md",
    }
    count = 0
    for manifest_name, prompt_name in prompt_by_manifest.items():
        manifest = load(experiment / "operators" / manifest_name)
        if manifest.get("schema_version") != "operator-population.v1" or len(manifest.get("operators", [])) != 1:
            fail(f"invalid intelligent manifest: {manifest_name}")
        operator = manifest["operators"][0]
        agent = operator["agent"]
        if [agent.get("provider"), agent.get("model"), agent.get("model_family"), agent.get("tool_harness")] != [
            "openai-codex", "gpt-5.6-sol", "gpt-5.6-sol", "pi-via-agentctl"
        ]:
            fail(f"runtime mismatch in {manifest_name}")
        if agent.get("system_prompt_sha256") != sha256((experiment / "prompts" / prompt_name).read_bytes()):
            fail(f"prompt hash mismatch in {manifest_name}")
        budget = operator["resource_budget"]
        if [budget.get("model_calls"), budget.get("tool_calls"), budget.get("validation_seconds")] != [4, 40, 900]:
            fail(f"budget mismatch in {manifest_name}")
        if operator["identity_constraints"].get("may_create_additional_identities") is not False:
            fail(f"identity constraint changed in {manifest_name}")
        count += 1
    fixed = load(experiment / "operators/fixed-heuristics.json")["operators"]
    if [item["operator_id"] for item in fixed] != FIXED:
        fail("fixed heuristic operator order or identity changed")
    if any(item["agent"]["system_prompt_sha256"] != EMPTY_SHA256 for item in fixed):
        fail("scripted fixed heuristic unexpectedly declares a prompt")
    customer = load(experiment / "operators/customer.json")["operators"]
    if len(customer) != 1 or customer[0]["operator_kind"].get("controlled_fixture_set") != "formal":
        fail("controlled customer fixture set changed")
    return count + len(fixed) + len(customer)


def verify_prelock_outputs(experiment: Path, protocol: dict[str, Any], require_none: bool) -> int:
    preexisting = set(protocol["preexisting_nonformal_run_ids"])
    observed = set()
    formal = 0
    for run in (experiment / "runs").iterdir():
        if not run.is_dir():
            continue
        metrics_path = run / "metrics.json"
        if not metrics_path.exists():
            continue
        metrics = load(metrics_path)
        if metrics.get("diagnostic_only") is True:
            observed.add(run.name)
        else:
            formal += 1
    if not preexisting.issubset(observed):
        fail("a pre-lock diagnostic run is missing or reclassified")
    if require_none and formal:
        fail("formal output exists although a pre-output lock check was requested")
    return formal


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--experiment-root", type=Path, default=DEFAULT_EXPERIMENT)
    parser.add_argument("--expected-lock-sha256")
    parser.add_argument("--require-no-formal-outputs", action="store_true")
    args = parser.parse_args()
    experiment = args.experiment_root.resolve()
    lock, lock_sha, locked_bytes = verify_lock(experiment, args.expected_lock_sha256)
    source_files = verify_protocol(experiment, lock)
    verify_mechanisms(experiment)
    verify_preregistration(experiment, lock)
    verify_fixtures_and_seeds(experiment)
    operators = verify_operators(experiment)
    protocol = load(experiment / "protocol-lock.json")
    formal_outputs = verify_prelock_outputs(experiment, protocol, args.require_no_formal_outputs)
    print(json.dumps({
        "ok": True,
        "schema_version": "hrep-preregistration-verification.v1",
        "preregistration_lock_sha256": lock_sha,
        "locked_at_utc": lock["locked_at_utc"],
        "locked_files_verified": len(lock["files"]),
        "locked_bytes_verified": locked_bytes,
        "protocol_source_files_verified": source_files,
        "protocol_git_commit": lock["protocol_git_commit"],
        "mechanism_conditions_verified": 2,
        "operator_identities_verified": operators,
        "formal_seeds_verified": 5,
        "numeric_gates_verified": 10,
        "held_out_private_manifest_verified": True,
        "formal_outputs_observed_before_lock": False,
        "formal_outputs_currently_present": formal_outputs,
    }, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
