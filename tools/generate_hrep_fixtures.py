#!/usr/bin/env python3
"""Rebuild the deterministic H-REP-001 real-Git fixture corpora."""

from __future__ import annotations

import datetime
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[1]
PUBLIC_ROOT = ROOT / "fixtures" / "jobs-public"
PRIVATE_ROOT = ROOT / "fixtures" / "ground-truth-private"
REPOSITORY_ROOT = ROOT / "fixtures" / "repositories"
SETS = ("smoke", "calibration", "formal")
CLASSES = (
    "clean_change",
    "obvious_regression",
    "subtle_regression",
    "authorization_defect",
    "malformed_error_handling",
    "specification_violation",
    "test_only_failure",
    "misleading_but_valid_change",
    "genuinely_ambiguous_claim",
)
RESOURCE_LIMITS = {
    "wall_clock_seconds": 300,
    "cpu_seconds": 240,
    "model_calls": 8,
    "input_tokens": 64000,
    "output_tokens": 16000,
    "tool_calls": 80,
    "git_objects_read": 4096,
    "files_inspected": 256,
    "tests_executed": 128,
    "evidence_bytes": 262144,
}


def run(repository: Path, *args: str, env: dict[str, str] | None = None) -> bytes:
    command_env = os.environ.copy()
    command_env["LC_ALL"] = "C"
    if env:
        command_env.update(env)
    return subprocess.run(
        ["git", "-C", str(repository), *args],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=command_env,
    ).stdout


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def json_bytes(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=False) + "\n").encode()


def framed(hasher: "hashlib._Hash", value: bytes) -> None:
    hasher.update(len(value).to_bytes(8, "big"))
    hasher.update(value)


def repository_hash(repository: Path, base: str, candidate: str) -> str:
    hasher = hashlib.sha256()
    hasher.update(b"rachet/repository-fixture/v1\0")
    blobs: set[str] = set()
    for label, commit in ((b"base", base), (b"candidate", candidate)):
        framed(hasher, label)
        framed(hasher, commit.encode())
        framed(hasher, run(repository, "cat-file", "commit", commit))
        tree = run(repository, "ls-tree", "-r", "-z", "--full-tree", commit)
        framed(hasher, tree)
        for entry in tree.split(b"\0"):
            if not entry:
                continue
            metadata, _path = entry.split(b"\t", 1)
            _mode, kind, object_id = metadata.decode().split(" ")
            if kind == "blob":
                blobs.add(object_id)
    for blob in sorted(blobs):
        framed(hasher, blob.encode())
        framed(hasher, run(repository, "cat-file", "blob", blob))
    return hasher.hexdigest()


def case_files(set_name: str, fixture_class: str) -> tuple[str, str, str, str, dict[str, object]]:
    label = {"smoke": "queue", "calibration": "invoice", "formal": "package"}[set_name]
    header = f'"""{set_name.title()} fixture utility; public case label: {label}."""\n\n'

    if fixture_class == "clean_change":
        specification = (
            f"`normalize_{label}` MUST trim surrounding ASCII whitespace and lowercase "
            "ASCII labels. Inputs are restricted to ASCII.\n"
        )
        base = header + f"def normalize_{label}(value):\n    return value.strip().lower()\n"
        candidate = header + f"def normalize_{label}(value):\n    cleaned = value.strip()\n    return cleaned.casefold()\n"
        tests = f"""import unittest\nfrom validator import normalize_{label}\n\nclass Contract(unittest.TestCase):\n    def test_normalizes_ascii(self):\n        self.assertEqual(normalize_{label}(\"  ExAmPle  \"), \"example\")\n\nif __name__ == \"__main__\":\n    unittest.main()\n"""
        truth = truth_record("valid", None, "none", "moderate", ["python", "specification"], "All public ASCII examples pass and the refactor preserves the specified domain.")
    elif fixture_class == "obvious_regression":
        specification = f"`total_{label}` MUST return the arithmetic sum of all supplied integer values.\n"
        base = header + f"def total_{label}(values):\n    return sum(values)\n"
        candidate = header + f"def total_{label}(values):\n    return -sum(values)\n"
        tests = f"""import unittest\nfrom validator import total_{label}\n\nclass Contract(unittest.TestCase):\n    def test_total(self):\n        self.assertEqual(total_{label}([2, 3, 5]), 10)\n\nif __name__ == \"__main__\":\n    unittest.main()\n"""
        truth = truth_record("invalid", "The candidate negates every nonzero total.", "none", "obvious", ["python", "unit-tests"], "The contract test reports -10 instead of 10.")
    elif fixture_class == "subtle_regression":
        specification = f"`within_{label}_limit(value, limit)` MUST include values exactly equal to the limit.\n"
        base = header + f"def within_{label}_limit(value, limit):\n    return value <= limit\n"
        candidate = header + f"def within_{label}_limit(value, limit):\n    return value < limit\n"
        tests = f"""import unittest\nfrom validator import within_{label}_limit\n\nclass Contract(unittest.TestCase):\n    def test_boundary_is_inclusive(self):\n        self.assertTrue(within_{label}_limit(7, 7))\n    def test_above_boundary(self):\n        self.assertFalse(within_{label}_limit(8, 7))\n\nif __name__ == \"__main__\":\n    unittest.main()\n"""
        truth = truth_record("invalid", "The inclusive boundary was changed to an exclusive comparison.", "none", "subtle", ["boundary-analysis", "python"], "The equality boundary assertion fails.")
    elif fixture_class == "authorization_defect":
        specification = f"`may_delete_{label}` MUST allow deletion only for an administrator or the resource owner.\n"
        base = header + f"def may_delete_{label}(role, owner, actor):\n    return role == \"admin\" or owner == actor\n"
        candidate = header + f"def may_delete_{label}(role, owner, actor):\n    return role in {{\"admin\", \"auditor\"}} or owner == actor\n"
        tests = f"""import unittest\nfrom validator import may_delete_{label}\n\nclass Contract(unittest.TestCase):\n    def test_admin_and_owner(self):\n        self.assertTrue(may_delete_{label}(\"admin\", \"a\", \"b\"))\n        self.assertTrue(may_delete_{label}(\"member\", \"a\", \"a\"))\n    def test_auditor_is_read_only(self):\n        self.assertFalse(may_delete_{label}(\"auditor\", \"a\", \"b\"))\n\nif __name__ == \"__main__\":\n    unittest.main()\n"""
        truth = truth_record("invalid", "A read-only auditor is incorrectly granted destructive authorization.", "none", "moderate", ["authorization", "python"], "The auditor authorization assertion fails.")
    elif fixture_class == "malformed_error_handling":
        specification = f"`parse_{label}_port` MUST return a port in 1..65535 and MUST raise `ConfigError` for malformed or out-of-range input.\n"
        base = header + "class ConfigError(ValueError):\n    pass\n\n" + f"def parse_{label}_port(text):\n    try:\n        port = int(text)\n    except (TypeError, ValueError) as error:\n        raise ConfigError(\"invalid port\") from error\n    if not 1 <= port <= 65535:\n        raise ConfigError(\"port out of range\")\n    return port\n"
        candidate = header + "class ConfigError(ValueError):\n    pass\n\n" + f"def parse_{label}_port(text):\n    try:\n        port = int(text)\n    except (TypeError, ValueError):\n        return 0\n    if not 1 <= port <= 65535:\n        return 0\n    return port\n"
        tests = f"""import unittest\nfrom validator import ConfigError, parse_{label}_port\n\nclass Contract(unittest.TestCase):\n    def test_valid(self):\n        self.assertEqual(parse_{label}_port(\"443\"), 443)\n    def test_malformed_raises(self):\n        with self.assertRaises(ConfigError):\n            parse_{label}_port(\"not-a-port\")\n\nif __name__ == \"__main__\":\n    unittest.main()\n"""
        truth = truth_record("invalid", "Malformed input is converted to the sentinel 0 instead of raising ConfigError.", "none", "moderate", ["error-handling", "python"], "The malformed-input assertion observes no ConfigError.")
    elif fixture_class == "specification_violation":
        specification = f"`sort_{label}_names` MUST sort names case-insensitively while preserving their original spelling.\n"
        base = header + f"def sort_{label}_names(values):\n    return sorted(values, key=str.casefold)\n"
        candidate = header + f"def sort_{label}_names(values):\n    return sorted(values)\n"
        tests = f"""import unittest\nfrom validator import sort_{label}_names\n\nclass Contract(unittest.TestCase):\n    def test_case_insensitive_order(self):\n        self.assertEqual(sort_{label}_names([\"zulu\", \"Alpha\"]), [\"Alpha\", \"zulu\"])\n        self.assertEqual(sort_{label}_names([\"beta\", \"Zulu\", \"alpha\"]), [\"alpha\", \"beta\", \"Zulu\"])\n\nif __name__ == \"__main__\":\n    unittest.main()\n"""
        truth = truth_record("invalid", "The candidate uses code-point ordering rather than required case-insensitive ordering.", "none", "moderate", ["specification", "python"], "The mixed-case three-name ordering assertion fails.")
    elif fixture_class == "test_only_failure":
        specification = f"The candidate test suite MUST pass and `is_{label}_ready(True)` MUST return true.\n"
        base = header + f"def is_{label}_ready(value):\n    return bool(value)\n"
        candidate = base
        base_tests = f"""import unittest\nfrom validator import is_{label}_ready\n\nclass Contract(unittest.TestCase):\n    def test_ready(self):\n        self.assertTrue(is_{label}_ready(True))\n\nif __name__ == \"__main__\":\n    unittest.main()\n"""
        tests = base_tests.replace("assertTrue(is_", "assertFalse(is_")
        truth = truth_record("invalid", "Only the test changed, introducing an assertion that contradicts the specified behavior.", "none", "obvious", ["test-review", "python"], "The candidate suite fails because true readiness is asserted false.")
        return specification, base, candidate, base_tests, {"candidate_tests": tests, "truth": truth}
    elif fixture_class == "misleading_but_valid_change":
        specification = f"`clamp_{label}(value, low, high)` MUST clamp value to inclusive ordered bounds where low <= high.\n"
        base = header + f"def clamp_{label}(value, low, high):\n    return max(low, min(high, value))\n"
        candidate = header + f"def clamp_{label}(value, low, high):\n    # Sorting looks unusual but selects the median of ordered bounds and value.\n    return sorted((low, value, high))[1]\n"
        tests = f"""import unittest\nfrom validator import clamp_{label}\n\nclass Contract(unittest.TestCase):\n    def test_below_inside_above(self):\n        self.assertEqual(clamp_{label}(-2, 0, 10), 0)\n        self.assertEqual(clamp_{label}(4, 0, 10), 4)\n        self.assertEqual(clamp_{label}(12, 0, 10), 10)\n\nif __name__ == \"__main__\":\n    unittest.main()\n"""
        truth = truth_record("valid", None, "none", "subtle", ["equivalence", "python"], "Boundary and interior examples pass; median selection is equivalent for ordered bounds.")
    else:
        specification = f"`first_{label}` MUST return the first element of a non-empty sequence. Behavior for an empty sequence is not specified.\n"
        base = header + f"def first_{label}(values):\n    return values[0] if values else None\n"
        candidate = header + f"def first_{label}(values):\n    if not values:\n        raise ValueError(\"empty sequence\")\n    return values[0]\n"
        tests = f"""import unittest\nfrom validator import first_{label}\n\nclass Contract(unittest.TestCase):\n    def test_non_empty(self):\n        self.assertEqual(first_{label}([3, 4]), 3)\n\nif __name__ == \"__main__\":\n    unittest.main()\n"""
        truth = truth_record("ambiguous", None, "specification_incomplete", "expert", ["ambiguity", "specification"], "All specified non-empty behavior passes; the changed empty-input behavior is outside the written contract.")

    return specification, base, candidate, tests, {"candidate_tests": tests, "truth": truth}


def truth_record(verdict: str, defect: str | None, ambiguity: str, tier: str, tags: list[str], evidence: str) -> dict[str, object]:
    return {
        "verdict": verdict,
        "seeded_defect_description": defect,
        "reproduction_procedure": [{"argv": ["python3", "-m", "unittest", "discover", "-s", "tests", "-v"]}],
        "expected_evidence": [evidence],
        "ambiguity": ambiguity,
        "difficulty": {
            "tier": tier,
            "expected_validation_seconds": {"obvious": 30, "moderate": 90, "subtle": 180, "expert": 240}[tier],
            "skill_tags": tags,
        },
    }


def write_repository(repository: Path, fixture_id: str, base_source: str, candidate_source: str, base_tests: str, candidate_tests: str, serial: int) -> tuple[str, str]:
    repository.mkdir(parents=True)
    run(repository, "init", "--quiet", "--initial-branch=main", "--template=")
    run(repository, "config", "user.name", "Rachet Fixture Author")
    run(repository, "config", "user.email", "fixtures@rachet.invalid")
    (repository / "tests").mkdir()
    (repository / "README.md").write_text(f"# {fixture_id}\n\nControlled H-REP-001 validation repository.\n")
    (repository / "validator.py").write_text(base_source)
    (repository / "tests" / "test_validator.py").write_text(base_tests)
    run(repository, "add", "README.md", "validator.py", "tests/test_validator.py")
    base_time = datetime.datetime(2002, 1, 1, tzinfo=datetime.timezone.utc) + datetime.timedelta(days=serial * 2)
    candidate_time = base_time + datetime.timedelta(days=1)
    base_date = base_time.strftime("%Y-%m-%dT%H:%M:%SZ")
    candidate_date = candidate_time.strftime("%Y-%m-%dT%H:%M:%SZ")
    run(repository, "commit", "--quiet", "-m", "fixture base", env={"GIT_AUTHOR_DATE": base_date, "GIT_COMMITTER_DATE": base_date})
    base = run(repository, "rev-parse", "HEAD").decode().strip()
    (repository / "validator.py").write_text(candidate_source)
    (repository / "tests" / "test_validator.py").write_text(candidate_tests)
    run(repository, "add", "validator.py", "tests/test_validator.py")
    run(repository, "commit", "--quiet", "--allow-empty", "-m", "candidate change", env={"GIT_AUTHOR_DATE": candidate_date, "GIT_COMMITTER_DATE": candidate_date})
    candidate = run(repository, "rev-parse", "HEAD").decode().strip()
    shutil.rmtree(repository / ".git" / "logs", ignore_errors=True)
    return base, candidate


def rebuild() -> None:
    for root in (PUBLIC_ROOT, PRIVATE_ROOT, REPOSITORY_ROOT):
        shutil.rmtree(root, ignore_errors=True)
        root.mkdir(parents=True)

    for set_index, set_name in enumerate(SETS):
        public_set = PUBLIC_ROOT / set_name
        private_set = PRIVATE_ROOT / set_name
        public_set.mkdir()
        private_set.mkdir()
        public_entries = []
        private_entries = []

        for class_index, fixture_class in enumerate(CLASSES):
            fixture_id = f"{set_name}-{fixture_class.replace('_', '-')}"
            public_case = public_set / fixture_id
            private_case = private_set / fixture_id
            repository = REPOSITORY_ROOT / fixture_id
            public_case.mkdir()
            private_case.mkdir()

            specification, base_source, candidate_source, base_tests, details = case_files(set_name, fixture_class)
            candidate_tests = str(details["candidate_tests"])
            base, candidate = write_repository(
                repository,
                fixture_id,
                base_source,
                candidate_source,
                base_tests,
                candidate_tests,
                set_index * len(CLASSES) + class_index,
            )
            repository_digest = repository_hash(repository, base, candidate)

            spec_bytes = specification.encode()
            validation_bytes = (
                f"# Validation input for {fixture_id}\n\n"
                "Inspect the exact base-to-candidate diff and run only declared commands. "
                "No evaluator labels are included.\n"
            ).encode()
            (public_case / "specification.md").write_bytes(spec_bytes)
            (public_case / "validation.md").write_bytes(validation_bytes)

            claim_statement = "The candidate commit satisfies the supplied specification and its committed test suite passes."
            if fixture_class == "genuinely_ambiguous_claim":
                claim_statement = "The candidate preserves the intended empty-sequence behavior and satisfies the supplied specification."
            public_fixture = {
                "schema_version": 1,
                "fixture_id": fixture_id,
                "class": fixture_class,
                "repository": {
                    "path": fixture_id,
                    "base_commit": base,
                    "candidate_commit": candidate,
                    "integrity_sha256": repository_digest,
                },
                "specification": {
                    "artifact_id": "specification",
                    "path": f"{fixture_id}/specification.md",
                    "media_type": "text/markdown",
                    "sha256": sha256(spec_bytes),
                },
                "artifacts": [{
                    "artifact_id": "validation-input",
                    "path": f"{fixture_id}/validation.md",
                    "media_type": "text/markdown",
                    "sha256": sha256(validation_bytes),
                }],
                "claims": [{
                    "claim_id": "claim/candidate-satisfies-specification",
                    "statement": claim_statement,
                }],
                "permitted_commands": [
                    {"argv": ["git", "diff", "--check", base, candidate]},
                    {"argv": ["git", "diff", base, candidate, "--", "validator.py", "tests/test_validator.py"]},
                    {"argv": ["python3", "-m", "unittest", "discover", "-s", "tests", "-v"]},
                ],
                "resource_limits": RESOURCE_LIMITS,
            }
            public_bytes = json_bytes(public_fixture)
            public_path = public_case / "fixture.json"
            public_path.write_bytes(public_bytes)
            public_entries.append({"fixture_id": fixture_id, "path": f"{fixture_id}/fixture.json", "sha256": sha256(public_bytes)})

            truth = dict(details["truth"])
            truth["claim_id"] = "claim/candidate-satisfies-specification"
            private_fixture = {
                "schema_version": 1,
                "fixture_id": fixture_id,
                "public_fixture_sha256": sha256(public_bytes),
                "claims": [truth],
            }
            private_bytes = json_bytes(private_fixture)
            private_path = private_case / "truth.json"
            private_path.write_bytes(private_bytes)
            private_entries.append({"fixture_id": fixture_id, "path": f"{fixture_id}/truth.json", "sha256": sha256(private_bytes)})

        public_entries.sort(key=lambda entry: entry["fixture_id"])
        private_entries.sort(key=lambda entry: entry["fixture_id"])
        public_manifest = json_bytes({"schema_version": 1, "set": set_name, "fixtures": public_entries})
        private_manifest = json_bytes({"schema_version": 1, "set": set_name, "fixtures": private_entries})
        (public_set / "manifest.json").write_bytes(public_manifest)
        (private_set / "manifest.json").write_bytes(private_manifest)
        (public_set / "private-manifest.sha256").write_text(sha256(private_manifest) + "\n")


if __name__ == "__main__":
    rebuild()
