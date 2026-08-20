use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
    sync::atomic::{AtomicU64, Ordering},
};

use super::{
    FixtureClass, FixtureError, FixtureManifest, FixtureManifestEntry, FixtureSetKind,
    IntegrityHash, PermittedCommand, PublicArtifact, PublicClaim, PublicFixture,
    PublicFixtureLoader, RepositoryFixture, ResourceLimits,
    private::PrivateFixtureLoader,
    schema::{
        AmbiguityClassification, ClaimGroundTruth, DifficultyMetadata, DifficultyTier,
        GroundTruthVerdict, PrivateFixture,
    },
    verify_calibration_formal_disjoint,
};

static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

struct TempDirectory(PathBuf);

impl TempDirectory {
    fn new(label: &str) -> Self {
        let serial = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "rachet-lab-{label}-{}-{serial}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).unwrap();
        Self(path)
    }
}

impl Drop for TempDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

struct RepositoryHistory {
    root: TempDirectory,
    base: String,
    candidate: String,
}

struct PublicSetup {
    root: TempDirectory,
    fixture_path: PathBuf,
    fixture: PublicFixture,
    fixture_bytes: Vec<u8>,
}

#[test]
fn valid_public_and_private_fixtures_load_deterministically() {
    let repository = repository();
    let public = public_setup(
        "valid-public",
        &repository,
        "calibration-001",
        FixtureSetKind::Calibration,
    );
    let loader = PublicFixtureLoader::new(&public.root.0, &repository.root.0).unwrap();

    let first = loader.load().unwrap();
    let second = loader.load().unwrap();
    assert_eq!(first.set(), FixtureSetKind::Calibration);
    assert_eq!(first.manifest_hash(), second.manifest_hash());
    assert_eq!(first.fixtures().len(), 1);
    assert_eq!(
        first.fixtures()[0].fixture_hash(),
        second.fixtures()[0].fixture_hash()
    );
    assert_eq!(
        first.fixtures()[0].repository_path(),
        repository.root.0.as_path()
    );

    let private_root = TempDirectory::new("valid-private");
    let private_fixture = PrivateFixture {
        schema_version: 1,
        fixture_id: public.fixture.fixture_id.clone(),
        public_fixture_sha256: IntegrityHash::digest(&public.fixture_bytes),
        claims: vec![ClaimGroundTruth {
            claim_id: "claim/tests-pass".to_owned(),
            verdict: GroundTruthVerdict::Invalid,
            seeded_defect_description: Some("candidate breaks the expected output".to_owned()),
            reproduction_procedure: vec![command(&["cargo", "test"])],
            expected_evidence: vec!["the regression test fails".to_owned()],
            ambiguity: AmbiguityClassification::None,
            difficulty: DifficultyMetadata {
                tier: DifficultyTier::Moderate,
                expected_validation_seconds: 120,
                skill_tags: vec!["rust".to_owned()],
            },
        }],
    };
    let private_path = private_root.0.join("calibration-001.private.json");
    let private_bytes = serde_json::to_vec_pretty(&private_fixture).unwrap();
    fs::write(&private_path, &private_bytes).unwrap();
    let private_manifest = manifest(
        FixtureSetKind::Calibration,
        "calibration-001",
        "calibration-001.private.json",
        IntegrityHash::digest(&private_bytes),
    );
    let private_manifest_bytes = serde_json::to_vec_pretty(&private_manifest).unwrap();
    fs::write(
        private_root.0.join("manifest.json"),
        &private_manifest_bytes,
    )
    .unwrap();

    let truth = PrivateFixtureLoader::new(&private_root.0)
        .unwrap()
        .load_for(&first, IntegrityHash::digest(&private_manifest_bytes))
        .unwrap();
    assert_eq!(truth.set, FixtureSetKind::Calibration);
    assert_eq!(
        truth.manifest_hash,
        IntegrityHash::digest(&private_manifest_bytes)
    );
    assert_eq!(truth.fixtures.len(), 1);
    assert_eq!(truth.fixtures[0], private_fixture);
}

#[test]
fn malformed_and_hash_mismatched_public_fixtures_fail_closed() {
    let repository = repository();
    let setup = public_setup(
        "hash-mismatch",
        &repository,
        "calibration-001",
        FixtureSetKind::Calibration,
    );
    fs::write(&setup.fixture_path, b"{}\n").unwrap();
    let loader = PublicFixtureLoader::new(&setup.root.0, &repository.root.0).unwrap();
    assert!(matches!(
        loader.load(),
        Err(FixtureError::HashMismatch { .. })
    ));

    let malformed = public_setup(
        "malformed",
        &repository,
        "calibration-002",
        FixtureSetKind::Calibration,
    );
    let mut value = serde_json::to_value(&malformed.fixture).unwrap();
    value
        .as_object_mut()
        .unwrap()
        .insert("private_truth".to_owned(), serde_json::json!(true));
    let malformed_bytes = serde_json::to_vec_pretty(&value).unwrap();
    fs::write(&malformed.fixture_path, &malformed_bytes).unwrap();
    write_manifest(
        &malformed.root.0,
        FixtureSetKind::Calibration,
        "calibration-002",
        "calibration-002.json",
        IntegrityHash::digest(&malformed_bytes),
    );
    let loader = PublicFixtureLoader::new(&malformed.root.0, &repository.root.0).unwrap();
    assert!(matches!(loader.load(), Err(FixtureError::Json { .. })));
}

#[test]
fn repository_and_private_manifest_hash_mismatches_fail() {
    let repository = repository();
    let mut setup = public_setup(
        "repository-mismatch",
        &repository,
        "calibration-001",
        FixtureSetKind::Calibration,
    );
    setup.fixture.repository.integrity_sha256 = IntegrityHash::digest(b"wrong repository");
    let bytes = serde_json::to_vec_pretty(&setup.fixture).unwrap();
    fs::write(&setup.fixture_path, &bytes).unwrap();
    write_manifest(
        &setup.root.0,
        FixtureSetKind::Calibration,
        "calibration-001",
        "calibration-001.json",
        IntegrityHash::digest(&bytes),
    );
    let loader = PublicFixtureLoader::new(&setup.root.0, &repository.root.0).unwrap();
    assert!(matches!(
        loader.load(),
        Err(FixtureError::HashMismatch { .. })
    ));

    let valid = public_setup(
        "private-hash-public",
        &repository,
        "calibration-002",
        FixtureSetKind::Calibration,
    );
    let public_set = PublicFixtureLoader::new(&valid.root.0, &repository.root.0)
        .unwrap()
        .load()
        .unwrap();
    let private_root = TempDirectory::new("private-hash");
    fs::write(private_root.0.join("manifest.json"), b"{}\n").unwrap();
    let result = PrivateFixtureLoader::new(&private_root.0)
        .unwrap()
        .load_for(&public_set, IntegrityHash::digest(b"not the manifest"));
    assert!(matches!(result, Err(FixtureError::HashMismatch { .. })));
}

#[test]
fn hrep_corpora_cover_all_classes_and_verify_public_private_integrity() {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let repositories = workspace.join("fixtures/repositories");
    let expected_classes = [
        FixtureClass::CleanChange,
        FixtureClass::ObviousRegression,
        FixtureClass::SubtleRegression,
        FixtureClass::AuthorizationDefect,
        FixtureClass::MalformedErrorHandling,
        FixtureClass::SpecificationViolation,
        FixtureClass::TestOnlyFailure,
        FixtureClass::MisleadingButValidChange,
        FixtureClass::GenuinelyAmbiguousClaim,
    ];
    let mut calibration = None;
    let mut formal = None;
    let mut all_ids = std::collections::BTreeSet::new();

    for (set_name, set_kind) in [
        ("smoke", FixtureSetKind::Smoke),
        ("calibration", FixtureSetKind::Calibration),
        ("formal", FixtureSetKind::Formal),
    ] {
        let public_root = workspace.join("fixtures/jobs-public").join(set_name);
        let private_root = workspace
            .join("fixtures/ground-truth-private")
            .join(set_name);
        let loaded = PublicFixtureLoader::new(&public_root, &repositories)
            .unwrap()
            .load()
            .unwrap();
        assert_eq!(loaded.set(), set_kind);
        assert_eq!(loaded.fixtures().len(), expected_classes.len());
        for expected in expected_classes {
            assert_eq!(
                loaded
                    .fixtures()
                    .iter()
                    .filter(|fixture| fixture.definition().class == expected)
                    .count(),
                1,
                "{set_name} must contain class {expected:?} exactly once"
            );
        }
        for fixture in loaded.fixtures() {
            assert!(all_ids.insert(fixture.definition().fixture_id.clone()));
        }

        let expected_private_hash: IntegrityHash =
            fs::read_to_string(public_root.join("private-manifest.sha256"))
                .unwrap()
                .trim()
                .parse()
                .unwrap();
        let private = PrivateFixtureLoader::new(private_root)
            .unwrap()
            .load_for(&loaded, expected_private_hash)
            .unwrap();
        assert_eq!(private.fixtures.len(), expected_classes.len());
        for (public_fixture, private_fixture) in loaded.fixtures().iter().zip(&private.fixtures) {
            assert_eq!(
                git_output(public_fixture.repository_path(), &["rev-parse", "HEAD"]),
                public_fixture.definition().repository.candidate_commit
            );
            let output = Command::new("python3")
                .args(["-m", "unittest", "discover", "-s", "tests", "-v"])
                .current_dir(public_fixture.repository_path())
                .env("PYTHONDONTWRITEBYTECODE", "1")
                .output()
                .unwrap();
            assert_eq!(
                output.status.success(),
                private_fixture.claims[0].verdict != GroundTruthVerdict::Invalid,
                "unexpected candidate test result for {}:\n{}",
                public_fixture.definition().fixture_id,
                String::from_utf8_lossy(&output.stderr)
            );
        }
        let verdicts: Vec<_> = private
            .fixtures
            .iter()
            .map(|fixture| fixture.claims[0].verdict)
            .collect();
        assert_eq!(
            verdicts
                .iter()
                .filter(|verdict| **verdict == GroundTruthVerdict::Valid)
                .count(),
            2
        );
        assert_eq!(
            verdicts
                .iter()
                .filter(|verdict| **verdict == GroundTruthVerdict::Invalid)
                .count(),
            6
        );
        assert_eq!(
            verdicts
                .iter()
                .filter(|verdict| **verdict == GroundTruthVerdict::Ambiguous)
                .count(),
            1
        );

        match set_kind {
            FixtureSetKind::Calibration => calibration = Some(loaded),
            FixtureSetKind::Formal => formal = Some(loaded),
            FixtureSetKind::Smoke => {}
        }
    }

    verify_calibration_formal_disjoint(&calibration.unwrap(), &formal.unwrap()).unwrap();
}

#[test]
fn calibration_and_formal_sets_are_labeled_and_repository_disjoint() {
    let repository = repository();
    let calibration = public_setup(
        "disjoint-calibration",
        &repository,
        "calibration-001",
        FixtureSetKind::Calibration,
    );
    let formal = public_setup(
        "disjoint-formal",
        &repository,
        "formal-001",
        FixtureSetKind::Formal,
    );
    let calibration = PublicFixtureLoader::new(&calibration.root.0, &repository.root.0)
        .unwrap()
        .load()
        .unwrap();
    let formal = PublicFixtureLoader::new(&formal.root.0, &repository.root.0)
        .unwrap()
        .load()
        .unwrap();

    assert!(verify_calibration_formal_disjoint(&calibration, &formal).is_err());
    assert!(verify_calibration_formal_disjoint(&formal, &calibration).is_err());
}

fn repository() -> RepositoryHistory {
    let root = TempDirectory::new("repository");
    git(&root.0, &["init", "--quiet"]);
    git(&root.0, &["config", "user.name", "Fixture Author"]);
    git(
        &root.0,
        &["config", "user.email", "fixture@example.invalid"],
    );
    fs::write(root.0.join("value.txt"), b"base\n").unwrap();
    git(&root.0, &["add", "value.txt"]);
    git_commit(&root.0, "base", "2001-01-01T00:00:00Z");
    let base = git_output(&root.0, &["rev-parse", "HEAD"]);

    fs::write(root.0.join("value.txt"), b"candidate regression\n").unwrap();
    git(&root.0, &["add", "value.txt"]);
    git_commit(&root.0, "candidate", "2001-01-02T00:00:00Z");
    let candidate = git_output(&root.0, &["rev-parse", "HEAD"]);
    RepositoryHistory {
        root,
        base,
        candidate,
    }
}

fn public_setup(
    label: &str,
    repository: &RepositoryHistory,
    fixture_id: &str,
    set: FixtureSetKind,
) -> PublicSetup {
    let root = TempDirectory::new(label);
    let specification = b"The candidate must preserve the base behavior.\n";
    fs::write(root.0.join("specification.md"), specification).unwrap();
    let fixture = PublicFixture {
        schema_version: 1,
        fixture_id: fixture_id.to_owned(),
        class: FixtureClass::ObviousRegression,
        repository: RepositoryFixture {
            path: ".".to_owned(),
            base_commit: repository.base.clone(),
            candidate_commit: repository.candidate.clone(),
            integrity_sha256: super::repository_integrity_hash(
                &repository.root.0,
                &repository.base,
                &repository.candidate,
            )
            .unwrap(),
        },
        specification: PublicArtifact {
            artifact_id: "specification".to_owned(),
            path: "specification.md".to_owned(),
            media_type: "text/markdown".to_owned(),
            sha256: IntegrityHash::digest(specification),
        },
        artifacts: vec![],
        claims: vec![PublicClaim {
            claim_id: "claim/tests-pass".to_owned(),
            statement: "The candidate preserves required behavior".to_owned(),
        }],
        permitted_commands: vec![command(&["cargo", "test"])],
        resource_limits: ResourceLimits {
            wall_clock_seconds: 300,
            cpu_seconds: 300,
            model_calls: 10,
            input_tokens: 100_000,
            output_tokens: 20_000,
            tool_calls: 100,
            git_objects_read: 10_000,
            files_inspected: 1_000,
            tests_executed: 1_000,
            evidence_bytes: 1_000_000,
        },
    };
    let fixture_bytes = serde_json::to_vec_pretty(&fixture).unwrap();
    let fixture_path = root.0.join(format!("{fixture_id}.json"));
    fs::write(&fixture_path, &fixture_bytes).unwrap();
    write_manifest(
        &root.0,
        set,
        fixture_id,
        &format!("{fixture_id}.json"),
        IntegrityHash::digest(&fixture_bytes),
    );
    PublicSetup {
        root,
        fixture_path,
        fixture,
        fixture_bytes,
    }
}

fn write_manifest(
    root: &Path,
    set: FixtureSetKind,
    fixture_id: &str,
    path: &str,
    hash: IntegrityHash,
) {
    fs::write(
        root.join("manifest.json"),
        serde_json::to_vec_pretty(&manifest(set, fixture_id, path, hash)).unwrap(),
    )
    .unwrap();
}

fn manifest(
    set: FixtureSetKind,
    fixture_id: &str,
    path: &str,
    hash: IntegrityHash,
) -> FixtureManifest {
    FixtureManifest {
        schema_version: 1,
        set,
        fixtures: vec![FixtureManifestEntry {
            fixture_id: fixture_id.to_owned(),
            path: path.to_owned(),
            sha256: hash,
        }],
    }
}

fn command(argv: &[&str]) -> PermittedCommand {
    PermittedCommand {
        argv: argv.iter().map(|argument| (*argument).to_owned()).collect(),
    }
}

fn git_commit(repository: &Path, message: &str, date: &str) {
    let output = Command::new("git")
        .arg("-C")
        .arg(repository)
        .args(["commit", "--quiet", "-m", message])
        .env("GIT_AUTHOR_DATE", date)
        .env("GIT_COMMITTER_DATE", date)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "git commit failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn git(repository: &Path, args: &[&str]) {
    let output = Command::new("git")
        .arg("-C")
        .arg(repository)
        .args(args)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "git {args:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn git_output(repository: &Path, args: &[&str]) -> String {
    let output = Command::new("git")
        .arg("-C")
        .arg(repository)
        .args(args)
        .output()
        .unwrap();
    assert!(output.status.success());
    String::from_utf8(output.stdout).unwrap().trim().to_owned()
}
