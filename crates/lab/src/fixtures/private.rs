use std::{collections::BTreeSet, path::PathBuf};

use super::{
    FIXTURE_SCHEMA_VERSION, FixtureError, FixtureManifest, FixtureManifestEntry, FixtureSetKind,
    IntegrityHash, LoadedPublicFixtureSet,
    public::{
        canonical_directory, invalid, parse_json, read_bounded, resolve_file, validate_command,
        validate_identifier, validate_manifest, validate_text, verify_hash,
    },
    schema::{AmbiguityClassification, GroundTruthVerdict, PrivateFixture},
};

const MANIFEST_FILE: &str = "manifest.json";

/// Evaluator-only capability. It is crate-private so operator consumers cannot
/// construct it, enumerate private fixture IDs, or read truth through lab APIs.
pub struct PrivateFixtureLoader {
    private_root: PathBuf,
}

pub struct LoadedPrivateFixtureSet {
    pub set: FixtureSetKind,
    pub manifest_hash: IntegrityHash,
    pub fixtures: Vec<PrivateFixture>,
}

impl PrivateFixtureLoader {
    pub fn new(private_root: impl AsRef<std::path::Path>) -> Result<Self, FixtureError> {
        Ok(Self {
            private_root: canonical_directory(private_root.as_ref(), "private fixture root")?,
        })
    }

    pub fn load_for(
        &self,
        public: &LoadedPublicFixtureSet,
        expected_manifest_hash: IntegrityHash,
    ) -> Result<LoadedPrivateFixtureSet, FixtureError> {
        let manifest_path = self.private_root.join(MANIFEST_FILE);
        let manifest_bytes = read_bounded(&manifest_path)?;
        verify_hash(
            "private fixture manifest".to_owned(),
            expected_manifest_hash,
            &manifest_bytes,
        )?;
        let manifest: FixtureManifest = parse_json(&manifest_path, &manifest_bytes)?;
        validate_manifest(&manifest, "private fixture manifest")?;
        if manifest.set != public.set() {
            return Err(invalid(
                "private fixture manifest",
                "partition does not match public manifest",
            ));
        }
        if manifest.fixtures.len() != public.fixtures().len() {
            return Err(invalid(
                "private fixture manifest",
                "fixture count does not match public manifest",
            ));
        }

        let mut fixtures = Vec::with_capacity(manifest.fixtures.len());
        for (entry, public_fixture) in manifest.fixtures.iter().zip(public.fixtures()) {
            if entry.fixture_id != public_fixture.definition().fixture_id {
                return Err(invalid(
                    "private fixture manifest",
                    "fixture IDs do not exactly match the ordered public manifest",
                ));
            }
            fixtures.push(self.load_fixture(entry, public_fixture)?);
        }

        Ok(LoadedPrivateFixtureSet {
            set: manifest.set,
            manifest_hash: expected_manifest_hash,
            fixtures,
        })
    }

    fn load_fixture(
        &self,
        entry: &FixtureManifestEntry,
        public: &super::LoadedPublicFixture,
    ) -> Result<PrivateFixture, FixtureError> {
        let path = resolve_file(&self.private_root, &entry.path, "private fixture")?;
        let bytes = read_bounded(&path)?;
        verify_hash(
            format!("private fixture {}", entry.fixture_id),
            entry.sha256,
            &bytes,
        )?;
        let fixture: PrivateFixture = parse_json(&path, &bytes)?;
        validate_private_fixture(&fixture, entry, public)?;
        Ok(fixture)
    }
}

fn validate_private_fixture(
    fixture: &PrivateFixture,
    entry: &FixtureManifestEntry,
    public: &super::LoadedPublicFixture,
) -> Result<(), FixtureError> {
    if fixture.schema_version != FIXTURE_SCHEMA_VERSION {
        return Err(invalid(
            format!("private fixture {}", entry.fixture_id),
            format!("unsupported schema version {}", fixture.schema_version),
        ));
    }
    if fixture.fixture_id != entry.fixture_id {
        return Err(invalid(
            format!("private fixture {}", entry.fixture_id),
            "declared fixture ID does not match manifest",
        ));
    }
    if fixture.public_fixture_sha256 != public.fixture_hash() {
        return Err(FixtureError::HashMismatch {
            subject: format!("public binding for private fixture {}", fixture.fixture_id),
            expected: public.fixture_hash(),
            actual: fixture.public_fixture_sha256,
        });
    }
    if fixture.claims.len() != public.definition().claims.len() {
        return Err(invalid(
            format!("private fixture {} claims", fixture.fixture_id),
            "claim count does not match public fixture",
        ));
    }

    let public_claims: BTreeSet<&str> = public
        .definition()
        .claims
        .iter()
        .map(|claim| claim.claim_id.as_str())
        .collect();
    let mut truth_claims = BTreeSet::new();
    for truth in &fixture.claims {
        validate_identifier("private claim ID", &truth.claim_id)?;
        if !truth_claims.insert(truth.claim_id.as_str()) {
            return Err(invalid(
                "private claims",
                format!("duplicate claim ID {}", truth.claim_id),
            ));
        }
        if !public_claims.contains(truth.claim_id.as_str()) {
            return Err(invalid(
                "private claims",
                format!("unknown public claim ID {}", truth.claim_id),
            ));
        }
        if truth.reproduction_procedure.is_empty() {
            return Err(invalid(
                format!("ground truth for {}", truth.claim_id),
                "reproduction procedure must not be empty",
            ));
        }
        for command in &truth.reproduction_procedure {
            validate_command(command)?;
        }
        if truth.expected_evidence.is_empty() {
            return Err(invalid(
                format!("ground truth for {}", truth.claim_id),
                "expected evidence must not be empty",
            ));
        }
        for evidence in &truth.expected_evidence {
            validate_text("expected evidence", evidence)?;
        }
        if let Some(description) = &truth.seeded_defect_description {
            validate_text("seeded defect description", description)?;
        }
        if truth.verdict == GroundTruthVerdict::Invalid && truth.seeded_defect_description.is_none()
        {
            return Err(invalid(
                format!("ground truth for {}", truth.claim_id),
                "invalid verdict requires a seeded defect description",
            ));
        }
        match (truth.verdict, truth.ambiguity) {
            (GroundTruthVerdict::Ambiguous, AmbiguityClassification::None) => {
                return Err(invalid(
                    format!("ground truth for {}", truth.claim_id),
                    "ambiguous verdict requires an ambiguity classification",
                ));
            }
            (GroundTruthVerdict::Valid | GroundTruthVerdict::Invalid, ambiguity)
                if ambiguity != AmbiguityClassification::None =>
            {
                return Err(invalid(
                    format!("ground truth for {}", truth.claim_id),
                    "non-ambiguous verdict must use ambiguity classification none",
                ));
            }
            _ => {}
        }
        if truth.difficulty.expected_validation_seconds == 0 {
            return Err(invalid(
                format!("difficulty for {}", truth.claim_id),
                "expected validation duration must be nonzero",
            ));
        }
        let mut tags = BTreeSet::new();
        for tag in &truth.difficulty.skill_tags {
            validate_identifier("difficulty skill tag", tag)?;
            if !tags.insert(tag.as_str()) {
                return Err(invalid(
                    format!("difficulty for {}", truth.claim_id),
                    format!("duplicate skill tag {tag}"),
                ));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod visibility_tests {
    use super::{LoadedPrivateFixtureSet, PrivateFixtureLoader};

    #[test]
    fn private_loader_types_remain_evaluator_internal() {
        // This unit test can name crate-private types. External operator crates
        // cannot; compile-time visibility is the security boundary of this API.
        fn accepts_loader(_: Option<PrivateFixtureLoader>) {}
        fn accepts_set(_: Option<LoadedPrivateFixtureSet>) {}
        accepts_loader(None);
        accepts_set(None);
    }
}
