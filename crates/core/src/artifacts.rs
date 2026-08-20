//! Immutable, content-addressed Git artifact references.

use crate::{
    bounded::BoundedBytes,
    limits::{MAX_CONTENT_LOCATOR_HINT_BYTES, MAX_MEDIA_TYPE_BYTES, MAX_REPOSITORY_LOCATOR_BYTES},
    primitives::{JobId, Sha256Digest},
};
use commonware_codec::Write as _;
use core::fmt;

/// A bounded informational locator used by operators to fetch a repository.
pub type RepositoryLocator = BoundedBytes<MAX_REPOSITORY_LOCATOR_BYTES>;
/// A bounded informational locator used to fetch digest-addressed content.
pub type ContentLocatorHint = BoundedBytes<MAX_CONTENT_LOCATOR_HINT_BYTES>;
/// A bounded media-type label for digest-addressed content.
pub type MediaType = BoundedBytes<MAX_MEDIA_TYPE_BYTES>;

/// An immutable Git object identifier.
///
/// Both Git's SHA-1 object format and its SHA-256 object format are represented
/// explicitly. The variant is part of artifact identity, so an algorithm is
/// never inferred after construction.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum GitHash {
    /// A Git object identifier from a SHA-1 object-format repository.
    Sha1([u8; 20]) = 0,
    /// A Git object identifier from a SHA-256 object-format repository.
    Sha256([u8; 32]) = 1,
}

impl GitHash {
    /// Constructs a SHA-1 Git object identifier.
    pub const fn sha1(bytes: [u8; 20]) -> Self {
        Self::Sha1(bytes)
    }

    /// Constructs a SHA-256 Git object identifier.
    pub const fn sha256(bytes: [u8; 32]) -> Self {
        Self::Sha256(bytes)
    }

    /// Returns the raw object identifier bytes.
    pub const fn as_bytes(&self) -> &[u8] {
        match self {
            Self::Sha1(bytes) => bytes,
            Self::Sha256(bytes) => bytes,
        }
    }

    /// Returns whether this is a SHA-1 Git object identifier.
    pub const fn is_sha1(&self) -> bool {
        matches!(self, Self::Sha1(_))
    }

    /// Returns whether this is a SHA-256 Git object identifier.
    pub const fn is_sha256(&self) -> bool {
        matches!(self, Self::Sha256(_))
    }

    fn append_identity_bytes(&self, output: &mut Vec<u8>) {
        self.write(output);
    }
}

impl AsRef<[u8]> for GitHash {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl TryFrom<&[u8]> for GitHash {
    type Error = InvalidGitHashLength;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        match bytes.len() {
            20 => Ok(Self::Sha1(
                bytes.try_into().expect("length was checked as SHA-1"),
            )),
            32 => Ok(Self::Sha256(
                bytes.try_into().expect("length was checked as SHA-256"),
            )),
            actual => Err(InvalidGitHashLength { actual }),
        }
    }
}

impl TryFrom<Vec<u8>> for GitHash {
    type Error = InvalidGitHashLength;

    fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
        Self::try_from(bytes.as_slice())
    }
}

/// Raw bytes did not have the length of a supported Git object identifier.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InvalidGitHashLength {
    actual: usize,
}

impl InvalidGitHashLength {
    /// Returns the rejected byte length.
    pub const fn actual(self) -> usize {
        self.actual
    }
}

impl fmt::Display for InvalidGitHashLength {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "Git object identifier length {} is neither SHA-1 (20) nor SHA-256 (32)",
            self.actual
        )
    }
}

impl std::error::Error for InvalidGitHashLength {}

/// A digest-addressed reference to off-chain content.
///
/// The content body is deliberately absent. `locator_hint` and `media_type`
/// help operators retrieve and interpret content but do not authenticate it;
/// consumers must verify `digest`.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ContentRef {
    /// SHA-256 digest authenticating the off-chain content body.
    pub digest: Sha256Digest,
    /// Informational, bounded retrieval hint.
    pub locator_hint: ContentLocatorHint,
    /// Informational, bounded media-type label.
    pub media_type: MediaType,
}

impl ContentRef {
    /// Constructs a reference to off-chain content.
    pub const fn new(
        digest: Sha256Digest,
        locator_hint: ContentLocatorHint,
        media_type: MediaType,
    ) -> Self {
        Self {
            digest,
            locator_hint,
            media_type,
        }
    }

    /// Consumes the reference and returns its digest and informational metadata.
    pub fn into_parts(self) -> (Sha256Digest, ContentLocatorHint, MediaType) {
        (self.digest, self.locator_hint, self.media_type)
    }
}

/// Immutable references identifying a proposed Git software change.
///
/// `repository` is an operator-facing locator, not repository content. The
/// referenced specification body is likewise kept off chain.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct GitArtifact {
    /// Informational repository locator used by operators.
    pub repository: RepositoryLocator,
    /// Commit from which validation starts.
    pub base_commit: GitHash,
    /// Candidate commit being validated.
    pub candidate_commit: GitHash,
    /// Digest-addressed, off-chain validation specification.
    pub specification: ContentRef,
}

impl GitArtifact {
    /// Constructs an immutable Git software-change reference.
    pub const fn new(
        repository: RepositoryLocator,
        base_commit: GitHash,
        candidate_commit: GitHash,
        specification: ContentRef,
    ) -> Self {
        Self {
            repository,
            base_commit,
            candidate_commit,
            specification,
        }
    }

    /// Derives the job identity of this immutable software change.
    ///
    /// The canonical identity projection is the repository locator, tagged base
    /// and candidate Git hashes, and specification digest, in that order. The
    /// specification's locator and media type are informational and excluded.
    pub fn job_id(&self) -> JobId {
        let mut identity = Vec::with_capacity(
            MAX_REPOSITORY_LOCATOR_BYTES + 2 + 32 + 32 + self.specification.digest.as_ref().len(),
        );
        self.repository.write(&mut identity);
        self.base_commit.append_identity_bytes(&mut identity);
        self.candidate_commit.append_identity_bytes(&mut identity);
        identity.extend_from_slice(self.specification.digest.as_ref());
        JobId::derive(&identity)
    }
}

/// The immutable artifact portion of a job plus an optional predecessor link.
///
/// Supersession is linkage metadata: it does not rewrite the predecessor and is
/// not part of the software-change identity.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct JobArtifact {
    /// Immutable Git references for this job revision.
    pub artifact: GitArtifact,
    /// Earlier job replaced by this revision, if any.
    pub supersedes: Option<JobId>,
}

impl JobArtifact {
    /// Constructs a job artifact with optional predecessor linkage.
    pub const fn new(artifact: GitArtifact, supersedes: Option<JobId>) -> Self {
        Self {
            artifact,
            supersedes,
        }
    }

    /// Returns the immutable software-change identity.
    pub fn job_id(&self) -> JobId {
        self.artifact.job_id()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn bounded<const MAX: usize>(bytes: &[u8]) -> BoundedBytes<MAX> {
        BoundedBytes::try_from(bytes).expect("test value is bounded")
    }

    fn content_ref(digest_byte: u8, locator: &[u8], media_type: &[u8]) -> ContentRef {
        ContentRef::new(
            Sha256Digest::from([digest_byte; 32]),
            bounded(locator),
            bounded(media_type),
        )
    }

    fn artifact() -> GitArtifact {
        GitArtifact::new(
            bounded(b"https://example.invalid/repository.git"),
            GitHash::sha1([0x11; 20]),
            GitHash::sha256([0x22; 32]),
            content_ref(0x33, b"ipfs://specification", b"application/toml"),
        )
    }

    #[test]
    fn sha1_and_sha256_git_hashes_round_trip_without_algorithm_loss() {
        for hash in [GitHash::sha1([0x51; 20]), GitHash::sha256([0x52; 32])] {
            let restored = GitHash::try_from(hash.as_bytes()).unwrap();
            assert_eq!(restored, hash);
            assert_eq!(restored.is_sha1(), hash.is_sha1());
            assert_eq!(restored.is_sha256(), hash.is_sha256());
        }

        let error = GitHash::try_from([0_u8; 21].as_slice()).unwrap_err();
        assert_eq!(error.actual(), 21);
    }

    #[test]
    fn content_references_round_trip_as_digest_and_bounded_metadata() {
        let reference = content_ref(0x71, b"https://content.invalid/spec", b"text/markdown");
        let expected = reference.clone();
        let (digest, locator_hint, media_type) = reference.into_parts();
        assert_eq!(ContentRef::new(digest, locator_hint, media_type), expected);
    }

    #[test]
    fn candidate_commit_and_specification_digest_change_job_identity() {
        let baseline = artifact();

        let mut changed_candidate = baseline.clone();
        changed_candidate.candidate_commit = GitHash::sha256([0x23; 32]);
        assert_ne!(changed_candidate.job_id(), baseline.job_id());

        let mut changed_specification = baseline.clone();
        changed_specification.specification.digest = Sha256Digest::from([0x34; 32]);
        assert_ne!(changed_specification.job_id(), baseline.job_id());
    }

    #[test]
    fn informational_content_hints_and_supersedes_do_not_change_artifact_identity() {
        let baseline = artifact();

        let mut changed_hints = baseline.clone();
        changed_hints.specification.locator_hint = bounded(b"https://mirror.invalid/spec");
        changed_hints.specification.media_type = bounded(b"application/octet-stream");
        assert_eq!(changed_hints.job_id(), baseline.job_id());

        let predecessor = JobId::derive(b"predecessor");
        assert_eq!(
            JobArtifact::new(baseline.clone(), None).job_id(),
            JobArtifact::new(baseline, Some(predecessor)).job_id()
        );
    }

    #[test]
    fn repository_and_evidence_bodies_cannot_enter_through_unbounded_fields() {
        let error = RepositoryLocator::new(vec![0; MAX_REPOSITORY_LOCATOR_BYTES + 1])
            .expect_err("a repository locator cannot contain a repository body");
        assert_eq!(error.maximum(), MAX_REPOSITORY_LOCATOR_BYTES);
        assert_eq!(error.actual(), MAX_REPOSITORY_LOCATOR_BYTES + 1);
        assert!(ContentLocatorHint::new(vec![0; MAX_CONTENT_LOCATOR_HINT_BYTES + 1]).is_err());
        assert!(MediaType::new(vec![0; MAX_MEDIA_TYPE_BYTES + 1]).is_err());

        let reference = content_ref(0x81, b"cas://evidence", b"application/json");
        assert_eq!(reference.digest, Sha256Digest::from([0x81; 32]));
        assert_eq!(reference.locator_hint.as_slice(), b"cas://evidence");
    }
}
