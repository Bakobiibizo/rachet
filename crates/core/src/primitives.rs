//! Canonical protocol identifiers, versions, and hash domains.

use commonware_cryptography::{Hasher as _, Sha256, ed25519, sha256};

/// The SHA-256 digest used by all protocol content identifiers.
pub type Sha256Digest = sha256::Digest;

/// The Ed25519 public-key representation used by network actors.
pub type Ed25519PublicKey = ed25519::PublicKey;

/// The current protocol version.
pub const CURRENT_PROTOCOL_VERSION: ProtocolVersion = ProtocolVersion::V1;
/// The current canonical codec version.
pub const CURRENT_CODEC_VERSION: CodecVersion = CodecVersion::V1;

macro_rules! version_type {
    ($name:ident, $description:literal) => {
        #[doc = $description]
        #[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
        #[repr(transparent)]
        pub struct $name(u16);

        impl $name {
            /// Version one, used by the v1 protocol.
            pub const V1: Self = Self(1);

            /// Constructs a version from its canonical integer value.
            pub const fn new(value: u16) -> Self {
                Self(value)
            }

            /// Returns the canonical integer value.
            pub const fn get(self) -> u16 {
                self.0
            }

            /// Returns whether this implementation supports the version.
            pub const fn is_supported(self) -> bool {
                self.0 == Self::V1.0
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::V1
            }
        }

        impl From<u16> for $name {
            fn from(value: u16) -> Self {
                Self::new(value)
            }
        }

        impl From<$name> for u16 {
            fn from(value: $name) -> Self {
                value.get()
            }
        }
    };
}

version_type!(
    ProtocolVersion,
    "A version of the state-transition protocol."
);
version_type!(CodecVersion, "A version of the canonical consensus codec.");

/// A network identifier fixed by genesis.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(transparent)]
pub struct ChainId(pub [u8; 32]);

impl ChainId {
    /// Constructs a chain identifier from its canonical bytes.
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns the canonical bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl From<[u8; 32]> for ChainId {
    fn from(bytes: [u8; 32]) -> Self {
        Self::new(bytes)
    }
}

impl AsRef<[u8]> for ChainId {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// The public key identifying a customer, validator, or resolution authority.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(transparent)]
pub struct ActorId(pub Ed25519PublicKey);

impl ActorId {
    /// Returns the canonical public-key bytes.
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl From<Ed25519PublicKey> for ActorId {
    fn from(public_key: Ed25519PublicKey) -> Self {
        Self(public_key)
    }
}

impl AsRef<[u8]> for ActorId {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

/// A protocol-defined SHA-256 namespace.
///
/// Hashing is exactly `SHA-256(domain || canonical_content)`. Domains are fixed,
/// non-prefix strings and include a version component.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum HashDomain {
    Action = 0,
    Job = 1,
    Claim = 2,
    Attestation = 3,
    Evidence = 4,
    Challenge = 5,
    Commitment = 6,
    Block = 7,
    State = 8,
    MechanismSet = 9,
    Experiment = 10,
}

impl HashDomain {
    /// Returns the exact bytes prepended to canonical content.
    pub const fn as_bytes(self) -> &'static [u8] {
        match self {
            Self::Action => b"validation-network/action/v1",
            Self::Job => b"validation-network/job/v1",
            Self::Claim => b"validation-network/claim/v1",
            Self::Attestation => b"validation-network/attestation/v1",
            Self::Evidence => b"validation-network/evidence/v1",
            Self::Challenge => b"validation-network/challenge/v1",
            Self::Commitment => b"validation-network/commitment/v1",
            Self::Block => b"validation-network/block/v1",
            Self::State => b"validation-network/state/v1",
            Self::MechanismSet => b"validation-network/mechanism-set/v1",
            Self::Experiment => b"validation-network/experiment/v1",
        }
    }
}

/// Hashes canonical encoded content in a protocol-defined domain.
pub fn hash_canonical(domain: HashDomain, canonical_content: &[u8]) -> Sha256Digest {
    let mut hasher = Sha256::new();
    hasher.update(domain.as_bytes());
    hasher.update(canonical_content);
    hasher.finalize()
}

macro_rules! digest_identifier {
    ($name:ident, $domain:ident, $description:literal) => {
        #[doc = $description]
        #[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
        #[repr(transparent)]
        pub struct $name(pub Sha256Digest);

        impl $name {
            /// Derives the identifier from canonical encoded content.
            pub fn derive(canonical_content: &[u8]) -> Self {
                Self(hash_canonical(HashDomain::$domain, canonical_content))
            }

            /// Constructs an identifier from an already validated digest.
            pub const fn from_digest(digest: Sha256Digest) -> Self {
                Self(digest)
            }

            /// Returns the underlying digest.
            pub const fn digest(self) -> Sha256Digest {
                self.0
            }

            /// Returns the canonical digest bytes.
            pub fn as_bytes(&self) -> &[u8] {
                self.0.as_ref()
            }
        }

        impl From<Sha256Digest> for $name {
            fn from(digest: Sha256Digest) -> Self {
                Self::from_digest(digest)
            }
        }

        impl From<$name> for Sha256Digest {
            fn from(identifier: $name) -> Self {
                identifier.digest()
            }
        }

        impl AsRef<[u8]> for $name {
            fn as_ref(&self) -> &[u8] {
                self.as_bytes()
            }
        }
    };
}

digest_identifier!(JobId, Job, "The identity of an immutable validation job.");
digest_identifier!(ClaimId, Claim, "The identity of a canonical claim.");
digest_identifier!(
    AttestationId,
    Attestation,
    "The identity of a canonical attestation."
);
digest_identifier!(EvidenceId, Evidence, "The identity of registered evidence.");
digest_identifier!(ChallengeId, Challenge, "The identity of a challenge.");
digest_identifier!(CommitmentId, Commitment, "The identity of a commitment.");
digest_identifier!(
    ActionId,
    Action,
    "The identity of a signed protocol action."
);
digest_identifier!(
    MechanismSetId,
    MechanismSet,
    "The identity of the genesis-fixed mechanism set."
);
digest_identifier!(ExperimentId, Experiment, "The identity of an experiment.");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versions_are_explicit_and_reject_unknown_support() {
        assert_eq!(CURRENT_PROTOCOL_VERSION.get(), 1);
        assert_eq!(CURRENT_CODEC_VERSION.get(), 1);
        assert!(ProtocolVersion::V1.is_supported());
        assert!(CodecVersion::V1.is_supported());
        assert!(!ProtocolVersion::new(0).is_supported());
        assert!(!CodecVersion::new(2).is_supported());
    }

    #[test]
    fn identifier_derivation_is_deterministic_and_domain_separated() {
        let content = b"canonical bytes";
        assert_eq!(JobId::derive(content), JobId::derive(content));
        assert_ne!(
            JobId::derive(content).as_bytes(),
            ClaimId::derive(content).as_bytes()
        );
        assert_ne!(
            ClaimId::derive(content).as_bytes(),
            ActionId::derive(content).as_bytes()
        );
        assert_ne!(JobId::derive(content), JobId::derive(b"different bytes"));
    }

    #[test]
    fn domain_hash_has_a_stable_sha256_vector() {
        let expected = [
            0xb6, 0xe7, 0x28, 0x38, 0x0b, 0x3d, 0xf0, 0xc5, 0x5f, 0xea, 0x1a, 0xef, 0xf5, 0xfa,
            0x05, 0x52, 0xaa, 0x12, 0x10, 0x3b, 0x37, 0x77, 0x5b, 0x1c, 0x1d, 0x32, 0xa3, 0x6a,
            0x68, 0xee, 0xcf, 0x7b,
        ];
        assert_eq!(JobId::derive(b"canonical bytes").as_bytes(), expected);
    }

    #[test]
    fn every_required_domain_is_distinct() {
        let domains = [
            HashDomain::Action,
            HashDomain::Job,
            HashDomain::Claim,
            HashDomain::Attestation,
            HashDomain::Evidence,
            HashDomain::Challenge,
            HashDomain::Commitment,
            HashDomain::Block,
            HashDomain::State,
            HashDomain::MechanismSet,
            HashDomain::Experiment,
        ];

        for (index, domain) in domains.iter().enumerate() {
            assert!(domain.as_bytes().ends_with(b"/v1"));
            for other in domains.iter().skip(index + 1) {
                assert_ne!(domain.as_bytes(), other.as_bytes());
                assert!(!domain.as_bytes().starts_with(other.as_bytes()));
                assert!(!other.as_bytes().starts_with(domain.as_bytes()));
            }
        }
    }
}
