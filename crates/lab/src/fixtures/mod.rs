//! Strict, integrity-bound experiment fixture loading.
//!
//! Public loading is a separate filesystem capability from evaluator-private
//! truth loading. Only the public capability and public schemas are exported.
//!
//! Evaluator truth cannot be named through the operator-facing module:
//! ```compile_fail
//! use rachet_lab::fixtures::private::PrivateFixtureLoader;
//! ```

mod error;
mod hash;
pub(crate) mod private;
mod public;
mod repository;
pub(crate) mod schema;

pub use error::FixtureError;
pub use hash::IntegrityHash;
pub use public::{
    LoadedPublicFixture, LoadedPublicFixtureSet, PublicFixtureLoader,
    verify_calibration_formal_disjoint,
};
pub use repository::repository_integrity_hash;
pub use schema::{
    FIXTURE_SCHEMA_VERSION, FixtureClass, FixtureManifest, FixtureManifestEntry, FixtureSetKind,
    PermittedCommand, PublicArtifact, PublicClaim, PublicFixture, RepositoryFixture,
    ResourceLimits,
};

#[cfg(test)]
mod tests;
