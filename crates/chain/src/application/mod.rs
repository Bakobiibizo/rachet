//! Consensus application and authenticated-state boundary.

mod genesis;
mod proposal;
mod replay;
pub mod state;
mod verification;

pub(crate) use genesis::compile_mechanism_set;
pub use genesis::{
    GenesisError, GenesisMetadata, GenesisState, MAX_RESOLUTION_AUTHORITIES, StatefulApplication,
    StatefulBlock, is_empty_genesis_namespace,
};
pub use proposal::{ProposalActionSource, select_proposal_actions};
