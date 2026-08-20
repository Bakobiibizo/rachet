//! Pure state transitions.

mod action;
mod block;
mod commitments;
mod epochs;
mod evidence;
mod jobs;
mod resolutions;

pub(crate) use action::apply_verified_action;
pub use action::{ActionExecutionError, execute_action};
pub use block::{BlockExecutionError, ExecutionOutput, TransitionContext, execute_block};
pub use commitments::{
    CommitmentTransitionError, create_commitment, expire_commitments, load_commitment,
    reveal_commitment,
};
pub use epochs::{HeightEventError, execute_height_events};
pub use evidence::{
    EvidenceAttestationError, load_attestation, load_evidence, register_evidence,
    submit_attestation,
};
pub use jobs::{
    ActorRoles, CreatedJob, JobTransitionError, actor_roles, close_job, create_job,
    ensure_customer_role, ensure_resolution_authority_role, ensure_validation_operator_role,
    load_claim, load_job,
};
pub use resolutions::{
    ChallengeResolutionError, ChallengeResolutionOutcome, ClaimResolutionOutcome, create_challenge,
    load_challenge, resolve_challenge, resolve_claim,
};
