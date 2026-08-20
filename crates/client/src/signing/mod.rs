//! Canonical, replay-resistant network action signing.

use crate::identity::ActorIdentity;
use commonware_codec::{Encode as _, EncodeSize, Write};
use rachet_core::{
    actions::{ActionValidationError, SignedAction},
    primitives::{CURRENT_PROTOCOL_VERSION, ChainId, ProtocolVersion},
};
use std::fmt;

/// All caller-supplied fields needed to sign one canonical action.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActionSigningRequest<P> {
    /// Genesis-fixed destination chain.
    pub chain_id: ChainId,
    /// State-transition protocol version.
    pub protocol_version: ProtocolVersion,
    /// Exact next actor nonce.
    pub nonce: u64,
    /// Inclusive last valid block height.
    pub valid_until_height: u64,
    /// Canonical action payload.
    pub payload: P,
}

impl<P> ActionSigningRequest<P> {
    /// Builds a request for the currently supported protocol version.
    pub const fn current(
        chain_id: ChainId,
        nonce: u64,
        valid_until_height: u64,
        payload: P,
    ) -> Self {
        Self {
            chain_id,
            protocol_version: CURRENT_PROTOCOL_VERSION,
            nonce,
            valid_until_height,
            payload,
        }
    }
}

/// Signs an action with an actor identity, binding every replay-sensitive field.
pub fn sign_action<P: Write + EncodeSize>(
    identity: &ActorIdentity,
    request: ActionSigningRequest<P>,
) -> Result<SignedAction<P>, SigningError> {
    if !request.protocol_version.is_supported() {
        return Err(SigningError::UnsupportedProtocolVersion {
            received: request.protocol_version.get(),
        });
    }
    SignedAction::sign(
        identity.private_key(),
        request.protocol_version,
        request.chain_id,
        request.nonce,
        request.valid_until_height,
        request.payload,
    )
    .map_err(SigningError::Action)
}

/// Returns the canonical bytes accepted by action ingress.
pub fn canonical_action<P: Write + EncodeSize>(action: &SignedAction<P>) -> Vec<u8> {
    action.encode().to_vec()
}

/// Stable client-side signing failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SigningError {
    /// This client does not sign unsupported protocol versions.
    UnsupportedProtocolVersion { received: u16 },
    /// Core rejected the canonical action envelope.
    Action(ActionValidationError),
}

impl SigningError {
    /// Returns a stable machine-readable error code.
    pub const fn code(self) -> &'static str {
        match self {
            Self::UnsupportedProtocolVersion { .. } => "ACTION_VERSION_UNSUPPORTED",
            Self::Action(error) => error.code(),
        }
    }
}

impl fmt::Display for SigningError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedProtocolVersion { received } => {
                write!(formatter, "unsupported protocol version {received}")
            }
            Self::Action(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for SigningError {}

#[cfg(test)]
mod tests {
    use super::*;
    use rachet_core::{
        actions::{Action, ActionVerificationContext, CloseJob},
        primitives::JobId,
    };

    fn payload() -> Action {
        Action::CloseJob(CloseJob {
            job_id: JobId::derive(b"client signing fixture"),
        })
    }

    #[test]
    fn signed_canonical_actions_verify_in_core_with_bound_nonce_chain_and_version() {
        let identity = ActorIdentity::generate().unwrap();
        let chain_id = ChainId::new([0x59; 32]);
        let signed = sign_action(
            &identity,
            ActionSigningRequest::current(chain_id, 7, 42, payload()),
        )
        .unwrap();

        let expected_id = signed
            .verify(&ActionVerificationContext::current(chain_id, 41), 7)
            .unwrap();
        assert_eq!(expected_id, signed.action_id());
        assert_eq!(canonical_action(&signed).len(), signed.canonical_len());

        let mut wrong_nonce = signed.clone();
        wrong_nonce.nonce = 8;
        assert_eq!(
            wrong_nonce
                .verify(&ActionVerificationContext::current(chain_id, 41), 8)
                .unwrap_err()
                .code(),
            "ACTION_SIGNATURE_INVALID"
        );
        assert_eq!(
            signed
                .verify(
                    &ActionVerificationContext::current(ChainId::new([0x5a; 32]), 41),
                    7,
                )
                .unwrap_err()
                .code(),
            "ACTION_CHAIN_ID_INVALID"
        );
    }

    #[test]
    fn unsupported_versions_are_not_signed() {
        let identity = ActorIdentity::generate().unwrap();
        let error = sign_action(
            &identity,
            ActionSigningRequest {
                chain_id: ChainId::new([1; 32]),
                protocol_version: ProtocolVersion::new(2),
                nonce: 0,
                valid_until_height: 1,
                payload: payload(),
            },
        )
        .unwrap_err();
        assert_eq!(error.code(), "ACTION_VERSION_UNSUPPORTED");
    }
}
