//! Canonical validation block types and deterministic commitments.
//!
//! Application epochs are derived only from block height. `timestamp_ms` is
//! committed block metadata, but none of the validation or root APIs use it to
//! derive transition context, deadlines, or economic behavior.

use crate::{
    actions::{Action, SignedAction},
    bounded::{BoundedVec, LengthExceeded},
    events::ActionReceipt,
    limits::{MAX_ACTIONS_PER_BLOCK, MAX_BLOCK_BODY_BYTES, ProtocolLimits},
    primitives::{
        ChainId, Ed25519PublicKey, HashDomain, MechanismSetId, ProtocolVersion, Sha256Digest,
        hash_canonical,
    },
    state::StateBatch,
};
use commonware_codec::{EncodeSize, FixedSize, Write};
use commonware_cryptography::{Hasher as _, Sha256};
use core::fmt;

const ACTION_ROOT_DOMAIN: &[u8] = b"validation-network/block/action-root/v1";
const RECEIPT_ROOT_DOMAIN: &[u8] = b"validation-network/block/receipt-root/v1";

/// The consensus-node key that led a proposal.
///
/// This is deliberately distinct from [`crate::primitives::ActorId`]: consensus
/// authority and validation-operator identity are separate protocol roles.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(transparent)]
pub struct ConsensusNodeId(Ed25519PublicKey);

impl ConsensusNodeId {
    /// Returns the consensus public key without converting it to an actor ID.
    pub const fn public_key(&self) -> &Ed25519PublicKey {
        &self.0
    }

    /// Returns the canonical public-key bytes.
    pub fn as_bytes(&self) -> &[u8] {
        self.public_key().as_ref()
    }
}

impl From<Ed25519PublicKey> for ConsensusNodeId {
    fn from(public_key: Ed25519PublicKey) -> Self {
        Self(public_key)
    }
}

impl AsRef<[u8]> for ConsensusNodeId {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

/// Consensus metadata bound to a block proposal.
///
/// These fixed-width fields mirror the information supplied by Simplex while
/// keeping the protocol core independent of Commonware consensus code. The
/// chain adapter is responsible for an exact conversion at its boundary.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ConsensusContext {
    /// Consensus epoch (not the application/economic epoch in the header).
    pub consensus_epoch: u64,
    /// Current consensus view.
    pub view: u64,
    /// Consensus node selected as leader for this view.
    pub leader: ConsensusNodeId,
    /// View in which the parent payload was proposed.
    pub parent_view: u64,
    /// Parent payload digest supplied by consensus.
    pub parent_block: Sha256Digest,
}

/// The fixed, canonically encoded commitments for one application block.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct BlockHeader {
    pub protocol_version: ProtocolVersion,
    pub chain_id: ChainId,
    pub height: u64,
    pub epoch: u64,
    pub parent_block: Sha256Digest,
    pub parent_state_root: Sha256Digest,
    pub action_root: Sha256Digest,
    pub receipt_root: Sha256Digest,
    pub post_state_root: Sha256Digest,
    pub mechanism_set_id: MechanismSetId,
    /// Informational wall-clock metadata. Canonical transitions must not read it.
    pub timestamp_ms: u64,
}

/// A consensus proposal and its bounded canonical action body.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Block {
    pub context: ConsensusContext,
    pub header: BlockHeader,
    pub actions: BoundedVec<SignedAction<Action>, MAX_ACTIONS_PER_BLOCK>,
}

impl Block {
    /// Maximum canonical bytes for a block, including fixed consensus/header fields.
    ///
    /// The body portion includes its action-count prefix. Network adapters must add
    /// only their own fixed wrapper overhead when setting channel message limits.
    pub const MAX_ENCODED_BYTES: usize =
        ConsensusContext::SIZE + BlockHeader::SIZE + MAX_BLOCK_BODY_BYTES;

    /// Constructs a block while enforcing the implementation action and body maxima.
    pub fn new(
        context: ConsensusContext,
        header: BlockHeader,
        actions: Vec<SignedAction<Action>>,
    ) -> Result<Self, BlockValidationError> {
        let actions = BoundedVec::new(actions).map_err(BlockValidationError::ActionCount)?;
        Self::from_bounded_actions(context, header, actions)
    }

    /// Constructs a block from an already count-bounded action body.
    pub fn from_bounded_actions(
        context: ConsensusContext,
        header: BlockHeader,
        actions: BoundedVec<SignedAction<Action>, MAX_ACTIONS_PER_BLOCK>,
    ) -> Result<Self, BlockValidationError> {
        let block = Self {
            context,
            header,
            actions,
        };
        block.validate_body_limit(MAX_BLOCK_BODY_BYTES)?;
        Ok(block)
    }

    /// Returns the exact canonical encoded body length, including its count prefix.
    pub fn body_len(&self) -> usize {
        self.actions.encode_size()
    }

    /// Returns the domain-separated digest of the complete canonical block.
    pub fn digest(&self) -> Sha256Digest {
        let mut encoded = Vec::with_capacity(self.encode_size());
        self.write(&mut encoded);
        hash_canonical(HashDomain::Block, &encoded)
    }

    /// Validates all pre-execution header, ancestry, genesis, and body commitments.
    ///
    /// `timestamp_ms` is intentionally absent from [`BlockValidationContext`] and
    /// is not inspected here. A chain adapter may enforce metadata clock policy,
    /// but canonical execution cannot observe that policy or timestamp value.
    pub fn validate_structure(
        &self,
        expected: &BlockValidationContext,
    ) -> Result<(), BlockValidationError> {
        if !self.header.protocol_version.is_supported() {
            return Err(BlockValidationError::UnsupportedProtocolVersion {
                received: self.header.protocol_version.get(),
            });
        }
        if self.header.protocol_version != expected.protocol_version {
            return Err(BlockValidationError::ProtocolVersionMismatch {
                expected: expected.protocol_version.get(),
                received: self.header.protocol_version.get(),
            });
        }
        if self.header.chain_id != expected.chain_id {
            return Err(BlockValidationError::ChainIdMismatch);
        }
        if self.header.height != expected.height {
            return Err(BlockValidationError::HeightMismatch {
                expected: expected.height,
                received: self.header.height,
            });
        }
        let derived_epoch = epoch_for_height(self.header.height, expected.blocks_per_epoch)?;
        if self.header.epoch != derived_epoch {
            return Err(BlockValidationError::EpochMismatch {
                expected: derived_epoch,
                received: self.header.epoch,
            });
        }
        if self.header.parent_block != expected.parent_block {
            return Err(BlockValidationError::ParentBlockMismatch);
        }
        if self.context.parent_block != self.header.parent_block {
            return Err(BlockValidationError::ConsensusParentMismatch);
        }
        if self.context != expected.consensus_context {
            return Err(BlockValidationError::ConsensusContextMismatch);
        }
        if self.header.parent_state_root != expected.parent_state_root {
            return Err(BlockValidationError::ParentStateRootMismatch);
        }
        if self.header.mechanism_set_id != expected.mechanism_set_id {
            return Err(BlockValidationError::MechanismSetMismatch);
        }

        let limits = expected.limits.config();
        let maximum_actions = limits.actions_per_block as usize;
        if self.actions.len() > maximum_actions {
            return Err(BlockValidationError::ConfiguredActionCountExceeded {
                maximum: maximum_actions,
                actual: self.actions.len(),
            });
        }
        self.validate_body_limit(limits.block_body_bytes as usize)?;

        let computed = action_root(self.actions.as_slice());
        if self.header.action_root != computed {
            return Err(BlockValidationError::ActionRootMismatch);
        }
        Ok(())
    }

    /// Validates commitments available after deterministic execution.
    pub fn validate_execution(
        &self,
        receipts: &[ActionReceipt],
        post_state_root: Sha256Digest,
    ) -> Result<(), BlockValidationError> {
        if receipts.len() != self.actions.len() {
            return Err(BlockValidationError::ReceiptCountMismatch {
                expected: self.actions.len(),
                received: receipts.len(),
            });
        }
        if self.header.receipt_root != receipt_root(receipts) {
            return Err(BlockValidationError::ReceiptRootMismatch);
        }
        if self.header.post_state_root != post_state_root {
            return Err(BlockValidationError::PostStateRootMismatch);
        }
        Ok(())
    }

    fn validate_body_limit(&self, maximum: usize) -> Result<(), BlockValidationError> {
        let actual = self.body_len();
        if actual > maximum {
            return Err(BlockValidationError::BlockBodyTooLarge { maximum, actual });
        }
        Ok(())
    }
}

/// Genesis- and ancestry-derived values against which a candidate is checked.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlockValidationContext {
    pub consensus_context: ConsensusContext,
    pub protocol_version: ProtocolVersion,
    pub chain_id: ChainId,
    pub height: u64,
    pub parent_block: Sha256Digest,
    pub parent_state_root: Sha256Digest,
    pub mechanism_set_id: MechanismSetId,
    pub blocks_per_epoch: u64,
    pub limits: ProtocolLimits,
}

/// Derives the application/economic epoch from height and genesis configuration.
pub const fn epoch_for_height(
    height: u64,
    blocks_per_epoch: u64,
) -> Result<u64, BlockValidationError> {
    if blocks_per_epoch == 0 {
        return Err(BlockValidationError::ZeroBlocksPerEpoch);
    }
    Ok(height / blocks_per_epoch)
}

/// Commits, in order, to complete canonical signed actions.
pub fn action_root(actions: &[SignedAction<Action>]) -> Sha256Digest {
    sequence_root(ACTION_ROOT_DOMAIN, actions)
}

/// Commits, in action order, to deterministic canonical receipts.
pub fn receipt_root(receipts: &[ActionReceipt]) -> Sha256Digest {
    sequence_root(RECEIPT_ROOT_DOMAIN, receipts)
}

/// Returns the deterministic root supplied by the canonical state batch.
pub fn state_root(state: &dyn StateBatch) -> Sha256Digest {
    state.root()
}

fn sequence_root<T: Write + EncodeSize>(domain: &[u8], values: &[T]) -> Sha256Digest {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(&u64_length(values.len()));
    for value in values {
        let mut encoded = Vec::with_capacity(value.encode_size());
        value.write(&mut encoded);
        hasher.update(&u64_length(encoded.len()));
        hasher.update(&encoded);
    }
    hasher.finalize()
}

fn u64_length(length: usize) -> [u8; 8] {
    u64::try_from(length)
        .expect("canonical lengths fit u64 on supported Linux targets")
        .to_be_bytes()
}

/// Stable failures produced by block construction and commitment validation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BlockValidationError {
    ActionCount(LengthExceeded),
    UnsupportedProtocolVersion { received: u16 },
    ProtocolVersionMismatch { expected: u16, received: u16 },
    ChainIdMismatch,
    HeightMismatch { expected: u64, received: u64 },
    ZeroBlocksPerEpoch,
    EpochMismatch { expected: u64, received: u64 },
    ParentBlockMismatch,
    ConsensusParentMismatch,
    ConsensusContextMismatch,
    ParentStateRootMismatch,
    MechanismSetMismatch,
    ConfiguredActionCountExceeded { maximum: usize, actual: usize },
    BlockBodyTooLarge { maximum: usize, actual: usize },
    ActionRootMismatch,
    ReceiptCountMismatch { expected: usize, received: usize },
    ReceiptRootMismatch,
    PostStateRootMismatch,
}

impl BlockValidationError {
    /// Returns the stable machine-readable protocol error code.
    pub const fn code(self) -> &'static str {
        match self {
            Self::ActionCount(_) | Self::ConfiguredActionCountExceeded { .. } => {
                "BLOCK_ACTION_COUNT_INVALID"
            }
            Self::UnsupportedProtocolVersion { .. } => "BLOCK_VERSION_UNSUPPORTED",
            Self::ProtocolVersionMismatch { .. } => "BLOCK_VERSION_INVALID",
            Self::ChainIdMismatch => "BLOCK_CHAIN_ID_INVALID",
            Self::HeightMismatch { .. } => "BLOCK_HEIGHT_INVALID",
            Self::ZeroBlocksPerEpoch => "BLOCK_EPOCH_CONFIG_INVALID",
            Self::EpochMismatch { .. } => "BLOCK_EPOCH_INVALID",
            Self::ParentBlockMismatch => "BLOCK_PARENT_INVALID",
            Self::ConsensusParentMismatch => "BLOCK_CONSENSUS_PARENT_INVALID",
            Self::ConsensusContextMismatch => "BLOCK_CONSENSUS_CONTEXT_INVALID",
            Self::ParentStateRootMismatch => "BLOCK_PARENT_STATE_ROOT_INVALID",
            Self::MechanismSetMismatch => "BLOCK_MECHANISM_SET_INVALID",
            Self::BlockBodyTooLarge { .. } => "BLOCK_BODY_TOO_LARGE",
            Self::ActionRootMismatch => "BLOCK_ACTION_ROOT_INVALID",
            Self::ReceiptCountMismatch { .. } => "BLOCK_RECEIPT_COUNT_INVALID",
            Self::ReceiptRootMismatch => "BLOCK_RECEIPT_ROOT_INVALID",
            Self::PostStateRootMismatch => "BLOCK_STATE_ROOT_INVALID",
        }
    }
}

impl fmt::Display for BlockValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::error::Error for BlockValidationError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        actions::{CloseJob, Ed25519Signature, SIGNED_ACTION_FIXED_BYTES},
        bounded::BoundedBytes,
        limits::{MAX_COMMITMENT_PAYLOAD_BYTES, MAX_COMMITMENT_SALT_BYTES, ProtocolLimitsConfig},
        primitives::{ActionId, ActorId},
        state::{InMemoryStateBatch, StateKey},
    };
    use bytes::Buf as _;
    use commonware_codec::{Decode, Encode, Error as CodecError, Read as _};
    use commonware_cryptography::{Sha256, Signer as _, ed25519};

    struct Fixture {
        block: Block,
        expected: BlockValidationContext,
        receipts: Vec<ActionReceipt>,
        post_state_root: Sha256Digest,
    }

    fn digest(byte: u8) -> Sha256Digest {
        Sha256Digest::from([byte; 32])
    }

    fn fixture() -> Fixture {
        let private_key = ed25519::PrivateKey::from_seed(23);
        let leader = ConsensusNodeId::from(ed25519::PrivateKey::from_seed(24).public_key());
        let chain_id = ChainId::new([0x11; 32]);
        let parent_block = digest(0x22);
        let parent_state_root = digest(0x33);
        let mechanism_set_id = MechanismSetId::from_digest(digest(0x44));
        let context = ConsensusContext {
            consensus_epoch: 2,
            view: 17,
            leader,
            parent_view: 16,
            parent_block,
        };
        let action = SignedAction::sign(
            &private_key,
            ProtocolVersion::V1,
            chain_id,
            0,
            999,
            Action::CloseJob(CloseJob::new(crate::primitives::JobId::derive(
                b"vector-job",
            ))),
        )
        .unwrap();
        let receipt = ActionReceipt::new(
            action.action_id(),
            action.actor.clone(),
            action.nonce,
            vec![crate::events::CanonicalEvent::JobClosed {
                job_id: crate::primitives::JobId::derive(b"vector-job"),
            }],
        )
        .unwrap();
        let mut state = InMemoryStateBatch::new();
        state.put(StateKey::protocol_config(), b"v1".as_slice().into());
        state.put(
            StateKey::protocol_epoch(),
            2_u64.to_be_bytes().as_slice().into(),
        );
        let post_state_root = state_root(&state);
        let actions = vec![action];
        let receipts = vec![receipt];
        let header = BlockHeader {
            protocol_version: ProtocolVersion::V1,
            chain_id,
            height: 200,
            epoch: 2,
            parent_block,
            parent_state_root,
            action_root: action_root(&actions),
            receipt_root: receipt_root(&receipts),
            post_state_root,
            mechanism_set_id,
            timestamp_ms: 1_725_000_000_123,
        };
        let block = Block::new(context.clone(), header, actions).unwrap();
        let expected = BlockValidationContext {
            consensus_context: context,
            protocol_version: ProtocolVersion::V1,
            chain_id,
            height: 200,
            parent_block,
            parent_state_root,
            mechanism_set_id,
            blocks_per_epoch: 100,
            limits: ProtocolLimits::V1,
        };
        Fixture {
            block,
            expected,
            receipts,
            post_state_root,
        }
    }

    #[test]
    fn height_derived_epochs_have_exact_boundaries_and_reject_zero_length() {
        assert_eq!(epoch_for_height(0, 100), Ok(0));
        assert_eq!(epoch_for_height(99, 100), Ok(0));
        assert_eq!(epoch_for_height(100, 100), Ok(1));
        assert_eq!(epoch_for_height(u64::MAX, 1), Ok(u64::MAX));
        assert_eq!(
            epoch_for_height(7, 0),
            Err(BlockValidationError::ZeroBlocksPerEpoch)
        );
    }

    #[test]
    fn block_codec_round_trips_and_rejects_truncation_trailing_and_oversized_counts() {
        let block = fixture().block;
        let encoded = block.encode();
        assert_eq!(Block::decode_cfg(encoded.clone(), &()).unwrap(), block);
        for length in 0..encoded.len() {
            assert!(
                Block::decode_cfg(encoded.slice(..length), &()).is_err(),
                "block accepted truncation at byte {length}"
            );
        }
        let mut trailing = encoded.to_vec();
        trailing.push(0xff);
        assert!(matches!(
            Block::decode_cfg(trailing.as_slice(), &()),
            Err(CodecError::ExtraData(1))
        ));

        let mut oversized_count = Vec::new();
        block.context.write(&mut oversized_count);
        block.header.write(&mut oversized_count);
        (MAX_ACTIONS_PER_BLOCK + 1).write(&mut oversized_count);
        assert!(matches!(
            Block::decode_cfg(oversized_count.as_slice(), &()),
            Err(CodecError::InvalidLength(length)) if length == MAX_ACTIONS_PER_BLOCK + 1
        ));

        let mut invalid_enum = encoded.to_vec();
        let action_tag_offset = block.context.encode_size()
            + block.header.encode_size()
            + 1_usize.encode_size()
            + SIGNED_ACTION_FIXED_BYTES
            - Ed25519Signature::SIZE;
        invalid_enum[action_tag_offset] = 0xff;
        assert!(matches!(
            Block::decode_cfg(invalid_enum.as_slice(), &()),
            Err(CodecError::InvalidEnum(0xff))
        ));
    }

    #[test]
    fn structure_validation_rejects_every_context_and_header_mismatch() {
        let Fixture {
            block,
            expected,
            receipts,
            post_state_root,
        } = fixture();
        block.validate_structure(&expected).unwrap();
        block
            .validate_execution(&receipts, post_state_root)
            .unwrap();

        let mut malformed = block.clone();
        malformed.header.protocol_version = ProtocolVersion::new(2);
        assert_eq!(
            malformed.validate_structure(&expected),
            Err(BlockValidationError::UnsupportedProtocolVersion { received: 2 })
        );

        let mut expected_version = expected.clone();
        expected_version.protocol_version = ProtocolVersion::new(2);
        assert_eq!(
            block.validate_structure(&expected_version),
            Err(BlockValidationError::ProtocolVersionMismatch {
                expected: 2,
                received: 1
            })
        );

        let mut malformed = block.clone();
        malformed.header.chain_id = ChainId::new([0xff; 32]);
        assert_eq!(
            malformed.validate_structure(&expected),
            Err(BlockValidationError::ChainIdMismatch)
        );

        let mut malformed = block.clone();
        malformed.header.height += 1;
        assert!(matches!(
            malformed.validate_structure(&expected),
            Err(BlockValidationError::HeightMismatch { .. })
        ));

        let mut malformed = block.clone();
        malformed.header.epoch += 1;
        assert!(matches!(
            malformed.validate_structure(&expected),
            Err(BlockValidationError::EpochMismatch { .. })
        ));

        let mut malformed = block.clone();
        malformed.header.parent_block = digest(0xa1);
        assert_eq!(
            malformed.validate_structure(&expected),
            Err(BlockValidationError::ParentBlockMismatch)
        );

        let mut malformed = block.clone();
        malformed.context.parent_block = digest(0xa2);
        assert_eq!(
            malformed.validate_structure(&expected),
            Err(BlockValidationError::ConsensusParentMismatch)
        );

        let mut malformed = block.clone();
        malformed.context.view += 1;
        assert_eq!(
            malformed.validate_structure(&expected),
            Err(BlockValidationError::ConsensusContextMismatch)
        );

        let mut malformed = block.clone();
        malformed.header.parent_state_root = digest(0xa3);
        assert_eq!(
            malformed.validate_structure(&expected),
            Err(BlockValidationError::ParentStateRootMismatch)
        );

        let mut malformed = block.clone();
        malformed.header.mechanism_set_id = MechanismSetId::from_digest(digest(0xa4));
        assert_eq!(
            malformed.validate_structure(&expected),
            Err(BlockValidationError::MechanismSetMismatch)
        );

        let mut malformed = block.clone();
        malformed.header.action_root = digest(0xa5);
        assert_eq!(
            malformed.validate_structure(&expected),
            Err(BlockValidationError::ActionRootMismatch)
        );
    }

    #[test]
    fn execution_validation_rejects_receipt_count_receipt_root_and_state_root() {
        let Fixture {
            mut block,
            receipts,
            post_state_root,
            ..
        } = fixture();
        assert!(matches!(
            block.validate_execution(&[], post_state_root),
            Err(BlockValidationError::ReceiptCountMismatch {
                expected: 1,
                received: 0
            })
        ));
        block.header.receipt_root = digest(0xb1);
        assert_eq!(
            block.validate_execution(&receipts, post_state_root),
            Err(BlockValidationError::ReceiptRootMismatch)
        );
        block.header.receipt_root = receipt_root(&receipts);
        assert_eq!(
            block.validate_execution(&receipts, digest(0xb2)),
            Err(BlockValidationError::PostStateRootMismatch)
        );
    }

    #[test]
    fn genesis_configured_action_and_body_limits_are_enforced() {
        let mut fixture = fixture();
        let second = fixture.block.actions.as_slice()[0].clone();
        fixture.block.actions.try_push(second).unwrap();
        fixture.block.header.action_root = action_root(fixture.block.actions.as_slice());
        let mut config = ProtocolLimitsConfig::V1;
        config.actions_per_block = 1;
        fixture.expected.limits = ProtocolLimits::new(config).unwrap();
        assert_eq!(
            fixture.block.validate_structure(&fixture.expected),
            Err(BlockValidationError::ConfiguredActionCountExceeded {
                maximum: 1,
                actual: 2
            })
        );

        let private_key = ed25519::PrivateKey::from_seed(25);
        let payload =
            BoundedBytes::<MAX_COMMITMENT_PAYLOAD_BYTES>::new(vec![0x55; 65_000]).unwrap();
        let salt = BoundedBytes::<MAX_COMMITMENT_SALT_BYTES>::default();
        let large = SignedAction::sign(
            &private_key,
            ProtocolVersion::V1,
            fixture.block.header.chain_id,
            0,
            999,
            Action::RevealCommitment(crate::actions::RevealCommitment {
                commitment_id: crate::primitives::CommitmentId::derive(b"large"),
                payload,
                salt,
            }),
        )
        .unwrap();
        let large_actions = vec![large; 65];
        assert!(matches!(
            Block::new(
                fixture.block.context.clone(),
                fixture.block.header.clone(),
                large_actions.clone()
            ),
            Err(BlockValidationError::BlockBodyTooLarge {
                maximum: MAX_BLOCK_BODY_BYTES,
                ..
            })
        ));

        let unchecked = Block {
            context: fixture.block.context,
            header: fixture.block.header,
            actions: BoundedVec::new(large_actions).unwrap(),
        };
        let actual = unchecked.body_len();
        assert!(actual > MAX_BLOCK_BODY_BYTES);

        let mut oversized = unchecked.encode();
        let initial = oversized.remaining();
        assert!(matches!(
            Block::read_cfg(&mut oversized, &()),
            Err(CodecError::EndOfBuffer)
        ));
        assert!(
            initial - oversized.remaining()
                <= ConsensusContext::SIZE + BlockHeader::SIZE + MAX_BLOCK_BODY_BYTES,
            "oversized bodies must stop reading at or before the allocation budget"
        );
        assert!(
            oversized.has_remaining(),
            "oversized payload bytes must remain unread after bounded rejection"
        );
        assert_eq!(
            Block::MAX_ENCODED_BYTES,
            ConsensusContext::SIZE + BlockHeader::SIZE + MAX_BLOCK_BODY_BYTES
        );
    }

    #[test]
    fn timestamp_is_committed_metadata_but_cannot_change_economic_commitments() {
        let Fixture {
            block,
            expected,
            receipts,
            post_state_root,
        } = fixture();
        let mut later = block.clone();
        later.header.timestamp_ms = u64::MAX;

        later.validate_structure(&expected).unwrap();
        later
            .validate_execution(&receipts, post_state_root)
            .unwrap();
        assert_eq!(later.header.epoch, block.header.epoch);
        assert_eq!(later.header.action_root, block.header.action_root);
        assert_eq!(later.header.receipt_root, block.header.receipt_root);
        assert_eq!(later.header.post_state_root, block.header.post_state_root);
        assert_ne!(later.digest(), block.digest());
    }

    #[test]
    fn block_and_root_conformance_vectors_are_stable() {
        let Fixture {
            block,
            receipts,
            post_state_root,
            ..
        } = fixture();
        let encoded = block.encode();
        assert_eq!(encoded.len(), 518);

        let expected = [
            [
                0x16, 0x72, 0x18, 0xab, 0xe9, 0x92, 0xd8, 0x2c, 0xf4, 0xe4, 0xd2, 0x92, 0x73, 0x6b,
                0x55, 0x78, 0x1c, 0x53, 0x3e, 0x9e, 0xcc, 0x95, 0x38, 0x6b, 0x4e, 0xaf, 0xc5, 0xc3,
                0xfb, 0x22, 0x63, 0x2f,
            ],
            [
                0xe9, 0xe2, 0xab, 0xd7, 0x95, 0x4f, 0x75, 0x3e, 0x71, 0x56, 0x97, 0x74, 0x8b, 0x54,
                0xd7, 0xee, 0xaf, 0x16, 0xa8, 0x03, 0x4a, 0xc1, 0xd6, 0x97, 0x42, 0xb6, 0xdd, 0x1e,
                0x2a, 0x16, 0x03, 0xc1,
            ],
            [
                0xb6, 0x78, 0x2e, 0xcc, 0xdd, 0xad, 0x6d, 0x44, 0x77, 0xb9, 0x47, 0x5d, 0x83, 0xef,
                0x25, 0xd8, 0x5b, 0x4d, 0x91, 0x56, 0x84, 0xe6, 0xed, 0x53, 0xac, 0xe7, 0xdd, 0x18,
                0x2d, 0x8d, 0x3d, 0xdc,
            ],
            [
                0xd1, 0x92, 0xb6, 0x37, 0xef, 0x5b, 0x36, 0x80, 0xf3, 0x64, 0xf2, 0x7f, 0x13, 0x78,
                0xc5, 0x2a, 0xdb, 0x27, 0xdc, 0x57, 0xd3, 0x51, 0x6e, 0xba, 0xa0, 0x1d, 0xa6, 0xf6,
                0xf3, 0x74, 0x47, 0x81,
            ],
            [
                0xcf, 0x7a, 0xac, 0x03, 0x6f, 0x4a, 0x92, 0xca, 0x8a, 0x18, 0xaf, 0xe6, 0x69, 0x6e,
                0xb1, 0xfa, 0x74, 0xcb, 0xd2, 0xe7, 0x1b, 0xd1, 0xda, 0x62, 0xb7, 0x2f, 0xb6, 0x53,
                0x08, 0xea, 0xd8, 0x8f,
            ],
        ];
        let actual = [
            action_root(block.actions.as_slice()),
            receipt_root(&receipts),
            post_state_root,
            block.digest(),
            Sha256::hash(&encoded),
        ];
        for (digest, expected) in actual.iter().zip(expected) {
            assert_eq!(digest.as_ref(), expected);
        }

        // The signature itself is part of the action commitment and must remain
        // fixed under deterministic Ed25519 signing.
        let signature: &Ed25519Signature = &block.actions.as_slice()[0].signature;
        assert_eq!(signature.as_ref().len(), 64);
        assert_eq!(
            block.actions.as_slice()[0].action_id(),
            ActionId::derive(&block.actions.as_slice()[0].encode())
        );
        assert_eq!(
            receipts[0].actor,
            ActorId::from(ed25519::PrivateKey::from_seed(23).public_key())
        );
    }
}
