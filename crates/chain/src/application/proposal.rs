//! Deterministic proposal selection and execution on Commonware-supplied batches.

use super::{StatefulApplication, StatefulBlock, state::QmdbStateBatch};
use crate::application::genesis::compile_mechanism_set;
use commonware_codec::EncodeSize;
use commonware_consensus::{
    CertifiableBlock as _, Heightable as _, simplex::types::Context as SimplexContext,
};
use commonware_cryptography::{Digestible as _, ed25519, sha256::Digest};
use commonware_glue::stateful::{
    Proposed,
    db::{DatabaseSet, Shared, Unmerkleized as _},
};
use commonware_parallel::Sequential;
use commonware_runtime::Spawner;
use commonware_storage::{Context as StorageContext, merkle::Location, translator::OneCap};
use commonware_utils::{SystemTimeExt as _, non_empty_range};
use futures::{Stream, StreamExt as _};
use rachet_core::{
    actions::{Action, SignedAction},
    blocks::{
        Block as ProtocolBlock, BlockHeader, ConsensusContext as ProtocolConsensusContext,
        ConsensusNodeId, epoch_for_height,
    },
    limits::{MAX_ACTIONS_PER_BLOCK, MAX_BLOCK_BODY_BYTES, ProtocolLimits},
    mechanisms::MechanismSet,
    primitives::Sha256Digest,
    state::{StateBatch as _, StateKey},
    transition::{ExecutionOutput, TransitionContext, execute_block},
};
use rachet_mechanisms::registry::MechanismInstance;
use std::{collections::BTreeSet, sync::Arc};

use super::state::QmdbStateDatabase;

type Databases<E> = Shared<QmdbStateDatabase<E, OneCap, Sequential>>;
type Unmerkleized<E> = <Databases<E> as DatabaseSet<E>>::Unmerkleized;
pub(crate) type Merkleized<E> = <Databases<E> as DatabaseSet<E>>::Merkleized;

const CATALOG_NAMESPACE: [u8; 3] = [0x30, 0xff, 0xff];
const CATALOG_HEAD_KEY: &[u8] = b"\x30\xff\xffrachet-chain/state-catalog/head/v1";
const CATALOG_NODE_PREFIX: &[u8] = b"\x30\xff\xffrachet-chain/state-catalog/node/v1/";
const CATALOG_HEAD_MAGIC: &[u8; 4] = b"RCI1";

/// Read-only proposal input supplied by the node's pending-action component.
///
/// The later bounded-pool work item implements this boundary directly. Keeping
/// selection here means every provider is subject to the same canonical block
/// limits and ordering before authoritative execution.
pub trait ProposalActionSource: Send {
    /// Returns one owned snapshot of the provider's current candidates.
    fn candidates(&self) -> Vec<SignedAction<Action>>;
}

impl ProposalActionSource for Vec<SignedAction<Action>> {
    fn candidates(&self) -> Vec<SignedAction<Action>> {
        self.clone()
    }
}

/// Sorts candidates by section 20.3's canonical key and returns the largest
/// ordered prefix within the configured action-count and body-byte limits.
pub fn select_proposal_actions(
    mut candidates: Vec<SignedAction<Action>>,
    limits: ProtocolLimits,
) -> Vec<SignedAction<Action>> {
    candidates.sort_unstable_by(|left, right| {
        (&left.actor, left.nonce, left.action_id()).cmp(&(
            &right.actor,
            right.nonce,
            right.action_id(),
        ))
    });

    let config = limits.config();
    let maximum_actions = usize::min(config.actions_per_block as usize, MAX_ACTIONS_PER_BLOCK);
    let maximum_bytes = usize::min(config.block_body_bytes as usize, MAX_BLOCK_BODY_BYTES);
    let mut selected = Vec::with_capacity(usize::min(candidates.len(), maximum_actions));
    let count_prefix_bytes = 0_usize.encode_size();
    let mut body_bytes = count_prefix_bytes;

    for candidate in candidates.into_iter().take(maximum_actions) {
        let Some(next_size) = body_bytes.checked_add(candidate.encode_size()) else {
            break;
        };
        if next_size > maximum_bytes {
            break;
        }
        body_bytes = next_size;
        selected.push(candidate);
    }
    selected
}

pub(crate) async fn propose<E>(
    application: &StatefulApplication,
    (runtime, consensus): (E, SimplexContext<Digest, ed25519::PublicKey>),
    ancestry: impl Stream<Item = Arc<StatefulBlock>> + Send,
    batches: Unmerkleized<E>,
    input: &mut Box<dyn ProposalActionSource>,
) -> Option<Proposed<StatefulApplication, E>>
where
    E: StorageContext + Spawner + rand_core::Rng + Send + Sync + 'static,
{
    let mut ancestry = Box::pin(ancestry);
    let parent = ancestry.next().await?;
    if consensus.parent.1 != parent.digest() || consensus.parent.0 != parent.context().round.view()
    {
        return None;
    }

    let genesis = application.genesis_state();
    let protocol = genesis.protocol().protocol();
    let parent_protocol = parent.protocol();
    if parent_protocol.header.protocol_version != protocol.version()
        || parent_protocol.header.chain_id != genesis.chain_id()
        || parent_protocol.header.mechanism_set_id != genesis.protocol().mechanism_set_id()
    {
        return None;
    }

    let height = parent.height().get().checked_add(1)?;
    let epoch = epoch_for_height(height, protocol.blocks_per_epoch()).ok()?;
    let actions = select_proposal_actions(input.candidates(), genesis.limits());
    let transition = TransitionContext {
        chain_id: genesis.chain_id(),
        protocol_version: protocol.version(),
        height,
        epoch,
        mechanism_set_id: genesis.protocol().mechanism_set_id(),
    };
    let mechanisms = compile_mechanism_set(genesis.protocol().mechanism_set()).ok()?;
    let (execution, merkleized) = execute_candidate(
        batches,
        parent_protocol.header.post_state_root,
        &transition,
        &actions,
        mechanisms,
    )
    .await?;
    let bounds = merkleized.bounds();
    let qmdb_range = non_empty_range!(merkleized.sync_boundary(), Location::new(bounds.total_size));
    let parent_digest = parent.digest();
    let context = ProtocolConsensusContext {
        consensus_epoch: consensus.round.epoch().get(),
        view: consensus.round.view().get(),
        leader: ConsensusNodeId::from(consensus.leader.clone()),
        parent_view: consensus.parent.0.get(),
        parent_block: parent_digest,
    };
    let timestamp_ms = u64::try_from(runtime.current().epoch().as_millis()).ok()?;
    let header = BlockHeader {
        protocol_version: protocol.version(),
        chain_id: genesis.chain_id(),
        height,
        epoch,
        parent_block: parent_digest,
        parent_state_root: parent_protocol.header.post_state_root,
        action_root: execution.action_root,
        receipt_root: execution.receipt_root,
        post_state_root: execution.post_state_root,
        mechanism_set_id: genesis.protocol().mechanism_set_id(),
        timestamp_ms,
    };
    let protocol = ProtocolBlock::new(context, header, actions).ok()?;
    let block = StatefulBlock::from_parts(
        protocol,
        merkleized.root(),
        merkleized.ops_root(),
        qmdb_range,
    );
    Some(Proposed { block, merkleized })
}

/// Re-executes one candidate and writes its deterministic delta to the supplied fork batch.
///
/// Proposal, verification, and later replay use this boundary so logical execution and the
/// adapter's authenticated state catalog cannot diverge between paths.
pub(crate) async fn execute_candidate<E>(
    batches: Unmerkleized<E>,
    expected_parent_root: Sha256Digest,
    transition: &TransitionContext,
    actions: &[SignedAction<Action>],
    mechanisms: MechanismSet<MechanismInstance>,
) -> Option<(ExecutionOutput, Merkleized<E>)>
where
    E: StorageContext + Spawner + rand_core::Rng + Send + Sync + 'static,
{
    let (mut state, indexed_keys, catalog_count) = materialize_state(&batches).await?;
    if state.root() != expected_parent_root {
        return None;
    }

    let execution = execute_block(&mut state, transition, actions, &mechanisms).ok()?;
    let commit = state.finish().ok()?;
    if commit.logical_root() != execution.post_state_root {
        return None;
    }

    let mut batches = batches;
    for (key, value) in commit.updates() {
        batches = batches.write(key.clone(), value.clone());
    }
    let mut next_catalog_index = catalog_count;
    for key in commit.entries().iter().map(|(key, _)| key.as_bytes()) {
        if is_catalog_key(key) {
            return None;
        }
        if !indexed_keys.contains(key) {
            batches = batches.write(catalog_node_key(next_catalog_index), Some(key.to_vec()));
            next_catalog_index = next_catalog_index.checked_add(1)?;
        }
    }
    if next_catalog_index != catalog_count || catalog_count == 0 {
        batches = batches.write(
            CATALOG_HEAD_KEY.to_vec(),
            Some(encode_catalog_head(next_catalog_index)),
        );
    }

    Some((execution, batches.merkleize().await.ok()?))
}

async fn materialize_state<E>(
    batches: &Unmerkleized<E>,
) -> Option<(QmdbStateBatch, BTreeSet<Vec<u8>>, u64)>
where
    E: StorageContext + Spawner + rand_core::Rng + Send + Sync + 'static,
{
    let head = batches.get(&CATALOG_HEAD_KEY.to_vec()).await.ok()?;
    let (load_keys, indexed_keys, count) = if let Some(head) = head {
        let count = decode_catalog_head(&head)?;
        let mut keys = BTreeSet::new();
        for index in 0..count {
            let encoded = batches.get(&catalog_node_key(index)).await.ok()??;
            let key = StateKey::from_canonical_bytes(&encoded).ok()?;
            if is_catalog_key(key.as_bytes()) || !keys.insert(encoded) {
                return None;
            }
        }
        (keys.clone(), keys, count)
    } else {
        // The exact genesis snapshot predates the adapter catalog so its
        // conformance-locked bytes and root remain unchanged. The empty
        // indexed set causes the first child to catalog both genesis keys.
        (
            [
                StateKey::protocol_config().as_bytes().to_vec(),
                StateKey::protocol_epoch().as_bytes().to_vec(),
            ]
            .into_iter()
            .collect(),
            BTreeSet::new(),
            0,
        )
    };

    let mut entries = Vec::new();
    for encoded in &load_keys {
        if let Some(value) = batches.get(encoded).await.ok()? {
            let key = StateKey::from_canonical_bytes(encoded).ok()?;
            entries.push((key, value.into_boxed_slice()));
        }
    }
    Some((
        QmdbStateBatch::from_entries(entries).ok()?,
        indexed_keys,
        count,
    ))
}

fn is_catalog_key(key: &[u8]) -> bool {
    key.starts_with(&CATALOG_NAMESPACE)
}

fn catalog_node_key(index: u64) -> Vec<u8> {
    let mut key = Vec::with_capacity(CATALOG_NODE_PREFIX.len() + 8);
    key.extend_from_slice(CATALOG_NODE_PREFIX);
    key.extend_from_slice(&index.to_be_bytes());
    key
}

fn encode_catalog_head(count: u64) -> Vec<u8> {
    let mut encoded = Vec::with_capacity(CATALOG_HEAD_MAGIC.len() + 8);
    encoded.extend_from_slice(CATALOG_HEAD_MAGIC);
    encoded.extend_from_slice(&count.to_be_bytes());
    encoded
}

fn decode_catalog_head(encoded: &[u8]) -> Option<u64> {
    if encoded.len() != CATALOG_HEAD_MAGIC.len() + 8
        || &encoded[..CATALOG_HEAD_MAGIC.len()] != CATALOG_HEAD_MAGIC
    {
        return None;
    }
    Some(u64::from_be_bytes(
        encoded[CATALOG_HEAD_MAGIC.len()..].try_into().ok()?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_cryptography::{Signer as _, ed25519};
    use rachet_core::{
        actions::CloseJob,
        primitives::{ChainId, JobId, ProtocolVersion},
    };

    fn signed(seed: u64, nonce: u64) -> SignedAction<Action> {
        SignedAction::sign(
            &ed25519::PrivateKey::from_seed(seed),
            ProtocolVersion::V1,
            ChainId::new([7; 32]),
            nonce,
            100,
            Action::CloseJob(CloseJob::new(JobId::derive(&seed.to_be_bytes()))),
        )
        .unwrap()
    }

    #[test]
    fn selection_is_canonical_and_a_bounded_prefix() {
        let low_actor = signed(1, 0);
        let high_actor_first = signed(2, 0);
        let high_actor_second = signed(2, 1);
        let mut expected = [
            high_actor_second.clone(),
            low_actor.clone(),
            high_actor_first.clone(),
        ];
        expected.sort_unstable_by(|left, right| {
            (&left.actor, left.nonce, left.action_id()).cmp(&(
                &right.actor,
                right.nonce,
                right.action_id(),
            ))
        });

        let mut config = rachet_core::limits::ProtocolLimitsConfig::V1;
        config.actions_per_block = 2;
        let selected = select_proposal_actions(
            vec![high_actor_second, low_actor, high_actor_first],
            ProtocolLimits::new(config).unwrap(),
        );
        assert_eq!(selected, expected[..2]);
    }

    #[test]
    fn catalog_head_codec_is_exact() {
        assert_eq!(decode_catalog_head(&encode_catalog_head(42)), Some(42));
        assert_eq!(decode_catalog_head(b"RCI1"), None);
        assert_eq!(decode_catalog_head(b"BAD!\0\0\0\0\0\0\0\0"), None);
        assert!(catalog_node_key(1) < catalog_node_key(2));
        assert!(is_catalog_key(CATALOG_HEAD_KEY));
    }

    #[test]
    fn action_source_returns_an_owned_snapshot() {
        let source = vec![signed(5, 0)];
        let mut snapshot = source.candidates();
        snapshot.clear();
        assert!(snapshot.is_empty());
        assert_eq!(source.len(), 1);
    }
}
