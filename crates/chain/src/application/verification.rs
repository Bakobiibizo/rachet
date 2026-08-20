//! Stateful proposal verification against a Commonware-supplied parent batch.

use super::{
    StatefulApplication, StatefulBlock,
    genesis::compile_mechanism_set,
    proposal::{Merkleized, execute_candidate},
    state::QmdbStateDatabase,
};
use commonware_consensus::{CertifiableBlock as _, simplex::types::Context as SimplexContext};
use commonware_cryptography::{Digestible as _, ed25519, sha256::Digest};
use commonware_glue::stateful::db::{DatabaseSet, Merkleized as _, Shared};
use commonware_parallel::Sequential;
use commonware_runtime::Spawner;
use commonware_storage::{Context as StorageContext, merkle::Location, translator::OneCap};
use commonware_utils::non_empty_range;
use futures::{Stream, StreamExt as _};
use rachet_core::{
    blocks::{
        BlockValidationContext, ConsensusContext as ProtocolConsensusContext, ConsensusNodeId,
    },
    transition::TransitionContext,
};
use std::sync::Arc;

type Databases<E> = Shared<QmdbStateDatabase<E, OneCap, Sequential>>;
type Unmerkleized<E> = <Databases<E> as DatabaseSet<E>>::Unmerkleized;

pub(crate) async fn verify<E>(
    application: &StatefulApplication,
    consensus: SimplexContext<Digest, ed25519::PublicKey>,
    ancestry: impl Stream<Item = Arc<StatefulBlock>> + Send,
    batches: Unmerkleized<E>,
) -> Option<Merkleized<E>>
where
    E: StorageContext + Spawner + rand_core::Rng + Send + Sync + 'static,
{
    // Stateful supplies the candidate first and its parent second. Reject a
    // truncated ancestry stream before touching the speculative batch.
    let mut ancestry = Box::pin(ancestry);
    let block = ancestry.next().await?;
    let parent = ancestry.next().await?;

    let parent_digest = parent.digest();
    if consensus.parent.1 != parent_digest || consensus.parent.0 != parent.context().round.view() {
        return None;
    }

    let genesis = application.genesis_state();
    let configured_protocol = genesis.protocol().protocol();
    let parent_protocol = parent.protocol();
    if parent_protocol.header.protocol_version != configured_protocol.version()
        || parent_protocol.header.chain_id != genesis.chain_id()
        || parent_protocol.header.mechanism_set_id != genesis.protocol().mechanism_set_id()
    {
        return None;
    }

    let height = parent_protocol.header.height.checked_add(1)?;
    let protocol_context = ProtocolConsensusContext {
        consensus_epoch: consensus.round.epoch().get(),
        view: consensus.round.view().get(),
        leader: ConsensusNodeId::from(consensus.leader.clone()),
        parent_view: consensus.parent.0.get(),
        parent_block: consensus.parent.1,
    };
    let validation = BlockValidationContext {
        consensus_context: protocol_context,
        protocol_version: configured_protocol.version(),
        chain_id: genesis.chain_id(),
        height,
        parent_block: parent_digest,
        parent_state_root: parent_protocol.header.post_state_root,
        mechanism_set_id: genesis.protocol().mechanism_set_id(),
        blocks_per_epoch: configured_protocol.blocks_per_epoch(),
        limits: genesis.limits(),
    };
    block.protocol().validate_structure(&validation).ok()?;

    let transition = TransitionContext {
        chain_id: genesis.chain_id(),
        protocol_version: configured_protocol.version(),
        height,
        epoch: block.protocol().header.epoch,
        mechanism_set_id: genesis.protocol().mechanism_set_id(),
    };
    let mechanisms = compile_mechanism_set(genesis.protocol().mechanism_set()).ok()?;
    let (execution, merkleized) = execute_candidate(
        batches,
        parent_protocol.header.post_state_root,
        &transition,
        block.protocol().actions.as_slice(),
        mechanisms,
    )
    .await?;
    block
        .protocol()
        .validate_execution(&execution.receipts, execution.post_state_root)
        .ok()?;

    let bounds = merkleized.bounds();
    let range = non_empty_range!(merkleized.sync_boundary(), Location::new(bounds.total_size));
    let sync_target = block.sync_target();
    if block.qmdb_state_root() != merkleized.root()
        || sync_target.root != merkleized.ops_root()
        || sync_target.range != range
    {
        return None;
    }

    Some(merkleized)
}
