//! Deterministic replay of certified blocks for Stateful lazy recovery.

use super::{
    StatefulApplication, StatefulBlock,
    genesis::compile_mechanism_set,
    proposal::{Merkleized, execute_candidate},
    state::QmdbStateDatabase,
};
use commonware_glue::stateful::db::{DatabaseSet, Merkleized as _, Shared};
use commonware_parallel::Sequential;
use commonware_runtime::Spawner;
use commonware_storage::{Context as StorageContext, merkle::Location, translator::OneCap};
use commonware_utils::non_empty_range;
use rachet_core::transition::TransitionContext;

type Databases<E> = Shared<QmdbStateDatabase<E, OneCap, Sequential>>;
type Unmerkleized<E> = <Databases<E> as DatabaseSet<E>>::Unmerkleized;

/// Reconstructs the exact speculative state previously accepted for a certified block.
///
/// Stateful invokes this path when its in-memory pending ancestry is absent after restart.
/// Any mismatch is corruption or non-determinism, so replay deliberately panics rather than
/// turning a certified block into a new validity decision.
pub(crate) async fn apply<E>(
    application: &StatefulApplication,
    block: &StatefulBlock,
    batches: Unmerkleized<E>,
) -> Merkleized<E>
where
    E: StorageContext + Spawner + rand_core::Rng + Send + Sync + 'static,
{
    let genesis = application.genesis_state();
    let header = &block.protocol().header;
    let configured_protocol = genesis.protocol().protocol();
    assert_eq!(
        header.protocol_version,
        configured_protocol.version(),
        "certified replay protocol version must match genesis"
    );
    assert_eq!(
        header.chain_id,
        genesis.chain_id(),
        "certified replay chain must match genesis"
    );
    assert_eq!(
        header.mechanism_set_id,
        genesis.protocol().mechanism_set_id(),
        "certified replay mechanism set must match genesis"
    );

    let transition = TransitionContext {
        chain_id: genesis.chain_id(),
        protocol_version: configured_protocol.version(),
        height: header.height,
        epoch: header.epoch,
        mechanism_set_id: genesis.protocol().mechanism_set_id(),
    };
    let mechanisms = compile_mechanism_set(genesis.protocol().mechanism_set())
        .unwrap_or_else(|error| panic!("certified replay mechanism compilation failed: {error}"));
    let (execution, merkleized) = execute_candidate(
        batches,
        header.parent_state_root,
        &transition,
        block.protocol().actions.as_slice(),
        mechanisms,
    )
    .await
    .unwrap_or_else(|| panic!("certified block execution failed during lazy replay"));

    assert_eq!(
        execution.action_root, header.action_root,
        "certified replay action root diverged"
    );
    assert_eq!(
        execution.receipt_root, header.receipt_root,
        "certified replay receipt root diverged"
    );
    assert_eq!(
        execution.post_state_root, header.post_state_root,
        "certified replay logical state root diverged"
    );
    assert_eq!(
        merkleized.root(),
        block.qmdb_state_root(),
        "certified replay QMDB state root diverged"
    );

    let bounds = merkleized.bounds();
    let range = non_empty_range!(merkleized.sync_boundary(), Location::new(bounds.total_size));
    let target = block.sync_target();
    assert_eq!(
        merkleized.ops_root(),
        target.root,
        "certified replay QMDB operations root diverged"
    );
    assert_eq!(
        range, target.range,
        "certified replay QMDB operation range diverged"
    );

    merkleized
}
