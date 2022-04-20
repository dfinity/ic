//! This tests the speed of loading blocks from persistence with varying payload
//! sizes.

use criterion::{criterion_group, criterion_main, Criterion};
use ic_artifact_pool::consensus_pool::ConsensusPoolImpl;
use ic_consensus_message::ConsensusMessageHashable;
use ic_interfaces::consensus_pool::{ChangeAction, ChangeSet, ConsensusPool, MutableConsensusPool};
use ic_logger::replica_logger::no_op_logger;
use ic_test_utilities::FastForwardTimeSource;
use ic_test_utilities::{
    consensus::{fake::*, make_genesis},
    types::ids::{node_test_id, subnet_test_id},
    types::messages::SignedIngressBuilder,
};
use ic_types::{
    batch::{BatchPayload, IngressPayload},
    consensus::{dkg, Block, BlockProposal, HasHeight, Payload, Rank},
    Height,
};

// Helper to run the persistence tests below.
// It creates the config and logger that is passed to the instances and then
// makes sure that the the databases are destroyed before the test fails.
fn run_test<T>(_test_name: &str, test: T)
where
    T: FnOnce(&mut ConsensusPoolImpl),
{
    ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
        let mut consensus_pool = ConsensusPoolImpl::new_from_cup_without_bytes(
            subnet_test_id(0),
            make_genesis(ic_types::consensus::dkg::Summary::fake()),
            pool_config,
            ic_metrics::MetricsRegistry::new(),
            no_op_logger(),
        );
        test(&mut consensus_pool);
    })
}

fn prepare(pool: &mut ConsensusPoolImpl, num: usize) {
    let cup = pool
        .validated()
        .catch_up_package()
        .get_by_height(Height::from(0))
        .next()
        .unwrap();
    let parent = cup.content.block.as_ref();
    let mut changeset = ChangeSet::new();
    for i in 0..num {
        let mut block = Block::from_parent(parent);
        block.rank = Rank(i as u64);
        let ingress = IngressPayload::from(vec![SignedIngressBuilder::new()
            .method_payload(vec![0; 128 * 1024])
            .build()]);
        block.payload = Payload::new(
            ic_crypto::crypto_hash,
            (
                BatchPayload {
                    ingress,
                    ..BatchPayload::default()
                },
                dkg::Dealings::new_empty(parent.payload.as_ref().dkg_interval_start_height()),
                None,
            )
                .into(),
        );
        let proposal = BlockProposal::fake(block, node_test_id(i as u64));
        changeset.push(ChangeAction::AddToValidated(proposal.into_message()));
    }
    let time_source = FastForwardTimeSource::new();
    pool.apply_changes(time_source.as_ref(), changeset);
}

fn sum_block_heights(pool: &dyn ConsensusPool) -> u64 {
    pool.validated()
        .block_proposal()
        .get_all()
        .map(|block| block.height().get())
        .sum::<u64>()
}

fn sum_ingress_counts(pool: &dyn ConsensusPool) -> usize {
    pool.validated()
        .block_proposal()
        .get_all()
        .map(|proposal| {
            let block: Block = proposal.into();
            let batch = &block.payload.as_ref().as_data().batch;
            batch.ingress.message_count()
        })
        .sum::<usize>()
}

/// Speed test for loading and copying block proposals.
fn load_blocks(criterion: &mut Criterion) {
    let mut group = criterion.benchmark_group("block_loading");
    run_test("load_blocks", |pool: &mut ConsensusPoolImpl| {
        prepare(pool, 20);
        group.bench_function("Load blocks and sum their heights", |bench| {
            bench.iter(|| {
                sum_block_heights(pool);
            })
        });
        group.bench_function("Load blocks and sum their ingress counts", |bench| {
            bench.iter(|| {
                sum_ingress_counts(pool);
            })
        });
    })
}

criterion_group!(benches, load_blocks);

criterion_main!(benches);
