//! This tests the speed of loading blocks from persistence with varying payload
//! sizes.

use std::time::{Duration, Instant};

use criterion::{Criterion, criterion_group, criterion_main};
use ic_artifact_pool::consensus_pool::ConsensusPoolImpl;
use ic_interfaces::consensus_pool::{
    ChangeAction, ConsensusPool, Mutations, ValidatedConsensusArtifact,
};
use ic_interfaces::p2p::consensus::MutablePool;
use ic_interfaces::time_source::SysTimeSource;
use ic_logger::replica_logger::no_op_logger;
use ic_test_utilities_consensus::{fake::*, make_genesis};
use ic_test_utilities_types::{
    ids::{node_test_id, subnet_test_id},
    messages::SignedIngressBuilder,
};
use ic_types::consensus::dkg::{DkgDataPayload, DkgSummary};
use ic_types::consensus::{BlockPayload, DataPayload};
use ic_types::{
    Height,
    batch::{BatchPayload, IngressPayload},
    consensus::{Block, BlockProposal, ConsensusMessageHashable, HasHeight, Payload, Rank},
    time::UNIX_EPOCH,
};

// Helper to run the persistence tests below.
// It creates the config and logger that is passed to the instances and then
// makes sure that the the databases are destroyed before the test fails.
fn run_test<T>(_test_name: &str, test: T)
where
    T: FnOnce(&mut ConsensusPoolImpl),
{
    ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
        let mut consensus_pool = ConsensusPoolImpl::new(
            node_test_id(0),
            subnet_test_id(0),
            (&make_genesis(DkgSummary::fake())).into(),
            pool_config,
            ic_metrics::MetricsRegistry::new(),
            no_op_logger(),
            std::sync::Arc::new(SysTimeSource::new()),
        );
        test(&mut consensus_pool);
    })
}

fn prepare(pool: &mut ConsensusPoolImpl, num: u64) {
    let mut changeset = Mutations::new();
    for i in 0..num {
        let proposal = fake_block(pool, i, 1, 128 * 1024);
        changeset.push(ChangeAction::AddToValidated(ValidatedConsensusArtifact {
            msg: proposal.into_message(),
            timestamp: UNIX_EPOCH,
        }));
    }
    pool.apply(changeset);
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

fn fake_block(
    pool: &ConsensusPoolImpl,
    nonce: u64,
    ingress_count: usize,
    ingress_size: usize,
) -> BlockProposal {
    let cup = pool
        .validated()
        .catch_up_package()
        .get_by_height(Height::from(0))
        .next()
        .unwrap();
    let parent = cup.content.block.as_ref();
    let mut block = Block::from_parent(parent);
    block.rank = Rank(nonce);
    let ingress = IngressPayload::from(
        (0..ingress_count)
            .map(|index| {
                SignedIngressBuilder::new()
                    .method_payload(vec![0; ingress_size])
                    .method_name(format!("method_{index}"))
                    .build()
            })
            .collect::<Vec<_>>(),
    );
    block.payload = Payload::new(
        ic_types::crypto::crypto_hash,
        BlockPayload::Data(DataPayload {
            batch: BatchPayload {
                ingress,
                ..BatchPayload::default()
            },
            dkg: DkgDataPayload::new_empty(parent.payload.as_ref().dkg_interval_start_height()),
            idkg: None,
        }),
    );
    BlockProposal::fake(block, node_test_id(nonce))
}

/// Speed test for storing block proposals.
fn add_validated_block(criterion: &mut Criterion) {
    let mut group = criterion.benchmark_group("Adding a validated block");
    const MB: usize = 1024 * 1024;

    ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
        for (ingress_count, ingress_size) in [
            (1, 1),
            (1_000, 1),
            (1, 2 * MB),
            (2, 2 * MB),
            (4, 2 * MB),
            (8, 2 * MB),
            (16, 2 * MB),
        ] {
            group.bench_function(
                format!("ingress_count: {ingress_count}, ingress_size: {ingress_size}"),
                |bench| {
                    bench.iter_custom(|iters| {
                        let mut total_duration = Duration::ZERO;
                        let mut pool = ConsensusPoolImpl::new(
                            node_test_id(0),
                            subnet_test_id(0),
                            (&make_genesis(DkgSummary::fake())).into(),
                            pool_config.clone(),
                            ic_metrics::MetricsRegistry::new(),
                            no_op_logger(),
                            std::sync::Arc::new(SysTimeSource::new()),
                        );
                        let block = fake_block(&pool, 0, ingress_count, ingress_size);
                        let height = block.height();

                        for _ in 0..iters {
                            let changeset =
                                vec![ChangeAction::AddToValidated(ValidatedConsensusArtifact {
                                    msg: block.clone().into_message(),
                                    timestamp: UNIX_EPOCH,
                                })];
                            // only the insertion duration is measured
                            let start = Instant::now();
                            pool.apply(changeset);
                            total_duration += start.elapsed();
                            // remove the block we just inserted
                            pool.apply(vec![ChangeAction::PurgeValidatedBelow(height.increment())]);
                        }

                        total_duration
                    });
                },
            );
        }
    })
}

criterion_group!(benches, load_blocks, add_validated_block);

criterion_main!(benches);
