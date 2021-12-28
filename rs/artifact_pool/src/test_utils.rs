//! A collection of testing utilities for this crate.
//!
//! This module contains a set of tests that are generic over the trait
//! [`PoolTestHelper`], as well as a test suite implemented on top of this
//! trait.
//!
//! By implementing this trait on a Pool implementation (in a test submodule),
//! the tests in this module can be used to test the Pool implementation.

use crate::consensus_pool::{MutablePoolSection, PoolSectionOp, PoolSectionOps};
use ic_consensus_message::ConsensusMessageHashable;
use ic_interfaces::consensus_pool::{
    HeightIndexedPool, HeightRange, PoolSection, ValidatedConsensusArtifact,
};
use ic_logger::ReplicaLogger;
use ic_test_utilities::{
    consensus::{fake::*, make_genesis},
    mock_time,
    types::ids::node_test_id,
};
use ic_types::{
    artifact::{ConsensusMessage, ConsensusMessageId},
    consensus::{
        dkg::Summary, Block, BlockPayload, BlockProposal, Finalization, FinalizationContent,
        FinalizationShare, MultiSignature, MultiSignatureShare, Notarization, NotarizationContent,
        NotarizationShare, RandomBeacon, RandomBeaconContent, RandomBeaconShare, RandomTape,
        RandomTapeContent, RandomTapeShare, ThresholdSignatureShare,
    },
    crypto::{ThresholdSigShare, ThresholdSigShareOf},
    Height,
};
use std::{
    panic,
    path::{Path, PathBuf},
    time::Duration,
};

pub(crate) trait PoolTestHelper: Clone {
    type PersistentHeightIndexedPool: MutablePoolSection<ValidatedConsensusArtifact>;

    fn run_persistent_pool_test<T, R>(_test_name: &str, test: T) -> R
    where
        Self: Sized,
        T: FnOnce(Self, ReplicaLogger) -> R + panic::UnwindSafe;

    fn new_consensus_pool(self, log: ReplicaLogger) -> Self::PersistentHeightIndexedPool;

    fn persistent_pool_validated_persistent_db_path(&self) -> &PathBuf;
}

// Tests the pool though the PoolSection trait, including inserting
// and rebooting.
pub(crate) fn test_as_pool_section<T>()
where
    T: PoolTestHelper,
{
    T::run_persistent_pool_test("test_as_pool_section", |config, log| {
        let height = Height::from(11);
        let block_proposal = fake_block_proposal(Height::from(11));
        let msg = ConsensusMessage::BlockProposal(block_proposal);
        let msg_expected = msg.clone();
        let hash = msg_expected.get_cm_hash();
        let msg_id = ConsensusMessageId { hash, height };
        // Create a pool and insert an item.
        {
            let mut pool = T::new_consensus_pool(config.clone(), log.clone());
            let mut ops = PoolSectionOps::new();
            ops.insert(ValidatedConsensusArtifact {
                msg,
                timestamp: mock_time(),
            });
            pool.mutate(ops);
        }
        // Test that we can get the item after rebuilding the pool.
        {
            let mut pool = T::new_consensus_pool(config.clone(), log.clone());
            assert!(pool.contains(&msg_id));
            let get_result = pool.get(&msg_id);
            match get_result {
                Some(artifact_result) => {
                    assert_eq!(artifact_result, msg_expected);
                }
                None => {
                    panic!("Get failed");
                }
            }
            let mut ops = PoolSectionOps::new();
            ops.remove(msg_id.clone());
            pool.mutate(ops);
        }
        // Test that the item's removal survived a reboot.
        {
            let pool = T::new_consensus_pool(config, log);
            assert!(!pool.contains(&msg_id));
            assert!(pool.get(&msg_id).is_none());
        }
    })
}

pub(crate) fn make_summary(genesis_height: Height) -> Summary {
    let mut summary = Summary::fake();
    summary.height = genesis_height;
    summary
}

fn fake_block_proposal(h: Height) -> BlockProposal {
    let parent = make_genesis(make_summary(h.decrement())).content.block;
    BlockProposal::fake(Block::from_parent(parent.as_ref()), node_test_id(0))
}

pub(crate) fn fake_random_beacon(h: Height) -> RandomBeacon {
    let parent = make_genesis(make_summary(h.decrement()))
        .content
        .random_beacon;
    RandomBeacon::from_parent(parent.as_ref())
}

// Tests the pool through the HeightIndexedPool trait.
//
// This is the most comprehensive functional test. It directly tests all
// of the HeightIndexedPool methods, it also indirectly tests whether
// reference counting is working properly. This because if we have
// reference count leak and some instance of DB is alive, the destroy()
// call in run_persistent_pool_test() will fail as it requires exclusive
// access to the DB directory.
pub(crate) fn test_as_height_indexed_pool<T>()
where
    T: PoolTestHelper,
{
    T::run_persistent_pool_test("test_as_height_indexed_pool", |config, log| {
        let rb_ops = random_beacon_ops();
        let fz_ops = finalization_ops();
        let nz_ops = notarization_ops();
        let bp_ops = block_proposal_ops();
        let rbs_ops = random_beacon_share_ops();
        let nzs_ops = notarization_share_ops();
        let fzs_ops = finalization_share_ops();
        let rt_ops = random_tape_ops();
        let rts_ops = random_tape_share_ops();

        // Insert a bunch of items and test that the pool returns them
        {
            let mut pool = T::new_consensus_pool(config.clone(), log.clone());

            pool.mutate(rb_ops.clone());
            match_ops_to_results(&rb_ops, pool.random_beacon(), false);

            pool.mutate(fz_ops.clone());
            match_ops_to_results(&fz_ops, pool.finalization(), false);

            pool.mutate(nz_ops.clone());
            match_ops_to_results(&nz_ops, pool.notarization(), false);

            pool.mutate(bp_ops.clone());
            match_ops_to_results(&bp_ops, pool.block_proposal(), false);

            pool.mutate(rbs_ops.clone());
            match_ops_to_results(&rbs_ops, pool.random_beacon_share(), true);

            pool.mutate(nzs_ops.clone());
            match_ops_to_results(&nzs_ops, pool.notarization_share(), true);

            pool.mutate(fzs_ops.clone());
            match_ops_to_results(&fzs_ops, pool.finalization_share(), true);

            pool.mutate(rt_ops.clone());
            match_ops_to_results(&rt_ops, pool.random_tape(), false);

            pool.mutate(rts_ops.clone());
            match_ops_to_results(&rts_ops, pool.random_tape_share(), true);
        }

        // Test the matching after a reboot.
        {
            let pool = T::new_consensus_pool(config, log);
            match_ops_to_results(&rb_ops, pool.random_beacon(), false);
            match_ops_to_results(&fz_ops, pool.finalization(), false);
            match_ops_to_results(&nz_ops, pool.notarization(), false);
            match_ops_to_results(&bp_ops, pool.block_proposal(), false);
            match_ops_to_results(&rbs_ops, pool.random_beacon_share(), true);
            match_ops_to_results(&nzs_ops, pool.notarization_share(), true);
            match_ops_to_results(&fzs_ops, pool.finalization_share(), true);
            match_ops_to_results(&rt_ops, pool.random_tape(), false);
            match_ops_to_results(&rts_ops, pool.random_tape_share(), true);
        }
    })
}

// Tests if payloads are persisted and removed correctly together with block
// proposals.
pub(crate) fn test_block_proposal_and_payload_correspondence<T>()
where
    T: PoolTestHelper,
{
    T::run_persistent_pool_test(
        "test_block_proposal_and_payload_correspondence",
        |config, log| {
            let insert_ops = block_proposal_ops();
            let msgs = insert_ops
                .ops
                .iter()
                .map(|op| {
                    if let PoolSectionOp::Insert(artifact) = op {
                        &artifact.msg
                    } else {
                        panic!("Expect Insert but found {:?}", op)
                    }
                })
                .collect::<Vec<_>>();
            let mut remove_ops = msgs
                .iter()
                .map(|msg| PoolSectionOp::Remove(msg.get_id()))
                .collect::<Vec<PoolSectionOp<ValidatedConsensusArtifact>>>();
            let mut payloads: Vec<BlockPayload> = msgs
                .iter()
                .map(|msg| {
                    BlockProposal::assert(msg)
                        .unwrap()
                        .as_ref()
                        .payload
                        .as_ref()
                        .clone()
                })
                .collect::<Vec<_>>();
            let mut pool = T::new_consensus_pool(config, log);
            pool.mutate(insert_ops);
            let proposals = pool.block_proposal().get_all().collect::<Vec<_>>();
            assert!(proposals.iter().all(|proposal| proposal.check_integrity()));
            assert_eq!(
                payloads,
                proposals
                    .iter()
                    .map(|proposal| proposal.as_ref().payload.as_ref().clone())
                    .collect::<Vec<_>>()
            );

            // Remove the first 5 block proposals
            let _ = payloads.split_off(5);
            let remove_first_5 = remove_ops.split_off(5);
            pool.mutate(PoolSectionOps {
                ops: remove_first_5,
            });
            let iter = pool.block_proposal().get_all();
            assert_eq!(
                payloads,
                iter.map(|proposal| proposal.as_ref().payload.as_ref().clone())
                    .collect::<Vec<_>>()
            );

            // Remove all
            pool.mutate(PoolSectionOps { ops: remove_ops });
            let mut iter = pool.block_proposal().get_all();
            assert!(iter.next().is_none());
        },
    )
}

// Tests that iterators are created on snapshots of the pool and that
// the returned values do not reflect any updates after the iterator
// was created.
//
// This also illustrates passing iterators by value when the pool is
// left behind, emulating how iterators might be used to perform
// async work.
pub(crate) fn test_iterating_while_inserting_doesnt_see_new_updates<T>()
where
    T: PoolTestHelper,
{
    T::run_persistent_pool_test(
        "test_iterating_while_inserting_doesnt_see_new_updates",
        |config, log| {
            let rb_ops = random_beacon_ops();
            let mut pool = T::new_consensus_pool(config, log);
            pool.mutate(rb_ops);
            let iter = pool.random_beacon().get_all();

            // Before we go through the iterator values we'll remove all of
            // of the values in the current range and add values before and after
            // the iterator's initial range (3..15).
            let mut ops = PoolSectionOps::new();
            ops.insert(make_random_beacon_at_height(1));
            ops.insert(make_random_beacon_at_height(2));
            ops.insert(make_random_beacon_at_height(20));
            for i in 3..20 {
                ops.remove(make_random_beacon_msg_id_at_height(i));
            }
            pool.mutate(ops);

            // The original iterator shouldn't observe the changes
            // we made above
            check_iter_original(iter);

            // A new iterator should see the new values.
            check_iter_mutated(pool.random_beacon().get_all());
        },
    );
}

// Tests that iterators obtained from the pool can outlive it, meaning it's
// safe to pass them around without the pool itself. Even though it isn't
// likely that the iterator will outlive the pool, ever, it is necessary
// to make make sure it can to guarantee the safety of passing it as an
// argument without the pool.
pub(crate) fn test_iterator_can_outlive_the_pool<T>()
where
    T: PoolTestHelper,
{
    T::run_persistent_pool_test("test_iterator_can_outlive_the_pool", |config, log| {
        let rb_ops = random_beacon_ops();
        let iter;

        // Create a pool in this inner scope, which will be destroyed
        // before the iterator is used.
        {
            let mut pool = T::new_consensus_pool(config, log);
            pool.mutate(rb_ops.clone());
            iter = pool.random_beacon().get_all();
        }

        let msgs_from_pool: Vec<RandomBeacon> = iter.collect();
        assert_eq!(msgs_from_pool.len(), rb_ops.ops.len());
        for (i, op) in rb_ops.ops.iter().enumerate() {
            if let PoolSectionOp::Insert(artifact) = &op {
                assert_eq!(
                    RandomBeacon::assert(&artifact.msg).unwrap(),
                    &msgs_from_pool[i]
                );
            }
        }
    });
}

// Tests that, if configured to do so, the pool will delete the data
// directories on drop. This is useful to cleanup after running
// tests.
pub(crate) fn test_persistent_pool_path_is_cleanedup_after_tests<T>()
where
    T: PoolTestHelper,
{
    let tmp = T::run_persistent_pool_test(
        "test_persistent_pool_path_is_cleanedup_after_tests",
        |config, log| {
            let path = config
                .persistent_pool_validated_persistent_db_path()
                .clone();
            let rb_ops = random_beacon_ops();
            {
                let mut pool = T::new_consensus_pool(config, log);
                pool.mutate(rb_ops);
            }
            path
        },
    );
    assert!(!Path::new(&tmp).exists());
}

// Test if timestamp survives reboot.
pub(crate) fn test_timestamp_survives_reboot<T>()
where
    T: PoolTestHelper,
{
    T::run_persistent_pool_test("test_purge_survives_reboot", |config, log| {
        let time_0 = mock_time() + Duration::from_secs(1234);
        // create a pool and insert an artifact
        {
            let mut pool = T::new_consensus_pool(config.clone(), log.clone());
            // insert a few things
            let mut ops = PoolSectionOps::new();
            let random_beacon = fake_random_beacon(Height::from(10));
            let msg = ConsensusMessage::RandomBeacon(random_beacon);
            let msg_id = msg.get_id();
            ops.insert(ValidatedConsensusArtifact {
                msg,
                timestamp: time_0,
            });
            pool.mutate(ops);

            assert_eq!(pool.get_timestamp(&msg_id), Some(time_0));
        }

        // create the same pool again, check if timestamp was preserved
        {
            let pool = T::new_consensus_pool(config, log);
            let random_beacon = pool
                .random_beacon()
                .get_by_height(Height::from(10))
                .next()
                .unwrap();
            let msg_id = random_beacon.get_id();
            assert_eq!(pool.get_timestamp(&msg_id), Some(time_0));
        }
    });
}

// Support functions for the tests
pub(crate) fn random_beacon_ops() -> PoolSectionOps<ValidatedConsensusArtifact> {
    let mut ops = PoolSectionOps::new();
    for i in 3..19 {
        let random_beacon = fake_random_beacon(Height::from(i));
        let msg = ConsensusMessage::RandomBeacon(random_beacon);
        ops.insert(ValidatedConsensusArtifact {
            msg,
            timestamp: mock_time(),
        });
    }
    ops
}

fn block_proposal_ops() -> PoolSectionOps<ValidatedConsensusArtifact> {
    let mut ops = PoolSectionOps::new();
    for i in 1..18 {
        let block_proposal = fake_block_proposal(Height::from(i));
        let msg = ConsensusMessage::BlockProposal(block_proposal);
        ops.insert(ValidatedConsensusArtifact {
            msg,
            timestamp: mock_time(),
        });
    }
    ops
}

fn finalization_ops() -> PoolSectionOps<ValidatedConsensusArtifact> {
    let mut ops = PoolSectionOps::new();
    for i in 2..13 {
        let height = Height::from(i);
        let block_proposal = fake_block_proposal(height);
        let block = block_proposal.content.get_hash().clone();
        let content = FinalizationContent::new(height, block);
        let signature = MultiSignature::fake();
        let msg = ConsensusMessage::Finalization(Finalization { content, signature });
        ops.insert(ValidatedConsensusArtifact {
            msg,
            timestamp: mock_time(),
        });
    }
    ops
}

fn notarization_ops() -> PoolSectionOps<ValidatedConsensusArtifact> {
    let mut ops = PoolSectionOps::new();
    for i in 2..14 {
        let height = Height::from(i);
        let block_proposal = fake_block_proposal(height);
        let block = block_proposal.content.get_hash().clone();
        let content = NotarizationContent::new(height, block);
        let signature = MultiSignature::fake();
        let msg = ConsensusMessage::Notarization(Notarization { content, signature });
        ops.insert(ValidatedConsensusArtifact {
            msg,
            timestamp: mock_time(),
        });
    }
    ops
}

fn random_beacon_share_ops() -> PoolSectionOps<ValidatedConsensusArtifact> {
    let mut ops = PoolSectionOps::new();
    for i in 3..21 {
        let height = Height::from(i);
        for j in 0..3 {
            let random_beacon = fake_random_beacon(Height::from(i));
            let parent = ic_crypto::crypto_hash(&random_beacon);
            let content = RandomBeaconContent::new(height, parent);
            let signature = ThresholdSigShareOf::new(ThresholdSigShare(vec![]));
            let signer = node_test_id(j);
            let signature = ThresholdSignatureShare { signature, signer };
            let msg = ConsensusMessage::RandomBeaconShare(RandomBeaconShare { content, signature });
            ops.insert(ValidatedConsensusArtifact {
                msg,
                timestamp: mock_time(),
            });
        }
    }
    ops
}

fn notarization_share_ops() -> PoolSectionOps<ValidatedConsensusArtifact> {
    let mut ops = PoolSectionOps::new();
    for i in 4..16 {
        let height = Height::from(i);
        let block_proposal = fake_block_proposal(height);
        for j in 0..3 {
            let block = block_proposal.content.get_hash().clone();
            let content = NotarizationContent::new(height, block);
            let signature = MultiSignatureShare::fake(node_test_id(j));
            let msg = ConsensusMessage::NotarizationShare(NotarizationShare { content, signature });
            ops.insert(ValidatedConsensusArtifact {
                msg,
                timestamp: mock_time(),
            });
        }
    }
    ops
}

fn finalization_share_ops() -> PoolSectionOps<ValidatedConsensusArtifact> {
    let mut ops = PoolSectionOps::new();
    for i in 5..14 {
        let height = Height::from(i);
        let block_proposal = fake_block_proposal(height);
        for j in 0..3 {
            let block = block_proposal.content.get_hash().clone();
            let content = FinalizationContent::new(height, block);
            let signature = MultiSignatureShare::fake(node_test_id(j));
            let msg = ConsensusMessage::FinalizationShare(FinalizationShare { content, signature });
            ops.insert(ValidatedConsensusArtifact {
                msg,
                timestamp: mock_time(),
            });
        }
    }
    ops
}

fn random_tape_ops() -> PoolSectionOps<ValidatedConsensusArtifact> {
    let mut ops = PoolSectionOps::new();
    for i in 3..19 {
        let random_tape = RandomTape::fake(RandomTapeContent::new(Height::from(i)));
        let msg = ConsensusMessage::RandomTape(random_tape);
        ops.insert(ValidatedConsensusArtifact {
            msg,
            timestamp: mock_time(),
        });
    }
    ops
}

fn random_tape_share_ops() -> PoolSectionOps<ValidatedConsensusArtifact> {
    let mut ops = PoolSectionOps::new();
    for i in 5..20 {
        let height = Height::from(i);
        for j in 0..3 {
            let content = RandomTapeContent::new(height);
            let signature = ThresholdSigShareOf::new(ThresholdSigShare(vec![]));
            let signer = node_test_id(j);
            let signature = ThresholdSignatureShare { signature, signer };
            let msg = ConsensusMessage::RandomTapeShare(RandomTapeShare { content, signature });
            ops.insert(ValidatedConsensusArtifact {
                msg,
                timestamp: mock_time(),
            });
        }
    }
    ops
}

// Tests that the messages from the pool match the messages that we inserted,
// namely:
// - That we get the same number of messages back.
// - That height is monotonically increasing (iterators are in order, for
//   height).
// - That the max and min match.
// - That all the messages are present in the original messages.
//
// Returns the min/max height found to use in later tests.
fn match_all_ops<T: ConsensusMessageHashable + Eq + std::fmt::Debug>(
    msgs_from_pool: &[T],
    original_ops: &[T],
    multiple_values: bool,
) -> (Height, Height) {
    let mut min_height = Height::from(1000 * 1000);
    let mut max_height = Height::from(0);
    let mut monotonic_height = Height::from(0);
    assert_eq!(msgs_from_pool.len(), original_ops.len());
    for msg in msgs_from_pool.iter() {
        let msg_height = msg.get_id().height;
        if msg_height < min_height {
            min_height = msg_height;
        }
        if msg_height > max_height {
            max_height = msg_height;
        }
        if multiple_values {
            assert!(monotonic_height <= msg_height);
        } else {
            assert!(monotonic_height < msg_height);
        }
        monotonic_height = msg_height;
        assert!(original_ops.contains(msg));
    }
    assert_eq!(min_height, original_ops[0].get_id().height);
    assert_eq!(
        max_height,
        original_ops[original_ops.len() - 1].get_id().height
    );
    (min_height, max_height)
}

fn match_ops_to_results<T: ConsensusMessageHashable + Eq + std::fmt::Debug>(
    ops: &PoolSectionOps<ValidatedConsensusArtifact>,
    pool_by_type: &dyn HeightIndexedPool<T>,
    multiple_values: bool,
) {
    let mut ops_vec = Vec::new();
    for op in &ops.ops {
        if let PoolSectionOp::Insert(artifact) = op {
            ops_vec.push(T::assert(&artifact.msg).unwrap().clone())
        }
    }
    let min_height;
    let max_height;
    //Test that all the ops are found in the results.
    {
        let msgs_from_pool: Vec<T> = pool_by_type.get_all().collect();
        let (new_min, new_max) = match_all_ops(&msgs_from_pool, &ops_vec, multiple_values);
        min_height = new_min;
        max_height = new_max;
    }

    // Test get by range
    {
        let msgs_from_pool: Vec<T> = pool_by_type
            .get_by_height_range(HeightRange::new(min_height, max_height))
            .collect();
        match_all_ops(&msgs_from_pool, &ops_vec, multiple_values);
    }

    // Test get highest
    if !multiple_values {
        let result = pool_by_type.get_highest();
        if let Ok(highest) = &result {
            if let PoolSectionOp::Insert(artifact) = &ops.ops[ops.ops.len() - 1] {
                assert_eq!(T::assert(&artifact.msg).unwrap(), highest);
            } else {
                panic!("Got error: {:?}", result.err());
            }
        }
    // Test get highest iter
    } else {
        assert_eq!(pool_by_type.get_highest_iter().count(), 3);
    }
}

fn make_random_beacon_at_height(i: u64) -> ValidatedConsensusArtifact {
    let random_beacon = fake_random_beacon(Height::from(i));
    ValidatedConsensusArtifact {
        msg: ConsensusMessage::RandomBeacon(random_beacon),
        timestamp: mock_time(),
    }
}

fn make_random_beacon_msg_id_at_height(i: u64) -> ConsensusMessageId {
    let hash = make_random_beacon_at_height(i).msg.get_cm_hash();
    let height = Height::from(i);
    ConsensusMessageId { hash, height }
}

fn check_iter_original(iter: Box<dyn Iterator<Item = RandomBeacon>>) {
    // Now make sure the iterator still sees the old values
    // and doesn't see the new ones.
    let msgs_from_pool: Vec<RandomBeacon> = iter.collect();
    assert_eq!(msgs_from_pool.len(), 16);
    for i in 3..15 {
        let msg = &msgs_from_pool[i - 3];
        assert_eq!(msg.content.height, Height::from(i as u64));
    }
}

fn check_iter_mutated(iter: Box<dyn Iterator<Item = RandomBeacon>>) {
    let msgs_from_pool: Vec<RandomBeacon> = iter.collect();
    assert_eq!(msgs_from_pool.len(), 3);
    assert_eq!(msgs_from_pool[0].content.height, Height::from(1));
    assert_eq!(msgs_from_pool[1].content.height, Height::from(2));
    assert_eq!(msgs_from_pool[2].content.height, Height::from(20));
}
