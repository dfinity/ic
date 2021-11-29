//! A collection of testing utilities for this crate.
//! These can be used to implemnet pools.

use crate::consensus_pool::{PoolSectionOp, PoolSectionOps};
use ic_consensus_message::ConsensusMessageHashable;
use ic_interfaces::consensus_pool::{HeightIndexedPool, HeightRange, ValidatedConsensusArtifact};
use ic_test_utilities::{
    consensus::{fake::*, make_genesis},
    mock_time,
    types::ids::node_test_id,
};
use ic_types::{
    artifact::ConsensusMessage,
    consensus::{
        dkg::Summary, Block, BlockProposal, Finalization, FinalizationContent, FinalizationShare,
        MultiSignature, MultiSignatureShare, Notarization, NotarizationContent, NotarizationShare,
        RandomBeacon, RandomBeaconContent, RandomBeaconShare, RandomTape, RandomTapeContent,
        RandomTapeShare, ThresholdSignatureShare,
    },
    crypto::{ThresholdSigShare, ThresholdSigShareOf},
    Height,
};

pub fn make_summary(genesis_height: Height) -> Summary {
    let mut summary = Summary::fake();
    summary.height = genesis_height;
    summary
}

pub fn fake_block_proposal(h: Height) -> BlockProposal {
    let parent = make_genesis(make_summary(h.decrement())).content.block;
    BlockProposal::fake(Block::from_parent(parent.as_ref()), node_test_id(0))
}

pub fn fake_random_beacon(h: Height) -> RandomBeacon {
    let parent = make_genesis(make_summary(h.decrement()))
        .content
        .random_beacon;
    RandomBeacon::from_parent(parent.as_ref())
}

pub fn random_beacon_ops() -> PoolSectionOps<ValidatedConsensusArtifact> {
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

pub fn block_proposal_ops() -> PoolSectionOps<ValidatedConsensusArtifact> {
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

pub fn finalization_ops() -> PoolSectionOps<ValidatedConsensusArtifact> {
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

pub fn notarization_ops() -> PoolSectionOps<ValidatedConsensusArtifact> {
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

pub fn random_beacon_share_ops() -> PoolSectionOps<ValidatedConsensusArtifact> {
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

pub fn notarization_share_ops() -> PoolSectionOps<ValidatedConsensusArtifact> {
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

pub fn finalization_share_ops() -> PoolSectionOps<ValidatedConsensusArtifact> {
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

pub fn random_tape_ops() -> PoolSectionOps<ValidatedConsensusArtifact> {
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

pub fn random_tape_share_ops() -> PoolSectionOps<ValidatedConsensusArtifact> {
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
pub fn match_all_ops<T: ConsensusMessageHashable + Eq + std::fmt::Debug>(
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

pub fn match_ops_to_results<T: ConsensusMessageHashable + Eq + std::fmt::Debug>(
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
