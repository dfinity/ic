#![allow(dead_code)]

//! Some canisters may want to use randomness, for example a lottery canister.
//! Since a canister is executed on many replicas and we want the different
//! replicas to have the same state, we must use agreed-upon pseudo-randomness.
//! The RandomTape fulfills this purpose. The RandomTapeMaker is responsible for
//! contributing to the creation of the random tape.
//!
//! How it works:
//!
//! 1. We deliver both the payload for finalized block at height h together with
//! a random tape at height h. This is handled by the finalizer.
//!
//! 2. As soon as we finalize a block at height h, we start to create the random
//! tape for height h+1. This is handled by random tape maker.
//!
//! 3. For security purpose, when the payload of height h is executed, it should
//! not access random tape at the same height. This is because the random tape
//! at h may be already known before a block at h is finalized, creating a
//! window for a malicious blockmaker to launch an attack. To mitigate this
//! attack, accessing randomness in a canister has to be an async call, where
//! the randomness of height h+1 will be returned when the next block/batch/
//! random tape is delivered.

use crate::consensus::{
    membership::{Membership, MembershipError},
    pool_reader::PoolReader,
    prelude::*,
    utils::active_low_threshold_transcript,
    ConsensusCrypto,
};
use ic_interfaces::messaging::MessageRouting;
use ic_logger::{error, trace, ReplicaLogger};
use ic_types::replica_config::ReplicaConfig;
use std::cmp::{max, min};
use std::sync::Arc;

pub struct RandomTapeMaker {
    replica_config: ReplicaConfig,
    membership: Arc<Membership>,
    crypto: Arc<dyn ConsensusCrypto>,
    message_routing: Arc<dyn MessageRouting>,
    log: ReplicaLogger,
}

impl RandomTapeMaker {
    /// Instantiate a new random tape maker and save a copy of the config.
    pub fn new(
        replica_config: ReplicaConfig,
        membership: Arc<Membership>,
        crypto: Arc<dyn ConsensusCrypto>,
        message_routing: Arc<dyn MessageRouting>,
        log: ReplicaLogger,
    ) -> RandomTapeMaker {
        RandomTapeMaker {
            replica_config,
            membership,
            crypto,
            message_routing,
            log,
        }
    }

    /// Determine if a random tape share should be created for height h
    fn should_create_share(&self, pool: &PoolReader<'_>, height: Height) -> bool {
        match self.membership.node_belongs_to_threshold_committee(
            self.replica_config.node_id,
            height,
            RandomTape::committee(),
        ) {
            Err(MembershipError::RegistryClientError(_)) => return false,
            Err(MembershipError::NodeNotFound(_)) => panic!(
                "Node {:?} does not belong to subnet {:?}",
                self.replica_config.node_id, self.replica_config.subnet_id
            ),
            Err(MembershipError::UnableToRetrieveDkgSummary(h)) => {
                error!(
                    self.log,
                    "Couldn't find transcript at height {} with finalized height {} and CUP height {}",
                    h,
                    pool.get_finalized_height(),
                    pool.get_catch_up_height()
                );
                return false;
            }
            Ok(false) => {
                // At the given height, this replica is not part of the random beacon committee
                // (which is also responsible for creating the random tape), so we do not have
                // to create a share right now.
                return false;
            }
            Ok(true) => {}
        }

        if pool.get_random_tape(height).is_some() {
            // the random tape for h already exists, so we don't have to create a share
            // anymore
            return false;
        }

        if pool
            .get_random_tape_shares(height, height)
            .any(|s| s.signature.signer == self.replica_config.node_id)
        {
            // I've already created my random tape share for height h, so I don't have to do
            // it again.
            return false;
        }

        // If I am a random tape committee member at height h, I don't have the random
        // tape at height h yet, and I haven't created a share for random tape
        // h, then I should create a share.
        true
    }

    /// Construct a RandomTapeShare for the given height
    fn create_random_tape_share(
        &self,
        height: Height,
        pool: &PoolReader<'_>,
    ) -> Option<RandomTapeShare> {
        let content = RandomTapeContent::new(height);

        if let Some(transcript) = active_low_threshold_transcript(pool.as_cache(), height) {
            match self
                .crypto
                .sign(&content, self.replica_config.node_id, transcript.dkg_id)
            {
                Ok(signature) => Some(RandomTapeShare { content, signature }),
                Err(err) => {
                    error!(self.log, "Couldn't create a signature: {:?}", err);
                    None
                }
            }
        } else {
            error!(
                self.log,
                "Couldn't find the transcript at height {}", height
            );
            None
        }
    }

    pub fn on_state_change(&self, pool: &PoolReader<'_>) -> Vec<RandomTapeShare> {
        trace!(self.log, "on_state_change");

        // Determine for which heights we want to create random tape shares. We
        // create shares for all heights that are still needed, up to the
        // finalized height + 1. Normally, we expect to start at the next
        // expected batch height from message routing, because rounds before
        // that are already executed. When we are catching up however, we may
        // already have a newer catch-up package while expected batch height is not
        // updated until state sync is completed, while we know we do not need
        // random tape shares anymore for heights smaller or equal to the catch-up
        // package height. We therefore create shares for heights
        // max(expected_batch_height, catch_up_package_height + 1) up to finalized
        // height + 1.
        let next_batch_height = max(
            self.message_routing.expected_batch_height().get(),
            pool.get_catch_up_height().get() + 1,
        );
        let finalized_height = pool.get_finalized_height().get();
        let max_height = min(
            next_batch_height + RANDOM_TAPE_CHECK_MAX_HEIGHT_RANGE,
            finalized_height + 1,
        );
        (next_batch_height..=max_height)
            .filter(|h| self.should_create_share(pool, Height::from(*h)))
            .filter_map(|h| self.create_random_tape_share(Height::from(h), pool))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus::{
        add_all_to_validated,
        mocks::{dependencies, Dependencies},
    };
    use ic_interfaces::consensus_pool::MutableConsensusPool;
    use ic_logger::replica_logger::no_op_logger;
    use ic_test_utilities::{consensus::fake::*, message_routing::FakeMessageRouting};

    // Returns the vector of heights for which `changes` contains a ChangeAction
    // that adds a random tape share for that height to the validated pool.
    fn heights_of_added_shares(changes: &[RandomTapeShare]) -> Vec<Height> {
        changes.iter().map(|s| s.height()).collect()
    }

    #[test]
    fn test_random_tape_maker() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            let Dependencies {
                mut pool,
                replica_config,
                membership,
                time_source,
                crypto,
                ..
            } = dependencies(pool_config, 4);
            let message_routing = Arc::new(FakeMessageRouting::new());
            pool.advance_round_normal_operation();
            *message_routing.next_batch_height.write().unwrap() = Height::from(2);

            let random_tape_maker = RandomTapeMaker::new(
                replica_config,
                membership,
                crypto,
                message_routing.clone(),
                no_op_logger(),
            );

            // With a pool with just one block (with finalized height 1) and the next
            // expected batch height 2, we should add one random tape share (for
            // height 2).
            let shares = random_tape_maker.on_state_change(&PoolReader::new(&pool));

            assert_eq!(shares.len(), 1);
            assert_eq!(heights_of_added_shares(&shares), vec![Height::from(2)]);

            // After adding our random tape share for height 2, we should not create
            // any more shares
            pool.apply_changes(time_source.as_ref(), add_all_to_validated(shares));
            let shares = random_tape_maker.on_state_change(&PoolReader::new(&pool));
            assert_eq!(shares.len(), 0);

            // when the finalized chain grows by 3 blocks (to reach finalized height 4), the
            // random_tape_maker should immediately create random tape shares for
            // heights 3, 4, 5.

            let mut round = pool.prepare_round().dont_add_random_tape();
            round.advance();
            round.advance();
            round.advance();
            let shares = random_tape_maker.on_state_change(&PoolReader::new(&pool));
            assert_eq!(shares.len(), 3);
            assert_eq!(
                heights_of_added_shares(&shares),
                vec![Height::from(3), Height::from(4), Height::from(5)]
            );
            // when we advance the pool by three heights again (advancing the finalized
            // height to 7), but we add a full random tape for height 7, we should
            // only construct a share for heights 6 and 8.
            pool.apply_changes(time_source.as_ref(), add_all_to_validated(shares));
            let mut round = pool.prepare_round().dont_add_random_tape();
            round.advance();
            round.advance();
            round.advance();
            pool.insert_validated(ConsensusMessage::RandomTape(RandomTape::fake(
                RandomTapeContent::new(Height::from(7)),
            )));

            let shares = random_tape_maker.on_state_change(&PoolReader::new(&pool));
            assert_eq!(shares.len(), 2);
            assert_eq!(
                heights_of_added_shares(&shares),
                vec![Height::from(6), Height::from(8)]
            );

            // The finalized chain grows by 2 more blocks (now reaching 9), which means the
            // random tape maker would could create shares for heights 9 and 10.
            // However, we let message routing expect batch 10 (indicating that batch
            // 8 already was delivered so there is no need to construct random tape 8
            // anymore. We therefore expect the random tape maker to only add a
            // share for height 10.
            pool.apply_changes(time_source.as_ref(), add_all_to_validated(shares));
            let mut round = pool.prepare_round().dont_add_random_tape();
            round.advance();
            round.advance();
            *message_routing.next_batch_height.write().unwrap() = Height::from(10);

            let shares = random_tape_maker.on_state_change(&PoolReader::new(&pool));
            assert_eq!(shares.len(), 1);
            assert_eq!(heights_of_added_shares(&shares), vec![Height::from(10)]);
        })
    }
}
