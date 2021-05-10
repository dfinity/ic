//! Random beacon maker is responsible for creating random beacon share
//! for the node if the node is a beacon maker and no such share exists.
use crate::consensus::{
    membership::{Membership, MembershipError},
    pool_reader::PoolReader,
    prelude::*,
    utils::active_low_threshold_transcript,
    ConsensusCrypto,
};
use ic_logger::{error, trace, ReplicaLogger};
use ic_types::replica_config::ReplicaConfig;
use std::sync::Arc;

/// Random beacon maker is responsible for creating beacon shares
pub struct RandomBeaconMaker {
    replica_config: ReplicaConfig,
    membership: Arc<Membership>,
    crypto: Arc<dyn ConsensusCrypto>,
    log: ReplicaLogger,
}

impl<'a> RandomBeaconMaker {
    /// Instantiate a new random beacon maker and save a copy of the config.
    pub fn new(
        replica_config: ReplicaConfig,
        membership: Arc<Membership>,
        crypto: Arc<dyn ConsensusCrypto>,
        log: ReplicaLogger,
    ) -> Self {
        Self {
            replica_config,
            membership,
            crypto,
            log,
        }
    }

    /// If a beacon share should be proposed, propose it.
    pub fn on_state_change(&self, pool: &PoolReader<'_>) -> Option<RandomBeaconShare> {
        trace!(self.log, "on_state_change");
        let my_node_id = self.replica_config.node_id;
        let height = pool.get_notarized_height();
        let beacon = pool.get_random_beacon(height)?;
        let next_height = height.increment();
        let next_beacon = pool.get_random_beacon(next_height);
        match self.membership.node_belongs_to_threshold_committee(
            my_node_id,
            next_height,
            RandomBeacon::committee(),
        ) {
            Err(MembershipError::RegistryClientError(_)) => None,
            Err(MembershipError::NodeNotFound(_)) => {
                panic!("This node does not belong to this subnet")
            }
            Err(MembershipError::UnableToRetrieveDkgSummary(h)) => {
                error!(
                    self.log,
                    "Couldn't find transcript at height {} with finalized height {} and CUP height {}",
                    h,
                    pool.get_finalized_height(),
                    pool.get_catch_up_height()
                );
                None
            }
            Ok(is_beacon_maker)
                if is_beacon_maker
                    && next_beacon.is_none()
                    && pool
                        .get_random_beacon_shares(next_height)
                        .find(|s| s.signature.signer == my_node_id)
                        .is_none() =>
            {
                let content =
                    RandomBeaconContent::new(next_height, ic_crypto::crypto_hash(&beacon));
                // One might wonder whether it is appropriate to use the
                // dkg_id from the start_block at h to generate the
                // random beacon at height h. The reason this is
                // possible is because we actually generate the random
                // beacon at height h only after there exists a block at
                // height h, and we only use the random beacon at height
                // h-1 in the validation of blocks at height h.
                if let Some(transcript) =
                    active_low_threshold_transcript(pool.as_cache(), next_height)
                {
                    match self.crypto.sign(&content, my_node_id, transcript.dkg_id) {
                        Ok(signature) => Some(RandomBeaconShare { content, signature }),
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
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    //! BeaconMaker unit tests
    use super::*;
    use crate::consensus::mocks::{dependencies, Dependencies};
    use ic_interfaces::consensus_pool::ConsensusPool;
    use ic_logger::replica_logger::no_op_logger;

    #[test]
    fn test_beacon_maker() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            let Dependencies {
                mut pool,
                membership,
                replica_config,
                crypto,
                ..
            } = dependencies(pool_config, 1);

            let beacon_maker =
                RandomBeaconMaker::new(replica_config, membership, crypto, no_op_logger());

            // 1. Make the next beacon share
            let beacon_share = beacon_maker
                .on_state_change(&PoolReader::new(&pool))
                .expect("Expecting RandomBeaconShare");

            // 2. Skip making another share
            pool.insert_validated(beacon_share);
            assert!(beacon_maker
                .on_state_change(&PoolReader::new(&pool))
                .is_none());

            // 3. Next next beacon can't be made due to missing notarized block
            pool.insert_validated(pool.make_next_beacon());
            assert!(beacon_maker
                .on_state_change(&PoolReader::new(&pool))
                .is_none());

            // 4. Next next beacon can be made once we have another block
            let beacon = pool.validated().random_beacon().get_highest().unwrap();
            let next_block = pool.make_next_block();
            pool.insert_validated(next_block.clone());
            pool.notarize(&next_block);
            let beacon_share = beacon_maker
                .on_state_change(&PoolReader::new(&pool))
                .expect("Expecting RandomBeaconShare");
            assert!(beacon_share.content.parent == ic_crypto::crypto_hash(&beacon));
        })
    }
}
