//! CatchUpPackage maker is responsible for creating shares for CatchUpPackage.
//! The requirements of when we should create a CatchUpPackage are given below:
//!
//! 1. CatchUpPackage has to include (the block of) a DKG summary that is
//!    considered finalized.
//!
//! 2. DKG has to traverse blocks to lookup DKG payloads, therefore the interval
//!    between CatchUpPackages has to be bigger than or equal to the DKG interval.
//!
//! 3. The block in the CatchUpPackage has been executed, and its execution
//!    state is known.
//!
//! At the moment, we will start to make a CatchUpPackage once a DKG summary
//! block is considered finalized.

use ic_consensus_utils::{
    active_high_threshold_transcript, crypto::ConsensusCrypto,
    get_oldest_idkg_state_registry_version, membership::Membership, pool_reader::PoolReader,
};
use ic_interfaces::messaging::MessageRouting;
use ic_interfaces_state_manager::{
    PermanentStateHashError::*, StateHashError, StateManager, TransientStateHashError::*,
};
use ic_logger::{debug, error, trace, ReplicaLogger};
use ic_replicated_state::ReplicatedState;
use ic_types::{
    consensus::{
        Block, CatchUpContent, CatchUpPackage, CatchUpPackageShare, CatchUpShareContent,
        HasCommittee, HasHeight, HashedBlock, HashedRandomBeacon,
    },
    replica_config::ReplicaConfig,
};
use std::sync::Arc;

/// CatchUpPackage maker is responsible for creating beacon shares
pub struct CatchUpPackageMaker {
    replica_config: ReplicaConfig,
    membership: Arc<Membership>,
    crypto: Arc<dyn ConsensusCrypto>,
    state_manager: Arc<dyn StateManager<State = ReplicatedState>>,
    message_routing: Arc<dyn MessageRouting>,
    log: ReplicaLogger,
}

impl CatchUpPackageMaker {
    /// Instantiate a new CatchUpPackage maker and save a copy of the config.
    pub fn new(
        replica_config: ReplicaConfig,
        membership: Arc<Membership>,
        crypto: Arc<dyn ConsensusCrypto>,
        state_manager: Arc<dyn StateManager<State = ReplicatedState>>,
        message_routing: Arc<dyn MessageRouting>,
        log: ReplicaLogger,
    ) -> Self {
        Self {
            replica_config,
            membership,
            crypto,
            state_manager,
            message_routing,
            log,
        }
    }

    /// Invoke state sync if required. This will call fetch_state repeatedly
    /// as needed, because state sync (or matching against existing state hash
    /// during recovery) happens asynchronously.
    fn invoke_state_sync(&self, pool: &PoolReader<'_>) {
        let catch_up_package = pool.get_highest_catch_up_package();
        let catch_up_height = catch_up_package.height();
        if self.message_routing.expected_batch_height() < catch_up_height {
            // if message routing expects a batch for a height smaller than the
            // height of the latest CUP, we will need to invoke state sync, as
            // the artifacts lower than the CUP height are purged
            let cup_interval_length = catch_up_package
                .content
                .block
                .into_inner()
                .payload
                .as_ref()
                .as_summary()
                .dkg
                .interval_length;

            self.state_manager.fetch_state(
                catch_up_height,
                catch_up_package.content.state_hash,
                cup_interval_length,
            );
        }
    }

    /// Checks if the state hash referenced from the latest CUP matches the one
    /// returned from our local state manager. Report the divergence if it
    /// does not.
    fn report_state_divergence_if_required(&self, pool: &PoolReader<'_>) {
        let catch_up_package = pool.get_highest_catch_up_package();
        if let Ok(hash) = self
            .state_manager
            .get_state_hash_at(catch_up_package.height())
        {
            // Since the genesis CUP contains a dummy state hash, we only perform this check
            // for heights greater than 0.
            if catch_up_package.height().get() > 0 && hash != catch_up_package.content.state_hash {
                // This will delete the diverged states and panic.
                self.state_manager
                    .report_diverged_checkpoint(catch_up_package.height())
            }
        }
    }

    /// If a CatchUpPackageShare should be proposed, propose it.
    pub fn on_state_change(&self, pool: &PoolReader<'_>) -> Option<CatchUpPackageShare> {
        trace!(self.log, "on_state_change");

        // Invoke state sync if required
        self.invoke_state_sync(pool);

        self.report_state_divergence_if_required(pool);

        let current_cup_height = pool.get_catch_up_height();
        let mut block = pool.get_highest_summary_block();

        while block.height() > current_cup_height {
            let result = self.consider_block(pool, block.clone());
            if result.is_some() {
                // If we were able to generate a share, we simply return.
                // Subsequent calls into the catch up package maker will only
                // result in the creation of shares at earlier heights being, if
                // the creation of this share does not result in an aggregated
                // catch up package.
                return result;
            }

            let next_start_height = pool
                .get_finalized_block(block.height.decrement())?
                .payload
                .as_ref()
                .dkg_interval_start_height();
            block = pool.get_finalized_block(next_start_height)?;
        }
        None
    }

    /// Consider the provided block for the creation of a catch up package.
    fn consider_block(
        &self,
        pool: &PoolReader<'_>,
        start_block: Block,
    ) -> Option<CatchUpPackageShare> {
        let height = start_block.height();

        // Skip if this node is not in the committee to make CUP shares
        let my_node_id = self.replica_config.node_id;
        if self.membership.node_belongs_to_threshold_committee(
            my_node_id,
            height,
            CatchUpPackage::committee(),
        ) != Ok(true)
        {
            return None;
        }

        // Skip if this node has already made a share
        if pool
            .get_catch_up_package_shares(height)
            .any(|share| share.signature.signer == my_node_id)
        {
            return None;
        }

        // Skip if random beacon does not exist for the height
        let random_beacon = pool.get_random_beacon(height)?;

        // Skip if the state referenced by finalization tip has not caught up to
        // this height. This is to increase the chance that states are available to
        // validate payloads at the chain tip.
        if pool.get_finalized_tip().context.certified_height < height {
            return None;
        }

        match self.state_manager.get_state_hash_at(height) {
            Err(StateHashError::Transient(StateNotCommittedYet(_))) => {
                // TODO: Setup a delay before retry
                debug!(
                    self.log,
                    "Cannot make CUP at height {} because state is not committed yet. Will retry",
                    height
                );
                None
            }
            Err(StateHashError::Transient(HashNotComputedYet(_))) => {
                debug!(self.log, "Cannot make CUP at height {} because state hash is not computed yet. Will retry", height);
                None
            }
            Err(StateHashError::Permanent(StateRemoved(_))) => {
                // This should never happen as we don't want to remove the state
                // for CUP before the hash is fetched.
                panic!(
                    "State at height {} had disappeared before we had a chance to make a CUP. This should not happen.",
                    height,
                );
            }
            Err(StateHashError::Permanent(StateNotFullyCertified(_))) => {
                panic!(
                    "Height {} is not a fully certified height. This should not happen.",
                    height,
                );
            }
            Ok(state_hash) => {
                let summary = start_block.payload.as_ref().as_summary();
                let registry_version = if let Some(idkg) = summary.idkg.as_ref() {
                    // Should succeed as we already got the hash above
                    let state = self
                        .state_manager
                        .get_state_at(height)
                        .map_err(|err| {
                            error!(
                                self.log,
                                "Cannot make IDKG CUP at height {}: `get_state_hash_at` \
                                succeeded but `get_state_at` failed with {}. Will retry",
                                height,
                                err,
                            )
                        })
                        .ok()?;
                    get_oldest_idkg_state_registry_version(idkg, state.get_ref())
                } else {
                    None
                };
                let content = CatchUpContent::new(
                    HashedBlock::new(ic_types::crypto::crypto_hash, start_block),
                    HashedRandomBeacon::new(ic_types::crypto::crypto_hash, random_beacon),
                    state_hash,
                    registry_version,
                );
                let share_content = CatchUpShareContent::from(&content);
                if let Some(transcript) = active_high_threshold_transcript(pool.as_cache(), height)
                {
                    match self.crypto.sign(&content, my_node_id, transcript.dkg_id) {
                        Ok(signature) => {
                            // Caution: The log string below is checked in replica_determinism_test.
                            // Changing the string might break the test.
                            debug!(
                                self.log,
                                "Proposing a CatchUpPackageShare at height {}", height
                            );
                            Some(CatchUpPackageShare {
                                content: share_content,
                                signature,
                            })
                        }
                        Err(err) => {
                            error!(self.log, "Couldn't create a signature: {:?}", err);
                            None
                        }
                    }
                } else {
                    error!(self.log, "Couldn't find transcript at height {}", height);
                    None
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    //! CatchUpPackageMaker unit tests
    use crate::idkg::test_utils::{
        add_available_quadruple_to_payload, empty_idkg_payload, fake_ecdsa_master_public_key_id,
        fake_signature_request_context_with_pre_sig, fake_state_with_signature_requests,
    };

    use super::*;
    use ic_consensus_mocks::{
        dependencies_with_subnet_params, dependencies_with_subnet_records_with_raw_state_manager,
        Dependencies,
    };
    use ic_logger::replica_logger::no_op_logger;
    use ic_test_utilities::message_routing::FakeMessageRouting;
    use ic_test_utilities_registry::SubnetRecordBuilder;
    use ic_test_utilities_types::ids::{node_test_id, subnet_test_id};
    use ic_types::{
        consensus::{idkg::PreSigId, BlockPayload, Payload, SummaryPayload},
        crypto::CryptoHash,
        CryptoHashOfState, Height, RegistryVersion,
    };
    use std::sync::{Arc, RwLock};

    #[test]
    fn test_catch_up_package_maker() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            let interval_length = 5;
            let committee: Vec<_> = (0..4).map(node_test_id).collect();
            let Dependencies {
                mut pool,
                membership,
                replica_config,
                crypto,
                state_manager,
                ..
            } = dependencies_with_subnet_params(
                pool_config,
                subnet_test_id(0),
                vec![(
                    1,
                    SubnetRecordBuilder::from(&committee)
                        .with_dkg_interval_length(interval_length)
                        .build(),
                )],
            );

            state_manager
                .get_mut()
                .expect_get_state_hash_at()
                .return_const(Ok(CryptoHashOfState::from(CryptoHash(vec![1, 2, 3]))));

            let message_routing = FakeMessageRouting::new();
            *message_routing.next_batch_height.write().unwrap() = Height::from(2);
            let message_routing = Arc::new(message_routing);

            let cup_maker = CatchUpPackageMaker::new(
                replica_config,
                membership,
                crypto,
                state_manager.clone(),
                message_routing,
                no_op_logger(),
            );

            // 1. Genesis CUP already exists, we won't make a new one
            assert!(cup_maker.on_state_change(&PoolReader::new(&pool)).is_none());

            // Skip the first DKG interval
            pool.advance_round_normal_operation_n(interval_length);

            let mut proposal = pool.make_next_block();
            let block = proposal.content.as_mut();
            block.context.certified_height = block.height();
            proposal.content = HashedBlock::new(ic_types::crypto::crypto_hash, block.clone());
            pool.insert_validated(proposal.clone());
            pool.notarize(&proposal);
            pool.finalize(&proposal);

            // 4. Beacon does not exist, we can't make a new CUP share
            assert!(cup_maker.on_state_change(&PoolReader::new(&pool)).is_none());

            // 5. Beacon now exists, we can make a new CUP share
            pool.insert_validated(pool.make_next_beacon());
            let share = cup_maker
                .on_state_change(&PoolReader::new(&pool))
                .expect("Expecting CatchUpPackageShare");

            assert_eq!(&share.content.block, proposal.content.get_hash());
            assert_eq!(
                share.content.state_hash,
                state_manager.get_state_hash_at(Height::from(0)).unwrap()
            );
            assert_eq!(
                share
                    .content
                    .oldest_registry_version_in_use_by_replicated_state,
                None
            );
        })
    }

    #[test]
    fn test_catch_up_package_maker_with_registry_version() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            let interval_length = 5;
            let committee: Vec<_> = (0..4).map(node_test_id).collect();
            let Dependencies {
                mut pool,
                membership,
                replica_config,
                crypto,
                state_manager,
                ..
            } = dependencies_with_subnet_records_with_raw_state_manager(
                pool_config,
                subnet_test_id(0),
                vec![(
                    1,
                    SubnetRecordBuilder::from(&committee)
                        .with_dkg_interval_length(interval_length)
                        .build(),
                )],
            );

            state_manager
                .get_mut()
                .expect_get_state_hash_at()
                .return_const(Ok(CryptoHashOfState::from(CryptoHash(vec![1, 2, 3]))));

            let key_id = fake_ecdsa_master_public_key_id();

            // Create three quadruple Ids and contexts, quadruple "2" will remain unmatched.
            let pre_sig_id1 = PreSigId(1);
            let pre_sig_id2 = PreSigId(2);
            let pre_sig_id3 = PreSigId(3);

            let contexts = vec![
                fake_signature_request_context_with_pre_sig(1, key_id.clone(), Some(pre_sig_id1)),
                fake_signature_request_context_with_pre_sig(2, key_id.clone(), None),
                fake_signature_request_context_with_pre_sig(3, key_id.clone(), Some(pre_sig_id3)),
            ];

            state_manager
                .get_mut()
                .expect_get_state_at()
                .return_const(Ok(fake_state_with_signature_requests(
                    Height::from(0),
                    contexts.clone(),
                )
                .get_labeled_state()));

            let message_routing = FakeMessageRouting::new();
            *message_routing.next_batch_height.write().unwrap() = Height::from(2);
            let message_routing = Arc::new(message_routing);

            let cup_maker = CatchUpPackageMaker::new(
                replica_config,
                membership,
                crypto,
                state_manager.clone(),
                message_routing,
                no_op_logger(),
            );

            // Genesis CUP already exists, we won't make a new one
            assert!(cup_maker.on_state_change(&PoolReader::new(&pool)).is_none());

            // Skip the first DKG interval
            pool.advance_round_normal_operation_n(interval_length);

            let mut proposal = pool.make_next_block();
            let block = proposal.content.as_mut();
            block.context.certified_height = block.height();

            let mut idkg = empty_idkg_payload(subnet_test_id(0));
            // Add the three quadruples using registry version 3, 1 and 2 in order
            add_available_quadruple_to_payload(&mut idkg, pre_sig_id1, RegistryVersion::from(3));
            add_available_quadruple_to_payload(&mut idkg, pre_sig_id2, RegistryVersion::from(1));
            add_available_quadruple_to_payload(&mut idkg, pre_sig_id3, RegistryVersion::from(2));

            let dkg = block.payload.as_ref().as_summary().dkg.clone();
            block.payload = Payload::new(
                ic_types::crypto::crypto_hash,
                BlockPayload::Summary(SummaryPayload {
                    dkg,
                    idkg: Some(idkg),
                }),
            );
            proposal.content = HashedBlock::new(ic_types::crypto::crypto_hash, block.clone());

            pool.advance_round_with_block(&proposal);

            let share = cup_maker
                .on_state_change(&PoolReader::new(&pool))
                .expect("Expecting CatchUpPackageShare");

            assert_eq!(&share.content.block, proposal.content.get_hash());
            assert_eq!(
                share.content.state_hash,
                state_manager.get_state_hash_at(Height::from(0)).unwrap()
            );
            // Since the quadruple using registry version 1 wasn't matched, the oldest one in use
            // by the replicated state should be the registry version of quadruple 3, which is 2.
            assert_eq!(
                share
                    .content
                    .oldest_registry_version_in_use_by_replicated_state,
                Some(RegistryVersion::from(2))
            );
        })
    }

    #[test]
    fn test_invoke_state_sync() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            let interval_length = 3;
            let committee: Vec<_> = (0..5).map(node_test_id).collect();
            let Dependencies {
                mut pool,
                membership,
                replica_config,
                crypto,
                state_manager,
                ..
            } = dependencies_with_subnet_params(
                pool_config,
                subnet_test_id(0),
                vec![(
                    1,
                    SubnetRecordBuilder::from(&committee)
                        .with_dkg_interval_length(interval_length)
                        .build(),
                )],
            );

            pool.advance_round_normal_operation_n(5);
            let cup_height = PoolReader::new(&pool).get_catch_up_height();
            assert_eq!(cup_height, Height::from(4));

            state_manager
                .get_mut()
                .expect_get_state_hash_at()
                .return_const(Ok(CryptoHashOfState::from(CryptoHash(Vec::new()))));

            let fetch_height = Arc::new(RwLock::new(Height::from(0)));
            let fetch_height_cl = fetch_height.clone();
            state_manager.get_mut().expect_fetch_state().returning(
                move |height, _hash, _cup_interval_length| {
                    *fetch_height_cl.write().unwrap() = height;
                },
            );

            let message_routing = FakeMessageRouting::new();
            *message_routing.next_batch_height.write().unwrap() = Height::from(2);
            let message_routing = Arc::new(message_routing);

            let cup_maker = CatchUpPackageMaker::new(
                replica_config,
                membership,
                crypto,
                state_manager,
                message_routing,
                no_op_logger(),
            );

            // Check if fetch state is correctly triggered
            cup_maker.on_state_change(&PoolReader::new(&pool));
            assert_eq!(*fetch_height.read().unwrap(), cup_height);
        })
    }

    #[test]
    fn test_state_divergence_report() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            let interval_length = 3;
            let committee: Vec<_> = (0..5).map(node_test_id).collect();
            let Dependencies {
                mut pool,
                membership,
                replica_config,
                crypto,
                state_manager,
                ..
            } = dependencies_with_subnet_params(
                pool_config,
                subnet_test_id(0),
                vec![(
                    1,
                    SubnetRecordBuilder::from(&committee)
                        .with_dkg_interval_length(interval_length)
                        .build(),
                )],
            );

            state_manager
                .get_mut()
                .expect_fetch_state()
                .return_const(());

            let message_routing = Arc::new(FakeMessageRouting::new());
            let cup_maker = CatchUpPackageMaker::new(
                replica_config,
                membership,
                crypto,
                state_manager.clone(),
                message_routing,
                no_op_logger(),
            );

            pool.advance_round_normal_operation_n(5);
            let cup_height = PoolReader::new(&pool).get_catch_up_height();
            assert_eq!(cup_height, Height::from(4));

            state_manager
                .get_mut()
                .expect_get_state_hash_at()
                .times(1)
                .return_const(Err(StateHashError::Transient(StateNotCommittedYet(
                    cup_height,
                ))));

            // Nothing happens, because the state is not committed yet.
            assert!(cup_maker.on_state_change(&PoolReader::new(&pool)).is_none());

            state_manager
                .get_mut()
                .expect_get_state_hash_at()
                .times(1)
                .return_const(Err(StateHashError::Transient(HashNotComputedYet(
                    cup_height,
                ))));

            // Still nothing happens, because the state hash is not computed
            // yet.
            assert!(cup_maker.on_state_change(&PoolReader::new(&pool)).is_none());

            // Now make the state manager return a hash which differs from the mocked hash
            // in our fixtures (empty one).
            state_manager
                .get_mut()
                .expect_get_state_hash_at()
                .return_const(Ok(CryptoHashOfState::from(CryptoHash(vec![1, 2, 3]))));

            state_manager
                .get_mut()
                .expect_report_diverged_checkpoint()
                .times(1)
                .return_const(());
            cup_maker.on_state_change(&PoolReader::new(&pool));
        })
    }
}
