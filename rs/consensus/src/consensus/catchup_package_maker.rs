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

use crate::consensus::status;
use ic_consensus_utils::{
    active_high_threshold_nidkg_id, crypto::ConsensusCrypto, get_oldest_state_registry_version,
    membership::Membership, pool_reader::PoolReader,
};
use ic_interfaces::messaging::MessageRouting;
use ic_interfaces_state_manager::{
    PermanentStateHashError::*, StateHashError, StateManager, TransientStateHashError::*,
};
use ic_logger::{ReplicaLogger, debug, error, trace};
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
pub(crate) struct CatchUpPackageMaker {
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
        let mut block = pool.get_highest_finalized_summary_block();

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

        let halting = || {
            status::should_halt(
                height,
                self.membership.registry_client.as_ref(),
                self.membership.subnet_id,
                pool,
                &self.log,
            ) == Some(true)
        };
        // Wait for the finalization tip's validation context's certified height to reach the
        // summary height to ensure that states and payloads before the summary are not purged too
        // early: they may still be required to validate non-notarized blocks after the summary.
        // It is only safe to purge these states and payloads once we know that all blocks
        // referencing them have been notarized (which is implied by the condition below), because
        // then, catching up nodes may validate those blocks via the notarization fast path
        // instead, even if the referenced states and payloads no longer exist.
        // Though, we make an exception if we are halting at this height, which was introduced
        // after the incident on subnet `3hhby` on 2026-05-22.
        // Checkpointing was slow at an upgrade boundary, and consensus continued creating blocks
        // until reaching `ACCEPTABLE_NOTARIZATION_CERTIFICATION_GAP`, each with a validation
        // context's certified height equal to the upgrade height minus 1. When checkpointing
        // finally finished, a new certified height was available, but since the block maker is
        // always one height ahead of the notary, we had already created a block, also with a
        // certified height equal to the upgrade height minus 1. The notary would notarize it but
        // reach the bound again. Since the CUP maker (here) waits for the finalized tip's
        // validation context's certified height to reach the upgrade height, no CUP was ever
        // created, and the subnet stalled.
        // By allowing the CUP maker to make a CUP share even when the finalized tip's validation
        // context has not caught up to the CUP height, we can ensure that a CUP will be created.
        // It is not a problem to make this exception, because when we are halting, all blocks have
        // empty payloads, and thus do not need to access states and payloads at the validation
        // context's certified height.
        if pool.get_finalized_tip().context.certified_height < height && !halting() {
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
                debug!(
                    self.log,
                    "Cannot make CUP at height {} because state hash is not computed yet. Will retry",
                    height
                );
                None
            }
            Err(StateHashError::Permanent(StateRemoved(_))) => {
                // This should never happen as we don't want to remove the state
                // for CUP before the hash is fetched.
                panic!(
                    "State at height {height} had disappeared before we had a chance to make a CUP. This should not happen.",
                );
            }
            Err(StateHashError::Permanent(StateNotFullyCertified(_))) => {
                panic!("Height {height} is not a fully certified height. This should not happen.",);
            }
            Ok(state_hash) => {
                // Should succeed as we already got the hash above
                let state = self
                    .state_manager
                    .get_state_at(height)
                    .map_err(|err| {
                        error!(
                            self.log,
                            "Cannot make CUP at height {}: `get_state_hash_at` \
                            succeeded but `get_state_at` failed with {}. Will retry",
                            height,
                            err,
                        )
                    })
                    .ok()?;
                let registry_version = get_oldest_state_registry_version(state.get_ref());
                let content = CatchUpContent::new(
                    HashedBlock::new(ic_types::crypto::crypto_hash, start_block),
                    HashedRandomBeacon::new(ic_types::crypto::crypto_hash, random_beacon),
                    state_hash,
                    registry_version,
                );
                let share_content = CatchUpShareContent::from(&content);
                if let Some(dkg_id) = active_high_threshold_nidkg_id(pool.as_cache(), height) {
                    match self.crypto.sign(&content, my_node_id, dkg_id) {
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
    use super::*;
    use ic_consensus_mocks::{
        Dependencies, dependencies_with_subnet_params,
        dependencies_with_subnet_records_with_raw_state_manager,
    };
    use ic_logger::replica_logger::no_op_logger;
    use ic_protobuf::registry::subnet::v1::SubnetRecord;
    use ic_registry_client_helpers::subnet::SubnetRegistry;
    use ic_replicated_state::metadata_state::subnet_call_context_manager::{
        SetupInitialDkgContext, SignWithThresholdContext,
    };
    use ic_test_utilities::message_routing::FakeMessageRouting;
    use ic_test_utilities_consensus::{
        dkg::fake_setup_initial_dkg_context,
        fake_state_with_contexts,
        idkg::{
            empty_idkg_payload, fake_ecdsa_idkg_master_public_key_id,
            fake_signature_request_context_with_registry_version,
        },
    };
    use ic_test_utilities_registry::SubnetRecordBuilder;
    use ic_test_utilities_types::ids::{node_test_id, subnet_test_id};
    use ic_types::{
        CryptoHashOfState, Height, RegistryVersion,
        consensus::{BlockPayload, BlockProposal, Payload, SummaryPayload, idkg::PreSigId},
        crypto::CryptoHash,
    };
    use rstest::rstest;
    use std::sync::{Arc, RwLock};

    fn assert_cup_share_matches_block_and_state(
        share: &CatchUpPackageShare,
        proposal: &BlockProposal,
        state_manager: &dyn StateManager<State = ReplicatedState>,
        oldest_registry_version_in_use_by_replicated_state: Option<RegistryVersion>,
    ) {
        assert_eq!(&share.content.block, proposal.content.get_hash());
        assert_eq!(
            share.content.state_hash,
            state_manager.get_state_hash_at(proposal.height()).unwrap()
        );
        assert_eq!(
            share
                .content
                .oldest_registry_version_in_use_by_replicated_state,
            oldest_registry_version_in_use_by_replicated_state
        );
    }

    fn with_cup_maker_setup<T>(run: impl FnOnce(CatchUpPackageMaker, u64, Dependencies) -> T) -> T {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            let dkg_interval_length = 5;
            let committee: Vec<_> = (0..4).map(node_test_id).collect();
            let mut deps = dependencies_with_subnet_params(
                pool_config,
                subnet_test_id(0),
                vec![(
                    1,
                    SubnetRecordBuilder::from(&committee)
                        .with_dkg_interval_length(dkg_interval_length)
                        .build(),
                )],
            );

            // Ignore state sync and state divergence
            deps.state_manager
                .get_mut()
                .expect_fetch_state()
                .return_const(());
            deps.state_manager
                .get_mut()
                .expect_report_diverged_checkpoint()
                .return_const(());

            deps.state_manager
                .get_mut()
                .expect_get_state_hash_at()
                .return_const(Ok(CryptoHashOfState::from(CryptoHash(vec![1, 2, 3]))));

            let message_routing = Arc::new(FakeMessageRouting::new());

            let cup_maker = CatchUpPackageMaker::new(
                deps.replica_config.clone(),
                deps.membership.clone(),
                deps.crypto.clone(),
                deps.state_manager.clone(),
                message_routing,
                no_op_logger(),
            );

            // Genesis CUP already exists, we won't make a new one
            assert!(
                cup_maker
                    .on_state_change(&PoolReader::new(&deps.pool))
                    .is_none()
            );
            // Skip the first DKG interval
            deps.pool
                .advance_round_normal_operation_n(dkg_interval_length);

            run(cup_maker, dkg_interval_length, deps)
        })
    }

    #[test]
    fn test_catch_up_package_maker_waits_for_beacon() {
        with_cup_maker_setup(
            |cup_maker,
             _,
             Dependencies {
                 mut pool,
                 state_manager,
                 ..
             }| {
                let mut proposal = pool.make_next_block();
                let block = proposal.content.as_mut();
                block.context.certified_height = block.height();
                proposal.content = HashedBlock::new(ic_types::crypto::crypto_hash, block.clone());
                pool.insert_validated(proposal.clone());
                pool.notarize(&proposal);
                pool.finalize(&proposal);

                // Beacon does not exist, we can't make a new CUP share
                assert!(cup_maker.on_state_change(&PoolReader::new(&pool)).is_none());

                // Beacon now exists, we can make a new CUP share
                pool.insert_validated(pool.make_next_beacon());
                let share = cup_maker
                    .on_state_change(&PoolReader::new(&pool))
                    .expect("Expecting CatchUpPackageShare");

                assert_cup_share_matches_block_and_state(
                    &share,
                    &proposal,
                    state_manager.as_ref(),
                    None,
                );
            },
        )
    }

    #[test]
    fn test_catch_up_package_maker_waits_for_finalized_tip_certified_height_to_reach_cup_height() {
        with_cup_maker_setup(
            |cup_maker,
             _,
             Dependencies {
                 mut pool,
                 state_manager,
                 ..
             }| {
                let mut summary_proposal = pool.make_next_block();
                let summary_block = summary_proposal.content.as_mut();
                let summary_height = summary_block.height();
                summary_block.context.certified_height = summary_height - 1.into();
                summary_proposal.content =
                    HashedBlock::new(ic_types::crypto::crypto_hash, summary_block.clone());
                pool.advance_round_with_block(&summary_proposal);

                // Finalized tip's certified height is behind the CUP height, we can't make a new
                // CUP share
                assert!(cup_maker.on_state_change(&PoolReader::new(&pool)).is_none());

                let mut proposal = pool.make_next_block();
                let block = proposal.content.as_mut();
                block.context.certified_height = summary_height;
                proposal.content = HashedBlock::new(ic_types::crypto::crypto_hash, block.clone());
                pool.advance_round_with_block(&proposal);

                // Finalized tip's certified height has caught up to the CUP height, we can make a
                // new CUP share
                let share = cup_maker
                    .on_state_change(&PoolReader::new(&pool))
                    .expect("Expecting CatchUpPackageShare");

                assert_cup_share_matches_block_and_state(
                    &share,
                    &summary_proposal,
                    state_manager.as_ref(),
                    None,
                );
            },
        )
    }

    #[test]
    fn test_catch_up_package_maker_does_not_wait_for_finalized_tip_when_halting() {
        with_cup_maker_setup(
            |cup_maker,
             dkg_interval_length,
             Dependencies {
                 mut pool,
                 state_manager,
                 registry,
                 registry_data_provider,
                 ..
             }| {
                let existing_subnet_record = registry
                    .get_subnet_record(subnet_test_id(0), registry_data_provider.latest_version())
                    .unwrap()
                    .unwrap();
                let upgrade_registry_version = RegistryVersion::from(10);
                registry_data_provider
                    .add(
                        &ic_registry_keys::make_subnet_record_key(subnet_test_id(0)),
                        upgrade_registry_version,
                        Some(SubnetRecord {
                            replica_version_id: "upgrade_version".to_string(),
                            ..existing_subnet_record
                        }),
                    )
                    .unwrap();
                registry.update_to_latest_version();

                let mut upgrade_proposal = pool.make_next_block();
                let upgrade_block = upgrade_proposal.content.as_mut();
                let mut upgrade_summary = upgrade_block.payload.as_ref().as_summary().clone();
                // Manually modify the summary's registry version to trigger the update
                upgrade_summary.dkg.registry_version = upgrade_registry_version;
                upgrade_block.payload = Payload::new(
                    ic_types::crypto::crypto_hash,
                    BlockPayload::Summary(upgrade_summary),
                );
                upgrade_proposal.content =
                    HashedBlock::new(ic_types::crypto::crypto_hash, upgrade_block.clone());
                pool.advance_round_with_block(&upgrade_proposal);
                pool.insert_validated(pool.make_catch_up_package(upgrade_proposal.height()));

                pool.advance_round_normal_operation_n(dkg_interval_length);

                let mut proposal = pool.make_next_block();
                let block = proposal.content.as_mut();
                block.context.certified_height = block.height() - 1.into();
                proposal.content = HashedBlock::new(ic_types::crypto::crypto_hash, block.clone());
                pool.advance_round_with_block(&proposal);

                // Even if finalized tip's certified height is behind the CUP height, we are halting
                // and thus can make a new CUP share
                let share = cup_maker
                    .on_state_change(&PoolReader::new(&pool))
                    .expect("Expecting CatchUpPackageShare");

                assert_cup_share_matches_block_and_state(
                    &share,
                    &proposal,
                    state_manager.as_ref(),
                    None,
                );
            },
        )
    }

    /// Build a vector of signature contexts where the oldest matched
    /// pre-signature is pinned at `RegistryVersion(2)`. The unmatched context
    /// at `RegistryVersion(1)` should be ignored.
    fn signature_contexts_with_oldest_v2() -> Vec<SignWithThresholdContext> {
        let key_id = fake_ecdsa_idkg_master_public_key_id();
        vec![
            fake_signature_request_context_with_registry_version(
                Some(PreSigId(1)),
                key_id.inner(),
                RegistryVersion::from(3),
            ),
            fake_signature_request_context_with_registry_version(
                None,
                key_id.inner(),
                RegistryVersion::from(1),
            ),
            fake_signature_request_context_with_registry_version(
                Some(PreSigId(3)),
                key_id.inner(),
                RegistryVersion::from(2),
            ),
        ]
    }

    /// A single signature context pinning `RegistryVersion(5)`.
    fn signature_contexts_pinning_v5() -> Vec<SignWithThresholdContext> {
        let key_id = fake_ecdsa_idkg_master_public_key_id();
        vec![fake_signature_request_context_with_registry_version(
            Some(PreSigId(1)),
            key_id.inner(),
            RegistryVersion::from(5),
        )]
    }

    #[rstest]
    #[case::sign_requests_only(signature_contexts_with_oldest_v2(), vec![])]
    #[case::setup_initial_dkg_only(
        vec![],
        vec![fake_setup_initial_dkg_context(RegistryVersion::from(2))],
    )]
    #[case::signature_older_than_setup_initial_dkg(
        signature_contexts_with_oldest_v2(),
        vec![fake_setup_initial_dkg_context(RegistryVersion::from(5))],
    )]
    #[case::setup_initial_dkg_older_than_signature(
        signature_contexts_pinning_v5(),
        vec![fake_setup_initial_dkg_context(RegistryVersion::from(2))],
    )]
    fn test_catch_up_package_maker_with_registry_version(
        #[case] signature_contexts: Vec<SignWithThresholdContext>,
        #[case] setup_initial_dkg_contexts: Vec<SetupInitialDkgContext>,
        #[values(true, false)] with_idkg_payload: bool,
    ) {
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

            let height = Height::from(0);
            state_manager
                .get_mut()
                .expect_get_state_hash_at()
                .return_const(Ok(CryptoHashOfState::from(CryptoHash(vec![1, 2, 3]))));

            state_manager
                .get_mut()
                .expect_get_state_at()
                .return_const(Ok(fake_state_with_contexts(
                    height,
                    signature_contexts,
                    setup_initial_dkg_contexts,
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

            if with_idkg_payload {
                let idkg = empty_idkg_payload(subnet_test_id(0));
                let dkg = block.payload.as_ref().as_summary().dkg.clone();
                block.payload = Payload::new(
                    ic_types::crypto::crypto_hash,
                    BlockPayload::Summary(SummaryPayload {
                        dkg,
                        idkg: Some(idkg),
                    }),
                );
            }
            proposal.content = HashedBlock::new(ic_types::crypto::crypto_hash, block.clone());

            pool.advance_round_with_block(&proposal);

            let share = cup_maker
                .on_state_change(&PoolReader::new(&pool))
                .expect("Expecting CatchUpPackageShare");

            assert_eq!(&share.content.block, proposal.content.get_hash());
            assert_eq!(
                share.content.state_hash,
                state_manager.get_state_hash_at(height).unwrap()
            );
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
