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
use ic_consensus_dkg::payload_builder::get_post_split_dkg_summary;
use ic_consensus_utils::{
    crypto::ConsensusCrypto, get_current_transcript_from_summary_block,
    get_oldest_state_registry_version, membership::Membership, pool_reader::PoolReader,
    subnet_splitting,
};
use ic_interfaces::messaging::MessageRouting;
use ic_interfaces_registry::RegistryClient;
use ic_interfaces_state_manager::{
    PermanentStateHashError::*, StateHashError, StateManager, TransientStateHashError::*,
};
use ic_logger::{ReplicaLogger, debug, error, trace, warn};
use ic_replicated_state::ReplicatedState;
use ic_types::{
    Height, NodeId, SubnetId,
    batch::ValidationContext,
    consensus::{
        Block, BlockPayload, CatchUpContent, CatchUpPackageShare, CatchUpShareContent, HasHeight,
        HashedBlock, HashedRandomBeacon, Payload, RandomBeacon, RandomBeaconContent, Rank,
        SummaryPayload, catchup::CatchUpPackageType,
    },
    crypto::{
        CombinedThresholdSig, CombinedThresholdSigOf, CryptoHash, CryptoHashOf, Signed,
        crypto_hash, threshold_sig::ni_dkg::NiDkgTag,
    },
    replica_config::ReplicaConfig,
    signature::ThresholdSignature,
};
use std::sync::Arc;

/// [`CatchUpPackage`] maker is responsible for creating CUP shares
pub(crate) struct CatchUpPackageMaker {
    replica_config: ReplicaConfig,
    membership: Arc<Membership>,
    crypto: Arc<dyn ConsensusCrypto>,
    state_manager: Arc<dyn StateManager<State = ReplicatedState>>,
    message_routing: Arc<dyn MessageRouting>,
    registry: Arc<dyn RegistryClient>,
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
        registry: Arc<dyn RegistryClient>,
        log: ReplicaLogger,
    ) -> Self {
        Self {
            replica_config,
            membership,
            crypto,
            state_manager,
            message_routing,
            registry,
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
    pub(crate) fn consider_block(
        &self,
        pool: &PoolReader<'_>,
        start_block: Block,
    ) -> Option<CatchUpPackageShare> {
        let summary_height = start_block.height();

        let cup_type = get_catch_up_package_type(
            self.registry.as_ref(),
            self.replica_config.node_id,
            &start_block,
        )
        .inspect_err(|err| {
            warn!(
                every_n_seconds => 5,
                self.log,
                "Failed to get the catch up package type: {err}",
            )
        })
        .ok()?;

        let cup_height = self.get_cup_height(&start_block, cup_type);

        let my_node_id = self.replica_config.node_id;
        // Skip if this node has already made a share
        if pool
            .get_catch_up_package_shares(cup_height)
            .any(|share| share.signature.signer == my_node_id)
        {
            return None;
        }

        let halting = || {
            status::should_halt(
                summary_height,
                Some(&start_block),
                self.membership.registry_client.as_ref(),
                self.membership.subnet_id,
                pool,
                &self.replica_config.replica_version,
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
        if pool.get_finalized_tip().context.certified_height < summary_height && !halting() {
            return None;
        }

        let state_hash = match self.state_manager.get_state_hash_at(summary_height) {
            Ok(state_hash) => state_hash,
            Err(StateHashError::Transient(StateNotCommittedYet(_))) => {
                // TODO: Setup a delay before retry
                debug!(
                    every_n_seconds => 5,
                    self.log,
                    "Cannot make CUP at height {} because \
                    state is not committed yet. Will retry",
                    summary_height
                );
                return None;
            }
            Err(StateHashError::Transient(HashNotComputedYet(_))) => {
                debug!(
                    every_n_seconds => 5,
                    self.log,
                    "Cannot make CUP at height {} because \
                    state hash is not computed yet. Will retry",
                    summary_height
                );
                return None;
            }
            Err(StateHashError::Permanent(StateRemoved(_))) => {
                // This should never happen as we don't want to remove the state
                // for CUP before the hash is fetched.
                panic!(
                    "State at height {summary_height} had disappeared before \
                    we had a chance to make a CUP. \
                    This should not happen.",
                );
            }
            Err(StateHashError::Permanent(StateNotFullyCertified(_))) => {
                panic!(
                    "Height {summary_height} is not a fully certified height. \
                    This should not happen.",
                );
            }
        };

        // Should succeed as we already got the hash above
        let state = self
            .state_manager
            .get_state_at(summary_height)
            .inspect_err(|err| {
                error!(
                    every_n_seconds => 5,
                    self.log,
                    "Cannot make CUP at height {summary_height}: `get_state_hash_at` \
                    succeeded but `get_state_at` failed with {err}. Will retry",
                )
            })
            .ok()?;
        let oldest_registry_version_in_use_by_replicated_state =
            get_oldest_state_registry_version(state.get_ref());

        let cup_block = self
            .get_cup_block(start_block, cup_type)
            .inspect_err(|err| {
                warn!(
                    every_n_seconds => 5,
                    self.log,
                    "Couldn't get a block for a CUP: {err}",
                )
            })
            .ok()?;

        let random_beacon = self
            .get_cup_random_beacon(pool, &cup_block, cup_type)
            .inspect_err(|err| {
                warn!(
                    every_n_seconds => 5,
                    self.log,
                    "Couldn't get a random beacon for a CUP: {err}",
                )
            })
            .ok()?;

        let high_threshold_transcript =
            get_current_transcript_from_summary_block(&cup_block, &NiDkgTag::HighThreshold)
                .or_else(|| {
                    warn!(
                        every_n_seconds => 5,
                        self.log,
                        "Couldn't find transcript at height {cup_height}",
                    );
                    None
                })?;
        // Skip if this node is not in the committee to make CUP shares
        if !high_threshold_transcript
            .committee
            .get()
            .contains(&my_node_id)
        {
            return None;
        }

        let high_dkg_id = high_threshold_transcript.dkg_id.clone();
        let content = CatchUpContent::new(
            HashedBlock::new(ic_types::crypto::crypto_hash, cup_block),
            HashedRandomBeacon::new(ic_types::crypto::crypto_hash, random_beacon),
            state_hash,
            oldest_registry_version_in_use_by_replicated_state,
        );
        let share_content = CatchUpShareContent::from(&content);
        let signature = self
            .crypto
            .sign(&content, my_node_id, high_dkg_id)
            .inspect_err(|err| {
                error!(
                    every_n_seconds => 5,
                    self.log,
                    "Couldn't create a signature at height {cup_height}: {err}",
                )
            })
            .ok()?;

        debug!(
            every_n_seconds => 5,
            self.log,
            "Proposing a CatchUpPackageShare (type: {cup_type:?}) at height {cup_height}",
        );
        Some(CatchUpPackageShare {
            content: share_content,
            signature,
        })
    }

    fn get_cup_height(&self, summary_block: &Block, cup_type: CatchUpPackageType) -> Height {
        // IMPORTANT: keep this in sync with the height of the block returned by `get_cup_block`.
        match cup_type {
            CatchUpPackageType::Normal => summary_block.height(),
            // During subnet splitting we skip one DKG interval
            CatchUpPackageType::PostSplit { .. } => summary_block
                .payload
                .as_ref()
                .as_summary()
                .dkg
                .get_next_start_height(),
        }
    }

    fn get_cup_block(
        &self,
        summary_block: Block,
        cup_type: CatchUpPackageType,
    ) -> Result<Block, String> {
        #[cfg(debug_assertions)]
        let expected_height = self.get_cup_height(&summary_block, cup_type);

        let cup_block = match cup_type {
            CatchUpPackageType::Normal => summary_block,
            CatchUpPackageType::PostSplit { new_subnet_id } => create_post_split_summary_block(
                &summary_block,
                new_subnet_id,
                self.registry.as_ref(),
            )
            .map_err(|err| format!("Failed to create a post split block: {err}"))?,
        };

        #[cfg(debug_assertions)]
        assert_eq!(
            cup_block.height(),
            expected_height,
            "The CUP block height should match the expected CUP height"
        );

        Ok(cup_block)
    }

    fn get_cup_random_beacon(
        &self,
        pool: &PoolReader<'_>,
        cup_block: &Block,
        cup_type: CatchUpPackageType,
    ) -> Result<RandomBeacon, String> {
        match cup_type {
            CatchUpPackageType::Normal => pool
                .get_random_beacon(cup_block.height())
                .ok_or_else(|| format!("No random beacon found at height {}", cup_block.height())),
            // During subnet splitting we create a dummy, unsigned random beacon, because at the
            // height at which we are building a CUP, we won't have a random beacon.
            CatchUpPackageType::PostSplit { .. } => create_post_split_random_beacon(cup_block),
        }
    }
}

pub(crate) fn get_catch_up_package_type(
    registry: &dyn RegistryClient,
    node_id: NodeId,
    summary_block: &Block,
) -> Result<CatchUpPackageType, String> {
    let Some(splitting_args) = subnet_splitting::is_split_scheduled(summary_block) else {
        return Ok(CatchUpPackageType::Normal);
    };

    subnet_splitting::get_post_split_subnet_assignment(
        node_id,
        summary_block,
        registry,
        splitting_args,
    )
    .map(|assignment| CatchUpPackageType::PostSplit {
        new_subnet_id: assignment.new_subnet_id,
    })
    .map_err(|err| format!("Failed to get the new subnet assignment: {err}"))
}

pub(crate) fn create_post_split_summary_block(
    splitting_summary_block: &Block,
    subnet_id: SubnetId,
    registry: &dyn RegistryClient,
) -> Result<Block, String> {
    let post_split_dkg_summary =
        get_post_split_dkg_summary(subnet_id, registry, splitting_summary_block)
            .map_err(|err| format!("Failed to get post-split DKG summary: {err}"))?;

    let post_split_height = post_split_dkg_summary.height;
    Ok(Block {
        version: splitting_summary_block.version.clone(),
        // Fake parent
        parent: CryptoHashOf::from(CryptoHash(vec![])),
        payload: Payload::new(
            crypto_hash,
            BlockPayload::Summary(SummaryPayload {
                dkg: post_split_dkg_summary,
                // Splitting a chain-key enabled subnet is not supported yet
                idkg: None,
            }),
        ),
        height: post_split_height,
        rank: Rank(0),
        context: ValidationContext {
            registry_version: splitting_summary_block.context.registry_version,
            certified_height: post_split_height,
            // time needs to be strictly increasing
            time: splitting_summary_block.context.time + std::time::Duration::from_millis(1),
        },
    })
}

// During subnet splitting we create a dummy, unsigned random beacon, because at the
// height at which we are building a CUP, we won't have a random beacon.
pub(crate) fn create_post_split_random_beacon(cup_block: &Block) -> Result<RandomBeacon, String> {
    let transcript = get_current_transcript_from_summary_block(cup_block, &NiDkgTag::LowThreshold)
        .ok_or_else(|| {
            format!(
                "Couldn't find post-split transcript at height {}",
                cup_block.height(),
            )
        })?;

    Ok(Signed {
        content: RandomBeaconContent {
            version: cup_block.version.clone(),
            height: cup_block.height(),
            parent: CryptoHashOf::from(CryptoHash(vec![])),
        },
        signature: ThresholdSignature {
            signer: transcript.dkg_id.clone(),
            signature: CombinedThresholdSigOf::new(CombinedThresholdSig(vec![])),
        },
    })
}

#[cfg(test)]
mod tests {
    //! CatchUpPackageMaker unit tests
    use super::*;
    use ic_consensus_mocks::{Dependencies, DependenciesBuilder};
    use ic_consensus_utils::subnet_splitting::PostSplitAssignmentError;
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
    use ic_test_utilities_logger::with_test_replica_logger;
    use ic_test_utilities_registry::{SubnetRecordBuilder, insert_initial_dkg_transcript};
    use ic_test_utilities_types::ids::{subnet_test_id, test_replica_version};
    use ic_types::{
        CryptoHashOfState, Height, NodeId, RegistryVersion,
        consensus::{
            BlockPayload, BlockProposal, ConsensusMessageHashable, HasVersion, Payload,
            SummaryPayload,
            dkg::{SplittingArgs, SubnetSplittingStatus},
            idkg::PreSigId,
        },
        crypto::CryptoHash,
    };
    use ic_types_test_utils::ids::{NODE_1, NODE_2, NODE_3, NODE_4, NODE_5};
    use ic_types_test_utils::ids::{SUBNET_1, SUBNET_2, SUBNET_3};
    use rstest::rstest;
    use std::collections::BTreeSet;
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
            let mut deps = DependenciesBuilder::new(pool_config, 4)
                .with_dkg_interval_length(dkg_interval_length)
                .build();

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
                deps.registry.clone(),
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
    fn test_consistency_cup_type_height_block() {
        with_cup_maker_setup(|cup_maker, _, Dependencies { pool, .. }| {
            let proposal = pool.make_next_block();
            let block = proposal.content.as_ref();
            let cup_type = get_catch_up_package_type(
                cup_maker.registry.as_ref(),
                cup_maker.replica_config.node_id,
                block,
            )
            .expect("Failed to get CUP type");
            assert_eq!(cup_type, CatchUpPackageType::Normal);
            let cup_height = cup_maker.get_cup_height(block, cup_type);
            let cup_block = cup_maker
                .get_cup_block(block.clone(), cup_type)
                .expect("Failed to get CUP block");
            assert_eq!(cup_height, cup_block.height());
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
            let Dependencies {
                mut pool,
                membership,
                replica_config,
                crypto,
                registry,
                state_manager,
                ..
            } = DependenciesBuilder::new(pool_config, 4)
                .with_dkg_interval_length(interval_length)
                .without_state_manager_expectations()
                .build();

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
                registry,
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
            let Dependencies {
                mut pool,
                membership,
                replica_config,
                registry,
                crypto,
                state_manager,
                ..
            } = DependenciesBuilder::new(pool_config, 5)
                .with_dkg_interval_length(interval_length)
                .build();

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
                registry,
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
            let Dependencies {
                mut pool,
                membership,
                replica_config,
                crypto,
                state_manager,
                registry,
                ..
            } = DependenciesBuilder::new(pool_config, 5)
                .with_dkg_interval_length(interval_length)
                .build();

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
                registry,
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

    const SOURCE_SUBNET_ID: SubnetId = SUBNET_1;
    const DESTINATION_SUBNET_ID: SubnetId = SUBNET_2;
    const INITIAL_REGISTRY_VERSION: RegistryVersion = RegistryVersion::new(1);
    const SPLITTING_REGISTRY_VERSION: RegistryVersion = RegistryVersion::new(2);
    const INTERVAL_LENGTH: Height = Height::new(9);

    // In this test the subnet initially has 4 nodes, and after the split `NODE_1, NODE_2` will stay
    // in the original subnet, and `NODE_3, NODE_4` will be moved to a new one.
    #[rstest]
    #[case::source_subnet_node(NODE_1, SOURCE_SUBNET_ID, &[NODE_1, NODE_2])]
    #[case::source_subnet_node(NODE_2, SOURCE_SUBNET_ID, &[NODE_1, NODE_2])]
    #[case::destination_subnet_node(NODE_3, DESTINATION_SUBNET_ID, &[NODE_3, NODE_4])]
    #[case::destination_subnet_node(NODE_4, DESTINATION_SUBNET_ID, &[NODE_3, NODE_4])]
    #[trace]
    fn create_post_split_cup_share_test(
        #[case] node_id: NodeId,
        // The subnet the node lands on after the split, which determines the block it puts into
        // the CUP
        #[case] expected_new_subnet_id: SubnetId,
        // The membership of `expected_new_subnet_id` after the split
        #[case] expected_committee: &[NodeId],
        #[values(Height::new(0), Height::new(1000))] context_certified_height: Height,
    ) {
        with_test_replica_logger(|log| {
            ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
                let Dependencies {
                    mut pool,
                    membership,
                    registry,
                    registry_data_provider,
                    crypto,
                    state_manager,
                    replica_config,
                    ..
                } = DependenciesBuilder::multiple_subnets(
                    pool_config,
                    vec![
                        (
                            INITIAL_REGISTRY_VERSION.get(),
                            SOURCE_SUBNET_ID,
                            SubnetRecordBuilder::from(&[NODE_1, NODE_2, NODE_3, NODE_4])
                                .with_dkg_interval_length(INTERVAL_LENGTH.get())
                                .build(),
                        ),
                        (
                            SPLITTING_REGISTRY_VERSION.get(),
                            SOURCE_SUBNET_ID,
                            SubnetRecordBuilder::from(&[NODE_1, NODE_2])
                                .with_dkg_interval_length(INTERVAL_LENGTH.get())
                                .build(),
                        ),
                        (
                            SPLITTING_REGISTRY_VERSION.get(),
                            DESTINATION_SUBNET_ID,
                            SubnetRecordBuilder::from(&[NODE_3, NODE_4])
                                .with_dkg_interval_length(INTERVAL_LENGTH.get())
                                .build(),
                        ),
                    ],
                )
                .with_replica_config(ReplicaConfig {
                    node_id,
                    subnet_id: SOURCE_SUBNET_ID,
                    replica_version: test_replica_version(),
                })
                .build();
                // Manually insert DKG transcripts at the splitting version to simulate what the
                // registry would do. The setup above only inserts the transcripts at the initial
                // version.
                insert_initial_dkg_transcript(
                    SPLITTING_REGISTRY_VERSION.get(),
                    SOURCE_SUBNET_ID,
                    &SubnetRecordBuilder::from(&[NODE_1, NODE_2])
                        .with_dkg_interval_length(INTERVAL_LENGTH.get())
                        .build(),
                    &registry_data_provider,
                );
                registry.reload();

                let fake_state_hash = CryptoHashOfState::from(CryptoHash(vec![1, 2, 3]));
                state_manager
                    .get_mut()
                    .expect_get_state_hash_at()
                    .return_const(Ok(fake_state_hash.clone()));

                let message_routing = FakeMessageRouting::new();
                *message_routing.next_batch_height.write().unwrap() = Height::from(2);
                let message_routing = Arc::new(message_routing);

                let cup_maker = CatchUpPackageMaker::new(
                    replica_config.clone(),
                    membership,
                    crypto,
                    state_manager,
                    message_routing,
                    registry.clone(),
                    log,
                );

                pool.advance_round_normal_operation_n(INTERVAL_LENGTH.get());

                let subnet_splitting_status = SubnetSplittingStatus::Scheduled(SplittingArgs {
                    source_subnet_id: SOURCE_SUBNET_ID,
                    destination_subnet_id: DESTINATION_SUBNET_ID,
                });
                let mut proposal = pool.make_next_block();
                let block = proposal.content.as_mut();
                block.context.certified_height = context_certified_height;
                block.context.registry_version = SPLITTING_REGISTRY_VERSION;
                let mut payload = block.payload.as_ref().as_summary().clone();
                payload.dkg.subnet_splitting_status = subnet_splitting_status;
                block.payload = Payload::new(
                    ic_types::crypto::crypto_hash,
                    BlockPayload::Summary(payload),
                );
                proposal.content = HashedBlock::new(ic_types::crypto::crypto_hash, block.clone());
                pool.insert_validated(proposal.clone());
                pool.notarize(&proposal);
                pool.finalize(&proposal);

                // Consistency-check between `get_catch_up_package_type`, get_cup_height` and `get_cup_block`
                let block = proposal.content.as_ref();
                let cup_type =
                    get_catch_up_package_type(registry.as_ref(), replica_config.node_id, block)
                        .expect("Failed to get CUP type");
                assert_eq!(
                    cup_type,
                    CatchUpPackageType::PostSplit {
                        new_subnet_id: expected_new_subnet_id
                    }
                );
                let cup_height = cup_maker.get_cup_height(block, cup_type);
                let cup_block = cup_maker
                    .get_cup_block(block.clone(), cup_type)
                    .expect("Failed to get CUP block");
                assert_eq!(cup_height, cup_block.height());

                let share = cup_maker
                    .consider_block(&PoolReader::new(&pool), proposal.content.as_ref().clone())
                    .expect("Should succeed with valid inputs");

                assert!(share.check_integrity());
                assert_eq!(share.content.version, *proposal.content.version());

                // The share only carries the hash of the CUP block, so instead of pinning that
                // hash we re-derive the two blocks the node could have chosen from, and check that
                // it chose the one belonging to the subnet it lands on.
                let post_split_block = |subnet_id| {
                    create_post_split_summary_block(
                        proposal.content.as_ref(),
                        subnet_id,
                        registry.as_ref(),
                    )
                    .expect("Should be able to create a post split block")
                };
                let other_subnet_id = if expected_new_subnet_id == SOURCE_SUBNET_ID {
                    DESTINATION_SUBNET_ID
                } else {
                    SOURCE_SUBNET_ID
                };
                let expected_block = post_split_block(expected_new_subnet_id);
                let other_block = post_split_block(other_subnet_id);

                // Like a genesis or recovery CUP block, a post-split block is built from registry
                // CUP contents, and records the same registry version in its DKG summary and in
                // its validation context.
                assert_eq!(
                    expected_block
                        .payload
                        .as_ref()
                        .as_summary()
                        .dkg
                        .registry_version,
                    expected_block.context.registry_version,
                );
                assert_eq!(
                    expected_block.context.registry_version,
                    SPLITTING_REGISTRY_VERSION,
                );

                // The DKG transcripts of the post-split block are the ones of the subnet the node
                // lands on, i.e. their committee is that subnet's membership ...
                let expected_committee =
                    expected_committee.iter().copied().collect::<BTreeSet<_>>();
                for tag in [NiDkgTag::LowThreshold, NiDkgTag::HighThreshold] {
                    assert_eq!(
                        get_current_transcript_from_summary_block(&expected_block, &tag)
                            .expect("Post split block should contain a current transcript")
                            .committee
                            .get(),
                        &expected_committee,
                    );
                }
                // ... which is why nodes landing on different subnets create different blocks.
                assert_ne!(crypto_hash(&expected_block), crypto_hash(&other_block));

                assert_eq!(share.content.block, crypto_hash(&expected_block));
                assert_eq!(
                    share.content.random_beacon.get_value().content.height,
                    proposal.content.height() + INTERVAL_LENGTH + Height::new(1),
                );
                assert_eq!(
                    share.content.random_beacon.get_value().content.version,
                    *proposal.content.version(),
                );
                assert_eq!(share.content.state_hash, fake_state_hash);
                assert_eq!(
                    share
                        .content
                        .oldest_registry_version_in_use_by_replicated_state,
                    None
                );
                assert_eq!(share.signature.signer, node_id);
            })
        })
    }

    // During a scheduled subnet split, a node which ends up neither in the source subnet nor in
    // the destination subnet cannot determine the type of the CUP to create, and thus should not
    // create any CUP share.
    #[rstest]
    #[case::node_unassigned_after_split(None)]
    #[case::node_moved_to_unrelated_subnet(Some(SUBNET_3))]
    #[trace]
    fn no_post_split_cup_share_for_node_outside_both_subnets_test(
        #[case] new_subnet_of_cup_maker: Option<SubnetId>,
    ) {
        with_test_replica_logger(|log| {
            ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
                let mut records = vec![
                    (
                        INITIAL_REGISTRY_VERSION.get(),
                        SOURCE_SUBNET_ID,
                        SubnetRecordBuilder::from(&[NODE_1, NODE_2, NODE_3, NODE_4, NODE_5])
                            .with_dkg_interval_length(INTERVAL_LENGTH.get())
                            .build(),
                    ),
                    (
                        SPLITTING_REGISTRY_VERSION.get(),
                        SOURCE_SUBNET_ID,
                        SubnetRecordBuilder::from(&[NODE_1, NODE_2])
                            .with_dkg_interval_length(INTERVAL_LENGTH.get())
                            .build(),
                    ),
                    (
                        SPLITTING_REGISTRY_VERSION.get(),
                        DESTINATION_SUBNET_ID,
                        SubnetRecordBuilder::from(&[NODE_3, NODE_4])
                            .with_dkg_interval_length(INTERVAL_LENGTH.get())
                            .build(),
                    ),
                ];
                if let Some(subnet_id) = new_subnet_of_cup_maker {
                    records.push((
                        SPLITTING_REGISTRY_VERSION.get(),
                        subnet_id,
                        SubnetRecordBuilder::from(&[NODE_5])
                            .with_dkg_interval_length(INTERVAL_LENGTH.get())
                            .build(),
                    ));
                }

                let Dependencies {
                    mut pool,
                    membership,
                    registry,
                    crypto,
                    state_manager,
                    replica_config,
                    ..
                } = DependenciesBuilder::multiple_subnets(pool_config, records)
                    .with_replica_config(ReplicaConfig {
                        node_id: NODE_5,
                        subnet_id: SOURCE_SUBNET_ID,
                        replica_version: test_replica_version(),
                    })
                    .build();

                let fake_state_hash = CryptoHashOfState::from(CryptoHash(vec![1, 2, 3]));
                state_manager
                    .get_mut()
                    .expect_get_state_hash_at()
                    .return_const(Ok(fake_state_hash.clone()));

                let message_routing = FakeMessageRouting::new();
                *message_routing.next_batch_height.write().unwrap() = Height::from(2);
                let message_routing = Arc::new(message_routing);

                let cup_maker = CatchUpPackageMaker::new(
                    replica_config.clone(),
                    membership,
                    crypto,
                    state_manager,
                    message_routing,
                    registry.clone(),
                    log,
                );

                pool.advance_round_normal_operation_n(INTERVAL_LENGTH.get());

                let subnet_splitting_status = SubnetSplittingStatus::Scheduled(SplittingArgs {
                    source_subnet_id: SOURCE_SUBNET_ID,
                    destination_subnet_id: DESTINATION_SUBNET_ID,
                });
                let mut proposal = pool.make_next_block();
                let block = proposal.content.as_mut();
                block.context.certified_height = block.height;
                block.context.registry_version = SPLITTING_REGISTRY_VERSION;
                let mut payload = block.payload.as_ref().as_summary().clone();
                payload.dkg.subnet_splitting_status = subnet_splitting_status;
                block.payload = Payload::new(
                    ic_types::crypto::crypto_hash,
                    BlockPayload::Summary(payload),
                );
                proposal.content = HashedBlock::new(ic_types::crypto::crypto_hash, block.clone());
                pool.insert_validated(proposal.clone());
                pool.notarize(&proposal);
                pool.finalize(&proposal);

                assert!(
                    get_catch_up_package_type(
                        registry.as_ref(),
                        replica_config.node_id,
                        proposal.content.as_ref()
                    )
                    .expect_err("Expected error for node outside of both subnets")
                    .contains(
                        &match new_subnet_of_cup_maker {
                            Some(subnet_id) =>
                                PostSplitAssignmentError::DisallowedMembershipChange(subnet_id),
                            None =>
                                PostSplitAssignmentError::Unassigned(SPLITTING_REGISTRY_VERSION),
                        }
                        .to_string()
                    )
                );
                assert_eq!(
                    cup_maker
                        .consider_block(&PoolReader::new(&pool), proposal.content.as_ref().clone()),
                    None,
                    "A node outside of both subnets should not create a CUP share"
                );
            })
        })
    }
}
