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
    active_high_threshold_nidkg_id, crypto::ConsensusCrypto, get_oldest_state_registry_version,
    membership::Membership, pool_reader::PoolReader,
};
use ic_interfaces::messaging::MessageRouting;
use ic_interfaces_registry::RegistryClient;
use ic_interfaces_state_manager::{
    PermanentStateHashError::*, StateHashError, StateManager, TransientStateHashError::*,
};
use ic_logger::{ReplicaLogger, debug, error, info, trace, warn};
use ic_registry_client_helpers::node::NodeRegistry;
use ic_replicated_state::ReplicatedState;
use ic_types::{
    Height, NodeId, SubnetId,
    batch::ValidationContext,
    consensus::{
        Block, BlockPayload, CatchUpContent, CatchUpPackage, CatchUpPackageShare,
        CatchUpShareContent, HasCommittee, HasHeight, HashedBlock, HashedRandomBeacon, Payload,
        RandomBeacon, RandomBeaconContent, Rank, SummaryPayload,
        dkg::{SplittingArgs, SubnetSplittingStatus},
    },
    crypto::{
        CombinedThresholdSig, CombinedThresholdSigOf, CryptoHash, CryptoHashOf, Signed,
        crypto_hash,
        threshold_sig::ni_dkg::{NiDkgId, NiDkgTag, NiDkgTranscript},
    },
    replica_config::ReplicaConfig,
    signature::ThresholdSignature,
};
use std::sync::Arc;

/// [`CatchUpPackage`] maker is responsible for creating beacon shares
pub(crate) struct CatchUpPackageMaker {
    replica_config: ReplicaConfig,
    membership: Arc<Membership>,
    crypto: Arc<dyn ConsensusCrypto>,
    state_manager: Arc<dyn StateManager<State = ReplicatedState>>,
    message_routing: Arc<dyn MessageRouting>,
    registry: Arc<dyn RegistryClient>,
    log: ReplicaLogger,
}

/// Type of [`CatchUpPackage`].
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub(crate) enum CatchUpPackageType {
    Normal,
    /// After deliverying a splitting block to the DSM, we immediately create a CUP at the start of
    /// the next dkg interval and we create a new summary block and a dummy random beacon on the fly.
    PostSplit {
        new_subnet_id: SubnetId,
    },
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
        .inspect_err(|err| warn!(self.log, "Failed to get the catch up package type: {err}"))
        .ok()?;

        let halting = || {
            status::should_halt(
                summary_height,
                Some(&start_block),
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
        if pool.get_finalized_tip().context.certified_height < summary_height && !halting() {
            return None;
        }

        let state_hash = match self.state_manager.get_state_hash_at(summary_height) {
            Ok(state_hash) => state_hash,
            Err(StateHashError::Transient(StateNotCommittedYet(_))) => {
                // TODO: Setup a delay before retry
                debug!(
                    self.log,
                    "Cannot make CUP at height {} because \
                    state is not committed yet. Will retry",
                    summary_height
                );
                return None;
            }
            Err(StateHashError::Transient(HashNotComputedYet(_))) => {
                debug!(
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
            .map_err(|err| {
                error!(
                    self.log,
                    "Cannot make CUP at height {summary_height}: `get_state_hash_at` \
                    succeeded but `get_state_at` failed with {err}. Will retry",
                )
            })
            .ok()?;
        let oldest_registry_version_in_use_by_replicated_state =
            get_oldest_state_registry_version(state.get_ref());

        // Skip if this node has already made a share
        if pool
            .get_catch_up_package_shares(self.get_cup_height(&start_block, cup_type))
            .any(|share| share.signature.signer == self.replica_config.node_id)
        {
            return None;
        }

        let cup_block = self
            .get_cup_block(start_block, cup_type)
            .inspect_err(|err| warn!(self.log, "Can't get a block for a CUP: {err}"))
            .ok()?;

        let random_beacon = self
            .get_cup_random_beacon(pool, &cup_block, cup_type)
            .inspect_err(|err| warn!(self.log, "Can't get a random beacon for a CUP: {err}"))
            .ok()?;

        let high_dkg_id = self
            .get_high_dkg_id(pool, &cup_block, cup_type)
            .inspect_err(|err| warn!(self.log, "Can't get a high dkg id for a CUP: {err}"))
            .ok()?;

        if !self
            .node_belongs_to_threshold_committee(&cup_block, cup_type)
            .inspect_err(|err| warn!(self.log, "Can't check if node belongs to committee: {err}"))
            .unwrap_or_default()
        {
            return None;
        }

        let content = CatchUpContent::new(
            HashedBlock::new(ic_types::crypto::crypto_hash, cup_block),
            HashedRandomBeacon::new(ic_types::crypto::crypto_hash, random_beacon),
            state_hash,
            oldest_registry_version_in_use_by_replicated_state,
        );

        let share_content = CatchUpShareContent::from(&content);
        let share_height = share_content.height();
        match self
            .crypto
            .sign(&content, self.replica_config.node_id, high_dkg_id)
        {
            Ok(signature) => {
                info!(
                    self.log,
                    "Proposing a CatchUpPackageShare (type: {cup_type:?}) at height {share_height}"
                );
                Some(CatchUpPackageShare {
                    content: share_content,
                    signature,
                })
            }
            Err(err) => {
                error!(
                    self.log,
                    "Couldn't create a signature at height {share_height}: {err}"
                );
                None
            }
        }
    }

    fn get_cup_height(&self, summary_block: &Block, cup_type: CatchUpPackageType) -> Height {
        match cup_type {
            CatchUpPackageType::Normal => summary_block.height,
            // During subnet splitting we skip one dkg interval
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
        match cup_type {
            CatchUpPackageType::Normal => Ok(summary_block),
            CatchUpPackageType::PostSplit { new_subnet_id } => create_post_split_summary_block(
                &summary_block,
                new_subnet_id,
                self.registry.as_ref(),
            )
            .map_err(|err| format!("Failed to create a post split block: {err}")),
        }
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

    fn get_high_dkg_id(
        &self,
        pool: &PoolReader<'_>,
        cup_block: &Block,
        cup_type: CatchUpPackageType,
    ) -> Result<NiDkgId, String> {
        // TODO: can we always take the transcript from the block?
        match cup_type {
            CatchUpPackageType::Normal => {
                active_high_threshold_nidkg_id(pool.as_cache(), cup_block.height).ok_or_else(|| {
                    format!("Couldn't find transcript at height {}", cup_block.height)
                })
            }
            CatchUpPackageType::PostSplit { .. } => {
                match get_current_transcript_from_summary_block(cup_block, &NiDkgTag::HighThreshold)
                {
                    Some(transcript) => Ok(transcript.dkg_id.clone()),
                    None => Err(format!(
                        "Couldn't find post-split transcript at height {}",
                        cup_block.height
                    )),
                }
            }
        }
    }

    fn node_belongs_to_threshold_committee(
        &self,
        cup_block: &Block,
        cup_type: CatchUpPackageType,
    ) -> Result<bool, String> {
        // TODO: can we always take the transcript from the block?
        match cup_type {
            CatchUpPackageType::Normal => self
                .membership
                .node_belongs_to_threshold_committee(
                    self.replica_config.node_id,
                    cup_block.height,
                    CatchUpPackage::committee(),
                )
                .map_err(|err| {
                    format!("Failed to check if node belongs to threshold committee {err:?}")
                }),
            CatchUpPackageType::PostSplit { .. } => {
                match get_current_transcript_from_summary_block(cup_block, &NiDkgTag::HighThreshold)
                {
                    Some(transcript) => Ok(transcript
                        .committee
                        .get()
                        .contains(&self.replica_config.node_id)),
                    None => Err(format!(
                        "Couldn't find post-split transcript at height {}",
                        cup_block.height
                    )),
                }
            }
        }
    }
}

pub(crate) fn get_catch_up_package_type(
    registry: &dyn RegistryClient,
    node_id: NodeId,
    summary_block: &Block,
) -> Result<CatchUpPackageType, String> {
    match summary_block
        .payload
        .as_ref()
        .as_summary()
        .dkg
        .subnet_splitting_status()
    {
        SubnetSplittingStatus::Scheduled(SplittingArgs {
            destination_subnet_id,
            source_subnet_id,
        }) => {
            let new_subnet_id = get_new_subnet_id(
                registry,
                summary_block,
                node_id,
                source_subnet_id,
                destination_subnet_id,
            )
            .map_err(|err| format!("Failed to get the new subnet assignment: {err}"))?;

            Ok(CatchUpPackageType::PostSplit { new_subnet_id })
        }
        SubnetSplittingStatus::NotScheduled | SubnetSplittingStatus::PostSplit { .. } => {
            Ok(CatchUpPackageType::Normal)
        }
    }
}

/// Note: this panics if the given block is not a summary block.
fn get_current_transcript_from_summary_block<'a>(
    summary_block: &'a Block,
    tag: &NiDkgTag,
) -> Option<&'a NiDkgTranscript> {
    summary_block
        .payload
        .as_ref()
        .as_summary()
        .dkg
        .current_transcript(tag)
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
        parent: CryptoHashOf::from(CryptoHash(Vec::new())),
        payload: Payload::new(
            crypto_hash,
            BlockPayload::Summary(SummaryPayload {
                dkg: post_split_dkg_summary,
                // Copy over the IDKG summary from the splitting block
                idkg: splitting_summary_block
                    .payload
                    .as_ref()
                    .as_summary()
                    .idkg
                    .clone(),
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
    match get_current_transcript_from_summary_block(cup_block, &NiDkgTag::LowThreshold) {
        Some(transcript) => Ok(Signed {
            content: RandomBeaconContent {
                version: cup_block.version.clone(),
                height: cup_block.height(),
                parent: CryptoHashOf::from(CryptoHash(Vec::new())),
            },
            signature: ThresholdSignature {
                signer: transcript.dkg_id.clone(),
                signature: CombinedThresholdSigOf::new(CombinedThresholdSig(vec![])),
            },
        }),
        None => Err(format!(
            "Couldn't find post-split transcript at height {}",
            cup_block.height(),
        )),
    }
}

fn get_new_subnet_id(
    registry: &dyn RegistryClient,
    summary_block: &Block,
    node_id: NodeId,
    source_subnet_id: SubnetId,
    destination_subnet_id: SubnetId,
) -> Result<SubnetId, String> {
    let registry_version = summary_block.context.registry_version;
    let new_subnet_id = registry
        .get_subnet_id_from_node_id(node_id, registry_version)
        .map_err(|err| {
            format!(
                "Failed to get the new subnet id at \
                registry version {registry_version}: {err}"
            )
        })?
        .ok_or_else(|| {
            format!(
                "Node is not assigned to any subnet at \
                registry version {registry_version}"
            )
        })?;

    if ![source_subnet_id, destination_subnet_id].contains(&new_subnet_id) {
        return Err(format!(
            "According to the registry version {registry_version} \
            the node belongs to neither source subnet nor the destination subnet"
        ));
    }

    Ok(new_subnet_id)
}

#[cfg(test)]
mod tests {
    //! CatchUpPackageMaker unit tests
    use super::*;
    use ic_consensus_mocks::{
        Dependencies, DependenciesBuilder, dependencies_with_subnet_params,
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
    use ic_test_utilities_logger::with_test_replica_logger;
    use ic_test_utilities_registry::{SubnetRecordBuilder, insert_initial_dkg_transcript};
    use ic_test_utilities_types::ids::{node_test_id, subnet_test_id};
    use ic_types::{
        CryptoHashOfState, Height, NodeId, RegistryVersion,
        consensus::{
            BlockPayload, BlockProposal, ConsensusMessageHashable, HasVersion, Payload,
            SummaryPayload, idkg::PreSigId,
        },
        crypto::CryptoHash,
    };
    use ic_types_test_utils::ids::{NODE_1, NODE_2, NODE_3, NODE_4};
    use ic_types_test_utils::ids::{SUBNET_1, SUBNET_2};
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
                deps.registry,
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
                registry,
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
            let committee: Vec<_> = (0..5).map(node_test_id).collect();
            let Dependencies {
                mut pool,
                membership,
                replica_config,
                registry,
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
            let committee: Vec<_> = (0..5).map(node_test_id).collect();
            let Dependencies {
                mut pool,
                membership,
                replica_config,
                crypto,
                state_manager,
                registry,
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

    // In this test the subnet initially has 4 nodes, and after the split `NODE_1, NODE_2` will stay
    // in the original subnet, and `NODE_3, NODE_4` will be moved to a new one.
    #[rstest]
    #[case::source_subnet_node(
        NODE_1,
        "d5a517cd0906e1d36b43edf4103ef9b0dfb0e6892a87712ce5ed6602bfa5c97e"
    )]
    #[case::source_subnet_node(
        NODE_2,
        "d5a517cd0906e1d36b43edf4103ef9b0dfb0e6892a87712ce5ed6602bfa5c97e"
    )]
    #[case::destination_subnet_node(
        NODE_3,
        "e8614bf48bba176a546186f90e7cfc02ec573e4b87296e9d73a70547ca168416"
    )]
    #[case::destination_subnet_node(
        NODE_4,
        "e8614bf48bba176a546186f90e7cfc02ec573e4b87296e9d73a70547ca168416"
    )]
    #[trace]
    fn create_post_split_cup_share_test(
        #[case] node_id: NodeId,
        // We don't necessarily care what the hash is, but we want to ensure that different
        // nodes produce different blocks (and hence different hashes), depending on which subnet
        // they are going to land on
        #[case] expected_block_hash_in_cup: &str,
        #[values(Height::new(0), Height::new(1000))] context_certified_height: Height,
    ) {
        with_test_replica_logger(|log| {
            ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
                use ic_types::consensus::backwards_compatibility::BackwardsCompatibleOption;

                const SOURCE_SUBNET_ID: SubnetId = SUBNET_1;
                const DESTINATION_SUBNET_ID: SubnetId = SUBNET_2;
                const INITIAL_REGISTRY_VERSION: RegistryVersion = RegistryVersion::new(1);
                const SPLITTING_REGISTRY_VERSION: RegistryVersion = RegistryVersion::new(2);
                const INTERVAL_LENGTH: Height = Height::new(9);
                let fake_state_hash = CryptoHashOfState::from(CryptoHash(vec![1, 2, 3]));

                let Dependencies {
                    mut pool,
                    membership,
                    registry,
                    crypto,
                    state_manager,
                    replica_config,
                    ..
                } = DependenciesBuilder::new(
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
                .add_additional_registry_mutation(|registry_data_provider| {
                    insert_initial_dkg_transcript(
                        SPLITTING_REGISTRY_VERSION.get(),
                        SOURCE_SUBNET_ID,
                        &SubnetRecordBuilder::from(&[NODE_1, NODE_2])
                            .with_dkg_interval_length(INTERVAL_LENGTH.get())
                            .build(),
                        registry_data_provider,
                    )
                })
                .with_replica_config(ReplicaConfig {
                    node_id,
                    subnet_id: SOURCE_SUBNET_ID,
                })
                .with_mocked_state_manager()
                .build();

                state_manager
                    .get_mut()
                    .expect_get_state_hash_at()
                    .return_const(Ok(fake_state_hash.clone()));

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
                payload.dkg.subnet_splitting_status =
                    BackwardsCompatibleOption::new_for_test_only(Some(subnet_splitting_status));
                block.payload = Payload::new(
                    ic_types::crypto::crypto_hash,
                    BlockPayload::Summary(payload),
                );
                proposal.content = HashedBlock::new(ic_types::crypto::crypto_hash, block.clone());
                pool.insert_validated(proposal.clone());
                pool.notarize(&proposal);
                pool.finalize(&proposal);

                let share = cup_maker
                    .consider_block(&PoolReader::new(&pool), proposal.content.as_ref().clone())
                    .expect("Should succeed with valid inputs");

                assert!(share.check_integrity());
                assert_eq!(share.content.version, *proposal.content.version());
                assert_eq!(
                    hex::encode(&share.content.block.get().0),
                    expected_block_hash_in_cup
                );
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

    #[test]
    fn create_post_split_summary_block_copies_idkg_summary() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            use ic_types::consensus::backwards_compatibility::BackwardsCompatibleOption;

            const SOURCE_SUBNET_ID: SubnetId = SUBNET_1;
            const DESTINATION_SUBNET_ID: SubnetId = SUBNET_2;
            const INITIAL_REGISTRY_VERSION: RegistryVersion = RegistryVersion::new(1);
            const SPLITTING_REGISTRY_VERSION: RegistryVersion = RegistryVersion::new(2);
            const INTERVAL_LENGTH: Height = Height::new(9);

            let Dependencies {
                mut pool, registry, ..
            } = DependenciesBuilder::new(
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
            .add_additional_registry_mutation(|registry_data_provider| {
                insert_initial_dkg_transcript(
                    SPLITTING_REGISTRY_VERSION.get(),
                    SOURCE_SUBNET_ID,
                    &SubnetRecordBuilder::from(&[NODE_1, NODE_2])
                        .with_dkg_interval_length(INTERVAL_LENGTH.get())
                        .build(),
                    registry_data_provider,
                )
            })
            .with_replica_config(ReplicaConfig {
                node_id: NODE_1,
                subnet_id: SOURCE_SUBNET_ID,
            })
            .with_mocked_state_manager()
            .build();

            pool.advance_round_normal_operation_n(INTERVAL_LENGTH.get());

            let subnet_splitting_status =
                ic_types::consensus::dkg::SubnetSplittingStatus::Scheduled(SplittingArgs {
                    source_subnet_id: SOURCE_SUBNET_ID,
                    destination_subnet_id: DESTINATION_SUBNET_ID,
                });

            let mut proposal = pool.make_next_block();
            let block = proposal.content.as_mut();
            block.context.registry_version = SPLITTING_REGISTRY_VERSION;
            let mut payload = block.payload.as_ref().as_summary().clone();
            payload.dkg.subnet_splitting_status =
                BackwardsCompatibleOption::new_for_test_only(Some(subnet_splitting_status));
            let idkg = empty_idkg_payload(SOURCE_SUBNET_ID);
            payload.idkg = Some(idkg.clone());
            block.payload = Payload::new(
                ic_types::crypto::crypto_hash,
                BlockPayload::Summary(payload),
            );
            proposal.content = HashedBlock::new(ic_types::crypto::crypto_hash, block.clone());
            pool.insert_validated(proposal.clone());
            pool.notarize(&proposal);
            pool.finalize(&proposal);

            let splitting_block = proposal.content.as_ref();
            let post_split_block = create_post_split_summary_block(
                splitting_block,
                SOURCE_SUBNET_ID,
                registry.as_ref(),
            )
            .expect("create_post_split_summary_block should succeed");

            let post_split_idkg = post_split_block
                .payload
                .as_ref()
                .as_summary()
                .idkg
                .as_ref()
                .expect("Post-split summary block should have an IDKG summary");

            assert_eq!(
                *post_split_idkg, idkg,
                "IDKG summary in post-split block should match the splitting block's IDKG summary"
            );
        })
    }
}
