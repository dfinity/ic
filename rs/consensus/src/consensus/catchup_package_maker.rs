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

use ic_consensus_dkg::payload_builder::get_post_split_dkg_summary;
use ic_consensus_utils::{
    active_high_threshold_nidkg_id, crypto::ConsensusCrypto,
    get_oldest_idkg_state_registry_version, membership::Membership, pool_reader::PoolReader,
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
        RandomBeacon, RandomBeaconContent, Rank, SummaryPayload, dkg::SubnetSplittingStatus,
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

        match cup_type {
            CatchUpPackageType::Normal => {
                // Skip if the state referenced by finalization tip has not caught up to
                // this height. This is to increase the chance that states are available to
                // validate payloads at the chain tip.
                if pool.get_finalized_tip().context.certified_height < summary_height {
                    return None;
                }
            }
            CatchUpPackageType::PostSplit { .. } => {
                // During subnet splitting we don't need to wait for the state at the height to be
                // certified
            }
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

        let summary = start_block.payload.as_ref().as_summary();

        let oldest_registry_version_in_use_by_replicated_state = if summary.idkg.is_some() {
            // Should succeed as we already got the hash above
            let state = self
                .state_manager
                .get_state_at(summary_height)
                .inspect_err(|err| {
                    error!(
                        self.log,
                        "Cannot make IDKG CUP at height {summary_height}: `get_state_hash_at` \
                        succeeded but `get_state_at` failed with {err}. Will retry",
                    )
                })
                .ok()?;
            get_oldest_idkg_state_registry_version(state.get_ref())
        } else {
            None
        };

        // Skip if this node has already made a share
        if pool
            .get_catch_up_package_shares(self.get_cup_height(&start_block, cup_type))
            .any(|share| share.signature.signer == self.replica_config.node_id)
        {
            return None;
        }

        let cup_block = self
            .get_cup_block(start_block.clone(), cup_type)
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
                        .position(self.replica_config.node_id)
                        .is_some()),
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
        .subnet_splitting_status
    {
        Some(SubnetSplittingStatus::Scheduled {
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
        _ => Ok(CatchUpPackageType::Normal),
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

    let height = post_split_dkg_summary.height;
    Ok(Block {
        version: splitting_summary_block.version.clone(),
        // Fake parent
        parent: CryptoHashOf::from(CryptoHash(Vec::new())),
        payload: Payload::new(
            crypto_hash,
            BlockPayload::Summary(SummaryPayload {
                dkg: post_split_dkg_summary,
                idkg: None,
            }),
        ),
        height,
        rank: Rank(0),
        context: ValidationContext {
            registry_version: splitting_summary_block.context.registry_version,
            certified_height: height,
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
    use ic_test_utilities::message_routing::FakeMessageRouting;
    use ic_test_utilities_consensus::idkg::{
        empty_idkg_payload, fake_ecdsa_idkg_master_public_key_id,
        fake_signature_request_context_with_registry_version, fake_state_with_signature_requests,
    };
    use ic_test_utilities_logger::with_test_replica_logger;
    use ic_test_utilities_registry::{SubnetRecordBuilder, insert_initial_dkg_transcript};
    use ic_test_utilities_types::ids::{node_test_id, subnet_test_id};
    use ic_types::{
        CryptoHashOfState, Height, NodeId, RegistryVersion,
        consensus::{
            BlockPayload, ConsensusMessageHashable, HasVersion, Payload, SummaryPayload,
            idkg::PreSigId,
        },
        crypto::CryptoHash,
        messages::CallbackId,
    };
    use ic_types_test_utils::ids::{NODE_1, NODE_2, NODE_3, NODE_4};
    use ic_types_test_utils::ids::{SUBNET_1, SUBNET_2};
    use rstest::rstest;
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
                registry,
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

            let key_id = fake_ecdsa_idkg_master_public_key_id();

            // Create three quadruple Ids and contexts, context "2" will remain unmatched.
            let pre_sig_id1 = PreSigId(1);
            let pre_sig_id3 = PreSigId(3);

            let contexts = vec![
                (
                    CallbackId::new(1),
                    fake_signature_request_context_with_registry_version(
                        Some(pre_sig_id1),
                        key_id.inner(),
                        RegistryVersion::from(3),
                    ),
                ),
                (
                    CallbackId::new(2),
                    fake_signature_request_context_with_registry_version(
                        None,
                        key_id.inner(),
                        RegistryVersion::from(1),
                    ),
                ),
                (
                    CallbackId::new(3),
                    fake_signature_request_context_with_registry_version(
                        Some(pre_sig_id3),
                        key_id.inner(),
                        RegistryVersion::from(2),
                    ),
                ),
            ];

            state_manager
                .get_mut()
                .expect_get_state_at()
                .return_const(Ok(fake_state_with_signature_requests(
                    height,
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

            let idkg = empty_idkg_payload(subnet_test_id(0));
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
                state_manager.get_state_hash_at(height).unwrap()
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
                    ReplicaConfig {
                        node_id,
                        subnet_id: SOURCE_SUBNET_ID,
                    },
                    membership,
                    crypto,
                    state_manager,
                    message_routing,
                    registry,
                    log,
                );

                pool.advance_round_normal_operation_n(INTERVAL_LENGTH.get());

                let subnet_splitting_status = SubnetSplittingStatus::Scheduled {
                    source_subnet_id: SOURCE_SUBNET_ID,
                    destination_subnet_id: DESTINATION_SUBNET_ID,
                };
                let mut proposal = pool.make_next_block();
                let block = proposal.content.as_mut();
                block.context.certified_height = context_certified_height;
                block.context.registry_version = SPLITTING_REGISTRY_VERSION;
                let mut payload = block.payload.as_ref().as_summary().clone();
                payload.dkg.subnet_splitting_status = Some(subnet_splitting_status);
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
}
