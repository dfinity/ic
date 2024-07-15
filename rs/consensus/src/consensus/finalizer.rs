//! In the internet computer consensus protocol, parties may propose blocks in
//! the form of block proposals. A participant can "notarize" any proposals they
//! think are valid in a round by producing a notarization share for the
//! proposal. Once enough participants have produced a notarization share for
//! the same block proposal, these shares can be aggregated into a complete
//! notarization for the proposal. The notarized proposal then becomes a
//! candidate to extend the blockchain.
//!
//! As there can be multiple such notarized proposals, parties need to agree
//! on a single one to be considered canonical for each round. We call this
//! process finalization.
//!
//! If a single proposal has been notarized in the previous round and if a
//! participant produced at most one notarization share for that round, this
//! participant produces a finalization share for the notarized proposal.
//! Once enough finalization shares are produced, the shares can be aggregated
//! into a complete finalization, at which point the block and its ancestors
//! become finalized.
use crate::consensus::{
    batch_delivery::deliver_batches,
    metrics::{BatchStats, BlockStats, FinalizerMetrics},
};
use ic_consensus_utils::{
    crypto::ConsensusCrypto, membership::Membership, pool_reader::PoolReader,
};
use ic_interfaces::{
    ingress_manager::IngressSelector,
    messaging::{MessageRouting, MessageRoutingError},
};
use ic_interfaces_registry::RegistryClient;
use ic_logger::{debug, trace, ReplicaLogger};
use ic_metrics::MetricsRegistry;
use ic_types::{
    consensus::{FinalizationContent, FinalizationShare, HashedBlock},
    replica_config::ReplicaConfig,
    Height, ReplicaVersion,
};
use std::{cell::RefCell, sync::Arc};

pub struct Finalizer {
    pub(crate) replica_config: ReplicaConfig,
    registry_client: Arc<dyn RegistryClient>,
    membership: Arc<Membership>,
    pub(crate) crypto: Arc<dyn ConsensusCrypto>,
    message_routing: Arc<dyn MessageRouting>,
    ingress_selector: Arc<dyn IngressSelector>,
    pub(crate) log: ReplicaLogger,
    metrics: FinalizerMetrics,
    prev_finalized_height: RefCell<Height>,
}

impl Finalizer {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        replica_config: ReplicaConfig,
        registry_client: Arc<dyn RegistryClient>,
        membership: Arc<Membership>,
        crypto: Arc<dyn ConsensusCrypto>,
        message_routing: Arc<dyn MessageRouting>,
        ingress_selector: Arc<dyn IngressSelector>,
        log: ReplicaLogger,
        metrics_registry: MetricsRegistry,
    ) -> Self {
        Self {
            replica_config,
            registry_client,
            membership,
            crypto,
            message_routing,
            ingress_selector,
            log,
            metrics: FinalizerMetrics::new(metrics_registry),
            prev_finalized_height: RefCell::new(Height::from(0)),
        }
    }

    /// Attempt to:
    /// * deliver finalized blocks (as `Batch`s) via `Messaging`
    /// * publish finalization shares for relevant rounds
    pub fn on_state_change(&self, pool: &PoolReader<'_>) -> Vec<FinalizationShare> {
        trace!(self.log, "on_state_change");
        let notarized_height = pool.get_notarized_height();
        let finalized_height = pool.get_finalized_height();

        let h = self.message_routing.expected_batch_height();
        if *self.prev_finalized_height.borrow() < finalized_height {
            debug!(
                self.log,
                "finalized_height {:?} expected_batch_height {:?}", finalized_height, h,
            );
            *self.prev_finalized_height.borrow_mut() = finalized_height;
        }

        // Try to deliver finalized batches to messaging
        let _ = deliver_batches(
            &*self.message_routing,
            &self.membership,
            pool,
            &*self.registry_client,
            self.replica_config.subnet_id,
            ReplicaVersion::default(),
            &self.log,
            None,
            Some(&|result, block_stats, batch_stats| {
                self.process_batch_delivery_result(result, block_stats, batch_stats)
            }),
        );

        // Try to finalize rounds from finalized_height + 1 up to (and including)
        // notarized_height
        (finalized_height.increment().get()..=notarized_height.get())
            .filter_map(|h| self.finalize_height(pool, Height::from(h)))
            .collect()
    }

    // Write logs, report metrics depending on the batch deliver result.
    #[allow(clippy::too_many_arguments)]
    fn process_batch_delivery_result(
        &self,
        result: &Result<(), MessageRoutingError>,
        block_stats: BlockStats,
        batch_stats: BatchStats,
    ) {
        match result {
            Ok(()) => {
                self.metrics.process(&block_stats, &batch_stats);
                for ingress in batch_stats.ingress_ids.iter() {
                    debug!(
                        self.log,
                        "ingress_message_delivered";
                        ingress_message.message_id => format!("{}", ingress),
                    );
                }
                self.ingress_selector
                    .request_purge_finalized_messages(batch_stats.ingress_ids);
            }
            Err(MessageRoutingError::QueueIsFull) => {
                self.metrics
                    .batches_delivered
                    .with_label_values(&["MessageRoutingError::QueueIsFull"])
                    .inc();
            }
            Err(MessageRoutingError::Ignored { .. }) => {
                unreachable!("Unexpected error on a valid batch number");
            }
        }
    }

    /// Attempt to find a notarized block at the given height that this node
    /// can publish a finalization share for. A block is only returned if:
    /// * This replica is a notary at height `h`
    /// * This replica has not created a finalization share for height `h` yet
    /// * This replica has exactly one fully notarized block at height `h`
    /// * This replica has not created a notarization share for height `h` on
    ///   any block other than the single fully notarized block at height `h`
    ///
    /// In this case, the single notarized block is returned. Otherwise,
    /// return `None`
    fn pick_block_to_finality_sign(&self, pool: &PoolReader<'_>, h: Height) -> Option<HashedBlock> {
        let me = self.replica_config.node_id;
        let previous_beacon = pool.get_random_beacon(h.decrement())?;
        // check whether this replica was a notary at height h
        if !self
            .membership
            .node_belongs_to_notarization_committee(h, &previous_beacon, me)
            .ok()?
        {
            return None;
        }

        // if this replica already created a finalization share for height `h`, we do
        // not need to finality sign a block anymore
        if pool
            .get_finalization_shares(h, h)
            .any(|share| share.signature.signer == me)
        {
            return None;
        }

        // look up all fully notarized blocks for height `h`
        let mut notarized_blocks: Vec<_> = pool.get_notarized_blocks(h).collect();

        // Check if we have exactly one notarized block, and if so, determine that block
        let notarized_block = match notarized_blocks.len() {
            0 => {
                // If there are no notarized blocks at height `h`, we panic, as we should only
                // try to finalize heights that are notarized.
                unreachable!(
                    "Trying to finalize height {:?} but no notarized block found",
                    h
                )
            }
            1 => notarized_blocks.remove(0),
            _ => {
                // if there are multiple fully notarized blocks, there is no chance we reach
                // finality, so there is no point in creating a finalization share
                return None;
            }
        };

        // If notarization shares exists created by this replica at height `h`
        // that sign a block different than `notarized_block`, do not finalize.
        let other_notarized_shares_exists = pool
            .get_notarization_shares(h)
            .any(|x| x.signature.signer == me && x.content.block != *notarized_block.get_hash());
        if other_notarized_shares_exists {
            return None;
        }

        Some(notarized_block)
    }

    /// Try to create a finalization share for a notarized block at the given
    /// height
    fn finalize_height(&self, pool: &PoolReader<'_>, height: Height) -> Option<FinalizationShare> {
        let content = FinalizationContent::new(
            height,
            self.pick_block_to_finality_sign(pool, height)?
                .get_hash()
                .clone(),
        );
        let signature = self
            .crypto
            .sign(
                &content,
                self.replica_config.node_id,
                pool.registry_version(height)?,
            )
            .ok()?;
        Some(FinalizationShare { content, signature })
    }
}

#[cfg(test)]
mod tests {
    //! Finalizer unit tests
    use super::*;
    use crate::consensus::batch_delivery::generate_responses_to_setup_initial_dkg_calls;
    use ic_consensus_mocks::{dependencies, dependencies_with_subnet_params, Dependencies};
    use ic_crypto_test_utils_ni_dkg::dummy_transcript_for_tests;
    use ic_logger::replica_logger::no_op_logger;
    use ic_management_canister_types::SetupInitialDKGResponse;
    use ic_metrics::MetricsRegistry;
    use ic_registry_subnet_type::SubnetType;
    use ic_replicated_state::{
        metadata_state::subnet_call_context_manager::SetupInitialDkgContext, SystemMetadata,
    };
    use ic_test_utilities::{
        ingress_selector::FakeIngressSelector, message_routing::FakeMessageRouting,
    };
    use ic_test_utilities_registry::SubnetRecordBuilder;
    use ic_test_utilities_types::ids::{node_test_id, subnet_test_id};
    use ic_types::{
        consensus::{HasHeight, HashedBlock},
        crypto::threshold_sig::ni_dkg::{NiDkgId, NiDkgTag, NiDkgTargetId, NiDkgTargetSubnet},
        messages::{CallbackId, Payload, Request, NO_DEADLINE},
        CanisterId, Cycles, PrincipalId, RegistryVersion, SubnetId,
    };
    use std::{
        collections::{BTreeMap, BTreeSet},
        str::FromStr,
        sync::Arc,
    };

    /// Given a single block, just finalize it
    #[test]
    fn test_finalizer_behavior() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            let Dependencies {
                mut pool,
                replica_config,
                membership,
                registry,
                crypto,
                ..
            } = dependencies(pool_config, 1);
            let message_routing = FakeMessageRouting::new();

            assert_eq!(pool.advance_round_normal_operation(), Height::from(1));

            // 1. When notarized_height = finalized_height = expected_height - 1
            *message_routing.next_batch_height.write().unwrap() = Height::from(2);

            let message_routing = Arc::new(message_routing);
            let ingress_selector = Arc::new(FakeIngressSelector::new());

            let finalizer = Finalizer::new(
                replica_config,
                registry,
                membership,
                crypto,
                message_routing.clone(),
                ingress_selector,
                no_op_logger(),
                MetricsRegistry::new(),
            );
            let shares = finalizer.on_state_change(&PoolReader::new(&pool));
            let b = message_routing.batches.read().unwrap().clone();
            *message_routing.batches.write().unwrap() = Vec::new();
            assert!(b.is_empty());
            assert!(shares.is_empty());

            // 2. When notarized_height = finalized_height = expected_height
            *message_routing.next_batch_height.write().unwrap() = Height::from(1);
            let shares = finalizer.on_state_change(&PoolReader::new(&pool));
            let b = message_routing.batches.read().unwrap().clone();
            *message_routing.batches.write().unwrap() = Vec::new();
            assert!(!b.is_empty());
            // First block, nothing to remove.
            assert!(shares.is_empty());

            // 3. When notarization exists, create a finalization share
            pool.insert_validated(pool.make_next_beacon());
            let block = pool.make_next_block();
            pool.insert_validated(block.clone());
            pool.notarize(&block);

            *message_routing.next_batch_height.write().unwrap() = Height::from(2);
            let shares = finalizer.on_state_change(&PoolReader::new(&pool));
            let b = message_routing.batches.read().unwrap().clone();
            *message_routing.batches.write().unwrap() = Vec::new();
            assert!(b.is_empty());
            assert!(shares.len() == 1);

            // 4. When finalization share exists, don't create a full finalization
            // (this is done in the aggregator now), and don't create another share
            // if I have already signed.
            let finalization_share = &shares[0];
            pool.insert_validated(finalization_share.clone());
            *message_routing.next_batch_height.write().unwrap() = Height::from(2);
            let shares = finalizer.on_state_change(&PoolReader::new(&pool));
            let b = message_routing.batches.read().unwrap().clone();
            *message_routing.batches.write().unwrap() = Vec::new();
            assert!(b.is_empty());
            assert!(shares.is_empty());
        })
    }

    // We expect block maker to correctly detect version change and start
    // making only empty blocks.
    #[test]
    fn test_batch_not_delivered_in_protocol_upgrade() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            let committee = vec![node_test_id(0)];
            let dkg_interval_length = 3;
            let Dependencies {
                mut pool,
                replica_config,
                membership,
                registry,
                crypto,
                ..
            } = dependencies_with_subnet_params(
                pool_config,
                subnet_test_id(0),
                vec![
                    (
                        1,
                        SubnetRecordBuilder::from(&committee)
                            .with_dkg_interval_length(dkg_interval_length)
                            .with_replica_version("1")
                            .build(),
                    ),
                    (
                        10,
                        SubnetRecordBuilder::from(&committee)
                            .with_dkg_interval_length(dkg_interval_length)
                            .with_replica_version("2")
                            .build(),
                    ),
                ],
            );
            let metrics_registry = MetricsRegistry::new();
            let message_routing = Arc::new(FakeMessageRouting::new());
            *message_routing.next_batch_height.write().unwrap() = Height::from(2);
            let ingress_selector = Arc::new(FakeIngressSelector::new());
            let finalizer = Finalizer::new(
                replica_config,
                registry,
                membership,
                crypto,
                message_routing.clone(),
                ingress_selector,
                no_op_logger(),
                metrics_registry,
            );

            // 1. Make progress until a CUP block
            pool.advance_round_normal_operation_n(dkg_interval_length);
            assert_eq!(
                PoolReader::new(&pool).registry_version(Height::from(3)),
                Some(RegistryVersion::from(1))
            );

            // 2. Make CUP block at next start block
            let mut block_proposal = pool.make_next_block();
            let block = block_proposal.content.as_mut();
            assert!(block.payload.is_summary());
            assert_eq!(
                block.payload.as_ref().as_summary().dkg.registry_version,
                RegistryVersion::from(1)
            );
            assert_eq!(block.context.registry_version, RegistryVersion::from(10));
            block_proposal.content = HashedBlock::new(ic_types::crypto::crypto_hash, block.clone());
            pool.insert_validated(block_proposal.clone());
            pool.insert_validated(pool.make_next_beacon());
            pool.insert_validated(pool.make_next_tape());
            pool.notarize(&block_proposal);
            pool.finalize(&block_proposal);

            let catch_up_package = pool.make_catch_up_package(block_proposal.height());
            pool.insert_validated(catch_up_package);

            // 3. continue to make next CUP, expect block summary version to become 10
            pool.advance_round_normal_operation_n(3);
            assert_eq!(
                PoolReader::new(&pool).registry_version(Height::from(7)),
                Some(RegistryVersion::from(1))
            );
            let block_proposal = pool.make_next_block();
            let block = block_proposal.content.as_ref();
            assert!(block.payload.is_summary());
            assert_eq!(block.context.registry_version, RegistryVersion::from(10));
            assert_eq!(
                block.payload.as_ref().as_summary().dkg.registry_version,
                RegistryVersion::from(10)
            );

            pool.insert_validated(block_proposal.clone());
            pool.insert_validated(pool.make_next_beacon());
            pool.insert_validated(pool.make_next_tape());
            pool.notarize(&block_proposal);
            pool.finalize(&block_proposal);

            // expect batch to be still delivered for block at CUP height
            *message_routing.next_batch_height.write().unwrap() = block_proposal.height();
            pool.insert_validated(pool.make_next_tape());
            let _ = finalizer.on_state_change(&PoolReader::new(&pool));
            assert_eq!(
                *message_routing.next_batch_height.write().unwrap(),
                block_proposal.height().increment(),
            );

            // expect batch to be not delivered for next block
            pool.advance_round_normal_operation();
            pool.insert_validated(pool.make_next_tape());
            assert_eq!(
                PoolReader::new(&pool).registry_version(Height::from(9)),
                Some(RegistryVersion::from(10))
            );
            assert_eq!(
                PoolReader::new(&pool).registry_version(Height::from(10)),
                Some(RegistryVersion::from(10))
            );
            let _ = finalizer.on_state_change(&PoolReader::new(&pool));
            assert_eq!(
                *message_routing.next_batch_height.write().unwrap(),
                block_proposal.height().increment(),
            );
        })
    }

    #[test]
    fn test_generate_responses_to_subnet_calls() {
        const TARGET_ID: NiDkgTargetId = NiDkgTargetId::new([8; 32]);

        // Manually create `SystemMetadata` with custom context
        let mut metadata = SystemMetadata::new(subnet_test_id(0), SubnetType::System);
        metadata
            .subnet_call_context_manager
            .setup_initial_dkg_contexts = vec![(
            CallbackId::from(0),
            // NOTE: From this struct we only need the target id, therefore we will initialize the
            // rest with dummy data
            SetupInitialDkgContext {
                request: Request {
                    receiver: CanisterId::from(0),
                    sender: CanisterId::from(0),
                    sender_reply_callback: CallbackId::from(0),
                    payment: Cycles::zero(),
                    method_name: "".to_string(),
                    method_payload: vec![],
                    metadata: None,
                    deadline: NO_DEADLINE,
                },
                nodes_in_target_subnet: BTreeSet::new(),
                target_id: TARGET_ID,
                registry_version: RegistryVersion::from(1),
                time: metadata.batch_time,
            },
        )]
        .drain(..)
        .collect::<BTreeMap<_, _>>();

        // Build some transcipts with matching ids and tags
        let transcripts_for_new_subnets = vec![
            (
                NiDkgId {
                    start_block_height: Height::from(0),
                    dealer_subnet: subnet_test_id(0),
                    dkg_tag: NiDkgTag::LowThreshold,
                    target_subnet: NiDkgTargetSubnet::Remote(TARGET_ID),
                },
                CallbackId::from(1),
                Ok(dummy_transcript_for_tests()),
            ),
            (
                NiDkgId {
                    start_block_height: Height::from(0),
                    dealer_subnet: subnet_test_id(0),
                    dkg_tag: NiDkgTag::HighThreshold,
                    target_subnet: NiDkgTargetSubnet::Remote(TARGET_ID),
                },
                CallbackId::from(1),
                Ok(dummy_transcript_for_tests()),
            ),
        ]
        .drain(..)
        .collect::<Vec<_>>();

        // Run the
        let result = generate_responses_to_setup_initial_dkg_calls(
            &transcripts_for_new_subnets[..],
            &no_op_logger(),
        );
        assert_eq!(result.len(), 1);

        // Deserialize the `SetupInitialDKGResponse` and check the subnet id
        let payload = match &result[0].payload {
            Payload::Data(data) => data,
            Payload::Reject(_) => panic!("Payload was rejected unexpectedly"),
        };
        let initial_transcript_records = SetupInitialDKGResponse::decode(payload).unwrap();
        assert_eq!(
            initial_transcript_records.fresh_subnet_id,
            SubnetId::from(
                PrincipalId::from_str(
                    "icdrs-3sfmz-hm6r3-cdzf5-cfroa-3cddh-aght7-azz25-eo34b-4strl-wae"
                )
                .unwrap()
            )
        );
    }
}
