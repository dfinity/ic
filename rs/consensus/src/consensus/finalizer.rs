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
    membership::Membership,
    metrics::FinalizerMetrics,
    pool_reader::PoolReader,
    prelude::*,
    utils::{crypto_hashable_to_seed, get_block_hash_string, lookup_replica_version},
    ConsensusCrypto,
};
use ic_interfaces::{
    ingress_manager::IngressSelector,
    messaging::{MessageRouting, MessageRoutingError},
    registry::RegistryClient,
    state_manager::StateManager,
};
use ic_logger::{debug, info, trace, warn, ReplicaLogger};
use ic_metrics::MetricsRegistry;
use ic_protobuf::log::consensus_log_entry::v1::ConsensusLogEntry;
use ic_protobuf::registry::crypto::v1::PublicKey as PublicKeyProto;
use ic_replicated_state::ReplicatedState;
use ic_types::{
    crypto::threshold_sig::ni_dkg::{NiDkgId, NiDkgTargetSubnet::Remote, NiDkgTranscript},
    messages::Response,
    replica_config::ReplicaConfig,
    CountBytes, ReplicaVersion,
};
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::sync::Arc;

pub struct Finalizer {
    replica_config: ReplicaConfig,
    registry_client: Arc<dyn RegistryClient>,
    membership: Arc<Membership>,
    crypto: Arc<dyn ConsensusCrypto>,
    message_routing: Arc<dyn MessageRouting>,
    ingress_selector: Arc<dyn IngressSelector>,
    state_manager: Arc<dyn StateManager<State = ReplicatedState>>,
    log: ReplicaLogger,
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
        state_manager: Arc<dyn StateManager<State = ReplicatedState>>,
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
            state_manager,
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

        // Try to deliver finalized batches to messaging
        self.deliver_batches(pool, finalized_height);

        // Try to finalize rounds from finalized_height + 1 up to (and including)
        // notarized_height
        (finalized_height.increment().get()..=notarized_height.get())
            .filter_map(|h| self.finalize_height(pool, Height::from(h)))
            .collect()
    }

    /// Deliver all finalized blocks from
    /// `message_routing.expected_batch_height` to `finalized_height` via
    /// `Messaging`.
    fn deliver_batches(&self, pool: &PoolReader<'_>, finalized_height: Height) {
        let mut h = self.message_routing.expected_batch_height();
        assert!(
            h.get() > 0,
            "deliver_batches: expected_batch_height must be greater than 0"
        );
        if *self.prev_finalized_height.borrow() < finalized_height {
            debug!(
                self.log,
                "finalized_height {:?} expected_batch_height {:?}", finalized_height, h,
            );
            *self.prev_finalized_height.borrow_mut() = finalized_height;
        }
        while h <= finalized_height {
            match (pool.get_finalized_block(h), pool.get_random_tape(h)) {
                (Some(block), Some(tape)) => {
                    debug!(
                        self.log,
                        "Finalized height";
                        consensus => ConsensusLogEntry { height: Some(h.get()), hash: Some(get_block_hash_string(&block)) }
                    );
                    self.metrics
                        .finalization_certified_state_difference
                        .set((block.height() - block.context.certified_height).get() as i64);
                    let mut consensus_responses = Vec::<Response>::new();
                    if block.payload.is_summary() {
                        let summary = block.payload.as_ref().as_summary();
                        info!(
                            self.log,
                            "New DKG summary with config ids created: {:?}",
                            summary.configs.keys().collect::<Vec<_>>()
                        );
                        // Compute consensus' responses to subnet calls.
                        consensus_responses = generate_responses_to_subnet_calls(
                            &*self.state_manager,
                            block.context.certified_height,
                            summary.transcripts_for_new_subnets(),
                            &self.log,
                        );
                    }
                    // When we are not deliverying CUP block, we must check replica_version
                    else {
                        match pool.registry_version(h).and_then(|registry_version| {
                            lookup_replica_version(
                                self.registry_client.as_ref(),
                                self.replica_config.subnet_id,
                                &self.log,
                                registry_version,
                            )
                        }) {
                            Some(replica_version)
                                if replica_version != ReplicaVersion::default() =>
                            {
                                debug!(
                                self.log,
                                "Batch of height {} is not delivered before replica upgrades to new version {}",
                                h,
                                replica_version.as_ref()
                            );
                                return;
                            }
                            None => {
                                warn!(
                                    self.log,
                                    "Skipping batch delivery because replica version is unknown",
                                );
                                return;
                            }
                            _ => {}
                        }
                    }

                    let block_hash = get_block_hash_string(&block);

                    let randomness = Randomness::from(crypto_hashable_to_seed(&tape));
                    let batch = Batch {
                        batch_number: h,
                        requires_full_state_hash: block.payload.is_summary(),
                        payload: if block.payload.is_summary() {
                            BatchPayload::default()
                        } else {
                            BlockPayload::from(block.payload).into_batch_payload()
                        },
                        randomness,
                        registry_version: block.context.registry_version,
                        time: block.context.time,
                        consensus_responses,
                    };
                    if !self.deliver_batch(batch, &block_hash) {
                        break;
                    }
                    h = h.increment();
                }
                (None, _) => {
                    trace!(
                        self.log,
                        "Do not deliver height {:?} because no finalized block was found. This should indicate we are waiting for state sync.",
                        h);
                    break;
                }
                (_, None) => {
                    // Do not deliver batch if we don't have random tape
                    trace!(
                        self.log,
                        "Do not deliver height {:?} because RandomTape is not ready. Will re-try later",
                        h);
                    break;
                }
            }
        }
    }

    /// Deliver the given batch to Message Routing. Returns `true` if the
    /// delivery was successful, returns false otherwise.
    fn deliver_batch(&self, batch: Batch, block_hash: &str) -> bool {
        let batch_height = batch.batch_number.get();
        debug!(self.log, "deliver batch {:?}", batch_height);
        let ingress_count = batch.payload.ingress.message_count();
        let ingress_bytes = batch.payload.ingress.count_bytes();
        let xnet_bytes = batch.payload.xnet.count_bytes();
        let ingress_ids = batch.payload.ingress.message_ids();
        match self.message_routing.deliver_batch(batch) {
            Ok(()) => {
                self.metrics
                    .batches_delivered
                    .with_label_values(&["success"])
                    .inc();
                self.metrics.batch_height.set(batch_height as i64);
                self.metrics
                    .ingress_messages_delivered
                    .observe(ingress_count as f64);
                self.metrics
                    .ingress_message_bytes_delivered
                    .observe(ingress_bytes as f64);
                self.metrics.xnet_bytes_delivered.observe(xnet_bytes as f64);
                debug!(
                    self.log,
                    "block_delivered";
                    block.hash => block_hash
                );
                for ingress in ingress_ids.iter() {
                    debug!(
                        self.log,
                        "ingress_message_delivered";
                        ingress_message.message_id => format!("{}", ingress),
                    );
                }
                self.ingress_selector
                    .request_purge_finalized_messages(ingress_ids);
                true
            }
            Err(MessageRoutingError::QueueIsFull) => {
                self.metrics
                    .batches_delivered
                    .with_label_values(&["MessageRoutingError::QueueIsFull"])
                    .inc();
                false
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
    /// In this case, the the single notarized block is returned. Otherwise,
    /// return `None`
    fn pick_block_to_finality_sign(&self, pool: &PoolReader<'_>, h: Height) -> Option<Block> {
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
        let other_notarizaed_shares_exists = pool.get_notarization_shares(h).any(|x| {
            x.signature.signer == me && x.content.block != ic_crypto::crypto_hash(&notarized_block)
        });
        if other_notarizaed_shares_exists {
            return None;
        }

        Some(notarized_block)
    }

    /// Try to create a finalization share for a notarized block at the given
    /// height
    fn finalize_height(&self, pool: &PoolReader<'_>, height: Height) -> Option<FinalizationShare> {
        let content = FinalizationContent::new(
            height,
            ic_crypto::crypto_hash(&self.pick_block_to_finality_sign(pool, height)?),
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

    /// Generate finalization shares for each notarized block in the validated
    /// pool.
    #[cfg(feature = "malicious_code")]
    pub(crate) fn maliciously_finalize_all(&self, pool: &PoolReader<'_>) -> Vec<FinalizationShare> {
        use ic_interfaces::consensus_pool::HeightRange;
        use ic_protobuf::log::malicious_behaviour_log_entry::v1::{
            MaliciousBehaviour, MaliciousBehaviourLogEntry,
        };
        trace!(self.log, "maliciously_finalize");
        let mut finalization_shares = Vec::new();

        let min_height = pool.get_finalized_height().increment();
        let max_height = pool.get_notarized_height();

        let proposals = pool
            .pool()
            .validated()
            .block_proposal()
            .get_by_height_range(HeightRange::new(min_height, max_height));

        for proposal in proposals {
            let block = proposal.as_ref();

            // if this replica already created a finalization share for this block, we do
            // not finality sign this block anymore. The point is not to spam.
            let signed_this_block_before = pool
                .pool()
                .validated()
                .finalization_share()
                .get_by_height(block.height)
                .any(|share| {
                    share.signature.signer == self.replica_config.node_id
                        && share.content.block == *proposal.content.get_hash()
                });

            if !signed_this_block_before {
                if let Some(finalization_share) = self.maliciously_finalize_block(pool, block) {
                    finalization_shares.push(finalization_share);
                }
            }
        }

        if !finalization_shares.is_empty() {
            info!(
                self.log,
                "[MALICIOUS] maliciously finalizing {} proposals",
                finalization_shares.len();
                malicious_behaviour => MaliciousBehaviourLogEntry { malicious_behaviour: MaliciousBehaviour::FinalizeAll as i32}
            );
        }

        finalization_shares
    }

    /// Try to create a finalization share for a given block.
    #[cfg(feature = "malicious_code")]
    fn maliciously_finalize_block(
        &self,
        pool: &PoolReader<'_>,
        block: &Block,
    ) -> Option<FinalizationShare> {
        let content = FinalizationContent::new(block.height, ic_crypto::crypto_hash(&block));
        let signature = self
            .crypto
            .sign(
                &content,
                self.replica_config.node_id,
                pool.registry_version(block.height)?,
            )
            .ok()?;
        Some(FinalizationShare { content, signature })
    }
}

/// This function creates responses to the message routing with computed DKG key
/// material for remote subnets.
pub fn generate_responses_to_subnet_calls(
    state_manager: &dyn StateManager<State = ReplicatedState>,
    certified_height: Height,
    transcripts_for_new_subnets: &BTreeMap<NiDkgId, Result<NiDkgTranscript, String>>,
    log: &ReplicaLogger,
) -> Vec<Response> {
    use ic_crypto::utils::ni_dkg::initial_ni_dkg_transcript_record_from_transcript;
    use ic_replicated_state::metadata_state::SubnetCallContext;
    use ic_types::{crypto::threshold_sig::ni_dkg::NiDkgTag, ic00::SetupInitialDKGResponse};

    let mut consensus_responses = Vec::<Response>::new();
    if let Ok(state) = state_manager.get_state_at(certified_height) {
        let contexts = &state
            .get_ref()
            .metadata
            .subnet_call_context_manager
            .contexts;
        for (callback_id, context) in contexts.iter() {
            let SubnetCallContext::SetupInitialDKGContext { target_id, .. } = context;

            let transcript = |dkg_tag| {
                transcripts_for_new_subnets
                    .iter()
                    .filter_map(|(id, transcript)| {
                        if id.dkg_tag == dkg_tag && id.target_subnet == Remote(*target_id) {
                            Some(transcript)
                        } else {
                            None
                        }
                    })
                    .last()
            };

            if let (Some(Ok(low_threshold_transcript)), Some(Ok(high_threshold_transcript))) = (
                transcript(NiDkgTag::LowThreshold),
                transcript(NiDkgTag::HighThreshold),
            ) {
                info!(
                    log,
                    "Found transcripts for other subnets with ids {:?} and {:?}",
                    low_threshold_transcript.dkg_id,
                    high_threshold_transcript.dkg_id
                );
                let low_threshold_transcript_record =
                    initial_ni_dkg_transcript_record_from_transcript(
                        low_threshold_transcript.clone(),
                    );
                let high_threshold_transcript_record =
                    initial_ni_dkg_transcript_record_from_transcript(
                        high_threshold_transcript.clone(),
                    );

                // This is what we expect consensus to reply with.
                let threshold_sig_pk = high_threshold_transcript.public_key();
                let subnet_threshold_public_key = PublicKeyProto::from(threshold_sig_pk);
                let key_der: Vec<u8> =
                    ic_crypto::threshold_sig_public_key_to_der(threshold_sig_pk).unwrap();
                let fresh_subnet_id =
                    SubnetId::new(PrincipalId::new_self_authenticating(key_der.as_slice()));

                let initial_transcript_records = SetupInitialDKGResponse {
                    low_threshold_transcript_record,
                    high_threshold_transcript_record,
                    fresh_subnet_id,
                    subnet_threshold_public_key,
                };

                consensus_responses.push(Response {
                    originator: CanisterId::ic_00(),
                    respondent: CanisterId::ic_00(),
                    originator_reply_callback: *callback_id,
                    refund: Funds::zero(),
                    response_payload: messages::Payload::Data(initial_transcript_records.encode()),
                });
            }
        }
    }
    consensus_responses
}

#[cfg(test)]
mod tests {
    //! Finalizer unit tests
    use super::*;
    use crate::consensus::mocks::{dependencies, dependencies_with_subnet_params, Dependencies};
    use ic_logger::replica_logger::no_op_logger;
    use ic_metrics::MetricsRegistry;
    use ic_test_utilities::{
        ingress_selector::FakeIngressSelector,
        message_routing::FakeMessageRouting,
        registry::SubnetRecordBuilder,
        state_manager::FakeStateManager,
        types::ids::{node_test_id, subnet_test_id},
    };
    use std::sync::Arc;

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
            let state_manager = Arc::new(FakeStateManager::new());

            let finalizer = Finalizer::new(
                replica_config,
                registry,
                membership,
                crypto,
                message_routing.clone(),
                ingress_selector,
                state_manager,
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
                Arc::new(FakeStateManager::new()),
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
                block.payload.as_ref().as_summary().registry_version,
                RegistryVersion::from(1)
            );
            assert_eq!(block.context.registry_version, RegistryVersion::from(10));
            block_proposal.content = HashedBlock::new(ic_crypto::crypto_hash, block.clone());
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
                block.payload.as_ref().as_summary().registry_version,
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
}
