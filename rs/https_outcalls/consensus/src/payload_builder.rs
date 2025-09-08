//! Implementation of the payload builder of the canister http feature

use crate::{
    metrics::CanisterHttpPayloadBuilderMetrics,
    payload_builder::{
        parse::bytes_to_payload,
        utils::{group_shares_by_callback_id, grouped_shares_meet_divergence_criteria},
    },
};
use ic_consensus_utils::{
    crypto::ConsensusCrypto, membership::Membership, registry_version_at_height,
};
use ic_error_types::RejectCode;
use ic_interfaces::{
    batch_payload::{BatchPayloadBuilder, IntoMessages, PastPayload, ProposalContext},
    canister_http::{
        CanisterHttpPayloadValidationError, CanisterHttpPayloadValidationFailure, CanisterHttpPool,
        InvalidCanisterHttpPayloadReason,
    },
    consensus::{self, PayloadValidationError},
    consensus_pool::ConsensusPoolCache,
    validation::ValidationError,
};
use ic_interfaces_registry::RegistryClient;
use ic_interfaces_state_manager::StateReader;
use ic_logger::{warn, ReplicaLogger};
use ic_metrics::MetricsRegistry;
use ic_registry_client_helpers::subnet::SubnetRegistry;
use ic_replicated_state::ReplicatedState;
use ic_types::{
    batch::{
        CanisterHttpPayload, ConsensusResponse, ValidationContext, MAX_CANISTER_HTTP_PAYLOAD_SIZE,
    },
    canister_http::{
        CanisterHttpRequestContext, CanisterHttpResponse, CanisterHttpResponseContent,
        CanisterHttpResponseDivergence, CanisterHttpResponseMetadata, CanisterHttpResponseProof,
        CanisterHttpResponseWithConsensus, Replication, CANISTER_HTTP_MAX_RESPONSES_PER_BLOCK,
        CANISTER_HTTP_TIMEOUT_INTERVAL,
    },
    consensus::Committee,
    crypto::Signed,
    messages::{CallbackId, Payload, RejectContext},
    registry::RegistryClientError,
    signature::{BasicSignature, BasicSignatureBatch},
    CountBytes, Height, NodeId, NumBytes, RegistryVersion, SubnetId,
};
use rayon::prelude::*;
use std::time::{Duration, Instant};
use std::{
    collections::{BTreeMap, BTreeSet, HashSet},
    mem::size_of,
    sync::{Arc, RwLock},
};

pub(crate) mod parse;
#[cfg(all(test, feature = "proptest"))]
mod proptests;
#[cfg(test)]
mod tests;
mod utils;

/// Statistics about http messages. The stats contain data about
/// the number of canister http message types in a canister http payload
/// but also data about the payload_size
#[derive(Debug, Default)]
pub struct CanisterHttpBatchStats {
    pub responses: usize,
    pub timeouts: usize,
    pub divergence_responses: usize,
    pub single_signature_responses: usize,
    pub payload_bytes: usize,
}

enum CandidateOrDivergence {
    Candidate(
        (
            CanisterHttpResponseMetadata,
            BTreeSet<BasicSignature<CanisterHttpResponseMetadata>>,
            CanisterHttpResponse,
        ),
    ),
    Divergence(CanisterHttpResponseDivergence),
}

/// Implementation of the [`BatchPayloadBuilder`] for the canister http feature.
pub struct CanisterHttpPayloadBuilderImpl {
    pool: Arc<RwLock<dyn CanisterHttpPool>>,
    cache: Arc<dyn ConsensusPoolCache>,
    crypto: Arc<dyn ConsensusCrypto>,
    state_reader: Arc<dyn StateReader<State = ReplicatedState>>,
    membership: Arc<Membership>,
    subnet_id: SubnetId,
    registry: Arc<dyn RegistryClient>,
    metrics: CanisterHttpPayloadBuilderMetrics,
    log: ReplicaLogger,
}

impl CanisterHttpPayloadBuilderImpl {
    /// Create and initialize an instance of [`CanisterHttpPayloadBuilderImpl`].
    pub fn new(
        pool: Arc<RwLock<dyn CanisterHttpPool>>,
        cache: Arc<dyn ConsensusPoolCache>,
        crypto: Arc<dyn ConsensusCrypto>,
        state_reader: Arc<dyn StateReader<State = ReplicatedState>>,
        subnet_id: SubnetId,
        registry: Arc<dyn RegistryClient>,
        metrics_registry: &MetricsRegistry,
        log: ReplicaLogger,
    ) -> Self {
        let membership = Arc::new(Membership::new(cache.clone(), registry.clone(), subnet_id));

        match rayon::ThreadPoolBuilder::new().num_threads(4).build_global() {
            Ok(_) => println!("Successfully created a global thread pool with 4 threads."),
            Err(e) => println!("Error building global thread pool: {}", e),
        }

        Self {
            pool,
            cache,
            crypto,
            state_reader,
            membership,
            subnet_id,
            registry,
            metrics: CanisterHttpPayloadBuilderMetrics::new(metrics_registry),
            log,
        }
    }

    /// Returns true, if the canister http feature is enabled in the registry
    fn is_enabled(
        &self,
        validation_context: &ValidationContext,
    ) -> Result<bool, RegistryClientError> {
        self.registry
            .get_features(self.subnet_id, validation_context.registry_version)
            .map(|features| features.unwrap_or_default().http_requests)
    }

    /// Aggregates the signature and creates the [`CanisterHttpResponseWithConsensus`] message.
    fn aggregate(
        &self,
        registry_version: RegistryVersion,
        metadata: CanisterHttpResponseMetadata,
        shares: BTreeSet<BasicSignature<CanisterHttpResponseMetadata>>,
        content: CanisterHttpResponse,
    ) -> Option<CanisterHttpResponseWithConsensus> {
        match self
            .crypto
            .aggregate(shares.iter().collect(), registry_version)
        {
            Err(err) => {
                warn!(
                    self.log,
                    "Failed to aggregate signature for CanisterHttpResponse: {:?}", err
                );
                None
            }
            Ok(signature) => Some(CanisterHttpResponseWithConsensus {
                content,
                proof: Signed {
                    content: metadata,
                    signature,
                },
            }),
        }
    }

    fn get_canister_http_payload_impl(
        &self,
        height: Height,
        validation_context: &ValidationContext,
        delivered_ids: HashSet<CallbackId>,
        max_payload_size: NumBytes,
    ) -> CanisterHttpPayload {

        println!("BLOCKPROPOSAL at height={}", height);
        let total_start = Instant::now();



        // let busy_wait_duration = Duration::from_millis(70);
        // let start = Instant::now();
        // while start.elapsed() < busy_wait_duration {
        //     // This hint tells the CPU that we are in a spin-loop,
        //     // which can be more efficient than just an empty loop
        //     // and prevents the compiler from optimizing it away.
        //     std::hint::spin_loop();
        // }
    
        // --- Block 1: Initial Setup & Registry Lookups ---
        let block_1_start = Instant::now();
        let threshold = match self
            .membership
            .get_committee_threshold(height, Committee::CanisterHttp)
        {
            Ok(threshold) => threshold,
            Err(err) => {
                warn!(self.log, "Failed to get membership: {:?}", err);
                return CanisterHttpPayload::default();
            }
        };
    
        let consensus_registry_version =
            match registry_version_at_height(self.cache.as_ref(), height) {
                Some(registry_version) => registry_version,
                None => {
                    warn!(
                    self.log,
                    "Failed to obtain consensus registry version in canister http payload builder"
                );
                    return CanisterHttpPayload::default();
                }
            };
    
        let faults_tolerated = match self.membership.get_canister_http_committee(height) {
            Ok(members) => ic_types::consensus::get_faults_tolerated(members.len()),
            _ => {
                warn!(self.log, "Failed to get canister http committee");
                return CanisterHttpPayload::default();
            }
        };
        let block_1_setup_duration = block_1_start.elapsed();
    
        // --- Block 2: State Loading & Timeout Scan ---
        let block_2_start = Instant::now();
        let mut accumulated_size = 0;
        let mut timeouts = vec![];
    
        let empty_contexts = BTreeMap::new();
        let state_result = self
            .state_reader
            .get_state_at(validation_context.certified_height);
        let canister_http_request_contexts =
            state_result.as_ref().map_or(&empty_contexts, |state| {
                &state
                    .get_ref()
                    .metadata
                    .subnet_call_context_manager
                    .canister_http_request_contexts
            });
    
        for (callback_id, request) in canister_http_request_contexts {
            let candidate_size = callback_id.count_bytes();
            let size = NumBytes::new((accumulated_size + candidate_size) as u64);
            if size >= max_payload_size {
                break;
            } else if request.time + CANISTER_HTTP_TIMEOUT_INTERVAL < validation_context.time
                && !delivered_ids.contains(callback_id)
            {
                timeouts.push(*callback_id);
                accumulated_size += candidate_size;
            }
        }
        let block_2_timeouts_duration = block_2_start.elapsed();
    
        let mut candidates = vec![];
        let mut divergence_responses = vec![];
        let mut responses_included = 0;
    
        // --- Block 3: Pool Access, Share Filtering, and Consensus Finding ---
        let block_3_start = Instant::now();
        let mut sub_3a_filtering_duration = Duration::ZERO;
        let mut sub_3b_grouping_duration = Duration::ZERO;
        let mut sub_3c_consensus_finding_duration = Duration::ZERO;
        let mut block_4_candidate_sizing_duration = Duration::ZERO;
    
        {
            let pool_access = self.pool.read().unwrap();
            let filtering_start = Instant::now();
            let share_candidates = pool_access
                .get_validated_shares()
                .filter(|&response| {
                    utils::check_share_against_context(
                        consensus_registry_version,
                        response,
                        validation_context,
                    )
                })
                .filter(|&response| !delivered_ids.contains(&response.content.id));
            sub_3a_filtering_duration = filtering_start.elapsed();
    
            let grouping_start = Instant::now();
            let response_candidates_by_callback_id = group_shares_by_callback_id(share_candidates);
            sub_3b_grouping_duration = grouping_start.elapsed();
    
            let consensus_finding_start = Instant::now();
            let candidates_and_divergences: Vec<_> = response_candidates_by_callback_id
                .into_iter()
                .filter_map(|(id, grouped_shares)| {
                    let consensus_candidate =
                        grouped_shares.iter().find_map(|(metadata, shares)| {
                            match canister_http_request_contexts
                                .get(&id)
                                .map(|context| &context.replication)
                            {
                                Some(Replication::NonReplicated(node_id)) => {
                                    shares
                                        .iter()
                                        .find(|share| share.signature.signer == *node_id)
                                        .map(|correct_share| (metadata, vec![*correct_share]))
                                }
                                None | Some(Replication::FullyReplicated) => {
                                    let signers: BTreeSet<_> =
                                        shares.iter().map(|share| share.signature.signer).collect();
                                    if signers.len() >= threshold {
                                        Some((metadata, shares.clone()))
                                    } else {
                                        None
                                    }
                                }
                            }
                        });
    
                    if let Some((metadata, shares)) = consensus_candidate {
                        pool_access
                            .get_response_content_by_hash(&metadata.content_hash)
                            .map(|content| {
                                CandidateOrDivergence::Candidate((
                                    metadata.clone(),
                                    shares.iter().map(|share| share.signature.clone()).collect(),
                                    content,
                                ))
                            })
                    } else if grouped_shares_meet_divergence_criteria(&grouped_shares, faults_tolerated)
                    {
                        Some(CandidateOrDivergence::Divergence(
                            CanisterHttpResponseDivergence {
                                shares: grouped_shares
                                    .into_iter()
                                    .flat_map(|(_, shares)| shares.into_iter().cloned())
                                    .collect(),
                            },
                        ))
                    } else {
                        None
                    }
                })
                .collect();
            sub_3c_consensus_finding_duration = consensus_finding_start.elapsed();
    
            // --- Block 4: Candidate Selection & Size Checks ---
            let block_4_start = Instant::now();
            for candidate_or_divergence in candidates_and_divergences {
                match candidate_or_divergence {
                    CandidateOrDivergence::Candidate((metadata, shares, content)) => {
                        let candidate_size =
                            size_of::<CanisterHttpResponseProof>() + content.count_bytes();
                        let size = NumBytes::new((accumulated_size + candidate_size) as u64);
                        if size < max_payload_size {
                            candidates.push((metadata.clone(), shares, content));
                            responses_included += 1;
                            accumulated_size += candidate_size;
                        }
                    }
                    CandidateOrDivergence::Divergence(divergence) => {
                        let divergence_size = divergence.count_bytes();
                        let size = NumBytes::new((accumulated_size + divergence_size) as u64);
                        if size < max_payload_size {
                            divergence_responses.push(divergence);
                            responses_included += 1;
                            accumulated_size += divergence_size;
                        }
                    }
                }
                if responses_included >= CANISTER_HTTP_MAX_RESPONSES_PER_BLOCK {
                    break;
                }
            }    
            block_4_candidate_sizing_duration = block_4_start.elapsed();
        };
        
        let block_3_pool_processing_duration = block_3_start.elapsed();
    
        // --- Block 5: Final Aggregation & Payload Construction ---
        let block_5_start = Instant::now();
        let payload = CanisterHttpPayload {
            responses: candidates
                .drain(..)
                .filter_map(|(metadata, shares, content)| {
                    self.aggregate(consensus_registry_version, metadata, shares, content)
                })
                .collect(),
            timeouts,
            divergence_responses,
        };
        let block_5_aggregation_duration = block_5_start.elapsed();
        let total_duration = total_start.elapsed();
    
        println!(
            "CanisterHttpGetPayload: result=OK total_us={} num_responses={} num_timeouts={} num_divergence={} block_1_setup_us={} block_2_timeouts_us={} block_3_pool_processing_us={} (sub_3a_filtering_us={}, sub_3b_grouping_us={}, sub_3c_consensus_finding_us={}) block_4_candidate_sizing_us={} block_5_aggregation_us={}",
            total_duration.as_micros(),
            payload.responses.len(),
            payload.timeouts.len(),
            payload.divergence_responses.len(),
            block_1_setup_duration.as_micros(),
            block_2_timeouts_duration.as_micros(),
            block_3_pool_processing_duration.as_micros(),
            sub_3a_filtering_duration.as_micros(),
            sub_3b_grouping_duration.as_micros(),
            sub_3c_consensus_finding_duration.as_micros(),
            block_4_candidate_sizing_duration.as_micros(), // Note: This is now timed outside the pool lock
            block_5_aggregation_duration.as_micros(),
        );
    
        payload
    }

    pub fn validate_canister_http_payload_impl(
        &self,
        height: Height,
        payload: &CanisterHttpPayload,
        validation_context: &ValidationContext,
        delivered_ids: HashSet<CallbackId>,
    ) -> Result<(), PayloadValidationError> {

        println!("BLOCKVERIFIER start at height={}", height);

        let total_start = Instant::now();

        // let busy_wait_duration = Duration::from_millis(70);
        // let start = Instant::now();
        // while start.elapsed() < busy_wait_duration {
        //     // This hint tells the CPU that we are in a spin-loop,
        //     // which can be more efficient than just an empty loop
        //     // and prevents the compiler from optimizing it away.
        //     std::hint::spin_loop();
        // }


        // --- Block 1: Initial Checks ---
        let block_1_start = Instant::now();
        // if payload.is_empty() {
        //     // Log this special case and exit.
        //     println!(
        //         "CanisterHttpPayloadValidation: result=OK reason=\"EmptyPayload\" total_us={}",
        //         total_start.elapsed().as_micros()
        //     );
        //     return Ok(());
        // }
        if !self.is_enabled(validation_context).map_err(|err| {
            ValidationError::ValidationFailed(
                consensus::PayloadValidationFailure::RegistryUnavailable(err),
            )
        })? {
            return validation_failed(CanisterHttpPayloadValidationFailure::Disabled);
        }
        if payload.num_non_timeout_responses() > CANISTER_HTTP_MAX_RESPONSES_PER_BLOCK {
            return invalid_artifact(InvalidCanisterHttpPayloadReason::TooManyResponses {
                expected: CANISTER_HTTP_MAX_RESPONSES_PER_BLOCK,
                received: payload.num_non_timeout_responses(),
            });
        }
        let block_1_duration = block_1_start.elapsed();

        // --- Block 2: State Loading and Timeout Validation ---
        let block_2_start = Instant::now();
        let state = &self
            .state_reader
            .get_state_at(validation_context.certified_height)
            .map_err(|_| {
                CanisterHttpPayloadValidationError::ValidationFailed(
                    CanisterHttpPayloadValidationFailure::StateUnavailable,
                )
            })?;
        let http_contexts = &state
            .get_ref()
            .metadata
            .subnet_call_context_manager
            .canister_http_request_contexts;
        for timeout_id in &payload.timeouts {
            let request = http_contexts.get(timeout_id).ok_or(
                CanisterHttpPayloadValidationError::InvalidArtifact(
                    InvalidCanisterHttpPayloadReason::UnknownCallbackId(*timeout_id),
                ),
            )?;
            if request.time + CANISTER_HTTP_TIMEOUT_INTERVAL >= validation_context.time
                || delivered_ids.contains(timeout_id)
            {
                return invalid_artifact(InvalidCanisterHttpPayloadReason::NotTimedOut(
                    *timeout_id,
                ));
            }
        }
        let block_2_duration = block_2_start.elapsed();

        // --- Block 3: Registry Version Lookup ---
        let block_3_start = Instant::now();
        let consensus_registry_version = registry_version_at_height(self.cache.as_ref(), height)
            .ok_or(CanisterHttpPayloadValidationError::ValidationFailed(
                CanisterHttpPayloadValidationFailure::ConsensusRegistryVersionUnavailable,
            ))?;
        let block_3_duration = block_3_start.elapsed();

        // --- Block 4 & 5: Response Loops (Cheap Checks) ---
        let block_4_5_start = Instant::now();
        for response in &payload.responses {
            utils::check_response_consistency(response)
                .map_err(CanisterHttpPayloadValidationError::InvalidArtifact)?;
            utils::check_response_against_context(
                consensus_registry_version,
                response,
                validation_context,
            )
            .map_err(CanisterHttpPayloadValidationError::InvalidArtifact)?;
            if delivered_ids.contains(&response.content.id) {
                return invalid_artifact(InvalidCanisterHttpPayloadReason::DuplicateResponse(
                    response.content.id,
                ));
            }
        }
        let mut non_replicated_ids = HashSet::new();
        for response in &payload.responses {
            let callback_id = &response.content.id;
            if let Some(&CanisterHttpRequestContext {
                replication: Replication::NonReplicated(_),
                ..
            }) = http_contexts.get(callback_id)
            {
                if !non_replicated_ids.insert(callback_id) {
                    return invalid_artifact(InvalidCanisterHttpPayloadReason::DuplicateResponse(
                        *callback_id,
                    ));
                }
            }
        }
        let block_4_5_duration = block_4_5_start.elapsed();

        // --- Block 6 & 7: Committee Lookup & Main Signature Verification Loop ---
        let block_6_7_start = Instant::now();
        let committee = self
            .membership
            .get_canister_http_committee(height)
            .map_err(|_| {
                CanisterHttpPayloadValidationError::ValidationFailed(
                    CanisterHttpPayloadValidationFailure::Membership,
                )
            })?;
        // NEW: Initialize detailed cumulative timers for the loop's interior
        let mut loop7_committee_logic_duration = Duration::ZERO;
        let mut loop7_signer_check_duration = Duration::ZERO;
        let mut loop7_crypto_verify_duration = Duration::ZERO; // Renamed for clarity

        let mut proofs = vec![];

        let x: Result<(), PayloadValidationError> = payload
            .responses
            .iter()
            .map(|response| {
                // --- Measure Sub-block A: Committee/Threshold Logic ---
                let committee_logic_start = Instant::now();
                let callback_id = response.content.id;
                let (effective_committee, effective_threshold) =
                    match http_contexts.get(&callback_id) {
                        Some(&CanisterHttpRequestContext {
                            replication: Replication::NonReplicated(ref node_id),
                            ..
                        }) => (vec![*node_id], 1),
                        None
                        | Some(&CanisterHttpRequestContext {
                            replication: Replication::FullyReplicated,
                            ..
                        }) => {
                            let threshold = match self
                                .membership
                                .get_committee_threshold(height, Committee::CanisterHttp)
                            {
                                Ok(threshold) => threshold,
                                Err(err) => {
                                    warn!(self.log, "Failed to get membership: {:?}", err);
                                    return validation_failed(
                                        CanisterHttpPayloadValidationFailure::Membership,
                                    );
                                }
                            };
                            (committee.clone(), threshold)
                        }
                    };
                let loop7_committee_logic_duration = committee_logic_start.elapsed();

                // --- Measure Sub-block B: Signer Validation ---
                let signer_check_start = Instant::now();
                let (valid_signers, invalid_signers): (Vec<NodeId>, Vec<NodeId>) = response
                    .proof
                    .signature
                    .signatures_map
                    .keys()
                    .cloned()
                    .partition(|signer| effective_committee.iter().any(|id| id == signer));
                if !invalid_signers.is_empty() {
                    return invalid_artifact(InvalidCanisterHttpPayloadReason::SignersNotMembers {
                        invalid_signers,
                        committee: effective_committee,
                        valid_signers,
                    });
                }

                if valid_signers.len() < effective_threshold {
                    return invalid_artifact(InvalidCanisterHttpPayloadReason::NotEnoughSigners {
                        committee: effective_committee,
                        signers: valid_signers,
                        expected_threshold: effective_threshold,
                    });
                }
                let loop7_signer_check_duration = signer_check_start.elapsed();

                let crypto_start = Instant::now();

                proofs.push(&response.proof);

                let loop7_crypto_verify_duration = crypto_start.elapsed();
                Ok(())
            })
            .collect();
        x?;

        let crypto_verify_start = Instant::now();
        let mut batches_by_proof = vec![];

        proofs.iter().for_each(|proof| {
            batches_by_proof.push((&proof.content, &proof.signature));
        });

        let num_proofs = batches_by_proof.len();
        let num_threads = rayon::current_num_threads();
        // Ceiling division to ensure all items are processed
        let chunk_size = (num_proofs + num_threads - 1) / num_threads;

        // 2. CHUNK & 3. PROCESS (in parallel)
        let result = batches_by_proof
            .par_chunks(chunk_size)
            .try_for_each(|chunk| {
                // Each thread receives a `chunk`, which is a `&[(H, BasicSignatureBatch<H>)]`.
                // This slice perfectly matches the signature of our verification function.
                self.crypto.verify_multi_sig_batch(chunk, consensus_registry_version)
            });

        // 4. COMBINE RESULTS: Handle the final combined result.
        result.map_err(|err| {
            CanisterHttpPayloadValidationError::InvalidArtifact(
                InvalidCanisterHttpPayloadReason::SignatureError(Box::new(err)),
            )
        })?;

        let loop7_crypto_verify_duration = crypto_verify_start.elapsed();

        let block_6_7_duration = block_6_7_start.elapsed();

        // --- Block 8: Divergence Proofs ---
        let block_8_start = Instant::now();
        let mut crypto_ind_verify_duration = Duration::ZERO;
        if !payload.divergence_responses.is_empty() {
            let faults_tolerated = match self.membership.get_canister_http_committee(height) {
                Ok(members) => ic_types::consensus::get_faults_tolerated(members.len()),
                _ => {
                    warn!(self.log, "Failed to get canister http committee");
                    return validation_failed(CanisterHttpPayloadValidationFailure::Membership);
                }
            };

            for response in &payload.divergence_responses {
                let (valid_signers, invalid_signers): (Vec<NodeId>, Vec<NodeId>) = response
                    .shares
                    .iter()
                    .map(|share| share.signature.signer)
                    .partition(|signer| committee.iter().any(|id| id == signer));
                if !invalid_signers.is_empty() {
                    return invalid_artifact(InvalidCanisterHttpPayloadReason::SignersNotMembers {
                        invalid_signers,
                        committee: committee.clone(),
                        valid_signers,
                    });
                }

                for share in response.shares.iter() {
                    let crypto_start = Instant::now();
                    self.crypto
                        .verify(share, consensus_registry_version)
                        .map_err(|err| {
                            CanisterHttpPayloadValidationError::InvalidArtifact(
                                InvalidCanisterHttpPayloadReason::SignatureError(Box::new(err)),
                            )
                        })?;
                    crypto_ind_verify_duration += crypto_start.elapsed();
                }

                let grouped_shares = group_shares_by_callback_id(response.shares.iter());
                if grouped_shares.len() != 1 {
                    return invalid_artifact(
                        InvalidCanisterHttpPayloadReason::DivergenceProofContainsMultipleCallbackIds,
                    );
                }
                for (_, grouped_shares) in grouped_shares {
                    if !grouped_shares_meet_divergence_criteria(&grouped_shares, faults_tolerated) {
                        return invalid_artifact(
                            InvalidCanisterHttpPayloadReason::DivergenceProofDoesNotMeetDivergenceCriteria,
                        );
                    }
                }
            }
        }
        let block_8_duration = block_8_start.elapsed();

        // This is the only log output for the entire successful run.
        println!(
            "CanisterHttpPayloadValidation: result=OK total_us={} num_responses={} num_timeouts={} num_divergence={} block_1_initial_checks_us={} block_2_state_timeouts_us={} block_3_registry_us={} block_4_5_cheap_response_loops_us={} block_6_7_sig_verify_loop_us={} (loop7_committee_logic_us={}, loop7_signer_check_us={}, loop7_crypto_agg_us={}) block_8_divergence_loop_us={} (crypto_ind_us={})",
            total_start.elapsed().as_micros(),
            payload.responses.len(),
            payload.timeouts.len(),
            payload.divergence_responses.len(),
            block_1_duration.as_micros(),
            block_2_duration.as_micros(),
            block_3_duration.as_micros(),
            block_4_5_duration.as_micros(),
            block_6_7_duration.as_micros(),
            // --- NEW DETAILED METRICS FOR THE LOOP ---
            loop7_committee_logic_duration.as_micros(),
            loop7_signer_check_duration.as_micros(),
            loop7_crypto_verify_duration.as_micros(),
            // --- END NEW METRICS ---
            block_8_duration.as_micros(),
            crypto_ind_verify_duration.as_micros()
        );

        println!("BLOCKVERIFIER end at height={}", height);

        Ok(())
    }
}

impl BatchPayloadBuilder for CanisterHttpPayloadBuilderImpl {
    fn build_payload(
        &self,
        height: Height,
        max_size: NumBytes,
        past_payloads: &[PastPayload],
        context: &ValidationContext,
    ) -> Vec<u8> {
        let _time = self
            .metrics
            .op_duration
            .with_label_values(&["build"])
            .start_timer();

        // Check whether feature is enabled, return empty payload if not enabled
        // or registry unavailable
        match self.is_enabled(context) {
            Err(_) => {
                warn!(self.log, "CanisterHttpPayloadBuilder: Registry unavailable");
                return vec![];
            }
            Ok(false) => return vec![],
            Ok(true) => (),
        }

        let max_size = std::cmp::min(
            max_size,
            NumBytes::new(MAX_CANISTER_HTTP_PAYLOAD_SIZE as u64),
        );
        let delivered_ids = parse::parse_past_payload_ids(past_payloads, &self.log);
        let payload = self.get_canister_http_payload_impl(height, context, delivered_ids, max_size);
        parse::payload_to_bytes(&payload, max_size)
    }

    fn validate_payload(
        &self,
        height: Height,
        proposal_context: &ProposalContext,
        payload: &[u8],
        past_payloads: &[PastPayload],
    ) -> Result<(), PayloadValidationError> {
        let _time = self
            .metrics
            .op_duration
            .with_label_values(&["validate"])
            .start_timer();

        // Empty payloads are always valid
        // if payload.is_empty() {
        //     return Ok(());
        // }

        if payload.len() > MAX_CANISTER_HTTP_PAYLOAD_SIZE {
            return Err(ValidationError::InvalidArtifact(
                consensus::InvalidPayloadReason::InvalidCanisterHttpPayload(
                    InvalidCanisterHttpPayloadReason::PayloadTooBig {
                        expected: MAX_CANISTER_HTTP_PAYLOAD_SIZE,
                        received: payload.len(),
                    },
                ),
            ));
        }

        let delivered_ids = parse::parse_past_payload_ids(past_payloads, &self.log);
        let payload = parse::bytes_to_payload(payload).map_err(|e| {
            ValidationError::InvalidArtifact(
                consensus::InvalidPayloadReason::InvalidCanisterHttpPayload(
                    InvalidCanisterHttpPayloadReason::DecodeError(e),
                ),
            )
        })?;
        self.validate_canister_http_payload_impl(
            height,
            &payload,
            proposal_context.validation_context,
            delivered_ids,
        )
    }
}

impl IntoMessages<(Vec<ConsensusResponse>, CanisterHttpBatchStats)>
    for CanisterHttpPayloadBuilderImpl
{
    fn into_messages(payload: &[u8]) -> (Vec<ConsensusResponse>, CanisterHttpBatchStats) {
        let mut stats = CanisterHttpBatchStats::default();

        let messages = bytes_to_payload(payload)
            .expect("Failed to parse a payload that was already validated");

        let responses = messages.responses.into_iter().map(|response| {
            if response.proof.signature.signatures_map.len() == 1 {
                stats.single_signature_responses += 1;
            }
            stats.responses += 1;
            ConsensusResponse::new(
                response.content.id,
                match response.content.content {
                    CanisterHttpResponseContent::Success(data) => Payload::Data(data),
                    CanisterHttpResponseContent::Reject(canister_http_reject) => {
                        Payload::Reject(RejectContext::from(&canister_http_reject))
                    }
                },
            )
        });

        let timeouts = messages.timeouts.iter().map(|callback| {
            // Map timeouts to a rejected response
            stats.timeouts += 1;
            ConsensusResponse::new(
                *callback,
                Payload::Reject(RejectContext::new(
                    RejectCode::SysTransient,
                    "Canister http request timed out",
                )),
            )
        });

        let divergece_responses = messages
            .divergence_responses
            .iter()
            .filter_map(divergence_response_into_reject)
            .inspect(|_| stats.divergence_responses += 1);

        let responses = responses
            .chain(timeouts)
            .chain(divergece_responses)
            .collect();

        (responses, stats)
    }
}

/// Turns a [`CanisterHttpResponseDivergence`] into a [`ConsensusResponse`] containing a rejection.
///
/// This function generates a detailed error message.
/// This will enable a developer to get some insight into the nature of the divergence problems, which they are facing.
/// It allows to get insight into whether the responses are split among a very small number of possible responses or each replica
/// got a unique response.
/// The first issue could point to some issue rate limiting (e.g. some replicas receive 429s) while the later would point to an
/// issue with the transform function (e.g. some non-deterministic component such as timestamp has not been removed).
///
/// The function includes request id and timeout, which are also part of the hashed value.
fn divergence_response_into_reject(
    response: &CanisterHttpResponseDivergence,
) -> Option<ConsensusResponse> {
    // Get the id and timeout, which need to be reported in the error message as well
    let Some((id, timeout)) = response
        .shares
        .first()
        .map(|share| (share.content.id, share.content.timeout))
    else {
        // NOTE: We skip delivering the divergence response, if it has no shares
        // Such a divergence response should never validate, therefore this should never happen
        // However, if it where ever to happen, we can ignore it here.
        // This is sound, since eventually a timeout will end the outstanding callback anyway.
        return None;
    };

    // Count the different content hashes, that we have encountered in the divergence resonse
    let mut hash_counts = BTreeMap::new();
    response
        .shares
        .iter()
        .map(|share| share.content.content_hash.clone().get().0)
        .for_each(|share| {
            hash_counts
                .entry(share)
                .and_modify(|count| *count += 1)
                .or_insert(1);
        });

    // Now convert into a vector
    let mut hash_counts = hash_counts.into_iter().collect::<Vec<_>>();

    // Sort in ascending order by number of counts
    hash_counts.sort_by_key(|(_, count)| *count);
    // Convert them into hex strings
    let hash_counts = hash_counts
        .iter()
        .rev()
        .map(|(hash, count)| format!("[{}: {}]", hex::encode(hash), count))
        .collect::<Vec<_>>();

    Some(ConsensusResponse::new(
        id,
        Payload::Reject(RejectContext::new(
            RejectCode::SysTransient,
            format!(
                "No consensus could be reached. Replicas had different responses. Details: request_id: {}, timeout: {}, hashes: {}",
                id, timeout.as_nanos_since_unix_epoch(), hash_counts.join(", ")
            ),
        )),
    ))
}

fn validation_failed(
    err: CanisterHttpPayloadValidationFailure,
) -> Result<(), PayloadValidationError> {
    Err(ValidationError::ValidationFailed(
        consensus::PayloadValidationFailure::CanisterHttpPayloadValidationFailed(err),
    ))
}

fn invalid_artifact(
    reason: InvalidCanisterHttpPayloadReason,
) -> Result<(), PayloadValidationError> {
    Err(ValidationError::InvalidArtifact(
        consensus::InvalidPayloadReason::InvalidCanisterHttpPayload(reason),
    ))
}
