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
use ic_logger::{ReplicaLogger, warn};
use ic_metrics::MetricsRegistry;
use ic_registry_client_helpers::subnet::SubnetRegistry;
use ic_replicated_state::ReplicatedState;
use ic_types::{
    CountBytes, Height, NodeId, NumBytes, RegistryVersion, SubnetId,
    batch::{
        CanisterHttpPayload, ConsensusResponse, MAX_CANISTER_HTTP_PAYLOAD_SIZE, ValidationContext,
    },
    canister_http::{
        CANISTER_HTTP_MAX_RESPONSES_PER_BLOCK, CANISTER_HTTP_TIMEOUT_INTERVAL,
        CanisterHttpRequestContext, CanisterHttpResponse, CanisterHttpResponseContent,
        CanisterHttpResponseDivergence, CanisterHttpResponseMetadata, CanisterHttpResponseProof,
        CanisterHttpResponseWithConsensus, Replication,
    },
    consensus::Committee,
    crypto::Signed,
    messages::{CallbackId, Payload, RejectContext},
    registry::RegistryClientError,
    signature::BasicSignature,
};
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
        // Get the threshold value that is needed for consensus
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

        // Get the consensus registry version
        let consensus_registry_version = match registry_version_at_height(
            self.cache.as_ref(),
            height,
        ) {
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

        let mut accumulated_size = 0;
        let mut responses_included = 0;

        let mut candidates = vec![];
        let mut timeouts = vec![];
        let mut divergence_responses = vec![];

        // Metrics counters
        let mut unique_includable_responses = 0;
        let mut timeouts_included = 0;
        let mut total_share_count = 0;
        let mut active_shares = 0;
        let mut unique_responses_count = 0;

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

        // Check the state for timeouts NOTE: We can not use the existing
        // timed out artifacts for this task, since we don't have consensus
        // on them. For example a malicious node might publish a single
        // timed out metadata share and we would pick it up to generate a
        // time out response. Instead, we scan the state metadata for timed
        // out requests and generate time out responses based on that
        // Iterate over all outstanding canister http requests
        for (callback_id, request) in canister_http_request_contexts {
            unique_includable_responses += 1;
            let candidate_size = callback_id.count_bytes();
            let size = NumBytes::new((accumulated_size + candidate_size) as u64);
            if size >= max_payload_size {
                // All timeouts have the same size, so we can stop iterating.
                break;
            } else if request.time + CANISTER_HTTP_TIMEOUT_INTERVAL < validation_context.time
                && !delivered_ids.contains(callback_id)
            {
                timeouts_included += 1;
                timeouts.push(*callback_id);
                accumulated_size += candidate_size;
            }
        }

        // Since aggegating the signatures is expensive, we don't want to do the
        // size checks after aggregation. Also we don't want to hold the lock on
        // the pool while aggregating. Therefore, we pick the candidates for the
        // payload first, then aggregate the signatures in a second step
        {
            let pool_access = self.pool.read().unwrap();

            // Get share candidates to include in the block
            let share_candidates = pool_access
                .get_validated_shares()
                .inspect(|_| {
                    total_share_count += 1;
                })
                // Filter out shares that are timed out or have the wrong registry versions
                .filter(|&response| {
                    utils::check_share_against_context(
                        consensus_registry_version,
                        response,
                        validation_context,
                    )
                })
                .inspect(|_| {
                    active_shares += 1;
                })
                // Filter out shares for responses to requests that already have
                // responses in the block chain up to the point we are creating a
                // new payload.
                .filter(|&response| !delivered_ids.contains(&response.content.id));

            // Group the shares by their metadata
            let response_candidates_by_callback_id = group_shares_by_callback_id(share_candidates);

            self.metrics.total_shares.set(total_share_count);
            self.metrics.active_shares.set(active_shares);

            let candidates_and_divergences = response_candidates_by_callback_id
                .into_iter()
                .filter_map(|(id, grouped_shares)| {
                    let consensus_candidate =
                        grouped_shares.iter().find_map(|(metadata, shares)| {
                            unique_responses_count += 1;
                            match canister_http_request_contexts
                                .get(&id)
                                .map(|context| &context.replication)
                            {
                                Some(Replication::NonReplicated(node_id)) => {
                                    // For a non-replicated call, we require EXACTLY ONE share,
                                    // and it MUST be from the designated node.
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
                    } else {
                        // No set of grouped shares large enough was found
                        // so now we check whether we have divergence.
                        if grouped_shares_meet_divergence_criteria(
                            &grouped_shares,
                            faults_tolerated,
                        ) {
                            Some(CandidateOrDivergence::Divergence(
                                CanisterHttpResponseDivergence {
                                    shares: grouped_shares
                                        .into_iter()
                                        .flat_map(|(_, shares)| shares.into_iter().cloned())
                                        .collect(),
                                },
                            ))
                        } else {
                            // If not, we don't include this response candidate at all
                            None
                        }
                    }
                });

            for candidate_or_divergence in candidates_and_divergences {
                unique_includable_responses += 1;
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
        };

        self.metrics.included_timeouts.set(timeouts_included);
        self.metrics.unique_responses.set(unique_responses_count);
        self.metrics
            .unique_includable_responses
            .set(unique_includable_responses);

        // Now that we have the candidates, aggregate the signatures and construct the payload

        CanisterHttpPayload {
            responses: candidates
                .drain(..)
                .filter_map(|(metadata, shares, content)| {
                    self.aggregate(consensus_registry_version, metadata, shares, content)
                })
                .collect(),
            timeouts,
            divergence_responses,
        }
    }

    fn validate_canister_http_payload_impl(
        &self,
        height: Height,
        payload: &CanisterHttpPayload,
        validation_context: &ValidationContext,
        delivered_ids: HashSet<CallbackId>,
    ) -> Result<(), PayloadValidationError> {
        // Empty payloads are always valid
        if payload.is_empty() {
            return Ok(());
        }

        // Check whether feature is enabled and reject if it isn't.
        // NOTE: All payloads that are processed at this point are non-empty
        if !self.is_enabled(validation_context).map_err(|err| {
            ValidationError::ValidationFailed(
                consensus::PayloadValidationFailure::RegistryUnavailable(err),
            )
        })? {
            return validation_failed(CanisterHttpPayloadValidationFailure::Disabled);
        }

        // Check number of responses
        if payload.num_non_timeout_responses() > CANISTER_HTTP_MAX_RESPONSES_PER_BLOCK {
            return invalid_artifact(InvalidCanisterHttpPayloadReason::TooManyResponses {
                expected: CANISTER_HTTP_MAX_RESPONSES_PER_BLOCK,
                received: payload.num_non_timeout_responses(),
            });
        }

        // Validate the timed out calls
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
            // Get requests
            let request = http_contexts.get(timeout_id).ok_or(
                CanisterHttpPayloadValidationError::InvalidArtifact(
                    InvalidCanisterHttpPayloadReason::UnknownCallbackId(*timeout_id),
                ),
            )?;

            // Check that they are timed out and no dupicates
            if request.time + CANISTER_HTTP_TIMEOUT_INTERVAL >= validation_context.time
                || delivered_ids.contains(timeout_id)
            {
                return invalid_artifact(InvalidCanisterHttpPayloadReason::NotTimedOut(
                    *timeout_id,
                ));
            }
        }

        // Get the consensus registry version
        let consensus_registry_version = registry_version_at_height(self.cache.as_ref(), height)
            .ok_or(CanisterHttpPayloadValidationError::ValidationFailed(
                CanisterHttpPayloadValidationFailure::ConsensusRegistryVersionUnavailable,
            ))?;

        // Check conditions on individual responses
        for response in &payload.responses {
            // Check that response is consistent
            utils::check_response_consistency(response)
                .map_err(CanisterHttpPayloadValidationError::InvalidArtifact)?;

            // Validate response against `ValidationContext`
            utils::check_response_against_context(
                consensus_registry_version,
                response,
                validation_context,
            )
            .map_err(CanisterHttpPayloadValidationError::InvalidArtifact)?;

            // Check that the response is not submitted twice
            if delivered_ids.contains(&response.content.id) {
                return invalid_artifact(InvalidCanisterHttpPayloadReason::DuplicateResponse(
                    response.content.id,
                ));
            }
        }

        // Check that there are no duplicate responses among non-replicated requests.
        // As it's very easy for a malicious delegated node to submit multiple responses (even different).
        let mut non_replicated_ids = HashSet::new();
        for response in &payload.responses {
            let callback_id = &response.content.id;

            if let Some(&CanisterHttpRequestContext {
                replication: Replication::NonReplicated(_),
                ..
            }) = http_contexts.get(callback_id)
                && !non_replicated_ids.insert(callback_id)
            {
                return invalid_artifact(InvalidCanisterHttpPayloadReason::DuplicateResponse(
                    *callback_id,
                ));
            }
        }

        let committee = self
            .membership
            .get_canister_http_committee(height)
            .map_err(|_| {
                CanisterHttpPayloadValidationError::ValidationFailed(
                    CanisterHttpPayloadValidationFailure::Membership,
                )
            })?;

        // Verify the signatures
        // NOTE: We do this in a separate loop because this check is expensive and we want to
        // do all the cheap checks first
        for response in &payload.responses {
            let callback_id = response.content.id;
            let (effective_committee, effective_threshold) = match http_contexts.get(&callback_id) {
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

            self.crypto
                .verify_aggregate(&response.proof, consensus_registry_version)
                .map_err(|err| {
                    CanisterHttpPayloadValidationError::InvalidArtifact(
                        InvalidCanisterHttpPayloadReason::SignatureError(Box::new(err)),
                    )
                })?;
        }

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
                    committee,
                    valid_signers,
                });
            }

            for share in response.shares.iter() {
                self.crypto
                    .verify(share, consensus_registry_version)
                    .map_err(|err| {
                        CanisterHttpPayloadValidationError::InvalidArtifact(
                            InvalidCanisterHttpPayloadReason::SignatureError(Box::new(err)),
                        )
                    })?;
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
        if payload.is_empty() {
            return Ok(());
        }

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
                id,
                timeout.as_nanos_since_unix_epoch(),
                hash_counts.join(", ")
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
