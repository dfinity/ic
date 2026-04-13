//! Implementation of the payload builder of the canister http feature

use crate::{
    metrics::CanisterHttpPayloadBuilderMetrics,
    payload_builder::{
        parse::bytes_to_payload,
        utils::{
            estimate_response_with_consensus_size, find_flexible_responses,
            find_fully_replicated_response, find_non_replicated_response,
            group_shares_by_callback_id, grouped_shares_meet_divergence_criteria,
        },
    },
};
use candid::{Decode, Encode};
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
use ic_management_canister_types_private::{
    CanisterHttpResponsePayload, FlexibleHttpRequestResult,
};
use ic_metrics::MetricsRegistry;
use ic_registry_client_helpers::subnet::SubnetRegistry;
use ic_replicated_state::ReplicatedState;
use ic_types::{
    CountBytes, Height, NodeId, NumBytes, RegistryVersion, SubnetId,
    batch::{
        CanisterHttpPayload, ConsensusResponse, FlexibleCanisterHttpResponses,
        MAX_CANISTER_HTTP_PAYLOAD_SIZE, ValidationContext,
    },
    canister_http::{
        CANISTER_HTTP_MAX_RESPONSES_PER_BLOCK, CANISTER_HTTP_TIMEOUT_INTERVAL,
        CanisterHttpResponse, CanisterHttpResponseContent, CanisterHttpResponseDivergence,
        CanisterHttpResponseMetadata, CanisterHttpResponseWithConsensus, Replication,
    },
    consensus::Committee,
    crypto::{Signed, crypto_hash},
    messages::{CallbackId, Payload, RejectContext},
    registry::RegistryClientError,
    signature::BasicSignature,
};
use std::{
    collections::{BTreeMap, BTreeSet, HashSet},
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
    pub flexible_ok_responses: usize,
    pub flexible_ok_responses_candid_failures: usize,
    pub payload_bytes: usize,
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
        // Derive threshold and faults_tolerated from a single committee call
        let committee_members = match self.membership.get_canister_http_committee(height) {
            Ok(members) => members,
            Err(err) => {
                warn!(self.log, "Failed to get canister http committee: {:?}", err);
                return CanisterHttpPayload::default();
            }
        };
        let faults_tolerated = ic_types::consensus::get_faults_tolerated(committee_members.len());
        let threshold = committee_members.len() - faults_tolerated;

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

        let state = match self
            .state_reader
            .get_state_at(validation_context.certified_height)
        {
            Ok(state) => state,
            Err(err) => {
                warn!(
                    self.log,
                    "CanisterHttpPayloadBuilder: state unavailable at height {}: {err:?}",
                    validation_context.certified_height,
                );
                return CanisterHttpPayload::default();
            }
        };

        let canister_http_request_contexts = &state
            .get_ref()
            .metadata
            .subnet_call_context_manager
            .canister_http_request_contexts;

        let mut accumulated_size = 0;
        let mut responses_included = 0;

        let mut candidates = vec![];
        let mut timeouts = vec![];
        let mut divergence_responses = vec![];
        let mut flexible_responses = vec![];

        // Metrics counters
        let mut total_share_count = 0;
        let mut active_shares = 0;

        // Since aggregating signatures is potentially expensive (currently for
        // BasicSignatures it is not expensive), we pick the candidates first
        // (under the pool lock), then aggregate in a separate step.
        {
            let pool_access = self.pool.read().unwrap();

            // Get share candidates to include in the block
            let share_candidates = pool_access
                .get_validated_shares()
                .inspect(|_| {
                    total_share_count += 1;
                })
                // Filter out shares with the wrong registry version
                .filter(|&share| share.content.registry_version == consensus_registry_version)
                .inspect(|_| {
                    active_shares += 1;
                })
                // Filter out shares for responses to requests that already have
                // responses in the block chain up to the point we are creating a
                // new payload.
                .filter(|&response| !delivered_ids.contains(&response.content.id));

            // Group the shares by their metadata
            let shares_by_callback_id = group_shares_by_callback_id(share_candidates);

            self.metrics.total_shares.set(total_share_count);
            self.metrics.active_shares.set(active_shares);

            // Single pass over all open request contexts. Each callback_id is
            // handled exactly once.
            for (callback_id, request) in canister_http_request_contexts {
                if delivered_ids.contains(callback_id) {
                    continue;
                }
                if request.time + CANISTER_HTTP_TIMEOUT_INTERVAL < validation_context.time {
                    let candidate_size = callback_id.count_bytes();
                    let size = NumBytes::new((accumulated_size + candidate_size) as u64);
                    if size < max_payload_size {
                        timeouts.push(*callback_id);
                        accumulated_size += candidate_size;
                        // Because timeouts are very cheap to verify, they are
                        // not counted as responses (so that they are irrelevant
                        // for the CANISTER_HTTP_MAX_RESPONSES_PER_BLOCK limit.
                    }
                    continue;
                }
                if responses_included >= CANISTER_HTTP_MAX_RESPONSES_PER_BLOCK {
                    // We use `continue` here and not `break` so that more
                    // timeouts can be included in the payload.
                    continue;
                }
                let Some(grouped_shares) = shares_by_callback_id.get(callback_id) else {
                    continue;
                };
                match &request.replication {
                    Replication::FullyReplicated => {
                        if let Some((metadata, shares, content)) =
                            find_fully_replicated_response(grouped_shares, threshold, &*pool_access)
                        {
                            let candidate_size =
                                estimate_response_with_consensus_size(&metadata, &shares, &content);
                            let size = NumBytes::new((accumulated_size + candidate_size) as u64);
                            if size < max_payload_size {
                                candidates.push((metadata, shares, content));
                                responses_included += 1;
                                accumulated_size += candidate_size;
                            }
                        } else if grouped_shares_meet_divergence_criteria(
                            grouped_shares,
                            faults_tolerated,
                        ) {
                            let divergence = CanisterHttpResponseDivergence {
                                shares: grouped_shares
                                    .values()
                                    .flat_map(|shares| shares.iter())
                                    .map(|share| (*share).clone())
                                    .collect(),
                            };
                            let divergence_size = divergence.count_bytes();
                            let size = NumBytes::new((accumulated_size + divergence_size) as u64);
                            if size < max_payload_size {
                                divergence_responses.push(divergence);
                                responses_included += 1;
                                accumulated_size += divergence_size;
                            }
                        }
                    }
                    Replication::NonReplicated(designated_node_id) => {
                        if let Some((metadata, shares, content)) = find_non_replicated_response(
                            grouped_shares,
                            designated_node_id,
                            &*pool_access,
                        ) {
                            let candidate_size =
                                estimate_response_with_consensus_size(&metadata, &shares, &content);
                            let size = NumBytes::new((accumulated_size + candidate_size) as u64);
                            if size < max_payload_size {
                                candidates.push((metadata, shares, content));
                                responses_included += 1;
                                accumulated_size += candidate_size;
                            }
                        }
                    }
                    Replication::Flexible {
                        committee,
                        min_responses,
                        max_responses,
                    } => {
                        if let Some((group, group_size)) = find_flexible_responses(
                            *callback_id,
                            grouped_shares,
                            committee,
                            *min_responses,
                            *max_responses,
                            accumulated_size,
                            max_payload_size,
                            &*pool_access,
                        ) {
                            flexible_responses.push(group);
                            responses_included += 1;
                            accumulated_size += group_size;
                        }
                    }
                }
            }
        }

        CanisterHttpPayload {
            responses: candidates
                .into_iter()
                .filter_map(|(metadata, shares, content)| {
                    self.aggregate(consensus_registry_version, metadata, shares, content)
                })
                .collect(),
            timeouts,
            divergence_responses,
            flexible_responses,
            flexible_errors: vec![],
        }
    }

    fn validate_canister_http_payload_impl(
        &self,
        height: Height,
        payload: &CanisterHttpPayload,
        validation_context: &ValidationContext,
        mut delivered_ids: HashSet<CallbackId>,
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

        // Validate the timed out calls
        for timeout_id in &payload.timeouts {
            // Get requests
            let request = http_contexts.get(timeout_id).ok_or(
                CanisterHttpPayloadValidationError::InvalidArtifact(
                    InvalidCanisterHttpPayloadReason::UnknownCallbackId(*timeout_id),
                ),
            )?;

            // Check that the request has actually timed out
            if request.time + CANISTER_HTTP_TIMEOUT_INTERVAL >= validation_context.time {
                return invalid_artifact(InvalidCanisterHttpPayloadReason::NotTimedOut(
                    *timeout_id,
                ));
            }
            // Check for duplicates (already delivered or repeated in this payload)
            if !delivered_ids.insert(*timeout_id) {
                return invalid_artifact(InvalidCanisterHttpPayloadReason::DuplicateResponse(
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

            // Validate response against consensus registry version
            if response.proof.content.registry_version != consensus_registry_version {
                return invalid_artifact(
                    InvalidCanisterHttpPayloadReason::RegistryVersionMismatch {
                        expected: consensus_registry_version,
                        received: response.proof.content.registry_version,
                    },
                );
            }

            // Check that the response is not submitted twice
            if !delivered_ids.insert(response.content.id) {
                return invalid_artifact(InvalidCanisterHttpPayloadReason::DuplicateResponse(
                    response.content.id,
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
            let request_context = http_contexts.get(&callback_id).ok_or(
                CanisterHttpPayloadValidationError::InvalidArtifact(
                    InvalidCanisterHttpPayloadReason::UnknownCallbackId(callback_id),
                ),
            )?;

            let (effective_committee, effective_threshold) = match request_context.replication {
                Replication::NonReplicated(node_id) => (vec![node_id], 1),
                Replication::FullyReplicated => {
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
                Replication::Flexible { .. } => {
                    return invalid_artifact(
                        InvalidCanisterHttpPayloadReason::InvalidPayloadSection(callback_id),
                    );
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
            for (callback_id, grouped_shares) in grouped_shares {
                if !delivered_ids.insert(callback_id) {
                    return invalid_artifact(InvalidCanisterHttpPayloadReason::DuplicateResponse(
                        callback_id,
                    ));
                }
                let context = http_contexts.get(&callback_id).ok_or(
                    CanisterHttpPayloadValidationError::InvalidArtifact(
                        InvalidCanisterHttpPayloadReason::UnknownCallbackId(callback_id),
                    ),
                )?;
                if !matches!(context.replication, Replication::FullyReplicated) {
                    return invalid_artifact(
                        InvalidCanisterHttpPayloadReason::InvalidPayloadSection(callback_id),
                    );
                }
                if !grouped_shares_meet_divergence_criteria(&grouped_shares, faults_tolerated) {
                    return invalid_artifact(
                        InvalidCanisterHttpPayloadReason::DivergenceProofDoesNotMeetDivergenceCriteria,
                    );
                }
            }
        }

        // Validate flexible responses
        for group in &payload.flexible_responses {
            let callback_id = group.callback_id;

            if !delivered_ids.insert(callback_id) {
                return invalid_artifact(InvalidCanisterHttpPayloadReason::DuplicateResponse(
                    callback_id,
                ));
            }

            // Look up the request context and verify it's a Flexible replication
            let context = http_contexts.get(&callback_id).ok_or(
                CanisterHttpPayloadValidationError::InvalidArtifact(
                    InvalidCanisterHttpPayloadReason::UnknownCallbackId(callback_id),
                ),
            )?;
            let Replication::Flexible {
                committee: flex_committee,
                min_responses,
                max_responses,
            } = &context.replication
            else {
                return invalid_artifact(InvalidCanisterHttpPayloadReason::InvalidPayloadSection(
                    callback_id,
                ));
            };

            // Check response count is within [min_responses, max_responses]
            let (min_responses, max_responses) = (*min_responses, *max_responses);
            let count = group.responses.len();
            if count < min_responses as usize || count > max_responses as usize {
                return invalid_artifact(
                    InvalidCanisterHttpPayloadReason::FlexibleResponseCountOutOfRange {
                        callback_id,
                        count,
                        min_responses,
                        max_responses,
                    },
                );
            }

            let mut seen_signers = HashSet::new();

            for entry in &group.responses {
                // Callback id consistency
                if entry.response.id != callback_id {
                    return invalid_artifact(
                        InvalidCanisterHttpPayloadReason::FlexibleCallbackIdMismatch {
                            callback_id,
                            mismatched_id: entry.response.id,
                        },
                    );
                }
                if entry.proof.content.id != callback_id {
                    return invalid_artifact(
                        InvalidCanisterHttpPayloadReason::FlexibleCallbackIdMismatch {
                            callback_id,
                            mismatched_id: entry.proof.content.id,
                        },
                    );
                }

                // Rejects are not allowed in flexible ok-responses
                if matches!(
                    entry.response.content,
                    CanisterHttpResponseContent::Reject(_)
                ) {
                    return invalid_artifact(
                        InvalidCanisterHttpPayloadReason::FlexibleRejectNotAllowedInOkResponses {
                            callback_id,
                        },
                    );
                }

                // No duplicate signers
                let signer = entry.proof.signature.signer;
                if !seen_signers.insert(signer) {
                    return invalid_artifact(
                        InvalidCanisterHttpPayloadReason::FlexibleDuplicateSigner {
                            callback_id,
                            signer,
                        },
                    );
                }

                // Signer must be in the flexible committee
                if !flex_committee.contains(&signer) {
                    return invalid_artifact(
                        InvalidCanisterHttpPayloadReason::FlexibleSignerNotInCommittee {
                            callback_id,
                            signer,
                        },
                    );
                }

                // Content hash must match
                let calculated_hash = crypto_hash(&entry.response);
                if calculated_hash != entry.proof.content.content_hash {
                    return invalid_artifact(
                        InvalidCanisterHttpPayloadReason::ContentHashMismatch {
                            metadata_hash: entry.proof.content.content_hash.clone(),
                            calculated_hash,
                        },
                    );
                }

                // Content size must match
                let calculated_size = entry.response.content.count_bytes() as u32;
                if calculated_size != entry.proof.content.content_size {
                    return invalid_artifact(
                        InvalidCanisterHttpPayloadReason::ContentSizeMismatch {
                            metadata_size: entry.proof.content.content_size,
                            calculated_size,
                        },
                    );
                }

                // Registry version must match
                if entry.proof.content.registry_version != consensus_registry_version {
                    return invalid_artifact(
                        InvalidCanisterHttpPayloadReason::RegistryVersionMismatch {
                            expected: consensus_registry_version,
                            received: entry.proof.content.registry_version,
                        },
                    );
                }

                // Verify the individual share signature
                self.crypto
                    .verify(&entry.proof, consensus_registry_version)
                    .map_err(|err| {
                        CanisterHttpPayloadValidationError::InvalidArtifact(
                            InvalidCanisterHttpPayloadReason::SignatureError(Box::new(err)),
                        )
                    })?;
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
        parse::payload_to_bytes(payload, max_size)
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

        let divergence_responses = messages
            .divergence_responses
            .into_iter()
            .filter_map(divergence_response_into_reject)
            .inspect(|_| stats.divergence_responses += 1);

        let flexible_ok_responses = messages
            .flexible_responses
            .into_iter()
            .map(flexible_ok_responses_into_consensus_response)
            .inspect(|result| match result {
                Some(_) => stats.flexible_ok_responses += 1,
                None => stats.flexible_ok_responses_candid_failures += 1,
            })
            .flatten();

        let responses = responses
            .chain(timeouts)
            .chain(divergence_responses)
            .chain(flexible_ok_responses)
            .collect();

        (responses, stats)
    }
}

/// Converts a [`FlexibleCanisterHttpResponses`] into a [`ConsensusResponse`].
///
/// Returns `None` if Candid decoding/encoding fails, which leads to skipping
/// the delivery of this response. This should never occur, but if it does,
/// eventually a timeout will gracefully end the outstanding callback.
fn flexible_ok_responses_into_consensus_response(
    response_group: FlexibleCanisterHttpResponses,
) -> Option<ConsensusResponse> {
    let payloads: Vec<_> = response_group
        .responses
        .into_iter()
        .filter_map(|entry| match entry.response.content {
            CanisterHttpResponseContent::Success(data) => {
                Some(Decode!(&data, CanisterHttpResponsePayload).ok())
            }
            CanisterHttpResponseContent::Reject(_) => {
                // Unreachable: payload building/validation ensure
                // that there are no rejects in the ok-responses.
                None
            }
        })
        // Decoding errors short-circuit the collection and None is returned.
        .collect::<Option<_>>()?;

    let bytes = Encode!(&FlexibleHttpRequestResult::Ok(payloads)).ok()?;

    Some(ConsensusResponse::new(
        response_group.callback_id,
        Payload::Data(bytes),
    ))
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
/// The function includes request id, which is also part of the hashed value.
fn divergence_response_into_reject(
    response: CanisterHttpResponseDivergence,
) -> Option<ConsensusResponse> {
    let Some(id) = response.shares.first().map(|share| share.content.id) else {
        // NOTE: We skip delivering the divergence response, if it has no shares
        // Such a divergence response should never validate, therefore this should never happen
        // However, if it where ever to happen, we can ignore it here.
        // This is sound, since eventually a timeout will end the outstanding callback anyway.
        return None;
    };

    // Count the different content hashes, that we have encountered in the divergence response
    let mut hash_counts = BTreeMap::new();
    response
        .shares
        .into_iter()
        .map(|share| share.content.content_hash.get().0)
        .for_each(|hash| {
            hash_counts
                .entry(hash)
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
                "No consensus could be reached. Replicas had different responses. Details: request_id: {}, hashes: {}",
                id,
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
