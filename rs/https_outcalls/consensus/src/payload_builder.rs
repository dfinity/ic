//! Implementation of the payload builder of the canister http feature

use crate::{
    metrics::CanisterHttpPayloadBuilderMetrics,
    payload_builder::{
        parse::bytes_to_payload,
        utils::{
            FlexibleFindResult, RefundedNodes, ResponseShareSigInput, find_async_receipts,
            find_flexible_result, find_fully_replicated_response, find_non_flexible_out_of_cycles,
            find_non_replicated_response, group_shares_by_callback_id,
            grouped_shares_meet_divergence_criteria, response_share_sig_inputs,
            validate_flexible_response_with_proof, validate_response_share,
        },
    },
};
use candid::{Decode, Encode};
use ic_consensus_utils::{
    crypto::ConsensusCrypto,
    membership::{CanisterHttpCommittee, Membership, MembershipError},
};
use ic_error_types::RejectCode;
use ic_https_outcalls_pricing::fees::{flexible_initial_spent, non_flexible_initial_spent};
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
    CanisterHttpResponsePayload, FlexibleHttpGlobalError, FlexibleHttpNodeDetail,
    FlexibleHttpNodeError, FlexibleHttpRequestErr, FlexibleHttpRequestResult,
    HttpRequestResourceReport,
};
use ic_metrics::MetricsRegistry;
use ic_registry_client_helpers::subnet::SubnetRegistry;
use ic_replicated_state::ReplicatedState;
use ic_replicated_state::metadata_state::subnet_call_context_manager::DELIVERED_CANISTER_HTTP_REQUEST_CONTEXT_TIMEOUT;
use ic_types::{
    CountBytes, Height, NodeId, NumBytes, RegistryVersion, SubnetId,
    batch::{
        CanisterHttpAsyncSpent, CanisterHttpInitialSpent, CanisterHttpPayload, CanisterHttpSpent,
        ConsensusResponse, FlexibleCanisterHttpError, FlexibleCanisterHttpResponseWithProof,
        FlexibleCanisterHttpResponses, MAX_CANISTER_HTTP_PAYLOAD_SIZE, ValidationContext,
    },
    canister_http::{
        CANISTER_HTTP_MAX_RESPONSES_PER_BLOCK, CANISTER_HTTP_TIMEOUT_INTERVAL,
        CanisterHttpRequestContext, CanisterHttpResponseContent, CanisterHttpResponseDivergence,
        CanisterHttpResponseShare, Replication,
    },
    consensus::Threshold,
    messages::{CallbackId, Payload, RejectContext},
    registry::RegistryClientError,
    signature::BasicSigBatchEntry,
};
use ic_types_cycles::Cycles;
use std::{
    collections::{BTreeMap, BTreeSet, HashSet},
    sync::{Arc, RwLock},
};

pub(crate) mod parse;
pub use parse::PastPayloads;

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
    pub out_of_cycles: usize,
    pub async_receipts: usize,
    pub single_signature_responses: usize,
    pub flexible_ok_responses: usize,
    pub flexible_ok_responses_candid_failures: usize,
    pub flexible_errors: BTreeMap<&'static str, usize>,
    pub flexible_errors_candid_failures: usize,
    pub payload_bytes: usize,
}

/// Implementation of the [`BatchPayloadBuilder`] for the canister http feature.
pub struct CanisterHttpPayloadBuilderImpl {
    pool: Arc<RwLock<dyn CanisterHttpPool>>,
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

    fn get_canister_http_payload_impl(
        &self,
        validation_context: &ValidationContext,
        past_payloads: PastPayloads,
        max_payload_size: NumBytes,
    ) -> CanisterHttpPayload {
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

        let PastPayloads {
            delivered_ids,
            refunded_nodes,
        } = past_payloads;

        let subnet_call_context_manager = &state.get_ref().metadata.subnet_call_context_manager;
        let canister_http_request_contexts =
            &subnet_call_context_manager.canister_http_request_contexts;
        let delivered_canister_http_request_contexts =
            &subnet_call_context_manager.delivered_canister_http_request_contexts;

        let mut accumulated_size = 0;
        let mut responses_included = 0;

        let mut responses = vec![];
        let mut timeouts = vec![];
        let mut divergence_responses = vec![];
        let mut out_of_cycles = vec![];
        let mut flexible_responses = vec![];
        let mut flexible_errors = vec![];
        let mut async_receipts = vec![];

        // Metrics counters
        let mut total_share_count = 0;
        let mut active_shares = 0;

        // Pick the candidates under the pool lock.
        {
            let pool_access = self.pool.read().unwrap();

            // Get share candidates to include in the block
            let share_candidates = pool_access
                .get_validated_shares()
                .inspect(|_| {
                    total_share_count += 1;
                })
                // Filter out shares for responses to requests that already have
                // responses in the block chain up to the point we are creating a
                // new payload.
                .filter(|&share| !delivered_ids.contains(&share.content.id()))
                .inspect(|_| {
                    active_shares += 1;
                });

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
                    // Because timeouts are very cheap to verify, they are
                    // not counted as responses (so that they are irrelevant
                    // for the CANISTER_HTTP_MAX_RESPONSES_PER_BLOCK limit.
                    if matches!(request.replication, Replication::Flexible { .. }) {
                        let error = FlexibleCanisterHttpError::Timeout {
                            callback_id: *callback_id,
                        };
                        let candidate_size = error.count_bytes();
                        let size = NumBytes::new((accumulated_size + candidate_size) as u64);
                        if size < max_payload_size {
                            flexible_errors.push(error);
                            accumulated_size += candidate_size;
                        }
                    } else {
                        let candidate_size = callback_id.count_bytes();
                        let size = NumBytes::new((accumulated_size + candidate_size) as u64);
                        if size < max_payload_size {
                            timeouts.push(*callback_id);
                            accumulated_size += candidate_size;
                        }
                    }
                    let groups = shares_by_callback_id.get(callback_id);
                    let (groups, success, reject) = groups.map_or((0, 0, 0), |groups| {
                        let (mut success, mut reject) = (0, 0);
                        for share in groups.values().flatten() {
                            if share.content.is_reject() {
                                reject += 1;
                            } else {
                                success += 1;
                            }
                        }
                        (groups.len(), success, reject)
                    });
                    warn!(
                        self.log,
                        "CanisterHttpPayloadBuilder: timeout for callback_id {callback_id} \
                        with {groups} groups ({success} success, {reject} reject), pricing {:?}, \
                        replication {:?}, refund status {:?}",
                        request.pricing_version,
                        request.replication,
                        request.refund_status
                    );
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
                        // Committee threshold and faults_tolerated for this
                        // request are derived from the registry version pinned in
                        // its context.
                        let CanisterHttpCommittee {
                            committee,
                            threshold,
                            faults_tolerated,
                        } = match self
                            .membership
                            .get_canister_http_committee(request.registry_version)
                        {
                            Ok(committee) => committee,
                            Err(err) => {
                                warn!(self.log, "Failed to get canister http committee: {:?}", err);
                                continue;
                            }
                        };
                        if let Some(response) = find_fully_replicated_response(
                            grouped_shares,
                            threshold,
                            request,
                            &*pool_access,
                            &self.log,
                            &self.metrics,
                        ) {
                            let candidate_size = response.count_bytes();
                            let size = NumBytes::new((accumulated_size + candidate_size) as u64);
                            if size < max_payload_size {
                                responses.push(response);
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
                        } else if let Some(error) = find_non_flexible_out_of_cycles(
                            *callback_id,
                            grouped_shares,
                            &BTreeSet::from_iter(committee),
                            threshold,
                            request,
                        ) {
                            let error_size = error.count_bytes();
                            let size = NumBytes::new((accumulated_size + error_size) as u64);
                            if size < max_payload_size {
                                out_of_cycles.push(error);
                                responses_included += 1;
                                accumulated_size += error_size;
                            }
                        }
                    }
                    Replication::NonReplicated(designated_node_id) => {
                        if let Some(response) = find_non_replicated_response(
                            grouped_shares,
                            designated_node_id,
                            request,
                            &*pool_access,
                            &self.log,
                            &self.metrics,
                        ) {
                            let candidate_size = response.count_bytes();
                            let size = NumBytes::new((accumulated_size + candidate_size) as u64);
                            if size < max_payload_size {
                                responses.push(response);
                                responses_included += 1;
                                accumulated_size += candidate_size;
                            }
                        } else if let Some(error) = find_non_flexible_out_of_cycles(
                            *callback_id,
                            grouped_shares,
                            // Only the designated replica's response is ever delivered, so
                            // it is a committee of one and its own threshold.
                            &BTreeSet::from([*designated_node_id]),
                            /* threshold = */ 1,
                            request,
                        ) {
                            let error_size = error.count_bytes();
                            let size = NumBytes::new((accumulated_size + error_size) as u64);
                            if size < max_payload_size {
                                out_of_cycles.push(error);
                                responses_included += 1;
                                accumulated_size += error_size;
                            }
                        }
                    }
                    Replication::Flexible {
                        committee,
                        min_responses,
                        max_responses,
                    } => match find_flexible_result(
                        *callback_id,
                        grouped_shares,
                        committee,
                        *min_responses,
                        *max_responses,
                        accumulated_size,
                        max_payload_size,
                        request,
                        &*pool_access,
                    ) {
                        FlexibleFindResult::OkResponses(group, group_size) => {
                            // Note: budget tracking w.r.t. `max_payload_size`
                            // is done directly in `find_flexible_result`.
                            flexible_responses.push(group);
                            responses_included += 1;
                            accumulated_size += group_size;
                        }
                        FlexibleFindResult::Error(error, error_size) => {
                            let size = NumBytes::new((accumulated_size + error_size) as u64);
                            if size < max_payload_size {
                                flexible_errors.push(error);
                                responses_included += 1;
                                accumulated_size += error_size;
                            }
                        }
                        FlexibleFindResult::Pending => {}
                    },
                }
            }

            // Collect the asynchronous receipts of the requests that have already
            // been responded to.
            for (callback_id, request) in delivered_canister_http_request_contexts {
                if responses_included >= CANISTER_HTTP_MAX_RESPONSES_PER_BLOCK {
                    // Break early to avoid iterating through all open contexts.
                    break;
                }
                // Skip contexts that have already timed out.
                if delivered_context_timed_out(request, validation_context) {
                    continue;
                }
                let Some(grouped_shares) = shares_by_callback_id.get(callback_id) else {
                    continue;
                };
                let committee = match self.request_committee(request) {
                    Ok(committee) => committee,
                    Err(err) => {
                        warn!(self.log, "Failed to get canister http committee: {:?}", err);
                        continue;
                    }
                };
                // Skip shares for nodes that have already issued a refund for this request,
                // according to the certified state or any past payload above it.
                let already_refunded = RefundedNodes::new(*callback_id, request, &refunded_nodes);
                for share in find_async_receipts(grouped_shares, &committee, &already_refunded) {
                    if responses_included >= CANISTER_HTTP_MAX_RESPONSES_PER_BLOCK {
                        break;
                    }
                    let share_size = share.count_bytes();
                    let size = NumBytes::new((accumulated_size + share_size) as u64);
                    if size < max_payload_size {
                        async_receipts.push(share.clone());
                        responses_included += 1;
                        accumulated_size += share_size;
                    }
                }
            }
        }

        if responses_included >= CANISTER_HTTP_MAX_RESPONSES_PER_BLOCK {
            warn!(
                every_n_seconds => 15,
                self.log,
                "CanisterHttpPayloadBuilder: reached max responses per block ({})",
                CANISTER_HTTP_MAX_RESPONSES_PER_BLOCK
            );
            self.metrics.max_responses_per_block_reached.inc();
        }

        CanisterHttpPayload {
            responses,
            timeouts,
            divergence_responses,
            out_of_cycles,
            flexible_responses,
            flexible_errors,
            async_receipts,
        }
    }

    /// The set of replicas that may have produced a receipt for this request,
    /// evaluated at the registry version pinned in the request context.
    fn request_committee(
        &self,
        context: &CanisterHttpRequestContext,
    ) -> Result<BTreeSet<NodeId>, MembershipError> {
        match &context.replication {
            Replication::FullyReplicated => self
                .membership
                .get_canister_http_committee(context.registry_version)
                .map(|committee| BTreeSet::from_iter(committee.committee)),
            // Only the designated replica ever produces a receipt.
            Replication::NonReplicated(node_id) => Ok(BTreeSet::from([*node_id])),
            Replication::Flexible { committee, .. } => Ok(committee.clone()),
        }
    }

    /// The replicas a response to a *non-flexible* request may come from, and how
    /// many of them have to agree on one for it to be delivered.
    fn non_flexible_committee(
        &self,
        callback_id: CallbackId,
        context: &CanisterHttpRequestContext,
    ) -> Result<(BTreeSet<NodeId>, Threshold), CanisterHttpPayloadValidationError> {
        match &context.replication {
            Replication::FullyReplicated => {
                let CanisterHttpCommittee {
                    committee,
                    threshold,
                    ..
                } = self
                    .membership
                    .get_canister_http_committee(context.registry_version)
                    .map_err(|err| {
                        warn!(self.log, "Failed to get membership: {:?}", err);
                        CanisterHttpPayloadValidationError::ValidationFailed(
                            CanisterHttpPayloadValidationFailure::Membership,
                        )
                    })?;
                Ok((BTreeSet::from_iter(committee), threshold))
            }
            Replication::NonReplicated(node_id) => Ok((BTreeSet::from([*node_id]), 1)),
            Replication::Flexible { .. } => {
                Err(CanisterHttpPayloadValidationError::InvalidArtifact(
                    InvalidCanisterHttpPayloadReason::InvalidPayloadSection(callback_id),
                ))
            }
        }
    }

    pub fn validate_canister_http_payload_impl(
        &self,
        payload: &CanisterHttpPayload,
        validation_context: &ValidationContext,
        past_payloads: PastPayloads,
    ) -> Result<(), PayloadValidationError> {
        let PastPayloads {
            mut delivered_ids,
            refunded_nodes,
        } = past_payloads;
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
        let subnet_call_context_manager = &state.get_ref().metadata.subnet_call_context_manager;
        let http_contexts = &subnet_call_context_manager.canister_http_request_contexts;
        let delivered_http_contexts =
            &subnet_call_context_manager.delivered_canister_http_request_contexts;

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

        // Shares reconstructed from aggregated response proofs.
        let mut reconstructed_shares: Vec<(CanisterHttpResponseShare, RegistryVersion)> =
            Vec::new();
        // Accumulates all signatures in the payload, so that they can be checked
        // in a single batched multi-message verification call at the very end.
        let mut sig_inputs: Vec<ResponseShareSigInput> = Vec::new();

        // Check conditions on individual responses
        for response in &payload.responses {
            // Check that response is consistent
            utils::check_response_consistency(response)
                .map_err(CanisterHttpPayloadValidationError::InvalidArtifact)?;

            // Check that the response is not submitted twice
            if !delivered_ids.insert(response.content.id) {
                return invalid_artifact(InvalidCanisterHttpPayloadReason::DuplicateResponse(
                    response.content.id,
                ));
            }

            let callback_id = response.content.id;
            let request_context = http_contexts.get(&callback_id).ok_or(
                CanisterHttpPayloadValidationError::InvalidArtifact(
                    InvalidCanisterHttpPayloadReason::UnknownCallbackId(callback_id),
                ),
            )?;

            utils::check_content_size_within_limit(
                &response.proof.metadata,
                callback_id,
                request_context,
            )
            .map_err(CanisterHttpPayloadValidationError::InvalidArtifact)?;

            let subnet_size = request_context.subnet_size;
            let (effective_committee, effective_threshold) =
                self.non_flexible_committee(callback_id, request_context)?;

            let (valid_signers, invalid_signers): (Vec<NodeId>, Vec<NodeId>) = response
                .proof
                .signatures
                .keys()
                .cloned()
                .partition(|signer| effective_committee.contains(signer));
            if !invalid_signers.is_empty() {
                return invalid_artifact(InvalidCanisterHttpPayloadReason::SignersNotMembers {
                    invalid_signers,
                    committee: effective_committee.into_iter().collect(),
                    valid_signers,
                });
            }

            if valid_signers.len() < effective_threshold {
                return invalid_artifact(InvalidCanisterHttpPayloadReason::NotEnoughSigners {
                    committee: effective_committee.into_iter().collect(),
                    signers: valid_signers,
                    expected_threshold: effective_threshold,
                });
            }

            // Enforce the per-replica spend limit on every receipt in the proof.
            for sig in response.proof.signatures.values() {
                utils::check_spent_within_limit(&sig.payment_receipt, request_context)
                    .map_err(CanisterHttpPayloadValidationError::InvalidArtifact)?;
            }

            // The collective initial spend must match the value recomputed from
            // the request context's subnet size and the signed per-replica
            // receipts, and must stay within the signers' collective allowance.
            let expected = non_flexible_initial_spent(&response.proof, subnet_size);
            if response.initial_spent != expected {
                return invalid_artifact(InvalidCanisterHttpPayloadReason::InitialSpentMismatch {
                    callback_id,
                    received: response.initial_spent,
                    expected,
                });
            }
            utils::check_initial_spent_within_limit(
                response.initial_spent,
                response.proof.signatures.len(),
                callback_id,
                request_context,
                None,
            )
            .map_err(CanisterHttpPayloadValidationError::InvalidArtifact)?;

            // Reconstruct the per-signer shares from the response proof.
            reconstructed_shares.extend(
                utils::reconstruct_individual_shares(&response.proof)
                    .map(|share| (share, request_context.registry_version)),
            );
        }

        // Defer signature verification of the reconstructed response shares.
        sig_inputs.extend(
            reconstructed_shares
                .iter()
                .map(|(share, registry_version)| BasicSigBatchEntry {
                    signer: share.signature.signer,
                    signature: &share.signature.signature,
                    message: &share.content,
                    registry_version: *registry_version,
                }),
        );

        for response in &payload.divergence_responses {
            // A divergence proof must contain shares for exactly one callback id.
            let grouped_shares = group_shares_by_callback_id(response.shares.iter());
            if grouped_shares.len() != 1 {
                return invalid_artifact(
                    InvalidCanisterHttpPayloadReason::DivergenceProofContainsMultipleCallbackIds,
                );
            }

            let mut seen_signers = HashSet::new();
            for share in &response.shares {
                let signer = share.signature.signer;
                if !seen_signers.insert(signer) {
                    return invalid_artifact(
                        InvalidCanisterHttpPayloadReason::DivergenceDuplicateSigner {
                            callback_id: share.content.id(),
                            signer,
                        },
                    );
                }
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

                // The committee is the subnet node set at the registry version
                // pinned in the request context.
                let CanisterHttpCommittee {
                    committee,
                    faults_tolerated,
                    ..
                } = self
                    .membership
                    .get_canister_http_committee(context.registry_version)
                    .map_err(|_| {
                        CanisterHttpPayloadValidationError::ValidationFailed(
                            CanisterHttpPayloadValidationFailure::Membership,
                        )
                    })?;

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

                // Defer signature verification.
                sig_inputs.extend(response_share_sig_inputs(
                    &response.shares,
                    context.registry_version,
                ));

                // Enforce the per-replica spend and response size limits for divergence
                // shares.
                for share in grouped_shares.values().flatten() {
                    utils::check_spent_within_limit(&share.content.payment_receipt, context)
                        .map_err(CanisterHttpPayloadValidationError::InvalidArtifact)?;
                    utils::check_content_size_within_limit(
                        &share.content.metadata,
                        callback_id,
                        context,
                    )
                    .map_err(CanisterHttpPayloadValidationError::InvalidArtifact)?;
                }

                if !grouped_shares_meet_divergence_criteria(&grouped_shares, faults_tolerated) {
                    return invalid_artifact(
                        InvalidCanisterHttpPayloadReason::DivergenceProofDoesNotMeetDivergenceCriteria,
                    );
                }
            }
        }

        // Validate out-of-cycles errors for fully- and non-replicated requests.
        for error in &payload.out_of_cycles {
            let callback_id = error.callback_id;
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
            // Which replicas a response could come from, and how many of them have to
            // agree on it for it to be delivered.
            let (committee, threshold) = self.non_flexible_committee(callback_id, context)?;

            let mut seen_signers = HashSet::new();
            for share in &error.shares {
                validate_response_share(share, callback_id, &committee, &mut seen_signers, context)
                    .map_err(CanisterHttpPayloadValidationError::InvalidArtifact)?;
            }
            // Defer signature verification.
            sig_inputs.extend(response_share_sig_inputs(
                &error.shares,
                context.registry_version,
            ));

            // The shares must prove that the committee's remaining allowances can no
            // longer pay for a response...
            let expected = utils::check_non_flexible_out_of_cycles(
                error.shares.iter(),
                committee.len(),
                threshold,
                callback_id,
                context,
            )
            .map_err(CanisterHttpPayloadValidationError::InvalidArtifact)?;
            // ...and the figures reported to the caller must be the ones it is proved by.
            for (field, received, expected) in [
                ("min_cost", error.min_cost, expected.min_cost),
                (
                    "unspent_allowance",
                    error.unspent_allowance,
                    expected.unspent_allowance,
                ),
            ] {
                if received != expected {
                    return invalid_artifact(
                        InvalidCanisterHttpPayloadReason::OutOfCyclesFigureMismatch {
                            callback_id,
                            field,
                            received,
                            expected,
                        },
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
            let subnet_size = context.subnet_size;
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

            for response_with_proof in &group.responses {
                validate_flexible_response_with_proof(
                    response_with_proof,
                    callback_id,
                    flex_committee,
                    &mut seen_signers,
                    context,
                )
                .map_err(CanisterHttpPayloadValidationError::InvalidArtifact)?;

                if response_with_proof.response.content.is_reject() {
                    return invalid_artifact(
                        InvalidCanisterHttpPayloadReason::FlexibleRejectNotAllowedInOkResponses {
                            callback_id,
                        },
                    );
                }
            }

            // Validate `extra_shares` metadata.
            for share in &group.extra_shares {
                validate_response_share(
                    share,
                    callback_id,
                    flex_committee,
                    &mut seen_signers,
                    context,
                )
                .map_err(CanisterHttpPayloadValidationError::InvalidArtifact)?;
            }

            // The collective initial spend must match the value recomputed from
            // the request context's subnet size and the signed receipts, and must
            // stay within the collective allowance of all contributing replicas,
            // i.e. of the responses' signers and the extra shares' signers.
            let expected = flexible_initial_spent(
                group.responses.iter().map(|r| &r.proof),
                group.extra_shares.iter(),
                subnet_size,
                min_responses,
            );
            if group.initial_spent != expected {
                return invalid_artifact(InvalidCanisterHttpPayloadReason::InitialSpentMismatch {
                    callback_id,
                    received: group.initial_spent,
                    expected,
                });
            }
            utils::check_initial_spent_within_limit(
                group.initial_spent,
                group.responses.len() + group.extra_shares.len(),
                callback_id,
                context,
                None,
            )
            .map_err(CanisterHttpPayloadValidationError::InvalidArtifact)?;

            // Defer signature verification.
            sig_inputs.extend(response_share_sig_inputs(
                group
                    .responses
                    .iter()
                    .map(|r| &r.proof)
                    .chain(group.extra_shares.iter()),
                context.registry_version,
            ));
        }

        // Validate flexible errors
        for error in &payload.flexible_errors {
            let callback_id = error.callback_id();

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
            let subnet_size = context.subnet_size;
            let Replication::Flexible {
                committee: flex_committee,
                min_responses,
                ..
            } = &context.replication
            else {
                return invalid_artifact(InvalidCanisterHttpPayloadReason::InvalidPayloadSection(
                    callback_id,
                ));
            };
            let min_responses = *min_responses as usize;

            // Every error but a timeout carries signed receipts whose response body
            // is not delivered. Validate their metadata.
            let shares_without_response = error.shares_without_delivered_response();
            let mut seen_signers = HashSet::new();
            for share in shares_without_response {
                validate_response_share(
                    share,
                    callback_id,
                    flex_committee,
                    &mut seen_signers,
                    context,
                )
                .map_err(CanisterHttpPayloadValidationError::InvalidArtifact)?;
            }
            // Defer signature verification.
            sig_inputs.extend(response_share_sig_inputs(
                shares_without_response,
                context.registry_version,
            ));

            match error {
                FlexibleCanisterHttpError::Timeout { .. } => {
                    if context.time + CANISTER_HTTP_TIMEOUT_INTERVAL >= validation_context.time {
                        return invalid_artifact(InvalidCanisterHttpPayloadReason::NotTimedOut(
                            callback_id,
                        ));
                    }
                }
                FlexibleCanisterHttpError::TooManyRejects {
                    reject_responses,
                    extra_shares,
                    initial_spent,
                    ..
                } => {
                    for response_with_proof in reject_responses {
                        validate_flexible_response_with_proof(
                            response_with_proof,
                            callback_id,
                            flex_committee,
                            &mut seen_signers,
                            context,
                        )
                        .map_err(CanisterHttpPayloadValidationError::InvalidArtifact)?;

                        if !response_with_proof.response.content.is_reject() {
                            return invalid_artifact(
                                InvalidCanisterHttpPayloadReason::FlexibleRejectExpectedInErrorResponse(
                                    callback_id,
                                ),
                            );
                        }
                    }

                    // The collective initial spend must match the value recomputed
                    // from the request context's subnet size and the signed
                    // receipts, and must stay within the collective allowance of
                    // all contributing replicas.
                    let expected = flexible_initial_spent(
                        reject_responses.iter().map(|r| &r.proof),
                        extra_shares.iter(),
                        subnet_size,
                        min_responses as u32,
                    );
                    if *initial_spent != expected {
                        return invalid_artifact(
                            InvalidCanisterHttpPayloadReason::InitialSpentMismatch {
                                callback_id,
                                received: *initial_spent,
                                expected,
                            },
                        );
                    }
                    utils::check_initial_spent_within_limit(
                        *initial_spent,
                        reject_responses.len() + extra_shares.len(),
                        callback_id,
                        context,
                        None,
                    )
                    .map_err(CanisterHttpPayloadValidationError::InvalidArtifact)?;

                    let max_allowed_rejects = flex_committee.len().saturating_sub(min_responses);
                    if reject_responses.len() <= max_allowed_rejects {
                        return invalid_artifact(
                            InvalidCanisterHttpPayloadReason::FlexibleInsufficientRejectCount {
                                callback_id,
                                reject_count: reject_responses.len(),
                                min_needed: max_allowed_rejects + 1,
                            },
                        );
                    }

                    // Defer signature verification of the reject responses; the
                    // extra shares' signatures are already deferred above.
                    sig_inputs.extend(response_share_sig_inputs(
                        reject_responses.iter().map(|r| &r.proof),
                        context.registry_version,
                    ));
                }
                FlexibleCanisterHttpError::ResponsesTooLarge {
                    all_seen_shares,
                    total_requests,
                    min_responses: claimed_min_responses,
                    ..
                } => {
                    if *total_requests != flex_committee.len() as u32 {
                        return invalid_artifact(
                            InvalidCanisterHttpPayloadReason::FlexibleResponsesTooLargeParamMismatch {
                                callback_id,
                                field: "total_requests",
                                expected: flex_committee.len() as u32,
                                actual: *total_requests,
                            },
                        );
                    }
                    if *claimed_min_responses != min_responses as u32 {
                        return invalid_artifact(
                            InvalidCanisterHttpPayloadReason::FlexibleResponsesTooLargeParamMismatch {
                                callback_id,
                                field: "min_responses",
                                expected: min_responses as u32,
                                actual: *claimed_min_responses,
                            },
                        );
                    }

                    let num_unseen = flex_committee.len().saturating_sub(all_seen_shares.len());
                    let min_known_ok_needed = min_responses.saturating_sub(num_unseen);

                    let mut ok_entry_sizes: Vec<usize> = all_seen_shares
                        .iter()
                        .filter(|share| !share.content.is_reject())
                        .map(|share| {
                            FlexibleCanisterHttpResponseWithProof::count_bytes_from_parts(
                                share.content.content_size() as usize,
                                share,
                            )
                        })
                        .collect();
                    if ok_entry_sizes.len() < min_known_ok_needed {
                        return invalid_artifact(
                            InvalidCanisterHttpPayloadReason::FlexibleResponsesTooLargeInsufficientEvidence {
                                callback_id,
                                ok_count: ok_entry_sizes.len(),
                                min_known_ok_needed,
                            },
                        );
                    }

                    ok_entry_sizes.sort_unstable();
                    let smallest_sum: usize = ok_entry_sizes.iter().take(min_known_ok_needed).sum();
                    if smallest_sum <= MAX_CANISTER_HTTP_PAYLOAD_SIZE {
                        return invalid_artifact(
                            InvalidCanisterHttpPayloadReason::FlexibleResponsesNotTooLarge(
                                callback_id,
                            ),
                        );
                    }
                }
                FlexibleCanisterHttpError::OutOfCycles {
                    all_seen_shares,
                    min_cost,
                    unspent_allowance,
                    ..
                } => {
                    // The shares must prove that the committee's remaining
                    // allowances can no longer pay for a response...
                    let expected = utils::check_flexible_out_of_cycles(
                        all_seen_shares.iter(),
                        flex_committee.len(),
                        min_responses as u32,
                        callback_id,
                        context,
                    )
                    .map_err(CanisterHttpPayloadValidationError::InvalidArtifact)?;
                    // ...and the figures reported to the caller must be the ones it
                    // is proved by.
                    for (field, received, expected) in [
                        ("min_cost", *min_cost, expected.min_cost),
                        (
                            "unspent_allowance",
                            *unspent_allowance,
                            expected.unspent_allowance,
                        ),
                    ] {
                        if received != expected {
                            return invalid_artifact(
                                InvalidCanisterHttpPayloadReason::OutOfCyclesFigureMismatch {
                                    callback_id,
                                    field,
                                    received,
                                    expected,
                                },
                            );
                        }
                    }
                }
            }
        }

        // Validate asynchronous receipts: the signed spends of replicas that the
        // already delivered response of their outcall did not account for.
        let mut receipts_by_callback: BTreeMap<CallbackId, Vec<&CanisterHttpResponseShare>> =
            BTreeMap::new();
        for share in &payload.async_receipts {
            receipts_by_callback
                .entry(share.content.id())
                .or_default()
                .push(share);
        }
        for (callback_id, shares) in receipts_by_callback {
            // Only an outcall that has already been responded to can be refunded asynchronously.
            let context = delivered_http_contexts.get(&callback_id).ok_or(
                CanisterHttpPayloadValidationError::InvalidArtifact(
                    InvalidCanisterHttpPayloadReason::UnknownDeliveredCallbackId(callback_id),
                ),
            )?;
            // Reject if the context for this share has already timed out.
            if delivered_context_timed_out(context, validation_context) {
                return invalid_artifact(
                    InvalidCanisterHttpPayloadReason::DeliveredCallbackTimedOut(callback_id),
                );
            }
            let committee = self.request_committee(context).map_err(|err| {
                warn!(self.log, "Failed to get membership: {:?}", err);
                CanisterHttpPayloadValidationError::ValidationFailed(
                    CanisterHttpPayloadValidationFailure::Membership,
                )
            })?;

            // A replica may only be refunded once.
            let already_refunded = RefundedNodes::new(callback_id, context, &refunded_nodes);
            let mut seen_signers = HashSet::new();
            for &share in &shares {
                validate_response_share(share, callback_id, &committee, &mut seen_signers, context)
                    .map_err(CanisterHttpPayloadValidationError::InvalidArtifact)?;

                let signer = share.signature.signer;
                if already_refunded.contains(&signer) {
                    return invalid_artifact(InvalidCanisterHttpPayloadReason::AlreadyRefunded {
                        callback_id,
                        signer,
                    });
                }
            }

            // Defer signature verification.
            sig_inputs.extend(response_share_sig_inputs(shares, context.registry_version));
        }

        // Batch-verify the signatures of the deferred shares.
        if !sig_inputs.is_empty() {
            self.crypto
                .verify_basic_sig_batch_multi_msg(&sig_inputs)
                .map_err(|err| {
                    CanisterHttpPayloadValidationError::InvalidArtifact(
                        InvalidCanisterHttpPayloadReason::SignatureError(Box::new(err)),
                    )
                })?;
        }

        Ok(())
    }
}

impl BatchPayloadBuilder for CanisterHttpPayloadBuilderImpl {
    fn build_payload(
        &self,
        _height: Height,
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
        let past_payloads = parse::parse_past_payloads(past_payloads, &self.log);
        let payload = self.get_canister_http_payload_impl(context, past_payloads, max_size);
        parse::payload_to_bytes(payload, max_size)
    }

    fn validate_payload(
        &self,
        _height: Height,
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

        let past_payloads = parse::parse_past_payloads(past_payloads, &self.log);
        let payload = parse::bytes_to_payload(payload).map_err(|e| {
            ValidationError::InvalidArtifact(
                consensus::InvalidPayloadReason::InvalidCanisterHttpPayload(
                    InvalidCanisterHttpPayloadReason::DecodeError(e),
                ),
            )
        })?;
        self.validate_canister_http_payload_impl(
            &payload,
            proposal_context.validation_context,
            past_payloads,
        )
    }
}

impl
    IntoMessages<(
        Vec<ConsensusResponse>,
        CanisterHttpSpent,
        CanisterHttpBatchStats,
    )> for CanisterHttpPayloadBuilderImpl
{
    fn into_messages(
        payload: &[u8],
    ) -> (
        Vec<ConsensusResponse>,
        CanisterHttpSpent,
        CanisterHttpBatchStats,
    ) {
        let mut stats = CanisterHttpBatchStats::default();

        let messages = bytes_to_payload(payload)
            .expect("Failed to parse a payload that was already validated");

        let mut consensus_responses = Vec::new();
        let mut spent = CanisterHttpSpent::default();

        // Fully-replicated (and non-replicated) responses: emit the collective
        // initial spend that was computed during payload building and validated
        // during payload validation. Divergence and timeout responses carry no
        // spend report.
        for response in messages.responses {
            if response.proof.signatures.len() == 1 {
                stats.single_signature_responses += 1;
            }
            stats.responses += 1;

            let callback = response.content.id;
            let nodes: BTreeSet<NodeId> = response.proof.signatures.keys().copied().collect();
            let amount = response.initial_spent;

            consensus_responses.push(ConsensusResponse::new(
                callback,
                match response.content.content {
                    CanisterHttpResponseContent::Success(data) => Payload::Data(data),
                    CanisterHttpResponseContent::Reject(canister_http_reject) => {
                        Payload::Reject(RejectContext::from(&canister_http_reject))
                    }
                },
            ));
            spent.initial.push(CanisterHttpInitialSpent {
                callback,
                amount,
                nodes,
            });
        }

        // Timeouts: map to a rejected response. A timed-out request has no
        // signed shares, hence no spend report.
        for callback in &messages.timeouts {
            stats.timeouts += 1;
            consensus_responses.push(ConsensusResponse::new(
                *callback,
                Payload::Reject(RejectContext::new(
                    RejectCode::SysTransient,
                    "Canister http request timed out",
                )),
            ));
        }

        // Divergences deliver no response body, so their consensus cost is zero:
        // the initial spend is just the per-replica cost each diverging signer
        // incurred, summed on the fly from the shares.
        for divergence_response in messages.divergence_responses {
            let nodes: BTreeSet<NodeId> = divergence_response
                .shares
                .iter()
                .map(|share| share.signature.signer)
                .collect();
            let amount = divergence_response
                .shares
                .iter()
                .map(|share| share.content.spent())
                .sum();
            if let Some(consensus_response) = divergence_response_into_reject(divergence_response) {
                stats.divergence_responses += 1;
                spent.initial.push(CanisterHttpInitialSpent {
                    callback: consensus_response.callback,
                    amount,
                    nodes,
                });
                consensus_responses.push(consensus_response);
            }
        }

        // Out of cycles: like a divergence, this delivers no body, so its consensus
        // cost is zero and its spend is just what the replicas reported.
        for error in messages.out_of_cycles {
            stats.out_of_cycles += 1;
            let nodes: BTreeSet<NodeId> = error
                .shares
                .iter()
                .map(|share| share.signature.signer)
                .collect();
            let amount = error.shares.iter().map(|share| share.content.spent()).sum();
            spent.initial.push(CanisterHttpInitialSpent {
                callback: error.callback_id,
                amount,
                nodes,
            });
            consensus_responses.push(ConsensusResponse::new(
                error.callback_id,
                Payload::Reject(RejectContext::new(
                    RejectCode::CanisterReject,
                    out_of_cycles_reject_message(
                        &error.shares,
                        error.unspent_allowance,
                        error.min_cost,
                    ),
                )),
            ));
        }

        // The collective initial spend was computed during payload building
        // and validated during payload validation.
        for response_group in messages.flexible_responses {
            let callback = response_group.callback_id;
            let amount = response_group.initial_spent;
            let nodes: BTreeSet<NodeId> = response_group
                .responses
                .iter()
                .map(|r| r.proof.signature.signer)
                .chain(
                    response_group
                        .extra_shares
                        .iter()
                        .map(|share| share.signature.signer),
                )
                .collect();
            match flexible_ok_responses_into_consensus_response(response_group) {
                Some(consensus_response) => {
                    stats.flexible_ok_responses += 1;
                    consensus_responses.push(consensus_response);
                    spent.initial.push(CanisterHttpInitialSpent {
                        callback,
                        amount,
                        nodes,
                    });
                }
                None => stats.flexible_ok_responses_candid_failures += 1,
            }
        }

        for error in messages.flexible_errors {
            let report = match &error {
                // `TooManyRejects` delivers reject bodies, so its spend (including the
                // consensus term) was computed during payload building and validated.
                FlexibleCanisterHttpError::TooManyRejects {
                    reject_responses,
                    extra_shares,
                    initial_spent,
                    ..
                } => {
                    let nodes: BTreeSet<NodeId> = reject_responses
                        .iter()
                        .map(|r| r.proof.signature.signer)
                        .chain(extra_shares.iter().map(|share| share.signature.signer))
                        .collect();
                    Some(CanisterHttpInitialSpent {
                        callback: error.callback_id(),
                        amount: *initial_spent,
                        nodes,
                    })
                }
                // `ResponsesTooLarge` and `OutOfCycles` deliver no body, so their
                // consensus cost is zero and their spend is summed on the fly from
                // the seen shares.
                FlexibleCanisterHttpError::ResponsesTooLarge {
                    all_seen_shares, ..
                }
                | FlexibleCanisterHttpError::OutOfCycles {
                    all_seen_shares, ..
                } => {
                    let nodes: BTreeSet<NodeId> = all_seen_shares
                        .iter()
                        .map(|share| share.signature.signer)
                        .collect();
                    let amount = all_seen_shares
                        .iter()
                        .map(|share| share.content.spent())
                        .sum();
                    Some(CanisterHttpInitialSpent {
                        callback: error.callback_id(),
                        amount,
                        nodes,
                    })
                }
                // Timeouts carry no shares and produce no spend report.
                FlexibleCanisterHttpError::Timeout { .. } => None,
            };
            let kind = error.kind();
            match flexible_error_into_consensus_response(error) {
                Some(consensus_response) => {
                    *stats.flexible_errors.entry(kind).or_default() += 1;
                    consensus_responses.push(consensus_response);
                    if let Some(report) = report {
                        spent.initial.push(report);
                    }
                }
                None => stats.flexible_errors_candid_failures += 1,
            }
        }

        let mut async_spent: BTreeMap<CallbackId, BTreeMap<NodeId, Cycles>> = BTreeMap::new();
        for share in messages.async_receipts {
            stats.async_receipts += 1;
            async_spent
                .entry(share.content.id())
                .or_default()
                .insert(share.signature.signer, share.content.spent());
        }
        spent.asynchronous.extend(
            async_spent
                .into_iter()
                .map(|(callback, shares)| CanisterHttpAsyncSpent { callback, shares }),
        );

        (consensus_responses, spent, stats)
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

/// Converts a [`FlexibleCanisterHttpError`] into a [`ConsensusResponse`]
/// carrying a Candid-encoded [`FlexibleHttpRequestResult::Err`].
///
/// Returns `None` if Candid encoding fails (should never happen).
fn flexible_error_into_consensus_response(
    error: FlexibleCanisterHttpError,
) -> Option<ConsensusResponse> {
    let callback_id = error.callback_id();

    let err = match error {
        FlexibleCanisterHttpError::Timeout { .. } => FlexibleHttpRequestErr {
            global_error: Some(FlexibleHttpGlobalError::Timeout(candid::Reserved)),
            node_details: vec![],
            message: "Flexible HTTP request timed out".to_string(),
        },
        FlexibleCanisterHttpError::TooManyRejects {
            reject_responses, ..
        } => {
            let message = format!(
                "Too many rejects: {} responses are rejects",
                reject_responses.len(),
            );
            let node_details: Vec<_> = reject_responses
                .into_iter()
                .filter_map(|reject_response| {
                    match reject_response.response.content {
                        CanisterHttpResponseContent::Reject(reject) => {
                            Some(FlexibleHttpNodeDetail {
                                node_id: candid::Principal::from(
                                    reject_response.proof.signature.signer.get(),
                                ),
                                report: HttpRequestResourceReport::default(),
                                error: Some(FlexibleHttpNodeError {
                                    code: format!("{:?}", reject.reject_code),
                                    message: reject.message,
                                }),
                            })
                        }
                        CanisterHttpResponseContent::Success(_) => {
                            // Unreachable: payload building/validation ensure
                            // that there are no oks in the reject-responses.
                            None
                        }
                    }
                })
                .collect();
            FlexibleHttpRequestErr {
                global_error: Some(FlexibleHttpGlobalError::TooManyRejects(candid::Reserved)),
                node_details,
                message,
            }
        }
        FlexibleCanisterHttpError::ResponsesTooLarge {
            all_seen_shares,
            total_requests,
            min_responses,
            ..
        } => {
            let num_ok = all_seen_shares
                .iter()
                .filter(|s| !s.content.is_reject())
                .count() as u32;
            let num_reject = all_seen_shares.len() as u32 - num_ok;
            let num_unseen = total_requests.saturating_sub(all_seen_shares.len() as u32);
            let min_known_ok_needed = min_responses.saturating_sub(num_unseen);

            let node_details: Vec<_> = all_seen_shares
                .iter()
                .map(|share| {
                    let code = if share.content.is_reject() {
                        "reject"
                    } else {
                        "ok"
                    };
                    FlexibleHttpNodeDetail {
                        node_id: candid::Principal::from(share.signature.signer.get()),
                        report: HttpRequestResourceReport::default(),
                        error: Some(FlexibleHttpNodeError {
                            code: code.to_string(),
                            message: format!("{} bytes", share.content.content_size()),
                        }),
                    }
                })
                .collect();

            let mut ok_sizes: Vec<_> = all_seen_shares
                .iter()
                .filter(|s| !s.content.is_reject())
                .map(|share| share.content.content_size())
                .collect();
            // Sort defensively, as validator doesn't enforce ordering on `all_seen_shares`
            ok_sizes.sort_unstable();
            let relevant_ok_sizes: Vec<_> = ok_sizes
                .iter()
                .take(min_known_ok_needed as usize)
                .map(|size| size.to_string())
                .collect();

            let message = format!(
                "Responses too large: need at least {min_responses} \
                 OK responses to fit within {MAX_CANISTER_HTTP_PAYLOAD_SIZE} bytes, \
                 but even the smallest {min_known_ok_needed} \
                 (= {min_responses} min_responses - {num_unseen} unseen) of {num_ok} \
                 OK responses have sizes [{}] bytes \
                 ({num_ok} ok + {num_reject} reject + {num_unseen} unseen = {total_requests} total_requests)",
                relevant_ok_sizes.join(", "),
            );
            FlexibleHttpRequestErr {
                global_error: Some(FlexibleHttpGlobalError::ResponsesTooLarge(candid::Reserved)),
                node_details,
                message,
            }
        }
        FlexibleCanisterHttpError::OutOfCycles {
            all_seen_shares,
            min_cost,
            unspent_allowance,
            ..
        } => {
            let node_details: Vec<_> = all_seen_shares
                .iter()
                .map(|share| FlexibleHttpNodeDetail {
                    node_id: candid::Principal::from(share.signature.signer.get()),
                    report: HttpRequestResourceReport::default(),
                    error: Some(FlexibleHttpNodeError {
                        code: if share.content.is_reject() {
                            "reject".to_string()
                        } else {
                            "ok".to_string()
                        },
                        message: format!("{} cycles spent", share.content.spent()),
                    }),
                })
                .collect();

            let message =
                out_of_cycles_reject_message(&all_seen_shares, unspent_allowance, min_cost);
            FlexibleHttpRequestErr {
                global_error: Some(FlexibleHttpGlobalError::OutOfCycles(candid::Reserved)),
                node_details,
                message,
            }
        }
    };

    let bytes = Encode!(&FlexibleHttpRequestResult::Err(err)).ok()?;

    Some(ConsensusResponse::new(callback_id, Payload::Data(bytes)))
}

fn out_of_cycles_reject_message(
    shares: &[CanisterHttpResponseShare],
    unspent_allowance: Cycles,
    min_cost: Cycles,
) -> String {
    let total_spent: Cycles = shares.iter().map(|share| share.content.spent()).sum();
    format!(
        "Out of cycles: {} of the assigned replicas reported a collective spend of {total_spent} cycles, \
         leaving {unspent_allowance} cycles of the attached payment (after base fee deduction). \
         Delivering a response would cost at least {min_cost} cycles.",
        shares.len(),
    )
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
    let Some(id) = response.shares.first().map(|share| share.content.id()) else {
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
        .map(|share| share.content.metadata.content_hash.get().0)
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

/// Returns true if a delivered context has timed out, meaning no further
/// asynchronous receipts are accepted.
fn delivered_context_timed_out(
    context: &CanisterHttpRequestContext,
    validation_context: &ValidationContext,
) -> bool {
    validation_context
        .time
        .saturating_duration_since(context.time)
        >= DELIVERED_CANISTER_HTTP_REQUEST_CONTEXT_TIMEOUT
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
