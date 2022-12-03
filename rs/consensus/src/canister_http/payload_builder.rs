//! Implementation of the payload builder of the canister http feature

use crate::{
    canister_http::metrics::CanisterHttpPayloadBuilderMetrics,
    consensus::{utils::registry_version_at_height, ConsensusCrypto, Membership},
};
use ic_interfaces::{
    canister_http::{
        CanisterHttpPayloadBuilder, CanisterHttpPayloadValidationError,
        CanisterHttpPermanentValidationError, CanisterHttpPool,
        CanisterHttpTransientValidationError,
    },
    consensus_pool::ConsensusPoolCache,
};
use ic_interfaces_registry::RegistryClient;
use ic_interfaces_state_manager::StateManager;
use ic_logger::{warn, ReplicaLogger};
use ic_metrics::MetricsRegistry;
use ic_registry_client_helpers::subnet::SubnetRegistry;
use ic_replicated_state::ReplicatedState;
use ic_types::{
    batch::{CanisterHttpPayload, ValidationContext, MAX_CANISTER_HTTP_PAYLOAD_SIZE},
    canister_http::{
        CanisterHttpResponse, CanisterHttpResponseDivergence, CanisterHttpResponseMetadata,
        CanisterHttpResponseProof, CanisterHttpResponseShare, CanisterHttpResponseWithConsensus,
        CANISTER_HTTP_MAX_RESPONSES_PER_BLOCK, CANISTER_HTTP_TIMEOUT_INTERVAL,
    },
    consensus::Committee,
    crypto::Signed,
    messages::CallbackId,
    registry::RegistryClientError,
    signature::BasicSignature,
    CountBytes, Height, NodeId, NumBytes, RegistryVersion, SubnetId,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    mem::size_of,
    sync::{Arc, RwLock},
};

#[cfg(test)]
mod tests;
mod utils;

/// Implementation of the [`CanisterHttpPayloadBuilder`].
pub struct CanisterHttpPayloadBuilderImpl {
    pool: Arc<RwLock<dyn CanisterHttpPool>>,
    cache: Arc<dyn ConsensusPoolCache>,
    crypto: Arc<dyn ConsensusCrypto>,
    state_manager: Arc<dyn StateManager<State = ReplicatedState>>,
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
        state_manager: Arc<dyn StateManager<State = ReplicatedState>>,
        membership: Arc<Membership>,
        subnet_id: SubnetId,
        registry: Arc<dyn RegistryClient>,
        metrics_registry: &MetricsRegistry,
        log: ReplicaLogger,
    ) -> Self {
        Self {
            pool,
            cache,
            crypto,
            state_manager,
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
}

/// This function takes a mapping of response metadata to supporting shares
/// and determines, whether the divergence criterium is met.
///
/// The divergence criterium is met, if enough nodes support different responses,
/// such that the support of nodes who are missing from the set
/// (since their shares have not been received yet) can not bring any response
/// above the required threshold.
///
/// Specifically, what is done is as follows:
/// - The sets of shares are sorted from largest to smallest, and then the
/// largest set is removed.
/// - A new set of "diverging signers" is created by collecting every node id
/// that has signed a share not in the largest group.
/// - Finally any signers appearing in the largest group are
/// removed from the diverging signers group.
/// - If the size of this group exceeds the number of faults tolerated, then the
/// divergence criteria is met.
fn grouped_shares_meet_divergence_criteria(
    grouped_shares: &BTreeMap<CanisterHttpResponseMetadata, Vec<&CanisterHttpResponseShare>>,
    faults_tolerated: usize,
) -> bool {
    let mut share_for_content_signers: Vec<BTreeSet<NodeId>> = grouped_shares
        .iter()
        .map(|(_, shares)| shares.iter().map(|share| share.signature.signer).collect())
        .collect();
    share_for_content_signers.sort_by_key(|b| core::cmp::Reverse(b.len()));
    if let Some(largest_signers) = share_for_content_signers.get(0) {
        let mut non_largest_signers = BTreeSet::new();
        for signer_group in share_for_content_signers.iter().skip(1) {
            for signer in signer_group.iter() {
                non_largest_signers.insert(*signer);
            }
        }
        let otherwise_committed_signer_count =
            non_largest_signers.difference(largest_signers).count();
        otherwise_committed_signer_count > faults_tolerated
    } else {
        false
    }
}

fn group_shares_by_callback_id<'a, Shares: Iterator<Item = &'a CanisterHttpResponseShare>>(
    shares: Shares,
) -> BTreeMap<CallbackId, BTreeMap<CanisterHttpResponseMetadata, Vec<&'a CanisterHttpResponseShare>>>
{
    let mut map: BTreeMap<
        CallbackId,
        BTreeMap<CanisterHttpResponseMetadata, Vec<&'a CanisterHttpResponseShare>>,
    > = BTreeMap::new();
    for share in shares {
        map.entry(share.content.id)
            .or_default()
            .entry(share.content.clone())
            .or_default()
            .push(share);
    }
    map
}

impl CanisterHttpPayloadBuilder for CanisterHttpPayloadBuilderImpl {
    fn get_canister_http_payload(
        &self,
        height: Height,
        validation_context: &ValidationContext,
        past_payloads: &[&CanisterHttpPayload],
        byte_limit: NumBytes,
    ) -> CanisterHttpPayload {
        let _time = self
            .metrics
            .op_duration
            .with_label_values(&["build"])
            .start_timer();

        // Check whether feature is enabled, return empty payload if not enabled
        // or registry unavailable
        match self.is_enabled(validation_context) {
            Err(_) => {
                warn!(self.log, "CanisterHttpPayloadBuilder: Registry unavailable");
                return CanisterHttpPayload::default();
            }
            Ok(false) => return CanisterHttpPayload::default(),
            Ok(true) => (),
        }

        // Payload size should not be bigger than MAX_CANISTER_HTTP_PAYLOAD_SIZE
        let max_payload_size = std::cmp::min(
            byte_limit,
            NumBytes::new(MAX_CANISTER_HTTP_PAYLOAD_SIZE as u64),
        );

        // Get a set of the messages of the already delivered responses
        let delivered_ids = utils::get_past_payload_ids(past_payloads);
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

        let mut divergence_responses = vec![];

        // Since aggegating the signatures is expensive, we don't want to do the
        // size checks after aggregation. Also we don't want to hold the lock on
        // the pool while aggregating. Therefore, we pick the candidates for the
        // payload first, then aggregate the signatures in a second step
        let (mut candidates, timeouts) = {
            let pool_access = self.pool.read().unwrap();
            let mut total_share_count = 0;
            let mut active_shares = 0;

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

            let mut unique_responses_count = 0;

            let responses =
                response_candidates_by_callback_id
                    .into_iter()
                    .filter_map(|(_, grouped_shares)| {
                        if let Some((metadata, shares)) =
                            grouped_shares.iter().find(|(_, shares)| {
                                unique_responses_count += 1;
                                let signers: BTreeSet<_> =
                                    shares.iter().map(|share| share.signature.signer).collect();
                                // We need at least threshold different signers to include the response
                                signers.len() >= threshold
                            })
                        {
                            // A set of grouped shares large enough to meet the
                            // threshold was found, we should produce a result.
                            pool_access
                                .get_response_content_by_hash(&metadata.content_hash)
                                .map(|content| {
                                    (
                                        metadata.clone(),
                                        shares
                                            .iter()
                                            .map(|share| share.signature.clone())
                                            .collect(),
                                        content,
                                    )
                                })
                        } else {
                            // No set of grouped shares large enough was found
                            // so now we check whether we have divergence.
                            if grouped_shares_meet_divergence_criteria(
                                &grouped_shares,
                                faults_tolerated,
                            ) {
                                divergence_responses.push(CanisterHttpResponseDivergence {
                                    shares: grouped_shares
                                        .into_iter()
                                        .flat_map(|(_, shares)| shares.into_iter().cloned())
                                        .collect(),
                                });
                            }
                            None
                        }
                    });

            // Select from the response candidates those that will fit into the
            // payload.
            let mut accumulated_size = 0;
            let mut candidates = vec![];
            let mut unique_includable_responses = 0;
            let mut responses_included = 0;
            let mut timeouts_included = 0;

            // Check the state for timeouts NOTE: We can not use the existing
            // timed out artifacts for this task, since we don't have consensus
            // on them. For example a malicious node might publish a single
            // timed out metadata share and we would pick it up to generate a
            // time out response. Instead, we scan the state metadata for timed
            // out requests and generate time out responses based on that
            let mut timeouts = vec![];
            if let Ok(state) = self
                .state_manager
                .get_state_at(validation_context.certified_height)
            {
                // Iterate over all outstanding canister http requests
                for (callback_id, request) in state
                    .get_ref()
                    .metadata
                    .subnet_call_context_manager
                    .canister_http_request_contexts
                    .iter()
                {
                    unique_includable_responses += 1;
                    let candidate_size = callback_id.count_bytes();
                    let size = NumBytes::new((accumulated_size + candidate_size) as u64);
                    if size >= max_payload_size {
                        // All timeouts have the same size, so we can stop iterating.
                        break;
                    } else if request.time + CANISTER_HTTP_TIMEOUT_INTERVAL
                        < validation_context.time
                        && !delivered_ids.contains(callback_id)
                    {
                        timeouts_included += 1;
                        timeouts.push(*callback_id);
                        accumulated_size += candidate_size;
                    }
                }
            }

            for (metadata, shares, content) in responses {
                unique_includable_responses += 1;
                // FIXME: This MUST be the same size calculation as
                // CanisterHttpResponseWithConsensus::count_bytes. This
                // should be explicit in the code
                let candidate_size = size_of::<CanisterHttpResponseProof>() + content.count_bytes();
                let size = NumBytes::new((accumulated_size + candidate_size) as u64);
                if size < max_payload_size {
                    if responses_included >= CANISTER_HTTP_MAX_RESPONSES_PER_BLOCK {
                        break;
                    }
                    candidates.push((metadata.clone(), shares, content));
                    responses_included += 1;
                    accumulated_size += candidate_size;
                }
            }

            self.metrics.included_timeouts.set(timeouts_included);
            self.metrics.unique_responses.set(unique_responses_count);
            self.metrics
                .unique_includable_responses
                .set(unique_includable_responses);

            (candidates, timeouts)
        };

        // Now that we have the candidates, aggregate the signatures and construct the payload
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

        payload
    }

    fn validate_canister_http_payload(
        &self,
        height: Height,
        payload: &CanisterHttpPayload,
        validation_context: &ValidationContext,
        past_payloads: &[&CanisterHttpPayload],
    ) -> Result<NumBytes, CanisterHttpPayloadValidationError> {
        let _time = self
            .metrics
            .op_duration
            .with_label_values(&["validate"])
            .start_timer();

        // Empty payloads are always valid
        if payload.is_empty() {
            return Ok(0.into());
        }

        // Check whether feature is enabled and reject if it isn't.
        // NOTE: All payloads that are processed at this point are non-empty
        if !self.is_enabled(validation_context).map_err(|err| {
            CanisterHttpPayloadValidationError::Transient(
                CanisterHttpTransientValidationError::RegistryUnavailable(err),
            )
        })? {
            return Err(CanisterHttpPayloadValidationError::Transient(
                CanisterHttpTransientValidationError::Disabled,
            ));
        }

        // Check number of responses
        if payload.num_non_timeout_responses() > CANISTER_HTTP_MAX_RESPONSES_PER_BLOCK {
            return Err(CanisterHttpPayloadValidationError::Permanent(
                CanisterHttpPermanentValidationError::TooManyResponses {
                    expected: CANISTER_HTTP_MAX_RESPONSES_PER_BLOCK,
                    received: payload.num_non_timeout_responses(),
                },
            ));
        }

        // Check size of the payload
        // TODO: Account for size of timeouts
        let payload_size = payload
            .responses
            .iter()
            .map(CountBytes::count_bytes)
            .sum::<usize>();
        if payload_size > MAX_CANISTER_HTTP_PAYLOAD_SIZE {
            return Err(CanisterHttpPayloadValidationError::Permanent(
                CanisterHttpPermanentValidationError::PayloadTooBig {
                    expected: MAX_CANISTER_HTTP_PAYLOAD_SIZE,
                    received: payload_size,
                },
            ));
        }

        let delivered_ids = utils::get_past_payload_ids(past_payloads);

        // Validate the timed out calls
        let state = &self
            .state_manager
            .get_state_at(validation_context.certified_height)
            .map_err(|_| {
                CanisterHttpPayloadValidationError::Transient(
                    CanisterHttpTransientValidationError::StateUnavailable,
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
                CanisterHttpPayloadValidationError::Permanent(
                    CanisterHttpPermanentValidationError::UnknownCallbackId(*timeout_id),
                ),
            )?;

            // Check that they are timed out and no dupicates
            if request.time + CANISTER_HTTP_TIMEOUT_INTERVAL >= validation_context.time
                || delivered_ids.contains(timeout_id)
            {
                return Err(CanisterHttpPayloadValidationError::Permanent(
                    CanisterHttpPermanentValidationError::NotTimedOut(*timeout_id),
                ));
            }
        }

        // Get the consensus registry version
        let consensus_registry_version = registry_version_at_height(self.cache.as_ref(), height)
            .ok_or(CanisterHttpPayloadValidationError::Transient(
                CanisterHttpTransientValidationError::ConsensusRegistryVersionUnavailable,
            ))?;

        // Check conditions on individual reponses
        for response in &payload.responses {
            // Check that response is consistent
            utils::check_response_consistency(response)
                .map_err(CanisterHttpPayloadValidationError::Permanent)?;

            // Validate response against `ValidationContext`
            utils::check_response_against_context(
                consensus_registry_version,
                response,
                validation_context,
            )
            .map_err(CanisterHttpPayloadValidationError::Permanent)?;

            // Check that the response is not submitted twice
            if delivered_ids.contains(&response.content.id) {
                return Err(CanisterHttpPayloadValidationError::Permanent(
                    CanisterHttpPermanentValidationError::DuplicateResponse(response.content.id),
                ));
            }
        }

        let committee = self
            .membership
            .get_canister_http_committee(height)
            .map_err(|_| {
                CanisterHttpPayloadValidationError::Transient(
                    CanisterHttpTransientValidationError::Membership,
                )
            })?;

        // Verify the signatures
        // NOTE: We do this in a separate loop because this check is expensive and we want to
        // do all the cheap checks first
        for response in &payload.responses {
            let threshold = match self
                .membership
                .get_committee_threshold(height, Committee::CanisterHttp)
            {
                Ok(threshold) => threshold,
                Err(err) => {
                    warn!(self.log, "Failed to get membership: {:?}", err);
                    return Err(CanisterHttpPayloadValidationError::Transient(
                        CanisterHttpTransientValidationError::Membership,
                    ));
                }
            };
            let (valid_signers, invalid_signers): (Vec<NodeId>, Vec<NodeId>) = response
                .proof
                .signature
                .signatures_map
                .keys()
                .cloned()
                .partition(|signer| committee.iter().any(|id| id == signer));
            if !invalid_signers.is_empty() {
                return Err(CanisterHttpPayloadValidationError::Permanent(
                    CanisterHttpPermanentValidationError::SignersNotMembers {
                        invalid_signers,
                        committee,
                        valid_signers,
                    },
                ));
            }
            if valid_signers.len() < threshold {
                return Err(CanisterHttpPayloadValidationError::Permanent(
                    CanisterHttpPermanentValidationError::NotEnoughSigners {
                        committee,
                        signers: valid_signers,
                        expected_threshold: threshold,
                    },
                ));
            }
            self.crypto
                .verify_aggregate(&response.proof, consensus_registry_version)
                .map_err(|err| {
                    CanisterHttpPayloadValidationError::Permanent(
                        CanisterHttpPermanentValidationError::SignatureError(Box::new(err)),
                    )
                })?;
        }

        let faults_tolerated = match self.membership.get_canister_http_committee(height) {
            Ok(members) => ic_types::consensus::get_faults_tolerated(members.len()),
            _ => {
                warn!(self.log, "Failed to get canister http committee");
                return Err(CanisterHttpPayloadValidationError::Transient(
                    CanisterHttpTransientValidationError::Membership,
                ));
            }
        };

        for response in &payload.divergence_responses {
            let (valid_signers, invalid_signers): (Vec<NodeId>, Vec<NodeId>) = response
                .shares
                .iter()
                .map(|share| share.signature.signer)
                .partition(|signer| committee.iter().any(|id| id == signer));

            if !invalid_signers.is_empty() {
                return Err(CanisterHttpPayloadValidationError::Permanent(
                    CanisterHttpPermanentValidationError::SignersNotMembers {
                        invalid_signers,
                        committee,
                        valid_signers,
                    },
                ));
            }

            for share in response.shares.iter() {
                self.crypto
                    .verify(share, consensus_registry_version)
                    .map_err(|err| {
                        CanisterHttpPayloadValidationError::Permanent(
                            CanisterHttpPermanentValidationError::SignatureError(Box::new(err)),
                        )
                    })?;
            }

            let grouped_shares = group_shares_by_callback_id(response.shares.iter());
            if grouped_shares.len() != 1 {
                return Err(CanisterHttpPayloadValidationError::Permanent(
                    CanisterHttpPermanentValidationError::DivergenceProofContainsMultipleCallbackIds
                ));
            }
            for (_, grouped_shares) in grouped_shares {
                if !grouped_shares_meet_divergence_criteria(&grouped_shares, faults_tolerated) {
                    return Err(CanisterHttpPayloadValidationError::Permanent(
                        CanisterHttpPermanentValidationError::DivergenceProofDoesNotMeetDivergenceCriteria
                    ));
                }
            }
        }

        // Successfully return with payload size
        Ok(NumBytes::from(payload_size as u64))
    }
}
