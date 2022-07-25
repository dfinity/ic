//! This module encapsulates all components required for canister http requests.
use crate::consensus::{
    utils::{group_shares, registry_version_at_height},
    ConsensusCrypto, Membership,
};
use ic_crypto::crypto_hash;
use ic_interfaces::{
    canister_http::{
        CanisterHttpGossip, CanisterHttpPayloadBuilder, CanisterHttpPayloadValidationError,
        CanisterHttpPermanentValidationError, CanisterHttpPool,
        CanisterHttpTransientValidationError,
    },
    consensus_pool::ConsensusPoolCache,
    registry::RegistryClient,
};
use ic_interfaces_state_manager::StateManager;
use ic_logger::{warn, ReplicaLogger};
use ic_metrics::{buckets::decimal_buckets, MetricsRegistry};
use ic_registry_client_helpers::subnet::SubnetRegistry;
use ic_replicated_state::ReplicatedState;
use ic_types::{
    artifact::{CanisterHttpResponseId, Priority, PriorityFn},
    batch::{CanisterHttpPayload, ValidationContext, MAX_CANISTER_HTTP_PAYLOAD_SIZE},
    canister_http::{
        CanisterHttpResponse, CanisterHttpResponseAttribute, CanisterHttpResponseMetadata,
        CanisterHttpResponseProof, CanisterHttpResponseShare, CanisterHttpResponseWithConsensus,
        CANISTER_HTTP_TIMEOUT_INTERVAL,
    },
    consensus::Committee,
    crypto::Signed,
    messages::CallbackId,
    registry::RegistryClientError,
    signature::MultiSignatureShare,
    CountBytes, Height, NumBytes, RegistryVersion, SubnetId,
};
pub use pool_manager::CanisterHttpPoolManagerImpl;
use prometheus::{HistogramVec, IntGauge};
use std::convert::TryInto;
use std::{
    collections::{BTreeSet, HashSet},
    mem::size_of,
    sync::{Arc, RwLock},
};

pub mod pool_manager;

/// The canonical implementation of [`CanisterHttpGossip`]
pub struct CanisterHttpGossipImpl {
    consensus_cache: Arc<dyn ConsensusPoolCache>,
    state_manager: Arc<dyn StateManager<State = ReplicatedState>>,
    log: ReplicaLogger,
}

impl CanisterHttpGossipImpl {
    /// Construcet a new CanisterHttpGossipImpl instance
    pub fn new(
        consensus_cache: Arc<dyn ConsensusPoolCache>,
        state_manager: Arc<dyn StateManager<State = ReplicatedState>>,
        log: ReplicaLogger,
    ) -> Self {
        CanisterHttpGossipImpl {
            consensus_cache,
            state_manager,
            log,
        }
    }
}

impl CanisterHttpGossip for CanisterHttpGossipImpl {
    fn get_priority_function(
        &self,
        _canister_http_pool: &dyn CanisterHttpPool,
    ) -> PriorityFn<CanisterHttpResponseId, CanisterHttpResponseAttribute> {
        let finalized_height = self.consensus_cache.finalized_block().height;
        let registry_version =
            registry_version_at_height(self.consensus_cache.as_ref(), finalized_height).unwrap();
        let known_request_ids: BTreeSet<_> = self
            .state_manager
            .get_latest_state()
            .get_ref()
            .metadata
            .subnet_call_context_manager
            .canister_http_request_contexts
            .iter()
            .map(|item| *item.0)
            .collect();
        let log = self.log.clone();
        Box::new(
            move |_, attr: &'_ CanisterHttpResponseAttribute| match attr {
                CanisterHttpResponseAttribute::Share(
                    msg_registry_version,
                    callback_id,
                    _content_hash,
                ) => {
                    if *msg_registry_version != registry_version {
                        warn!(log, "Dropping canister http response share with callback id: {}, because registry version {} does not match expected version {}", callback_id, msg_registry_version, registry_version);
                        return Priority::Drop;
                    }
                    if known_request_ids.contains(callback_id) {
                        Priority::Fetch
                    } else {
                        Priority::Stash
                    }
                }
            },
        )
    }
}

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

    /// Checks, whether the response is consistent
    ///
    /// Consistency means:
    /// - The signed metadata is the same as the metadata of the response
    /// - The content_hash is the same as the hash of the content
    ///
    /// **NOTE**: The signature is not checked
    fn check_response_consistency(
        response: &CanisterHttpResponseWithConsensus,
    ) -> Result<(), CanisterHttpPermanentValidationError> {
        let content = &response.content;
        let metadata = &response.proof.content;

        // Check metadata field consistency
        match (
            metadata.id == content.id,
            metadata.timeout == content.timeout,
        ) {
            (true, true) => (),
            _ => {
                return Err(CanisterHttpPermanentValidationError::InvalidMetadata {
                    metadata_id: metadata.id,
                    content_id: content.id,
                    metadata_timeout: metadata.timeout,
                    content_timeout: content.timeout,
                });
            }
        }

        // Check the calculated hash matches the metadata hash
        let calculated_hash = crypto_hash(content);
        if calculated_hash != metadata.content_hash {
            return Err(CanisterHttpPermanentValidationError::ContentHashMismatch {
                metadata_hash: metadata.content_hash.clone(),
                calculated_hash,
            });
        }

        Ok(())
    }

    /// Checks whether the response is valid against the provided [`ValidationContext`]
    fn check_response_against_context(
        &self,
        registry_version: RegistryVersion,
        response: &CanisterHttpResponseWithConsensus,
        context: &ValidationContext,
    ) -> Result<(), CanisterHttpPermanentValidationError> {
        // Check that response has not timed out
        if response.content.timeout < context.time {
            return Err(CanisterHttpPermanentValidationError::Timeout {
                timed_out_at: response.content.timeout,
                validation_time: context.time,
            });
        }

        // Check that registry version matched
        if response.proof.content.registry_version != registry_version {
            return Err(
                CanisterHttpPermanentValidationError::RegistryVersionMismatch {
                    expected: registry_version,
                    received: response.proof.content.registry_version,
                },
            );
        }

        Ok(())
    }

    /// Returns true if the [`CanisterHttpResponseShare`] is valid against the [`ValidationContext`]
    fn check_share_against_context(
        &self,
        registry_version: RegistryVersion,
        share: &CanisterHttpResponseShare,
        context: &ValidationContext,
    ) -> bool {
        share.content.timeout > context.time && share.content.registry_version == registry_version
    }

    /// Creates a [`HashSet`] of [`CallbackId`]s from `past_payloads`
    fn get_past_payload_ids(past_payloads: &[&CanisterHttpPayload]) -> HashSet<CallbackId> {
        past_payloads
            .iter()
            .flat_map(|payload| {
                payload
                    .responses
                    .iter()
                    .map(|response| response.content.id)
                    .chain(payload.timeouts.iter().cloned())
            })
            .collect()
    }

    /// Aggregates the signature and creates the [`CanisterHttpResponseWithConsensus`] message.
    fn aggregate(
        &self,
        registry_version: RegistryVersion,
        metadata: CanisterHttpResponseMetadata,
        shares: BTreeSet<MultiSignatureShare<CanisterHttpResponseMetadata>>,
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

        // Check whether feature is enabled, return empty payload if not enabled or registry unavailable
        match self.is_enabled(validation_context) {
            Err(_) => {
                warn!(self.log, "CanisterHttpPayloadBuilder: Registry unavailable");
                return CanisterHttpPayload::default();
            }
            Ok(false) => return CanisterHttpPayload::default(),
            Ok(true) => (),
        }

        // Get a set of the messages of the already delivered responses
        let delivered_ids = Self::get_past_payload_ids(past_payloads);
        // Get the threshold value that is needed for consensus
        let threshold = match self.membership.get_committee_threshold(
            validation_context.certified_height,
            Committee::HighThreshold,
        ) {
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

        // Since aggegating the signatures is expensive, we don't want to do the size checks after
        // aggregation. Also we don't want to hold the lock on the pool while aggregating.
        // Therefore, we pick the candidates for the payload first, then aggregate the signatures
        // in a second step
        let (mut candidates, timeouts) = {
            let pool_access = self.pool.read().unwrap();
            let mut total_share_count = 0;
            let mut active_shares = 0;

            // Get share candidates to include in the block
            let share_candidates = pool_access
                .get_validated_shares()
                .map(|v| {
                    total_share_count += 1;
                    v
                })
                // Filter out shares that are timed out or have the wrong registry versions
                .filter(|&response| {
                    self.check_share_against_context(
                        consensus_registry_version,
                        response,
                        validation_context,
                    )
                })
                .map(|v| {
                    active_shares += 1;
                    v
                })
                // Filter out shares for responses to requests that already have
                // responses in the block chain up to the point we are creating a
                // new payload.
                .filter(|&response| !delivered_ids.contains(&response.content.id))
                .cloned();

            // Group the shares by their metadata
            let response_candidates = group_shares(share_candidates);

            self.metrics.total_shares.set(total_share_count);
            self.metrics.active_shares.set(active_shares);

            self.metrics
                .unique_responses
                .set(response_candidates.len().try_into().unwrap());

            let response_candidates = response_candidates
                .iter()
                // Filter out groups that don't have enough shares to have consensus
                .filter(|(_, shares)| shares.len() >= threshold)
                // Fetch the associated content
                .filter_map(|(metadata, shares)| {
                    pool_access
                        .get_response_content_by_hash(&metadata.content_hash)
                        .map(|content| (metadata, shares, content))
                });

            // From the response candidates, we select the ones, that will fit into the payload
            let mut accumulated_size = 0;
            let mut candidates = vec![];
            let mut unique_includable_responses = 0;

            for (metadata, shares, content) in response_candidates {
                unique_includable_responses += 1;
                // FIXME: This MUST be the same size calculation as CanisterHttpResponseWithConsensus::count_bytes.
                // This should be explicit in the code
                let candidate_size = size_of::<CanisterHttpResponseProof>() + content.count_bytes();
                if NumBytes::new((accumulated_size + candidate_size) as u64) < byte_limit {
                    candidates.push((metadata.clone(), shares.clone(), content));
                    accumulated_size += candidate_size;
                }
            }

            // Check the state for timeouts
            // NOTE: We can not use the existing timed out artifacts for this task, since we don't have consensus on them.
            // For example a malicious node might publish a single timed out metadata share and we would pick it up
            // to generate a time out response.
            // Instead, we scan the state metadata for timed out requests and generate time out responses based on that
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
                    // TODO: Account for size of timeouts
                    // Check for timed out requests and include them into the block
                    // if they have not been delivered yet
                    if request.time + CANISTER_HTTP_TIMEOUT_INTERVAL < validation_context.time
                        && !delivered_ids.contains(callback_id)
                    {
                        timeouts.push(*callback_id);
                    }
                }
            }

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

        let delivered_ids = Self::get_past_payload_ids(past_payloads);

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
            Self::check_response_consistency(response)
                .map_err(CanisterHttpPayloadValidationError::Permanent)?;

            // Validate response against `ValidationContext`
            self.check_response_against_context(
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

        // Verify the signatures
        // NOTE: We do this in a separate loop because this check is expensive and we want to
        // do all the cheap checks first
        for response in &payload.responses {
            self.crypto
                .verify_aggregate(&response.proof, consensus_registry_version)
                .map_err(|err| {
                    CanisterHttpPayloadValidationError::Permanent(
                        CanisterHttpPermanentValidationError::SignatureError(Box::new(err)),
                    )
                })?;
        }

        // Successfully return with payload size
        Ok(NumBytes::from(payload_size as u64))
    }
}

struct CanisterHttpPayloadBuilderMetrics {
    /// Records the time it took to perform an operation
    op_duration: HistogramVec,
    /// The total number of validated shares in the pool
    total_shares: IntGauge,
    /// The number of shares which are not timed out or have ineligible registry
    /// versions.
    active_shares: IntGauge,
    /// The number of unique responses
    unique_responses: IntGauge,
    /// The number of unique responses which are includable in the latest
    /// attempt to create a block for which there are shares in the pool. In
    /// particular, these responses have met the threshold for inclusion.
    unique_includable_responses: IntGauge,
}

impl CanisterHttpPayloadBuilderMetrics {
    fn new(metrics_registry: &MetricsRegistry) -> Self {
        Self {
            op_duration: metrics_registry.histogram_vec(
                "canister_http_payload_build_duration",
                "The time it took the payload builder to perform an operation",
                // 0.1ms - 5s
                decimal_buckets(-4, 0),
                &["operation"],
            ),
            total_shares: metrics_registry.int_gauge(
                "canister_http_total_validated_shares",
                "The total number of validated shares in the pool",
            ),
            active_shares: metrics_registry.int_gauge(
                "canister_http_total_active_validated_shares",
                "The total number of validated shares that are not timed out or made with invalid registry version."
            ),
            unique_responses: metrics_registry.int_gauge(
                "canister_http_unique_responses",
                "The total number of unique responses that are currently active"
            ),
            unique_includable_responses: metrics_registry.int_gauge(
                "canister_http_unique_includable_responses",
                "The total number of unique responses that could be included in a block"
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus::mocks::{dependencies_with_subnet_params, Dependencies};
    use ic_artifact_pool::canister_http_pool::CanisterHttpPoolImpl;
    use ic_interfaces::{
        artifact_pool::UnvalidatedArtifact,
        canister_http::{CanisterHttpChangeAction, MutableCanisterHttpPool},
        validation::ValidationError,
    };
    use ic_logger::replica_logger::no_op_logger;
    use ic_protobuf::registry::subnet::v1::SubnetFeatures;
    use ic_test_utilities::{
        mock_time,
        types::ids::{canister_test_id, node_test_id, subnet_test_id},
    };
    use ic_test_utilities_registry::SubnetRecordBuilder;
    use ic_types::{
        canister_http::CanisterHttpResponseContent,
        crypto::{CombinedMultiSig, CombinedMultiSigOf, IndividualMultiSig, IndividualMultiSigOf},
        signature::MultiSignature,
        time::UNIX_EPOCH,
    };
    use std::{ops::DerefMut, time::Duration};

    /// Check that a single well formed request with shares makes it through the block maker
    #[test]
    fn single_request_test() {
        let (response, metadata) = test_response_and_metadata(0);
        let shares = metadata_to_shares(4, &metadata);

        // Initialize a CanisterHttpPayloadBuilder with the pool
        test_config_with_http_feature(4, |payload_builder, canister_http_pool| {
            // Add response and shares to pool
            // NOTE: We are only adding 3 of the 4 shares, and still expect the response to be successfully created
            {
                let mut pool_access = canister_http_pool.write().unwrap();
                add_own_share_to_pool(pool_access.deref_mut(), &shares[0], &response);
                add_received_shares_to_pool(pool_access.deref_mut(), shares[1..3].to_vec());
            }

            // Build a payload
            let payload = payload_builder.get_canister_http_payload(
                Height::new(1),
                &ValidationContext {
                    registry_version: RegistryVersion::new(1),
                    certified_height: Height::new(0),
                    time: mock_time(),
                },
                &[],
                NumBytes::new(4 * 1024 * 1024),
            );

            //  Make sure the response is contained in the payload
            assert_eq!(payload.num_responses(), 1);
            assert_eq!(payload.responses[0].content, response);
        });
    }

    /// Submit a number of requests to the payload builder:
    ///
    /// - One has insufficient support
    /// - One has timed out
    /// - One has wrong registry version
    /// - One is oversized (Larger than 2 MiB)
    /// - Two are valid, but one is already in pasts payloads
    ///
    /// Expect:
    /// - Only one response to make it into the payload
    #[test]
    fn multiple_payload_test() {
        // Initialize a CanisterHttpPayloadBuilder with the pool
        let (valid_response, valid_metadata) = test_response_and_metadata(0);

        test_config_with_http_feature(4, |payload_builder, canister_http_pool| {
            // Add response and shares to pool
            let (past_response, past_metadata) = {
                let mut pool_access = canister_http_pool.write().unwrap();

                // Add the valid response into the pool
                let shares = metadata_to_shares(4, &valid_metadata);
                add_own_share_to_pool(pool_access.deref_mut(), &shares[0], &valid_response);
                add_received_shares_to_pool(pool_access.deref_mut(), shares[1..4].to_vec());

                // Add a valid response into the pool but only two shares
                let (response, metadata) = test_response_and_metadata(1);
                let shares = metadata_to_shares(4, &metadata);
                add_own_share_to_pool(pool_access.deref_mut(), &shares[0], &response);
                add_received_shares_to_pool(pool_access.deref_mut(), shares[1..2].to_vec());

                // Add a response that is already timed out
                let (mut response, mut metadata) = test_response_and_metadata(2);
                response.timeout = mock_time();
                metadata.timeout = mock_time();
                let shares = metadata_to_shares(4, &metadata);
                add_own_share_to_pool(pool_access.deref_mut(), &shares[0], &response);
                add_received_shares_to_pool(pool_access.deref_mut(), shares[1..4].to_vec());

                // Add a response with mismatching registry version
                let (response, mut metadata) = test_response_and_metadata(3);
                metadata.registry_version = RegistryVersion::new(5);
                let shares = metadata_to_shares(4, &metadata);
                add_own_share_to_pool(pool_access.deref_mut(), &shares[0], &response);
                add_received_shares_to_pool(pool_access.deref_mut(), shares[1..4].to_vec());

                // Add a oversized response
                let (mut response, metadata) = test_response_and_metadata(4);
                response.content = CanisterHttpResponseContent::Success(vec![123; 2 * 1024 * 1024]);
                let shares = metadata_to_shares(4, &metadata);
                add_own_share_to_pool(pool_access.deref_mut(), &shares[0], &response);
                add_received_shares_to_pool(pool_access.deref_mut(), shares[1..4].to_vec());

                // Add response which is valid but we will put it into past_payloads
                let (past_response, past_metadata) = test_response_and_metadata(5);
                let shares = metadata_to_shares(4, &past_metadata);
                add_own_share_to_pool(pool_access.deref_mut(), &shares[0], &past_response);
                add_received_shares_to_pool(pool_access.deref_mut(), shares[1..4].to_vec());

                (past_response, past_metadata)
            };

            // Set up past payload
            let past_payload = CanisterHttpPayload {
                responses: vec![CanisterHttpResponseWithConsensus {
                    content: past_response,
                    proof: Signed {
                        content: past_metadata,
                        signature: MultiSignature::<CanisterHttpResponseMetadata> {
                            signature: CombinedMultiSigOf::new(CombinedMultiSig(vec![])),
                            signers: vec![],
                        },
                    },
                }],
                timeouts: vec![],
            };

            // Build a payload
            let payload = payload_builder.get_canister_http_payload(
                Height::new(1),
                &ValidationContext {
                    registry_version: RegistryVersion::new(1),
                    certified_height: Height::new(0),
                    time: mock_time() + Duration::from_secs(3),
                },
                &[&past_payload],
                NumBytes::new(4 * 1024 * 1024),
            );

            //  Make sure the response is not contained in the payload
            assert_eq!(payload.num_responses(), 1);
            assert_eq!(payload.responses[0].content, valid_response);
        });
    }

    /// Test that oversized payloads don't validate
    #[test]
    fn oversized_validation() {
        let validation_result = run_validatation_test(
            |response, _| {
                // Give response oversized content
                response.content = CanisterHttpResponseContent::Success(vec![123; 2 * 1024 * 1024]);
            },
            &default_validation_context(),
        );
        match validation_result {
            Err(ValidationError::Permanent(
                CanisterHttpPermanentValidationError::PayloadTooBig { expected, received },
            )) if expected == 2 * 1024 * 1024 && received > expected => (),
            x => panic!("Expected PayloadTooBig, got {:?}", x),
        }
    }

    /// Test that inconsistent payloads don't validate
    #[test]
    fn inconsistend_validation() {
        let validation_result = run_validatation_test(
            |_, metadata| {
                // Set metadata callback id to a different id
                metadata.id = CallbackId::new(2);
            },
            &default_validation_context(),
        );
        match validation_result {
            Err(ValidationError::Permanent(
                CanisterHttpPermanentValidationError::InvalidMetadata {
                    metadata_id,
                    content_id,
                    ..
                },
            )) if metadata_id == CallbackId::new(2) && content_id == CallbackId::new(0) => (),
            x => panic!("Expected InvalidMetadata, got {:?}", x),
        }
    }

    /// Test that payloads with wrong registry version don't validate
    #[test]
    fn registry_version_validation() {
        let validation_result = run_validatation_test(
            |_, metadata| {
                // Set metadata to a newer registry version
                metadata.registry_version = RegistryVersion::new(2);
            },
            &ValidationContext {
                ..default_validation_context()
            },
        );
        match validation_result {
            Err(ValidationError::Permanent(
                CanisterHttpPermanentValidationError::RegistryVersionMismatch { .. },
            )) => (),
            x => panic!("Expected RegistryVersionMismatch, got {:?}", x),
        }
    }

    /// Test that payloads with wrong hash don't validate
    #[test]
    fn hash_validation() {
        let validation_result = run_validatation_test(
            |response, _| {
                // Change response content to have a different hash
                response.content = CanisterHttpResponseContent::Success(b"cba".to_vec());
            },
            &default_validation_context(),
        );
        match validation_result {
            Err(ValidationError::Permanent(
                CanisterHttpPermanentValidationError::ContentHashMismatch { .. },
            )) => (),
            x => panic!("Expected ContentHashMismatch, got {:?}", x),
        }
    }

    /// Test that payloads which are timed out don't validate
    #[test]
    fn timeout_validation() {
        let validation_result = run_validatation_test(
            |_, _| { /* Nothing to modify */ },
            &ValidationContext {
                // Set the time further in the future, such that this payload is timed out
                time: mock_time() + Duration::from_secs(20),
                ..default_validation_context()
            },
        );
        match validation_result {
            Err(ValidationError::Permanent(CanisterHttpPermanentValidationError::Timeout {
                timed_out_at,
                validation_time,
            })) if timed_out_at < validation_time => (),
            x => panic!("Expected Timeout, got {:?}", x),
        }
    }

    /// Test that payloads don't validate, if registry for height does not exist
    #[test]
    fn registry_unavailable_validation() {
        let validation_result = run_validatation_test(
            |_, _| { /* Nothing to modify */ },
            &ValidationContext {
                // Use a higher registry version, that does not exist yet
                registry_version: RegistryVersion::new(2),
                ..default_validation_context()
            },
        );
        match validation_result {
            Err(ValidationError::Transient(
                CanisterHttpTransientValidationError::RegistryUnavailable(
                    RegistryClientError::VersionNotAvailable { version },
                ),
            )) if version == RegistryVersion::new(2) => (),
            x => panic!("Expected RegistryUnavailable, got {:?}", x),
        }
    }

    /// Test that payloads don't validate when feature is disabled
    ///
    /// NOTE: We use the fact that the feature is disabled for registry version 0, so we can still reuse
    /// the existing helper functions
    #[test]
    fn feature_disabled_validation() {
        let validation_result = run_validatation_test(
            |_, mut metadata| {
                // Set registry version to 0
                metadata.registry_version = RegistryVersion::new(0);
            },
            &ValidationContext {
                // Use registry version 0
                registry_version: RegistryVersion::new(0),
                ..default_validation_context()
            },
        );
        match validation_result {
            Err(ValidationError::Transient(CanisterHttpTransientValidationError::Disabled)) => (),
            x => panic!("Expected Disabled, got {:?}", x),
        }
    }

    /// Test that duplicate payloads don't validate
    #[test]
    fn duplicate_validation() {
        test_config_with_http_feature(4, |payload_builder, _| {
            let (response, metadata) = test_response_and_metadata(0);

            let payload = CanisterHttpPayload {
                responses: vec![response_and_metadata_to_proof(&response, &metadata)],
                timeouts: vec![],
            };

            let validation_result = payload_builder.validate_canister_http_payload(
                Height::from(1),
                &payload,
                &default_validation_context(),
                &[&payload],
            );

            match validation_result {
                Err(ValidationError::Permanent(
                    CanisterHttpPermanentValidationError::DuplicateResponse(id),
                )) if id == CallbackId::new(0) => (),
                x => panic!("Expected DuplicateResponse, got {:?}", x),
            }
        });
    }

    /// Build some test metadata and response, which is valid and can be used in different tests
    fn test_response_and_metadata(
        callback_id: u64,
    ) -> (CanisterHttpResponse, CanisterHttpResponseMetadata) {
        // Build a response
        let response = CanisterHttpResponse {
            id: CallbackId::new(callback_id),
            timeout: mock_time() + Duration::from_secs(10),
            canister_id: canister_test_id(0),
            content: CanisterHttpResponseContent::Success(b"abc".to_vec()),
        };

        // Create metadata of response
        let metadata = CanisterHttpResponseMetadata {
            id: response.id,
            timeout: response.timeout,
            content_hash: crypto_hash(&response),
            registry_version: RegistryVersion::new(1),
        };

        (response, metadata)
    }

    /// Replicates the behaviour of receiving and successfully validating a share over the network
    fn add_received_shares_to_pool(
        pool: &mut dyn MutableCanisterHttpPool,
        shares: Vec<CanisterHttpResponseShare>,
    ) {
        for share in shares {
            let hash = crypto_hash(&share);

            pool.insert(UnvalidatedArtifact {
                message: share,
                peer_id: node_test_id(0),
                timestamp: mock_time(),
            });

            pool.apply_changes(vec![CanisterHttpChangeAction::MoveToValidated(hash)])
        }
    }

    /// Replicates the behaviour of adding your own share (and content) to the pool
    fn add_own_share_to_pool(
        pool: &mut dyn MutableCanisterHttpPool,
        share: &CanisterHttpResponseShare,
        content: &CanisterHttpResponse,
    ) {
        pool.apply_changes(vec![CanisterHttpChangeAction::AddToValidated(
            share.clone(),
            content.clone(),
        )]);
    }

    /// Creates a [`CanisterHttpResponseShare`] from [`CanisterHttpResponseMetadata`]
    fn metadata_to_share(
        from_node: u64,
        metadata: &CanisterHttpResponseMetadata,
    ) -> CanisterHttpResponseShare {
        Signed {
            content: metadata.clone(),
            signature: MultiSignatureShare::<CanisterHttpResponseMetadata> {
                // NOTE: Since we are using CryptoReturningOk we don't need an actual signature
                signature: IndividualMultiSigOf::new(IndividualMultiSig(vec![])),
                signer: node_test_id(from_node),
            },
        }
    }

    /// Creates a [`CanisterHttpResponseWithConsensus`] from a [`CanisterHttpResponse`] and [`CanisterHttpResponseMetadata`]
    fn response_and_metadata_to_proof(
        response: &CanisterHttpResponse,
        metadata: &CanisterHttpResponseMetadata,
    ) -> CanisterHttpResponseWithConsensus {
        CanisterHttpResponseWithConsensus {
            content: response.clone(),
            proof: Signed {
                content: metadata.clone(),
                signature: MultiSignature {
                    signature: CombinedMultiSigOf::new(CombinedMultiSig(vec![])),
                    signers: vec![],
                },
            },
        }
    }

    /// Creates a vector of [`CanisterHttpResponseShare`]s by calling [`metadata_to_share`]
    fn metadata_to_shares(
        num_nodes: u64,
        metadata: &CanisterHttpResponseMetadata,
    ) -> Vec<CanisterHttpResponseShare> {
        (0..num_nodes)
            .into_iter()
            .map(|id| metadata_to_share(id, metadata))
            .collect()
    }

    /// Mock up a test node, which has the feauture enabled
    fn test_config_with_http_feature<T>(
        num_nodes: usize,
        run: impl FnOnce(CanisterHttpPayloadBuilderImpl, Arc<RwLock<CanisterHttpPoolImpl>>) -> T,
    ) -> T {
        let committee = (0..num_nodes)
            .into_iter()
            .map(|id| node_test_id(id as u64))
            .collect::<Vec<_>>();
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            let mut subnet_record = SubnetRecordBuilder::from(&committee).build();
            subnet_record.features = Some(SubnetFeatures {
                http_requests: true,
                ..SubnetFeatures::default()
            });

            let Dependencies {
                crypto,
                registry,
                membership,
                pool,
                canister_http_pool,
                state_manager,
                ..
            } = dependencies_with_subnet_params(
                pool_config,
                subnet_test_id(0),
                vec![(1, subnet_record)],
            );

            let payload_builder = CanisterHttpPayloadBuilderImpl::new(
                canister_http_pool.clone(),
                pool.get_cache(),
                crypto,
                state_manager,
                membership,
                subnet_test_id(0),
                registry,
                &MetricsRegistry::new(),
                no_op_logger(),
            );

            run(payload_builder, canister_http_pool)
        })
    }

    /// The default validation context used in the validation tests
    fn default_validation_context() -> ValidationContext {
        ValidationContext {
            registry_version: RegistryVersion::new(1),
            certified_height: Height::new(0),
            time: UNIX_EPOCH + Duration::from_secs(5),
        }
    }

    /// Mocks up a test environment and test response and metadata. Lets the caller modify them and
    /// then runs validation on it and returns the validation result.
    ///
    /// This is useful to run a number of tests against the payload validator, without the need
    /// to mock up all needed structures again and again.
    fn run_validatation_test<F>(
        mut modify: F,
        validation_context: &ValidationContext,
    ) -> Result<NumBytes, CanisterHttpPayloadValidationError>
    where
        F: FnMut(&mut CanisterHttpResponse, &mut CanisterHttpResponseMetadata),
    {
        test_config_with_http_feature(4, |payload_builder, _| {
            let (mut response, mut metadata) = test_response_and_metadata(0);
            modify(&mut response, &mut metadata);

            let payload = CanisterHttpPayload {
                responses: vec![response_and_metadata_to_proof(&response, &metadata)],
                timeouts: vec![],
            };

            payload_builder.validate_canister_http_payload(
                Height::from(1),
                &payload,
                validation_context,
                &[],
            )
        })
    }
}
