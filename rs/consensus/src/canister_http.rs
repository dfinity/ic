//! This module encapsulates all components required for canister http requests.
use crate::consensus::{
    utils::{group_shares, registry_version_at_height},
    ConsensusCrypto, Membership,
};
use ic_crypto::crypto_hash;
use ic_interfaces::{
    canister_http::{
        CanisterHttpGossip, CanisterHttpPayloadBuilder, CanisterHttpPayloadValidationError,
        CanisterHttpPermananentValidationError, CanisterHttpPool,
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
    },
    consensus::Committee,
    crypto::Signed,
    messages::CallbackId,
    registry::RegistryClientError,
    signature::MultiSignatureShare,
    CountBytes, Height, NumBytes, RegistryVersion, SubnetId,
};
use prometheus::HistogramVec;
use std::{
    collections::{BTreeSet, HashSet},
    mem::size_of,
    sync::{Arc, RwLock},
};

pub mod pool_manager;

/// The canonical implementation of [`CanisterHttpGossip`]
struct CanisterHttpGossipImpl {
    consensus_cache: Arc<dyn ConsensusPoolCache>,
    state_manager: Arc<dyn StateManager<State = ReplicatedState>>,
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
        Box::new(
            move |_, attr: &'_ CanisterHttpResponseAttribute| match attr {
                CanisterHttpResponseAttribute::Share(
                    msg_registry_version,
                    callback_id,
                    _content_hash,
                ) => {
                    if *msg_registry_version != registry_version {
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
    ) -> Result<(), CanisterHttpPermananentValidationError> {
        let content = &response.content;
        let metadata = &response.proof.content;

        // Check metadata field consistency
        match (
            metadata.id == content.id,
            metadata.timeout == content.timeout,
        ) {
            (true, true) => (),
            _ => {
                return Err(CanisterHttpPermananentValidationError::InvalidMetadata {
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
            return Err(
                CanisterHttpPermananentValidationError::ContentHashMismatch {
                    metadata_hash: metadata.content_hash.clone(),
                    calculated_hash,
                },
            );
        }

        Ok(())
    }

    /// Checks whether the response is valid against the provided [`ValidationContext`]
    fn check_response_against_context(
        &self,
        registry_version: RegistryVersion,
        response: &CanisterHttpResponseWithConsensus,
        context: &ValidationContext,
    ) -> Result<(), CanisterHttpPermananentValidationError> {
        // Check that response has not timed out
        if response.content.timeout >= context.time {
            return Err(CanisterHttpPermananentValidationError::Timeout {
                timed_out_at: response.content.timeout,
                validation_time: context.time,
            });
        }

        // Check that registry version matched
        if response.proof.content.registry_version != registry_version {
            return Err(
                CanisterHttpPermananentValidationError::RegistryVersionMismatch {
                    expected: registry_version,
                    received: response.proof.content.registry_version,
                },
            );
        }

        Ok(())
    }

    /// Returns true, if the [`CanisterHttpResponseShare`] is valid against the [`ValidationContext`]
    fn check_share_against_context(
        &self,
        registry_version: RegistryVersion,
        share: &CanisterHttpResponseShare,
        context: &ValidationContext,
    ) -> bool {
        !(share.content.timeout >= context.time
            || share.content.registry_version != registry_version)
    }

    /// Creates a [`HashSet`] of [`CallbackId`]s from `past_payloads`
    fn get_past_payload_ids(past_payloads: &[&CanisterHttpPayload]) -> HashSet<CallbackId> {
        past_payloads
            .iter()
            .flat_map(|payload| payload.0.iter().map(|response| response.content.id))
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
        let mut candidates = {
            let pool_access = self.pool.read().unwrap();

            // Get share candidates to include in the block
            let share_candidates = pool_access
                .get_validated_shares()
                // Filter out shares that are timed out or have the wrong registry versions
                .filter(|&response| {
                    !self.check_share_against_context(
                        consensus_registry_version,
                        response,
                        validation_context,
                    )
                })
                // Filter out shares, that contains Ids which we already have consensus on
                .filter(|&response| !delivered_ids.contains(&response.content.id))
                .cloned();

            // Group the shares by their metadata
            let response_candidates = group_shares(share_candidates);
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

            for (metadata, shares, content) in response_candidates {
                // FIXME: This MUST be the same size calculation as CanisterHttpResponseWithConsensus::count_bytes.
                // This should be explicit in the code
                let candidate_size = size_of::<CanisterHttpResponseProof>() + content.count_bytes();
                if NumBytes::new((accumulated_size + candidate_size) as u64) < byte_limit {
                    candidates.push((metadata.clone(), shares.clone(), content));
                    accumulated_size += candidate_size;
                }
            }

            candidates
        };

        // Now that we have the candidates, aggregate the signatures and construct the payload
        let payload = CanisterHttpPayload(
            candidates
                .drain(..)
                .filter_map(|(metadata, shares, content)| {
                    self.aggregate(consensus_registry_version, metadata, shares, content)
                })
                .collect(),
        );

        // Check validation as safety measure
        match self.validate_canister_http_payload(
            height,
            &payload,
            validation_context,
            past_payloads,
        ) {
            Ok(_) => (),
            Err(err) => {
                warn!(self.log, "CanisterHttpPayloadBuilder failed to build a payload that passes validation: {:?}", err);
                return CanisterHttpPayload::default();
            }
        }

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
        let payload_size = payload.0.iter().map(CountBytes::count_bytes).sum::<usize>();
        if payload_size > MAX_CANISTER_HTTP_PAYLOAD_SIZE {
            return Err(CanisterHttpPayloadValidationError::Permanent(
                CanisterHttpPermananentValidationError::PayloadTooBig {
                    expected: MAX_CANISTER_HTTP_PAYLOAD_SIZE,
                    received: payload_size,
                },
            ));
        }

        let delivered_ids = Self::get_past_payload_ids(past_payloads);

        // Get the consensus registry version
        let consensus_registry_version = registry_version_at_height(self.cache.as_ref(), height)
            .ok_or(CanisterHttpPayloadValidationError::Transient(
                CanisterHttpTransientValidationError::ConsensusRegistryVersionUnavailable,
            ))?;

        // Check conditions on individual reponses
        for response in &payload.0 {
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
                    CanisterHttpPermananentValidationError::DuplicateResponse(response.content.id),
                ));
            }
        }

        // Verify the signatures
        // NOTE: We do this in a separate loop because this check is expensive and we want to
        // do all the cheap checks first
        for response in &payload.0 {
            self.crypto
                .verify_aggregate(&response.proof, consensus_registry_version)
                .map_err(|err| {
                    CanisterHttpPayloadValidationError::Permanent(
                        CanisterHttpPermananentValidationError::SignatureError(Box::new(err)),
                    )
                })?;
        }

        // Successfully return with payload size
        Ok(NumBytes::from(payload_size as u64))
    }
}

struct CanisterHttpPayloadBuilderMetrics {
    // Records the time it took to perform an operation
    op_duration: HistogramVec,
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
        }
    }
}
