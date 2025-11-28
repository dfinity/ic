//! This module provides the component responsible for generating and validating
//! payloads relevant to VetKd.

use crate::metrics::VetKdPayloadBuilderMetrics;
use crate::utils::{
    group_shares_by_callback_id, invalid_artifact, invalid_artifact_err, parse_past_payload_ids,
    validation_failed, validation_failed_err,
};
use ic_consensus_utils::{
    crypto::ConsensusCrypto, get_registry_version_and_interval_length_at_height,
};
use ic_error_types::RejectCode;
use ic_interfaces::crypto::ErrorReproducibility;
use ic_interfaces::{
    batch_payload::{BatchPayloadBuilder, IntoMessages, PastPayload, ProposalContext},
    consensus::PayloadValidationError,
    consensus_pool::ConsensusPoolCache,
    idkg::IDkgPool,
    vetkd::{InvalidVetKdPayloadReason, VetKdPayloadValidationFailure},
};
use ic_interfaces_registry::RegistryClient;
use ic_interfaces_state_manager::StateReader;
use ic_logger::{ReplicaLogger, warn};
use ic_management_canister_types_private::{MasterPublicKeyId, Payload, VetKdDeriveKeyResult};
use ic_metrics::MetricsRegistry;
use ic_registry_client_helpers::chain_keys::ChainKeysRegistry;
use ic_registry_client_helpers::subnet::SubnetRegistry;
use ic_replicated_state::{
    ReplicatedState,
    metadata_state::subnet_call_context_manager::{SignWithThresholdContext, ThresholdArguments},
};
use ic_types::crypto::vetkd::{VetKdKeyShareCombinationError, VetKdKeyVerificationError};
use ic_types::{
    CountBytes, Height, NumBytes, SubnetId, Time,
    batch::{
        ConsensusResponse, ValidationContext, VetKdAgreement, VetKdErrorCode, VetKdPayload,
        bytes_to_vetkd_payload, vetkd_payload_to_bytes,
    },
    crypto::vetkd::{VetKdArgs, VetKdEncryptedKey},
    messages::{CallbackId, Payload as ResponsePayload, RejectContext},
};
use num_traits::ops::saturating::SaturatingSub;
use rayon::ThreadPool;
use rayon::iter::{IntoParallelIterator, IntoParallelRefIterator, ParallelIterator};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use std::{
    collections::{BTreeMap, BTreeSet, HashSet},
    sync::{Arc, RwLock},
};

mod metrics;
#[cfg(test)]
mod test_utils;
mod utils;

/// In addition to a timeout, we expire request contexts that were created more than one entire
/// DKG interval ago. VetKD NiDkgTranscripts are reshared during every interval. However, it is
/// important that for any given request, we use the same transcript to create, validate and
/// combine vetKD shares. Consequently, once the NiDkgTranscript that was paired with a request
/// context disappears from the summary block, the outstanding request should be rejected.
///
/// Request contexts are paired with the summary's "next transcript", if such a transcript exists,
/// otherwise the "current transcript" is used.
/// This guarantees that the transcript will exist for at least one DKG interval starting with the
/// creation of the context: If it was a "next transcript", then it will still exist as a "current
/// transcript" in the subsequent interval. If it was a "current transcript", then this implies
/// that there was no "next transcript". Therefore the "current transcript" will remain a "current
/// transcript" during the next interval, as well.
#[derive(Debug)]
struct RequestExpiry {
    time: Option<Time>,
    height: Height,
}

/// Implementation of the [`BatchPayloadBuilder`] for the VetKd feature.
pub struct VetKdPayloadBuilderImpl {
    pool: Arc<RwLock<dyn IDkgPool>>,
    cache: Arc<dyn ConsensusPoolCache>,
    crypto: Arc<dyn ConsensusCrypto>,
    state_reader: Arc<dyn StateReader<State = ReplicatedState>>,
    thread_pool: Arc<ThreadPool>,
    subnet_id: SubnetId,
    registry: Arc<dyn RegistryClient>,
    metrics: VetKdPayloadBuilderMetrics,
    log: ReplicaLogger,
}

impl VetKdPayloadBuilderImpl {
    /// Create and initialize an instance of [`VetKdPayloadBuilderImpl`].
    pub fn new(
        pool: Arc<RwLock<dyn IDkgPool>>,
        cache: Arc<dyn ConsensusPoolCache>,
        crypto: Arc<dyn ConsensusCrypto>,
        state_reader: Arc<dyn StateReader<State = ReplicatedState>>,
        thread_pool: Arc<ThreadPool>,
        subnet_id: SubnetId,
        registry: Arc<dyn RegistryClient>,
        metrics_registry: &MetricsRegistry,
        log: ReplicaLogger,
    ) -> Self {
        Self {
            pool,
            cache,
            crypto,
            state_reader,
            thread_pool,
            subnet_id,
            registry,
            metrics: VetKdPayloadBuilderMetrics::new(metrics_registry),
            log,
        }
    }

    /// Return the set of enabled VetKD key IDs and request expiry time according to
    /// the chain key config at the registry version corresponding to the given block height.
    fn get_enabled_keys_and_expiry(
        &self,
        height: Height,
        context_time: Time,
    ) -> Result<(BTreeSet<MasterPublicKeyId>, RequestExpiry), PayloadValidationError> {
        let Some((registry_version, dkg_interval_length)) =
            get_registry_version_and_interval_length_at_height(self.cache.as_ref(), height)
        else {
            warn!(
                self.log,
                "Failed to obtain consensus registry version and interval length in VetKd payload builder"
            );
            return Err(validation_failed(
                VetKdPayloadValidationFailure::DkgSummaryUnavailable(height),
            ));
        };

        let config = match self
            .registry
            .get_chain_key_config(self.subnet_id, registry_version)
        {
            Ok(Some(config)) => config,
            Ok(None) => {
                return Err(invalid_artifact(InvalidVetKdPayloadReason::Disabled));
            }
            Err(err) => {
                warn!(
                    self.log,
                    "VetKdPayloadBuilder: Registry unavailable: {:?}", err
                );
                return Err(validation_failed(
                    VetKdPayloadValidationFailure::RegistryClientError(err),
                ));
            }
        };

        let request_expiry_time = config
            .signature_request_timeout_ns
            .and_then(|timeout| context_time.checked_sub(Duration::from_nanos(timeout)));

        let enabled_subnets = self
            .registry
            .get_chain_key_enabled_subnets(registry_version)
            .map_err(|err| {
                warn!(
                    self.log,
                    "VetKdPayloadBuilder: Registry unavailable: {:?}", err
                );
                validation_failed(VetKdPayloadValidationFailure::RegistryClientError(err))
            })?
            .unwrap_or_default();

        let key_ids = config
            .key_configs
            .into_iter()
            .map(|key_config| key_config.key_id)
            // Skip keys that don't need to run NIDKG protocol
            .filter(|key_id| key_id.is_vetkd_key())
            // Skip keys that are disabled
            .filter(|key_id| {
                enabled_subnets
                    .get(key_id)
                    .is_some_and(|subnets| subnets.contains(&self.subnet_id))
            })
            .collect();

        let request_expiry_height = height.saturating_sub(&dkg_interval_length);

        Ok((
            key_ids,
            RequestExpiry {
                time: request_expiry_time,
                height: request_expiry_height,
            },
        ))
    }

    fn get_vetkd_payload_impl(
        &self,
        request_expiry: RequestExpiry,
        valid_keys: BTreeSet<MasterPublicKeyId>,
        state: &ReplicatedState,
        delivered_ids: HashSet<CallbackId>,
        max_payload_size: NumBytes,
    ) -> VetKdPayload {
        let grouped_shares = {
            let pool_access = self.pool.read().unwrap();
            group_shares_by_callback_id(
                pool_access
                    .validated()
                    .vetkd_key_shares()
                    .map(|(_id, share)| share)
                    .filter(|share| !delivered_ids.contains(&share.request_id.callback_id)),
            )
        };

        let accumulated_size_estimate = AtomicUsize::new(0);
        let candidates = self.thread_pool.install(|| {
            state
                .signature_request_contexts()
                .par_iter()
                .flat_map(|(callback_id, context)| {
                    if !context.is_vetkd() {
                        // Skip non-vetkd contexts.
                        return None;
                    }

                    if delivered_ids.contains(callback_id) {
                        // Skip contexts for which we already delivered a response.
                        return None;
                    }

                    if let Some(reject) = reject_if_invalid(
                        &valid_keys,
                        context,
                        &request_expiry,
                        Some(&self.metrics),
                    ) {
                        return Some((*callback_id, reject));
                    }

                    let shares = grouped_shares.get(callback_id)?;
                    let ThresholdArguments::VetKd(ctxt_args) = &context.args else {
                        return None;
                    };
                    let args = VetKdArgs {
                        caller: context.request.sender.get_ref(),
                        context: context.derivation_path.as_ref().first().expect(
                            "the context's derivation path for vetKD should have exactly one element",
                        ), 
                        ni_dkg_id: &ctxt_args.ni_dkg_id,
                        input: &ctxt_args.input,
                        transport_public_key: &ctxt_args.transport_public_key,
                    };
                    let key_id = context.key_id();
                    match self.crypto.combine_encrypted_key_shares(shares, &args) {
                        Ok(key) => {
                            self.metrics
                                .payload_metrics_inc("vetkd_agreement_completed", &key_id);
                            let result = VetKdDeriveKeyResult {
                                encrypted_key: key.encrypted_key,
                            };
                            Some((*callback_id, VetKdAgreement::Success(result.encode())))
                        }
                        Err(
                            VetKdKeyShareCombinationError::UnsatisfiedReconstructionThreshold {
                                ..
                            },
                        ) => None,
                        Err(err) => {
                            warn!(
                                self.log,
                                "Failed to combine vetKD key shares: callback_id = {:?}, {:?}",
                                callback_id,
                                err
                            );
                            self.metrics
                                .payload_errors_inc("combine_key_shares", &key_id);
                            None
                        }
                    }
                })
                .take_any_while(|(callback_id, candidate)| {
                    let candidate_size = callback_id.count_bytes() + candidate.count_bytes();
                    accumulated_size_estimate
                        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current_size| {
                            let new_size = current_size + candidate_size;
                            if new_size > max_payload_size.get() as usize {
                                return None;
                            }
                            Some(new_size)
                        })
                        .is_ok()
                })
                .collect::<BTreeMap<_, _>>()
        });

        VetKdPayload {
            vetkd_agreements: candidates,
        }
    }

    fn validate_vetkd_payload_impl(
        &self,
        payload: VetKdPayload,
        request_expiry: RequestExpiry,
        valid_keys: BTreeSet<MasterPublicKeyId>,
        state: &ReplicatedState,
        delivered_ids: HashSet<CallbackId>,
    ) -> Result<(), PayloadValidationError> {
        let contexts = state.signature_request_contexts();

        self.thread_pool.install(|| {
            payload
                .vetkd_agreements
                .into_par_iter()
                .map(|(id, agreement)| {
                    if delivered_ids.contains(&id) {
                        return invalid_artifact_err(InvalidVetKdPayloadReason::DuplicateResponse(
                            id,
                        ));
                    }

                    let Some(context) = contexts.get(&id) else {
                        return invalid_artifact_err(InvalidVetKdPayloadReason::MissingContext(id));
                    };

                    if !context.is_vetkd() {
                        return invalid_artifact_err(
                            InvalidVetKdPayloadReason::UnexpectedIDkgContext(id),
                        );
                    }

                    let expected_reject =
                        reject_if_invalid(&valid_keys, context, &request_expiry, None);

                    match agreement {
                        VetKdAgreement::Success(data) => {
                            if expected_reject.is_some() {
                                return invalid_artifact_err(
                                    InvalidVetKdPayloadReason::MismatchedAgreement {
                                        expected: expected_reject,
                                        received: None,
                                    },
                                );
                            } else {
                                self.validate_vetkd_agreement(id, context, data)?
                            }
                        }
                        reject => {
                            if Some(&reject) != expected_reject.as_ref() {
                                return invalid_artifact_err(
                                    InvalidVetKdPayloadReason::MismatchedAgreement {
                                        expected: expected_reject,
                                        received: Some(reject),
                                    },
                                );
                            }
                        }
                    }

                    Ok(())
                })
                .collect::<Result<Vec<()>, _>>()
        })?;

        Ok(())
    }

    /// Validate the VetKD key given in `data` according to the context of its request.
    fn validate_vetkd_agreement(
        &self,
        id: CallbackId,
        context: &SignWithThresholdContext,
        data: Vec<u8>,
    ) -> Result<(), PayloadValidationError> {
        let ThresholdArguments::VetKd(ctxt_args) = &context.args else {
            return invalid_artifact_err(InvalidVetKdPayloadReason::UnexpectedIDkgContext(id));
        };
        let args =
            VetKdArgs {
                caller: context.request.sender.get_ref(),
                context: context.derivation_path.as_ref().first().expect(
                    "the context's derivation path for vetKD should have exactly one element",
                ),
                ni_dkg_id: &ctxt_args.ni_dkg_id,
                input: &ctxt_args.input,
                transport_public_key: &ctxt_args.transport_public_key,
            };
        let reply = match VetKdDeriveKeyResult::decode(&data) {
            Ok(data) => data,
            Err(error) => {
                return invalid_artifact_err(InvalidVetKdPayloadReason::DecodingError(format!(
                    "{error:?}",
                )));
            }
        };
        let encrypted_key = VetKdEncryptedKey {
            encrypted_key: reply.encrypted_key,
        };
        self.crypto
            .verify_encrypted_key(&encrypted_key, &args)
            .map_err(|err| {
                if err.is_reproducible() {
                    warn!(self.log, "Invalid VetKD payload: {err:?}");
                    invalid_artifact(InvalidVetKdPayloadReason::VetKdKeyVerificationError(err))
                } else {
                    warn!(self.log, "VetKD payload validation failure: {err:?}");
                    let label = match err {
                        VetKdKeyVerificationError::ThresholdSigDataNotFound(_) => {
                            "validation_failed_nidkg_transcript_not_loaded"
                        }
                        _ => "validation_failed",
                    };
                    self.metrics.payload_errors_inc(label, &context.key_id());
                    validation_failed(VetKdPayloadValidationFailure::VetKdKeyVerificationError(
                        err,
                    ))
                }
            })
    }
}

impl BatchPayloadBuilder for VetKdPayloadBuilderImpl {
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

        let Ok((valid_keys, request_expiry)) =
            self.get_enabled_keys_and_expiry(height, context.time)
        else {
            return vec![];
        };

        let Ok(state) = self.state_reader.get_state_at(context.certified_height) else {
            return vec![];
        };

        let delivered_ids = parse_past_payload_ids(past_payloads, &self.log);
        let payload = self.get_vetkd_payload_impl(
            request_expiry,
            valid_keys,
            state.get_ref(),
            delivered_ids,
            max_size,
        );
        vetkd_payload_to_bytes(payload, max_size)
    }

    fn validate_payload(
        &self,
        height: Height,
        context: &ProposalContext,
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

        let (valid_keys, request_expiry) =
            self.get_enabled_keys_and_expiry(height, context.validation_context.time)?;

        let state = match self
            .state_reader
            .get_state_at(context.validation_context.certified_height)
        {
            Ok(state) => state,
            Err(err) => {
                return validation_failed_err(VetKdPayloadValidationFailure::StateUnavailable(err));
            }
        };

        let delivered_ids = parse_past_payload_ids(past_payloads, &self.log);
        let payload = bytes_to_vetkd_payload(payload)
            .map_err(|e| invalid_artifact(InvalidVetKdPayloadReason::DeserializationFailed(e)))?;

        self.validate_vetkd_payload_impl(
            payload,
            request_expiry,
            valid_keys,
            state.get_ref(),
            delivered_ids,
        )
    }
}

impl IntoMessages<Vec<ConsensusResponse>> for VetKdPayloadBuilderImpl {
    fn into_messages(payload: &[u8]) -> Vec<ConsensusResponse> {
        let messages = bytes_to_vetkd_payload(payload)
            .expect("Failed to parse a payload that was already validated");

        messages
            .vetkd_agreements
            .into_iter()
            .map(|(id, response)| {
                ConsensusResponse::new(
                    id,
                    match response {
                        VetKdAgreement::Success(data) => ResponsePayload::Data(data),
                        VetKdAgreement::Reject(error_code) => {
                            ResponsePayload::Reject(match error_code {
                                VetKdErrorCode::TimedOut => RejectContext::new(
                                    RejectCode::SysTransient,
                                    "VetKD request expired",
                                ),
                                VetKdErrorCode::InvalidKey => RejectContext::new(
                                    RejectCode::SysTransient,
                                    "Invalid or disabled key_id in VetKD request",
                                ),
                            })
                        }
                    },
                )
            })
            .collect()
    }
}

/// Reject the given context if
/// 1. it requests a key ID that isn't part of `valid_keys`,
/// 2. the request is expired according to the given `request_expiry.time`,
/// 3. the request is expired according to the given `request_expiry.height`
fn reject_if_invalid(
    valid_keys: &BTreeSet<MasterPublicKeyId>,
    context: &SignWithThresholdContext,
    request_expiry: &RequestExpiry,
    metrics: Option<&VetKdPayloadBuilderMetrics>,
) -> Option<VetKdAgreement> {
    let key_id = context.key_id();
    if !valid_keys.contains(&key_id) {
        if let Some(metrics) = metrics {
            metrics.payload_errors_inc("invalid_key_id", &key_id);
        }
        return Some(VetKdAgreement::Reject(VetKdErrorCode::InvalidKey));
    }

    if request_expiry
        .time
        .is_some_and(|expiry| context.batch_time < expiry)
    {
        if let Some(metrics) = metrics {
            metrics.payload_errors_inc("expired_request", &key_id);
        }
        return Some(VetKdAgreement::Reject(VetKdErrorCode::TimedOut));
    }

    // We time out vetKD requests that take longer than one DKG interval.
    // Otherwise the required NiDKG transcript might disappear before we
    // can complete the request.
    if let ThresholdArguments::VetKd(args) = &context.args
        && args.height < request_expiry.height
    {
        if let Some(metrics) = metrics {
            metrics.payload_errors_inc("expired_transcript", &key_id);
        }
        return Some(VetKdAgreement::Reject(VetKdErrorCode::TimedOut));
    }

    None
}

#[cfg(test)]
mod tests {
    use assert_matches::assert_matches;
    use core::{convert::From, iter::Iterator, time::Duration};
    use ic_consensus_mocks::{
        Dependencies, dependencies_with_subnet_records_with_raw_state_manager,
    };
    use ic_interfaces::consensus::{InvalidPayloadReason, PayloadValidationFailure};
    use ic_interfaces::idkg::IDkgChangeAction;
    use ic_interfaces::p2p::consensus::MutablePool;
    use ic_interfaces::validation::ValidationError;
    use ic_logger::no_op_logger;
    use ic_management_canister_types_private::VetKdKeyId;
    use ic_registry_subnet_features::ChainKeyConfig;
    use ic_registry_subnet_features::KeyConfig;
    use ic_test_utilities_registry::SubnetRecordBuilder;
    use ic_types::RegistryVersion;
    use ic_types::consensus::idkg::IDkgMessage;
    use ic_types::state_manager::StateManagerError;
    use ic_types::subnet_id_into_protobuf;
    use ic_types::time::UNIX_EPOCH;
    use ic_types::time::current_time;
    use ic_types_test_utils::ids::{node_test_id, subnet_test_id};
    use rayon::ThreadPoolBuilder;
    use std::str::FromStr;

    use super::*;
    use crate::test_utils::*;

    /// The DKG interval length during tests
    const DKG_INTERVAL_LENGTH: u64 = 59;

    /// The height of the payload to be tested
    const HEIGHT: Height = Height::new(134);

    /// The certified state height to be referenced
    const CERTIFIED_HEIGHT: Height = Height::new(133);

    /// The validation context to be used during tests
    const VALIDATION_CONTEXT: ValidationContext = ValidationContext {
        registry_version: RegistryVersion::new(10),
        certified_height: CERTIFIED_HEIGHT,
        time: UNIX_EPOCH,
    };

    /// The maximum payload size during tests
    const MAX_SIZE: NumBytes = NumBytes::new(1024);

    #[test]
    fn test_into_messages() {
        let agreements = make_vetkd_agreements(0, 1, 2);
        let payload = as_bytes(agreements.clone());
        let messages = VetKdPayloadBuilderImpl::into_messages(&payload);
        for i in 0..3 {
            let id = CallbackId::from(i);
            let agreement = agreements.get(&id).unwrap();
            let response = &messages[i as usize];
            assert_eq!(id, response.callback);
            match agreement {
                VetKdAgreement::Reject(VetKdErrorCode::InvalidKey) => {
                    let ResponsePayload::Reject(context) = &response.payload else {
                        panic!("Unexpected response: {response:?}");
                    };
                    context.assert_contains(
                        RejectCode::SysTransient,
                        "Invalid or disabled key_id in VetKD request",
                    );
                }
                VetKdAgreement::Reject(VetKdErrorCode::TimedOut) => {
                    let ResponsePayload::Reject(context) = &response.payload else {
                        panic!("Unexpected response: {response:?}");
                    };
                    context.assert_contains(RejectCode::SysTransient, "VetKD request expired");
                }
                VetKdAgreement::Success(data) => {
                    let ResponsePayload::Data(response_data) = &response.payload else {
                        panic!("Unexpected response: {response:?}");
                    };
                    assert_eq!(data, response_data);
                }
            }
        }
    }

    /// Run the given function for a payload builder that was setup using the given
    /// config, request contexts, and message shares.
    fn test_payload_builder<T>(
        config: Option<ChainKeyConfig>,
        contexts: BTreeMap<CallbackId, SignWithThresholdContext>,
        shares: Vec<IDkgMessage>,
        run: impl FnOnce(VetKdPayloadBuilderImpl) -> T,
    ) -> T {
        test_payload_builder_ext(config, true, contexts, shares, CERTIFIED_HEIGHT, true, run)
    }

    fn test_payload_builder_ext<T>(
        config: Option<ChainKeyConfig>,
        keys_enabled: bool,
        contexts: BTreeMap<CallbackId, SignWithThresholdContext>,
        shares: Vec<IDkgMessage>,
        certified_height: Height,
        finalize_last_summary: bool,
        run: impl FnOnce(VetKdPayloadBuilderImpl) -> T,
    ) -> T {
        let committee = (0..4).map(|id| node_test_id(id as u64)).collect::<Vec<_>>();
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            // Add the config to registry
            let subnet_record_builder =
                SubnetRecordBuilder::from(&committee).with_dkg_interval_length(DKG_INTERVAL_LENGTH);
            let subnet_record_builder = if let Some(config) = config.clone() {
                subnet_record_builder.with_chain_key_config(config)
            } else {
                subnet_record_builder
            };
            let subnet_id = subnet_test_id(0);

            let Dependencies {
                crypto,
                mut pool,
                idkg_pool,
                state_manager,
                registry,
                registry_data_provider,
                ..
            } = dependencies_with_subnet_records_with_raw_state_manager(
                pool_config,
                subnet_id,
                vec![(1, subnet_record_builder.build())],
            );

            // Enable the configured keys
            if let Some(config) = config
                && keys_enabled
            {
                for key_id in config.key_ids() {
                    registry_data_provider
                        .add(
                            &ic_registry_keys::make_chain_key_enabled_subnet_list_key(&key_id),
                            registry.get_latest_version().increment(),
                            Some(
                                ic_protobuf::registry::crypto::v1::ChainKeyEnabledSubnetList {
                                    subnets: vec![subnet_id_into_protobuf(subnet_test_id(0))],
                                },
                            ),
                        )
                        .expect("Could not add chain-key enabled subnet list");
                }
                registry.update_to_latest_version();
            }

            // Setup the state manager expectation
            let mut state = ic_test_utilities_state::get_initial_state(0, 0);
            state
                .metadata
                .subnet_call_context_manager
                .sign_with_threshold_contexts = contexts;

            // We will not return states above the certified height
            state_manager
                .get_mut()
                .expect_get_state_at()
                .returning(move |height| {
                    if height <= certified_height {
                        Ok(ic_interfaces_state_manager::Labeled::new(
                            certified_height,
                            Arc::new(state.clone()),
                        ))
                    } else {
                        Err(StateManagerError::StateRemoved(height))
                    }
                });

            if finalize_last_summary {
                pool.advance_round_normal_operation_n(certified_height.get());
            } else {
                pool.advance_round_normal_operation_n(certified_height.get() - DKG_INTERVAL_LENGTH);
                pool.advance_round_normal_operation_no_finalization_n(DKG_INTERVAL_LENGTH);
            }

            // Add the message shares
            let mutations = shares
                .into_iter()
                .map(IDkgChangeAction::AddToValidated)
                .collect();
            idkg_pool.write().unwrap().apply(mutations);

            let payload_builder = VetKdPayloadBuilderImpl::new(
                idkg_pool.clone(),
                pool.get_cache(),
                crypto,
                state_manager,
                Arc::new(ThreadPoolBuilder::new().num_threads(16).build().unwrap()),
                subnet_id,
                registry,
                &MetricsRegistry::new(),
                no_op_logger(),
            );

            // Run the test
            run(payload_builder)
        })
    }

    fn build_and_validate(
        builder: &VetKdPayloadBuilderImpl,
        max_size: NumBytes,
        past_payloads: &[PastPayload],
        context: &ValidationContext,
    ) -> Vec<u8> {
        let height = context.certified_height.increment();
        let payload = builder.build_payload(height, max_size, past_payloads, context);
        let context = ProposalContext {
            proposer: node_test_id(0),
            validation_context: context,
        };
        let validation = builder.validate_payload(height, &context, &payload, past_payloads);
        assert!(validation.is_ok());
        payload
    }

    #[test]
    fn test_build_payload() {
        build_payload_test(true)
    }

    #[test]
    fn test_build_payload_no_finalized_summary() {
        build_payload_test(false)
    }

    fn build_payload_test(finalize_last_summary: bool) {
        let config = make_chain_key_config();
        let contexts = make_contexts(&config);
        let shares = make_shares(&contexts);
        let proposal_context = ProposalContext {
            proposer: node_test_id(0),
            validation_context: &VALIDATION_CONTEXT,
        };
        test_payload_builder_ext(
            Some(config),
            true,
            contexts,
            shares,
            CERTIFIED_HEIGHT,
            finalize_last_summary,
            |builder| {
                let payload = build_and_validate(&builder, MAX_SIZE, &[], &VALIDATION_CONTEXT);

                let mut payload_deserialized = bytes_to_vetkd_payload(&payload).unwrap();
                assert_eq!(payload_deserialized.vetkd_agreements.len(), 2);
                assert_matches!(
                    payload_deserialized
                        .vetkd_agreements
                        .get(&CallbackId::from(1)),
                    Some(VetKdAgreement::Success(_))
                );
                assert_matches!(
                    payload_deserialized
                        .vetkd_agreements
                        .get(&CallbackId::from(2)),
                    Some(VetKdAgreement::Success(_))
                );

                // payload containing aggreements that can't be decoded should be invalid
                payload_deserialized
                    .vetkd_agreements
                    .insert(CallbackId::from(1), VetKdAgreement::Success(vec![]));
                let payload = as_bytes(payload_deserialized.vetkd_agreements);
                let validation = builder.validate_payload(HEIGHT, &proposal_context, &payload, &[]);
                assert_matches!(
                    validation.unwrap_err(),
                    ValidationError::InvalidArtifact(InvalidPayloadReason::InvalidVetKdPayload(
                        InvalidVetKdPayloadReason::DecodingError(_)
                    ))
                );

                // payload that can't be deserialized should be invalid
                let validation =
                    builder.validate_payload(HEIGHT, &proposal_context, &[1, 2, 3], &[]);
                assert_matches!(
                    validation.unwrap_err(),
                    ValidationError::InvalidArtifact(InvalidPayloadReason::InvalidVetKdPayload(
                        InvalidVetKdPayloadReason::DeserializationFailed(_)
                    ))
                );

                // payload that rejects valid contexts should be invalid
                let payload = as_bytes(make_vetkd_agreements_with_payload(
                    &[1, 2],
                    VetKdAgreement::Reject(VetKdErrorCode::TimedOut),
                ));
                let validation = builder.validate_payload(HEIGHT, &proposal_context, &payload, &[]);
                assert_matches!(
                    validation.unwrap_err(),
                    ValidationError::InvalidArtifact(InvalidPayloadReason::InvalidVetKdPayload(
                        InvalidVetKdPayloadReason::MismatchedAgreement { expected, received }
                    )) if expected.is_none()
                       && received == Some(VetKdAgreement::Reject(VetKdErrorCode::TimedOut))
                );

                // Empty payloads should always be valid
                let validation = builder.validate_payload(HEIGHT, &proposal_context, &[], &[]);
                assert!(validation.is_ok());
            },
        )
    }

    #[test]
    fn test_build_empty_payloads_when_feature_disabled() {
        // No chain key config is passed
        test_payload_builder(None, BTreeMap::new(), vec![], |builder| {
            let payload = build_and_validate(&builder, MAX_SIZE, &[], &VALIDATION_CONTEXT);
            assert!(payload.is_empty());

            let proposal_context = ProposalContext {
                proposer: node_test_id(0),
                validation_context: &VALIDATION_CONTEXT,
            };

            // Non-empty payloads should be rejected
            let payload = as_bytes(make_vetkd_agreements(0, 1, 2));
            let validation = builder.validate_payload(HEIGHT, &proposal_context, &payload, &[]);
            assert_matches!(
                validation.unwrap_err(),
                ValidationError::InvalidArtifact(InvalidPayloadReason::InvalidVetKdPayload(
                    InvalidVetKdPayloadReason::Disabled
                ))
            );
        })
    }

    #[test]
    fn test_build_empty_payload_if_state_doesnt_exist() {
        let config = make_chain_key_config();
        let contexts = make_contexts(&config);
        let shares = make_shares(&contexts);
        let context = ValidationContext {
            // There is no state for this certified height yet
            certified_height: CERTIFIED_HEIGHT.increment(),
            ..VALIDATION_CONTEXT
        };
        test_payload_builder(Some(config), contexts, shares, |builder| {
            let payload = build_and_validate(&builder, MAX_SIZE, &[], &context);
            assert!(payload.is_empty());

            let proposal_context = ProposalContext {
                proposer: node_test_id(0),
                validation_context: &context,
            };

            // Non-empty payload validation should be fail if we don't have the state
            let payload = as_bytes(make_vetkd_agreements(0, 1, 2));
            let validation = builder.validate_payload(HEIGHT, &proposal_context, &payload, &[]);
            assert_matches!(
                validation.unwrap_err(),
                ValidationError::ValidationFailed(
                    PayloadValidationFailure::VetKdPayloadValidationFailed(
                        VetKdPayloadValidationFailure::StateUnavailable(_)
                    )
                )
            );
        })
    }

    #[test]
    fn test_build_empty_payload_if_pool_is_empty() {
        let config = make_chain_key_config();
        let contexts = make_contexts(&config);
        test_payload_builder(Some(config), contexts, vec![], |builder| {
            let payload = build_and_validate(&builder, MAX_SIZE, &[], &VALIDATION_CONTEXT);
            assert!(payload.is_empty());
        })
    }

    #[test]
    fn test_build_empty_payload_max_size_zero() {
        let config = make_chain_key_config();
        let contexts = make_contexts(&config);
        let shares = make_shares(&contexts);
        test_payload_builder(Some(config), contexts, shares, |builder| {
            let payload = build_and_validate(&builder, NumBytes::from(0), &[], &VALIDATION_CONTEXT);
            assert!(payload.is_empty());
        })
    }

    #[test]
    fn test_build_payload_respects_max_size() {
        let config = make_chain_key_config();
        let contexts = make_contexts(&config);
        let shares = make_shares(&contexts);
        test_payload_builder(Some(config), contexts, shares, |builder| {
            // Use a smaller maximum size
            let max = NumBytes::from(30);
            // First try with the original size limit
            let payload = build_and_validate(&builder, MAX_SIZE, &[], &VALIDATION_CONTEXT);
            // Payload size should exceed the smaller limit
            assert!(payload.len() as u64 > max.get());
            let payload_deserialized = bytes_to_vetkd_payload(&payload).unwrap();
            assert_eq!(payload_deserialized.vetkd_agreements.len(), 2);

            // Now enforce the smaller limit
            let payload = build_and_validate(&builder, max, &[], &VALIDATION_CONTEXT);
            assert!(payload.len() as u64 <= max.get());
            let payload_deserialized = bytes_to_vetkd_payload(&payload).unwrap();
            // Only one of the agreements should have been included
            assert_eq!(payload_deserialized.vetkd_agreements.len(), 1);
            let (id, agreement) = payload_deserialized.vetkd_agreements.iter().next().unwrap();
            assert_matches!(agreement, VetKdAgreement::Success(_));
            assert!(id.get() == 1 || id.get() == 2);
        })
    }

    #[test]
    fn test_build_empty_payload_if_all_contexts_answered() {
        let config = make_chain_key_config();
        let contexts = make_contexts(&config);
        let payloads = [
            as_bytes(make_vetkd_agreements(0, 1, 2)),
            as_bytes(make_vetkd_agreements(2, 3, 4)),
        ];
        let past_payloads = payloads
            .iter()
            .map(|bytes| as_past_payload(bytes))
            .collect::<Vec<_>>();
        let shares = make_shares(&contexts);
        test_payload_builder(Some(config), contexts, shares, |builder| {
            let payload =
                build_and_validate(&builder, MAX_SIZE, &past_payloads, &VALIDATION_CONTEXT);
            assert!(payload.is_empty());

            // Payload with agreements that are already part of past payloads should be rejected
            let payload = as_bytes(make_vetkd_agreements(0, 1, 2));
            let validation = builder.validate_payload(
                HEIGHT,
                &ProposalContext {
                    proposer: node_test_id(0),
                    validation_context: &VALIDATION_CONTEXT,
                },
                &payload,
                &past_payloads,
            );
            assert_matches!(
                validation.unwrap_err(),
                ValidationError::InvalidArtifact(InvalidPayloadReason::InvalidVetKdPayload(
                    InvalidVetKdPayloadReason::DuplicateResponse(_)
                ))
            );
        })
    }

    #[test]
    fn test_reject_payloads_for_unknown_contexts() {
        let config = make_chain_key_config();
        let contexts = make_contexts(&config);
        let shares = make_shares(&contexts);
        let proposal_context = ProposalContext {
            proposer: node_test_id(0),
            validation_context: &VALIDATION_CONTEXT,
        };
        test_payload_builder(Some(config), contexts, shares, |builder| {
            // Payload with agreements for IDKG contexts should be rejected
            let payload = as_bytes(make_vetkd_agreements(0, 1, 2));
            let validation = builder.validate_payload(HEIGHT, &proposal_context, &payload, &[]);
            assert_matches!(
                validation.unwrap_err(),
                ValidationError::InvalidArtifact(InvalidPayloadReason::InvalidVetKdPayload(
                    InvalidVetKdPayloadReason::UnexpectedIDkgContext(id)
                )) if id.get() == 0
            );

            // Payload with agreements for unknown contexts should be rejected
            let payload = as_bytes(make_vetkd_agreements(3, 4, 5));
            let validation = builder.validate_payload(HEIGHT, &proposal_context, &payload, &[]);
            assert_matches!(
                validation.unwrap_err(),
                ValidationError::InvalidArtifact(InvalidPayloadReason::InvalidVetKdPayload(
                    InvalidVetKdPayloadReason::MissingContext(id)
                )) if id.get() >= 3 && id.get() <= 5
            );
        })
    }

    #[test]
    fn test_reject_invalid_keys() {
        let config = ChainKeyConfig {
            key_configs: vec![KeyConfig {
                key_id: MasterPublicKeyId::VetKd(
                    VetKdKeyId::from_str("bls12_381_g2:unused_key").unwrap(),
                ),
                pre_signatures_to_create_in_advance: 0,
                max_queue_size: 3,
            }],
            ..ChainKeyConfig::default()
        };
        reject_invalid_contexts_test(
            config,
            VALIDATION_CONTEXT,
            TestConfig {
                enabled_keys: true,
                finalize_last_summary: true,
                expected_error: VetKdErrorCode::InvalidKey,
                rejected_error: VetKdErrorCode::TimedOut,
            },
        );
    }

    #[test]
    fn test_reject_disabled_keys() {
        let config = make_chain_key_config();
        reject_invalid_contexts_test(
            config,
            VALIDATION_CONTEXT,
            TestConfig {
                enabled_keys: false,
                finalize_last_summary: true,
                expected_error: VetKdErrorCode::InvalidKey,
                rejected_error: VetKdErrorCode::TimedOut,
            },
        );
    }

    #[test]
    fn test_reject_timed_out_contexts() {
        let config = make_chain_key_config();
        let context = ValidationContext {
            // Fast-forward time until contexts are expired.
            time: UNIX_EPOCH + Duration::from_secs(2),
            ..VALIDATION_CONTEXT
        };
        reject_invalid_contexts_test(
            config,
            context,
            TestConfig {
                enabled_keys: true,
                finalize_last_summary: true,
                expected_error: VetKdErrorCode::TimedOut,
                rejected_error: VetKdErrorCode::InvalidKey,
            },
        );
    }

    #[test]
    fn test_reject_contexts_for_expired_transcripts() {
        let config = make_chain_key_config();
        let context = ValidationContext {
            // Fast-forward chain until requested transcripts are no longer part
            // of the summary block.
            certified_height: CERTIFIED_HEIGHT + Height::new(60),
            ..VALIDATION_CONTEXT
        };
        reject_invalid_contexts_test(
            config,
            context,
            TestConfig {
                enabled_keys: true,
                finalize_last_summary: true,
                expected_error: VetKdErrorCode::TimedOut,
                rejected_error: VetKdErrorCode::InvalidKey,
            },
        );
    }

    #[test]
    fn test_reject_contexts_for_expired_transcripts_no_finalized_summary() {
        let config = make_chain_key_config();
        let context = ValidationContext {
            // Fast-forward chain until requested transcripts are no longer part
            // of the summary block.
            certified_height: CERTIFIED_HEIGHT + Height::new(60),
            ..VALIDATION_CONTEXT
        };
        reject_invalid_contexts_test(
            config,
            context,
            TestConfig {
                enabled_keys: true,
                finalize_last_summary: false,
                expected_error: VetKdErrorCode::TimedOut,
                rejected_error: VetKdErrorCode::InvalidKey,
            },
        );
    }

    struct TestConfig {
        enabled_keys: bool,
        finalize_last_summary: bool,
        expected_error: VetKdErrorCode,
        rejected_error: VetKdErrorCode,
    }

    fn reject_invalid_contexts_test(
        config: ChainKeyConfig,
        validation_context: ValidationContext,
        test_config: TestConfig,
    ) {
        let TestConfig {
            enabled_keys,
            finalize_last_summary,
            expected_error,
            rejected_error,
        } = test_config;
        let contexts = make_contexts(&make_chain_key_config());
        let shares = make_shares(&contexts);
        let proposal_context = ProposalContext {
            proposer: node_test_id(0),
            validation_context: &validation_context,
        };
        test_payload_builder_ext(
            Some(config),
            enabled_keys,
            contexts.clone(),
            shares,
            validation_context.certified_height,
            finalize_last_summary,
            |builder| {
                let serialized_payload =
                    build_and_validate(&builder, MAX_SIZE, &[], &validation_context);
                let payload = bytes_to_vetkd_payload(&serialized_payload).unwrap();
                assert_eq!(payload.vetkd_agreements.len(), 2);
                for (id, context) in contexts {
                    match context.key_id() {
                        MasterPublicKeyId::Ecdsa(_) | MasterPublicKeyId::Schnorr(_) => {
                            assert!(!payload.vetkd_agreements.contains_key(&id));
                        }
                        MasterPublicKeyId::VetKd(_) => {
                            assert_eq!(
                                payload.vetkd_agreements.get(&id).unwrap(),
                                &VetKdAgreement::Reject(expected_error)
                            );
                        }
                    }
                }

                // payload with different rejects for the same contexts should be rejected
                let payload = as_bytes(make_vetkd_agreements_with_payload(
                    &[1, 2],
                    VetKdAgreement::Reject(rejected_error),
                ));
                let height = validation_context.certified_height.increment();
                let validation = builder.validate_payload(height, &proposal_context, &payload, &[]);
                assert_matches!(
                    validation.unwrap_err(),
                    ValidationError::InvalidArtifact(InvalidPayloadReason::InvalidVetKdPayload(
                        InvalidVetKdPayloadReason::MismatchedAgreement { expected, received }
                    )) if expected == Some(VetKdAgreement::Reject(expected_error))
                       && received == Some(VetKdAgreement::Reject(rejected_error))
                );

                // payload with success responses for the same contexts should be rejected
                let payload = as_bytes(make_vetkd_agreements_with_payload(
                    &[1, 2],
                    VetKdAgreement::Success(vec![1, 1, 1]),
                ));
                let validation = builder.validate_payload(height, &proposal_context, &payload, &[]);
                assert_matches!(
                    validation.unwrap_err(),
                    ValidationError::InvalidArtifact(InvalidPayloadReason::InvalidVetKdPayload(
                        InvalidVetKdPayloadReason::MismatchedAgreement { expected, received }
                    )) if expected == Some(VetKdAgreement::Reject(expected_error))
                       && received.is_none()
                );

                // Empty payloads should always be valid
                let validation = builder.validate_payload(height, &proposal_context, &[], &[]);
                assert!(validation.is_ok());
            },
        )
    }

    #[test]
    fn test_get_enabled_keys_and_expiry_if_disabled() {
        test_payload_builder(None, BTreeMap::new(), vec![], |builder| {
            let res = builder
                .get_enabled_keys_and_expiry(HEIGHT, UNIX_EPOCH)
                .unwrap_err();
            assert_matches!(
                res,
                ValidationError::InvalidArtifact(InvalidPayloadReason::InvalidVetKdPayload(
                    InvalidVetKdPayloadReason::Disabled
                ))
            )
        })
    }

    #[test]
    fn test_get_enabled_keys_and_expiry_if_enabled_no_keys() {
        test_payload_builder(
            Some(ChainKeyConfig::default()),
            BTreeMap::new(),
            vec![],
            |builder| {
                let (keys, expiry) = builder
                    .get_enabled_keys_and_expiry(HEIGHT, UNIX_EPOCH)
                    .unwrap();
                assert!(keys.is_empty());
                assert!(expiry.time.is_none());
                assert_eq!(
                    expiry.height,
                    Height::new(HEIGHT.get() - DKG_INTERVAL_LENGTH)
                );
            },
        )
    }

    #[test]
    fn test_get_enabled_keys_and_expiry_if_enabled_multiple_keys() {
        let config = make_chain_key_config();
        let timeout = Duration::from_nanos(config.signature_request_timeout_ns.unwrap());
        let now = current_time();
        test_payload_builder(Some(config), BTreeMap::new(), vec![], |builder| {
            let (keys, expiry) = builder.get_enabled_keys_and_expiry(HEIGHT, now).unwrap();
            assert_eq!(keys.len(), 2);
            assert!(keys.contains(&MasterPublicKeyId::VetKd(
                VetKdKeyId::from_str("bls12_381_g2:some_key").unwrap()
            )));
            assert!(keys.contains(&MasterPublicKeyId::VetKd(
                VetKdKeyId::from_str("bls12_381_g2:some_other_key").unwrap()
            )));
            assert_matches!(expiry.time, Some(time) if time == now.saturating_sub(timeout));
            assert_eq!(
                expiry.height,
                Height::new(HEIGHT.get() - DKG_INTERVAL_LENGTH)
            );
        })
    }

    #[test]
    fn test_get_enabled_keys_and_expiry_if_disabled_multiple_keys() {
        let height = CERTIFIED_HEIGHT;
        let config = make_chain_key_config();
        let timeout = Duration::from_nanos(config.signature_request_timeout_ns.unwrap());
        let now = current_time();
        test_payload_builder_ext(
            Some(config),
            false,
            BTreeMap::new(),
            vec![],
            height,
            true,
            |builder| {
                let (keys, expiry) = builder.get_enabled_keys_and_expiry(HEIGHT, now).unwrap();
                assert!(keys.is_empty());
                assert_matches!(expiry.time, Some(time) if time == now.saturating_sub(timeout));
                assert_eq!(
                    expiry.height,
                    Height::new(HEIGHT.get() - DKG_INTERVAL_LENGTH)
                );
            },
        )
    }
}
