//! This module provides the component responsible for generating and validating
//! payloads relevant to VetKd.

use crate::utils::{
    group_shares_by_callback_id, invalid_artifact, invalid_artifact_err, parse_past_payload_ids,
    validation_failed, validation_failed_err,
};
use ic_consensus_utils::{crypto::ConsensusCrypto, registry_version_at_height};
use ic_error_types::RejectCode;
use ic_interfaces::{
    batch_payload::{BatchPayloadBuilder, IntoMessages, PastPayload, ProposalContext},
    consensus::PayloadValidationError,
    consensus_pool::ConsensusPoolCache,
    idkg::IDkgPool,
    vetkd::{InvalidVetKdPayloadReason, VetKdPayloadValidationFailure},
};
use ic_interfaces_registry::RegistryClient;
use ic_interfaces_state_manager::StateReader;
use ic_logger::{warn, ReplicaLogger};
use ic_management_canister_types_private::{
    MasterPublicKeyId, Payload, VetKdDeriveEncryptedKeyResult,
};
use ic_metrics::MetricsRegistry;
use ic_registry_client_helpers::chain_keys::ChainKeysRegistry;
use ic_registry_client_helpers::subnet::SubnetRegistry;
use ic_replicated_state::{
    metadata_state::subnet_call_context_manager::{SignWithThresholdContext, ThresholdArguments},
    ReplicatedState,
};
use ic_types::{
    batch::{
        bytes_to_vetkd_payload, vetkd_payload_to_bytes, ConsensusResponse, ValidationContext,
        VetKdAgreement, VetKdErrorCode, VetKdPayload,
    },
    crypto::{
        vetkd::{VetKdArgs, VetKdEncryptedKey},
        ExtendedDerivationPath,
    },
    messages::{CallbackId, Payload as ResponsePayload, RejectContext},
    CountBytes, Height, NumBytes, SubnetId, Time,
};
use std::time::Duration;
use std::{
    collections::{BTreeMap, BTreeSet, HashSet},
    sync::{Arc, RwLock},
};

mod utils;

/// Implementation of the [`BatchPayloadBuilder`] for the VetKd feature.
/// TODO: Add metrics
pub struct VetKdPayloadBuilderImpl {
    pool: Arc<RwLock<dyn IDkgPool>>,
    cache: Arc<dyn ConsensusPoolCache>,
    _crypto: Arc<dyn ConsensusCrypto>,
    state_reader: Arc<dyn StateReader<State = ReplicatedState>>,
    subnet_id: SubnetId,
    registry: Arc<dyn RegistryClient>,
    log: ReplicaLogger,
}

impl VetKdPayloadBuilderImpl {
    /// Create and initialize an instance of [`VetKdPayloadBuilderImpl`].
    pub fn new(
        pool: Arc<RwLock<dyn IDkgPool>>,
        cache: Arc<dyn ConsensusPoolCache>,
        crypto: Arc<dyn ConsensusCrypto>,
        state_reader: Arc<dyn StateReader<State = ReplicatedState>>,
        subnet_id: SubnetId,
        registry: Arc<dyn RegistryClient>,
        _metrics_registry: &MetricsRegistry,
        log: ReplicaLogger,
    ) -> Self {
        Self {
            pool,
            cache,
            _crypto: crypto,
            state_reader,
            subnet_id,
            registry,
            log,
        }
    }

    /// Return the set of enabled VetKD key IDs and request expiry time according to
    /// the chain key config at the registry version corresponding to the given block height.
    fn get_enabled_keys_and_expiry(
        &self,
        height: Height,
        context_time: Time,
    ) -> Result<(BTreeSet<MasterPublicKeyId>, Option<Time>), PayloadValidationError> {
        let Some(registry_version) = registry_version_at_height(self.cache.as_ref(), height) else {
            warn!(
                self.log,
                "Failed to obtain consensus registry version in VetKd payload builder"
            );
            return Err(validation_failed(
                VetKdPayloadValidationFailure::RegistryVersionUnavailable(height),
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
            .get_chain_key_signing_subnets(registry_version)
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
            .filter(|key_id| !key_id.is_idkg_key())
            // Skip keys that are disabled
            .filter(|key_id| {
                enabled_subnets
                    .get(key_id)
                    .is_some_and(|subnets| subnets.contains(&self.subnet_id))
            })
            .collect();

        Ok((key_ids, request_expiry_time))
    }

    fn get_vetkd_payload_impl(
        &self,
        request_expiry_time: Option<Time>,
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

        // Iterate over all outstanding VetKD requests
        let mut candidates = BTreeMap::new();
        let mut accumulated_size = 0;
        for (callback_id, context) in state.signature_request_contexts() {
            if !context.is_vetkd() {
                // Skip non-vetkd contexts.
                continue;
            }

            if delivered_ids.contains(callback_id) {
                // Skip contexts for which we already delivered a response.
                continue;
            }

            let candidate = if let Some(reject) =
                reject_if_invalid(&valid_keys, context, request_expiry_time)
            {
                reject
            } else {
                let Some(_shares) = grouped_shares.get(callback_id) else {
                    continue;
                };
                let ThresholdArguments::VetKd(ctxt_args) = &context.args else {
                    continue;
                };
                let _args = VetKdArgs {
                    derivation_path: ExtendedDerivationPath {
                        caller: context.request.sender.into(),
                        derivation_path: context.derivation_path.clone(),
                    },
                    ni_dkg_id: ctxt_args.ni_dkg_id.clone(),
                    derivation_id: ctxt_args.derivation_id.clone(),
                    encryption_public_key: ctxt_args.encryption_public_key.clone(),
                };
                todo!("Call crypto endpoint to combine shares");
            };

            let candidate_size = callback_id.count_bytes() + candidate.count_bytes();
            let size = NumBytes::new((accumulated_size + candidate_size) as u64);
            if size >= max_payload_size {
                break;
            } else {
                accumulated_size += candidate_size;
                candidates.insert(*callback_id, candidate);
            }
        }

        VetKdPayload {
            vetkd_agreements: candidates,
        }
    }

    fn validate_vetkd_payload_impl(
        &self,
        payload: VetKdPayload,
        request_expiry_time: Option<Time>,
        valid_keys: BTreeSet<MasterPublicKeyId>,
        state: &ReplicatedState,
        delivered_ids: HashSet<CallbackId>,
    ) -> Result<(), PayloadValidationError> {
        let contexts = state.signature_request_contexts();

        for (id, agreement) in payload.vetkd_agreements {
            if delivered_ids.contains(&id) {
                return invalid_artifact_err(InvalidVetKdPayloadReason::DuplicateResponse(id));
            }

            let Some(context) = contexts.get(&id) else {
                return invalid_artifact_err(InvalidVetKdPayloadReason::MissingContext(id));
            };

            if !context.is_vetkd() {
                return invalid_artifact_err(InvalidVetKdPayloadReason::UnexpectedIDkgContext(id));
            }

            let expected_reject = reject_if_invalid(&valid_keys, context, request_expiry_time);

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
        }

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
        let _args = VetKdArgs {
            derivation_path: ExtendedDerivationPath {
                caller: context.request.sender.into(),
                derivation_path: context.derivation_path.clone(),
            },
            ni_dkg_id: ctxt_args.ni_dkg_id.clone(),
            derivation_id: ctxt_args.derivation_id.clone(),
            encryption_public_key: ctxt_args.encryption_public_key.clone(),
        };
        let reply = match VetKdDeriveEncryptedKeyResult::decode(&data) {
            Ok(data) => data,
            Err(error) => {
                return invalid_artifact_err(InvalidVetKdPayloadReason::DecodingError(format!(
                    "{error:?}",
                )))
            }
        };
        let _signature = VetKdEncryptedKey {
            encrypted_key: reply.encrypted_key,
        };
        todo!("Call crypto endpoint to verify combined key");
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
        let Ok((valid_keys, request_expiry_time)) =
            self.get_enabled_keys_and_expiry(height, context.time)
        else {
            return vec![];
        };

        let Ok(state) = self.state_reader.get_state_at(context.certified_height) else {
            return vec![];
        };

        let delivered_ids = parse_past_payload_ids(past_payloads, &self.log);
        let payload = self.get_vetkd_payload_impl(
            request_expiry_time,
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
        // Empty payloads are always valid
        if payload.is_empty() {
            return Ok(());
        }

        let (valid_keys, request_expiry_time) =
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
            request_expiry_time,
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
                                    RejectCode::CanisterError,
                                    "VetKD request expired",
                                ),
                                VetKdErrorCode::InvalidKey => RejectContext::new(
                                    RejectCode::CanisterError,
                                    "Invalid key_id in VetKD request",
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
/// 1. it requests a key ID that isn't part of `valid_keys`, or
/// 2. the request is expired according to the given `request_expiry_time`
fn reject_if_invalid(
    valid_keys: &BTreeSet<MasterPublicKeyId>,
    context: &SignWithThresholdContext,
    request_expiry_time: Option<Time>,
) -> Option<VetKdAgreement> {
    if !valid_keys.contains(&context.key_id()) {
        Some(VetKdAgreement::Reject(VetKdErrorCode::InvalidKey))
    } else if request_expiry_time.is_some_and(|expiry| context.batch_time < expiry) {
        Some(VetKdAgreement::Reject(VetKdErrorCode::TimedOut))
    } else {
        None
    }
}
