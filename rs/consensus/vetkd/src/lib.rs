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

#[cfg(test)]
mod test_utils;
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

#[cfg(test)]
mod tests {
    use assert_matches::assert_matches;
    use core::time::Duration;
    use core::{convert::From, iter::Iterator};
    use ic_artifact_pool::idkg_pool::IDkgPoolImpl;
    use ic_consensus_mocks::dependencies_with_subnet_records_with_raw_state_manager;
    use ic_consensus_mocks::Dependencies;
    use ic_interfaces::consensus::InvalidPayloadReason;
    use ic_interfaces::consensus::PayloadValidationFailure;
    use ic_interfaces::idkg::IDkgChangeAction;
    use ic_interfaces::p2p::consensus::MutablePool;
    use ic_interfaces::validation::ValidationError;
    use ic_interfaces_state_manager::StateManagerError;
    use ic_logger::no_op_logger;
    use ic_management_canister_types::VetKdKeyId;
    use ic_registry_subnet_features::KeyConfig;
    use ic_test_utilities_registry::SubnetRecordBuilder;
    use ic_types::consensus::idkg::IDkgMessage;
    use ic_types::time::UNIX_EPOCH;
    use ic_types::RegistryVersion;
    use ic_types_test_utils::ids::{node_test_id, subnet_test_id};
    use std::str::FromStr;

    use super::*;
    use crate::test_utils::*;

    const CERTIFIED_HEIGHT: u64 = 10;

    #[test]
    fn test_into_messages() {
        let agreements = make_vetkd_agreements([0, 1, 2]);
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
                        RejectCode::CanisterError,
                        "Invalid key_id in VetKD request",
                    );
                }
                VetKdAgreement::Reject(VetKdErrorCode::TimedOut) => {
                    let ResponsePayload::Reject(context) = &response.payload else {
                        panic!("Unexpected response: {response:?}");
                    };
                    context.assert_contains(RejectCode::CanisterError, "VetKD request expired");
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

    fn test_payload_builder<T>(
        config: Option<ChainKeyConfig>,
        contexts: BTreeMap<CallbackId, SignWithThresholdContext>,
        shares: Vec<IDkgMessage>,
        run: impl FnOnce(VetKdPayloadBuilderImpl) -> T,
    ) -> T {
        let committee = (0..4).map(|id| node_test_id(id as u64)).collect::<Vec<_>>();
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            let subnet_record_builder = SubnetRecordBuilder::from(&committee);
            let subnet_record_builder = if let Some(config) = config {
                subnet_record_builder.with_chain_key_config(config)
            } else {
                subnet_record_builder
            };

            let Dependencies {
                crypto,
                registry,
                pool,
                idkg_pool,
                state_manager,
                ..
            } = dependencies_with_subnet_records_with_raw_state_manager(
                pool_config,
                subnet_test_id(0),
                vec![(1, subnet_record_builder.build())],
            );

            let mut state = ic_test_utilities_state::get_initial_state(0, 0);
            state
                .metadata
                .subnet_call_context_manager
                .sign_with_threshold_contexts = contexts;

            let certified_height = Height::new(CERTIFIED_HEIGHT);
            state_manager
                .get_mut()
                .expect_get_state_at()
                .returning(move |height| {
                    if height == certified_height {
                        Ok(ic_interfaces_state_manager::Labeled::new(
                            certified_height,
                            Arc::new(state.clone()),
                        ))
                    } else {
                        Err(StateManagerError::StateRemoved(height))
                    }
                });

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
                subnet_test_id(0),
                registry,
                &MetricsRegistry::new(),
                no_op_logger(),
            );

            run(payload_builder)
        })
    }

    #[test]
    #[should_panic(expected = "not yet implemented")]
    fn test_build_payload() {
        let config = make_chain_key_config();
        let contexts = make_contexts(&config);
        let shares = make_shares(&contexts);
        let certified_height = Height::new(CERTIFIED_HEIGHT);
        let height = certified_height.increment();
        let context = ValidationContext {
            registry_version: RegistryVersion::new(10),
            certified_height,
            time: UNIX_EPOCH,
        };
        let proposal_context = ProposalContext {
            proposer: node_test_id(0),
            validation_context: &context,
        };
        test_payload_builder(Some(config), contexts, shares, |builder| {
            let payload = builder.build_payload(height, NumBytes::from(1024), &[], &context);

            // TODO validate payload manually

            let validation = builder.validate_payload(height, &proposal_context, &payload, &[]);
            assert!(validation.is_ok());

            // payload that can't be deserialized should be invalid
            let validation = builder.validate_payload(height, &proposal_context, &[1, 2, 3], &[]);
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
            let validation = builder.validate_payload(height, &proposal_context, &payload, &[]);
            assert_matches!(
                validation.unwrap_err(),
                ValidationError::InvalidArtifact(InvalidPayloadReason::InvalidVetKdPayload(
                    InvalidVetKdPayloadReason::MismatchedAgreement { expected, received }
                )) if expected == None
                   && received == Some(VetKdAgreement::Reject(VetKdErrorCode::TimedOut))
            );
        })
    }

    #[test]
    fn test_build_empty_payloads_when_feature_disabled() {
        let certified_height = Height::new(CERTIFIED_HEIGHT);
        let height = certified_height.increment();
        let context = ValidationContext {
            registry_version: RegistryVersion::new(10),
            certified_height,
            time: UNIX_EPOCH,
        };
        test_payload_builder(None, BTreeMap::new(), vec![], |builder| {
            let payload = builder.build_payload(height, NumBytes::from(1024), &[], &context);
            assert!(payload.is_empty());

            // Non-empty payloads should be rejected
            let payload = as_bytes(make_vetkd_agreements([0, 1, 2]));
            let validation = builder.validate_payload(
                height,
                &ProposalContext {
                    proposer: node_test_id(0),
                    validation_context: &context,
                },
                &payload,
                &[],
            );
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
        let certified_height = Height::new(CERTIFIED_HEIGHT);
        let height = certified_height.increment();
        let context = ValidationContext {
            registry_version: RegistryVersion::new(10),
            // There is no state for this certified height yet
            certified_height: certified_height.increment(),
            time: UNIX_EPOCH,
        };
        test_payload_builder(Some(config), contexts, shares, |builder| {
            let payload = builder.build_payload(height, NumBytes::from(1024), &[], &context);
            assert!(payload.is_empty());

            // Non-empty payload validation should be fail if we don't have the state
            let payload = as_bytes(make_vetkd_agreements([0, 1, 2]));
            let validation = builder.validate_payload(
                height,
                &ProposalContext {
                    proposer: node_test_id(0),
                    validation_context: &context,
                },
                &payload,
                &[],
            );
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
        let certified_height = Height::new(CERTIFIED_HEIGHT);
        test_payload_builder(Some(config), contexts, vec![], |builder| {
            let height = certified_height.increment();
            let context = ValidationContext {
                registry_version: RegistryVersion::new(10),
                certified_height: certified_height,
                time: UNIX_EPOCH,
            };
            let payload = builder.build_payload(height, NumBytes::from(1024), &[], &context);
            assert!(payload.is_empty());

            // Empty payloads should always be valid
            let validation = builder.validate_payload(
                height,
                &ProposalContext {
                    proposer: node_test_id(0),
                    validation_context: &context,
                },
                &payload,
                &[],
            );
            assert!(validation.is_ok());
        })
    }

    #[test]
    #[should_panic(expected = "not yet implemented")]
    fn test_build_empty_payload_max_size_zero() {
        let config = make_chain_key_config();
        let contexts = make_contexts(&config);
        let shares = make_shares(&contexts);
        let certified_height = Height::new(CERTIFIED_HEIGHT);
        test_payload_builder(Some(config), contexts, shares, |builder| {
            let payload = builder.build_payload(
                certified_height.increment(),
                NumBytes::from(0),
                &[],
                &ValidationContext {
                    registry_version: RegistryVersion::new(10),
                    certified_height: certified_height,
                    time: UNIX_EPOCH,
                },
            );
            assert!(payload.is_empty());
        })
    }

    #[test]
    #[should_panic(expected = "not yet implemented")]
    fn test_build_payload_respects_max_size() {
        let config = make_chain_key_config();
        let contexts = make_contexts(&config);
        let shares = make_shares(&contexts);
        let certified_height = Height::new(CERTIFIED_HEIGHT);
        let height = certified_height.increment();
        let context = ValidationContext {
            registry_version: RegistryVersion::new(10),
            certified_height,
            time: UNIX_EPOCH,
        };
        test_payload_builder(Some(config), contexts, shares, |builder| {
            let payload = builder.build_payload(height, NumBytes::from(50), &[], &context);
            let payload_deserialized = bytes_to_vetkd_payload(&payload).unwrap();
            assert_eq!(payload_deserialized.vetkd_agreements.len(), 1);
            // TODO validate agreement is success

            let validation = builder.validate_payload(
                height,
                &ProposalContext {
                    proposer: node_test_id(0),
                    validation_context: &context,
                },
                &payload,
                &[],
            );
            assert!(validation.is_ok());
        })
    }

    #[test]
    fn test_build_empty_payload_if_all_contexts_answered() {
        let config = make_chain_key_config();
        let contexts = make_contexts(&config);
        let payloads = vec![
            as_bytes(make_vetkd_agreements([0, 1, 2])),
            as_bytes(make_vetkd_agreements([2, 3, 4])),
        ];
        let past_payloads = payloads
            .iter()
            .map(|p| as_past_payload(&p))
            .collect::<Vec<_>>();
        let shares = make_shares(&contexts);
        let certified_height = Height::new(CERTIFIED_HEIGHT);
        let height = certified_height.increment();
        let context = ValidationContext {
            registry_version: RegistryVersion::new(10),
            certified_height,
            time: UNIX_EPOCH,
        };
        test_payload_builder(Some(config), contexts, shares, |builder| {
            let payload =
                builder.build_payload(height, NumBytes::from(1024), &past_payloads, &context);
            assert!(payload.is_empty());

            // Payload with agreements that are already part of past payloads should be rejected
            let payload = as_bytes(make_vetkd_agreements([0, 1, 2]));
            let validation = builder.validate_payload(
                height,
                &ProposalContext {
                    proposer: node_test_id(0),
                    validation_context: &context,
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
        let certified_height = Height::new(CERTIFIED_HEIGHT);
        let height = certified_height.increment();
        let context = ValidationContext {
            registry_version: RegistryVersion::new(10),
            certified_height,
            time: UNIX_EPOCH,
        };
        let proposal_context = ProposalContext {
            proposer: node_test_id(0),
            validation_context: &context,
        };
        test_payload_builder(Some(config), contexts, shares, |builder| {
            // Payload with agreements for IDKG contexts should be rejected
            let payload = as_bytes(make_vetkd_agreements([0, 1, 2]));
            let validation = builder.validate_payload(height, &proposal_context, &payload, &[]);
            assert_matches!(
                validation.unwrap_err(),
                ValidationError::InvalidArtifact(InvalidPayloadReason::InvalidVetKdPayload(
                    InvalidVetKdPayloadReason::IDkgContext(id)
                )) if id.get() == 0
            );

            // Payload with agreements for unknown contexts should be rejected
            let payload = as_bytes(make_vetkd_agreements([3, 4, 5]));
            let validation = builder.validate_payload(height, &proposal_context, &payload, &[]);
            assert_matches!(
                validation.unwrap_err(),
                ValidationError::InvalidArtifact(InvalidPayloadReason::InvalidVetKdPayload(
                    InvalidVetKdPayloadReason::MissingContext(id)
                )) if id.get() == 3
            );
        })
    }

    #[test]
    fn test_reject_payloads_with_mismatched_agreement() {
        let config = make_chain_key_config();
        let contexts = make_contexts(&config);
        let shares = make_shares(&contexts);
        let certified_height = Height::new(CERTIFIED_HEIGHT);
        let height = certified_height.increment();
        let context = ValidationContext {
            registry_version: RegistryVersion::new(10),
            certified_height,
            time: UNIX_EPOCH,
        };
        let proposal_context = ProposalContext {
            proposer: node_test_id(0),
            validation_context: &context,
        };
        test_payload_builder(Some(config), contexts, shares, |builder| {
            // Payload with agreements for IDKG contexts should be rejected
            let payload = as_bytes(make_vetkd_agreements([0, 1, 2]));
            let validation = builder.validate_payload(height, &proposal_context, &payload, &[]);
            assert_matches!(
                validation.unwrap_err(),
                ValidationError::InvalidArtifact(InvalidPayloadReason::InvalidVetKdPayload(
                    InvalidVetKdPayloadReason::IDkgContext(id)
                )) if id.get() == 0
            );

            // Payload with agreements for unknown contexts should be rejected
            let payload = as_bytes(make_vetkd_agreements([3, 4, 5]));
            let validation = builder.validate_payload(height, &proposal_context, &payload, &[]);
            assert_matches!(
                validation.unwrap_err(),
                ValidationError::InvalidArtifact(InvalidPayloadReason::InvalidVetKdPayload(
                    InvalidVetKdPayloadReason::MissingContext(id)
                )) if id.get() == 3
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
        // Create contexts for a different config
        let contexts = make_contexts(&make_chain_key_config());
        let shares = make_shares(&contexts);
        let certified_height = Height::new(CERTIFIED_HEIGHT);
        let height = certified_height.increment();
        let context = ValidationContext {
            registry_version: RegistryVersion::new(10),
            certified_height,
            time: UNIX_EPOCH,
        };
        let proposal_context = ProposalContext {
            proposer: node_test_id(0),
            validation_context: &context,
        };
        test_payload_builder(Some(config), contexts.clone(), shares, |builder| {
            let serialized_payload =
                builder.build_payload(height, NumBytes::from(1024), &[], &context);
            let payload = bytes_to_vetkd_payload(&serialized_payload).unwrap();
            assert_eq!(payload.vetkd_agreements.len(), 2);
            for (id, context) in contexts {
                match context.key_id() {
                    MasterPublicKeyId::Ecdsa(_) | MasterPublicKeyId::Schnorr(_) => {
                        assert!(!payload.vetkd_agreements.contains_key(&id));
                    }
                    MasterPublicKeyId::VetKd(_) => {
                        assert_matches!(
                            payload.vetkd_agreements.get(&id).unwrap(),
                            VetKdAgreement::Reject(VetKdErrorCode::InvalidKey)
                        );
                    }
                }
            }

            let validation =
                builder.validate_payload(height, &proposal_context, &serialized_payload, &[]);
            assert!(validation.is_ok());

            // payload with different rejects for the same contexts should be rejected
            let payload = as_bytes(make_vetkd_agreements_with_payload(
                &[1, 2],
                VetKdAgreement::Reject(VetKdErrorCode::TimedOut),
            ));
            let validation = builder.validate_payload(height, &proposal_context, &payload, &[]);
            assert_matches!(
                validation.unwrap_err(),
                ValidationError::InvalidArtifact(InvalidPayloadReason::InvalidVetKdPayload(
                    InvalidVetKdPayloadReason::MismatchedAgreement { expected, received }
                )) if expected == Some(VetKdAgreement::Reject(VetKdErrorCode::InvalidKey))
                   && received == Some(VetKdAgreement::Reject(VetKdErrorCode::TimedOut))
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
                )) if expected == Some(VetKdAgreement::Reject(VetKdErrorCode::InvalidKey))
                   && received == None
            );
        })
    }

    #[test]
    fn test_reject_timed_out_contexts() {
        let config = make_chain_key_config();
        let contexts = make_contexts(&config);
        let shares = make_shares(&contexts);
        let certified_height = Height::new(CERTIFIED_HEIGHT);
        let height = certified_height.increment();
        let context = ValidationContext {
            registry_version: RegistryVersion::new(10),
            certified_height,
            time: UNIX_EPOCH.checked_add(Duration::from_secs(2)).unwrap(),
        };
        let proposal_context = ProposalContext {
            proposer: node_test_id(0),
            validation_context: &context,
        };
        test_payload_builder(Some(config), contexts.clone(), shares, |builder| {
            let serialized_payload =
                builder.build_payload(height, NumBytes::from(1024), &[], &context);
            let payload = bytes_to_vetkd_payload(&serialized_payload).unwrap();
            assert_eq!(payload.vetkd_agreements.len(), 2);
            for (id, context) in contexts {
                match context.key_id() {
                    MasterPublicKeyId::Ecdsa(_) | MasterPublicKeyId::Schnorr(_) => {
                        assert!(!payload.vetkd_agreements.contains_key(&id));
                    }
                    MasterPublicKeyId::VetKd(_) => {
                        assert_matches!(
                            payload.vetkd_agreements.get(&id).unwrap(),
                            VetKdAgreement::Reject(VetKdErrorCode::TimedOut)
                        );
                    }
                }
            }

            let validation =
                builder.validate_payload(height, &proposal_context, &serialized_payload, &[]);
            assert!(validation.is_ok());

            // payload with different rejects for the same contexts should be rejected
            let payload = as_bytes(make_vetkd_agreements_with_payload(
                &[1, 2],
                VetKdAgreement::Reject(VetKdErrorCode::InvalidKey),
            ));
            let validation = builder.validate_payload(height, &proposal_context, &payload, &[]);
            assert_matches!(
                validation.unwrap_err(),
                ValidationError::InvalidArtifact(InvalidPayloadReason::InvalidVetKdPayload(
                    InvalidVetKdPayloadReason::MismatchedAgreement { expected, received }
                )) if expected == Some(VetKdAgreement::Reject(VetKdErrorCode::TimedOut))
                   && received == Some(VetKdAgreement::Reject(VetKdErrorCode::InvalidKey))
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
                )) if expected == Some(VetKdAgreement::Reject(VetKdErrorCode::TimedOut))
                   && received == None
            );
        })
    }
}
