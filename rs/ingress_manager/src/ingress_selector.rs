//! The Ingress Selector selects Signed Ingress Messages for the inclusion in
//! Consensus batches (PayloadBuilder). It is also used to validate the Ingress
//! messages of Consensus payloads and to keep track of finalized Ingress
//! Messages to ensure that no message is added to a block more than once.
use crate::IngressManager;
use ic_constants::MAX_INGRESS_TTL;
use ic_cycles_account_manager::IngressInductionCost;
use ic_interfaces::{
    execution_environment::IngressHistoryReader,
    ingress_manager::{
        IngressPayloadValidationError, IngressPermanentError, IngressSelector, IngressSetQuery,
        IngressTransientError,
    },
    ingress_pool::{IngressPoolSelect, SelectResult},
    validation::{ValidationError, ValidationResult},
};
use ic_interfaces_state_manager::StateManagerError;
use ic_logger::{error, warn};
use ic_registry_client_helpers::subnet::IngressMessageSettings;
use ic_replicated_state::ReplicatedState;
use ic_types::{
    artifact::IngressMessageId,
    batch::{IngressPayload, ValidationContext},
    consensus::Payload,
    ingress::{IngressSets, IngressStatus},
    messages::{MessageId, SignedIngress},
    CanisterId, CountBytes, Cycles, Height, NumBytes, Time,
};
use ic_validator::{validate_request, RequestValidationError};
use std::{collections::BTreeMap, sync::Arc};

impl<'a> IngressSelector for IngressManager {
    fn get_ingress_payload(
        &self,
        past_ingress: &dyn IngressSetQuery,
        context: &ValidationContext,
        byte_limit: NumBytes,
    ) -> IngressPayload {
        let _timer = self.metrics.ingress_selector_get_payload_time.start_timer();
        let certified_height = context.certified_height;
        let past_ingress_set = match IngressSetChain::new(context.time, past_ingress, || {
            IngressHistorySet::new(self.ingress_hist_reader.as_ref(), certified_height)
        }) {
            Ok(past_ingress_set) => past_ingress_set,
            Err(err) => {
                warn!(
                    every_n_seconds => 5,
                    self.log,
                    "IngressHistoryReader doesn't have state for height {}: {:?}",
                    certified_height,
                    err
                );
                return IngressPayload::default();
            }
        };

        let state = match self.state_manager.get_state_at(certified_height) {
            Ok(state) => state,
            Err(err) => {
                warn!(
                    every_n_seconds => 5,
                    self.log,
                    "StateManager doesn't have state for height {}: {:?}", certified_height, err
                );
                return IngressPayload::default();
            }
        }
        .take();

        let min_expiry = context.time;
        let max_expiry = context.time + MAX_INGRESS_TTL;
        let expiry_range = min_expiry..=max_expiry;

        let settings = self
            .get_ingress_message_settings(context.registry_version)
            .expect("Couldn't fetch ingress message parameters from the registry.");

        // Select valid ingress messages and stop once the total size
        // becomes greater than byte_limit.
        let mut accumulated_size = 0;
        let mut cycles_needed: BTreeMap<CanisterId, Cycles> = BTreeMap::new();
        let mut num_messages = 0;

        let messages_in_payload = self.ingress_pool.select_validated(
            expiry_range,
            Box::new(move |ingress_obj| {
                let result = self.validate_ingress(
                    IngressMessageId::from(ingress_obj),
                    &ingress_obj.signed_ingress,
                    &state,
                    context,
                    &settings,
                    &past_ingress_set,
                    num_messages,
                    &mut cycles_needed,
                );
                match result {
                    Ok(()) => {
                        num_messages += 1;
                        // Calculate the size and abort once we have hit the limit
                        accumulated_size += ingress_obj.signed_ingress.count_bytes();
                        if accumulated_size > byte_limit.get() as usize {
                            return SelectResult::Abort;
                        }

                        SelectResult::Selected(ingress_obj.signed_ingress.clone())
                    }
                    Err(ValidationError::Permanent(
                        IngressPermanentError::IngressPayloadTooBig(_, _),
                    )) => SelectResult::Abort,
                    Err(ValidationError::Permanent(
                        IngressPermanentError::IngressPayloadTooManyMessages(_, _),
                    )) => SelectResult::Abort,
                    _ => SelectResult::Skip,
                }
            }),
        );

        let payload = IngressPayload::from(messages_in_payload);
        let payload_size = payload.count_bytes();
        debug_assert!(payload_size <= byte_limit.get() as usize);

        // A last step is to validate the payload we just created. It will be
        // an error if this fails, in which case we log the error, and return
        // an empty payload instead.
        match self.validate_ingress_payload(&payload, past_ingress, context) {
            Ok(()) => payload,
            Err(err) => {
                error!(self.log, "Created an invalid IngressPayload: {:?}", err);
                IngressPayload::default()
            }
        }
    }

    fn validate_ingress_payload(
        &self,
        payload: &IngressPayload,
        past_ingress: &dyn IngressSetQuery,
        context: &ValidationContext,
    ) -> ValidationResult<IngressPayloadValidationError> {
        let _timer = self
            .metrics
            .ingress_selector_validate_payload_time
            .start_timer();

        let certified_height = context.certified_height;
        let settings = self
            .get_ingress_message_settings(context.registry_version)
            .expect("Couldn't get IngressMessageSettings from the registry.");

        let past_ingress = match IngressSetChain::new(context.time, past_ingress, || {
            IngressHistorySet::new(self.ingress_hist_reader.as_ref(), certified_height)
        }) {
            Ok(ingress_set) => ingress_set,
            Err(err) => {
                warn!(
                    self.log,
                    "IngressHistoryReader doesn't have state for height {} yet: {:?}",
                    certified_height,
                    err
                );
                return Err(err);
            }
        };

        let state = match self.state_manager.get_state_at(certified_height) {
            Ok(state) => state.take(),
            Err(err) => {
                warn!(
                    self.log,
                    "StateManager doesn't have state for height {}: {:?}", certified_height, err,
                );
                return Err(match err {
                    StateManagerError::StateRemoved(h) => {
                        ValidationError::Permanent(IngressPermanentError::StateRemoved(h))
                    }
                    StateManagerError::StateNotCommittedYet(h) => {
                        ValidationError::Transient(IngressTransientError::StateNotCommittedYet(h))
                    }
                });
            }
        };

        if payload.message_count() > settings.max_ingress_messages_per_block {
            return Err(ValidationError::Permanent(
                IngressPermanentError::IngressPayloadTooManyMessages(
                    payload.message_count(),
                    settings.max_ingress_messages_per_block,
                ),
            ));
        }

        // Tracks the sum of cycles needed per canister.
        let mut cycles_needed: BTreeMap<CanisterId, Cycles> = BTreeMap::new();
        for i in 0..payload.message_count() {
            let (ingress_id, ingress) = payload
                .get(i)
                .map_err(IngressPermanentError::IngressPayloadError)?;

            self.validate_ingress(
                ingress_id.clone(),
                &ingress,
                &state,
                context,
                &settings,
                &past_ingress,
                0, // message count is checked above.
                &mut cycles_needed,
            )?;
        }

        Ok(())
    }

    fn filter_past_payloads(
        &self,
        past_payloads: &[(Height, Time, Payload)],
        context: &ValidationContext,
    ) -> IngressSets {
        let mut ingress_payload_cache = self.ingress_payload_cache.write().unwrap();

        // Record the metrics
        self.metrics
            .ingress_payload_cache_size
            .set(ingress_payload_cache.len() as i64);

        let past_ingress: Vec<_> = past_payloads
            .iter()
            .filter_map(|(height, _, payload)| {
                if payload.is_summary() {
                    None
                } else {
                    let payload_hash = payload.get_hash();
                    let batch = &payload.as_ref().as_data().batch;
                    let ingress = ingress_payload_cache
                        .entry((*height, payload_hash.clone()))
                        .or_insert_with(|| {
                            Arc::new(batch.ingress.message_ids().into_iter().collect())
                        });
                    Some(ingress.clone())
                }
            })
            .collect();

        // We assume that 'past_payloads' comes in descending heights, following the
        // block parent traversal order.
        if let Some((min_height, _, _)) = past_payloads.last() {
            // The step below is to garbage collect no longer used past ingress payload
            // cache. It assumes the sequence of calls to payload selection/validation
            // leads to a monotonic sequence of lower-bound (min_height).
            //
            // Usually this is true, but even when it is not true (e.g. in tests) it is
            // always safe to remove entries from ingress_payload_cache at the expense
            // of having to re-compute them.
            let keys: Vec<_> = ingress_payload_cache.keys().cloned().collect();
            for key in keys {
                if key.0 < *min_height {
                    ingress_payload_cache.remove(&key);
                }
            }
        }

        let min_block_time = match past_payloads.last() {
            None => context.time,
            Some((_, time, _)) => *time,
        };

        IngressSets::new(past_ingress, min_block_time)
    }

    fn request_purge_finalized_messages(&self, message_ids: Vec<IngressMessageId>) {
        self.messages_to_purge.write().unwrap().push(message_ids)
    }
}

impl IngressManager {
    #[allow(clippy::too_many_arguments)]
    fn validate_ingress(
        &self,
        ingress_id: IngressMessageId,
        signed_ingress: &SignedIngress,
        state: &ReplicatedState,
        context: &ValidationContext,
        settings: &IngressMessageSettings,
        past_ingress_set: &IngressSetChain<IngressHistorySet>,
        num_messages: usize,
        cycles_needed: &mut BTreeMap<CanisterId, Cycles>,
    ) -> ValidationResult<IngressPayloadValidationError> {
        let ingress_message_size = signed_ingress.count_bytes();
        // The message is invalid if its size is larger than the configured maximum.
        if ingress_message_size > settings.max_ingress_bytes_per_message {
            return Err(ValidationError::Permanent(
                IngressPermanentError::IngressMessageTooBig(
                    ingress_message_size,
                    settings.max_ingress_bytes_per_message,
                ),
            ));
        }

        if num_messages >= settings.max_ingress_messages_per_block {
            return Err(ValidationError::Permanent(
                IngressPermanentError::IngressPayloadTooManyMessages(
                    num_messages,
                    settings.max_ingress_messages_per_block,
                ),
            ));
        }

        // Do not include the message if it's a duplicate.
        if past_ingress_set.contains(&ingress_id) {
            let message_id = MessageId::from(&ingress_id);
            return Err(ValidationError::Permanent(
                IngressPermanentError::DuplicatedIngressMessage(message_id),
            ));
        }

        // Skip the message if there aren't enough cycles to induct the message.
        let msg = signed_ingress.content();
        match self.cycles_account_manager.ingress_induction_cost(msg) {
            Ok(IngressInductionCost::Fee {
                payer,
                cost: ingress_cost,
            }) => match state.canister_state(&payer) {
                Some(canister) => {
                    let cumulative_ingress_cost = cycles_needed
                        .entry(payer)
                        .or_insert_with(|| Cycles::from(0));
                    if let Err(err) = self.cycles_account_manager.can_withdraw_cycles(
                        &canister.system_state,
                        *cumulative_ingress_cost + ingress_cost,
                        canister.memory_usage(state.metadata.own_subnet_type),
                        canister.scheduler_state.compute_allocation,
                    ) {
                        return Err(ValidationError::Permanent(
                            IngressPermanentError::InsufficientCycles(err),
                        ));
                    }
                    *cumulative_ingress_cost += ingress_cost;
                }
                None => {
                    return Err(ValidationError::Permanent(
                        IngressPermanentError::CanisterNotFound(payer),
                    ));
                }
            },
            Ok(IngressInductionCost::Free) => {
                // Do nothing.
            }
            Err(_) => {
                return Err(ValidationError::Permanent(
                    IngressPermanentError::InvalidManagementMessage,
                ));
            }
        };

        // Do not include the message if it is considered invalid with
        // respect to the given context (expiry & registry_version).
        if let Err(err) = validate_request(
            signed_ingress.as_ref(),
            self.ingress_signature_crypto.as_ref(),
            context.time,
            context.registry_version,
            &self.malicious_flags,
        ) {
            let message_id = MessageId::from(&ingress_id);
            return Err(ValidationError::Permanent(match err {
                RequestValidationError::InvalidIngressExpiry(msg)
                | RequestValidationError::InvalidDelegationExpiry(msg) => {
                    IngressPermanentError::IngressExpired(message_id, msg)
                }
                err => {
                    IngressPermanentError::IngressValidationError(message_id, format!("{}", err))
                }
            }));
        }
        Ok(())
    }
}

/// An IngressSetQuery implementation based on IngressHistoryReader.
struct IngressHistorySet {
    get_status: Box<dyn Fn(&MessageId) -> IngressStatus>,
}

impl IngressHistorySet {
    fn new(
        ingress_hist_reader: &dyn IngressHistoryReader,
        certified_height: Height,
    ) -> Result<Self, IngressPayloadValidationError> {
        let set = ingress_hist_reader
            .get_status_at_height(certified_height)
            .map(|get_status| IngressHistorySet { get_status })
            .map_err(IngressPermanentError::IngressHistoryError)?;
        Ok(set)
    }
}

impl IngressSetQuery for IngressHistorySet {
    fn contains(&self, msg_id: &IngressMessageId) -> bool {
        (self.get_status)(&msg_id.into()) != IngressStatus::Unknown
    }

    fn get_expiry_lower_bound(&self) -> Time {
        ic_types::time::UNIX_EPOCH
    }
}

/// Chaining of two IngressSetQuery objects. We only look up the second
/// one if the first one is false.
///
/// Because an `IngressSetQuery` covers a range starting from its expiry lower
/// bound, if the first one already covers the range of interest, we do not need
/// to consult the second one.
struct IngressSetChain<'a, T> {
    first: &'a dyn IngressSetQuery,
    next: Option<T>,
}

impl<'a, T: IngressSetQuery> IngressSetChain<'a, T> {
    /// Return the Chaining of two IngerssSetQuery object that can be
    /// used to check if an ingress message with an expiry time in the range
    /// of `time .. time + MAX_INGRESS_TTL` already exists in the set.
    ///
    /// If the first IngressSetQuery is enough to cover the full range (i.e.
    /// its expiry lower bound <= time - MAX_INGRESS_TTL), the second
    /// IngressSetQuery object will not be used.
    fn new<Err>(
        time: Time,
        first: &'a dyn IngressSetQuery,
        second: impl Fn() -> Result<T, Err>,
    ) -> Result<IngressSetChain<'a, T>, Err> {
        let next = if first.get_expiry_lower_bound() + MAX_INGRESS_TTL <= time {
            None
        } else {
            Some(second()?)
        };
        Ok(IngressSetChain { first, next })
    }
}

impl<'a, T: IngressSetQuery> IngressSetQuery for IngressSetChain<'a, T> {
    fn contains(&self, msg_id: &IngressMessageId) -> bool {
        if self.first.contains(msg_id) {
            true
        } else {
            self.next
                .as_ref()
                .map(|set| set.contains(msg_id))
                .unwrap_or(false)
        }
    }

    fn get_expiry_lower_bound(&self) -> Time {
        self.next
            .as_ref()
            .map(|set| set.get_expiry_lower_bound())
            .unwrap_or_else(|| self.first.get_expiry_lower_bound())
    }
}

#[cfg(test)]
mod tests {
    // NOTE: These tests need to be run in a tokio runtime, because they internally
    // use the `RegistryClient` which spawns tokio tasks. Without tokio, the tests
    // would compile but panic at runtime.
    use super::*;
    use crate::tests::{access_ingress_pool, setup, setup_registry, setup_with_params};
    use assert_matches::assert_matches;
    use ic_crypto::crypto_hash;
    use ic_ic00_types::{CanisterIdRecord, Payload, IC_00};
    use ic_interfaces::{
        artifact_pool::UnvalidatedArtifact,
        execution_environment::IngressHistoryError,
        gossip_pool::GossipPool,
        ingress_pool::{ChangeAction, MutableIngressPool},
        time_source::TimeSource,
    };
    use ic_test_utilities::{
        cycles_account_manager::CyclesAccountManagerBuilder,
        history::MockIngressHistory,
        mock_time,
        state::{CanisterStateBuilder, ReplicatedStateBuilder},
        types::{
            ids::{canister_test_id, node_test_id, subnet_test_id, user_test_id},
            messages::SignedIngressBuilder,
        },
        FastForwardTimeSource,
    };
    use ic_types::{
        artifact::{IngressMessageAttribute, IngressMessageId},
        batch::IngressPayload,
        ingress::{IngressState, IngressStatus},
        messages::{MessageId, SignedIngress},
        time::current_time_and_expiry_time,
        Height, RegistryVersion,
    };
    use std::{collections::HashSet, convert::TryInto, time::Duration};

    const MAX_SIZE: usize = 1000;
    const MAX_SIZE_AS_NUM_BYTES: NumBytes = NumBytes::new(MAX_SIZE as u64);

    #[tokio::test]
    async fn test_get_empty_ingress_payload() {
        setup(|ingress_manager, _| {
            let ingress_msgs = ingress_manager.get_ingress_payload(
                &HashSet::new(),
                &ValidationContext {
                    time: mock_time(),
                    registry_version: RegistryVersion::from(1),
                    certified_height: Height::from(0),
                },
                MAX_SIZE_AS_NUM_BYTES,
            );
            assert_eq!(ingress_msgs.message_count(), 0);
        })
    }

    #[tokio::test]
    async fn test_validate_empty_ingress_payload() {
        setup(|ingress_manager, _| {
            let ingress_validation = ingress_manager.validate_ingress_payload(
                &IngressPayload::default(),
                &HashSet::new(),
                &ValidationContext {
                    time: mock_time(),
                    registry_version: RegistryVersion::from(1),
                    certified_height: Height::from(0),
                },
            );

            assert_matches!(ingress_validation, Ok(_));
        })
    }

    #[tokio::test]
    async fn test_validate_ingress_payload_max_messages() {
        setup(|ingress_manager, _| {
            let mut payload = Vec::new();
            let settings = ingress_manager
                .get_ingress_message_settings(RegistryVersion::from(1))
                .unwrap();
            for i in 0..=settings.max_ingress_messages_per_block {
                let ingress = SignedIngressBuilder::new()
                    .canister_id(canister_test_id(0))
                    .nonce(i as u64)
                    .expiry_time(mock_time() + MAX_INGRESS_TTL)
                    .build();
                payload.push(ingress)
            }

            let ingress_validation = ingress_manager.validate_ingress_payload(
                &IngressPayload::from(payload),
                &HashSet::new(),
                &ValidationContext {
                    time: mock_time(),
                    registry_version: RegistryVersion::from(1),
                    certified_height: Height::from(0),
                },
            );

            assert_matches!(
                ingress_validation,
                Err(ValidationError::Permanent(
                    IngressPermanentError::IngressPayloadTooManyMessages(_, _),
                ),)
            );
        })
    }

    #[tokio::test]
    async fn test_expiry_get_payload() {
        setup_with_params(
            None,
            None,
            None,
            Some(
                ReplicatedStateBuilder::default()
                    .with_canister(
                        CanisterStateBuilder::default()
                            .with_canister_id(canister_test_id(0))
                            .build(),
                    )
                    .build(),
            ),
            |ingress_manager, ingress_pool| {
                let time = mock_time();
                let time_source = FastForwardTimeSource::new();
                let validation_context = ValidationContext {
                    time: time + MAX_INGRESS_TTL,
                    registry_version: RegistryVersion::from(1),
                    certified_height: Height::from(0),
                };

                // Message with same expiry time as validation context time should be selected
                let m1 = SignedIngressBuilder::new()
                    .canister_id(canister_test_id(0))
                    .method_name("m1".to_string())
                    .expiry_time(time + MAX_INGRESS_TTL)
                    .build();
                // Message with expiry TTL in the future should not be selected
                let m2 = SignedIngressBuilder::new()
                    .canister_id(canister_test_id(0))
                    .method_name("m2".to_string())
                    .expiry_time(time + 2 * MAX_INGRESS_TTL + Duration::new(0, 1))
                    .build();
                // Expired message should not be selected
                let m3 = SignedIngressBuilder::new()
                    .canister_id(canister_test_id(0))
                    .method_name("m3".to_string())
                    .expiry_time(time)
                    .build();

                let ingress_messages = vec![m1.clone(), m2, m3];
                for m in ingress_messages.iter() {
                    let message_id = IngressMessageId::from(m);
                    let attribute = IngressMessageAttribute::new(m);
                    access_ingress_pool(&ingress_pool, |mut ingress_pool| {
                        ingress_pool.insert(UnvalidatedArtifact {
                            message: m.clone(),
                            peer_id: node_test_id(0),
                            timestamp: time_source.get_relative_time(),
                        });
                        ingress_pool.apply_changeset(vec![ChangeAction::MoveToValidated((
                            message_id.clone(),
                            node_test_id(0),
                            m.count_bytes(),
                            attribute,
                            crypto_hash(m.binary()).get(),
                        ))]);
                        // check that message is indeed in the pool
                        assert!(ingress_pool.contains(&message_id));
                    });
                }

                let payload = ingress_manager.get_ingress_payload(
                    &HashSet::new(),
                    &validation_context,
                    MAX_SIZE_AS_NUM_BYTES,
                );
                assert_eq!(payload.message_count(), 1);
                let msgs: Vec<SignedIngress> = payload.try_into().unwrap();
                assert!(msgs.contains(&m1));
            },
        )
    }

    #[tokio::test]
    async fn test_expiry_validate_payload() {
        setup_with_params(
            None,
            None,
            None,
            Some(
                ReplicatedStateBuilder::default()
                    .with_canister(
                        CanisterStateBuilder::default()
                            .with_canister_id(canister_test_id(0))
                            .build(),
                    )
                    .build(),
            ),
            |ingress_manager, _| {
                let mut time = mock_time();
                let validation_context = ValidationContext {
                    time,
                    registry_version: RegistryVersion::from(1),
                    certified_height: Height::from(0),
                };

                // Check if message with same expiry time as validation context time
                // passes
                let ingress_msg1 = SignedIngressBuilder::new()
                    .canister_id(canister_test_id(0))
                    .expiry_time(time)
                    .sign_for_randomly_generated_sender()
                    .build();
                let payload1 = IngressPayload::from(vec![ingress_msg1]);
                let result = ingress_manager.validate_ingress_payload(
                    &payload1,
                    &HashSet::new(),
                    &validation_context,
                );
                assert_matches!(result, Ok(_));

                // Check if message with expiry TTL in the future passes
                let ingress_msg2 = SignedIngressBuilder::new()
                    .canister_id(canister_test_id(0))
                    .expiry_time(time + MAX_INGRESS_TTL)
                    .sign_for_randomly_generated_sender()
                    .build();
                let payload2 = IngressPayload::from(vec![ingress_msg2]);
                let result = ingress_manager.validate_ingress_payload(
                    &payload2,
                    &HashSet::new(),
                    &validation_context,
                );
                assert_matches!(result, Ok(_));

                // Check if message with expiry more than TTL in the future passes
                let ingress_msg3 = SignedIngressBuilder::new()
                    .canister_id(canister_test_id(0))
                    .expiry_time(time + 2 * MAX_INGRESS_TTL)
                    .sign_for_randomly_generated_sender()
                    .build();
                let payload3 = IngressPayload::from(vec![ingress_msg3]);
                let ingress_validation = ingress_manager.validate_ingress_payload(
                    &payload3,
                    &HashSet::new(),
                    &validation_context,
                );
                assert_matches!(
                    ingress_validation,
                    Err(ValidationError::Permanent(
                        IngressPermanentError::IngressExpired(_, _)
                    ))
                );

                // Check if expired message passes
                let ingress_msg4 = SignedIngressBuilder::new()
                    .canister_id(canister_test_id(0))
                    .expiry_time(time)
                    .build();
                let payload4 = IngressPayload::from(vec![ingress_msg4]);
                time += MAX_INGRESS_TTL;
                let ingress_validation = ingress_manager.validate_ingress_payload(
                    &payload4,
                    &HashSet::new(),
                    &ValidationContext {
                        time,
                        registry_version: RegistryVersion::from(1),
                        certified_height: Height::from(0),
                    },
                );
                assert_matches!(
                    ingress_validation,
                    Err(ValidationError::Permanent(
                        IngressPermanentError::IngressExpired(_, _)
                    ))
                );
            },
        );
    }

    #[tokio::test]
    // Validation should fail if the ingress message exists in the past payload
    async fn test_validate_ingress_payload_exists() {
        setup(|ingress_manager, _| {
            let ingress_msg1 = SignedIngressBuilder::new()
                .nonce(2)
                .expiry_time(mock_time() + MAX_INGRESS_TTL)
                .build();
            let mut hash_set = HashSet::new();
            hash_set.insert(IngressMessageId::from(&ingress_msg1));
            let payload = IngressPayload::from(vec![ingress_msg1]);
            let ingress_validation = ingress_manager.validate_ingress_payload(
                &payload,
                &hash_set,
                &ValidationContext {
                    time: mock_time(),
                    registry_version: RegistryVersion::from(1),
                    certified_height: Height::from(0),
                },
            );
            assert_matches!(
                ingress_validation,
                Err(ValidationError::Permanent(
                    IngressPermanentError::DuplicatedIngressMessage(_)
                ))
            );
        });
    }

    #[tokio::test]
    async fn test_get_ingress_payload_once() {
        setup_with_params(
            None,
            None,
            None,
            Some(
                ReplicatedStateBuilder::default()
                    .with_canister(
                        CanisterStateBuilder::default()
                            .with_canister_id(canister_test_id(0))
                            .build(),
                    )
                    .build(),
            ),
            |ingress_manager, ingress_pool| {
                let time_source = FastForwardTimeSource::new();
                let validation_context = ValidationContext {
                    time: mock_time(),
                    registry_version: RegistryVersion::from(1),
                    certified_height: Height::from(0),
                };

                // insert an ingress msg in ingress pool
                let ingress_msg1 = SignedIngressBuilder::new()
                    .canister_id(canister_test_id(0))
                    .expiry_time(mock_time() + MAX_INGRESS_TTL)
                    .build();
                let message_id = IngressMessageId::from(&ingress_msg1);
                let attribute = IngressMessageAttribute::new(&ingress_msg1);
                access_ingress_pool(&ingress_pool, |mut ingress_pool| {
                    ingress_pool.insert(UnvalidatedArtifact {
                        message: ingress_msg1.clone(),
                        peer_id: node_test_id(0),
                        timestamp: time_source.get_relative_time(),
                    });
                    let ingress_size1 = ingress_msg1.count_bytes();
                    ingress_pool.apply_changeset(vec![ChangeAction::MoveToValidated((
                        message_id,
                        node_test_id(0),
                        ingress_size1,
                        attribute,
                        crypto_hash(ingress_msg1.binary()).get(),
                    ))]);
                });

                // get ingress message in payload
                let first_ingress_payload = ingress_manager.get_ingress_payload(
                    &HashSet::new(),
                    &validation_context,
                    MAX_SIZE_AS_NUM_BYTES,
                );
                assert_eq!(first_ingress_payload.message_count(), 1);
            },
        )
    }

    #[tokio::test]
    async fn test_get_ingress_payload_twice() {
        setup_with_params(
            None,
            None,
            None,
            Some(
                ReplicatedStateBuilder::default()
                    .with_canister(
                        CanisterStateBuilder::default()
                            .with_canister_id(canister_test_id(0))
                            .build(),
                    )
                    .build(),
            ),
            |ingress_manager, ingress_pool| {
                let time_source = FastForwardTimeSource::new();
                let validation_context = ValidationContext {
                    time: mock_time(),
                    registry_version: RegistryVersion::from(1),
                    certified_height: Height::from(0),
                };

                // insert an ingress msg in ingress pool
                let ingress_msg1 = SignedIngressBuilder::new()
                    .canister_id(canister_test_id(0))
                    .expiry_time(mock_time() + MAX_INGRESS_TTL)
                    .build();
                let message_id = IngressMessageId::from(&ingress_msg1);
                let attribute = IngressMessageAttribute::new(&ingress_msg1);
                access_ingress_pool(&ingress_pool, |mut ingress_pool| {
                    ingress_pool.insert(UnvalidatedArtifact {
                        message: ingress_msg1.clone(),
                        peer_id: node_test_id(0),
                        timestamp: time_source.get_relative_time(),
                    });
                    let ingress_size1 = ingress_msg1.count_bytes();
                    ingress_pool.apply_changeset(vec![ChangeAction::MoveToValidated((
                        message_id,
                        node_test_id(0),
                        ingress_size1,
                        attribute,
                        crypto_hash(ingress_msg1.binary()).get(),
                    ))]);
                });

                // get ingress message in payload
                let first_ingress_payload = ingress_manager.get_ingress_payload(
                    &HashSet::new(),
                    &validation_context,
                    MAX_SIZE_AS_NUM_BYTES,
                );
                assert_eq!(first_ingress_payload.message_count(), 1);

                // we should not get it again because it is part of past payloads
                let mut hash_set = HashSet::new();
                for i in 0..first_ingress_payload.message_count() {
                    let (id, _) = first_ingress_payload.get(i).unwrap();
                    hash_set.insert(id);
                }
                let second_ingress_payload = ingress_manager.get_ingress_payload(
                    &hash_set,
                    &validation_context,
                    MAX_SIZE_AS_NUM_BYTES,
                );
                assert_eq!(second_ingress_payload.message_count(), 0);
            },
        )
    }

    #[tokio::test]
    // Select two small messages in the artifact pool
    async fn test_get_payload_small_size_accumulation() {
        setup_with_params(
            None,
            None,
            None,
            Some(
                ReplicatedStateBuilder::default()
                    .with_canister(
                        CanisterStateBuilder::default()
                            .with_canister_id(canister_test_id(0))
                            .build(),
                    )
                    .build(),
            ),
            |ingress_manager, ingress_pool| {
                let time_source = FastForwardTimeSource::new();

                // create two small messages
                let ingress_msg1 = SignedIngressBuilder::new()
                    .canister_id(canister_test_id(0))
                    .nonce(2)
                    .expiry_time(mock_time() + MAX_INGRESS_TTL)
                    .build();
                let ingress_msg2 = SignedIngressBuilder::new()
                    .canister_id(canister_test_id(0))
                    .nonce(3)
                    .expiry_time(mock_time() + MAX_INGRESS_TTL)
                    .build();

                // add them to the pool
                access_ingress_pool(&ingress_pool, |mut ingress_pool| {
                    let message_id = IngressMessageId::from(&ingress_msg1);
                    let attribute = IngressMessageAttribute::new(&ingress_msg1);
                    ingress_pool.insert(UnvalidatedArtifact {
                        message: ingress_msg1.clone(),
                        peer_id: node_test_id(0),
                        timestamp: time_source.get_relative_time(),
                    });
                    ingress_pool.apply_changeset(vec![ChangeAction::MoveToValidated((
                        message_id,
                        node_test_id(0),
                        ingress_msg1.count_bytes(),
                        attribute,
                        crypto_hash(ingress_msg1.binary()).get(),
                    ))]);

                    let attribute = IngressMessageAttribute::new(&ingress_msg2);
                    let message_id = IngressMessageId::from(&ingress_msg2);
                    ingress_pool.insert(UnvalidatedArtifact {
                        message: ingress_msg2.clone(),
                        peer_id: node_test_id(0),
                        timestamp: time_source.get_relative_time(),
                    });
                    ingress_pool.apply_changeset(vec![ChangeAction::MoveToValidated((
                        message_id,
                        node_test_id(0),
                        ingress_msg2.count_bytes(),
                        attribute,
                        crypto_hash(ingress_msg2.binary()).get(),
                    ))]);
                });

                let validation_context = ValidationContext {
                    time: mock_time(),
                    registry_version: RegistryVersion::from(1),
                    certified_height: Height::from(0),
                };

                let ingress_payload = ingress_manager.get_ingress_payload(
                    &HashSet::new(),
                    &validation_context,
                    MAX_SIZE_AS_NUM_BYTES,
                );
                assert_eq!(ingress_payload.message_count(), 2);
            },
        )
    }

    #[tokio::test]
    // Select only one out of two big messages in the artifact pool
    async fn test_get_payload_large_size_accumulation() {
        let subnet_id = subnet_test_id(0);
        let registry = setup_registry(subnet_id, MAX_SIZE);
        setup_with_params(
            None,
            Some((registry, subnet_id)),
            None,
            Some(
                ReplicatedStateBuilder::default()
                    .with_canister(
                        CanisterStateBuilder::default()
                            .with_canister_id(canister_test_id(0))
                            .build(),
                    )
                    .build(),
            ),
            |ingress_manager, ingress_pool| {
                let time_source = FastForwardTimeSource::new();

                // create two large messages (one of them would fit)
                let ingress_msg1 = SignedIngressBuilder::new()
                    .canister_id(canister_test_id(0))
                    .nonce(1)
                    .expiry_time(mock_time() + MAX_INGRESS_TTL)
                    .method_payload(vec![0; MAX_SIZE / 2 + 2])
                    .build();
                let ingress_msg2 = SignedIngressBuilder::new()
                    .canister_id(canister_test_id(0))
                    .nonce(2)
                    .expiry_time(mock_time() + MAX_INGRESS_TTL)
                    .method_payload(vec![0; MAX_SIZE / 2 + 2])
                    .build();

                // add them to the pool
                access_ingress_pool(&ingress_pool, |mut ingress_pool| {
                    let message_id = IngressMessageId::from(&ingress_msg1);
                    let attribute = IngressMessageAttribute::new(&ingress_msg1);
                    ingress_pool.insert(UnvalidatedArtifact {
                        message: ingress_msg1.clone(),
                        peer_id: node_test_id(0),
                        timestamp: time_source.get_relative_time(),
                    });
                    ingress_pool.apply_changeset(vec![ChangeAction::MoveToValidated((
                        message_id,
                        node_test_id(0),
                        ingress_msg1.count_bytes(),
                        attribute,
                        crypto_hash(ingress_msg1.binary()).get(),
                    ))]);

                    let attribute = IngressMessageAttribute::new(&ingress_msg2);
                    let message_id = IngressMessageId::from(&ingress_msg2);
                    ingress_pool.insert(UnvalidatedArtifact {
                        message: ingress_msg2.clone(),
                        peer_id: node_test_id(0),
                        timestamp: time_source.get_relative_time(),
                    });
                    ingress_pool.apply_changeset(vec![ChangeAction::MoveToValidated((
                        message_id,
                        node_test_id(0),
                        ingress_msg2.count_bytes(),
                        attribute,
                        crypto_hash(ingress_msg2.binary()).get(),
                    ))]);
                });

                let validation_context = ValidationContext {
                    time: mock_time(),
                    registry_version: RegistryVersion::from(1),
                    certified_height: Height::from(0),
                };

                let ingress_payload = ingress_manager.get_ingress_payload(
                    &HashSet::new(),
                    &validation_context,
                    NumBytes::new(MAX_SIZE as u64),
                );
                assert_eq!(ingress_payload.message_count(), 1);
            },
        )
    }

    #[tokio::test]
    // Validation should fail if the history status of ingress message is "Received"
    async fn test_validate_ingress_payload_invalid_history() {
        let mut ingress_hist_reader = Box::new(MockIngressHistory::new());
        ingress_hist_reader
            .expect_get_status_at_height()
            .returning(|_| {
                Ok(Box::new(|_| IngressStatus::Known {
                    receiver: canister_test_id(0).get(),
                    user_id: user_test_id(0),
                    time: mock_time(),
                    state: IngressState::Received,
                }))
            });
        setup_with_params(
            Some(ingress_hist_reader),
            None,
            None,
            None,
            |ingress_manager, _| {
                let ingress_msg1 = SignedIngressBuilder::new()
                    .nonce(2)
                    .expiry_time(mock_time() + MAX_INGRESS_TTL)
                    .build();
                let payload = IngressPayload::from(vec![ingress_msg1]);
                let ingress_validation = ingress_manager.validate_ingress_payload(
                    &payload,
                    &HashSet::new(),
                    &ValidationContext {
                        time: mock_time(),
                        registry_version: RegistryVersion::from(1),
                        certified_height: Height::from(0),
                    },
                );
                assert_matches!(
                    ingress_validation,
                    Err(ValidationError::Permanent(
                        IngressPermanentError::DuplicatedIngressMessage(_),
                    ),)
                );
            },
        );
    }

    #[tokio::test]
    // Validation should fail if the history status of ingress message returns an
    // error
    async fn test_validate_ingress_payload_error_history() {
        let mut ingress_hist_reader = Box::new(MockIngressHistory::new());
        ingress_hist_reader
            .expect_get_status_at_height()
            .returning(|_| Err(IngressHistoryError::StateNotAvailableYet(Height::from(0))));
        setup_with_params(
            Some(ingress_hist_reader),
            None,
            None,
            None,
            |ingress_manager, _| {
                let ingress_msg1 = SignedIngressBuilder::new()
                    .nonce(2)
                    .expiry_time(mock_time() + MAX_INGRESS_TTL)
                    .build();
                let payload = IngressPayload::from(vec![ingress_msg1]);
                let ingress_validation = ingress_manager.validate_ingress_payload(
                    &payload,
                    &HashSet::new(),
                    &ValidationContext {
                        time: mock_time(),
                        registry_version: RegistryVersion::from(1),
                        certified_height: Height::from(0),
                    },
                );
                assert_matches!(
                    ingress_validation,
                    Err(ValidationError::Permanent(IngressPermanentError::IngressHistoryError(
                            IngressHistoryError::StateNotAvailableYet(h)
                    ))) if h == Height::from(0)
                );
            },
        )
    }

    #[tokio::test]
    // If the ingress message is invalid, it should be ignored and the next
    // ingress message should be added to the payload.
    async fn test_get_ingress_payload_invalid_ingress() {
        let ingress_msg1 = SignedIngressBuilder::new()
            .canister_id(canister_test_id(0))
            .nonce(2)
            .expiry_time(mock_time() + MAX_INGRESS_TTL)
            .build();
        let message_id1 = IngressMessageId::from(&ingress_msg1);
        let message_id1_cl = message_id1.clone();
        let mut ingress_hist_reader = Box::new(MockIngressHistory::new());
        ingress_hist_reader
            .expect_get_status_at_height()
            .returning(move |_| {
                let message_id1_cl = MessageId::from(&message_id1_cl);
                Ok(Box::new(move |msg_id| {
                    if *msg_id == message_id1_cl {
                        IngressStatus::Known {
                            receiver: canister_test_id(0).get(),
                            user_id: user_test_id(0),
                            time: mock_time(),
                            state: IngressState::Processing,
                        }
                    } else {
                        IngressStatus::Unknown
                    }
                }))
            });

        setup_with_params(
            Some(ingress_hist_reader),
            None,
            None,
            Some(
                ReplicatedStateBuilder::default()
                    .with_canister(
                        CanisterStateBuilder::default()
                            .with_canister_id(canister_test_id(0))
                            .build(),
                    )
                    .build(),
            ),
            |ingress_manager, ingress_pool| {
                let time_source = FastForwardTimeSource::new();
                let ingress_msg2 = SignedIngressBuilder::new()
                    .canister_id(canister_test_id(0))
                    .nonce(3)
                    .expiry_time(mock_time() + MAX_INGRESS_TTL)
                    .build();
                let message_id2 = IngressMessageId::from(&ingress_msg2);

                let attribute1 = IngressMessageAttribute::new(&ingress_msg1);
                let attribute2 = IngressMessageAttribute::new(&ingress_msg2);

                access_ingress_pool(&ingress_pool, |mut ingress_pool| {
                    ingress_pool.insert(UnvalidatedArtifact {
                        message: ingress_msg1.clone(),
                        peer_id: node_test_id(0),
                        timestamp: time_source.get_relative_time(),
                    });
                    ingress_pool.apply_changeset(vec![ChangeAction::MoveToValidated((
                        message_id1,
                        node_test_id(0),
                        ingress_msg1.count_bytes(),
                        attribute1,
                        crypto_hash(ingress_msg1.binary()).get(),
                    ))]);
                    ingress_pool.insert(UnvalidatedArtifact {
                        message: ingress_msg2.clone(),
                        peer_id: node_test_id(0),
                        timestamp: time_source.get_relative_time(),
                    });
                    ingress_pool.apply_changeset(vec![ChangeAction::MoveToValidated((
                        message_id2,
                        node_test_id(0),
                        ingress_msg2.count_bytes(),
                        attribute2,
                        crypto_hash(ingress_msg2.binary()).get(),
                    ))]);
                });

                let validation_context = ValidationContext {
                    time: mock_time(),
                    registry_version: RegistryVersion::from(1),
                    certified_height: Height::from(0),
                };

                let ingress_payload = ingress_manager.get_ingress_payload(
                    &HashSet::new(),
                    &validation_context,
                    MAX_SIZE_AS_NUM_BYTES,
                );

                assert_eq!(ingress_payload.message_count(), 1);
                let messages: Vec<_> = ingress_payload.try_into().unwrap();
                assert!(messages.contains(&ingress_msg2));
            },
        )
    }

    #[tokio::test]
    async fn test_ingress_signature_verification() {
        setup_with_params(
            None,
            None,
            None,
            Some(
                ReplicatedStateBuilder::default()
                    .with_canister(
                        CanisterStateBuilder::default()
                            .with_canister_id(canister_test_id(0))
                            .build(),
                    )
                    .build(),
            ),
            |ingress_manager, _| {
                let time = current_time_and_expiry_time().1;
                let ingress_message1 = SignedIngressBuilder::new()
                    .canister_id(canister_test_id(0))
                    .expiry_time(time)
                    .sign_for_randomly_generated_sender()
                    .build();
                let ingress_message2 = SignedIngressBuilder::new()
                    .canister_id(canister_test_id(0))
                    .expiry_time(time)
                    .sign_for_randomly_generated_sender()
                    .nonce(4)
                    .build();
                let ingress_id2 = IngressMessageId::from(&ingress_message2);

                let payload1 = IngressPayload::from(vec![ingress_message1]);
                let ingress_validation = ingress_manager.validate_ingress_payload(
                    &payload1,
                    &HashSet::new(),
                    &ValidationContext {
                        time,
                        registry_version: RegistryVersion::from(1),
                        certified_height: Height::from(0),
                    },
                );

                assert_matches!(ingress_validation, Ok(_));

                let payload2 = IngressPayload::from(vec![ingress_message2]);
                let ingress_validation = ingress_manager.validate_ingress_payload(
                    &payload2,
                    &HashSet::new(),
                    &ValidationContext {
                        time,
                        registry_version: RegistryVersion::from(1),
                        certified_height: Height::from(0),
                    },
                );
                // expected failure due to incorrect allocation / missing canister.
                assert_matches!(
                    ingress_validation,
                    Err(
                        ValidationError::Permanent(
                            IngressPermanentError::IngressValidationError(id, _),
                        ),
                    ) if id == MessageId::from(&ingress_id2)
                );
            },
        );
    }

    #[tokio::test]
    async fn test_get_payload_canister_has_sufficient_cycles() {
        let subnet_id = subnet_test_id(0);
        let registry = setup_registry(subnet_id, MAX_SIZE);
        let time = mock_time();
        // Canister 0 has enough to induct this message...
        let m1 = SignedIngressBuilder::new()
            .canister_id(canister_test_id(0))
            .expiry_time(time + MAX_INGRESS_TTL)
            .nonce(1)
            .build();

        // .. but not enough for this message
        let m2 = SignedIngressBuilder::new()
            .canister_id(canister_test_id(0))
            .expiry_time(time + MAX_INGRESS_TTL)
            .nonce(2)
            .build();

        // Canister 1 has no cycles at all.
        let m3 = SignedIngressBuilder::new()
            .canister_id(canister_test_id(1))
            .expiry_time(time + MAX_INGRESS_TTL)
            .nonce(3)
            .build();

        // Canister that doesn't exist.
        let m4 = SignedIngressBuilder::new()
            .canister_id(canister_test_id(2))
            .expiry_time(time + MAX_INGRESS_TTL)
            .nonce(3)
            .build();

        let cycles_account_manager = CyclesAccountManagerBuilder::new()
            .with_subnet_id(subnet_id)
            .build();

        setup_with_params(
            None,
            Some((registry, subnet_id)),
            None,
            Some(
                ReplicatedStateBuilder::default()
                    .with_canister(
                        CanisterStateBuilder::default()
                            .with_canister_id(canister_test_id(0))
                            // Enough cycles to induct only m1
                            .with_cycles(
                                cycles_account_manager
                                    .ingress_induction_cost(m1.content())
                                    .unwrap()
                                    .cost(),
                            )
                            .build(),
                    )
                    .with_canister(
                        CanisterStateBuilder::default()
                            .with_canister_id(canister_test_id(1))
                            // No cycles
                            .with_cycles(0)
                            .build(),
                    )
                    .build(),
            ),
            |ingress_manager, ingress_pool| {
                let time_source = FastForwardTimeSource::new();
                let validation_context = ValidationContext {
                    time: time + MAX_INGRESS_TTL,
                    registry_version: RegistryVersion::from(1),
                    certified_height: Height::from(0),
                };

                let ingress_messages = vec![m1.clone(), m2, m3, m4];

                for m in ingress_messages.iter() {
                    let message_id = IngressMessageId::from(m);
                    let attribute = IngressMessageAttribute::new(m);
                    access_ingress_pool(&ingress_pool, |mut ingress_pool| {
                        ingress_pool.insert(UnvalidatedArtifact {
                            message: m.clone(),
                            peer_id: node_test_id(0),
                            timestamp: time_source.get_relative_time(),
                        });
                        ingress_pool.apply_changeset(vec![ChangeAction::MoveToValidated((
                            message_id.clone(),
                            node_test_id(0),
                            m.count_bytes(),
                            attribute,
                            crypto_hash(m.binary()).get(),
                        ))]);
                        // check that message is indeed in the pool
                        assert!(ingress_pool.contains(&message_id));
                    });
                }

                let payload = ingress_manager.get_ingress_payload(
                    &HashSet::new(),
                    &validation_context,
                    MAX_SIZE_AS_NUM_BYTES,
                );
                assert_eq!(payload.message_count(), 1);
                let msgs: Vec<SignedIngress> = payload.try_into().unwrap();
                assert!(msgs.contains(&m1));
            },
        )
    }

    #[tokio::test]
    // Validation should fail if receiving canisters has insufficient balance.
    async fn test_validate_canister_has_insufficient_balance() {
        let subnet_id = subnet_test_id(0);
        let registry = setup_registry(subnet_id, MAX_SIZE);
        setup_with_params(
            None,
            Some((registry, subnet_id)),
            None,
            Some(
                ReplicatedStateBuilder::default()
                    .with_canister(
                        CanisterStateBuilder::default()
                            .with_canister_id(canister_test_id(0))
                            // Not enough cycles
                            .with_cycles(0)
                            .build(),
                    )
                    .build(),
            ),
            |ingress_manager, _| {
                let time = mock_time();
                let m1 = SignedIngressBuilder::new()
                    .canister_id(canister_test_id(0))
                    .expiry_time(time + MAX_INGRESS_TTL)
                    .nonce(1)
                    .build();

                let m2 = SignedIngressBuilder::new()
                    .canister_id(canister_test_id(0))
                    .expiry_time(time + MAX_INGRESS_TTL)
                    .nonce(2)
                    .build();

                let payload = IngressPayload::from(vec![m1, m2]);
                let ingress_validation = ingress_manager.validate_ingress_payload(
                    &payload,
                    &HashSet::new(),
                    &ValidationContext {
                        time: mock_time(),
                        registry_version: RegistryVersion::from(1),
                        certified_height: Height::from(0),
                    },
                );
                assert_matches!(
                    ingress_validation,
                    Err(ValidationError::Permanent(
                        IngressPermanentError::InsufficientCycles(_)
                    ))
                );
            },
        );
    }

    #[tokio::test]
    // Validation should fail if receiving canister doesn't exist.
    async fn test_validate_canister_not_found() {
        let subnet_id = subnet_test_id(0);
        let registry = setup_registry(subnet_id, MAX_SIZE);
        setup_with_params(
            None,
            Some((registry, subnet_id)),
            None,
            None,
            |ingress_manager, _| {
                let time = mock_time();
                // Canister 0 doesn't exist.
                let m1 = SignedIngressBuilder::new()
                    .canister_id(canister_test_id(0))
                    .expiry_time(time + MAX_INGRESS_TTL)
                    .nonce(1)
                    .build();

                let payload = IngressPayload::from(vec![m1]);
                let ingress_validation = ingress_manager.validate_ingress_payload(
                    &payload,
                    &HashSet::new(),
                    &ValidationContext {
                        time: mock_time(),
                        registry_version: RegistryVersion::from(1),
                        certified_height: Height::from(0),
                    },
                );
                assert_matches!(
                    ingress_validation,
                    Err(ValidationError::Permanent(
                        IngressPermanentError::CanisterNotFound(_)
                    ))
                );
            },
        );
    }

    #[tokio::test]
    async fn test_validate_management_message_to_non_existing_canister() {
        let subnet_id = subnet_test_id(0);
        let registry = setup_registry(subnet_id, MAX_SIZE);
        setup_with_params(
            None,
            Some((registry, subnet_id)),
            None,
            Some(
                ReplicatedStateBuilder::new()
                    .with_subnet_id(subnet_id)
                    .build(),
            ),
            |ingress_manager, _| {
                let time = mock_time();
                for sender in [IC_00, CanisterId::from(subnet_id)].iter() {
                    // Message to check the status of a canister that doesn't exist.
                    let msg = SignedIngressBuilder::new()
                        .canister_id(*sender)
                        .method_name("canister_status")
                        .method_payload(CanisterIdRecord::from(canister_test_id(2)).encode())
                        .expiry_time(time + MAX_INGRESS_TTL)
                        .build();

                    let payload = IngressPayload::from(vec![msg]);
                    assert_matches!(
                        ingress_manager.validate_ingress_payload(
                            &payload,
                            &HashSet::new(),
                            &ValidationContext {
                                time: mock_time(),
                                registry_version: RegistryVersion::from(1),
                                certified_height: Height::from(0),
                            },
                        ),
                        // Validation should fail since the canister that needs to pay for the
                        // message doesn't exist.
                        Err(ValidationError::Permanent(IngressPermanentError::CanisterNotFound(canister_id)))
                            if canister_id == canister_test_id(2)
                    );
                }
            },
        );
    }

    #[tokio::test]
    // Validation should succeed if receiving canister is subnet or IC00
    async fn test_validate_management_message_to_existing_canister_with_sufficient_cycles() {
        let subnet_id = subnet_test_id(0);
        let registry = setup_registry(subnet_id, MAX_SIZE);
        setup_with_params(
            None,
            Some((registry, subnet_id)),
            None,
            Some(
                ReplicatedStateBuilder::new()
                    .with_subnet_id(subnet_id)
                    .with_canister(
                        CanisterStateBuilder::new()
                            .with_canister_id(canister_test_id(2))
                            .with_cycles(u128::MAX)
                            .build(),
                    )
                    .build(),
            ),
            |ingress_manager, _| {
                let time = mock_time();
                for sender in [IC_00, CanisterId::from(subnet_id)].iter() {
                    // Message to check the status of a canister that exists.
                    let msg = SignedIngressBuilder::new()
                        .canister_id(*sender)
                        .method_name("canister_status")
                        .method_payload(CanisterIdRecord::from(canister_test_id(2)).encode())
                        .expiry_time(time + MAX_INGRESS_TTL)
                        .build();

                    let payload = IngressPayload::from(vec![msg]);
                    // Validation should succeed since the canister being addressed
                    // exists and has enough cycles.
                    assert!(ingress_manager
                        .validate_ingress_payload(
                            &payload,
                            &HashSet::new(),
                            &ValidationContext {
                                time: mock_time(),
                                registry_version: RegistryVersion::from(1),
                                certified_height: Height::from(0),
                            },
                        )
                        .is_ok());
                }
            },
        );
    }

    #[tokio::test]
    async fn test_validate_management_message_to_existing_canister_with_insufficient_cycles() {
        let subnet_id = subnet_test_id(0);
        let registry = setup_registry(subnet_id, MAX_SIZE);
        setup_with_params(
            None,
            Some((registry, subnet_id)),
            None,
            Some(
                ReplicatedStateBuilder::new()
                    .with_subnet_id(subnet_id)
                    .with_canister(
                        CanisterStateBuilder::new()
                            .with_canister_id(canister_test_id(2))
                            .with_cycles(0)
                            .build(),
                    )
                    .build(),
            ),
            |ingress_manager, _| {
                let time = mock_time();
                for sender in [IC_00, CanisterId::from(subnet_id)].iter() {
                    // Message to check the status of a canister that exists.
                    let msg = SignedIngressBuilder::new()
                        .canister_id(*sender)
                        .method_name("canister_status")
                        .method_payload(CanisterIdRecord::from(canister_test_id(2)).encode())
                        .expiry_time(time + MAX_INGRESS_TTL)
                        .build();

                    let payload = IngressPayload::from(vec![msg]);
                    // Validation should fail since the canister being addressed
                    // doesn't have enough cycles.
                    assert_matches!(ingress_manager
                        .validate_ingress_payload(
                            &payload,
                            &HashSet::new(),
                            &ValidationContext {
                                time: mock_time(),
                                registry_version: RegistryVersion::from(1),
                                certified_height: Height::from(0),
                            },
                        ),
                        // Validation should fail since the canister that needs to pay for the
                        // message doesn't have enough cycles.
                        Err(ValidationError::Permanent(IngressPermanentError::InsufficientCycles(err)))
                            if err.canister_id == canister_test_id(2)
                    );
                }
            },
        );
    }

    #[tokio::test]
    async fn test_validate_invalid_management_message() {
        let subnet_id = subnet_test_id(0);
        let registry = setup_registry(subnet_id, MAX_SIZE);
        setup_with_params(
            None,
            Some((registry, subnet_id)),
            None,
            Some(
                ReplicatedStateBuilder::new()
                    .with_subnet_id(subnet_id)
                    .build(),
            ),
            |ingress_manager, _| {
                let time = mock_time();
                for sender in [IC_00, CanisterId::from(subnet_id)].iter() {
                    // Management message without a payload. This is invalid because then we don't
                    // know who pays for this.
                    let msg = SignedIngressBuilder::new()
                        .canister_id(*sender)
                        .method_name("canister_status")
                        .expiry_time(time + MAX_INGRESS_TTL)
                        .build();
                    let payload = IngressPayload::from(vec![msg]);

                    // Validation should fail since the canister being addressed
                    // doesn't have enough cycles.
                    assert_matches!(
                        ingress_manager.validate_ingress_payload(
                            &payload,
                            &HashSet::new(),
                            &ValidationContext {
                                time: mock_time(),
                                registry_version: RegistryVersion::from(1),
                                certified_height: Height::from(0),
                            },
                        ),
                        // Validation should fail since the canister that needs to pay for the
                        // message doesn't have enough cycles.
                        Err(ValidationError::Permanent(
                            IngressPermanentError::InvalidManagementMessage
                        ))
                    );

                    // Management message with a non-existing method name. This is invalid because
                    // then we don't know who pays for this.
                    let msg = SignedIngressBuilder::new()
                        .canister_id(*sender)
                        .method_name("abc")
                        .expiry_time(time + MAX_INGRESS_TTL)
                        .build();
                    let payload = IngressPayload::from(vec![msg]);

                    // Validation should fail since the canister being addressed
                    // doesn't have enough cycles.
                    assert_matches!(
                        ingress_manager.validate_ingress_payload(
                            &payload,
                            &HashSet::new(),
                            &ValidationContext {
                                time: mock_time(),
                                registry_version: RegistryVersion::from(1),
                                certified_height: Height::from(0),
                            },
                        ),
                        // Validation should fail since the canister that needs to pay for the
                        // message doesn't have enough cycles.
                        Err(ValidationError::Permanent(
                            IngressPermanentError::InvalidManagementMessage
                        ))
                    );
                }
            },
        );
    }

    #[tokio::test]
    async fn test_nearly_oversized_ingress() {
        const MAX_SIZE: usize = 2 * 1024 * 1024;
        const ALMOST_MAX_SIZE: usize = 2 * 1024 * 1024 - 140;

        let subnet_id = subnet_test_id(0);
        let registry = setup_registry(subnet_id, MAX_SIZE);

        setup_with_params(
            None,
            Some((registry, subnet_id)),
            None,
            Some(
                ReplicatedStateBuilder::new()
                    .with_subnet_id(subnet_id)
                    .with_canister(
                        CanisterStateBuilder::default()
                            .with_canister_id(canister_test_id(0))
                            .build(),
                    )
                    .build(),
            ),
            |ingress_manager, ingress_pool| {
                let msg = SignedIngressBuilder::new()
                    .method_payload(vec![0; ALMOST_MAX_SIZE])
                    .expiry_time(mock_time())
                    .build();

                assert_eq!(
                    IngressPayload::from(vec![msg.clone()]).count_bytes(),
                    msg.count_bytes()
                );

                let msg_id = IngressMessageId::from(&msg);
                let msg_attribute = IngressMessageAttribute::new(&msg);
                let msg_hash = ic_crypto::crypto_hash(msg.binary()).get();
                let _payload = IngressPayload::from(vec![msg.clone()]);

                ingress_pool.write().unwrap().insert(UnvalidatedArtifact {
                    message: msg,
                    peer_id: node_test_id(0),
                    timestamp: mock_time(),
                });
                ingress_pool
                    .write()
                    .unwrap()
                    .apply_changeset(vec![ChangeAction::MoveToValidated((
                        msg_id,
                        node_test_id(0),
                        0,
                        msg_attribute,
                        msg_hash,
                    ))]);

                let validation_context = ValidationContext {
                    registry_version: RegistryVersion::new(1),
                    certified_height: Height::new(0),
                    time: mock_time(),
                };

                let _payload = ingress_manager.get_ingress_payload(
                    &HashSet::new(),
                    &validation_context,
                    NumBytes::new(MAX_SIZE as u64),
                );
            },
        );
    }
}
