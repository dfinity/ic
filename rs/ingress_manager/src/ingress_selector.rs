//! The Ingress Selector selects Signed Ingress Messages for the inclusion in
//! Consensus batches (PayloadBuilder). It is also used to validate the Ingress
//! messages of Consensus payloads and to keep track of finalized Ingress
//! Messages to ensure that no message is added to a block more than once.
use crate::{CustomRandomState, IngressManager};
use ic_constants::{MAX_INGRESS_TTL, SMALL_APP_SUBNET_MAX_SIZE};
use ic_cycles_account_manager::IngressInductionCost;
use ic_interfaces::{
    execution_environment::{IngressHistoryError, IngressHistoryReader},
    ingress_manager::{
        IngressPayloadValidationError, IngressPayloadValidationFailure, IngressSelector,
        IngressSetQuery, InvalidIngressPayloadReason,
    },
    ingress_pool::ValidatedIngressArtifact,
    validation::{ValidationError, ValidationResult},
};
use ic_logger::warn;
use ic_management_canister_types::CanisterStatusType;
use ic_registry_client_helpers::subnet::IngressMessageSettings;
use ic_replicated_state::ReplicatedState;
use ic_types::{
    artifact::IngressMessageId,
    batch::{IngressPayload, ValidationContext},
    consensus::Payload,
    ingress::{IngressSets, IngressStatus},
    messages::{extract_effective_canister_id, MessageId, SignedIngress},
    CanisterId, CountBytes, Cycles, Height, NumBytes, Time,
};
use ic_validator::RequestValidationError;
use std::{collections::BTreeMap, collections::HashMap, sync::Arc};

/// Number of round-robin iterations that need to happen, before we weaken the selection
/// rule #2. This weakening helps the ingress selector progress when the quota is either
/// not increasing fast enough or in the worst case stuck.
///
/// Strong inclusion rule:
///       The quota is a hard limit, with the exception of a canister's *first* message.
///
/// Weak inclusion rule:
///       The quota is a hard limit, with the exception of a canister's first *n*
///       messages, where n is the current round-robin iteration count.
///
/// The weak rule compromises on fairness to ensure our ingress selector doesn't get
/// stuck.
const ITERATIONS_BEFORE_WEAKEN_INCLUDE_RULE: u32 = 4;

impl IngressSelector for IngressManager {
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

        let state = match self.state_reader.get_state_at(certified_height) {
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

        let ingress_pool = self.ingress_pool.read().unwrap();

        /* --------------------------------------------------------------------------- */
        // BEGIN Building the Canister Queues
        /* --------------------------------------------------------------------------- */
        #[derive(Default)]
        struct CanisterQueue<'a> {
            /// Number of bytes the canister's queue that was included in ingress
            bytes_included: usize,
            msgs_included: u32,
            msgs: Vec<&'a ValidatedIngressArtifact>,
        }

        let mut canister_queues = HashMap::<_, CanisterQueue, CustomRandomState>::with_hasher(
            self.random_state.create_state(),
        );

        let artifacts = ingress_pool
            .validated()
            .get_all_by_expiry_range(expiry_range);

        for artifact in artifacts {
            let pool_obj = canister_queues
                .entry(artifact.msg.signed_ingress.canister_id())
                .or_default();
            pool_obj.msgs.push(artifact);
        }
        let canister_count = canister_queues.len();

        // At this point messages are sorted by expiry time. In order to prevent malicious
        // users from putting their messages ahead of others by carefully crafting the expiry
        // times, we sort the ingress messages by the time they were delivered to the pool.
        // NOTE: We sort in reverse order, because messages are pop()-ed from the back.
        for v in canister_queues.values_mut() {
            v.msgs.sort_unstable_by_key(|artifact| {
                std::cmp::Reverse(artifact.timestamp.as_nanos_since_unix_epoch())
            });
        }
        /* --------------------------------------------------------------------------- */
        // END
        /* --------------------------------------------------------------------------- */

        // Initial per-canister quota of ingress bytes. If a canister doesn't have enough
        // messages to fill the quota, the quota increases proportionally for subsequent
        // canisters.
        let mut quota = match canister_count {
            0 => return IngressPayload::default(),
            canister_count => byte_limit.get() as usize / canister_count,
        };

        let mut messages_in_payload = vec![];

        let mut canisters: Vec<_> = canister_queues.keys().cloned().collect();

        // Do round-robin iterations until the payload is full or no messages are left
        let mut round_robin_iter: u32 = 0;
        'outer: while !canister_queues.is_empty() {
            round_robin_iter += 1;
            // Execute a single round-robin iteration, by looping through the canisters
            // and selecting messages up bound by per-canister quota and payload size.
            let mut i = 0;
            while i < canisters.len() {
                let canister_id = canisters[i];
                // For a given canister, add valid ingress messsages until quota is met
                let queue = &mut canister_queues.get_mut(&canister_id).unwrap();
                while let Some(msg) = queue.msgs.last() {
                    let ingress = &msg.msg.signed_ingress;
                    let result = self.validate_ingress(
                        IngressMessageId::from(ingress),
                        ingress,
                        &state,
                        context,
                        &settings,
                        &past_ingress_set,
                        num_messages,
                        &mut cycles_needed,
                    );
                    // Any message that generates validation errors gets removed from
                    // the canister's queue.
                    match result {
                        Ok(()) => (),
                        Err(ValidationError::InvalidArtifact(
                            InvalidIngressPayloadReason::IngressPayloadTooManyMessages(_, _),
                        )) => break 'outer,
                        _ => {
                            queue.msgs.pop();
                            continue;
                        }
                    };

                    let ingress_size = ingress.count_bytes();

                    // Break criterion #1: global byte limit
                    if (accumulated_size + ingress_size) as u64 > byte_limit.get() {
                        break 'outer;
                    }

                    // Break criterion #2: canister with at least max(1, n) included
                    // messages crossed quota, where n is the number of round robin
                    // iterations - ITERATIONS_BEFORE_WEAKEN_INCLUDE_RULE.
                    // See documentation of [`ITERATIONS_BEFORE_WEAKEN_INCLUDE_RULE`].
                    if queue.msgs_included
                        >= std::cmp::max(
                            1,
                            round_robin_iter.saturating_sub(ITERATIONS_BEFORE_WEAKEN_INCLUDE_RULE),
                        )
                        && (queue.bytes_included + ingress_size) > quota
                    {
                        break;
                    }

                    num_messages += 1;
                    accumulated_size += ingress_size;
                    queue.msgs_included += 1;
                    queue.bytes_included += ingress_size;
                    // The quota is not a hard limit. We always include the first message
                    // of each canister. This is why we check the third break criterion
                    // after this line.
                    messages_in_payload.push(ingress.clone());
                    queue.msgs.pop();
                }

                // Swap-remove canisters with an empty queue.
                if queue.msgs.is_empty() {
                    canisters.swap_remove(i);
                    // iterate again over current index because of swap_remove
                } else {
                    i += 1;
                }
            }

            if byte_limit.get() as usize <= accumulated_size {
                // No remaining quota means the block is full. No more iterations needed.
                break;
            } else {
                // Disperse excess quota amongst all remaining canisters.
                match canisters.len() {
                    0 => break,
                    canister_count => {
                        quota += (byte_limit.get() as usize - accumulated_size) / canister_count;
                    }
                };
            }
        }
        // Relevant ingress was cloned, and no references are held, so we drop the lock.
        drop(ingress_pool);

        // NOTE: Since the `Vec<SignedIngress>` is deserialized and slightly smaller than the
        // serialized `IngressPayload`, we need to check the size of the latter.
        // In the improbable case, that the deserialized form fits the size limit but the
        // serialized form does not, we need to remove some `SignedIngress` and try again.
        let payload = loop {
            let payload = IngressPayload::from(messages_in_payload.clone());
            let payload_size = payload.count_bytes();
            if payload_size < byte_limit.get() as usize {
                break payload;
            }

            warn!(
                self.log,
                "Serialized form of ingress (was {} bytes) did not pass \
                size restriction ({} bytes), reducing ingress and trying again",
                payload_size,
                byte_limit.get()
            );
            messages_in_payload.pop();
            if messages_in_payload.is_empty() {
                break IngressPayload::default();
            }
        };

        let payload_size = payload.count_bytes();
        debug_assert!(payload_size <= byte_limit.get() as usize);

        payload
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
                    every_n_seconds => 30,
                    self.log,
                    "IngressHistoryReader doesn't have state for height {} yet: {:?}",
                    certified_height,
                    err
                );

                return Err(ValidationError::ValidationFailed(
                    IngressPayloadValidationFailure::IngressHistoryError(certified_height, err),
                ));
            }
        };

        let state = match self.state_reader.get_state_at(certified_height) {
            Ok(state) => state.take(),
            Err(err) => {
                warn!(
                    every_n_seconds => 30,
                    self.log,
                    "StateManager doesn't have state for height {}: {:?}", certified_height, err
                );

                return Err(ValidationError::ValidationFailed(
                    IngressPayloadValidationFailure::StateManagerError(certified_height, err),
                ));
            }
        };

        if payload.message_count() > settings.max_ingress_messages_per_block {
            return Err(ValidationError::InvalidArtifact(
                InvalidIngressPayloadReason::IngressPayloadTooManyMessages(
                    payload.message_count(),
                    settings.max_ingress_messages_per_block,
                ),
            ));
        }

        // Tracks the sum of cycles needed per canister.
        let mut cycles_needed: BTreeMap<CanisterId, Cycles> = BTreeMap::new();
        for ingress_message in payload.as_ref() {
            let ingress_id = IngressMessageId::from(ingress_message);

            self.validate_ingress(
                ingress_id,
                ingress_message,
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

    fn has_message(&self, message_id: &IngressMessageId) -> bool {
        self.ingress_pool
            .as_ref()
            .read()
            .unwrap()
            .validated()
            .get(message_id)
            .is_some()
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
            return Err(ValidationError::InvalidArtifact(
                InvalidIngressPayloadReason::IngressMessageTooBig(
                    ingress_message_size,
                    settings.max_ingress_bytes_per_message,
                ),
            ));
        }

        if num_messages >= settings.max_ingress_messages_per_block {
            return Err(ValidationError::InvalidArtifact(
                InvalidIngressPayloadReason::IngressPayloadTooManyMessages(
                    num_messages,
                    settings.max_ingress_messages_per_block,
                ),
            ));
        }

        // Do not include the message if it's a duplicate.
        if past_ingress_set.contains(&ingress_id) {
            let message_id = MessageId::from(&ingress_id);
            return Err(ValidationError::InvalidArtifact(
                InvalidIngressPayloadReason::DuplicatedIngressMessage(message_id),
            ));
        }

        // Do not include the message if the recipient is Stopping or Stopped.
        let msg = signed_ingress.content();
        if !msg.is_addressed_to_subnet(self.subnet_id) {
            let canister_id = msg.canister_id();
            let canister_state = state.canister_state(&canister_id).ok_or({
                ValidationError::InvalidArtifact(InvalidIngressPayloadReason::CanisterNotFound(
                    canister_id,
                ))
            })?;
            match canister_state.status() {
                CanisterStatusType::Running => {}
                CanisterStatusType::Stopping => {
                    return Err(ValidationError::InvalidArtifact(
                        InvalidIngressPayloadReason::CanisterStopping(canister_id),
                    ));
                }
                CanisterStatusType::Stopped => {
                    return Err(ValidationError::InvalidArtifact(
                        InvalidIngressPayloadReason::CanisterStopped(canister_id),
                    ));
                }
            }
        }

        // Skip the message if there aren't enough cycles to induct the message.
        let effective_canister_id =
            extract_effective_canister_id(msg, self.subnet_id).map_err(|_| {
                ValidationError::InvalidArtifact(
                    InvalidIngressPayloadReason::InvalidManagementMessage,
                )
            })?;
        let subnet_size = state
            .metadata
            .network_topology
            .get_subnet_size(&state.metadata.own_subnet_id)
            .unwrap_or(SMALL_APP_SUBNET_MAX_SIZE);
        match self.cycles_account_manager.ingress_induction_cost(
            msg,
            effective_canister_id,
            subnet_size,
        ) {
            IngressInductionCost::Fee {
                payer,
                cost: ingress_cost,
            } => match state.canister_state(&payer) {
                Some(canister) => {
                    let cumulative_ingress_cost =
                        cycles_needed.entry(payer).or_insert_with(Cycles::zero);
                    if let Err(err) = self.cycles_account_manager.can_withdraw_cycles(
                        &canister.system_state,
                        *cumulative_ingress_cost + ingress_cost,
                        canister.memory_usage(),
                        canister.message_memory_usage(),
                        canister.scheduler_state.compute_allocation,
                        subnet_size,
                        false, // error here is not returned back to the user => no need to reveal top up balance
                    ) {
                        return Err(ValidationError::InvalidArtifact(
                            InvalidIngressPayloadReason::InsufficientCycles(err),
                        ));
                    }
                    *cumulative_ingress_cost += ingress_cost;
                }
                None => {
                    return Err(ValidationError::InvalidArtifact(
                        InvalidIngressPayloadReason::CanisterNotFound(payer),
                    ));
                }
            },
            IngressInductionCost::Free => {
                // Do nothing.
            }
        };

        // Do not include the message if it is considered invalid with
        // respect to the given context (expiry & registry_version).
        if let Err(err) = self.request_validator.validate_request(
            signed_ingress.as_ref(),
            context.time,
            &self.registry_root_of_trust_provider(context.registry_version),
        ) {
            let message_id = MessageId::from(&ingress_id);
            return Err(ValidationError::InvalidArtifact(match err {
                RequestValidationError::InvalidIngressExpiry(msg)
                | RequestValidationError::InvalidDelegationExpiry(msg) => {
                    InvalidIngressPayloadReason::IngressExpired(message_id, msg)
                }
                err => InvalidIngressPayloadReason::IngressValidationError(
                    message_id,
                    format!("{}", err),
                ),
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
    ) -> Result<Self, IngressHistoryError> {
        ingress_hist_reader
            .get_status_at_height(certified_height)
            .map(|get_status| IngressHistorySet { get_status })
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
    use crate::{
        tests::{access_ingress_pool, setup, setup_registry, setup_with_params},
        RandomStateKind,
    };
    use assert_matches::assert_matches;
    use ic_artifact_pool::ingress_pool::IngressPoolImpl;
    use ic_interfaces::{
        execution_environment::IngressHistoryError,
        ingress_pool::ChangeAction,
        p2p::consensus::{MutablePool, UnvalidatedArtifact, ValidatedPoolReader},
        time_source::TimeSource,
    };
    use ic_interfaces_mocks::consensus_pool::MockConsensusTime;
    use ic_interfaces_state_manager::{StateManagerError, StateManagerResult};
    use ic_interfaces_state_manager_mocks::MockStateManager;
    use ic_management_canister_types::{CanisterIdRecord, Payload, IC_00};
    use ic_metrics::MetricsRegistry;
    use ic_replicated_state::CanisterState;
    use ic_test_utilities::{
        artifact_pool_config::with_test_pool_config,
        crypto::temp_crypto_component_with_fake_registry,
        cycles_account_manager::CyclesAccountManagerBuilder,
    };
    use ic_test_utilities_logger::with_test_replica_logger;
    use ic_test_utilities_state::{
        CanisterStateBuilder, MockIngressHistory, ReplicatedStateBuilder,
    };
    use ic_test_utilities_time::FastForwardTimeSource;
    use ic_test_utilities_types::{
        ids::{canister_test_id, node_test_id, subnet_test_id, user_test_id},
        messages::SignedIngressBuilder,
    };
    use ic_types::{
        artifact::IngressMessageId,
        batch::IngressPayload,
        ingress::{IngressState, IngressStatus},
        malicious_flags::MaliciousFlags,
        messages::{MessageId, SignedIngress},
        time::{expiry_time_from_now, UNIX_EPOCH},
        Height, RegistryVersion,
    };
    use rand::RngCore;
    use std::sync::RwLock;
    use std::{collections::HashSet, convert::TryInto, time::Duration};

    const MAX_SIZE: usize = 1000;
    const MAX_SIZE_AS_NUM_BYTES: NumBytes = NumBytes::new(MAX_SIZE as u64);

    #[tokio::test]
    async fn test_get_empty_ingress_payload() {
        setup(|ingress_manager, _| {
            let ingress_msgs = ingress_manager.get_ingress_payload(
                &HashSet::new(),
                &ValidationContext {
                    time: UNIX_EPOCH,
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
                    time: UNIX_EPOCH,
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
                    .expiry_time(UNIX_EPOCH + MAX_INGRESS_TTL)
                    .build();
                payload.push(ingress)
            }

            let ingress_validation = ingress_manager.validate_ingress_payload(
                &IngressPayload::from(payload),
                &HashSet::new(),
                &ValidationContext {
                    time: UNIX_EPOCH,
                    registry_version: RegistryVersion::from(1),
                    certified_height: Height::from(0),
                },
            );

            assert_matches!(
                ingress_validation,
                Err(ValidationError::InvalidArtifact(
                    InvalidIngressPayloadReason::IngressPayloadTooManyMessages(_, _),
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
                let time = UNIX_EPOCH;
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
                    access_ingress_pool(&ingress_pool, |ingress_pool| {
                        ingress_pool.insert(UnvalidatedArtifact {
                            message: m.clone(),
                            peer_id: node_test_id(0),
                            timestamp: time_source.get_relative_time(),
                        });
                        ingress_pool
                            .apply_changes(vec![ChangeAction::MoveToValidated(message_id.clone())]);
                        // check that message is indeed in the pool
                        assert!(ingress_pool.get(&message_id).is_some());
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
                let mut time = UNIX_EPOCH;
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
                    Err(ValidationError::InvalidArtifact(
                        InvalidIngressPayloadReason::IngressExpired(_, _)
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
                    Err(ValidationError::InvalidArtifact(
                        InvalidIngressPayloadReason::IngressExpired(_, _)
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
                .expiry_time(UNIX_EPOCH + MAX_INGRESS_TTL)
                .build();
            let mut hash_set = HashSet::new();
            hash_set.insert(IngressMessageId::from(&ingress_msg1));
            let payload = IngressPayload::from(vec![ingress_msg1]);
            let ingress_validation = ingress_manager.validate_ingress_payload(
                &payload,
                &hash_set,
                &ValidationContext {
                    time: UNIX_EPOCH,
                    registry_version: RegistryVersion::from(1),
                    certified_height: Height::from(0),
                },
            );
            assert_matches!(
                ingress_validation,
                Err(ValidationError::InvalidArtifact(
                    InvalidIngressPayloadReason::DuplicatedIngressMessage(_)
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
                    time: UNIX_EPOCH,
                    registry_version: RegistryVersion::from(1),
                    certified_height: Height::from(0),
                };

                // insert an ingress msg in ingress pool
                let ingress_msg1 = SignedIngressBuilder::new()
                    .canister_id(canister_test_id(0))
                    .expiry_time(UNIX_EPOCH + MAX_INGRESS_TTL)
                    .build();
                let message_id = IngressMessageId::from(&ingress_msg1);
                access_ingress_pool(&ingress_pool, |ingress_pool| {
                    ingress_pool.insert(UnvalidatedArtifact {
                        message: ingress_msg1.clone(),
                        peer_id: node_test_id(0),
                        timestamp: time_source.get_relative_time(),
                    });
                    ingress_pool.apply_changes(vec![ChangeAction::MoveToValidated(message_id)]);
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
                    time: UNIX_EPOCH,
                    registry_version: RegistryVersion::from(1),
                    certified_height: Height::from(0),
                };

                // insert an ingress msg in ingress pool
                let ingress_msg1 = SignedIngressBuilder::new()
                    .canister_id(canister_test_id(0))
                    .expiry_time(UNIX_EPOCH + MAX_INGRESS_TTL)
                    .build();
                let message_id = IngressMessageId::from(&ingress_msg1);
                access_ingress_pool(&ingress_pool, |ingress_pool| {
                    ingress_pool.insert(UnvalidatedArtifact {
                        message: ingress_msg1.clone(),
                        peer_id: node_test_id(0),
                        timestamp: time_source.get_relative_time(),
                    });
                    ingress_pool.apply_changes(vec![ChangeAction::MoveToValidated(message_id)]);
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
                    .expiry_time(UNIX_EPOCH + MAX_INGRESS_TTL)
                    .build();
                let ingress_msg2 = SignedIngressBuilder::new()
                    .canister_id(canister_test_id(0))
                    .nonce(3)
                    .expiry_time(UNIX_EPOCH + MAX_INGRESS_TTL)
                    .build();

                // add them to the pool
                access_ingress_pool(&ingress_pool, |ingress_pool| {
                    let message_id = IngressMessageId::from(&ingress_msg1);
                    ingress_pool.insert(UnvalidatedArtifact {
                        message: ingress_msg1.clone(),
                        peer_id: node_test_id(0),
                        timestamp: time_source.get_relative_time(),
                    });
                    ingress_pool.apply_changes(vec![ChangeAction::MoveToValidated(message_id)]);

                    let message_id = IngressMessageId::from(&ingress_msg2);
                    ingress_pool.insert(UnvalidatedArtifact {
                        message: ingress_msg2.clone(),
                        peer_id: node_test_id(0),
                        timestamp: time_source.get_relative_time(),
                    });
                    ingress_pool.apply_changes(vec![ChangeAction::MoveToValidated(message_id)]);
                });

                let validation_context = ValidationContext {
                    time: UNIX_EPOCH,
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
                    .expiry_time(UNIX_EPOCH + MAX_INGRESS_TTL)
                    .method_payload(vec![0; MAX_SIZE / 2 + 2])
                    .build();
                let ingress_msg2 = SignedIngressBuilder::new()
                    .canister_id(canister_test_id(0))
                    .nonce(2)
                    .expiry_time(UNIX_EPOCH + MAX_INGRESS_TTL)
                    .method_payload(vec![0; MAX_SIZE / 2 + 2])
                    .build();

                // add them to the pool
                access_ingress_pool(&ingress_pool, |ingress_pool| {
                    let message_id = IngressMessageId::from(&ingress_msg1);
                    ingress_pool.insert(UnvalidatedArtifact {
                        message: ingress_msg1.clone(),
                        peer_id: node_test_id(0),
                        timestamp: time_source.get_relative_time(),
                    });
                    ingress_pool.apply_changes(vec![ChangeAction::MoveToValidated(message_id)]);

                    let message_id = IngressMessageId::from(&ingress_msg2);
                    ingress_pool.insert(UnvalidatedArtifact {
                        message: ingress_msg2.clone(),
                        peer_id: node_test_id(0),
                        timestamp: time_source.get_relative_time(),
                    });
                    ingress_pool.apply_changes(vec![ChangeAction::MoveToValidated(message_id)]);
                });

                let validation_context = ValidationContext {
                    time: UNIX_EPOCH,
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
                    time: UNIX_EPOCH,
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
                    .expiry_time(UNIX_EPOCH + MAX_INGRESS_TTL)
                    .build();
                let payload = IngressPayload::from(vec![ingress_msg1]);
                let ingress_validation = ingress_manager.validate_ingress_payload(
                    &payload,
                    &HashSet::new(),
                    &ValidationContext {
                        time: UNIX_EPOCH,
                        registry_version: RegistryVersion::from(1),
                        certified_height: Height::from(0),
                    },
                );
                assert_matches!(
                    ingress_validation,
                    Err(ValidationError::InvalidArtifact(
                        InvalidIngressPayloadReason::DuplicatedIngressMessage(_),
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
                    .expiry_time(UNIX_EPOCH + MAX_INGRESS_TTL)
                    .build();
                let payload = IngressPayload::from(vec![ingress_msg1]);
                let ingress_validation = ingress_manager.validate_ingress_payload(
                    &payload,
                    &HashSet::new(),
                    &ValidationContext {
                        time: UNIX_EPOCH,
                        registry_version: RegistryVersion::from(1),
                        certified_height: Height::from(0),
                    },
                );
                assert_matches!(
                    ingress_validation,
                    Err(ValidationError::ValidationFailed(IngressPayloadValidationFailure::IngressHistoryError(h1,
                            IngressHistoryError::StateNotAvailableYet(h2)
                    ))) if h1 == Height::from(0) && h2 == Height::from(0)
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
            .expiry_time(UNIX_EPOCH + MAX_INGRESS_TTL)
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
                            time: UNIX_EPOCH,
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
                    .expiry_time(UNIX_EPOCH + MAX_INGRESS_TTL)
                    .build();
                let message_id2 = IngressMessageId::from(&ingress_msg2);

                access_ingress_pool(&ingress_pool, |ingress_pool| {
                    ingress_pool.insert(UnvalidatedArtifact {
                        message: ingress_msg1.clone(),
                        peer_id: node_test_id(0),
                        timestamp: time_source.get_relative_time(),
                    });
                    ingress_pool.apply_changes(vec![ChangeAction::MoveToValidated(message_id1)]);
                    ingress_pool.insert(UnvalidatedArtifact {
                        message: ingress_msg2.clone(),
                        peer_id: node_test_id(0),
                        timestamp: time_source.get_relative_time(),
                    });
                    ingress_pool.apply_changes(vec![ChangeAction::MoveToValidated(message_id2)]);
                });

                let validation_context = ValidationContext {
                    time: UNIX_EPOCH,
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
                let time = expiry_time_from_now();
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
                        ValidationError::InvalidArtifact(
                            InvalidIngressPayloadReason::IngressValidationError(id, _),
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
        let time = UNIX_EPOCH;
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
                    .with_node_ids(
                        (1..=SMALL_APP_SUBNET_MAX_SIZE as u64)
                            .map(node_test_id)
                            .collect(),
                    )
                    .with_canister(
                        CanisterStateBuilder::default()
                            .with_canister_id(canister_test_id(0))
                            // Enough cycles to induct only m1
                            .with_cycles(
                                cycles_account_manager
                                    .ingress_induction_cost(
                                        m1.content(),
                                        None,
                                        SMALL_APP_SUBNET_MAX_SIZE,
                                    )
                                    .cost(),
                            )
                            .build(),
                    )
                    .with_canister(
                        CanisterStateBuilder::default()
                            .with_canister_id(canister_test_id(1))
                            // No cycles
                            .with_cycles(0u128)
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

                let ingress_messages = vec![m1.clone(), m2.clone(), m3, m4];

                for m in ingress_messages.iter() {
                    let message_id = IngressMessageId::from(m);
                    access_ingress_pool(&ingress_pool, |ingress_pool| {
                        ingress_pool.insert(UnvalidatedArtifact {
                            message: m.clone(),
                            peer_id: node_test_id(0),
                            timestamp: time_source.get_relative_time(),
                        });
                        ingress_pool
                            .apply_changes(vec![ChangeAction::MoveToValidated(message_id.clone())]);
                        // check that message is indeed in the pool
                        assert!(ingress_pool.get(&message_id).is_some());
                    });
                }

                let payload = ingress_manager.get_ingress_payload(
                    &HashSet::new(),
                    &validation_context,
                    MAX_SIZE_AS_NUM_BYTES,
                );
                assert_eq!(payload.message_count(), 1);
                let msgs: Vec<SignedIngress> = payload.try_into().unwrap();
                // either m1 or m2, could be random. But not both.
                assert!(msgs.contains(&m1) || msgs.contains(&m2));
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
                            .with_cycles(0u128)
                            .build(),
                    )
                    .build(),
            ),
            |ingress_manager, _| {
                let time = UNIX_EPOCH;
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
                        time: UNIX_EPOCH,
                        registry_version: RegistryVersion::from(1),
                        certified_height: Height::from(0),
                    },
                );
                assert_matches!(
                    ingress_validation,
                    Err(ValidationError::InvalidArtifact(
                        InvalidIngressPayloadReason::InsufficientCycles(_)
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
                let time = UNIX_EPOCH;
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
                        time: UNIX_EPOCH,
                        registry_version: RegistryVersion::from(1),
                        certified_height: Height::from(0),
                    },
                );
                assert_matches!(
                    ingress_validation,
                    Err(ValidationError::InvalidArtifact(
                        InvalidIngressPayloadReason::CanisterNotFound(_)
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
                let time = UNIX_EPOCH;
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
                                time: UNIX_EPOCH,
                                registry_version: RegistryVersion::from(1),
                                certified_height: Height::from(0),
                            },
                        ),
                        // Validation should fail since the canister that needs to pay for the
                        // message doesn't exist.
                        Err(ValidationError::InvalidArtifact(InvalidIngressPayloadReason::CanisterNotFound(canister_id)))
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
                let time = UNIX_EPOCH;
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
                                time: UNIX_EPOCH,
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
                            .with_cycles(0u128)
                            .build(),
                    )
                    .build(),
            ),
            |ingress_manager, _| {
                let time = UNIX_EPOCH;
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
                                time: UNIX_EPOCH,
                                registry_version: RegistryVersion::from(1),
                                certified_height: Height::from(0),
                            },
                        ),
                        // Validation should fail since the canister that needs to pay for the
                        // message doesn't have enough cycles.
                        Err(ValidationError::InvalidArtifact(InvalidIngressPayloadReason::InsufficientCycles(err)))
                            if err.canister_id == canister_test_id(2)
                    );
                }
            },
        );
    }

    /// Sets up the ingress manager with all the dependencies and validates the provided payload.
    fn payload_validation_test_case(
        payload: IngressPayload,
        past_ingress: HashSet<IngressMessageId>,
        validation_context: ValidationContext,
        ingress_history_response: Result<(), IngressHistoryError>,
        state_manager_response: StateManagerResult<ReplicatedState>,
    ) -> ValidationResult<IngressPayloadValidationError> {
        with_test_replica_logger(|log| {
            with_test_pool_config(|pool_config| {
                let mut ingress_hist_reader = MockIngressHistory::new();

                match ingress_history_response {
                    Ok(()) => ingress_hist_reader
                        .expect_get_status_at_height()
                        .returning(|_| Ok(Box::new(|_| IngressStatus::Unknown))),
                    Err(err) => ingress_hist_reader
                        .expect_get_status_at_height()
                        .returning(move |_| Err(err.clone())),
                };

                let subnet_id = subnet_test_id(0);
                let node_id = node_test_id(1);

                let registry = setup_registry(subnet_id, 60 * 1024 * 1024);

                let consensus_time = MockConsensusTime::new();

                let mut state_manager = MockStateManager::new();
                state_manager
                    .expect_get_state_at()
                    .return_const(state_manager_response.map(|response| {
                        ic_interfaces_state_manager::Labeled::new(
                            Height::new(0),
                            Arc::new(response),
                        )
                    }));

                let metrics_registry = MetricsRegistry::new();
                let ingress_signature_crypto =
                    Arc::new(temp_crypto_component_with_fake_registry(node_id));
                let cycles_account_manager = Arc::new(
                    CyclesAccountManagerBuilder::new()
                        .with_subnet_id(subnet_id)
                        .build(),
                );
                let ingress_pool = Arc::new(RwLock::new(IngressPoolImpl::new(
                    node_id,
                    pool_config,
                    metrics_registry.clone(),
                    log.clone(),
                )));
                let time_source = FastForwardTimeSource::new();
                time_source.set_time(UNIX_EPOCH).unwrap();
                let ingress_manager = IngressManager::new(
                    time_source,
                    Arc::new(consensus_time),
                    Box::new(ingress_hist_reader),
                    ingress_pool.clone(),
                    registry,
                    ingress_signature_crypto,
                    metrics_registry,
                    subnet_id,
                    log,
                    Arc::new(state_manager),
                    cycles_account_manager,
                    MaliciousFlags::default(),
                    RandomStateKind::Random,
                );

                ingress_manager.validate_ingress_payload(
                    &payload,
                    &past_ingress,
                    &validation_context,
                )
            })
        })
    }

    #[test]
    fn test_validate_empty_payload_succeeds() {
        let validation_result = payload_validation_test_case(
            IngressPayload::from(vec![]),
            HashSet::new(),
            ValidationContext {
                time: UNIX_EPOCH,
                registry_version: RegistryVersion::from(1),
                certified_height: Height::from(0),
            },
            /*history_reader_response=*/ Ok(()),
            /*state_manager_response=*/ Ok(ReplicatedStateBuilder::default().build()),
        );

        assert_eq!(validation_result, Ok(()),);
    }

    #[test]
    fn test_validate_history_error_results_in_failure() {
        let certified_height = Height::new(0);
        let error = IngressHistoryError::StateRemoved(Height::new(1));
        let validation_result = payload_validation_test_case(
            IngressPayload::from(vec![]),
            HashSet::new(),
            ValidationContext {
                time: UNIX_EPOCH,
                registry_version: RegistryVersion::from(1),
                certified_height,
            },
            /*history_reader_response=*/ Err(error.clone()),
            /*state_manager_response=*/ Ok(ReplicatedStateBuilder::default().build()),
        );

        assert_eq!(
            validation_result,
            Err(IngressPayloadValidationError::ValidationFailed(
                IngressPayloadValidationFailure::IngressHistoryError(certified_height, error,)
            ))
        );
    }

    #[test]
    fn test_validate_state_manager_error_results_in_failure() {
        let certified_height = Height::new(0);
        let error = StateManagerError::StateNotCommittedYet(Height::new(1));
        let validation_result = payload_validation_test_case(
            IngressPayload::from(vec![]),
            HashSet::new(),
            ValidationContext {
                time: UNIX_EPOCH,
                registry_version: RegistryVersion::from(1),
                certified_height,
            },
            /*history_reader_response=*/ Ok(()),
            /*state_manager_response=*/ Err(error.clone()),
        );

        assert_eq!(
            validation_result,
            Err(IngressPayloadValidationError::ValidationFailed(
                IngressPayloadValidationFailure::StateManagerError(certified_height, error,)
            ))
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
                let time = UNIX_EPOCH;
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
                                time: UNIX_EPOCH,
                                registry_version: RegistryVersion::from(1),
                                certified_height: Height::from(0),
                            },
                        ),
                        // Validation should fail since the canister that needs to pay for the
                        // message doesn't have enough cycles.
                        Err(ValidationError::InvalidArtifact(
                            InvalidIngressPayloadReason::InvalidManagementMessage
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
                                time: UNIX_EPOCH,
                                registry_version: RegistryVersion::from(1),
                                certified_height: Height::from(0),
                            },
                        ),
                        // Validation should fail since the canister that needs to pay for the
                        // message doesn't have enough cycles.
                        Err(ValidationError::InvalidArtifact(
                            InvalidIngressPayloadReason::InvalidManagementMessage
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
                    .expiry_time(UNIX_EPOCH)
                    .build();

                let msg_id = IngressMessageId::from(&msg);
                let _payload = IngressPayload::from(vec![msg.clone()]);

                ingress_pool.write().unwrap().insert(UnvalidatedArtifact {
                    message: msg,
                    peer_id: node_test_id(0),
                    timestamp: UNIX_EPOCH,
                });
                ingress_pool
                    .write()
                    .unwrap()
                    .apply_changes(vec![ChangeAction::MoveToValidated(msg_id)]);

                let validation_context = ValidationContext {
                    registry_version: RegistryVersion::new(1),
                    certified_height: Height::new(0),
                    time: UNIX_EPOCH,
                };

                let _payload = ingress_manager.get_ingress_payload(
                    &HashSet::new(),
                    &validation_context,
                    NumBytes::new(MAX_SIZE as u64),
                );
            },
        );
    }

    fn insert_unvalidated_ingress_with_timestamp(
        msgs: Vec<SignedIngress>,
        pool: &Arc<RwLock<IngressPoolImpl>>,
        timestamp: Time,
    ) {
        for m in msgs.iter() {
            let message_id = IngressMessageId::from(m);
            access_ingress_pool(pool, |ingress_pool| {
                ingress_pool.insert(UnvalidatedArtifact {
                    message: m.clone(),
                    peer_id: node_test_id(0),
                    timestamp,
                });
                ingress_pool.apply_changes(vec![ChangeAction::MoveToValidated(message_id.clone())]);
                // check that message is indeed in the pool
                assert!(ingress_pool.get(&message_id).is_some());
            });
        }
    }

    /// Generates a list of ingress messages with given parameters, and 500 billion cycles
    fn generate_ingress_with_params(
        cid: CanisterId,
        msg_count: usize,
        bytes: usize,
        expiry: Time,
    ) -> (Vec<SignedIngress>, CanisterState) {
        let msgs: Vec<_> = (0..msg_count)
            .map(|_| {
                SignedIngressBuilder::new()
                    .canister_id(cid)
                    .expiry_time(expiry)
                    .nonce(rand::thread_rng().next_u64())
                    .method_payload(vec![0xff; bytes])
                    .build()
            })
            .collect();

        (
            msgs,
            CanisterStateBuilder::default()
                .with_canister_id(cid)
                .with_cycles(Cycles::new(500_000_000_000))
                .build(),
        )
    }

    #[tokio::test]
    async fn test_ordering_fairness() {
        const MAX_SIZE: usize = 300 * 30; // initial quota: 300 bytes per canister
        let subnet_id = subnet_test_id(0);
        let registry = setup_registry(subnet_id, MAX_SIZE);
        let time = UNIX_EPOCH;

        let (messages_0, canister_0) = generate_ingress_with_params(
            canister_test_id(0),
            /* msg_count = */ 10,
            /* bytes = */ 900,
            time + Duration::from_secs(40),
        );
        let mut small_payloads = vec![(messages_0, canister_0)];

        for canister_id in (1..3).map(canister_test_id) {
            let (m, c) = generate_ingress_with_params(
                canister_id,
                /* msg_count = */ 2,
                /* bytes = */ 246,
                time + Duration::from_secs(10),
            );
            small_payloads.push((m, c))
        }
        small_payloads.push(generate_ingress_with_params(
            canister_test_id(1),
            /* msg_count = */ 1,
            /* bytes = */ 246,
            time + Duration::from_secs(25),
        ));
        small_payloads.push(generate_ingress_with_params(
            canister_test_id(2),
            /* msg_count = */ 1,
            /* bytes = */ 446,
            time + Duration::from_secs(35),
        ));

        // small ingress messages that fall below quota, to generate surplus that
        // is later dispersed amongst the first three canisters.
        for canister_id in (3..30).map(canister_test_id) {
            small_payloads.push(generate_ingress_with_params(
                canister_id,
                /* msg_count = */ 1,
                /* bytes = */ 1,
                time + Duration::from_secs(30),
            ))
        }

        let mut replicated_state = ReplicatedStateBuilder::new().with_subnet_id(subnet_id);
        for p in small_payloads.iter() {
            replicated_state = replicated_state.with_canister(p.1.clone());
        }

        setup_with_params(
            None,
            Some((registry, subnet_id)),
            None,
            Some(replicated_state.build()),
            |ingress_manager, ingress_pool| {
                let validation_context = ValidationContext {
                    time,
                    registry_version: RegistryVersion::from(1),
                    certified_height: Height::from(0),
                };
                for p in small_payloads.into_iter() {
                    let timestamp = p.0[0].expiry_time();
                    insert_unvalidated_ingress_with_timestamp(p.0, &ingress_pool, timestamp);
                }
                let payload = ingress_manager.get_ingress_payload(
                    &HashSet::new(),
                    &validation_context,
                    NumBytes::new(MAX_SIZE as u64),
                );
                let msgs: Vec<SignedIngress> = payload.try_into().unwrap();

                assert_eq!(
                    2,
                    msgs.iter()
                        .filter(|m| m.canister_id() == canister_test_id(0))
                        .count()
                );
                assert_eq!(
                    3,
                    msgs.iter()
                        .filter(|m| m.canister_id() == canister_test_id(1))
                        .count()
                );
                // Greater-equals, because we can't rely on the order in which canisters
                // are iterated over. If the canister_id(0) is earlier in the iteration
                // order, we'll include 2 messages from canister_id(2) - otherwise it's 3.
                assert!(
                    msgs.iter()
                        .filter(|m| m.canister_id() == canister_test_id(2))
                        .count()
                        >= 2
                );
            },
        )
    }
    #[tokio::test]
    async fn test_not_stuck() {
        const MSG_SIZE: usize = 154;
        const CANISTER_COUNT: usize = MSG_SIZE + 1;
        const MAX_SIZE: usize = MSG_SIZE * (CANISTER_COUNT + 1);
        let subnet_id = subnet_test_id(0);
        let registry = setup_registry(subnet_id, MAX_SIZE);
        let time = UNIX_EPOCH;

        let mut small_payloads = Vec::new();

        for i in 0..CANISTER_COUNT {
            let (messages_0, canister_0) = generate_ingress_with_params(
                canister_test_id(i as u64),
                /* msg_count = */ 10,
                /* bytes = */ 1,
                time + Duration::from_secs(40),
            );

            small_payloads.push((messages_0, canister_0));
        }

        let mut replicated_state = ReplicatedStateBuilder::new().with_subnet_id(subnet_id);
        for p in small_payloads.iter() {
            replicated_state = replicated_state.with_canister(p.1.clone());
        }

        setup_with_params(
            None,
            Some((registry, subnet_id)),
            None,
            Some(replicated_state.build()),
            |ingress_manager, ingress_pool| {
                let validation_context = ValidationContext {
                    time,
                    registry_version: RegistryVersion::from(1),
                    certified_height: Height::from(0),
                };
                for p in small_payloads.into_iter() {
                    let timestamp = p.0[0].expiry_time();
                    insert_unvalidated_ingress_with_timestamp(p.0, &ingress_pool, timestamp);
                }
                // This should not get stuck. If it does, the ingress selector has a bug.
                ingress_manager.get_ingress_payload(
                    &HashSet::new(),
                    &validation_context,
                    NumBytes::new(MAX_SIZE as u64),
                );
            },
        )
    }
}
