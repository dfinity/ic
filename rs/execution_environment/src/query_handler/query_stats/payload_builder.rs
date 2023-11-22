use crossbeam_channel::{Receiver, TryRecvError};
use ic_base_types::{CanisterId, NodeId};
use ic_interfaces::{
    batch_payload::{BatchPayloadBuilder, PastPayload, ProposalContext},
    consensus::{PayloadTransientError, PayloadValidationError},
    query_stats::QueryStatsTransientValidationError,
    validation::ValidationError,
};
use ic_interfaces_state_manager::StateReader;
use ic_logger::{warn, ReplicaLogger};
use ic_replicated_state::ReplicatedState;
use ic_types::{
    batch::{LocalQueryStats, QueryStatsPayload, ValidationContext, ENABLE_QUERY_STATS},
    Height, NumBytes, QueryStatsEpoch,
};
use std::{
    collections::BTreeSet,
    sync::{Arc, RwLock},
};

/// The parameters for the payload builder that are handed over by the execution
/// environment during initialization.
///
/// We initialize the [`QueryStatsPayloadBuilder`] in two steps, because otherwise
/// we would have to pass consensus related arguments (like the [`NodeId`]) to the
/// execution environment.
pub struct QueryStatsPayloadBuilderParams(pub(crate) Receiver<LocalQueryStats>);

impl QueryStatsPayloadBuilderParams {
    pub fn into_payload_builder(
        self,
        state_reader: Arc<dyn StateReader<State = ReplicatedState>>,
        node_id: NodeId,
        log: ReplicaLogger,
    ) -> Box<dyn BatchPayloadBuilder> {
        Box::new(QueryStatsPayloadBuilderImpl {
            state_reader,
            node_id,
            log,
            current_stats: RwLock::new(None),
            receiver: self.0,
        })
    }
}

pub struct QueryStatsPayloadBuilderImpl {
    state_reader: Arc<dyn StateReader<State = ReplicatedState>>,
    node_id: NodeId,
    log: ReplicaLogger,
    current_stats: RwLock<Option<LocalQueryStats>>,
    receiver: Receiver<LocalQueryStats>,
}

impl BatchPayloadBuilder for QueryStatsPayloadBuilderImpl {
    fn build_payload(
        &self,
        height: Height,
        max_size: NumBytes,
        past_payloads: &[PastPayload],
        context: &ValidationContext,
    ) -> Vec<u8> {
        match self.receiver.try_recv() {
            Ok(new_epoch) => {
                let Ok(mut epoch) = self.current_stats.write() else {
                    return vec![];
                };
                *epoch = Some(new_epoch);
            }
            Err(TryRecvError::Empty) => (),
            Err(TryRecvError::Disconnected) => {
                warn!(
                    every_n_seconds => 5,
                    self.log,
                    "QueryStatsCollector has been dropped. This is a bug"
                );
            }
        }

        match ENABLE_QUERY_STATS {
            true => self.build_payload_impl(height, max_size, past_payloads, context),
            false => vec![],
        }
    }

    fn validate_payload(
        &self,
        height: Height,
        proposal_context: &ProposalContext,
        payload: &[u8],
        past_payloads: &[PastPayload],
    ) -> Result<(), PayloadValidationError> {
        // Empty payloads are always valid
        if payload.is_empty() {
            return Ok(());
        }

        // Check whether feature is enabled and reject if it isn't.
        // NOTE: All payloads that are processed at this point are non-empty
        if !ENABLE_QUERY_STATS {
            return transient_error(QueryStatsTransientValidationError::Disabled);
        }

        self.validate_payload_impl(
            height,
            payload,
            past_payloads,
            proposal_context.validation_context,
        )
    }
}

impl QueryStatsPayloadBuilderImpl {
    fn build_payload_impl(
        &self,
        _height: Height,
        max_size: NumBytes,
        past_payloads: &[PastPayload],
        context: &ValidationContext,
    ) -> Vec<u8> {
        let Ok(current_stats) = self.current_stats.read() else {
            return vec![];
        };
        let current_stats = match current_stats.as_ref() {
            Some(stats) => stats,
            // TODO: Log this case
            None => return vec![],
        };

        let Some(previous_ids) = self.get_previous_ids(current_stats.epoch, past_payloads, context)
        else {
            return vec![];
        };

        // Pick all stats that have not been sent before
        let messages = current_stats
            .stats
            .iter()
            .filter(|stats| !previous_ids.contains(&stats.canister_id))
            .cloned()
            .collect();

        let payload = QueryStatsPayload {
            epoch: current_stats.epoch,
            proposer: self.node_id,
            stats: messages,
        };

        // Serialize the payload, drop messages at the end if necessary
        payload.serialize_with_limit(max_size)
    }

    fn validate_payload_impl(
        &self,
        _height: Height,
        _payload: &[u8],
        _past_payloads: &[PastPayload],
        _context: &ValidationContext,
    ) -> Result<(), PayloadValidationError> {
        // TODO(CON-1142): Check that the payload actually deserializes
        // TODO(CON-1142): Check that nodeid is actually in subnet
        // (Should this only be done during delivery?)
        // TODO(CON-1142): Check epoch (strictly higher then epoch in state, lower)
        // TODO(CON-1142): Check that payload does not contain previous ids (Needed?)
        Ok(())
    }
    fn get_previous_ids(
        &self,
        current_epoch: QueryStatsEpoch,
        past_payloads: &[PastPayload],
        context: &ValidationContext,
    ) -> Option<BTreeSet<CanisterId>> {
        // Get unaggregated stats from certified state
        let certified_height = context.certified_height;
        let state_stats = &match self.state_reader.get_state_at(certified_height) {
            Ok(state) => state,
            Err(err) => {
                warn!(
                    every_n_seconds => 5,
                    self.log,
                    "StateManager doesn't have state for height {}: {:?}", certified_height, err
                );

                return None;
            }
        }
        .take()
        .epoch_query_stats;
        // The query stats can be sent over multiple payloads
        // To not resend the same stats twice, we need to filter out the canister ids
        // we have already sent. It is imporant to only filter against canister ids if
        // the stats are not of a previous epoch
        let mut previous_ids = BTreeSet::<CanisterId>::new();

        // Check the certified state for stats already sent
        // Skip if certified state is not the same epoch
        if state_stats.epoch == Some(current_epoch) {
            previous_ids.extend(
                state_stats
                    .stats
                    .iter()
                    .filter(|(_, stat_map)| stat_map.contains_key(&self.node_id))
                    .map(|(canister_id, _)| canister_id),
            );
        }

        // Check past payloads for stats already sent
        previous_ids.extend(
            past_payloads
                .iter()
                // Deserialize the payload
                .filter_map(|past_payload| {
                    QueryStatsPayload::deserialize(past_payload.payload)
                        // TODO: Log error
                        .ok()
                        .flatten()
                })
                // Filter out payloads that have a different epoch or are sent from different node
                .filter(|stats| stats.epoch == current_epoch && stats.proposer == self.node_id)
                // Map payload to CanisterIds
                .flat_map(|stats| {
                    stats
                        .stats
                        .iter()
                        .map(|stat| stat.canister_id)
                        .collect::<Vec<CanisterId>>()
                }),
        );

        Some(previous_ids)
    }
}

fn transient_error(err: QueryStatsTransientValidationError) -> Result<(), PayloadValidationError> {
    Err(ValidationError::Transient(
        PayloadTransientError::QueryStatsPayloadValidationError(err),
    ))
}
#[cfg(test)]
mod tests {
    use super::*;
    use ic_interfaces_state_manager_mocks::MockStateManager;
    use ic_logger::replica_logger::no_op_logger;
    use ic_test_utilities::{mock_time, state::ReplicatedStateBuilder};
    use ic_types::{
        batch::{CanisterQueryStats, QueryStats, RawQueryStats},
        crypto::{CryptoHash, CryptoHashOf},
        RegistryVersion,
    };
    use ic_types_test_utils::ids::{canister_test_id, node_test_id};
    use std::{ops::Range, time::Duration};

    const MAX_PAYLOAD_SIZE: NumBytes = NumBytes::new(1024 * 1024);

    /// Test simple inclusion of a stat
    ///
    /// - Put statistics of one canister into `current_stats`  
    /// - Build a payload
    /// - Check that the statistic is in the build payload
    #[test]
    fn query_stats_inclusion_test() {
        let test_stats = test_epoch_stats(1, 1);
        let state = test_state(RawQueryStats::default());
        let payload_builder = setup_payload_builder_impl(state, test_stats);

        let context = ValidationContext {
            registry_version: RegistryVersion::new(0),
            certified_height: Height::new(0),
            time: mock_time(),
        };

        let (payload, serialized_payload) = build_and_validate(
            &payload_builder,
            Height::new(1),
            MAX_PAYLOAD_SIZE,
            &[],
            &context,
        );

        assert!(!serialized_payload.is_empty());
        assert_eq!(payload.proposer, node_test_id(1));
        assert_eq!(payload.epoch, QueryStatsEpoch::new(1));
        assert_eq!(payload.stats.len(), 1);
    }

    /// Test that the payload builder respects the size limit and does not
    /// include more stats if it does not fit
    ///
    /// - Put 1000 statistics into `current_stats`
    /// - Build a payload that can only be 2000 bytes large
    /// - Check that payload is in fact smaller than 2000 bytes
    /// - Check that less than 1000 statistics have been included
    #[test]
    fn size_limit_test() {
        let test_stats = test_epoch_stats(1, 1000);
        let state = test_state(RawQueryStats::default());
        let payload_builder = setup_payload_builder_impl(state, test_stats);

        let context = ValidationContext {
            registry_version: RegistryVersion::new(0),
            certified_height: Height::new(0),
            time: mock_time(),
        };

        let (payload, serialized_payload) = build_and_validate(
            &payload_builder,
            Height::new(1),
            NumBytes::new(2000),
            &[],
            &context,
        );

        assert!(!serialized_payload.is_empty());
        assert!(serialized_payload.len() < 2000);
        assert_eq!(payload.proposer, node_test_id(1));
        assert_eq!(payload.epoch, QueryStatsEpoch::new(1));
        assert!(payload.stats.len() < 1000);
    }

    /// Test that ids already in state or in past payload will not be included
    ///
    /// - Build [`LocalQueryStats`] with 500 entries
    /// - Put first 200 entries into the state
    /// - Put the next 100 into `past_payloads`
    /// - Put the next 100 into another `past_payloads`
    /// - Build a payload
    /// - Check that it only includes the last 100 entries
    #[test]
    fn past_payload_test() {
        let test_stats = test_epoch_stats(1, 500);
        let state = test_state(epoch_stats_for_state(&test_stats, 0..200, node_test_id(1)));
        let payload_builder = setup_payload_builder_impl(state, test_stats.clone());

        let past_payload1 = payload_from_range(&test_stats, 200..300, node_test_id(1));
        let past_payload1 = as_past_payload(&past_payload1, 1);

        let past_payload2 = payload_from_range(&test_stats, 300..400, node_test_id(1));
        let past_payload2 = as_past_payload(&past_payload2, 2);

        let context = ValidationContext {
            registry_version: RegistryVersion::new(0),
            certified_height: Height::new(0),
            time: mock_time(),
        };

        let (payload, serialized_payload) = build_and_validate(
            &payload_builder,
            Height::new(3),
            MAX_PAYLOAD_SIZE,
            &[past_payload2, past_payload1],
            &context,
        );

        assert!(!serialized_payload.is_empty());
        assert_eq!(payload.proposer, node_test_id(1));
        assert_eq!(payload.epoch, QueryStatsEpoch::new(1));
        assert!(payload.stats.len() == 100);
        for stat_idx in 0..100 {
            assert_eq!(payload.stats[stat_idx], test_stats.stats[stat_idx + 400]);
        }
    }

    /// Test that the payload builder checks that past_payloads and staticstics in
    /// the state which are only excluded when they are from the same node id.
    ///
    /// - Build [`LocalQueryStats`] with 500 entries
    /// - Put first 100 entries into the state as own node id
    /// - Put next 100 entries into the state as foreign node id
    /// - Put the next 100 into `past_payloads` as own node id
    /// - Put the next 100 into another `past_payloads` as foreign id
    /// - Build a payload
    /// - Check that it includes the entries 100 to 200, 300 to 500
    #[test]
    fn test_node_id_check() {
        let test_stats = test_epoch_stats(1, 500);

        let stats1 = epoch_stats_for_state(&test_stats, 0..100, node_test_id(1));
        let stats2 = epoch_stats_for_state(&test_stats, 100..200, node_test_id(2));
        let stats = merge_raw_query_stats(stats1, stats2);
        let state = test_state(stats);

        let payload_builder = setup_payload_builder_impl(state, test_stats.clone());

        let past_payload1 = payload_from_range(&test_stats, 200..300, node_test_id(1));
        let past_payload1 = as_past_payload(&past_payload1, 1);

        let past_payload2 = payload_from_range(&test_stats, 300..400, node_test_id(2));
        let past_payload2 = as_past_payload(&past_payload2, 2);

        let context = ValidationContext {
            registry_version: RegistryVersion::new(0),
            certified_height: Height::new(0),
            time: mock_time(),
        };

        let (payload, serialized_payload) = build_and_validate(
            &payload_builder,
            Height::new(3),
            MAX_PAYLOAD_SIZE,
            &[past_payload2, past_payload1],
            &context,
        );

        assert!(!serialized_payload.is_empty());
        assert_eq!(payload.proposer, node_test_id(1));
        assert_eq!(payload.epoch, QueryStatsEpoch::new(1));

        assert!(payload.stats.len() == 300);

        for stat_idx in 0..100 {
            assert_eq!(payload.stats[stat_idx], test_stats.stats[stat_idx + 100]);
        }
        for stat_idx in 100..300 {
            assert_eq!(payload.stats[stat_idx], test_stats.stats[stat_idx + 200]);
        }
    }

    fn build_and_validate(
        payload_builder: &QueryStatsPayloadBuilderImpl,
        height: Height,
        max_size: NumBytes,
        past_payloads: &[PastPayload],
        context: &ValidationContext,
    ) -> (QueryStatsPayload, Vec<u8>) {
        let payload = payload_builder.build_payload_impl(height, max_size, past_payloads, context);
        assert!(payload_builder
            .validate_payload_impl(height, &payload, past_payloads, context)
            .is_ok());

        (
            QueryStatsPayload::deserialize(&payload).unwrap().unwrap(),
            payload,
        )
    }

    /// Set up a payload builder for testing with the supplied internal state
    fn setup_payload_builder_impl(
        state: MockStateManager,
        stats: LocalQueryStats,
    ) -> QueryStatsPayloadBuilderImpl {
        let (_, rx) = crossbeam_channel::bounded(1);
        QueryStatsPayloadBuilderImpl {
            state_reader: Arc::new(state),
            node_id: node_test_id(1),
            log: no_op_logger(),
            current_stats: Some(stats).into(),
            receiver: rx,
        }
    }

    /// Generate some statistics for testing
    fn test_epoch_stats(epoch: u64, num_stats: u64) -> LocalQueryStats {
        LocalQueryStats {
            epoch: QueryStatsEpoch::new(epoch),
            stats: (0..num_stats)
                .map(|id| CanisterQueryStats {
                    canister_id: canister_test_id(id),
                    stats: QueryStats {
                        num_calls: 1,
                        num_instructions: 1000,
                        ingress_payload_size: 1000,
                        egress_payload_size: 1000,
                    },
                })
                .collect(),
        }
    }

    fn epoch_stats_for_state(
        query_stats: &LocalQueryStats,
        range: Range<usize>,
        node: NodeId,
    ) -> RawQueryStats {
        RawQueryStats {
            epoch: Some(query_stats.epoch),
            stats: query_stats.stats[range]
                .iter()
                .map(|stat| {
                    (
                        stat.canister_id,
                        [(node, stat.stats.clone())].into_iter().collect(),
                    )
                })
                .collect(),
        }
    }

    fn merge_raw_query_stats(mut stats1: RawQueryStats, stats2: RawQueryStats) -> RawQueryStats {
        assert_eq!(stats1.epoch, stats2.epoch);

        for (canister_id, stat2) in stats2.stats {
            stats1
                .stats
                .entry(canister_id)
                // NOTE: This assumes that there are no nodeids identical in stats1 and stats2
                .and_modify(|entry| entry.extend(stat2.clone().into_iter()))
                .or_insert(stat2);
        }

        stats1
    }

    fn payload_from_range(
        query_stats: &LocalQueryStats,
        range: Range<usize>,
        node: NodeId,
    ) -> Vec<u8> {
        let past_payload = QueryStatsPayload {
            epoch: query_stats.epoch,
            proposer: node,
            stats: query_stats.stats[range].to_vec(),
        };
        past_payload.serialize_with_limit(MAX_PAYLOAD_SIZE)
    }

    fn as_past_payload(payload: &[u8], height: u64) -> PastPayload {
        PastPayload {
            height: Height::from(height),
            time: mock_time() + Duration::from_nanos(10 * height),
            block_hash: CryptoHashOf::from(CryptoHash(vec![])),
            payload,
        }
    }

    /// Generate some test state which has some predetermined statisticss
    fn test_state(query_stats: RawQueryStats) -> MockStateManager {
        let mut state_manager = MockStateManager::new();
        state_manager.expect_get_state_at().return_const(Ok(
            ic_interfaces_state_manager::Labeled::new(
                Height::new(0),
                Arc::new(
                    ReplicatedStateBuilder::new()
                        .with_query_stats(query_stats)
                        .build(),
                ),
            ),
        ));
        state_manager
    }
}
