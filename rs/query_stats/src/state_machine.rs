use ic_logger::{error, info, ReplicaLogger};
use ic_replicated_state::ReplicatedState;
use ic_types::{
    batch::{QueryStats, QueryStatsPayload, RawQueryStats},
    consensus::get_faults_tolerated,
    epoch_from_height, CanisterId, Height,
};
use std::collections::BTreeMap;

use crate::metrics::QueryStatsAggregatorMetrics;

/// Aggregate given query stats
///
/// Aggregation needs to be deterministic and needs to be able to tolerate malicious nodes over- or under-reporting charges.
/// Since we know we have a random distribution of queries to nodes, we do the aggregation as follows:
///
/// - Aggregate only stats from more than 2/3 nodes have sent query stats.
/// - Take the median: this ensure we choose a value that has been reported either by an honest node, or
///   the value is close to those of honest nodes.
///
/// This function does not check the first property. This has to be done by the caller.
fn aggregate_query_stats(stats: Vec<&QueryStats>) -> QueryStats {
    fn get_median<T: Default + Ord + Copy, F>(stats: &Vec<&QueryStats>, f: F) -> T
    where
        F: FnMut(&&QueryStats) -> T,
    {
        let mut values: Vec<T> = stats.iter().map(f).collect();
        values.sort();
        values.get(stats.len() / 2).cloned().unwrap_or(T::default())
    }

    // Take the median for each of the values in stats
    QueryStats {
        num_calls: get_median(&stats, |stats| stats.num_calls),
        num_instructions: get_median(&stats, |stats| stats.num_instructions),
        ingress_payload_size: get_median(&stats, |stats| stats.ingress_payload_size),
        egress_payload_size: get_median(&stats, |stats| stats.egress_payload_size),
    }
}

/// Aggregate given query stats and into each canister's state.
fn apply_query_stats_to_canister(
    aggregated_stats: &QueryStats,
    canister_id: CanisterId,
    state: &mut ReplicatedState,
    logger: &ReplicaLogger,
) {
    // Note that the use of the number of nodes in the subnet like this does not handle the case that
    // the number of machines in the subnet might have changed throughout an epoch.
    // Given that subnet topology changes are an infrequent event, we tolerate this occasional inaccuracy here.
    let num_nodes_in_subnet = state.system_metadata().node_public_keys.len() as u128;
    if let Some(canister_state) = state.canister_state_mut(&canister_id) {
        let canister_query_stats = &mut canister_state.scheduler_state.total_query_stats;
        canister_query_stats.num_calls += aggregated_stats.num_calls as u128 * num_nodes_in_subnet;
        canister_query_stats.num_instructions +=
            aggregated_stats.num_instructions as u128 * num_nodes_in_subnet;
        canister_query_stats.ingress_payload_size +=
            aggregated_stats.ingress_payload_size as u128 * num_nodes_in_subnet;
        canister_query_stats.egress_payload_size +=
            aggregated_stats.egress_payload_size as u128 * num_nodes_in_subnet;
    } else {
        info!(
            logger,
            "Received query stats for a canister {} which does not exist.", canister_id,
        );
    }
}

/// Add the epoch stats of the current round to the metadata
/// and on a new epoch aggregate currently stored stats into
/// the canister query stats.
pub fn deliver_query_stats(
    query_stats: &QueryStatsPayload,
    state: &mut ReplicatedState,
    height: Height,
    logger: &ReplicaLogger,
    epoch_length: u64,
    metrics: &QueryStatsAggregatorMetrics,
) {
    let epoch = epoch_from_height(height, epoch_length);

    // If current epoch doesn't match the epoch we received
    if Some(epoch) != state.epoch_query_stats.epoch {
        if let Some(state_epoch) = state.epoch_query_stats.epoch {
            if state_epoch.get() + 1 == epoch.get() {
                // Determine number of nodes in subnet
                if let Some(num_nodes) = state
                    .system_metadata()
                    .network_topology
                    .get_subnet_size(&state.metadata.own_subnet_id)
                {
                    // We first aggregate to a temporary data structure, so that we can release the borrow on the state
                    let mut query_stats_to_be_applied = vec![];
                    for (canister_id, inner) in &state.epoch_query_stats.stats {
                        // Aggregate node statistics only if we have received query stats from this canister from enough nodes.
                        // Otherwise malicious nodes could have a large impact on the choosen value.
                        let need_stats_from = num_nodes - get_faults_tolerated(num_nodes);
                        if inner.len() >= need_stats_from {
                            // Aggregate data
                            let individual_stats: Vec<&QueryStats> =
                                inner.iter().map(|(_, stats)| stats).collect();

                            let aggregated_stats = aggregate_query_stats(individual_stats);
                            query_stats_to_be_applied.push((*canister_id, aggregated_stats));
                        }
                    }

                    // For each canister, apply the aggregated stats
                    for (canister_id, aggregated_stats) in query_stats_to_be_applied {
                        apply_query_stats_to_canister(
                            &aggregated_stats,
                            canister_id,
                            state,
                            logger,
                        );
                    }
                }
            }
        }

        metrics
            .query_stats_aggregator_current_epoch
            .set(epoch.get() as i64);

        state.epoch_query_stats = RawQueryStats {
            epoch: Some(epoch),
            stats: BTreeMap::new(),
        };
    }

    let epoch_query_stats = &mut state.epoch_query_stats;
    for message in &query_stats.stats {
        let previous_value = epoch_query_stats
            .stats
            .entry(message.canister_id)
            .or_default()
            .insert(
                query_stats.proposer,
                QueryStats {
                    num_calls: message.stats.num_calls,
                    num_instructions: message.stats.num_instructions,
                    ingress_payload_size: message.stats.ingress_payload_size,
                    egress_payload_size: message.stats.egress_payload_size,
                },
            );
        if previous_value.is_some() {
            error!(
                    logger,
                    "Received duplicate query stats for canister {} from same proposer {}. This is a bug, possibly in the payload builder.",
                    message.canister_id, query_stats.proposer
                );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ic_interfaces_state_manager::StateManager;
    use ic_logger::replica_logger::no_op_logger;
    use ic_test_utilities::state_manager::FakeStateManager;
    use ic_types::{batch::CanisterQueryStats, NodeId, PrincipalId, QueryStatsEpoch};
    use ic_types_test_utils::ids::canister_test_id;

    /// Tests that we correctly collect temporary query stats in the replicated state throughout an epoch.
    #[test]
    pub fn test_query_stats() {
        let test_canister_stats = QueryStats {
            num_calls: 1,
            num_instructions: 2,
            ingress_payload_size: 3,
            egress_payload_size: 4,
        };
        let uninstalled_canister = canister_test_id(1);
        let proposer = NodeId::from(PrincipalId::new_node_test_id(1));
        let query_stats = QueryStatsPayload {
            epoch: QueryStatsEpoch::from(1),
            proposer,
            stats: vec![CanisterQueryStats {
                canister_id: uninstalled_canister,
                stats: test_canister_stats.clone(),
            }],
        };

        let (_, mut state) = FakeStateManager::new().take_tip();
        let epoch_length = ic_config::execution_environment::QUERY_STATS_EPOCH_LENGTH;
        deliver_query_stats(
            &query_stats,
            &mut state,
            Height::new(1),
            &no_op_logger(),
            epoch_length,
            &QueryStatsAggregatorMetrics::new(&ic_metrics::MetricsRegistry::new()),
        );

        // Check that query stats are added to replicated state.
        assert!(state.epoch_query_stats.epoch.is_some());
        assert!(state
            .epoch_query_stats
            .stats
            .contains_key(&uninstalled_canister));
        assert_eq!(
            state
                .epoch_query_stats
                .stats
                .get(&uninstalled_canister)
                .unwrap()
                .get(&proposer)
                .unwrap(),
            &test_canister_stats
        );
    }
}
