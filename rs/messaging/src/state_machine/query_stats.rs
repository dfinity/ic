use ic_base_types::CanisterId;
use ic_logger::{error, info, ReplicaLogger};
use ic_replicated_state::ReplicatedState;
use ic_types::batch::{CanisterQueryStats, EpochStatsMessages, ReceivedEpochStats};
use ic_types::{epoch_from_height, Height};
use std::collections::BTreeMap;

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
fn aggregate_canister_query_stats(stats: Vec<&CanisterQueryStats>) -> CanisterQueryStats {
    fn get_median<T: Default + Ord + Copy, F>(stats: &Vec<&CanisterQueryStats>, f: F) -> T
    where
        F: FnMut(&&CanisterQueryStats) -> T,
    {
        let mut values: Vec<T> = stats.iter().map(f).collect();
        values.sort();
        values.get(stats.len() / 2).cloned().unwrap_or(T::default())
    }

    // Take the median for each of the values in stats
    CanisterQueryStats {
        num_calls: get_median(&stats, |stats| stats.num_calls),
        num_instructions: get_median(&stats, |stats| stats.num_instructions),
        ingress_payload_size: get_median(&stats, |stats| stats.ingress_payload_size),
        egress_payload_size: get_median(&stats, |stats| stats.egress_payload_size),
    }
}

/// Aggregate given query stats and into each canister's state.
fn apply_query_stats_to_canister(
    logger: &ReplicaLogger,
    canister_id: CanisterId,
    aggregated_stats: &CanisterQueryStats,
    state: &mut ReplicatedState,
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
    logger: &ReplicaLogger,
    query_stats: &EpochStatsMessages,
    state: &mut ReplicatedState,
    height: Height,
) {
    let epoch = epoch_from_height(height);

    // If current epoch doesn't match the epoch we received
    if Some(epoch) != state.epoch_query_stats.epoch {
        if let Some(state_epoch) = state.epoch_query_stats.epoch {
            if state_epoch.get() + 1 == epoch.get() {
                let num_nodes = state.system_metadata().node_public_keys.len();

                // We first aggregate to a temporary data structure, so that we can release the borrow on the state
                let mut query_stats_to_be_applied = vec![];
                for (canister_id, inner) in &state.epoch_query_stats.stats {
                    // Aggregate node statistics only if we have received query stats from this canister from enough nodes.
                    // Otherwise malicious nodes could have a large impact on the choosen value.
                    if inner.len() > (num_nodes as f32 / 3. * 2. + 1.).ceil() as usize {
                        // Aggregate data
                        let individual_stats: Vec<&CanisterQueryStats> =
                            inner.iter().map(|(_, stats)| stats).collect();

                        let aggregated_stats = aggregate_canister_query_stats(individual_stats);
                        query_stats_to_be_applied.push((*canister_id, aggregated_stats));
                    }
                }

                // For each canister, apply the aggregated stats
                for (canister_id, aggregated_stats) in query_stats_to_be_applied {
                    apply_query_stats_to_canister(logger, canister_id, &aggregated_stats, state);
                }
            }
        }

        state.epoch_query_stats = ReceivedEpochStats {
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
                CanisterQueryStats {
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
