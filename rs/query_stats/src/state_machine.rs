//! Implementation of the `QueryStatsAggregator` replicated state machine.
//!
//! For the sound aggregation of the query stats, it is necessary to maintain some replicated state.
//! The code is not entirely trivial, as there are a number of corner cases to keep track of.
//!
//! # State
//!
//! The QueryStats feature keeps state in two way:
//! - The aggregated stats of each canister as part of the canister's [`Metadata`].
//! - The unaggregated stats are stored in [`RawQueryStats`], which is processed by functions in this
//!     module, until it can be aggregated into canisters.
//!
//! The state in [`RawQueryStats`] is a map of
//! [`NodeId`] -> [`QueryStatsEpoch`] -> [`CanisterId`] -> [`QueryStats`],
//! as well as a counter `highest_aggregated_epoch` which indicates up until which epoch the state has already
//! been aggregated.
//! Within this module, we call the [`CanisterId`] -> [`QueryStats`] part the record.
//! The record with the highest [`QueryStatsEpoch`] is called the current record, all other records
//! are called fully submitted records.
//!
//! # State transitions
//!
//! The core function of this module is [`deliver_query_stats`].
//! When this function is called, the current [`QueryStatsPayload`] is added to the state.
//! Note that we can only add additional entries to the current record by submitting a payload with the same epoch,
//! or start a new record by submitting a payload with a higher record.
//!
//! There can be gaps in the records of a node since nodes may leave and join, loose their stats
//! or simply don't have anything to report.
//! We consider a gap simply as an empty submitted record.
//!
//! After adding the current payload to the state we remove all records for epochs which are equal or below
//! `highest_aggregated_epoch`.
//! If nodes end up without any records whatsoever, we also remove them entirely.
//!
//! Then check whether we are able to aggregate.
//! In order to be able to aggregate, we need more than 2/3 of the nodes to have a submitted record for
//! `highest_aggregated_epoch + 1` (i.e. have some record `> highest_aggregated_epoch + 1`).
//!
//! If this is the case, we calculate the median of each of the statistics value for each [`CanisterId`]
//! and add it to the canister's statistic.
//! Now we increase `highest_aggregated_epoch` by `1`.
//!
//! # Inclusion of partial records into aggregation
//!
//! The aggregation triggers when more than 2/3 of the nodes have fully submitted a record.
//! We can not wait longer to trigger the aggregation, as this would allow a malicious node
//! to prevent aggregation entirely.
//! When calculating the median, there is a design decision:
//! Should we include the data of the not submitted 1/3 of the nodes into the calculation or not?
//!
//! Both choices are sound but change the values calculated by the aggregation:
//!
//! ## Include the data
//!
//! Usually these nodes have a complete set of statistics, as they had a whole epoch of time to
//! send the data and including the data creates a more precise data set.
//! On the other hand, if nodes actually fail to transmit their statistics and we count them as empty
//! records rather than omit them, we calculate lower values (possibly 0 values, if nodes are malicious).
//!
//! ## Exclude the data
//!
//! If we omit 1/3 of the records, it is still guaranteed that the median is calculated from values submitted
//! by honest nodes.
//!
//! ## Conclusion
//!
//! We have chosen to exclude the data.

use crate::metrics::{QueryStatsAggregatorMetrics, CRITICAL_ERROR_AGGREGATION_FAILURE};
use ic_logger::{error, info, ReplicaLogger};
use ic_replicated_state::ReplicatedState;
use ic_types::{
    batch::{QueryStats, QueryStatsPayload, RawQueryStats},
    consensus::get_faults_tolerated,
    CanisterId, NodeId, QueryStatsEpoch,
};
use std::{
    cmp::Ordering,
    collections::BTreeMap,
    ops::{Add, Div},
};

fn get_median<T: Default + Ord + Copy + Add<Output = T> + Div<Output = T> + From<u8>, F>(
    stats: &[&QueryStats],
    f: F,
) -> T
where
    F: FnMut(&&QueryStats) -> T,
{
    let mut values: Vec<T> = stats.iter().map(f).collect();
    values.sort_unstable();
    let mid = values.len() / 2;

    if values.len() % 2 == 0 {
        let left = values
            .get(mid.saturating_sub(1))
            .cloned()
            .unwrap_or(T::default());
        let right = values.get(mid).cloned().unwrap_or(T::default());
        (left + right) / 2u8.into()
    } else {
        values.get(mid).cloned().unwrap_or(T::default())
    }
}

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
    num_nodes: usize,
    state: &mut ReplicatedState,
    logger: &ReplicaLogger,
) {
    // Note that the use of the number of nodes in the subnet like this does not handle the case that
    // the number of machines in the subnet might have changed throughout an epoch.
    // Given that subnet topology changes are an infrequent event, we tolerate this occasional inaccuracy here.
    let num_nodes = num_nodes as u128;
    if let Some(canister_state) = state.canister_state_mut(&canister_id) {
        let canister_query_stats = &mut canister_state.scheduler_state.total_query_stats;
        canister_query_stats.num_calls += aggregated_stats.num_calls as u128 * num_nodes;
        canister_query_stats.num_instructions +=
            aggregated_stats.num_instructions as u128 * num_nodes;
        canister_query_stats.ingress_payload_size +=
            aggregated_stats.ingress_payload_size as u128 * num_nodes;
        canister_query_stats.egress_payload_size +=
            aggregated_stats.egress_payload_size as u128 * num_nodes;
    } else {
        info!(
            logger,
            "Received query stats for a canister {} which does not exist.", canister_id,
        );
    }
}

/// Adds the newly delivered [`QueryStatsPayload`] to the aggregator state
///
/// If the incoming [`QueryStatsPayload`] has a higher epoch than any existing entry
/// (or there are no entries for this [`NodeId`]) it is appended to the end of the record.
/// If it has the same epoch as the last entry, the entries are merged.
///
/// It is an error if the incoming [`QueryStatsPayload`] has an epoch lower than the last entry.
/// In that case, the payload is ignored.
///
/// # Returns
///
/// - `true` if the payload was added to the [`RawQueryStats`]
/// - `false` otherwise
fn process_payload(
    query_stats: &QueryStatsPayload,
    state: &mut ReplicatedState,
    logger: &ReplicaLogger,
    metrics: &QueryStatsAggregatorMetrics,
) -> bool {
    let state = &mut state.epoch_query_stats;

    // Check that we are not adding a payload for a height that has already been aggregated.
    if Some(query_stats.epoch) <= state.highest_aggregated_epoch {
        return false;
    }

    let node = state.stats.entry(query_stats.proposer).or_default();
    let stats = match node.last_key_value() {
        Some((highest_epoch, _)) => match highest_epoch.cmp(&query_stats.epoch) {
            // Add a new entry to the end of the records
            Ordering::Less => node.entry(query_stats.epoch).or_default(),
            // Get the last record
            Ordering::Equal => node.get_mut(&query_stats.epoch).unwrap(),
            // Node is trying to submit a record which should already be fully submitted
            Ordering::Greater => {
                error!(logger, "QueryStatsAggregator: Trying to add payload for epoch {:?} for proposer {:?}\
                    after already submitting values for {:?}. This is likely a bug in the payload builder.", 
                    query_stats.epoch,
                    query_stats.proposer,
                    highest_epoch
                );
                return false;
            }
        },
        None => node.entry(query_stats.epoch).or_default(),
    };

    let mut query_stats_received = QueryStats::default();
    for message in &query_stats.stats {
        // Collect metrics about reveived statistics
        query_stats_received.saturating_accumulate(&message.stats);

        // Insert the record into the state machine
        let previous_record = stats.insert(message.canister_id, message.stats.clone());

        // If there was a previous record, we have received a set of statistics twice, which is likely a bug
        if previous_record.is_some() {
            error!(
                logger,
                "Received duplicate query stats for canister {} from same proposer {}.\
                This is a bug, possibly in the payload builder.",
                message.canister_id,
                query_stats.proposer
            );
        }
    }
    metrics.query_stats_received.add(&query_stats_received);

    true
}

/// Tries to aggregate the next epoch.
///
/// First, it checks for each node, whether there is a complete record for the epoch in question.
/// A record is considered complete as soon as there exists data of a higher epoch.
/// If there only exists data for a higher epoch, the record is considered complete but empty.
///
/// # Returns
///
/// - `true` if an epoch was aggregated
/// - `false` otherwise
fn try_aggregate_one_epoch(
    replicated_state: &mut ReplicatedState,
    logger: &ReplicaLogger,
    metrics: &QueryStatsAggregatorMetrics,
) -> bool {
    // For the aggregation to work correctly, we need to remove all entries from epochs equal or
    // below current `highest_aggregated_epoch`.
    purge_records(replicated_state);

    // Get the number of nodes of this subnet
    let num_nodes = replicated_state
        .system_metadata()
        .network_topology
        .get_subnet_size(&replicated_state.metadata.own_subnet_id);
    debug_assert!(num_nodes.is_some());
    let Some(num_nodes) = num_nodes else {
        metrics.query_stats_critical_error_aggregator_failure.inc();
        error!(
            logger,
            "{}: QueryStats Aggregator: Failed to get own subnet size",
            CRITICAL_ERROR_AGGREGATION_FAILURE
        );
        return false;
    };

    let state = &mut replicated_state.epoch_query_stats;

    // Get the next epoch that we want to aggregate
    // Usually this is `highest_aggregated_epoch + 1`, but occasionally there might be
    // large gaps in between (e.g. the feature was deactivated for a while).
    // If we checked each `highest_aggregated_epoch + 1`, we would aggregate a lot of 0 epochs
    // Instead, we check for the lowest epoch that any node has stored as the `next_epoch`.
    let Some(&next_epoch) = state
        .stats
        .values()
        .filter_map(|records| records.first_key_value())
        .map(|(epoch, _stats)| epoch)
        .min()
    else {
        return false;
    };

    // Get the aggregatable records from the different `node_id`s
    let mut num_nodes_with_stats = 0;
    let mut aggregatable_records = vec![];
    for records in state.stats.values() {
        match records.len() {
            // If there are no records at all, this node has no stats to contribute
            0 => (),
            // If there is only one record and it's the one for a higher epoch, we know that this node has empty stats for
            // the current round. If the epoch is the current epoch, we don't know if the node has already fully
            // commited the record.
            1 => {
                let (epoch, _) = records.first_key_value().unwrap();
                if *epoch > next_epoch {
                    num_nodes_with_stats += 1;
                }
            }
            // If we have 2 or more records we know that the data is aggregatable.
            // We still need to check, whether the first record actually points to the epoch we care about.
            // Otherwise this node has empty stats to report for the current epoch.
            2.. => {
                num_nodes_with_stats += 1;
                let (epoch, stats) = records.first_key_value().unwrap();
                if *epoch == next_epoch {
                    aggregatable_records.push(stats)
                }
            }
        }
    }

    // Check if we have enough nodes with reports to aggregate an epoch
    let need_stats_from = num_nodes.saturating_sub(get_faults_tolerated(num_nodes));
    if num_nodes_with_stats < need_stats_from {
        return false;
    }

    // Increase the highest aggregated epoch
    state.highest_aggregated_epoch = Some(next_epoch);

    // We have an iterator over maps but we want a map over iterators
    let mut records: BTreeMap<CanisterId, Vec<_>> = BTreeMap::new();
    aggregatable_records
        .iter()
        .flat_map(|inner| inner.iter())
        .for_each(|(&canister_id, stat)| records.entry(canister_id).or_default().push(stat));

    info!(
        logger,
        "QueryStats aggregation summary: num_nodes: {}, need_stats_from: {}, \
            num_nodes_with_stats: {}, aggregatable_records: {}, aggregatable_canisters: {}",
        num_nodes,
        need_stats_from,
        num_nodes_with_stats,
        aggregatable_records.len(),
        records.len(),
    );

    // Aggregate statistics
    let mut empty_stats_counter: usize = 0;
    let mut total_stats_counter: usize = 0;

    let empty_stats = QueryStats::default();
    let mut query_stats_to_be_applied = vec![];
    for (canister_id, mut stats) in records {
        let num_empty_stats = num_nodes_with_stats.saturating_sub(stats.len());
        stats.append(&mut vec![&empty_stats; num_empty_stats]);

        empty_stats_counter += num_empty_stats;
        total_stats_counter += stats.len();

        let aggregated_stats = aggregate_query_stats(stats);
        query_stats_to_be_applied.push((canister_id, aggregated_stats));
    }

    metrics
        .query_stats_empty_stats_aggregated
        .add(empty_stats_counter as i64);
    metrics
        .query_stats_total_aggregated
        .add(total_stats_counter as i64);

    let mut delivered_query_stats = QueryStats::default();
    for (canister_id, aggregated_stats) in query_stats_to_be_applied {
        delivered_query_stats.saturating_accumulate(&aggregated_stats);

        apply_query_stats_to_canister(
            &aggregated_stats,
            canister_id,
            num_nodes,
            replicated_state,
            logger,
        );
    }

    metrics.query_stats_delivered.add(&delivered_query_stats);

    true
}

/// Removes all records for epochs equal or lower than `highest_aggregated_epoch`.
/// Then it removes all node_id entries which are empty.
fn purge_records(state: &mut ReplicatedState) {
    let state = &mut state.epoch_query_stats;

    let Some(highest_aggregated_epoch) = state.highest_aggregated_epoch else {
        return;
    };

    // Delete records for epoch that are already aggregated
    state.stats.iter_mut().for_each(|(_node_id, records)| {
        records.retain(|&epoch, _| epoch > highest_aggregated_epoch)
    });

    // Delete node_ids that don't have any entries
    state.stats.retain(|_node_id, records| !records.is_empty());
}

/// Update the metrics to reflect the current state of the aggregator
fn update_metrics(state: &ReplicatedState, metrics: &QueryStatsAggregatorMetrics) {
    let state = &state.epoch_query_stats;

    metrics.query_stats_aggregator_current_epoch.set(
        (state
            .highest_aggregated_epoch
            .map(|epoch| epoch.get())
            .unwrap_or(0) as i64)
            + 1,
    );

    let num_records: usize = state
        .stats
        .values()
        .map(|epochs| epochs.values().map(|record| record.len()).sum::<usize>())
        .sum();
    metrics
        .query_stats_aggregator_num_records
        .set(num_records as i64)
}

/// Add the epoch stats of the current round to the metadata
/// and on a new epoch aggregate currently stored stats into
/// the canister query stats.
pub fn deliver_query_stats(
    query_stats: &QueryStatsPayload,
    state: &mut ReplicatedState,
    logger: &ReplicaLogger,
    metrics: &QueryStatsAggregatorMetrics,
) {
    if process_payload(query_stats, state, logger, metrics) {
        // While in theory is is guaranteed that `try_aggregate_one_epoch` will eventually return
        // `false`, the code is relatively complex and we don't want to rely on correct implementation
        // only.
        for _ in 0..100 {
            if !try_aggregate_one_epoch(state, logger, metrics) {
                break;
            }
        }

        update_metrics(state, metrics)
    }
}

// Returns the QueryStats of a given [`NodeId`] and [`QueryStatsEpoch`]
pub(crate) fn get_stats_for_node_id_and_epoch<'a>(
    state: &'a RawQueryStats,
    node_id: &NodeId,
    epoch: &QueryStatsEpoch,
) -> Option<&'a BTreeMap<CanisterId, QueryStats>> {
    state
        .stats
        .get(node_id)
        .and_then(|records| records.get(epoch))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ic_logger::replica_logger::no_op_logger;
    use ic_test_utilities_state::{CanisterStateBuilder, ReplicatedStateBuilder};
    use ic_types::{
        batch::{CanisterQueryStats, TotalQueryStats},
        NodeId, QueryStatsEpoch,
    };
    use ic_types_test_utils::ids::{canister_test_id, node_test_id};

    #[test]
    fn full_aggregation_test() {
        let state = test_message_processing(4, 1);
        let stats = get_canister_query_stats(&state, &canister_test_id(1))
            .expect("Expected the stats to be aggregated already");

        assert_eq!(stats.num_calls, 0);
        assert_eq!(stats.num_instructions, 360);
        assert_eq!(stats.ingress_payload_size, 0);
        assert_eq!(stats.egress_payload_size, 0);

        // Test that the behaviour is the same if `next_epoch` has a gap
        let state = test_message_processing(4, 1337);
        let stats2 = get_canister_query_stats(&state, &canister_test_id(1))
            .expect("Expected the stats to be aggregated already");
        assert_eq!(stats, stats2)
    }

    #[test]
    fn partially_empty_threshold_aggregation_test() {
        let state = test_message_processing(3, 1);
        let stats = get_canister_query_stats(&state, &canister_test_id(1))
            .expect("Expected the stats to be aggregated already");

        assert_eq!(stats.num_calls, 0);
        assert_eq!(stats.num_instructions, 360);
        assert_eq!(stats.ingress_payload_size, 0);
        assert_eq!(stats.egress_payload_size, 0);

        // Test that the behaviour is the same if `next_epoch` has a gap
        let state = test_message_processing(3, 1337);
        let stats2 = get_canister_query_stats(&state, &canister_test_id(1))
            .expect("Expected the stats to be aggregated already");
        assert_eq!(stats, stats2)
    }

    #[test]
    fn below_threshold_aggregation_test() {
        let state = test_message_processing(2, 1);
        let stats = get_canister_query_stats(&state, &canister_test_id(1))
            .expect("Expected the stats to be aggregated already");

        assert_eq!(stats.num_calls, 0);
        assert_eq!(stats.num_instructions, 320);
        assert_eq!(stats.ingress_payload_size, 0);
        assert_eq!(stats.egress_payload_size, 0);

        // Test that the behaviour is the same if `next_epoch` has a gap
        let state = test_message_processing(2, 1337);
        let stats2 = get_canister_query_stats(&state, &canister_test_id(1))
            .expect("Expected the stats to be aggregated already");
        assert_eq!(stats, stats2)
    }

    fn test_message_processing(num_epoch0_msgs: usize, next_epoch: u64) -> ReplicatedState {
        let mut state = test_state();

        let example_data = [(1, 80), (2, 90), (3, 110), (4, 120)];
        for (id, insts) in &example_data[..num_epoch0_msgs] {
            let id = node_test_id(*id);
            let stats = test_payload(id, 0, *insts);
            deliver_stats(stats, &mut state);
        }

        let stats = test_payload(node_test_id(1), next_epoch, 0);
        deliver_stats(stats, &mut state);
        let stats = test_payload(node_test_id(2), next_epoch, 0);
        deliver_stats(stats, &mut state);

        // Check that up until this point nothing has been aggregated yet
        assert_eq!(
            get_canister_query_stats(&state, &canister_test_id(1)),
            Some(TotalQueryStats::default())
        );
        let stats = test_payload(node_test_id(3), next_epoch, 0);
        deliver_stats(stats, &mut state);

        state
    }

    fn test_state() -> ReplicatedState {
        ReplicatedStateBuilder::new()
            .with_node_ids((1..=4).map(node_test_id).collect())
            .with_canister(
                CanisterStateBuilder::new()
                    .with_canister_id(canister_test_id(1))
                    .build(),
            )
            .build()
    }

    fn deliver_stats(query_stats: QueryStatsPayload, state: &mut ReplicatedState) {
        deliver_query_stats(
            &query_stats,
            state,
            &no_op_logger(),
            &QueryStatsAggregatorMetrics::new(&ic_metrics::MetricsRegistry::new()),
        );
    }

    fn test_payload(proposer: NodeId, epoch: u64, insts: u64) -> QueryStatsPayload {
        QueryStatsPayload {
            epoch: QueryStatsEpoch::from(epoch),
            proposer,
            stats: vec![CanisterQueryStats {
                canister_id: canister_test_id(1),
                stats: QueryStats {
                    num_calls: 0,
                    num_instructions: insts,
                    ingress_payload_size: 0,
                    egress_payload_size: 0,
                },
            }],
        }
    }

    fn get_canister_query_stats(
        state: &ReplicatedState,
        canister_id: &CanisterId,
    ) -> Option<TotalQueryStats> {
        state
            .canister_state(canister_id)
            .map(|canister_state| canister_state.scheduler_state.total_query_stats.clone())
    }
}
