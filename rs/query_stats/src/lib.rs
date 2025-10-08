use crossbeam_channel::{Sender, TrySendError};
use ic_config::{execution_environment::Config, flag_status::FlagStatus};
use ic_logger::{ReplicaLogger, info, warn};
use ic_metrics::MetricsRegistry;
use ic_types::{
    CanisterId, Height, QueryStatsEpoch,
    batch::{CanisterQueryStats, LocalQueryStats, QueryStats},
    epoch_from_height,
};
use std::sync::Mutex;
use std::{collections::BTreeMap, sync::RwLock};

mod metrics;
mod payload_builder;
mod state_machine;

pub use self::metrics::QueryStatsAggregatorMetrics;
pub use self::payload_builder::{QueryStatsPayloadBuilderImpl, QueryStatsPayloadBuilderParams};
pub use self::state_machine::deliver_query_stats;

use self::metrics::CollectorMetrics;

pub fn init_query_stats(
    log: ReplicaLogger,
    config: &Config,
    metrics_registry: &MetricsRegistry,
) -> (QueryStatsCollector, QueryStatsPayloadBuilderParams) {
    let (tx, rx) = crossbeam_channel::bounded(1);
    (
        QueryStatsCollector {
            log: log.clone(),
            current_query_stats: Mutex::new(BTreeMap::new()),
            current_epoch: RwLock::new(None),
            sender: tx,
            query_stats_epoch_length: config.query_stats_epoch_length,
            metrics: CollectorMetrics::new(metrics_registry),
        },
        QueryStatsPayloadBuilderParams {
            rx,
            metrics_registry: metrics_registry.clone(),
            epoch_length: config.query_stats_epoch_length,
            enabled: config.query_stats_aggregation == FlagStatus::Enabled,
        },
    )
}

/// A component that collects statistics for locally executed query calls.
///
/// It makes those stats available to be appended to consensus blocks via
/// the payload builder interface.
pub struct QueryStatsCollector {
    log: ReplicaLogger,
    pub current_query_stats: Mutex<BTreeMap<CanisterId, QueryStats>>, // Needs to be pub for testing
    current_epoch: RwLock<Option<QueryStatsEpoch>>,
    sender: Sender<LocalQueryStats>,
    query_stats_epoch_length: u64,
    metrics: CollectorMetrics,
}

impl QueryStatsCollector {
    pub fn set_epoch_from_height(&self, height: Height) {
        self.set_epoch(epoch_from_height(height, self.query_stats_epoch_length));
    }

    pub fn set_epoch(&self, new_epoch: QueryStatsEpoch) {
        let mut current_epoch = self.current_epoch.write().unwrap();
        let Some(previous_epoch) = *current_epoch else {
            *current_epoch = Some(new_epoch);
            self.metrics
                .query_stats_collector_current_epoch
                .set(new_epoch.get() as i64);
            return;
        };

        if previous_epoch >= new_epoch {
            // Epoch is unchanged or smaller than a previously seen one. This can happen if
            // concurrent query handler threads get a different certified state and there is
            // a race for which one will execute first.
            //
            // For the purpose of query stats, this does not matter, as we always account queries
            // to the highest epoch seen when serving query calls.
            return;
        }

        // Reset locally observed stats for new epoch
        let mut state = self.current_query_stats.lock().unwrap();
        let previous_stats = std::mem::take(&mut *state);

        // Epoch changed, send stats from previous epoch to block maker
        match self.sender.try_send(LocalQueryStats {
            epoch: previous_epoch,
            stats: previous_stats
                .into_iter()
                .map(|(canister_id, stats)| CanisterQueryStats { canister_id, stats })
                .collect(),
        }) {
            Ok(()) => (),
            Err(TrySendError::Full(_)) => {
                warn!(
                    every_n_seconds => 5,
                    self.log,
                    "QueryStatsPayloadBuilder has not been called for an entire epoch. \
                    Consensus is likely starving."
                );
            }
            Err(TrySendError::Disconnected(_)) => {
                warn!(
                    every_n_seconds => 5,
                    self.log,
                    "QueryStatsPayloadBuilder has been dropped. This is a bug"
                );
            }
        }
        *current_epoch = Some(new_epoch);
        self.metrics
            .query_stats_collector_current_epoch
            .set(new_epoch.get() as i64);
    }

    pub fn register_query_statistics(&self, canister_id: CanisterId, stats: &QueryStats) {
        let current_epoch = *self.current_epoch.read().unwrap();
        if current_epoch.is_none() {
            info!(
                every_n_seconds => 30,
                self.log,
                "QueryStatsCollector epoch not set - omitting stats for canister {} - num_calls: {} num_instructions: {} - payload_size: {}:{}",
                canister_id, stats.num_calls, stats.num_instructions, stats.ingress_payload_size, stats.egress_payload_size
            );
            return;
        }

        let mut state = self.current_query_stats.lock().unwrap();
        state
            .entry(canister_id)
            .or_default()
            .saturating_accumulate(stats);

        self.metrics.query_stats_collector.add(stats);
        self.metrics
            .query_stats_collector_num_canister_ids
            .set(state.len() as i64);
    }
}
