use ic_metrics::MetricsRegistry;

use prometheus::IntGauge;

/// Metrics for query stats collector
///
/// The collector is responsible for locally collecting statistics for
/// each query executed. It is not part of the replicated state machine.
pub(crate) struct CollectorMetrics {
    /// The number of canister IDs registered in the collector for the current epoch.
    pub(crate) query_stats_collector_num_canister_ids: IntGauge,
    /// The epoch for which query calls are locally collected at the moment.
    pub(crate) query_stats_collector_current_epoch: IntGauge,
}

impl CollectorMetrics {
    pub(crate) fn new(metrics_registry: &MetricsRegistry) -> Self {
        Self {
            query_stats_collector_num_canister_ids: metrics_registry.int_gauge(
                "query_stats_collector_num_canister_ids",
                "Current number of canister ids in the query stats collector",
            ),
            query_stats_collector_current_epoch: metrics_registry.int_gauge(
                "query_stats_collector_current_epoch",
                "Current epoch of the query stats collector",
            ),
        }
    }
}

/// Metrics for query stats aggregator
///
/// The query stats aggregator runs as part of the replicated state machine.
/// It deterministically aggregates query stats received from consensus blocks.
#[derive(Clone)]
pub struct QueryStatsAggregatorMetrics {
    /// The epoch for which we currently aggregate query stats.
    /// This is lower than the epoch for which we collect stats, as there is
    /// a delay for propagating local query stats via consensus blocks.
    pub query_stats_aggregator_current_epoch: IntGauge,
}

impl QueryStatsAggregatorMetrics {
    pub fn new(metrics_registry: &MetricsRegistry) -> Self {
        Self {
            query_stats_aggregator_current_epoch: metrics_registry.int_gauge(
                "query_stats_aggregator_current_epoch",
                "Current epoch of the query stats aggregator",
            ),
        }
    }
}
