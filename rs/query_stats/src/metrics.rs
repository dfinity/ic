use ic_metrics::{buckets::decimal_buckets, MetricsRegistry};
use prometheus::{HistogramVec, IntCounter, IntGauge};

pub(crate) const CRITICAL_ERROR_AGGREGATION_FAILURE: &str = "query_stats_aggregator_failure";

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

/// Metrics for the [`QueryStatsPayloadBuilder`].
///
/// The payload builder runs as part of consensus and is responsible for
/// adding locally received metrics into the block
#[derive(Clone)]
pub(crate) struct QueryStatsPayloadBuilderMetrics {
    /// Records the time it took to perform an operation
    pub(crate) query_stats_payload_builder_duration: HistogramVec,
    /// The current epoch as seen by the payload builder.
    ///
    /// Should be slightly behind the current epoch of [`CollectorMetrics`]
    pub(crate) query_stats_payload_builder_current_epoch: IntGauge,
    /// Number of canister ids of the current epoch yet to be included into a payload
    ///
    /// Should decrease rapidly after a new epoch starts
    pub(crate) query_stats_payload_builder_num_canister_ids: IntGauge,
}

impl QueryStatsPayloadBuilderMetrics {
    pub(crate) fn new(metrics_registry: &MetricsRegistry) -> Self {
        Self {
            query_stats_payload_builder_duration: metrics_registry.histogram_vec(
                "query_stats_payload_builder_duration",
                "The time it took the payload builder to perform an operation",
                // 0.1ms - 5s
                decimal_buckets(-4, 0),
                &["operation"],
            ),
            query_stats_payload_builder_current_epoch: metrics_registry.int_gauge(
                "query_stats_payload_builder_current_epoch",
                "The current epoch as seen by the payload builder",
            ),
            query_stats_payload_builder_num_canister_ids: metrics_registry.int_gauge(
                "query_stats_payload_builder_num_canister_ids",
                "Number of canister ids of the current epoch yet to be included into a payload",
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
    /// The number of records stored in the unaggregateed state
    pub query_stats_aggregator_num_records: IntGauge,
    /// Critical error occuring in aggregator
    pub query_stats_critical_error_aggregator_failure: IntCounter,
}

impl QueryStatsAggregatorMetrics {
    pub fn new(metrics_registry: &MetricsRegistry) -> Self {
        Self {
            query_stats_aggregator_current_epoch: metrics_registry.int_gauge(
                "query_stats_aggregator_current_epoch",
                "Current epoch of the query stats aggregator",
            ),
            query_stats_aggregator_num_records: metrics_registry.int_gauge(
                "query_stats_aggregator_num_records",
                "The number of records stored in the unaggregateed state",
            ),
            query_stats_critical_error_aggregator_failure: metrics_registry
                .error_counter(CRITICAL_ERROR_AGGREGATION_FAILURE),
        }
    }
}
