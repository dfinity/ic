use ic_metrics::{buckets::decimal_buckets, MetricsRegistry};
use ic_types::batch::QueryStats;
use prometheus::{HistogramVec, IntCounter, IntGauge};

pub(crate) const CRITICAL_ERROR_AGGREGATION_FAILURE: &str = "query_stats_aggregator_failure";

/// A set of the statistics reported by this feature
///
/// Occasionally, we want to export the metrics which contain the statistics reported
/// by various components. This struct is a helper to make this reporting more concise
#[derive(Clone, Debug)]
pub(crate) struct QueryStatsMetricsSet {
    num_calls: IntGauge,
    num_instructions: IntGauge,
    request_bytes: IntGauge,
    response_bytes: IntGauge,
}

impl QueryStatsMetricsSet {
    pub fn new(metrics_registry: &MetricsRegistry, name: &str) -> Self {
        Self {
            num_calls: metrics_registry.int_gauge(
                format!("query_stats_{}_num_calls", name),
                "Sum of calls".to_string(),
            ),
            num_instructions: metrics_registry.int_gauge(
                format!("query_stats_{}_num_instructions", name),
                "Sum of instructions".to_string(),
            ),
            request_bytes: metrics_registry.int_gauge(
                format!("query_stats_{}_request_bytes", name),
                "Sum of request bytes".to_string(),
            ),
            response_bytes: metrics_registry.int_gauge(
                format!("query_stats_{}_response_bytes", name),
                "Sum of response bytes".to_string(),
            ),
        }
    }

    pub fn add(&self, query_stats: &QueryStats) {
        self.num_calls.add(query_stats.num_calls as i64);
        self.num_instructions
            .add(query_stats.num_instructions as i64);
        self.request_bytes
            .add(query_stats.ingress_payload_size as i64);
        self.response_bytes
            .add(query_stats.egress_payload_size as i64);
    }
}

/// Metrics for query stats collector
///
/// The collector is responsible for locally collecting statistics for
/// each query executed. It is not part of the replicated state machine.
pub(crate) struct CollectorMetrics {
    /// The statistics as currently reported by the collector
    pub query_stats_collector: QueryStatsMetricsSet,
    /// The number of canister IDs registered in the collector for the current epoch.
    pub query_stats_collector_num_canister_ids: IntGauge,
    /// The epoch for which query calls are locally collected at the moment.
    pub query_stats_collector_current_epoch: IntGauge,
}

impl CollectorMetrics {
    pub(crate) fn new(metrics_registry: &MetricsRegistry) -> Self {
        Self {
            query_stats_collector: QueryStatsMetricsSet::new(metrics_registry, "collector"),
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
    /// Records the statistics received from the collector
    pub(crate) query_stats_payload_builder_current: QueryStatsMetricsSet,
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
            query_stats_payload_builder_current: QueryStatsMetricsSet::new(
                metrics_registry,
                "payload_builder_current",
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
#[derive(Clone, Debug)]
pub struct QueryStatsAggregatorMetrics {
    /// Sum of stats received from the payload builder
    pub(crate) query_stats_received: QueryStatsMetricsSet,
    /// The epoch for which we currently aggregate query stats.
    /// This is lower than the epoch for which we collect stats, as there is
    /// a delay for propagating local query stats via consensus blocks.
    pub(crate) query_stats_aggregator_current_epoch: IntGauge,
    /// The number of records stored in the unaggregateed state
    pub(crate) query_stats_aggregator_num_records: IntGauge,
    /// Sum of statistics delivered to the canisters
    pub(crate) query_stats_delivered: QueryStatsMetricsSet,
    /// Number of empty stats that were part of the aggregation
    pub(crate) query_stats_empty_stats_aggregated: IntGauge,
    /// Total number of stats (including empty) that were part of the aggregation
    pub(crate) query_stats_total_aggregated: IntGauge,
    /// Critical error occuring in aggregator
    pub(crate) query_stats_critical_error_aggregator_failure: IntCounter,
}

impl QueryStatsAggregatorMetrics {
    pub fn new(metrics_registry: &MetricsRegistry) -> Self {
        Self {
            query_stats_received: QueryStatsMetricsSet::new(
                metrics_registry,
                "aggregator_received",
            ),
            query_stats_aggregator_current_epoch: metrics_registry.int_gauge(
                "query_stats_aggregator_current_epoch",
                "Current epoch of the query stats aggregator",
            ),
            query_stats_aggregator_num_records: metrics_registry.int_gauge(
                "query_stats_aggregator_num_records",
                "The number of records stored in the unaggregateed state",
            ),
            query_stats_delivered: QueryStatsMetricsSet::new(metrics_registry, "delivered"),
            query_stats_empty_stats_aggregated: metrics_registry.int_gauge(
                "query_stats_empty_stats_aggregated",
                "Number of empty stats that where part of the aggregation",
            ),
            query_stats_total_aggregated: metrics_registry.int_gauge(
                "query_stats_total_aggregated",
                "Number of total stats that where part of the aggregation",
            ),
            query_stats_critical_error_aggregator_failure: metrics_registry
                .error_counter(CRITICAL_ERROR_AGGREGATION_FAILURE),
        }
    }
}
