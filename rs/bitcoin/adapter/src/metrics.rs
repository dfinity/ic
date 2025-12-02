use ic_metrics::{
    MetricsRegistry,
    buckets::{decimal_buckets, decimal_buckets_with_zero, exponential_buckets},
};
use prometheus::{Histogram, HistogramVec, IntCounter, IntCounterVec, IntGauge};

pub(crate) const LABEL_GET_SUCCESSOR: &str = "get_successor";
pub(crate) const LABEL_REQUEST_TYPE: &str = "type";
pub(crate) const LABEL_SEND_TRANSACTION: &str = "send_transaction";

#[derive(Clone, Debug)]
pub struct ServiceMetrics {
    pub request_duration: HistogramVec,
}

impl ServiceMetrics {
    pub fn new(metrics_registry: &MetricsRegistry) -> Self {
        Self {
            request_duration: metrics_registry.histogram_vec(
                "request_duration",
                "Request duration to adapter",
                // 1ms, 2ms, 5ms, 10ms, 20ms, 50ms, 100ms, 200ms, 500ms
                decimal_buckets(-3, -1),
                &[LABEL_REQUEST_TYPE],
            ),
        }
    }
}

#[derive(Clone, Debug)]
pub struct GetSuccessorMetrics {
    pub processed_block_hashes: Histogram,
    pub response_blocks: Histogram,
    pub prune_headers_anchor_height: IntGauge,
}

impl GetSuccessorMetrics {
    pub fn new(metrics_registry: &MetricsRegistry) -> Self {
        Self {
            processed_block_hashes: metrics_registry.histogram(
                "processed_block_hashes",
                "Number of processed block hashes sent in one request",
                // 1, 10, 100, 1000, 10000
                exponential_buckets(1.0, 10.0, 4),
            ),
            response_blocks: metrics_registry.histogram(
                "response_blocks",
                "Number of blocks returned in response",
                // 1, 10, 100, 1000
                exponential_buckets(1.0, 10.0, 3),
            ),
            prune_headers_anchor_height: metrics_registry.int_gauge(
                "prune_headers_anchor_height",
                "Anchor height used to prune headers",
            ),
        }
    }
}

#[derive(Clone, Debug)]
pub struct RouterMetrics {
    pub idle: IntCounter,
    pub bitcoin_messages_sent: IntCounterVec,
    pub bitcoin_messages_received: IntCounterVec,
    pub available_connections: IntGauge,
    pub connections: IntCounter,
    pub known_peer_addresses: IntGauge,
}

impl RouterMetrics {
    pub fn new(metrics_registry: &MetricsRegistry) -> Self {
        Self {
            idle: metrics_registry.int_counter(
                "idle_total",
                "Number of times the blockchain manager is put into idle mode.",
            ),
            bitcoin_messages_sent: metrics_registry.int_counter_vec(
                "bitcoin_network_messages_sent_total",
                "Bitcoin network messages sent.",
                &[LABEL_REQUEST_TYPE],
            ),
            bitcoin_messages_received: metrics_registry.int_counter_vec(
                "bitcoin_network_messages_received_total",
                "Bitcoin network messages received.",
                &[LABEL_REQUEST_TYPE],
            ),
            available_connections: metrics_registry
                .int_gauge("available_connections", "Active bitcoin peer connections."),
            connections: metrics_registry
                .int_counter("connection_total", "Connection setup attempts."),
            known_peer_addresses: metrics_registry
                .int_gauge("known_peer_addresses", "Known peer addresses."),
        }
    }
}

#[derive(Clone, Debug)]
pub struct BlockchainStateMetrics {
    pub tip_height: IntGauge,
    pub block_cache_size: IntGauge,
    pub block_cache_elements: IntGauge,
    pub tips: IntGauge,
}

impl BlockchainStateMetrics {
    pub fn new(metrics_registry: &MetricsRegistry) -> Self {
        Self {
            tip_height: metrics_registry.int_gauge("tip_height", "Current tip height."),
            block_cache_size: metrics_registry
                .int_gauge("block_cache_size_bytes", "Current size of block cache."),
            block_cache_elements: metrics_registry.int_gauge(
                "block_cache_elements",
                "Number of blocks currently stored in the block cache.",
            ),
            tips: metrics_registry.int_gauge("blockchain_tips", "Number of active tips."),
        }
    }
}

#[derive(Clone, Debug)]
pub struct HeaderCacheMetrics {
    pub anchor_height_on_disk: IntGauge,
    pub on_disk_db_size: IntGauge,
    pub on_disk_elements: IntGauge,
    pub in_memory_elements: IntGauge,
    pub headers_pruned_from_memory: Histogram,
}

impl HeaderCacheMetrics {
    pub fn new(metrics_registry: &MetricsRegistry) -> Self {
        Self {
            anchor_height_on_disk: metrics_registry.int_gauge(
                "anchor_height_on_disk",
                "Anchor height as stored by on-disk header cache.",
            ),
            on_disk_db_size: metrics_registry.int_gauge(
                "header_cache_on_disk_db_size",
                "Current size in bytes of the on-disk header cache database.",
            ),
            on_disk_elements: metrics_registry.int_gauge(
                "header_cache_on_disk_elements",
                "Number of headers currently stored in the on-disk header cache.",
            ),
            in_memory_elements: metrics_registry.int_gauge(
                "header_cache_in_memory_elements",
                "Number of headers currently stored in the in-memory header cache.",
            ),
            headers_pruned_from_memory: metrics_registry.histogram(
                "headers_pruned_from_memory",
                "Number of headers pruned from memory each time",
                // 0, 1, 2, 5, 10, 20, 50, 100, 200, 500, 1000, 2000, 5000
                decimal_buckets_with_zero(0, 3),
            ),
        }
    }
}

#[derive(Clone, Debug)]
pub struct TransactionMetrics {
    pub txn_ops: IntCounterVec,
}

impl TransactionMetrics {
    pub fn new(metrics_registry: &MetricsRegistry) -> Self {
        Self {
            txn_ops: metrics_registry.int_counter_vec(
                "txn_ops_total",
                "Number transaction operations. A transaction can either be added or removed.",
                &["op", "reason"],
            ),
        }
    }
}
