use ic_metrics::{
    buckets::{decimal_buckets, exponential_buckets},
    MetricsRegistry,
};
use prometheus::{Histogram, HistogramVec, IntCounter, IntCounterVec, IntGauge};

pub(crate) const LABEL_GET_SUCCESSOR: &str = "get_successor";
pub(crate) const LABEL_REQUEST_TYPE: &str = "type";
pub(crate) const LABEL_SEND_TRANSACTION: &str = "send_transaction";

#[derive(Debug, Clone)]
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

#[derive(Debug, Clone)]
pub struct GetSuccessorMetrics {
    pub processed_block_hashes: Histogram,
    pub response_blocks: Histogram,
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
        }
    }
}

#[derive(Debug, Clone)]
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

#[derive(Debug, Clone)]
pub struct BlockchainStateMetrics {
    pub tip_height: IntGauge,
    pub block_cache_size: IntGauge,
    pub block_cache_elements: IntGauge,
    pub header_cache_size: IntGauge,
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
            header_cache_size: metrics_registry.int_gauge(
                "header_cache_size",
                "Number of headers stored in the adapter.",
            ),
            tips: metrics_registry.int_gauge("blockchain_tips", "Number of active tips."),
        }
    }
}

#[derive(Debug, Clone)]
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
