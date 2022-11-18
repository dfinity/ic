use ic_metrics::MetricsRegistry;
use prometheus::{IntCounter, IntCounterVec, IntGauge};

pub(crate) const LABEL_GET_SUCCESSOR: &str = "get_successor";
pub(crate) const LABEL_REQUEST_TYPE: &str = "type";
pub(crate) const LABEL_SEND_TRANSACTION: &str = "send_transaction";

#[derive(Debug, Clone)]
pub struct ServiceMetrics {
    pub requests: IntCounterVec,
}

impl ServiceMetrics {
    pub fn new(metrics_registry: &MetricsRegistry) -> Self {
        Self {
            requests: metrics_registry.int_counter_vec(
                "requests_total",
                "Requests served by the adapter.",
                &[LABEL_REQUEST_TYPE],
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
    pub header_cache_size: IntGauge,
    pub tips: IntGauge,
}

impl BlockchainStateMetrics {
    pub fn new(metrics_registry: &MetricsRegistry) -> Self {
        Self {
            tip_height: metrics_registry.int_gauge("tip_height", "Current tip height."),
            block_cache_size: metrics_registry
                .int_gauge("block_cache_size_bytes", "Current size of block cache."),
            header_cache_size: metrics_registry.int_gauge(
                "header_cache_size",
                "Number of headers stored in the adapter.",
            ),
            tips: metrics_registry.int_gauge("blockchain_tips", "Number of active tips."),
        }
    }
}
