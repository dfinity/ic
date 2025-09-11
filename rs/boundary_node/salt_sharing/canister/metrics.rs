use ic_cdk::stable::WASM_PAGE_SIZE_IN_BYTES;
use ic_http_types::{HttpResponse, HttpResponseBuilder};
use prometheus::{
    CounterVec, Encoder, Gauge, IntGauge, Opts, Registry, Result as PrometheusResult, TextEncoder,
};
use std::{borrow::BorrowMut, cell::RefCell};

use crate::storage::{API_BOUNDARY_NODE_PRINCIPALS, SALT};

thread_local! {
    pub static METRICS: RefCell<CanisterMetrics> = RefCell::new(CanisterMetrics::new().expect("failed to create Prometheus metrics"));
}

/// Represents all metrics collected in the canister
pub struct CanisterMetrics {
    pub registry: Registry, // Prometheus registry
    pub last_salt_id: IntGauge,
    pub api_boundary_nodes_count: IntGauge,
    pub last_canister_change_time: IntGauge,
    pub last_successful_registry_poll_time: IntGauge,
    pub registry_poll_calls: CounterVec,
    pub stable_memory_size: Gauge,
}

impl CanisterMetrics {
    pub fn new() -> PrometheusResult<Self> {
        let registry = Registry::new();

        let last_salt_id = IntGauge::new("last_salt_id", "ID of the latest salt")?;

        let api_boundary_nodes_count = IntGauge::new(
            "api_boundary_nodes_count",
            "Number of API boundary nodes with read access to salt.",
        )?;

        let last_canister_change_time = IntGauge::new(
            "last_successful_canister_upgrade",
            "The Unix timestamp of the last successful canister upgrade",
        )?;

        let last_successful_registry_poll_time = IntGauge::new(
            "last_successful_registry_poll",
            "The Unix timestamp of the last successful poll of the API boundary nodes from registry canister",
        )?;

        let registry_poll_calls = CounterVec::new(
            Opts::new(
                "registry_poll_calls",
                "Number of registry polling calls with the status and message (in case of error)",
            ),
            &["status", "message"],
        )?;

        let stable_memory_size = Gauge::new(
            "stable_memory_bytes",
            "Size of the stable memory allocated by this canister in bytes.",
        )?;

        // Register all metrics in the registry
        registry.register(Box::new(last_salt_id.clone()))?;
        registry.register(Box::new(api_boundary_nodes_count.clone()))?;
        registry.register(Box::new(last_canister_change_time.clone()))?;
        registry.register(Box::new(last_successful_registry_poll_time.clone()))?;
        registry.register(Box::new(registry_poll_calls.clone()))?;
        registry.register(Box::new(stable_memory_size.clone()))?;

        Ok(Self {
            registry,
            last_salt_id,
            api_boundary_nodes_count,
            last_canister_change_time,
            last_successful_registry_poll_time,
            registry_poll_calls,
            stable_memory_size,
        })
    }
}

pub fn export_metrics_as_http_response() -> HttpResponse {
    // Certain metrics need to be recomputed
    recompute_metrics();

    let mut buffer = vec![];
    let encoder = TextEncoder::new();
    let registry = METRICS.with(|cell| cell.borrow().registry.clone());
    let metrics_family = registry.gather();

    match encoder.encode(&metrics_family, &mut buffer) {
        Ok(()) => HttpResponseBuilder::ok()
            .header("Content-Type", "text/plain")
            .with_body_and_content_length(buffer)
            .build(),
        Err(err) => {
            // Return an HTTP 500 error with detailed error information
            HttpResponseBuilder::server_error(format!("Failed to encode metrics: {err:?}")).build()
        }
    }
}

pub fn recompute_metrics() {
    METRICS.with(|cell| {
        let mut cell = cell.borrow_mut();

        let memory = (ic_cdk::stable::stable_size() * WASM_PAGE_SIZE_IN_BYTES) as f64;
        cell.stable_memory_size.borrow_mut().set(memory);

        let api_bns_count = API_BOUNDARY_NODE_PRINCIPALS.with(|cell| cell.borrow().len());
        cell.api_boundary_nodes_count.set(api_bns_count as i64);

        if let Some(stored_salt) = SALT.with(|cell| cell.borrow().get(&())) {
            cell.last_salt_id.set(stored_salt.salt_id as i64);
        }
    });
}
