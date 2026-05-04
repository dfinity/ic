use crate::{
    add_config::AddsConfig,
    disclose::DisclosesRules,
    state::CanisterApi,
    types::{AddConfigError, DiscloseRulesError, Timestamp},
};
use ic_cdk::stable::WASM_PAGE_SIZE_IN_BYTES;
use ic_http_types::{HttpResponse, HttpResponseBuilder};
use prometheus::{
    CounterVec, Encoder, Gauge, IntGauge, Opts, Registry, Result as PrometheusResult, TextEncoder,
};
use std::{borrow::BorrowMut, cell::RefCell};

thread_local! {
    pub static METRICS: RefCell<CanisterMetrics> = RefCell::new(CanisterMetrics::new().expect("failed to create Prometheus metrics"));
}

/// Represents all metrics collected in the canister
pub struct CanisterMetrics {
    pub registry: Registry, // Prometheus registry
    pub active_rate_limit_rules_count: IntGauge,
    pub active_version: IntGauge,
    pub api_boundary_nodes_count: IntGauge,
    pub canister_api_calls: CounterVec,
    pub configs_count: IntGauge,
    pub incidents_count: IntGauge,
    pub last_canister_change_time: IntGauge,
    pub last_successful_registry_poll_time: IntGauge,
    pub registry_poll_calls: CounterVec,
    pub stable_memory_size: Gauge,
}

impl CanisterMetrics {
    pub fn new() -> PrometheusResult<Self> {
        let registry = Registry::new();

        let stable_memory_size = Gauge::new(
            "stable_memory_bytes",
            "Size of the stable memory allocated by this canister in bytes.",
        )?;

        let canister_api_calls = CounterVec::new(
            Opts::new(
                "canister_api_calls",
                "Number of calls to the canister methods with the status and message (in case of error)",
            ),
            &["method", "status", "message"],
        )?;

        let api_boundary_nodes_count = IntGauge::new(
            "api_boundary_nodes_count",
            "Number of API boundary nodes with full read access permission to rate-limit config.",
        )?;

        let active_version = IntGauge::new(
            "active_config_version",
            "Version of the currently active configuration",
        )?;

        let active_rate_limit_rules_count = IntGauge::new(
            "active_rules_count",
            "Number of rate-limit rules in the active configuration",
        )?;

        let incidents_count =
            IntGauge::new("stored_incidents_count", "Number of stored incidents")?;

        let configs_count = IntGauge::new(
            "stored_configs_count",
            "Number of stored rate-limit configurations",
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

        let last_canister_change_time = IntGauge::new(
            "last_successful_canister_upgrade",
            "The Unix timestamp of the last successful canister upgrade",
        )?;

        // Register all metrics in the registry
        registry.register(Box::new(stable_memory_size.clone()))?;
        registry.register(Box::new(canister_api_calls.clone()))?;
        registry.register(Box::new(api_boundary_nodes_count.clone()))?;
        registry.register(Box::new(active_version.clone()))?;
        registry.register(Box::new(active_rate_limit_rules_count.clone()))?;
        registry.register(Box::new(incidents_count.clone()))?;
        registry.register(Box::new(configs_count.clone()))?;
        registry.register(Box::new(last_successful_registry_poll_time.clone()))?;
        registry.register(Box::new(registry_poll_calls.clone()))?;
        registry.register(Box::new(last_canister_change_time.clone()))?;

        Ok(Self {
            registry,
            active_rate_limit_rules_count,
            active_version,
            api_boundary_nodes_count,
            canister_api_calls,
            configs_count,
            incidents_count,
            last_canister_change_time,
            last_successful_registry_poll_time,
            registry_poll_calls,
            stable_memory_size,
        })
    }
}

pub fn export_metrics_as_http_response(
    registry: &Registry,
    canister_api: impl CanisterApi,
) -> HttpResponse {
    // Certain metrics need to be recomputed
    recompute_metrics(canister_api);

    let mut buffer = vec![];
    let encoder = TextEncoder::new();
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

pub fn recompute_metrics(canister_api: impl CanisterApi) {
    METRICS.with(|cell| {
        let mut cell = cell.borrow_mut();

        let memory = (ic_cdk::stable::stable_size() * WASM_PAGE_SIZE_IN_BYTES) as f64;

        cell.stable_memory_size.borrow_mut().set(memory);
        cell.api_boundary_nodes_count
            .set(canister_api.api_boundary_nodes_count() as i64);
        cell.active_version
            .set(canister_api.get_version().unwrap_or(0) as i64);
        cell.configs_count.set(canister_api.configs_count() as i64);
        cell.incidents_count
            .set(canister_api.incidents_count() as i64);
        cell.active_rate_limit_rules_count
            .set(canister_api.active_rules_count() as i64);
    });
}

pub struct WithMetrics<T> {
    inner: T,
}

impl<T> WithMetrics<T> {
    pub fn new(inner: T) -> Self {
        Self { inner }
    }
}

impl<T: AddsConfig> AddsConfig for WithMetrics<T> {
    fn add_config(
        &self,
        input_config: rate_limits_api::InputConfig,
        time: Timestamp,
    ) -> Result<(), AddConfigError> {
        // Inner must be invoked first and then metrics are updated.
        let result = self.inner.add_config(input_config, time);
        // Update metrics.
        let method = "add_config";
        let status = if result.is_ok() { "success" } else { "failure" };
        let message: &str = result.as_ref().err().map_or("", |err| err.as_ref());
        update_canister_call_metrics(method, status, message);
        // Return unchanged result.
        result
    }
}

impl<T: DisclosesRules> DisclosesRules for WithMetrics<T> {
    fn disclose_rules(
        &self,
        arg: rate_limits_api::DiscloseRulesArg,
        current_time: Timestamp,
    ) -> Result<(), DiscloseRulesError> {
        // Inner must be invoked first and then metrics are updated.
        let result = self.inner.disclose_rules(arg, current_time);
        // Update metrics.
        let method = "disclose_rules";
        let status = if result.is_ok() { "success" } else { "failure" };
        let message: &str = result.as_ref().err().map_or("", |err| err.as_ref());
        update_canister_call_metrics(method, status, message);
        // Return unchanged result.
        result
    }
}

fn update_canister_call_metrics(method_name: &str, status: &str, message: &str) {
    METRICS.with(|cell| {
        let metric = &cell.borrow_mut().canister_api_calls;
        metric
            .with_label_values(&[method_name, status, message])
            .inc();
    });
}

pub fn with_metrics_registry<T, F>(f: F) -> T
where
    F: FnOnce(&Registry) -> T,
{
    METRICS.with(|cell| {
        let registry = cell.borrow().registry.clone();
        f(&registry)
    })
}
