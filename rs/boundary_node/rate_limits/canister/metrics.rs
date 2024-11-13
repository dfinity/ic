use crate::{
    add_config::{AddConfigError, AddsConfig},
    disclose::{DiscloseRulesError, DisclosesRules},
    storage::{API_BOUNDARY_NODE_PRINCIPALS, CONFIGS, INCIDENTS},
    types::Timestamp,
};
use ic_canisters_http_types::{HttpResponse, HttpResponseBuilder};
use ic_cdk::api::stable::WASM_PAGE_SIZE_IN_BYTES;
use prometheus::{CounterVec, Encoder, Gauge, IntGauge, Opts, Registry, TextEncoder};
use std::cell::RefCell;

const SERVICE_NAME: &str = "rate_limit";

thread_local! {
    static STABLE_MEMORY_SIZE: RefCell<Gauge> = RefCell::new(Gauge::new(
        format!("{SERVICE_NAME}_stable_memory_bytes"),
        "Size of the stable memory allocated by this canister in bytes.").unwrap());

    static CANISTER_API_CALLS_COUNTER: RefCell<CounterVec> = RefCell::new(CounterVec::new(Opts::new(
        format!("{SERVICE_NAME}_canister_api_calls"),
        "Number of calls to the canister methods with the status and message (in case of error)",
    ), &["method", "status", "message"]).unwrap());

    static API_BOUNDARY_NODES_COUNT: RefCell<IntGauge> = RefCell::new(IntGauge::new(
            format!("{SERVICE_NAME}_api_boundary_nodes_count"),
            "Number of API boundary nodes with full read access permission to rate-limit config.").unwrap());

    static ACTIVE_VERSION: RefCell<IntGauge> = RefCell::new(IntGauge::new(
        format!("{SERVICE_NAME}_active_config_version"),
        "Version of the currently active configuration").unwrap());

    static ACTIVE_RATE_LIMIT_RULES_COUNT: RefCell<IntGauge> = RefCell::new(IntGauge::new(
        format!("{SERVICE_NAME}_active_rules_count"),
        "Number of rate-limit rules in the active configuration").unwrap());

    static INCIDENTS_COUNT: RefCell<IntGauge> = RefCell::new(IntGauge::new(
        format!("{SERVICE_NAME}_stored_incidents_count"),
        "Number of stored incidents").unwrap());

    static CONFIGS_COUNT: RefCell<IntGauge> = RefCell::new(IntGauge::new(
        format!("{SERVICE_NAME}_stored_configs_count"),
        "Number of stored rate-limit configurations").unwrap());

    pub static LAST_SUCCESSFUL_REGISTRY_POLL_TIME: RefCell<IntGauge> = RefCell::new(IntGauge::new(
        format!("{SERVICE_NAME}_last_successful_registry_poll"),
        "The Unix timestamp of the last successful poll of the API boundary nodes from registry canister").unwrap());

    pub static LAST_CANISTER_UPGRADE_TIME: RefCell<IntGauge> = RefCell::new(IntGauge::new(
        format!("{SERVICE_NAME}_last_successful_canister_upgrade"),
        "The Unix timestamp of the last successful canister upgrade").unwrap());

    static METRICS_REGISTRY: RefCell<Registry> = RefCell::new({
        let registry = Registry::new();

        STABLE_MEMORY_SIZE.with(|cell| {
            let cell = Box::new(cell.borrow().clone());
            registry.register(cell).unwrap();
        });

        CANISTER_API_CALLS_COUNTER.with(|cell| {
            let cell = Box::new(cell.borrow().clone());
            registry.register(cell).unwrap();
        });

        API_BOUNDARY_NODES_COUNT.with(|cell| {
            let cell = Box::new(cell.borrow().clone());
            registry.register(cell).unwrap();
        });

        ACTIVE_VERSION.with(|cell| {
            let cell = Box::new(cell.borrow().clone());
            registry.register(cell).unwrap();
        });

        ACTIVE_RATE_LIMIT_RULES_COUNT.with(|cell| {
            let cell = Box::new(cell.borrow().clone());
            registry.register(cell).unwrap();
        });

        INCIDENTS_COUNT.with(|cell| {
            let cell = Box::new(cell.borrow().clone());
            registry.register(cell).unwrap();
        });

        CONFIGS_COUNT.with(|cell| {
            let cell = Box::new(cell.borrow().clone());
            registry.register(cell).unwrap();
        });

        LAST_SUCCESSFUL_REGISTRY_POLL_TIME.with(|cell| {
            let cell = Box::new(cell.borrow().clone());
            registry.register(cell).unwrap();
        });

        LAST_CANISTER_UPGRADE_TIME.with(|cell| {
            let cell = Box::new(cell.borrow().clone());
            registry.register(cell).unwrap();
        });

        registry
    });
}

pub fn export_metrics_as_http_response(registry: &Registry) -> HttpResponse {
    // Certain metrics need to be recomputed
    recompute_metrics();

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
            HttpResponseBuilder::server_error(format!("Failed to encode metrics: {:?}", err))
                .build()
        }
    }
}

pub fn recompute_metrics() {
    STABLE_MEMORY_SIZE.with(|cell| {
        let memory = (ic_cdk::api::stable::stable_size() * WASM_PAGE_SIZE_IN_BYTES) as f64;
        cell.borrow_mut().set(memory);
    });

    API_BOUNDARY_NODES_COUNT.with(|cell| {
        cell.borrow_mut()
            .set(API_BOUNDARY_NODE_PRINCIPALS.with(|cell| cell.borrow().len() as i64));
    });

    ACTIVE_VERSION.with(|cell| {
        cell.borrow_mut().set(
            CONFIGS.with(|cell| cell.borrow().last_key_value().map_or(0, |(key, _)| key)) as i64,
        );
    });

    CONFIGS_COUNT.with(|cell| {
        cell.borrow_mut()
            .set(CONFIGS.with(|cell| cell.borrow().len() as i64));
    });

    INCIDENTS_COUNT.with(|cell| {
        cell.borrow_mut()
            .set(INCIDENTS.with(|cell| cell.borrow().len() as i64));
    });

    ACTIVE_RATE_LIMIT_RULES_COUNT.with(|cell| {
        cell.borrow_mut().set(CONFIGS.with(|cell| {
            cell.borrow()
                .last_key_value()
                .map_or(0, |(_, value)| value.rule_ids.len() as i64)
        }));
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
    CANISTER_API_CALLS_COUNTER.with(|cell| {
        let metric = cell.borrow_mut();
        metric
            .with_label_values(&[method_name, status, message])
            .inc();
    });
}

pub fn with_metrics_registry<T, F>(f: F) -> T
where
    F: FnOnce(&Registry) -> T,
{
    METRICS_REGISTRY.with(|cell| {
        let registry = cell.borrow().clone();
        f(&registry)
    })
}
