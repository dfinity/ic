use axum::{
    body::Body,
    error_handling::HandleErrorLayer,
    extract::{Request, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::get,
};
use ic_async_utils::start_tcp_listener;
use ic_config::metrics::{Config, Exporter};
use ic_metrics::registry::MetricsRegistry;
use prometheus::{Encoder, IntCounterVec, TextEncoder};
use slog::{error, trace};
use std::net::SocketAddr;
use std::string::String;
use std::time::Duration;
use thiserror::Error;
use tower::{
    limit::concurrency::GlobalConcurrencyLimitLayer, load_shed::error::Overloaded,
    timeout::error::Elapsed, BoxError, ServiceBuilder,
};

const LOG_INTERVAL_SECS: u64 = 30;

const DEFAULT_ADAPTER_COLLECTION_TIMEOUT: Duration = Duration::from_secs(1);
/// Fraction of prometheus timeout that is applied to adapter collection.
/// Needed because we don't want adapter metrics scrape timeout to cause
/// a prometheus scrape timeout.
const PROMETHEUS_TIMEOUT_FRACTION: f64 = 0.5;
/// Header in prometheus scrape request that indicates the timeout used by scraping service.
const PROMETHEUS_TIMEOUT_HEADER: &str = "X-Prometheus-Scrape-Timeout-Seconds";

/// The type of a metrics runtime implementation.
pub struct MetricsHttpEndpoint {
    rt_handle: tokio::runtime::Handle,
    config: Config,
    metrics_registry: MetricsRegistry,
    log: slog::Logger,
    metrics: MetricsEndpointMetrics,
}

#[derive(Error, Debug)]
struct HttpError {
    response: Response<Body>,
}

impl std::fmt::Display for HttpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self.response)
    }
}
impl From<BoxError> for HttpError {
    fn from(err: BoxError) -> Self {
        let builder = if err.is::<Overloaded>() {
            Response::builder().status(StatusCode::TOO_MANY_REQUESTS)
        } else if err.is::<Elapsed>() {
            Response::builder().status(StatusCode::GATEWAY_TIMEOUT)
        } else {
            Response::builder().status(StatusCode::INTERNAL_SERVER_ERROR)
        };
        let response = builder
            .body(Body::from(""))
            .expect("Building response can't fail.");
        Self { response }
    }
}

#[derive(Clone)]
struct MetricsEndpointMetrics {
    connections_total: IntCounterVec,
}

impl MetricsEndpointMetrics {
    fn new(metrics_registry: MetricsRegistry) -> Self {
        Self {
            connections_total: metrics_registry.int_counter_vec(
                "metrics_endpoint_tcp_connections_total",
                "Total number of accepted TCP connections.",
                &["protocol"],
            ),
        }
    }
}

/// An implementation of the metrics runtime type.
impl MetricsHttpEndpoint {
    pub fn new(
        rt_handle: tokio::runtime::Handle,
        config: Config,
        metrics_registry: MetricsRegistry,
        log: &slog::Logger,
    ) -> Self {
        let log = log.new(slog::o!("Application" => "MetricsRuntime"));

        let metrics = Self {
            rt_handle,
            config,
            metrics_registry: metrics_registry.clone(),
            log,
            metrics: MetricsEndpointMetrics::new(metrics_registry),
        };

        match metrics.config.exporter {
            Exporter::Http(socket_addr) => metrics.start_http(socket_addr),
            Exporter::Log => metrics.start_log(),
            Exporter::File(_) => {}
        };

        metrics
    }

    /// Spawn a background task which dump the metrics to the log.  This task
    /// does not terminate and if/when we support clean shutdown this task will
    /// need to be joined.
    fn start_log(&self) {
        let log = self.log.clone();
        let metrics_registry = self.metrics_registry.clone();
        self.rt_handle.spawn(async move {
            let encoder = TextEncoder::new();
            let mut interval = tokio::time::interval(Duration::from_secs(LOG_INTERVAL_SECS));
            loop {
                interval.tick().await;

                // Replica metrics need to be served even if some adapters are unresponsive.
                // To guarantee this, each adapter enforces either the default timeout (1s)
                let metrics_registry_replica = metrics_registry.clone();
                let metrics_registry_adapter = metrics_registry.clone();
                let (mf_replica, mut mf_adapters) = tokio::join!(
                    tokio::spawn(
                        async move { metrics_registry_replica.prometheus_registry().gather() }
                    ),
                    metrics_registry_adapter
                        .adapter_registry()
                        .gather(DEFAULT_ADAPTER_COLLECTION_TIMEOUT)
                );
                mf_adapters.append(&mut mf_replica.unwrap_or_default());

                let mut buffer = Vec::with_capacity(mf_adapters.len());
                encoder.encode(&mf_adapters, &mut buffer).unwrap();
                let metrics = String::from_utf8(buffer).unwrap();
                trace!(log, "{}", metrics);
            }
        });
    }

    /// Spawn a background task to accept and handle metrics connections.  This
    /// task does not terminate and if/when we support clean shutdown this
    /// task will need to be joined.
    fn start_http(&self, address: SocketAddr) {
        // we need to enter the tokio context in order to create the timeout layer and the tcp
        // socket

        let mut addr = "[::]:9090".parse::<SocketAddr>().unwrap();
        addr.set_port(address.port());
        let tcp_listener = start_tcp_listener(addr, &self.rt_handle);
        let _enter: tokio::runtime::EnterGuard = self.rt_handle.enter();
        let metrics_service = get(metrics_endpoint)
            .layer(
                ServiceBuilder::new()
                    .layer(HandleErrorLayer::new(map_box_error_to_response))
                    .load_shed()
                    .timeout(Duration::from_secs(self.config.request_timeout_seconds))
                    .layer(GlobalConcurrencyLimitLayer::new(
                        self.config.max_concurrent_requests,
                    )),
            )
            .with_state((self.metrics_registry.clone(), self.metrics.clone()))
            .into_make_service();
        self.rt_handle.spawn(async move {
            axum::serve(tcp_listener, metrics_service)
                .await
                .expect("Failed to serve.")
        });
    }
}

impl Drop for MetricsHttpEndpoint {
    fn drop(&mut self) {
        if let Exporter::File(ref path) = self.config.exporter {
            match std::fs::OpenOptions::new()
                .write(true)
                .truncate(true)
                .create(true)
                .open(path)
            {
                Ok(mut file) => {
                    let encoder = TextEncoder::new();
                    let metric_families = self.metrics_registry.prometheus_registry().gather();
                    encoder
                        .encode(&metric_families, &mut file)
                        .unwrap_or_else(|err| {
                            error!(
                                self.log,
                                "Failed to encode metrics to file {}: {}",
                                path.display(),
                                err
                            );
                        });
                }
                Err(err) => {
                    error!(self.log, "Failed to open file {}: {}", path.display(), err);
                }
            }
        }
    }
}

async fn metrics_endpoint(
    State((metrics_registry, metrics)): State<(MetricsRegistry, MetricsEndpointMetrics)>,
    req: Request<Body>,
) -> impl IntoResponse {
    metrics.connections_total.with_label_values(&["http"]).inc();
    let encoder = TextEncoder::new();
    // Replica metrics need to be served even if some adapters are unresponsive.
    // To guarantee this, each adapter enforces either the default timeout (1s) or
    // a fraction of the timeout provided by Prometheus in the scrape request header.
    let metrics_registry_replica = metrics_registry.clone();
    let metrics_registry_adapter = metrics_registry.clone();
    let (mf_replica, mut mf_adapters) = tokio::join!(
        tokio::spawn(async move { metrics_registry_replica.prometheus_registry().gather() }),
        metrics_registry_adapter.adapter_registry().gather(
            req.headers()
                .get(PROMETHEUS_TIMEOUT_HEADER)
                .and_then(|h| h.to_str().ok())
                .and_then(|h| Some(Duration::from_secs_f64(h.parse().ok()?)))
                .map(|h| { h.mul_f64(PROMETHEUS_TIMEOUT_FRACTION) })
                .unwrap_or(DEFAULT_ADAPTER_COLLECTION_TIMEOUT),
        )
    );
    mf_adapters.append(&mut mf_replica.unwrap_or_default());

    let mut buffer = Vec::with_capacity(mf_adapters.len());
    encoder.encode(&mf_adapters, &mut buffer).unwrap();

    Response::new(Body::from(buffer))
}

async fn map_box_error_to_response(err: BoxError) -> (StatusCode, String) {
    if err.is::<Overloaded>() {
        (
            StatusCode::TOO_MANY_REQUESTS,
            "The service is overloaded.".to_string(),
        )
    } else if err.is::<Elapsed>() {
        (
            StatusCode::GATEWAY_TIMEOUT,
            "Request took longer than the deadline.".to_string(),
        )
    } else {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Unexpected error: {}", err),
        )
    }
}
