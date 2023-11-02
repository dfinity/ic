use hyper::{server::conn::Http, Body, Request, Response, StatusCode};
use ic_async_utils::start_tcp_listener;
use ic_config::metrics::{Config, Exporter};
use ic_crypto_tls_interfaces::TlsHandshake;
use ic_interfaces_registry::RegistryClient;
use ic_metrics::registry::MetricsRegistry;
use prometheus::{Encoder, IntCounterVec, TextEncoder};
use slog::{error, trace, warn};
use std::net::SocketAddr;
use std::string::String;
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio_io_timeout::TimeoutStream;
use tower::{
    limit::concurrency::GlobalConcurrencyLimitLayer, load_shed::error::Overloaded,
    timeout::error::Elapsed, util::BoxCloneService, BoxError, Service, ServiceBuilder, ServiceExt,
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
    crypto_tls: Option<(Arc<dyn RegistryClient>, Arc<dyn TlsHandshake + Send + Sync>)>,
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
        registry_client: Arc<dyn RegistryClient>,
        crypto: Arc<dyn TlsHandshake + Send + Sync>,
        log: &slog::Logger,
    ) -> Self {
        let log = log.new(slog::o!("Application" => "MetricsRuntime"));

        let metrics = Self {
            rt_handle,
            config,
            metrics_registry: metrics_registry.clone(),
            crypto_tls: Some((registry_client, crypto)),
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

    /// Create a MetricsHttpEndpoint supporting only HTTP for insecure use cases
    /// e.g. testing binaries where the node certificate may not be available.
    pub fn new_insecure(
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
            crypto_tls: None,
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
        let _enter = self.rt_handle.enter();

        let metrics_registry = self.metrics_registry.clone();
        let metrics_svc = ServiceBuilder::new()
            .load_shed()
            .timeout(Duration::from_secs(self.config.request_timeout_seconds))
            .layer(GlobalConcurrencyLimitLayer::new(
                self.config.max_concurrent_requests,
            ))
            .service_fn(move |req: Request<Body>| {
                // Clone again to ensure that `metrics_registry` outlives this closure.
                let metrics_registry = metrics_registry.clone();
                let encoder = TextEncoder::new();
                async move {
                    // Replica metrics need to be served even if some adapters are unresponsive.
                    // To guarantee this, each adapter enforces either the default timeout (1s) or
                    // a fraction of the timeout provided by Prometheus in the scrape request header.
                    let metrics_registry_replica = metrics_registry.clone();
                    let metrics_registry_adapter = metrics_registry.clone();
                    let (mf_replica, mut mf_adapters) = tokio::join!(
                        tokio::spawn(async move {
                            metrics_registry_replica.prometheus_registry().gather()
                        }),
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

                    Ok::<_, std::convert::Infallible>(Response::new(Body::from(buffer)))
                }
            })
            .map_result(move |result| -> Result<Response<Body>, HttpError> {
                match result {
                    Ok(response) => Ok(response),
                    Err(err) => Ok(HttpError::from(err).response),
                }
            });
        let metrics_svc = BoxCloneService::new(metrics_svc);

        let log = self.log.clone();
        let crypto_tls = self.crypto_tls.clone();
        let metrics = self.metrics.clone();
        let config = self.config.clone();
        let conn_svc = ServiceBuilder::new().service_fn(move |tcp_stream: TcpStream| {
            let log = log.clone();
            let metrics_svc = metrics_svc.clone();
            let metrics = metrics.clone();
            let crypto_tls = crypto_tls.clone();
            let config = config.clone();

            async move {
                match crypto_tls {
                    Some((registry_client, crypto)) => {
                        handshake_and_serve_connection(
                            log,
                            config,
                            tcp_stream,
                            metrics_svc,
                            registry_client,
                            crypto,
                            metrics,
                        )
                        .await
                    }
                    None => {
                        metrics.connections_total.with_label_values(&["http"]).inc();
                        serve_connection_with_read_timeout(
                            tcp_stream,
                            metrics_svc,
                            config.connection_read_timeout_seconds,
                        )
                        .await
                    }
                }
            }
        });
        let conn_svc = BoxCloneService::new(conn_svc);

        // Temporarily listen on [::] so that we accept both IPv4 and IPv6 connections.
        // This requires net.ipv6.bindv6only = 0.  TODO: revert this once we have rolled
        // out IPv6 in prometheus and ic_p8s_service_discovery.
        let mut addr = "[::]:9090".parse::<SocketAddr>().unwrap();
        addr.set_port(address.port());
        let tcp_listener = start_tcp_listener(addr);
        self.rt_handle.spawn(async move {
            loop {
                let mut conn_svc = conn_svc.clone();
                if let Ok((tcp_stream, _)) = tcp_listener.accept().await {
                    tokio::spawn(async move {
                        let _ = conn_svc
                            .ready()
                            .await
                            .expect("The load shedder must always be ready.")
                            .call(tcp_stream)
                            .await;
                    });
                }
            }
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

async fn handshake_and_serve_connection(
    log: slog::Logger,
    config: Config,
    tcp_stream: TcpStream,
    metrics_svc: BoxCloneService<Request<Body>, Response<Body>, HttpError>,
    registry_client: Arc<dyn RegistryClient>,
    tls_handshake: Arc<dyn TlsHandshake + Send + Sync>,
    metrics: MetricsEndpointMetrics,
) -> Result<(), hyper::Error> {
    let mut b = [0_u8; 1];
    if tcp_stream.peek(&mut b).await.is_ok() && b[0] == 22 {
        let registry_version = registry_client.get_latest_version();
        match tls_handshake
            .perform_tls_server_handshake_without_client_auth(tcp_stream, registry_version)
            .await
        {
            Err(err) => {
                warn!(log, "TLS handshake failed {}", err);
                Ok(())
            }
            Ok(stream) => {
                metrics
                    .connections_total
                    .with_label_values(&["https"])
                    .inc();
                serve_connection_with_read_timeout(
                    stream,
                    metrics_svc,
                    config.connection_read_timeout_seconds,
                )
                .await
            }
        }
    } else {
        metrics.connections_total.with_label_values(&["http"]).inc();
        serve_connection_with_read_timeout(
            tcp_stream,
            metrics_svc,
            config.connection_read_timeout_seconds,
        )
        .await
    }
}

async fn serve_connection_with_read_timeout<T: AsyncRead + AsyncWrite + 'static>(
    stream: T,
    metrics_svc: BoxCloneService<Request<Body>, Response<Body>, HttpError>,
    connection_read_timeout_seconds: u64,
) -> Result<(), hyper::Error> {
    let http = Http::new();
    let mut stream = TimeoutStream::new(stream);
    stream.set_read_timeout(Some(Duration::from_secs(connection_read_timeout_seconds)));
    let stream = Box::pin(stream);
    http.serve_connection(stream, metrics_svc).await
}
