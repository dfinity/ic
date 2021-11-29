//! Async server that executes blackbox probes.

use crate::metrics::ProberMetrics;
use crate::probe::{Probe, ProbeResult, ProbeResultHelper};
use ic_metrics::{MetricsRegistry, Timer};
use prometheus::{Encoder, TextEncoder};
use slog::{info, warn, Logger};
use std::sync::Arc;
use std::time::{Duration, Instant};
use std::{borrow::Cow, convert::TryFrom, io::Cursor, net::SocketAddr};
use tiny_http::{Header, Request, Response, Server, StatusCode};
use url::Url;

/// An async server that executes blackbox probes.
///
/// Exposed APIs:
///
/// * `/probe/{name}[?<probe_parameters>]`
///   - Executes the probe identified by name, with the provided parameters
///     (specific to each probe).
/// * `/metrics`
///   - Exposes the prober's own metrics, encoded in plaintext.
pub struct Prober {
    server: Server,
    metrics: Arc<ProberMetrics>,
    registry: Arc<MetricsRegistry>,
    log: Arc<Logger>,
}

const PROBE_PATH_PREFIX: &str = "/probe/";
const METRICS_PATH: &str = "/metrics";
const OTHER_PATH: &str = "other";

/// Scrape timeout header provided by Prometheus.
const HEADER_SCRAPE_TIMEOUT: &str = "X-Prometheus-Scrape-Timeout-Seconds";

/// Default scrape/probe timeout, when not provided by Prometheus.
const SCRAPE_TIMEOUT_DEFAULT: Duration = Duration::from_secs(10);
/// Amount to subtract from scrape/probe timeout, to account for network and
/// prober overhead.
const SCRAPE_TIMEOUT_OFFSET: Duration = Duration::from_millis(500);

pub const STATUS_CODE_OK: StatusCode = StatusCode(200);
pub const STATUS_CODE_BAD_REQUEST: StatusCode = StatusCode(400);
pub const STATUS_CODE_NOT_FOUND: StatusCode = StatusCode(404);
pub const STATUS_CODE_INTERNAL_SERVER_ERROR: StatusCode = StatusCode(500);

/// A parameter iterator type (that happens to match the type returned by
/// `url::Url::query_pairs()`).
pub type ParamIterator<'a> = &'a mut (dyn Iterator<Item = (Cow<'a, str>, Cow<'a, str>)> + Send);

impl Prober {
    /// Creates a `Prober` listening on the given address, exporting its own
    /// metrics to the given registry and using the given logger for logging.
    pub fn new(address: SocketAddr, registry: MetricsRegistry, log: Logger) -> Self {
        let server =
            Server::http(address).unwrap_or_else(|e| panic!("Starting HTTP server failed: {}", e));
        Self {
            server,
            metrics: Arc::new(ProberMetrics::new(&registry)),
            registry: Arc::new(registry),
            log: Arc::new(log),
        }
    }

    /// Runs the prober in an infinite loop. Never returns.
    pub fn run(&self) {
        info!(
            self.log,
            "IC Prober listening on {}",
            self.server.server_addr()
        );

        let base_url =
            Arc::new(Url::parse(&format!("http://{}/", self.server.server_addr())).unwrap());
        loop {
            match self.server.recv() {
                Ok(request) => {
                    let handle_http_request_future = handle_http_request(
                        request,
                        base_url.clone(),
                        self.metrics.clone(),
                        self.registry.clone(),
                        self.log.clone(),
                    );
                    tokio::task::spawn(handle_http_request_future);
                }
                Err(e) => warn!(self.log, "server.recv() returned error: {}", e),
            }
        }
    }
}

/// Handles an incoming HTTP request by parsing the URL, handing over to
/// `route_request()` and replying with the produced response.
async fn handle_http_request(
    request: Request,
    base_url: Arc<Url>,
    metrics: Arc<ProberMetrics>,
    registry: Arc<MetricsRegistry>,
    log: Arc<Logger>,
) {
    let timer = Timer::start();

    let url = request.url();
    let (path, status, response) = match base_url.join(url) {
        Ok(url) => {
            let deadline = probe_deadline(&request, &log);
            route_request(url, deadline, &metrics, &registry, &log).await
        }

        Err(e) => {
            let msg = format!("Invalid URL {}: {}", url, e);
            warn!(log, "{}", msg);
            (
                OTHER_PATH,
                STATUS_CODE_BAD_REQUEST,
                Response::from_data(msg).with_status_code(STATUS_CODE_BAD_REQUEST),
            )
        }
    };
    request
        .respond(response)
        .unwrap_or_else(|e| warn!(log, "Error responding: {}", e));

    metrics
        .request_duration
        .with_label_values(&[path, &status.0.to_string()])
        .observe(timer.elapsed());
}

/// Routes a request to the appropriate handler; or produces an `HTTP 404 Not
/// Found` response if the URL doesn't match any handler.
///
/// Returns a tuple containing the matched path/path prefix, response status
/// code and response.
async fn route_request(
    url: Url,
    deadline: Instant,
    metrics: &ProberMetrics,
    registry: &MetricsRegistry,
    log: &Logger,
) -> (&'static str, StatusCode, Response<Cursor<Vec<u8>>>) {
    match url.path() {
        probe_path if probe_path.starts_with(PROBE_PATH_PREFIX) => {
            let probe_name = &probe_path[PROBE_PATH_PREFIX.len()..];
            let res =
                handle_probe(probe_name, deadline, &mut url.query_pairs(), metrics, log).await;
            if let Err((status_code, msg)) = res.as_ref() {
                info!(
                    log,
                    "Probe {} failed with HTTP {}: {}", url, status_code.0, msg
                );
            }
            (PROBE_PATH_PREFIX, res.status_code(), res.into_response())
        }

        METRICS_PATH => (METRICS_PATH, STATUS_CODE_OK, encode(registry)),

        _ => {
            info!(log, "No matching handler for {}", url);
            (
                OTHER_PATH,
                STATUS_CODE_NOT_FOUND,
                Response::from_data("Not Found").with_status_code(STATUS_CODE_NOT_FOUND),
            )
        }
    }
}

/// Executes the probe identified by the given name and returns the metrics it
/// produced; an error response on invalid parameters or internal error; or `404
/// Not Found` if a probe with the given name does not exist.
pub async fn handle_probe(
    name: &str,
    deadline: Instant,
    params: ParamIterator<'_>,
    metrics: &ProberMetrics,
    log: &Logger,
) -> ProbeResult {
    let timer = Timer::start();

    let probe = Probe::try_from(name)?;
    let result = probe.run(params, deadline, log).await;

    metrics
        .probe_duration
        .with_label_values(&[name, &result.status_code().0.to_string()])
        .observe(timer.elapsed());

    result
}

/// Encodes the given `MetricsRegistry` as a plaintext `Response`.
pub fn encode(registry: &MetricsRegistry) -> Response<Cursor<Vec<u8>>> {
    let metric_families = registry.prometheus_registry().gather();
    let encoder = TextEncoder::default();
    let mut buffer = vec![];
    encoder.encode(&metric_families, &mut buffer).unwrap();

    let mut response = Response::from_data(buffer);
    let content_type = Header::from_bytes(&b"Content-Type"[..], encoder.format_type())
        .expect("Could not parse Content-Type header");
    response.add_header(content_type);

    response
}

/// Calculates a timeout for a probe based on Prometheus'
// `X-Prometheus-Scrape-Timeout-Seconds` header minus some offset to account for
// any communication overhead.
fn probe_deadline(request: &Request, log: &Logger) -> Instant {
    let probe_timeout = request
        .headers()
        .iter()
        .find(|h| h.field.as_str().as_str() == HEADER_SCRAPE_TIMEOUT)
        .map(|h| {
            h.value
                .as_str()
                .parse::<f64>()
                .map_err(|e| info!(log, "Invalid {} header: {}", HEADER_SCRAPE_TIMEOUT, e))
        })
        .and_then(|r| r.map(Duration::from_secs_f64).ok())
        .unwrap_or(SCRAPE_TIMEOUT_DEFAULT);

    Instant::now() + probe_timeout - SCRAPE_TIMEOUT_OFFSET
}
