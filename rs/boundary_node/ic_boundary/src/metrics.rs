use std::{
    net::SocketAddr,
    pin::Pin,
    sync::{atomic::AtomicBool, Arc},
    time::Instant,
};

use anyhow::Error;
use arc_swap::ArcSwapOption;
use async_trait::async_trait;
use axum::{
    body::Body,
    extract::{ConnectInfo, State},
    http::Request,
    middleware::Next,
    response::{IntoResponse, Response},
    Extension,
};
use bytes::Buf;
use futures::task::{Context as FutContext, Poll};
use http::header::{HeaderMap, HeaderValue, CONTENT_LENGTH, CONTENT_TYPE};
use http_body::Body as HttpBody;
use ic_types::{messages::ReplicaHealthStatus, CanisterId, SubnetId};
use prometheus::{
    proto::MetricFamily, register_histogram_vec_with_registry,
    register_int_counter_vec_with_registry, register_int_gauge_vec_with_registry,
    register_int_gauge_with_registry, Encoder, HistogramOpts, HistogramVec, IntCounterVec,
    IntGauge, IntGaugeVec, Registry, TextEncoder,
};
use tikv_jemalloc_ctl::{epoch, stats};
use tokio::sync::RwLock;
use tower_http::request_id::RequestId;
use tracing::info;

use crate::{
    cache::{Cache, CacheStatus},
    core::Run,
    geoip,
    http::http_version,
    persist::RouteSubnet,
    retry::RetryResult,
    routes::{ErrorCause, RequestContext, RequestType},
    snapshot::{Node, RegistrySnapshot},
    socket::TcpConnectInfo,
};

const KB: f64 = 1024.0;

pub const HTTP_DURATION_BUCKETS: &[f64] = &[0.05, 0.2, 0.5, 1.0, 2.0, 4.0, 7.0, 11.0];
pub const HTTP_REQUEST_SIZE_BUCKETS: &[f64] = &[128.0, KB, 2.0 * KB, 4.0 * KB, 8.0 * KB];
pub const HTTP_RESPONSE_SIZE_BUCKETS: &[f64] = &[1.0 * KB, 8.0 * KB, 64.0 * KB, 256.0 * KB];

// https://prometheus.io/docs/instrumenting/exposition_formats/#basic-info
const PROMETHEUS_CONTENT_TYPE: &str = "text/plain; version=0.0.4";

const NODE_ID_LABEL: &str = "node_id";
const SUBNET_ID_LABEL: &str = "subnet_id";
const SUBNET_ID_UNKNOWN: &str = "unknown";

pub struct MetricsCache {
    buffer: Vec<u8>,
}

impl MetricsCache {
    pub fn new(capacity: usize) -> Self {
        Self {
            // Preallocate a large enough vector, it'll be expanded if needed
            buffer: Vec::with_capacity(capacity),
        }
    }
}

// Iterates over given metric families and removes metrics that have
// node_id+subnet_id labels and where the corresponding nodes are
// not present in the registry snapshot
fn remove_stale_metrics(
    snapshot: Arc<RegistrySnapshot>,
    mut mfs: Vec<MetricFamily>,
) -> Vec<MetricFamily> {
    mfs.iter_mut().for_each(|mf| {
        // Iterate over the metrics in the metric family
        let metrics = mf
            .take_metric()
            .into_iter()
            .filter(|v| {
                // See if this metric has node_id/subnet_id labels
                let node_id = v
                    .get_label()
                    .iter()
                    .find(|&v| v.get_name() == NODE_ID_LABEL)
                    .map(|x| x.get_value());

                let subnet_id = v
                    .get_label()
                    .iter()
                    .find(|&v| v.get_name() == SUBNET_ID_LABEL)
                    .map(|x| x.get_value());

                match (node_id, subnet_id) {
                    // Check if we got both node_id and subnet_id labels
                    (Some(node_id), Some(subnet_id)) => snapshot
                        .nodes
                        // Check if the node_id is in the snapshot
                        .get(node_id)
                        // Check if its subnet_id matches, otherwise the metric needs to be removed
                        .map(|x| x.subnet_id.to_string() == subnet_id)
                        .unwrap_or(false),

                    // If there's only subnet_id label - check if this subnet exists
                    // TODO create a hashmap of subnets in snapshot for faster lookup, currently complexity is O(n)
                    // but since we have very few subnets currently (<40) probably it's Ok
                    (None, Some(subnet_id)) => {
                        subnet_id == SUBNET_ID_UNKNOWN
                            || snapshot
                                .subnets
                                .iter()
                                .any(|x| x.id.to_string() == subnet_id)
                    }

                    // Otherwise just pass this metric through
                    _ => true,
                }
            })
            .collect();

        mf.set_metric(metrics);
    });

    mfs
}

pub struct MetricsRunner {
    metrics_cache: Arc<RwLock<MetricsCache>>,
    registry: Registry,
    encoder: TextEncoder,

    cache: Option<Arc<Cache>>,
    cache_items: IntGauge,
    cache_size: IntGauge,

    mem_allocated: IntGauge,
    mem_resident: IntGauge,

    published_registry_snapshot: Arc<ArcSwapOption<RegistrySnapshot>>,
}

// Snapshots & encodes the metrics for the handler to export
impl MetricsRunner {
    pub fn new(
        metrics_cache: Arc<RwLock<MetricsCache>>,
        registry: Registry,
        cache: Option<Arc<Cache>>,
        published_registry_snapshot: Arc<ArcSwapOption<RegistrySnapshot>>,
    ) -> Self {
        let cache_items = register_int_gauge_with_registry!(
            format!("cache_items"),
            format!("Number of items in the request cache"),
            registry
        )
        .unwrap();

        let cache_size = register_int_gauge_with_registry!(
            format!("cache_size"),
            format!("Size of items in the request cache in bytes"),
            registry
        )
        .unwrap();

        let mem_allocated = register_int_gauge_with_registry!(
            format!("memory_allocated"),
            format!("Allocated memory in bytes"),
            registry
        )
        .unwrap();

        let mem_resident = register_int_gauge_with_registry!(
            format!("memory_resident"),
            format!("Resident memory in bytes"),
            registry
        )
        .unwrap();

        Self {
            metrics_cache,
            registry,
            encoder: TextEncoder::new(),
            cache,
            cache_items,
            cache_size,
            mem_allocated,
            mem_resident,
            published_registry_snapshot,
        }
    }
}

#[async_trait]
impl Run for MetricsRunner {
    async fn run(&mut self) -> Result<(), Error> {
        // Record jemalloc memory usage
        epoch::advance().unwrap();
        self.mem_allocated
            .set(stats::allocated::read().unwrap() as i64);
        self.mem_resident
            .set(stats::resident::read().unwrap() as i64);

        // Gather cache stats if it's enabled, otherwise set to zero
        let (cache_items, cache_size) = match self.cache.as_ref() {
            Some(v) => {
                v.housekeep().await;
                (v.len(), v.size())
            }

            None => (0, 0),
        };

        self.cache_items.set(cache_items as i64);
        self.cache_size.set(cache_size as i64);

        // Get a snapshot of metrics
        let mut metric_families = self.registry.gather();

        // If we have a published snapshot - use it to remove the metrics not present anymore
        if let Some(snapshot) = self.published_registry_snapshot.load_full() {
            metric_families = remove_stale_metrics(snapshot, metric_families);
        }

        // Take a write lock, truncate the vector and encode the metrics into it
        let mut metrics_cache = self.metrics_cache.write().await;
        metrics_cache.buffer.clear();
        self.encoder
            .encode(&metric_families, &mut metrics_cache.buffer)?;

        Ok(())
    }
}

// A wrapper for http::Body implementations that tracks the number of bytes sent
pub struct MetricsBody<D, E> {
    inner: Pin<Box<dyn HttpBody<Data = D, Error = E> + Send + 'static>>,
    // TODO see if we can make this FnOnce somehow
    callback: Box<dyn Fn(u64, Result<(), String>) + Send + 'static>,
    callback_done: AtomicBool,
    expected_size: Option<u64>,
    bytes_sent: u64,
}

impl<D, E> MetricsBody<D, E> {
    pub fn new<B>(
        body: B,
        content_length: Option<HeaderValue>,
        callback: impl Fn(u64, Result<(), String>) + Send + 'static,
    ) -> Self
    where
        B: HttpBody<Data = D, Error = E> + Send + 'static,
        D: Buf,
    {
        // Body can sometimes provide an exact size in the hint, use that
        let expected_size = body.size_hint().exact().or_else(|| {
            // Try to parse header if provided otherwise
            content_length.and_then(|x| x.to_str().ok().and_then(|x| x.parse::<u64>().ok()))
        });

        let mut body = Self {
            inner: Box::pin(body),
            callback: Box::new(callback),
            callback_done: AtomicBool::new(false),
            expected_size,
            bytes_sent: 0,
        };

        // If the size is known and zero - just execute the callback now, it won't be called anywhere else
        if expected_size == Some(0) {
            body.do_callback(Ok(()));
        }

        body
    }

    // In certain cases the users of HttpBody trait can cause us to run callbacks more than once
    // Use AtomicBool to prevent that and run it at most once
    pub fn do_callback(&mut self, res: Result<(), String>) {
        // Make locking scope shorter
        {
            let done = self.callback_done.get_mut();
            if *done {
                return;
            }
            *done = true;
        }

        (self.callback)(self.bytes_sent, res);
    }
}

// According to the research, the users of HttpBody can determine the time when
// there's no more data to fetch in several ways:
//
// 1) When there's no Content-Length header they just call poll_data() until it yields Poll::Ready(None)
// 2) When there's such header - they call poll_data() until they get advertised in the header number of bytes
//    and don't call poll_data() anymore so Poll::Ready(None) variant is never reached
// 3) They call is_end_stream() and if it returns true then they don't call poll_data() anymore
// 4) By using size_hint() if it yields an exact number
//
// So we have to cover all these:
// * We don't implement is_end_stream() (default impl in Trait just returns false) so that
//   the caller will have to use poll_data()
// * We have to have a Content-Length stored to check if we got already that much data
// * We check size_hint() for an exact value

impl<D, E> HttpBody for MetricsBody<D, E>
where
    D: Buf,
    E: std::string::ToString,
{
    type Data = D;
    type Error = E;

    fn poll_data(
        mut self: Pin<&mut Self>,
        cx: &mut FutContext<'_>,
    ) -> Poll<Option<Result<Self::Data, Self::Error>>> {
        let poll = self.inner.as_mut().poll_data(cx);

        match &poll {
            // There is still some data available
            Poll::Ready(Some(v)) => match v {
                Ok(buf) => {
                    self.bytes_sent += buf.remaining() as u64;

                    // Check if we already got what was expected
                    if Some(self.bytes_sent) >= self.expected_size {
                        self.do_callback(Ok(()));
                    }
                }

                // Error occured, execute callback
                Err(e) => {
                    // Error is not Copy/Clone so use string instead
                    self.do_callback(Err(e.to_string()));
                }
            },

            // Nothing left, execute callback
            Poll::Ready(None) => {
                self.do_callback(Ok(()));
            }

            // Do nothing
            Poll::Pending => {}
        }

        poll
    }

    fn poll_trailers(
        mut self: Pin<&mut Self>,
        cx: &mut FutContext<'_>,
    ) -> Poll<Result<Option<HeaderMap>, Self::Error>> {
        self.inner.as_mut().poll_trailers(cx)
    }

    fn size_hint(&self) -> http_body::SizeHint {
        self.inner.size_hint()
    }
}

pub struct WithMetrics<T>(pub T, pub MetricParams);

#[derive(Clone)]
pub struct MetricParams {
    pub action: String,
    pub counter: IntCounterVec,
    pub recorder: HistogramVec,
}

impl MetricParams {
    pub fn new(registry: &Registry, action: &str) -> Self {
        Self::new_with_opts(registry, action, &["status"], None)
    }

    pub fn new_with_opts(
        registry: &Registry,
        action: &str,
        labels: &[&str],
        buckets: Option<&[f64]>,
    ) -> Self {
        let mut recorder_opts = HistogramOpts::new(
            format!("{action}_duration_sec"),
            format!("Records the duration of {action} calls in seconds"),
        );

        if let Some(b) = buckets {
            recorder_opts.buckets = b.to_vec();
        }

        Self {
            action: action.to_string(),

            // Count
            counter: register_int_counter_vec_with_registry!(
                format!("{action}_total"),
                format!("Counts occurrences of {action} calls"),
                labels,
                registry
            )
            .unwrap(),

            // Duration
            recorder: register_histogram_vec_with_registry!(recorder_opts, labels, registry)
                .unwrap(),
        }
    }
}

pub struct WithMetricsPersist<T>(pub T, pub MetricParamsPersist);

#[derive(Clone)]
pub struct MetricParamsPersist {
    pub ranges: IntGauge,
    pub nodes: IntGauge,
}

impl MetricParamsPersist {
    pub fn new(registry: &Registry) -> Self {
        Self {
            // Number of ranges
            ranges: register_int_gauge_with_registry!(
                format!("persist_ranges"),
                format!("Number of canister ranges currently published"),
                registry
            )
            .unwrap(),

            // Number of nodes
            nodes: register_int_gauge_with_registry!(
                format!("persist_nodes"),
                format!("Number of nodes currently published"),
                registry
            )
            .unwrap(),
        }
    }
}

#[derive(Clone)]
pub struct WithMetricsCheck<T>(pub T, pub MetricParamsCheck);

#[derive(Clone)]
pub struct MetricParamsCheck {
    pub counter: IntCounterVec,
    pub recorder: HistogramVec,
    pub status: IntGaugeVec,
}

impl MetricParamsCheck {
    pub fn new(registry: &Registry) -> Self {
        let mut opts = HistogramOpts::new(
            "check_duration_sec",
            "Records the duration of check calls in seconds",
        );
        opts.buckets = HTTP_DURATION_BUCKETS.to_vec();

        let labels = &["status", NODE_ID_LABEL, SUBNET_ID_LABEL, "addr"];

        Self {
            counter: register_int_counter_vec_with_registry!(
                "check_total",
                "Counts occurrences of check calls",
                labels,
                registry
            )
            .unwrap(),

            // Duration
            recorder: register_histogram_vec_with_registry!(opts, labels, registry).unwrap(),

            // Status of node
            status: register_int_gauge_vec_with_registry!(
                "check_status",
                "Last check result of a given node",
                &labels[1..4],
                registry
            )
            .unwrap(),
        }
    }
}

#[derive(Clone)]
pub struct HttpMetricParams {
    pub action: String,
    pub log_failed_requests_only: bool,
    pub counter: IntCounterVec,
    pub durationer: HistogramVec,
    pub request_sizer: HistogramVec,
    pub response_sizer: HistogramVec,
}

impl HttpMetricParams {
    pub fn new(registry: &Registry, action: &str, log_failed_requests_only: bool) -> Self {
        const LABELS_HTTP: &[&str] = &[
            "request_type",
            "status_code",
            SUBNET_ID_LABEL,
            "error_cause",
            "cache_status",
            "cache_bypass",
            "retry",
        ];

        Self {
            action: action.to_string(),
            log_failed_requests_only,

            counter: register_int_counter_vec_with_registry!(
                format!("{action}_total"),
                format!("Counts occurrences of {action} calls"),
                LABELS_HTTP,
                registry
            )
            .unwrap(),

            durationer: register_histogram_vec_with_registry!(
                format!("{action}_duration_sec"),
                format!("Records the duration of {action} request processing in seconds"),
                LABELS_HTTP,
                HTTP_DURATION_BUCKETS.to_vec(),
                registry
            )
            .unwrap(),

            request_sizer: register_histogram_vec_with_registry!(
                format!("{action}_request_size"),
                format!("Records the size of {action} requests"),
                LABELS_HTTP,
                HTTP_REQUEST_SIZE_BUCKETS.to_vec(),
                registry
            )
            .unwrap(),

            response_sizer: register_histogram_vec_with_registry!(
                format!("{action}_response_size"),
                format!("Records the size of {action} responses"),
                LABELS_HTTP,
                HTTP_RESPONSE_SIZE_BUCKETS.to_vec(),
                registry
            )
            .unwrap(),
        }
    }
}

pub struct WithMetricsSnapshot<T>(pub T, pub MetricParamsSnapshot);

#[derive(Clone)]
pub struct MetricParamsSnapshot {
    pub version: IntGauge,
    pub timestamp: IntGauge,
}

impl MetricParamsSnapshot {
    pub fn new(registry: &Registry) -> Self {
        Self {
            version: register_int_gauge_with_registry!(
                format!("registry_version"),
                format!("Currently published registry version"),
                registry
            )
            .unwrap(),

            timestamp: register_int_gauge_with_registry!(
                format!("registry_timestamp"),
                format!("Timestamp of the last registry update"),
                registry
            )
            .unwrap(),
        }
    }
}

#[derive(Clone)]
pub struct HttpMetricParamsStatus {
    pub counter: IntCounterVec,
}

impl HttpMetricParamsStatus {
    pub fn new(registry: &Registry) -> Self {
        Self {
            counter: register_int_counter_vec_with_registry!(
                format!("http_request_status_total"),
                format!("Counts occurrences of status calls"),
                &["health"],
                registry
            )
            .unwrap(),
        }
    }
}

pub async fn metrics_middleware_status(
    State(metric_params): State<HttpMetricParamsStatus>,
    request: Request<Body>,
    next: Next<Body>,
) -> impl IntoResponse {
    let response = next.run(request).await;
    let health = response
        .extensions()
        .get::<ReplicaHealthStatus>()
        .unwrap()
        .as_ref();

    let HttpMetricParamsStatus { counter } = metric_params;
    counter.with_label_values(&[health]).inc();

    response
}

// middleware to log and measure proxied canister and subnet requests
pub async fn metrics_middleware(
    State(metric_params): State<HttpMetricParams>,
    Extension(request_id): Extension<RequestId>,
    request: Request<Body>,
    next: Next<Body>,
) -> impl IntoResponse {
    let request_id = request_id.header_value().to_str().unwrap_or("").to_string();

    let ip_family = request
        .extensions()
        .get::<ConnectInfo<TcpConnectInfo>>()
        .map(|x| (x.0).0)
        .or(request
            .extensions()
            .get::<ConnectInfo<SocketAddr>>()
            .map(|x| x.0))
        .map(|x| if x.is_ipv4() { "4" } else { "6" })
        .unwrap_or("0");

    let request_type = &request
        .extensions()
        .get::<RequestType>()
        .cloned()
        .unwrap_or_default();
    let request_type: &'static str = request_type.into();

    let country_code = request
        .extensions()
        .get::<geoip::GeoData>()
        .map(|x| x.country_code.clone())
        .unwrap_or("N/A".into());

    // for canister requests we extract canister_id
    let canister_id = request
        .extensions()
        .get::<CanisterId>()
        .map(|x| x.to_string());

    // for /api/v2/subnet requests we extract subnet_id directly from extension
    let subnet_id = request
        .extensions()
        .get::<SubnetId>()
        .map(|x| x.to_string());

    let http_version = http_version(request.version());

    // Perform the request & measure duration
    let start_time = Instant::now();
    let response = next.run(request).await;
    let proc_duration = start_time.elapsed().as_secs_f64();

    // in case subnet_id=None (i.e. for /api/v2/canister/... request), we get the target subnet_id from the RouteSubnet extension
    let subnet_id = subnet_id.or(response
        .extensions()
        .get::<Arc<RouteSubnet>>()
        .map(|x| x.id.to_string()));

    // Extract extensions
    let ctx = response
        .extensions()
        .get::<Arc<RequestContext>>()
        .cloned()
        .unwrap_or_default();

    // Actual canister id is the one the request was routed to
    // Might be different because of e.g. Bitcoin middleware
    let canister_id_actual = response.extensions().get::<CanisterId>().cloned();
    let error_cause = response.extensions().get::<ErrorCause>().cloned();
    let retry_result = response.extensions().get::<RetryResult>().cloned();
    let node = response.extensions().get::<Arc<Node>>();
    let cache_status = response
        .extensions()
        .get::<CacheStatus>()
        .cloned()
        .unwrap_or_default();

    // Prepare fields
    let status_code = response.status();
    let sender = ctx.sender.map(|x| x.to_string());
    let node_id = node.as_ref().map(|x| x.id.to_string());

    let HttpMetricParams {
        action,
        log_failed_requests_only,
        counter,
        durationer,
        request_sizer,
        response_sizer,
    } = metric_params;

    // Closure that gets called when the response body is fully read (or an error occurs)
    let record_metrics = move |response_size: u64, _body_result: Result<(), String>| {
        let full_duration = start_time.elapsed().as_secs_f64();
        let failed = error_cause.is_some() || !status_code.is_success();

        let (error_cause, error_details) = match &error_cause {
            Some(v) => (Some(v.to_string()), v.details()),
            None => (None, None),
        };

        let cache_bypass_reason = match &cache_status {
            CacheStatus::Bypass(v) => Some(v.to_string()),
            _ => None,
        };

        let retry_result = retry_result.clone();

        // Prepare labels
        // Otherwise "temporary value dropped" error occurs
        let error_cause_lbl = error_cause.clone().unwrap_or("none".to_string());
        let subnet_id_lbl = subnet_id.clone().unwrap_or(SUBNET_ID_UNKNOWN.to_string());
        let cache_status_lbl = &cache_status.to_string();
        let cache_bypass_reason_lbl = cache_bypass_reason.clone().unwrap_or("none".to_string());
        let retry_lbl =
            // Check if retry happened and if it succeeded
            if let Some(v) = &retry_result {
                if v.success {
                    "ok"
                } else {
                    "fail"
                }
            } else {
                "no"
            };

        // Average cardinality up to 150k
        let labels = &[
            request_type,                     // x3
            status_code.as_str(),             // x27 but usually x8
            subnet_id_lbl.as_str(),           // x37 as of now
            error_cause_lbl.as_str(),         // x15 but usually x6
            cache_status_lbl.as_str(),        // x4
            cache_bypass_reason_lbl.as_str(), // x6 but since it relates only to BYPASS cache status -> total for 2 fields is x9
            retry_lbl,                        // x3
        ];

        counter.with_label_values(labels).inc();
        durationer.with_label_values(labels).observe(proc_duration);
        request_sizer
            .with_label_values(labels)
            .observe(ctx.request_size as f64);
        response_sizer
            .with_label_values(labels)
            .observe(response_size as f64);

        if !log_failed_requests_only || failed {
            info!(
                action,
                request_id,
                http = http_version,
                request_type,
                error_cause,
                error_details,
                status = status_code.as_u16(),
                subnet_id,
                node_id,
                canister_id,
                canister_id_actual = canister_id_actual.map(|x| x.to_string()),
                canister_id_cbor = ctx.canister_id.map(|x| x.to_string()),
                sender,
                method = ctx.method_name,
                duration = proc_duration,
                duration_full = full_duration,
                request_size = ctx.request_size,
                response_size,
                retry_count = &retry_result.as_ref().map(|x| x.retries),
                retry_success = &retry_result.map(|x| x.success),
                %cache_status,
                cache_bypass_reason = cache_bypass_reason.map(|x| x.to_string()),
                country_code,
                client_ip_family = ip_family,
            );
        }
    };

    let (parts, body) = response.into_parts();
    let content_length = parts.headers.get(CONTENT_LENGTH).cloned();
    let body = MetricsBody::new(body, content_length, record_metrics);

    Response::from_parts(parts, body)
}

#[derive(Clone)]
pub struct MetricsHandlerArgs {
    pub cache: Arc<RwLock<MetricsCache>>,
}

// Axum handler for /metrics endpoint
pub async fn metrics_handler(
    State(MetricsHandlerArgs { cache }): State<MetricsHandlerArgs>,
) -> impl IntoResponse {
    // Get a read lock and clone the buffer contents
    (
        [(CONTENT_TYPE, PROMETHEUS_CONTENT_TYPE)],
        cache.read().await.buffer.clone(),
    )
}

#[cfg(test)]
pub mod test;
