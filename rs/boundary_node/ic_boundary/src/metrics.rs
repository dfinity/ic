use std::{pin::Pin, sync::Arc, time::Instant};

use anyhow::Error;
use async_trait::async_trait;
use axum::{
    body::Body,
    extract::State,
    http::Request,
    middleware::Next,
    response::{IntoResponse, Response},
    Extension,
};
use bytes::Buf;
use futures::task::{Context as FutContext, Poll};
use http::header::{HeaderMap, HeaderValue, CONTENT_LENGTH, CONTENT_TYPE};
use http_body::Body as HttpBody;
use ic_types::{messages::ReplicaHealthStatus, CanisterId};
use jemalloc_ctl::{epoch, stats};
use prometheus::{
    register_histogram_vec_with_registry, register_int_counter_vec_with_registry,
    register_int_gauge_with_registry, Encoder, HistogramOpts, HistogramVec, IntCounterVec,
    IntGauge, Registry, TextEncoder,
};
use tokio::sync::RwLock;
use tower_http::request_id::RequestId;
use tracing::info;

use crate::{
    cache::CacheStatus,
    core::Run,
    routes::{ErrorCause, RequestContext},
    snapshot::Node,
};

const KB: f64 = 1024.0;

pub const HTTP_DURATION_BUCKETS: &[f64] = &[0.05, 0.1, 0.2, 0.4, 0.8, 2.0, 4.0];
pub const HTTP_REQUEST_SIZE_BUCKETS: &[f64] =
    &[128.0, 256.0, 512.0, KB, 2.0 * KB, 4.0 * KB, 8.0 * KB];
pub const HTTP_RESPONSE_SIZE_BUCKETS: &[f64] =
    &[1.0 * KB, 8.0 * KB, 64.0 * KB, 256.0 * KB, 512.0 * KB];

// https://prometheus.io/docs/instrumenting/exposition_formats/#basic-info
const PROMETHEUS_CONTENT_TYPE: &str = "text/plain; version=0.0.4";

const LABELS_HTTP: &[&str] = &[
    "request_type",
    "status_code",
    "subnet_id",
    "node_id",
    "error_cause",
    "cache_status",
    "cache_bypass",
];

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

pub struct MetricsRunner {
    cache: Arc<RwLock<MetricsCache>>,
    registry: Registry,
    encoder: TextEncoder,

    mem_allocated: IntGauge,
    mem_resident: IntGauge,
}

// Snapshots & encodes the metrics for the handler to export
impl MetricsRunner {
    pub fn new(cache: Arc<RwLock<MetricsCache>>, registry: Registry) -> Self {
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
            cache,
            registry,
            encoder: TextEncoder::new(),
            mem_allocated,
            mem_resident,
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

        // Get a snapshot of metrics
        let metric_families = self.registry.gather();

        // Take a write lock, truncate the vector and encode the metrics into it
        let mut cache = self.cache.write().await;
        cache.buffer.clear();
        self.encoder.encode(&metric_families, &mut cache.buffer)?;

        Ok(())
    }
}

// A wrapper for http::Body implementations that tracks the number of bytes sent
pub struct MetricsBody<D, E> {
    inner: Pin<Box<dyn HttpBody<Data = D, Error = E> + Send + 'static>>,
    // TODO see if we can make this FnOnce somehow
    callback: Box<dyn Fn(u64, Result<(), String>) + Send + 'static>,
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

        Self {
            inner: Box::pin(body),
            callback: Box::new(callback),
            expected_size,
            bytes_sent: 0,
        }
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
                        (self.callback)(self.bytes_sent, Ok(()));
                    }
                }

                // Error occured, execute callback
                Err(e) => {
                    // Error is not Copy/Clone so use string instead
                    (self.callback)(self.bytes_sent, Err(e.to_string()));
                }
            },

            // Nothing left, execute callback
            Poll::Ready(None) => {
                (self.callback)(self.bytes_sent, Ok(()));
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
            // Count
            ranges: register_int_gauge_with_registry!(
                format!("persist_ranges"),
                format!("Number of canister ranges currently published"),
                registry
            )
            .unwrap(),

            // Duration
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
pub struct HttpMetricParams {
    pub action: String,
    pub counter: IntCounterVec,
    pub durationer: HistogramVec,
    pub request_sizer: HistogramVec,
    pub response_sizer: HistogramVec,
}

impl HttpMetricParams {
    pub fn new(registry: &Registry, action: &str) -> Self {
        Self {
            action: action.to_string(),

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
        .to_string();

    let HttpMetricParamsStatus { counter } = metric_params;
    counter.with_label_values(&[health.as_str()]).inc();

    response
}

// middleware to log and measure proxied requests
pub async fn metrics_middleware(
    State(metric_params): State<HttpMetricParams>,
    Extension(request_id): Extension<RequestId>,
    request: Request<Body>,
    next: Next<Body>,
) -> impl IntoResponse {
    let request_id = request_id
        .header_value()
        .to_str()
        .unwrap_or("bad_request_id")
        .to_string();

    // Perform the request & measure duration
    let start_time = Instant::now();
    let response = next.run(request).await;
    let proc_duration = start_time.elapsed().as_secs_f64();

    // Extract extensions
    let ctx = response
        .extensions()
        .get::<RequestContext>()
        .cloned()
        .unwrap_or_default();

    let error_cause = response.extensions().get::<ErrorCause>().cloned();
    let canister_id = response.extensions().get::<CanisterId>().cloned();
    let node = response.extensions().get::<Node>().cloned();
    let cache_status = response
        .extensions()
        .get::<CacheStatus>()
        .cloned()
        .unwrap_or_default();

    // Prepare fields
    let request_type = ctx.request_type.to_string();
    let status_code = response.status();
    let sender = ctx.sender.map(|x| x.to_string());
    let node_id = node.as_ref().map(|x| x.id.to_string());
    let subnet_id = node.as_ref().map(|x| x.subnet_id.to_string());

    let HttpMetricParams {
        action,
        counter,
        durationer,
        request_sizer,
        response_sizer,
    } = metric_params;

    // Closure that gets called when the response body is fully read (or an error occurs)
    let record_metrics = move |response_size: u64, body_result: Result<(), String>| {
        let full_duration = start_time.elapsed().as_secs_f64();

        let (error_cause, error_details) = match &error_cause {
            Some(v) => (Some(v.to_string()), v.details()),
            None => (None, None),
        };

        let cache_bypass_reason = match &cache_status {
            CacheStatus::Bypass(v) => Some(v.to_string()),
            _ => None,
        };

        // Prepare labels
        // Otherwise "temporary value dropped" error occurs
        let error_cause_lbl = error_cause.clone().unwrap_or("none".to_string());
        let subnet_id_lbl = subnet_id.clone().unwrap_or("unknown".to_string());
        let node_id_lbl = node_id.clone().unwrap_or("unknown".to_string());
        let cache_status_lbl = &cache_status.to_string();
        let cache_bypass_reason_lbl = cache_bypass_reason.clone().unwrap_or("none".to_string());

        // TODO Potential cardinality is about 8M which is a lot
        // Check over a long period in PROD and measure
        let labels = &[
            request_type.as_str(),            // x4
            status_code.as_str(),             // x27 average
            subnet_id_lbl.as_str(),           // x37 but since each node is in a single subnet -> x1
            node_id_lbl.as_str(),             // x550
            error_cause_lbl.as_str(),         // x15 but not sure if all errors would ever manifest
            cache_status_lbl.as_str(),        // x4
            cache_bypass_reason_lbl.as_str(), // x5 but since it relates only to BYPASS cache status -> total for 2 fields is x9
        ];

        counter.with_label_values(labels).inc();
        durationer.with_label_values(labels).observe(proc_duration);
        request_sizer
            .with_label_values(labels)
            .observe(ctx.request_size as f64);
        response_sizer
            .with_label_values(labels)
            .observe(response_size as f64);

        info!(
            action,
            request_id,
            request_type = ctx.request_type.to_string(),
            error_cause,
            error_details,
            status = status_code.as_u16(),
            subnet_id,
            node_id,
            canister_id = canister_id.map(|x| x.to_string()),
            canister_id_cbor = ctx.canister_id.map(|x| x.to_string()),
            sender,
            method_name = ctx.method_name,
            proc_duration,
            full_duration,
            request_size = ctx.request_size,
            response_size,
            body_error = body_result.err(),
            %cache_status,
            cache_bypass_reason = cache_bypass_reason.map(|x| x.to_string()),
            nonce_len = ctx.nonce.clone().map(|x| x.len()),
            arg_len = ctx.arg.clone().map(|x| x.len()),
        );
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
