use std::{pin::Pin, time::Instant};

use axum::{
    body::Body,
    extract::State,
    http::{Request, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use bytes::Buf;
use futures::task::{Context as FutContext, Poll};
use http::header::{HeaderMap, HeaderValue, CONTENT_LENGTH};
use http_body::Body as HttpBody;
use prometheus::{
    register_histogram_vec_with_registry, register_int_counter_vec_with_registry, Encoder,
    HistogramOpts, HistogramVec, IntCounterVec, Registry, TextEncoder,
};
use tower_http::request_id::RequestId;
use tracing::info;

use crate::routes::RequestContext;

const KB: f64 = 1024.0;
const MB: f64 = 1024.0 * KB;

pub const HTTP_DURATION_BUCKETS: &[f64] = &[0.05, 0.1, 0.2, 0.4, 0.6, 0.8, 1.0, 2.0, 3.0, 10.0];
pub const HTTP_REQUEST_SIZE_BUCKETS: &[f64] =
    &[128.0, 256.0, 512.0, KB, 2.0 * KB, 4.0 * KB, 8.0 * KB];
pub const HTTP_RESPONSE_SIZE_BUCKETS: &[f64] = &[
    1.0 * KB,
    8.0 * KB,
    64.0 * KB,
    128.0 * KB,
    512.0 * KB,
    1.0 * MB,
    2.0 * MB,
    8.0 * MB,
    16.0 * MB,
];

const LABELS_HTTP: &[&str] = &[
    "request_type",
    "status_code",
    "subnet_id",
    "node_id",
    "error_cause",
    "is_anonymous",
    "body_error",
];

// A wrapper for http::Body implementations that tracks the number of bytes sent
pub struct MetricsBody<D, E> {
    inner: Pin<Box<dyn HttpBody<Data = D, Error = E> + Send + 'static>>,
    callback: Box<dyn Fn(u64, Result<(), String>) + Send + 'static>,
    content_length: Option<u64>,
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
        // Try to parse header if provided
        let content_length =
            content_length.and_then(|x| x.to_str().ok().and_then(|x| x.parse::<u64>().ok()));

        Self {
            inner: Box::pin(body),
            callback: Box::new(callback),
            content_length,
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
//
// So we have to cover all these:
// * We don't implement is_end_stream() (default impl in Trait just returns false) so that
//   the caller will have to use poll_data()
// * We have to have a Content-Length stored to check if we got already that much data

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
                    if let Some(v) = self.content_length {
                        if self.bytes_sent >= v {
                            (self.callback)(self.bytes_sent, Ok(()));
                        }
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

#[derive(Clone)]
pub struct HttpMetricParams {
    pub action: String,
    pub counter: IntCounterVec,
    pub durationer: HistogramVec,
    pub durationer_full: HistogramVec,
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

            durationer_full: register_histogram_vec_with_registry!(
                format!("{action}_duration_full_sec"),
                format!("Records the full duration of {action} requests in seconds"),
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

// for http calls through axum we do axum middleware instead of WithMetrics
pub async fn with_metrics_middleware(
    State(metric_params): State<HttpMetricParams>,
    request: Request<Body>,
    next: Next<Body>,
) -> impl IntoResponse {
    let request_id = request
        .extensions()
        .get::<RequestId>()
        .and_then(|id| id.header_value().to_str().ok())
        .unwrap_or("bad_request_id")
        .to_string();

    let start_time = Instant::now();
    let response = next.run(request).await;
    let proc_duration = start_time.elapsed().as_secs_f64();

    let request_ctx = response
        .extensions()
        .get::<RequestContext>()
        .cloned()
        .unwrap_or_default();

    let request_type = request_ctx.request_type.to_string();
    let status_code = response.status();

    let subnet_id = request_ctx
        .node
        .as_ref()
        .map(|x| x.subnet_id.to_string())
        .unwrap_or("unknown".to_string());

    let node_id = request_ctx
        .node
        .as_ref()
        .map(|x| x.id.to_string())
        .unwrap_or("unknown".to_string());

    let error_cause = format!("{}", request_ctx.error_cause);

    let sender = request_ctx.sender.map(|x| x.to_string());

    let HttpMetricParams {
        action,
        counter,
        durationer,
        durationer_full,
        request_sizer,
        response_sizer,
    } = metric_params;

    // Closure that gets called when the response body is fully read (or an error occurs)
    let record_metrics = move |response_size: u64, body_result: Result<(), String>| {
        let full_duration = start_time.elapsed().as_secs_f64();

        let is_anonymous = request_ctx
            .is_anonymous()
            .map(|p| if p { "yes" } else { "no" }) // Faster than to_string().as_str()
            .unwrap_or("unknown");

        let labels = &[
            request_type.as_str(),
            status_code.as_str(),
            subnet_id.as_str(),
            node_id.as_str(),
            error_cause.as_str(),
            is_anonymous,
            if body_result.is_err() { "yes" } else { "no" },
        ];

        counter.with_label_values(labels).inc();
        durationer.with_label_values(labels).observe(proc_duration);
        durationer_full
            .with_label_values(labels)
            .observe(full_duration);
        request_sizer
            .with_label_values(labels)
            .observe(request_ctx.request_size as f64);
        response_sizer
            .with_label_values(labels)
            .observe(response_size as f64);

        info!(
            action,
            request_id,
            request_type = format!("{}", request_ctx.request_type),
            error_cause,
            error_details = request_ctx.error_cause.details(),
            status = status_code.as_u16(),
            subnet_id,
            node_id,
            canister_id = request_ctx.canister_id.map(|x| x.to_string()),
            canister_id_cbor = request_ctx.canister_id_cbor.map(|x| x.to_string()),
            sender,
            method_name = request_ctx.method_name,
            proc_duration,
            full_duration,
            request_size = request_ctx.request_size,
            response_size,
            body_error = body_result.err(),
        );
    };

    let (parts, body) = response.into_parts();
    let content_length = parts.headers.get(CONTENT_LENGTH).cloned();
    let body = MetricsBody::new(body, content_length, record_metrics);

    Response::from_parts(parts, body)
}

#[derive(Clone)]
pub struct MetricsHandlerArgs {
    pub registry: Registry,
}

pub async fn metrics_handler(
    State(MetricsHandlerArgs { registry }): State<MetricsHandlerArgs>,
) -> Response<Body> {
    let metric_families = registry.gather();

    let encoder = TextEncoder::new();

    let mut metrics_text = Vec::new();
    if encoder.encode(&metric_families, &mut metrics_text).is_err() {
        return Response::builder()
            .status(StatusCode::INTERNAL_SERVER_ERROR)
            .body("Internal Server Error".into())
            .unwrap();
    };

    Response::builder()
        .status(200)
        .body(metrics_text.into())
        .unwrap()
}
