use std::time::Instant;

use axum::{
    body::Body,
    extract::State,
    http::{Request, StatusCode},
    middleware::Next,
    response::Response,
};
use http::header;
use prometheus::{
    register_histogram_vec_with_registry, register_int_counter_vec_with_registry, Encoder,
    HistogramOpts, HistogramVec, IntCounterVec, Registry, TextEncoder,
};
use tower_http::request_id::RequestId;
use tracing::info;

use crate::routes::RequestContext;

pub const HTTP_DURATION_BUCKETS: &[f64] = &[0.05, 0.1, 0.2, 0.4, 0.6, 0.8, 1.0, 2.0, 3.0, 10.0];
pub const HTTP_REQUEST_SIZE_BUCKETS: &[f64] = &[128.0, 256.0, 512.0, 1024.0, 2048.0, 4096.0];
pub const HTTP_RESPONSE_SIZE_BUCKETS: &[f64] =
    &[1024.0, 2048.0, 4096.0, 8192.0, 16384.0, 32768.0, 65536.0];

const LABELS_HTTP: &[&str] = &[
    "request_type",
    "status_code",
    "subnet_id",
    "node_id",
    "error_cause",
    "is_anonymous",
];

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
                format!("Records the duration of {action} calls in seconds"),
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
) -> Result<Response, Response> {
    let request_size = request
        .headers()
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u32>().ok())
        .unwrap_or(0);

    let request_id = request.extensions().get::<RequestId>();
    let request_id = request_id
        .and_then(|id| id.header_value().to_str().ok())
        .unwrap_or("bad_request_id")
        .to_owned();

    let start_time = Instant::now();
    let response = next.run(request).await;
    let duration = start_time.elapsed().as_secs_f64();

    let response_size = response
        .headers()
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u32>().ok())
        .unwrap_or(0);

    let routes_ctx = response
        .extensions()
        .get::<RequestContext>()
        .cloned()
        .unwrap_or_default();

    let request_type = routes_ctx.request_type.to_string();
    let status_code = response.status();
    let subnet_id = routes_ctx
        .node
        .as_ref()
        .map(|x| x.subnet_id.to_string())
        .unwrap_or("unknown".to_string());
    let node_id = routes_ctx
        .node
        .as_ref()
        .map(|x| x.id.to_string())
        .unwrap_or("unknown".to_string());
    let error_cause = format!("{}", routes_ctx.error_cause);

    let sender = routes_ctx.sender.map(|x| x.to_string());
    let is_anonymous = routes_ctx
        .sender
        .map(|p| {
            if p.to_string() == *"2vxsx-fae" {
                "1"
            } else {
                "0"
            }
        })
        .unwrap_or("0");

    let HttpMetricParams {
        action,
        counter,
        durationer,
        request_sizer,
        response_sizer,
    } = metric_params;

    let labels = &[
        request_type.as_str(),
        status_code.as_str(),
        subnet_id.as_str(),
        node_id.as_str(),
        error_cause.as_str(),
        is_anonymous,
    ];

    counter.with_label_values(labels).inc();
    durationer.with_label_values(labels).observe(duration);
    request_sizer
        .with_label_values(labels)
        .observe(request_size.into());
    response_sizer
        .with_label_values(labels)
        .observe(response_size.into());

    info!(
        action,
        request_id,
        request_type = format!("{}", routes_ctx.request_type),
        error_cause,
        error_details = routes_ctx.error_cause.details(),
        status = status_code.as_u16(),
        subnet_id,
        node_id,
        canister_id = routes_ctx.canister_id.map(|x| x.to_string()),
        canister_id_cbor = routes_ctx.canister_id_cbor.map(|x| x.to_string()),
        sender,
        method_name = routes_ctx.method_name,
        duration,
        request_size = routes_ctx.request_size,
        response_size,
    );

    Ok(response)
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
