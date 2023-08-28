use std::time::Instant;

use anyhow::Error;
use axum::{
    body::Body,
    extract::State,
    http::{Request, StatusCode},
    middleware::Next,
    response::Response,
};
use http::header;
use opentelemetry::{
    metrics::{Counter, Histogram, Meter},
    sdk::metrics::{new_view, Aggregation, Instrument, MeterProviderBuilder, Stream},
    KeyValue,
};
use prometheus::{Encoder, Registry, TextEncoder};
use tower_http::request_id::RequestId;
use tracing::info;

use crate::routes::RequestContext;

pub struct HistogramDefinition(
    pub &'static str,   // action
    pub &'static [f64], // boundaries
);

pub fn apply_histogram_definitions(
    b: MeterProviderBuilder,
    defs: &[HistogramDefinition],
) -> Result<MeterProviderBuilder, Error> {
    defs.iter()
        .try_fold(b, |b, &HistogramDefinition(action, boundaries)| {
            Ok::<_, Error>(b.with_view(new_view(
                Instrument::new().name(format!("{action}_duration_sec")), // criteria
                Stream::new().aggregation(Aggregation::ExplicitBucketHistogram {
                    boundaries: boundaries.to_owned(),
                    record_min_max: false,
                }), // mask
            )?))
        })
}

pub struct WithMetrics<T>(pub T, pub MetricParams);

#[derive(Clone)]
pub struct MetricParams {
    pub action: String,
    pub counter: Counter<u64>,
    pub recorder: Histogram<f64>,
}

impl MetricParams {
    pub fn new(meter: &Meter, action: &str) -> Self {
        Self {
            action: action.to_string(),

            // Counter
            counter: meter
                .u64_counter(format!("{action}_total"))
                .with_description(format!("Counts occurences of {action} calls"))
                .init(),

            // Duration
            recorder: meter
                .f64_histogram(format!("{action}_duration_sec"))
                .with_description(format!("Records the duration of {action} calls in seconds"))
                .init(),
        }
    }
}

#[derive(Clone)]
pub struct HttpMetricParams {
    pub action: String,
    pub counter: Counter<u64>,
    pub durationer: Histogram<f64>,
    pub request_sizer: Histogram<u64>,
    pub response_sizer: Histogram<u64>,
}

impl HttpMetricParams {
    pub fn new(meter: &Meter, action: &str) -> Self {
        Self {
            action: action.to_string(),
            counter: meter
                .u64_counter(format!("{action}_total"))
                .with_description(format!("Counts occurences of {action} calls"))
                .init(),
            durationer: meter
                .f64_histogram(format!("{action}_duration_sec"))
                .with_description(format!("Records the duration of {action} calls in seconds"))
                .init(),
            request_sizer: meter
                .u64_histogram(format!("{action}_request_size"))
                .with_description(format!("Records the size of {action} requests"))
                .init(),
            response_sizer: meter
                .u64_histogram(format!("{action}_response_size"))
                .with_description(format!("Records the size of {action} responses."))
                .init(),
        }
    }
}

// for http calls through axum we do axum middleware instead of WithMetrics
pub async fn with_metrics_middleware(
    State(metric_params): State<HttpMetricParams>,
    request: Request<Body>,
    next: Next<Body>,
) -> Result<Response, Response> {
    let start_time = Instant::now();

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

    let response = next.run(request).await;

    let duration = start_time.elapsed().as_secs_f64();

    let routes_ctx = response
        .extensions()
        .get::<RequestContext>()
        .cloned()
        .unwrap_or_default();

    let subnet_id = routes_ctx.node.as_ref().map(|x| x.subnet_id.to_string());
    let node_id = routes_ctx.node.as_ref().map(|x| x.id.to_string());
    let error_cause = format!("{}", routes_ctx.error_cause);
    let sender = routes_ctx.sender.map(|x| x.to_string());

    let HttpMetricParams {
        action,
        counter,
        durationer,
        request_sizer,
        response_sizer,
    } = metric_params;

    let labels = &[
        KeyValue::new("request_type", routes_ctx.request_type.to_string()),
        KeyValue::new("status_code", response.status().as_str().to_owned()),
        KeyValue::new("subnet_id", subnet_id.clone().unwrap_or(String::from("-"))),
        KeyValue::new("node_id", node_id.clone().unwrap_or(String::from("-"))),
        KeyValue::new("error_cause", error_cause.clone()),
        KeyValue::new(
            "is_anonymous",
            routes_ctx
                .sender
                .map(|p| {
                    if p.to_string() == *"2vxsx-fae" {
                        "1"
                    } else {
                        "0"
                    }
                })
                .unwrap_or("-"),
        ),
    ];

    let response_size = response
        .headers()
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u32>().ok())
        .unwrap_or(0);

    counter.add(1, labels);
    durationer.record(duration, labels);
    request_sizer.record(request_size.into(), labels);
    response_sizer.record(response_size.into(), labels);

    info!(
        action,
        request_id,
        request_type = format!("{}", routes_ctx.request_type),
        error_cause,
        error_details = routes_ctx.error_cause.details(),
        status = response.status().as_u16(),
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
