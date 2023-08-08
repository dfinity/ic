use std::time::Instant;

use anyhow::{anyhow, Error};
use async_trait::async_trait;
use axum::{
    body::Body,
    extract::{FromRef, State},
    http::{Request, StatusCode},
    middleware::{self, Next},
    response::Response,
    Extension,
};
use http::{header, HeaderValue};
use opentelemetry::{
    baggage::BaggageExt,
    metrics::{Counter, Histogram, Meter},
    trace::FutureExt,
    Context, KeyValue,
};
use opentelemetry_prometheus::{ExporterBuilder, PrometheusExporter};
use prometheus::{Encoder, Registry, TextEncoder};
use tower_http::request_id::RequestId;
use tracing::{error, info, warn};

use crate::{
    check::{Check, CheckError, CheckResult},
    persist::{Persist, PersistResults, PersistStatus},
    routes::{MiddlewareState, RequestContext},
    snapshot::{Node, RoutingTable},
};

pub struct WithMetrics<T>(pub T, pub MetricParams);

#[derive(Clone)]
pub struct MetricParams {
    pub action: String,
    pub counter: Counter<u64>,
    pub durationer: Histogram<f64>,
}

impl MetricParams {
    pub fn new(meter: &Meter, namespace: &str, action: &str) -> Self {
        Self {
            action: action.to_string(),
            counter: meter
                .u64_counter(format!("{namespace}.{action}.total"))
                .with_description(format!("Counts occurences of {action} calls"))
                .init(),
            durationer: meter
                .f64_histogram(format!("{namespace}.{action}.duration_sec"))
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
    pub fn new(meter: &Meter, namespace: &str, action: &str) -> Self {
        Self {
            action: action.to_string(),
            counter: meter
                .u64_counter(format!("{namespace}.{action}.total"))
                .with_description(format!("Counts occurences of {action} calls"))
                .init(),
            durationer: meter
                .f64_histogram(format!("{namespace}.{action}.duration_sec"))
                .with_description(format!("Records the duration of {action} calls in seconds"))
                .init(),
            request_sizer: meter
                .u64_histogram(format!("{namespace}.{action}.request_size"))
                .with_description(format!("Records the size of {action} requests"))
                .init(),
            response_sizer: meter
                .u64_histogram(format!("{namespace}.{action}.response_size"))
                .with_description(format!("Records the size of {action} responses."))
                .init(),
        }
    }
}

#[async_trait]
impl<T: Persist> Persist for WithMetrics<T> {
    async fn persist(&self, rt: RoutingTable) -> Result<PersistStatus, Error> {
        let result = self.0.persist(rt).await?;

        match &result {
            PersistStatus::SkippedEmpty => {
                error!("Lookup table is empty!");
            }

            PersistStatus::Completed(s) => {
                info!(
                    "Lookup table published: subnet ranges: {:?} -> {:?}, nodes: {:?} -> {:?}",
                    s.ranges_old, s.ranges_new, s.nodes_old, s.nodes_new,
                );
            }
        }

        Ok(result)
    }
}

#[async_trait]
impl<T: Check> Check for WithMetrics<T> {
    // TODO add metrics
    async fn check(&self, node: &Node) -> Result<CheckResult, CheckError> {
        let start_time = Instant::now();
        let out = self.0.check(node).await;
        let duration = start_time.elapsed().as_secs_f32();

        let status = match &out {
            Ok(_) => "ok".to_string(),
            Err(e) => format!("error_{}", e.short()),
        };

        let (block_height, replica_version) = out.as_ref().map_or((-1, "unknown"), |out| {
            (out.height as i64, out.replica_version.as_str())
        });

        let cx = Context::current();
        let bgg = cx.baggage();

        info!(
            action = self.1.action,
            subnet_id = %bgg.get("subnet_id").unwrap(),
            node_id = %bgg.get("node_id").unwrap(),
            addr = %bgg.get("addr").unwrap(),
            status,
            duration,
            block_height,
            replica_version,
            error = ?out.as_ref().err(),
        );

        out
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

    let labels = &[
        KeyValue::new("request_type", routes_ctx.request_type.to_string()),
        KeyValue::new("status_code", response.status().to_string()),
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

    let HttpMetricParams {
        action,
        counter,
        durationer,
        request_sizer,
        response_sizer,
    } = metric_params;

    let response_size = response
        .headers()
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u32>().ok())
        .unwrap_or(0);

    let _ctx = Context::current();
    counter.add(&_ctx, 1, labels);
    durationer.record(&_ctx, duration, labels);
    request_sizer.record(&_ctx, request_size.into(), labels);
    response_sizer.record(&_ctx, response_size.into(), labels);

    info!(
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

// Get the metric_params from the combined state
impl<T> FromRef<MiddlewareState<T>> for HttpMetricParams {
    fn from_ref(state: &MiddlewareState<T>) -> HttpMetricParams {
        state.metric_params.clone()
    }
}

#[derive(Clone)]
pub struct MetricsHandlerArgs {
    pub exporter: PrometheusExporter,
}

pub async fn metrics_handler(
    State(MetricsHandlerArgs { exporter }): State<MetricsHandlerArgs>,
) -> Response<Body> {
    let metric_families = exporter.registry().gather();

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
