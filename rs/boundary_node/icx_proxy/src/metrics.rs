use std::{borrow::Cow, net::SocketAddr};

use anyhow::{Context, Error};
use axum::{handler::Handler, routing::get, Extension, Router};
use candid::Principal;
use clap::Args;
use hyper::{self, Body, Request, Response, StatusCode, Uri};
use ic_agent::Agent;
use opentelemetry::{
    global,
    metrics::{Counter, Meter},
    sdk::Resource,
    KeyValue,
};
use opentelemetry_prometheus::PrometheusExporter;
use prometheus::{Encoder, TextEncoder};

use crate::{headers::HeadersData, logging::add_trace_layer, validate::Validate};

/// The options for metrics
#[derive(Args)]
pub struct MetricsOpts {
    /// Address to expose Prometheus metrics on
    /// Examples: 127.0.0.1:9090, [::1]:9090
    #[clap(long)]
    metrics_addr: Option<SocketAddr>,
}

pub struct WithMetrics<T>(pub T, pub MetricParams);

pub struct MetricParams {
    pub counter: Counter<u64>,
}

impl MetricParams {
    pub fn new(meter: &Meter, name: &str) -> Self {
        Self {
            counter: meter
                .u64_counter(format!("{name}.total"))
                .with_description(format!("Counts occurences of {name} calls"))
                .init(),
        }
    }
}

impl<T: Validate> Validate for WithMetrics<T> {
    fn validate(
        &self,
        required: bool,
        headers_data: &HeadersData,
        canister_id: &Principal,
        agent: &Agent,
        uri: &Uri,
        response_body: &[u8],
    ) -> Result<(), Cow<'static, str>> {
        let out = self.0.validate(
            required,
            headers_data,
            canister_id,
            agent,
            uri,
            response_body,
        );

        let mut status = if out.is_ok() { "ok" } else { "fail" };
        if cfg!(feature = "skip_body_verification") {
            status = "skip";
        }

        let labels = &[KeyValue::new("status", status)];

        let MetricParams { counter } = &self.1;
        counter.add(1, labels);

        out
    }
}

#[derive(Clone)]
struct HandlerArgs {
    exporter: PrometheusExporter,
}

async fn metrics_handler(
    Extension(HandlerArgs { exporter }): Extension<HandlerArgs>,
    _: Request<Body>,
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
pub fn setup(opts: MetricsOpts) -> (Meter, Runner) {
    let exporter = opentelemetry_prometheus::exporter()
        .with_resource(Resource::new(vec![KeyValue::new("service", "prober")]))
        .init();
    (
        global::meter("icx-proxy"),
        Runner {
            exporter,
            metrics_addr: opts.metrics_addr,
        },
    )
}

pub struct Runner {
    exporter: PrometheusExporter,
    metrics_addr: Option<SocketAddr>,
}

impl Runner {
    pub async fn run(self) -> Result<(), Error> {
        if self.metrics_addr.is_none() {
            return Ok(());
        }

        let metrics_router = Router::new().route(
            "/metrics",
            get(metrics_handler.layer(Extension(HandlerArgs {
                exporter: self.exporter,
            }))),
        );

        axum::Server::bind(&self.metrics_addr.unwrap())
            .serve(add_trace_layer(metrics_router).into_make_service())
            .await
            .context("failed to start metrics server")?;

        Ok(())
    }
}
