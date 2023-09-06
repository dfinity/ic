use std::{borrow::Cow, net::SocketAddr};

use anyhow::{Context, Error};
use axum::{handler::Handler, routing::get, Extension, Router};
use candid::Principal;
use clap::Args;
use hyper::{self, Body, Request, Response, StatusCode};
use ic_agent::Agent;
use opentelemetry::{
    metrics::{Counter, Meter, MeterProvider as _},
    sdk::metrics::MeterProvider,
    KeyValue,
};
use opentelemetry_prometheus::exporter;
use prometheus::{labels, Encoder as PrometheusEncoder, Registry, TextEncoder};

use crate::http::request::HttpRequest;
use crate::http::response::HttpResponse;
use crate::{logging::add_trace_layer, validate::Validate};

/// The options for metrics
#[derive(Args)]
pub struct MetricsOpts {
    /// Address to expose Prometheus metrics on
    /// Examples: 127.0.0.1:9090, [::1]:9090
    #[clap(long)]
    metrics_addr: Option<SocketAddr>,
}

#[derive(Clone)]
pub struct WithMetrics<T>(pub T, pub MetricParams);

#[derive(Clone)]
pub struct MetricParams {
    pub counter: Counter<u64>,
}

impl MetricParams {
    pub fn new(meter: &Meter, name: &str) -> Self {
        Self {
            counter: meter
                .u64_counter(name.to_string())
                .with_description(format!("Counts occurences of {name} calls"))
                .init(),
        }
    }
}

impl<T: Validate> Validate for WithMetrics<T> {
    fn validate(
        &self,
        agent: &Agent,
        canister_id: &Principal,
        request: &HttpRequest,
        response: &HttpResponse,
    ) -> Result<(), Cow<'static, str>> {
        let out = self.0.validate(agent, canister_id, request, response);

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
    registry: Registry,
}

async fn metrics_handler(
    Extension(HandlerArgs { registry }): Extension<HandlerArgs>,
    _: Request<Body>,
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
pub fn setup(opts: MetricsOpts) -> (Meter, Runner) {
    let service_name = "prober";
    let registry: Registry = Registry::new_custom(
        None,
        Some(labels! {"service".into() => service_name.into()}),
    )
    .unwrap();
    let exporter = exporter().with_registry(registry.clone()).build().unwrap();
    let provider = MeterProvider::builder().with_reader(exporter).build();
    (
        provider.meter("icx_proxy"),
        Runner {
            registry,
            metrics_addr: opts.metrics_addr,
        },
    )
}

pub struct Runner {
    registry: Registry,
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
                registry: self.registry,
            }))),
        );

        axum::Server::bind(&self.metrics_addr.unwrap())
            .serve(add_trace_layer(metrics_router).into_make_service())
            .await
            .context("failed to start metrics server")?;

        Ok(())
    }
}
