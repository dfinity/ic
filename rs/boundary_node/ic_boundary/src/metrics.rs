use std::time::Instant;

use anyhow::{anyhow, Error};
use async_trait::async_trait;
use axum::{
    body::Body,
    http::{Response, StatusCode},
};
use opentelemetry::{baggage::BaggageExt, trace::FutureExt, Context, KeyValue};
use prometheus::{Encoder, Registry, TextEncoder};
use tracing::{error, info, warn};

use crate::{
    check::{Check, CheckError, CheckResult},
    persist::{Persist, PersistResults, PersistStatus},
    snapshot::{Node, RoutingTable},
};

pub async fn handler(registry: &Registry) -> Response<Body> {
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

pub struct WithMetrics<T>(pub T, pub MetricParams);

pub struct MetricParams {
    pub action: String,
}

impl MetricParams {
    pub fn new(namespace: &str, action: &str) -> Self {
        Self {
            action: action.to_string(),
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
        let block_height = out.as_ref().map_or(-1, |out| out.height as i64);

        let cx = Context::current();
        let bgg = cx.baggage();

        info!(
            action = self.1.action,
            subnet_id = %bgg.get("subnet_id").unwrap(),
            node_id = %bgg.get("node_id").unwrap(),
            addr = %bgg.get("addr").unwrap(),
            status,
            duration = duration,
            block_height,
            error = ?out.as_ref().err(),
        );

        out
    }
}
