use std::time::Instant;

use anyhow::Error;
use async_trait::async_trait;
use ic_registry_client::client::RegistryClientImpl;
use opentelemetry::{
    baggage::BaggageExt,
    metrics::{Counter, Meter, ValueRecorder},
    Context, KeyValue,
};
use tracing::info;

use crate::{
    registry::{CreateRegistryClient, RoutingTable, Snapshot},
    Check, Persist, PersistStatus, Run,
};

pub struct MetricParams {
    pub action: String,
    pub counter: Counter<u64>,
    pub recorder: ValueRecorder<f64>,
}

impl MetricParams {
    pub fn new(meter: &Meter, namespace: &str, action: &str) -> Self {
        Self {
            action: action.to_string(),
            counter: meter
                .u64_counter(format!("{namespace}.{action}.total"))
                .with_description(format!("Counts occurences of {action} calls"))
                .init(),
            recorder: meter
                .f64_value_recorder(format!("{namespace}.{action}.duration_sec"))
                .with_description(format!("Records the duration of {action} calls in sec"))
                .init(),
        }
    }
}

pub struct WithMetrics<T>(pub T, pub MetricParams);

#[async_trait]
impl<T: CreateRegistryClient> CreateRegistryClient for WithMetrics<T> {
    async fn create_registry_client(&mut self) -> Result<RegistryClientImpl, Error> {
        let start_time = Instant::now();

        let out = self.0.create_registry_client().await;

        let status = if out.is_ok() { "ok" } else { "fail" };
        let duration = start_time.elapsed().as_secs_f64();

        let labels = &[KeyValue::new("status", status)];

        let MetricParams {
            action,
            counter,
            recorder,
        } = &self.1;

        counter.add(1, labels);
        recorder.record(duration, labels);

        info!(action = action.as_str(), status, duration, error = ?out.as_ref().err());

        out
    }
}

#[async_trait]
impl<T: Snapshot> Snapshot for WithMetrics<T> {
    async fn snapshot(&mut self) -> Result<RoutingTable, Error> {
        let start_time = Instant::now();

        let out = self.0.snapshot().await;

        let status = if out.is_ok() { "ok" } else { "fail" };
        let duration = start_time.elapsed().as_secs_f64();

        let labels = &[KeyValue::new("status", status)];

        let MetricParams {
            action,
            counter,
            recorder,
        } = &self.1;

        counter.add(1, labels);
        recorder.record(duration, labels);

        let (out, registry_version) = match out {
            Ok(rt) => {
                let v = rt.registry_version.to_string();
                (Ok(rt), v)
            }
            _ => (out, String::from("N/A")),
        };

        info!(action = action.as_str(), status, duration, registry_version, error = ?out.as_ref().err());

        out
    }
}

#[async_trait]
impl<T: Check> Check for WithMetrics<T> {
    async fn check(&self, addr: &str) -> Result<(), Error> {
        let start_time = Instant::now();

        let out = self.0.check(addr).await;

        let status = if out.is_ok() { "ok" } else { "fail" };
        let duration = start_time.elapsed().as_secs_f64();

        let ctx = Context::current();
        let ctx = ctx.baggage();

        let labels = &[
            KeyValue::new("subnet_id", ctx.get("subnet_id").unwrap().to_string()),
            KeyValue::new("node_id", ctx.get("node_id").unwrap().to_string()),
            KeyValue::new("status", status),
        ];

        let MetricParams {
            action,
            counter,
            recorder,
        } = &self.1;

        counter.add(1, labels);
        recorder.record(duration, labels);

        info!(
            action = action.as_str(),
            subnet_id = ctx.get("subnet_id").unwrap().to_string().as_str(),
            node_id = ctx.get("node_id").unwrap().to_string().as_str(),
            addr,
            status,
            duration,
            error = ?out.as_ref().err(),
        );

        out
    }
}

#[async_trait]
impl<T: Persist> Persist for WithMetrics<T> {
    async fn persist(&mut self, rt: RoutingTable) -> Result<PersistStatus, Error> {
        let start_time = Instant::now();

        let out = self.0.persist(rt).await;

        let status = match out {
            Ok(PersistStatus::Completed) => "completed",
            Ok(PersistStatus::SkippedUnchanged) => "skipped-unchanged",
            Ok(PersistStatus::SkippedEmpty) => "skipped-empty",
            Err(_) => "fail",
        };
        let duration = start_time.elapsed().as_secs_f64();

        let labels = &[KeyValue::new("status", status)];

        let MetricParams {
            action,
            counter,
            recorder,
        } = &self.1;

        counter.add(1, labels);
        recorder.record(duration, labels);

        info!(action = action.as_str(), status, duration, error = ?out.as_ref().err());

        out
    }
}

#[async_trait]
impl<T: Run> Run for WithMetrics<T> {
    async fn run(&mut self) -> Result<(), Error> {
        let start_time = Instant::now();

        let out = self.0.run().await;

        let status = if out.is_ok() { "ok" } else { "fail" };
        let duration = start_time.elapsed().as_secs_f64();

        let labels = &[KeyValue::new("status", status)];

        let MetricParams {
            action,
            counter,
            recorder,
        } = &self.1;

        counter.add(1, labels);
        recorder.record(duration, labels);

        info!(action = action.as_str(), status, duration, error = ?out.as_ref().err());

        out
    }
}
