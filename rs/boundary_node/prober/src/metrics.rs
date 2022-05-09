use ic_agent::{ic_types::Principal, Agent};

use anyhow::Error;
use async_trait::async_trait;
use opentelemetry::{baggage::BaggageExt, metrics::Meter, Context};
use tokio::time::Instant;

use opentelemetry::{
    metrics::{Counter, ValueRecorder},
    KeyValue,
};
use tracing::info;

use crate::{Create, Delete, Install, Load, Probe, Run, ServiceContext, Stop};

pub struct MetricParams {
    pub counter: Counter<u64>,
    pub recorder: ValueRecorder<f64>,
}

impl MetricParams {
    pub fn new(meter: &Meter, name: &str) -> Self {
        Self {
            counter: meter
                .u64_counter(format!("{name}.total"))
                .with_description(format!("Counts occurences of {name} calls"))
                .init(),
            recorder: meter
                .f64_value_recorder(format!("{name}.duration_nsec"))
                .with_description(format!("Records the duration of {name} calls in nsec"))
                .init(),
        }
    }
}

pub struct WithMetrics<T>(pub T, pub MetricParams);

#[async_trait]
impl<T: Load<ServiceContext> + Send + Sync> Load<ServiceContext> for WithMetrics<T> {
    async fn load(&self) -> Result<ServiceContext, Error> {
        let start_time = Instant::now();

        let out = self.0.load().await;

        let status = if out.is_ok() { "ok" } else { "fail" };
        let duration = start_time.elapsed().as_secs_f64();

        let labels = &[KeyValue::new("status", status)];

        let MetricParams { counter, recorder } = &self.1;
        counter.add(1, labels);
        recorder.record(duration, labels);

        info!(action = "load", status, duration, error = ?out.as_ref().err());

        out
    }
}

#[async_trait]
impl<T: Create + Send + Sync> Create for WithMetrics<T> {
    async fn create(&self, agent: &Agent, wallet_id: &str) -> Result<Principal, Error> {
        let start_time = Instant::now();

        let out = self.0.create(agent, wallet_id).await;

        let status = if out.is_ok() { "ok" } else { "fail" };
        let duration = start_time.elapsed().as_secs_f64();

        let ctx = Context::current();
        let ctx = ctx.baggage();

        let labels = &[
            KeyValue::new("subnet_id", ctx.get("subnet_id").unwrap().to_string()),
            KeyValue::new("node_id", ctx.get("node_id").unwrap().to_string()),
            KeyValue::new("socket_addr", ctx.get("socket_addr").unwrap().to_string()),
            KeyValue::new("status", status),
            KeyValue::new("wallet", wallet_id.to_string()),
        ];

        let MetricParams { counter, recorder } = &self.1;
        counter.add(1, labels);
        recorder.record(duration, labels);

        info!(
            action = "create",
            subnet_id = ctx.get("subnet_id").unwrap().to_string().as_str(),
            node_id = ctx.get("node_id").unwrap().to_string().as_str(),
            socket_addr = ctx.get("socket_addr").unwrap().to_string().as_str(),
            wallet = wallet_id.to_string().as_str(),
            status,
            duration,
            error = ?out.as_ref().err(),
        );

        out
    }
}

#[async_trait]
impl<T: Install + Send + Sync> Install for WithMetrics<T> {
    async fn install(
        &self,
        agent: &Agent,
        wallet_id: &str,
        canister_id: Principal,
    ) -> Result<(), Error> {
        let start_time = Instant::now();

        let out = self.0.install(agent, wallet_id, canister_id).await;

        let status = if out.is_ok() { "ok" } else { "fail" };
        let duration = start_time.elapsed().as_secs_f64();

        let ctx = Context::current();
        let ctx = ctx.baggage();

        let labels = &[
            KeyValue::new("subnet_id", ctx.get("subnet_id").unwrap().to_string()),
            KeyValue::new("node_id", ctx.get("node_id").unwrap().to_string()),
            KeyValue::new("socket_addr", ctx.get("socket_addr").unwrap().to_string()),
            KeyValue::new("status", status),
            KeyValue::new("wallet", wallet_id.to_string()),
        ];

        let MetricParams { counter, recorder } = &self.1;
        counter.add(1, labels);
        recorder.record(duration, labels);

        info!(
            action = "install",
            subnet_id = ctx.get("subnet_id").unwrap().to_string().as_str(),
            node_id = ctx.get("node_id").unwrap().to_string().as_str(),
            socket_addr = ctx.get("socket_addr").unwrap().to_string().as_str(),
            wallet = wallet_id.to_string().as_str(),
            canister = canister_id.to_string().as_str(),
            status,
            duration,
            error = ?out.as_ref().err(),
        );

        out
    }
}

#[async_trait]
impl<T: Probe + Send + Sync> Probe for WithMetrics<T> {
    async fn probe(&self, agent: &Agent, canister_id: Principal) -> Result<(), Error> {
        let start_time = Instant::now();

        let out = self.0.probe(agent, canister_id).await;

        let status = if out.is_ok() { "ok" } else { "fail" };
        let duration = start_time.elapsed().as_secs_f64();

        let ctx = Context::current();
        let ctx = ctx.baggage();

        let labels = &[
            KeyValue::new("subnet_id", ctx.get("subnet_id").unwrap().to_string()),
            KeyValue::new("node_id", ctx.get("node_id").unwrap().to_string()),
            KeyValue::new("socket_addr", ctx.get("socket_addr").unwrap().to_string()),
            KeyValue::new("status", status),
        ];

        let MetricParams { counter, recorder } = &self.1;
        counter.add(1, labels);
        recorder.record(duration, labels);

        info!(
            action = "probe",
            subnet_id = ctx.get("subnet_id").unwrap().to_string().as_str(),
            node_id = ctx.get("node_id").unwrap().to_string().as_str(),
            socket_addr = ctx.get("socket_addr").unwrap().to_string().as_str(),
            canister = canister_id.to_string().as_str(),
            status,
            duration,
            error = ?out.as_ref().err(),
        );

        out
    }
}

#[async_trait]
impl<T: Stop + Send + Sync> Stop for WithMetrics<T> {
    async fn stop(
        &self,
        agent: &Agent,
        wallet_id: &str,
        canister_id: Principal,
    ) -> Result<(), Error> {
        let start_time = Instant::now();

        let out = self.0.stop(agent, wallet_id, canister_id).await;

        let status = if out.is_ok() { "ok" } else { "fail" };
        let duration = start_time.elapsed().as_secs_f64();

        let ctx = Context::current();
        let ctx = ctx.baggage();

        let labels = &[
            KeyValue::new("subnet_id", ctx.get("subnet_id").unwrap().to_string()),
            KeyValue::new("node_id", ctx.get("node_id").unwrap().to_string()),
            KeyValue::new("socket_addr", ctx.get("socket_addr").unwrap().to_string()),
            KeyValue::new("status", status),
            KeyValue::new("wallet", wallet_id.to_string()),
        ];

        let MetricParams { counter, recorder } = &self.1;
        counter.add(1, labels);
        recorder.record(duration, labels);

        info!(
            action = "stop",
            subnet_id = ctx.get("subnet_id").unwrap().to_string().as_str(),
            node_id = ctx.get("node_id").unwrap().to_string().as_str(),
            socket_addr = ctx.get("socket_addr").unwrap().to_string().as_str(),
            wallet = wallet_id.to_string().as_str(),
            canister = canister_id.to_string().as_str(),
            status,
            duration,
            error = ?out.as_ref().err(),
        );

        out
    }
}

#[async_trait]
impl<T: Delete + Send + Sync> Delete for WithMetrics<T> {
    async fn delete(
        &self,
        agent: &Agent,
        wallet_id: &str,
        canister_id: Principal,
    ) -> Result<(), Error> {
        let start_time = Instant::now();

        let out = self.0.delete(agent, wallet_id, canister_id).await;

        let status = if out.is_ok() { "ok" } else { "fail" };
        let duration = start_time.elapsed().as_secs_f64();

        let ctx = Context::current();
        let ctx = ctx.baggage();

        let labels = &[
            KeyValue::new("subnet_id", ctx.get("subnet_id").unwrap().to_string()),
            KeyValue::new("node_id", ctx.get("node_id").unwrap().to_string()),
            KeyValue::new("socket_addr", ctx.get("socket_addr").unwrap().to_string()),
            KeyValue::new("status", status),
            KeyValue::new("wallet", wallet_id.to_string()),
        ];

        let MetricParams { counter, recorder } = &self.1;
        counter.add(1, labels);
        recorder.record(duration, labels);

        info!(
            action = "delete",
            subnet_id = ctx.get("subnet_id").unwrap().to_string().as_str(),
            node_id = ctx.get("node_id").unwrap().to_string().as_str(),
            socket_addr = ctx.get("socket_addr").unwrap().to_string().as_str(),
            wallet = wallet_id.to_string().as_str(),
            canister = canister_id.to_string().as_str(),
            status,
            duration,
            error = ?out.as_ref().err(),
        );

        out
    }
}

#[async_trait]
impl<T: Run + Send + Sync> Run for WithMetrics<T> {
    async fn run(&mut self) -> Result<(), Error> {
        let start_time = Instant::now();

        let out = self.0.run().await;

        let status = if out.is_ok() { "ok" } else { "fail" };
        let duration = start_time.elapsed().as_secs_f64();

        let labels = &[KeyValue::new("status", status)];

        let MetricParams { counter, recorder } = &self.1;
        counter.add(1, labels);
        recorder.record(duration, labels);

        info!(action = "run", status, duration, error = ?out.as_ref().err());

        out
    }
}
