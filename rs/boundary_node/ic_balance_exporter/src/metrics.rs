use ic_agent::ic_types::Principal;

use anyhow::Error;
use async_trait::async_trait;
use opentelemetry::metrics::Meter;
use opentelemetry::{
    metrics::{Counter, ValueRecorder},
    KeyValue,
};
use tokio::time::Instant;
use tracing::info;

use crate::{Load, Run, Scrape, ServiceContext};

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
impl<T: Load> Load for WithMetrics<T> {
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
impl<T: Scrape> Scrape for WithMetrics<T> {
    async fn scrape(&self, wallet: &Principal) -> Result<u64, Error> {
        let start_time = Instant::now();

        let out = self.0.scrape(wallet).await;

        let status = if out.is_ok() { "ok" } else { "fail" };
        let duration = start_time.elapsed().as_secs_f64();

        let labels = &[
            KeyValue::new("status", status),
            KeyValue::new("wallet", wallet.to_string()),
        ];

        let MetricParams { counter, recorder } = &self.1;
        counter.add(1, labels);
        recorder.record(duration, labels);

        info!(
            action = "scrape",
            wallet = wallet.to_string().as_str(),
            amount = ?out.as_ref().ok(),
            status,
            duration,
            error = ?out.as_ref().err(),
        );

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

        let MetricParams { counter, recorder } = &self.1;
        counter.add(1, labels);
        recorder.record(duration, labels);

        info!(
            action = "run",
            status,
            duration,
            error = ?out.as_ref().err(),
        );

        out
    }
}
