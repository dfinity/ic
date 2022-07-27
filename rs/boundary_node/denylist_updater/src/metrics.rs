use std::time::Instant;

use anyhow::Error;
use async_trait::async_trait;
use opentelemetry::{
    metrics::{Counter, Meter, ValueRecorder},
    KeyValue,
};
use tracing::info;

use crate::{Entry, List, Reload, Run, Update};

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
impl<T: List> List for WithMetrics<T> {
    async fn list(&self) -> Result<Vec<Entry>, Error> {
        let start_time = Instant::now();

        let out = self.0.list().await;

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
impl<T: Update> Update for WithMetrics<T> {
    async fn update(&self, entries: Vec<Entry>) -> Result<(), Error> {
        let start_time = Instant::now();

        let out = self.0.update(entries).await;

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
impl<T: Reload> Reload for WithMetrics<T> {
    async fn reload(&self) -> Result<(), Error> {
        let start_time = Instant::now();

        let out = self.0.reload().await;

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
