use std::time::Instant;

use anyhow::Error;
use async_trait::async_trait;
use ic_registry_client::client::RegistryClientImpl;
use opentelemetry::{
    baggage::BaggageExt,
    metrics::{Counter, Histogram, Meter, ObservableGauge},
    Context, KeyValue,
};
use tracing::info;

use crate::{
    check::{Check, CheckResult},
    registry::{CreateRegistryClient, RoutingTable, Snapshot},
    reload::Reload,
    Persist, PersistStatus, Run,
};

pub struct MetricParams {
    pub action: String,
    pub counter: Counter<u64>,
    pub recorder: Histogram<f64>,
}

impl MetricParams {
    pub fn new(meter: &Meter, namespace: &str, action: &str) -> Self {
        Self {
            action: action.to_string(),
            counter: meter
                .u64_counter(format!("{namespace}.{action}.total"))
                .with_description(format!("Counts occurrences of {action} calls"))
                .init(),
            recorder: meter
                .f64_histogram(format!("{namespace}.{action}.duration_sec"))
                .with_description(format!("Records the duration of {action} calls in seconds"))
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

        let cx = Context::current();

        counter.add(&cx, 1, labels);
        recorder.record(&cx, duration, labels);

        info!(action, status, duration, error = ?out.as_ref().err());

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

        let cx = Context::current();

        counter.add(&cx, 1, labels);
        recorder.record(&cx, duration, labels);

        let (out, registry_version) = match out {
            Ok(rt) => {
                let v = rt.registry_version.to_string();
                (Ok(rt), v)
            }
            _ => (out, String::from("N/A")),
        };

        info!(action, status, duration, registry_version, error = ?out.as_ref().err());

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

        let cx = Context::current();

        counter.add(&cx, 1, labels);
        recorder.record(&cx, duration, labels);

        info!(action, status, duration, error = ?out.as_ref().err());

        out
    }
}

#[async_trait]
impl<T: Persist> Persist for WithMetrics<T> {
    async fn persist(&self, rt: &RoutingTable) -> Result<PersistStatus, Error> {
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

        let cx = Context::current();

        counter.add(&cx, 1, labels);
        recorder.record(&cx, duration, labels);

        info!(action, status, duration, error = ?out.as_ref().err());

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

        let cx = Context::current();

        counter.add(&cx, 1, labels);
        recorder.record(&cx, duration, labels);

        info!(action, status, duration, error = ?out.as_ref().err());

        out
    }
}

pub struct CheckMetricParams {
    action: String,
    counter: Counter<u64>,
    recorder: Histogram<f64>,
    status_gauge: ObservableGauge<u64>,
    height_gauge: ObservableGauge<i64>,
}

impl CheckMetricParams {
    pub fn new(meter: &Meter, namespace: &str, action: &str) -> Self {
        Self {
            action: action.to_string(),
            counter: meter
                .u64_counter(format!("{namespace}.{action}.total"))
                .with_description(format!("Counts occurrences of {action} calls"))
                .init(),
            recorder: meter
                .f64_histogram(format!("{namespace}.{action}.duration_sec"))
                .with_description(format!("Records the duration of {action} calls in seconds"))
                .init(),
            status_gauge: meter
                .u64_observable_gauge(format!("{namespace}.{action}.status"))
                .with_description(format!("Tracks the status of {action} calls"))
                .init(),
            height_gauge: meter
                .i64_observable_gauge(format!("{namespace}.{action}.block_height"))
                .with_description(format!("Tracks the returned height from {action} calls"))
                .init(),
        }
    }
}

pub struct CheckWithMetrics<T>(pub T, pub CheckMetricParams);

#[async_trait]
impl<T: Check> Check for CheckWithMetrics<T> {
    async fn check(&self, addr: &str) -> Result<CheckResult, Error> {
        let start_time = Instant::now();

        let out = self.0.check(addr).await;

        let status = if out.is_ok() { "ok" } else { "fail" };
        let block_height = out.as_ref().map_or(-1, |out| out.height as i64);
        let duration = start_time.elapsed().as_secs_f64();

        let cx = Context::current();
        let bgg = cx.baggage();

        // Make labels (histogram needs `status`, gauges need to not have `status`)
        let labels = &[
            KeyValue::new("subnet_id", bgg.get("subnet_id").unwrap().to_string()),
            KeyValue::new("node_id", bgg.get("node_id").unwrap().to_string()),
            KeyValue::new("addr", addr.to_string()),
            KeyValue::new("status", status),
        ];
        let gauge_labels = &labels[..3];

        let CheckMetricParams {
            action,
            counter,
            recorder,
            status_gauge,
            height_gauge,
        } = &self.1;

        counter.add(&cx, 1, labels);
        recorder.record(&cx, duration, labels);
        height_gauge.observe(&cx, block_height, gauge_labels);
        status_gauge.observe(&cx, out.is_ok().into(), gauge_labels);

        info!(
            action,
            subnet_id = %bgg.get("subnet_id").unwrap(),
            node_id = %bgg.get("node_id").unwrap(),
            addr,
            status,
            duration,
            block_height,
            error = ?out.as_ref().err(),
        );

        out
    }
}
