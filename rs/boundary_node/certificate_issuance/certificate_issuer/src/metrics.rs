use std::time::Instant;

use anyhow::Error;
use async_trait::async_trait;
use candid::Principal;
use opentelemetry::{
    metrics::{Counter, Histogram, Meter},
    Context, KeyValue,
};
use tracing::info;
use trust_dns_resolver::{error::ResolveError, lookup::Lookup, proto::rr::RecordType};

use crate::{
    acme,
    certificate::{self, ExportError, UploadError},
    check::{Check, CheckError},
    dns::{self, Record, Resolve},
    registration::{
        Create, CreateError, Get, GetError, Id, Registration, Update, UpdateError, UpdateType,
    },
    work::{Dispense, DispenseError, Process, ProcessError, Queue, QueueError, Task},
};

#[derive(Clone)]
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
                .with_description(format!("Counts occurences of {action} calls"))
                .init(),
            recorder: meter
                .f64_histogram(format!("{namespace}.{action}.duration_sec"))
                .with_description(format!("Records the duration of {action} calls in sec"))
                .init(),
        }
    }
}

#[derive(Clone)]
pub struct WithMetrics<T>(pub T, pub MetricParams);

#[async_trait]
impl<T: Create> Create for WithMetrics<T> {
    async fn create(&self, name: &str, canister: &Principal) -> Result<Id, CreateError> {
        let start_time = Instant::now();

        let out = self.0.create(name, canister).await;

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

        info!(action = action.as_str(), name, status, duration, error = ?out.as_ref().err());

        out
    }
}

#[async_trait]
impl<T: Update> Update for WithMetrics<T> {
    async fn update(&self, id: &str, typ: &UpdateType) -> Result<(), UpdateError> {
        let start_time = Instant::now();

        let out = self.0.update(id, typ).await;

        let status = if out.is_ok() { "ok" } else { "fail" };
        let duration = start_time.elapsed().as_secs_f64();

        let labels = &[
            KeyValue::new("status", status),
            KeyValue::new(
                "type",
                match typ {
                    UpdateType::Canister(_) => "update_canister".into(), // ignore canister id as it's unbounded
                    UpdateType::State(state) => state.to_string(),
                },
            ),
        ];

        let MetricParams {
            action,
            counter,
            recorder,
        } = &self.1;

        let cx = Context::current();

        counter.add(&cx, 1, labels);
        recorder.record(&cx, duration, labels);

        info!(action = action.as_str(), id = id.to_string(), typ = ?typ, status, duration, error = ?out.as_ref().err());

        out
    }
}

#[async_trait]
impl<T: Get> Get for WithMetrics<T> {
    async fn get(&self, id: &str) -> Result<Registration, GetError> {
        let start_time = Instant::now();

        let out = self.0.get(id).await;

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

        info!(action = action.as_str(), id = id.to_string(), status, duration, error = ?out.as_ref().err());

        out
    }
}

#[async_trait]
impl<T: Queue> Queue for WithMetrics<T> {
    async fn queue(&self, id: &Id, t: u64) -> Result<(), QueueError> {
        let start_time = Instant::now();

        let out = self.0.queue(id, t).await;

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

        info!(action = action.as_str(), id = id.to_string(), t, status, duration, error = ?out.as_ref().err());

        out
    }
}

#[async_trait]
impl<T: Dispense> Dispense for WithMetrics<T> {
    async fn dispense(&self) -> Result<(Id, Task), DispenseError> {
        let start_time = Instant::now();

        let out = self.0.dispense().await;

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

        info!(action = action.as_str(), status, duration, error = ?out.as_ref().err());

        out
    }

    async fn peek(&self) -> Result<Id, DispenseError> {
        let start_time = Instant::now();

        let out = self.0.peek().await;

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

        info!(action = action.as_str(), status, duration, error = ?out.as_ref().err());

        out
    }
}

#[async_trait]
impl<T: Process> Process for WithMetrics<T> {
    async fn process(&self, id: &Id, task: &Task) -> Result<(), ProcessError> {
        let start_time = Instant::now();

        let out = self.0.process(id, task).await;

        let status = if out.is_ok() { "ok" } else { "fail" };
        let duration = start_time.elapsed().as_secs_f64();

        let labels = &[
            KeyValue::new("status", status),
            KeyValue::new("task", task.action.to_string()),
        ];

        let MetricParams {
            action,
            counter,
            recorder,
        } = &self.1;

        let cx = Context::current();

        counter.add(&cx, 1, labels);
        recorder.record(&cx, duration, labels);

        info!(action = action.as_str(), id, name = task.name, task = task.action.to_string(), status, duration, error = ?out.as_ref().err());

        out
    }
}

#[async_trait]
impl<T: Resolve> Resolve for WithMetrics<T> {
    async fn lookup(&self, name: &str, record_type: RecordType) -> Result<Lookup, ResolveError> {
        let start_time = Instant::now();

        let out = self.0.lookup(name, record_type).await;

        let status = if out.is_ok() { "ok" } else { "fail" };
        let duration = start_time.elapsed().as_secs_f64();

        let labels = &[
            KeyValue::new("status", status),
            KeyValue::new("record_type", record_type.to_string()),
        ];

        let MetricParams {
            action,
            counter,
            recorder,
        } = &self.1;

        let cx = Context::current();

        counter.add(&cx, 1, labels);
        recorder.record(&cx, duration, labels);

        info!(action = action.as_str(), name, record_type = record_type.to_string(), status, duration, error = ?out.as_ref().err());

        out
    }
}

#[async_trait]
impl<T: dns::Create> dns::Create for WithMetrics<T> {
    async fn create(&self, zone: &str, name: &str, record: Record) -> Result<(), Error> {
        let start_time = Instant::now();

        let out = self.0.create(zone, name, record).await;

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

        info!(action = action.as_str(), zone, name, status, duration, error = ?out.as_ref().err());

        out
    }
}

#[async_trait]
impl<T: dns::Delete> dns::Delete for WithMetrics<T> {
    async fn delete(&self, zone: &str, name: &str) -> Result<(), Error> {
        let start_time = Instant::now();

        let out = self.0.delete(zone, name).await;

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

        info!(action = action.as_str(), zone, name, status, duration, error = ?out.as_ref().err());

        out
    }
}

#[async_trait]
impl<T: acme::Order> acme::Order for WithMetrics<T> {
    async fn order(&self, name: &str) -> Result<String, Error> {
        let start_time = Instant::now();

        let out = self.0.order(name).await;

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

        info!(action = action.as_str(), name, status, duration, error = ?out.as_ref().err());

        out
    }
}

#[async_trait]
impl<T: acme::Ready> acme::Ready for WithMetrics<T> {
    async fn ready(&self, name: &str) -> Result<(), Error> {
        let start_time = Instant::now();

        let out = self.0.ready(name).await;

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

        info!(action = action.as_str(), name, status, duration, error = ?out.as_ref().err());

        out
    }
}

#[async_trait]
impl<T: acme::Finalize> acme::Finalize for WithMetrics<T> {
    async fn finalize(&self, name: &str) -> Result<(String, String), Error> {
        let start_time = Instant::now();

        let out = self.0.finalize(name).await;

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

        info!(action = action.as_str(), name, status, duration, error = ?out.as_ref().err());

        out
    }
}

#[async_trait]
impl<T: certificate::Upload> certificate::Upload for WithMetrics<T> {
    async fn upload(&self, id: &str, pair: certificate::Pair) -> Result<(), UploadError> {
        let start_time = Instant::now();

        let out = self.0.upload(id, pair).await;

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

        info!(action = action.as_str(), id, status, duration, error = ?out.as_ref().err());

        out
    }
}

#[async_trait]
impl<T: certificate::Export> certificate::Export for WithMetrics<T> {
    async fn export(&self) -> Result<Vec<certificate::Package>, ExportError> {
        let start_time = Instant::now();

        let out = self.0.export().await;

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

        info!(action = action.as_str(), status, duration, error = ?out.as_ref().err());

        out
    }
}

#[async_trait]
impl<T: Check> Check for WithMetrics<T> {
    async fn check(&self, name: &str) -> Result<Principal, CheckError> {
        let start_time = Instant::now();

        let out = self.0.check(name).await;

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

        info!(action = action.as_str(), name, status, duration, error = ?out.as_ref().err());

        out
    }
}
