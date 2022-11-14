use std::time::Instant;

use anyhow::Error;
use async_trait::async_trait;
use candid::Principal;
use hyper::{Body, Request, Response};
use opentelemetry::{
    metrics::{Counter, Histogram, Meter},
    Context, KeyValue,
};
use tracing::info;
use trust_dns_resolver::{error::ResolveError, lookup::Lookup, proto::rr::RecordType};
use uuid::Uuid;

use crate::{
    acme, certificate,
    check::{Check, CheckError},
    dns::{self, Record, Resolve},
    http::HttpClient,
    registration::{Create, CreateError, Get, GetError, Registration, State, Update, UpdateError},
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
    async fn create(&self, domain: &str, canister: &Principal) -> Result<Uuid, CreateError> {
        let start_time = Instant::now();

        let out = self.0.create(domain, canister).await;

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

        info!(action = action.as_str(), domain, status, duration, error = ?out.as_ref().err());

        out
    }
}

#[async_trait]
impl<T: Update> Update for WithMetrics<T> {
    async fn update(&self, id: &Uuid, state: &State) -> Result<(), UpdateError> {
        let start_time = Instant::now();

        let out = self.0.update(id, state).await;

        let status = if out.is_ok() { "ok" } else { "fail" };
        let duration = start_time.elapsed().as_secs_f64();

        let labels = &[
            KeyValue::new("status", status),
            KeyValue::new("state", state.to_string()),
        ];

        let MetricParams {
            action,
            counter,
            recorder,
        } = &self.1;

        let cx = Context::current();

        counter.add(&cx, 1, labels);
        recorder.record(&cx, duration, labels);

        info!(action = action.as_str(), id = id.to_string(), state = state.to_string(), status, duration, error = ?out.as_ref().err());

        out
    }
}

#[async_trait]
impl<T: Get> Get for WithMetrics<T> {
    async fn get(&self, id: &Uuid) -> Result<Registration, GetError> {
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
    async fn queue(&self, id: &Uuid, t: u64) -> Result<(), QueueError> {
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
    async fn dispense(&self) -> Result<(Uuid, Task), DispenseError> {
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
}

#[async_trait]
impl<T: Process> Process for WithMetrics<T> {
    async fn process(&self, task: &Task) -> Result<(), ProcessError> {
        let start_time = Instant::now();

        let out = self.0.process(task).await;

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

        info!(action = action.as_str(), domain = task.domain, task = task.action.to_string(), status, duration, error = ?out.as_ref().err());

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
impl<T: HttpClient> HttpClient for WithMetrics<T> {
    async fn request(&self, req: Request<Body>) -> Result<Response<Body>, hyper::Error> {
        let start_time = Instant::now();

        let (uri, method) = (req.uri().to_string(), req.method().to_string());

        let out = self.0.request(req).await;

        let status = if out.is_ok() { "ok" } else { "fail" };
        let duration = start_time.elapsed().as_secs_f64();

        let labels = &[
            KeyValue::new("status", status),
            KeyValue::new("method", method.to_string()),
        ];

        let MetricParams {
            action,
            counter,
            recorder,
        } = &self.1;

        let cx = Context::current();

        counter.add(&cx, 1, labels);
        recorder.record(&cx, duration, labels);

        info!(action = action.as_str(), uri, method, status, duration, error = ?out.as_ref().err());

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
    async fn upload(&self, id: &str, pair: &certificate::Pair) -> Result<(), Error> {
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
    async fn export(&self) -> Result<Vec<certificate::Package>, Error> {
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
    async fn check(&self, domain: &str) -> Result<Principal, CheckError> {
        let start_time = Instant::now();

        let out = self.0.check(domain).await;

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

        info!(action = action.as_str(), domain, status, duration, error = ?out.as_ref().err());

        out
    }
}
