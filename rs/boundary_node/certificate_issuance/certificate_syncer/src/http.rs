use std::time::Instant;

use async_trait::async_trait;
use hyper::{client::connect::Connect, Body, Request, Response};
use mockall::automock;
use opentelemetry::KeyValue;
use tracing::info;

use crate::metrics::{MetricParams, WithMetrics};

#[automock]
#[async_trait]
pub trait HttpClient: Send + Sync {
    async fn request(&self, req: Request<Body>) -> Result<Response<Body>, hyper::Error>;
}

pub struct HyperClient<T> {
    c: hyper::Client<T>,
}

impl<T> HyperClient<T> {
    pub fn new(c: hyper::Client<T>) -> Self {
        Self { c }
    }
}

#[async_trait]
impl<T> HttpClient for HyperClient<T>
where
    T: Connect + Clone + Send + Sync + 'static,
{
    async fn request(&self, req: Request<Body>) -> Result<Response<Body>, hyper::Error> {
        self.c.request(req).await
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

        counter.add(1, labels);
        recorder.record(duration, labels);

        info!(action = action.as_str(), uri, method, status, duration, error = ?out.as_ref().err());

        out
    }
}
