use std::time::Instant;

use async_trait::async_trait;
use mockall::automock;
use opentelemetry::KeyValue;
use reqwest::{Client, Error, Request, Response};
use tracing::info;

use crate::metrics::{MetricParams, WithMetrics};

#[automock]
#[async_trait]
pub trait HttpClient: Send + Sync {
    async fn execute(&self, req: Request) -> Result<Response, Error>;
}

pub struct ReqwestClient(Client);

impl ReqwestClient {
    pub fn new(c: Client) -> Self {
        Self(c)
    }
}

#[async_trait]
impl HttpClient for ReqwestClient {
    async fn execute(&self, req: Request) -> Result<Response, Error> {
        self.0.execute(req).await
    }
}

#[async_trait]
impl<T: HttpClient> HttpClient for WithMetrics<T> {
    async fn execute(&self, req: Request) -> Result<Response, Error> {
        let start_time = Instant::now();

        let url_string = req.url().to_string();
        let method = req.method().to_string();

        let out = self.0.execute(req).await;

        let status = if out.is_ok() { "ok" } else { "fail" };
        let duration = start_time.elapsed().as_secs_f64();

        let labels = &[
            KeyValue::new("status", status),
            KeyValue::new("method", method.clone()),
        ];

        let MetricParams {
            action,
            counter,
            recorder,
        } = &self.1;

        counter.add(1, labels);
        recorder.record(duration, labels);

        info!(action = action.as_str(), url_string, method, status, duration, error = ?out.as_ref().err());

        out
    }
}
