use std::time::Instant;

use async_trait::async_trait;
use opentelemetry::KeyValue;
use reqwest::{Error as ReqwestError, Request, Response};
use tracing::info;

use crate::metrics::{MetricParams, WithMetrics};

#[async_trait]
pub trait HttpClient: Send + Sync {
    async fn execute(&self, req: Request) -> Result<Response, ReqwestError>;
}

pub struct ReqwestClient(pub reqwest::Client);

#[async_trait]
impl HttpClient for ReqwestClient {
    async fn execute(&self, req: Request) -> Result<Response, ReqwestError> {
        self.0.execute(req).await
    }
}

#[async_trait]
impl<T: HttpClient> HttpClient for WithMetrics<T> {
    async fn execute(&self, req: Request) -> Result<Response, ReqwestError> {
        let start_time = Instant::now();

        // Attribute (Method)
        let method = req.method().to_string();

        // Attribute (Scheme)
        let scheme = req.url().scheme().to_string();

        // Attribute (Host)
        let host = match req.url().host_str() {
            Some(h) => h.to_string(),
            None => "".to_string(),
        };

        // Attribute (Path)
        let path = req.url().path().to_string();

        // Attribute (Query)
        let query = match req.url().query() {
            Some(q) => q.to_string(),
            None => "".to_string(),
        };

        let out = self.0.execute(req).await;

        let status = match out {
            Ok(_) => "ok",
            Err(_) => "fail",
        };

        let duration = start_time.elapsed().as_secs_f64();

        // Attribute (Status Code)
        let status_code = match &out {
            Ok(out) => format!("{}", out.status().as_u16()),
            Err(_) => "".to_string(),
        };

        let MetricParams {
            action,
            counter,
            recorder,
        } = &self.1;

        let labels = &[
            KeyValue::new("status", status),
            KeyValue::new("method", method.clone()),
            KeyValue::new("scheme", scheme.clone()),
            KeyValue::new("host", host.clone()),
            KeyValue::new("status_code", status_code.clone()),
        ];

        counter.add(1, labels);
        recorder.record(duration, labels);

        info!(
            action = action.as_str(),
            method,
            scheme,
            host,
            path,
            query,
            status_code,
            status,
            duration,
            error = ?out.as_ref().err(),
        );

        out
    }
}
