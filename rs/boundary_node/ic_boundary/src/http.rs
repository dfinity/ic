use std::time::Instant;

use async_trait::async_trait;
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
        // Attribute (Method)
        let method = req.method().to_string();

        // Attribute (Scheme)
        let scheme = req.url().scheme().to_string();

        // Attribute (Host)
        let host = req.url().host_str().unwrap_or("").to_string();

        // Attribute (Path)
        let path = req.url().path().to_string();

        // Attribute (Query)
        let query = req.url().query().unwrap_or("").to_string();

        let start_time = Instant::now();
        let out = self.0.execute(req).await;
        let duration = start_time.elapsed().as_secs_f64();

        let status = if out.is_ok() { "ok" } else { "fail" };

        // Attribute (Status Code)
        let status_code = match &out {
            Ok(out) => out.status().as_u16().to_string(),
            Err(_) => "000".to_string(),
        };

        let MetricParams {
            action,
            counter,
            recorder,
        } = &self.1;

        let labels = &[
            status,
            method.as_str(),
            scheme.as_str(),
            host.as_str(),
            status_code.as_str(),
        ];

        counter.with_label_values(labels).inc();
        recorder.with_label_values(labels).observe(duration);

        info!(
            action = action.as_str(),
            method = method.as_str(),
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
