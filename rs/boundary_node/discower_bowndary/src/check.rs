use crate::node::Node;
use async_trait::async_trait;
use ic_agent::agent::http_transport::hyper_transport::hyper::{Method, StatusCode};
use ic_agent::agent::http_transport::reqwest_transport::reqwest::{Client, Request};
use std::fmt::Debug;
use std::time::{Duration, Instant};
use thiserror::Error;
use tracing::error;
use url::Url;

const SERVICE_NAME: &str = "HealthCheckImpl";

#[derive(Error, Debug, PartialEq, Clone)]
pub enum HealthCheckError {
    #[error(r#"Cannot parse url: "{0}""#)]
    UrlParseError(#[from] url::ParseError),
}

#[derive(Clone, PartialEq, Debug, Default)]
pub struct HealthCheckResult {
    pub latency: Option<Duration>,
}

impl HealthCheckResult {
    pub fn is_healthy(&self) -> bool {
        self.latency.is_some()
    }
}

#[async_trait]
pub trait HealthCheck: Send + Sync + Debug {
    async fn check(&self, node: &Node) -> Result<HealthCheckResult, HealthCheckError>;
}

#[derive(Debug)]
pub struct HealthCheckImpl {
    http_client: Client,
    timeout: Duration,
}

impl HealthCheckImpl {
    pub fn new(http_client: Client, timeout: Duration) -> Self {
        Self {
            http_client,
            timeout,
        }
    }
}

#[async_trait]
impl HealthCheck for HealthCheckImpl {
    async fn check(&self, node: &Node) -> Result<HealthCheckResult, HealthCheckError> {
        let url = Url::parse(&format!("https://{}/health", node.domain))?;

        let mut request = Request::new(Method::GET, url.clone());
        *request.timeout_mut() = Some(self.timeout);

        let start = Instant::now();
        let response = self.http_client.execute(request).await;
        let elapsed = start.elapsed();

        // Set latency to Some() only for successful health check.
        let latency = match response {
            Ok(res) if res.status() == StatusCode::NO_CONTENT => Some(elapsed),
            Ok(res) => {
                error!(
                    "{SERVICE_NAME}: check() for url={url} received unexpected http status {}",
                    res.status()
                );
                None
            }
            Err(err) => {
                error!("{SERVICE_NAME}: check() failed for url={url}: {err:?}");
                None
            }
        };

        Ok(HealthCheckResult { latency })
    }
}
