use crate::node::Node;
use async_trait::async_trait;
use http::{Method, StatusCode};
use ic_agent::agent::http_transport::reqwest_transport::reqwest::{Client, Request};
use std::fmt::Debug;
use std::time::Duration;
use thiserror::Error;
use tracing::error;
use url::Url;

const SERVICE_NAME: &str = "HealthCheckImpl";

#[derive(Error, Debug, PartialEq, Clone)]
pub enum HealthCheckError {
    #[error(r#"Cannot parse url: "{0}""#)]
    UrlParseError(#[from] url::ParseError),
}

#[derive(Clone, PartialEq, Debug)]
pub struct HealthCheckResult {
    pub is_healthy: bool,
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

        let is_healthy = match self.http_client.execute(request).await {
            Ok(response) => matches!(response.status(), StatusCode::NO_CONTENT),
            Err(err) => {
                error!("{SERVICE_NAME}: check() failed for url={url}: {err:?}");
                false
            }
        };
        Ok(HealthCheckResult { is_healthy })
    }
}
