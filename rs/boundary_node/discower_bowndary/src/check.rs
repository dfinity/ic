use crate::node::Node;
use async_trait::async_trait;
use http::{Method, StatusCode};
use ic_agent::agent::http_transport::reqwest_transport::reqwest::{Client, Request};
use std::fmt::Debug;
use std::time::Duration;
use url::Url;

#[derive(Debug, PartialEq, Clone)]
pub enum HealthCheckError {}

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
        let url = Url::parse(&format!("https://{}/health", node.domain)).unwrap();

        let mut request = Request::new(Method::GET, url);
        *request.timeout_mut() = Some(self.timeout);

        let is_healthy = match self.http_client.execute(request).await {
            Ok(response) => matches!(response.status(), StatusCode::NO_CONTENT),
            Err(_) => false,
        };
        Ok(HealthCheckResult { is_healthy })
    }
}
