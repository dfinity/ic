use crate::node::Node;
use async_trait::async_trait;
use std::fmt::Debug;

#[derive(Debug, PartialEq, Clone)]
pub enum HealthCheckError {}

#[derive(Clone, PartialEq)]
pub struct HealthCheckResult {
    is_healthy: bool,
}

#[async_trait]
pub trait HealthCheck: Send + Sync + Debug {
    async fn check(&self, node: &Node) -> Result<HealthCheckResult, HealthCheckError>;
}

#[derive(Debug)]
pub struct NodeHealthCheckerMock;

#[async_trait]
impl HealthCheck for NodeHealthCheckerMock {
    async fn check(&self, node: &Node) -> Result<HealthCheckResult, HealthCheckError> {
        println!("HealthCheck: node {:?} checked", node);
        Ok(HealthCheckResult { is_healthy: true })
    }
}
