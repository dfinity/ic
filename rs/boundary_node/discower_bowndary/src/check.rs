use crate::{node::Node, types::GlobalShared};
use arc_swap::ArcSwap;
use async_trait::async_trait;
use std::{collections::HashMap, fmt::Debug, sync::Arc};

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
pub struct NodeHealthCheckerMock {
    // A simple map holding strings (node domain names) as keys, and bool (is_healthy status) as values.
    pub health_map: GlobalShared<HashMap<String, bool>>,
}

impl Default for NodeHealthCheckerMock {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl HealthCheck for NodeHealthCheckerMock {
    async fn check(&self, node: &Node) -> Result<HealthCheckResult, HealthCheckError> {
        let nodes = self.health_map.load_full();
        let is_healthy = *nodes.get(&node.domain).unwrap();
        Ok(HealthCheckResult { is_healthy })
    }
}

impl NodeHealthCheckerMock {
    pub fn new() -> Self {
        Self {
            health_map: Arc::new(ArcSwap::from_pointee(HashMap::new())),
        }
    }

    pub fn modify_domains_health(&self, domains_with_statuses: Vec<(&str, bool)>) {
        let mut nodes_map = (*self.health_map.load_full()).clone();
        domains_with_statuses.iter().for_each(|node| {
            nodes_map
                .entry(node.0.to_string())
                .and_modify(|health| *health = node.1)
                .or_insert(node.1);
        });
        self.health_map.store(Arc::new(nodes_map.clone()));
    }
}
