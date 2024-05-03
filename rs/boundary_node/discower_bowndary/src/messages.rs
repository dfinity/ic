use crate::{check::HealthCheckResult, node::Node};

#[derive(Debug, Clone)]
pub struct FetchedNodes {
    // TODO: if needed change to Vec<Arc<Node>>
    pub nodes: Vec<Node>,
}

pub struct NodeHealthChanged {
    pub node: Node,
    pub health: HealthCheckResult,
}
