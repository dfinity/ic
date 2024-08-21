use crate::{check::HealthCheckResult, node::Node};

#[derive(Debug, Clone)]
pub struct FetchedNodes {
    pub nodes: Vec<Node>,
}

pub struct NodeHealthUpdate {
    pub node: Node,
    pub health: HealthCheckResult,
}
