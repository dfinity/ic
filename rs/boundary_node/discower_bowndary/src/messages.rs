use crate::{check::HealthCheckResult, node::Node};

#[derive(Clone, Debug)]
pub struct FetchedNodes {
    pub nodes: Vec<Node>,
}

pub struct NodeHealthUpdate {
    pub node: Node,
    pub health: HealthCheckResult,
}
