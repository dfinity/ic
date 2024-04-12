use crate::{check::HealthCheckResult, node::Node};
use std::fmt::Debug;

#[derive(Debug, Clone)]
pub enum NodesSnapshotError {}

#[derive(Default, Debug, Clone)]
pub struct Snapshot {
    // fields storing nodes in some way vector, map ...
}

impl Snapshot {
    pub fn new() -> Self {
        // TODO: add seed somewhere
        Self {}
    }

    pub fn random_node(&self) -> Option<Node> {
        // Mocked for now. Should actually pick some random node from the stored nodes ...
        let node = Node::new("ic0.app".to_string());
        Some(node)
    }

    pub fn update_node(
        &mut self,
        health_checked_node: (&Node, HealthCheckResult),
    ) -> Result<(), NodesSnapshotError> {
        // Mocked for now. Should find the node and update it ...
        println!("Snapshot: updating {:?} health info", health_checked_node.0);
        Ok(())
    }
}
