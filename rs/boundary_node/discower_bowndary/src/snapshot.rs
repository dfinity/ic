use crate::{check::HealthCheckResult, node::Node};
use std::fmt::Debug;

pub const IC0_SEED_DOMAIN: &str = "ic0.app";

#[derive(PartialEq, Debug, Default)]
pub struct NodesChanged(pub bool);

#[derive(Clone, Debug)]
pub enum NodesSnapshotError {}

pub trait Snapshot: Send + Sync + Clone + Debug {
    fn next(&self) -> Option<Node>;
    fn sync_with(&mut self, nodes: &[Node]) -> Result<NodesChanged, NodesSnapshotError>;
    fn has_healthy_nodes(&self) -> bool;
    fn update_node_health(
        &mut self,
        node: &Node,
        health: HealthCheckResult,
    ) -> Result<bool, NodesSnapshotError>;
}
