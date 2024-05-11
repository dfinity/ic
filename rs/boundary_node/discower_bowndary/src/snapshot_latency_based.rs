use crate::{
    check::HealthCheckResult,
    node::Node,
    snapshot::{NodesChanged, NodesSnapshotError, Snapshot},
};

#[derive(Default, Debug, Clone)]
struct LatencyBasedSnapshot;

impl Snapshot for LatencyBasedSnapshot {
    fn next(&self) -> Option<Node> {
        todo!()
    }

    fn sync_with(&mut self, _nodes: &[Node]) -> Result<NodesChanged, NodesSnapshotError> {
        todo!()
    }

    fn has_healthy_nodes(&self) -> bool {
        todo!()
    }

    fn update_node_health(
        &mut self,
        _node: &Node,
        _health: HealthCheckResult,
    ) -> Result<bool, NodesSnapshotError> {
        todo!()
    }
}
