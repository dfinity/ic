use crate::{check::HealthCheckResult, node::Node};
use std::{
    collections::HashSet,
    fmt::Debug,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
};

pub const IC0_SEED_DOMAIN: &str = "ic0.app";

#[derive(Debug, Clone)]
pub enum NodesSnapshotError {}

#[derive(Default, Debug, Clone)]
pub struct Snapshot {
    // TODO: switch to different data structure/s when implementing latency based strategy + for a better efficiency.
    current_idx: Arc<AtomicUsize>,
    healthy_nodes: HashSet<String>,
}

pub struct NodesChange {
    pub nodes_added: Vec<Node>,
    pub nodes_removed: Vec<Node>,
}

impl Snapshot {
    pub fn new(seed_domains: Vec<&str>) -> Self {
        Self {
            current_idx: Arc::new(AtomicUsize::new(0)),
            healthy_nodes: HashSet::from_iter(seed_domains.into_iter().map(|s| s.to_string())),
        }
    }

    pub fn sync_with(&mut self, nodes: &[Node]) -> Result<NodesChange, NodesSnapshotError> {
        let new_nodes = HashSet::from_iter(nodes.iter().map(|n| n.domain.clone()));
        // Find nodes that were removed from topology.
        let nodes_removed: HashSet<String> =
            self.healthy_nodes.difference(&new_nodes).cloned().collect();
        // Find nodes that were added to topology.
        let nodes_added: HashSet<String> =
            new_nodes.difference(&self.healthy_nodes).cloned().collect();
        // Non-existing nodes can be immediately removed.
        for node in nodes_removed.iter() {
            self.healthy_nodes.remove(node);
        }
        // NOTE: newly added nodes will eventually appear in the map after the first health check, via update_node() invocation.
        let nodes_change = NodesChange {
            nodes_added: nodes_added.into_iter().map(Node::new).collect(),
            nodes_removed: nodes_removed.into_iter().map(Node::new).collect(),
        };
        Ok(nodes_change)
    }

    pub fn update_node_health(
        &mut self,
        node: &Node,
        health: HealthCheckResult,
    ) -> Result<(), NodesSnapshotError> {
        if health.is_healthy {
            self.healthy_nodes.insert(node.domain.clone());
        } else {
            // Unhealthy nodes are simply removed.
            self.healthy_nodes.remove(&node.domain);
        }
        Ok(())
    }

    pub fn next(&self) -> Option<Node> {
        let prev_idx = self.current_idx.fetch_add(1, Ordering::Relaxed);
        // TODO: maybe switch to different data structures for a better efficiency, this sampling is O(healthy_nodes).
        let domain = self
            .healthy_nodes
            .iter()
            .nth(prev_idx % self.healthy_nodes.len())
            .unwrap();
        Some(Node::new(domain))
    }
}
