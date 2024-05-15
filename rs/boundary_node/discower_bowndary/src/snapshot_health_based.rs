use std::{
    collections::HashSet,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
};

use crate::{
    check::HealthCheckResult,
    node::Node,
    snapshot::{NodesChanged, NodesSnapshotError, Snapshot},
};

#[derive(Default, Debug, Clone)]
pub struct HealthBasedSnapshot {
    current_idx: Arc<AtomicUsize>,
    healthy_nodes: HashSet<String>,
    existing_nodes: HashSet<String>,
}

impl HealthBasedSnapshot {
    pub fn new() -> Self {
        Self {
            current_idx: Arc::new(AtomicUsize::new(0)),
            healthy_nodes: HashSet::new(),
            existing_nodes: HashSet::new(),
        }
    }
}

impl Snapshot for HealthBasedSnapshot {
    fn sync_with(&mut self, nodes: &[Node]) -> Result<NodesChanged, NodesSnapshotError> {
        let new_nodes = HashSet::from_iter(nodes.iter().map(|n| n.domain.clone()));
        // Find nodes that were removed from topology.
        let nodes_removed: HashSet<String> = self
            .existing_nodes
            .difference(&new_nodes)
            .cloned()
            .collect();
        // Find nodes that were added to topology.
        let nodes_added: HashSet<String> = new_nodes
            .difference(&self.existing_nodes)
            .cloned()
            .collect();
        for node in nodes_added.iter() {
            self.existing_nodes.insert(node.clone());
            // NOTE: newly added nodes will appear in the healthy_nodes indirectly after the first health check, via update_node() invocation.
        }
        for node in nodes_removed.iter() {
            self.existing_nodes.remove(node);
            self.healthy_nodes.remove(node);
        }
        let nodes_changed = NodesChanged(!nodes_removed.is_empty() || !nodes_added.is_empty());
        Ok(nodes_changed)
    }

    fn update_node_health(
        &mut self,
        node: &Node,
        health: HealthCheckResult,
    ) -> Result<bool, NodesSnapshotError> {
        if health.is_healthy() && self.existing_nodes.contains(&node.domain) {
            Ok(self.healthy_nodes.insert(node.domain.clone()))
        } else {
            Ok(self.healthy_nodes.remove(&node.domain))
        }
    }

    fn has_healthy_nodes(&self) -> bool {
        !self.healthy_nodes.is_empty()
    }

    fn next(&self) -> Option<Node> {
        if self.healthy_nodes.is_empty() {
            return None;
        }
        let prev_idx = self.current_idx.fetch_add(1, Ordering::Relaxed);
        self.healthy_nodes
            .iter()
            .nth(prev_idx % self.healthy_nodes.len())
            .map(Node::new)
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;
    use std::{collections::HashSet, sync::atomic::Ordering};

    use crate::snapshot::Snapshot;
    use crate::{check::HealthCheckResult, node::Node};

    use super::HealthBasedSnapshot;

    #[test]
    fn test_snapshot_init() {
        // Arrange
        let snapshot = HealthBasedSnapshot::new();
        // Check
        assert!(snapshot.healthy_nodes.is_empty());
        assert!(snapshot.existing_nodes.is_empty());
        assert!(!snapshot.has_healthy_nodes());
        assert_eq!(snapshot.current_idx.load(Ordering::SeqCst), 0);
        assert!(snapshot.next().is_none());
    }

    #[test]
    fn test_update_node_health_with_healthy_node_fails() {
        // Arrange
        let mut snapshot = HealthBasedSnapshot::new();
        // Act
        let node = Node::new("api1.com");
        let health = HealthCheckResult {
            latency: Some(Duration::from_secs(1)),
        };
        let is_updated = snapshot
            .update_node_health(&node, health)
            .expect("node update failed");
        assert!(!is_updated);
        assert!(!snapshot.has_healthy_nodes());
    }

    #[test]
    fn test_update_node_health_with_healthy_node_succeeds() {
        // Arrange
        let mut snapshot = HealthBasedSnapshot::new();
        let node = Node::new("api1.com");
        let health = HealthCheckResult {
            latency: Some(Duration::from_secs(1)),
        };
        snapshot.existing_nodes.insert(node.domain.clone());
        // Act
        let is_updated = snapshot
            .update_node_health(&node, health)
            .expect("node update failed");
        assert!(is_updated);
        assert_eq!(
            snapshot.healthy_nodes,
            HashSet::from_iter(vec![node.clone().domain])
        );
        assert!(snapshot.has_healthy_nodes());
        assert_eq!(snapshot.next().unwrap(), node);
        assert_eq!(snapshot.current_idx.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn test_update_node_health_with_unhealthy_node_fails() {
        // Arrange
        let mut snapshot = HealthBasedSnapshot::new();
        let node = Node::new("api1.com");
        let health = HealthCheckResult {
            latency: Some(Duration::from_secs(1)),
        };
        // Act
        let is_updated = snapshot
            .update_node_health(&node, health)
            .expect("node update failed");
        assert!(!is_updated);
        assert!(!snapshot.has_healthy_nodes());
        assert!(snapshot.next().is_none());
    }

    #[test]
    fn test_update_node_health_with_unhealthy_node_succeeds() {
        // Arrange
        let mut snapshot = HealthBasedSnapshot::new();
        let node = Node::new("api1.com");
        snapshot.healthy_nodes.insert(node.clone().domain);
        let health = HealthCheckResult {
            latency: Some(Duration::from_secs(1)),
        };
        // Act
        let is_updated = snapshot
            .update_node_health(&node, health)
            .expect("node update failed");
        assert!(is_updated);
        assert!(!snapshot.has_healthy_nodes());
        assert!(snapshot.next().is_none());
    }

    #[test]
    fn test_sync_with_existing_node() {
        // Arrange
        let mut snapshot = HealthBasedSnapshot::new();
        let node = Node::new("api1.com");
        snapshot.existing_nodes.insert(node.clone().domain);
        // Act
        let nodes_changed = snapshot.sync_with(&[node.clone()]).unwrap();
        assert!(!nodes_changed.0);
        assert!(snapshot.healthy_nodes.is_empty());
        assert_eq!(
            snapshot.existing_nodes,
            HashSet::from_iter(vec![node.clone().domain])
        );
    }

    #[test]
    fn test_sync_with_one_new_node_1() {
        // Arrange
        let mut snapshot = HealthBasedSnapshot::new();
        // Act
        let node = Node::new("api1.com");
        let nodes_changed = snapshot.sync_with(&[node.clone()]).unwrap();
        assert!(nodes_changed.0);
        assert!(snapshot.healthy_nodes.is_empty());
        assert_eq!(
            snapshot.existing_nodes,
            HashSet::from_iter(vec![node.clone().domain])
        );
    }

    #[test]
    fn test_sync_with_new_node_2() {
        // Arrange
        let mut snapshot = HealthBasedSnapshot::new();
        let node_1 = Node::new("api1.com");
        snapshot.existing_nodes.insert(node_1.domain);
        // Act
        let node_2 = Node::new("api2.com");
        let nodes_changed = snapshot.sync_with(&[node_2.clone()]).unwrap();
        assert!(nodes_changed.0);
        assert!(snapshot.healthy_nodes.is_empty());
        assert_eq!(
            snapshot.existing_nodes,
            HashSet::from_iter(vec![node_2.domain])
        );
    }

    #[test]
    fn test_sync_with_an_empty_node_list() {
        // Arrange
        let mut snapshot = HealthBasedSnapshot::new();
        let node_1 = Node::new("api1.com");
        let node_2 = Node::new("api2.com");
        snapshot.existing_nodes.insert(node_1.domain);
        snapshot.existing_nodes.insert(node_2.domain);
        // Act
        let nodes_changed = snapshot.sync_with(&[]).unwrap();
        assert!(nodes_changed.0);
        assert!(snapshot.healthy_nodes.is_empty());
        assert!(snapshot.existing_nodes.is_empty());
    }
}
