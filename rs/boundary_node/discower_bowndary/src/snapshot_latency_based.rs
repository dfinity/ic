use crate::{
    check::HealthCheckResult,
    node::Node,
    snapshot::{NodesChanged, NodesSnapshotError, Snapshot},
};
use rand::Rng;
use simple_moving_average::{SumTreeSMA, SMA};
use std::{collections::HashSet, time::Duration};

// Some big value >> health check timeout
const MAX_LATENCY: Duration = Duration::from_secs(100);

const WINDOW_SIZE: usize = 10;

type LatencyMovAvg = SumTreeSMA<f64, f64, WINDOW_SIZE>;

#[derive(Clone, Debug)]
struct WeightedNode {
    domain: String,
    latency_mov_avg: LatencyMovAvg,
    weight: f64,
}

#[derive(Clone, Debug, Default)]
pub struct LatencyBasedSnapshot {
    weighted_nodes: Vec<WeightedNode>,
    existing_nodes: HashSet<String>,
}

impl LatencyBasedSnapshot {
    pub fn new() -> Self {
        Self {
            weighted_nodes: vec![],
            existing_nodes: HashSet::new(),
        }
    }
}

// rand_num is expected to be in [0, 1]
#[inline(always)]
fn weighted_random_sampling(weights: &[f64], rand_num: f64) -> Option<usize> {
    let sum: f64 = weights.iter().sum();
    let mut mapped_value = rand_num * sum;
    for (idx, weight) in weights.iter().enumerate() {
        mapped_value -= weight;
        if mapped_value <= 0.0 {
            return Some(idx);
        }
    }
    None
}

impl Snapshot for LatencyBasedSnapshot {
    fn next(&self) -> Option<Node> {
        let mut rng = rand::thread_rng();
        let rand_num = rng.gen::<f64>(); // random num in [0, 1)
        let weights = self
            .weighted_nodes
            .iter()
            .map(|n| n.weight)
            .collect::<Vec<_>>();
        let idx = weighted_random_sampling(weights.as_slice(), rand_num);
        idx.map(|idx| Node::new(self.weighted_nodes[idx].domain.clone()))
    }

    fn sync_with(&mut self, nodes: &[Node]) -> Result<NodesChanged, NodesSnapshotError> {
        let new_nodes = HashSet::from_iter(nodes.iter().map(|n| n.domain.clone()));
        // Find removed nodes from topology.
        let nodes_removed: HashSet<String> = self
            .existing_nodes
            .difference(&new_nodes)
            .cloned()
            .collect();
        // Find added nodes to topology.
        let nodes_added: HashSet<String> = new_nodes
            .difference(&self.existing_nodes)
            .cloned()
            .collect();
        for node in nodes_added.iter() {
            self.existing_nodes.insert(node.clone());
            // NOTE: newly added nodes will appear in the weighted_nodes indirectly after the first health check, via update_node() invocation.
        }
        for node in nodes_removed.iter() {
            self.existing_nodes.remove(node);
            let idx = self
                .weighted_nodes
                .iter()
                .position(|x| x.domain == node.as_str());
            idx.map(|idx| self.weighted_nodes.swap_remove(idx));
        }
        let nodes_changed = NodesChanged(!nodes_removed.is_empty() || !nodes_added.is_empty());
        Ok(nodes_changed)
    }

    fn has_healthy_nodes(&self) -> bool {
        !self.weighted_nodes.is_empty()
    }

    fn update_node_health(
        &mut self,
        node: &Node,
        health: HealthCheckResult,
    ) -> Result<bool, NodesSnapshotError> {
        if !self.existing_nodes.contains(&node.domain) {
            return Ok(false);
        }

        // When latency is None, we assign some big value
        let latency = health.latency.unwrap_or(MAX_LATENCY).as_millis() as f64;

        if let Some(idx) = self
            .weighted_nodes
            .iter()
            .position(|x| x.domain == node.domain)
        {
            // Node is already in array (not the first update call).
            self.weighted_nodes[idx].latency_mov_avg.add_sample(latency);
            let latency_avg = self.weighted_nodes[idx].latency_mov_avg.get_average();
            // Nodes with smaller average latency are preferred for routing.
            // Hence we use inverted values for weights.
            self.weighted_nodes[idx].weight = 1.0 / latency_avg;
        } else {
            // Node is not yet in array (first update call).
            let mut latency_mov_avg = LatencyMovAvg::new();
            latency_mov_avg.add_sample(latency);
            let weight = 1.0 / latency_mov_avg.get_average();
            self.weighted_nodes.push(WeightedNode {
                latency_mov_avg,
                domain: node.domain.clone(),
                weight,
            })
        }
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use simple_moving_average::SMA;

    use crate::{
        check::HealthCheckResult, node::Node, snapshot::Snapshot,
        snapshot_latency_based::MAX_LATENCY,
    };

    use super::{weighted_random_sampling, LatencyBasedSnapshot};

    #[test]
    fn test_snapshot_init() {
        // Arrange
        let snapshot = LatencyBasedSnapshot::new();
        // Check
        assert!(snapshot.weighted_nodes.is_empty());
        assert!(snapshot.existing_nodes.is_empty());
        assert!(!snapshot.has_healthy_nodes());
        assert!(snapshot.next().is_none());
    }

    #[test]
    fn test_update_node_health_for_non_existing_node_fails() {
        // Arrange
        let mut snapshot = LatencyBasedSnapshot::new();
        // Act
        let node = Node::new("api1.com");
        let health = HealthCheckResult {
            latency: Some(Duration::from_secs(1)),
        };
        let is_updated = snapshot
            .update_node_health(&node, health)
            .expect("node update failed");
        assert!(!is_updated);
        assert!(snapshot.weighted_nodes.is_empty());
    }

    #[test]
    fn test_update_node_health_for_existing_node_succeeds() {
        // Arrange
        let mut snapshot = LatencyBasedSnapshot::new();
        let node = Node::new("api1.com");
        let health = HealthCheckResult {
            latency: Some(Duration::from_secs(1)),
        };
        snapshot.existing_nodes.insert(node.domain.clone());
        // Act
        // First update
        let is_updated = snapshot
            .update_node_health(&node, health)
            .expect("node update failed");
        assert!(is_updated);
        assert!(snapshot.has_healthy_nodes());
        let weighted_node = snapshot.weighted_nodes.first().unwrap();
        assert_eq!(weighted_node.latency_mov_avg.get_average(), 1000.0);
        assert_eq!(weighted_node.weight, 0.001);
        assert_eq!(snapshot.next().unwrap().domain, node.domain);
        // Second update
        let health = HealthCheckResult {
            latency: Some(Duration::from_secs(2)),
        };
        let is_updated = snapshot
            .update_node_health(&node, health)
            .expect("node update failed");
        assert!(is_updated);
        let weighted_node = snapshot.weighted_nodes.first().unwrap();
        assert_eq!(weighted_node.latency_mov_avg.get_average(), 1500.0);
        assert_eq!(weighted_node.weight, 1.0 / 1500.0);
        assert_eq!(snapshot.next().unwrap().domain, node.domain);
        // Third update
        let health = HealthCheckResult {
            latency: Some(Duration::from_secs(3)),
        };
        let is_updated = snapshot
            .update_node_health(&node, health)
            .expect("node update failed");
        assert!(is_updated);
        let weighted_node = snapshot.weighted_nodes.first().unwrap();
        assert_eq!(weighted_node.latency_mov_avg.get_average(), 2000.0);
        assert_eq!(weighted_node.weight, 1.0 / 2000.0);
        assert_eq!(snapshot.next().unwrap().domain, node.domain);
        // Forth update with none
        let health = HealthCheckResult { latency: None };
        let is_updated = snapshot
            .update_node_health(&node, health)
            .expect("node update failed");
        assert!(is_updated);
        let weighted_node = snapshot.weighted_nodes.first().unwrap();
        assert_eq!(
            weighted_node.latency_mov_avg.get_average(),
            (MAX_LATENCY.as_millis() as f64 + 1000.0 + 2000.0 + 3000.0) / 4.0
        );
        assert_eq!(
            weighted_node.weight,
            4.0 / (MAX_LATENCY.as_millis() as f64 + 1000.0 + 2000.0 + 3000.0)
        );
        assert_eq!(snapshot.next().unwrap().domain, node.domain);
    }

    #[test]
    fn test_weighted_random_sampling() {
        // Case 1: empty array
        let arr: &[f64] = &[];
        let idx = weighted_random_sampling(arr, 0.5);
        assert_eq!(idx, None);
        // Case 2: single element in array
        let arr: &[f64] = &[1.0];
        let idx = weighted_random_sampling(arr, 0.0);
        assert_eq!(idx, Some(0));
        let idx = weighted_random_sampling(arr, 1.0);
        assert_eq!(idx, Some(0));
        let idx = weighted_random_sampling(arr, 1.5);
        assert_eq!(idx, None);
        // Case 3: two elements in array
        let arr: &[f64] = &[1.0, 2.0]; // prefixed_sum = [1.0, 3.0]
        let idx = weighted_random_sampling(arr, 0.33); // 0.3 * 3 < 1.0
        assert_eq!(idx, Some(0));
        let idx = weighted_random_sampling(arr, 0.35); // 0.35 * 3 > 1.0
        assert_eq!(idx, Some(1));
        // Case 4: four elements in array
        let arr: &[f64] = &[1.0, 2.0, 1.5, 2.5]; // prefixed_sum = [1.0, 3.0, 4.5, 7.0]
        let idx = weighted_random_sampling(arr, 0.14); // 0.14 * 7 < 1.0
        assert_eq!(idx, Some(0)); // probability 0.14
        let idx = weighted_random_sampling(arr, 0.15); // 0.15 * 7 > 1.0
        assert_eq!(idx, Some(1));
        let idx = weighted_random_sampling(arr, 0.42); // 0.42 * 7 < 3.0
        assert_eq!(idx, Some(1)); // probability 0.28
        let idx = weighted_random_sampling(arr, 0.43); // 0.43 * 7 > 3.0
        assert_eq!(idx, Some(2));
        let idx = weighted_random_sampling(arr, 0.64); // 0.64 * 7 < 4.5
        assert_eq!(idx, Some(2)); // probability 0.22
        let idx = weighted_random_sampling(arr, 0.65); // 0.65 * 7 > 4.5
        assert_eq!(idx, Some(3));
        let idx = weighted_random_sampling(arr, 0.99);
        assert_eq!(idx, Some(3)); // probability 0.35
        let idx = weighted_random_sampling(arr, 1.1);
        assert_eq!(idx, None);
    }
}
