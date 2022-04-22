#![allow(dead_code)]

use super::types::*;
use ic_logger::trace;
use rand::seq::SliceRandom;
use rand::Rng;
use std::time::Duration;

fn get_instance_with_least_outgoing_message_timestamp<'a, 'b>(
    instances: &'b [ConsensusInstance<'a>],
) -> Option<&'b ConsensusInstance<'a>> {
    instances.iter().min_by(|i, j| {
        let t_i = i.out_queue.borrow().peek().map(|x| x.timestamp);
        let t_j = j.out_queue.borrow().peek().map(|x| x.timestamp);
        compare_timestamp(t_i, t_j)
    })
}

/// Pick the next message that has the least timestamp(m_out(i)) value among all
/// nodes, and always set receiving timestamp to be 1 unit greater than this
/// timestamp. It ensures globally that messages are always received in the
/// order they are sent.
#[derive(Debug)]
pub struct Sequential;

impl Sequential {
    pub fn new() -> Box<Sequential> {
        Box::new(Sequential)
    }
}

impl DeliveryStrategy for Sequential {
    fn deliver_next(&self, runner: &dyn ConsensusInstances<'_>) -> bool {
        let logger = runner.logger();
        let instances = runner.instances();
        if let Some(instance) = get_instance_with_least_outgoing_message_timestamp(instances) {
            if let Some(x) = instance.out_queue.borrow_mut().pop() {
                let time_step = Duration::from_millis(UNIT_TIME_STEP);
                let timestamp = x.timestamp + time_step;
                let msg = Message {
                    message: x.message,
                    timestamp,
                };
                for other in instances.iter() {
                    if other.deps.replica_config.node_id != instance.deps.replica_config.node_id {
                        trace!(
                            logger,
                            "Deliver from instance {} to {}: {:?}",
                            instance.deps.replica_config.node_id,
                            other.deps.replica_config.node_id,
                            msg,
                        );
                        let mut in_queue = other.in_queue.borrow_mut();
                        in_queue.push(Input::Message(msg.clone()));
                    }
                }
                return true;
            }
        }
        false
    }
}

/// Pick the next message that has the least timestamp(m_out(i)) value among all
/// nodes, and set the receiving timestamp randomly.  It does not ensure that
/// messages are received in the order they are sent.
#[derive(Debug)]
pub struct RandomReceive {
    /// The max time lapse in milliseconds before a message reaches all nodes.
    max_delta: u64,
}

impl RandomReceive {
    pub fn new(max_delta: u64) -> Box<RandomReceive> {
        Box::new(RandomReceive { max_delta })
    }
}

impl DeliveryStrategy for RandomReceive {
    fn deliver_next(&self, runner: &dyn ConsensusInstances<'_>) -> bool {
        let logger = runner.logger();
        let instances = runner.instances();
        if let Some(instance) = get_instance_with_least_outgoing_message_timestamp(instances) {
            if let Some(x) = instance.out_queue.borrow_mut().pop() {
                let mut rng = runner.rng();
                for other in instances.iter() {
                    if other.deps.replica_config.node_id != instance.deps.replica_config.node_id {
                        let mut in_queue = other.in_queue.borrow_mut();
                        let delay = rng.gen_range(UNIT_TIME_STEP, self.max_delta);
                        let msg = Message {
                            message: x.message.clone(),
                            timestamp: x.timestamp + Duration::from_millis(delay),
                        };
                        trace!(
                            logger,
                            "Deliver from instance {} to {}: {:?}",
                            instance.deps.replica_config.node_id,
                            other.deps.replica_config.node_id,
                            msg,
                        );
                        in_queue.push(Input::Message(msg));
                    }
                }
                return true;
            }
        }
        false
    }
}

/// Implement a random graph topology and message latency is determined by the
/// distance between two nodes.
#[derive(Debug)]
pub struct RandomGraph {
    degree: usize,
    unit_latency: Duration,
    distances: Vec<Vec<usize>>,
}

impl DeliveryStrategy for RandomGraph {
    fn deliver_next(&self, runner: &dyn ConsensusInstances<'_>) -> bool {
        let logger = runner.logger();
        let instances = runner.instances();
        if let Some(instance) = get_instance_with_least_outgoing_message_timestamp(instances) {
            if let Some(x) = instance.out_queue.borrow_mut().pop() {
                for other in instances.iter() {
                    if other.deps.replica_config.node_id != instance.deps.replica_config.node_id {
                        let mut in_queue = other.in_queue.borrow_mut();
                        let delay =
                            self.distances[instance.index][other.index] as u32 * self.unit_latency;
                        let msg = Message {
                            message: x.message.clone(),
                            timestamp: x.timestamp + delay,
                        };
                        trace!(
                            logger,
                            "Deliver from instance {} to {}: {:?}",
                            instance.deps.replica_config.node_id,
                            other.deps.replica_config.node_id,
                            msg,
                        );
                        in_queue.push(Input::Message(msg));
                    }
                }
                return true;
            }
        }
        false
    }
}

impl RandomGraph {
    /// Create a new RandomGraph object using the given randomness generator.
    /// It will panic if there are repeated failures in creating connected graph
    /// due to
    pub fn new<T: Rng>(num_nodes: usize, degree: usize, max_delta: u64, rng: &mut T) -> Box<Self> {
        assert!(degree < num_nodes);
        let mut tries = 0;
        loop {
            let mut distances = random_graph(num_nodes, degree, rng);
            if let Some(max_distance) = distance_vector(&mut distances) {
                let unit_latency =
                    Duration::from_millis(max_delta / (1 + std::cmp::max(1, max_distance)) as u64);
                return Box::new(RandomGraph {
                    degree,
                    unit_latency,
                    distances,
                });
            }
            tries += 1;
            assert!(
                tries < 10,
                "Insufficient degree {} for {} nodes",
                degree,
                num_nodes
            );
        }
    }
}

/// Return a random graph of given num_nodes, and of a fixed degree.
/// The graph is represented as NxN matrix, where cell value is 0 for all (i, i)
/// pairs, 1 for all connected (i, j) pairs, or `num_nodes` for disconnected
/// pairs (since the max distance between any pair of nodes should be less than
/// num_nodes).
#[allow(clippy::needless_range_loop)]
fn random_graph<T: Rng>(num_nodes: usize, degree: usize, rng: &mut T) -> Vec<Vec<usize>> {
    let mut distances = vec![vec![num_nodes; num_nodes]; num_nodes];
    for i in 0..num_nodes {
        distances[i][i] = 0;
        let mut indices: Vec<_> = (0..num_nodes).collect();
        indices.remove(i);
        indices.shuffle(rng);
        for j in 0..degree {
            distances[i][indices[j]] = 1;
        }
    }
    distances
}

/// Floyd–Warshall algorithm that computes the distance between all pairs of
/// nodes. Return max distance (or diameter) if successful, or None otherwise.
fn distance_vector(distances: &mut [Vec<usize>]) -> Option<usize> {
    let n = distances.len();
    for k in 0..n {
        for i in 0..n {
            for j in 0..n {
                let distance = distances[i][k] + distances[k][j];
                if distance < distances[i][j] {
                    distances[i][j] = distance;
                }
            }
        }
    }
    let max_distance = distances
        .iter()
        .fold(0, |max, v| std::cmp::max(max, *v.iter().max().unwrap()));
    let connected = distances.iter().all(|v| v.iter().all(|x| *x < n));
    if connected {
        Some(max_distance)
    } else {
        None
    }
}

#[allow(clippy::needless_range_loop)]
#[cfg(test)]
mod test {
    use super::*;
    use rand::thread_rng;
    use rand_chacha::{rand_core::SeedableRng, ChaChaRng};

    fn check_distance(graph: &[Vec<usize>], degree: usize) {
        let n = graph.len();
        for i in 0..n {
            assert_eq!(graph[i].len(), n);
            // distance to self is always 0
            assert_eq!(graph[i][i], 0);
            // only distance to self is 0
            assert_eq!(1, graph[i].iter().filter(|x| **x == 0).count());
            // unit-distance connections matches degree
            assert_eq!(degree, graph[i].iter().filter(|x| **x == 1).count())
        }
    }

    #[test]
    fn test_random_graph() {
        let mut rng = thread_rng();
        let n = 10;
        let degree = 5;
        let graph = random_graph(n, degree, &mut rng);
        check_distance(&graph, degree);
    }

    #[test]
    fn test_distance_vector() {
        let mut rng = thread_rng();
        let n = 10;
        let degree = 5;
        let mut tries = 0;
        loop {
            let mut graph = random_graph(n, degree, &mut rng);
            if distance_vector(&mut graph).is_some() {
                check_distance(&graph, degree);
                break;
            }
            tries += 1;
            assert!(tries < 10);
        }
    }

    #[test]
    fn test_random_graph_one_node() {
        let mut rng = thread_rng();
        let n = 1;
        let degree = 0;
        let mut graph = random_graph(n, degree, &mut rng);
        assert!(distance_vector(&mut graph).is_some());
        check_distance(&graph, degree);
    }

    #[test]
    fn test_insufficient_degree() {
        // Use a fixed seeded RNG to avoid false positives.
        let mut rng = ChaChaRng::seed_from_u64(0);
        let n = 30;
        let degree = 2;
        let mut graph = random_graph(n, degree, &mut rng);
        assert!(distance_vector(&mut graph).is_none());
    }
}
