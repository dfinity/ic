#[cfg(test)]
mod tests;

use ic_base_types::{NodeId, PrincipalId, RegistryVersion, SubnetId};
use ic_interfaces_registry::RegistryClient;
use ic_logger::ReplicaLogger;
use ic_metrics::MetricsRegistry;
use ic_registry_client_helpers::{
    node::{NodeRecord, NodeRegistry},
    subnet::SubnetRegistry,
};
use prometheus::{GaugeVec, IntCounter, IntGauge, Opts};
use rand::{Rng, thread_rng};
use std::{
    collections::BTreeMap,
    convert::TryFrom,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use super::{Error, get_node_operator_id};

/// Function that generates a random value in the range [`low`, `high`), i.e.
/// inclusive of `low` and exclusive of `high`
pub type GenRangeFn = Box<dyn Fn(u64, u64) -> u64 + Sync + Send>;

const NANOS_PER_SEC: u64 = 1_000_000_000;

/// How long a node is considered unhealthy after a failed request. It may be
/// tried again after this long, so a node that stays down costs one failed
/// request per TTL.
pub const UNHEALTHY_NODE_TTL: Duration = Duration::from_secs(10);

const METRIC_RTT_EMA: &str = "xnet_builder_rtt_ema_seconds";
const METRIC_UNKNOWN_DCOP: &str = "xnet_builder_unknown_dcop_total";
pub(crate) const METRIC_UNHEALTHY_NODES: &str = "xnet_builder_unhealthy_nodes";

const LABEL_FROM: &str = "from";
const LABEL_TO: &str = "to";

const OPERATOR_UNKNOWN: &str = "unknown";

/// Helper for probabilistically selecting a healthy node on a given subnet,
/// weighted by proximity.
///
/// Proximity is modeled as the exponential moving average (EMA) of roundtrip
/// time (RTT) per datacenter operator (under the assumption that all nodes
/// belonging to a datacenter operator are colocated). The probability of a
/// specific node on a given subnet being selected is inversely proportional to
/// the RTT EMA of its operator.
///
/// Node health is sourced from a shared `UnhealthyNodes` instance, and is based
/// on recent XNet query outcomes.
pub struct ProximityMap {
    /// Exponential moving averages (EMA) of roundtrip times by datacenter
    /// operator.
    roundtrip_ema_nanos: Mutex<BTreeMap<Vec<u8>, u64>>,

    /// Used for retrieving subnet node lists and node transport info.
    registry: Arc<dyn RegistryClient>,

    /// Tracks recently unhealthy nodes, based on recent XNet query outcomes.
    unhealthy_nodes: Arc<UnhealthyNodes>,

    /// Generates a random value in the range [`low`, `high`), i.e. inclusive of
    /// `low` and exclusive of `high`, to use for picking a replica.
    gen_range: GenRangeFn,

    /// Exported `roundtrip_ema_nanos` values.
    metric_rtt_ema: GaugeVec,

    /// Count of RTT observations where the operator could not be resolved.
    metric_unknown_dcop: IntCounter,

    log: ReplicaLogger,
}

impl ProximityMap {
    /// Creates a new `ProximityMap` for `node` using `thread_rng()` as RNG.
    pub fn new(
        node: NodeId,
        registry: Arc<dyn RegistryClient>,
        unhealthy_nodes: Arc<UnhealthyNodes>,
        metrics_registry: &MetricsRegistry,
        log: ReplicaLogger,
    ) -> ProximityMap {
        fn thread_rng_gen_range(low: u64, high: u64) -> u64 {
            thread_rng().gen_range(low..high)
        }

        Self::with_rng(
            Box::new(thread_rng_gen_range),
            node,
            registry,
            unhealthy_nodes,
            metrics_registry,
            log,
        )
    }

    /// Creates a new `ProximityMap` for `node` using the provided `gen_range`
    /// RNG.
    pub fn with_rng(
        gen_range: GenRangeFn,
        node: NodeId,
        registry: Arc<dyn RegistryClient>,
        unhealthy_nodes: Arc<UnhealthyNodes>,
        metrics_registry: &MetricsRegistry,
        log: ReplicaLogger,
    ) -> ProximityMap {
        // Retrieve own operator at latest registry version. This does not change while
        // the replica is running.
        let registry_version = registry.get_latest_version();
        let own_operator = get_node_operator_id(&node, registry.as_ref(), &registry_version, &log)
            .map_or_else(
                || OPERATOR_UNKNOWN.into(),
                |own_operator| node_operator_to_string(&own_operator),
            );
        let metric_rtt_ema = metrics_registry.register(GaugeVec::new(Opts::new(METRIC_RTT_EMA, "Exponential moving average of roundtrip time in seconds as measured by XNetPayloadBuilder, by source and destination DC operator.").const_label(LABEL_FROM, own_operator), &[LABEL_TO]).unwrap());
        let metric_unknown_dcop = metrics_registry.int_counter(
            METRIC_UNKNOWN_DCOP,
            "Number of times that DCOP could not be resolved while recording XNet RTT.",
        );

        Self {
            roundtrip_ema_nanos: Default::default(),
            registry,
            unhealthy_nodes,
            gen_range,
            metric_rtt_ema,
            metric_unknown_dcop,
            log,
        }
    }

    /// Picks a random node on `subnet` (as defined at registry version
    /// `version`) weighted by proximity (nodes belonging to operators with
    /// lower RTT are picked with higher probability). Unhealthy nodes are not
    /// picked, unless all of the subnet's nodes are unhealthy.
    ///
    /// E.g. given  mean RTTs of `[0.1s, 0.5s. 1s]` the computed weights
    /// (`[10_000, 2_000, 1_000]`) would result in cumulative weights `[10_000,
    /// 12_000, 13_000]`. We then use a random value in the `1..=13_000` range
    /// to select one of the nodes:
    ///
    ///  * a random value in the `1..=10_000` range will select the first node;
    ///  * a value in the `10_001..=12_000` range will select the second node;
    ///  * and a value in the `12_001..=13_000` range will result in selecting
    ///    the third node.
    pub fn pick_node(
        &self,
        subnet: SubnetId,
        version: RegistryVersion,
    ) -> Result<(NodeId, NodeRecord), Error> {
        // Retrieve `subnet`'s nodes, minus the unhealthy ones.
        let mut nodes = self
            .registry
            .get_node_ids_on_subnet(subnet, version)
            .map_err(|e| Error::RegistryGetSubnetInfoFailed(subnet, e))?
            .filter(|nodes| !nodes.is_empty())
            .ok_or(Error::MissingSubnet(subnet))?;
        self.unhealthy_nodes.filter_at_least(1, &mut nodes);

        // Compute the individual and total weight of all nodes with explicit weights
        // (nodes of operators for which we've recorded at least one roundtrip time).
        let mut node_weights = vec![0; nodes.len()];
        let mut total_weight = 0;
        let mut weighted_nodes = 0;
        for (i, node) in nodes.iter().enumerate() {
            if let Some(node_operator) =
                get_node_operator_id(node, self.registry.as_ref(), &version, &self.log)
                && let Some(node_weight) = self.weight(&node_operator)
            {
                node_weights[i] = node_weight;
                total_weight += node_weight;
                weighted_nodes += 1;
            }
        }

        // Mean weight to assign to nodes that we don't have explicit weights for.
        let mean_weight = total_weight.checked_div(weighted_nodes).unwrap_or(1);

        // Cumulative node weights, to be used for weighted random selection.
        let cumulative_weights: Vec<u64> = node_weights
            .into_iter()
            .map(|weight| if weight != 0 { weight } else { mean_weight })
            .scan(0, |accumulator, weight| {
                (*accumulator) += weight;
                Some(*accumulator)
            })
            .collect();
        let total_weight = *cumulative_weights.last().unwrap();

        // Pick a random node by weight.
        let node_index = cumulative_weights
            .binary_search(&(self.gen_range)(1, total_weight + 1))
            .unwrap_or_else(|e| e);

        let node = nodes[node_index];
        let node_record = self
            .registry
            .get_node_record(node, version)
            .map_err(|e| Error::RegistryGetNodeInfoFailed(node, e))?;

        match node_record {
            Some(node_record) => Ok((node, node_record)),
            None => Err(Error::MissingXNetEndpoint(node)),
        }
    }

    /// Updates the RTT EMA for the node operator of `node` with the newly
    /// observed `duration`.
    pub fn observe_roundtrip_time(&self, node: NodeId, duration: Duration) {
        // Bound durations to between 1µs and 1s (specifically avoiding 0).
        let duration_nanos = (duration.as_nanos() as u64).clamp(1_000, NANOS_PER_SEC);

        let version = self.registry.get_latest_version();
        if let Some(node_operator) =
            get_node_operator_id(&node, self.registry.as_ref(), &version, &self.log)
        {
            let metric_rtt_ema = self
                .metric_rtt_ema
                .with_label_values(&[&node_operator_to_string(&node_operator)]);

            let rtt_ema_nanos = *self
                .roundtrip_ema_nanos
                .lock()
                .unwrap()
                .entry(node_operator)
                .and_modify(|ema| *ema = (*ema * 9 + duration_nanos) / 10)
                .or_insert_with(|| duration_nanos);

            metric_rtt_ema.set(rtt_ema_nanos as f64 * 1e-9);
        } else {
            self.metric_unknown_dcop.inc();
        }
    }

    /// Computes the weight of nodes operated by `node_operator`.
    ///
    /// Weight should be inversely proportional to the RTT EMA, so it is
    /// computed as `1_000 / rtt_ema`, where `rtt_ema` is the exponential
    /// moving average of roundtrip times to `node_operator`. With the EMA
    /// guaranteed to be between 1µs and 1s, the returned weight will be between
    /// `1_000` and `1_000_000_000`.
    fn weight(&self, node_operator: &[u8]) -> Option<u64> {
        self.roundtrip_ema_nanos
            .lock()
            .unwrap()
            .get(node_operator)
            .map(|ema_nanos| 1_000 * NANOS_PER_SEC / ema_nanos)
    }
}

/// The set of nodes whose last request failed, with entries expiring after a
/// TTL.
///
/// Populated by `XNetClient`; consulted by whoever selects such nodes, so that
/// a node that is not serving requests is skipped instead of being picked again
/// and again.
///
/// Entries are keyed by `NodeId` alone; the per-subnet semantics of
/// `filter_at_least()` come from the node list it is given.
pub struct UnhealthyNodes {
    /// Expiry times of the entries.
    nodes: Mutex<BTreeMap<NodeId, Instant>>,

    /// How long a node is considered unhealthy after a failed request.
    ttl: Duration,

    /// Exported number of unhealthy nodes.
    metric_unhealthy_nodes: IntGauge,
}

impl UnhealthyNodes {
    pub fn new(ttl: Duration, metrics_registry: &MetricsRegistry) -> Self {
        Self {
            nodes: Default::default(),
            ttl,
            metric_unhealthy_nodes: metrics_registry.int_gauge(
                METRIC_UNHEALTHY_NODES,
                "Number of unhealthy XNet nodes, i.e. nodes whose last XNet request failed within the unhealthy node TTL.",
            ),
        }
    }

    /// Records a failed request to `node`.
    pub fn observe_failure(&self, node: NodeId) {
        let mut nodes = self.nodes.lock().unwrap();
        nodes.insert(node, Instant::now() + self.ttl);
        self.prune(&mut nodes);
    }

    /// Records a successful request to `node`.
    pub fn observe_success(&self, node: NodeId) {
        let mut nodes = self.nodes.lock().unwrap();
        nodes.remove(&node);
        self.prune(&mut nodes);
    }

    /// Drops the unhealthy nodes from `nodes`, as long as at least `minimum`
    /// remain; else leaves `nodes` as it is. So that a subnet-wide endpoint
    /// problem or a local network fault cannot leave the caller with too few
    /// nodes to choose from -- or none at all.
    pub fn filter_at_least(&self, minimum: usize, nodes: &mut Vec<NodeId>) {
        let mut unhealthy = self.nodes.lock().unwrap();
        self.prune(&mut unhealthy);

        let is_healthy = |node: &NodeId| !unhealthy.contains_key(node);
        if nodes
            .iter()
            .filter(|node| is_healthy(node))
            .take(minimum)
            .count()
            < minimum
        {
            return;
        }
        nodes.retain(is_healthy);
    }

    /// Drops the expired entries and updates the metric.
    fn prune(&self, nodes: &mut BTreeMap<NodeId, Instant>) {
        let now = Instant::now();
        nodes.retain(|_, expiry| *expiry > now);
        self.metric_unhealthy_nodes.set(nodes.len() as i64);
    }
}

/// Returns the string representation of `node_operator` as `PrincipalId`; or
/// `"unknown"` if the conversion to `PrincipalId` fails.
fn node_operator_to_string(node_operator: &[u8]) -> String {
    PrincipalId::try_from(node_operator).ok().map_or_else(
        || OPERATOR_UNKNOWN.into(),
        |node_operator| node_operator.to_string(),
    )
}
