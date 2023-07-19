//! Peer Manager
//!
//! The peer manager component periodically checks the registry
//! and determines the subnet membership according to the latest
//! registry version and the version currently used by consensus.
//!
//! The subnet memebership is made available as shared state via a tokio watcher.
//!
//! The compoment runs in a background task and should be started only once.
//! If mutiple components require the shared state (i.e. the subnet membership)
//! the returned receiver should be cloned.
//!
use std::{
    collections::{BTreeSet, HashMap},
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use ic_interfaces::consensus_pool::ConsensusPoolCache;
use ic_interfaces_registry::RegistryClient;
use ic_logger::{warn, ReplicaLogger};
use ic_metrics::MetricsRegistry;
use ic_registry_client_helpers::subnet::SubnetTransportRegistry;
use ic_types::{NodeId, RegistryVersion, SubnetId};
use metrics::PeerManagerMetrics;
use tokio::{
    runtime::Handle,
    sync::watch::{channel, Receiver},
    task::JoinHandle,
};

const TOPOLOGY_UPDATE_INTERVAL: Duration = Duration::from_secs(3);

mod metrics;

/// Starts a background task that publishes the most
/// recent `SubnetTopology` for the given `subnet_id` into a watch channel.
pub fn start_peer_manager(
    log: ReplicaLogger,
    metrics_registry: &MetricsRegistry,
    rt: &Handle,
    subnet_id: SubnetId,
    consensus_pool_cache: Arc<dyn ConsensusPoolCache>,
    registry_client: Arc<dyn RegistryClient>,
) -> (JoinHandle<()>, Receiver<SubnetTopology>) {
    // Init with empty subnet membership.
    let (tx, rx) = channel(SubnetTopology::default());
    let metrics = PeerManagerMetrics::new(metrics_registry);

    let peer_manager = PeerManager {
        log,
        metrics,
        subnet_id,
        registry_client,
        consensus_pool_cache,
        topology_sender: tx,
    };

    (rt.spawn(peer_manager.run()), rx)
}

struct PeerManager {
    log: ReplicaLogger,
    metrics: PeerManagerMetrics,
    subnet_id: SubnetId,

    // Used to determine topology
    registry_client: Arc<dyn RegistryClient>,
    consensus_pool_cache: Arc<dyn ConsensusPoolCache>,

    // Shared state
    topology_sender: tokio::sync::watch::Sender<SubnetTopology>,
}

impl PeerManager {
    async fn run(self) {
        let mut interval = tokio::time::interval(TOPOLOGY_UPDATE_INTERVAL);
        loop {
            let _ = interval.tick().await;
            self.metrics.topology_updates.inc();

            let mut topology = self.get_latest_subnet_topology();
            let _timer = self.metrics.topology_watcher_update_duration.start_timer();
            // Notify watchers of latest shared state iff the latest topology is different to the old one.
            self.topology_sender
                .send_if_modified(move |old_topology: &mut SubnetTopology| {
                    if old_topology == &topology {
                        false
                    } else {
                        std::mem::swap(old_topology, &mut topology);
                        true
                    }
                });
        }
    }

    /// Get all nodes that are relevant for this subnet according to subnet membership.
    fn get_latest_subnet_topology(&self) -> SubnetTopology {
        let _timer = self.metrics.topology_update_duration.start_timer();

        let curr_registry_version = self.registry_client.get_latest_version();
        let consensus_registry_version = self
            .consensus_pool_cache
            .get_oldest_registry_version_in_use();
        let mut subnet_nodes = HashMap::new();

        // Iterate from min(consensus_registry_version,latest_local_registry_version) to max(consensus_registry_version,latest_local_registry_version).
        // The `consensus_registry_version` is extracted from the latest CUP seen.
        // The `latest_local_registry_version` is the latest registry version known to this node.
        // In almost any case `latest_local_registry_version >= consensus_registry_version` but there may exist cases where this condition does not hold.
        // In that case we should at least include our latest local view of the subnet.
        let earliest_registry_version = consensus_registry_version.min(curr_registry_version);
        let latest_registry_version = consensus_registry_version.max(curr_registry_version);
        for version in earliest_registry_version.get()..=latest_registry_version.get() {
            let version = RegistryVersion::from(version);

            let transport_info = match self
                .registry_client
                .get_subnet_transport_infos(self.subnet_id, version)
            {
                Ok(Some(transport_info)) => transport_info,
                Ok(None) => {
                    warn!(
                        self.log,
                        "Got transport infos but is empty. version {}", version
                    );
                    Vec::new()
                }
                Err(e) => {
                    warn!(
                        self.log,
                        "Failed to get transport information from registry at version {} : {}",
                        version,
                        e
                    );
                    Vec::new()
                }
            };

            for (peer_id, info) in transport_info {
                let maybe_endpoint = info
                    .p2p_flow_endpoints
                    .get(0)
                    .and_then(|flow_endpoint| flow_endpoint.endpoint.as_ref());

                match maybe_endpoint {
                    Some(flow_endpoint) => {
                        if let Ok(ip_addr) = flow_endpoint.ip_addr.parse::<IpAddr>() {
                            // Insert even if already present because we prefer to have the value
                            // with the highest registry version.
                            subnet_nodes.insert(
                                peer_id,
                                SocketAddr::new(ip_addr, flow_endpoint.port as u16),
                            );
                        } else {
                            warn!(
                                self.log,
                                "Failed to get parse Ip addr {} for peer {} at registry version {}",
                                flow_endpoint.ip_addr,
                                peer_id,
                                version
                            );
                        }
                    }
                    None => {
                        warn!(
                            self.log,
                            "Failed to get flow endpoint for peer {} at registry version {}",
                            peer_id,
                            version
                        );
                    }
                }
            }
        }
        SubnetTopology {
            subnet_nodes,
            earliest_registry_version,
            latest_registry_version,
        }
    }
}

/// Holds socket addresses of all peers in a subnet.
#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub struct SubnetTopology {
    subnet_nodes: HashMap<NodeId, SocketAddr>,
    earliest_registry_version: RegistryVersion,
    latest_registry_version: RegistryVersion,
}

impl SubnetTopology {
    pub fn new<T: IntoIterator<Item = (NodeId, SocketAddr)>>(subnet_nodes: T) -> Self {
        Self {
            subnet_nodes: HashMap::from_iter(subnet_nodes),
            ..Default::default()
        }
    }

    pub fn iter(&self) -> impl Iterator<Item = (&NodeId, &SocketAddr)> {
        self.subnet_nodes.iter()
    }

    pub fn is_member(&self, node: &NodeId) -> bool {
        self.subnet_nodes.contains_key(node)
    }

    pub fn get_addr(&self, node: &NodeId) -> Option<SocketAddr> {
        self.subnet_nodes.get(node).copied()
    }

    pub fn latest_registry_version(&self) -> RegistryVersion {
        self.latest_registry_version
    }

    pub fn earliest_registry_version(&self) -> RegistryVersion {
        self.earliest_registry_version
    }

    pub fn get_subnet_nodes(&self) -> BTreeSet<NodeId> {
        self.subnet_nodes.keys().copied().collect()
    }
}
