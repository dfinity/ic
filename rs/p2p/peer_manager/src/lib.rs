//! Peer Manager
//!
//! The peer manager component periodically checks the registry
//! and determines the subnet membership according to the latest
//! registry version and the version currently used by consensus.
//! The subnet memebership is made available as shared state in a tokio watcher.
//! Components that want to use the shared state should clone the returned receiver.
//! It is expected that there exists a 1-n relationship for the peer manager.
use std::{
    collections::{BTreeSet, HashMap},
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use ic_interfaces::consensus_pool::ConsensusPoolCache;
use ic_interfaces_registry::RegistryClient;
use ic_logger::{error, ReplicaLogger};
use ic_metrics::MetricsRegistry;
use ic_registry_client_helpers::subnet::{SubnetRegistry, SubnetTransportRegistry};
use ic_types::{registry::RegistryClientError, NodeId, RegistryVersion, SubnetId};
use metrics::PeerManagerMetrics;
use tokio::{
    runtime::Handle,
    sync::watch::{channel, Receiver},
    task::JoinHandle,
};

const TOPOLOGY_UPDATE_INTERVAL: Duration = Duration::from_secs(3);

mod metrics;

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

            match self.get_latest_subnet_topology() {
                Ok(ref mut topology) => {
                    let timer = self.metrics.topology_wachter_update_duration.start_timer();
                    // Update shared state with new topology. Only notify wachters if state actually changed.
                    self.topology_sender.send_if_modified(
                        move |old_topology: &mut SubnetTopology| {
                            if old_topology == topology {
                                false
                            } else {
                                std::mem::swap(old_topology, topology);
                                true
                            }
                        },
                    );
                    drop(timer)
                }
                Err(e) => {
                    self.metrics.topology_update_errors.inc();
                    error!(self.log, "Failed to update local subnet topology: {}", e);
                }
            }
        }
    }

    /// Get all nodes that are relevant for this subnet according to subnet memebership.
    fn get_latest_subnet_topology(&self) -> Result<SubnetTopology, SubnetTopologyError> {
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
            let nodes_at_version = self
                .registry_client
                .get_node_ids_on_subnet(self.subnet_id, version)
                .map_err(|e| SubnetTopologyError::RegistryError {
                    operation: "transport_infos".to_string(),
                    source: e,
                })?
                .ok_or(SubnetTopologyError::RegistryFieldEmpty {
                    field: "connection_endpoint".to_string(),
                })?;

            let transport_info = self
                .registry_client
                .get_subnet_transport_infos(self.subnet_id, version)
                .map_err(|e| SubnetTopologyError::RegistryError {
                    operation: "transport_infos".to_string(),
                    source: e,
                })?
                .ok_or(SubnetTopologyError::RegistryFieldEmpty {
                    field: "transport_infos".to_string(),
                })?;
            for node in nodes_at_version {
                let flow_endpoint = transport_info
                    .iter()
                    .find(|&n| n.0 == node)
                    .ok_or(SubnetTopologyError::RegistryFieldEmpty {
                        field: "node_transport_info".to_string(),
                    })?
                    .1
                    .p2p_flow_endpoints
                    .get(0)
                    .ok_or(SubnetTopologyError::RegistryFieldEmpty {
                        field: "flow_endpoints".to_string(),
                    })?
                    .endpoint
                    .as_ref()
                    .ok_or(SubnetTopologyError::RegistryFieldEmpty {
                        field: "connection_endpoint".to_string(),
                    })?;
                let ip_addr = flow_endpoint.ip_addr.parse::<IpAddr>().map_err(|e| {
                    SubnetTopologyError::ParseError {
                        field: "flow_endpoint_ip_addr".to_string(),
                        reason: e.to_string(),
                    }
                })?;
                // Insert even if already present because we prefer to have the value
                // with the highest registry version.
                subnet_nodes.insert(node, SocketAddr::new(ip_addr, flow_endpoint.port as u16));
            }
        }
        Ok(SubnetTopology {
            subnet_nodes,
            earliest_registry_version,
            latest_registry_version,
        })
    }
}

/// Hold P2P endpoint addresses of all peers in the subnet of this node.
/// Note: The subnet nodes stored includes this node.
#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub struct SubnetTopology {
    subnet_nodes: HashMap<NodeId, SocketAddr>,
    earliest_registry_version: RegistryVersion,
    latest_registry_version: RegistryVersion,
}

impl SubnetTopology {
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

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
enum SubnetTopologyError {
    RegistryError {
        operation: String,
        source: RegistryClientError,
    },
    RegistryFieldEmpty {
        field: String,
    },
    ParseError {
        field: String,
        reason: String,
    },
}

impl std::fmt::Display for SubnetTopologyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RegistryError { operation, source } => {
                write!(f, "failed fetch {operation} from registry: {source}",)
            }
            Self::RegistryFieldEmpty { field } => {
                write!(f, "registry field {field} was unexpectetly empty")
            }
            Self::ParseError { field, reason } => {
                write!(f, "Failed to parse registry field {field}: {reason}")
            }
        }
    }
}
