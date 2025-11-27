//! Peer Manager
//!
//! The peer manager component periodically checks the registry
//! and determines the subnet membership according to the latest
//! registry version and the version currently used by consensus.
//!
//! The subnet membership is made available as shared state via a tokio watcher.
//!
//! The component runs in a background task and should be started only once.
//! If multiple components require the shared state (i.e. the subnet membership)
//! the returned receiver should be cloned.
//!
use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use ic_base_types::{RegistryVersion, SubnetId};
use ic_interfaces::consensus_pool::ConsensusPoolCache;
use ic_interfaces_registry::RegistryClient;
use ic_logger::{ReplicaLogger, warn};
use ic_metrics::MetricsRegistry;
use ic_quic_transport::SubnetTopology;
use ic_registry_client_helpers::subnet::SubnetTransportRegistry;
use metrics::PeerManagerMetrics;
use tokio::{
    runtime::Handle,
    sync::watch::{Receiver, channel},
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
            self.metrics
                .earliest_registry_version
                .set(topology.earliest_registry_version().get() as i64);
            self.metrics
                .latest_registry_version
                .set(topology.latest_registry_version().get() as i64);
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

        let mut subnet_nodes = HashMap::new();

        // Iterate from `min(consensus_registry_version, latest_local_registry_version)` to
        // `latest_local_registry_version`.
        // The `consensus_registry_version` is extracted from the latest CUP seen.
        // The `latest_local_registry_version` is the latest registry version known to this node.
        // In almost any case `latest_local_registry_version >= consensus_registry_version` but
        // there may exist cases where this condition does not hold.
        // In that case we should at least include our latest local view of the subnet.
        let latest_local_registry_version = self.registry_client.get_latest_version();
        let consensus_registry_version = self
            .consensus_pool_cache
            .get_oldest_registry_version_in_use();
        let earliest_registry_version =
            consensus_registry_version.min(latest_local_registry_version);

        for version in earliest_registry_version.get()..=latest_local_registry_version.get() {
            let version = RegistryVersion::from(version);

            let transport_info = match self
                .registry_client
                .get_subnet_node_records(self.subnet_id, version)
            {
                Ok(Some(transport_info)) => transport_info,
                Ok(None) => {
                    warn!(
                        self.log,
                        "Got transport infos but it's empty. Registry version {version}"
                    );
                    self.metrics
                        .topology_watcher_errors
                        .with_label_values(&["empty_list_of_node_records"])
                        .inc();

                    Vec::new()
                }
                Err(err) => {
                    warn!(
                        self.log,
                        "Failed to get node record from registry at version {version}: {err}"
                    );
                    self.metrics
                        .topology_watcher_errors
                        .with_label_values(&["error_getting_node_records"])
                        .inc();

                    Vec::new()
                }
            };

            for (peer_id, info) in transport_info {
                match info.http {
                    Some(endpoint) => {
                        match endpoint.ip_addr.parse::<IpAddr>() {
                            Ok(ip_addr) => {
                                // Insert even if already present because we prefer to have the
                                // value with the highest registry version.
                                subnet_nodes.insert(peer_id, SocketAddr::new(ip_addr, 4100));
                            }
                            Err(err) => {
                                warn!(
                                    self.log,
                                    "Failed to parse Ip addr {} for peer {peer_id} \
                                    at registry version {version}: {err}",
                                    endpoint.ip_addr,
                                );
                                self.metrics
                                    .topology_watcher_errors
                                    .with_label_values(&["error_parsing_ip_address"])
                                    .inc();
                            }
                        };
                    }
                    None => {
                        warn!(
                            self.log,
                            "Failed to get flow endpoint for peer {peer_id} \
                            at registry version {version}",
                        );
                        self.metrics
                            .topology_watcher_errors
                            .with_label_values(&["http_field_missing"])
                            .inc();
                    }
                }
            }
        }

        SubnetTopology::new(
            subnet_nodes,
            earliest_registry_version,
            latest_local_registry_version,
        )
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use ic_base_types::NodeId;
    use ic_interfaces_mocks::consensus_pool::MockConsensusPoolCache;
    use ic_logger::no_op_logger;
    use ic_registry_client_fake::FakeRegistryClient;
    use ic_registry_client_helpers::node::{ConnectionEndpoint, NodeRecord};
    use ic_registry_keys::make_node_record_key;
    use ic_registry_proto_data_provider::ProtoRegistryDataProvider;
    use ic_test_utilities_registry::{SubnetRecordBuilder, add_single_subnet_record};
    use ic_types_test_utils::ids::{NODE_1, NODE_2, NODE_3, NODE_4, SUBNET_0};

    use super::*;

    fn set_up_peer_manager(
        consensus_registry_version: RegistryVersion,
        membership_over_time: Vec<(RegistryVersion, Vec<NodeId>)>,
    ) -> PeerManager {
        let mut mock_consensus_pool = MockConsensusPoolCache::new();
        mock_consensus_pool
            .expect_get_oldest_registry_version_in_use()
            .return_const(consensus_registry_version);

        let data_provider = Arc::new(ProtoRegistryDataProvider::new());

        for (registry_version, nodes) in membership_over_time {
            add_single_subnet_record(
                &data_provider,
                registry_version.get(),
                SUBNET_0,
                SubnetRecordBuilder::new()
                    .with_committee(nodes.as_slice())
                    .build(),
            );

            for node in nodes {
                let node_record = NodeRecord {
                    http: Some(ConnectionEndpoint {
                        ip_addr: String::from("127.0.0.1"),
                        port: 8080,
                    }),
                    ..Default::default()
                };

                data_provider
                    .add(
                        &make_node_record_key(node),
                        registry_version,
                        Some(node_record),
                    )
                    .unwrap();
            }
        }

        let registry_client = Arc::new(FakeRegistryClient::new(data_provider));
        registry_client.update_to_latest_version();

        let (tx, _rx) = channel(SubnetTopology::default());
        PeerManager {
            log: no_op_logger(),
            metrics: PeerManagerMetrics::new(&MetricsRegistry::new()),
            subnet_id: SUBNET_0,
            registry_client,
            consensus_pool_cache: Arc::new(mock_consensus_pool),
            topology_sender: tx,
        }
    }

    #[test]
    fn ignores_too_old_registry_versions_test() {
        const CONSENSUS_REGISTRY_VERSION: RegistryVersion = RegistryVersion::new(10);
        let peer_manager = set_up_peer_manager(
            CONSENSUS_REGISTRY_VERSION,
            vec![
                (RegistryVersion::new(9), vec![NODE_1, NODE_2]),
                (RegistryVersion::new(10), vec![NODE_2, NODE_3]),
                (RegistryVersion::new(11), vec![NODE_3, NODE_4]),
            ],
        );

        let topology = peer_manager.get_latest_subnet_topology();

        assert_eq!(
            topology.earliest_registry_version(),
            CONSENSUS_REGISTRY_VERSION,
        );
        assert_eq!(topology.latest_registry_version(), RegistryVersion::new(11));
        assert_eq!(
            topology.get_subnet_nodes(),
            BTreeSet::from_iter([NODE_2, NODE_3, NODE_4])
        );
    }

    #[test]
    fn ignores_too_new_consensus_registry_version_test() {
        const CONSENSUS_REGISTRY_VERSION: RegistryVersion = RegistryVersion::new(12);
        let peer_manager = set_up_peer_manager(
            CONSENSUS_REGISTRY_VERSION,
            vec![
                (RegistryVersion::new(9), vec![NODE_1, NODE_2]),
                (RegistryVersion::new(10), vec![NODE_2, NODE_3]),
                (RegistryVersion::new(11), vec![NODE_3, NODE_4]),
            ],
        );

        let topology = peer_manager.get_latest_subnet_topology();

        assert_eq!(
            topology.earliest_registry_version(),
            RegistryVersion::new(11)
        );
        assert_eq!(topology.latest_registry_version(), RegistryVersion::new(11));
        assert_eq!(
            topology.get_subnet_nodes(),
            BTreeSet::from_iter([NODE_3, NODE_4])
        );
    }
}
