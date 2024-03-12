//! The module is responsible for watching for topology changes by polling the registry.
//! If nodes are added or removed from the subnet of the current node, then the appropriate
//! 'add_peer' and 'remove_peer' calls are executed.

use crate::gossip_protocol::GossipImpl;
use ic_logger::error;
use ic_protobuf::registry::node::v1::NodeRecord;
use ic_registry_client_helpers::subnet::SubnetTransportRegistry;
use ic_types::{NodeId, RegistryVersion};
use std::{
    collections::BTreeMap,
    net::{IpAddr, SocketAddr},
    str::FromStr,
};

impl GossipImpl {
    // Update the peer manager state based on the latest registry value.
    pub(crate) fn refresh_topology(&self) {
        let latest_registry_version = self.registry_client.get_latest_version();
        let earliest_registry_version = self
            .consensus_pool_cache
            .get_oldest_registry_version_in_use();
        self.metrics
            .registry_version_used
            .set(latest_registry_version.get() as i64);

        let subnet_nodes = self.merge_subnet_membership(latest_registry_version);
        let self_not_in_subnet = !subnet_nodes.contains_key(&self.node_id);

        // If a peer is not in the nodes within this subnet, remove.
        // If self is not in the subnet, remove all peers.
        for peer_id in self.get_current_peer_ids().iter() {
            if !subnet_nodes.contains_key(peer_id) || self_not_in_subnet {
                self.remove_peer(peer_id);
            }
        }
        // If self is not subnet, exit early to avoid adding nodes to the list of peers.
        if self_not_in_subnet {
            return;
        }
        // Add in nodes to peer manager.
        for (node_id, node_record) in subnet_nodes.iter() {
            match get_peer_addr(node_record) {
                None => {
                    // Invalid socket addresses should not be pushed in the registry/config on first place.
                    error!(self.log, "Invalid socket addr: node_id = {:?}", *node_id);
                    // If getting the peer socket fails, remove the node. This removal makes it possible
                    // to attempt a re-addition on the next refresh cycle.
                    self.remove_peer(node_id)
                }
                Some(peer_addr) => self.add_peer(
                    *node_id,
                    peer_addr,
                    latest_registry_version,
                    earliest_registry_version,
                ),
            }
        }
    }

    // Merge node records from subnet_membership_version (provided by consensus)
    // to latest_registry_version. This returns the current subnet membership set.
    fn merge_subnet_membership(
        &self,
        latest_registry_version: RegistryVersion,
    ) -> BTreeMap<NodeId, NodeRecord> {
        let subnet_membership_version = self
            .consensus_pool_cache
            .get_oldest_registry_version_in_use();
        let mut subnet_nodes = BTreeMap::new();
        // Iterate from min(consensus_registry_version,latest_local_registry_version) to max(consensus_registry_version,latest_local_registry_version).
        // The `consensus_registry_version` is extracted from the latest CUP seen.
        // The `latest_local_registry_version` is the latest registry version known to this node.
        // In almost any case `latest_local_registry_version >= consensus_registry_version` but there may exist cases where this condition does not hold.
        // In that case we should at least include our latest local view of the subnet.
        for version in subnet_membership_version
            .get()
            .min(latest_registry_version.get())
            ..=subnet_membership_version
                .get()
                .max(latest_registry_version.get())
        {
            let version = RegistryVersion::from(version);
            let node_records = self
                .registry_client
                .get_subnet_node_records(self.subnet_id, version)
                .unwrap_or(None)
                .unwrap_or_default();
            for node in node_records {
                subnet_nodes.insert(node.0, node.1);
            }
        }
        subnet_nodes
    }
}

fn get_peer_addr(node_record: &NodeRecord) -> Option<SocketAddr> {
    node_record
        .http
        .as_ref()
        .and_then(|endpoint| Some((IpAddr::from_str(&endpoint.ip_addr).ok()?, 4100)))
        .map(SocketAddr::from)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::download_management::tests::new_test_gossip_impl_with_registry;
    use ic_interfaces_mocks::consensus_pool::MockConsensusPoolCache;
    use ic_interfaces_registry::RegistryClient;
    use ic_protobuf::registry::node::v1::ConnectionEndpoint;
    use ic_registry_client_fake::FakeRegistryClient;
    use ic_test_utilities::{
        p2p::{p2p_test_setup_logger, test_group_set_registry, P2P_SUBNET_ID_DEFAULT},
        port_allocation::allocate_ports,
    };
    use ic_test_utilities_types::ids::subnet_test_id;
    use std::sync::Arc;

    #[test]
    fn test_get_peer_addr() {
        let node_record: NodeRecord = Default::default();
        let peer_addr = get_peer_addr(&node_record);
        assert!(peer_addr.is_none());

        let node_record = NodeRecord {
            http: Some(ConnectionEndpoint {
                ip_addr: "2001:db8:0:1:1:1:1:1".to_string(),
                port: 200,
            }),
            ..Default::default()
        };

        let peer_addr = get_peer_addr(&node_record).unwrap();
        assert_eq!(
            peer_addr.to_string(),
            "[2001:db8:0:1:1:1:1:1]:4100".to_string()
        );
    }

    #[test]
    fn test_merge_subnet_membership() {
        let logger = p2p_test_setup_logger();
        let num_replicas = 3;

        let allocated_ports = allocate_ports("127.0.0.1", num_replicas as u16)
            .expect("Port allocation for test failed");
        let node_port_allocation: Vec<u16> = allocated_ports.iter().map(|np| np.port).collect();
        let data_provider = test_group_set_registry(
            subnet_test_id(P2P_SUBNET_ID_DEFAULT),
            Arc::new(node_port_allocation),
        );
        let registry_data_provider = data_provider;
        let registry_client = Arc::new(FakeRegistryClient::new(registry_data_provider));
        registry_client.update_to_latest_version();

        // Create consensus cache that returns a oldest registry version higher than the the local view.
        let mut mock_consensus_cache = MockConsensusPoolCache::new();
        let consensus_registry_client = registry_client.clone();
        mock_consensus_cache
            .expect_get_oldest_registry_version_in_use()
            .returning(move || {
                RegistryVersion::from(consensus_registry_client.get_latest_version().get() + 5)
            });
        let consensus_pool_cache = Arc::new(mock_consensus_cache);

        let rt = tokio::runtime::Runtime::new().unwrap();
        let gossip = new_test_gossip_impl_with_registry(
            num_replicas,
            &logger,
            Arc::clone(&registry_client) as Arc<_>,
            Arc::clone(&consensus_pool_cache) as Arc<_>,
            rt.handle().clone(),
        );
        // Make sure the subnet membership in non-empty
        assert!(!gossip
            .merge_subnet_membership(registry_client.get_latest_version())
            .is_empty())
    }
}
