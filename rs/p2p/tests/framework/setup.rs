use ic_config::transport::TransportConfig;
use ic_interfaces_registry::RegistryClient;
use ic_logger::*;
use ic_metrics::MetricsRegistry;
use ic_protobuf::registry::{
    node::{ConnectionEndpoint, NodeRecord},
    subnet::{SubnetListRecord, SubnetRecord},
};
use ic_registry_nns_data_provider::{
    keys::{make_node_record_key, make_subnet_list_record_key, make_subnet_record_key},
    proto_registry_data_provider::ProtoRegistryDataProvider,
};
/// This file contains the helper functions required to setup testing framework.
use ic_test_utilities::types::ids::node_test_id;
use ic_types::{
    replica_config::ReplicaConfig,
    transport::{TransportMessageType, TransportTomlConfig},
    NodeId, RegistryVersion, SubnetId,
};

use std::collections::HashMap;
use std::{fs, fs::File, sync::Arc, thread::sleep, time::Duration};

pub(crate) const P2P_SUBNET_ID_DEFAULT: u64 = 0;
const P2P_TEST_ROOT: &str = "p2p_test";
const P2P_TEST_STOP: &str = "stop";

// get_node_from_registry
//
//    Extracts Node_Info list for a particular subnet from the registry.
//
// Parameters
//    registry       in-memory registry
//    subnet_id      subnet id whose members are to be looked up
pub(crate) fn get_nodes_from_registry(
    registry: Arc<dyn RegistryClient>,
    subnet_id: SubnetId,
) -> Vec<(NodeId, NodeRecord)> {
    use ic_registry_client::helper::subnet::SubnetTransportRegistry;
    let latest_version = registry.get_latest_version();
    registry
        .get_subnet_transport_infos(subnet_id, latest_version)
        .expect("Could not retrieve subnet transport infos from registry")
        .expect("Subnet transport information not available at this version.")
}

// get_peers
//
//    Get peer node ids for a replica
//
// Parameters
//    registry_node_list   List of node belonging to a subnet
//    node_id              node whose peers are to be looked up
pub(crate) fn get_peers(
    registry_node_list: &[(NodeId, NodeRecord)],
    node_id: NodeId,
) -> Vec<NodeId> {
    let mut node_ids: Vec<_> = registry_node_list.iter().map(|(id, _)| *id).collect();
    node_ids.retain(|&n| n != node_id);
    node_ids
}

/// Prepare a registry data provider such that it contains all information
/// necessary for transport to discover nodes with ports given by
/// `node_port_allocations` on a subnetwork `subnet_id`.
pub(crate) fn test_group_set_registry(
    data_provider: &Arc<ProtoRegistryDataProvider>,
    subnet_id: SubnetId,
    node_port_allocation: Arc<Vec<u16>>,
) {
    let version = RegistryVersion::from(1);

    // set subnet list
    data_provider
        .add(
            make_subnet_list_record_key.as_str(),
            version,
            Some(SubnetListRecord {
                subnets: vec![subnet_id.get()],
            }),
        )
        .expect("Coult not add subnet list record.");

    // set subnet membership

    let node_ids: Vec<_> = (0..node_port_allocation.len())
        .map(|n| node_test_id(n as u64))
        .collect();
    data_provider
        .add(
            &make_subnet_record_key(subnet_id),
            version,
            Some(SubnetRecord {
                membership: node_ids.iter().map(|id| id.get()).collect::<Vec<_>>(),
                initial_dkg_transcript: Some(Default::default()),
            }),
        )
        .expect("Could not add subnet record.");

    for node_id in node_ids {
        let connection_endpoint = Some(ConnectionEndpoint {
            ip_addr: "127.0.0.1".to_string(),
            port: node_port_allocation[node_id.get() as usize] as u32,
        });
        let mut node_record = NodeRecord::default();
        data_provider
            .add(&make_node_record_key(node_id), version, Some(node_record))
            .expect("Could not add node record.");
    }
}

//
// get_replica_transport_config
//
//    Setup/Extend a registry for a test-group.
//
// Parameters
//    num_replicas      Number for participating replicas
//    subnet_id         test group subnet id
//    registry          registry object that is to be extended
//
pub(crate) fn get_replica_transport_config(
    replica_config: &ReplicaConfig,
    registry: Arc<dyn RegistryClient>,
) -> TransportConfig {
    // Match the registry port config to the replica transport config
    let node_id = replica_config.node_id;
    let subnet_id = replica_config.subnet_id;

    let node_record = get_nodes_from_registry(registry, subnet_id)
        .iter()
        .find_map(|(id, nr)| {
            if *id == node_id {
                Some(nr.clone())
            } else {
                None
            }
        })
        .expect("Transport information not found in registry");

    // we assume all connection endpoints to have the same settings, so we just pull
    // out the port of some connection endpoint.
    let port = node_record
        .gossip_advert
        .expect("gossip_advert endpoint not present in node record.")
        .port;
    use std::convert::TryFrom;
    let port = u16::try_from(port).expect("Could not convert u32 to u16");

    // Build toml representation of the the config
    let toml_config = TransportTomlConfig {
        node_ip: "127.0.0.1".to_string(),
        p2p_flows: "1234-1".to_string(),
        tls_config: None,
    };

    TransportConfig::from(&toml_config)
}
