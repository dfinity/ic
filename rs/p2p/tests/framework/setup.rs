/// This file contains the helper functions required to setup testing framework.
use ic_interfaces::{p2p::P2PRunner, registry::RegistryClient};
use ic_logger::*;
use ic_metrics::MetricsRegistry;
use ic_protobuf::registry::{
    node::{ConnectionEndpoint, NodeRecord},
    subnet::{SubnetListRecord, SubnetRecord},
};
use ic_registry_common::{
    keys::{make_node_record_key, make_subnet_record_key, SUBNET_LIST_KEY},
    proto_registry_data_provider::ProtoRegistryDataProvider,
};
use ic_test_utilities::types::ids::node_test_id;
use ic_types::{
    replica_config::ReplicaConfig,
    transport::{TransportConfig, TransportMessageType, TransportTomlConfig},
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

// P2PTestContext
//
//    Create a context for individual replicas participating in a test
pub struct P2PTestContext {
    pub node_id: NodeId,                        // replica id
    pub subnet_id: SubnetId,                    // Dummy test subnet ID
    pub metrics_registry: MetricsRegistry,      // monitor metrics from various ICP layers
    pub test_synchronizer: P2PTestSynchronizer, // Provide basic inter-test synchronization
    pub p2p: Box<dyn P2PRunner>,                // p2p object to drive the ICP stack
}

impl P2PTestContext {
    pub(crate) fn new(
        node_id: NodeId,
        subnet_id: SubnetId,
        metrics_registry: MetricsRegistry,
        test_synchronizer: P2PTestSynchronizer,
        p2p: Box<dyn P2PRunner>,
    ) -> Self {
        P2PTestContext {
            node_id,
            subnet_id,
            metrics_registry,
            test_synchronizer,
            p2p,
        }
    }
}

// P2PTestSynchronizer
//
//    Provides synchronization mechanism between P2P tests.
//    Following primitives are provided.
//
//    Barrier
//         Test scoped named barriers.
//         Test don't proceed until all tests in the group reach the barrier.
//
//    Stop/Done signal
//          Any replica in the test group can signal that the test is complete.
//          Other replicas can poll to see if a test completion has been
// signaled.
//
#[derive(Clone)]
pub struct P2PTestSynchronizer {
    test_id: u32,
    test_dir_path: std::path::PathBuf,
    pub node_id: NodeId,
    num_replicas: u16,
    node_port_allocation: Arc<Vec<u16>>,
}

impl P2PTestSynchronizer {
    pub(crate) fn new(
        test_dir_path: std::path::PathBuf,
        node_id: NodeId,
        num_replicas: u16,
        node_port_allocation: Arc<Vec<u16>>,
    ) -> Self {
        P2PTestSynchronizer {
            test_id: std::process::id(),
            test_dir_path,
            node_id,
            num_replicas,
            node_port_allocation,
        }
    }

    // Get the root directory for this test group
    pub(crate) fn get_test_group_directory(&self) -> std::path::PathBuf {
        let mut dir = self.test_dir_path.clone();
        dir.push(P2P_TEST_ROOT);
        dir.push(format!("test_id_{}", self.test_id));
        dir
    }

    // Sets up the test directory before starting the test.  ALL IPC
    // information will be lost. To be called by the test control
    // process before forking test replicas
    pub(crate) fn setup_test_group_directory(&self) -> std::io::Result<()> {
        let test_directory = self.get_test_group_directory();
        println!("Setup {:?}", test_directory);
        let _ = fs::remove_dir_all(test_directory.clone());
        fs::create_dir_all(test_directory)
    }

    // Cleanup the test directory at the end of the test. Should be
    // called by the test control process
    pub(crate) fn cleanup_test_group_directory(&self) -> std::io::Result<()> {
        Ok(fs::remove_dir_all(self.get_test_group_directory())?)
    }

    // Is test-group completion signalled
    pub fn is_group_stopped(&self) -> bool {
        let mut dir = self.get_test_group_directory();
        dir.push(P2P_TEST_STOP);
        fs::metadata(dir.as_path()).is_ok()
    }

    // Signal stop/done for the test-group.
    pub fn set_group_stop(&self) {
        let mut dir = self.get_test_group_directory();

        dir.push(P2P_TEST_STOP);
        let file = File::create(dir.as_path());
        file.expect("Test stop signal failed");
    }

    // wait_on_barrier_int
    // Internal helper funtion providing blocking/non-blocking behavior in case a
    // barrier has not reached
    fn wait_on_barrier_int(&self, barrier_name: String, block: bool) -> Result<(), i32> {
        let mut dir = self.get_test_group_directory();
        let mut result;
        dir.push(&barrier_name);
        fs::create_dir_all(&dir)
            .unwrap_or_else(|_| panic!("Cannot create barrier dir for {}", &barrier_name));

        // Signal barrier
        let mut signal_file_name = dir.clone();
        signal_file_name.push(format!("Node_{}", self.node_id.get()));
        let file = File::create(signal_file_name.as_path());
        file.expect("Barrier Signal Failed");

        // Wait barrier
        loop {
            let mut signal_count = 0;
            let dir_content = fs::read_dir(&dir).expect("Barrier Wait Failed");
            for _entry in dir_content {
                signal_count += 1;
            }
            result = Err(-1);
            if signal_count >= self.num_replicas {
                result = Ok(());
                break;
            }
            if block {
                sleep(Duration::from_millis(5));
                continue;
            }
            break;
        }
        result
    }

    // Wait on a named barrier until all replicas in the the test-
    // group singal the barrier. Calling wait implictly signals the
    // barrier for the calling replica.
    pub fn wait_on_barrier(&self, barrier_name: String) {
        self.wait_on_barrier_int(barrier_name, true)
            .expect("Blocking wait on barrier failed");
    }

    // Wait on a named barrier until all replicas in the the test-
    // group singal the barrier. Calling wait implictly signals the
    // barrier for the calling replica.
    pub fn try_wait_on_barrier(&self, barrier_name: String) -> Result<(), i32> {
        self.wait_on_barrier_int(barrier_name, false)
    }
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
            SUBNET_LIST_KEY,
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
