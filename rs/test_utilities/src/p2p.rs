//! This file contains the helper functions required to setup testing framework.

use crate::types::ids::node_test_id;
use ic_config::{
    logger::{default_logtarget, Config as LoggerConfig, LogFormat},
    transport::{TransportConfig, TransportFlowConfig},
};
use ic_interfaces::registry::RegistryClient;
use ic_logger::*;
use ic_metrics::MetricsRegistry;
use ic_p2p::P2PThreadJoiner;
use ic_protobuf::registry::node::v1::{
    connection_endpoint::Protocol, ConnectionEndpoint, FlowEndpoint, NodeRecord,
};
use ic_registry_proto_data_provider::ProtoRegistryDataProvider;
use ic_test_utilities_registry::{setup_registry_non_final, SubnetRecordBuilder};
use ic_types::{replica_config::ReplicaConfig, NodeId, RegistryVersion, SubnetId};

use ic_registry_keys::make_node_record_key;
use std::collections::HashMap;
use std::{fs, fs::File, sync::Arc, thread::sleep, time::Duration};

pub const P2P_SUBNET_ID_DEFAULT: u64 = 0;
const P2P_TEST_ROOT: &str = "p2p_test";
const P2P_TEST_STOP: &str = "stop";

// get_node_from_registry
//
//    Extracts Node_Info list for a particular subnet from the registry.
//
// Parameters
//    registry       in-memory registry
//    subnet_id      subnet id whose members are to be looked up
pub fn get_nodes_from_registry(
    registry: Arc<dyn RegistryClient>,
    subnet_id: SubnetId,
) -> Vec<(NodeId, NodeRecord)> {
    use ic_registry_client_helpers::subnet::SubnetTransportRegistry;
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
pub fn get_peers(registry_node_list: &[(NodeId, NodeRecord)], node_id: NodeId) -> Vec<NodeId> {
    let mut node_ids: Vec<_> = registry_node_list.iter().map(|(id, _)| *id).collect();
    node_ids.retain(|n| (*n).get() != node_id.get());
    node_ids
}

// P2PTestContext
//
//    Create a context for individual replicas participating in a test
pub struct P2PTestContext {
    pub node_num: u64,                     // u64 from which the replica id is derived
    pub node_id: NodeId,                   // replica id
    pub subnet_id: SubnetId,               // Dummy test subnet ID
    pub metrics_registry: MetricsRegistry, // monitor metrics from various ICP layers
    pub test_synchronizer: P2PTestSynchronizer, // Provide basic inter-test synchronization
    pub _p2p_thread_joiner: P2PThreadJoiner, // p2p object to drive the ICP stack
}

impl P2PTestContext {
    pub fn new(
        node_num: u64,
        subnet_id: SubnetId,
        metrics_registry: MetricsRegistry,
        test_synchronizer: P2PTestSynchronizer,
        p2p_thread_joiner: P2PThreadJoiner,
    ) -> Self {
        P2PTestContext {
            node_num,
            node_id: node_test_id(node_num),
            subnet_id,
            metrics_registry,
            test_synchronizer,
            _p2p_thread_joiner: p2p_thread_joiner,
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
    _node_port_allocation: Arc<Vec<u16>>,
}

impl P2PTestSynchronizer {
    pub fn new(
        test_dir_path: std::path::PathBuf,
        node_id: NodeId,
        num_replicas: u16,
        _node_port_allocation: Arc<Vec<u16>>,
    ) -> Self {
        P2PTestSynchronizer {
            test_id: std::process::id(),
            test_dir_path,
            node_id,
            num_replicas,
            _node_port_allocation,
        }
    }

    // Get the root directory for this test group
    pub fn get_test_group_directory(&self) -> std::path::PathBuf {
        let mut dir = self.test_dir_path.clone();
        dir.push(P2P_TEST_ROOT);
        dir.push(format!("test_id_{}", self.test_id));
        dir
    }

    // Sets up the test directory before starting the test.  ALL IPC
    // information will be lost. To be called by the test control
    // process before forking test replicas
    pub fn setup_test_group_directory(&self) -> std::io::Result<()> {
        let test_directory = self.get_test_group_directory();
        println!("Setup {:?}", test_directory);
        let _ = fs::remove_dir_all(test_directory.clone());
        fs::create_dir_all(test_directory)
    }

    // Cleanup the test directory at the end of the test. Should be
    // called by the test control process
    pub fn cleanup_test_group_directory(&self) -> std::io::Result<()> {
        fs::remove_dir_all(self.get_test_group_directory())
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
pub fn test_group_set_registry(
    subnet_id: SubnetId,
    node_port_allocation: Arc<Vec<u16>>,
) -> Arc<ProtoRegistryDataProvider> {
    let version = RegistryVersion::from(1);

    // set subnet membership
    let node_nums: Vec<u64> = (0..(node_port_allocation.len() as u64)).collect();
    let (data_provider, _) = setup_registry_non_final(
        subnet_id,
        vec![(
            1,
            SubnetRecordBuilder::from(
                &node_nums
                    .clone()
                    .into_iter()
                    .map(node_test_id)
                    .collect::<Vec<_>>(),
            )
            .build(),
        )],
    );

    for node_num in node_nums {
        let connection_endpoint = Some(ConnectionEndpoint {
            ip_addr: "127.0.0.1".to_string(),
            port: node_port_allocation[node_num as usize] as u32,
            protocol: Protocol::P2p1Tls13 as i32,
        });
        let flow_end_point = FlowEndpoint {
            flow_tag: 0,
            endpoint: connection_endpoint,
        };
        let flow_end_points = vec![flow_end_point];

        let node_record = NodeRecord {
            p2p_flow_endpoints: flow_end_points,
            http: Some(ConnectionEndpoint {
                ip_addr: "127.0.0.1".to_string(),
                port: node_num as u32, /* NOTE: this port is not used in any test */
                protocol: Protocol::Http1 as i32,
            }),
            prometheus_metrics_http: Some(ConnectionEndpoint {
                ip_addr: "127.0.0.1".to_string(),
                port: 9090,
                protocol: Protocol::Http1 as i32,
            }),
            ..Default::default()
        };
        data_provider
            .add(
                &make_node_record_key(node_test_id(node_num)),
                version,
                Some(node_record),
            )
            .expect("Could not add node record.");
    }

    data_provider
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
pub fn get_replica_transport_config(
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
    let port = node_record.p2p_flow_endpoints[0]
        .endpoint
        .as_ref()
        .expect("p2p flow endpoint not present in node record.")
        .port;
    use std::convert::TryFrom;
    let port = u16::try_from(port).expect("Could not convert u32 to u16");

    TransportConfig {
        node_ip: "127.0.0.1".to_string(),
        p2p_flows: vec![TransportFlowConfig {
            flow_tag: 0,
            server_port: port,
            queue_size: 8,
        }],
    }
}

/// Sets up logging for P2P tests.
///
/// The returned `LoggerImpl` wraps a guard that stops async logging on drop.
/// It must be held onto until the end of the test.
pub fn p2p_test_setup_logger() -> LoggerImpl {
    // setup logging
    let logger_config = LoggerConfig {
        node_id: 1,
        dc_id: 200,
        level: slog::Level::Debug,
        format: LogFormat::TextFull,
        debug_overrides: vec![],
        sampling_rates: HashMap::new(),
        enabled_tags: vec![],
        target: default_logtarget(),
        ..LoggerConfig::default()
    };
    LoggerImpl::new(&logger_config, "P2PTestLogger".to_string())
}
