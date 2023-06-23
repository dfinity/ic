use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};

use ic_logger::ReplicaLogger;
use ic_metrics::MetricsRegistry;
use ic_peer_manager::{start_peer_manager, SubnetTopology};
use ic_protobuf::registry::{
    node::v1::{ConnectionEndpoint, FlowEndpoint, NodeRecord, Protocol},
    subnet::v1::SubnetRecord,
};
use ic_registry_client_fake::FakeRegistryClient;
use ic_registry_keys::make_node_record_key;
use ic_registry_proto_data_provider::ProtoRegistryDataProvider;
use ic_test_utilities::{
    consensus::MockConsensusCache,
    types::ids::{node_test_id, subnet_test_id},
};
use ic_test_utilities_logger::with_test_replica_logger;
use ic_test_utilities_registry::add_subnet_record;
use ic_types::{NodeId, RegistryVersion};
use tokio::{runtime::Handle, sync::watch::Receiver, task::JoinHandle};

/// Handle that can be used to update anything relevant to the subnet topology.
struct RegistyConsensusHandle {
    // NodeId in subnet as byte vector
    membership: Vec<Vec<u8>>,
    pub oldest_regisry_version: Arc<AtomicU64>,
    pub registry_client: Arc<FakeRegistryClient>,
    pub data_provider: ProtoRegistryDataProvider,
}

impl RegistyConsensusHandle {
    pub fn add_node(&mut self, version: RegistryVersion, node_id: NodeId, ip: &str) {
        let mut subnet_record = SubnetRecord::default();

        self.membership.push(node_id.get().to_vec());
        subnet_record.membership = self.membership.clone();
        add_subnet_record(
            &Arc::new(self.data_provider.clone()),
            version.get(),
            subnet_test_id(0),
            subnet_record,
        );
        let connection_endpoint = Some(ConnectionEndpoint {
            ip_addr: ip.to_string(),
            port: 1000_u32,
            protocol: Protocol::P2p1Tls13 as i32,
        });
        let flow_end_point = FlowEndpoint {
            endpoint: connection_endpoint,
        };
        let flow_end_points = vec![flow_end_point];

        let node_record = NodeRecord {
            p2p_flow_endpoints: flow_end_points,
            ..Default::default()
        };
        self.data_provider
            .add(&make_node_record_key(node_id), version, Some(node_record))
            .expect("Could not add node record.");
        self.registry_client.update_to_latest_version();
    }

    pub fn remove_node(&mut self, version: RegistryVersion, node_id: NodeId) {
        let mut subnet_record = SubnetRecord::default();

        let index = self
            .membership
            .iter()
            .position(|x| *x == node_id.get().to_vec())
            .unwrap();
        self.membership.remove(index);

        subnet_record.membership = self.membership.clone();
        add_subnet_record(
            &Arc::new(self.data_provider.clone()),
            version.get(),
            subnet_test_id(0),
            subnet_record,
        );
        self.registry_client.update_to_latest_version();
    }

    /// Inserts a bogues protobuf value into the registry key value store.
    /// This can be used to advance the latest registry version.
    pub fn set_latest_registry_version(&mut self, version: RegistryVersion) {
        self.data_provider
            .add::<SubnetRecord>("bogus", version, None)
            .unwrap();
        self.registry_client.update_to_latest_version();
    }

    pub fn set_oldest_consensus_registry_version(&mut self, version: RegistryVersion) {
        self.oldest_regisry_version
            .store(version.get(), Ordering::SeqCst);
    }
}

fn create_peer_manager(
    rt: &Handle,
    log: ReplicaLogger,
) -> (
    JoinHandle<()>,
    Receiver<SubnetTopology>,
    RegistyConsensusHandle,
) {
    let oldest_registry_version = Arc::new(AtomicU64::new(0));
    let oldest_registry_version_c = oldest_registry_version.clone();
    let mut mock_cache = MockConsensusCache::new();
    mock_cache
        .expect_get_oldest_registry_version_in_use()
        .returning(move || RegistryVersion::from(oldest_registry_version.load(Ordering::SeqCst)));

    let data_provider_proto = ProtoRegistryDataProvider::new();
    let registry_client = Arc::new(FakeRegistryClient::new(Arc::new(
        data_provider_proto.clone(),
    )));

    let (jh, rcv) = start_peer_manager(
        log,
        &MetricsRegistry::default(),
        rt,
        subnet_test_id(0),
        Arc::new(mock_cache) as Arc<_>,
        registry_client.clone() as Arc<_>,
    );
    (
        jh,
        rcv,
        RegistyConsensusHandle {
            membership: Vec::new(),
            oldest_regisry_version: oldest_registry_version_c,
            registry_client,
            data_provider: data_provider_proto,
        },
    )
}

#[test]
fn test_single_node() {
    with_test_replica_logger(|log| {
        let rt = tokio::runtime::Runtime::new().unwrap();

        let (jh, mut receiver, mut registry_consensus_handle) =
            create_peer_manager(rt.handle(), log);

        rt.block_on(async move {
            let node_id = node_test_id(1);
            registry_consensus_handle.add_node(
                RegistryVersion::from(1),
                node_id,
                "2a02:41b:300e:0:6801:a3ff:fe71:4168",
            );
            registry_consensus_handle
                .set_oldest_consensus_registry_version(RegistryVersion::from(0));

            // Wait for the peer manager to pick up the change.
            receiver.changed().await.unwrap();

            assert!(receiver.borrow().is_member(&node_id));
            assert!(receiver.borrow().iter().count() == 1);
            // If join handle finished sth went wrong and we propagate the error.
            if jh.is_finished() {
                jh.await.unwrap();
                panic!("Join handle should not finish.");
            }
        });
    })
}

#[test]
fn test_single_node_with_invalid_ip() {
    with_test_replica_logger(|log| {
        let rt = tokio::runtime::Runtime::new().unwrap();

        let (jh, mut receiver, mut registry_consensus_handle) =
            create_peer_manager(rt.handle(), log);

        rt.block_on(async move {
            let node_id = node_test_id(1);
            registry_consensus_handle.add_node(
                RegistryVersion::from(1),
                node_id,
                "2a02:41b:300e:0:6801:a3ff:fe71::::",
            );
            registry_consensus_handle
                .set_oldest_consensus_registry_version(RegistryVersion::from(0));

            // Wait for the peer manager to pick up the change.
            receiver.changed().await.unwrap();

            // Peer has invalid IP and is therefore not relevant for subnet topology.
            assert!(receiver.borrow().iter().count() == 0);
            // If join handle finished sth went wrong and we propagate the error.
            if jh.is_finished() {
                jh.await.unwrap();
                panic!("Join handle should not finish.");
            }
        });
    })
}

#[test]
fn test_add_multiple_nodes() {
    with_test_replica_logger(|log| {
        let rt = tokio::runtime::Runtime::new().unwrap();

        let (jh, mut receiver, mut registry_consensus_handle) =
            create_peer_manager(rt.handle(), log);

        rt.block_on(async move {
            // Add first node
            let node_id_1 = node_test_id(1);
            registry_consensus_handle.add_node(
                RegistryVersion::from(1),
                node_id_1,
                "2a02:41b:300e:0:6801:a3ff:fe71:4168",
            );
            registry_consensus_handle
                .set_oldest_consensus_registry_version(RegistryVersion::from(0));

            // Wait for the peer manager to pick up the change.
            receiver.changed().await.unwrap();
            assert!(receiver.borrow().is_member(&node_id_1));
            assert!(receiver.borrow().iter().count() == 1);

            // Add second node
            let node_id_2 = node_test_id(2);
            registry_consensus_handle.add_node(
                RegistryVersion::from(2),
                node_id_2,
                "2a02:41b:300e:0:6801:a3ff:fe71:4169",
            );

            // Wait for the peer manager to pick up the change.
            receiver.changed().await.unwrap();
            assert!(receiver.borrow().is_member(&node_id_2));
            assert!(receiver.borrow().iter().count() == 2);

            // If join handle finished sth went wrong and we propagate the error.
            if jh.is_finished() {
                jh.await.unwrap();
                panic!("Join handle should not finish.");
            }
        });
    })
}

#[test]
fn test_add_multiple_nodes_remove_node() {
    with_test_replica_logger(|log| {
        let rt = tokio::runtime::Runtime::new().unwrap();

        let (jh, mut receiver, mut registry_consensus_handle) =
            create_peer_manager(rt.handle(), log);

        rt.block_on(async move {
            registry_consensus_handle
                .set_oldest_consensus_registry_version(RegistryVersion::from(0));
            // Add a few nodes
            for i in 1..11 {
                let node_id = node_test_id(i);
                registry_consensus_handle.add_node(
                    RegistryVersion::from(i),
                    node_id,
                    "2a02:41b:300e:0:6801:a3ff:fe71:4168",
                );
            }

            // Wait for the peer manager to pick up the change.
            receiver
                .wait_for(|topology| topology.iter().count() == 10)
                .await
                .unwrap();
            for i in 1..11 {
                assert!(receiver.borrow().is_member(&node_test_id(i)));
                assert!(receiver.borrow().iter().count() == 10);
            }

            // Remove one node
            let removed_node_id = node_test_id(2);
            registry_consensus_handle.remove_node(RegistryVersion::from(12), removed_node_id);

            receiver.changed().await.unwrap();
            // Node should not yet be removed since consensus registry version is still at 0.
            assert!(receiver.borrow().is_member(&removed_node_id));
            assert!(receiver.borrow().iter().count() == 10);
            // Updating the consenus registry version to version higher than the remove proposal so
            // the node actually should gets removed.
            registry_consensus_handle
                .set_oldest_consensus_registry_version(RegistryVersion::from(13));
            registry_consensus_handle.set_latest_registry_version(RegistryVersion::from(14));
            receiver.changed().await.unwrap();
            assert!(!receiver.borrow().is_member(&removed_node_id));
            assert!(receiver.borrow().iter().count() == 9);

            // If join handle finished sth went wrong and we propagate the error.
            if jh.is_finished() {
                jh.await.unwrap();
                panic!("Join handle should not finish.");
            }
        });
    })
}
