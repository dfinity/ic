use ic_base_types::{NodeId, PrincipalId, RegistryVersion, SubnetId};
use ic_crypto_temp_crypto::{NodeKeysToGenerate, TempCryptoComponent};
use ic_crypto_tls_interfaces::TlsConfig;
use ic_logger::ReplicaLogger;
use ic_metrics::MetricsRegistry;
use ic_peer_manager::{start_peer_manager, SubnetTopology};
use ic_protobuf::registry::{
    node::v1::{ConnectionEndpoint, FlowEndpoint, NodeRecord},
    subnet::v1::SubnetRecord,
};
use ic_registry_client_fake::FakeRegistryClient;
use ic_registry_keys::make_node_record_key;
use ic_registry_local_registry::LocalRegistry;
use ic_registry_local_store::{compact_delta_to_changelog, LocalStoreImpl, LocalStoreWriter};
use ic_registry_proto_data_provider::ProtoRegistryDataProvider;
use ic_test_utilities::{consensus::MockConsensusCache, types::ids::subnet_test_id};
use ic_test_utilities_registry::add_subnet_record;
use std::{
    str::FromStr,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};
use tempfile::TempDir;
use tokio::{runtime::Handle, sync::watch::Receiver, task::JoinHandle};

/// Creates a temp crypto component with TLS key and specified node id.
/// It also adds the tls keys to the registry data provider.
pub fn temp_crypto_component_with_tls_keys(
    registry_and_data: &RegistryConsensusHandle,
    node_id: NodeId,
) -> Arc<dyn TlsConfig + Send + Sync> {
    TempCryptoComponent::builder()
        .with_registry_client_and_data(
            registry_and_data.registry_client.clone(),
            registry_and_data.data_provider.clone(),
        )
        .with_node_id(node_id)
        .with_keys(NodeKeysToGenerate::only_tls_key_and_cert())
        .build_arc()
}

/// Handle that can be used to update anything relevant to the subnet topology.
#[derive(Clone)]
pub struct RegistryConsensusHandle {
    // NodeId in subnet as byte vector
    membership: Arc<Mutex<Vec<Vec<u8>>>>,
    pub oldest_registry_version: Arc<AtomicU64>,
    pub registry_client: Arc<FakeRegistryClient>,
    pub data_provider: Arc<ProtoRegistryDataProvider>,
}

impl RegistryConsensusHandle {
    pub fn add_node(
        &mut self,
        version: RegistryVersion,
        node_id: NodeId,
        endpoints: Vec<Option<(&str, u16)>>,
    ) {
        let mut subnet_record = SubnetRecord::default();

        let mut membership = self.membership.lock().unwrap();
        membership.push(node_id.get().to_vec());
        subnet_record.membership = membership.clone();
        add_subnet_record(
            &self.data_provider,
            version.get(),
            subnet_test_id(0),
            subnet_record,
        );

        let flow_end_points = endpoints
            .into_iter()
            .map(|endpoint| FlowEndpoint {
                endpoint: endpoint.map(|(ip, port)| ConnectionEndpoint {
                    ip_addr: ip.to_string(),
                    port: port as u32,
                }),
            })
            .collect();

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

        let mut membership = self.membership.lock().unwrap();
        let index = membership
            .iter()
            .position(|x| *x == node_id.get().to_vec())
            .unwrap();
        membership.remove(index);

        subnet_record.membership = membership.clone();
        add_subnet_record(
            &self.data_provider,
            version.get(),
            subnet_test_id(0),
            subnet_record,
        );
        self.registry_client.update_to_latest_version();
    }

    /// Inserts a bogus protobuf value into the registry key value store.
    /// This can be used to advance the latest registry version.
    pub fn set_latest_registry_version(&mut self, version: RegistryVersion) {
        self.data_provider
            .add::<SubnetRecord>("bogus", version, None)
            .unwrap();
        self.registry_client.update_to_latest_version();
    }

    pub fn set_oldest_consensus_registry_version(&mut self, version: RegistryVersion) {
        self.oldest_registry_version
            .store(version.get(), Ordering::SeqCst);
    }
}

pub fn create_peer_manager_and_registry_handle(
    rt: &Handle,
    log: ReplicaLogger,
) -> (
    JoinHandle<()>,
    Receiver<SubnetTopology>,
    RegistryConsensusHandle,
) {
    let oldest_registry_version = Arc::new(AtomicU64::new(0));
    let oldest_registry_version_c = oldest_registry_version.clone();
    let mut mock_cache = MockConsensusCache::new();
    mock_cache
        .expect_get_oldest_registry_version_in_use()
        .returning(move || RegistryVersion::from(oldest_registry_version.load(Ordering::SeqCst)));

    let data_provider_proto = Arc::new(ProtoRegistryDataProvider::new());
    let registry_client = Arc::new(FakeRegistryClient::new(data_provider_proto.clone()));

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
        RegistryConsensusHandle {
            membership: Arc::new(Mutex::new(Vec::new())),
            oldest_registry_version: oldest_registry_version_c,
            registry_client,
            data_provider: data_provider_proto,
        },
    )
}

/// Get protobuf-encoded snapshot of the mainnet registry state (around jan. 2022)
fn get_mainnet_delta_00_6d_c1() -> (TempDir, LocalStoreImpl) {
    let tempdir = TempDir::new().unwrap();
    let store = LocalStoreImpl::new(tempdir.path());
    let changelog =
        compact_delta_to_changelog(ic_registry_local_store_artifacts::MAINNET_DELTA_00_6D_C1)
            .expect("")
            .1;

    for (v, changelog_entry) in changelog.into_iter().enumerate() {
        let v = RegistryVersion::from((v + 1) as u64);
        store.store(v, changelog_entry).unwrap();
    }
    (tempdir, store)
}

pub fn create_peer_manager_with_local_store(
    rt: &Handle,
    log: ReplicaLogger,
    subnet_id: SubnetId,
) -> (
    JoinHandle<()>,
    Receiver<SubnetTopology>,
    Arc<LocalRegistry>,
    Arc<AtomicU64>,
    TempDir,
) {
    let oldest_registry_version = Arc::new(AtomicU64::new(0));
    let oldest_registry_version_c = oldest_registry_version.clone();
    let mut mock_cache = MockConsensusCache::new();
    mock_cache
        .expect_get_oldest_registry_version_in_use()
        .returning(move || RegistryVersion::from(oldest_registry_version.load(Ordering::SeqCst)));

    let (tmp, _local_store) = get_mainnet_delta_00_6d_c1();
    let local_registry = LocalRegistry::new(tmp.path(), Duration::from_millis(500)).unwrap();

    let registry_client = Arc::new(local_registry);

    let (jh, rcv) = start_peer_manager(
        log,
        &MetricsRegistry::default(),
        rt,
        subnet_id,
        Arc::new(mock_cache) as Arc<_>,
        registry_client.clone() as Arc<_>,
    );
    (jh, rcv, registry_client, oldest_registry_version_c, tmp)
}

pub fn mainnet_nns_subnet() -> SubnetId {
    SubnetId::new(
        PrincipalId::from_str("tdb26-jop6k-aogll-7ltgs-eruif-6kk7m-qpktf-gdiqx-mxtrf-vb5e6-eqe")
            .unwrap(),
    )
}

pub fn mainnet_app_subnet() -> SubnetId {
    SubnetId::new(
        PrincipalId::from_str("6pbhf-qzpdk-kuqbr-pklfa-5ehhf-jfjps-zsj6q-57nrl-kzhpd-mu7hc-vae")
            .unwrap(),
    )
}
