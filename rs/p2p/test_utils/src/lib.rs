use axum::{http::Request, Router};
use bytes::Bytes;
use consensus::{TestConsensus, U64Artifact};
use futures::{
    future::{join_all, BoxFuture},
    FutureExt,
};
use ic_artifact_downloader::FetchArtifact;
use ic_base_types::{NodeId, PrincipalId, RegistryVersion, SubnetId};
use ic_crypto_temp_crypto::{NodeKeysToGenerate, TempCryptoComponent};
use ic_crypto_tls_interfaces::TlsConfig;
use ic_interfaces::p2p::artifact_manager::JoinGuard;
use ic_interfaces_mocks::consensus_pool::MockConsensusPoolCache;
use ic_logger::ReplicaLogger;
use ic_metrics::MetricsRegistry;
use ic_peer_manager::start_peer_manager;
use ic_protobuf::registry::{
    node::v1::{ConnectionEndpoint, NodeRecord},
    subnet::v1::SubnetRecord,
};
use ic_quic_transport::{create_udp_socket, ConnId, QuicTransport, SubnetTopology, Transport};
use ic_registry_client_fake::FakeRegistryClient;
use ic_registry_keys::make_node_record_key;
use ic_registry_local_registry::LocalRegistry;
use ic_registry_local_store::{compact_delta_to_changelog, LocalStoreImpl, LocalStoreWriter};
use ic_registry_proto_data_provider::ProtoRegistryDataProvider;
use ic_test_utilities_registry::add_subnet_record;
use ic_test_utilities_types::ids::subnet_test_id;
use std::{
    collections::{HashMap, HashSet},
    net::SocketAddr,
    str::FromStr,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex, RwLock,
    },
    time::Duration,
};
use tempfile::TempDir;
use tokio::{
    runtime::Handle,
    sync::watch::{self, Receiver},
    task::JoinHandle,
};
use turmoil::start_test_processor;

pub mod consensus;
pub mod mocks;
pub mod turmoil;

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
    pub fn add_node(&mut self, version: RegistryVersion, node_id: NodeId, ip_addr: Option<&str>) {
        let mut subnet_record = SubnetRecord::default();

        let mut membership = self.membership.lock().unwrap();
        membership.push(node_id.get().to_vec());
        subnet_record.membership.clone_from(&membership);

        add_subnet_record(
            &self.data_provider,
            version.get(),
            subnet_test_id(0),
            subnet_record,
        );
        let node_record = NodeRecord {
            http: ip_addr.map(|addr| ConnectionEndpoint {
                ip_addr: addr.to_string(),
                port: 8080,
            }),
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

        subnet_record.membership.clone_from(&membership);
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

pub fn create_registry_handle() -> (MockConsensusPoolCache, RegistryConsensusHandle) {
    let oldest_registry_version = Arc::new(AtomicU64::new(0));
    let oldest_registry_version_c = oldest_registry_version.clone();
    let mut mock_cache = MockConsensusPoolCache::new();
    mock_cache
        .expect_get_oldest_registry_version_in_use()
        .returning(move || RegistryVersion::from(oldest_registry_version.load(Ordering::SeqCst)));

    let data_provider_proto = Arc::new(ProtoRegistryDataProvider::new());
    let registry_client = Arc::new(FakeRegistryClient::new(data_provider_proto.clone()));
    (
        mock_cache,
        RegistryConsensusHandle {
            membership: Arc::new(Mutex::new(Vec::new())),
            oldest_registry_version: oldest_registry_version_c,
            registry_client,
            data_provider: data_provider_proto,
        },
    )
}

pub fn create_peer_manager_and_registry_handle(
    rt: &Handle,
    log: ReplicaLogger,
) -> (
    JoinHandle<()>,
    Receiver<SubnetTopology>,
    RegistryConsensusHandle,
) {
    let (mock_cache, registry_handle) = create_registry_handle();
    let (jh, rcv) = start_peer_manager(
        log,
        &MetricsRegistry::default(),
        rt,
        subnet_test_id(0),
        Arc::new(mock_cache) as Arc<_>,
        registry_handle.registry_client.clone() as Arc<_>,
    );
    (jh, rcv, registry_handle)
}

/// Id is used to get a unique localhost address space. So it should be different for each test.
#[allow(clippy::type_complexity)]
pub fn fully_connected_localhost_subnet(
    rt: &Handle,
    log: ReplicaLogger,
    id: u8,
    router: Vec<(NodeId, Router)>,
) -> (
    Vec<(NodeId, Arc<dyn Transport>)>,
    watch::Receiver<SubnetTopology>,
) {
    assert!(
        id > 0,
        "ID is used to reserve a localhost address that is unique and shoud not be zero."
    );
    let mut node_ids = Vec::new();
    let (_jh, topology_watcher, mut registry_handler) =
        create_peer_manager_and_registry_handle(rt, log.clone());
    for (i, (node, router)) in router.into_iter().enumerate() {
        let node_crypto = temp_crypto_component_with_tls_keys(&registry_handler, node);
        registry_handler.registry_client.update_to_latest_version();
        registry_handler.registry_client.reload();

        let socket: SocketAddr = format!("127.1.{id}.{}:4100", i + 1).parse().unwrap();

        let transport = Arc::new(QuicTransport::start(
            &log,
            &MetricsRegistry::default(),
            rt,
            node_crypto,
            registry_handler.registry_client.clone(),
            node,
            topology_watcher.clone(),
            create_udp_socket(rt, socket),
            router,
        )) as Arc<_>;
        registry_handler.add_node(
            RegistryVersion::from(i as u64 + 1),
            node,
            Some(&socket.ip().to_string()),
        );
        node_ids.push((node, transport));
    }
    (node_ids, topology_watcher)
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
    let mut mock_cache = MockConsensusPoolCache::new();
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

/// Utility to check connectivity between peers.
/// Requires that transport has the `router()` installed
/// and periodically call `check` in a loop.
#[derive(Clone, Debug)]
#[allow(clippy::type_complexity)]
pub struct ConnectivityChecker {
    peers: Arc<RwLock<HashMap<NodeId, HashMap<NodeId, ConnId>>>>,
}

impl ConnectivityChecker {
    pub fn new(peers: &[NodeId]) -> Self {
        let mut hm = HashMap::new();

        for peer_id in peers {
            hm.insert(*peer_id, HashMap::new());
        }

        Self {
            peers: Arc::new(RwLock::new(hm)),
        }
    }

    /// Router used by check function to verify connectivity.
    pub fn router() -> Router {
        Router::new().route("/Ping", axum::routing::get(|| async { "Pong" }))
    }

    pub fn check_fut(
        &self,
    ) -> impl Fn(NodeId, Arc<dyn Transport>) -> BoxFuture<'static, ()> + Clone + 'static {
        let conn_checker = self.clone();
        move |peer, transport| {
            let conn_checker_clone = conn_checker.clone();
            async move {
                loop {
                    conn_checker_clone.check(peer, transport.clone()).await;
                    tokio::time::sleep(Duration::from_millis(250)).await;
                }
            }
            .boxed()
        }
    }

    /// Checks connectivity of this peer to peers provided in `add_peer` function.
    async fn check(&self, this_peer: NodeId, transport: Arc<dyn Transport>) {
        // Collect rpc futures to all peers
        let mut futs = vec![];
        for (peer, conn_id) in transport.peers() {
            let request = Request::builder().uri("/Ping").body(Bytes::new()).unwrap();
            let transport_clone = transport.clone();
            futs.push(async move {
                (
                    tokio::time::timeout(
                        Duration::from_secs(1),
                        transport_clone.rpc(&peer, request),
                    )
                    .await,
                    peer,
                    conn_id,
                )
            });
        }
        let futs_res = join_all(futs).await;
        // Apply results of rpc futures
        let mut peers = self.peers.write().unwrap();
        peers.get_mut(&this_peer).unwrap().clear();
        for res in futs_res {
            match res {
                (Ok(Ok(_)), peer, conn_id) => {
                    peers.get_mut(&this_peer).unwrap().insert(peer, conn_id);
                }
                (_, peer, _) => {
                    peers.get_mut(&this_peer).unwrap().remove(&peer);
                }
            }
        }
    }

    /// Every peer is connected to every other peer.
    pub fn fully_connected(&self) -> bool {
        let peers = self.peers.read().unwrap();
        for p1 in peers.keys() {
            for p2 in peers.keys() {
                if p1 != p2 && !self.connected_pair(p1, p2) {
                    return false;
                }
            }
        }
        true
    }

    /// Every peer is connected to every other peer that is not in the except list.
    pub fn fully_connected_except(&self, except_list: Vec<NodeId>) -> bool {
        let set: HashSet<NodeId> = HashSet::from_iter(except_list);
        let peers = self.peers.read().unwrap();
        for p1 in peers.keys() {
            for p2 in peers.keys() {
                if p1 != p2
                    && !set.contains(p1)
                    && !set.contains(p2)
                    && !self.connected_pair(p1, p2)
                {
                    return false;
                }
            }
        }
        true
    }

    /// This peer is not reachable by any other peer.
    pub fn unreachable(&self, unreachable_peer: &NodeId) -> bool {
        let peers = self.peers.read().unwrap();
        for peer_id in peers.keys() {
            if unreachable_peer != peer_id && !self.disconnected_from(peer_id, unreachable_peer) {
                return false;
            }
        }
        true
    }

    /// Clear connected status table for this peer
    pub fn reset(&self, peer: &NodeId) {
        let mut peers = self.peers.write().unwrap();
        peers.get_mut(peer).unwrap().clear();
    }

    /// Check if a both peers are connected to each other.
    pub fn connected_pair(&self, peer_1: &NodeId, peer_2: &NodeId) -> bool {
        let peers = self.peers.read().unwrap();

        let connected_peer_1 = peers.get(peer_1).unwrap();
        let connected_peer_2 = peers.get(peer_2).unwrap();

        connected_peer_1.contains_key(peer_2) && connected_peer_2.contains_key(peer_1)
    }

    pub fn connected_with_min_id(&self, peer_1: &NodeId, peer_2: &NodeId, conn_id: u64) -> bool {
        let peers = self.peers.read().unwrap();
        if let Some(v) = peers.get(peer_1) {
            return v.get(peer_2) >= Some(&ConnId::from(conn_id));
        }
        false
    }

    /// Checks if peer1 is disconnected from peer2.
    pub fn disconnected_from(&self, peer_1: &NodeId, peer_2: &NodeId) -> bool {
        let peers = self.peers.read().unwrap();

        let connected_peer_1 = peers.get(peer_1).unwrap();

        !connected_peer_1.contains_key(peer_2)
    }
}

pub fn start_consensus_manager(
    log: ReplicaLogger,
    rt_handle: Handle,
    processor: TestConsensus<U64Artifact>,
) -> (
    Box<dyn JoinGuard>,
    ic_consensus_manager::ConsensusManagerBuilder,
) {
    let _enter = rt_handle.enter();
    let pool = Arc::new(RwLock::new(processor));
    let (artifact_processor_jh, artifact_manager_event_rx, artifact_sender) =
        start_test_processor(pool.clone(), pool.clone().read().unwrap().clone());
    let bouncer_factory = Arc::new(pool.clone().read().unwrap().clone());
    let mut cm1 = ic_consensus_manager::ConsensusManagerBuilder::new(
        log.clone(),
        rt_handle.clone(),
        MetricsRegistry::default(),
    );
    let downloader = FetchArtifact::new(
        log,
        rt_handle,
        pool,
        bouncer_factory,
        MetricsRegistry::default(),
    );
    cm1.add_client(artifact_manager_event_rx, artifact_sender, downloader);
    (artifact_processor_jh, cm1)
}
