use axum::body::Body;
use hyper::{
    client::conn::http1::{handshake, SendRequest},
    Method, Request, StatusCode,
};
use hyper_util::rt::TokioIo;
use ic_agent::Agent;
use ic_config::http_handler::Config;
use ic_crypto_tls_interfaces::TlsConfig;
use ic_crypto_tls_interfaces_mocks::{MockTlsConfig, MockTlsHandshake};
use ic_crypto_tree_hash::{LabeledTree, MixedHashTree};
use ic_error_types::UserError;
use ic_http_endpoints_public::start_server;
use ic_interfaces::{
    consensus_pool::ConsensusPoolCache,
    execution_environment::{IngressFilterService, QueryExecutionResponse, QueryExecutionService},
    ingress_pool::IngressPoolThrottler,
};
use ic_interfaces_mocks::consensus_pool::MockConsensusPoolCache;
use ic_interfaces_registry::RegistryClient;
use ic_interfaces_registry_mocks::MockRegistryClient;
use ic_interfaces_state_manager::{CertifiedStateSnapshot, Labeled, StateReader};
use ic_interfaces_state_manager_mocks::MockStateManager;
use ic_logger::replica_logger::no_op_logger;
use ic_metrics::MetricsRegistry;
use ic_pprof::{Pprof, PprofCollector};
use ic_protobuf::registry::{
    crypto::v1::{AlgorithmId as AlgorithmIdProto, PublicKey as PublicKeyProto},
    provisional_whitelist::v1::ProvisionalWhitelist as ProvisionalWhitelistProto,
    subnet::v1::SubnetRecord,
};
use ic_registry_keys::{
    make_crypto_threshold_signing_pubkey_key, make_provisional_whitelist_record_key,
    make_subnet_record_key,
};
use ic_registry_provisional_whitelist::ProvisionalWhitelist;
use ic_registry_routing_table::{CanisterMigrations, RoutingTable};
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::{
    canister_snapshots::CanisterSnapshots, CanisterQueues, NetworkTopology, ReplicatedState,
    SystemMetadata,
};
use ic_test_utilities::crypto::{temp_crypto_component_with_fake_registry, CryptoReturningOk};
use ic_test_utilities_state::ReplicatedStateBuilder;
use ic_test_utilities_types::ids::{node_test_id, subnet_test_id};
use ic_types::{
    artifact::UnvalidatedArtifactMutation,
    artifact_kind::IngressArtifact,
    batch::RawQueryStats,
    consensus::certification::{Certification, CertificationContent},
    crypto::{
        threshold_sig::{
            ni_dkg::{NiDkgId, NiDkgTag, NiDkgTargetSubnet},
            ThresholdSigPublicKey,
        },
        CombinedThresholdSig, CombinedThresholdSigOf, CryptoHash, Signed,
    },
    malicious_flags::MaliciousFlags,
    messages::{CertificateDelegation, SignedIngressContent, UserQuery},
    signature::ThresholdSignature,
    time::UNIX_EPOCH,
    CryptoHashOfPartialState, Height, RegistryVersion,
};
use mockall::{mock, predicate::*};
use prost::Message;
use std::{
    collections::BTreeMap, convert::Infallible, net::SocketAddr, sync::Arc, sync::RwLock,
    time::Duration,
};
use tokio::{
    net::{TcpSocket, TcpStream},
    sync::mpsc::UnboundedReceiver,
};
use tower::{util::BoxCloneService, Service, ServiceExt};
use tower_test::mock::Handle;

pub type IngressFilterHandle =
    Handle<(ProvisionalWhitelist, SignedIngressContent), Result<(), UserError>>;
pub type QueryExecutionHandle =
    Handle<(UserQuery, Option<CertificateDelegation>), QueryExecutionResponse>;

fn setup_query_execution_mock() -> (QueryExecutionService, QueryExecutionHandle) {
    let (service, handle) = tower_test::mock::pair::<
        (UserQuery, Option<CertificateDelegation>),
        QueryExecutionResponse,
    >();

    let infallible_service =
        tower::service_fn(move |request: (UserQuery, Option<CertificateDelegation>)| {
            let mut service_clone = service.clone();
            async move {
                Ok::<QueryExecutionResponse, Infallible>(
                    service_clone
                        .ready()
                        .await
                        .expect("Mocking Infallible service. Waiting for readiness failed.")
                        .call(request)
                        .await
                        .expect(
                            "Mocking Infallible service and can therefore not return an error.",
                        ),
                )
            }
        });
    (BoxCloneService::new(infallible_service), handle)
}

#[allow(clippy::type_complexity)]
pub fn setup_ingress_filter_mock() -> (IngressFilterService, IngressFilterHandle) {
    let (service, handle) = tower_test::mock::pair::<
        (ProvisionalWhitelist, SignedIngressContent),
        Result<(), UserError>,
    >();

    let infallible_service = tower::service_fn(
        move |request: (ProvisionalWhitelist, SignedIngressContent)| {
            let mut service_clone = service.clone();
            async move {
                Ok::<Result<(), UserError>, Infallible>({
                    service_clone
                        .ready()
                        .await
                        .expect("Mocking Infallible service. Waiting for readiness failed.")
                        .call(request)
                        .await
                        .expect("Mocking Infallible service and can therefore not return an error.")
                })
            }
        },
    );
    (BoxCloneService::new(infallible_service), handle)
}

pub fn default_read_certified_state(
    _labeled_tree: &LabeledTree<()>,
) -> Option<(
    Arc<ReplicatedState>,
    ic_crypto_tree_hash::MixedHashTree,
    ic_types::consensus::certification::Certification,
)> {
    let rs: Arc<ReplicatedState> = Arc::new(ReplicatedStateBuilder::new().build());
    let mht = MixedHashTree::Leaf(Vec::new());
    let cert = Certification {
        height: Height::from(1),
        signed: Signed {
            signature: ThresholdSignature {
                signer: NiDkgId {
                    start_block_height: Height::from(0),
                    dealer_subnet: subnet_test_id(0),
                    dkg_tag: NiDkgTag::HighThreshold,
                    target_subnet: NiDkgTargetSubnet::Local,
                },
                signature: CombinedThresholdSigOf::new(CombinedThresholdSig(vec![])),
            },
            content: CertificationContent::new(CryptoHashOfPartialState::from(CryptoHash(vec![]))),
        },
    };

    Some((rs, mht, cert))
}

pub fn default_certified_state_reader(
) -> Option<Box<dyn CertifiedStateSnapshot<State = ReplicatedState> + 'static>> {
    struct FakeCertifiedStateSnapshot(Arc<ReplicatedState>, MixedHashTree, Certification);

    impl CertifiedStateSnapshot for FakeCertifiedStateSnapshot {
        type State = ReplicatedState;

        fn get_state(&self) -> &ReplicatedState {
            &self.0
        }

        fn get_height(&self) -> Height {
            self.2.height
        }

        fn read_certified_state(
            &self,
            _paths: &LabeledTree<()>,
        ) -> Option<(MixedHashTree, Certification)> {
            Some((self.1.clone(), self.2.clone()))
        }
    }

    let (state, hash_tree, certification) = default_read_certified_state(&LabeledTree::Leaf(()))?;
    Some(Box::new(FakeCertifiedStateSnapshot(
        state,
        hash_tree,
        certification,
    )))
}

pub fn default_get_latest_state() -> Labeled<Arc<ReplicatedState>> {
    let mut metadata = SystemMetadata::new(subnet_test_id(1), SubnetType::Application);

    let network_topology = NetworkTopology {
        subnets: BTreeMap::new(),
        routing_table: Arc::new(RoutingTable::default()),
        canister_migrations: Arc::new(CanisterMigrations::default()),
        nns_subnet_id: subnet_test_id(1),
        ecdsa_signing_subnets: Default::default(),
        bitcoin_mainnet_canister_id: None,
        bitcoin_testnet_canister_id: None,
    };

    metadata.network_topology = network_topology;
    metadata.batch_time = UNIX_EPOCH;

    Labeled::new(
        Height::from(1),
        Arc::new(ReplicatedState::new_from_checkpoint(
            BTreeMap::new(),
            metadata,
            CanisterQueues::default(),
            RawQueryStats::default(),
            CanisterSnapshots::default(),
        )),
    )
}

pub fn default_latest_certified_height() -> Height {
    Height::from(1)
}

/// Basic state manager with one subnet (nns) at height 1.
fn basic_state_manager_mock() -> MockStateManager {
    let mut mock_state_manager = MockStateManager::new();

    mock_state_manager
        .expect_get_latest_state()
        .returning(default_get_latest_state);

    mock_state_manager
        .expect_read_certified_state()
        .returning(default_read_certified_state);

    mock_state_manager
        .expect_read_certified_state()
        .returning(default_read_certified_state);

    mock_state_manager
        .expect_latest_certified_height()
        .returning(default_latest_certified_height);

    mock_state_manager
        .expect_get_certified_state_snapshot()
        .returning(default_certified_state_reader);

    mock_state_manager
}

// Basic mock consensus pool cache at height 1.
fn basic_consensus_pool_cache() -> MockConsensusPoolCache {
    let mut mock_consensus_cache = MockConsensusPoolCache::new();
    mock_consensus_cache
        .expect_is_replica_behind()
        .return_const(false);
    mock_consensus_cache
}

// Basic registry client mock at version 1
pub fn basic_registry_client() -> MockRegistryClient {
    let mut mock_registry_client = MockRegistryClient::new();
    mock_registry_client
        .expect_get_latest_version()
        .return_const(RegistryVersion::from(1));
    mock_registry_client
        .expect_get_value()
        .withf(move |key, version| {
            key == make_crypto_threshold_signing_pubkey_key(subnet_test_id(1)).as_str()
                && version == &RegistryVersion::from(1)
        })
        .return_const({
            let pk = PublicKeyProto {
                algorithm: AlgorithmIdProto::ThresBls12381 as i32,
                key_value: [42; ThresholdSigPublicKey::SIZE].to_vec(),
                version: 0,
                proof_data: None,
                timestamp: Some(42),
            };
            let mut v = Vec::new();
            pk.encode(&mut v).unwrap();
            Ok(Some(v))
        });
    // Needed for call requests.
    mock_registry_client
        .expect_get_value()
        .withf(move |key, version| {
            key == make_subnet_record_key(subnet_test_id(1)).as_str()
                && version == &RegistryVersion::from(1)
        })
        .return_const({
            let pk = SubnetRecord {
                max_ingress_bytes_per_message: 1000,
                max_ingress_messages_per_block: 10,
                ..Default::default()
            };
            let mut v = Vec::new();
            pk.encode(&mut v).unwrap();
            Ok(Some(v))
        });
    mock_registry_client
        .expect_get_value()
        .withf(move |key, version| {
            key == make_provisional_whitelist_record_key().as_str()
                && version == &RegistryVersion::from(1)
        })
        .return_const({
            let pk = ProvisionalWhitelistProto {
                list_type: 1,
                ..Default::default()
            };
            let mut v = Vec::new();
            pk.encode(&mut v).unwrap();
            Ok(Some(v))
        });

    mock_registry_client
}

pub async fn wait_for_status_healthy(agent: &Agent) -> Result<(), &'static str> {
    let fut = async {
        loop {
            let result = agent.status().await;
            match result {
                Ok(status) if status.replica_health_status == Some("healthy".to_string()) => {
                    break;
                }
                _ => {}
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    };
    tokio::time::timeout(Duration::from_secs(10), fut)
        .await
        .map_err(|_| "Timeout while waiting for http endpoint to be healthy")
}

// Get a free port on this host to which we can connect transport to.
pub fn get_free_localhost_socket_addr() -> SocketAddr {
    let socket = TcpSocket::new_v4().unwrap();
    socket.set_reuseport(false).unwrap();
    socket.set_reuseaddr(false).unwrap();
    socket.bind("127.0.0.1:0".parse().unwrap()).unwrap();
    socket.local_addr().unwrap()
}

pub async fn create_conn_and_send_request(addr: SocketAddr) -> (SendRequest<Body>, StatusCode) {
    let target_stream = TcpStream::connect(addr)
        .await
        .expect("tcp connection to server address failed");

    let (mut request_sender, connection) = handshake(TokioIo::new(target_stream))
        .await
        .expect("tcp client handshake failed");

    // spawn a task to poll the connection and drive the HTTP state
    tokio::spawn(async move {
        connection.await.unwrap();
    });

    let request = Request::builder()
        .method(Method::GET)
        .uri(format!("http://{}/api/v2/status", addr))
        .body(Body::from(""))
        .expect("Building the request failed.");
    let response = request_sender
        .send_request(request)
        .await
        .expect("failed to send request");

    (request_sender, response.status())
}

mock! {
    IngressPoolThrottler {}

    impl IngressPoolThrottler for IngressPoolThrottler {
        fn exceeds_threshold(&self) -> bool;
    }
}

pub struct HttpEndpointBuilder {
    rt_handle: tokio::runtime::Handle,
    config: Config,
    state_manager: Arc<dyn StateReader<State = ReplicatedState>>,
    consensus_cache: Arc<dyn ConsensusPoolCache>,
    registry_client: Arc<dyn RegistryClient>,
    delegation_from_nns: Option<CertificateDelegation>,
    pprof_collector: Arc<dyn PprofCollector>,
    tls_config: Arc<dyn TlsConfig + Send + Sync>,
}

impl HttpEndpointBuilder {
    pub fn new(rt_handle: tokio::runtime::Handle, config: Config) -> Self {
        Self {
            rt_handle,
            config,
            state_manager: Arc::new(basic_state_manager_mock()),
            consensus_cache: Arc::new(basic_consensus_pool_cache()),
            registry_client: Arc::new(basic_registry_client()),
            delegation_from_nns: None,
            pprof_collector: Arc::new(Pprof),
            tls_config: Arc::new(MockTlsConfig::new()),
        }
    }

    pub fn with_state_manager(
        mut self,
        state_manager: impl StateReader<State = ReplicatedState> + 'static,
    ) -> Self {
        self.state_manager = Arc::new(state_manager);
        self
    }

    pub fn with_consensus_cache(
        mut self,
        consensus_cache: impl ConsensusPoolCache + 'static,
    ) -> Self {
        self.consensus_cache = Arc::new(consensus_cache);
        self
    }

    pub fn with_registry_client(mut self, registry_client: impl RegistryClient + 'static) -> Self {
        self.registry_client = Arc::new(registry_client);
        self
    }

    pub fn with_delegation_from_nns(mut self, delegation_from_nns: CertificateDelegation) -> Self {
        self.delegation_from_nns.replace(delegation_from_nns);
        self
    }

    pub fn with_pprof_collector(mut self, pprof_collector: impl PprofCollector + 'static) -> Self {
        self.pprof_collector = Arc::new(pprof_collector);
        self
    }

    pub fn with_tls_config(mut self, tls_config: impl TlsConfig + Send + Sync + 'static) -> Self {
        self.tls_config = Arc::new(tls_config);
        self
    }

    pub fn run(
        self,
    ) -> (
        IngressFilterHandle,
        UnboundedReceiver<UnvalidatedArtifactMutation<IngressArtifact>>,
        QueryExecutionHandle,
    ) {
        let metrics = MetricsRegistry::new();
        let (ingress_filter, ingress_filter_handle) = setup_ingress_filter_mock();
        let (query_exe, query_exe_handler) = setup_query_execution_mock();
        // Run test on "nns" to avoid fetching root delegation
        let subnet_id = subnet_test_id(1);
        let nns_subnet_id = subnet_test_id(1);
        let node_id = node_test_id(1);

        let tls_handshake = Arc::new(MockTlsHandshake::new());
        let sig_verifier = Arc::new(temp_crypto_component_with_fake_registry(node_test_id(0)));
        let crypto = Arc::new(CryptoReturningOk::default());

        #[allow(clippy::disallowed_methods)]
        let (ingress_tx, ingress_rx) = tokio::sync::mpsc::unbounded_channel();
        let mut ingress_pool_throtller = MockIngressPoolThrottler::new();
        ingress_pool_throtller
            .expect_exceeds_threshold()
            .returning(|| false);
        start_server(
            self.rt_handle,
            &metrics,
            self.config,
            ingress_filter,
            query_exe,
            Arc::new(RwLock::new(ingress_pool_throtller)),
            ingress_tx,
            self.state_manager,
            crypto as Arc<_>,
            self.registry_client,
            self.tls_config,
            tls_handshake,
            sig_verifier,
            node_id,
            subnet_id,
            nns_subnet_id,
            no_op_logger(),
            self.consensus_cache,
            SubnetType::Application,
            MaliciousFlags::default(),
            self.delegation_from_nns,
            self.pprof_collector,
            ic_tracing::ReloadHandles::new(tracing_subscriber::reload::Layer::new(vec![]).1),
        );
        (ingress_filter_handle, ingress_rx, query_exe_handler)
    }
}
