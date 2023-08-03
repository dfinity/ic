use crossbeam::channel::Receiver;
use hyper::{
    client::conn::{handshake, SendRequest},
    Body, Method, Request, StatusCode,
};
use ic_agent::Agent;
use ic_config::http_handler::Config;
use ic_crypto_tls_interfaces_mocks::MockTlsHandshake;
use ic_crypto_tree_hash::{LabeledTree, MixedHashTree};
use ic_error_types::UserError;
use ic_http_endpoints_public::start_server;
use ic_interfaces::{
    artifact_pool::UnvalidatedArtifact,
    consensus_pool::ConsensusPoolCache,
    execution_environment::{IngressFilterService, QueryExecutionService},
    ingress_pool::IngressPoolThrottler,
    time_source::SysTimeSource,
};
use ic_interfaces_registry::RegistryClient;
use ic_interfaces_registry_mocks::MockRegistryClient;
use ic_interfaces_state_manager::{CertifiedStateReader, Labeled, StateReader};
use ic_interfaces_state_manager_mocks::MockStateManager;
use ic_logger::replica_logger::no_op_logger;
use ic_metrics::MetricsRegistry;
use ic_pprof::PprofCollector;
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
use ic_replicated_state::{CanisterQueues, NetworkTopology, ReplicatedState, SystemMetadata};
use ic_test_utilities::{
    consensus::MockConsensusCache,
    crypto::temp_crypto_component_with_fake_registry,
    mock_time,
    state::ReplicatedStateBuilder,
    types::ids::{node_test_id, subnet_test_id},
};
use ic_types::{
    batch::{BatchPayload, ValidationContext},
    consensus::{
        certification::{Certification, CertificationContent},
        dkg::Dealings,
        Block, Payload, Rank,
    },
    crypto::{
        threshold_sig::{
            ni_dkg::{NiDkgId, NiDkgTag, NiDkgTargetSubnet},
            ThresholdSigPublicKey,
        },
        CombinedThresholdSig, CombinedThresholdSigOf, CryptoHash, CryptoHashOf, Signed,
    },
    malicious_flags::MaliciousFlags,
    messages::{
        CertificateDelegation, HttpQueryResponse, SignedIngress, SignedIngressContent, UserQuery,
    },
    signature::ThresholdSignature,
    CryptoHashOfPartialState, Height, RegistryVersion,
};
use mockall::{mock, predicate::*};
use prost::Message;
use std::{collections::BTreeMap, net::SocketAddr, sync::Arc, sync::RwLock, time::Duration};
use tokio::net::{TcpSocket, TcpStream};
use tower::{util::BoxCloneService, Service, ServiceExt};
use tower_test::mock::Handle;

pub type IngressFilterHandle =
    Handle<(ProvisionalWhitelist, SignedIngressContent), Result<(), UserError>>;
pub type QueryExecutionHandle =
    Handle<(UserQuery, Option<CertificateDelegation>), HttpQueryResponse>;

fn setup_query_execution_mock() -> (QueryExecutionService, QueryExecutionHandle) {
    let (service, handle) =
        tower_test::mock::pair::<(UserQuery, Option<CertificateDelegation>), HttpQueryResponse>();

    let infallible_service =
        tower::service_fn(move |request: (UserQuery, Option<CertificateDelegation>)| {
            let mut service_clone = service.clone();
            async move {
                Ok::<HttpQueryResponse, std::convert::Infallible>({
                    service_clone
                        .ready()
                        .await
                        .expect("Mocking Infallible service. Waiting for readiness failed.")
                        .call(request)
                        .await
                        .expect("Mocking Infallible service and can therefore not return an error.")
                })
            }
        });
    (BoxCloneService::new(infallible_service), handle)
}

#[allow(clippy::type_complexity)]
fn setup_ingress_filter_mock() -> (IngressFilterService, IngressFilterHandle) {
    let (service, handle) = tower_test::mock::pair::<
        (ProvisionalWhitelist, SignedIngressContent),
        Result<(), UserError>,
    >();

    let infallible_service = tower::service_fn(
        move |request: (ProvisionalWhitelist, SignedIngressContent)| {
            let mut service_clone = service.clone();
            async move {
                Ok::<Result<(), UserError>, std::convert::Infallible>({
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
) -> Option<Box<dyn CertifiedStateReader<State = ReplicatedState> + 'static>> {
    struct FakeCertifiedStateReader(Arc<ReplicatedState>, MixedHashTree, Certification);

    impl CertifiedStateReader for FakeCertifiedStateReader {
        type State = ReplicatedState;

        fn get_state(&self) -> &ReplicatedState {
            &self.0
        }

        fn read_certified_state(
            &self,
            _paths: &LabeledTree<()>,
        ) -> Option<(MixedHashTree, Certification)> {
            Some((self.1.clone(), self.2.clone()))
        }
    }

    let (state, hash_tree, certification) = default_read_certified_state(&LabeledTree::Leaf(()))?;
    Some(Box::new(FakeCertifiedStateReader(
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
    metadata.batch_time = mock_time();

    Labeled::new(
        Height::from(1),
        Arc::new(ReplicatedState::new_from_checkpoint(
            BTreeMap::new(),
            metadata,
            CanisterQueues::default(),
        )),
    )
}

pub fn default_latest_certified_height() -> Height {
    Height::from(1)
}

/// Basic state manager with one subnet (nns) at height 1.
pub fn basic_state_manager_mock() -> MockStateManager {
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
        .expect_get_certified_state_reader()
        .returning(default_certified_state_reader);

    mock_state_manager
}

// Basic mock consensus pool cache at height 1.
pub fn basic_consensus_pool_cache() -> MockConsensusCache {
    let mut mock_consensus_cache = MockConsensusCache::new();
    mock_consensus_cache
        .expect_finalized_block()
        .returning(move || {
            Block::new(
                CryptoHashOf::from(CryptoHash(Vec::new())),
                Payload::new(
                    ic_types::crypto::crypto_hash,
                    (
                        BatchPayload::default(),
                        Dealings::new_empty(Height::from(1)),
                        None,
                    )
                        .into(),
                ),
                Height::from(1),
                Rank(456),
                ValidationContext {
                    registry_version: RegistryVersion::from(1),
                    certified_height: Height::from(1),
                    time: mock_time(),
                },
            )
        });
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

    let (mut request_sender, connection) = handshake(target_stream)
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
pub fn start_http_endpoint(
    rt: tokio::runtime::Handle,
    config: Config,
    state_manager: Arc<dyn StateReader<State = ReplicatedState>>,
    consensus_cache: Arc<dyn ConsensusPoolCache>,
    registry_client: Arc<dyn RegistryClient>,
    pprof_collector: Arc<dyn PprofCollector>,
) -> (
    IngressFilterHandle,
    Receiver<UnvalidatedArtifact<SignedIngress>>,
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
    let time_source = Arc::new(SysTimeSource::new());
    let (ingress_tx, ingress_rx) = crossbeam::channel::unbounded();
    let mut ingress_pool_throtller = MockIngressPoolThrottler::new();
    ingress_pool_throtller
        .expect_exceeds_threshold()
        .returning(|| false);
    start_server(
        rt,
        &metrics,
        config,
        ingress_filter,
        query_exe,
        Arc::new(RwLock::new(ingress_pool_throtller)),
        ingress_tx,
        time_source,
        state_manager,
        registry_client,
        tls_handshake,
        sig_verifier,
        node_id,
        subnet_id,
        nns_subnet_id,
        no_op_logger(),
        consensus_cache,
        SubnetType::Application,
        MaliciousFlags::default(),
        pprof_collector,
    );
    (ingress_filter_handle, ingress_rx, query_exe_handler)
}
