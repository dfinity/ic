use axum::body::Body;
use hyper::{
    client::conn::http1::{handshake, SendRequest},
    Method, Request, StatusCode,
};
use hyper_util::rt::TokioIo;
use ic_config::http_handler::Config;
use ic_crypto_tls_interfaces::TlsConfig;
use ic_crypto_tls_interfaces_mocks::MockTlsConfig;
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
    messages::{CertificateDelegation, MessageId, Query, SignedIngress, SignedIngressContent},
    signature::ThresholdSignature,
    time::UNIX_EPOCH,
    CryptoHashOfPartialState, Height, RegistryVersion,
};
use mockall::{mock, predicate::*};
use prost::Message;
use std::{collections::BTreeMap, convert::Infallible, net::SocketAddr, sync::Arc, sync::RwLock};
use tokio::{
    net::{TcpSocket, TcpStream},
    sync::{
        mpsc::{channel, unbounded_channel, Sender, UnboundedReceiver},
        watch,
    },
};
use tower::{util::BoxCloneService, Service, ServiceExt};
use tower_test::mock::Handle;

pub type IngressFilterHandle =
    Handle<(ProvisionalWhitelist, SignedIngressContent), Result<(), UserError>>;
pub type QueryExecutionHandle =
    Handle<(Query, Option<CertificateDelegation>), QueryExecutionResponse>;

fn setup_query_execution_mock() -> (QueryExecutionService, QueryExecutionHandle) {
    let (service, handle) =
        tower_test::mock::pair::<(Query, Option<CertificateDelegation>), QueryExecutionResponse>();

    let infallible_service =
        tower::service_fn(move |request: (Query, Option<CertificateDelegation>)| {
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
        subnets: Default::default(),
        routing_table: Arc::new(RoutingTable::default()),
        canister_migrations: Arc::new(CanisterMigrations::default()),
        nns_subnet_id: subnet_test_id(1),
        idkg_signing_subnets: Default::default(),
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

// basic ingress pool throttler mock
fn basic_ingress_pool_throttler() -> MockIngressPoolThrottler {
    let mut mock_ingress_pool_throttler = MockIngressPoolThrottler::new();
    mock_ingress_pool_throttler
        .expect_exceeds_threshold()
        .return_const(false);
    mock_ingress_pool_throttler
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
    pub IngressPoolThrottler {}

    impl IngressPoolThrottler for IngressPoolThrottler {
        fn exceeds_threshold(&self) -> bool;
    }
}

pub struct HttpEndpointHandles {
    pub ingress_filter: IngressFilterHandle,
    pub ingress_rx: UnboundedReceiver<UnvalidatedArtifactMutation<SignedIngress>>,
    pub query_execution: QueryExecutionHandle,
    pub terminal_state_ingress_messages: Sender<(MessageId, Height)>,
    pub certified_height_watcher: watch::Sender<Height>,
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
    certified_height: Option<Height>,
    ingress_pool_throttler: Arc<RwLock<dyn IngressPoolThrottler + Send + Sync>>,
}

impl HttpEndpointBuilder {
    pub fn new(rt_handle: tokio::runtime::Handle, config: Config) -> Self {
        Self {
            rt_handle,
            config,
            state_manager: Arc::new(basic_state_manager_mock()),
            consensus_cache: Arc::new(basic_consensus_pool_cache()),
            registry_client: Arc::new(basic_registry_client()),
            ingress_pool_throttler: Arc::new(RwLock::new(basic_ingress_pool_throttler())),
            delegation_from_nns: None,
            pprof_collector: Arc::new(Pprof),
            tls_config: Arc::new(MockTlsConfig::new()),
            certified_height: None,
        }
    }

    pub fn with_state_manager(
        mut self,
        state_manager: impl StateReader<State = ReplicatedState> + 'static,
    ) -> Self {
        self.state_manager = Arc::new(state_manager);
        self
    }

    pub fn with_certified_height(mut self, height: Height) -> Self {
        self.certified_height = Some(height);
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

    pub fn with_ingress_pool_throttler(
        mut self,
        ingress_pool_throttler: Arc<RwLock<dyn IngressPoolThrottler + Send + Sync>>,
    ) -> Self {
        self.ingress_pool_throttler = ingress_pool_throttler;
        self
    }

    pub fn run(self) -> HttpEndpointHandles {
        let metrics = MetricsRegistry::new();

        let (ingress_filter, ingress_filter_handle) = setup_ingress_filter_mock();
        let (query_exe, query_exe_handler) = setup_query_execution_mock();
        let (certified_height_watcher_tx, certified_height_watcher_rx) =
            watch::channel(self.certified_height.unwrap_or_default());

        let (terminal_state_ingress_messages_tx, terminal_state_ingress_messages_rx) = channel(100);

        // Run test on "nns" to avoid fetching root delegation
        let subnet_id = subnet_test_id(1);
        let nns_subnet_id = subnet_test_id(1);
        let node_id = node_test_id(1);

        let sig_verifier = Arc::new(temp_crypto_component_with_fake_registry(node_test_id(0)));
        let crypto = Arc::new(CryptoReturningOk::default());

        #[allow(clippy::disallowed_methods)]
        let (ingress_tx, ingress_rx) = unbounded_channel();

        let log = no_op_logger();

        start_server(
            self.rt_handle,
            &metrics,
            self.config,
            ingress_filter,
            query_exe,
            self.ingress_pool_throttler,
            ingress_tx,
            self.state_manager,
            crypto as Arc<_>,
            self.registry_client,
            self.tls_config,
            sig_verifier,
            node_id,
            subnet_id,
            nns_subnet_id,
            log,
            self.consensus_cache,
            SubnetType::Application,
            MaliciousFlags::default(),
            self.delegation_from_nns,
            self.pprof_collector,
            ic_tracing::ReloadHandles::new(tracing_subscriber::reload::Layer::new(vec![]).1),
            certified_height_watcher_rx,
            terminal_state_ingress_messages_rx,
            true,
        );

        HttpEndpointHandles {
            ingress_filter: ingress_filter_handle,
            ingress_rx,
            query_execution: query_exe_handler,
            terminal_state_ingress_messages: terminal_state_ingress_messages_tx,
            certified_height_watcher: certified_height_watcher_tx,
        }
    }
}

pub mod test_agent {
    use super::*;
    use ic_crypto_tree_hash::{Label, Path};

    use ic_types::{
        messages::{
            Blob, HttpCallContent, HttpCanisterUpdate, HttpQueryContent, HttpReadState,
            HttpReadStateContent, HttpRequestEnvelope, HttpUserQuery, SignedIngress,
        },
        time::current_time,
        PrincipalId,
    };
    use reqwest::header::CONTENT_TYPE;
    use serde_cbor::Value as CBOR;
    use std::time::Duration;

    const INGRESS_EXPIRY_DURATION: Duration = Duration::from_secs(300);
    const METHOD_NAME: &str = "test";
    const SENDER: PrincipalId = PrincipalId::new_anonymous();
    const ARG: Vec<u8> = vec![];
    pub const APPLICATION_CBOR: &str = "application/cbor";

    pub async fn wait_for_status_healthy(addr: &SocketAddr) -> Result<(), &'static str> {
        let fut = async {
            loop {
                let url = format!("http://{}/api/v2/status", addr);

                let response = reqwest::Client::new()
                    .get(url)
                    .header(CONTENT_TYPE, APPLICATION_CBOR)
                    .send()
                    .await;

                let Ok(response) = response else {
                    tokio::time::sleep(Duration::from_millis(250)).await;
                    continue;
                };

                if response.status() != StatusCode::OK {
                    tokio::time::sleep(Duration::from_millis(250)).await;
                    continue;
                }

                let Ok(response) = response.bytes().await else {
                    tokio::time::sleep(Duration::from_millis(250)).await;
                    continue;
                };

                let replica_status = serde_cbor::from_slice::<CBOR>(&response)
                    .expect("Status endpoint is a valid CBOR.");

                if let CBOR::Map(map) = replica_status {
                    if let Some(CBOR::Text(status)) =
                        map.get(&CBOR::Text("replica_health_status".to_string()))
                    {
                        if status == "healthy" {
                            return;
                        }
                    }
                }

                tokio::time::sleep(Duration::from_millis(250)).await;
            }
        };
        tokio::time::timeout(Duration::from_secs(10), fut)
            .await
            .map_err(|_| "Timeout while waiting for http endpoint to be healthy")
    }

    #[derive(Copy, Clone, Debug)]
    pub enum Call {
        V2,
        V3,
    }

    #[derive(Clone, Debug)]
    pub struct IngressMessage {
        canister_id: PrincipalId,
        effective_canister_id: PrincipalId,
        ingress_expiry: u64,
        method_name: String,
    }

    impl Default for IngressMessage {
        fn default() -> Self {
            Self {
                canister_id: PrincipalId::default(),
                effective_canister_id: PrincipalId::default(),
                ingress_expiry: (current_time() + INGRESS_EXPIRY_DURATION)
                    .as_nanos_since_unix_epoch(),
                method_name: METHOD_NAME.to_string(),
            }
        }
    }

    impl IngressMessage {
        pub fn with_canister_id(
            mut self,
            canister_id: PrincipalId,
            effective_canister_id: PrincipalId,
        ) -> Self {
            self.canister_id = canister_id;
            self.effective_canister_id = effective_canister_id;
            self
        }
        pub fn with_ingress_expiry(mut self, ingress_expiry: Duration) -> Self {
            self.ingress_expiry = (current_time() + ingress_expiry).as_nanos_since_unix_epoch();
            self
        }
        pub fn with_method_name(mut self, method_name: String) -> Self {
            self.method_name = method_name;
            self
        }

        fn envelope(&self) -> HttpRequestEnvelope<HttpCallContent> {
            let call_content = HttpCallContent::Call {
                update: HttpCanisterUpdate {
                    canister_id: Blob(self.canister_id.into_vec()),
                    method_name: self.method_name.clone(),
                    ingress_expiry: self.ingress_expiry,
                    arg: Blob(ARG),
                    sender: Blob(SENDER.into_vec()),
                    nonce: None,
                },
            };

            HttpRequestEnvelope {
                content: call_content,
                sender_pubkey: None,
                sender_sig: None,
                sender_delegation: None,
            }
        }

        pub fn message_id(&self) -> MessageId {
            let signed_ingress: SignedIngress = self.envelope().try_into().unwrap();
            signed_ingress.id()
        }
    }

    impl Call {
        pub async fn call(
            &self,
            addr: SocketAddr,
            ingress_message: IngressMessage,
        ) -> reqwest::Response {
            let envelope = ingress_message.envelope();
            let body = serde_cbor::to_vec(&envelope).unwrap();

            let version = match self {
                Call::V2 => "v2",
                Call::V3 => "v3",
            };

            let url = format!(
                "http://{}/api/{}/canister/{}/call",
                addr, version, ingress_message.effective_canister_id
            );

            reqwest::Client::new()
                .post(url)
                .body(body)
                .header(CONTENT_TYPE, APPLICATION_CBOR)
                .send()
                .await
                .unwrap()
        }
    }

    #[derive(Default)]
    pub struct Query {
        canister_id: PrincipalId,
        effective_canister_id: PrincipalId,
    }

    impl Query {
        pub fn new(canister_id: PrincipalId, effective_canister_id: PrincipalId) -> Self {
            Self {
                canister_id,
                effective_canister_id,
            }
        }

        pub async fn query(self, addr: SocketAddr) -> reqwest::Response {
            let ingress_expiry =
                (current_time() + INGRESS_EXPIRY_DURATION).as_nanos_since_unix_epoch();

            let call_content = HttpQueryContent::Query {
                query: HttpUserQuery {
                    canister_id: Blob(self.canister_id.into_vec()),
                    method_name: METHOD_NAME.to_string(),
                    arg: Blob(ARG),
                    sender: Blob(SENDER.into_vec()),
                    ingress_expiry,
                    nonce: None,
                },
            };

            let envelope = HttpRequestEnvelope {
                content: call_content,
                sender_pubkey: None,
                sender_sig: None,
                sender_delegation: None,
            };

            let body = serde_cbor::to_vec(&envelope).unwrap();
            let url = format!(
                "http://{}/api/v2/canister/{}/query",
                addr, self.effective_canister_id
            );

            reqwest::Client::new()
                .post(url)
                .body(body)
                .header(CONTENT_TYPE, APPLICATION_CBOR)
                .send()
                .await
                .unwrap()
        }
    }

    pub struct CanisterReadState {
        paths: Vec<Path>,
        effective_canister_id: PrincipalId,
    }

    impl Default for CanisterReadState {
        fn default() -> Self {
            Self {
                paths: vec![Path::from(Label::from("time"))],
                effective_canister_id: PrincipalId::default(),
            }
        }
    }

    impl CanisterReadState {
        pub fn new(paths: Vec<Path>, effective_canister_id: PrincipalId) -> Self {
            Self {
                paths,
                effective_canister_id,
            }
        }

        pub async fn read_state(self, addr: SocketAddr) -> reqwest::Response {
            let ingress_expiry =
                (current_time() + INGRESS_EXPIRY_DURATION).as_nanos_since_unix_epoch();

            let call_content = HttpReadStateContent::ReadState {
                read_state: HttpReadState {
                    paths: self.paths,
                    sender: Blob(SENDER.into_vec()),
                    ingress_expiry,
                    nonce: None,
                },
            };

            let envelope = HttpRequestEnvelope {
                content: call_content,
                sender_pubkey: None,
                sender_sig: None,
                sender_delegation: None,
            };

            let body = serde_cbor::to_vec(&envelope).unwrap();
            let url = format!(
                "http://{}/api/v2/canister/{}/read_state",
                addr, self.effective_canister_id
            );

            reqwest::Client::new()
                .post(url)
                .body(body)
                .header(CONTENT_TYPE, APPLICATION_CBOR)
                .send()
                .await
                .unwrap()
        }
    }
}
