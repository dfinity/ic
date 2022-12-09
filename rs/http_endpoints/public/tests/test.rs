use crate::common::{
    basic_consensus_pool_cache, basic_registry_client, basic_state_manager_mock,
    setup_ingress_filter_mock, setup_ingress_ingestion_mock, setup_query_execution_mock,
    IngressFilterHandle, IngressIngestionHandle, QueryExecutionHandle,
};
use hyper::{
    client::{connect::HttpConnector, Client},
    Body, Error, Method, Request, Response,
};
use ic_agent::{
    agent::{http_transport::ReqwestHttpReplicaV2Transport, QueryBuilder, UpdateBuilder},
    agent_error::HttpErrorPayload,
    export::Principal,
    hash_tree::Label,
    identity::AnonymousIdentity,
    Agent, AgentError,
};
use ic_config::http_handler::Config;
use ic_crypto_tls_interfaces_mocks::MockTlsHandshake;
use ic_crypto_tree_hash::MixedHashTree;
use ic_http_endpoints_public::{start_server, MAX_OUTSTANDING_CONNECTIONS};
use ic_interfaces::consensus_pool::ConsensusPoolCache;
use ic_interfaces_registry::RegistryClient;
use ic_interfaces_registry_mocks::MockRegistryClient;
use ic_interfaces_state_manager::{Labeled, StateReader};
use ic_interfaces_state_manager_mocks::MockStateManager;
use ic_logger::replica_logger::no_op_logger;
use ic_metrics::MetricsRegistry;
use ic_protobuf::registry::crypto::v1::{
    AlgorithmId as AlgorithmIdProto, PublicKey as PublicKeyProto,
};
use ic_registry_keys::make_crypto_threshold_signing_pubkey_key;
use ic_registry_routing_table::{CanisterMigrations, RoutingTable};
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::{
    BitcoinState, CanisterQueues, NetworkTopology, ReplicatedState, SystemMetadata,
};
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
    messages::{Blob, HttpQueryResponse, HttpQueryResponseReply},
    signature::ThresholdSignature,
    CryptoHashOfPartialState, Height, RegistryVersion,
};
use prost::Message;
use std::{
    collections::BTreeMap,
    net::SocketAddr,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};
use tokio::{
    net::TcpSocket,
    runtime::Runtime,
    time::{sleep, Duration},
};

mod common;

// Get a free port on this host to which we can connect transport to.
fn get_free_localhost_socket_addr() -> std::io::Result<SocketAddr> {
    let socket = TcpSocket::new_v4()?;
    socket.set_reuseport(false)?;
    socket.set_reuseaddr(false)?;
    socket.bind("127.0.0.1:0".parse().unwrap())?;
    socket.local_addr()
}

async fn send_request(
    client: &Client<HttpConnector, Body>,
    addr: SocketAddr,
) -> Result<Response<Body>, Error> {
    let req = Request::builder()
        .method(Method::GET)
        .uri(format!("http://{}", addr))
        .body(Body::from(""))
        .expect("Building the request failed.");

    client.request(req).await
}

async fn create_client_and_send_request(
    addr: SocketAddr,
) -> Result<Client<HttpConnector, Body>, Error> {
    let client: Client<HttpConnector, Body> = Client::builder().http2_only(true).build_http();

    send_request(&client, addr).await?;
    Ok(client)
}

fn start_http_endpoint(
    rt: tokio::runtime::Handle,
    addr: SocketAddr,
    state_manager: Arc<dyn StateReader<State = ReplicatedState>>,
    consensus_cache: Arc<dyn ConsensusPoolCache>,
    registry_client: Arc<dyn RegistryClient>,
) -> (
    IngressFilterHandle,
    IngressIngestionHandle,
    QueryExecutionHandle,
) {
    let metrics = MetricsRegistry::new();
    let config = Config {
        listen_addr: addr,
        ..Default::default()
    };
    let (ingress_filter, ingress_filter_handle) = setup_ingress_filter_mock();
    let (ingress_ingestion, ingress_ingestion_handler) = setup_ingress_ingestion_mock();
    let (query_exe, query_exe_handler) = setup_query_execution_mock();
    // Run test on "nns" to avoid fetching root delegation
    let subnet_id = subnet_test_id(1);
    let nns_subnet_id = subnet_test_id(1);

    let tls_handshake = Arc::new(MockTlsHandshake::new());
    let sig_verifier = Arc::new(temp_crypto_component_with_fake_registry(node_test_id(0)));
    start_server(
        rt,
        metrics,
        config,
        ingress_filter,
        ingress_ingestion,
        query_exe,
        state_manager,
        registry_client,
        tls_handshake,
        sig_verifier,
        subnet_id,
        nns_subnet_id,
        no_op_logger(),
        consensus_cache,
        SubnetType::Application,
        MaliciousFlags::default(),
    );
    (
        ingress_filter_handle,
        ingress_ingestion_handler,
        query_exe_handler,
    )
}

#[test]
fn test_healthy_behind() {
    let rt = Runtime::new().unwrap();
    let addr = get_free_localhost_socket_addr().expect("No ports available on host");
    let certified_state_height = Height::from(1);
    let consensus_height = Height::from(certified_state_height.get() + 25);

    let mut mock_state_manager = MockStateManager::new();
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
    mock_state_manager
        .expect_get_latest_state()
        .returning(move || {
            let mut metadata = SystemMetadata::new(subnet_test_id(1), SubnetType::Application);
            metadata.batch_time = mock_time();
            Labeled::new(
                certified_state_height,
                Arc::new(ReplicatedState::new_from_checkpoint(
                    BTreeMap::new(),
                    metadata,
                    CanisterQueues::default(),
                    Vec::new(),
                    BitcoinState::default(),
                )),
            )
        });
    mock_state_manager
        .expect_latest_certified_height()
        .returning(move || certified_state_height);
    mock_state_manager
        .expect_read_certified_state()
        .returning(move |_labeled_tree| {
            let rs: Arc<ReplicatedState> = Arc::new(ReplicatedStateBuilder::new().build());
            let mht = MixedHashTree::Leaf(Vec::new());
            let cert = Certification {
                height: certified_state_height,
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
                    content: CertificationContent::new(CryptoHashOfPartialState::from(CryptoHash(
                        vec![],
                    ))),
                },
            };
            Some((rs, mht, cert))
        });

    // We use this atomic to make sure that the health transistion is from healthy -> certified_state_behind
    let healthy = Arc::new(AtomicBool::new(false));
    let healthy_c = healthy.clone();
    let mut mock_consensus_cache = MockConsensusCache::new();
    mock_consensus_cache
        .expect_finalized_block()
        .returning(move || {
            // The last certified height seen in a block is used to determine if
            // replica is behind.
            let certified_height = if !healthy_c.load(Ordering::SeqCst) {
                certified_state_height
            } else {
                consensus_height
            };
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
                Height::from(224),
                Rank(456),
                ValidationContext {
                    registry_version: RegistryVersion::from(99),
                    certified_height,
                    time: mock_time(),
                },
            )
        });

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

    start_http_endpoint(
        rt.handle().clone(),
        addr,
        Arc::new(mock_state_manager),
        Arc::new(mock_consensus_cache),
        Arc::new(mock_registry_client),
    );

    let agent = Agent::builder()
        .with_transport(ReqwestHttpReplicaV2Transport::create(format!("http://{}", addr)).unwrap())
        .build()
        .unwrap();

    rt.block_on(async {
        loop {
            match agent.status().await {
                Ok(status) if status.replica_health_status == Some("healthy".to_string()) => break,
                _ => {
                    sleep(Duration::from_millis(250)).await;
                }
            }
        }
    });
    healthy.store(true, Ordering::SeqCst);

    let status = rt.block_on(agent.status()).unwrap();
    assert_eq!(
        status.replica_health_status,
        Some("certified_state_behind".to_string())
    );
}

// Check spec enforcement for read_state requests. https://internetcomputer.org/docs/current/references/ic-interface-spec#http-read-state
// Paths containing `.../canister_id/..` require the `canister_id` to be the same as the effective canister id
// specified through the url `/api/v2/canister/<effective_canister_id>/read_state`. Read state requests that request paths
// with different canister ids should be rejected.
#[test]
fn test_unathorized_controller() {
    let rt = Runtime::new().unwrap();
    let addr = get_free_localhost_socket_addr().expect("No ports available on host");

    let mock_state_manager = basic_state_manager_mock();
    let mock_consensus_cache = basic_consensus_pool_cache();
    let mock_registry_client = basic_registry_client();

    start_http_endpoint(
        rt.handle().clone(),
        addr,
        Arc::new(mock_state_manager),
        Arc::new(mock_consensus_cache),
        Arc::new(mock_registry_client),
    );

    let agent = Agent::builder()
        .with_transport(ReqwestHttpReplicaV2Transport::create(format!("http://{}", addr)).unwrap())
        .build()
        .unwrap();

    let canister1 = Principal::from_text("223xb-saaaa-aaaaf-arlqa-cai").unwrap();
    let canister2 = Principal::from_text("224lq-3aaaa-aaaaf-ase7a-cai").unwrap();
    let paths: Vec<Vec<Label>> = vec![vec![
        "canister".into(),
        canister2.into(),
        "metadata".into(),
        "time".into(),
    ]];

    let expected_error = AgentError::HttpError(HttpErrorPayload {
        status: 400,
        content_type: None,
        content: format!(
            "Effective canister id in URL {} does not match requested canister id: {}.",
            canister1, canister2
        )
        .as_bytes()
        .to_vec(),
    });
    rt.block_on(async {
        loop {
            match agent.read_state_raw(paths.clone(), canister1).await {
                Err(err) => {
                    if err == expected_error {
                        break;
                    }
                    println!("Received unexpeceted error: {:?}", err);
                    sleep(Duration::from_millis(250)).await
                }
                Ok(r) => {
                    println!("Received unexpeceted success: {:?}", r);
                    sleep(Duration::from_millis(250)).await
                }
            }
        }
    });
}

// Test that that http endpoint rejects queries with mismatch between canister id an effective canister id.
#[test]
fn test_unathorized_query() {
    let rt = Runtime::new().unwrap();
    let addr = get_free_localhost_socket_addr().expect("No ports available on host");

    let mock_state_manager = basic_state_manager_mock();
    let mock_consensus_cache = basic_consensus_pool_cache();
    let mock_registry_client = basic_registry_client();

    let (_, _, mut query_handler) = start_http_endpoint(
        rt.handle().clone(),
        addr,
        Arc::new(mock_state_manager),
        Arc::new(mock_consensus_cache),
        Arc::new(mock_registry_client),
    );

    let agent = Agent::builder()
        .with_transport(ReqwestHttpReplicaV2Transport::create(format!("http://{}", addr)).unwrap())
        .build()
        .unwrap();

    let canister1 = Principal::from_text("223xb-saaaa-aaaaf-arlqa-cai").unwrap();
    let canister2 = Principal::from_text("224lq-3aaaa-aaaaf-ase7a-cai").unwrap();

    // Query mock that returns empty Ok("success") response.
    rt.spawn(async move {
        loop {
            let (_, resp) = query_handler.next_request().await.unwrap();
            resp.send_response(HttpQueryResponse::Replied {
                reply: HttpQueryResponseReply {
                    arg: Blob("success".into()),
                },
            })
        }
    });

    // Query call tests.
    let mut query_tests = Vec::new();

    // Valid query call with canister_id = effective_canister_id
    let query = QueryBuilder::new(&agent, canister1, "test".to_string())
        .with_effective_canister_id(canister1)
        .with_arg(Vec::new())
        .sign()
        .unwrap();
    let expected_resp = "success".into();
    query_tests.push((query, Ok(expected_resp)));

    // Invalid query call with canister_id != effective_canister_id
    let query = QueryBuilder::new(&agent, canister1, "test".to_string())
        .with_effective_canister_id(canister2)
        .with_arg(Vec::new())
        .sign()
        .unwrap();
    let expected_resp = AgentError::HttpError(HttpErrorPayload {
        status: 400,
        content_type: None,
        content: format!(
            "Specified CanisterId {} does not match effective canister id in URL {}",
            canister1, canister2
        )
        .as_bytes()
        .to_vec(),
    });
    query_tests.push((query, Err(expected_resp)));

    rt.block_on(async {
        for (query, expected_resp) in query_tests {
            loop {
                let q = query.clone();
                let resp = agent
                    .query_signed(q.effective_canister_id, q.signed_query)
                    .await;
                if resp == expected_resp {
                    break;
                }
                println!("Received unexpeceted response: {:?}", resp);
                sleep(Duration::from_millis(250)).await
            }
        }
    });
}

// Test that that http endpoint rejects calls with mismatch between canister id an effective canister id.
#[test]
fn test_unathorized_call() {
    let rt = Runtime::new().unwrap();
    let addr = get_free_localhost_socket_addr().expect("No ports available on host");

    let mock_state_manager = basic_state_manager_mock();
    let mock_consensus_cache = basic_consensus_pool_cache();
    let mock_registry_client = basic_registry_client();

    let (mut ingress_filter, mut ingress_sender, _) = start_http_endpoint(
        rt.handle().clone(),
        addr,
        Arc::new(mock_state_manager),
        Arc::new(mock_consensus_cache),
        Arc::new(mock_registry_client),
    );

    let agent = Agent::builder()
        .with_identity(AnonymousIdentity)
        .with_transport(ReqwestHttpReplicaV2Transport::create(format!("http://{}", addr)).unwrap())
        .build()
        .unwrap();

    let canister1 = Principal::from_text("223xb-saaaa-aaaaf-arlqa-cai").unwrap();
    let canister2 = Principal::from_text("224lq-3aaaa-aaaaf-ase7a-cai").unwrap();

    // Ingress sender mock that returns empty Ok(()) response.
    rt.spawn(async move {
        loop {
            let (_, resp) = ingress_sender.next_request().await.unwrap();
            resp.send_response(Ok(()))
        }
    });

    // Ingress filter mock that returns empty Ok(()) response.
    rt.spawn(async move {
        loop {
            let (_, resp) = ingress_filter.next_request().await.unwrap();
            resp.send_response(Ok(()))
        }
    });

    // Query call tests.
    let mut update_tests = Vec::new();

    // Valid update call with canister_id = effective_canister_id
    let update = UpdateBuilder::new(&agent, canister1, "test".to_string())
        .with_effective_canister_id(canister1)
        .with_arg(Vec::new())
        .sign()
        .unwrap();
    update_tests.push((update.clone(), Ok(update.request_id)));

    // Invalid update call with canister_id != effective_canister_id
    let update = UpdateBuilder::new(&agent, canister1, "test".to_string())
        .with_effective_canister_id(canister2)
        .with_arg(Vec::new())
        .sign()
        .unwrap();
    let expected_resp = AgentError::HttpError(HttpErrorPayload {
        status: 400,
        content_type: None,
        content: format!(
            "Specified CanisterId {} does not match effective canister id in URL {}",
            canister1, canister2
        )
        .as_bytes()
        .to_vec(),
    });
    update_tests.push((update, Err(expected_resp)));

    // Update call to mgmt canister with different effective canister id.
    let update = UpdateBuilder::new(&agent, Principal::management_canister(), "test".to_string())
        .with_effective_canister_id(canister2)
        .with_arg(Vec::new())
        .sign()
        .unwrap();
    update_tests.push((update.clone(), Ok(update.request_id)));

    // Update call to mgmt canister.
    let update = UpdateBuilder::new(&agent, Principal::management_canister(), "test".to_string())
        .with_effective_canister_id(Principal::management_canister())
        .with_arg(Vec::new())
        .sign()
        .unwrap();
    update_tests.push((update.clone(), Ok(update.request_id)));

    rt.block_on(async {
        for (update, expected_resp) in update_tests {
            loop {
                let u = update.clone();
                let resp = agent
                    .update_signed(u.effective_canister_id, u.signed_update)
                    .await;
                if resp == expected_resp {
                    break;
                }
                println!("Received unexpeceted response: {:?}", resp);
                sleep(Duration::from_millis(250)).await
            }
        }
    });
}

/// Once we have reached the number of outstanding connection, new connections should be refused.
#[tokio::test]
#[ignore]
async fn test_max_outstanding_conections() {
    let rt_handle = tokio::runtime::Handle::current();
    let addr = get_free_localhost_socket_addr().unwrap();

    let mock_state_manager = basic_state_manager_mock();
    let mock_consensus_cache = basic_consensus_pool_cache();
    let mock_registry_client = basic_registry_client();

    start_http_endpoint(
        rt_handle.clone(),
        addr,
        Arc::new(mock_state_manager),
        Arc::new(mock_consensus_cache),
        Arc::new(mock_registry_client),
    );

    // it is important to keep around the http clients so the connections don't get closed
    let mut clients = vec![];
    for _i in 0..MAX_OUTSTANDING_CONNECTIONS {
        let c = create_client_and_send_request(addr)
            .await
            .expect("Creating a new http client/tcp connection and sending a message failed.");
        clients.push(c);
    }
    // Check we hit the limit of live TCP connections by expecting a failure when yet
    // another request is send.
    let mut connection_error = false;
    if let Err(e) = create_client_and_send_request(addr).await {
        connection_error = e.is_closed();
    }
    assert!(connection_error);
}
