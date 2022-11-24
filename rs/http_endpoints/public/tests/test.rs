use crate::common::{
    setup_ingress_filter_mock, setup_ingress_ingestion_mock, setup_query_execution_mock,
};
use ic_agent::{agent::http_transport::ReqwestHttpReplicaV2Transport, Agent};
use ic_config::http_handler::Config;
use ic_crypto_tls_interfaces_mocks::MockTlsHandshake;
use ic_crypto_tree_hash::MixedHashTree;
use ic_http_endpoints_public::start_server;
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
    signature::ThresholdSignature,
    CryptoHashOfPartialState, Height, RegistryVersion,
};
use prost::Message;
use std::{
    collections::BTreeMap,
    net::{IpAddr, Ipv4Addr, SocketAddr},
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

pub fn get_free_port() -> std::io::Result<u16> {
    let socket = TcpSocket::new_v4()?;
    // This allows transport to bind to this address,
    // even though the socket is already bound.
    socket.set_reuseport(true)?;
    socket.set_reuseaddr(true)?;
    socket.bind("127.0.0.1:0".parse().unwrap())?;
    Ok(socket.local_addr()?.port())
}

fn start_http_endpoint(
    rt: tokio::runtime::Handle,
    port: u16,
    state_manager: Arc<dyn StateReader<State = ReplicatedState>>,
    consensus_cache: Arc<dyn ConsensusPoolCache>,
    registry_client: Arc<dyn RegistryClient>,
) {
    let metrics = MetricsRegistry::new();
    let config = Config {
        listen_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), port),
        ..Default::default()
    };
    let (ingress_filter, _ingress_filter_handle) = setup_ingress_filter_mock();
    let (ingress_ingestion, _ingress_ingestion_handler) = setup_ingress_ingestion_mock();
    let (query_exe, _query_exe_handler) = setup_query_execution_mock();
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
}

#[test]
fn test_healthy_behind() {
    let rt = Runtime::new().unwrap();
    let port = get_free_port().expect("No ports available on host");
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
        port,
        Arc::new(mock_state_manager),
        Arc::new(mock_consensus_cache),
        Arc::new(mock_registry_client),
    );

    let agent = Agent::builder()
        .with_transport(
            ReqwestHttpReplicaV2Transport::create(format!("http://127.0.0.1:{}", port)).unwrap(),
        )
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
