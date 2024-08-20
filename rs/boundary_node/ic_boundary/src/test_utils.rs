// Stuff here used in tests and benchmarks.
// Since benchmarks use ic-boundary as an external library crate - this has to be public.

use std::{sync::Arc, time::Duration};

use arc_swap::ArcSwapOption;
use async_trait::async_trait;
use axum::Router;
use clap::Parser;
use http;
use ic_base_types::NodeId;
use ic_certification_test_utils::CertificateBuilder;
use ic_certification_test_utils::CertificateData::*;
use ic_crypto_tree_hash::Digest;
use ic_protobuf::registry::{
    crypto::v1::{PublicKey as PublicKeyProto, X509PublicKeyCert},
    node::v1::{ConnectionEndpoint, NodeRecord},
    routing_table::v1::RoutingTable as PbRoutingTable,
    subnet::v1::{SubnetListRecord, SubnetRecord},
};
use ic_registry_client_fake::FakeRegistryClient;
use ic_registry_keys::{
    make_crypto_threshold_signing_pubkey_key, make_crypto_tls_cert_key, make_node_record_key,
    make_routing_table_record_key, make_subnet_list_record_key, make_subnet_record_key,
    ROOT_SUBNET_ID_KEY,
};
use ic_registry_proto_data_provider::ProtoRegistryDataProvider;
use ic_registry_routing_table::{CanisterIdRange, RoutingTable as RoutingTableIC};
use ic_registry_subnet_type::SubnetType;
use ic_types::{
    crypto::threshold_sig::ThresholdSigPublicKey, replica_version::ReplicaVersion, time::Time,
    CanisterId, RegistryVersion, SubnetId,
};
use prometheus::Registry;
use rand::Rng;
use reqwest;

use crate::{
    cache::Cache,
    cli::Cli,
    core::setup_router,
    http::HttpClient,
    persist::{Persist, Persister, Routes},
    snapshot::{node_test_id, subnet_test_id, RegistrySnapshot, Snapshot, Snapshotter, Subnet},
    socket::TcpConnectInfo,
};

struct TestHttpClient(usize);

#[async_trait]
impl HttpClient for TestHttpClient {
    async fn execute(&self, req: reqwest::Request) -> Result<reqwest::Response, reqwest::Error> {
        let status = if req.url().path().ends_with("/call") {
            http::StatusCode::ACCEPTED
        } else {
            http::StatusCode::OK
        };

        let mut resp = http::response::Response::new("a".repeat(self.0));
        *resp.status_mut() = status;
        resp.headers_mut().insert("Content-Length", self.0.into());

        Ok(reqwest::Response::from(resp))
    }
}

fn new_random_certified_data() -> Digest {
    let mut random_certified_data: [u8; 32] = [0; 32];
    rand::thread_rng().fill(&mut random_certified_data);
    Digest(random_certified_data)
}

pub fn valid_tls_certificate_and_validation_time() -> (X509PublicKeyCert, Time) {
    /// converted to seconds since `UNIX_EPOCH` by hand
    const NOT_BEFORE: u64 = 1667585534;
    (
        X509PublicKeyCert {
            certificate_der: hex::decode(
                "3082015630820108a00302010202140098d074\
            7d24ca04a2f036d8665402b4ea784830300506032b6570304a3148304606035504030\
            c3f34696e71622d327a63766b2d663679716c2d736f776f6c2d76673365732d7a3234\
            6a642d6a726b6f772d6d686e73642d756b7666702d66616b35702d6161653020170d3\
            232313130343138313231345a180f39393939313233313233353935395a304a314830\
            4606035504030c3f34696e71622d327a63766b2d663679716c2d736f776f6c2d76673\
            365732d7a32346a642d6a726b6f772d6d686e73642d756b7666702d66616b35702d61\
            6165302a300506032b6570032100246acd5f38372411103768e91169dadb7370e9990\
            9a65639186ac6d1c36f3735300506032b6570034100d37e5ccfc32146767e5fd73343\
            649f5b5564eb78e6d8d424d8f01240708bc537a2a9bcbcf6c884136d18d2b475706d7\
            bb905f52faf28707735f1d90ab654380b",
            )
            .unwrap(),
        },
        Time::from_secs_since_unix_epoch(NOT_BEFORE).expect("failed to convert seconds to Time"),
    )
}

pub fn new_threshold_key() -> ThresholdSigPublicKey {
    let (_, pk, _) = CertificateBuilder::new(CanisterData {
        canister_id: CanisterId::from_u64(1),
        certified_data: new_random_certified_data(),
    })
    .build();

    pk
}

pub fn test_subnet_record() -> SubnetRecord {
    SubnetRecord {
        membership: vec![],
        max_ingress_bytes_per_message: 2 * 1024 * 1024,
        max_ingress_messages_per_block: 1000,
        max_block_payload_size: 4 * 1024 * 1024,
        unit_delay_millis: 500,
        initial_notary_delay_millis: 1500,
        replica_version_id: ReplicaVersion::default().into(),
        dkg_interval_length: 59,
        dkg_dealings_per_block: 1,
        start_as_nns: false,
        subnet_type: SubnetType::Application.into(),
        is_halted: false,
        halt_at_cup_height: false,
        features: Some(Default::default()),
        max_number_of_canisters: 0,
        ssh_readonly_access: vec![],
        ssh_backup_access: vec![],
        ecdsa_config: None,
        chain_key_config: None,
    }
}

// Generate a fake registry client with some data
#[allow(clippy::type_complexity)]
pub fn create_fake_registry_client(
    subnet_count: usize,
    nodes_per_subnet: usize,
    force_node_id: Option<NodeId>,
) -> (
    FakeRegistryClient,
    Vec<(NodeId, String)>,
    Vec<(SubnetId, CanisterIdRange)>,
) {
    let mut subnets: Vec<Vec<u8>> = vec![];
    let data_provider = ProtoRegistryDataProvider::new();
    let reg_ver = RegistryVersion::new(1);

    let nns_subnet_id = subnet_test_id(0);

    // Add NNS subnet
    data_provider
        .add(
            ROOT_SUBNET_ID_KEY,
            reg_ver,
            Some(ic_types::subnet_id_into_protobuf(nns_subnet_id)),
        )
        .unwrap();

    data_provider
        .add(
            &make_crypto_threshold_signing_pubkey_key(nns_subnet_id),
            reg_ver,
            Some(PublicKeyProto::from(new_threshold_key())),
        )
        .unwrap();

    // Routing table
    let mut routing_table = RoutingTableIC::default();
    let mut nodes = vec![];
    let mut ranges = vec![];

    for i in 0..subnet_count {
        let subnet_id = subnet_test_id(1 + i as u64);
        subnets.push(subnet_id.get().into_vec());

        let mut subnet_record = test_subnet_record();

        for j in 0..nodes_per_subnet {
            let node_id = force_node_id.unwrap_or_else(|| node_test_id((1000 * i + j + 1) as u64));
            let node_ip = format!("192.168.{}.{}", i + 1, j + 1);
            nodes.push((node_id, node_ip.clone()));

            subnet_record.membership.push(node_id.get().into_vec());

            // Set connection information
            let http_endpoint = ConnectionEndpoint {
                ip_addr: node_ip,
                port: 8080,
            };

            data_provider
                .add(
                    &make_node_record_key(node_id),
                    reg_ver,
                    Some(NodeRecord {
                        http: Some(http_endpoint),
                        ..Default::default()
                    }),
                )
                .unwrap();

            // Add some TLS certificate
            data_provider
                .add(
                    &make_crypto_tls_cert_key(node_id),
                    reg_ver,
                    Some(valid_tls_certificate_and_validation_time().0),
                )
                .expect("failed to add TLS certificate to registry");
        }

        // Add subnet
        data_provider
            .add(
                &make_subnet_record_key(subnet_id),
                reg_ver,
                Some(subnet_record),
            )
            .expect("could not add subnet");

        // Add subnet to routing table
        let canister_range = CanisterIdRange {
            start: CanisterId::from_u64((i as u64) * 1_000_000),
            end: CanisterId::from_u64((i as u64) * 1_000_000 + 999_999),
        };

        ranges.push((subnet_id, canister_range));
        routing_table.insert(canister_range, subnet_id).unwrap();
    }

    // Add list of subnets
    data_provider
        .add(
            make_subnet_list_record_key().as_str(),
            reg_ver,
            Some(SubnetListRecord { subnets }),
        )
        .expect("could not add subnet list record");

    // Add routing table
    data_provider
        .add(
            &make_routing_table_record_key(),
            reg_ver,
            Some(PbRoutingTable::from(routing_table)),
        )
        .expect("could not add routing table");

    let registry_client = FakeRegistryClient::new(Arc::new(data_provider));
    registry_client.update_to_latest_version();

    (registry_client, nodes, ranges)
}

pub fn setup_test_router(
    enable_cache: bool,
    enable_logging: bool,
    subnet_count: usize,
    nodes_per_subnet: usize,
    response_size: usize,
    rate_limit_subnet: Option<usize>,
) -> (Router, Vec<Subnet>) {
    use axum::extract::connect_info::MockConnectInfo;
    use std::net::SocketAddr;

    let mut args = vec![
        "",
        "--local-store-path",
        "/tmp",
        "--log-null",
        "--retry-update-call",
    ];
    if !enable_logging {
        args.push("--disable-request-logging");
    }

    // Hacky, but required due to &str
    let rate_limit_subnet = rate_limit_subnet.unwrap_or(0).to_string();
    if rate_limit_subnet != "0" {
        args.push("--rate-limit-per-second-per-subnet");
        args.push(rate_limit_subnet.as_str());
    }

    #[cfg(not(feature = "tls"))]
    let cli = Cli::parse_from(args);
    #[cfg(feature = "tls")]
    let cli = Cli::parse_from({
        args.extend_from_slice(&["--hostname", "foobar"]);
        args
    });

    let routing_table: Arc<ArcSwapOption<Routes>> = Arc::new(ArcSwapOption::empty());
    let registry_snapshot: Arc<ArcSwapOption<RegistrySnapshot>> = Arc::new(ArcSwapOption::empty());

    let http_client = Arc::new(TestHttpClient(response_size));
    let metrics_registry = Registry::new_custom(None, None).unwrap();

    let (registry_client, _, _) = create_fake_registry_client(subnet_count, nodes_per_subnet, None);
    let (channel_send, _) = tokio::sync::watch::channel(None);
    let mut snapshotter = Snapshotter::new(
        registry_snapshot.clone(),
        channel_send,
        Arc::new(registry_client),
        Duration::ZERO,
    );
    let persister = Persister::new(routing_table.clone());

    snapshotter.snapshot().unwrap();
    let subnets = registry_snapshot.load_full().unwrap().subnets.clone();
    persister.persist(subnets.clone());

    let router = setup_router(
        registry_snapshot,
        routing_table,
        http_client,
        None,
        None,
        &cli,
        &metrics_registry,
        enable_cache.then_some(Arc::new(
            Cache::new(10485760, 262144, Duration::from_secs(1), false).unwrap(),
        )),
    );

    let router = router.layer(MockConnectInfo(TcpConnectInfo(SocketAddr::from((
        [0, 0, 0, 0],
        1337,
    )))));

    (router, subnets)
}
