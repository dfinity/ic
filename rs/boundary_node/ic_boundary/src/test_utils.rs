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
use ic_crypto_test_utils_keys::public_keys::valid_tls_certificate_and_validation_time;
use ic_crypto_tree_hash::Digest;
use ic_protobuf::registry::{
    crypto::v1::PublicKey as PublicKeyProto,
    node::v1::{ConnectionEndpoint, NodeRecord},
    routing_table::v1::RoutingTable as PbRoutingTable,
    subnet::v1::SubnetListRecord,
};
use ic_registry_client_fake::FakeRegistryClient;
use ic_registry_keys::{
    make_crypto_threshold_signing_pubkey_key, make_crypto_tls_cert_key, make_node_record_key,
    make_routing_table_record_key, make_subnet_list_record_key, make_subnet_record_key,
    ROOT_SUBNET_ID_KEY,
};
use ic_registry_proto_data_provider::ProtoRegistryDataProvider;
use ic_registry_routing_table::{CanisterIdRange, RoutingTable as RoutingTableIC};
use ic_test_utilities_registry::test_subnet_record;
use ic_test_utilities_types::ids::{node_test_id, subnet_test_id};
use ic_types::{
    crypto::threshold_sig::ThresholdSigPublicKey, CanisterId, RegistryVersion, SubnetId,
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
    snapshot::{RegistrySnapshot, Snapshot, Snapshotter, Subnet},
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

pub fn new_threshold_key() -> ThresholdSigPublicKey {
    let (_, pk, _) = CertificateBuilder::new(CanisterData {
        canister_id: CanisterId::from_u64(1),
        certified_data: new_random_certified_data(),
    })
    .build();

    pk
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
) -> (Router, Vec<Subnet>) {
    use axum::extract::connect_info::MockConnectInfo;
    use std::net::SocketAddr;

    let mut args = vec!["", "--local-store-path", "/tmp", "--log-null"];
    if !enable_logging {
        args.push("--disable-request-logging");
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
