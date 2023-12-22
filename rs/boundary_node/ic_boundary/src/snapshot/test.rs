use super::*;

use std::net::{IpAddr, Ipv4Addr};

use ic_certification_test_utils::CertificateData::*;
use ic_certification_test_utils::*;
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
use ic_test_utilities::types::ids::{node_test_id, subnet_test_id};
use ic_test_utilities_registry::test_subnet_record;
use ic_types::{
    crypto::threshold_sig::ThresholdSigPublicKey, CanisterId, NodeId, PrincipalId, RegistryVersion,
};
use rand::Rng;

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
pub fn create_fake_registry_client(subnet_count: u8) -> FakeRegistryClient {
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

    for i in 0..subnet_count {
        let subnet_id = subnet_test_id(1 + i as u64);
        let node_id = node_test_id(1001 + i as u64);
        let node_ip = format!("192.168.0.{}", 1 + i);

        subnets.push(subnet_id.get().into_vec());

        let mut subnet_record = test_subnet_record();
        subnet_record.membership = vec![node_id.get().into_vec()];

        // Add subnet with node
        data_provider
            .add(
                &make_subnet_record_key(subnet_id),
                reg_ver,
                Some(subnet_record),
            )
            .unwrap();

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

        // Add subnet to routing table
        let canister_range = CanisterIdRange {
            start: CanisterId::from((i as u64) * 1_000_000),
            end: CanisterId::from((i as u64) * 1_000_000 + 999_999),
        };

        routing_table.insert(canister_range, subnet_id).unwrap();
    }

    // Add list of subnets
    data_provider
        .add(
            make_subnet_list_record_key().as_str(),
            reg_ver,
            Some(SubnetListRecord { subnets }),
        )
        .expect("Could not add subnet list record.");

    // Add routing table
    data_provider
        .add(
            &make_routing_table_record_key(),
            reg_ver,
            Some(PbRoutingTable::from(routing_table)),
        )
        .unwrap();

    let registry_client = FakeRegistryClient::new(Arc::new(data_provider));
    registry_client.update_to_latest_version();

    registry_client
}

pub fn create_fake_registry_client_single_node() -> FakeRegistryClient {
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

    let subnet_id = subnet_test_id(1);
    // Same node_id that valid_tls_certificate_and_validation_time() is valid for
    let node_id = NodeId::from(
        PrincipalId::from_str("4inqb-2zcvk-f6yql-sowol-vg3es-z24jd-jrkow-mhnsd-ukvfp-fak5p-aae")
            .unwrap(),
    );
    let node_ip = "192.168.0.1".into();

    subnets.push(subnet_id.get().into_vec());

    let mut subnet_record = test_subnet_record();
    subnet_record.membership = vec![node_id.get().into_vec()];

    // Add subnet with node
    data_provider
        .add(
            &make_subnet_record_key(subnet_id),
            reg_ver,
            Some(subnet_record),
        )
        .unwrap();

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

    // Add subnet to routing table
    let canister_range = CanisterIdRange {
        start: CanisterId::from(0),
        end: CanisterId::from(999_999),
    };

    routing_table.insert(canister_range, subnet_id).unwrap();

    // Add list of subnets
    data_provider
        .add(
            make_subnet_list_record_key().as_str(),
            reg_ver,
            Some(SubnetListRecord { subnets }),
        )
        .expect("Could not add subnet list record.");

    // Add routing table
    data_provider
        .add(
            &make_routing_table_record_key(),
            reg_ver,
            Some(PbRoutingTable::from(routing_table)),
        )
        .unwrap();

    let registry_client = FakeRegistryClient::new(Arc::new(data_provider));
    registry_client.update_to_latest_version();

    registry_client
}

pub fn create_nodes() -> Vec<(&'static str, IpAddr, u16)> {
    vec![
        (
            "y7s52-3xjam-aaaaa-aaaap-2ai",
            IpAddr::V4(Ipv4Addr::new(192, 168, 0, 1)),
            8080,
        ),
        (
            "ftjgm-3pkam-aaaaa-aaaap-2ai",
            IpAddr::V4(Ipv4Addr::new(192, 168, 0, 2)),
            8080,
        ),
        (
            "ymia2-u7lam-aaaaa-aaaap-2ai",
            IpAddr::V4(Ipv4Addr::new(192, 168, 0, 3)),
            8080,
        ),
        (
            "ehgbm-kxmam-aaaaa-aaaap-2ai",
            IpAddr::V4(Ipv4Addr::new(192, 168, 0, 4)),
            8080,
        ),
    ]
}

#[tokio::test]
async fn test_routing_table() -> Result<(), Error> {
    let snapshot = Arc::new(ArcSwapOption::empty());
    let reg = Arc::new(create_fake_registry_client(4));
    let mut snapshotter = Snapshotter::new(Arc::clone(&snapshot), reg, Duration::ZERO);
    snapshotter.snapshot().await?;
    let snapshot = snapshot.load_full().unwrap();

    assert_eq!(snapshot.version, 1);
    assert_eq!(snapshot.subnets.len(), 4);

    let subnets = [
        (
            "yndj2-3ybaa-aaaaa-aaaap-yai",
            ("rwlgt-iiaaa-aaaaa-aaaaa-cai", "chwmy-2yaaa-aaaaa-pii7q-cai"),
        ),
        (
            "fbysm-3acaa-aaaaa-aaaap-yai",
            ("jza6g-bqaaa-aaaaa-pijaa-cai", "n7ie4-qyaaa-aaaaa-6qr7q-cai"),
        ),
        (
            "y6zu2-uqdaa-aaaaa-aaaap-yai",
            ("2fehv-lqaaa-aaaaa-6qsaa-cai", "fhryv-yyaaa-aaaab-ny27q-cai"),
        ),
        (
            "evxvm-kyeaa-aaaaa-aaaap-yai",
            ("ozhkl-dqaaa-aaaab-ny3aa-cai", "v4fqt-faaaa-aaaab-5bd7q-cai"),
        ),
    ];

    let nodes = create_nodes();

    for i in 0..snapshot.subnets.len() {
        let sn = &snapshot.subnets[i];
        assert_eq!(sn.id.to_string(), subnets[i].0);

        assert_eq!(sn.ranges.len(), 1);
        assert_eq!(sn.ranges[0].start.to_string(), subnets[i].1 .0);
        assert_eq!(sn.ranges[0].end.to_string(), subnets[i].1 .1);

        assert_eq!(sn.nodes.len(), 1);
        assert_eq!(sn.nodes[0].id.to_string(), nodes[i].0);
        assert_eq!(sn.nodes[0].addr, nodes[i].1);
        assert_eq!(sn.nodes[0].port, nodes[i].2);

        assert_eq!(
            sn.nodes[0].tls_certificate,
            valid_tls_certificate_and_validation_time()
                .0
                .certificate_der,
        );
    }

    Ok(())
}
