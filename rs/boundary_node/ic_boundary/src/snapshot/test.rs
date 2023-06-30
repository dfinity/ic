use super::*;

use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr},
    time::SystemTime,
};

use ic_crypto_test_utils_keys::public_keys::valid_tls_certificate;
use ic_protobuf::registry::{
    node::v1::{ConnectionEndpoint, NodeRecord, Protocol},
    routing_table::v1::RoutingTable as PbRoutingTable,
    subnet::v1::{SubnetListRecord, SubnetRecord},
};
use ic_registry_client_fake::FakeRegistryClient;
use ic_registry_keys::{
    make_crypto_tls_cert_key, make_node_record_key, make_routing_table_record_key,
    make_subnet_list_record_key, make_subnet_record_key, ROOT_SUBNET_ID_KEY,
};
use ic_registry_proto_data_provider::ProtoRegistryDataProvider;
use ic_registry_routing_table::{CanisterIdRange, RoutingTable as RoutingTableIC};
use ic_test_utilities::types::ids::{node_test_id, subnet_test_id};
use ic_test_utilities_registry::test_subnet_record;
use ic_types::{CanisterId, RegistryVersion, ReplicaVersion, SubnetId};
use rustls::{server::DnsName, Certificate, ServerName};

// CN = s52il-lowsg-eip4y-pt5lv-sbdpb-vg4gg-4iasu-egajp-yluji-znfz3-2qe
const TEST_CERTIFICATE: &str = "3082015530820107a00302010202136abf05c1260364e09ad5f4ad0e9cb90a6e0edb300506032b6570304a3148304606035504030c3f733532696c2d6c6f7773672d\
                                65697034792d7074356c762d73626470622d76673467672d34696173752d6567616a702d796c756a692d7a6e667a332d3271653020170d3232313131343135303230\
                                345a180f39393939313233313233353935395a304a3148304606035504030c3f733532696c2d6c6f7773672d65697034792d7074356c762d73626470622d76673467\
                                672d34696173752d6567616a702d796c756a692d7a6e667a332d327165302a300506032b65700321002b5c5af2776114a400d71995cf9cdb72ca1a26b59b875a3d70\
                                c79bf48b5f210b300506032b6570034100f3ded920aa535295c69fd97c8da2d73ce525370456cdaacc4863b25e19b0d2af1961454ac5ff9a9e182ea54034ceed0dd0\
                                2a7bd9421ae1f844c894544bca9602";

fn test_certificate() -> Vec<u8> {
    hex::decode(TEST_CERTIFICATE).unwrap()
}

// Generate a fake registry client with some data
fn create_fake_registry_client(subnet_count: u8) -> FakeRegistryClient {
    let mut subnets: Vec<Vec<u8>> = vec![];
    let data_provider = ProtoRegistryDataProvider::new();
    let reg_ver = RegistryVersion::new(1);

    // Add NNS subnet
    data_provider
        .add(
            ROOT_SUBNET_ID_KEY,
            reg_ver,
            Some(ic_types::subnet_id_into_protobuf(subnet_test_id(0))),
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
            protocol: Protocol::Http1 as i32,
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
                Some(valid_tls_certificate()),
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
        .expect("Coult not add subnet list record.");

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

fn create_nodes() -> Vec<(&'static str, IpAddr, u16)> {
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
    let rt = ArcSwapOption::const_empty();
    let reg = Arc::new(create_fake_registry_client(4));
    let mut runner = Runner::new(&rt, reg);
    runner.run().await?;
    let rt = rt.load_full().unwrap();

    assert_eq!(rt.registry_version, 1);
    assert_eq!(rt.nns_subnet_id.to_string(), "fscpm-uiaaa-aaaaa-aaaap-yai");
    assert_eq!(rt.subnets.len(), 4);

    let subnets = vec![
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

    for i in 0..rt.subnets.len() {
        let sn = &rt.subnets[i];
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
            valid_tls_certificate().certificate_der,
        );
    }

    Ok(())
}

fn check_certificate_verification(
    helper: &HTTPClientHelper,
    name: &str,
    der: Vec<u8>,
) -> Result<(), Error> {
    let crt = Certificate(der);
    let intermediates: Vec<Certificate> = vec![];
    let server_name = ServerName::try_from(name).unwrap();
    let scts: Vec<&[u8]> = vec![];
    let ocsp_response: Vec<u8> = vec![];

    helper.verify_server_cert(
        &crt,
        intermediates.as_slice(),
        &server_name,
        &mut scts.into_iter(),
        ocsp_response.as_slice(),
        SystemTime::now(),
    )?;

    Ok(())
}

#[tokio::test]
async fn test_verify_tls_certificate() -> Result<(), Error> {
    let rt = ArcSwapOption::const_empty();
    let reg = Arc::new(create_fake_registry_client(4));
    let mut runner = Runner::new(&rt, reg);
    let helper = HTTPClientHelper::new(&rt);
    runner.run().await?;

    let rt = rt.load_full().unwrap();

    for sn in rt.subnets.iter() {
        let node_name = sn.nodes[0].id.to_string();

        check_certificate_verification(
            &helper,
            node_name.as_str(),
            valid_tls_certificate().certificate_der,
        )?;

        // Check with different cert -> should fail
        let r = check_certificate_verification(&helper, node_name.as_str(), test_certificate());
        assert!(matches!(r, Err(_)));
    }

    Ok(())
}

// Check that resolver yields correct IPs
#[tokio::test]
async fn test_resolve() -> Result<(), Error> {
    use hyper::client::connect::dns::Name;

    let reg = Arc::new(create_fake_registry_client(4));
    let rt = ArcSwapOption::const_empty();
    let helper = HTTPClientHelper::new(&rt);
    let mut runner = Runner::new(&rt, reg);
    runner.run().await?;

    // Check that resolved node's IPs match expected ones
    let nodes = create_nodes();

    for node in nodes.into_iter() {
        let res = helper.resolve(Name::from_str(node.0).unwrap()).await;

        match res {
            Ok(mut r) => {
                assert_eq!(r.next().unwrap().clone().ip(), node.1);
            }

            Err(_) => {
                panic!("should not error out")
            }
        }
    }

    // Check the lookup failure for unknown node name
    let res = helper.resolve(Name::from_str("foo-bar-baz").unwrap()).await;
    assert!(matches!(res, Result::Err(_)));

    Ok(())
}
