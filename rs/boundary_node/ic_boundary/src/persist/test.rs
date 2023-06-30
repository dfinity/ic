use super::{principal_to_u256, Persist, PersistStatus, Persister, RouteSubnet, Routes};

use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr},
    sync::Arc,
};

use anyhow::Error;
use arc_swap::ArcSwapOption;
use candid::Principal;
use ethnum::u256;
use ic_crypto_test_utils_keys::public_keys::valid_tls_certificate;
use ic_protobuf::registry::subnet::v1::SubnetType;
use ic_test_utilities::types::ids::node_test_id;

use crate::snapshot::{CanisterRange, Node, RoutingTable, Subnet};

#[test]
fn test_principal_to_u256() -> Result<(), Error> {
    assert!(principal_to_u256("foo-bar-baz").is_err());

    assert_eq!(
        principal_to_u256("tg57h-slwo4-l4fga-d4zo2-4pc5z-lujes-uxqp3-pzchi-krm7r-sgvix-pae")?,
        u256::from_be_bytes([
            0x00, 0x00, 0x00, 0x76, 0x77, 0x17, 0xc2, 0x98, 0x03, 0xe6, 0x5d, 0xae, 0x3c, 0x5d,
            0xca, 0xe8, 0x92, 0x4a, 0x97, 0x83, 0xf6, 0xfc, 0x88, 0xe8, 0x54, 0x59, 0xf8, 0xc8,
            0xd5, 0x45, 0xde, 0x02
        ])
    );

    assert_eq!(
        principal_to_u256("iineg-fibai-bqibi-ga4ea-searc-ijrif-iwc4m-bsibb-eirsi-jjge4-ucs")?,
        u256::from_be_bytes([
            0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10, 0x11,
            0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25,
            0x26, 0x27, 0x28, 0x29
        ])
    );

    assert_eq!(
        principal_to_u256("xtqug-aqaae-bagba-faydq-q")?,
        u256::from_be_bytes([
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04,
            0x05, 0x06, 0x07, 0x08
        ])
    );

    Ok(())
}

fn node(i: u64) -> Node {
    Node {
        id: node_test_id(1001 + i).get().0,
        addr: IpAddr::V4(Ipv4Addr::new(192, 168, 0, i as u8)),
        port: 8080,
        tls_certificate: valid_tls_certificate().certificate_der,
    }
}

fn generate_test_routing_table(offset: u64) -> RoutingTable {
    let node1 = node(1 + offset);
    let node2 = node(2 + offset);
    let node3 = node(3 + offset);

    let subnet1 = Subnet {
        id: Principal::from_text("tdb26-jop6k-aogll-7ltgs-eruif-6kk7m-qpktf-gdiqx-mxtrf-vb5e6-eqe")
            .unwrap(),
        subnet_type: SubnetType::Application,
        ranges: vec![
            CanisterRange {
                start: Principal::from_text("f7crg-kabae").unwrap(),
                end: Principal::from_text("sxiki-5ygae-aq").unwrap(),
            },
            CanisterRange {
                start: Principal::from_text("t5his-7iiae-aq").unwrap(),
                end: Principal::from_text("jlzvg-byp77-7qcai").unwrap(),
            },
        ],
        nodes: vec![node1.clone()],
    };

    let subnet2 = Subnet {
        id: Principal::from_text("uzr34-akd3s-xrdag-3ql62-ocgoh-ld2ao-tamcv-54e7j-krwgb-2gm4z-oqe")
            .unwrap(),
        subnet_type: SubnetType::Application,
        ranges: vec![
            CanisterRange {
                start: Principal::from_text("sqjm4-qahae-aq").unwrap(),
                end: Principal::from_text("sqjm4-qahae-aq").unwrap(),
            },
            CanisterRange {
                start: Principal::from_text("6l3jn-7icca-aaaai-b").unwrap(),
                end: Principal::from_text("ca5tg-macd7-776ai-b").unwrap(),
            },
        ],
        nodes: vec![node2.clone()],
    };

    let subnet3 = Subnet {
        id: Principal::from_text("snjp4-xlbw4-mnbog-ddwy6-6ckfd-2w5a2-eipqo-7l436-pxqkh-l6fuv-vae")
            .unwrap(),
        subnet_type: SubnetType::Application,
        ranges: vec![CanisterRange {
            start: Principal::from_text("zdpgc-saqaa-aacai").unwrap(),
            end: Principal::from_text("fij4j-bi777-7qcai").unwrap(),
        }],
        nodes: vec![node3.clone()],
    };

    RoutingTable {
        registry_version: 1,
        nns_subnet_id: Principal::from_text("fscpm-uiaaa-aaaaa-aaaap-yai").unwrap(),
        subnets: vec![subnet1, subnet2, subnet3],
        nodes: HashMap::from([
            (node1.id.to_string(), node1),
            (node2.id.to_string(), node2),
            (node3.id.to_string(), node3),
        ]),
    }
}

fn generate_test_routes(offset: u64) -> Routes {
    let subnet1 = RouteSubnet {
        id: "tdb26-jop6k-aogll-7ltgs-eruif-6kk7m-qpktf-gdiqx-mxtrf-vb5e6-eqe".to_string(),
        range_start: principal_to_u256("f7crg-kabae").unwrap(),
        range_end: principal_to_u256("sxiki-5ygae-aq").unwrap(),
        nodes: vec![node(1 + offset)],
    };

    let subnet2 = RouteSubnet {
        id: "uzr34-akd3s-xrdag-3ql62-ocgoh-ld2ao-tamcv-54e7j-krwgb-2gm4z-oqe".to_string(),
        range_start: principal_to_u256("sqjm4-qahae-aq").unwrap(),
        range_end: principal_to_u256("sqjm4-qahae-aq").unwrap(),
        nodes: vec![node(2 + offset)],
    };

    let subnet3 = RouteSubnet {
        id: "tdb26-jop6k-aogll-7ltgs-eruif-6kk7m-qpktf-gdiqx-mxtrf-vb5e6-eqe".to_string(),
        range_start: principal_to_u256("t5his-7iiae-aq").unwrap(),
        range_end: principal_to_u256("jlzvg-byp77-7qcai").unwrap(),
        nodes: vec![node(1 + offset)],
    };

    let subnet4 = RouteSubnet {
        id: "snjp4-xlbw4-mnbog-ddwy6-6ckfd-2w5a2-eipqo-7l436-pxqkh-l6fuv-vae".to_string(),
        range_start: principal_to_u256("zdpgc-saqaa-aacai").unwrap(),
        range_end: principal_to_u256("fij4j-bi777-7qcai").unwrap(),
        nodes: vec![node(3 + offset)],
    };

    let subnet5 = RouteSubnet {
        id: "uzr34-akd3s-xrdag-3ql62-ocgoh-ld2ao-tamcv-54e7j-krwgb-2gm4z-oqe".to_string(),
        range_start: principal_to_u256("6l3jn-7icca-aaaai-b").unwrap(),
        range_end: principal_to_u256("ca5tg-macd7-776ai-b").unwrap(),
        nodes: vec![node(2 + offset)],
    };

    Routes {
        subnets: vec![
            Arc::new(subnet1),
            Arc::new(subnet2),
            Arc::new(subnet3),
            Arc::new(subnet4),
            Arc::new(subnet5),
        ],
    }
}

#[tokio::test]
async fn test_persist() -> Result<(), Error> {
    let routes = generate_test_routes(0);
    let routing_table = generate_test_routing_table(0);

    let rt_init = ArcSwapOption::const_empty();
    let mut persister = Persister::new(&rt_init);

    // Persist the routing table
    let result = persister.persist(routing_table.clone()).await.unwrap();
    // Check the result
    assert!(matches!(result, PersistStatus::Completed));
    // Compare the persisted table state with expected
    assert_eq!(&routes, rt_init.load_full().unwrap().as_ref());

    let result = persister.persist(routing_table.clone()).await.unwrap();
    assert!(matches!(result, PersistStatus::SkippedUnchanged));
    // Check if the table hasn't changed
    assert_eq!(&routes, rt_init.load_full().unwrap().as_ref());

    // Check empty table
    let empty_table = RoutingTable {
        registry_version: 1,
        nns_subnet_id: Principal::from_text("fscpm-uiaaa-aaaaa-aaaap-yai").unwrap(),
        subnets: vec![],
        nodes: HashMap::new(),
    };

    let result = persister.persist(empty_table).await.unwrap();
    assert!(matches!(result, PersistStatus::SkippedEmpty));
    // Check if the table hasn't changed
    assert_eq!(&routes, rt_init.load_full().unwrap().as_ref());

    // Generate different table
    let routing_table = generate_test_routing_table(1);
    let result = persister.persist(routing_table).await.unwrap();
    // Check if it was updated
    assert!(matches!(result, PersistStatus::Completed));
    // Check if the routing table matches expected one
    let routes_new = generate_test_routes(1);
    assert_eq!(&routes_new, rt_init.load_full().unwrap().as_ref());

    Ok(())
}

#[test]
fn test_lookup() -> Result<(), Error> {
    let r = generate_test_routes(0);

    assert_eq!(
        r.lookup("ryjl3-tyaaa-aaaaa-aaaba-cai").unwrap().id,
        "tdb26-jop6k-aogll-7ltgs-eruif-6kk7m-qpktf-gdiqx-mxtrf-vb5e6-eqe"
    );

    assert_eq!(
        r.lookup("qjdve-lqaaa-aaaaa-aaaeq-cai").unwrap().id,
        "tdb26-jop6k-aogll-7ltgs-eruif-6kk7m-qpktf-gdiqx-mxtrf-vb5e6-eqe"
    );

    assert_eq!(
        r.lookup("2b2k4-rqaaa-aaaaa-qaatq-cai").unwrap().id,
        "snjp4-xlbw4-mnbog-ddwy6-6ckfd-2w5a2-eipqo-7l436-pxqkh-l6fuv-vae"
    );

    assert_eq!(
        r.lookup("rdmx6-jaaaa-aaaaa-aaadq-cai").unwrap().id,
        "uzr34-akd3s-xrdag-3ql62-ocgoh-ld2ao-tamcv-54e7j-krwgb-2gm4z-oqe"
    );

    assert_eq!(
        r.lookup("sqjm4-qahae-aq").unwrap().id,
        "uzr34-akd3s-xrdag-3ql62-ocgoh-ld2ao-tamcv-54e7j-krwgb-2gm4z-oqe"
    );

    assert_eq!(
        r.lookup("rdmx6-jaaaa-aaaaa-aaadq-cai").unwrap().id,
        "uzr34-akd3s-xrdag-3ql62-ocgoh-ld2ao-tamcv-54e7j-krwgb-2gm4z-oqe"
    );

    assert_eq!(
        r.lookup("uc7f6-kaaaa-aaaaq-qaaaa-cai").unwrap().id,
        "uzr34-akd3s-xrdag-3ql62-ocgoh-ld2ao-tamcv-54e7j-krwgb-2gm4z-oqe"
    );

    // Test failure
    assert!(r.lookup("32fn4-qqaaa-aaaak-ad65a-cai").is_err());
    assert!(r.lookup("3we4s-lyaaa-aaaak-aegrq-cai").is_err());

    Ok(())
}
