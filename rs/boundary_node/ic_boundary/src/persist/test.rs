use super::{principal_bytes_to_u256, Persist, PersistStatus, Persister, RouteSubnet, Routes};

use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr},
    sync::Arc,
};

use anyhow::Error;
use arc_swap::ArcSwapOption;
use candid::Principal;
use ethnum::u256;
use ic_registry_subnet_type::SubnetType;

use crate::{
    snapshot::{node_test_id, CanisterRange, Node, Subnet},
    test_utils::valid_tls_certificate_and_validation_time,
};

// Converts string principal to a u256
fn principal_to_u256(p: &str) -> Result<u256, Error> {
    // Parse textual representation into a byte slice
    let p = Principal::from_text(p)?;
    let p = p.as_slice();

    Ok(principal_bytes_to_u256(p))
}

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

pub fn node(i: u64, subnet_id: Principal) -> Arc<Node> {
    Arc::new(Node {
        id: node_test_id(1001 + i).get().0,
        subnet_id,
        subnet_type: SubnetType::Application,
        addr: IpAddr::V4(Ipv4Addr::new(192, 168, 0, i as u8)),
        port: 8080,
        tls_certificate: valid_tls_certificate_and_validation_time()
            .0
            .certificate_der,
        avg_latency_secs: f64::MAX,
    })
}

pub fn generate_test_subnets(offset: u64) -> Vec<Subnet> {
    let subnet_id_1 =
        Principal::from_text("tdb26-jop6k-aogll-7ltgs-eruif-6kk7m-qpktf-gdiqx-mxtrf-vb5e6-eqe")
            .unwrap();
    let subnet_id_2 =
        Principal::from_text("uzr34-akd3s-xrdag-3ql62-ocgoh-ld2ao-tamcv-54e7j-krwgb-2gm4z-oqe")
            .unwrap();
    let subnet_id_3 =
        Principal::from_text("snjp4-xlbw4-mnbog-ddwy6-6ckfd-2w5a2-eipqo-7l436-pxqkh-l6fuv-vae")
            .unwrap();

    let node1 = node(1 + offset, subnet_id_1);
    let node2 = node(2 + offset, subnet_id_2);
    let node3 = node(3 + offset, subnet_id_3);

    let subnet1 = Subnet {
        id: subnet_id_1,
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
        replica_version: "7742d96ddd30aa6b607c9d2d4093a7b714f5b25b".to_string(),
    };

    let subnet2 = Subnet {
        id: subnet_id_2,
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
        replica_version: "7742d96ddd30aa6b607c9d2d4093a7b714f5b25b".to_string(),
    };

    let subnet3 = Subnet {
        id: subnet_id_3,
        subnet_type: SubnetType::Application,
        ranges: vec![CanisterRange {
            start: Principal::from_text("zdpgc-saqaa-aacai").unwrap(),
            end: Principal::from_text("fij4j-bi777-7qcai").unwrap(),
        }],
        nodes: vec![node3.clone()],
        replica_version: "7742d96ddd30aa6b607c9d2d4093a7b714f5b25b".to_string(),
    };

    vec![subnet1, subnet2, subnet3]
}

pub fn generate_test_routes(offset: u64) -> Routes {
    let subnet_id_1 =
        Principal::from_text("tdb26-jop6k-aogll-7ltgs-eruif-6kk7m-qpktf-gdiqx-mxtrf-vb5e6-eqe")
            .unwrap();
    let subnet_id_2 =
        Principal::from_text("uzr34-akd3s-xrdag-3ql62-ocgoh-ld2ao-tamcv-54e7j-krwgb-2gm4z-oqe")
            .unwrap();
    let subnet_id_3 =
        Principal::from_text("snjp4-xlbw4-mnbog-ddwy6-6ckfd-2w5a2-eipqo-7l436-pxqkh-l6fuv-vae")
            .unwrap();

    let subnet1 = RouteSubnet {
        id: subnet_id_1,
        range_start: principal_to_u256("f7crg-kabae").unwrap(),
        range_end: principal_to_u256("sxiki-5ygae-aq").unwrap(),
        nodes: vec![node(1 + offset, subnet_id_1)],
    };

    let subnet2 = RouteSubnet {
        id: subnet_id_2,
        range_start: principal_to_u256("sqjm4-qahae-aq").unwrap(),
        range_end: principal_to_u256("sqjm4-qahae-aq").unwrap(),
        nodes: vec![node(2 + offset, subnet_id_2)],
    };

    let subnet3 = RouteSubnet {
        id: subnet_id_1,
        range_start: principal_to_u256("t5his-7iiae-aq").unwrap(),
        range_end: principal_to_u256("jlzvg-byp77-7qcai").unwrap(),
        nodes: vec![node(1 + offset, subnet_id_1)],
    };

    let subnet4 = RouteSubnet {
        id: subnet_id_3,
        range_start: principal_to_u256("zdpgc-saqaa-aacai").unwrap(),
        range_end: principal_to_u256("fij4j-bi777-7qcai").unwrap(),
        nodes: vec![node(3 + offset, subnet_id_3)],
    };

    let subnet5 = RouteSubnet {
        id: subnet_id_2,
        range_start: principal_to_u256("6l3jn-7icca-aaaai-b").unwrap(),
        range_end: principal_to_u256("ca5tg-macd7-776ai-b").unwrap(),
        nodes: vec![node(2 + offset, subnet_id_2)],
    };

    let subnets = vec![
        Arc::new(subnet1),
        Arc::new(subnet2),
        Arc::new(subnet3),
        Arc::new(subnet4),
        Arc::new(subnet5),
    ];

    let subnet_map = subnets
        .iter()
        .map(|subnet| (subnet.id, subnet.clone()))
        .collect::<HashMap<_, _>>();

    Routes {
        node_count: 3,
        subnets,
        subnet_map,
    }
}

#[test]
fn test_persist() -> Result<(), Error> {
    let routes = generate_test_routes(0);
    let subnets = generate_test_subnets(0);

    let rt_init = Arc::new(ArcSwapOption::empty());
    let persister = Persister::new(Arc::clone(&rt_init));

    // Persist the routing table
    let result = persister.persist(subnets.clone());
    // Check the result
    assert!(matches!(result, PersistStatus::Completed(_)));
    // Compare the persisted table state with expected
    assert_eq!(&routes, rt_init.load_full().unwrap().as_ref());

    // Check empty table
    let result = persister.persist(vec![]);
    assert!(matches!(result, PersistStatus::SkippedEmpty));
    // Check if the table hasn't changed
    assert_eq!(&routes, rt_init.load_full().unwrap().as_ref());

    // Generate different table
    let subnets = generate_test_subnets(1);
    let result = persister.persist(subnets);
    // Check if it was updated
    assert!(matches!(result, PersistStatus::Completed(_)));
    // Check if the routing table matches expected one
    let routes_new = generate_test_routes(1);
    assert_eq!(&routes_new, rt_init.load_full().unwrap().as_ref());

    Ok(())
}

#[test]
fn test_lookup() -> Result<(), Error> {
    let r = generate_test_routes(0);

    assert_eq!(
        r.lookup_by_canister_id(Principal::from_text("ryjl3-tyaaa-aaaaa-aaaba-cai").unwrap())
            .unwrap()
            .id
            .to_string(),
        "tdb26-jop6k-aogll-7ltgs-eruif-6kk7m-qpktf-gdiqx-mxtrf-vb5e6-eqe"
    );

    assert_eq!(
        r.lookup_by_canister_id(Principal::from_text("qjdve-lqaaa-aaaaa-aaaeq-cai").unwrap())
            .unwrap()
            .id
            .to_string(),
        "tdb26-jop6k-aogll-7ltgs-eruif-6kk7m-qpktf-gdiqx-mxtrf-vb5e6-eqe"
    );

    assert_eq!(
        r.lookup_by_canister_id(Principal::from_text("2b2k4-rqaaa-aaaaa-qaatq-cai").unwrap())
            .unwrap()
            .id
            .to_string(),
        "snjp4-xlbw4-mnbog-ddwy6-6ckfd-2w5a2-eipqo-7l436-pxqkh-l6fuv-vae"
    );

    assert_eq!(
        r.lookup_by_canister_id(Principal::from_text("rdmx6-jaaaa-aaaaa-aaadq-cai").unwrap())
            .unwrap()
            .id
            .to_string(),
        "uzr34-akd3s-xrdag-3ql62-ocgoh-ld2ao-tamcv-54e7j-krwgb-2gm4z-oqe"
    );

    assert_eq!(
        r.lookup_by_canister_id(Principal::from_text("sqjm4-qahae-aq").unwrap())
            .unwrap()
            .id
            .to_string(),
        "uzr34-akd3s-xrdag-3ql62-ocgoh-ld2ao-tamcv-54e7j-krwgb-2gm4z-oqe"
    );

    assert_eq!(
        r.lookup_by_canister_id(Principal::from_text("rdmx6-jaaaa-aaaaa-aaadq-cai").unwrap())
            .unwrap()
            .id
            .to_string(),
        "uzr34-akd3s-xrdag-3ql62-ocgoh-ld2ao-tamcv-54e7j-krwgb-2gm4z-oqe"
    );

    assert_eq!(
        r.lookup_by_canister_id(Principal::from_text("uc7f6-kaaaa-aaaaq-qaaaa-cai").unwrap())
            .unwrap()
            .id
            .to_string(),
        "uzr34-akd3s-xrdag-3ql62-ocgoh-ld2ao-tamcv-54e7j-krwgb-2gm4z-oqe"
    );

    // Test failure
    assert!(r
        .lookup_by_canister_id(Principal::from_text("32fn4-qqaaa-aaaak-ad65a-cai").unwrap())
        .is_none());
    assert!(r
        .lookup_by_canister_id(Principal::from_text("3we4s-lyaaa-aaaak-aegrq-cai").unwrap())
        .is_none());

    Ok(())
}
