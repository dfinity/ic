use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr},
    sync::Arc,
};

use arc_swap::ArcSwapOption;
use ic_crypto_test_utils_keys::public_keys::valid_tls_certificate_and_validation_time;
use ic_protobuf::registry::subnet::v1::SubnetType;
use ic_test_utilities::types::ids::{node_test_id, subnet_test_id};
use mockall::{predicate::*, *};

use super::*;
use crate::{
    persist::{Persister, Routes},
    snapshot::{CanisterRange, Node, RoutingTable, Subnet},
};

const NODE_ID_OFFSET: u64 = 1000;

impl Routes {
    // Check if given node exists in the lookup table
    // It's O(n) and used only in tests
    pub fn node_exists(&self, node_id: Principal) -> bool {
        for s in self.subnets.iter() {
            for n in s.nodes.iter() {
                if n.id == node_id {
                    return true;
                }
            }
        }

        false
    }
}

pub fn generate_custom_routing_table(
    subnet_count: u64,
    nodes_per_subnet: u64,
    offset: u64,
) -> RoutingTable {
    let mut subnets = Vec::new();
    let mut nodes_hash = HashMap::new();

    for i in 0..subnet_count {
        let subnet_id = subnet_test_id(offset + i).get().0;

        let mut nodes = Vec::new();
        for j in 0..nodes_per_subnet {
            let node = Node {
                id: node_test_id(NODE_ID_OFFSET + offset + i * 100 + j).get().0,
                subnet_id,
                addr: IpAddr::V4(Ipv4Addr::new(192, 168, i as u8, j as u8)),
                port: 8080,
                tls_certificate: valid_tls_certificate_and_validation_time()
                    .0
                    .certificate_der,
                replica_version: "7742d96ddd30aa6b607c9d2d4093a7b714f5b25b".to_string(),
            };

            nodes.push(node.clone());
            nodes_hash.insert(node.id.to_string(), node);
        }

        subnets.push(Subnet {
            id: subnet_id,
            subnet_type: SubnetType::Application,
            ranges: vec![CanisterRange {
                start: node_test_id(NODE_ID_OFFSET + offset + i * 100).get().0,
                end: node_test_id(NODE_ID_OFFSET + offset + i * 100 + nodes_per_subnet)
                    .get()
                    .0,
            }],
            nodes,
            replica_version: "7742d96ddd30aa6b607c9d2d4093a7b714f5b25b".to_string(),
        });
    }

    RoutingTable {
        registry_version: 1,
        nns_subnet_id: Principal::from_text("fscpm-uiaaa-aaaaa-aaaap-yai").unwrap(),
        subnets,
        nodes: nodes_hash,
    }
}

fn node_id(id: u64) -> Principal {
    node_test_id(NODE_ID_OFFSET + id).get().0
}

fn check_result_ver(height: u64, lat: u64, ver: &str) -> CheckResult {
    CheckResult {
        height,
        latency: Duration::from_millis(lat),
        replica_version: ver.to_string(),
    }
}

fn check_result(height: u64, lat: u64) -> CheckResult {
    check_result_ver(height, lat, "a17247bd86c7aa4e87742bf74d108614580f216d")
}

// Ensure that nodes that have failed healthcheck or lag behind are excluded
#[tokio::test(flavor = "multi_thread")]
async fn test_check_some_unhealthy() -> Result<(), Error> {
    let routes = Arc::new(ArcSwapOption::empty());
    let persist = Persister::new(Arc::clone(&routes));
    let routing_table = Arc::new(ArcSwapOption::from_pointee(generate_custom_routing_table(
        2, 2, 0,
    )));

    let mut check = MockCheck::new();

    check
        .expect_check()
        .withf(|x: &Node| x.id == node_id(0))
        .times(1)
        .returning(|_| Ok(check_result(1000, 0)));

    check
        .expect_check()
        .withf(|x: &Node| x.id == node_id(1))
        .times(1)
        .returning(|_| Err(CheckError::Health));

    check
        .expect_check()
        .withf(|x: &Node| x.id == node_id(100))
        .times(1)
        .returning(|_| Ok(check_result(1010, 0)));

    check
        .expect_check()
        .withf(|x: &Node| x.id == node_id(101))
        .times(1)
        .returning(|_| Ok(check_result(500, 0)));

    let mut check_runner = Runner::new(Arc::clone(&routing_table), 1, 10, persist, check);
    check_runner.run().await.expect("run should succeed");

    let rt = routes.load_full().unwrap();

    // Make sure that only nodes 1 and 101 are not included in the resulting table
    assert!(rt.node_exists(node_id(0)));
    assert!(!rt.node_exists(node_id(1)));
    assert!(rt.node_exists(node_id(100)));
    assert!(!rt.node_exists(node_id(101)));

    Ok(())
}

// Ensure that when nodes are removed from routing table -> they're removed from the resulting lookup table
#[tokio::test(flavor = "multi_thread")]
async fn test_check_nodes_gone() -> Result<(), Error> {
    let routes = Arc::new(ArcSwapOption::empty());
    let persist = Persister::new(Arc::clone(&routes));
    let mut check = MockCheck::new();

    check
        .expect_check()
        .withf(|x: &Node| vec![node_id(0), node_id(1), node_id(100), node_id(101)].contains(&x.id))
        .times(10) // called 4 times for big table and 2 times for small one and 4 again
        .returning(|_| Ok(check_result(1000, 0)));

    // Generate a table with 4 nodes first
    let routing_table = Arc::new(ArcSwapOption::from_pointee(generate_custom_routing_table(
        2, 2, 0,
    )));
    let mut check_runner = Runner::new(Arc::clone(&routing_table), 1, 10, persist, check);
    check_runner.run().await.expect("run should succeed");

    let rt = routes.load_full().unwrap();
    assert!(rt.node_exists(node_id(0)));
    assert!(rt.node_exists(node_id(1)));
    assert!(rt.node_exists(node_id(100)));
    assert!(rt.node_exists(node_id(101)));

    // Generate a smaller table with 2 nodes now and store it
    let new_table = Arc::new(generate_custom_routing_table(2, 1, 0));
    routing_table.store(Some(new_table));

    check_runner.run().await.expect("run should succeed");

    // Check that only 2 nodes left
    let rt = routes.load_full().unwrap();
    assert!(rt.node_exists(node_id(0)));
    assert!(!rt.node_exists(node_id(1)));
    assert!(rt.node_exists(node_id(100)));
    assert!(!rt.node_exists(node_id(101)));

    // Generate a bigger table with 4 nodes again
    let new_table = Arc::new(generate_custom_routing_table(2, 2, 0));
    routing_table.store(Some(new_table));

    check_runner.run().await.expect("run should succeed");

    // Check that nodes are back
    let rt = routes.load_full().unwrap();
    assert!(rt.node_exists(node_id(0)));
    assert!(rt.node_exists(node_id(1)));
    assert!(rt.node_exists(node_id(100)));
    assert!(rt.node_exists(node_id(101)));

    Ok(())
}

// Ensure that min_ok_count is respected
#[tokio::test(flavor = "multi_thread")]
async fn test_check_min_ok() -> Result<(), Error> {
    let routes = Arc::new(ArcSwapOption::empty());
    let persist = Persister::new(Arc::clone(&routes));
    let mut check = MockCheck::new();
    let mut seq1 = Sequence::new();

    check
        .expect_check()
        .withf(|x: &Node| vec![node_id(0), node_id(1), node_id(100), node_id(101)].contains(&x.id))
        .times(4)
        .returning(|_| Ok(check_result(1000, 0)))
        .in_sequence(&mut seq1);

    check
        .expect_check()
        .withf(|x: &Node| vec![node_id(0), node_id(1), node_id(100), node_id(101)].contains(&x.id))
        .times(4)
        .returning(|_| Err(CheckError::Health))
        .in_sequence(&mut seq1);

    check
        .expect_check()
        .withf(|x: &Node| vec![node_id(0), node_id(1), node_id(100), node_id(101)].contains(&x.id))
        .times(20)
        .returning(|_| Ok(check_result(1000, 0)))
        .in_sequence(&mut seq1);

    // Generate a table
    let routing_table = Arc::new(ArcSwapOption::from_pointee(generate_custom_routing_table(
        2, 2, 0,
    )));
    let mut check_runner = Runner::new(Arc::clone(&routing_table), 5, 10, persist, check);

    for i in 0..7 {
        check_runner.run().await.expect("run should succeed");

        let rt = routes.load_full().unwrap();

        // Nodes should be up on 1st iteration and then gone until 5 oks are gathered
        if i == 0 || i == 6 {
            assert!(rt.node_exists(node_id(0)));
            assert!(rt.node_exists(node_id(1)));
            assert!(rt.node_exists(node_id(100)));
            assert!(rt.node_exists(node_id(101)));
        } else {
            assert!(!rt.node_exists(node_id(0)));
            assert!(!rt.node_exists(node_id(1)));
            assert!(!rt.node_exists(node_id(100)));
            assert!(!rt.node_exists(node_id(101)));
        }
    }

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_check_node_upgrade() -> Result<(), Error> {
    let routes = Arc::new(ArcSwapOption::empty());
    let persist = Persister::new(Arc::clone(&routes));
    let mut check = MockCheck::new();
    let mut seq1 = Sequence::new();

    check
        .expect_check()
        .withf(|x: &Node| vec![node_id(0), node_id(1), node_id(100), node_id(101)].contains(&x.id))
        .times(4)
        .returning(|_| Ok(check_result_ver(1000, 0, "ver1")))
        .in_sequence(&mut seq1);

    check
        .expect_check()
        .withf(|x: &Node| vec![node_id(0), node_id(1), node_id(100), node_id(101)].contains(&x.id))
        .times(4)
        .returning(|_| Err(CheckError::Health))
        .in_sequence(&mut seq1);

    check
        .expect_check()
        .withf(|x: &Node| vec![node_id(0), node_id(1), node_id(100), node_id(101)].contains(&x.id))
        .times(4)
        .returning(|_| Ok(check_result_ver(1000, 0, "ver2")))
        .in_sequence(&mut seq1);

    // Generate a table
    let routing_table = Arc::new(ArcSwapOption::from_pointee(generate_custom_routing_table(
        2, 2, 0,
    )));
    let mut check_runner = Runner::new(Arc::clone(&routing_table), 5, 10, persist, check);

    for i in 0..3 {
        check_runner.run().await.expect("run should succeed");

        let rt = routes.load_full().unwrap();

        // Nodes should be up on 1st run, then gone on 2nd due to errors
        // and then back again on 3rd when the version changes
        if i == 1 {
            assert!(!rt.node_exists(node_id(0)));
            assert!(!rt.node_exists(node_id(1)));
            assert!(!rt.node_exists(node_id(100)));
            assert!(!rt.node_exists(node_id(101)));
        } else {
            assert!(rt.node_exists(node_id(0)));
            assert!(rt.node_exists(node_id(1)));
            assert!(rt.node_exists(node_id(100)));
            assert!(rt.node_exists(node_id(101)));
        }
    }

    Ok(())
}
