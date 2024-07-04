use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr},
    sync::Arc,
};

use arc_swap::ArcSwapOption;
use candid::Principal;
use ic_registry_subnet_type::SubnetType;

use super::*;
use crate::{
    persist::{Persister, Routes},
    snapshot::{node_test_id, subnet_test_id, CanisterRange, Node, RegistrySnapshot, Subnet},
    test_utils::valid_tls_certificate_and_validation_time,
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

pub fn generate_custom_registry_snapshot(
    subnet_count: u64,
    nodes_per_subnet: u64,
    offset: u64,
) -> RegistrySnapshot {
    let mut subnets = Vec::new();
    let mut nodes_hash = HashMap::new();

    for i in 0..subnet_count {
        let subnet_id = subnet_test_id(offset + i).get().0;

        let mut nodes = Vec::new();
        for j in 0..nodes_per_subnet {
            let node = Node {
                id: node_test_id(NODE_ID_OFFSET + offset + i * 100 + j).get().0,
                subnet_id,
                subnet_type: SubnetType::Application,
                addr: IpAddr::V4(Ipv4Addr::new(192, 168, i as u8, j as u8)),
                port: 8080,
                tls_certificate: valid_tls_certificate_and_validation_time()
                    .0
                    .certificate_der,
                avg_latency_secs: f64::MAX,
            };
            let node = Arc::new(node);

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

    RegistrySnapshot {
        version: 1,
        timestamp: 123,
        nns_public_key: vec![],
        subnets,
        nodes: nodes_hash,
    }
}

fn node_id(id: u64) -> Principal {
    node_test_id(NODE_ID_OFFSET + id).get().0
}

fn check_result(height: u64) -> CheckResult {
    CheckResult {
        height,
        replica_version: "foobar".into(),
    }
}

// Ensure that nodes that have failed healthcheck or lag behind are excluded
#[tokio::test(flavor = "multi_thread")]
async fn test_check_some_unhealthy() -> Result<(), Error> {
    let routes = Arc::new(ArcSwapOption::empty());
    let persister = Arc::new(Persister::new(Arc::clone(&routes)));

    let mut checker = MockCheck::new();
    checker
        .expect_check()
        .withf(|x: &Node| x.id == node_id(0))
        .returning(|_| Ok(check_result(1000)));

    checker
        .expect_check()
        .withf(|x: &Node| x.id == node_id(1))
        .returning(|_| Err(CheckError::Health));

    checker
        .expect_check()
        .withf(|x: &Node| x.id == node_id(100))
        .returning(|_| Ok(check_result(1010)));

    checker
        .expect_check()
        .withf(|x: &Node| x.id == node_id(101))
        .returning(|_| Ok(check_result(500)));

    let (channel_send, channel_recv) = watch::channel(None);
    let mut runner = Runner::new(
        channel_recv,
        10,
        persister,
        Arc::new(checker),
        Duration::from_millis(100),
        Duration::from_millis(1),
    );
    tokio::spawn(async move {
        let _ = runner.run().await;
    });

    let snapshot = generate_custom_registry_snapshot(2, 2, 0);
    channel_send.send(Some(Arc::new(snapshot))).unwrap();

    // Wait until the routing table is published
    // TODO improve
    for _ in 1..10 {
        if routes.load().is_some() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

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
    let persister = Arc::new(Persister::new(Arc::clone(&routes)));

    let mut checker = MockCheck::new();
    checker
        .expect_check()
        .withf(|x: &Node| [node_id(0), node_id(1), node_id(100), node_id(101)].contains(&x.id))
        .returning(|_| Ok(check_result(1000)));

    let (channel_send, channel_recv) = watch::channel(None);
    let mut runner = Runner::new(
        channel_recv,
        10,
        persister,
        Arc::new(checker),
        Duration::from_millis(100),
        Duration::from_millis(1),
    );
    tokio::spawn(async move {
        let _ = runner.run().await;
    });

    // Generate & apply snapshot with 4 nodes first
    let snapshot = generate_custom_registry_snapshot(2, 2, 0);
    channel_send.send(Some(Arc::new(snapshot.clone()))).unwrap();

    // Wait until the routing table is published
    // TODO improve
    for _ in 1..10 {
        if routes.load().is_some() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    let rt = routes.load_full().unwrap();
    assert_eq!(rt.node_count, 4);
    assert!(rt.node_exists(node_id(0)));
    assert!(rt.node_exists(node_id(1)));
    assert!(rt.node_exists(node_id(100)));
    assert!(rt.node_exists(node_id(101)));

    routes.store(None);
    // Generate a smaller snapshot with 2 nodes
    let snapshot = generate_custom_registry_snapshot(2, 1, 0);
    channel_send.send(Some(Arc::new(snapshot.clone()))).unwrap();
    // Wait until the routing table is published
    // TODO improve
    for _ in 1..10 {
        if routes.load().is_some() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    // Check that only 2 nodes left
    let rt = routes.load_full().unwrap();
    assert_eq!(rt.node_count, 2);
    assert!(rt.node_exists(node_id(0)));
    assert!(!rt.node_exists(node_id(1)));
    assert!(rt.node_exists(node_id(100)));
    assert!(!rt.node_exists(node_id(101)));

    routes.store(None);
    // Generate a bigger table with 4 nodes again
    let snapshot = generate_custom_registry_snapshot(2, 2, 0);
    channel_send.send(Some(Arc::new(snapshot.clone()))).unwrap();
    // Wait until the routing table is published
    for _ in 1..10 {
        if routes.load().is_some() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    // Check that nodes are back
    let rt = routes.load_full().unwrap();
    assert_eq!(rt.node_count, 4);
    assert!(rt.node_exists(node_id(0)));
    assert!(rt.node_exists(node_id(1)));
    assert!(rt.node_exists(node_id(100)));
    assert!(rt.node_exists(node_id(101)));

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_runner() -> Result<(), Error> {
    let mut checker = MockCheck::new();
    checker.expect_check().returning(|_| Ok(check_result(1000)));

    let routes = Arc::new(ArcSwapOption::empty());
    let persister = Arc::new(Persister::new(Arc::clone(&routes)));

    let (channel_send, channel_recv) = watch::channel(None);
    let mut runner = Runner::new(
        channel_recv,
        10,
        persister,
        Arc::new(checker),
        Duration::from_millis(100),
        Duration::from_millis(1),
    );

    tokio::spawn(async move {
        let _ = runner.run().await;
    });

    // Send the snapshot
    let snapshot = generate_custom_registry_snapshot(2, 2, 0);
    channel_send.send(Some(Arc::new(snapshot.clone()))).unwrap();

    // Wait until the routing table is published
    // TODO improve
    for _ in 1..10 {
        if routes.load().is_some() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    let rt = routes.load_full().unwrap();
    assert_eq!(rt.node_count, snapshot.nodes.len() as u32);
    for (i, j) in [(0, 1), (1, 0)].iter() {
        let mut nodes_left = rt.subnets[*i].nodes.clone();
        let mut nodes_right = snapshot.subnets[*j].nodes.clone();
        nodes_left.sort_by_key(|n| n.id);
        nodes_right.sort_by_key(|n| n.id);
        assert_eq!(nodes_left, nodes_right);
    }

    Ok(())
}
