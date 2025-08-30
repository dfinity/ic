use std::sync::atomic::Ordering;

use ic_base_types::RegistryVersion;
use ic_interfaces_registry::RegistryClient;
use ic_p2p_test_utils::{
    create_peer_manager_and_registry_handle, create_peer_manager_with_local_store,
    mainnet_app_subnet, mainnet_nns_subnet,
};
use ic_test_utilities_logger::with_test_replica_logger;
use ic_types_test_utils::ids::node_test_id;

#[test]
fn test_single_node() {
    with_test_replica_logger(|log| {
        let rt = tokio::runtime::Runtime::new().unwrap();

        let (jh, mut receiver, mut registry_consensus_handle) =
            create_peer_manager_and_registry_handle(rt.handle(), log);

        rt.block_on(async move {
            let node_id = node_test_id(1);
            registry_consensus_handle.add_node(
                RegistryVersion::from(1),
                node_id,
                Some("2a02:41b:300e:0:6801:a3ff:fe71:4168"),
            );
            registry_consensus_handle
                .set_oldest_consensus_registry_version(RegistryVersion::from(0));

            // Wait for the peer manager to pick up the change.
            receiver.changed().await.unwrap();

            assert!(receiver.borrow().is_member(&node_id));
            assert!(receiver.borrow().get_addr(&node_id).is_some());
            assert!(receiver.borrow().iter().count() == 1);
            // If join handle finished sth went wrong and we propagate the error.
            if jh.is_finished() {
                jh.await.unwrap();
                panic!("Join handle should not finish.");
            }
        });
    })
}

#[test]
fn test_single_node_with_invalid_ip() {
    with_test_replica_logger(|log| {
        let rt = tokio::runtime::Runtime::new().unwrap();

        let (jh, mut receiver, mut registry_consensus_handle) =
            create_peer_manager_and_registry_handle(rt.handle(), log);

        rt.block_on(async move {
            let node_id = node_test_id(1);
            registry_consensus_handle.add_node(
                RegistryVersion::from(1),
                node_id,
                Some("2a02:41b:300e:0:6801:a3ff:fe71::::"),
            );
            registry_consensus_handle
                .set_oldest_consensus_registry_version(RegistryVersion::from(0));

            // Wait for the peer manager to pick up the change.
            receiver.changed().await.unwrap();

            // Peer has invalid IP and is therefore not relevant for subnet topology.
            assert!(receiver.borrow().iter().count() == 0);
            // If join handle finished sth went wrong and we propagate the error.
            if jh.is_finished() {
                jh.await.unwrap();
                panic!("Join handle should not finish.");
            }
        });
    })
}

#[test]
fn test_add_multiple_nodes() {
    with_test_replica_logger(|log| {
        let rt = tokio::runtime::Runtime::new().unwrap();

        let (jh, mut receiver, mut registry_consensus_handle) =
            create_peer_manager_and_registry_handle(rt.handle(), log);

        rt.block_on(async move {
            // Add first node
            let node_id_1 = node_test_id(1);
            registry_consensus_handle.add_node(
                RegistryVersion::from(1),
                node_id_1,
                Some("2a02:41b:300e:0:6801:a3ff:fe71:4168"),
            );
            registry_consensus_handle
                .set_oldest_consensus_registry_version(RegistryVersion::from(0));

            // Wait for the peer manager to pick up the change.
            receiver.changed().await.unwrap();
            assert!(receiver.borrow().is_member(&node_id_1));
            assert!(receiver.borrow().get_addr(&node_id_1).is_some());
            assert!(receiver.borrow().iter().count() == 1);

            // Add second node
            let node_id_2 = node_test_id(2);
            registry_consensus_handle.add_node(
                RegistryVersion::from(2),
                node_id_2,
                Some("2a02:41b:300e:0:6801:a3ff:fe71:4168"),
            );

            // Wait for the peer manager to pick up the change.
            receiver.changed().await.unwrap();
            assert!(receiver.borrow().is_member(&node_id_2));
            assert!(receiver.borrow().get_addr(&node_id_2).is_some());
            assert!(receiver.borrow().iter().count() == 2);

            // If join handle finished sth went wrong and we propagate the error.
            if jh.is_finished() {
                jh.await.unwrap();
                panic!("Join handle should not finish.");
            }
        });
    })
}

#[test]
fn test_endpoint_with_no_addr() {
    with_test_replica_logger(|log| {
        let rt = tokio::runtime::Runtime::new().unwrap();

        let (jh, mut receiver, mut registry_consensus_handle) =
            create_peer_manager_and_registry_handle(rt.handle(), log);

        rt.block_on(async move {
            // Add first node
            let node_id_1 = node_test_id(1);
            registry_consensus_handle.add_node(RegistryVersion::from(1), node_id_1, None);
            registry_consensus_handle
                .set_oldest_consensus_registry_version(RegistryVersion::from(0));

            // Peers with no address are not in membership.
            receiver.changed().await.unwrap();
            assert!(!receiver.borrow().is_member(&node_id_1));

            // Add address to peer.
            registry_consensus_handle.add_node(
                RegistryVersion::from(2),
                node_id_1,
                Some("2a02:41b:300e:0:6801:a3ff:fe71:4169"),
            );
            receiver.changed().await.unwrap();
            assert!(receiver.borrow().is_member(&node_id_1));
            assert!(receiver.borrow().get_addr(&node_id_1).is_some());

            // If the join handle finished something went wrong and we propagate the error.
            if jh.is_finished() {
                jh.await.unwrap();
                panic!("Join handle should not finish.");
            }
        });
    })
}

#[test]
fn test_add_multiple_nodes_remove_node() {
    with_test_replica_logger(|log| {
        let rt = tokio::runtime::Runtime::new().unwrap();

        let (jh, mut receiver, mut registry_consensus_handle) =
            create_peer_manager_and_registry_handle(rt.handle(), log);

        rt.block_on(async move {
            registry_consensus_handle
                .set_oldest_consensus_registry_version(RegistryVersion::from(0));
            // Add a few nodes
            for i in 1..11 {
                let node_id = node_test_id(i);
                registry_consensus_handle.add_node(
                    RegistryVersion::from(i),
                    node_id,
                    Some("2a02:41b:300e:0:6801:a3ff:fe71:4168"),
                );
            }

            // Wait for the peer manager to pick up the change.
            receiver
                .wait_for(|topology| topology.iter().count() == 10)
                .await
                .unwrap();
            for i in 1..11 {
                assert!(receiver.borrow().is_member(&node_test_id(i)));
                assert!(receiver.borrow().iter().count() == 10);
            }

            // Remove one node
            let removed_node_id = node_test_id(2);
            registry_consensus_handle.remove_node(RegistryVersion::from(12), removed_node_id);

            receiver.changed().await.unwrap();
            // Node should not yet be removed since consensus registry version is still at 0.
            assert!(receiver.borrow().is_member(&removed_node_id));
            assert!(receiver.borrow().iter().count() == 10);
            // Updating the consenus registry version to version higher than the remove proposal so
            // the node actually should gets removed.
            registry_consensus_handle
                .set_oldest_consensus_registry_version(RegistryVersion::from(13));
            registry_consensus_handle.set_latest_registry_version(RegistryVersion::from(14));
            receiver.changed().await.unwrap();
            assert!(!receiver.borrow().is_member(&removed_node_id));
            assert!(receiver.borrow().iter().count() == 9);

            // If join handle finished sth went wrong and we propagate the error.
            if jh.is_finished() {
                jh.await.unwrap();
                panic!("Join handle should not finish.");
            }
        });
    })
}

#[test]
fn test_can_read_nns_mainnet_registry() {
    with_test_replica_logger(|log| {
        let rt = tokio::runtime::Runtime::new().unwrap();

        let (jh, mut receiver, registry_client, consensus_registry_version, _tmp) =
            create_peer_manager_with_local_store(rt.handle(), log, mainnet_nns_subnet());
        let highest_version = registry_client.get_latest_version();
        let interval = 5;

        rt.block_on(async move {
            for v in (highest_version.get() - interval)..=highest_version.get() {
                consensus_registry_version.store(v, Ordering::SeqCst);
                receiver.changed().await.unwrap();
                let peer_num = receiver.borrow().iter().count();
                // NNS subnet usually has 30-40 nodes. Sanity check by verifying that there are
                // always at least 30 nodes.
                assert!(
                    peer_num > 30,
                    "Mainnet nns subnet should always have at least 30 nodes"
                );
            }

            // If join handle finished sth went wrong and we propagate the error.
            if jh.is_finished() {
                jh.await.unwrap();
                panic!("Join handle should not finish.");
            }
        });
    })
}

#[test]
fn test_can_read_app_mainnet_registry() {
    with_test_replica_logger(|log| {
        let rt = tokio::runtime::Runtime::new().unwrap();

        let (jh, mut receiver, registry_client, consensus_registry_version, _tmp) =
            create_peer_manager_with_local_store(rt.handle(), log, mainnet_app_subnet());
        let highest_version = registry_client.get_latest_version();
        let interval = 5;

        rt.block_on(async move {
            for v in (highest_version.get() - interval)..=highest_version.get() {
                consensus_registry_version.store(v, Ordering::SeqCst);
                receiver.changed().await.unwrap();
                let peer_num = receiver.borrow().iter().count();
                // App subnets usually have 13 nodes. Sanity check by verifying that there are
                // always at least 11 nodes.
                assert!(
                    peer_num > 11,
                    "Mainnet app subnet should always have at least 11 nodes"
                );
            }

            // If join handle finished something went wrong and we propagate the error.
            if jh.is_finished() {
                jh.await.unwrap();
                panic!("Join handle should not finish.");
            }
        });
    })
}
