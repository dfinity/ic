use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use crate::common::{
    SharableMockChunkable, State, create_node, latency_30ms_throughput_1000mbits,
    latency_50ms_throughput_300mbits,
};
use common::SharableMockStateSync;
use ic_interfaces::p2p::state_sync::{AddChunkError, ChunkId, StateSyncArtifactId};
use ic_logger::info;
use ic_memory_transport::TransportRouter;
use ic_p2p_test_utils::{
    ConnectivityChecker,
    mocks::MockStateSync,
    turmoil::{
        PeerManagerAction, add_peer_manager_to_sim, add_transport_to_sim, wait_for,
        wait_for_timeout, waiter_fut,
    },
};
use ic_test_utilities_logger::with_test_replica_logger;
use ic_types::{Height, RegistryVersion, crypto::CryptoHash};
use ic_types_test_utils::ids::{NODE_1, NODE_2, NODE_3};
use tokio::sync::Notify;
use turmoil::Builder;

mod common;

const TEST_STATE_SYNC_TIMEOUT: Duration = Duration::from_secs(120);

#[test]
fn test_two_nodes_sync() {
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let rt_handle = runtime.handle().clone();
    with_test_replica_logger(|log| {
        runtime.block_on(async move {
            let mut transport_router = TransportRouter::new();

            let global_state = State::new();

            // Create node that provides global state.
            let (state_sync_1, _join_handle_1) = create_node(
                0,
                log.clone(),
                &mut transport_router,
                &rt_handle,
                true,
                global_state.clone(),
                latency_30ms_throughput_1000mbits(),
            );

            // Create empty node
            let (state_sync_2, _join_handle_2) = create_node(
                1,
                log,
                &mut transport_router,
                &rt_handle,
                false,
                global_state.clone(),
                latency_50ms_throughput_300mbits(),
            );

            global_state.add_new_chunks(100, 1_000_000);

            // Verify that empty node has caught up
            let fut = async move {
                while !state_sync_2.is_equal(&state_sync_1) {
                    tokio::time::sleep(Duration::from_secs(2)).await;
                }
            };
            tokio::time::timeout(TEST_STATE_SYNC_TIMEOUT, fut)
                .await
                .unwrap();
        });
    });
}

/// Test one node syncing the state in a 13 node subnet.
/// It also tests what happens if the syncing node link is
/// at capacity.
#[test]
fn test_full_subnet() {
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let rt_handle = runtime.handle().clone();
    with_test_replica_logger(|log| {
        runtime.block_on(async move {
            let mut transport_router = TransportRouter::new();
            let subnet_size = 13;
            let global_state = State::new();

            // Create empty node
            let (state_sync_empty, _join_handle_empty) = create_node(
                0,
                log.clone(),
                &mut transport_router,
                &rt_handle,
                false,
                global_state.clone(),
                latency_50ms_throughput_300mbits(),
            );

            let mut join_handles = Vec::new();
            let mut states = Vec::new();
            // Create nodes that provide global state.
            for i in 1..subnet_size {
                let (state_sync, join_handle) = create_node(
                    i,
                    log.clone(),
                    &mut transport_router,
                    &rt_handle,
                    true,
                    global_state.clone(),
                    latency_30ms_throughput_1000mbits(),
                );
                join_handles.push(join_handle);
                states.push(state_sync);
            }
            global_state.add_new_chunks(250, 1_000_000);

            // Verify that empty node has caught up
            let fut = async move {
                while !states.is_empty() {
                    tokio::time::sleep(Duration::from_secs(2)).await;
                    states.retain(|s| !s.is_equal(&state_sync_empty));
                }
            };
            tokio::time::timeout(TEST_STATE_SYNC_TIMEOUT, fut)
                .await
                .unwrap();
        });
    });
}

/// Test one node syncing the state in a 13 node subnet with many small chunks.
#[test]
fn test_full_subnet_mini_chunks() {
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let rt_handle = runtime.handle().clone();
    with_test_replica_logger(|log| {
        runtime.block_on(async move {
            let mut transport_router = TransportRouter::new();
            let subnet_size = 13;
            let global_state = State::new();

            // Create empty node
            let (state_sync_empty, _join_handle_empty) = create_node(
                0,
                log.clone(),
                &mut transport_router,
                &rt_handle,
                false,
                global_state.clone(),
                latency_50ms_throughput_300mbits(),
            );

            let mut join_handles = Vec::new();
            let mut states = Vec::new();
            // Create nodes that provide global state.
            for i in 1..subnet_size {
                let (state_sync, join_handle) = create_node(
                    i,
                    log.clone(),
                    &mut transport_router,
                    &rt_handle,
                    true,
                    global_state.clone(),
                    latency_30ms_throughput_1000mbits(),
                );
                join_handles.push(join_handle);
                states.push(state_sync);
            }
            global_state.add_new_chunks(40000, 1000);

            // Verify that empty node has caught up
            let fut = async move {
                while !states.is_empty() {
                    tokio::time::sleep(Duration::from_secs(2)).await;
                    states.retain(|s| !s.is_equal(&state_sync_empty));
                }
            };
            tokio::time::timeout(TEST_STATE_SYNC_TIMEOUT, fut)
                .await
                .unwrap();
        });
    });
}

/// Test one node syncing the state in a 13 node subnet with a quickly changing state to sync.
#[test]
fn test_full_subnet_fast_changing_state() {
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let rt_handle = runtime.handle().clone();
    with_test_replica_logger(|log| {
        runtime.block_on(async move {
            let mut transport_router = TransportRouter::new();
            let subnet_size = 13;
            let changing_state_duration = Duration::from_secs(20);
            let global_state = State::new();

            // Create empty node
            let (state_sync_empty, _join_handle_empty) = create_node(
                0,
                log.clone(),
                &mut transport_router,
                &rt_handle,
                false,
                global_state.clone(),
                latency_50ms_throughput_300mbits(),
            );

            let mut join_handles = Vec::new();
            let mut states = Vec::new();
            // Create nodes that provide global state.
            for i in 1..subnet_size {
                let (state_sync, join_handle) = create_node(
                    i,
                    log.clone(),
                    &mut transport_router,
                    &rt_handle,
                    true,
                    global_state.clone(),
                    latency_30ms_throughput_1000mbits(),
                );
                join_handles.push(join_handle);
                states.push(state_sync);
            }

            let fut = async move {
                loop {
                    global_state.add_new_chunks(100, 500_000);
                    tokio::time::sleep(Duration::from_secs(2)).await;
                }
            };
            // Let state sync run under a fast changing state
            let _ = tokio::time::timeout(changing_state_duration, fut).await;

            // Verify that empty node has caught up
            let fut = async move {
                while !states.is_empty() {
                    tokio::time::sleep(Duration::from_secs(2)).await;
                    states.retain(|s| !s.is_equal(&state_sync_empty));
                }
            };
            tokio::time::timeout(TEST_STATE_SYNC_TIMEOUT, fut)
                .await
                .unwrap();
        });
    });
}

/// Test 13 node subnet syncing state from one node.
#[test]
fn test_full_subnet_syncing_from_one_node() {
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let rt_handle = runtime.handle().clone();
    with_test_replica_logger(|log| {
        runtime.block_on(async move {
            let mut transport_router = TransportRouter::new();
            let subnet_size = 13;
            let global_state = State::new();

            // Create one node with global state
            let (state_sync_global, _join_handle_global) = create_node(
                0,
                log.clone(),
                &mut transport_router,
                &rt_handle,
                true,
                global_state.clone(),
                latency_30ms_throughput_1000mbits(),
            );

            let mut join_handles = Vec::new();
            let mut states = Vec::new();
            // Create node that try to sync the global state.
            for i in 1..subnet_size {
                let (state_sync, join_handle) = create_node(
                    i,
                    log.clone(),
                    &mut transport_router,
                    &rt_handle,
                    false,
                    global_state.clone(),
                    latency_50ms_throughput_300mbits(),
                );
                join_handles.push(join_handle);
                states.push(state_sync);
            }

            global_state.add_new_chunks(250, 500_000);

            // Verify that the empty nodes have caught up.
            let fut = async move {
                while !states.is_empty() {
                    tokio::time::sleep(Duration::from_secs(2)).await;
                    states.retain(|s| !s.is_equal(&state_sync_global));
                }
            };

            tokio::time::timeout(TEST_STATE_SYNC_TIMEOUT, fut)
                .await
                .unwrap();
        });
    });
}

/// Test state sync advert ping pong between two nodes over quic transport.
#[test]
fn test_single_advert_between_two_nodes() {
    with_test_replica_logger(|log| {
        let mut sim = Builder::new()
            .tick_duration(Duration::from_millis(100))
            .simulation_duration(Duration::from_secs(20))
            .build();
        let exit_notify = Arc::new(Notify::new());

        // Node 1 advertises height 1
        // Node 2 advertises height 2
        // n1_a1 = node1 advert1
        let received_advert_n1_a2 = Arc::new(AtomicBool::new(false));
        let received_advert_n2_a1 = Arc::new(AtomicBool::new(false));
        let state_sync_id_1 = StateSyncArtifactId {
            height: Height::from(1),
            hash: CryptoHash(vec![]),
        };
        let state_sync_id_2 = StateSyncArtifactId {
            height: Height::from(2),
            hash: CryptoHash(vec![]),
        };
        let state_sync_id_2_clone = state_sync_id_2.clone();
        let state_sync_id_1_clone = state_sync_id_1.clone();
        let received_advert_n1_a2_clone = received_advert_n1_a2.clone();
        let received_advert_n2_a1_clone = received_advert_n2_a1.clone();

        // Mock state sync that expects advert from other peer
        let mut state_sync_n1 = MockStateSync::new();
        state_sync_n1
            .expect_available_states()
            .return_const(vec![state_sync_id_1]);
        state_sync_n1
            .expect_maybe_start_state_sync()
            .withf(move |id| {
                if id == &state_sync_id_2_clone {
                    received_advert_n1_a2_clone.store(true, Ordering::SeqCst);
                    true
                } else {
                    false
                }
            })
            .returning(|_| None);

        let mut state_sync_n2 = MockStateSync::new();
        state_sync_n2
            .expect_available_states()
            .return_const(vec![state_sync_id_2]);
        state_sync_n2
            .expect_maybe_start_state_sync()
            .withf(move |id| {
                if id == &state_sync_id_1_clone {
                    received_advert_n2_a1_clone.store(true, Ordering::SeqCst);
                    true
                } else {
                    false
                }
            })
            .returning(|_| None);

        let (peer_manager_cmd_sender, topology_watcher, registry_handle) =
            add_peer_manager_to_sim(&mut sim, exit_notify.clone(), log.clone());

        add_transport_to_sim(
            &mut sim,
            log.clone(),
            NODE_1,
            registry_handle.clone(),
            topology_watcher.clone(),
            None,
            None,
            Some(Arc::new(state_sync_n1)),
            None,
            waiter_fut(),
        );

        add_transport_to_sim(
            &mut sim,
            log,
            NODE_2,
            registry_handle.clone(),
            topology_watcher,
            None,
            None,
            Some(Arc::new(state_sync_n2)),
            None,
            waiter_fut(),
        );

        peer_manager_cmd_sender
            .send(PeerManagerAction::Add((NODE_1, RegistryVersion::from(2))))
            .unwrap();
        peer_manager_cmd_sender
            .send(PeerManagerAction::Add((NODE_2, RegistryVersion::from(3))))
            .unwrap();
        registry_handle.registry_client.reload();
        registry_handle.registry_client.update_to_latest_version();

        // Wait until both peers have receive one state advert
        wait_for(&mut sim, || {
            received_advert_n2_a1.load(Ordering::SeqCst)
                && received_advert_n1_a2.load(Ordering::SeqCst)
        })
        .expect("Node did not receive advert from other peer");

        exit_notify.notify_waiters();
        sim.run().unwrap();
    });
}

/// Test state sync advert ping pong with multiple adverts between two nodes over quic transport.
/// Verifies that both adverts are advertised.
#[test]
fn test_multiple_advert_between_two_nodes() {
    with_test_replica_logger(|log| {
        let mut sim = Builder::new()
            .tick_duration(Duration::from_millis(100))
            .simulation_duration(Duration::from_secs(20))
            .build();
        let exit_notify = Arc::new(Notify::new());

        // Both nodes advertise height 1 and 2.
        // n1_a1 = node1 advert1
        let received_advert_n1_a1 = Arc::new(AtomicBool::new(false));
        let received_advert_n2_a1 = Arc::new(AtomicBool::new(false));
        let received_advert_n1_a2 = Arc::new(AtomicBool::new(false));
        let received_advert_n2_a2 = Arc::new(AtomicBool::new(false));
        let state_sync_id_1 = StateSyncArtifactId {
            height: Height::from(1),
            hash: CryptoHash(vec![]),
        };
        let state_sync_id_2 = StateSyncArtifactId {
            height: Height::from(2),
            hash: CryptoHash(vec![]),
        };
        let state_sync_id_2_clone = state_sync_id_2.clone();
        let state_sync_id_1_clone = state_sync_id_1.clone();
        let received_advert_n1_a1_clone = received_advert_n1_a1.clone();
        let received_advert_n2_a1_clone = received_advert_n2_a1.clone();
        let received_advert_n1_a2_clone = received_advert_n1_a2.clone();
        let received_advert_n2_a2_clone = received_advert_n2_a2.clone();

        // Mock state sync that expects both adverts.
        let mut state_sync_n1 = MockStateSync::new();
        state_sync_n1
            .expect_available_states()
            .return_const(vec![state_sync_id_1_clone, state_sync_id_2_clone]);
        let state_sync_id_2_clone = state_sync_id_2.clone();
        let state_sync_id_1_clone = state_sync_id_1.clone();
        state_sync_n1
            .expect_maybe_start_state_sync()
            .withf(move |id| {
                if id == &state_sync_id_1_clone {
                    received_advert_n2_a1_clone.store(true, Ordering::SeqCst);
                    true
                } else if id == &state_sync_id_2_clone {
                    received_advert_n2_a2_clone.store(true, Ordering::SeqCst);
                    true
                } else {
                    false
                }
            })
            .returning(|_| None);

        let state_sync_id_2_clone = state_sync_id_2.clone();
        let state_sync_id_1_clone = state_sync_id_1.clone();
        let mut state_sync_n2 = MockStateSync::new();
        state_sync_n2
            .expect_available_states()
            .return_const(vec![state_sync_id_1, state_sync_id_2]);
        state_sync_n2
            .expect_maybe_start_state_sync()
            .withf(move |id| {
                if id == &state_sync_id_1_clone {
                    received_advert_n1_a1_clone.store(true, Ordering::SeqCst);
                    true
                } else if id == &state_sync_id_2_clone {
                    received_advert_n1_a2_clone.store(true, Ordering::SeqCst);
                    true
                } else {
                    false
                }
            })
            .returning(|_| None);

        let (peer_manager_cmd_sender, topology_watcher, registry_handle) =
            add_peer_manager_to_sim(&mut sim, exit_notify.clone(), log.clone());

        add_transport_to_sim(
            &mut sim,
            log.clone(),
            NODE_1,
            registry_handle.clone(),
            topology_watcher.clone(),
            None,
            None,
            Some(Arc::new(state_sync_n1)),
            None,
            waiter_fut(),
        );

        add_transport_to_sim(
            &mut sim,
            log,
            NODE_2,
            registry_handle.clone(),
            topology_watcher,
            None,
            None,
            Some(Arc::new(state_sync_n2)),
            None,
            waiter_fut(),
        );

        peer_manager_cmd_sender
            .send(PeerManagerAction::Add((NODE_1, RegistryVersion::from(2))))
            .unwrap();
        peer_manager_cmd_sender
            .send(PeerManagerAction::Add((NODE_2, RegistryVersion::from(3))))
            .unwrap();
        registry_handle.registry_client.reload();
        registry_handle.registry_client.update_to_latest_version();

        // Wait until both peers have receive one state advert
        wait_for(&mut sim, || {
            received_advert_n1_a1.load(Ordering::SeqCst)
                && received_advert_n2_a1.load(Ordering::SeqCst)
                && received_advert_n2_a2.load(Ordering::SeqCst)
                && received_advert_n1_a2.load(Ordering::SeqCst)
        })
        .expect("Node did not receive advert from other peer");

        exit_notify.notify_waiters();
        sim.run().unwrap();
    });
}

/// Tests correct abortion of a state sync because of bad peer behaviour.
/// - Verifies that peers expected number of adverts
/// - Start state sync and add two peers
/// - One peer is removed by crashing the node
/// - Other peer is removed because of failed chunk verification
/// - Verify that there is no active state sync
#[test]
fn test_state_sync_abortion() {
    with_test_replica_logger(|log| {
        let mut sim = Builder::new()
            .tick_duration(Duration::from_millis(100))
            .simulation_duration(Duration::from_secs(40))
            .build();
        let exit_notify = Arc::new(Notify::new());

        let s1 = SharableMockStateSync::new();
        let s2 = SharableMockStateSync::new();
        let s3 = SharableMockStateSync::new();

        let (peer_manager_cmd_sender, topology_watcher, registry_handle) =
            add_peer_manager_to_sim(&mut sim, exit_notify.clone(), log.clone());

        let conn_checker = ConnectivityChecker::new(&[NODE_1, NODE_2, NODE_3]);

        add_transport_to_sim(
            &mut sim,
            log.clone(),
            NODE_1,
            registry_handle.clone(),
            topology_watcher.clone(),
            Some(ConnectivityChecker::router()),
            None,
            Some(Arc::new(s1.clone())),
            None,
            conn_checker.check_fut(),
        );

        add_transport_to_sim(
            &mut sim,
            log.clone(),
            NODE_2,
            registry_handle.clone(),
            topology_watcher.clone(),
            Some(ConnectivityChecker::router()),
            None,
            Some(Arc::new(s2.clone())),
            None,
            conn_checker.check_fut(),
        );

        add_transport_to_sim(
            &mut sim,
            log.clone(),
            NODE_3,
            registry_handle.clone(),
            topology_watcher,
            Some(ConnectivityChecker::router()),
            None,
            Some(Arc::new(s3.clone())),
            None,
            conn_checker.check_fut(),
        );

        peer_manager_cmd_sender
            .send(PeerManagerAction::Add((NODE_1, RegistryVersion::from(2))))
            .unwrap();
        peer_manager_cmd_sender
            .send(PeerManagerAction::Add((NODE_2, RegistryVersion::from(3))))
            .unwrap();
        peer_manager_cmd_sender
            .send(PeerManagerAction::Add((NODE_3, RegistryVersion::from(4))))
            .unwrap();
        registry_handle.registry_client.reload();
        registry_handle.registry_client.update_to_latest_version();

        // Wait till all nodes connected
        s1.get_mut().expect_available_states().return_const(vec![]);
        s2.get_mut().expect_available_states().return_const(vec![]);
        s3.get_mut().expect_available_states().return_const(vec![]);
        wait_for(&mut sim, || conn_checker.fully_connected())
            .expect("The network did not reach a fully connected state after startup");

        // Node 1 advertises 10 states
        s1.get_mut().checkpoint();
        s1.get_mut()
            .expect_available_states()
            .times(1)
            .return_once(|| {
                vec![
                    StateSyncArtifactId {
                        height: Height::from(1),
                        hash: CryptoHash(vec![]),
                    };
                    10
                ]
            });
        s1.get_mut().expect_available_states().return_const(vec![]);
        s1.get_mut()
            .expect_chunk()
            .returning(|_, _| Some(vec![].into()));

        // Verify that peers got expected number of adverts. The last advert on node 2
        // is used to start the state sync.
        s2.get_mut()
            .expect_maybe_start_state_sync()
            .times(9)
            .returning(|_| None);
        s3.get_mut()
            .expect_maybe_start_state_sync()
            .times(10)
            .returning(|_| None);

        // Start state sync for Node 2. Initially only Node 1 is part of the state sync.
        let c2 = SharableMockChunkable::new();
        c2.get_mut()
            .expect_chunks_to_download()
            .returning(|| Box::new(vec![ChunkId::from(1)].into_iter()) as Box<_>);
        c2.get_mut().expect_add_chunk().return_const(Ok(()));
        {
            let c2 = c2.clone();
            s2.get_mut()
                .expect_maybe_start_state_sync()
                .times(1)
                .return_once(|_| Some(Box::new(c2)));
        }
        s2.get_mut().expect_cancel_if_running().returning(|_| false);

        // Wait until both peers have receive one state advert
        wait_for(&mut sim, || {
            s2.maybe_start_state_sync_calls() == 10 && s3.maybe_start_state_sync_calls() == 10
        })
        .expect("Node did not receive advert from other peer");

        info!(
            log,
            "Started state sync on Node 2 based on adverts from Node 1"
        );

        // Add Node 3 to state sync by advertising the state once.
        s3.get_mut().checkpoint();
        s3.get_mut()
            .expect_chunk()
            .returning(|_, _| Some(vec![].into()));
        s3.get_mut()
            .expect_available_states()
            .once()
            .return_once(|| {
                vec![StateSyncArtifactId {
                    height: Height::from(1),
                    hash: CryptoHash(vec![]),
                }]
            });
        s1.get_mut()
            .expect_maybe_start_state_sync()
            .once()
            .returning(|_| None);
        s2.get_mut()
            .expect_maybe_start_state_sync()
            .never()
            .returning(|_| None);
        s3.get_mut().expect_available_states().return_const(vec![]);

        // Wait until both peers have receive one state advert.
        s1.clear();
        s2.clear();
        s3.clear();
        wait_for(&mut sim, || {
            s1.maybe_start_state_sync_calls() == 1 && s2.maybe_start_state_sync_calls() == 0
        })
        .unwrap();

        // Crash Node 1. This removes Node1 from the state sync.
        sim.crash(NODE_1.to_string());
        wait_for_timeout(&mut sim, || false, Duration::from_secs(5)).unwrap();

        // Simulate that Node 3 responds with an invalid chunk.
        c2.get_mut().checkpoint();
        c2.clear();
        c2.get_mut()
            .expect_add_chunk()
            .returning(|_, _| Err(AddChunkError::Invalid));
        c2.get_mut()
            .expect_chunks_to_download()
            .returning(|| Box::new(vec![ChunkId::from(1)].into_iter()) as Box<_>);
        wait_for(&mut sim, || c2.add_chunks_calls() >= 1).unwrap();

        // State sync should now be stopped. This means new incoming adverts will invoke `maybe_start_state_sync`
        s2.clear();
        s3.clear();
        s3.get_mut().checkpoint();
        s2.get_mut().checkpoint();
        s3.get_mut()
            .expect_available_states()
            .once()
            .return_once(|| {
                vec![StateSyncArtifactId {
                    height: Height::from(1),
                    hash: CryptoHash(vec![]),
                }]
            });
        s2.get_mut().expect_available_states().return_const(vec![]);
        s2.get_mut()
            .expect_maybe_start_state_sync()
            .once()
            .returning(|_| None);
        wait_for(&mut sim, || s2.maybe_start_state_sync_calls() == 1).unwrap();

        exit_notify.notify_waiters();
        // Check that all expectations are met.
        s1.get_mut().checkpoint();
        s2.get_mut().checkpoint();
        s3.get_mut().checkpoint();
        sim.run().unwrap();
    });
}
