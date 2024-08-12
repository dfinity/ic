use std::{backtrace::Backtrace, collections::HashMap, ops::Range, sync::Arc, time::Duration};

use futures::StreamExt;
use ic_logger::{replica_logger::no_op_logger, ReplicaLogger};
use ic_p2p_test_utils::{
    consensus::{TestConsensus, U64Artifact},
    fully_connected_localhost_subnet, start_consensus_manager,
    turmoil::{
        add_peer_manager_to_sim, add_transport_to_sim, run_simulation_for, wait_for,
        wait_for_timeout, waiter_fut, PeerManagerAction,
    },
};
use ic_test_utilities_logger::with_test_replica_logger;
use ic_types::{NodeId, RegistryVersion};
use ic_types_test_utils::ids::{node_test_id, NODE_1, NODE_2, NODE_3};
use rand::{rngs::ThreadRng, Rng};
use tokio::{sync::Notify, task::JoinSet};
use tokio_util::time::DelayQueue;
use turmoil::Builder;

const TIMEOUT_DURATION_TRIGGER: Duration = Duration::from_secs(5);

#[test]
fn test_artifact_sent_to_other_peer() {
    with_test_replica_logger(|log| {
        let mut sim = Builder::new()
            .tick_duration(Duration::from_millis(100))
            .simulation_duration(Duration::from_secs(60 * 60))
            .build();

        let exit_notify = Arc::new(Notify::new());
        let (peer_manager_cmd_sender, topology_watcher, registry_handle) =
            add_peer_manager_to_sim(&mut sim, exit_notify.clone(), log.clone());
        let processor_1 = TestConsensus::new(log.clone(), NODE_1, 1024, false);
        let processor_2 = TestConsensus::new(log.clone(), NODE_2, 2048, true);

        add_transport_to_sim(
            &mut sim,
            log.clone(),
            NODE_1,
            registry_handle.clone(),
            topology_watcher.clone(),
            None,
            None,
            None,
            Some(processor_1.clone()),
            waiter_fut(),
        );
        add_transport_to_sim(
            &mut sim,
            log.clone(),
            NODE_2,
            registry_handle.clone(),
            topology_watcher.clone(),
            None,
            None,
            None,
            Some(processor_2.clone()),
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

        processor_1.push_advert(1);

        wait_for(&mut sim, || processor_2.received_advert_once(1))
            .expect("NODE_2 did not receive the advert from NODE_1.");

        exit_notify.notify_waiters();
        sim.run().unwrap();
    });
}

#[test]
fn test_artifact_in_validated_pool_is_sent_to_peer_joining_subnet() {
    with_test_replica_logger(|log| {
        let mut sim = Builder::new()
            .tick_duration(Duration::from_millis(100))
            .simulation_duration(Duration::from_secs(60 * 60))
            .build();

        let exit_notify = Arc::new(Notify::new());
        let (peer_manager_cmd_sender, topology_watcher, registry_handle) =
            add_peer_manager_to_sim(&mut sim, exit_notify.clone(), log.clone());
        let processor_1 = TestConsensus::new(log.clone(), NODE_1, 1024, false);
        let processor_2 = TestConsensus::new(log.clone(), NODE_2, 2048, true);

        add_transport_to_sim(
            &mut sim,
            log.clone(),
            NODE_1,
            registry_handle.clone(),
            topology_watcher.clone(),
            None,
            None,
            None,
            Some(processor_1.clone()),
            waiter_fut(),
        );
        add_transport_to_sim(
            &mut sim,
            log.clone(),
            NODE_2,
            registry_handle.clone(),
            topology_watcher.clone(),
            None,
            None,
            None,
            Some(processor_2.clone()),
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

        // Node_1 sends the advert
        processor_1.push_advert(1);

        // Node_2 has received the advert
        wait_for(&mut sim, || processor_2.received_advert_once(1)).unwrap();

        // Node 3 joins the subnet
        let processor_3 = TestConsensus::new(log.clone(), NODE_3, 4096, false);
        add_transport_to_sim(
            &mut sim,
            log.clone(),
            NODE_3,
            registry_handle.clone(),
            topology_watcher.clone(),
            None,
            None,
            None,
            Some(processor_3.clone()),
            waiter_fut(),
        );

        peer_manager_cmd_sender
            .send(PeerManagerAction::Add((NODE_3, RegistryVersion::from(4))))
            .unwrap();
        registry_handle.registry_client.reload();
        registry_handle.registry_client.update_to_latest_version();

        // Node 3 has received the advert
        wait_for(&mut sim, || processor_3.received_advert_once(1))
            .expect("NODE_3 did not receive the advert from NODE_1 after joining the subnet.");

        exit_notify.notify_waiters();
        sim.run().unwrap();
    });
}

#[test]
fn test_flapping_connection_does_not_cause_duplicate_artifact_assemble() {
    with_test_replica_logger(|log| {
        let mut sim = Builder::new()
            .tick_duration(Duration::from_millis(100))
            .simulation_duration(Duration::from_secs(60 * 60))
            .build();

        let exit_notify = Arc::new(Notify::new());
        let (peer_manager_cmd_sender, topology_watcher, registry_handle) =
            add_peer_manager_to_sim(&mut sim, exit_notify.clone(), log.clone());
        let processor_1 = TestConsensus::new(log.clone(), NODE_1, 1024, false);
        let processor_2 = TestConsensus::new(log.clone(), NODE_2, 2048, true);

        add_transport_to_sim(
            &mut sim,
            log.clone(),
            NODE_1,
            registry_handle.clone(),
            topology_watcher.clone(),
            None,
            None,
            None,
            Some(processor_1.clone()),
            waiter_fut(),
        );
        add_transport_to_sim(
            &mut sim,
            log.clone(),
            NODE_2,
            registry_handle.clone(),
            topology_watcher.clone(),
            None,
            None,
            None,
            Some(processor_2.clone()),
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

        // Node_1 sends the advert
        processor_1.push_advert(1);

        // Node_2 has received the advert
        wait_for(&mut sim, || processor_2.received_advert_once(1)).unwrap();

        // Disconnect nodes, and run simulation for 5s.
        sim.partition(NODE_1.to_string(), NODE_2.to_string());
        processor_1.push_advert(2);
        wait_for_timeout(
            &mut sim,
            || processor_2.received_advert_once(2),
            Duration::from_secs(5),
        )
        .unwrap();

        sim.repair(NODE_1.to_string(), NODE_2.to_string());
        wait_for(&mut sim, || processor_2.received_advert_once(2)).unwrap();

        assert!(processor_2.received_advert_once(1));

        exit_notify.notify_waiters();
        sim.run().unwrap();
    });
}

async fn generate_consensus_events(
    processor: TestConsensus<U64Artifact>,
    test_duration: Duration,
    purge_fraction: f64,
    num_event: u64,
    max_purge_delay: Duration,
    id_range: Range<u64>,
) {
    enum Event {
        Insert(u64),
        Purge(u64),
    }
    let mut delay_queue = DelayQueue::new();
    {
        let mut rng = ThreadRng::default();

        for _ in 0..num_event {
            let rand_id = rng.gen_range(id_range.clone());
            let insert_time =
                Duration::from_millis(rng.gen_range(0..test_duration.as_millis()) as u64);
            delay_queue.insert(Event::Insert(rand_id), insert_time);
        }
    }

    while let Some(v) = delay_queue.next().await {
        match v.into_inner() {
            Event::Insert(e) => {
                processor.push_advert(e);

                let mut rng = ThreadRng::default();
                let should_purge = rng.gen_bool(purge_fraction);
                if should_purge {
                    let purge_delay = rng.gen_range(0..max_purge_delay.as_millis() as u64);
                    delay_queue.insert(Event::Purge(e), Duration::from_millis(purge_delay));
                }
            }
            Event::Purge(e) => processor.push_purge(e),
        }
    }
}

/// Verifies that all active adverts sent by Node A are present in the pool of every peer.
fn check_pools_equal(node_pool_map: &HashMap<NodeId, TestConsensus<U64Artifact>>) -> bool {
    for (node1, pool1) in node_pool_map {
        for (node2, pool2) in node_pool_map {
            // Check that all adverts produced by 1 were received by 2.
            if node2 != node1 {
                // If other pool subset everything is fine
                if !pool1.my_pool().is_subset(&pool2.peer_pool(node1)) {
                    // It can be case that multiple peers advertised same id and it only got downloaded from a different peer.
                    // In that case check that the id is contained in some other pool.
                    for diff in pool1.my_pool().difference(&pool2.peer_pool(node1)) {
                        let mut found = false;
                        for n in node_pool_map.keys() {
                            if n != node1 && pool2.peer_pool(n).contains(diff) {
                                found |= true;
                            }
                        }
                        if !found {
                            return false;
                        }
                    }
                }
            }
        }
    }
    true
}

struct LoadParameters {
    num_peers: u64,
    num_events: u64,
    purge_fraction: f64,
    id_overlap: bool,
    id_range: Range<u64>,
}

/// Generates load test for the consensus manager by generating a event sequence of pool additions/removals and verifies
/// that the pools contains all expected elements according to `check_pools_equal` after all events were emitted.
/// id: Unique test id that is used for localhost IP allocation.
/// num_peers: Number of consensus managers to spawn
/// num_events: Number of add/remove events to generate.
/// purge_fraction: Number of add events that have a corresponding purge event. Setting it to 1 means that every add event has remove event that follows later.
///                 Later meaning 0-MAX_PURGE_DELAY after the insert.
/// id_overlap: If true all advert ids used are unique for a peer.
/// id_range: ID range from which to pick a random advert ID.
fn load_test(
    log: ReplicaLogger,
    id: u8,
    LoadParameters {
        num_peers,
        num_events,
        purge_fraction,
        id_overlap,
        id_range,
    }: LoadParameters,
) {
    const TEST_DURATION: Duration = Duration::from_secs(20);
    const MAX_PURGE_DELAY: Duration = Duration::from_secs(4);

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(2)
        .build()
        .unwrap();
    let mut node_advert_map = HashMap::new();
    let mut jhs = vec![];
    let mut nodes = vec![];
    let mut cms = vec![];
    for i in 0..num_peers {
        let node = node_test_id(i);
        let processor = TestConsensus::new(log.clone(), node, 256 * (i as usize + 1), i % 2 == 0);
        let (jh, mut cm) =
            start_consensus_manager(no_op_logger(), rt.handle().clone(), processor.clone());
        jhs.push(jh);
        nodes.push((node, cm.router()));
        cms.push((node, cm));
        node_advert_map.insert(node, processor);
    }
    let (nodes, topology_watcher) = fully_connected_localhost_subnet(rt.handle(), log, id, nodes);
    for ((node1, transport), (node2, cm)) in nodes.into_iter().zip(cms.into_iter()) {
        assert!(node1 == node2);
        cm.run(transport, topology_watcher.clone());
    }

    rt.block_on(async move {
        let mut load_set = JoinSet::new();
        // Generate some random load
        for (i, processor) in node_advert_map.values().enumerate() {
            load_set.spawn(generate_consensus_events(
                processor.clone(),
                TEST_DURATION,
                purge_fraction,
                num_events,
                MAX_PURGE_DELAY,
                if id_overlap {
                    id_range.clone()
                } else {
                    let range_len = id_range.end - id_range.start;
                    Range {
                        start: id_range.start + i as u64 * range_len,
                        end: id_range.end + i as u64 * range_len,
                    }
                },
            ));
        }

        while load_set.join_next().await.is_some() {}

        loop {
            if check_pools_equal(&node_advert_map) {
                break;
            }
            tokio::time::sleep(Duration::from_secs(5)).await;
        }
    });
}
/// NOTE: The values used for the tests below do not test anything specific and are set
/// to cover a variety of scenarios. The error signal of these tests is flakiness which indicate
/// that there might be some hidden race condition in the code.
///
///
/// Small load test with four nodes and overlapping advert Id
#[test]
fn test_small_load_test() {
    // Abort process if a thread panics. This catches detached tokio tasks that panic.
    // https://github.com/tokio-rs/tokio/issues/4516
    std::panic::set_hook(Box::new(|info| {
        let stacktrace = Backtrace::force_capture();
        println!("Got panic. @info:{}\n@stackTrace:{}", info, stacktrace);
        std::process::abort();
    }));
    let load_params = LoadParameters {
        num_peers: 4,
        num_events: 100,
        purge_fraction: 0.5,
        id_overlap: true,
        id_range: 0..100,
    };
    load_test(no_op_logger(), 1, load_params);
}

/// Large load test with 40 nodes without overlapping id.
#[test]
fn test_large_load_test_many_nodes() {
    // Abort process if a thread panics. This catches detached tokio tasks that panic.
    // https://github.com/tokio-rs/tokio/issues/4516
    std::panic::set_hook(Box::new(|info| {
        let stacktrace = Backtrace::force_capture();
        println!("Got panic. @info:{}\n@stackTrace:{}", info, stacktrace);
        std::process::abort();
    }));
    let load_params = LoadParameters {
        num_peers: 8,
        num_events: 100,
        purge_fraction: 0.5,
        id_overlap: false,
        id_range: 0..1000000,
    };
    load_test(no_op_logger(), 2, load_params);
}

/// Load test with 20 nodes and large distribution of Id.
#[test]
fn test_load_test_many_ids() {
    // Abort process if a thread panics. This catches detached tokio tasks that panic.
    // https://github.com/tokio-rs/tokio/issues/4516
    std::panic::set_hook(Box::new(|info| {
        let stacktrace = Backtrace::force_capture();
        println!("Got panic. @info:{}\n@stackTrace:{}", info, stacktrace);
        std::process::abort();
    }));
    let load_params = LoadParameters {
        num_peers: 5,
        num_events: 200,
        purge_fraction: 0.8,
        id_overlap: false,
        id_range: 0..1000,
    };
    load_test(no_op_logger(), 3, load_params);
}

/// Small load test with four nodes and no purging..
#[test]
fn test_small_load_test_without_purging() {
    // Abort process if a thread panics. This catches detached tokio tasks that panic.
    // https://github.com/tokio-rs/tokio/issues/4516
    std::panic::set_hook(Box::new(|info| {
        let stacktrace = Backtrace::force_capture();
        println!("Got panic. @info:{}\n@stackTrace:{}", info, stacktrace);
        std::process::abort();
    }));
    let load_params = LoadParameters {
        num_peers: 4,
        num_events: 1000,
        purge_fraction: 0.0,
        id_overlap: true,
        id_range: 0..200,
    };
    load_test(no_op_logger(), 4, load_params);
}

/// Small load test with four nodes and no purging..
#[test]
fn test_small_load_test_with_non_overlap() {
    // Abort process if a thread panics. This catches detached tokio tasks that panic.
    // https://github.com/tokio-rs/tokio/issues/4516
    std::panic::set_hook(Box::new(|info| {
        let stacktrace = Backtrace::force_capture();
        println!("Got panic. @info:{}\n@stackTrace:{}", info, stacktrace);
        std::process::abort();
    }));
    let load_params = LoadParameters {
        num_peers: 4,
        num_events: 1000,
        purge_fraction: 0.1,
        id_overlap: false,
        id_range: 0..1000,
    };
    load_test(no_op_logger(), 5, load_params);
}

/// Test that nodes retransmits adverts tp peers that reconnect.
/// Scenario
/// 1. Node_1 connects to Node_2 and Node_3.
/// 2. Node_1 produces an artifact.
/// 3. Node_2 and Node_3 receive the artifact.
/// 4. Node_2 disconnects and re-connects to Node_1.
/// 5. Assert that Node_2 receives the artifact again from Node_1.
#[test]
fn test_adverts_are_retransmitted_on_reconnection() {
    with_test_replica_logger(|log| {
        let mut sim = Builder::new()
            .tick_duration(Duration::from_millis(100))
            .simulation_duration(Duration::from_secs(60 * 60))
            .build();

        let exit_notify = Arc::new(Notify::new());
        let (peer_manager_cmd_sender, topology_watcher, registry_handle) =
            add_peer_manager_to_sim(&mut sim, exit_notify.clone(), log.clone());
        let processor_1 = TestConsensus::new(log.clone(), NODE_1, 1024, false);
        let processor_2 = TestConsensus::new(log.clone(), NODE_2, 2048, true);
        let processor_3 = TestConsensus::new(log.clone(), NODE_3, 4096, true);

        add_transport_to_sim(
            &mut sim,
            log.clone(),
            NODE_1,
            registry_handle.clone(),
            topology_watcher.clone(),
            None,
            None,
            None,
            Some(processor_1.clone()),
            waiter_fut(),
        );
        add_transport_to_sim(
            &mut sim,
            log.clone(),
            NODE_2,
            registry_handle.clone(),
            topology_watcher.clone(),
            None,
            None,
            None,
            Some(processor_2.clone()),
            waiter_fut(),
        );
        add_transport_to_sim(
            &mut sim,
            log.clone(),
            NODE_3,
            registry_handle.clone(),
            topology_watcher.clone(),
            None,
            None,
            None,
            Some(processor_3.clone()),
            waiter_fut(),
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

        processor_1.push_advert(1);

        wait_for(&mut sim, || processor_2.received_advert_once(1))
            .expect("NODE_2 should receive `advert 1` from `NODE_1`.");

        wait_for(&mut sim, || processor_3.received_advert_once(1))
            .expect("NODE_3 should receive `advert 1` from `NODE_1`.");

        // Crash `NODE_3` nodes, and run simulation for 5s for `NODE_1` to detect disconnection.
        sim.crash(NODE_3.to_string());
        run_simulation_for(&mut sim, TIMEOUT_DURATION_TRIGGER).unwrap();
        sim.bounce(NODE_3.to_string());

        wait_for(&mut sim, || processor_3.received_advert_count(1) == 2)
            .expect("NODE_3 should receive `advert 1` twice from `NODE_1` since it reconnected.");

        wait_for(&mut sim, || processor_2.received_advert_once(1))
            .expect("NODE_2 should receive `advert 1` from `NODE_1`.");

        exit_notify.notify_waiters();
        sim.run().unwrap();
    });
}

/// Test that a node transmit adverts to its peers for adverts that were produced at a time
/// its peer was disconnected, but that eventually reconnect.
/// Scenario:
/// 1. Node_1 connects to Node_2.
/// 2. Node_1 and Node_2 disconnect.
/// 3. Node_1's processor produces an artifact to be sent.
/// 4. Node_1 and Node_2 reconnect.
/// 5. Node_2 receives the artifact.
#[test]
fn test_new_adverts_are_transmitted_on_reconnection() {
    with_test_replica_logger(|log| {
        let mut sim = Builder::new()
            .tick_duration(Duration::from_millis(100))
            .simulation_duration(Duration::from_secs(60 * 60))
            .build();

        let exit_notify = Arc::new(Notify::new());
        let (peer_manager_cmd_sender, topology_watcher, registry_handle) =
            add_peer_manager_to_sim(&mut sim, exit_notify.clone(), log.clone());
        let processor_1 = TestConsensus::new(log.clone(), NODE_1, 1024, false);
        let processor_2 = TestConsensus::new(log.clone(), NODE_2, 2048, true);
        let processor_3 = TestConsensus::new(log.clone(), NODE_3, 4096, false);

        add_transport_to_sim(
            &mut sim,
            log.clone(),
            NODE_1,
            registry_handle.clone(),
            topology_watcher.clone(),
            None,
            None,
            None,
            Some(processor_1.clone()),
            waiter_fut(),
        );
        add_transport_to_sim(
            &mut sim,
            log.clone(),
            NODE_2,
            registry_handle.clone(),
            topology_watcher.clone(),
            None,
            None,
            None,
            Some(processor_2.clone()),
            waiter_fut(),
        );
        add_transport_to_sim(
            &mut sim,
            log.clone(),
            NODE_3,
            registry_handle.clone(),
            topology_watcher.clone(),
            None,
            None,
            None,
            Some(processor_3.clone()),
            waiter_fut(),
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

        // ping pong advert
        processor_1.push_advert(1);
        wait_for(&mut sim, || processor_2.received_advert_once(1))
            .expect("`NODE_2` should receive the advert from `NODE_1`.");

        // Disconnect nodes, and run simulation for +5s to cause timeout in transport.
        // TODO: Adjust this timeout duration to be injected with a config struct.
        sim.partition(NODE_1.to_string(), NODE_2.to_string());
        run_simulation_for(&mut sim, TIMEOUT_DURATION_TRIGGER).unwrap();

        // Node_1 starts a send task while the link is broken.
        processor_1.push_advert(2);

        wait_for(&mut sim, || processor_3.received_advert_once(2)).expect(
            "`NODE_3` is connected to `NODE_1` and should receive the advert from `NODE_1`.",
        );

        sim.repair(NODE_1.to_string(), NODE_2.to_string());

        wait_for(&mut sim, || processor_2.received_advert_once(2))
            .expect("`NODE_2` should receive the advert from `NODE_1` after reconnecting.");

        exit_notify.notify_waiters();
        sim.run().unwrap();
    });
}

/// Test that a node transmit a message that is latency sensitive.
#[test]
fn test_large_msgs() {
    with_test_replica_logger(|log| {
        let mut sim = Builder::new()
            .max_message_latency(Duration::from_millis(0))
            .udp_capacity(1024 * 1024)
            .simulation_duration(Duration::from_secs(20 * 60))
            .build();

        let exit_notify = Arc::new(Notify::new());
        let (peer_manager_cmd_sender, topology_watcher, registry_handle) =
            add_peer_manager_to_sim(&mut sim, exit_notify.clone(), log.clone());
        let processor_1 = TestConsensus::new(log.clone(), NODE_1, 50 * 1024 * 1024, true);
        let processor_2 = TestConsensus::new(log.clone(), NODE_2, 10 * 1024 * 1024, true);

        add_transport_to_sim(
            &mut sim,
            log.clone(),
            NODE_1,
            registry_handle.clone(),
            topology_watcher.clone(),
            None,
            None,
            None,
            Some(processor_1.clone()),
            waiter_fut(),
        );
        add_transport_to_sim(
            &mut sim,
            log.clone(),
            NODE_2,
            registry_handle.clone(),
            topology_watcher.clone(),
            None,
            None,
            None,
            Some(processor_2.clone()),
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

        // ping pong advert
        processor_1.push_advert(1);
        wait_for(&mut sim, || processor_2.received_advert_once(1))
            .expect("`NODE_2` should receive the advert from `NODE_1`.");
        processor_2.push_advert(1);
        wait_for(&mut sim, || processor_1.received_advert_once(1))
            .expect("`NODE_2` should receive the advert from `NODE_1`.");
        processor_1.push_advert(2);
        wait_for(&mut sim, || processor_2.received_advert_once(2))
            .expect("`NODE_2` should receive the advert from `NODE_1`.");
        processor_2.push_advert(2);
        wait_for(&mut sim, || processor_1.received_advert_once(2))
            .expect("`NODE_2` should receive the advert from `NODE_1`.");

        exit_notify.notify_waiters();
        sim.run().unwrap();
    });
}
