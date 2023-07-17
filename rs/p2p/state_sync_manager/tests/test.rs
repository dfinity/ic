use std::time::Duration;

use crate::common::{
    create_node, latency_30ms_throughput_1000mbits, latency_50ms_throughput_300mbits, State,
};
use ic_memory_transport::TransportRouter;
use ic_test_utilities_logger::with_test_replica_logger;

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
