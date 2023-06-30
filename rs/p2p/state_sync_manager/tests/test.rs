use std::time::{Duration, Instant};

use crate::common::{
    create_node, latency_30ms_throughput_1000mbits, latency_50ms_throughput_300mbits, State,
};
use ic_memory_transport::TransportRouter;
use ic_test_utilities_logger::with_test_replica_logger;

mod common;

#[test]
fn test_two_nodes_sync() {
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let rt = runtime.handle().clone();
    with_test_replica_logger(|log| {
        runtime.block_on(async move {
            let mut transport_router = TransportRouter::new();

            let global_state = State::new();

            // Create node that provides global state.
            let (state_sync_1, _jh_1) = create_node(
                0,
                log.clone(),
                &mut transport_router,
                &rt,
                true,
                global_state.clone(),
                latency_30ms_throughput_1000mbits(),
            );

            // Create empty node
            let (state_sync_2, _jh_2) = create_node(
                1,
                log,
                &mut transport_router,
                &rt,
                false,
                global_state.clone(),
                latency_50ms_throughput_300mbits(),
            );

            let now = Instant::now();

            global_state.add_new_chunks(100, 1_000_000);

            // Verify that empty node has caught up
            let fut = async move {
                while !state_sync_2.is_equal(&state_sync_1) {
                    tokio::time::sleep(Duration::from_secs(2)).await;
                }
            };
            tokio::time::timeout(Duration::from_secs(60), fut)
                .await
                .unwrap();

            println!("Download took {:?}", now.elapsed());
        });
    });
}
