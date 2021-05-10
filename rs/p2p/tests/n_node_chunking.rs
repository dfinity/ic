//! The objective is to test that a set of needs, each holding one artifact,
//! exchange their artifacts.
//!
//! If there are `N` nodes and each artifact consists of `Q` chunks,
//! the expected result is that every peer receives all `N-1` artifacts from the
//! other peers, i.e., `(N-1)Q` chunks in total.
//!
//! Note that most of the logic is driven by a test artifact manager.

use ic_test_utilities::metrics::fetch_int_counter;
use std::time::Duration;

pub mod framework;

/// The barrier string constant used to wait on other peers to finish.
const ALL_NODES_SYNCED: &str = "ALL_NODES_SYNCED"; // Note that barriers have to be unique

/// This constant defines the maximum permissible number of iterations until
/// test completion.
/// If the test exceeds this bound, it fails.
const MAX_ALLOWED_ITER: u32 = 200;

/// The number of nodes in this test.
#[cfg(test)]
const NUM_TEST_INSTANCES: u16 = 3;

/// In this test, `NUM_TEST_INSTANCES` peers exchange chunks until each peer has
/// received the single artifact from each other peer.
#[tokio::test]
async fn n_node_chunking() {
    framework::spawn_replicas_as_threads(false, NUM_TEST_INSTANCES, |p2p_test_context| {
        p2p_test_context.p2p.run();
        let mut iter = 0;
        loop {
            std::thread::sleep(Duration::from_millis(600));
            iter += 1;
            if iter > MAX_ALLOWED_ITER {
                panic!("Test exceeded {} iterations", MAX_ALLOWED_ITER);
            }

            let artifacts_recv_count = fetch_int_counter(
                &p2p_test_context.metrics_registry,
                "gossip_artifacts_received",
            )
            .expect("Test cannot read gauge");
            println!(
                "Node {:?}: Number of received artifacts: {}",
                p2p_test_context.node_id, artifacts_recv_count
            );
            if artifacts_recv_count < NUM_TEST_INSTANCES as u64 - 1 {
                continue;
            }

            // Node has received all artifacts, continue operating till
            // all other nodes signal that they too have synced all the
            //artifacts.
            match p2p_test_context
                .test_synchronizer
                .try_wait_on_barrier(ALL_NODES_SYNCED.to_string())
            {
                Err(_) => {
                    continue;
                }
                Ok(_) => {
                    break;
                }
            }
        }
    });
}
