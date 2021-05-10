pub mod framework;

/// The number of peers used in this test.
#[cfg(test)]
const NUM_TEST_INSTANCES: u16 = 8;

/// The inverse of the fraction of nodes that fail stop in the test.
/// Concretely, the value `4` means that 25% of nodes fail.
const INVERSE_RATIO_FAILSTOP_NODES: u64 = 4;

/// The maximum height in this test.
const MAX_HEIGHT: u64 = 3;

/// The test runs `NUM_TEST_INSTANCES` nodes out of which a fraction of
/// `1/INVERSE_RATIO_FAILSTOP_NODES` nodes fail.
/// The test succeeds if the remaining nodes manage to run up to the height
/// `MAX_HEIGHT`.
#[tokio::test]
async fn n_node_gossip_with_failstop() {
    framework::spawn_replicas_as_threads(true, NUM_TEST_INSTANCES, |p2p_test_context| {
        std::println!("Node id: {}", p2p_test_context.node_id);
        // Every ith node fails where i = INVERSE_RATIO_FAILSTOP_NODES.
        if (p2p_test_context.node_num + 1) % INVERSE_RATIO_FAILSTOP_NODES == 0 {
            println!("Stopping node {:?}", p2p_test_context.node_id.clone().get());
            return;
        }
        p2p_test_context.p2p.run();
        println!("Runnning node {:?}", p2p_test_context.node_id.clone().get());

        framework::replica_run_till_height(&p2p_test_context, MAX_HEIGHT)
    });
}
