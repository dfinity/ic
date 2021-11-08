pub mod framework;

/// The number of nodes in this test.
#[cfg(test)]
const NUM_TEST_INSTANCES: u16 = 4;

/// The maximum height in this test.
const MAX_HEIGHT: u64 = 4;

/// The test runs `NUM_TEST_INSTANCES` nodes.
/// The test succeeds if the nodes manage to run up to the height `MAX_HEIGHT`.
#[tokio::test]
async fn n_node_gossip_using_threads() {
    framework::spawn_replicas_as_threads(true, NUM_TEST_INSTANCES, |p2p_test_context| {
        p2p_test_context.p2p.run();
        framework::replica_run_till_height(p2p_test_context, MAX_HEIGHT);
    });
}
