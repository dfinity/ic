//! Common test function for a couple of catch up tests.

const DKG_INTERVAL: u64 = 150;
const CATCH_UP_RETRIES: u64 = 40;
const STATE_MANAGER_MAX_RESIDENT_HEIGHT: &str = "state_manager_max_resident_height";

const CATCH_UP_PACKAGE_MAX_HEIGHT: &str = "artifact_pool_consensus_height_stat{pool_type=\"validated\",stat=\"max\",type=\"catch_up_package\"}";
const CATCH_UP_PACKAGE_MIN_HEIGHT: &str = "artifact_pool_consensus_height_stat{pool_type=\"validated\",stat=\"min\",type=\"catch_up_package\"}";
const FINALIZATION_MIN_HEIGHT: &str = "artifact_pool_consensus_height_stat{pool_type=\"validated\",stat=\"min\",type=\"finalization\"}";
const FINALIZATION_MAX_HEIGHT: &str = "artifact_pool_consensus_height_stat{pool_type=\"validated\",stat=\"max\",type=\"finalization\"}";

use ic_consensus_system_test_utils::node::{
    await_node_certified_height, get_node_certified_height,
};
use ic_system_test_driver::{
    driver::{
        test_env::TestEnv,
        test_env_api::{
            HasPublicApiUrl, HasTopologySnapshot, HasVm, IcNodeContainer, READY_WAIT_TIMEOUT,
            RETRY_BACKOFF,
        },
    },
    util::{MetricsFetcher, block_on},
};
use ic_types::Height;

use anyhow::bail;
use futures::join;
use slog::info;
use std::time::Duration;

const PROMETHEUS_SCRAPE_INTERVAL: Duration = Duration::from_secs(5);
// We need to wait a bit longer than [`PROMETHEUS_SCRAPE_INTERVAL`] to make sure that the new
// metrics have been scraped before querying them again.
const CUP_RETRY_DELAY: Duration = PROMETHEUS_SCRAPE_INTERVAL.saturating_mul(5);

/// Test that a single node can catch up to the rest of the network
pub fn test_catch_up_possible(env: TestEnv) {
    test(env, true)
}

/// Test that a single node can not catch up to the rest of the network
pub fn test_catch_up_impossible(env: TestEnv) {
    test(env, false)
}

fn test(env: TestEnv, expect_catch_up: bool) {
    let log = env.logger();
    let topology = env.topology_snapshot();

    info!(log, "Waiting for the nodes to become healthy ...");
    topology
        .root_subnet()
        .nodes()
        .for_each(|node| node.await_status_is_healthy().unwrap());
    info!(log, "All nodes are ready, IC setup succeeded.");

    // Get malicious node handle
    let malicious_node = topology
        .root_subnet()
        .nodes()
        .find(|n| n.is_malicious())
        .expect("No malicious node found in the subnet.");

    info!(
        log,
        "Node with id={} is malicious with behavior={:?}",
        malicious_node.node_id,
        malicious_node.malicious_behavior().unwrap()
    );

    let slow_node_certified_height = get_node_certified_height(&malicious_node, log.clone()).get();

    let slow_node_shut_down_height = DKG_INTERVAL * (1 + slow_node_certified_height / DKG_INTERVAL);
    info!(log, "Wait one DKG interval, then shut down the slow node");
    await_node_certified_height(
        &malicious_node,
        Height::from(slow_node_shut_down_height),
        log.clone(),
    );
    malicious_node.vm().kill();
    info!(log, "Killed the slow node");

    info!(log, "Wait another DKG interval, then restart the slow node");
    topology
        .root_subnet()
        .nodes()
        // Since the malicious node is down, we can only query the other nodes
        .filter(|n| !n.is_malicious())
        .for_each(|node| {
            await_node_certified_height(
                &node,
                Height::from(slow_node_shut_down_height + DKG_INTERVAL),
                log.clone(),
            )
        });
    malicious_node.vm().start();
    info!(log, "Restarted slow node");

    // Wait until the node is available again
    // If the node is not able to catch up, we can't wait until the endpoint
    // reports healthy, therefore we simply await until we can reach the endpoint.
    let _ = ic_system_test_driver::retry_with_msg!(
        format!(
            "check if malicious node {} is available",
            malicious_node.node_id
        ),
        log.clone(),
        READY_WAIT_TIMEOUT,
        RETRY_BACKOFF,
        || {
            if malicious_node.status().is_err() {
                bail!("Not ready!")
            } else {
                Ok(())
            }
        }
    );

    block_on(async move {
        info!(log, "Checking node catch up via metrics");

        // Regularly check whether the `state_manager_max_resident_height` metric of the malicious
        // node reaches the values of the healthy nodes
        let healthy_node_metrics = MetricsFetcher::new(
            topology
                .root_subnet()
                .nodes()
                .filter(|node| !node.is_malicious()),
            vec![STATE_MANAGER_MAX_RESIDENT_HEIGHT.to_string()],
        );

        let malicious_node_metrics = MetricsFetcher::new(
            std::iter::once(malicious_node),
            vec![
                STATE_MANAGER_MAX_RESIDENT_HEIGHT.to_string(),
                CATCH_UP_PACKAGE_MAX_HEIGHT.to_string(),
                CATCH_UP_PACKAGE_MIN_HEIGHT.to_string(),
                FINALIZATION_MIN_HEIGHT.to_string(),
                FINALIZATION_MAX_HEIGHT.to_string(),
            ],
        );

        let mut too_many_artifacts_detected = false;

        // Check whether the node has caught up by comparing malicious nodes metric to the rest
        for try_idx in 0..CATCH_UP_RETRIES {
            std::thread::sleep(CUP_RETRY_DELAY);
            info!(
                log,
                "Try {}: Checking if the slow node is still behind", try_idx
            );

            let (healthy_metrics, unhealthy_metrics) = match join!(
                healthy_node_metrics.fetch::<u64>(),
                malicious_node_metrics.fetch::<u64>()
            ) {
                (Ok(healthy), Ok(unhealthy)) => (healthy, unhealthy),
                _ => {
                    info!(log, "Could not connect to the nodes yet");
                    continue;
                }
            };

            let healthy_heights = healthy_metrics[STATE_MANAGER_MAX_RESIDENT_HEIGHT].clone();
            let unhealthy_height = unhealthy_metrics[STATE_MANAGER_MAX_RESIDENT_HEIGHT][0];

            info!(
                log,
                "The slow node has a CUP at height max {} min {} and \
                a finalized block chain from height {} to height {}",
                unhealthy_metrics[CATCH_UP_PACKAGE_MAX_HEIGHT][0],
                unhealthy_metrics[CATCH_UP_PACKAGE_MIN_HEIGHT][0],
                unhealthy_metrics[FINALIZATION_MIN_HEIGHT][0],
                unhealthy_metrics[FINALIZATION_MAX_HEIGHT][0]
            );

            // Purger is only active if we have CUPs at two different height. If purger is active we should purge old finalizations
            if unhealthy_metrics[FINALIZATION_MIN_HEIGHT][0]
                < unhealthy_metrics[CATCH_UP_PACKAGE_MAX_HEIGHT][0] - 50
                && unhealthy_metrics[CATCH_UP_PACKAGE_MAX_HEIGHT][0]
                    > unhealthy_metrics[CATCH_UP_PACKAGE_MIN_HEIGHT][0]
            {
                // In order to give the Purger extra time to purge the unnecessary artifacts, we
                // only panic when we have detected that we have too many Finalizations two times in
                // a row.
                assert!(
                    !too_many_artifacts_detected,
                    "We should have purged the finalizations below CUP height"
                );
                too_many_artifacts_detected = true;
            } else {
                too_many_artifacts_detected = false;
            }

            let min_healthy_height = healthy_heights.iter().min().unwrap();

            info!(
                log,
                "The slow node height: {:?}, rest of the nodes: {:?}",
                unhealthy_height,
                healthy_heights
            );

            if unhealthy_height >= min_healthy_height - 2 {
                if expect_catch_up {
                    info!(log, "The slow node managed to catch up. All good");
                    return;
                } else {
                    panic!("The slow node caught up which was not expected under these conditions");
                }
            };

            info!(
                log,
                "Try {}: The slow node is still considerably behind, retrying", try_idx
            );
        }
        if expect_catch_up {
            panic!("The slow node failed to catch up");
        } else {
            info!(log, "The slow node did not catch up as expected");
        }
    });
}
