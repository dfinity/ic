/* tag::catalog[]
Title:: Catch Up Test

Goal:: Demonstrate catch up behaviour of nodes when both execution and state sync are slow.

Runbook::
. Set up a malicious (defect) node that uses delays to simulate slow execution and state sync
. The defect node is now shut down and after a couple minutes restarted
. Check whether the node is able to catch up
. Additionally, we check that the artifacts are always purged below the latest CUP height (with some
  cushion), even when we are severely lagging behind the other nodes.

Success::
. Depending on the parameters we set in this test, we either expect the node to be able to catch up or not

Coverage::
In the test, the delays are artificially introduced. However, they simulate real node behaviour
in certain situations. The speed of state sync depends on the size of the state, while the execution speed
depends on the number of messages in the blocks to replay.

end::catalog[] */

const TARGET_FR_MS: u64 = 400;
const DKG_INTERVAL: u64 = 150;
const DKG_INTERVAL_TIME_MS: u64 = TARGET_FR_MS * DKG_INTERVAL;

const CATCH_UP_RETRIES: u64 = 40;

const STATE_MANAGER_MAX_RESIDENT_HEIGHT: &str = "state_manager_max_resident_height";

const CATCH_UP_PACKAGE_MAX_HEIGHT: &str = "artifact_pool_consensus_height_stat{pool_type=\"validated\",stat=\"max\",type=\"catch_up_package\"}";
const FINALIZATION_MIN_HEIGHT: &str = "artifact_pool_consensus_height_stat{pool_type=\"validated\",stat=\"min\",type=\"finalization\"}";
const FINALIZATION_MAX_HEIGHT: &str = "artifact_pool_consensus_height_stat{pool_type=\"validated\",stat=\"max\",type=\"finalization\"}";

use crate::{
    driver::{
        ic::{InternetComputer, Subnet},
        prometheus_vm::{HasPrometheus, PrometheusVm},
        test_env::TestEnv,
        test_env_api::{
            retry, HasPublicApiUrl, HasTopologySnapshot, HasVm, IcNodeContainer, IcNodeSnapshot,
            READY_WAIT_TIMEOUT, RETRY_BACKOFF,
        },
    },
    retry_with_msg,
    util::{block_on, MetricsFetcher},
};
use anyhow::{anyhow, bail};
use futures::join;
use ic_registry_subnet_type::SubnetType;
use ic_types::{malicious_behaviour::MaliciousBehaviour, Height};
use slog::{info, Logger};
use std::time::Duration;

const PROMETHEUS_SCRAPE_INTERVAL: Duration = Duration::from_secs(5);
// We need to wait a bit longer than [`PROMETHEUS_SCRAPE_INTERVAL`] to make sure that the new
// metrics have been scraped before querying them again.
const CUP_RETRY_DELAY: Duration = PROMETHEUS_SCRAPE_INTERVAL.saturating_mul(5);

// FIXME: We would expect the values for execution and state sync delay to be much smaller
/// This configuration should not create a catch up loop.
pub fn no_catch_up_loop(env: TestEnv) {
    config(env, 0.8, 0.5)
}

/// Without mechanisms to prevent a catch up loop, this setting would create a catch up loop
/// that would make it impossible for a node to catch up.
pub fn catch_up_loop(env: TestEnv) {
    config(env, 1.2, 0.8)
}

/// Test that a single node can catch up to the rest of the network
pub fn test_catch_up_possible(env: TestEnv) {
    test(env, true)
}

/// Test that a single node can not catch up to the rest of the network
pub fn test_catch_up_impossible(env: TestEnv) {
    test(env, false)
}

fn config(env: TestEnv, execution_delay_factor: f64, state_sync_delay_factor: f64) {
    let execution_delay_ms = (execution_delay_factor * TARGET_FR_MS as f64) as u64;
    let state_sync_delay_ms = (state_sync_delay_factor * DKG_INTERVAL_TIME_MS as f64) as u64;

    PrometheusVm::default()
        .with_scrape_interval(PROMETHEUS_SCRAPE_INTERVAL)
        .start(&env)
        .expect("failed to start prometheus VM");

    InternetComputer::new()
        .add_subnet(
            Subnet::new(SubnetType::System)
                .with_unit_delay(Duration::from_millis(TARGET_FR_MS))
                .with_initial_notary_delay(Duration::from_millis(TARGET_FR_MS))
                .with_dkg_interval_length(Height::from(DKG_INTERVAL - 1))
                .add_nodes(3)
                .add_malicious_nodes(
                    1,
                    MaliciousBehaviour::new(true)
                        .set_maliciously_delay_execution(Duration::from_millis(execution_delay_ms))
                        .set_maliciously_delay_state_sync(Duration::from_millis(
                            state_sync_delay_ms,
                        )),
                ),
        )
        .setup_and_start(&env)
        .expect("failed to setup IC under test");

    env.sync_with_prometheus();
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

    let slow_node_certified_height = get_certified_height(&malicious_node, log.clone()).get();

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
    let _ = retry_with_msg!(
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
                "The slow node has a CUP at height {} and \
                a finalized block chain from height {} to height {}",
                unhealthy_metrics[CATCH_UP_PACKAGE_MAX_HEIGHT][0],
                unhealthy_metrics[FINALIZATION_MIN_HEIGHT][0],
                unhealthy_metrics[FINALIZATION_MAX_HEIGHT][0]
            );

            if unhealthy_metrics[FINALIZATION_MIN_HEIGHT][0]
                < unhealthy_metrics[CATCH_UP_PACKAGE_MAX_HEIGHT][0] - 50
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

pub fn await_node_certified_height(node: &IcNodeSnapshot, target_height: Height, log: Logger) {
    retry_with_msg!(
        format!(
            "check if node {} is at height {}",
            node.node_id, target_height
        ),
        log,
        READY_WAIT_TIMEOUT,
        RETRY_BACKOFF,
        || {
            node.status()
                .and_then(|response| match response.certified_height {
                    Some(height) if height > target_height => Ok(()),
                    Some(height) => bail!(
                        "Target height not yet reached, height: {}, target: {}",
                        height,
                        target_height
                    ),
                    None => bail!("Certified height not available"),
                })
        }
    )
    .expect("The node did not reach the specified height in time")
}

pub fn get_certified_height(node: &IcNodeSnapshot, log: Logger) -> Height {
    retry_with_msg!(
        format!("get certified height of node {}", node.node_id),
        log,
        READY_WAIT_TIMEOUT,
        RETRY_BACKOFF,
        || {
            node.status().and_then(|response| {
                response
                    .certified_height
                    .ok_or_else(|| anyhow!("Certified height not available"))
            })
        }
    )
    .expect("Should be able to retrieve the certified height")
}
