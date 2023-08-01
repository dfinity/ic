/* tag::catalog[]
Title:: Catch Up Test

Goal:: Demonstrate catch up behaviour of nodes when both exectution and state sync are slow.

Runbook::
. Set up a malicious (defect) node that uses delays to simulate slow execution and state sync
. The defect node is now shut down and after a couple minutes restarted
. Check whether the node is able to catch up

Success::
. Depending on the parameters we set in this test, we either expect the node to be able to catch up or not

Coverage::
In the test, the delays are artificially introduced. However, they simulate real node behaviour
in certain situations. The speed of state sync depends on the size of the state, while the execution speed
depends on the number of messages in the blocks to replay.

end::catalog[] */

const TARGET_FR_MS: u64 = 400;
const DKG_INTERVAL: u64 = 100;
const DKG_INTERVAL_TIME_MS: u64 = TARGET_FR_MS * DKG_INTERVAL;

const CATCH_UP_RETRIES: u64 = 120;

const STATE_MANAGER_MAX_RESIDENT_HEIGHT: &str = "state_manager_max_resident_height";

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
    util::{block_on, MetricsFetcher},
};
use anyhow::bail;
use futures::join;
use ic_registry_subnet_type::SubnetType;
use ic_types::{malicious_behaviour::MaliciousBehaviour, Height};
use slog::{info, Logger};
use std::time::Duration;

// FIXME: We would expect the values for execution and state sync delay to be much smaller
/// This configuration should not create a catch up loop.
pub fn no_catch_up_loop(env: TestEnv) {
    config(env, 0.8, 0.5)
}

/// Without mechanisms to precvvent a catch up loop, this setting owuld create a catch up loop
// that would make it impossible for a node to catch up.
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
        .with_scrape_interval(Duration::from_secs(5))
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

    env.sync_prometheus_config_with_topology();
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

    // Wait two DKG intervals, then shut down malicious node
    topology.root_subnet().nodes().for_each(|node| {
        await_node_certified_height(&node, Height::from(2 * DKG_INTERVAL), log.clone())
    });
    malicious_node.vm().kill();
    info!(log, "Killed the slow node");

    // Wait two DKG intervals, then restart malicious node
    topology
        .root_subnet()
        .nodes()
        // Since the malicious node is down, we can only query the other nodes
        .filter(|n| !n.is_malicious())
        .for_each(|node| {
            await_node_certified_height(&node, Height::from(4 * DKG_INTERVAL), log.clone())
        });
    malicious_node.vm().start();
    info!(log, "Restarted slow node");

    // Wait until the node is available again
    // If the node is not able to catch up, we can't wait until the endpoint
    // reports healthy, therefore we simply await until we can reach the endpoint.
    let _ = retry(log.clone(), READY_WAIT_TIMEOUT, RETRY_BACKOFF, || {
        if malicious_node.status().is_err() {
            bail!("Not ready!")
        } else {
            Ok(())
        }
    });

    block_on(async move {
        info!(log, "Checking node catch up via metrics");

        // Regularly check whether the `state_manager_max_resident_height` metric of the malicious
        // node reaches the values of the healty nodes
        let healthy_node_metrics = MetricsFetcher::new(
            topology.root_subnet().nodes(),
            vec![STATE_MANAGER_MAX_RESIDENT_HEIGHT.to_string()],
        );

        let malicious_node_metrics = MetricsFetcher::new(
            std::iter::once(malicious_node),
            vec![STATE_MANAGER_MAX_RESIDENT_HEIGHT.to_string()],
        );

        // Check whether the node has caught up by comparing malicious nodes metric to the rest
        for try_idx in 0..CATCH_UP_RETRIES {
            std::thread::sleep(Duration::from_secs(5));
            info!(log, "Try {}", try_idx);

            let (healthy_heights, unhealthy_height) = match join!(
                healthy_node_metrics.fetch::<u64>(),
                malicious_node_metrics.fetch::<u64>()
            ) {
                (Ok(healthy), Ok(unhealthy)) => (
                    healthy[STATE_MANAGER_MAX_RESIDENT_HEIGHT].clone(),
                    unhealthy[STATE_MANAGER_MAX_RESIDENT_HEIGHT][0],
                ),
                _ => {
                    info!(log, "Could not connect to the nodes yet");
                    continue;
                }
            };

            let average_healthy_height =
                healthy_heights.iter().sum::<u64>() as f64 / healthy_heights.len() as f64;

            if (average_healthy_height - unhealthy_height as f64).abs() < 2.0 {
                if expect_catch_up {
                    info!(log, "The node managed to catch up. All good");
                    return;
                } else {
                    panic!("Node caught up which was not expected under these conditions");
                }
            };
            info!(
                log,
                "Try {}: Node is still considerably behind, retrying", try_idx
            );
            info!(
                log,
                "Restarting node height: {:?}, rest of the nodes: {:?}",
                unhealthy_height,
                healthy_heights
            );
        }
        if expect_catch_up {
            panic!("The node failed to catch up");
        } else {
            info!(log, "Node did not catch up as expected");
        }
    });
}

pub(crate) fn await_node_certified_height(
    node: &IcNodeSnapshot,
    target_height: Height,
    log: Logger,
) {
    retry(log, READY_WAIT_TIMEOUT, RETRY_BACKOFF, || {
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
    })
    .expect("The node did not reach the specified height in time")
}
