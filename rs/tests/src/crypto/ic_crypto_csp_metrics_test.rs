/* tag::catalog[]
Title:: ic-crypto-csp metrics test

Goal:: Ensure that metrics observed by the crypto csp are exported to the replica, and made
available on the metrics HTTP endpoint of the replica.

Runbook::
. Set up a subnet with a single node
. Wait for the node to start up correctly and be healthy
. Connect to the metrics endpoint of the replica process and retrieve the metrics
. Verify that metrics observed by the crypto csp process appear in the metrics

Success:: Metrics from the crypto csp process are made available on the replica metrics endpoint.

Coverage::
. The metrics are exported from the crypto csp process to the replica process
. The crypto csp metrics are exported by the replica process on the metrics HTTP endpoint


end::catalog[] */

use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::driver::ic::InternetComputer;
use ic_system_test_driver::driver::test_env::TestEnv;
use ic_system_test_driver::driver::test_env_api::{
    GetFirstHealthyNodeSnapshot, HasTopologySnapshot, IcNodeContainer,
};
use ic_system_test_driver::util::MetricsFetcher;
use slog::info;
use std::iter;

pub fn setup_with_single_node(env: TestEnv) {
    InternetComputer::new()
        .add_fast_single_node_subnet(SubnetType::System)
        .setup_and_start(&env)
        .expect("failed to setup IC under test");

    env.topology_snapshot()
        .subnets()
        .for_each(|subnet| subnet.await_all_nodes_healthy().unwrap());
}

const SAMPLE_ADAPTER_CRYPTOCSP_METRICS_NAME_PREFIX: &str =
    "adapter_cryptocsp_crypto_lock_acquisition_duration_seconds_bucket";

pub fn ic_crypto_csp_metrics_test(env: TestEnv) {
    let logger = env.logger();
    let node = env.get_first_healthy_node_snapshot();

    ic_system_test_driver::util::block_on(async move {
        let mut count = 0;
        let mut found = false;
        let metrics = MetricsFetcher::new(
            iter::once(node),
            vec![SAMPLE_ADAPTER_CRYPTOCSP_METRICS_NAME_PREFIX.to_string()],
        );
        loop {
            match metrics.fetch::<u64>().await {
                Ok(items) => {
                    info!(logger, "Received {} metrics", items.len());
                    if items.iter().any(|(key, _value)| {
                        key.starts_with(SAMPLE_ADAPTER_CRYPTOCSP_METRICS_NAME_PREFIX)
                    }) {
                        found = true;
                        break;
                    }
                }
                Err(err) => {
                    info!(logger, "Could not connect to metrics yet {:?}", err);
                }
            }
            count += 1;
            // Break after 200 tries
            if count > 200 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
        }
        if !found {
            panic!("Failed to observe any crypto csp metrics");
        }
    });
}
