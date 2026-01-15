/* tag::catalog[]
Title:: Query Stats Fault Tolerance test

Goal:: Demonstrate the threshold behaviour of the QueryStats feature

Runbook::
. Deploy a subnet with 4 replicas and install universal canister
. Store 4 bytes data on it
. Query the data from either 2/4, 3/4 or 4/4 nodes then wait an epoch
. Repeat this three times (to push the data through)

Success:: In the case where we only make 2/4 queries, we expect that there are no
statistics, whilein the other cases we expect the test to succeed.

end::catalog[] */
use crate::{
    round_robin_query_call, single_https_outcall, single_update_call, wait_until_next_epoch,
};
use candid::Principal;
use ic_agent::Agent;
use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::{
    driver::{
        test_env::TestEnv,
        test_env_api::{HasPublicApiUrl, HasTopologySnapshot, IcNodeContainer},
    },
    util::{UniversalCanister, block_on},
};
use ic_utils::{call::AsyncCall, interfaces::ManagementCanister};
use slog::info;
use std::{ops::Range, time::Duration};

pub fn query_stats_basic(env: TestEnv) {
    query_stats_fault_tolerance(env, round_robin_query_call, 0..4, true)
}

pub fn query_stats_above_threshold(env: TestEnv) {
    query_stats_fault_tolerance(env, round_robin_query_call, 1..4, true)
}

pub fn query_stats_below_threshold(env: TestEnv) {
    query_stats_fault_tolerance(env, round_robin_query_call, 2..4, false)
}

pub fn query_stats_https_outcalls(env: TestEnv) {
    query_stats_fault_tolerance(env, single_https_outcall, 0..4, false)
}

fn query_stats_fault_tolerance(
    env: TestEnv,
    canister_call: impl AsyncFn(&Principal, &[Agent]) -> (),
    query_range: Range<usize>,
    expect_success: bool,
) {
    let logger = env.logger();
    let subnet = env
        .topology_snapshot()
        .subnets()
        .find(|subnet| subnet.subnet_type() == SubnetType::Application)
        .expect("there is no application subnet");

    let uc_id = subnet.nodes().next().unwrap().effective_canister_id();
    let agents = subnet
        .nodes()
        .map(|node| node.build_default_agent())
        .collect::<Vec<_>>();

    block_on(async move {
        // Install universal canister
        let canister =
            UniversalCanister::new_with_retries(agents.first().unwrap(), uc_id, &logger).await;
        info!(logger, "Installed Universal Canister");
        let uc_id = canister.canister_id();

        // Store something on universal canister
        single_update_call(&uc_id, &agents).await;
        info!(logger, "Stored data on UC");

        // NOTE: The `canister_call` below sometimes fails, if we
        // execute it immediately and one of the nodes is slightly behind,
        // such that the Universal canister does not exist on that node yet
        tokio::time::sleep(Duration::from_secs(5)).await;

        // Do canister call against all nodes
        canister_call(&uc_id, &agents[query_range.clone()]).await;
        info!(logger, "Performed a canister call");

        wait_until_next_epoch(&subnet, &logger);

        // Do canister call against all nodes
        canister_call(&uc_id, &agents[query_range.clone()]).await;
        info!(logger, "Performed a canister call");

        wait_until_next_epoch(&subnet, &logger);

        // Do a canister call against all nodes
        canister_call(&uc_id, &agents[query_range]).await;
        info!(logger, "Performed a canister call");

        wait_until_next_epoch(&subnet, &logger);

        let query_stats = ManagementCanister::create(agents.first().unwrap())
            .canister_status(&uc_id)
            .call_and_wait()
            .await
            .unwrap()
            .0
            .query_stats;

        if expect_success {
            assert_eq!(query_stats.num_calls_total, 4u64);
            assert_ne!(query_stats.num_instructions_total, 0u64);
            assert_ne!(query_stats.request_payload_bytes_total, 0u64);
            assert_eq!(query_stats.response_payload_bytes_total, 16u64);
        } else {
            assert_eq!(query_stats.num_calls_total, 0u64);
            assert_eq!(query_stats.num_instructions_total, 0u64);
            assert_eq!(query_stats.request_payload_bytes_total, 0u64);
            assert_eq!(query_stats.response_payload_bytes_total, 0u64);
        }
    })
}
