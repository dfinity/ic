/* tag::catalog[]
Title:: Global reboot test.

Goal:: Test whether messages exchange between Xnet canisters on different subnets is robust with respect to nodes reboot.

Runbook::
0. Setup: 2 single-node Application subnets.
1. Build and install 3 Xnet canisters on each subnet.
2. Start all canisters (via update `start` call).
3. Wait 15 secs for canisters to exchange messages.
4. Collect metrics from all canisters (via query `metrics` call).
5. Reboot all nodes and wait till they become reachable again.
6. Wait another 15 secs for canisters to exchange messages.
7. Collect metrics from all canisters again.
8. Assert that metrics have progressed after reboot and no errors in calls are observed.
9. Stop all canisters (via update `stop_canister` call).
10. Delete all canisters (via update `delete_canister` call).
11. Assert all subnets can make progress (via installing universal canisters and storing a message).

Success::
1. Xnet canisters are successfully installed and started on each subnet.
2. Metrics collected on canisters before/after nodes reboot show progress (without errors).
3. Xnet canisters are successfully stopped and deleted.
4. Each subnet can still make progress after all these operations.

end::catalog[] */

use std::env;
use std::time::Duration;

use ic_system_test_driver::driver::test_env::TestEnv;
use ic_system_test_driver::driver::test_env_api::{
    get_dependency_path, HasPublicApiUrl, HasTopologySnapshot, HasVm, IcNodeContainer,
    IcNodeSnapshot, SubnetSnapshot,
};
use ic_system_test_driver::util::{
    assert_nodes_health_statuses, assert_subnet_can_make_progress, block_on, runtime_from_url,
    EndpointsStatus,
};

use canister_test::{Canister, Runtime, Wasm};
use dfn_candid::candid;
use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::driver::ic::InternetComputer;
use itertools::Itertools;
use slog::{info, Logger};
use tokio::time::sleep;
use xnet_test::{CanisterId, Metrics};

const SUBNETS_COUNT: usize = 2;
const CANISTERS_PER_SUBNET: usize = 3;
const CANISTER_TO_SUBNET_RATE: u64 = 10;
const PAYLOAD_SIZE_BYTES: u64 = 1024;
const MSG_EXEC_TIME_SEC: u64 = 15;

pub fn config(env: TestEnv) {
    (0..SUBNETS_COUNT)
        .fold(InternetComputer::new(), |ic, _idx| {
            ic.add_fast_single_node_subnet(SubnetType::Application)
        })
        .setup_and_start(&env)
        .expect("failed to setup IC under test");
    env.topology_snapshot().subnets().for_each(|subnet| {
        subnet
            .nodes()
            .for_each(|node| node.await_status_is_healthy().unwrap())
    });
}

pub fn test(env: TestEnv) {
    let all_nodes: Vec<IcNodeSnapshot> = env
        .topology_snapshot()
        .subnets()
        .flat_map(|s| s.nodes())
        .collect();
    assert_eq!(all_nodes.len(), SUBNETS_COUNT); // 1 node per subnet
    let subnets = env.topology_snapshot().subnets().collect_vec();
    test_on_subnets(env, subnets)
}

pub fn test_on_subnets(env: TestEnv, subnets: Vec<SubnetSnapshot>) {
    let log = env.logger();
    let all_nodes: Vec<IcNodeSnapshot> = subnets.iter().flat_map(|s| s.nodes()).collect();

    let runtimes: Vec<Runtime> = all_nodes
        .iter()
        .map(|n| runtime_from_url(n.get_public_url(), n.effective_canister_id()))
        .collect();
    // Step 1: Install Xnet canisters on each subnet.
    let wasm = Wasm::from_file(get_dependency_path(
        env::var("XNET_TEST_CANISTER_WASM_PATH").expect("XNET_TEST_CANISTER_WASM_PATH not set"),
    ));
    info!(log, "Installing Xnet canisters on subnets ...");
    let canisters = install_canisters(&runtimes, SUBNETS_COUNT, CANISTERS_PER_SUBNET, wasm);
    let canisters_count = canisters.iter().map(Vec::len).sum::<usize>();
    assert_eq!(canisters_count, SUBNETS_COUNT * CANISTERS_PER_SUBNET);
    info!(
        log,
        "All {} canisters installed successfully.", canisters_count
    );
    // Step 2: Start all canisters (via update `start` call).
    info!(log, "Calling start() on all canisters ...");
    start_all_canisters(&canisters, PAYLOAD_SIZE_BYTES, CANISTER_TO_SUBNET_RATE);
    // Step 3:  Wait 15 secs for canisters to exchange messages.
    info!(log, "Sending messages for {} secs ...", MSG_EXEC_TIME_SEC);
    block_on(async {
        sleep(Duration::from_secs(MSG_EXEC_TIME_SEC)).await;
    });
    // Step 4: Collect metrics from all canisters (via query `metrics` call).
    info!(log, "Collecting metrics from all canisters ...");
    let metrics_pre_reboot = collect_metrics(&canisters);
    // Step 5: Reboot all nodes and wait till they become reachable again.
    info!(log, "Rebooting all nodes ...");
    for n in all_nodes.iter().cloned() {
        n.vm().reboot();
        assert_nodes_health_statuses(log.clone(), &[n], EndpointsStatus::AllUnhealthy);
    }
    info!(log, "Waiting for endpoints to be reachable again ...");
    assert_nodes_health_statuses(
        log.clone(),
        all_nodes.as_slice(),
        EndpointsStatus::AllHealthy,
    );
    // Step 6: Wait another 15 secs for canisters to exchange messages.
    info!(log, "Sending messages for {} secs ...", MSG_EXEC_TIME_SEC);
    block_on(async {
        sleep(Duration::from_secs(MSG_EXEC_TIME_SEC)).await;
    });
    // Step 7: Collect metrics from all canisters again.
    info!(log, "Collecting metrics from all canisters ...");
    let metrics_post_reboot = collect_metrics(&canisters);
    // Step 8: Assert that metrics have progressed after reboot and no errors in calls are observed.
    assert_metrics_progress_without_errors(&log, &metrics_pre_reboot, &metrics_post_reboot);
    // Step 9: Stop all canisters (via update `stop_canister` call).
    info!(log, "Stopping all canisters ...");
    block_on(async {
        for canister in canisters.iter().flatten() {
            canister.stop().await.expect("Stopping canister failed.");
        }
    });
    // Step 10: Delete all canisters (via update `delete_canister` call).
    info!(log, "Deleting all canisters ...");
    block_on(async {
        for canister in canisters.iter().flatten() {
            canister.delete().await.expect("Deleting canister failed.");
        }
    });
    // Step 11: Assert all subnets can make progress (via installing universal canisters and storing a message).
    info!(log, "Asserting all subnets can still make progress ...");
    let update_message = b"This beautiful prose should be persisted for future generations";
    block_on(async {
        for n in all_nodes {
            assert_subnet_can_make_progress(update_message, &n).await;
        }
    });
    info!(log, "All subnets can progress via update/query calls.");
}

pub fn start_all_canisters(
    canisters: &[Vec<Canister>],
    payload_size_bytes: u64,
    canister_to_subnet_rate: u64,
) {
    let topology: Vec<Vec<CanisterId>> = canisters
        .iter()
        .map(|x| x.iter().map(|y| y.canister_id_vec8()).collect())
        .collect();
    block_on(async {
        for (subnet_idx, canister_idx, canister) in canisters
            .iter()
            .enumerate()
            .flat_map(|(x, v)| v.iter().enumerate().map(move |(y, v)| (x, y, v)))
        {
            let input = (&topology, canister_to_subnet_rate, payload_size_bytes);
            let _: String = canister
                .update_("start", candid, input)
                .await
                .unwrap_or_else(|_| {
                    panic!(
                        "Starting canister_idx={} on subnet_idx={} failed.",
                        canister_idx, subnet_idx
                    )
                });
        }
    });
}

pub fn assert_metrics_progress_without_errors(
    log: &Logger,
    metrics_pre_reboot: &[Vec<Metrics>],
    metrics_post_reboot: &[Vec<Metrics>],
) {
    for (subnet_idx, canister_idx) in metrics_pre_reboot
        .iter()
        .enumerate()
        .flat_map(|(s_idx, v)| (0..v.len()).map(move |c_idx| (s_idx, c_idx)))
    {
        let pre_reboot = &metrics_pre_reboot[subnet_idx][canister_idx];
        let post_reboot = &metrics_post_reboot[subnet_idx][canister_idx];

        assert_eq!(pre_reboot.seq_errors, 0);
        assert_eq!(post_reboot.seq_errors, 0);
        assert!(pre_reboot.requests_sent > 0);
        // Assert positive dynamics after reboot.
        assert!(post_reboot.requests_sent > pre_reboot.requests_sent);

        let responses_pre_reboot = pre_reboot.latency_distribution.buckets().last().unwrap().1
            + pre_reboot.reject_responses;
        let responses_post_reboot = post_reboot.latency_distribution.buckets().last().unwrap().1
            + post_reboot.reject_responses;
        assert!(responses_pre_reboot > 0);
        // Assert positive dynamics after reboot.
        assert!(responses_post_reboot > responses_pre_reboot);

        info!(
            log,
            "Metrics for subnet_idx={}, canister_idx={}, before reboot:\n{:?}\nafter reboot:\n{:?}",
            subnet_idx,
            canister_idx,
            pre_reboot,
            post_reboot
        );
    }
}

pub fn collect_metrics(canisters: &[Vec<Canister>]) -> Vec<Vec<Metrics>> {
    let mut metrics: Vec<Vec<Metrics>> = Vec::new();
    block_on(async {
        for (subnet_idx, canister_idx, canister) in canisters
            .iter()
            .enumerate()
            .flat_map(|(x, v)| v.iter().enumerate().map(move |(y, v)| (x, y, v)))
        {
            if canister_idx == 0 {
                metrics.push(vec![]);
            }
            let result = canister
                .query_("metrics", candid, ())
                .await
                .unwrap_or_else(|_| {
                    panic!(
                        "Collecting metrics for canister_idx={} on subnet_idx={} failed.",
                        canister_idx, subnet_idx
                    )
                });
            metrics[subnet_idx].push(result);
        }
    });
    metrics
}

pub fn install_canisters(
    endpoints_runtime: &[Runtime],
    subnets_count: usize,
    canisters_per_subnet: usize,
    wasm: Wasm,
) -> Vec<Vec<Canister>> {
    let mut canisters: Vec<Vec<Canister>> = Vec::new();
    block_on(async {
        for subnet_idx in 0..subnets_count {
            canisters.push(vec![]);
            for canister_idx in 0..canisters_per_subnet {
                let canister = wasm
                    .clone()
                    .install_(&endpoints_runtime[subnet_idx], vec![])
                    .await
                    .unwrap_or_else(|_| {
                        panic!(
                            "Installation of the canister_idx={} on subnet_idx={} failed.",
                            canister_idx, subnet_idx
                        )
                    });
                canisters[subnet_idx].push(canister);
            }
        }
    });
    canisters
}
