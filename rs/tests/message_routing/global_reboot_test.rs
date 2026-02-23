/* tag::catalog[]
Title:: Global reboot test.

Goal:: Test whether messages exchange between Xnet canisters on different subnets is robust with respect to nodes reboot.

Runbook::
0. Setup: 2 single-node Application subnets.
1. Build and install 3 Xnet canisters on each subnet.
2. Start all canisters (via update `start` call).
3. Wait for canisters to exchange messages, polling until all have received at least `RESPONSES_FOR_PROGRESS` responses (up to 120 secs). Collect "pre" metrics.
4. Reboot all nodes and wait until they become reachable again.
5. Wait for canisters to exchange messages, polling until all have received at least `RESPONSES_FOR_PROGRESS` more responses than recorded in the "pre" metrics (up to 120 secs). Collect "post" metrics.
6. Assert that no errors were observed in "post" metrics (implies no errors in "pre" metrics).
7. Stop all canisters (via update `stop_canister` call).
8. Delete all canisters (via update `delete_canister` call).
9. Assert that all subnets can make progress (via installing universal canisters and storing a message).

Success::
1. Xnet canisters are successfully installed and started on each subnet.
2. Metrics collected on canisters before/after nodes reboot show progress (without errors).
3. Xnet canisters are successfully stopped and deleted.
4. Each subnet can still make progress after all these operations.

end::catalog[] */

use anyhow::{Result, bail};
use candid::Principal;
use canister_test::{Canister, Runtime, Wasm};
use dfn_candid::candid;
use ic_management_canister_types::CanisterId;
use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::driver::group::SystemTestGroup;
use ic_system_test_driver::driver::ic::InternetComputer;
use ic_system_test_driver::driver::test_env::TestEnv;
use ic_system_test_driver::driver::test_env_api::{
    HasPublicApiUrl, HasTopologySnapshot, HasVm, IcNodeContainer, IcNodeSnapshot, SubnetSnapshot,
    get_dependency_path_from_env,
};
use ic_system_test_driver::systest;
use ic_system_test_driver::util::{
    EndpointsStatus, assert_nodes_health_statuses, assert_subnet_can_make_progress, block_on,
    runtime_from_url,
};
use itertools::Itertools;
use slog::{Logger, info};
use std::time::Duration;
use xnet_test::{Metrics, StartArgs};

const SUBNETS_COUNT: usize = 2;
const CANISTERS_PER_SUBNET: usize = 3;
const CANISTER_TO_SUBNET_RATE: u64 = 10;
/// 10 rounds worth of responses.
const RESPONSES_FOR_PROGRESS: usize = 10 * CANISTER_TO_SUBNET_RATE as usize;
const PAYLOAD_SIZE_BYTES: u64 = 1024;
const POLL_INTERVAL_SEC: u64 = 5;
const RESPONSES_RETRY_TIMEOUT_SEC: u64 = 120;

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(setup)
        .add_test(systest!(test))
        .execute_from_args()?;
    Ok(())
}

pub fn setup(env: TestEnv) {
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
    let wasm = Wasm::from_file(get_dependency_path_from_env("XNET_TEST_CANISTER_WASM_PATH"));
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
    // Step 3: Wait for all canisters to exchange messages and receive responses.
    info!(log, "Waiting for all canisters to receive responses ...");
    let all_zero_metrics = vec![vec![Metrics::default(); CANISTERS_PER_SUBNET]; SUBNETS_COUNT];
    let metrics_pre_reboot = wait_for_progress(&canisters, &all_zero_metrics, &log);
    // Step 4: Reboot all nodes and wait until they become reachable again.
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
    // Step 5: Wait for all canisters to exchange messages and receive responses.
    info!(log, "Waiting for all canisters to receive responses ...");
    let metrics_post_reboot = wait_for_progress(&canisters, &metrics_pre_reboot, &log);
    // Step 6: Assert that no errors were observed.
    assert_no_errors(&metrics_post_reboot, &log);
    // Step 7: Stop all canisters (via update `stop_canister` call).
    info!(log, "Stopping all canisters ...");
    block_on(async {
        for canister in canisters.iter().flatten() {
            canister.stop().await.expect("Stopping canister failed.");
        }
    });
    // Step 8: Delete all canisters (via update `delete_canister` call).
    info!(log, "Deleting all canisters ...");
    block_on(async {
        for canister in canisters.iter().flatten() {
            canister.delete().await.expect("Deleting canister failed.");
        }
    });
    // Step 9: Assert that all subnets can make progress (via installing universal
    // canisters and storing a message).
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
        .map(|x| {
            x.iter()
                .map(|y| Principal::try_from(y.canister_id_vec8()).unwrap())
                .collect()
        })
        .collect();
    block_on(async {
        for (subnet_idx, canister_idx, canister) in canisters
            .iter()
            .enumerate()
            .flat_map(|(x, v)| v.iter().enumerate().map(move |(y, v)| (x, y, v)))
        {
            let input = StartArgs {
                network_topology: topology.clone(),
                canister_to_subnet_rate,
                request_payload_size_bytes: payload_size_bytes,
                // A mix of guaranteed response and best-effort calls.
                call_timeouts_seconds: vec![None, Some(u32::MAX)],
                response_payload_size_bytes: payload_size_bytes,
            };
            let _: String = canister
                .update_("start", candid, (input,))
                .await
                .unwrap_or_else(|_| {
                    panic!(
                        "Starting canister_idx={canister_idx} on subnet_idx={subnet_idx} failed."
                    )
                });
        }
    });
}

/// Asserts that no call errors, sequence errors or reject responses were
/// observed. There should be none, as even though replicas were rebooted, this
/// should not have affected the subnets' behavior.
pub fn assert_no_errors(metrics: &[Vec<Metrics>], log: &Logger) {
    for (subnet_idx, subnet) in metrics.iter().enumerate() {
        for (canister_idx, metrics) in subnet.iter().enumerate() {
            assert!(
                metrics.seq_errors == 0
                    && metrics.call_errors == 0
                    && metrics.reject_responses == 0,
                "Metrics for subnet_idx={subnet_idx}, canister_idx={canister_idx}:\n{metrics:?}"
            );

            info!(
                log,
                "Metrics for subnet_idx={subnet_idx}, canister_idx={canister_idx}:\n{metrics:?}"
            );
        }
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
                        "Collecting metrics for canister_idx={canister_idx} on subnet_idx={subnet_idx} failed."
                    )
                });
            metrics[subnet_idx].push(result);
        }
    });
    metrics
}

/// Returns the total number of responses (successful + rejected) recorded in
/// the metrics.
fn responses_count(m: &Metrics) -> usize {
    m.latency_distribution.buckets().last().unwrap().1 + m.reject_responses
}

/// Returns `true` if every canister has received at least
/// `RESPONSES_FOR_PROGRESS` more responses than recorded in the baseline
/// metrics.
fn all_canisters_made_progress(metrics: &[Vec<Metrics>], baseline: &[Vec<Metrics>]) -> bool {
    metrics.iter().zip(baseline.iter()).all(|(m, b)| {
        m.iter()
            .zip(b.iter())
            .all(|(m, b)| responses_count(m) >= responses_count(b) + RESPONSES_FOR_PROGRESS)
    })
}

/// Waits for all canisters to receive new XNet responses relative to the ones
/// recorded in the baseline metrics.
///
/// Returns the new metrics on success. Panics if the timeout is reached.
pub fn wait_for_progress(
    canisters: &[Vec<Canister>],
    baseline: &[Vec<Metrics>],
    log: &Logger,
) -> Vec<Vec<Metrics>> {
    block_on(async {
        ic_system_test_driver::retry_with_msg_async!(
            "check_all_canisters_have_new_responses",
            &log,
            Duration::from_secs(RESPONSES_RETRY_TIMEOUT_SEC),
            Duration::from_secs(POLL_INTERVAL_SEC),
            || async {
                let metrics = collect_metrics(&canisters);
                if all_canisters_made_progress(&metrics, baseline) {
                    Ok(metrics)
                } else {
                    bail!("Not all canisters have received new Xnet responses yet")
                }
            }
        )
        .await
        .expect("Not all canisters received new Xnet responses within the timeout")
    })
}

pub fn install_canisters(
    endpoints_runtime: &[Runtime],
    subnets_count: usize,
    canisters_per_subnet: usize,
    wasm: Wasm,
) -> Vec<Vec<Canister<'_>>> {
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
                            "Installation of the canister_idx={canister_idx} on subnet_idx={subnet_idx} failed."
                        )
                    });
                canisters[subnet_idx].push(canister);
            }
        }
    });
    canisters
}
