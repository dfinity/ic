/* tag::catalog[]

Title:: Use workload to execute update/query calls on counter canisters.

Goal:: Ensure that at a moderate rate of requests per second, workload sends update/query requests to counter canisters successfully.
Update calls increments canisters counter. Query calls (with non-existing methods) on canisters are expected to fail.

Runbook::
0. Set up an IC with an application subnet.
1. Install X counter canisters on this subnet.
2. Instantiate and start the workload.
   Workload sends update/query requests to counter canisters in a round-robin fashion:
   [
       update[canister_id_0, "write"], // should be successful
       query[canister_id_1, "non_existing_method_a"], // should fail
       query[canister_id_0, "non_existing_method_b"], // should fail
       update[canister_id_1, "write"], // should be successful
    ].
   These requests are sent to a random node of an application subnet.
3. Assert the expected number of failed query calls on each canister.
4. Assert the expected number of successful update calls on each canister.

end::catalog[] */

use crate::canister_agent::HasCanisterAgentCapability;
use crate::canister_api::{CallMode, GenericRequest};
use crate::canister_requests;
use crate::driver::ic::{InternetComputer, Subnet};
use crate::driver::test_env::TestEnv;
use crate::driver::test_env_api::{
    HasPublicApiUrl, HasTopologySnapshot, IcNodeContainer, NnsInstallationBuilder,
};
use crate::generic_workload_engine::engine::Engine;
use crate::generic_workload_engine::metrics::{LoadTestMetricsProvider, RequestOutcome};
use crate::util::{assert_canister_counter_with_retries, block_on};

use ic_agent::{export::Principal, Agent};
use ic_base_types::PrincipalId;
use ic_prep_lib::subnet_configuration::constants;
use ic_registry_subnet_type::SubnetType;
use ic_utils::interfaces::ManagementCanister;
use slog::info;
use std::time::Duration;

const NODES_COUNT: usize = 3;
const NON_EXISTING_METHOD_A: &str = "non_existing_method_a";
const NON_EXISTING_METHOD_B: &str = "non_existing_method_b";
const MAX_RETRIES: u32 = 10;
const RETRY_WAIT: Duration = Duration::from_secs(10);
const SUCCESS_THRESHOLD: f32 = 0.95; // If more than 95% of the expected calls are successful the test passes
const REQUESTS_DISPATCH_EXTRA_TIMEOUT: Duration = Duration::from_secs(1);

/// Default configuration for this test
pub fn config(env: TestEnv) {
    InternetComputer::new()
        .add_subnet(Subnet::new(SubnetType::Application).add_nodes(NODES_COUNT))
        .setup_and_start(&env)
        .expect("failed to setup IC under test");
    env.topology_snapshot().subnets().for_each(|subnet| {
        subnet
            .nodes()
            .for_each(|node| node.await_status_is_healthy().unwrap())
    });
}

/// SLO test configuration with a NNS subnet and an app subnet with the same number of nodes as used on mainnet
pub fn two_third_latency_config(env: TestEnv) {
    InternetComputer::new()
        .add_subnet(Subnet::new(SubnetType::System).add_nodes(40))
        .add_subnet(
            Subnet::new(SubnetType::Application).add_nodes(constants::SMALL_APP_SUBNET_MAX_SIZE),
        )
        .setup_and_start(&env)
        .expect("failed to setup IC under test");
    env.topology_snapshot().subnets().for_each(|subnet| {
        subnet
            .nodes()
            .for_each(|node| node.await_status_is_healthy().unwrap())
    });
}

/// Default test installing two canisters and sending 60 requests per second for 30 seconds
/// This test is run in hourly jobs.
pub fn short_test(env: TestEnv) {
    let is_install_nns_canisters = false;
    let canister_count: usize = 2;
    let rps: usize = 60;
    let duration: Duration = Duration::from_secs(30);
    test(env, canister_count, rps, duration, is_install_nns_canisters);
}

/// SLO test installing two canisters and sending 200 requests per second for 500 seconds.
/// This test is run nightly.
pub fn two_third_latency_test(env: TestEnv) {
    let is_install_nns_canisters = true;
    let canister_count: usize = 2;
    let rps: usize = 200;
    let duration: Duration = Duration::from_secs(500);
    test(env, canister_count, rps, duration, is_install_nns_canisters);
}

fn test(
    env: TestEnv,
    canister_count: usize,
    rps: usize,
    duration: Duration,
    is_install_nns_canisters: bool,
) {
    let log = env.logger();
    let app_node = env
        .topology_snapshot()
        .subnets()
        .find(|s| s.subnet_type() == SubnetType::Application)
        .unwrap()
        .nodes()
        .next()
        .unwrap();

    if is_install_nns_canisters {
        info!(log, "Installing NNS canisters...");
        let nns_node = env
            .topology_snapshot()
            .root_subnet()
            .nodes()
            .next()
            .unwrap();
        NnsInstallationBuilder::new()
            .install(&nns_node, &env)
            .expect("Could not install NNS canisters");
    }

    block_on(async move {
        info!(
            log,
            "Step 1: Install {} canisters on the subnet..", canister_count
        );
        let mut canisters = Vec::new();
        let agent = app_node.build_canister_agent().await;

        for _ in 0..canister_count {
            canisters.push(
                install_counter_canister(&agent.get(), app_node.effective_canister_id()).await,
            );
        }
        info!(log, "{} canisters installed successfully.", canisters.len());
        assert_eq!(
            canisters.len(),
            canister_count,
            "Not all canisters deployed successfully, installed {:?} expected {:?}",
            canisters.len(),
            canister_count
        );
        info!(log, "Step 2: Instantiate and start the workload..");

        let payload: Vec<u8> = vec![0; 12];
        let generator = {
            let (agent, canisters, payload) = (agent.clone(), canisters.clone(), payload.clone());
            move |idx: usize| {
                let (agent, canisters, payload) =
                    (agent.clone(), canisters.clone(), payload.clone());
                async move {
                    let (agent, canisters, payload) =
                        (agent.clone(), canisters.clone(), payload.clone());
                    let request_outcome = canister_requests![
                        idx,
                        1 * agent => GenericRequest::new(canisters[1], NON_EXISTING_METHOD_A.to_string(), payload.clone(), CallMode::Query),
                        1 * agent => GenericRequest::new(canisters[0], NON_EXISTING_METHOD_B.to_string(), payload.clone(), CallMode::Query),
                        1 * agent => GenericRequest::new(canisters[0], "write".to_string(), payload.clone(), CallMode::Update),
                        1 * agent => GenericRequest::new(canisters[1], "write".to_string(), payload.clone(), CallMode::Update),
                    ];
                    request_outcome.into_test_outcome()
                }
            }
        };
        let metrics = Engine::new(log.clone(), generator, rps, duration)
            .increase_dispatch_timeout(REQUESTS_DISPATCH_EXTRA_TIMEOUT)
            .execute_simply(log.clone())
            .await;
        info!(log, "Reporting workload execution results ...");
        env.emit_report(format!("{metrics}"));
        info!(
            log,
            "Step 3: Assert expected number of failed query calls on each canister.."
        );
        let requests_count = rps * duration.as_secs() as usize;
        // 1/2 requests are query (failure) and 1/2 are update (success).
        let min_expected_failure_calls = (SUCCESS_THRESHOLD * requests_count as f32 / 2.0) as usize;
        let min_expected_success_calls = min_expected_failure_calls;
        info!(
            log,
            "Minimal expected number of success calls {}, failure calls {}",
            min_expected_success_calls,
            min_expected_failure_calls
        );
        info!(
            log,
            "Actual number of success calls {}, failure calls {}",
            metrics.success_calls(),
            metrics.failure_calls()
        );
        // Error messages should contain the name of failed method call.
        let errors = metrics.errors();
        assert!(
            errors.keys().any(|k| k.contains(NON_EXISTING_METHOD_A)),
            "Missing error key {}",
            NON_EXISTING_METHOD_A
        );
        assert!(
            errors.keys().any(|k| k.contains(NON_EXISTING_METHOD_B)),
            "Missing error key {}",
            NON_EXISTING_METHOD_B
        );
        assert!(
            metrics.failure_calls() >= min_expected_failure_calls,
            "The number of observed failure calls ({}) is less than expected ({})",
            metrics.failure_calls(),
            min_expected_failure_calls
        );
        assert!(
            metrics.success_calls() >= min_expected_success_calls,
            "The number of observed success calls ({}) is less than expected ({})",
            metrics.success_calls(),
            min_expected_success_calls
        );
        assert_eq!(
            requests_count,
            metrics.total_calls(),
            "Submitted {} calls, but the total number of recorded calls is {}",
            requests_count,
            metrics.total_calls()
        );
        info!(
            log,
            "Step 4: Assert the expected number of update calls on each canister.."
        );
        let min_expected_canister_counter = min_expected_success_calls / canister_count;
        info!(
            log,
            "Minimal expected counter value on canisters {}", min_expected_canister_counter
        );
        for canister in canisters.iter() {
            assert_canister_counter_with_retries(
                &log,
                &agent.get(),
                canister,
                payload.clone(),
                min_expected_canister_counter,
                MAX_RETRIES,
                RETRY_WAIT,
            )
            .await;
        }
    });
}

pub async fn install_counter_canister(
    agent: &Agent,
    effective_canister_id: PrincipalId,
) -> Principal {
    const COUNTER_CANISTER_WAT: &str = include_str!("./counter.wat");
    let mgr = ManagementCanister::create(agent);

    let canister_id = mgr
        .create_canister()
        .as_provisional_create_with_amount(None)
        .with_effective_canister_id(effective_canister_id)
        .call_and_wait()
        .await
        .unwrap()
        .0;

    mgr.install_code(
        &canister_id,
        wat::parse_str(COUNTER_CANISTER_WAT).unwrap().as_slice(),
    )
    .call_and_wait()
    .await
    .expect("Failed to install counter canister.");

    canister_id
}
