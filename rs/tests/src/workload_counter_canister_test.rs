/* tag::catalog[]

Title:: Use workload to execute update/query calls on counter canisters.

Goal:: Ensure that at a moderate rate of requests per second, workload sends update/query requests to counter canisters successfully.
Update calls increments canisters counter. Query calls (with non-existing methods) on canisters are expected to fail.

Runbook::
0. Set up an application subnet with N nodes.
1. Install X counter canisters on this subnet.
2. Instantiate and start the workload.
   Workload sends update/query requests to counter canisters in a round-robin fashion:
   [
       update[canister_id_0, "write"], // should be successful
       query[canister_id_1, "non_existing_method_a"], // should fail
       query[canister_id_0, "non_existing_method_b"], // should fail
       update[canister_id_1, "write"], // should be successful
    ].
   These requests are equally distributed between nodes of the subnet.
3. Assert the expected number of failed query calls on each canister.
4. Assert the expected number of successful update calls on each canister.

end::catalog[] */

use crate::driver::ic::{InternetComputer, Subnet};
use crate::util::{assert_create_agent, delay};
use crate::util::{assert_endpoints_reachability, EndpointsStatus};
use crate::workload::{CallSpec, Request, RoundRobinPlan, Workload};
use ic_agent::{export::Principal, Agent};
use ic_fondue::ic_manager::IcHandle;
use ic_registry_subnet_type::SubnetType;
use ic_utils::interfaces::ManagementCanister;
use slog::{debug, info};
use std::convert::TryInto;
use std::time::Duration;

const NODES_COUNT: usize = 3;
const CANISTERS_COUNT: usize = 2;
const RPS: usize = 60;
const DURATION: Duration = Duration::from_secs(30);
const NON_EXISTING_METHOD_A: &str = "non_existing_method_a";
const NON_EXISTING_METHOD_B: &str = "non_existing_method_b";
const MAX_RETRIES: u32 = 10;
const RETRY_WAIT: Duration = Duration::from_secs(10);

pub fn config() -> InternetComputer {
    InternetComputer::new().add_subnet(Subnet::new(SubnetType::Application).add_nodes(NODES_COUNT))
}

// This macro is an experimental/temporary approach for writing tests.
// Usually we have sync test() function and call block_on on async methods within the tests.
#[tokio::main]
pub async fn test(handle: IcHandle, ctx: &ic_fondue::pot::Context) {
    // Assert all nodes are reachable via http:://[IPv6]:8080/api/v2/status
    let mut rng = ctx.rng.clone();
    let endpoints: Vec<_> = handle.as_permutation(&mut rng).collect();
    assert_endpoints_reachability(endpoints.as_slice(), EndpointsStatus::AllReachable).await;
    info!(ctx.logger, "All nodes are reachable, IC setup succeeded.");
    // Step 1: Install X counter canisters on the subnet.
    let mut agents = Vec::new();
    let mut canisters = Vec::new();
    for ep in endpoints.iter() {
        agents.push(assert_create_agent(ep.url.as_str()).await);
    }
    info!(ctx.logger, "Installing canisters...");
    let install_agent = agents[0].clone();
    for _ in 0..CANISTERS_COUNT {
        canisters.push(install_counter_canister(&install_agent).await);
    }
    info!(
        ctx.logger,
        "{} canisters installed successfully.",
        canisters.len()
    );
    assert_eq!(canisters.len(), CANISTERS_COUNT);
    // Step 2: Instantiate and start the workload.
    let payload: Vec<u8> = vec![0; 12];
    let plan = RoundRobinPlan::new(vec![
        Request::Update(CallSpec::new(canisters[0], "write", payload.clone())),
        Request::Query(CallSpec::new(
            canisters[1],
            NON_EXISTING_METHOD_A,
            payload.clone(),
        )),
        Request::Query(CallSpec::new(
            canisters[0],
            NON_EXISTING_METHOD_B,
            payload.clone(),
        )),
        Request::Update(CallSpec::new(canisters[1], "write", payload.clone())),
    ]);
    let workload = Workload::new(agents, RPS, DURATION, plan, ctx.logger.clone());
    let metrics = workload
        .execute()
        .await
        .expect("Workload execution has failed.");
    // Step 3: Assert the expected number of failed query calls on each canister.
    info!(ctx.logger, "Asserting metrics are correct...");
    let requests_count = RPS * DURATION.as_secs() as usize;
    // 1/2 requests are query (failure) and 1/2 are update (success).
    let expected_failure_calls = requests_count / 2;
    let expected_success_calls = requests_count / 2;
    let errors = metrics.errors();
    assert_eq!(errors.len(), 2);
    // Error messages should contain the name of failed method call.
    assert!(errors.keys().any(|k| k.contains(NON_EXISTING_METHOD_A)));
    assert!(errors.keys().any(|k| k.contains(NON_EXISTING_METHOD_B)));
    assert!(errors
        .values()
        .all(|k| *k == expected_failure_calls / CANISTERS_COUNT));
    assert_eq!(expected_failure_calls, metrics.failure_calls());
    assert_eq!(expected_success_calls, metrics.success_calls());
    assert_eq!(requests_count, metrics.total_calls());
    // Step 4: Assert the expected number of update calls on each canister.
    let expected_canister_counter = expected_success_calls / CANISTERS_COUNT;
    for canister in canisters.iter() {
        assert_canister_counter_with_retries(
            &ctx.logger,
            &install_agent,
            canister,
            payload.clone(),
            expected_canister_counter,
            MAX_RETRIES,
            RETRY_WAIT,
        )
        .await;
    }
}

pub async fn install_counter_canister(agent: &Agent) -> Principal {
    const COUNTER_CANISTER_WAT: &[u8] = include_bytes!("./counter.wat");
    let mgr = ManagementCanister::create(agent);

    let canister_id = mgr
        .create_canister()
        .as_provisional_create_with_amount(None)
        .call_and_wait(delay())
        .await
        .unwrap()
        .0;

    mgr.install_code(
        &canister_id,
        wabt::wat2wasm(COUNTER_CANISTER_WAT).unwrap().as_slice(),
    )
    .call_and_wait(delay())
    .await
    .expect("Failed to install counter canister.");

    canister_id
}

async fn assert_canister_counter_with_retries(
    log: &slog::Logger,
    agent: &Agent,
    canister_id: &Principal,
    payload: Vec<u8>,
    expected_count: usize,
    max_retries: u32,
    retry_wait: Duration,
) {
    for i in 1..=1 + max_retries {
        debug!(
            log,
            "Reading counter value from canister with id={}, attempt {}.", canister_id, i
        );
        let res = agent
            .query(canister_id, "read")
            .with_arg(&payload)
            .call()
            .await
            .unwrap();
        let counter = u32::from_le_bytes(
            res.as_slice()
                .try_into()
                .expect("slice with incorrect length"),
        ) as usize;
        debug!(log, "Counter value is {}", counter);
        if counter == expected_count {
            debug!(
                log,
                "Counter value on canister is {}, matches the expectation.", counter
            );
            return;
        } else {
            debug!(
                log,
                "Counter value != expected_count, {} != {}", counter, expected_count
            );
            debug!(log, "Retrying in {} secs...", retry_wait.as_secs());
            tokio::time::sleep(retry_wait).await;
        }
    }
    panic!(
        "Expected counter value {} on counter_canister was not observed after {} retries.",
        expected_count, max_retries
    );
}
