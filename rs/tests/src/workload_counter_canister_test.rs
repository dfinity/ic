/* tag::catalog[]

Title:: Use workload to execute update/query calls on counter canisters.

Goal:: Ensure that at a moderate rate of requests per second, workload sends update/query requests to counter canisters successfully.

Runbook::
0. Set up an application subnet with N nodes.
1. Install X counter canisters on this subnet.
2. Instantiate and start the workload.
   Workload sends update/query requests in a round-robin fashion:
   [update[canister_id_0], query[canister_id_1], query[canister_id_0], update[canister_id_1]].
   These requests are equally distributed between nodes of the subnet.
3. Query the number of executed update calls on the counter canisters.
4. Assert that number of update calls on each canister = rps * workload_execution_sec / (2 * X).
   Factor 2 is present above as half of the calls are `query` and half are `update` (see Item 2.)

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
const RPS: usize = 20;
const DURATION: Duration = Duration::from_secs(20);

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
    // Install canisters.
    let mut agents = Vec::new();
    let mut canisters = Vec::new();
    for ep in endpoints.iter() {
        agents.push(assert_create_agent(ep.url.as_str()).await);
    }
    let install_agent = &agents[0];
    for _ in 0..CANISTERS_COUNT {
        canisters.push(install_counter_canister(install_agent).await);
    }
    // Initialize requests' plan for the workload.
    let payload: Vec<u8> = vec![0; 12];
    let plan = RoundRobinPlan::new(vec![
        Request::Update(CallSpec::new(canisters[0], "write", payload.clone())),
        Request::Query(CallSpec::new(canisters[1], "read", payload.clone())),
        Request::Query(CallSpec::new(canisters[0], "read", payload.clone())),
        Request::Update(CallSpec::new(canisters[1], "write", payload.clone())),
    ]);

    let workload = Workload::new(agents, RPS, DURATION, plan, ctx.logger.clone());

    let metrics = workload
        .execute()
        .await
        .expect("Workload execution failed.");

    info!(
        ctx.logger,
        "Min request duration={} ms.",
        metrics.min_request_duration().as_millis()
    );
    info!(
        ctx.logger,
        "Max request duration={} ms.",
        metrics.max_request_duration().as_millis()
    );

    // Assert metrics from workload's perspective.
    let requests_count = RPS * DURATION.as_secs() as usize;
    info!(ctx.logger, "Expected requests count={}", requests_count);
    assert_eq!(
        metrics.success_calls(),
        requests_count,
        "Not all calls were successful."
    );
    assert_eq!(
        metrics.failure_calls(),
        0,
        "Number of failed calls should be zero."
    );

    // Assert metrics from counter canisters' perspective (expected counter value).
    let agent = assert_create_agent(endpoints[0].url.as_str()).await;
    let expected_count = RPS * DURATION.as_secs() as usize / CANISTERS_COUNT / 2;
    for canister in canisters.iter() {
        assert_canister_counter_with_retries(
            &ctx.logger,
            &agent,
            canister,
            payload.clone(),
            expected_count,
            10,
            10,
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
    max_retries: u64,
    retry_wait_sec: u64,
) {
    for i in 0..max_retries + 1 {
        debug!(
            log,
            "Reading counter value from canister with id={}, attempt {}.",
            canister_id,
            i + 1
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
            debug!(log, "Retrying in {} secs...", retry_wait_sec);
            tokio::time::sleep(std::time::Duration::from_secs(retry_wait_sec)).await;
        }
    }
    panic!(
        "Expected counter value {} on counter_canister was not observed after {} retries.",
        expected_count, max_retries
    );
}
