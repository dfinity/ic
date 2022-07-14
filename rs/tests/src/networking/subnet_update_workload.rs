/* tag::catalog[]

Title:: Subnet handles update workloads.

Goal:: Ensure IC responds to update calls of a given size in a timely manner.

Runbook::
0. Instantiate an IC with one System and one Application subnet.
   - Optionally install one boundary node.
1. Install NNS canisters on the System subnet.
2. Build and install counter canister on each subnet.
3. Instantiate and simultaneously start two workloads (one per subnet).
   Workloads send update[canister_id, "write"] requests.
   If the boundary node option is used, all requests are dispatched to the subnets via the boundary node,
   otherwise requests are directly dispatched to all the nodes of the subnets in a round-robin fashion.
4. Collect metrics from both workloads and assert:
   - Ratio of requests with duration below DURATION_THRESHOLD should exceed MIN_REQUESTS_RATIO_BELOW_THRESHOLD.
   - Ratio of successful requests should exceed the min_success_ratio threshold.
5. Perform assertions on the counter canisters (via query `read` call)
   - Counter value on the canister should exceed the threshold = min_success_ratio * total_requests_count.

end::catalog[] */

use crate::driver::boundary_node::{BoundaryNode, BoundaryNodeVm};
use crate::driver::ic::{InternetComputer, Subnet};
use crate::driver::pot_dsl::get_ic_handle_and_ctx;
use crate::driver::test_env::{HasIcPrepDir, TestEnv};
use crate::driver::test_env_api::{retry_async, RETRY_BACKOFF, RETRY_TIMEOUT};
use crate::driver::test_env_api::{
    HasPublicApiUrl, HasTopologySnapshot, HasVmName, IcNodeContainer, NnsInstallationExt,
    SubnetSnapshot,
};

use crate::util::{
    assert_agent_observes_canister_module, assert_canister_counter_with_retries, block_on,
    create_agent_mapping,
};
use crate::workload::{CallSpec, Metrics, Request, RoundRobinPlan, Workload};
use ic_agent::{export::Principal, Agent};
use ic_prep_lib::subnet_configuration::constants;

use ic_registry_subnet_type::SubnetType;

use slog::{debug, info, Logger};

use std::thread::JoinHandle;
use std::time::Duration;

const BOUNDARY_NODE_NAME: &str = "boundary-node-1";
const COUNTER_CANISTER_WAT: &str = "counter.wat";
const CANISTER_METHOD: &str = "write";
// Duration of each request is placed into one of the two categories - below or above this threshold.
const APP_DURATION_THRESHOLD: Duration = Duration::from_secs(3);
const NNS_DURATION_THRESHOLD: Duration = Duration::from_secs(2);
// Ratio of requests with duration < DURATION_THRESHOLD should exceed this parameter.
const MIN_REQUESTS_RATIO_BELOW_THRESHOLD: f64 = 0.9;
// Parameters related to reading/asserting counter values of the canisters.
const MAX_CANISTER_READ_RETRIES: u32 = 4;
const CANISTER_READ_RETRY_WAIT: Duration = Duration::from_secs(10);
// Parameters related to workload creation.
const RESPONSES_COLLECTION_EXTRA_TIMEOUT: Duration = Duration::from_secs(30); // Responses are collected during the workload execution + this extra time, after all requests had been dispatched.
const REQUESTS_DISPATCH_EXTRA_TIMEOUT: Duration = Duration::from_secs(2); // This param can be slightly tweaked (1-2 sec), if the workload fails to dispatch requests precisely on time.

// Create an IC with two subnets, with variable number of nodes and boundary nodes
// Install NNS canister on system subnet
fn config(env: TestEnv, nodes_nns_subnet: usize, nodes_app_subnet: usize, use_boundary_node: bool) {
    InternetComputer::new()
        .add_subnet(Subnet::new(SubnetType::System).add_nodes(nodes_nns_subnet))
        .add_subnet(Subnet::new(SubnetType::Application).add_nodes(nodes_app_subnet))
        .setup_and_start(&env)
        .expect("Failed to setup IC under test.");
    if use_boundary_node {
        info!(
            &env.logger(),
            "Step 0: Additionally installing a boundary node ..."
        );
        let (handle, _ctx) = get_ic_handle_and_ctx(env.clone());
        let nns_urls = handle
            .public_api_endpoints
            .iter()
            .filter(|ep| ep.is_root_subnet)
            .map(|ep| ep.url.clone())
            .collect();
        BoundaryNode::new(String::from(BOUNDARY_NODE_NAME))
            .with_nns_urls(nns_urls)
            .with_nns_public_key(env.prep_dir("").unwrap().root_public_key_path())
            .start(&env)
            .expect("Failed to setup a universal VM.");
        info!(
            &env.logger(),
            "Step 0: Installation of the boundary nodes succeeded."
        );
    }
    info!(
        &env.logger(),
        "Step 1: Installing NNS canisters on the System subnet ..."
    );
    env.topology_snapshot()
        .root_subnet()
        .nodes()
        .next()
        .unwrap()
        .install_nns_canisters()
        .expect("Could not install NNS canisters.");
}

// Create IC with two subnets, a system subnet of the same size as the mainnet NNS
// and an app subnet of the same size as mainnet app subnets, and one boundary node
pub fn default_config(env: TestEnv) {
    config(
        env,
        constants::NNS_SUBNET_SIZE,
        constants::SMALL_APP_SUBNET_MAX_SIZE,
        true,
    )
}

// Create IC with two subnets, a system subnet with 18 more nodes than the mainnet NNS
// and an app subnet of the same size as mainnet NNS subnet, without a boundary node
pub fn large_config(env: TestEnv) {
    config(
        env,
        constants::NNS_SUBNET_SIZE + 18,
        constants::NNS_SUBNET_SIZE,
        false,
    )
}

// Run a long test (6h) with the max rps we bring across a boundary node
pub fn long_duration_test(env: TestEnv) {
    test(
        env,
        100,  //rps
        1000, //payload size bytes
        Duration::from_secs(6 * 60 * 60),
        true, //use boundary nodes
        0.95, //min_success_ratio
    );
}

// Run test with 5 large (100kb) update requests per second, sent directly
// to the replicas (to be extended to 6h)
pub fn large_payload_test(env: TestEnv) {
    test(
        env,
        5,       //rps
        100_000, //payload size bytes
        Duration::from_secs(6 * 60 * 60),
        false, //use boundary nodes
        0.95,  //min_success_ratio
    );
}

// Run a test with roughly half the rps supported by subnets, sent directly
// to the replicas (to be extended to 6h)
pub fn large_subnet_test(env: TestEnv) {
    test(
        env,
        280,  //rps
        1000, //payload size bytes
        Duration::from_secs(2 * 60 * 60),
        false, //use boundary nodes
        0.95,  //min_success_ratio
    );
}

// Run a test with configurable number of update requests per second,
// size of the payload, duration of the test, the requests can be sent
// to replica or boundary nodes and the required success ratio can be
// adjusted.
pub fn test(
    env: TestEnv,
    rps: usize,
    payload_size_bytes: usize,
    duration: Duration,
    use_boundary_node: bool,
    min_success_ratio: f64,
) {
    let log = env.logger();
    info!(
        &log,
        "Step 1: Checking readiness of all nodes after the IC setup ..."
    );
    let top_snapshot = env.topology_snapshot();
    top_snapshot.subnets().for_each(|subnet| {
        subnet
            .nodes()
            .for_each(|node| node.await_status_is_healthy().unwrap())
    });
    info!(&log, "All nodes are ready, IC setup succeeded.");
    info!(
        &log,
        "Step 2: Build and install one counter canisters on each subnet ..."
    );
    let app_subnet = top_snapshot
        .subnets()
        .find(|s| s.subnet_type() == SubnetType::Application)
        .unwrap();
    let nns_subnet = top_snapshot
        .subnets()
        .find(|s| s.subnet_type() == SubnetType::System)
        .unwrap();
    let app_canister = app_subnet
        .nodes()
        .next()
        .unwrap()
        .create_and_install_canister_with_arg(COUNTER_CANISTER_WAT, None);
    let nns_canister = nns_subnet
        .nodes()
        .next()
        .unwrap()
        .create_and_install_canister_with_arg(COUNTER_CANISTER_WAT, None);
    info!(
        &log,
        "Installation of counter canisters on both subnets has succeeded."
    );
    info!(&log, "Step 3: Instantiate and start workloads.");
    // Workload sends messages to canisters via node agents, so we create them.
    let app_agents = create_agents_for_subnet(&log, use_boundary_node, &env, &app_subnet);
    let nns_agents = create_agents_for_subnet(&log, use_boundary_node, &env, &nns_subnet);
    info!(
        &log,
        "Asserting all agents observe the installed canister ..."
    );
    block_on(async {
        for agent in nns_agents.iter() {
            retry_async(&log, RETRY_TIMEOUT, RETRY_BACKOFF, || async {
                assert_agent_observes_canister_module(agent, &nns_canister).await;
                Ok(())
            })
            .await
            .unwrap();
        }
        for agent in app_agents.iter() {
            retry_async(&log, RETRY_TIMEOUT, RETRY_BACKOFF, || async {
                assert_agent_observes_canister_module(agent, &app_canister).await;
                Ok(())
            })
            .await
            .unwrap();
        }
    });
    info!(&log, "All agents observe the installed canister module.");
    // Spawn one workload per subnet against the counter canister.
    let payload: Vec<u8> = vec![0; payload_size_bytes];
    let handle_nns_workload = spawn_workload(
        log.clone(),
        nns_canister,
        nns_agents,
        rps,
        duration,
        payload.clone(),
        NNS_DURATION_THRESHOLD,
    );
    let handle_app_workload = spawn_workload(
        log.clone(),
        app_canister,
        app_agents,
        rps,
        duration,
        payload.clone(),
        APP_DURATION_THRESHOLD,
    );
    let nns_metrics = handle_nns_workload
        .join()
        .expect("Workload execution against System subnet failed.");
    let app_metrics = handle_app_workload
        .join()
        .expect("Workload execution against Application subnet failed.");
    info!(
        &log,
        "Step 4: Collect metrics from the workloads and perform assertions ..."
    );
    let nns_duration_bucket = nns_metrics
        .find_request_duration_bucket(NNS_DURATION_THRESHOLD)
        .unwrap();
    let app_duration_bucket = app_metrics
        .find_request_duration_bucket(APP_DURATION_THRESHOLD)
        .unwrap();
    info!(
        &log,
        "Requests below {} or {} sec:\nRequests_count: System={} Application={}\nRequests_ratio: System={}, Application={}.",
        NNS_DURATION_THRESHOLD.as_secs(),
        APP_DURATION_THRESHOLD.as_secs(),
        nns_duration_bucket.requests_count_below_threshold(),
        app_duration_bucket.requests_count_below_threshold(),
        nns_duration_bucket.requests_ratio_below_threshold(),
        app_duration_bucket.requests_ratio_below_threshold(),
    );
    info!(
        &log,
        "Minimum expected success ratio is {}\n. Actual values on the subnets: System={}, Application={}",
        min_success_ratio,
        nns_metrics.success_ratio(),
        app_metrics.success_ratio()
    );
    assert!(
        nns_metrics.success_ratio() > min_success_ratio,
        "Too many requests failed on the System subnet."
    );
    assert!(
        app_metrics.success_ratio() > min_success_ratio,
        "Too many requests failed on the Application subnet."
    );
    assert!(
        nns_duration_bucket.requests_ratio_below_threshold() > MIN_REQUESTS_RATIO_BELOW_THRESHOLD
    );
    assert!(
        app_duration_bucket.requests_ratio_below_threshold() > MIN_REQUESTS_RATIO_BELOW_THRESHOLD
    );
    let total_requests_count = rps * duration.as_secs() as usize;
    let min_expected_counter = (min_success_ratio * total_requests_count as f64) as usize;
    info!(
        &log,
        "Step 5: Assert min counter value={} on the canisters has been reached ... ",
        min_expected_counter
    );
    let nns_agent = nns_subnet
        .nodes()
        .next()
        .map(|node| node.with_default_agent(|agent| async move { agent }))
        .unwrap();
    let app_agent = app_subnet
        .nodes()
        .next()
        .map(|node| node.with_default_agent(|agent| async move { agent }))
        .unwrap();
    block_on(async {
        assert_canister_counter_with_retries(
            &log,
            &nns_agent,
            &nns_canister,
            payload.clone(),
            min_expected_counter,
            MAX_CANISTER_READ_RETRIES,
            CANISTER_READ_RETRY_WAIT,
        )
        .await;
    });
    block_on(async {
        assert_canister_counter_with_retries(
            &log,
            &app_agent,
            &app_canister,
            payload.clone(),
            min_expected_counter,
            MAX_CANISTER_READ_RETRIES,
            CANISTER_READ_RETRY_WAIT,
        )
        .await;
    });
}

fn spawn_workload(
    log: Logger,
    canister_id: Principal,
    agents: Vec<Agent>,
    rps: usize,
    runtime: Duration,
    payload: Vec<u8>,
    duration_threshold: Duration,
) -> JoinHandle<Metrics> {
    let plan = RoundRobinPlan::new(vec![Request::Update(CallSpec::new(
        canister_id,
        CANISTER_METHOD,
        payload,
    ))]);
    let dispatch_timeout = REQUESTS_DISPATCH_EXTRA_TIMEOUT + runtime.div_f32(50.0);
    std::thread::spawn(move || {
        block_on(async {
            let workload = Workload::new(agents, rps, runtime, plan, log)
                .with_responses_collection_extra_timeout(RESPONSES_COLLECTION_EXTRA_TIMEOUT)
                .increase_requests_dispatch_timeout(dispatch_timeout)
                .with_requests_duration_bucket(duration_threshold);
            workload
                .execute()
                .await
                .expect("Execution of the workload failed.")
        })
    })
}

fn create_agents_for_subnet(
    log: &Logger,
    use_boundary_node: bool,
    env: &TestEnv,
    subnet: &SubnetSnapshot,
) -> Vec<Agent> {
    if use_boundary_node {
        let deployed_boundary_node = env.get_deployed_boundary_node(BOUNDARY_NODE_NAME).unwrap();
        let boundary_node_vm = deployed_boundary_node.get_vm().unwrap();
        info!(
            &env.logger(),
            "Agent for the boundary node with name={:?} will be used for the {:?} subnet workload.",
            deployed_boundary_node.vm_name(),
            subnet.subnet_type()
        );
        let agent = block_on(async {
            create_agent_mapping("https://ic0.app/", boundary_node_vm.ipv6.into())
                .await
                .unwrap_or_else(|err| {
                    panic!("Failed to create agent for https://ic0.app/: {:?}", err)
                })
        });
        vec![agent]
    } else {
        subnet
            .nodes()
            .map(|node| {
                debug!(
                    &log,
                    "Agent for the node with id={} from the {:?} subnet will be used for the workload.",
                    node.node_id,
                    subnet.subnet_type()
                );
                node.with_default_agent(|agent| async move { agent })
            })
            .collect::<_>()
    }
}
