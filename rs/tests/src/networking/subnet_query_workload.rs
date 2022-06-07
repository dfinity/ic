/* tag::catalog[]

Title:: Subnet handles query workloads.

Goal:: Ensure IC responds to queries of a given size in a timely manner.

Runbook::
0. Instantiate an IC with one System and one Application subnet.
1. Install NNS canisters on the System subnet.
2. Build and install one counter canister on the Application subnet.
3. Instantiate and start a workload against the Application subnet.
   Workload sends query[canister_id, "read"] requests.
   All requests are sent to the same node.
4. Collect metrics from the workload and assert:
   - Ratio of requests with duration below DURATION_THRESHOLD should exceed MIN_REQUESTS_RATIO_BELOW_THRESHOLD.
   - Ratio of successful requests should exceed min_success_ratio threshold.

end::catalog[] */

use crate::driver::ic::{InternetComputer, Subnet};
use crate::driver::test_env::TestEnv;
use crate::driver::test_env_api::{
    HasPublicApiUrl, HasTopologySnapshot, IcNodeContainer, NnsInstallationExt,
};
use crate::util::block_on;
use crate::workload::{CallSpec, Request, RoundRobinPlan, Workload};

use ic_registry_subnet_type::SubnetType;

use slog::{debug, info};

use std::time::Duration;

const COUNTER_CANISTER_WAT: &str = "counter.wat";
const CANISTER_METHOD: &str = "read";
// Size of the payload sent to the counter canister in query("write") call.
const PAYLOAD_SIZE_BYTES: usize = 1024;
// Duration of each request is placed into one of two categories - below or above this threshold.
const DURATION_THRESHOLD: Duration = Duration::from_secs(2);
// Ratio of requests with duration < DURATION_THRESHOLD should exceed this parameter.
const MIN_REQUESTS_RATIO_BELOW_THRESHOLD: f64 = 0.9;
// Parameters related to workload creation.
const RESPONSES_COLLECTION_EXTRA_TIMEOUT: Duration = Duration::from_secs(30); // Responses are collected during the workload execution + this extra time, after all requests had been dispatched.
const REQUESTS_DISPATCH_EXTRA_TIMEOUT: Duration = Duration::ZERO; // This param can be slightly tweaked (1-2 sec), if the workload fails to dispatch requests precisely on time.

// Test can be run with different setup/configuration parameters.
// This config holds these parameters.
#[derive(Debug, Clone, Copy)]
pub struct Config {
    nodes_nns_subnet: usize,
    nodes_app_subnet: usize,
    runtime: Duration,
    rps: usize,
    min_success_ratio: f64,
}

impl Config {
    /// Builds the IC instance.
    pub fn build(&self) -> impl FnOnce(TestEnv) {
        let config = *self;
        move |env: TestEnv| Config::config(env, config)
    }

    fn config(env: TestEnv, config: Config) {
        InternetComputer::new()
            .add_subnet(Subnet::new(SubnetType::System).add_nodes(config.nodes_nns_subnet))
            .add_subnet(Subnet::new(SubnetType::Application).add_nodes(config.nodes_app_subnet))
            .setup_and_start(&env)
            .expect("Failed to setup IC under test.");
    }

    /// Returns a test function based on the configuration.
    pub fn test(self) -> impl Fn(TestEnv) {
        move |env: TestEnv| test(env, self)
    }
}

pub fn config_sys_4_nodes_app_4_nodes() -> Config {
    Config {
        nodes_app_subnet: 4,
        nodes_nns_subnet: 4,
        rps: 1000,
        runtime: Duration::from_secs(60),
        min_success_ratio: 0.99,
    }
}

pub fn test(env: TestEnv, config: Config) {
    let log = env.logger();
    info!(
        &log,
        "Step 0: Checking readiness of all nodes after the IC setup ..."
    );
    let topology_snapshot = env.topology_snapshot();
    topology_snapshot.subnets().for_each(|subnet| {
        subnet
            .nodes()
            .for_each(|node| node.await_status_is_healthy().unwrap())
    });
    info!(&log, "All nodes are ready, IC setup succeeded.");
    info!(
        &log,
        "Step 1: Installing NNS canisters on the System subnet ..."
    );
    topology_snapshot
        .root_subnet()
        .nodes()
        .next()
        .unwrap()
        .install_nns_canisters()
        .expect("Could not install NNS canisters.");
    info!(&log, "NNS canisters installed successfully.");
    info!(
        &log,
        "Step 2: Build and install one counter canister on the Application subnet..."
    );
    let app_subnet = topology_snapshot
        .subnets()
        .find(|s| s.subnet_type() == SubnetType::Application)
        .unwrap();
    // Take the first node in the Application subnet.
    let app_node = app_subnet.nodes().next().unwrap();
    debug!(
        &log,
        "Node with id={} from the Application subnet will be used as a target for the workload.",
        app_node.node_id
    );
    let app_canister = app_node.create_and_install_canister_with_arg(COUNTER_CANISTER_WAT, None);
    info!(&log, "Installation of counter canister has succeeded.");
    info!(&log, "Step 3: Instantiate and start a workload using one node of the Application subnet as target.");
    // Workload sends messages to canister via node agents.
    // As we talk to a single node, we create one agent, accordingly.
    let app_agent = app_node.with_default_agent(|agent| async move { agent });
    // Spawn a workload against counter canister.
    let payload: Vec<u8> = vec![0; PAYLOAD_SIZE_BYTES];
    let plan = RoundRobinPlan::new(vec![Request::Query(CallSpec::new(
        app_canister,
        CANISTER_METHOD,
        payload,
    ))]);
    let workload = Workload::new(
        vec![app_agent],
        config.rps,
        config.runtime,
        plan,
        log.clone(),
    )
    .with_responses_collection_extra_timeout(RESPONSES_COLLECTION_EXTRA_TIMEOUT)
    .increase_requests_dispatch_timeout(REQUESTS_DISPATCH_EXTRA_TIMEOUT)
    .with_requests_duration_bucket(DURATION_THRESHOLD);
    let metrics = block_on(async {
        workload.execute().await.unwrap_or_else(|err| {
            panic!("Execution of the workload failed, err={:?}", err);
        })
    });
    info!(
        &log,
        "Step 4: Collect metrics from the workload and perform assertions ..."
    );
    let total_requests_count = config.rps * config.runtime.as_secs() as usize;
    let success_calls: usize = total_requests_count - metrics.errors().values().sum::<usize>();
    let success_ratio: f64 = (success_calls as f64) / total_requests_count as f64;
    let duration_bucket = metrics
        .find_request_duration_bucket(DURATION_THRESHOLD)
        .unwrap();
    debug!(&log, "Results of the workload execution {:?}", metrics);
    info!(
        &log,
        "Minimum expected success ratio is {}, actual success ratio is {}.",
        config.min_success_ratio,
        success_ratio
    );
    assert!(
        success_ratio > config.min_success_ratio,
        "Too many requests have failed."
    );
    info!(
        &log,
        "Requests below {} sec:\nRequests_count = {}\nRequests_ratio = {}",
        DURATION_THRESHOLD.as_secs(),
        duration_bucket.requests_count_below_threshold(),
        duration_bucket.requests_ratio_below_threshold(),
    );
    assert!(duration_bucket.requests_ratio_below_threshold() > MIN_REQUESTS_RATIO_BELOW_THRESHOLD);
}
