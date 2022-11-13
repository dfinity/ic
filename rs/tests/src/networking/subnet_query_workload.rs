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

use crate::driver::test_env::TestEnv;
use crate::driver::test_env_api::{HasPublicApiUrl, HasTopologySnapshot, IcNodeContainer};
use crate::util::block_on;
use crate::workload::{CallSpec, Request, RoundRobinPlan, Workload};

use ic_registry_subnet_type::SubnetType;

use slog::{debug, info, Logger};

use std::process::Command;
use std::time::Duration;

const COUNTER_CANISTER_WAT: &str = "rs/workload_generator/src/counter.wat";
const CANISTER_METHOD: &str = "read";
// Size of the payload sent to the counter canister in query("write") call.
const PAYLOAD_SIZE_BYTES: usize = 1024;
// Duration of each request is placed into one of two categories - below or above this threshold.
const DURATION_THRESHOLD: Duration = Duration::from_secs(2);
// Ratio of requests with duration < DURATION_THRESHOLD should exceed this parameter.
const MIN_REQUESTS_RATIO_BELOW_THRESHOLD: f64 = 0.9;
// Parameters related to workload creation.
const RESPONSES_COLLECTION_EXTRA_TIMEOUT: Duration = Duration::from_secs(30); // Responses are collected during the workload execution + this extra time, after all requests had been dispatched.
const REQUESTS_DISPATCH_EXTRA_TIMEOUT: Duration = Duration::from_secs(2); // This param can be slightly tweaked (1-2 sec), if the workload fails to dispatch requests precisely on time.

// Send workload to one node for 6h with 1000 rps
pub fn long_duration_test(env: TestEnv) {
    test(env, 1000, Duration::from_secs(6 * 60 * 60), 0.95)
}

// Send workload to one node for 2h with 1000 rps
pub fn large_subnet_test(env: TestEnv) {
    test(env, 1000, Duration::from_secs(2 * 60 * 60), 0.95)
}

pub fn log_max_open_files(log: &Logger) {
    let output = Command::new("sh")
        .arg("-c")
        .arg("ulimit -n")
        .output()
        .unwrap();
    let output = String::from_utf8_lossy(&output.stdout).replace('\n', "");
    info!(&log, "ulimit -n: {}", output);
}

// Run a test with configurable number of query requests per second,
// duration of the test, and the required success ratio.
pub fn test(env: TestEnv, rps: usize, runtime: Duration, min_success_ratio: f64) {
    let log = env.logger();
    log_max_open_files(&log);
    info!(
        &log,
        "Step 1: Checking readiness of all nodes after the IC setup ..."
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
    let dispatch_timeout = REQUESTS_DISPATCH_EXTRA_TIMEOUT + runtime.div_f32(50.0);
    let workload = Workload::new(vec![app_agent], rps, runtime, plan, log.clone())
        .with_responses_collection_extra_timeout(RESPONSES_COLLECTION_EXTRA_TIMEOUT)
        .increase_requests_dispatch_timeout(dispatch_timeout)
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
    let total_requests_count = rps * runtime.as_secs() as usize;
    let success_calls: usize = total_requests_count - metrics.errors().values().sum::<usize>();
    let success_ratio: f64 = (success_calls as f64) / total_requests_count as f64;
    let duration_bucket = metrics
        .find_request_duration_bucket(DURATION_THRESHOLD)
        .unwrap();
    debug!(&log, "Results of the workload execution {:?}", metrics);
    info!(
        &log,
        "Minimum expected success ratio is {}, actual success ratio is {}.",
        min_success_ratio,
        success_ratio
    );
    assert!(
        success_ratio > min_success_ratio,
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
