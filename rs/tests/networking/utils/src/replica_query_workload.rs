/* tag::catalog[]

Title:: Single replica handles query workloads.

Goal:: Ensure IC responds to queries of a given size in a timely manner.

Runbook::
0. Instantiate an IC with one System and one Application subnet.
   - Optionally install one boundary node.
1. Install NNS canisters on the System subnet.
2. Build and install one counter canister on the Application subnet.
3. Instantiate and start a workload against the Application subnet.
   Workload sends query[canister_id, "read"] requests.
   All requests are sent to the same node/replica.
4. Collect metrics from the workload and assert:
   - Ratio of requests with duration below DURATION_THRESHOLD should exceed MIN_REQUESTS_RATIO_BELOW_THRESHOLD.
   - Ratio of successful requests should exceed min_success_ratio threshold.

end::catalog[] */

use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::canister_api::{CallMode, GenericRequest};
use ic_system_test_driver::driver::test_env::TestEnv;
use ic_system_test_driver::driver::test_env_api::{
    HasPublicApiUrl, HasTopologySnapshot, IcNodeContainer,
};
use ic_system_test_driver::util::spawn_round_robin_workload_engine;

use slog::{debug, info, Logger};

use std::process::Command;
use std::time::Duration;

const COUNTER_CANISTER_WAT: &str = "rs/tests/src/counter.wat";
const CANISTER_METHOD: &str = "read";
// Size of the payload sent to the counter canister in query("write") call.
const PAYLOAD_SIZE_BYTES: usize = 1024;
// Duration of each request is placed into one of two categories - below or above this threshold.
const DURATION_THRESHOLD: Duration = Duration::from_secs(2);
// Parameters related to workload creation.
const REQUESTS_DISPATCH_EXTRA_TIMEOUT: Duration = Duration::from_secs(2); // This param can be slightly tweaked (1-2 sec), if the workload fails to dispatch requests precisely on time.

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
pub fn test(env: TestEnv, rps: usize, runtime: Duration) {
    let log = env.logger();
    log_max_open_files(&log);
    info!(
        &log,
        "Checking readiness of all nodes after the IC setup ..."
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
    let handle_workload = {
        let requests = vec![GenericRequest::new(
            app_canister,
            CANISTER_METHOD.to_string(),
            vec![0; PAYLOAD_SIZE_BYTES],
            CallMode::Query,
        )];
        spawn_round_robin_workload_engine(
            log.clone(),
            requests,
            vec![app_agent],
            rps,
            runtime,
            REQUESTS_DISPATCH_EXTRA_TIMEOUT,
            vec![DURATION_THRESHOLD],
        )
    };
    let load_metrics = handle_workload.join().expect("Workload execution failed.");
    info!(
        &log,
        "Step 4: Collect metrics from the workload and perform assertions ..."
    );
    let requests_count_below_threshold =
        load_metrics.requests_count_below_threshold(DURATION_THRESHOLD);
    info!(log, "Workload execution results: {load_metrics}");
    assert_eq!(
        load_metrics.failure_calls(),
        0,
        "Too many requests have failed."
    );
    let min_expected_counter = rps as u64 * runtime.as_secs();
    assert!(requests_count_below_threshold
        .iter()
        .all(|(_, count)| *count == min_expected_counter));
}
