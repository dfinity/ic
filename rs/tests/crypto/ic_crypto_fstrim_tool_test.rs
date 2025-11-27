/* tag::catalog[]
Title:: ic-crypto-fstrim_tool test

Goal:: Ensure that running the `fstrim_tool` utility succeeds. A system test is needed, since the
bazel integration tests run in `linux-sandbox`, and running `/sbin/fstrim` there results in a
`discard operation not supported` error.

Runbook::
. Set up a subnet with a single node
. Wait for the node to start up correctly and be healthy.
. Verify that the `fstrim.prom` file exists and contains the initial metrics.
. Attempt to run the systemd service `setup-fstrim-metrics` to initialize the metrics to be served
  by the `node_exporter`.
. Verify that the `setup-fstrim-metrics` service invocation succeeded, and that the metrics are
  still in the initialized state.
. Attempt to run the systemd service `fstrim_tool` to run `fstrim` and update the metrics.
. Verify that the `fstrim_tool` service invocation succeeded and that the metrics were updated
  successfully.
. Perform another invocation of the `fstrim_tool` service and verify that the second update of the
  metrics was also successful.

Success:: The `fstrim_tool` utility was successfully executed on the `/var/lib/ic/crypto` partition,
and the metrics were successfully written to a file from where the `node_exporter` can read them.

Coverage::
. The discard operation is supported
. The `fstrim_tool` service can successfully execute `fstrim` and write the metrics to a file.


end::catalog[] */

use anyhow::Result;
use ic_fstrim_tool::FsTrimMetrics;
use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::driver::group::SystemTestGroup;
use ic_system_test_driver::driver::ic::InternetComputer;
use ic_system_test_driver::driver::test_env::TestEnv;
use ic_system_test_driver::driver::test_env_api::{
    GetFirstHealthyNodeSnapshot, HasTopologySnapshot, IcNodeContainer, IcNodeSnapshot, SshSession,
};
use ic_system_test_driver::systest;
use slog::{Logger, info};
use std::io::{BufRead, BufReader};
use std::time::Duration;

const FSTRIM_METRICS_FILE: &str = "/run/node_exporter/collector_textfile/fstrim.prom";

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(setup_with_single_node)
        .add_test(systest!(ic_crypto_fstrim_tool_test))
        .execute_from_args()?;
    Ok(())
}

pub fn setup_with_single_node(env: TestEnv) {
    InternetComputer::new()
        .add_fast_single_node_subnet(SubnetType::System)
        .setup_and_start(&env)
        .expect("failed to setup IC under test");

    env.topology_snapshot()
        .subnets()
        .for_each(|subnet| subnet.await_all_nodes_healthy().unwrap());
}

pub fn ic_crypto_fstrim_tool_test(env: TestEnv) {
    let logger = env.logger();
    let node = env.get_first_healthy_node_snapshot();

    wait_for_initial_metrics_existence(&node, &logger);

    let initial_metrics = retrieve_fstrim_metrics(&node, &logger);
    info!(logger, "initial fstrim metrics: {:?}", initial_metrics);
    assert_metrics_are_initialized(&initial_metrics);

    initialize_fstrim_tool_metrics(&node, &logger);
    let reinitialized_metrics = retrieve_fstrim_metrics(&node, &logger);
    assert_metrics_are_initialized(&reinitialized_metrics);

    run_fstrim_tool(&node, &logger);

    let updated_metrics = retrieve_fstrim_metrics(&node, &logger);
    info!(logger, "updated fstrim metrics: {:?}", updated_metrics);
    assert_successful_run_and_metrics_valid_and_updated(&reinitialized_metrics, &updated_metrics);

    run_fstrim_tool(&node, &logger);

    let twice_updated_metrics = retrieve_fstrim_metrics(&node, &logger);
    info!(
        logger,
        "twice updated fstrim metrics: {:?}", twice_updated_metrics
    );
    assert_successful_run_and_metrics_valid_and_updated(&updated_metrics, &twice_updated_metrics);
}

fn wait_for_initial_metrics_existence(node: &IcNodeSnapshot, logger: &Logger) {
    ic_system_test_driver::retry_with_msg!(
        "check if initial metrics exist",
        logger.clone(),
        Duration::from_secs(500),
        Duration::from_secs(5),
        || node.block_on_bash_script(format!("[ -f {FSTRIM_METRICS_FILE} ]").as_str())
    )
    .unwrap_or_else(|e| panic!("Node didn't initialize fstrim metrics in time because {e:?}"));
}

fn retrieve_fstrim_metrics(node: &IcNodeSnapshot, logger: &Logger) -> FsTrimMetrics {
    let cat_fstrim_metrics_cmd = format!("sudo cat {FSTRIM_METRICS_FILE}");
    info!(
        logger,
        "retrieving fstrim metrics using command: {}", cat_fstrim_metrics_cmd
    );
    let metrics_string = node
        .block_on_bash_script(&cat_fstrim_metrics_cmd)
        .expect("unable to get fstrim metrics using SSH")
        .trim()
        .to_string();
    FsTrimMetrics::try_from(BufReader::new(metrics_string.as_bytes()).lines())
        .expect("unable to parse fstrim metrics")
}

fn initialize_fstrim_tool_metrics(node: &IcNodeSnapshot, logger: &Logger) {
    const INITIALIZE_FSTRIM_TOOL_METRICS_CMD: &str =
        "sudo systemctl start setup-fstrim-metrics.service";
    info!(
        logger,
        "initializing fstrim_tool metrics using command: {}", INITIALIZE_FSTRIM_TOOL_METRICS_CMD
    );
    let fstrim_metrics_output = node
        .block_on_bash_script(INITIALIZE_FSTRIM_TOOL_METRICS_CMD)
        .expect("unable to initialize fstrim_tool metrics using SSH")
        .trim()
        .to_string();
    assert_eq!(fstrim_metrics_output, "");
}

fn run_fstrim_tool(node: &IcNodeSnapshot, logger: &Logger) {
    const RUN_FSTRIM_TOOL_CMD: &str = "sudo systemctl start fstrim_tool.service";
    info!(
        logger,
        "running fstrim_tool using command: {}", RUN_FSTRIM_TOOL_CMD
    );
    let fstrim_metrics_output = node
        .block_on_bash_script(RUN_FSTRIM_TOOL_CMD)
        .expect("unable to run fstrim_tool using SSH")
        .trim()
        .to_string();
    assert_eq!(fstrim_metrics_output, "");
}

fn assert_metrics_are_initialized(metrics: &FsTrimMetrics) {
    assert_eq!(metrics.total_runs, 0f64);
    assert!(metrics.last_run_success);
    assert_eq!(metrics.last_duration_milliseconds, 0f64);
}

fn assert_successful_run_and_metrics_valid_and_updated(
    initial_metrics: &FsTrimMetrics,
    updated_metrics: &FsTrimMetrics,
) {
    assert!(initial_metrics.last_run_success);
    assert!(updated_metrics.last_run_success);
    assert_eq!(
        updated_metrics.total_runs,
        initial_metrics.total_runs + 1f64
    );
}
