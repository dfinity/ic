/* tag::catalog[]
Title:: ic-crypto-fstrim_tool test

Goal:: Ensure that running the `fstrim_tool` utility succeeds. A system test is needed, since the
bazel integration tests run in `linux-sandbox`, and running `/sbin/fstrim` there results in a
`discard operation not supported` error.

Runbook::
. Set up a subnet with a single node
. Wait for the node to start up correctly and be healthy
. Attempt to run the `fstrim_tool` utility with the `--target` flag set to the directory
  `/var/lib/ic/crypto` and the `--metrics` flag set to the file `/run/node_exporter/collector_textfile/fstrim.prom`
. Verify that the `fstrim_tool` invocation succeeded, and that the metrics were updated accordingly

Success:: The `fstrim_tool` utility was successfully executed on the `/var/lib/ic/crypto` partition,
and the metrics were successfully written to a file from where the `node_exporter` can read them.

Coverage::
. The discard operation is supported
. The `fstrim` metrics are written`


end::catalog[] */

use crate::driver::ic::InternetComputer;
use crate::driver::test_env::TestEnv;
use crate::driver::test_env_api::{
    GetFirstHealthyNodeSnapshot, HasTopologySnapshot, IcNodeContainer, IcNodeSnapshot, SshSession,
};
use ic_fstrim_tool::FsTrimMetrics;
use ic_registry_subnet_type::SubnetType;
use slog::{info, Logger};
use std::io::{BufRead, BufReader};

const FSTRIM_METRICS_FILE: &str = "/run/node_exporter/collector_textfile/fstrim.prom";

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

    run_fstrim_tool(&node, &logger, " --initialize_metrics_only");

    let initial_metrics = retrieve_fstrim_metrics(&node, &logger);
    info!(logger, "initial fstrim metrics: {:?}", initial_metrics);

    run_fstrim_tool(&node, &logger, "");

    let updated_metrics = retrieve_fstrim_metrics(&node, &logger);
    info!(logger, "updated fstrim metrics: {:?}", updated_metrics);
    assert_successful_run_and_metrics_valid_and_updated(&initial_metrics, &updated_metrics);

    run_fstrim_tool(&node, &logger, "");

    let twice_updated_metrics = retrieve_fstrim_metrics(&node, &logger);
    info!(
        logger,
        "twice updated fstrim metrics: {:?}", twice_updated_metrics
    );
    assert_successful_run_and_metrics_valid_and_updated(&updated_metrics, &twice_updated_metrics);
}

fn retrieve_fstrim_metrics(node: &IcNodeSnapshot, logger: &Logger) -> FsTrimMetrics {
    let cat_fstrim_metrics_cmd = format!("sudo cat {}", FSTRIM_METRICS_FILE);
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

fn run_fstrim_tool(node: &IcNodeSnapshot, logger: &Logger, init_only_flag: &str) {
    let run_fstrim_tool_cmd = format!(
        "sudo /opt/ic/bin/fstrim_tool --target /var/lib/ic/crypto --metrics {}{}",
        FSTRIM_METRICS_FILE, init_only_flag
    );
    info!(
        logger,
        "running fstrim_tool using command: {}", run_fstrim_tool_cmd
    );
    let fstrim_metrics_output = node
        .block_on_bash_script(&run_fstrim_tool_cmd)
        .expect("unable to run fstrim_tool using SSH")
        .trim()
        .to_string();
    assert_eq!(fstrim_metrics_output, "");
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
