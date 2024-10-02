#[rustfmt::skip]

use anyhow::Result;
use std::time::Duration;

use ic_limits::SMALL_APP_SUBNET_MAX_SIZE;
use ic_system_test_driver::driver::group::SystemTestGroup;
use ic_system_test_driver::driver::ic::ImageSizeGiB;
use ic_system_test_driver::systest;
use ic_tests::networking::replica_query_workload::test;
use ic_tests::networking::subnet_update_workload::config;

// Test parameters
// This value should more or less equal to
// config.query_execution_threads * (1 sec / <avg latency in secs for executing a single query to the counter canister>)
// The avg. latency in seconds for a query to the counter canister is 1 ms, according to latest data from execution.
const RPS: usize = 100;
const USE_BOUNDARY_NODE: bool = false;
const WORKLOAD_RUNTIME: Duration = Duration::from_secs(5 * 60);
// Timeout parameters
const TASK_TIMEOUT_DELTA: Duration = Duration::from_secs(10 * 60);
const OVERALL_TIMEOUT_DELTA: Duration = Duration::from_secs(5 * 60);

fn main() -> Result<()> {
    let per_task_timeout: Duration = WORKLOAD_RUNTIME + TASK_TIMEOUT_DELTA; // This should be a bit larger than the workload execution time.
    let overall_timeout: Duration = per_task_timeout + OVERALL_TIMEOUT_DELTA; // This should be a bit larger than the per_task_timeout.
    let config = |env| {
        config(
            env,
            SMALL_APP_SUBNET_MAX_SIZE,
            USE_BOUNDARY_NODE,
            // Since this is a long-running test, it accumulates a lot of disk space.
            // This is why we increase the default of 50 GiB to 500 GiB.
            Some(ImageSizeGiB::new(500)),
        )
    };
    let test = |env| test(env, RPS, WORKLOAD_RUNTIME);
    SystemTestGroup::new()
        .with_setup(config)
        .add_test(systest!(test))
        .with_timeout_per_test(per_task_timeout) // each task (including the setup function) may take up to `per_task_timeout`.
        .with_overall_timeout(overall_timeout) // the entire group may take up to `overall_timeout`.
        .execute_from_args()?;
    Ok(())
}
