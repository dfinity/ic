use anyhow::Result;
use ic_system_test_driver::driver::farm::HostFeature;
use std::time::Duration;

use ic_limits::SMALL_APP_SUBNET_MAX_SIZE;
use ic_networking_subnet_update_workload::{setup, test};
use ic_system_test_driver::driver::group::SystemTestGroup;
use ic_system_test_driver::systest;

// Test parameters
const RPS: usize = 5;
const PAYLOAD_SIZE_BYTES: usize = 100_000;
const USE_API_BOUNDARY_NODE: bool = false;
const WORKLOAD_RUNTIME: Duration = Duration::from_secs(5 * 60);
// Timeout parameters
const TASK_TIMEOUT_DELTA: Duration = Duration::from_secs(10 * 60);
const OVERALL_TIMEOUT_DELTA: Duration = Duration::from_secs(5 * 60);

fn main() -> Result<()> {
    let per_task_timeout: Duration = WORKLOAD_RUNTIME + TASK_TIMEOUT_DELTA; // This should be a bit larger than the workload execution time.
    let overall_timeout: Duration = per_task_timeout + OVERALL_TIMEOUT_DELTA; // This should be a bit larger than the per_task_timeout.
    let test = |env| {
        test(
            env,
            RPS,
            PAYLOAD_SIZE_BYTES,
            WORKLOAD_RUNTIME,
            USE_API_BOUNDARY_NODE,
        )
    };
    SystemTestGroup::new()
        .with_setup(|env| {
            setup(
                env,
                SMALL_APP_SUBNET_MAX_SIZE,
                None,
                vec![HostFeature::Performance],
            )
        })
        .add_test(systest!(test))
        .with_timeout_per_test(per_task_timeout) // each task (including the setup function) may take up to `per_task_timeout`.
        .with_overall_timeout(overall_timeout) // the entire group may take up to `overall_timeout`.
        .execute_from_args()?;
    Ok(())
}
