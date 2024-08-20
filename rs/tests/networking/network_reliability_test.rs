use std::time::Duration;

#[rustfmt::skip]

use anyhow::Result;

use ic_system_test_driver::driver::group::SystemTestGroup;
use ic_system_test_driver::systest;
use ic_tests::networking::network_reliability::{setup, test, Config};

// Test parameters
const CONFIG: Config = Config {
    nodes_system_subnet: 4,
    nodes_app_subnet: 7,
    runtime: Duration::from_secs(180),
    rps: 20,
};
// Timeout parameters
const TASK_TIMEOUT: Duration = Duration::from_secs(320 * 60);
const OVERALL_TIMEOUT: Duration = Duration::from_secs(350 * 60);

fn main() -> Result<()> {
    let setup = |env| setup(env, CONFIG);
    let test = |env| test(env, CONFIG);
    SystemTestGroup::new()
        .with_setup(setup)
        .add_test(systest!(test))
        .with_timeout_per_test(TASK_TIMEOUT) // each task (including the setup function) may take up to `per_task_timeout`.
        .with_overall_timeout(OVERALL_TIMEOUT) // the entire group may take up to `overall_timeout`.
        .execute_from_args()?;
    Ok(())
}
