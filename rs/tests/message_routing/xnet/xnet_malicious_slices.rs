#[rustfmt::skip]

use anyhow::Result;

use ic_system_test_driver::driver::group::SystemTestGroup;
use ic_system_test_driver::systest;
use ic_tests::message_routing::malicious_slices::Config;
use std::time::Duration;

const PER_TASK_TIMEOUT: Duration = Duration::from_secs(5 * 60);
const OVERALL_TIMEOUT: Duration = Duration::from_secs(10 * 60);

fn main() -> Result<()> {
    let config = Config::new();
    let test = config.clone().test();
    SystemTestGroup::new()
        .with_setup(config.build())
        .add_test(systest!(test))
        .with_timeout_per_test(PER_TASK_TIMEOUT) // each task (including the setup function) may take up to `per_task_timeout`.
        .with_overall_timeout(OVERALL_TIMEOUT) // the entire group may take up to `overall_timeout`.
        .execute_from_args()?;
    Ok(())
}
