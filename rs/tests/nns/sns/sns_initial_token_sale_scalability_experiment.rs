use std::time::Duration;

#[rustfmt::skip]

use anyhow::Result;

use ic_system_test_driver::driver::group::SystemTestGroup;
use ic_system_test_driver::systest;
use ic_tests::nns_tests::sns_deployment::{setup, test};

fn main() -> Result<()> {
    let max_group_lifetime = Duration::from_secs(55 * 60);
    let experiment_duration = Duration::from_secs(50 * 60);
    SystemTestGroup::new()
        .with_overall_timeout(max_group_lifetime)
        .with_timeout_per_test(experiment_duration)
        .with_setup(setup)
        .add_task_with_minimal_lifetime(systest!(test), experiment_duration)
        .execute_from_args()?;

    Ok(())
}
