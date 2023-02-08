use std::time::Duration;

#[rustfmt::skip]

use anyhow::Result;

use ic_tests::driver::new::group::SystemTestGroup;
use ic_tests::nns_tests::sns_deployment::{setup, test};
use ic_tests::systest;

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
