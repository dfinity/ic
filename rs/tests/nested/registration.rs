use anyhow::Result;
use ic_system_test_driver::{
    driver::{group::SystemTestGroup, test_env::TestEnv},
    systest,
};
use std::time::Duration;

fn registration_with_failed_units_check(env: TestEnv) {
    nested::registration(env.clone());
    nested::check_no_failed_systemd_units(env);
}

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(nested::setup)
        .with_teardown(nested::teardown)
        .add_test(systest!(registration_with_failed_units_check))
        .with_timeout_per_test(Duration::from_secs(20 * 60))
        .with_overall_timeout(Duration::from_secs(30 * 60))
        .execute_from_args()?;

    Ok(())
}
