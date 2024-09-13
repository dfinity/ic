use std::time::Duration;

#[rustfmt::skip]

use anyhow::Result;

use ic_system_test_driver::driver::group::SystemTestGroup;
use ic_system_test_driver::systest;
use ic_tests::orchestrator::subnet_recovery_app_subnet::{
    setup_large_tecdsa as setup, test_large_with_tecdsa as test,
};

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(setup)
        .with_overall_timeout(Duration::from_secs(30 * 60))
        .with_timeout_per_test(Duration::from_secs(30 * 60))
        .add_test(systest!(test))
        .execute_from_args()?;
    Ok(())
}
