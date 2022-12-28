use anyhow::Result;
use std::time::Duration;

use ic_tests::driver::new::group::SystemTestGroup;
use ic_tests::orchestrator::upgrade_downgrade::{config, upgrade_downgrade_app_subnet};
use ic_tests::systest;

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_overall_timeout(Duration::from_secs(15 * 60))
        .with_setup(config)
        .add_test(systest!(upgrade_downgrade_app_subnet))
        .execute_from_args()?;
    Ok(())
}
