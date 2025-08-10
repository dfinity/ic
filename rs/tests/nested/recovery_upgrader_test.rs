use anyhow::Result;
use ic_system_test_driver::{driver::group::SystemTestGroup, systest};
use std::time::Duration;

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(nested::simple_config)
        .add_test(systest!(nested::recovery_upgrader_test))
        .with_timeout_per_test(Duration::from_secs(20 * 60))
        .with_overall_timeout(Duration::from_secs(25 * 60))
        .execute_from_args()?;

    Ok(())
}
