use anyhow::Result;
use ic_system_test_driver::{driver::group::SystemTestGroup, systest};
use std::time::Duration;

fn main() -> Result<()> {
    // Start with the current branch version.
    SystemTestGroup::new()
        .with_setup(|e| nested::config(e, false))
        .add_test(systest!(nested::registration))
        .with_timeout_per_test(Duration::from_secs(20 * 60))
        .with_overall_timeout(Duration::from_secs(30 * 60))
        .execute_from_args()?;

    Ok(())
}
