use anyhow::Result;
use ic_system_test_driver::{
    driver::bootstrap::NestedVersionTarget, driver::group::SystemTestGroup, systest,
};
use std::time::Duration;

fn main() -> Result<()> {
    // Start on the current branch version
    let from = NestedVersionTarget::Branch(false);

    SystemTestGroup::new()
        .with_setup(move |e| nested::config(e, &from))
        .add_test(systest!(nested::registration))
        .with_timeout_per_test(Duration::from_secs(20 * 60))
        .with_overall_timeout(Duration::from_secs(30 * 60))
        .execute_from_args()?;

    Ok(())
}
