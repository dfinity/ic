use anyhow::Result;
use ic_system_test_driver::{
    driver::bootstrap::NestedVersionTarget, driver::group::SystemTestGroup, systest,
};
use std::time::Duration;

fn main() -> Result<()> {
    // Upgrade from the branch version, to the branch '-test` version.
    let from = NestedVersionTarget::Branch(false);
    let to = NestedVersionTarget::Branch(true);

    let todo = move |e| nested::upgrade(e, &to);

    SystemTestGroup::new()
        .with_setup(move |e| nested::config(e, &from))
        .add_test(systest!(todo))
        .with_timeout_per_test(Duration::from_secs(30 * 60))
        .with_overall_timeout(Duration::from_secs(40 * 60))
        .execute_from_args()?;

    Ok(())
}
