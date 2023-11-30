use anyhow::Result;
use ic_tests::{driver::group::SystemTestGroup, nested, systest};
use std::time::Duration;

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(nested::config)
        .add_test(systest!(nested::registration))
        .with_timeout_per_test(Duration::from_secs(20 * 60))
        .execute_from_args()?;

    Ok(())
}
