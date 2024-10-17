#[rustfmt::skip]

use anyhow::Result;
use ic_networking_system_test_utils::firewall_max_connections::{config, connection_count_test};
use ic_system_test_driver::{driver::group::SystemTestGroup, systest};

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(config)
        .add_test(systest!(connection_count_test))
        .execute_from_args()?;
    Ok(())
}
