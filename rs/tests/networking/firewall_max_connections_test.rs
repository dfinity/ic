#[rustfmt::skip]

use anyhow::Result;
use ic_system_test_driver::{driver::group::SystemTestGroup, systest};
use ic_tests::networking::firewall_max_connections::{config, connection_count_test};

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(config)
        .add_test(systest!(connection_count_test))
        .execute_from_args()?;
    Ok(())
}
