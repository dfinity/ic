#[rustfmt::skip]

use anyhow::Result;

use ic_tests::{
    driver::group::SystemTestGroup,
    networking::firewall_max_connections::{config, connection_count_test},
    systest,
};

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(config)
        .add_test(systest!(connection_count_test))
        .execute_from_args()?;
    Ok(())
}
