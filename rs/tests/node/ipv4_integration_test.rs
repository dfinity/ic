use anyhow::Result;

use ic_tests::{
    driver::group::SystemTestGroup,
    ipv4_tests::ipv4_integration_test::{config, test},
    systest,
};

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(config)
        .add_test(systest!(test))
        .execute_from_args()?;

    Ok(())
}
