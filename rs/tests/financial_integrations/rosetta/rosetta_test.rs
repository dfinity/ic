#[rustfmt::skip]

use anyhow::Result;

use ic_system_test_driver::driver::group::SystemTestGroup;
use ic_system_test_driver::systest;
use ic_tests::rosetta_test;

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(rosetta_test::config)
        .add_test(systest!(rosetta_test::test_everything))
        .execute_from_args()?;

    Ok(())
}
