#[rustfmt::skip]

use anyhow::Result;

use ic_system_test_driver::driver::group::SystemTestGroup;
use ic_system_test_driver::systest;
use ic_tests::consensus::cow_safety_test;

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(cow_safety_test::config)
        .add_test(systest!(cow_safety_test::test))
        .execute_from_args()?;
    Ok(())
}
