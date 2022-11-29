#[rustfmt::skip]

use anyhow::Result;

use ic_tests::consensus::cow_safety_test;
use ic_tests::driver::new::group::SystemTestGroup;
use ic_tests::systest;

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(cow_safety_test::config)
        .add_test(systest!(cow_safety_test::test))
        .execute_from_args()?;
    Ok(())
}
