#[rustfmt::skip]

use anyhow::Result;

use ic_tests::driver::new::group::SystemTestGroup;
use ic_tests::{rosetta_test, systest};

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(rosetta_test::config)
        .add_test(systest!(rosetta_test::test_everything))
        .execute_from_args()?;

    Ok(())
}
