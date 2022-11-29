#[rustfmt::skip]

use anyhow::Result;

use ic_tests::consensus::safety_test;
use ic_tests::driver::new::group::SystemTestGroup;
use ic_tests::systest;

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(safety_test::config)
        .add_test(systest!(safety_test::test))
        .execute_from_args()?;
    Ok(())
}
