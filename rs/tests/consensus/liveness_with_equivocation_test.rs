#[rustfmt::skip]

use anyhow::Result;
use ic_system_test_driver::driver::group::SystemTestGroup;
use ic_system_test_driver::systest;
use ic_tests::consensus::liveness_with_equivocation_test;

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(liveness_with_equivocation_test::config)
        .add_test(systest!(liveness_with_equivocation_test::test))
        .execute_from_args()?;
    Ok(())
}
