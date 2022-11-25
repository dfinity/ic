#[rustfmt::skip]

use anyhow::Result;
use ic_tests::consensus::liveness_with_equivocation_test;
use ic_tests::driver::new::group::SystemTestGroup;
use ic_tests::systest;

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(liveness_with_equivocation_test::config)
        .add_test(systest!(liveness_with_equivocation_test::test))
        .execute_from_args()?;
    Ok(())
}
