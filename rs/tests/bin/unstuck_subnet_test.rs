use anyhow::Result;

use ic_tests::driver::new::group::SystemTestGroup;
use ic_tests::orchestrator;
use ic_tests::systest;

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(orchestrator::unstuck_subnet_test::config)
        .add_test(systest!(orchestrator::unstuck_subnet_test::test))
        .execute_from_args()?;
    Ok(())
}
