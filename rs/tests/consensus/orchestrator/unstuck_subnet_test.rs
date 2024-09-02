use anyhow::Result;

use ic_system_test_driver::driver::group::SystemTestGroup;
use ic_system_test_driver::systest;
use ic_tests::orchestrator;

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(orchestrator::unstuck_subnet_test::config)
        .add_test(systest!(orchestrator::unstuck_subnet_test::test))
        .execute_from_args()?;
    Ok(())
}
