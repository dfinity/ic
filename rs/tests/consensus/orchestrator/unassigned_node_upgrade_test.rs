use anyhow::Result;

use ic_system_test_driver::driver::group::SystemTestGroup;
use ic_system_test_driver::systest;
use ic_tests::orchestrator;

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(orchestrator::unassigned_node_upgrade_test::config)
        .add_test(systest!(orchestrator::unassigned_node_upgrade_test::test))
        .execute_from_args()?;
    Ok(())
}
