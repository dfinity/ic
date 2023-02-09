use anyhow::Result;

use ic_tests::driver::new::group::SystemTestGroup;
use ic_tests::orchestrator;
use ic_tests::systest;

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(orchestrator::unassigned_node_upgrade_test::config)
        .add_test(systest!(orchestrator::unassigned_node_upgrade_test::test))
        .execute_from_args()?;
    Ok(())
}
