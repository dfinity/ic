use anyhow::Result;

use ic_tests::driver::new::group::SystemTestGroup;
use ic_tests::orchestrator;
use ic_tests::systest;

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(orchestrator::nns_backup::config)
        .add_test(systest!(orchestrator::nns_backup::test))
        .execute_from_args()?;
    Ok(())
}
