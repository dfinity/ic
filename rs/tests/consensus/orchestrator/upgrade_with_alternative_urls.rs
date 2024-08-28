use anyhow::Result;

use ic_system_test_driver::driver::group::SystemTestGroup;
use ic_system_test_driver::systest;
use ic_tests::orchestrator;

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(orchestrator::upgrade_with_alternative_urls::config)
        .add_test(systest!(orchestrator::upgrade_with_alternative_urls::test))
        .execute_from_args()?;
    Ok(())
}
