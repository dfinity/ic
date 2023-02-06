use anyhow::Result;

use ic_tests::driver::new::group::SystemTestGroup;
use ic_tests::orchestrator;
use ic_tests::systest;

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(orchestrator::upgrade_with_alternative_urls::config)
        .add_test(systest!(orchestrator::upgrade_with_alternative_urls::test))
        .execute_from_args()?;
    Ok(())
}
