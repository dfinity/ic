mod icrc1_agent_tests;

use anyhow::Result;

use ic_system_test_driver::driver::group::SystemTestGroup;
use ic_system_test_driver::systest;

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(icrc1_agent_tests::config)
        .add_test(systest!(icrc1_agent_tests::test))
        .execute_from_args()?;
    Ok(())
}
