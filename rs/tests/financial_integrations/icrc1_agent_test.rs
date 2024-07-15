#[rustfmt::skip]

use anyhow::Result;

use ic_system_test_driver::driver::group::SystemTestGroup;
use ic_system_test_driver::systest;
use ic_tests::icrc1_agent_test;

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(icrc1_agent_test::config)
        .add_test(systest!(icrc1_agent_test::test))
        .execute_from_args()?;
    Ok(())
}
