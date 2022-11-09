#[rustfmt::skip]

use anyhow::Result;

use ic_tests::driver::new::group::SystemTestGroup;
use ic_tests::{icrc1_agent_test, systest};

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(icrc1_agent_test::config)
        .add_test(systest!(icrc1_agent_test::test))
        .execute_from_args()?;
    Ok(())
}
