#[rustfmt::skip]

use anyhow::Result;

use ic_system_test_driver::driver::group::SystemTestGroup;
use ic_system_test_driver::systest;
use ic_tests::message_routing::memory_safety_test;

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(memory_safety_test::config)
        .add_test(systest!(memory_safety_test::test))
        .execute_from_args()?;
    Ok(())
}
