#[rustfmt::skip]

use anyhow::Result;

use ic_tests::driver::new::group::SystemTestGroup;
use ic_tests::message_routing::rejoin_test;
use ic_tests::systest;

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(rejoin_test::config)
        .add_test(systest!(rejoin_test::test))
        .execute_from_args()?;
    Ok(())
}
