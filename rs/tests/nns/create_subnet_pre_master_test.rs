#[rustfmt::skip]

use anyhow::Result;

use ic_system_test_driver::driver::group::SystemTestGroup;
use ic_system_test_driver::systest;
use ic_tests::nns_tests::create_subnet;

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(create_subnet::pre_master_config)
        .add_test(systest!(create_subnet::test))
        .execute_from_args()?;
    Ok(())
}
