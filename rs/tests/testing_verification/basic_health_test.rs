#[rustfmt::skip]

use anyhow::Result;

use ic_system_test_driver::driver::group::SystemTestGroup;
use ic_system_test_driver::systest;
use ic_tests::basic_health_test::{config_single_host, test};

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(config_single_host)
        .add_test(systest!(test))
        .execute_from_args()?;

    Ok(())
}
