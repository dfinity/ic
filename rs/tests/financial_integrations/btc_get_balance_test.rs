#[rustfmt::skip]

use anyhow::Result;

use ic_system_test_driver::driver::group::SystemTestGroup;
use ic_system_test_driver::systest;
use ic_tests::btc_integration;

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(btc_integration::btc::config)
        .add_test(systest!(btc_integration::btc::get_balance))
        .execute_from_args()?;

    Ok(())
}
