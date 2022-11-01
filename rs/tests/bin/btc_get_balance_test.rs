#[rustfmt::skip]

use anyhow::Result;

use ic_tests::driver::new::group::SystemTestGroup;
use ic_tests::{btc_integration, systest};

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(btc_integration::btc::config)
        .add_test(systest!(btc_integration::btc::get_balance))
        .execute_from_args()?;

    Ok(())
}
