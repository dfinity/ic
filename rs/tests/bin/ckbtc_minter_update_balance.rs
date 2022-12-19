#[rustfmt::skip]

use anyhow::Result;

use ic_tests::driver::new::group::SystemTestGroup;
use ic_tests::{ckbtc, systest};

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(ckbtc::lib::config)
        .add_test(systest!(
            ckbtc::minter::test_update_balance::test_update_balance
        ))
        .execute_from_args()?;
    Ok(())
}
