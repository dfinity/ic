#[rustfmt::skip]

use anyhow::Result;

use ic_tests::driver::new::group::SystemTestGroup;
use ic_tests::{ckbtc, systest};

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(ckbtc::lib::config)
        // TODO: par(
        .add_test(systest!(
            ckbtc::minter::test_get_btc_address::test_get_btc_address
        ))
        .add_test(systest!(
            ckbtc::minter::test_get_withdrawal_account::test_get_withdrawal_account
        ))
        // )
        .add_test(systest!(ckbtc::agent::test_ckbtc_minter_agent))
        .execute_from_args()?;

    Ok(())
}
