#[rustfmt::skip]

use anyhow::Result;

use ic_system_test_driver::driver::group::SystemTestGroup;
use ic_system_test_driver::systest;
use ic_tests::ckbtc;

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(ckbtc::lib::config)
        .add_test(systest!(ckbtc::minter::test_heartbeat::test_heartbeat))
        .execute_from_args()?;
    Ok(())
}
