use anyhow::Result;

use ic_tests::driver::group::SystemTestGroup;
use ic_tests::systest;
use ic_tests::tecdsa;

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(tecdsa::tschnorr_message_sizes_test::config)
        .add_test(systest!(
            tecdsa::tschnorr_message_sizes_test::test_xnet_limit
        ))
        .add_test(systest!(
            tecdsa::tschnorr_message_sizes_test::test_local_limit
        ))
        .execute_from_args()?;
    Ok(())
}
