use anyhow::Result;

use ic_tests::driver::group::SystemTestGroup;
use ic_tests::systest;
use ic_tests::tecdsa;

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(tecdsa::tecdsa_two_signing_subnets_test::config)
        .add_test(systest!(tecdsa::tecdsa_two_signing_subnets_test::test))
        .execute_from_args()?;
    Ok(())
}
