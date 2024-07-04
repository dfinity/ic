#[rustfmt::skip]

use anyhow::Result;

use ic_system_test_driver::driver::group::SystemTestGroup;
use ic_system_test_driver::systest;
use ic_tests::consensus;

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(consensus::request_auth_malicious_replica_test::config)
        .add_test(systest!(
            consensus::request_auth_malicious_replica_test::test
        ))
        .execute_from_args()?;

    Ok(())
}
