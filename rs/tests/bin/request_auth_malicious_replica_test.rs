#[rustfmt::skip]

use anyhow::Result;

use ic_tests::consensus;
use ic_tests::driver::new::group::SystemTestGroup;
use ic_tests::systest;

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(consensus::request_auth_malicious_replica_test::config)
        .add_test(systest!(
            consensus::request_auth_malicious_replica_test::test
        ))
        .execute_from_args()?;

    Ok(())
}
