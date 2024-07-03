#[rustfmt::skip]

use anyhow::Result;
use ic_system_test_driver::driver::group::SystemTestGroup;
use ic_system_test_driver::systest;
use ic_tests::crypto::ic_crypto_csp_umask_test::ic_crypto_csp_umask_test;
use ic_tests::crypto::ic_crypto_csp_umask_test::setup_with_single_node_and_short_dkg_interval;

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(setup_with_single_node_and_short_dkg_interval)
        .add_test(systest!(ic_crypto_csp_umask_test))
        .execute_from_args()?;
    Ok(())
}
