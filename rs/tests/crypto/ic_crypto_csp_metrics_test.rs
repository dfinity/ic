#[rustfmt::skip]

use anyhow::Result;
use ic_system_test_driver::driver::group::SystemTestGroup;
use ic_system_test_driver::systest;
use ic_tests::crypto::ic_crypto_csp_metrics_test::ic_crypto_csp_metrics_test;
use ic_tests::crypto::ic_crypto_csp_metrics_test::setup_with_single_node;

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(setup_with_single_node)
        .add_test(systest!(ic_crypto_csp_metrics_test))
        .execute_from_args()?;
    Ok(())
}
