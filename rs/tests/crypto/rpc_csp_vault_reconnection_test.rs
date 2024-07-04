#[rustfmt::skip]

use anyhow::Result;
use core::time::Duration;
use ic_system_test_driver::driver::group::SystemTestGroup;
use ic_system_test_driver::systest;
use ic_tests::crypto::rpc_csp_vault_reconnection_test::rpc_csp_vault_reconnection_test;
use ic_tests::crypto::rpc_csp_vault_reconnection_test::setup_with_single_node;

const FIFTEEN_MINUTES: Duration = Duration::from_secs(15 * 60);

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(setup_with_single_node)
        .add_test(systest!(rpc_csp_vault_reconnection_test))
        .with_overall_timeout(FIFTEEN_MINUTES)
        .with_timeout_per_test(FIFTEEN_MINUTES)
        .execute_from_args()?;
    Ok(())
}
