#[rustfmt::skip]

use anyhow::Result;
use ic_tests::crypto::rpc_csp_vault_reconnection_test::rpc_csp_vault_reconnection_test;
use ic_tests::crypto::rpc_csp_vault_reconnection_test::setup_with_single_node;
use ic_tests::driver::group::SystemTestGroup;
use ic_tests::systest;

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(setup_with_single_node)
        .add_test(systest!(rpc_csp_vault_reconnection_test))
        .execute_from_args()?;
    Ok(())
}
