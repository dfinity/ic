#[rustfmt::skip]

use anyhow::Result;
use ic_tests::crypto::ic_crypto_csp_socket_test::ic_crypto_csp_socket_test;
use ic_tests::crypto::ic_crypto_csp_socket_test::setup_with_single_node;
use ic_tests::driver::group::SystemTestGroup;
use ic_tests::systest;

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(setup_with_single_node)
        .add_test(systest!(ic_crypto_csp_socket_test))
        .execute_from_args()?;
    Ok(())
}
