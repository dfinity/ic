#[rustfmt::skip]

use anyhow::Result;

use ic_system_test_driver::driver::group::SystemTestGroup;
use ic_system_test_driver::systest;
use ic_tests::orchestrator::subnet_recovery_app_subnet::{
    setup_same_nodes_tecdsa as setup, test_no_upgrade_with_tecdsa as test,
    CHAIN_KEY_SUBNET_RECOVERY_TIMEOUT,
};

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_timeout_per_test(CHAIN_KEY_SUBNET_RECOVERY_TIMEOUT)
        .with_setup(setup)
        .add_test(systest!(test))
        .execute_from_args()?;
    Ok(())
}
