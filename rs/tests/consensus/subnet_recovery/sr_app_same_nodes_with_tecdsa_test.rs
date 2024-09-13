use anyhow::Result;

use ic_consensus_system_test_subnet_recovery_common::{
    setup_same_nodes_tecdsa as setup, test_with_tecdsa as test, CHAIN_KEY_SUBNET_RECOVERY_TIMEOUT,
};
use ic_system_test_driver::driver::group::SystemTestGroup;
use ic_system_test_driver::systest;

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_timeout_per_test(CHAIN_KEY_SUBNET_RECOVERY_TIMEOUT)
        .with_setup(setup)
        .add_test(systest!(test))
        .execute_from_args()?;
    Ok(())
}
