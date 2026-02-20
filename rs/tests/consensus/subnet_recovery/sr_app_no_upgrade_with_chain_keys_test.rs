use anyhow::Result;

use ic_consensus_system_test_subnet_recovery::common::{
    CHAIN_KEY_SUBNET_RECOVERY_TIMEOUT, setup_same_nodes_chain_keys as setup,
    test_no_upgrade_with_chain_keys as test,
};
use ic_system_test_driver::driver::group::SystemTestGroup;
use ic_system_test_driver::systest;

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_timeout_per_test(CHAIN_KEY_SUBNET_RECOVERY_TIMEOUT)
        .with_setup(setup)
        .without_assert_no_replica_restarts()
        .add_test(systest!(test))
        // The test corrupts the CUPs, so it's expected that the following error metric will be
        // non-zero.
        .remove_metrics_to_check("orchestrator_cup_deserialization_failed_total")
        .execute_from_args()?;
    Ok(())
}
