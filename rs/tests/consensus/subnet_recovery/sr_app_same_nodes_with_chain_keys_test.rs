use anyhow::Result;

use ic_consensus_system_test_subnet_recovery::common::{
    CHAIN_KEY_SUBNET_RECOVERY_TIMEOUT, setup_same_nodes_chain_keys as setup,
    test_with_chain_keys_and_remote_initial_dkg as test,
};
use ic_system_test_driver::driver::group::SystemTestGroup;
use ic_system_test_driver::systest;

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_timeout_per_test(CHAIN_KEY_SUBNET_RECOVERY_TIMEOUT)
        .with_setup(setup)
        .add_test(systest!(test))
        // The replica binary is "broken" and restarted by the orchestrator multiple times
        .remove_metrics_to_check("orchestrator_replica_process_start_attempts_total")
        .execute_from_args()?;
    Ok(())
}
