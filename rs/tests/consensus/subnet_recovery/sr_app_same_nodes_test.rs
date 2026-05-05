use anyhow::Result;

use ic_consensus_system_test_subnet_recovery::common::{
    CupCorruption, setup_same_nodes_huge_dkg_interval as setup, test_without_chain_keys as test,
};
use ic_system_test_driver::driver::group::SystemTestGroup;
use ic_system_test_driver::systest;

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(setup)
        .add_test(systest!(test; CupCorruption::NotCorrupted))
        // The replica binary is "broken" and restarted by the orchestrator multiple times
        .remove_metrics_to_check("orchestrator_replica_process_start_attempts_total")
        .execute_from_args()?;
    Ok(())
}
