use anyhow::Result;

use ic_consensus_system_test_subnet_recovery::common::{
    CupCorruption, setup_failover_nodes as setup, test_without_chain_keys as test,
};
use ic_system_test_driver::driver::group::SystemTestGroup;
use ic_system_test_driver::systest;

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(setup)
        .add_test(systest!(test; CupCorruption::CorruptedIncludingInvalidNiDkgId))
        .without_assert_no_replica_restarts()
        // The test corrupts the CUPs, so it's expected that the following error metric will be
        // non-zero.
        .remove_metrics_to_check("orchestrator_cup_deserialization_failed_total")
        .execute_from_args()?;
    Ok(())
}
