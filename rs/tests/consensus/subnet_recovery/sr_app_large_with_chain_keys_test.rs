use anyhow::Result;
use std::time::Duration;

use ic_consensus_system_test_subnet_recovery::common::{
    setup_large_chain_keys as setup, test_large_with_chain_keys as test,
};
use ic_system_test_driver::driver::group::SystemTestGroup;
use ic_system_test_driver::systest;

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(setup)
        .with_overall_timeout(Duration::from_secs(55 * 60))
        .with_timeout_per_test(Duration::from_secs(50 * 60))
        .without_assert_no_replica_restarts()
        .add_test(systest!(test))
        // TODO(CON-1644): remove if/when we better handle duplicate artifacts which could occur
        // during upgrades.
        .remove_metrics_to_check("idkg_invalidated_artifacts")
        .execute_from_args()?;
    Ok(())
}
