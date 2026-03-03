use anyhow::Result;
use ic_consensus_system_test_subnet_recovery::common::{
    setup_same_nodes as setup, test_no_upgrade_provision_write_access as test,
};
use ic_system_test_driver::driver::group::SystemTestGroup;
use ic_system_test_driver::systest;
use std::time::Duration;

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_overall_timeout(Duration::from_secs(20 * 60))
        .with_timeout_per_test(Duration::from_secs(15 * 60))
        .with_setup(setup)
        .without_assert_no_replica_restarts()
        .add_test(systest!(test))
        .execute_from_args()?;
    Ok(())
}
