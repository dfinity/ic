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
        .with_overall_timeout(Duration::from_secs(30 * 60))
        .with_timeout_per_test(Duration::from_secs(30 * 60))
        .add_test(systest!(test))
        .execute_from_args()?;
    Ok(())
}
