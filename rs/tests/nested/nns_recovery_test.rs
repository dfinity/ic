use anyhow::Result;
use ic_consensus_system_test_utils::impersonate_upstreams;
use ic_system_test_driver::{driver::group::SystemTestGroup, systest};
use nested::{DKG_INTERVAL, SUBNET_SIZE};
use std::time::Duration;

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(|env| {
            impersonate_upstreams::setup_upstreams_uvm(&env);
            nested::config(env, SUBNET_SIZE, Some(DKG_INTERVAL))
        })
        .add_test(systest!(nested::nns_recovery_test))
        .with_timeout_per_test(Duration::from_secs(30 * 60))
        .with_overall_timeout(Duration::from_secs(35 * 60))
        .execute_from_args()?;

    Ok(())
}
