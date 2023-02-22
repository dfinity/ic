use anyhow::Result;
use std::time::Duration;

use ic_tests::driver::new::group::SystemTestGroup;
use ic_tests::nns_tests::sns_deployment::{setup_static_testnet, workload_static_testnet};
use ic_tests::systest;

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_overall_timeout(Duration::from_secs(60 * 60))
        .with_timeout_per_test(Duration::from_secs(60 * 60))
        .with_setup(setup_static_testnet)
        .add_test(systest!(workload_static_testnet))
        .execute_from_args()?;

    Ok(())
}
