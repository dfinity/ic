use anyhow::Result;
use ic_tests::driver::new::group::SystemTestGroup;
use ic_tests::nns_tests::sns_aggregator::{config_fast, install_aggregator_with_checks};
use ic_tests::systest;

/// This is a non-interactive load test:
/// 1. Install NNS and SNS
/// 2. Install the aggregator canister
/// 3. Check that the aggregator finds the SNS
fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(config_fast)
        .add_test(systest!(install_aggregator_with_checks))
        .execute_from_args()?;
    Ok(())
}
