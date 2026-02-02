use anyhow::Result;
use ic_system_test_driver::driver::group::SystemTestGroup;
use ic_system_test_driver::systest;
use sns_system_test_lib::sns_aggregator::{
    config_fast, validate_aggregator_data, wait_until_aggregator_finds_sns,
};

/// This is a non-interactive load test:
/// 1. Install NNS, SNS, and the Aggregator canister
/// 2. Wait until the aggregator finds the SNS
/// 3. Initiate the token swap
/// 4. Wait until the aggregator finds swap params, and validate these params
fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(config_fast)
        .add_test(systest!(wait_until_aggregator_finds_sns))
        .add_test(systest!(validate_aggregator_data))
        .execute_from_args()?;
    Ok(())
}
