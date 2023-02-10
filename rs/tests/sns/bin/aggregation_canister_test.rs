use anyhow::Result;
use ic_tests::driver::new::group::SystemTestGroup;
use ic_tests::nns_tests::sns_aggregator::{
    config_fast, validate_aggregator_data, wait_until_aggregator_finds_sns,
};
use ic_tests::nns_tests::sns_deployment::initiate_token_swap;
use ic_tests::systest;

/// This is a non-interactive load test:
/// 1. Install NNS, SNS, and the Aggregator canister
/// 2. Wait until the aggregator finds the SNS
/// 3. Initiate the token sale
/// 4. Wait until the aggregator finds sale params, and validate these params
fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(config_fast)
        .add_test(systest!(wait_until_aggregator_finds_sns))
        .add_test(systest!(initiate_token_swap))
        .add_test(systest!(validate_aggregator_data))
        .execute_from_args()?;
    Ok(())
}
