#[rustfmt::skip]

use anyhow::Result;
use std::time::Duration;

use ic_system_test_driver::driver::group::SystemTestGroup;
use ic_system_test_driver::systest;
use ic_tests::nns_tests::sns_deployment::{
    add_one_participant, initiate_token_swap_with_oc_parameters, sns_setup,
    workload_rps1200_get_state_query, workload_rps1200_refresh_buyer_tokens,
    workload_rps400_get_state_query, workload_rps400_refresh_buyer_tokens,
    workload_rps800_get_state_query, workload_rps800_refresh_buyer_tokens,
};

/// This is a non-interactive load test:
/// 1. Install NNS and SNS
/// 2. Start the token sale
/// 3. For each `request` in [`get_state_query`, `refresh_buyer_tokens`]
///   - For each `rps` in [400, 800, 1200]
///     - Send `request` to the SnsSale canister at `rps` requests per second for 60s
/// 4. TODO: assert success (currently, one needs to read the report in the logs)
fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_overall_timeout(Duration::from_secs(30 * 60)) // 30 min
        .with_setup(sns_setup)
        .add_test(systest!(initiate_token_swap_with_oc_parameters))
        .add_test(systest!(workload_rps400_get_state_query))
        .add_test(systest!(workload_rps800_get_state_query))
        .add_test(systest!(workload_rps1200_get_state_query))
        .add_test(systest!(add_one_participant))
        .add_test(systest!(workload_rps400_refresh_buyer_tokens))
        .add_test(systest!(workload_rps800_refresh_buyer_tokens))
        .add_test(systest!(workload_rps1200_refresh_buyer_tokens))
        .execute_from_args()?;

    Ok(())
}
