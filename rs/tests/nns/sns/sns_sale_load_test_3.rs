use anyhow::Result;
use std::time::Duration;

use ic_system_test_driver::driver::group::SystemTestGroup;
use ic_system_test_driver::systest;
use ic_tests::nns_tests::sns_deployment::{
    initiate_token_swap_with_oc_parameters, sns_setup_with_many_sale_participants,
    workload_many_users_rps100_refresh_buyer_tokens,
    workload_many_users_rps200_refresh_buyer_tokens,
    workload_many_users_rps20_refresh_buyer_tokens,
    workload_many_users_rps400_refresh_buyer_tokens,
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
        .with_setup(sns_setup_with_many_sale_participants)
        .add_test(systest!(initiate_token_swap_with_oc_parameters))
        .add_test(systest!(workload_many_users_rps20_refresh_buyer_tokens))
        .add_test(systest!(workload_many_users_rps100_refresh_buyer_tokens))
        .add_test(systest!(workload_many_users_rps200_refresh_buyer_tokens))
        .add_test(systest!(workload_many_users_rps400_refresh_buyer_tokens))
        .execute_from_args()?;

    Ok(())
}
