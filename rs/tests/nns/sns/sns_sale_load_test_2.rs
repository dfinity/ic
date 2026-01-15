use anyhow::Result;
use ic_system_test_driver::driver::group::SystemTestGroup;
use ic_system_test_driver::driver::test_env::TestEnv;
use ic_system_test_driver::systest;
use sns_system_test_lib::sns_deployment::{
    add_one_participant, sns_setup, workload_rps400_get_state_query,
    workload_rps400_get_state_update, workload_rps400_refresh_buyer_tokens,
    workload_rps800_get_state_query, workload_rps800_get_state_update,
    workload_rps800_refresh_buyer_tokens, workload_rps1200_get_state_query,
    workload_rps1200_get_state_update, workload_rps1200_refresh_buyer_tokens,
};
use std::time::Duration;

fn workload_rps400_refresh_buyer_tokens_before(env: TestEnv) {
    workload_rps400_refresh_buyer_tokens(env)
}

fn workload_rps800_refresh_buyer_tokens_before(env: TestEnv) {
    workload_rps800_refresh_buyer_tokens(env)
}

fn workload_rps1200_refresh_buyer_tokens_before(env: TestEnv) {
    workload_rps1200_refresh_buyer_tokens(env)
}

fn workload_rps400_refresh_buyer_tokens_after(env: TestEnv) {
    workload_rps400_refresh_buyer_tokens(env)
}

fn workload_rps800_refresh_buyer_tokens_after(env: TestEnv) {
    workload_rps800_refresh_buyer_tokens(env)
}

fn workload_rps1200_refresh_buyer_tokens_after(env: TestEnv) {
    workload_rps1200_refresh_buyer_tokens(env)
}

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
        .add_test(systest!(workload_rps400_get_state_query))
        .add_test(systest!(workload_rps800_get_state_query))
        .add_test(systest!(workload_rps1200_get_state_query))
        .add_test(systest!(workload_rps400_get_state_update))
        .add_test(systest!(workload_rps800_get_state_update))
        .add_test(systest!(workload_rps1200_get_state_update))
        .add_test(systest!(workload_rps400_refresh_buyer_tokens_before))
        .add_test(systest!(workload_rps800_refresh_buyer_tokens_before))
        .add_test(systest!(workload_rps1200_refresh_buyer_tokens_before))
        .add_test(systest!(add_one_participant))
        .add_test(systest!(workload_rps400_refresh_buyer_tokens_after))
        .add_test(systest!(workload_rps800_refresh_buyer_tokens_after))
        .add_test(systest!(workload_rps1200_refresh_buyer_tokens_after))
        .execute_from_args()?;

    Ok(())
}
