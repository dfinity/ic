use anyhow::Result;
use ic_tests::driver::test_env::TestEnv;
use std::time::Duration;

use ic_tests::driver::group::SystemTestGroup;
use ic_tests::nns_tests::sns_deployment::{
    generate_ticket_participants_workload, initiate_token_swap, sns_setup_fast,
};
use ic_tests::systest;

/// Issue just three workflows over 1 second - this allows detecting possible degradations in the workload metrics aggregator logic.
fn multiple_ticket_participants(env: TestEnv) {
    generate_ticket_participants_workload(env, 3, Duration::from_secs(1));
}

/// This test is complementary to the //rs/tests/nns/sns:patment_flow_load_test, requiring less resources.
/// Its purpose is to excercise the same API, catching potential regressions in regular CI pipelines (pre-master, hourly, nightly).
///
/// Runbook:
/// 1. Install NNS (with N users, each with X ICP) and SNS
///     * N = NUM_SNS_SALE_PARTICIPANTS
///     * SNS_SALE_PARAM_MIN_PARTICIPANT_ICP_E8S <= X <= SNS_SALE_PARAM_MAX_PARTICIPANT_ICP_E8S
/// 2. Initiate Token Sale
/// 3. Transfer X ICP to the test user's sale sub-account of the SNS sale canister
/// 4. Create a token sale ticket (of X ICP) for the test user
/// 5. Initiate the participation of the test user
/// 6. Assert that the user is actually participating in the sale of X ICP worth of SNS tokens
fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(sns_setup_fast)
        .add_test(systest!(initiate_token_swap))
        .add_test(systest!(multiple_ticket_participants))
        .execute_from_args()?;
    Ok(())
}
