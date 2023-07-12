use anyhow::Result;
use ic_tests::driver::test_env::TestEnv;
use ic_tests::sns_client::SNS_SALE_PARAM_MIN_PARTICIPANT_ICP_E8S;
use std::time::Duration;

use ic_tests::driver::group::SystemTestGroup;
use ic_tests::nns_tests::sns_deployment::{
    generate_ticket_participants_workload, initiate_token_swap_with_oc_parameters,
    sns_setup_fast_legacy,
};
use ic_tests::systest;

/// Issue just three workflows over 1 second - this allows detecting possible degradations in the workload metrics aggregator logic.
fn multiple_ticket_participants(env: TestEnv) {
    generate_ticket_participants_workload(
        env,
        3,
        Duration::from_secs(1),
        SNS_SALE_PARAM_MIN_PARTICIPANT_ICP_E8S,
    );
}

/// This test is complementary to the //rs/tests/nns/sns:payment_flow_load_test, requiring less resources.
/// Its purpose is to excercise the same API, catching potential regressions in regular CI pipelines (pre-master, hourly, nightly).
///
/// Runbook:
/// 1. Install NNS (with N users, each with X ICP) and SNS
///     * N = NUM_SNS_SALE_PARTICIPANTS
///     * SNS_SALE_PARAM_MIN_PARTICIPANT_ICP_E8S <= X <= SNS_SALE_PARAM_MAX_PARTICIPANT_ICP_E8S
/// 2. Initiate Token Swap
/// 3. Transfer X ICP to the test user's swap sub-account of the SNS swap canister
/// 4. Create a token swap ticket (of X ICP) for the test user
/// 5. Initiate the participation of the test user
/// 6. Assert that the user is actually participating in the swap of X ICP worth of SNS tokens
fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_overall_timeout(Duration::from_secs(15 * 60)) // 15 min
        .with_setup(sns_setup_fast_legacy)
        .add_test(systest!(initiate_token_swap_with_oc_parameters))
        .add_test(systest!(multiple_ticket_participants))
        .execute_from_args()?;
    Ok(())
}
