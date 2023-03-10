use anyhow::Result;
use ic_tests::driver::test_env::TestEnv;
use std::time::Duration;

use ic_tests::driver::new::group::SystemTestGroup;
use ic_tests::nns_tests::sns_deployment::{
    generate_ticket_participants_workload, initiate_token_swap, sns_setup_with_many_icp_users,
};
use ic_tests::systest;

fn workload_rps100_many_ticket_participants(env: TestEnv) {
    generate_ticket_participants_workload(env, 100, Duration::from_secs(60));
}

/// This is a non-interactive test:
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
        .with_overall_timeout(Duration::from_secs(30 * 60)) // 30 min
        .with_setup(sns_setup_with_many_icp_users)
        .add_test(systest!(initiate_token_swap))
        .add_test(systest!(workload_rps100_many_ticket_participants))
        .execute_from_args()?;
    Ok(())
}
