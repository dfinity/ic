use anyhow::Result;
use std::time::Duration;

use ic_tests::driver::new::group::SystemTestGroup;
use ic_tests::driver::test_env::TestEnv;
use ic_tests::nns_tests::sns_deployment::{
    generate_ticket_participants_workload, initiate_token_swap, sns_setup_with_many_icp_users,
};
use ic_tests::systest;

fn workload_rps100_many_ticket_participants(env: TestEnv) {
    generate_ticket_participants_workload(env, 100, Duration::from_secs(60));
}

fn workload_rps95_many_ticket_participants(env: TestEnv) {
    generate_ticket_participants_workload(env, 95, Duration::from_secs(60));
}

fn workload_rps90_many_ticket_participants(env: TestEnv) {
    generate_ticket_participants_workload(env, 90, Duration::from_secs(60));
}

fn workload_rps85_many_ticket_participants(env: TestEnv) {
    generate_ticket_participants_workload(env, 85, Duration::from_secs(60));
}

fn workload_rps80_many_ticket_participants(env: TestEnv) {
    generate_ticket_participants_workload(env, 80, Duration::from_secs(60));
}

fn workload_rps75_many_ticket_participants(env: TestEnv) {
    generate_ticket_participants_workload(env, 75, Duration::from_secs(60));
}

fn workload_rps70_many_ticket_participants(env: TestEnv) {
    generate_ticket_participants_workload(env, 70, Duration::from_secs(60));
}

fn workload_rps65_many_ticket_participants(env: TestEnv) {
    generate_ticket_participants_workload(env, 65, Duration::from_secs(60));
}

fn workload_rps60_many_ticket_participants(env: TestEnv) {
    generate_ticket_participants_workload(env, 60, Duration::from_secs(60));
}

fn workload_rps55_many_ticket_participants(env: TestEnv) {
    generate_ticket_participants_workload(env, 55, Duration::from_secs(60));
}

fn workload_rps50_many_ticket_participants(env: TestEnv) {
    generate_ticket_participants_workload(env, 50, Duration::from_secs(60));
}

/// This is a non-interactive test:
/// 1. Install NNS (with N users, each with 60 * 2 * X ICP) and SNS
///     * N = NUM_SNS_SALE_PARTICIPANTS
///     * SNS_SALE_PARAM_MIN_PARTICIPANT_ICP_E8S <= X <= SNS_SALE_PARAM_MAX_PARTICIPANT_ICP_E8S
/// 2. Initiate Token Sale
/// 3. For each user:
///     - Transfer X ICP to the user's sale sub-account of the SNS sale canister
///     - Create a token sale ticket (of X ICP)
///     - Initiate the user's participation
///     - Assert that the user is actually participating in the sale of X ICP worth of SNS tokens
fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_overall_timeout(Duration::from_secs(60 * 60)) // 60 min
        .with_timeout_per_test(Duration::from_secs(60 * 60)) // 60 min
        .with_setup(sns_setup_with_many_icp_users)
        .add_test(systest!(initiate_token_swap))
        .add_test(systest!(workload_rps50_many_ticket_participants))
        .add_test(systest!(workload_rps55_many_ticket_participants))
        .add_test(systest!(workload_rps60_many_ticket_participants))
        .add_test(systest!(workload_rps65_many_ticket_participants))
        .add_test(systest!(workload_rps70_many_ticket_participants))
        .add_test(systest!(workload_rps75_many_ticket_participants))
        .add_test(systest!(workload_rps80_many_ticket_participants))
        .add_test(systest!(workload_rps85_many_ticket_participants))
        .add_test(systest!(workload_rps90_many_ticket_participants))
        .add_test(systest!(workload_rps95_many_ticket_participants))
        .add_test(systest!(workload_rps100_many_ticket_participants))
        .execute_from_args()?;
    Ok(())
}
