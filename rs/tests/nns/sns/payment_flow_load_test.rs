use anyhow::Result;
use std::time::Duration;

use ic_system_test_driver::driver::group::SystemTestGroup;
use ic_system_test_driver::driver::test_env::TestEnv;
use ic_system_test_driver::sns_client::SNS_SALE_PARAM_MIN_PARTICIPANT_ICP_E8S;
use ic_system_test_driver::systest;
use ic_tests::nns_tests::sns_deployment::{
    generate_ticket_participants_workload, initiate_token_swap_with_oc_parameters,
    sns_setup_with_many_icp_users,
};

fn workload_rps70_many_ticket_participants(env: TestEnv) {
    generate_ticket_participants_workload(
        &env,
        70,
        Duration::from_secs(60),
        SNS_SALE_PARAM_MIN_PARTICIPANT_ICP_E8S,
    );
}

fn workload_rps65_many_ticket_participants(env: TestEnv) {
    generate_ticket_participants_workload(
        &env,
        65,
        Duration::from_secs(60),
        SNS_SALE_PARAM_MIN_PARTICIPANT_ICP_E8S,
    );
}

fn workload_rps60_many_ticket_participants(env: TestEnv) {
    generate_ticket_participants_workload(
        &env,
        60,
        Duration::from_secs(60),
        SNS_SALE_PARAM_MIN_PARTICIPANT_ICP_E8S,
    );
}

fn workload_rps55_many_ticket_participants(env: TestEnv) {
    generate_ticket_participants_workload(
        &env,
        55,
        Duration::from_secs(60),
        SNS_SALE_PARAM_MIN_PARTICIPANT_ICP_E8S,
    );
}

fn workload_rps50_many_ticket_participants(env: TestEnv) {
    generate_ticket_participants_workload(
        &env,
        50,
        Duration::from_secs(60),
        SNS_SALE_PARAM_MIN_PARTICIPANT_ICP_E8S,
    );
}

/// This load test requires manual inspection of the resulting workload metrics.
/// It should not be run regularly as it requires more resources. However, the complementary
/// test //rs/tests/nns/sns:patment_flow_test exercises the same API and is intended to run
/// on regular CI pipelines (pre-master, hourly, nightly).
///
/// Runbook:
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
        .add_test(systest!(initiate_token_swap_with_oc_parameters))
        .add_test(systest!(workload_rps50_many_ticket_participants))
        .add_test(systest!(workload_rps55_many_ticket_participants))
        .add_test(systest!(workload_rps60_many_ticket_participants))
        .add_test(systest!(workload_rps65_many_ticket_participants))
        .add_test(systest!(workload_rps70_many_ticket_participants))
        .execute_from_args()?;
    Ok(())
}
