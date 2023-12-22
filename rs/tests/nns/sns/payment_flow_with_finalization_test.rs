use anyhow::Result;
use ic_nns_governance::pb::v1::CreateServiceNervousSystem;
use ic_tests::driver::group::SystemTestGroup;
use ic_tests::driver::test_env::TestEnv;
use ic_tests::driver::test_env_api::NnsCanisterWasmStrategy;
use ic_tests::nns_tests::neurons_fund;
use ic_tests::nns_tests::neurons_fund::NnsNfNeuron;
use ic_tests::nns_tests::sns_deployment;
use ic_tests::nns_tests::{
    sns_deployment::{generate_ticket_participants_workload, initiate_token_swap},
    swap_finalization::finalize_committed_swap,
};
use ic_tests::sns_client::test_create_service_nervous_system_proposal;
use ic_tests::systest;
use ic_tests::util::block_on;
use std::time::Duration;

fn create_service_nervous_system_proposal() -> CreateServiceNervousSystem {
    // The higher the value for MIN_PARTICIPANTS, the longer the test will take.
    // But lower values are less realistic. In the long term, we should have a
    // load test that uses a high value for MIN_PARTICIPANTS, but 4 is high enough
    // to still discover many potential problems.
    const MIN_PARTICIPANTS: u64 = 4;
    test_create_service_nervous_system_proposal(MIN_PARTICIPANTS)
}

fn nns_nf_neurons() -> Vec<NnsNfNeuron> {
    let cf_contribution = create_service_nervous_system_proposal()
        .swap_parameters
        .unwrap()
        .neurons_fund_investment_icp
        .unwrap()
        .e8s
        .unwrap();

    neurons_fund::initial_nns_neurons(cf_contribution * 100, 1)
}

fn sns_setup_legacy(env: TestEnv) {
    sns_deployment::setup_legacy(
        env,
        vec![],
        nns_nf_neurons(),
        create_service_nervous_system_proposal(),
        NnsCanisterWasmStrategy::TakeBuiltFromSources,
        true,
    );
}

/// Initiate the token swap with the parameters returned by
/// [`create_service_nervous_system_proposal`] (rather than the default
/// parameters)
fn initiate_token_swap_with_custom_parameters(env: TestEnv) {
    initiate_token_swap(env, create_service_nervous_system_proposal());
}

/// Creates ticket participants which will contribute in such a way that they'll hit max_icp_e8s with min_participants.
/// So if min_participants is 3 and max_participant_icp_e8s is 12 icp, we'll create 3 participants who contribute 4 icp each.
fn generate_ticket_participants_workload_necessary_to_close_the_swap(env: TestEnv) {
    let swap_params = create_service_nervous_system_proposal()
        .swap_parameters
        .unwrap();
    assert_ne!(
        swap_params.minimum_participants.unwrap(),
        0,
        "min_participants must be greater than zero!"
    );
    // We'll have the test use params.min_participants as the number of
    // participants, to allow the swap to have enough participants to close.
    let num_participants = swap_params.minimum_participants.unwrap();

    // Calculate a value for `contribution_per_user` that will cause the icp
    // raised by the swap to exactly equal `params.max_icp_e8s - cf_contribution`.
    let cf_contribution = create_service_nervous_system_proposal()
        .swap_parameters
        .unwrap()
        .neurons_fund_investment_icp
        .unwrap()
        .e8s
        .unwrap();

    let contribution_per_user = ic_tests::util::divide_perfectly(
        "max_icp_e8s",
        swap_params.maximum_icp.unwrap().e8s.unwrap() - cf_contribution,
        num_participants,
    )
    .unwrap();

    // The number of participants is the rps * the duration in seconds.
    // So if we set rps to `1`, and the duration to `num_participants`, we'll
    // have `num_participants` participants.
    generate_ticket_participants_workload(
        &env,
        1,
        Duration::from_secs(num_participants),
        contribution_per_user,
    );
}

fn finalize_swap(env: TestEnv) {
    let create_service_nervous_system_proposal = create_service_nervous_system_proposal();
    block_on(finalize_committed_swap(
        &env,
        create_service_nervous_system_proposal,
    ));
}

/// This test is similar to //rs/tests/nns/sns:payment_flow_test, except it also finalizes the swap.
/// A load test is currently not possible because finalization is too slow. This will be fixed during
/// one-proposal, so a load test will be added then.
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
/// 7. Finalize the swap
///
/// Some `get_open_ticket failed: SaleClosed` messages are expected.
/// These occur when the test is trying to assert that the user's ticket has been deleted, but the
/// swap has already closed.
fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_overall_timeout(Duration::from_secs(15 * 60)) // 15 min
        .with_setup(sns_setup_legacy)
        .add_test(systest!(initiate_token_swap_with_custom_parameters))
        .add_test(systest!(
            generate_ticket_participants_workload_necessary_to_close_the_swap
        ))
        .add_test(systest!(finalize_swap))
        .execute_from_args()?;
    Ok(())
}
