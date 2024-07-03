use anyhow::Result;
use ic_nns_governance::pb::v1::create_service_nervous_system::SwapParameters;
use ic_nns_governance::pb::v1::CreateServiceNervousSystem;
use ic_system_test_driver::driver::group::SystemTestGroup;
use ic_system_test_driver::driver::test_env::TestEnv;
use ic_system_test_driver::driver::test_env_api::NnsCanisterWasmStrategy;
use ic_system_test_driver::sns_client::test_create_service_nervous_system_proposal;
use ic_system_test_driver::systest;
use ic_system_test_driver::util::block_on;
use ic_tests::nns_tests::neurons_fund;
use ic_tests::nns_tests::neurons_fund::NnsNfNeuron;
use ic_tests::nns_tests::{
    sns_deployment, sns_deployment::generate_ticket_participants_workload, swap_finalization,
    swap_finalization::finalize_committed_swap,
};
use std::time::Duration;

// At the time of this writing, the empirically-determined maximum is that 2,084
// neurons' fund neurons can be sent in the init payload to the Swap canister,
// along with its other init field and gzipped wasm. If this limit is exceeded,
// SNS deployment will fail, with an error along the lines of:
// ```
// Failed to install WASM on canister 53zcu-tiaaa-aaaaa-qaaba-cai: error code 5: Canister qaa6y-5yaaa-aaaaa-aaafa-cai violated contract: attempted to send a message of size 2097171 exceeding the limit 2097152
// ```
// This test guarantees that no code change reduce the maximum to below 1,500.
// If there are above 1,000 NF neurons in production, that means we are in the
// "danger zone" and should modify the SNS to be robust to many more NF neurons.
const NEURONS_FUND_NUM_PARTICIPANTS: u64 = 1500;

fn create_service_nervous_system_proposal() -> CreateServiceNervousSystem {
    const MIN_PARTICIPANTS: u64 = 4;
    let csns = test_create_service_nervous_system_proposal(MIN_PARTICIPANTS);
    let swap_parameters = csns.swap_parameters.clone().unwrap();
    CreateServiceNervousSystem {
        swap_parameters: Some(SwapParameters {
            neurons_fund_participation: Some(true),
            ..swap_parameters
        }),
        ..csns
    }
}

fn nns_nf_neurons() -> Vec<NnsNfNeuron> {
    let max_nf_contribution = create_service_nervous_system_proposal()
        .swap_parameters
        .unwrap()
        .maximum_direct_participation_icp
        .unwrap()
        .e8s
        .unwrap()
        * 2;

    neurons_fund::initial_nns_neurons(max_nf_contribution * 10, NEURONS_FUND_NUM_PARTICIPANTS)
}

fn sns_setup_with_one_proposal(env: TestEnv) {
    sns_deployment::setup(
        &env,
        vec![],
        nns_nf_neurons(),
        create_service_nervous_system_proposal(),
        NnsCanisterWasmStrategy::TakeBuiltFromSources,
        true,
    );
}

fn wait_for_swap_to_start(env: TestEnv) {
    block_on(swap_finalization::wait_for_swap_to_start(&env));
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
    let contribution_per_user = ic_system_test_driver::util::divide_perfectly(
        "maximum_direct_participation_icp",
        swap_params
            .maximum_direct_participation_icp
            .expect("maximum_direct_participation_icp must be set")
            .e8s
            .expect("maximum_direct_participation_icp:e8s must be set"),
        num_participants,
    )
    .expect("unable to compute contribution_per_user");

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

/// This test is similar to //rs/tests/nns/sns:payment_flow_with_finalization_test,
/// but includes neurons' fund participation.
/// A load test is currently not possible because finalization is too slow. This will be fixed during
/// one-proposal, so a load test will be added then.
///
/// Runbook:
/// 1. Install NNS (with N users, each with X ICP, and NEURONS_FUND_NUM_PARTICIPANTS NF neurons) and SNS
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
        .with_overall_timeout(Duration::from_secs(150 * 60)) // 15 min
        .with_timeout_per_test(Duration::from_secs(600 * 60)) // 5 min
        .with_setup(sns_setup_with_one_proposal)
        .add_test(systest!(wait_for_swap_to_start))
        .add_test(systest!(
            generate_ticket_participants_workload_necessary_to_close_the_swap
        ))
        .add_test(systest!(finalize_swap))
        .execute_from_args()?;
    Ok(())
}
