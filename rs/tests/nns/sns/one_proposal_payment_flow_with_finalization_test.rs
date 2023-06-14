use anyhow::Result;
use ic_nervous_system_common::{i2d, E8};
use ic_nervous_system_proto::pb::v1::Tokens;
use ic_nns_common::pb::v1::NeuronId;
use ic_nns_governance::pb::v1::CreateServiceNervousSystem;
use ic_nns_governance::pb::v1::{neuron::DissolveState, Neuron};
use ic_sns_swap::pb::v1::DerivedState;
use ic_tests::driver::group::SystemTestGroup;
use ic_tests::driver::test_env::TestEnv;
use ic_tests::driver::test_env_api::NnsCanisterWasmStrategy;
use ic_tests::nns_tests::{
    sns_deployment,
    sns_deployment::{
        finalize_swap_and_check_success, generate_ticket_participants_workload, initiate_token_swap,
    },
};
use ic_tests::sns_client::{
    openchat_create_service_nervous_system_proposal, SNS_SALE_PARAM_MAX_PARTICIPANT_ICP_E8S,
    SNS_SALE_PARAM_MIN_PARTICIPANT_ICP_E8S,
};
use ic_tests::systest;
use ic_tests::util::{block_on, generate_identity};
use icp_ledger::Subaccount;
use rand::RngCore;
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaChaRng;
use rust_decimal::prelude::ToPrimitive;
use std::time::Duration;

const CF_CONTRIBUTION: u64 = 100 * E8;

fn create_service_nervous_system_proposal() -> CreateServiceNervousSystem {
    // The higher the value for MIN_PARTICIPANTS, the longer the test will take.
    // But lower values are less realistic. In the long term, we should have a
    // load test that uses a high value for MIN_PARTICIPANTS, but 4 is high enough
    // to still discover many potential problems.
    const MIN_PARTICIPANTS: u64 = 4;
    let openchat_parameters = openchat_create_service_nervous_system_proposal();
    CreateServiceNervousSystem {
        swap_parameters: Some(
            ic_nns_governance::pb::v1::create_service_nervous_system::SwapParameters {
                minimum_participants: Some(MIN_PARTICIPANTS),
                minimum_icp: Some(Tokens::from_e8s(SNS_SALE_PARAM_MIN_PARTICIPANT_ICP_E8S)),
                maximum_icp: Some(Tokens::from_e8s(SNS_SALE_PARAM_MAX_PARTICIPANT_ICP_E8S)),
                minimum_participant_icp: Some(Tokens::from_e8s(
                    SNS_SALE_PARAM_MIN_PARTICIPANT_ICP_E8S,
                )),
                maximum_participant_icp: Some(Tokens::from_e8s(
                    SNS_SALE_PARAM_MAX_PARTICIPANT_ICP_E8S,
                )),
                ..openchat_parameters
                    .swap_parameters
                    .as_ref()
                    .unwrap()
                    .clone()
            },
        ),
        ..openchat_parameters
    }
}

/// Deterministically generates a neuron that's joined the community fund (CF).
/// As long as at least one neuron is in the CF, the CF will contribute to the SNS.
fn nns_cf_neuron() -> Neuron {
    const TWELVE_MONTHS_SECONDS: u64 = 12 * 30 * 24 * 60 * 60;

    let (_keypair, _pubkey, principal) = generate_identity(2000);

    let mut rng = ChaChaRng::seed_from_u64(2000_u64);

    let id = Some(NeuronId { id: rng.next_u64() });
    let account = {
        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes);
        Subaccount(bytes)
    };
    Neuron {
        id,
        account: account.into(),
        maturity_e8s_equivalent: CF_CONTRIBUTION,
        cached_neuron_stake_e8s: E8,
        controller: Some(principal),
        dissolve_state: Some(DissolveState::DissolveDelaySeconds(TWELVE_MONTHS_SECONDS)),
        not_for_profit: false,
        // Join the community fund some time in the past.
        // (It's unclear what the semantics should be if the neuron joins in the
        // future.)
        joined_community_fund_timestamp_seconds: Some(1000),
        ..Default::default()
    }
}

fn sns_setup_with_one_proposal(env: TestEnv) {
    sns_deployment::setup(
        env,
        vec![],
        vec![nns_cf_neuron()],
        create_service_nervous_system_proposal(),
        NnsCanisterWasmStrategy::TakeBuiltFromSources,
        true,
    );
}

/// Initiate the token swap with the parameters returned by
/// [`create_service_nervous_system_proposal`] (rather than the default
/// parameters)
fn initiate_token_swap_with_custom_parameters(env: TestEnv) {
    initiate_token_swap(
        env,
        create_service_nervous_system_proposal(),
        CF_CONTRIBUTION,
    );
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
    // raised by the swap to exactly equal `params.max_icp_e8s - CF_CONTRIBUTION`.
    let contribution_per_user = ic_tests::util::divide_perfectly(
        "max_icp_e8s",
        swap_params.maximum_icp.unwrap().e8s.unwrap() - CF_CONTRIBUTION,
        num_participants,
    )
    .unwrap();

    // The number of participants is the rps * the duration in seconds.
    // So if we set rps to `1`, and the duration to `num_participants`, we'll
    // have `num_participants` participants.
    generate_ticket_participants_workload(
        env,
        1,
        Duration::from_secs(num_participants),
        contribution_per_user,
    );
}

fn finalize_swap(env: TestEnv) {
    let create_service_nervous_system_proposal = create_service_nervous_system_proposal();
    let swap_params = create_service_nervous_system_proposal
        .swap_parameters
        .as_ref()
        .unwrap()
        .clone();

    let sns_tokens_per_icp = i2d(create_service_nervous_system_proposal
        .sns_token_e8s()
        .unwrap())
    .checked_div(i2d(swap_params.maximum_icp.unwrap().e8s.unwrap()))
    .and_then(|d| d.to_f32())
    .unwrap();

    let expected_derived_swap_state = DerivedState {
        direct_participant_count: swap_params.minimum_participants,
        cf_participant_count: Some(1),
        cf_neuron_count: Some(1),
        buyer_total_icp_e8s: swap_params.maximum_icp.unwrap().e8s.unwrap(),
        sns_tokens_per_icp,
    };

    block_on(finalize_swap_and_check_success(
        env,
        expected_derived_swap_state,
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
        .with_setup(sns_setup_with_one_proposal)
        .add_test(systest!(initiate_token_swap_with_custom_parameters))
        .add_test(systest!(
            generate_ticket_participants_workload_necessary_to_close_the_swap
        ))
        .add_test(systest!(finalize_swap))
        .execute_from_args()?;
    Ok(())
}
