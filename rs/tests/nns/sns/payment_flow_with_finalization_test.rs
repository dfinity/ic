use std::time::Duration;

use anyhow::Result;
use ic_sns_init::pb::v1::SnsInitPayload;
use ic_tests::driver::test_env_api::NnsCanisterWasmStrategy;
use rust_decimal::prelude::ToPrimitive;

use ic_nervous_system_common::{i2d, E8};
use ic_sns_swap::pb::v1::{params::NeuronBasketConstructionParameters, DerivedState, Params};
use ic_tests::driver::group::SystemTestGroup;
use ic_tests::driver::test_env::TestEnv;
use ic_tests::nns_tests::{
    sns_deployment,
    sns_deployment::{
        finalize_swap_and_check_success, generate_ticket_participants_workload, initiate_token_swap,
    },
};
use ic_tests::sns_client::{
    oc_sns_init_payload, two_days_from_now_in_secs, SNS_SALE_PARAM_MAX_PARTICIPANT_ICP_E8S,
    SNS_SALE_PARAM_MIN_PARTICIPANT_ICP_E8S,
};
use ic_tests::systest;
use ic_tests::util::block_on;

fn sale_params() -> Params {
    Params {
        min_participants: 4,
        min_icp_e8s: SNS_SALE_PARAM_MIN_PARTICIPANT_ICP_E8S,
        max_icp_e8s: SNS_SALE_PARAM_MAX_PARTICIPANT_ICP_E8S,
        min_participant_icp_e8s: SNS_SALE_PARAM_MIN_PARTICIPANT_ICP_E8S,
        max_participant_icp_e8s: SNS_SALE_PARAM_MAX_PARTICIPANT_ICP_E8S,
        swap_due_timestamp_seconds: two_days_from_now_in_secs(),
        sns_token_e8s: 25_000_000 * E8,
        neuron_basket_construction_parameters: Some(NeuronBasketConstructionParameters {
            count: 5,
            dissolve_delay_interval_seconds: 7_889_400,
        }),
        sale_delay_seconds: None,
    }
}

fn init_payload() -> SnsInitPayload {
    oc_sns_init_payload()
}

fn sns_setup_fast(env: TestEnv) {
    sns_deployment::setup(
        env,
        vec![],
        init_payload(),
        NnsCanisterWasmStrategy::TakeBuiltFromSources,
        true,
    );
}

fn initiate_token_swap_with_custom_parameters(env: TestEnv) {
    let params = sale_params();
    // TODO: NNS1-2194: Add community fund investment and verify that it works as intended.
    let community_fund_investment_e8s = 0;
    initiate_token_swap(env, params, community_fund_investment_e8s);
}

/// Creates ticket participants and has them contribute in such a way that they'll hit max_icp_e8s with min_participants.
/// So if min_participants is 3 and max_participant_icp_e8s is 12 icp, we'll create 3 participants who contribute 4 icp each.
fn multiple_ticket_participants(env: TestEnv) {
    let params = sale_params();
    assert_ne!(
        params.min_participants, 0,
        "min_participants must be greater than zero!"
    );
    // We'll have the test use params.min_participants as the number of
    // participants, to allow the sale to have enough participants to close.
    let num_participants = params.min_participants as u64;

    // Calculate a value for `contribution_per_user` that will cause the icp
    // raised by the swap to exactly equal `params.max_participant_icp_e8s`.
    let contribution_per_user = ic_tests::util::divide_perfectly(
        "max_participant_icp_e8s",
        params.max_participant_icp_e8s,
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
    let params = sale_params();
    let init_payload = init_payload();

    let sns_tokens_per_icp = i2d(params.sns_token_e8s)
        .checked_div(i2d(params.max_icp_e8s))
        .and_then(|d| d.to_f32())
        .unwrap();

    let expected_derived_swap_state = DerivedState {
        direct_participant_count: Some(params.min_participants as u64),
        cf_participant_count: Some(0),
        cf_neuron_count: Some(0),
        buyer_total_icp_e8s: params.max_icp_e8s,
        sns_tokens_per_icp,
    };

    block_on(finalize_swap_and_check_success(
        env,
        expected_derived_swap_state,
        params,
        init_payload,
    ));
}

/// This test is similar to //rs/tests/nns/sns:payment_flow_test, except it also finalizes the sale.
/// A load test is currently not possible because finalization is too slow. This will be fixed during
/// one-proposal, so a load test will be added then.
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
/// 7. Finalize the sale
///
/// Some `get_open_ticket failed: SaleClosed` messages are expected.
/// These occur when the test is trying to assert that the user's ticket has been deleted, but the
/// sale has already closed.
fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_overall_timeout(Duration::from_secs(15 * 60)) // 15 min
        .with_setup(sns_setup_fast)
        .add_test(systest!(initiate_token_swap_with_custom_parameters))
        .add_test(systest!(multiple_ticket_participants))
        .add_test(systest!(finalize_swap))
        .execute_from_args()?;
    Ok(())
}
