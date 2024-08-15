use candid::Encode;
use canister_test::Wasm;
use ic_base_types::CanisterId;
use ic_nervous_system_common_test_keys::{TEST_NEURON_1_ID, TEST_NEURON_1_OWNER_PRINCIPAL};
use ic_nns_common::{
    pb::v1::NeuronId,
    types::{UpdateIcpXdrConversionRatePayload, UpdateIcpXdrConversionRatePayloadReason},
};
use ic_nns_constants::{EXCHANGE_RATE_CANISTER_ID, EXCHANGE_RATE_CANISTER_INDEX};
use ic_nns_governance_api::pb::v1::{
    manage_neuron_response, ExecuteNnsFunction, MakeProposalRequest, NnsFunction,
    ProposalActionRequest,
};
use ic_nns_test_utils::{
    common::NnsInitPayloadsBuilder,
    state_test_helpers::{
        create_canister_at_specified_id, get_icp_xdr_conversion_rate, nns_governance_make_proposal,
        nns_wait_for_proposal_execution, setup_nns_canisters, state_machine_builder_for_nns_tests,
    },
};
use ic_state_machine_tests::StateMachine;
use ic_types::time::GENESIS;
use ic_xrc_types::{Asset, AssetClass, ExchangeRateError, ExchangeRateMetadata};
use std::time::Duration;
use xrc_mock::{ExchangeRate, Response, XrcMockInitPayload};

const ONE_MINUTE_SECONDS: u64 = 60;
const FIVE_MINUTES_SECONDS: u64 = 5 * ONE_MINUTE_SECONDS;

/// Sets up the XRC mock canister.
fn setup_mock_exchange_rate_canister(machine: &StateMachine, payload: XrcMockInitPayload) {
    let wasm = Wasm::from_location_specified_by_env_var("xrc-mock", &[]);
    create_canister_at_specified_id(
        machine,
        EXCHANGE_RATE_CANISTER_INDEX,
        wasm.unwrap(),
        Some(Encode!(&payload).unwrap()),
        None,
    );
}

fn reinstall_mock_exchange_rate_canister(
    machine: &StateMachine,
    canister_id: CanisterId,
    payload: XrcMockInitPayload,
) {
    let wasm = Wasm::from_location_specified_by_env_var("xrc-mock", &[]).unwrap();
    machine
        .reinstall_canister(canister_id, wasm.bytes(), Encode!(&payload).unwrap())
        .expect("Failed to reinstall mock XRC canister");
}

// Creates an ICP/XDR conversion rate proposal.
fn propose_icp_xdr_rate(
    machine: &StateMachine,
    xdr_permyriad_per_icp: u64,
    timestamp_seconds: u64,
    reason: Option<UpdateIcpXdrConversionRatePayloadReason>,
) -> u64 {
    let payload = UpdateIcpXdrConversionRatePayload {
        data_source: "".to_string(),
        timestamp_seconds,
        xdr_permyriad_per_icp,
        reason,
    };

    // Use TEST_NEURON_1_ID as it is loaded with tokens.
    let neuron_id = NeuronId {
        id: TEST_NEURON_1_ID,
    };

    let proposal = MakeProposalRequest {
        title: Some(format!("Update ICP/XDR rate to {}", xdr_permyriad_per_icp)),
        summary: "".to_string(),
        url: "".to_string(),
        action: Some(ProposalActionRequest::ExecuteNnsFunction(
            ExecuteNnsFunction {
                nns_function: NnsFunction::IcpXdrConversionRate as i32,
                payload: Encode!(&payload).unwrap(),
            },
        )),
    };

    let response = nns_governance_make_proposal(
        machine,
        *TEST_NEURON_1_OWNER_PRINCIPAL,
        neuron_id,
        &proposal,
    );
    match response.command {
        Some(manage_neuron_response::Command::MakeProposal(make_proposal_response)) => {
            match make_proposal_response.proposal_id {
                Some(proposal_id) => proposal_id.id,
                None => panic!("Unable to find proposal ID!"),
            }
        }
        _ => panic!("Unable to submit the proposal: {:?}", response),
    }
}

fn new_icp_cxdr_mock_exchange_rate_canister_init_payload(
    rate: u64,
    icp_sources: Option<usize>,
    cxdr_sources: Option<usize>,
) -> XrcMockInitPayload {
    XrcMockInitPayload {
        response: Response::ExchangeRate(ExchangeRate {
            rate,
            base_asset: Some(Asset {
                symbol: "ICP".to_string(),
                class: AssetClass::Cryptocurrency,
            }),
            quote_asset: Some(Asset {
                symbol: "CXDR".to_string(),
                class: AssetClass::FiatCurrency,
            }),
            metadata: Some(ExchangeRateMetadata {
                decimals: 9,
                base_asset_num_queried_sources: 7,
                base_asset_num_received_rates: icp_sources.unwrap_or(5),
                quote_asset_num_queried_sources: 10,
                quote_asset_num_received_rates: cxdr_sources.unwrap_or(4),
                standard_deviation: 0,
                forex_timestamp: None,
            }),
        }),
    }
}

#[test]
fn test_enable_retrieving_rate_from_exchange_rate_canister() {
    // Step 1: Prepare the world.
    let state_machine = state_machine_builder_for_nns_tests()
        .with_time(GENESIS)
        .build();

    // Set up NNS.
    let nns_init_payload = NnsInitPayloadsBuilder::new()
        .with_exchange_rate_canister(EXCHANGE_RATE_CANISTER_ID)
        .build();
    setup_nns_canisters(&state_machine, nns_init_payload);

    // Install exchange rate canister.
    setup_mock_exchange_rate_canister(
        &state_machine,
        new_icp_cxdr_mock_exchange_rate_canister_init_payload(25_000_000_000, None, None),
    );

    // Check that the canister is initialized with the default rate.
    let cmc_first_rate_timestamp_seconds: u64 = 1620633600; // 10 May 2021 10:00:00 AM CEST
    let response = get_icp_xdr_conversion_rate(&state_machine);
    assert_eq!(
        response.data.timestamp_seconds,
        cmc_first_rate_timestamp_seconds
    );
    assert_eq!(response.data.xdr_permyriad_per_icp, 1_000_000);

    // Step 2: Verify that the rate has been set by calling the cycles minting canister.

    // The CMC will not call the exchange rate canister, as
    // the current time is set to genesis. We need to advance the time
    // to the CMC's first rate then add five minutes to ensure the heartbeat
    // is triggered (the CMC only calls the exchange rate canister
    // every five minutes: :05, :10, :15 and so on).
    let genesis_seconds = GENESIS.as_millis_since_unix_epoch() / 1_000;
    let seconds_diff =
        cmc_first_rate_timestamp_seconds.abs_diff(genesis_seconds) + FIVE_MINUTES_SECONDS;
    state_machine.advance_time(Duration::from_secs(seconds_diff));

    // Start testing. Advance the state machine so the heartbeat triggers
    // at the new time.
    state_machine.tick();
    // Wait to ensure that the call to the exchange rate canister completes.
    state_machine.run_until_completion(10_000);

    // Step 3: Verify that the rate has been set by calling the cycles minting canister.
    let response = get_icp_xdr_conversion_rate(&state_machine);

    // The rate's timestamp should be the CMC's first rate timestamp + five minutes + 8 secs.
    // Note on the 8 secs:
    // The mock exchange rate canister takes the current time and adds 6 seconds
    // to differentiate the timestamps between canisters. An additional 2 is
    // added for retrieving the rate initially.
    assert_eq!(
        response.data.timestamp_seconds,
        cmc_first_rate_timestamp_seconds + FIVE_MINUTES_SECONDS + 8
    );
    assert_eq!(response.data.xdr_permyriad_per_icp, 250_000);

    // Step 4: Change the rate and check that the cycles minting canister captures
    // the new rate.
    // Reinstall the mock exchange rate canister with an updated payload.
    reinstall_mock_exchange_rate_canister(
        &state_machine,
        EXCHANGE_RATE_CANISTER_ID,
        new_icp_cxdr_mock_exchange_rate_canister_init_payload(20_000_000_000, None, None),
    );

    // Advance the time 5 minutes into the future so the heartbeat will trigger.
    state_machine.advance_time(Duration::from_secs(FIVE_MINUTES_SECONDS));
    // Trigger the heartbeat.
    state_machine.tick();
    // Wait to ensure that the call to the exchange rate canister completes.
    state_machine.run_until_completion(10_000);

    let response = get_icp_xdr_conversion_rate(&state_machine);
    // The rate's timestamp should be the CMC's first rate timestamp + 5 minutes + 10 secs.
    // Note on the 10 secs:
    // Similar to retrieving the first rate. Another 2 seconds are tacked on
    // for retrieve the rate initially.
    assert_eq!(
        response.data.timestamp_seconds,
        cmc_first_rate_timestamp_seconds + (FIVE_MINUTES_SECONDS * 2) + 10
    );
    assert_eq!(response.data.xdr_permyriad_per_icp, 200_000);

    // Step 4: Ensure that the cycles minting canister handles errors correctly
    // from the exchange rate canister by attempting to call the exchange rate canister
    // a minute later.
    reinstall_mock_exchange_rate_canister(
        &state_machine,
        EXCHANGE_RATE_CANISTER_ID,
        XrcMockInitPayload {
            response: Response::Error(ExchangeRateError::StablecoinRateTooFewRates),
        },
    );

    // Advance the time to ensure to ensure the cycles minting canister is ready
    // to call the exchange rate canister again.
    state_machine.advance_time(Duration::from_secs(FIVE_MINUTES_SECONDS));
    // Trigger the heartbeat.
    state_machine.tick();

    let response = get_icp_xdr_conversion_rate(&state_machine);
    // The rate's timestamp should be the previous timestamp.
    assert_eq!(
        response.data.timestamp_seconds,
        cmc_first_rate_timestamp_seconds + (FIVE_MINUTES_SECONDS * 2) + 10
    );
    assert_eq!(response.data.xdr_permyriad_per_icp, 200_000);

    // Have the mock exchange rate canister return a rate.
    reinstall_mock_exchange_rate_canister(
        &state_machine,
        EXCHANGE_RATE_CANISTER_ID,
        new_icp_cxdr_mock_exchange_rate_canister_init_payload(21_000_000_000, None, None),
    );

    // Move on to the next minute which should cause the cycles minting canister
    // to trigger another attempt to reach out to the exchange rate canister due
    // to the previous error.
    state_machine.advance_time(Duration::from_secs(ONE_MINUTE_SECONDS));

    // Trigger heartbeat.
    state_machine.tick();

    let response = get_icp_xdr_conversion_rate(&state_machine);
    // The rate's timestamp should be the CMC's first rate timestamp + 16 minutes + 10 secs.
    // Note on the 14 secs:
    // Similar to retrieving the first rate. Another 2 seconds are tacked on
    // for retrieve the rate initially.
    assert_eq!(
        response.data.timestamp_seconds,
        cmc_first_rate_timestamp_seconds + (FIVE_MINUTES_SECONDS * 3) + ONE_MINUTE_SECONDS + 14
    );
    assert_eq!(response.data.xdr_permyriad_per_icp, 210_000);

    // Check that the cycles minting canister does not call the mock exchange rate canister
    // until the next five minute interval (advancing by four minutes).
    for i in 1..=4 {
        state_machine.advance_time(Duration::from_secs(ONE_MINUTE_SECONDS));
        state_machine.tick();

        let expected_timestamp = if i < 4 {
            cmc_first_rate_timestamp_seconds + (FIVE_MINUTES_SECONDS * 3) + ONE_MINUTE_SECONDS + 14
        } else {
            cmc_first_rate_timestamp_seconds + (FIVE_MINUTES_SECONDS * 4) + 22
        };

        let response = get_icp_xdr_conversion_rate(&state_machine);
        assert_eq!(
            response.data.timestamp_seconds, expected_timestamp,
            "failed at iteration: {}",
            i
        );
    }

    // Step 5: Test to ensure the cycles minting canister ignores rates will low number of sources.
    // Step 5a: Test with not enough ICP sources.
    reinstall_mock_exchange_rate_canister(
        &state_machine,
        EXCHANGE_RATE_CANISTER_ID,
        new_icp_cxdr_mock_exchange_rate_canister_init_payload(10_000_000_000, Some(3), None),
    );

    // Advance the time to ensure to ensure the cycles minting canister is ready
    // to call the exchange rate canister again.
    state_machine.advance_time(Duration::from_secs(FIVE_MINUTES_SECONDS));
    // Trigger the heartbeat.
    state_machine.tick();

    let response = get_icp_xdr_conversion_rate(&state_machine);
    // The rate's timestamp should be the previous timestamp.
    assert_eq!(
        response.data.timestamp_seconds,
        cmc_first_rate_timestamp_seconds + (FIVE_MINUTES_SECONDS * 4) + 22
    );
    assert_eq!(response.data.xdr_permyriad_per_icp, 210_000);

    // Step 5b: Test with not enough CXDR sources.
    reinstall_mock_exchange_rate_canister(
        &state_machine,
        EXCHANGE_RATE_CANISTER_ID,
        new_icp_cxdr_mock_exchange_rate_canister_init_payload(10_000_000_000, None, Some(1)),
    );

    // Advance the time to ensure to ensure the cycles minting canister is ready
    // to call the exchange rate canister again.
    state_machine.advance_time(Duration::from_secs(FIVE_MINUTES_SECONDS));
    // Trigger the heartbeat.
    state_machine.tick();

    let response = get_icp_xdr_conversion_rate(&state_machine);
    // The rate's timestamp should be the previous timestamp.
    assert_eq!(
        response.data.timestamp_seconds,
        cmc_first_rate_timestamp_seconds + (FIVE_MINUTES_SECONDS * 4) + 22
    );
    assert_eq!(response.data.xdr_permyriad_per_icp, 210_000);
}

#[test]
fn test_disabling_and_reenabling_exchange_rate_canister_calling_via_exchange_rate_proposal() {
    // Step 1: Prepare the world.
    let state_machine = state_machine_builder_for_nns_tests()
        .with_time(GENESIS)
        .build();

    // Set up NNS.
    let nns_init_payload = NnsInitPayloadsBuilder::new()
        .with_test_neurons()
        .with_exchange_rate_canister(EXCHANGE_RATE_CANISTER_ID)
        .build();
    setup_nns_canisters(&state_machine, nns_init_payload);

    // Install exchange rate canister.
    setup_mock_exchange_rate_canister(
        &state_machine,
        new_icp_cxdr_mock_exchange_rate_canister_init_payload(25_000_000_000, None, None),
    );

    // Check that the canister is initialized with the default rate.
    let cmc_first_rate_timestamp_seconds: u64 = 1620633600; // 10 May 2021 10:00:00 AM CEST
    let response = get_icp_xdr_conversion_rate(&state_machine);
    assert_eq!(
        response.data.timestamp_seconds,
        cmc_first_rate_timestamp_seconds
    );
    assert_eq!(response.data.xdr_permyriad_per_icp, 1_000_000);

    // Step 2: Verify that the rate has been set by calling the cycles minting canister.

    // The CMC will not call the exchange rate canister, as
    // the current time is set to genesis. We need to advance the time
    // to the CMC's first rate then add five minutes to ensure the heartbeat
    // is triggered (the CMC only calls the exchange rate canister
    // every five minutes: :05, :10, :15 and so on).
    let genesis_seconds = GENESIS.as_millis_since_unix_epoch() / 1_000;
    let seconds_diff =
        cmc_first_rate_timestamp_seconds.abs_diff(genesis_seconds) + FIVE_MINUTES_SECONDS;
    state_machine.advance_time(Duration::from_secs(seconds_diff));

    // Start testing. Advance the state machine so the heartbeat triggers
    // at the new time.
    state_machine.tick();
    // Wait to ensure that the call to the exchange rate canister completes.
    state_machine.run_until_completion(10_000);

    // Step 3: Verify that the rate has been set by calling the cycles minting canister.
    let response = get_icp_xdr_conversion_rate(&state_machine);

    // The rate's timestamp should be the CMC's first rate timestamp + five minutes + 8 secs.
    // Note on the 8 secs:
    // The mock exchange rate canister takes the current time and adds 6 seconds
    // to differentiate the timestamps between canisters. An additional 2 is
    // added for retrieving the rate initially.
    assert_eq!(
        response.data.timestamp_seconds,
        cmc_first_rate_timestamp_seconds + FIVE_MINUTES_SECONDS + 8
    );
    assert_eq!(response.data.xdr_permyriad_per_icp, 250_000);

    // Step 3: Send in a proposal with a diverged rate reason. Ensure that the CMC
    // stops calling the mock exchange rate canister.
    let proposal_id = propose_icp_xdr_rate(
        &state_machine,
        210_000,
        cmc_first_rate_timestamp_seconds + FIVE_MINUTES_SECONDS + ONE_MINUTE_SECONDS,
        Some(UpdateIcpXdrConversionRatePayloadReason::DivergedRate),
    );
    nns_wait_for_proposal_execution(&state_machine, proposal_id);

    // Check if proposal has set the rate.
    let response = get_icp_xdr_conversion_rate(&state_machine);
    assert_eq!(
        response.data.timestamp_seconds,
        cmc_first_rate_timestamp_seconds + FIVE_MINUTES_SECONDS + ONE_MINUTE_SECONDS
    );
    assert_eq!(response.data.xdr_permyriad_per_icp, 210_000);

    // Advance the time by 5 minutes and attempt to trigger a
    // call to the exchange rate canister.
    state_machine.advance_time(Duration::from_secs(FIVE_MINUTES_SECONDS));
    // Trigger the heartbeat.
    state_machine.tick();

    // Retrieve the current rate. It should still be 210_000.
    let response = get_icp_xdr_conversion_rate(&state_machine);
    assert_eq!(
        response.data.timestamp_seconds,
        cmc_first_rate_timestamp_seconds + FIVE_MINUTES_SECONDS + ONE_MINUTE_SECONDS
    );
    assert_eq!(response.data.xdr_permyriad_per_icp, 210_000);

    // Ensure that a proposal with a OldRate reason does not reactivate the
    // update cycle.
    let proposal_id = propose_icp_xdr_rate(
        &state_machine,
        200_000,
        cmc_first_rate_timestamp_seconds + FIVE_MINUTES_SECONDS * 2,
        Some(UpdateIcpXdrConversionRatePayloadReason::OldRate),
    );
    nns_wait_for_proposal_execution(&state_machine, proposal_id);

    let response = get_icp_xdr_conversion_rate(&state_machine);
    assert_eq!(
        response.data.timestamp_seconds,
        cmc_first_rate_timestamp_seconds + FIVE_MINUTES_SECONDS * 2
    );
    assert_eq!(response.data.xdr_permyriad_per_icp, 200_000);

    // Advance the time again and trigger the heartbeat.
    state_machine.advance_time(Duration::from_secs(FIVE_MINUTES_SECONDS));
    state_machine.tick();

    let response = get_icp_xdr_conversion_rate(&state_machine);
    assert_eq!(
        response.data.timestamp_seconds,
        cmc_first_rate_timestamp_seconds + FIVE_MINUTES_SECONDS * 2
    );
    assert_eq!(response.data.xdr_permyriad_per_icp, 200_000);

    // Re-enable calls to the exchange rate canister.
    let proposal_id = propose_icp_xdr_rate(
        &state_machine,
        220_000,
        cmc_first_rate_timestamp_seconds + FIVE_MINUTES_SECONDS * 3,
        Some(UpdateIcpXdrConversionRatePayloadReason::EnableAutomaticExchangeRateUpdates),
    );
    nns_wait_for_proposal_execution(&state_machine, proposal_id);

    let response = get_icp_xdr_conversion_rate(&state_machine);
    assert_eq!(
        response.data.timestamp_seconds,
        cmc_first_rate_timestamp_seconds + FIVE_MINUTES_SECONDS * 3
    );
    assert_eq!(response.data.xdr_permyriad_per_icp, 220_000);

    let response = get_icp_xdr_conversion_rate(&state_machine);
    assert_eq!(response.data.xdr_permyriad_per_icp, 220_000);
    assert_eq!(
        response.data.timestamp_seconds,
        cmc_first_rate_timestamp_seconds + FIVE_MINUTES_SECONDS * 3
    );

    // Advance the time again and trigger the heartbeat.
    state_machine.advance_time(Duration::from_secs(FIVE_MINUTES_SECONDS));
    state_machine.tick();

    let response = get_icp_xdr_conversion_rate(&state_machine);
    assert_eq!(response.data.xdr_permyriad_per_icp, 250_000);
    // The rate's timestamp should be the CMC's first rate timestamp + twenty minutes + 22 secs.
    // Note on the 22 secs:
    // The mock exchange rate canister takes the current time and adds 6 seconds
    // to differentiate the timestamps between canisters. An additional 2 is
    // added for retrieving the rate initially.
    assert_eq!(
        response.data.timestamp_seconds,
        cmc_first_rate_timestamp_seconds + FIVE_MINUTES_SECONDS * 4 + 22
    );
}
