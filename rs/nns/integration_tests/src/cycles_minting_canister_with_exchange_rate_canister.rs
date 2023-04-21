use std::time::Duration;

use candid::Encode;
use canister_test::Wasm;
use ic_base_types::CanisterId;
use ic_nns_constants::EXCHANGE_RATE_CANISTER_ID;
use ic_nns_test_utils::{
    common::NnsInitPayloadsBuilder,
    state_test_helpers::{create_canister, get_icp_xdr_conversion_rate, setup_nns_canisters},
};
use ic_state_machine_tests::StateMachine;
use ic_types::time::GENESIS;
use ic_xrc_types::{Asset, AssetClass, ExchangeRateError, ExchangeRateMetadata};
use xrc_mock::{ExchangeRate, Response, XrcMockInitPayload};

const ONE_MINUTE_SECONDS: u64 = 60;
const FIVE_MINUTES_SECONDS: u64 = 5 * ONE_MINUTE_SECONDS;

/// Sets up the XRC mock canister.
fn setup_mock_exchange_rate_canister(
    machine: &StateMachine,
    payload: XrcMockInitPayload,
) -> CanisterId {
    let wasm = Wasm::from_location_specified_by_env_var("xrc-mock", &[]);
    create_canister(
        machine,
        wasm.unwrap(),
        Some(Encode!(&payload).unwrap()),
        None,
    )
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

fn new_icp_cxdr_mock_exchange_rate_canister_init_payload(rate: u64) -> XrcMockInitPayload {
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
                base_asset_num_received_rates: 5,
                quote_asset_num_queried_sources: 10,
                quote_asset_num_received_rates: 4,
                standard_deviation: 0,
                forex_timestamp: None,
            }),
        }),
    }
}

#[test]
fn test_enable_retrieving_rate_from_exchange_rate_canister() {
    // Step 1: Prepare the world.
    let state_machine = StateMachine::new();

    // Set up NNS.
    let nns_init_payload = NnsInitPayloadsBuilder::new()
        .with_exchange_rate_canister(EXCHANGE_RATE_CANISTER_ID)
        .build();
    setup_nns_canisters(&state_machine, nns_init_payload);

    // Install exchange rate canister.
    let installed_exchange_rate_canister_id = setup_mock_exchange_rate_canister(
        &state_machine,
        new_icp_cxdr_mock_exchange_rate_canister_init_payload(25_000_000_000),
    );
    // Make sure the exchange rate canister ID and the installed canister ID match.
    assert_eq!(
        EXCHANGE_RATE_CANISTER_ID,
        installed_exchange_rate_canister_id
    );

    // Check that the canister is initialized with the default rate.
    let cmc_first_rate_timestamp_seconds: u64 = 1620633600; // 10 May 2021 10:00:00 AM CEST
    let response = get_icp_xdr_conversion_rate(&state_machine);
    assert_eq!(
        response.data.timestamp_seconds,
        cmc_first_rate_timestamp_seconds
    );
    assert_eq!(response.data.xdr_permyriad_per_icp, 1_000_000);

    // Step 3: Verify that the rate has been set by calling the cycles minting canister.

    // The CMC will not call the exchange rate canister, as
    // the current time is set to genesis. We need to advance the time
    // to the CMC's first rate then add five minutes to ensure the heartbeat
    // is triggered (the CMC only calls the exchange rate canister
    // every five minutes: :05, :10, :15 and so on).
    let genesis_seconds = GENESIS.as_millis_since_unix_epoch() / 1_000;
    let seconds_diff =
        cmc_first_rate_timestamp_seconds.abs_diff(genesis_seconds) + FIVE_MINUTES_SECONDS;
    state_machine.advance_time(Duration::from_secs(seconds_diff));

    // Step 2: Start testing. Advance the state machine so the heartbeat triggers
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
        new_icp_cxdr_mock_exchange_rate_canister_init_payload(20_000_000_000),
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

    // Step 5: Ensure that the cycles minting canister handles errors correctly
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
        new_icp_cxdr_mock_exchange_rate_canister_init_payload(21_000_000_000),
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
}
