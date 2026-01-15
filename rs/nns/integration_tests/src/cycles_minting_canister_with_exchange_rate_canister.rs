use candid::{CandidType, Encode};
use canister_test::Wasm;
use cycles_minting_canister::IcpXdrConversionRateCertifiedResponse;
use ic_base_types::CanisterId;
use ic_cbor::CertificateToCbor;
use ic_certificate_verification::VerifyCertificate;
use ic_certification::{Certificate, HashTree, LookupResult};
use ic_nns_constants::{
    CYCLES_MINTING_CANISTER_ID, EXCHANGE_RATE_CANISTER_ID, EXCHANGE_RATE_CANISTER_INDEX,
};
use ic_nns_test_utils::{
    common::NnsInitPayloadsBuilder,
    state_test_helpers::{
        create_canister_at_specified_id, get_average_icp_xdr_conversion_rate,
        get_icp_xdr_conversion_rate, setup_nns_canisters, state_machine_builder_for_nns_tests,
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
            "failed at iteration: {i}"
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

fn verify_cmc_certified_data<Data>(
    state_machine: &StateMachine,
    certificate: Vec<u8>,
    hash_tree: Vec<u8>,
    label: &[u8],
    data: Data,
) where
    Data: CandidType,
{
    // Verify the certificate with the IC root key.
    let root_key = state_machine.root_key_der();
    let certificate = Certificate::from_cbor(certificate.as_slice()).unwrap();
    let current_time_nanos = state_machine.get_time().as_nanos_since_unix_epoch() as u128;
    certificate
        .verify(
            CYCLES_MINTING_CANISTER_ID.as_ref(),
            root_key.as_slice(),
            &current_time_nanos,
            &60_000_000_000, // 1 minute in nanoseconds
        )
        .unwrap();

    // Verify the hash tree with the certificate.
    let certified_data = certificate.tree.lookup_path([
        b"canister",
        CYCLES_MINTING_CANISTER_ID.get().as_slice(),
        b"certified_data",
    ]);
    let certified_data = match certified_data {
        LookupResult::Found(certified_data) => certified_data,
        _ => panic!("Failed to find certified_data in certificate"),
    };
    let hash_tree: HashTree = serde_cbor::from_slice(&hash_tree)
        .expect("Failed to deserialize the witness into a HashTree");
    assert_eq!(hash_tree.digest(), certified_data);

    // Verify the data with the hash tree.
    let hash_tree_entry = hash_tree.lookup_path([label]);
    let hash_tree_entry = match hash_tree_entry {
        LookupResult::Found(entry) => entry,
        _ => panic!("Failed to find ICP_XDR_CONVERSION_RATE in hash tree"),
    };
    assert_eq!(Encode!(&data).unwrap(), hash_tree_entry);
}

#[test]
fn test_get_icp_xdr_conversion_rate_certification() {
    // Step 1: Prepare the world by setting up the NNS and the exchange rate canister.
    let state_machine = state_machine_builder_for_nns_tests().build();
    let nns_init_payload = NnsInitPayloadsBuilder::new()
        .with_test_neurons()
        .with_exchange_rate_canister(EXCHANGE_RATE_CANISTER_ID)
        .build();
    setup_nns_canisters(&state_machine, nns_init_payload);
    setup_mock_exchange_rate_canister(
        &state_machine,
        new_icp_cxdr_mock_exchange_rate_canister_init_payload(25_000_000_000, None, None),
    );

    // Step 2: Advance the time to ensure the exchange rate is updated and the data is certified.
    state_machine.advance_time(Duration::from_secs(60));
    state_machine.tick();

    // Step 3: Get the ICP/XDR conversion rate.
    let IcpXdrConversionRateCertifiedResponse {
        data,
        certificate,
        hash_tree,
    } = get_icp_xdr_conversion_rate(&state_machine);

    // Step 4: Verify the certification.
    verify_cmc_certified_data(
        &state_machine,
        certificate,
        hash_tree,
        b"ICP_XDR_CONVERSION_RATE",
        data,
    );
}

#[test]
fn test_get_average_icp_xdr_conversion_rate_certification() {
    // Step 1: Prepare the world by setting up the NNS and the exchange rate canister.
    let state_machine = state_machine_builder_for_nns_tests().build();
    let nns_init_payload = NnsInitPayloadsBuilder::new()
        .with_test_neurons()
        .with_exchange_rate_canister(EXCHANGE_RATE_CANISTER_ID)
        .build();
    setup_nns_canisters(&state_machine, nns_init_payload);
    setup_mock_exchange_rate_canister(
        &state_machine,
        new_icp_cxdr_mock_exchange_rate_canister_init_payload(25_000_000_000, None, None),
    );

    // Step 2: Advance the time to ensure the exchange rate is updated and the data is certified.
    state_machine.advance_time(Duration::from_secs(60));
    state_machine.tick();

    // Step 3: Get the average ICP/XDR conversion rate.
    let IcpXdrConversionRateCertifiedResponse {
        data,
        certificate,
        hash_tree,
    } = get_average_icp_xdr_conversion_rate(&state_machine);

    // Step 4: Verify the certification.
    verify_cmc_certified_data(
        &state_machine,
        certificate,
        hash_tree,
        b"AVERAGE_ICP_XDR_CONVERSION_RATE",
        data,
    );
}
