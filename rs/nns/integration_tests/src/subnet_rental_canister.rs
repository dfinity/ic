use candid::{CandidType, Decode, Deserialize, Encode};
use canister_test::Wasm;
use ic_base_types::PrincipalId;
use ic_nervous_system_common_test_keys::TEST_USER1_PRINCIPAL;
use ic_nns_constants::{
    EXCHANGE_RATE_CANISTER_ID, EXCHANGE_RATE_CANISTER_INDEX, LEDGER_CANISTER_ID,
    SUBNET_RENTAL_CANISTER_ID,
};
use ic_nns_governance_api::pb::v1::{
    manage_neuron_response::{Command as CommandResponse, RegisterVoteResponse},
    ExecuteNnsFunction, MakeProposalRequest, NnsFunction, ProposalActionRequest, Vote,
};
use ic_nns_test_utils::{
    common::NnsInitPayloadsBuilder,
    neuron_helpers::{get_neuron_1, get_neuron_2},
    state_test_helpers::{
        create_canister_at_specified_id, ledger_account_balance, nns_cast_vote,
        nns_governance_get_proposal_info_as_anonymous, nns_governance_make_proposal,
        nns_wait_for_proposal_execution, nns_wait_for_proposal_failure, setup_nns_canisters,
        setup_subnet_rental_canister_with_correct_canister_id, state_machine_builder_for_nns_tests,
    },
};
use ic_state_machine_tests::{StateMachine, WasmResult};
use ic_types::Time;
use ic_xrc_types::{Asset, AssetClass, ExchangeRateMetadata};
use icp_ledger::{
    AccountIdentifier, BinaryAccountBalanceArgs, Memo, Subaccount, Tokens, TransferArgs,
    DEFAULT_TRANSFER_FEE,
};
use std::time::Duration;
use xrc_mock::{ExchangeRate, Response, XrcMockInitPayload};

// A proposal payload to make a subnet rental request.
#[derive(candid::CandidType, candid::Deserialize)]
pub struct SubnetRentalRequest {
    pub user: PrincipalId,
    pub rental_condition_id: RentalConditionId,
}

// The following three Subnet Rental Canister types
// are copied from the Subnet Rental Canister's repository.
#[derive(Copy, Clone, CandidType, PartialEq, Eq, PartialOrd, Ord, Debug, Deserialize)]
pub enum RentalConditionId {
    App13CH,
}
#[derive(Clone, CandidType, PartialEq, Eq, PartialOrd, Ord, Debug, Deserialize)]
pub struct SubnetRentalProposalPayload {
    pub user: PrincipalId,
    pub rental_condition_id: RentalConditionId,
    pub proposal_id: u64,
    pub proposal_creation_time_seconds: u64,
}
#[derive(Clone, CandidType, PartialEq, Eq, PartialOrd, Ord, Debug, Deserialize)]
pub struct RentalRequest {
    pub user: PrincipalId,
    pub initial_cost_icp: Tokens,
    pub refundable_icp: Tokens,
    pub locked_amount_icp: Tokens,
    pub locked_amount_cycles: u128,
    pub initial_proposal_id: u64,
    pub creation_time_nanos: u64,
    pub rental_condition_id: RentalConditionId,
    pub last_locking_time_nanos: u64,
}

fn setup_state_machine_with_nns_canisters() -> StateMachine {
    let account = AccountIdentifier::new(*TEST_USER1_PRINCIPAL, None);
    let initial_balance = Tokens::new(1_000_000, 0).unwrap();
    let time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let midnight = time - time % 86400;
    let state_machine = state_machine_builder_for_nns_tests()
        .with_time(Time::from_secs_since_unix_epoch(midnight).unwrap())
        .build();
    let nns_init_payloads = NnsInitPayloadsBuilder::new()
        .with_test_neurons()
        .with_ledger_account(account, initial_balance)
        .with_exchange_rate_canister(EXCHANGE_RATE_CANISTER_ID)
        .build();
    setup_nns_canisters(&state_machine, nns_init_payloads);
    setup_subnet_rental_canister_with_correct_canister_id(&state_machine);
    state_machine
}

/// CXDR is an asset whose rate is derived from more sources than the XDR rate.
/// The input rate to this method is the integer multiple of 1e-9 CXDR that is worth 1 ICP,
/// e.g., `rate` equal to `12_000_000_000` corresponds to the conversion rate of 12 CXDR for 1 ICP.
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

fn setup_mock_exchange_rate_canister(machine: &StateMachine, rate: u64) {
    let wasm = Wasm::from_location_specified_by_env_var("xrc-mock", &[]);
    let payload = new_icp_cxdr_mock_exchange_rate_canister_init_payload(rate);
    if machine.canister_exists(EXCHANGE_RATE_CANISTER_ID) {
        machine
            .reinstall_canister(
                EXCHANGE_RATE_CANISTER_ID,
                wasm.unwrap().bytes(),
                Encode!(&payload).unwrap(),
            )
            .unwrap();
    } else {
        create_canister_at_specified_id(
            machine,
            EXCHANGE_RATE_CANISTER_INDEX,
            wasm.unwrap(),
            Some(Encode!(&payload).unwrap()),
            None,
        );
    }
}

fn get_todays_price(machine: &StateMachine) -> Tokens {
    let rental_price_icp = machine
        .execute_ingress(
            SUBNET_RENTAL_CANISTER_ID,
            "get_todays_price",
            Encode!(&RentalConditionId::App13CH).unwrap(),
        )
        .unwrap();
    match rental_price_icp {
        WasmResult::Reply(bytes) => Decode!(&bytes, Result<Tokens, String>).unwrap().unwrap(),
        WasmResult::Reject(reason) => panic!("canister call rejected: {}", reason),
    }
}

fn send_icp_to_rent_subnet(machine: &StateMachine, user_principal_id: PrincipalId) {
    // user finds current price by consulting Subnet Rental Canister
    let rental_price_icp = get_todays_price(machine);

    // user transfers required ICP to Subnet Rental Canister
    let transfer_args = TransferArgs {
        memo: Memo(0),
        amount: rental_price_icp,
        fee: Tokens::from_e8s(10_000),
        from_subaccount: None,
        to: AccountIdentifier::new(
            SUBNET_RENTAL_CANISTER_ID.get(),
            Some(Subaccount::from(&user_principal_id.clone())),
        )
        .to_address(),
        created_at_time: None,
    };
    machine
        .execute_ingress_as(
            user_principal_id,
            LEDGER_CANISTER_ID,
            "transfer",
            Encode!(&transfer_args).unwrap(),
        )
        .unwrap();
}

fn check_balance(
    machine: &StateMachine,
    owner: PrincipalId,
    subaccount: Option<Subaccount>,
) -> Tokens {
    let account = BinaryAccountBalanceArgs {
        account: AccountIdentifier::new(owner, subaccount).to_address(),
    };
    ledger_account_balance(machine, LEDGER_CANISTER_ID, &account)
}

/// Test description:
///
///     1. ICP price goes up and thus the rental price in ICP decreases.
///
///     2. Renter principal sends ICP to Subnet Rental Canister in order to rent a subnet.
///
///     3. A subnet rental NNS proposal for renter is created.
///
///     4. ICP price goes down and thus the rental price in ICP increases.
///
///     5. The subnet rental NNS proposal is adopted and executed with the rental price in ICP fixed at step 3.
///
///     6. Renter requests a refund, thereby aborting the rental request.
///
/// In the end, this results in no rental requests, and renter gets their money back.
#[test]
fn subnet_rental_request_lifecycle() {
    let state_machine = setup_state_machine_with_nns_canisters();

    setup_mock_exchange_rate_canister(&state_machine, 5_000_000_000);
    let price1 = get_todays_price(&state_machine);

    // advance time by one day
    state_machine.advance_time(Duration::from_secs(86_400));

    setup_mock_exchange_rate_canister(&state_machine, 10_000_000_000);
    let price2 = get_todays_price(&state_machine);

    // advance time by one day
    state_machine.advance_time(Duration::from_secs(86_400));

    setup_mock_exchange_rate_canister(&state_machine, 25_000_000_000);
    let price3 = get_todays_price(&state_machine);

    // price should keep declining
    assert!(price1 > price2);
    assert!(price2 > price3);

    // advance time by half a day
    state_machine.advance_time(Duration::from_secs(12 * 60 * 60));

    setup_mock_exchange_rate_canister(&state_machine, 15_000_000_000);
    let price = get_todays_price(&state_machine);

    // the price should not change since the day is the same and thus the price
    // at last midnight is unchanged
    assert_eq!(price, price3);

    // user makes the initial transfer at price3
    let renter = *TEST_USER1_PRINCIPAL;
    send_icp_to_rent_subnet(&state_machine, renter);

    let large_neuron = get_neuron_1();
    let small_neuron = get_neuron_2();

    let subnet_rental_request = SubnetRentalRequest {
        user: renter,
        rental_condition_id: RentalConditionId::App13CH,
    };
    let proposal = MakeProposalRequest {
        title: Some("Create subnet rental request".to_string()),
        summary: "".to_string(),
        url: "".to_string(),
        action: Some(ProposalActionRequest::ExecuteNnsFunction(
            ExecuteNnsFunction {
                nns_function: NnsFunction::SubnetRentalRequest as i32,
                payload: Encode!(&subnet_rental_request).expect("Error encoding proposal payload"),
            },
        )),
    };
    // Make proposal with small neuron. It does not have enough voting power such that the proposal would be adopted immediately.
    let cmd = nns_governance_make_proposal(
        &state_machine,
        small_neuron.principal_id,
        small_neuron.neuron_id,
        &proposal,
    )
    .command
    .expect("Making NNS proposal failed");
    let proposal_id = match cmd {
        CommandResponse::MakeProposal(resp) => resp.proposal_id.unwrap(),
        other => panic!("Unexpected response: {:?}", other),
    };
    let proposal_time = state_machine.get_time();

    // advance time by one day
    state_machine.advance_time(Duration::from_secs(86_400));

    let price4 = get_todays_price(&state_machine);

    // advance time by one day
    state_machine.advance_time(Duration::from_secs(86_400));

    setup_mock_exchange_rate_canister(&state_machine, 5_000_000_000);
    let price5 = get_todays_price(&state_machine);

    // price should keep increasing
    assert!(price3 < price4);
    assert!(price4 < price5);

    // the proposal should not be decided yet as it was proposed by the small neuron
    let proposal_info =
        nns_governance_get_proposal_info_as_anonymous(&state_machine, proposal_id.id);
    assert_eq!(proposal_info.decided_timestamp_seconds, 0);

    // large neuron votes and thus the proposal should be executed now
    let response = nns_cast_vote(
        &state_machine,
        large_neuron.principal_id,
        large_neuron.neuron_id,
        proposal_id.id,
        Vote::Yes,
    )
    .command
    .expect("Casting vote failed");
    assert_eq!(
        response,
        CommandResponse::RegisterVote(RegisterVoteResponse {})
    );
    nns_wait_for_proposal_execution(&state_machine, proposal_id.id);

    // check that the rental request has been created
    let raw_rental_requests = state_machine
        .query(
            SUBNET_RENTAL_CANISTER_ID,
            "list_rental_requests",
            Encode!(&()).unwrap(),
        )
        .unwrap();
    let rental_requests = match raw_rental_requests {
        WasmResult::Reply(bytes) => Decode!(&bytes, Vec<RentalRequest>).unwrap(),
        WasmResult::Reject(reason) => panic!("canister call rejected: {}", reason),
    };
    assert_eq!(rental_requests.len(), 1);
    let RentalRequest {
        user,
        initial_cost_icp,
        refundable_icp,
        locked_amount_icp,
        initial_proposal_id,
        creation_time_nanos,
        rental_condition_id,
        last_locking_time_nanos,

        locked_amount_cycles: _,
    } = rental_requests[0];
    assert_eq!(user, renter);
    assert!(
        initial_cost_icp.get_e8s() - initial_cost_icp.get_e8s() / 10 <= refundable_icp.get_e8s(),
        "initial cost = {}; refundable = {}",
        initial_cost_icp,
        refundable_icp
    );
    assert!(
        refundable_icp <= initial_cost_icp,
        "initial cost = {}; refundable = {}",
        initial_cost_icp,
        refundable_icp
    );
    assert!(locked_amount_icp.get_e8s() <= initial_cost_icp.get_e8s() / 10);
    assert_eq!(initial_proposal_id, proposal_id.id);
    assert!(proposal_time.as_nanos_since_unix_epoch() <= creation_time_nanos);
    assert!(proposal_time.as_nanos_since_unix_epoch() <= last_locking_time_nanos);
    assert_eq!(creation_time_nanos, last_locking_time_nanos);
    assert_eq!(rental_condition_id, RentalConditionId::App13CH);
    assert_eq!(initial_cost_icp, price3);

    // test user aborts rental request and gets refund
    let balance_before = check_balance(&state_machine, renter, None);
    state_machine
        .execute_ingress_as(
            renter,
            SUBNET_RENTAL_CANISTER_ID,
            "refund",
            Encode!(&()).unwrap(),
        )
        .unwrap();
    let balance_after = check_balance(&state_machine, renter, None);
    assert_eq!(
        balance_before.get_e8s() + refundable_icp.get_e8s(),
        balance_after.get_e8s() + DEFAULT_TRANSFER_FEE.get_e8s(),
    );

    // afterwards there should be no more rental requests
    let raw_rental_requests = state_machine
        .query(
            SUBNET_RENTAL_CANISTER_ID,
            "list_rental_requests",
            Encode!(&()).unwrap(),
        )
        .unwrap();
    let remaining_rental_requests = match raw_rental_requests {
        WasmResult::Reply(bytes) => Decode!(&bytes, Vec<RentalRequest>).unwrap(),
        WasmResult::Reject(reason) => panic!("canister call rejected: {}", reason),
    };
    assert!(remaining_rental_requests.is_empty());
}

#[test]
fn test_renting_a_subnet_without_paying_fails() {
    let state_machine = setup_state_machine_with_nns_canisters();

    setup_mock_exchange_rate_canister(&state_machine, 25_000_000_000);

    let large_neuron = get_neuron_1();

    let renter = *TEST_USER1_PRINCIPAL;
    let subnet_rental_request = SubnetRentalRequest {
        user: renter,
        rental_condition_id: RentalConditionId::App13CH,
    };
    let proposal = MakeProposalRequest {
        title: Some("Create subnet rental request".to_string()),
        summary: "".to_string(),
        url: "".to_string(),
        action: Some(ProposalActionRequest::ExecuteNnsFunction(
            ExecuteNnsFunction {
                nns_function: NnsFunction::SubnetRentalRequest as i32,
                payload: Encode!(&subnet_rental_request).expect("Error encoding proposal payload"),
            },
        )),
    };
    // Make proposal with large neuron. It has enough voting power such that the proposal will be adopted immediately.
    let cmd = nns_governance_make_proposal(
        &state_machine,
        large_neuron.principal_id,
        large_neuron.neuron_id,
        &proposal,
    )
    .command
    .expect("Making NNS proposal failed");
    let proposal_id = match cmd {
        CommandResponse::MakeProposal(resp) => resp.proposal_id.unwrap(),
        other => panic!("Unexpected response: {:?}", other),
    };

    // the proposal is expected to fail since the user did not make the initial transfer
    nns_wait_for_proposal_failure(&state_machine, proposal_id.id);
    let proposal_info =
        nns_governance_get_proposal_info_as_anonymous(&state_machine, proposal_id.id);
    assert!(proposal_info
        .failure_reason
        .unwrap()
        .error_message
        .contains("Subnet rental request proposal failed: InsufficientFunds"));

    // check that the rental request has NOT been created
    let raw_rental_requests = state_machine
        .query(
            SUBNET_RENTAL_CANISTER_ID,
            "list_rental_requests",
            Encode!(&()).unwrap(),
        )
        .unwrap();
    let rental_requests = match raw_rental_requests {
        WasmResult::Reply(bytes) => Decode!(&bytes, Vec<RentalRequest>).unwrap(),
        WasmResult::Reject(reason) => panic!("canister call rejected: {}", reason),
    };
    assert!(rental_requests.is_empty());
}
