use candid::Encode;
use candid::{Nat, Principal};
use ic_base_types::PrincipalId;
use ic_canister_client_sender::Sender;
use ic_ledger_core::Tokens;
use ic_nervous_system_common_test_keys::TEST_USER1_KEYPAIR;
use ic_nns_test_utils::{
    common::NnsInitPayloadsBuilder,
    sns_wasm::{add_wasm_via_proposal, build_ledger_sns_wasm},
    state_test_helpers::{
        icrc1_balance, icrc1_fee, icrc1_transfer, query, setup_nns_canisters,
        sns_claim_staked_neuron, sns_make_proposal, sns_stake_neuron,
        sns_wait_for_proposal_execution,
    },
};
use ic_state_machine_tests::StateMachine;

use ic_sns_governance::{
    pb::v1::{
        proposal::Action, ManageLedgerParameters, NervousSystemParameters, NeuronPermissionList,
        NeuronPermissionType, Proposal, ProposalId,
    },
    types::DEFAULT_TRANSFER_FEE,
};
use ic_sns_test_utils::{
    itest_helpers::SnsTestsInitPayloadBuilder, state_test_helpers::setup_sns_canisters,
};
use icrc_ledger_types::icrc1::{account::Account, transfer::TransferArg};

#[test]
fn test_manage_ledger_parameters_change_transfer_fee() {
    let state_machine = StateMachine::new();

    let user = PrincipalId::new_user_test_id(1000);
    let user_account = Account {
        owner: user.0,
        subaccount: None,
    };

    let nns_init_payloads = NnsInitPayloadsBuilder::new().with_test_neurons().build();

    let system_params = NervousSystemParameters {
        neuron_claimer_permissions: Some(NeuronPermissionList {
            permissions: NeuronPermissionType::all(),
        }),
        ..NervousSystemParameters::with_default_values()
    };

    let sns_init_payload = SnsTestsInitPayloadBuilder::new()
        .with_ledger_account(user_account, Tokens::new(10001, 0).unwrap())
        .with_nervous_system_parameters(system_params)
        .build();

    setup_nns_canisters(&state_machine, nns_init_payloads);
    let sns_canisters = setup_sns_canisters(&state_machine, sns_init_payload);

    add_wasm_via_proposal(&state_machine, build_ledger_sns_wasm());

    let neuron_nonce = 0;
    sns_stake_neuron(
        &state_machine,
        sns_canisters.governance_canister_id,
        sns_canisters.ledger_canister_id,
        user,
        Tokens::new(5005, 0).unwrap(),
        neuron_nonce,
    );
    let neuron = sns_claim_staked_neuron(
        &state_machine,
        sns_canisters.governance_canister_id,
        user,
        neuron_nonce,
        Some(100_000_000), // dissolve delay
    );

    assert!(icrc1_fee(&state_machine, sns_canisters.ledger_canister_id) == DEFAULT_TRANSFER_FEE);

    // change ledger transfer_fee with the ManageLedgerParameters proposal
    let new_fee = 34;

    let change_ledger_transfer_fee_proposal_id = sns_make_proposal(
        &state_machine,
        sns_canisters.governance_canister_id,
        user,
        neuron.clone(),
        Proposal {
            title: "Change ledger transfer fee".to_string(),
            action: Some(Action::ManageLedgerParameters(ManageLedgerParameters {
                transfer_fee: Some(new_fee),
                ..Default::default()
            })),
            ..Default::default()
        },
    )
    .unwrap();

    sns_wait_for_proposal_execution(
        &state_machine,
        sns_canisters.governance_canister_id,
        change_ledger_transfer_fee_proposal_id,
    );

    // check that the fee on the ledger has changed.
    let ledger_fee_after_proposal = icrc1_fee(&state_machine, sns_canisters.ledger_canister_id);

    assert!(ledger_fee_after_proposal != DEFAULT_TRANSFER_FEE);
    assert!(ledger_fee_after_proposal.get_e8s() == new_fee);

    // try making transfers using the new fee and the old fee.
    icrc1_transfer(
        &state_machine,
        sns_canisters.ledger_canister_id,
        user,
        TransferArg {
            amount: Nat::from(5),
            fee: Some(Nat::from(new_fee)),
            from_subaccount: None,
            to: Account {
                owner: Principal::management_canister(),
                subaccount: None,
            },
            memo: None,
            created_at_time: None,
        },
    )
    .expect("This transfer with the new fee must succeed");

    icrc1_transfer(
        &state_machine,
        sns_canisters.ledger_canister_id,
        user,
        TransferArg {
            amount: Nat::from(5),
            fee: Some(Nat::from(DEFAULT_TRANSFER_FEE.get_e8s())),
            from_subaccount: None,
            to: Account {
                owner: Principal::management_canister(),
                subaccount: None,
            },
            memo: None,
            created_at_time: None,
        },
    )
    .expect_err("This transfer with the old fee must fail.");

    let nervous_system_parameters_with_new_fee: NervousSystemParameters = {
        let nervous_system_parameters_raw = query(
            &state_machine,
            sns_canisters.governance_canister_id,
            "get_nervous_system_parameters",
            Encode!().unwrap(),
        )
        .unwrap();

        candid::decode_one(&nervous_system_parameters_raw).unwrap()
    };

    assert_eq!(
        nervous_system_parameters_with_new_fee.transaction_fee_e8s,
        Some(new_fee)
    );
}

#[test]
fn test_manage_ledger_parameters_change_fee_collector() {
    let state_machine = StateMachine::new();

    let user = PrincipalId::new_user_test_id(1000);
    let user_account = Account {
        owner: user.0,
        subaccount: None,
    };

    let nns_init_payloads = NnsInitPayloadsBuilder::new().with_test_neurons().build();

    let system_params = NervousSystemParameters {
        neuron_claimer_permissions: Some(NeuronPermissionList {
            permissions: NeuronPermissionType::all(),
        }),
        ..NervousSystemParameters::with_default_values()
    };

    let sns_init_payload = SnsTestsInitPayloadBuilder::new()
        .with_ledger_account(user_account, Tokens::new(10001, 0).unwrap())
        .with_nervous_system_parameters(system_params)
        .build();

    setup_nns_canisters(&state_machine, nns_init_payloads);
    let sns_canisters = setup_sns_canisters(&state_machine, sns_init_payload);

    add_wasm_via_proposal(&state_machine, build_ledger_sns_wasm());

    let neuron_nonce = 0;
    sns_stake_neuron(
        &state_machine,
        sns_canisters.governance_canister_id,
        sns_canisters.ledger_canister_id,
        user,
        Tokens::new(5005, 0).unwrap(),
        neuron_nonce,
    );
    let neuron = sns_claim_staked_neuron(
        &state_machine,
        sns_canisters.governance_canister_id,
        user,
        neuron_nonce,
        Some(100_000_000), // dissolve delay
    );

    // choose a new fee_collector
    let new_fee_collector = Account {
        owner: Sender::from_keypair(&TEST_USER1_KEYPAIR)
            .get_principal_id()
            .0,
        subaccount: None,
    };

    // check that a transfer does not send the fee to the new_fee_collector before the proposal
    icrc1_transfer(
        &state_machine,
        sns_canisters.ledger_canister_id,
        user,
        TransferArg {
            amount: Nat::from(5),
            fee: Some(Nat::from(DEFAULT_TRANSFER_FEE.get_e8s())),
            from_subaccount: None,
            to: Account {
                owner: Principal::management_canister(),
                subaccount: None,
            },
            memo: None,
            created_at_time: None,
        },
    )
    .unwrap();

    assert_eq!(
        icrc1_balance(
            &state_machine,
            sns_canisters.ledger_canister_id,
            new_fee_collector
        ),
        Tokens::ZERO,
    );

    // change the sns-ledger's fee_collector with the ManageLedgerParameters proposal
    let change_fee_collector_proposal_id: ProposalId = sns_make_proposal(
        &state_machine,
        sns_canisters.governance_canister_id,
        user,
        neuron.clone(),
        Proposal {
            title: "ManageLedgerParameters".to_string(),
            action: Some(Action::ManageLedgerParameters(ManageLedgerParameters {
                set_fee_collector: Some(new_fee_collector.into()),
                ..Default::default()
            })),
            ..Default::default()
        },
    )
    .unwrap();

    sns_wait_for_proposal_execution(
        &state_machine,
        sns_canisters.governance_canister_id,
        change_fee_collector_proposal_id,
    );

    // check that a transfer does send the fee to the new fee_collector now.
    icrc1_transfer(
        &state_machine,
        sns_canisters.ledger_canister_id,
        user,
        TransferArg {
            amount: Nat::from(5),
            fee: Some(Nat::from(DEFAULT_TRANSFER_FEE.get_e8s())),
            from_subaccount: None,
            to: Account {
                owner: Principal::management_canister(),
                subaccount: None,
            },
            memo: None,
            created_at_time: None,
        },
    )
    .unwrap();

    assert_eq!(
        icrc1_balance(
            &state_machine,
            sns_canisters.ledger_canister_id,
            new_fee_collector
        ),
        DEFAULT_TRANSFER_FEE
    );
}
