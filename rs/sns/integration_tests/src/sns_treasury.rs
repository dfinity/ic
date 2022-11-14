use candid::{Decode, Encode};
use ic_base_types::{CanisterId, PrincipalId};
use ic_icrc1::Account;
use ic_ledger_core::Tokens;
use ic_nervous_system_common::ledger::compute_distribution_subaccount;
use ic_nns_constants::LEDGER_CANISTER_ID;
use ic_nns_test_utils::common::NnsInitPayloadsBuilder;
use ic_nns_test_utils::state_test_helpers;
use ic_nns_test_utils::state_test_helpers::{
    icrc1_balance, query, setup_nns_canisters, sns_claim_staked_neuron, sns_make_proposal,
    sns_stake_neuron, sns_wait_for_proposal_execution,
};
use ic_sns_governance::governance::TREASURY_SUBACCOUNT_NONCE;
use ic_sns_governance::pb::v1::proposal::Action;
use ic_sns_governance::pb::v1::transfer_sns_treasury_funds::TransferFrom;
use ic_sns_governance::pb::v1::{
    NervousSystemParameters, NeuronPermissionList, NeuronPermissionType, Proposal,
    TransferSnsTreasuryFunds,
};
use ic_sns_governance::types::{DEFAULT_TRANSFER_FEE, E8S_PER_TOKEN};
use ic_sns_test_utils::itest_helpers::SnsTestsInitPayloadBuilder;
use ic_sns_test_utils::state_test_helpers::setup_sns_canisters;
use ic_state_machine_tests::StateMachine;
use icp_ledger::DEFAULT_TRANSFER_FEE as NNS_DEFAULT_TRANSFER_FEE;
use icp_ledger::{AccountIdentifier, BinaryAccountBalanceArgs, Subaccount as IcpSubaccount};
use std::ops::Sub;

fn icrc1_account_to_icp_accountidentifier(account: Account) -> AccountIdentifier {
    AccountIdentifier::new(account.owner, account.subaccount.map(IcpSubaccount))
}

#[test]
fn sns_treasury_can_transfer_funds_via_proposals() {
    state_test_helpers::reduce_state_machine_logging_unless_env_set();
    let state_machine = StateMachine::new();

    let user = PrincipalId::new_user_test_id(1000);
    let user_account = Account {
        owner: user,
        subaccount: None,
    };
    let user_account_identifier = icrc1_account_to_icp_accountidentifier(user_account.clone());

    let first_sns_canister_id = 11;
    let governance = CanisterId::from(first_sns_canister_id + 1);

    let sns_treasury_account_nns = Account {
        owner: governance.get(),
        subaccount: None,
    };

    let sns_treasury_account_sns = Account {
        owner: governance.get(),
        subaccount: Some(
            compute_distribution_subaccount(governance.get(), TREASURY_SUBACCOUNT_NONCE).0,
        ),
    };

    let sns_treasury_account_nns_identifier =
        icrc1_account_to_icp_accountidentifier(sns_treasury_account_nns.clone());

    let nns_init_payloads = NnsInitPayloadsBuilder::new()
        .with_ledger_accounts(vec![
            (user_account_identifier, Tokens::new(10000, 0).unwrap()),
            (
                sns_treasury_account_nns_identifier,
                Tokens::new(10000, 0).unwrap(),
            ),
        ])
        .with_test_neurons()
        .build();

    let system_params = NervousSystemParameters {
        neuron_claimer_permissions: Some(NeuronPermissionList {
            permissions: NeuronPermissionType::all(),
        }),
        ..NervousSystemParameters::with_default_values()
    };

    let sns_init_payload = SnsTestsInitPayloadBuilder::new()
        .with_ledger_account(
            sns_treasury_account_sns.clone(),
            Tokens::new(10000, 0).unwrap(),
        )
        // User needs majority of tokens to pass proposals
        .with_ledger_account(user_account.clone(), Tokens::new(10001, 0).unwrap())
        .with_nervous_system_parameters(system_params)
        .build();

    setup_nns_canisters(&state_machine, nns_init_payloads);
    let sns_canisters = setup_sns_canisters(&state_machine, sns_init_payload);

    // Ensure we lined up canisters correctly or the transfers won't work.
    assert_eq!(sns_canisters.governance_canister_id, governance);

    // Show that our treasuries have expected funds, and our user has expected funds
    let user_icp_balance = nns_ledger_balance(&state_machine, user_account.clone());

    let user_sns_balance = icrc1_balance(
        &state_machine,
        sns_canisters.ledger_canister_id,
        user_account.clone(),
    );
    assert_eq!(user_sns_balance, Tokens::new(10001, 0).unwrap());
    assert_eq!(user_icp_balance, Tokens::new(10000, 0).unwrap());

    let sns_sns_balance = icrc1_balance(
        &state_machine,
        sns_canisters.ledger_canister_id,
        sns_treasury_account_sns.clone(),
    );
    let sns_icp_balance = nns_ledger_balance(&state_machine, sns_treasury_account_nns.clone());

    assert_eq!(sns_sns_balance, Tokens::new(10000, 0).unwrap());
    assert_eq!(sns_icp_balance, Tokens::new(10000, 0).unwrap());

    let neuron_nonce = 0;
    sns_stake_neuron(
        &state_machine,
        sns_canisters.governance_canister_id,
        sns_canisters.ledger_canister_id,
        user,
        Tokens::new(10001, 0)
            .unwrap()
            .sub(DEFAULT_TRANSFER_FEE)
            .unwrap(),
        neuron_nonce,
    );
    // User claims neuron
    let neuron = sns_claim_staked_neuron(
        &state_machine,
        governance,
        user,
        neuron_nonce,
        Some(100_000_000),
    );
    // User proposes to give himself NNS treasury for dapp
    let transfer_icp_proposal_id = sns_make_proposal(
        &state_machine,
        governance,
        user,
        neuron.clone(),
        Proposal {
            title: "Transfer treasury NNS".to_string(),
            summary: "Transfer treasury to user".to_string(),
            url: "".to_string(),
            action: Some(Action::TransferSnsTreasuryFunds(TransferSnsTreasuryFunds {
                from_treasury: TransferFrom::IcpTreasury.into(),
                amount_e8s: 10000 * E8S_PER_TOKEN - NNS_DEFAULT_TRANSFER_FEE.get_e8s(),
                memo: None,
                to_principal: Some(user),
                to_subaccount: None,
            })),
        },
    )
    .unwrap();

    sns_wait_for_proposal_execution(&state_machine, governance, transfer_icp_proposal_id);

    // User proposes to give himself SNS token treasury

    let transfer_token_proposal_id = sns_make_proposal(
        &state_machine,
        governance,
        user,
        neuron,
        Proposal {
            title: "Transfer treasury SNS".to_string(),
            summary: "Transfer treasury to user".to_string(),
            url: "".to_string(),
            action: Some(Action::TransferSnsTreasuryFunds(TransferSnsTreasuryFunds {
                from_treasury: TransferFrom::SnsTokenTreasury.into(),
                amount_e8s: 10000 * E8S_PER_TOKEN - DEFAULT_TRANSFER_FEE.get_e8s(),
                memo: None,
                to_principal: Some(user),
                to_subaccount: None,
            })),
        },
    )
    .unwrap();

    sns_wait_for_proposal_execution(&state_machine, governance, transfer_token_proposal_id);

    // Show that our treasuries are drained, and our user has expected funds
    let user_icp_balance = nns_ledger_balance(&state_machine, user_account.clone());

    let user_sns_balance = icrc1_balance(
        &state_machine,
        sns_canisters.ledger_canister_id,
        user_account,
    );
    assert_eq!(user_sns_balance, Tokens::new(9999, 99990000).unwrap());
    assert_eq!(user_icp_balance, Tokens::new(19999, 99990000).unwrap());

    let sns_sns_balance = icrc1_balance(
        &state_machine,
        sns_canisters.ledger_canister_id,
        sns_treasury_account_sns,
    );
    let sns_icp_balance = nns_ledger_balance(&state_machine, sns_treasury_account_nns);

    assert_eq!(sns_sns_balance, Tokens::new(0, 0).unwrap());
    assert_eq!(sns_icp_balance, Tokens::new(0, 0).unwrap());
}

fn nns_ledger_balance(state_machine: &StateMachine, account: Account) -> Tokens {
    let blob = icrc1_account_to_icp_accountidentifier(account).to_address();
    Decode!(
        &query(
            state_machine,
            LEDGER_CANISTER_ID,
            "account_balance",
            Encode!(&BinaryAccountBalanceArgs { account: blob }).unwrap(),
        )
        .unwrap(),
        Tokens
    )
    .unwrap()
}
