use candid::{Decode, Encode};
use ic_base_types::{CanisterId, PrincipalId};
use ic_ledger_core::{tokens::CheckedSub, Tokens};
use ic_nervous_system_common::{
    ledger::compute_distribution_subaccount, ExplosiveTokens, E8, SECONDS_PER_DAY,
};
use ic_nns_common::types::UpdateIcpXdrConversionRatePayload;
use ic_nns_constants::{CYCLES_MINTING_CANISTER_ID, GOVERNANCE_CANISTER_ID, LEDGER_CANISTER_ID};
use ic_nns_test_utils::{
    common::NnsInitPayloadsBuilder,
    state_test_helpers,
    state_test_helpers::{
        icrc1_balance, query, setup_nns_canisters, sns_claim_staked_neuron, sns_make_proposal,
        sns_stake_neuron, sns_wait_for_proposal_execution,
    },
};
use ic_sns_governance::{
    governance::TREASURY_SUBACCOUNT_NONCE,
    pb::v1::{
        governance_error::ErrorType as SnsErrorType, proposal::Action,
        transfer_sns_treasury_funds::TransferFrom, GovernanceError as SnsGovernanceError,
        MintSnsTokens, NervousSystemParameters, NeuronId as SnsNeuronId, NeuronPermissionList,
        NeuronPermissionType, Proposal, TransferSnsTreasuryFunds,
    },
    types::{DEFAULT_TRANSFER_FEE, E8S_PER_TOKEN},
};
use ic_sns_swap::pb::v1::{Init as SwapInit, NeuronBasketConstructionParameters};
use ic_sns_test_utils::{
    itest_helpers::SnsTestsInitPayloadBuilder,
    state_test_helpers::{participate_in_swap, setup_sns_canisters, SnsTestCanisterIds},
};
use ic_state_machine_tests::StateMachine;
use icp_ledger::{
    AccountIdentifier, BinaryAccountBalanceArgs, Subaccount as IcpSubaccount,
    DEFAULT_TRANSFER_FEE as NNS_DEFAULT_TRANSFER_FEE,
};
use icrc_ledger_types::icrc1::account::Account;
use std::time::{Duration, SystemTime};

fn icrc1_account_to_icp_accountidentifier(account: Account) -> AccountIdentifier {
    AccountIdentifier::new(
        PrincipalId(account.owner),
        account.subaccount.map(IcpSubaccount),
    )
}

/// Creates and installs NNS and SNS canisters.
///
/// About the SNS:
///
///     * The treasury has has 10_000 ICP and 10_000 SNS tokens.
///
///     * Has a whale. I.e. a neuron that is so large that it can instantly pass any proposal it
///       wants.
///
/// The swap establishes that 1 SNS token is worth slightly less than 1 ICP.
fn new_treasury_scenario(
    state_machine: &mut StateMachine,
) -> (
    /* whale */ PrincipalId,
    /* also whale */ SnsNeuronId,
    SnsTestCanisterIds,
) {
    // What is special about this value: 1 second after the default value of
    // State.icp_xdr_conversion_rate.timestamp_seconds. This is
    // 10 May 2021 10 AM CEST + 1 second. We need to sync up with that in order for the
    // set_icp_xdr_conversion_rate call that we do later to have the intended effect.
    let start_timestamp_seconds = 1620633600 + 1;
    let start_time = SystemTime::UNIX_EPOCH
        .checked_add(Duration::from_secs(start_timestamp_seconds))
        .unwrap();
    state_machine.set_time(start_time);

    let whale_principal_id = PrincipalId::new_user_test_id(1000);
    let whale_account = Account {
        owner: whale_principal_id.0,
        subaccount: None,
    };
    let whale_account_identifier = icrc1_account_to_icp_accountidentifier(whale_account);

    // This principal will participate in the swap so that it reaches the Committed state. This is
    // needed in order to determine a valuation of the treasury, which is needed as part of
    // TransferSnsTreasuryFunds proposal validation.
    let participant_principal_id = PrincipalId::new_user_test_id(440_894_806);
    let participant_account = Account {
        owner: participant_principal_id.0,
        subaccount: None,
    };
    let participant_account_identifier =
        icrc1_account_to_icp_accountidentifier(participant_account);

    let first_sns_canister_id = 11;
    let governance = CanisterId::from(first_sns_canister_id + 1);

    let sns_treasury_account_nns = Account {
        owner: governance.get().0,
        subaccount: None,
    };

    let sns_treasury_account_sns = Account {
        owner: governance.get().0,
        subaccount: Some(
            compute_distribution_subaccount(governance.get(), TREASURY_SUBACCOUNT_NONCE).0,
        ),
    };

    let sns_treasury_account_nns_identifier =
        icrc1_account_to_icp_accountidentifier(sns_treasury_account_nns);

    let nns_init_payloads = NnsInitPayloadsBuilder::new()
        .with_ledger_accounts(vec![
            (whale_account_identifier, Tokens::new(10_000, 0).unwrap()),
            (
                sns_treasury_account_nns_identifier,
                Tokens::new(10000, 0).unwrap(),
            ),
            (
                participant_account_identifier,
                Tokens::new(100, 10_000).unwrap(),
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

    let mut sns_init_payload = SnsTestsInitPayloadBuilder::new()
        .with_ledger_account(sns_treasury_account_sns, Tokens::new(10000, 0).unwrap())
        // Whale needs majority of tokens to pass proposals
        .with_ledger_account(whale_account, Tokens::new(10001, 0).unwrap())
        .with_nervous_system_parameters(system_params)
        .build();
    sns_init_payload.swap = SwapInit {
        fallback_controller_principal_ids: vec![
            PrincipalId::new_user_test_id(803_233_237).to_string()
        ],

        // This is abnormal, but we do this, because this makes it easier to see that only
        // TransferSnsTreasuryFunds proposal(s) affect the treasury.
        should_auto_finalize: Some(false),

        sns_token_e8s: Some(101 * E8),

        // Global participation requirements.
        min_direct_participation_icp_e8s: Some(100 * E8),
        max_direct_participation_icp_e8s: Some(100 * E8),
        min_participants: Some(1),

        // Individual participant requirements.
        min_participant_icp_e8s: Some(100 * E8),
        max_participant_icp_e8s: Some(100 * E8),

        neuron_basket_construction_parameters: Some(NeuronBasketConstructionParameters {
            count: 1,
            dissolve_delay_interval_seconds: 1,
        }),

        swap_start_timestamp_seconds: Some(start_timestamp_seconds),
        swap_due_timestamp_seconds: Some(start_timestamp_seconds + SECONDS_PER_DAY),

        // Misc.
        nns_proposal_id: Some(42),
        transaction_fee_e8s: Some(10_000),
        neuron_minimum_stake_e8s: Some(1),

        ..Default::default()
    };

    setup_nns_canisters(state_machine, nns_init_payloads);
    let sns_test_canister_ids = setup_sns_canisters(state_machine, sns_init_payload);

    let SnsTestCanisterIds {
        governance_canister_id,
        swap_canister_id,
        ledger_canister_id: sns_ledger_canister_id,

        root_canister_id: _,
        index_canister_id: _,
    } = sns_test_canister_ids;

    participate_in_swap(
        state_machine,
        swap_canister_id,
        participant_principal_id,
        ExplosiveTokens::from(Tokens::new(100, 0).unwrap()),
    );

    // Ensure we lined up canisters correctly or the transfers won't work.
    assert_eq!(governance_canister_id, governance);

    // Double check original balances.

    // Double check the balances of the whale.
    let whale_icp_balance = nns_ledger_balance(state_machine, whale_account);
    let whale_sns_balance = icrc1_balance(state_machine, sns_ledger_canister_id, whale_account);
    assert_eq!(whale_sns_balance, Tokens::new(10001, 0).unwrap());
    assert_eq!(whale_icp_balance, Tokens::new(10000, 0).unwrap());

    // Double check the balances of the SNS treasury.
    let treasury_sns_token_balance = icrc1_balance(
        state_machine,
        sns_ledger_canister_id,
        sns_treasury_account_sns,
    );
    let treasury_icp_balance = nns_ledger_balance(state_machine, sns_treasury_account_nns);
    assert_eq!(treasury_sns_token_balance, Tokens::new(10000, 0).unwrap());
    assert_eq!(treasury_icp_balance, Tokens::new(10000, 0).unwrap());

    // Fashion an SNS neuron for the whale.
    let neuron_nonce = 0;
    sns_stake_neuron(
        state_machine,
        governance_canister_id,
        sns_ledger_canister_id,
        whale_principal_id,
        Tokens::new(10001, 0)
            .unwrap()
            .checked_sub(&DEFAULT_TRANSFER_FEE)
            .unwrap(),
        neuron_nonce,
    );
    let whale_neuron_id = sns_claim_staked_neuron(
        state_machine,
        governance_canister_id,
        whale_principal_id,
        neuron_nonce,
        Some(100_000_000),
    );

    (whale_principal_id, whale_neuron_id, sns_test_canister_ids)
}

#[test]
fn test_sns_treasury_can_transfer_funds_via_proposals() {
    // Step 1: Prepare the world.

    state_test_helpers::reduce_state_machine_logging_unless_env_set();
    let mut state_machine = StateMachine::new();

    let (whale_principal_id, whale_neuron_id, sns_test_canister_ids) =
        new_treasury_scenario(&mut state_machine);

    let SnsTestCanisterIds {
        governance_canister_id,
        ledger_canister_id: sns_ledger_canister_id,

        root_canister_id: _,
        swap_canister_id: _,
        index_canister_id: _,
    } = sns_test_canister_ids;

    let whale_account = Account {
        owner: whale_principal_id.0,
        subaccount: None,
    };

    let treasury_icp_account = Account {
        owner: PrincipalId::from(governance_canister_id).0,
        subaccount: None,
    };

    let treasury_sns_token_account = Account {
        owner: PrincipalId::from(governance_canister_id).0,
        subaccount: Some(
            compute_distribution_subaccount(
                PrincipalId::from(governance_canister_id),
                TREASURY_SUBACCOUNT_NONCE,
            )
            .0,
        ),
    };

    let start_timestamp_seconds = state_machine
        .time()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // Populate ICP price data in the Cycles Minting Canister. This is needed to verify that the
    // amount in the TransferSnsTreasuryFunds proposals is not too big. Since the amounts we are
    // dealing with here are "small" (< 100_000 XDR), any amount is allowed.
    state_machine
        .execute_ingress_as(
            PrincipalId::from(GOVERNANCE_CANISTER_ID), // sender
            CYCLES_MINTING_CANISTER_ID,                // destination
            "set_icp_xdr_conversion_rate",
            Encode!(&UpdateIcpXdrConversionRatePayload {
                data_source: "STONE TABLETS FROM HEAVEN".to_string(),
                timestamp_seconds: start_timestamp_seconds,
                xdr_permyriad_per_icp: 31_400, // 3.14 XDR per ICP.
                reason: None,
            })
            .unwrap(),
        )
        .unwrap();

    // Steps 2: Run the code under test.

    // Whale proposes to have the ICP in the treasury sent to him.
    let transfer_icp_proposal_id = sns_make_proposal(
        &state_machine,
        governance_canister_id,
        whale_principal_id,
        whale_neuron_id.clone(),
        Proposal {
            title: "Transfer treasury NNS".to_string(),
            summary: "Transfer treasury to user".to_string(),
            url: "".to_string(),
            action: Some(Action::TransferSnsTreasuryFunds(TransferSnsTreasuryFunds {
                from_treasury: TransferFrom::IcpTreasury.into(),
                amount_e8s: 10000 * E8S_PER_TOKEN - NNS_DEFAULT_TRANSFER_FEE.get_e8s(),
                memo: None,
                to_principal: Some(whale_principal_id),
                to_subaccount: None,
            })),
        },
    )
    .unwrap();
    sns_wait_for_proposal_execution(
        &state_machine,
        governance_canister_id,
        transfer_icp_proposal_id,
    );

    // Whale proposes to have the SNS tokens in the treasury sent to him.
    let transfer_token_proposal_id = sns_make_proposal(
        &state_machine,
        governance_canister_id,
        whale_principal_id,
        whale_neuron_id,
        Proposal {
            title: "Transfer treasury SNS".to_string(),
            summary: "Transfer treasury to user".to_string(),
            url: "".to_string(),
            action: Some(Action::TransferSnsTreasuryFunds(TransferSnsTreasuryFunds {
                from_treasury: TransferFrom::SnsTokenTreasury.into(),
                amount_e8s: 10000 * E8S_PER_TOKEN - DEFAULT_TRANSFER_FEE.get_e8s(),
                memo: None,
                to_principal: Some(whale_principal_id),
                to_subaccount: None,
            })),
        },
    )
    .unwrap();
    sns_wait_for_proposal_execution(
        &state_machine,
        governance_canister_id,
        transfer_token_proposal_id,
    );

    // Step 3: Inspect results.

    // Step 3.1: Inspect whale balances.
    let whale_icp_balance = nns_ledger_balance(&state_machine, whale_account);
    let whale_sns_balance = icrc1_balance(&state_machine, sns_ledger_canister_id, whale_account);
    assert_eq!(whale_sns_balance, Tokens::new(9999, 99990000).unwrap());
    assert_eq!(whale_icp_balance, Tokens::new(19999, 99990000).unwrap());

    // Step 3.1: Inspect treasury balances.
    let treasury_sns_token_balance = icrc1_balance(
        &state_machine,
        sns_ledger_canister_id,
        treasury_sns_token_account,
    );
    let treasury_icp_balance = nns_ledger_balance(&state_machine, treasury_icp_account);
    assert_eq!(treasury_sns_token_balance, Tokens::new(0, 0).unwrap());
    assert_eq!(treasury_icp_balance, Tokens::new(0, 0).unwrap());
}

#[test]
fn test_transfer_sns_treasury_funds_proposals_that_are_too_big_get_blocked_at_submission() {
    // Step 1: Prepare the world. What happens here is similar to what happens in Step 1 of the
    // previous test. The difference is that the price of ICP here is (unrealistically) high in
    // order to provoke a giant treasury valuation, which then puts a lower cap on the number of
    // tokens that proposals can transfer from the treasury.

    state_test_helpers::reduce_state_machine_logging_unless_env_set();
    let mut state_machine = StateMachine::new();

    let (whale_principal_id, whale_neuron_id, sns_test_canister_ids) =
        new_treasury_scenario(&mut state_machine);

    let SnsTestCanisterIds {
        governance_canister_id,
        ledger_canister_id: sns_ledger_canister_id,

        root_canister_id: _,
        swap_canister_id: _,
        index_canister_id: _,
    } = sns_test_canister_ids;

    let whale_account = Account {
        owner: whale_principal_id.0,
        subaccount: None,
    };

    let treasury_icp_account = Account {
        owner: PrincipalId::from(governance_canister_id).0,
        subaccount: None,
    };

    let treasury_sns_token_account = Account {
        owner: PrincipalId::from(governance_canister_id).0,
        subaccount: Some(
            compute_distribution_subaccount(
                PrincipalId::from(governance_canister_id),
                TREASURY_SUBACCOUNT_NONCE,
            )
            .0,
        ),
    };

    let start_timestamp_seconds = state_machine
        .time()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // This is where the difference described at the top of this section happens.
    state_machine
        .execute_ingress_as(
            PrincipalId::from(GOVERNANCE_CANISTER_ID), // sender
            CYCLES_MINTING_CANISTER_ID,                // destination
            "set_icp_xdr_conversion_rate",
            Encode!(&UpdateIcpXdrConversionRatePayload {
                data_source: "STONE TABLETS FROM HEAVEN".to_string(),
                timestamp_seconds: start_timestamp_seconds,
                // More specifically, here is where ICP is worth an (unrealistically) large amount.
                xdr_permyriad_per_icp: 5_000_000 * 10_000,
                reason: None,
            })
            .unwrap(),
        )
        .unwrap();

    // Steps 2: Run the code under test.

    // Whale proposes to give himself NNS treasury for dapp
    let take_icp_result_make_proposal_result = sns_make_proposal(
        &state_machine,
        governance_canister_id,
        whale_principal_id,
        whale_neuron_id.clone(),
        Proposal {
            title: "Transfer treasury NNS".to_string(),
            summary: "Transfer treasury to user".to_string(),
            url: "".to_string(),
            action: Some(Action::TransferSnsTreasuryFunds(TransferSnsTreasuryFunds {
                from_treasury: TransferFrom::IcpTreasury.into(),
                amount_e8s: 10000 * E8S_PER_TOKEN - NNS_DEFAULT_TRANSFER_FEE.get_e8s(),
                memo: None,
                to_principal: Some(whale_principal_id),
                to_subaccount: None,
            })),
        },
    );

    // Whale proposes to give himself SNS token treasury
    let take_sns_tokens_make_proposal_result = sns_make_proposal(
        &state_machine,
        governance_canister_id,
        whale_principal_id,
        whale_neuron_id,
        Proposal {
            title: "Transfer treasury SNS".to_string(),
            summary: "Transfer treasury to user".to_string(),
            url: "".to_string(),
            action: Some(Action::TransferSnsTreasuryFunds(TransferSnsTreasuryFunds {
                from_treasury: TransferFrom::SnsTokenTreasury.into(),
                amount_e8s: 10000 * E8S_PER_TOKEN - DEFAULT_TRANSFER_FEE.get_e8s(),
                memo: None,
                to_principal: Some(whale_principal_id),
                to_subaccount: None,
            })),
        },
    );

    // Step 3: Inspect results.

    // Step 3.1: Both proposals were rejected.
    match &take_icp_result_make_proposal_result {
        Err(err) => {
            let SnsGovernanceError {
                error_type,
                error_message,
            } = err;

            let error_type = SnsErrorType::try_from(*error_type).unwrap();
            assert_eq!(error_type, SnsErrorType::InvalidProposal, "{:?}", err);

            let error_message = error_message.to_lowercase();
            assert!(error_message.contains("amount"), "{:?}", err);
            assert!(error_message.contains("too large"), "{:?}", err);
        }

        wrong => panic!(
            "Proposal submission was NOT rejected (as it should have been): {:?}",
            wrong
        ),
    }
    match &take_sns_tokens_make_proposal_result {
        Err(err) => {
            let SnsGovernanceError {
                error_type,
                error_message,
            } = err;

            let error_type = SnsErrorType::try_from(*error_type).unwrap();
            assert_eq!(error_type, SnsErrorType::InvalidProposal, "{:?}", err);

            let error_message = error_message.to_lowercase();
            assert!(error_message.contains("amount"), "{:?}", err);
            assert!(error_message.contains("too large"), "{:?}", err);
        }

        wrong => panic!(
            "Proposal submission was NOT rejected (as it should have been): {:?}",
            wrong
        ),
    }

    // Step 3.2: Assert that balances are unchanged.

    // Step 3.2.1: Assert that the balances of the whale have not changed.
    let whale_icp_balance = nns_ledger_balance(&state_machine, whale_account);
    let whale_sns_balance = icrc1_balance(&state_machine, sns_ledger_canister_id, whale_account);
    assert_eq!(whale_sns_balance, Tokens::new(0, 0).unwrap());
    assert_eq!(whale_icp_balance, Tokens::new(10_000, 0).unwrap());

    // Step 3.2.2: Assert that treasury has not been touched.
    let treasury_sns_token_balance = icrc1_balance(
        &state_machine,
        sns_ledger_canister_id,
        treasury_sns_token_account,
    );
    let treasury_icp_balance = nns_ledger_balance(&state_machine, treasury_icp_account);
    assert_eq!(treasury_sns_token_balance, Tokens::new(10_000, 0).unwrap());
    assert_eq!(treasury_icp_balance, Tokens::new(10_000, 0).unwrap());
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

#[test]
fn sns_can_mint_funds_via_proposals() {
    state_test_helpers::reduce_state_machine_logging_unless_env_set();
    let state_machine = StateMachine::new();

    let user = PrincipalId::new_user_test_id(1000);
    let user_account = Account {
        owner: user.0,
        subaccount: None,
    };
    let user_account_identifier = icrc1_account_to_icp_accountidentifier(user_account);

    let first_sns_canister_id = 11;
    let governance = CanisterId::from(first_sns_canister_id + 1);

    let treasury_icp_account = Account {
        owner: governance.get().0,
        subaccount: None,
    };

    let treasury_sns_token_account = Account {
        owner: governance.get().0,
        subaccount: Some(
            compute_distribution_subaccount(governance.get(), TREASURY_SUBACCOUNT_NONCE).0,
        ),
    };

    let treasury_icp_account_identifier =
        icrc1_account_to_icp_accountidentifier(treasury_icp_account);

    let nns_init_payloads = NnsInitPayloadsBuilder::new()
        .with_ledger_accounts(vec![
            (user_account_identifier, Tokens::new(10000, 0).unwrap()),
            (
                treasury_icp_account_identifier,
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
        .with_ledger_account(treasury_sns_token_account, Tokens::new(10000, 0).unwrap())
        // User needs majority of the voting power to pass proposals
        .with_ledger_account(user_account, Tokens::new(10001, 0).unwrap())
        .with_nervous_system_parameters(system_params)
        .build();

    setup_nns_canisters(&state_machine, nns_init_payloads);
    let sns_canisters = setup_sns_canisters(&state_machine, sns_init_payload);

    // Ensure we lined up canisters correctly or the transfers won't work.
    assert_eq!(sns_canisters.governance_canister_id, governance);

    let user_sns_balance = icrc1_balance(
        &state_machine,
        sns_canisters.ledger_canister_id,
        user_account,
    );
    assert_eq!(user_sns_balance, Tokens::new(10001, 0).unwrap());

    let treasury_sns_token_balance = icrc1_balance(
        &state_machine,
        sns_canisters.ledger_canister_id,
        treasury_sns_token_account,
    );
    assert_eq!(treasury_sns_token_balance, Tokens::new(10000, 0).unwrap());

    let neuron_nonce = 0;
    sns_stake_neuron(
        &state_machine,
        sns_canisters.governance_canister_id,
        sns_canisters.ledger_canister_id,
        user,
        Tokens::new(10001, 0)
            .unwrap()
            .checked_sub(&DEFAULT_TRANSFER_FEE)
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

    // User proposes to mint himself SNS tokens
    let transfer_token_proposal_id = sns_make_proposal(
        &state_machine,
        governance,
        user,
        neuron,
        Proposal {
            title: "Mint SNS tokens".to_string(),
            summary: "Mint tokens to user".to_string(),
            url: "".to_string(),
            action: Some(Action::MintSnsTokens(MintSnsTokens {
                amount_e8s: Some(10000 * E8S_PER_TOKEN),
                memo: None,
                to_principal: Some(user),
                to_subaccount: None,
            })),
        },
    )
    .unwrap();

    sns_wait_for_proposal_execution(&state_machine, governance, transfer_token_proposal_id);

    // Show that our treasuries are not affected, and our user has expected funds
    let user_sns_balance = icrc1_balance(
        &state_machine,
        sns_canisters.ledger_canister_id,
        user_account,
    );
    assert_eq!(user_sns_balance, Tokens::new(10000, 0).unwrap());

    let treasury_sns_token_balance = icrc1_balance(
        &state_machine,
        sns_canisters.ledger_canister_id,
        treasury_sns_token_account,
    );
    assert_eq!(treasury_sns_token_balance, Tokens::new(10000, 0).unwrap());
}
