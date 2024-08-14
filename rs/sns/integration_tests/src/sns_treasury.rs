use candid::{Decode, Encode, Principal};
use cycles_minting_canister::DEFAULT_ICP_XDR_CONVERSION_RATE_TIMESTAMP_SECONDS;
use ic_base_types::{CanisterId, PrincipalId};
use ic_ledger_core::{tokens::CheckedSub, Tokens};
use ic_nervous_system_common::{
    ledger::compute_distribution_subaccount, ExplosiveTokens, DEFAULT_TRANSFER_FEE, E8,
    ONE_DAY_SECONDS,
};
use ic_nervous_system_proto::pb::v1::Percentage;
use ic_nns_common::types::UpdateIcpXdrConversionRatePayload;
use ic_nns_constants::{CYCLES_MINTING_CANISTER_ID, GOVERNANCE_CANISTER_ID, LEDGER_CANISTER_ID};
use ic_nns_test_utils::{
    common::NnsInitPayloadsBuilder,
    state_test_helpers::{
        self, icrc1_balance, query, setup_nns_canisters, sns_claim_staked_neuron, sns_get_proposal,
        sns_make_proposal, sns_stake_neuron, sns_wait_for_proposal_executed_or_failed,
        sns_wait_for_proposal_execution,
    },
};
use ic_sns_governance::{
    governance::TREASURY_SUBACCOUNT_NONCE,
    pb::v1::{
        governance_error::ErrorType as SnsErrorType, proposal::Action,
        transfer_sns_treasury_funds::TransferFrom, GovernanceError as SnsGovernanceError,
        MintSnsTokens, Motion, NervousSystemParameters, NeuronId as SnsNeuronId,
        NeuronPermissionList, NeuronPermissionType, Proposal, ProposalData,
        TransferSnsTreasuryFunds, Vote,
    },
    types::E8S_PER_TOKEN,
};
use ic_sns_swap::pb::v1::{Init as SwapInit, NeuronBasketConstructionParameters};
use ic_sns_test_utils::{
    itest_helpers::SnsTestsInitPayloadBuilder,
    state_test_helpers::{
        participate_in_swap, setup_sns_canisters, sns_cast_vote,
        state_machine_builder_for_sns_tests, SnsTestCanisterIds,
    },
};
use ic_state_machine_tests::StateMachine;
use icp_ledger::{
    AccountIdentifier, BinaryAccountBalanceArgs, Subaccount as IcpSubaccount,
    DEFAULT_TRANSFER_FEE as NNS_DEFAULT_TRANSFER_FEE,
};
use icrc_ledger_types::icrc1::account::Account;
use lazy_static::lazy_static;
use std::time::{Duration, SystemTime};

fn icrc1_account_to_icp_accountidentifier(account: Account) -> AccountIdentifier {
    AccountIdentifier::new(
        PrincipalId(account.owner),
        account.subaccount.map(IcpSubaccount),
    )
}

trait DefaultAccount {
    fn default_account(&self) -> Account;
}

impl DefaultAccount for PrincipalId {
    fn default_account(&self) -> Account {
        Account {
            owner: Principal::from(*self),
            subaccount: None,
        }
    }
}

// How can we generalize this to anything that can be converted to a PrincipalId?
impl DefaultAccount for CanisterId {
    fn default_account(&self) -> Account {
        PrincipalId::from(*self).default_account()
    }
}

trait FromAccount {
    fn from_account(src: Account) -> Self;
}

impl FromAccount for AccountIdentifier {
    fn from_account(src: Account) -> AccountIdentifier {
        AccountIdentifier::new(PrincipalId(src.owner), src.subaccount.map(IcpSubaccount))
    }
}

// The value here is used by the cycles-minting canister (CMC). We need to sync up with CMC in order
// for set_icp_xdr_conversion_rate to have the effect indicated by the name.
const START_TIMESTAMP_SECONDS: u64 = DEFAULT_ICP_XDR_CONVERSION_RATE_TIMESTAMP_SECONDS + 1;

lazy_static! {
    /// In new_treasury_scenario, this has a neuron with overwhelming voting power, such that it can
    /// instantly pass any proposal it wants.
    static ref WHALE: PrincipalId = PrincipalId::new_user_test_id(266_500_070);

    /// Unlike the (primary) whale, new_treasury_scenario does not give this an uber neuron, but
    /// this principal does have enough SNS tokens to create a neuron capable of voting in whatever
    /// the counterweight wants.
    static ref COUNTERWEIGHT: PrincipalId = PrincipalId::new_user_test_id(340_495_543);

    /// This principal participates in the swap created by new_treasury_scenario so that the swap
    /// reaches the Committed state. This is needed in order to determine a valuation of the
    /// treasury, which is needed as part of TransferSnsTreasuryFunds proposal validation.
    static ref PARTICIPANT: PrincipalId = PrincipalId::new_user_test_id(859_530_655);
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
    state_machine: &StateMachine,
) -> (/* whale */ SnsNeuronId, SnsTestCanisterIds) {
    let start_time = SystemTime::UNIX_EPOCH
        .checked_add(Duration::from_secs(START_TIMESTAMP_SECONDS))
        .unwrap();
    state_machine.set_time(start_time);

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
            (
                AccountIdentifier::from_account(WHALE.default_account()),
                Tokens::new(10_000, 0).unwrap(),
            ),
            (
                sns_treasury_account_nns_identifier,
                Tokens::new(10000, 0).unwrap(),
            ),
            (
                AccountIdentifier::from_account(PARTICIPANT.default_account()),
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
        // Whale and counterweight need funds to make (SNS) neurons.
        .with_ledger_account(WHALE.default_account(), Tokens::new(10001, 0).unwrap())
        .with_ledger_account(
            COUNTERWEIGHT.default_account(),
            Tokens::new(30_000, 0).unwrap(),
        )
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

        swap_start_timestamp_seconds: Some(START_TIMESTAMP_SECONDS),
        swap_due_timestamp_seconds: Some(START_TIMESTAMP_SECONDS + ONE_DAY_SECONDS),

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
        *PARTICIPANT,
        ExplosiveTokens::from(Tokens::new(100, 0).unwrap()),
    );

    // Ensure we lined up canisters correctly or the transfers won't work.
    assert_eq!(governance_canister_id, governance);

    // Double check original balances.

    // Double check the balances of the whale.
    let whale_icp_balance = nns_ledger_balance(state_machine, WHALE.default_account());
    let whale_sns_balance = icrc1_balance(
        state_machine,
        sns_ledger_canister_id,
        WHALE.default_account(),
    );
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
        *WHALE,
        Tokens::new(10001, 0)
            .unwrap()
            .checked_sub(&DEFAULT_TRANSFER_FEE)
            .unwrap(),
        neuron_nonce,
    );
    let whale_neuron_id = sns_claim_staked_neuron(
        state_machine,
        governance_canister_id,
        *WHALE,
        neuron_nonce,
        Some(100_000_000),
    );

    (whale_neuron_id, sns_test_canister_ids)
}

#[test]
fn test_sns_treasury_can_transfer_funds_via_proposals() {
    // Step 1: Prepare the world.

    state_test_helpers::reduce_state_machine_logging_unless_env_set();
    let state_machine = state_machine_builder_for_sns_tests().build();

    let (whale_neuron_id, sns_test_canister_ids) = new_treasury_scenario(&state_machine);

    let SnsTestCanisterIds {
        governance_canister_id,
        ledger_canister_id: sns_ledger_canister_id,

        root_canister_id: _,
        swap_canister_id: _,
        index_canister_id: _,
    } = sns_test_canister_ids;

    let treasury_icp_account = governance_canister_id.default_account();

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
        *WHALE,
        whale_neuron_id.clone(),
        Proposal {
            title: "Transfer treasury NNS".to_string(),
            summary: "Transfer treasury to user".to_string(),
            url: "".to_string(),
            action: Some(Action::TransferSnsTreasuryFunds(TransferSnsTreasuryFunds {
                from_treasury: TransferFrom::IcpTreasury.into(),
                amount_e8s: 10000 * E8S_PER_TOKEN - NNS_DEFAULT_TRANSFER_FEE.get_e8s(),
                memo: None,
                to_principal: Some(*WHALE),
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
        *WHALE,
        whale_neuron_id.clone(),
        Proposal {
            title: "Transfer treasury SNS".to_string(),
            summary: "Transfer treasury to user".to_string(),
            url: "".to_string(),
            action: Some(Action::TransferSnsTreasuryFunds(TransferSnsTreasuryFunds {
                from_treasury: TransferFrom::SnsTokenTreasury.into(),
                amount_e8s: 10000 * E8S_PER_TOKEN - DEFAULT_TRANSFER_FEE.get_e8s(),
                memo: None,
                to_principal: Some(*WHALE),
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
    let whale_icp_balance = nns_ledger_balance(&state_machine, WHALE.default_account());
    let whale_sns_balance = icrc1_balance(
        &state_machine,
        sns_ledger_canister_id,
        WHALE.default_account(),
    );
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

    // Side quest: TransferSnsTreasuryFunds is a "critical" proposal. As such, a higher bar needs to
    // be met in order to pass such proposals. Here, we inspect the fields that specify this higher
    // bar.
    {
        fn select_interesting_fields(proposal_data: &ProposalData) -> ProposalData {
            let ProposalData {
                minimum_yes_proportion_of_total,
                minimum_yes_proportion_of_exercised,
                initial_voting_period_seconds,
                wait_for_quiet_deadline_increase_seconds,
                ..
            } = proposal_data.clone();

            ProposalData {
                minimum_yes_proportion_of_total,
                minimum_yes_proportion_of_exercised,
                initial_voting_period_seconds,
                wait_for_quiet_deadline_increase_seconds,
                ..Default::default()
            }
        }

        let proposal = sns_get_proposal(
            &state_machine,
            governance_canister_id,
            transfer_icp_proposal_id,
        )
        .unwrap();
        assert_eq!(
            select_interesting_fields(&proposal),
            ProposalData {
                minimum_yes_proportion_of_total: Some(
                    // 20%
                    Percentage {
                        basis_points: Some(2000)
                    },
                ),
                minimum_yes_proportion_of_exercised: Some(
                    // 67%
                    Percentage {
                        basis_points: Some(6700)
                    },
                ),
                initial_voting_period_seconds: 5 * ONE_DAY_SECONDS,
                wait_for_quiet_deadline_increase_seconds: 5 * ONE_DAY_SECONDS / 2, // 2.5 days
                ..Default::default()
            },
            "{:#?}",
            proposal,
        );

        // Assert that the bar to pass other proposal types is lower.

        // First, we have to make such a proposal. Here, we call the proposal "benign".
        let benign_proposal_id = sns_make_proposal(
            &state_machine,
            governance_canister_id,
            *WHALE,
            whale_neuron_id,
            Proposal {
                title: "Transfer treasury SNS".to_string(),
                summary: "Transfer treasury to user".to_string(),
                url: "".to_string(),
                action: Some(Action::Motion(Motion {
                    motion_text: "Nothing to see here.".to_string(),
                })),
            },
        )
        .unwrap();
        sns_wait_for_proposal_execution(
            &state_machine,
            governance_canister_id,
            transfer_token_proposal_id,
        );

        // Now, we inspect the benign proposal.
        let proposal =
            sns_get_proposal(&state_machine, governance_canister_id, benign_proposal_id).unwrap();
        assert_eq!(
            select_interesting_fields(&proposal),
            ProposalData {
                minimum_yes_proportion_of_total: Some(
                    // 3%
                    Percentage {
                        basis_points: Some(300)
                    },
                ),
                minimum_yes_proportion_of_exercised: Some(
                    // 50%
                    Percentage {
                        basis_points: Some(5000)
                    },
                ),
                initial_voting_period_seconds: 4 * ONE_DAY_SECONDS,
                wait_for_quiet_deadline_increase_seconds: ONE_DAY_SECONDS,
                ..Default::default()
            },
            "{:#?}",
            proposal,
        );
    }
}

#[test]
fn test_transfer_sns_treasury_funds_proposals_that_are_too_big_get_blocked_at_submission() {
    // Step 1: Prepare the world. What happens here is similar to what happens in Step 1 of the
    // previous test. The difference is that the price of ICP here is (unrealistically) high in
    // order to provoke a giant treasury valuation, which then puts a lower cap on the number of
    // tokens that proposals can transfer from the treasury.

    state_test_helpers::reduce_state_machine_logging_unless_env_set();
    let state_machine = state_machine_builder_for_sns_tests().build();

    let (whale_neuron_id, sns_test_canister_ids) = new_treasury_scenario(&state_machine);

    let SnsTestCanisterIds {
        governance_canister_id,
        ledger_canister_id: sns_ledger_canister_id,

        root_canister_id: _,
        swap_canister_id: _,
        index_canister_id: _,
    } = sns_test_canister_ids;

    let treasury_icp_account = governance_canister_id.default_account();

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
        *WHALE,
        whale_neuron_id.clone(),
        Proposal {
            title: "Transfer treasury NNS".to_string(),
            summary: "Transfer treasury to user".to_string(),
            url: "".to_string(),
            action: Some(Action::TransferSnsTreasuryFunds(TransferSnsTreasuryFunds {
                from_treasury: TransferFrom::IcpTreasury.into(),
                amount_e8s: 10000 * E8S_PER_TOKEN - NNS_DEFAULT_TRANSFER_FEE.get_e8s(),
                memo: None,
                to_principal: Some(*WHALE),
                to_subaccount: None,
            })),
        },
    );

    // Whale proposes to give himself SNS token treasury
    let take_sns_tokens_make_proposal_result = sns_make_proposal(
        &state_machine,
        governance_canister_id,
        *WHALE,
        whale_neuron_id,
        Proposal {
            title: "Transfer treasury SNS".to_string(),
            summary: "Transfer treasury to user".to_string(),
            url: "".to_string(),
            action: Some(Action::TransferSnsTreasuryFunds(TransferSnsTreasuryFunds {
                from_treasury: TransferFrom::SnsTokenTreasury.into(),
                amount_e8s: 10000 * E8S_PER_TOKEN - DEFAULT_TRANSFER_FEE.get_e8s(),
                memo: None,
                to_principal: Some(*WHALE),
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
    let whale_icp_balance = nns_ledger_balance(&state_machine, WHALE.default_account());
    let whale_sns_balance = icrc1_balance(
        &state_machine,
        sns_ledger_canister_id,
        WHALE.default_account(),
    );
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

/// Story:
///
///     1. Two proposals are made (successfully).
///
///     2. The second one is adopted and executed first.
///
///     3. The first is adopted, but execution fails, because a big chunk of the allowance has been
///        spent by the second (already executed proposal).
#[test]
fn test_transfer_sns_treasury_funds_upper_bound_is_enforced_at_execution() {
    // Step 1: Prepare the world.

    state_test_helpers::reduce_state_machine_logging_unless_env_set();
    let state_machine = state_machine_builder_for_sns_tests().build();

    let (whale_neuron_id, sns_test_canister_ids) = new_treasury_scenario(&state_machine);

    let SnsTestCanisterIds {
        governance_canister_id,
        ledger_canister_id: sns_ledger_canister_id,

        root_canister_id: _,
        swap_canister_id: _,
        index_canister_id: _,
    } = sns_test_canister_ids;

    let start_timestamp_seconds = state_machine
        .time()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // Populate ICP price data in the Cycles Minting Canister. This is needed to verify that the
    // amount in the TransferSnsTreasuryFunds proposals is not too big. This results in a treasury
    // where the ICP in the treasury is worth roughly 42 * 10_000 XDR, which would be considered
    // "medium" for the purposes of limiting TransferSnsTreasuryFunds proposals. Because the amount
    // of ICP treasury is "medium", up to 25% of the ICP in the treasury can be disbursed within a 7
    // day window.
    state_machine
        .execute_ingress_as(
            PrincipalId::from(GOVERNANCE_CANISTER_ID), // sender
            CYCLES_MINTING_CANISTER_ID,                // destination
            "set_icp_xdr_conversion_rate",
            Encode!(&UpdateIcpXdrConversionRatePayload {
                data_source: "STONE TABLETS FROM HEAVEN".to_string(),
                timestamp_seconds: start_timestamp_seconds,
                xdr_permyriad_per_icp: 42 * 10_000, // 42 XDR per ICP.
                reason: None,
            })
            .unwrap(),
        )
        .unwrap();

    // Fashion another SNS neuron so that WHALE cannot instantly pass proposals.
    let neuron_nonce = 0;
    sns_stake_neuron(
        &state_machine,
        governance_canister_id,
        sns_ledger_canister_id,
        *COUNTERWEIGHT,
        Tokens::new(30_000, 0)
            .unwrap()
            .checked_sub(&DEFAULT_TRANSFER_FEE)
            .unwrap(),
        neuron_nonce,
    );
    let counterweight_neuron_id = sns_claim_staked_neuron(
        &state_machine,
        governance_canister_id,
        *COUNTERWEIGHT,
        neuron_nonce,
        Some(100_000_000),
    );

    // Steps 2: Run the code under test.

    let make_transfer_sns_treasury_funds_proposal = |index| {
        sns_make_proposal(
            &state_machine,
            governance_canister_id,
            *WHALE,
            whale_neuron_id.clone(),
            Proposal {
                title: format!("{}: Give whale 20% of the ICP in the treasury", index),
                summary: "".to_string(),
                url: "".to_string(),
                action: Some(Action::TransferSnsTreasuryFunds(TransferSnsTreasuryFunds {
                    from_treasury: TransferFrom::IcpTreasury as i32,
                    amount_e8s: 2_000 * E8, // 20% of the treasury
                    to_principal: Some(*WHALE),
                    to_subaccount: None,
                    memo: None,
                })),
            },
        )
        .unwrap()
    };

    let first_proposal_id = make_transfer_sns_treasury_funds_proposal(1);
    let second_proposal_id = make_transfer_sns_treasury_funds_proposal(2);

    // Make the second proposal pass.
    sns_cast_vote(
        &state_machine,
        governance_canister_id,
        *COUNTERWEIGHT,
        counterweight_neuron_id.clone(),
        second_proposal_id,
        Vote::Yes,
    );
    sns_wait_for_proposal_execution(&state_machine, governance_canister_id, second_proposal_id);

    // Make the first proposal pass.
    sns_cast_vote(
        &state_machine,
        governance_canister_id,
        *COUNTERWEIGHT,
        counterweight_neuron_id,
        first_proposal_id,
        Vote::Yes,
    );
    sns_wait_for_proposal_executed_or_failed(
        &state_machine,
        governance_canister_id,
        first_proposal_id,
    );

    // Step 3: Inspect results.

    // Step 3.1: Inspect failure reason to make sure it didn't fail for some other reason.
    let proposal =
        sns_get_proposal(&state_machine, governance_canister_id, first_proposal_id).unwrap();
    assert_ne!(proposal.failed_timestamp_seconds, 0, "{:#?}", proposal);

    let failure_reason = proposal.failure_reason.unwrap();
    let SnsGovernanceError {
        error_type,
        error_message,
    } = &failure_reason;
    assert_eq!(
        SnsErrorType::try_from(*error_type),
        Ok(SnsErrorType::PreconditionFailed),
        "{:#?}",
        failure_reason,
    );
    let error_message = error_message.to_lowercase();
    for keyword in ["7 day", "upper bound", "exceed", "try again"] {
        assert!(error_message.contains(keyword), "{:#?}", failure_reason);
    }

    // Step 3.2: Assert that treasury is smaller by approximately 2_000 ICP, not 4_000 ICP as would
    // be the case if both proposals were executed.
    let treasury_icp_account = governance_canister_id.default_account();
    let treasury_icp_balance = nns_ledger_balance(&state_machine, treasury_icp_account);
    assert_eq!(
        treasury_icp_balance,
        Tokens::from_e8s(8_000 * E8 - DEFAULT_TRANSFER_FEE.get_e8s()),
    );
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
    // Step 1: Prepare the world.

    state_test_helpers::reduce_state_machine_logging_unless_env_set();
    let state_machine = state_machine_builder_for_sns_tests().build();

    let (whale_neuron_id, sns_test_canister_ids) = new_treasury_scenario(&state_machine);

    let SnsTestCanisterIds {
        governance_canister_id,
        ledger_canister_id: sns_ledger_canister_id,

        root_canister_id: _,
        swap_canister_id: _,
        index_canister_id: _,
    } = sns_test_canister_ids;

    let start_timestamp_seconds = state_machine
        .time()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // Populate ICP price data in the Cycles Minting Canister. This is needed to verify that the
    // amount in MintSnsTokens proposals is not too big. This results in a treasury where the SNS
    // tokens in the treasury is worth a little bit less than 42 * 10_000 XDR, which would be
    // considered "medium" for the purposes of limiting MintSnsTokens proposals. Because the amount
    // of ICP treasury is "medium", up to 25% of the ICP in the treasury can be disbursed within a 7
    // day window.
    state_machine
        .execute_ingress_as(
            PrincipalId::from(GOVERNANCE_CANISTER_ID), // sender
            CYCLES_MINTING_CANISTER_ID,                // destination
            "set_icp_xdr_conversion_rate",
            Encode!(&UpdateIcpXdrConversionRatePayload {
                data_source: "STONE TABLETS FROM HEAVEN".to_string(),
                timestamp_seconds: start_timestamp_seconds,
                xdr_permyriad_per_icp: 42 * 10_000, // 42 XDR per ICP.
                reason: None,
            })
            .unwrap(),
        )
        .unwrap();

    // Step 2: Run the code under test.

    // User proposes to mint himself SNS tokens
    let proposal = Proposal {
        title: "First Mint".to_string(),
        summary: "".to_string(),
        url: "".to_string(),
        action: Some(Action::MintSnsTokens(MintSnsTokens {
            amount_e8s: Some(2_222 * E8),
            to_principal: Some(*WHALE),
            to_subaccount: None,
            memo: None,
        })),
    };
    let first_proposal_id = sns_make_proposal(
        &state_machine,
        governance_canister_id,
        *WHALE,
        whale_neuron_id.clone(),
        proposal.clone(),
    )
    .unwrap();
    sns_wait_for_proposal_execution(&state_machine, governance_canister_id, first_proposal_id);

    // Step 3: Inspect the result(s).

    // Assert that whale got his SNS tokens.
    let balance = icrc1_balance(
        &state_machine,
        sns_ledger_canister_id,
        Account {
            owner: Principal::from(*WHALE),
            subaccount: None,
        },
    );
    assert_eq!(balance, Tokens::new(2_222, 0).unwrap());

    // Whale tries again, but this time, it doesn't work, because of minting limits.
    let doomed_make_proposal_result = sns_make_proposal(
        &state_machine,
        governance_canister_id,
        *WHALE,
        whale_neuron_id,
        Proposal {
            title: "Second Mint".to_string(),
            ..proposal
        },
    );

    /* TODO(NNS1-2982): Uncomment.
    let err = doomed_make_proposal_result.unwrap_err();
    let SnsGovernanceError {
        error_type,
        error_message,
    } = &err;
    assert_eq!(
        SnsErrorType::try_from(*error_type),
        Ok(SnsErrorType::InvalidProposal),
        "{:#?}",
        err,
    );
    let error_message = error_message.to_lowercase();
    for snip in [
        "amount",
        "too large",
        "2222",
        "upper bound",
        "exceeded",
        "try again",
    ] {
        assert!(error_message.contains(snip), "{:#?}", err);
    }
    */
    doomed_make_proposal_result.unwrap(); // TODO(NNS1-2982): Delete this line.

    // Whale's balance is not affected by the second proposal.
    let balance = icrc1_balance(
        &state_machine,
        sns_ledger_canister_id,
        Account {
            owner: Principal::from(*WHALE),
            subaccount: None,
        },
    );
    let expected_balance_tokens = Tokens::new(
        2 * // TODO(NNS1-2982): Delete this line.
        2_222,
        0,
    )
    .unwrap();
    assert_eq!(balance, expected_balance_tokens);
}
