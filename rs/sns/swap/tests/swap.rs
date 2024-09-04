use crate::common::{
    buy_token, compute_multiple_successful_claim_swap_neurons_response,
    compute_single_successful_claim_swap_neurons_response, create_generic_cf_participants,
    create_generic_sns_neuron_recipes, create_successful_swap_neuron_basket_for_neurons_fund,
    create_successful_swap_neuron_basket_for_one_direct_participant,
    doubles::{
        spy_clients, spy_clients_exploding_root, LedgerExpect, NnsGovernanceClientCall,
        NnsGovernanceClientReply, SnsGovernanceClientCall, SnsGovernanceClientReply,
        SnsRootClientCall, SnsRootClientReply, SpyNnsGovernanceClient, SpySnsGovernanceClient,
        SpySnsRootClient,
    },
    get_account_balance_mock_ledger, get_snapshot_of_buyers_index_list, get_sns_balance,
    get_transfer_and_account_balance_mock_ledger, get_transfer_mock_ledger, i2principal_id_string,
    mock_stub, paginate_participants, successful_set_dapp_controllers_call_result,
    successful_set_mode_call_result, sweep, try_error_refund_err, try_error_refund_ok,
    verify_direct_participant_icp_balances, verify_direct_participant_sns_balances,
};
use assert_matches::assert_matches;
use candid::Principal;
use error_refund_icp_response::err::Type::Precondition;
use futures::{channel::mpsc, future::FutureExt, StreamExt};
use ic_base_types::{CanisterId, PrincipalId};
use ic_ledger_core::Tokens;
use ic_nervous_system_common::{
    assert_is_err, assert_is_ok, ledger::compute_neuron_staking_subaccount_bytes,
    NervousSystemError, E8, ONE_DAY_SECONDS, ONE_MONTH_SECONDS, START_OF_2022_TIMESTAMP_SECONDS,
};
use ic_nervous_system_common_test_keys::{
    TEST_USER1_PRINCIPAL, TEST_USER2_PRINCIPAL, TEST_USER3_PRINCIPAL,
};
use ic_nervous_system_common_test_utils::{
    drain_receiver_channel, InterleavingTestLedger, LedgerCall, LedgerControlMessage, LedgerReply,
    SpyLedger,
};
use ic_nervous_system_proto::pb::v1::Countries;
use ic_nervous_system_proto::pb::v1::Principals;
use ic_neurons_fund::{
    InvertibleFunction, MatchingFunction, NeuronsFundParticipationLimits,
    PolynomialMatchingFunction, SerializableFunction,
};
use ic_sns_governance::pb::v1::{
    claim_swap_neurons_request::{neuron_recipe, NeuronRecipe, NeuronRecipes},
    claim_swap_neurons_response::ClaimSwapNeuronsResult,
    governance, ClaimSwapNeuronsRequest, ClaimSwapNeuronsResponse, NeuronId, NeuronIds, SetMode,
    SetModeResponse,
};
use ic_sns_swap::{
    environment::CanisterClients,
    memory,
    pb::v1::{
        settle_neurons_fund_participation_response::NeuronsFundNeuron,
        sns_neuron_recipe::{ClaimedStatus, Investor, Investor::CommunityFund, NeuronAttributes},
        Lifecycle::{Aborted, Committed, Open, Pending, Unspecified},
        NeuronBasketConstructionParameters, SetDappControllersRequest, SetDappControllersResponse,
        *,
    },
    swap::{
        apportion_approximately_equally, principal_to_subaccount, CLAIM_SWAP_NEURONS_BATCH_SIZE,
        FIRST_PRINCIPAL_BYTES, NEURON_BASKET_MEMO_RANGE_START,
    },
    swap_builder::SwapBuilder,
};
use icp_ledger::DEFAULT_TRANSFER_FEE;
use icrc_ledger_types::icrc1::account::Account;
use maplit::btreemap;
use rust_decimal_macros::dec;
use std::{
    collections::{BTreeMap, HashSet},
    pin::Pin,
    str::FromStr,
    sync::{atomic, atomic::Ordering as AtomicOrdering},
    thread,
};

mod common;

// TODO(NNS1-1589): Unhack.
// use ic_sns_root::pb::v1::{SetDappControllersRequest, SetDappControllersResponse};

// For tests only. This does not imply that the canisters must have these IDs.
pub const SWAP_CANISTER_ID: CanisterId = CanisterId::from_u64(1152);

pub const NNS_GOVERNANCE_CANISTER_ID: CanisterId = CanisterId::from_u64(1185);
pub const ICP_LEDGER_CANISTER_ID: CanisterId = CanisterId::from_u64(1630);

pub const SNS_ROOT_CANISTER_ID: CanisterId = CanisterId::from_u64(4347);
pub const SNS_GOVERNANCE_CANISTER_ID: CanisterId = CanisterId::from_u64(1380);
pub const SNS_LEDGER_CANISTER_ID: CanisterId = CanisterId::from_u64(1571);

const OPEN_SNS_TOKEN_SWAP_PROPOSAL_ID: u64 = 746114;

const START_TIMESTAMP_SECONDS: u64 = START_OF_2022_TIMESTAMP_SECONDS + 42 * ONE_DAY_SECONDS;
const END_TIMESTAMP_SECONDS: u64 = START_TIMESTAMP_SECONDS + 7 * ONE_DAY_SECONDS;

fn neurons_fund_participation_limits() -> NeuronsFundParticipationLimits {
    NeuronsFundParticipationLimits {
        max_theoretical_neurons_fund_participation_amount_icp: dec!(333_000.0),
        contribution_threshold_icp: dec!(75_000.0),
        one_third_participation_milestone_icp: dec!(225_000.0),
        full_participation_milestone_icp: dec!(375_000.0),
    }
}

/// Returns a valid Init.
fn init_with_confirmation_text(confirmation_text: Option<String>) -> Init {
    let result = Init {
        nns_governance_canister_id: NNS_GOVERNANCE_CANISTER_ID.to_string(),
        sns_governance_canister_id: SNS_GOVERNANCE_CANISTER_ID.to_string(),
        sns_ledger_canister_id: SNS_LEDGER_CANISTER_ID.to_string(),
        icp_ledger_canister_id: ICP_LEDGER_CANISTER_ID.to_string(),
        sns_root_canister_id: SNS_ROOT_CANISTER_ID.to_string(),
        fallback_controller_principal_ids: vec![i2principal_id_string(1230578)],
        // Similar to, but different from values used in NNS.
        transaction_fee_e8s: Some(12_345),
        neuron_minimum_stake_e8s: Some(123_456_789),
        confirmation_text,
        restricted_countries: Some(Countries {
            iso_codes: vec!["CH".to_string()],
        }),
        min_participants: Some(1),
        min_direct_participation_icp_e8s: Some(10),
        max_direct_participation_icp_e8s: Some(100),
        min_participant_icp_e8s: Some(10),
        max_participant_icp_e8s: Some(20),
        swap_start_timestamp_seconds: None,
        swap_due_timestamp_seconds: Some(1234567),
        sns_token_e8s: Some(1000),
        neuron_basket_construction_parameters: Some(NeuronBasketConstructionParameters {
            count: 2,
            dissolve_delay_interval_seconds: 700,
        }),
        nns_proposal_id: Some(102),
        should_auto_finalize: Some(true),
        neurons_fund_participation_constraints: None,
        neurons_fund_participation: None,

        // The following fields are deprecated.
        min_icp_e8s: None,
        max_icp_e8s: None,
    };
    assert_is_ok!(result.validate());
    result
}

fn init() -> Init {
    init_with_confirmation_text(None)
}

fn init_with_neurons_fund_funding() -> Init {
    init_with_confirmation_text(None)
}

pub fn params() -> Params {
    let result = Params {
        min_participants: 3,
        min_icp_e8s: 1,
        max_icp_e8s: 1_000_000 * E8,
        min_direct_participation_icp_e8s: Some(1),
        max_direct_participation_icp_e8s: Some(1_000_000 * E8),
        min_participant_icp_e8s: 100 * E8,
        max_participant_icp_e8s: 100_000 * E8,
        swap_due_timestamp_seconds: END_TIMESTAMP_SECONDS,
        sns_token_e8s: 1_000_000 * E8,
        neuron_basket_construction_parameters: Some(NeuronBasketConstructionParameters {
            count: 3,
            dissolve_delay_interval_seconds: 7890000, // 3 months
        }),
        sale_delay_seconds: None,
    };
    assert_eq!(
        result.is_valid_if_initiated_at(START_TIMESTAMP_SECONDS),
        Ok(())
    );
    assert!(result.validate(&init()).is_ok());
    result
}

pub fn buyers() -> BTreeMap<String, BuyerState> {
    btreemap! {
        i2principal_id_string(1001) => BuyerState::new(50 * E8),
    }
}

fn create_generic_committed_swap() -> Swap {
    let init = init();

    let params = Params {
        min_participants: 1,
        neuron_basket_construction_parameters: Some(NeuronBasketConstructionParameters {
            count: 1,
            dissolve_delay_interval_seconds: ONE_MONTH_SECONDS,
        }),
        ..params()
    };
    Swap {
        lifecycle: Committed as i32,
        init: Some(init),
        params: Some(params.clone()),
        buyers: buyers(),
        cf_participants: vec![],
        neuron_recipes: vec![],
        open_sns_token_swap_proposal_id: Some(OPEN_SNS_TOKEN_SWAP_PROPOSAL_ID),
        finalize_swap_in_progress: None,
        decentralization_sale_open_timestamp_seconds: None,
        decentralization_swap_termination_timestamp_seconds: None,
        next_ticket_id: Some(0),
        purge_old_tickets_last_completion_timestamp_nanoseconds: Some(0),
        purge_old_tickets_next_principal: Some(FIRST_PRINCIPAL_BYTES.to_vec()),
        already_tried_to_auto_finalize: Some(false),
        auto_finalize_swap_response: None,
        direct_participation_icp_e8s: Some(50 * E8),
        neurons_fund_participation_icp_e8s: None,
    }
}

#[test]
fn fallback_controller_principal_ids_must_not_be_empty() {
    let mut init = init();
    init.fallback_controller_principal_ids.clear();
    assert!(init.validate().is_err(), "{:#?}", init);
}

#[test]
fn neuron_minimum_stake_e8s_is_required() {
    let init = Init {
        neuron_minimum_stake_e8s: None,
        ..init()
    };
    assert_is_err!(init.validate());
}

#[test]
fn transaction_fee_e8s_is_required() {
    let init = Init {
        transaction_fee_e8s: None,
        ..init()
    };
    assert_is_err!(init.validate());
}

#[test]
fn test_init() {
    let swap = SwapBuilder::new().build();
    assert!(swap.validate().is_ok());
}

fn now_fn(is_after: bool) -> u64 {
    if is_after {
        END_TIMESTAMP_SECONDS + 10
    } else {
        END_TIMESTAMP_SECONDS + 5
    }
}

/// Check that the behaviour is correct when the swap is due and the
/// minimum ICP hasn't been reached, i.e., the swap is aborted in this
/// case.
#[test]
fn test_min_icp() {
    let mut swap = SwapBuilder::new()
        .with_lifecycle(Open)
        .with_swap_start_due(Some(START_TIMESTAMP_SECONDS), Some(END_TIMESTAMP_SECONDS))
        .with_min_participants(2)
        .with_min_max_participant_icp(E8, 5 * E8)
        .with_min_max_direct_participation(5 * E8, 10 * E8)
        .build();

    // Cannot commit or abort, as the swap is not due yet.
    assert!(!swap.try_commit(END_TIMESTAMP_SECONDS - 1));
    assert!(!swap.try_abort(END_TIMESTAMP_SECONDS - 1));
    // Deposit 2 ICP from one buyer.
    assert!(swap
        .refresh_buyer_token_e8s(
            *TEST_USER1_PRINCIPAL,
            None,
            SWAP_CANISTER_ID,
            &mock_stub(vec![LedgerExpect::AccountBalance(
                Account {
                    owner: SWAP_CANISTER_ID.get().into(),
                    subaccount: Some(principal_to_subaccount(&TEST_USER1_PRINCIPAL.clone()))
                },
                Ok(Tokens::from_e8s(2 * E8))
            )])
        )
        .now_or_never()
        .unwrap()
        .is_ok());
    assert_eq!(
        swap.buyers
            .get(&TEST_USER1_PRINCIPAL.to_string())
            .unwrap()
            .amount_icp_e8s(),
        2 * E8
    );
    // Deposit 2 ICP from another buyer.
    assert!(swap
        .refresh_buyer_token_e8s(
            *TEST_USER2_PRINCIPAL,
            None,
            SWAP_CANISTER_ID,
            &mock_stub(vec![LedgerExpect::AccountBalance(
                Account {
                    owner: SWAP_CANISTER_ID.get().into(),
                    subaccount: Some(principal_to_subaccount(&TEST_USER2_PRINCIPAL.clone()))
                },
                Ok(Tokens::from_e8s(2 * E8))
            )])
        )
        .now_or_never()
        .unwrap()
        .is_ok());
    assert_eq!(
        swap.buyers
            .get(&TEST_USER2_PRINCIPAL.to_string())
            .unwrap()
            .amount_icp_e8s(),
        2 * E8
    );

    // Assert that the buyer list was updated in order
    let buyers_list = get_snapshot_of_buyers_index_list();
    assert_eq!(
        vec![*TEST_USER1_PRINCIPAL, *TEST_USER2_PRINCIPAL,],
        buyers_list
    );

    // There are now two participants with a total of 4 ICP.
    //
    // Cannot commit
    assert!(!swap.can_commit(END_TIMESTAMP_SECONDS));
    // This should now abort as the minimum hasn't been reached. This should not
    // commit.
    assert!(!swap.try_commit(END_TIMESTAMP_SECONDS));
    assert!(swap.try_abort(END_TIMESTAMP_SECONDS));
    assert_eq!(swap.lifecycle(), Aborted);
    {
        // "Sweep" all ICP, which should go back to the buyers.
        let SweepResult {
            success,
            failure,
            skipped,
            invalid,
            global_failures,
        } = swap
            .sweep_icp(
                now_fn,
                &mock_stub(vec![
                    LedgerExpect::TransferFunds(
                        2 * E8 - DEFAULT_TRANSFER_FEE.get_e8s(),
                        DEFAULT_TRANSFER_FEE.get_e8s(),
                        Some(principal_to_subaccount(&TEST_USER2_PRINCIPAL)),
                        Account {
                            owner: (*TEST_USER2_PRINCIPAL).into(),
                            subaccount: None,
                        },
                        0,
                        Ok(1066),
                    ),
                    LedgerExpect::TransferFunds(
                        2 * E8 - DEFAULT_TRANSFER_FEE.get_e8s(),
                        DEFAULT_TRANSFER_FEE.get_e8s(),
                        Some(principal_to_subaccount(&TEST_USER1_PRINCIPAL)),
                        Account {
                            owner: (*TEST_USER1_PRINCIPAL).into(),
                            subaccount: None,
                        },
                        0,
                        Ok(1067),
                    ),
                ]),
            )
            .now_or_never()
            .unwrap();
        assert_eq!(skipped, 0);
        assert_eq!(success, 2);
        assert_eq!(failure, 0);
        assert_eq!(invalid, 0);
        assert_eq!(global_failures, 0);
    }
}

/// Test going below the minimum and above the maximum ICP for a single participant.
#[test]
fn test_min_max_icp_per_buyer() {
    let mut swap = SwapBuilder::new()
        .with_sns_governance_canister_id(SNS_GOVERNANCE_CANISTER_ID)
        .with_lifecycle(Open)
        .with_swap_start_due(Some(START_TIMESTAMP_SECONDS), Some(END_TIMESTAMP_SECONDS))
        .with_min_participants(2)
        .with_min_max_participant_icp(E8, 5 * E8)
        .with_min_max_direct_participation(5 * E8, 10 * E8)
        .with_sns_tokens(200_000 * E8)
        .with_neuron_basket_count(3)
        .with_neurons_fund_participation()
        .build();

    assert_eq!(swap.lifecycle(), Open);
    // Cannot commit or abort, as the swap is not due yet.
    assert!(!swap.try_commit(END_TIMESTAMP_SECONDS - 1));
    assert!(!swap.try_abort(END_TIMESTAMP_SECONDS - 1));
    // Try to deposit 0.99999999 ICP, slightly less than the minimum.
    {
        let e = swap
            .refresh_buyer_token_e8s(
                *TEST_USER1_PRINCIPAL,
                None,
                SWAP_CANISTER_ID,
                &mock_stub(vec![LedgerExpect::AccountBalance(
                    Account {
                        owner: SWAP_CANISTER_ID.get().into(),
                        subaccount: Some(principal_to_subaccount(&TEST_USER1_PRINCIPAL.clone())),
                    },
                    Ok(Tokens::from_e8s(99999999)),
                )]),
            )
            .now_or_never()
            .unwrap();
        assert!(e.is_err());
        assert!(!swap.buyers.contains_key(&TEST_USER1_PRINCIPAL.to_string()));
    }
    // Try to deposit 6 ICP.
    {
        let e = swap
            .refresh_buyer_token_e8s(
                *TEST_USER1_PRINCIPAL,
                None,
                SWAP_CANISTER_ID,
                &mock_stub(vec![LedgerExpect::AccountBalance(
                    Account {
                        owner: SWAP_CANISTER_ID.get().into(),
                        subaccount: Some(principal_to_subaccount(&TEST_USER1_PRINCIPAL.clone())),
                    },
                    Ok(Tokens::from_e8s(6 * E8)),
                )]),
            )
            .now_or_never()
            .unwrap();
        assert!(e.is_ok());
        // Should only get 5 as that's the max per participant.
        assert_eq!(
            swap.buyers
                .get(&TEST_USER1_PRINCIPAL.to_string())
                .unwrap()
                .amount_icp_e8s(),
            5 * E8
        );
        // Make sure that a second refresh of the same principal doesn't change the balance.
        let e = swap
            .refresh_buyer_token_e8s(
                *TEST_USER1_PRINCIPAL,
                None,
                SWAP_CANISTER_ID,
                &mock_stub(vec![LedgerExpect::AccountBalance(
                    Account {
                        owner: SWAP_CANISTER_ID.get().into(),
                        subaccount: Some(principal_to_subaccount(&TEST_USER1_PRINCIPAL.clone())),
                    },
                    Ok(Tokens::from_e8s(10 * E8)),
                )]),
            )
            .now_or_never()
            .unwrap();
        assert!(e.is_ok());
        // Should still only be 5 as that's the max per participant.
        assert_eq!(
            swap.buyers
                .get(&TEST_USER1_PRINCIPAL.to_string())
                .unwrap()
                .amount_icp_e8s(),
            5 * E8
        );

        // Assert that the buyer list was updated in order
        let buyers_list = get_snapshot_of_buyers_index_list();
        assert_eq!(vec![*TEST_USER1_PRINCIPAL,], buyers_list);
    }
}

/// Test going over the total max ICP for the swap.
#[test]
fn test_max_icp() {
    let mut swap = SwapBuilder::new()
        .with_lifecycle(Open)
        .with_swap_start_due(Some(START_TIMESTAMP_SECONDS), Some(END_TIMESTAMP_SECONDS))
        .with_min_participants(2)
        .with_min_max_participant_icp(E8, 6 * E8)
        .with_min_max_direct_participation(5 * E8, 10 * E8)
        .build();

    // Cannot commit or abort, as the swap is not due yet.
    assert!(!swap.try_commit(END_TIMESTAMP_SECONDS - 1));
    assert!(!swap.try_abort(END_TIMESTAMP_SECONDS - 1));

    // Deposit 6 ICP from one buyer.
    assert!(swap
        .refresh_buyer_token_e8s(
            *TEST_USER1_PRINCIPAL,
            None,
            SWAP_CANISTER_ID,
            &mock_stub(vec![LedgerExpect::AccountBalance(
                Account {
                    owner: SWAP_CANISTER_ID.get().into(),
                    subaccount: Some(principal_to_subaccount(&TEST_USER1_PRINCIPAL.clone()))
                },
                Ok(Tokens::from_e8s(6 * E8))
            )])
        )
        .now_or_never()
        .unwrap()
        .is_ok());
    assert_eq!(
        swap.buyers
            .get(&TEST_USER1_PRINCIPAL.to_string())
            .unwrap()
            .amount_icp_e8s(),
        6 * E8
    );
    // Deposit 6 ICP from another buyer.
    assert!(swap
        .refresh_buyer_token_e8s(
            *TEST_USER2_PRINCIPAL,
            None,
            SWAP_CANISTER_ID,
            &mock_stub(vec![LedgerExpect::AccountBalance(
                Account {
                    owner: SWAP_CANISTER_ID.get().into(),
                    subaccount: Some(principal_to_subaccount(&TEST_USER2_PRINCIPAL.clone()))
                },
                Ok(Tokens::from_e8s(6 * E8))
            )])
        )
        .now_or_never()
        .unwrap()
        .is_ok());
    // But only 4 ICP is "accepted".
    assert_eq!(
        swap.buyers
            .get(&TEST_USER2_PRINCIPAL.to_string())
            .unwrap()
            .amount_icp_e8s(),
        4 * E8
    );
    // Can commit even if time isn't up as the max has been reached.
    assert!(swap.can_commit(END_TIMESTAMP_SECONDS - 1));
    // This should commit, and should not abort
    assert!(!swap.try_abort(END_TIMESTAMP_SECONDS - 1));
    assert!(swap.try_commit(END_TIMESTAMP_SECONDS - 1));
    assert_eq!(swap.lifecycle(), Committed);
    // Check that buyer balances are correct.
    verify_direct_participant_icp_balances(&swap, &TEST_USER1_PRINCIPAL, 6 * E8);
    verify_direct_participant_icp_balances(&swap, &TEST_USER2_PRINCIPAL, 4 * E8);
}

/// Test the happy path of a token swap. First 200k SNS tokens are sent. Then three buyers commit
/// 900 ICP, 600 ICP, and 400 ICP respectively. The Neurons' Fund commits 100 ICP from two
/// participants (one with two neurons and one with one neuron). Then the swap is committed and
/// the tokens distributed.
#[test]
fn test_scenario_happy() {
    let mut swap = SwapBuilder::new()
        .with_sns_governance_canister_id(SNS_GOVERNANCE_CANISTER_ID)
        .with_lifecycle(Open)
        .with_swap_start_due(Some(START_TIMESTAMP_SECONDS), Some(END_TIMESTAMP_SECONDS))
        .with_min_participants(3)
        .with_min_max_participant_icp(100 * E8, 100_000 * E8)
        .with_min_max_direct_participation(150 * E8, 2_000 * E8)
        .with_sns_tokens(200_000 * E8)
        .with_neuron_basket_count(3)
        .with_neurons_fund_participation()
        .build();

    assert_eq!(swap.lifecycle(), Open);
    assert_eq!(swap.sns_token_e8s().unwrap(), 200_000 * E8);
    // Cannot (re)-open, as already opened.
    assert!(!swap.can_open(END_TIMESTAMP_SECONDS));
    assert!(!swap.try_open(END_TIMESTAMP_SECONDS));
    // Cannot commit or abort, as the swap is not due yet.
    assert!(!swap.try_commit(END_TIMESTAMP_SECONDS - 1));
    assert!(!swap.try_abort(END_TIMESTAMP_SECONDS - 1));
    // Deposit 900 ICP from one buyer.
    assert!(swap
        .refresh_buyer_token_e8s(
            *TEST_USER1_PRINCIPAL,
            None,
            SWAP_CANISTER_ID,
            &mock_stub(vec![LedgerExpect::AccountBalance(
                Account {
                    owner: SWAP_CANISTER_ID.get().into(),
                    subaccount: Some(principal_to_subaccount(&TEST_USER1_PRINCIPAL))
                },
                Ok(Tokens::from_e8s(900 * E8))
            )])
        )
        .now_or_never()
        .unwrap()
        .is_ok());
    assert_eq!(
        swap.buyers
            .get(&TEST_USER1_PRINCIPAL.to_string())
            .unwrap()
            .amount_icp_e8s(),
        900 * E8
    );
    // Cannot commit or abort, as the swap is not due yet.
    assert!(!swap.try_commit(END_TIMESTAMP_SECONDS - 1));
    assert!(!swap.try_abort(END_TIMESTAMP_SECONDS - 1));
    // Deposit 600 ICP from another buyer.
    assert!(swap
        .refresh_buyer_token_e8s(
            *TEST_USER2_PRINCIPAL,
            None,
            SWAP_CANISTER_ID,
            &mock_stub(vec![LedgerExpect::AccountBalance(
                Account {
                    owner: SWAP_CANISTER_ID.get().into(),
                    subaccount: Some(principal_to_subaccount(&TEST_USER2_PRINCIPAL.clone()))
                },
                Ok(Tokens::from_e8s(600 * E8))
            )])
        )
        .now_or_never()
        .unwrap()
        .is_ok());
    assert_eq!(
        swap.buyers
            .get(&TEST_USER2_PRINCIPAL.to_string())
            .unwrap()
            .amount_icp_e8s(),
        600 * E8
    );
    // Now there are two participants. If the time was up, the swap
    // could be aborted, but not committed...
    {
        let mut abort_swap = swap.clone();
        assert!(!abort_swap.try_commit(END_TIMESTAMP_SECONDS));
        assert!(abort_swap.try_abort(END_TIMESTAMP_SECONDS));
        assert_eq!(abort_swap.lifecycle(), Aborted);
    }
    // Deposit 400 ICP from a third buyer.
    assert!(swap
        .refresh_buyer_token_e8s(
            *TEST_USER3_PRINCIPAL,
            None,
            SWAP_CANISTER_ID,
            &mock_stub(vec![LedgerExpect::AccountBalance(
                Account {
                    owner: SWAP_CANISTER_ID.get().into(),
                    subaccount: Some(principal_to_subaccount(&TEST_USER3_PRINCIPAL.clone()))
                },
                Ok(Tokens::from_e8s(400 * E8))
            )])
        )
        .now_or_never()
        .unwrap()
        .is_ok());
    assert_eq!(
        swap.buyers
            .get(&TEST_USER3_PRINCIPAL.to_string())
            .unwrap()
            .amount_icp_e8s(),
        400 * E8
    );
    // We should now have a sufficient number of participants.
    assert!(swap.sufficient_participation());
    // Cannot commit if the swap is not due.
    assert!(!swap.can_commit(END_TIMESTAMP_SECONDS - 1));

    // Cannot open while still open.
    assert_eq!(swap.lifecycle(), Open);
    assert!(!swap.can_open(END_TIMESTAMP_SECONDS));
    // Can commit if the swap is due.
    assert!(swap.can_commit(END_TIMESTAMP_SECONDS));
    // This should commit, but not abort...
    assert!(!swap.try_abort(END_TIMESTAMP_SECONDS));
    assert!(swap.try_commit(END_TIMESTAMP_SECONDS));
    assert_eq!(swap.lifecycle(), Committed);
    assert_eq!(
        swap.decentralization_swap_termination_timestamp_seconds,
        Some(END_TIMESTAMP_SECONDS)
    );
    // Should not be able to re-open after commit.
    assert!(!swap.can_open(END_TIMESTAMP_SECONDS));
    assert!(!swap.try_open(END_TIMESTAMP_SECONDS));

    // Each tuple represents (user principal ID, participation ICP e8s, ICP transfer success).
    let direct_participants = vec![
        (*TEST_USER2_PRINCIPAL, 600 * E8, false),
        (*TEST_USER3_PRINCIPAL, 400 * E8, true),
        (*TEST_USER1_PRINCIPAL, 900 * E8, true),
    ];

    // Each pair represents (NNS neuron ID, controller hotkey principal ID, participation ICP e8s).
    let neurons_fund_participants = [
        (0x91_u64, *TEST_USER1_PRINCIPAL, 50 * E8),
        (0x92_u64, *TEST_USER1_PRINCIPAL, 30 * E8),
        (0x93_u64, *TEST_USER2_PRINCIPAL, 20 * E8),
    ];

    let nns_governance_principal_id = swap.init.as_ref().unwrap().nns_governance_or_panic().get();

    let neurons_per_investor = swap
        .params
        .as_ref()
        .unwrap()
        .neuron_basket_construction_parameters
        .as_ref()
        .unwrap()
        .count;

    // Check that buyer balances are correct. Total SNS balance is 200k and total ICP is 2k.
    for (direct_participant_principal_id, participation_amount_icp_e8s, _) in &direct_participants {
        verify_direct_participant_icp_balances(
            &swap,
            direct_participant_principal_id,
            *participation_amount_icp_e8s,
        );
    }

    let mut finalize_swap_response = FinalizeSwapResponse::default();

    // Test `Swap.sweep_icp` in presence of a Ledger transfer error.
    {
        let expected_icp_ledger_transactions: Vec<_> = direct_participants
            .iter()
            .enumerate()
            .map(
                |(
                    i,
                    (
                        direct_participant_principal_id,
                        participation_amount_icp_e8s,
                        transfer_success,
                    ),
                )| {
                    let fee_icp_e8s = DEFAULT_TRANSFER_FEE.get_e8s();
                    LedgerExpect::TransferFunds(
                        *participation_amount_icp_e8s - fee_icp_e8s,
                        DEFAULT_TRANSFER_FEE.get_e8s(),
                        Some(principal_to_subaccount(direct_participant_principal_id)),
                        Account {
                            owner: SNS_GOVERNANCE_CANISTER_ID.get().into(),
                            subaccount: None,
                        },
                        0,
                        if *transfer_success {
                            Ok(i as u64)
                        } else {
                            Err(i as i32)
                        },
                    )
                },
            )
            .collect();
        let icp_ledger_with_one_failing_transaction = mock_stub(expected_icp_ledger_transactions);
        let icp_sweep_result = swap
            .sweep_icp(now_fn, &icp_ledger_with_one_failing_transaction)
            .now_or_never()
            .unwrap();
        assert_eq!(
            icp_sweep_result,
            SweepResult {
                success: 2,
                failure: 1,
                skipped: 0,
                invalid: 0,
                global_failures: 0,
            }
        );
        finalize_swap_response.set_sweep_icp_result(icp_sweep_result);

        let expected_retried_icp_ledger_transactions: Vec<_> = direct_participants
            .iter()
            .enumerate()
            .filter_map(
                |(
                    i,
                    (
                        direct_participant_principal_id,
                        participation_amount_icp_e8s,
                        transfer_success,
                    ),
                )| {
                    if *transfer_success {
                        // This transfer has already succeeded.
                        None
                    } else {
                        let fee_icp_e8s = DEFAULT_TRANSFER_FEE.get_e8s();
                        let ledger_expect = LedgerExpect::TransferFunds(
                            *participation_amount_icp_e8s - fee_icp_e8s,
                            DEFAULT_TRANSFER_FEE.get_e8s(),
                            Some(principal_to_subaccount(direct_participant_principal_id)),
                            Account {
                                owner: SNS_GOVERNANCE_CANISTER_ID.get().into(),
                                subaccount: None,
                            },
                            0,
                            Ok(i as u64),
                        );
                        Some(ledger_expect)
                    }
                },
            )
            .collect();
        let icp_ledger_with_succeeding_repeated_transactions =
            mock_stub(expected_retried_icp_ledger_transactions);
        let icp_sweep_result = swap
            .sweep_icp(now_fn, &icp_ledger_with_succeeding_repeated_transactions)
            .now_or_never()
            .unwrap();
        assert_eq!(
            icp_sweep_result,
            SweepResult {
                success: 1,
                failure: 0,
                skipped: 2,
                invalid: 0,
                global_failures: 0,
            }
        );
        finalize_swap_response.set_sweep_icp_result(icp_sweep_result);
    }

    // Invoke `Swap.settle_fund_participation`, modelling a situation in which the Neurons' Fund
    // decided to participate in the swap with a total of 100 ICP. This should result in three more
    // SNS neuron baskets that will need to be created, so overall there should be 6 baskets,
    // `neurons_per_investor` neurons each. Finally, test that `Swap.create_sns_neuron_recipes`
    // produces the 18 expected neurons.
    let nns_governance = {
        let mut nns_governance = SpyNnsGovernanceClient::new(vec![
            NnsGovernanceClientReply::SettleNeuronsFundParticipation(
                SettleNeuronsFundParticipationResponse {
                    result: Some(settle_neurons_fund_participation_response::Result::Ok(
                        settle_neurons_fund_participation_response::Ok {
                            neurons_fund_neuron_portions: neurons_fund_participants
                                .iter()
                                .map(
                                    |(
                                        nns_neuron_id,
                                        neurons_fund_participant_principal_id,
                                        participation_amount_icp_e8s,
                                    )| {
                                        NeuronsFundNeuron {
                                            nns_neuron_id: Some(*nns_neuron_id),
                                            amount_icp_e8s: Some(*participation_amount_icp_e8s),
                                            controller: Some(
                                                *neurons_fund_participant_principal_id,
                                            ),
                                            hotkeys: Some(Principals::from(Vec::new())),
                                            is_capped: Some(false),
                                        }
                                    },
                                )
                                .collect(),
                        },
                    )),
                },
            ),
        ]);

        finalize_swap_response.set_settle_neurons_fund_participation_result(
            swap.settle_neurons_fund_participation(&mut nns_governance)
                .now_or_never()
                .unwrap(),
        );

        println!(
            "finalize_swap_response.settle_neurons_fund_participation_result = {:#?}",
            finalize_swap_response
                .settle_neurons_fund_participation_result
                .unwrap()
        );

        assert_eq!(
            swap.create_sns_neuron_recipes(),
            SweepResult {
                success: 18,
                failure: 0,
                skipped: 0,
                invalid: 0,
                global_failures: 0,
            }
        );

        nns_governance
    };

    // Now test Swap finalization end-to-end.
    let expected_icp_ledger_transactions: Vec<_> = direct_participants
        .iter()
        .enumerate()
        .map(
            |(i, (direct_participant_principal_id, participation_amount_icp_e8s, _))| {
                let fee_icp_e8s = DEFAULT_TRANSFER_FEE.get_e8s();
                LedgerExpect::TransferFunds(
                    *participation_amount_icp_e8s - fee_icp_e8s,
                    DEFAULT_TRANSFER_FEE.get_e8s(),
                    Some(principal_to_subaccount(direct_participant_principal_id)),
                    Account {
                        owner: SNS_GOVERNANCE_CANISTER_ID.get().into(),
                        subaccount: None,
                    },
                    0,
                    Ok(i as u64),
                )
            },
        )
        .collect();

    let expected_sns_ledger_transactions: Vec<_> = direct_participants
        .iter()
        .cloned()
        .map(
            |(direct_participant_principal_id, participation_amount_icp_e8s, _)| {
                (
                    direct_participant_principal_id,
                    participation_amount_icp_e8s,
                    None::<usize>,
                )
            },
        )
        .chain(
            // Neurons' Fund neurons participate from the name of NNS Governance.
            neurons_fund_participants.iter().cloned().enumerate().map(
                |(nf_neuron_counter, (_, _, participation_amount_icp_e8s))| {
                    (
                        nns_governance_principal_id,
                        participation_amount_icp_e8s,
                        Some(nf_neuron_counter),
                    )
                },
            ),
        )
        .enumerate()
        .flat_map(
            |(i, (participant_principal_id, participation_amount_icp_e8s, nf_neuron_counter))| {
                // We have 100 SNS tokens per ICP; we have `neurons_per_investor` neurons per basket.
                let total_amount_sns_e8s = 100 * participation_amount_icp_e8s;
                apportion_approximately_equally(total_amount_sns_e8s, neurons_per_investor)
                    .unwrap()
                    .into_iter()
                    .enumerate()
                    .map(move |(memo_increment, sns_neuron_amount_sns_e8s)| {
                        let memo = if let Some(nf_neuron_counter) = nf_neuron_counter {
                            // This is a Neurons' Fund neuron.
                            NEURON_BASKET_MEMO_RANGE_START
                                + neurons_per_investor * (nf_neuron_counter as u64)
                                + (memo_increment as u64)
                        } else {
                            // This is a direct participant's neuron.
                            NEURON_BASKET_MEMO_RANGE_START + (memo_increment as u64)
                        };
                        LedgerExpect::TransferFunds(
                            sns_neuron_amount_sns_e8s,
                            0,
                            None,
                            Account {
                                owner: SNS_GOVERNANCE_CANISTER_ID.get().into(),
                                subaccount: Some(compute_neuron_staking_subaccount_bytes(
                                    participant_principal_id,
                                    memo,
                                )),
                            },
                            0,
                            Ok(i as u64),
                        )
                    })
            },
        )
        .collect();

    let expected_successful_swap_neuron_baskets: Vec<_> = direct_participants
        .into_iter()
        .flat_map(|(direct_participant_principal_id, _, _)| {
            create_successful_swap_neuron_basket_for_one_direct_participant(
                direct_participant_principal_id,
                neurons_per_investor,
            )
        })
        .chain(create_successful_swap_neuron_basket_for_neurons_fund(
            nns_governance_principal_id,
            neurons_fund_participants.len(),
            neurons_per_investor,
        ))
        .collect();

    let expected_sns_governance_claim_swap_neurons_calls = vec![
        SnsGovernanceClientReply::ClaimSwapNeurons(ClaimSwapNeuronsResponse::new(
            expected_successful_swap_neuron_baskets,
        )),
        SnsGovernanceClientReply::SetMode(SetModeResponse {}),
    ];

    // Check neuron recipes before finalization.
    for recipe in &swap.neuron_recipes {
        assert_eq!(
            ClaimedStatus::try_from(recipe.claimed_status.unwrap()).unwrap(),
            ClaimedStatus::Pending,
            "Recipe for {:?} does not have the correct claim status ({:?})",
            recipe.investor,
            recipe.claimed_status,
        );
    }

    let mut environment = {
        // Model "Sweeping" all ICP, going to the governance canister. Mock one failure.
        let icp_ledger = mock_stub(expected_icp_ledger_transactions);
        let sns_ledger = mock_stub(expected_sns_ledger_transactions);
        let sns_governance =
            SpySnsGovernanceClient::new(expected_sns_governance_claim_swap_neurons_calls);
        CanisterClients {
            sns_root: SpySnsRootClient::new(vec![
                // Add a mock reply of a successful call to SNS Root
                SnsRootClientReply::successful_set_dapp_controllers(),
            ]),
            sns_governance,
            nns_governance,
            icp_ledger,
            sns_ledger,
        }
    };

    {
        let response = swap
            .finalize(now_fn, &mut environment)
            .now_or_never()
            .unwrap();
        if let Some(sweep_sns_result) = response.sweep_sns_result {
            assert_eq!(
                sweep_sns_result,
                SweepResult {
                    success: 18,
                    failure: 0,
                    skipped: 0,
                    invalid: 0,
                    global_failures: 0,
                }
            );
        } else {
            panic!("Finalization failed: {:#?}", response);
        }
    };

    verify_direct_participant_sns_balances(&swap, &TEST_USER1_PRINCIPAL, 90000 * E8);
    verify_direct_participant_sns_balances(&swap, &TEST_USER2_PRINCIPAL, 60000 * E8);
    verify_direct_participant_sns_balances(&swap, &TEST_USER3_PRINCIPAL, 40000 * E8);

    for (i, recipe) in swap.neuron_recipes.iter().enumerate() {
        assert_eq!(
            ClaimedStatus::try_from(recipe.claimed_status.unwrap()).unwrap(),
            ClaimedStatus::Success,
            "Recipe for investor #{} ({:?}) does not have the correct claim status ({:?})",
            i,
            recipe.investor,
            recipe.claimed_status,
        );
    }

    let sns_transaction_fee_e8s = *swap
        .init_or_panic()
        .transaction_fee_e8s
        .as_ref()
        .expect("Transaction fee not known.");

    for recipe in &swap.neuron_recipes {
        let sns = recipe.sns.as_ref().unwrap();
        assert_eq!(
            sns.amount_transferred_e8s.unwrap(),
            sns.amount_e8s - sns_transaction_fee_e8s
        );
        assert_eq!(sns.transfer_fee_paid_e8s.unwrap(), sns_transaction_fee_e8s);
    }
}

#[tokio::test]
async fn test_finalize_swap_ok_matched_funding() {
    // Step 1: Prepare the world.

    let buyers = btreemap! {
        i2principal_id_string(1001) => BuyerState::new(50 * E8),
        i2principal_id_string(1002) => BuyerState::new(30 * E8),
        i2principal_id_string(1003) => BuyerState::new(20 * E8),
    };
    let mut swap = SwapBuilder::new()
        .with_nns_governance_canister_id(NNS_GOVERNANCE_CANISTER_ID)
        .with_sns_governance_canister_id(SNS_GOVERNANCE_CANISTER_ID)
        .with_sns_root_canister_id(SNS_ROOT_CANISTER_ID)
        .with_nns_proposal_id(OPEN_SNS_TOKEN_SWAP_PROPOSAL_ID)
        .with_lifecycle(Open)
        .with_swap_start_due(Some(START_TIMESTAMP_SECONDS), Some(END_TIMESTAMP_SECONDS))
        .with_min_participants(1)
        .with_min_max_participant_icp(1, 100)
        .with_min_max_direct_participation(36_000, 45_000)
        .with_sns_tokens(10 * E8)
        .with_neuron_basket_count(3)
        .with_neuron_basket_dissolve_delay_interval(7890000) // 3 months
        .with_neurons_fund_participation()
        .with_neurons_fund_participation_constraints(NeuronsFundParticipationConstraints {
            min_direct_participation_threshold_icp_e8s: Some(36_000 * E8),
            max_neurons_fund_participation_icp_e8s: Some(100_000),
            coefficient_intervals: vec![LinearScalingCoefficient {
                from_direct_participation_icp_e8s: Some(0),
                to_direct_participation_icp_e8s: Some(u64::MAX),
                slope_numerator: Some(1),
                slope_denominator: Some(1),
                intercept_icp_e8s: Some(0),
            }],
            ideal_matched_participation_function: None,
        })
        .with_buyers(buyers.clone())
        .build();

    swap.update_derived_fields();

    // Step 1.5: Attempt to auto-finalize the swap. It should not work, since
    // the swap is open. Not only should it not work, it should do nothing.
    assert_eq!(swap.lifecycle(), Open);
    assert_eq!(swap.already_tried_to_auto_finalize, Some(false));
    let auto_finalization_error = swap
        .try_auto_finalize(now_fn, &mut spy_clients_exploding_root())
        .await
        .unwrap_err();
    let allowed_to_finalize_error = swap.can_finalize().unwrap_err();
    assert_eq!(auto_finalization_error, allowed_to_finalize_error);
    assert_eq!(swap.already_tried_to_auto_finalize, Some(false));
    assert_eq!(swap.auto_finalize_swap_response, None);

    // Step 2: Commit the swap
    assert!(swap.try_commit(END_TIMESTAMP_SECONDS));
    assert_eq!(swap.lifecycle(), Committed);
    assert_eq!(
        swap.decentralization_swap_termination_timestamp_seconds,
        Some(END_TIMESTAMP_SECONDS)
    );

    // We need to create a function to generate the clients, so we can get them
    // twice: once for when we call `finalize` and once for when we call
    // `try_auto_finalize`
    pub fn get_clients() -> CanisterClients<
        SpySnsRootClient,
        SpySnsGovernanceClient,
        SpyLedger,
        SpyLedger,
        SpyNnsGovernanceClient,
    > {
        CanisterClients {
            sns_governance: SpySnsGovernanceClient::new(vec![
                SnsGovernanceClientReply::ClaimSwapNeurons(ClaimSwapNeuronsResponse::new(
                    [
                        create_successful_swap_neuron_basket_for_one_direct_participant(
                            PrincipalId::new_user_test_id(1001),
                            3,
                        ),
                        create_successful_swap_neuron_basket_for_one_direct_participant(
                            PrincipalId::new_user_test_id(1002),
                            3,
                        ),
                        create_successful_swap_neuron_basket_for_one_direct_participant(
                            PrincipalId::new_user_test_id(1003),
                            3,
                        ),
                        create_successful_swap_neuron_basket_for_one_direct_participant(
                            NNS_GOVERNANCE_CANISTER_ID.get(),
                            3,
                        ),
                    ]
                    .concat(),
                )),
                SnsGovernanceClientReply::SetMode(SetModeResponse {}),
            ]),
            // Mock 3 successful ICP Ledger::transfer_funds calls
            icp_ledger: SpyLedger::new(vec![
                LedgerReply::TransferFunds(Ok(1000)),
                LedgerReply::TransferFunds(Ok(1001)),
                LedgerReply::TransferFunds(Ok(1002)),
            ]),
            sns_ledger: {
                // Mock 12 successful SNS Ledger::transfer_funds calls (3 direct, 1 nf)
                let sns_ledger_reply_calls =
                    (0..12).map(|i| LedgerReply::TransferFunds(Ok(i))).collect();
                SpyLedger::new(sns_ledger_reply_calls)
            },
            // Mock 1 successful call to NNS governance settle_nf
            nns_governance: SpyNnsGovernanceClient::new(vec![
                NnsGovernanceClientReply::SettleNeuronsFundParticipation(
                    SettleNeuronsFundParticipationResponse {
                        result: Some(settle_neurons_fund_participation_response::Result::Ok(
                            settle_neurons_fund_participation_response::Ok {
                                neurons_fund_neuron_portions: vec![NeuronsFundNeuron {
                                    nns_neuron_id: Some(43),
                                    amount_icp_e8s: Some(100 * E8),
                                    controller: Some(PrincipalId::new_user_test_id(1)),
                                    hotkeys: Some(Principals::from(Vec::new())),
                                    is_capped: Some(true),
                                }],
                            },
                        )),
                    },
                ),
            ]),
            sns_root: SpySnsRootClient::new(vec![
                SnsRootClientReply::successful_set_dapp_controllers(),
            ]),
        }
    }

    let mut clients = get_clients();

    // Step 3: Run the code under test.
    // We'll test finalize and try_auto_finalize and make sure they have the
    // same result.
    let result = {
        // Clone swap & clients so we can run `finalize` and `try_auto_finalize` separately
        let mut try_auto_finalize_swap = swap.clone();
        let mut try_auto_finalize_clients = get_clients();

        // Call finalize on swap
        let finalize_result = swap.finalize(now_fn, &mut clients).await;

        // Call try_auto_finalize on the cloned version of swap
        assert_eq!(
            try_auto_finalize_swap.already_tried_to_auto_finalize,
            Some(false)
        );
        let try_auto_finalize_result = try_auto_finalize_swap
            .try_auto_finalize(now_fn, &mut try_auto_finalize_clients)
            .await
            .unwrap();
        assert_eq!(
            try_auto_finalize_swap.already_tried_to_auto_finalize,
            Some(true)
        );
        assert_eq!(swap.auto_finalize_swap_response, None);

        // Try auto-finalizing again. It won't work since an attempt has already
        // been made to auto-finalize the swap
        let auto_finalization_error = try_auto_finalize_swap
            .try_auto_finalize(now_fn, &mut try_auto_finalize_clients)
            .await
            .unwrap_err();
        assert!(
            auto_finalization_error.contains("an attempt has already been made to auto-finalize")
        );

        // Assert that finalization and auto-finalization had the same result
        assert_eq!(
            finalize_result, try_auto_finalize_result,
            "the result from finalization and auto-finalization should be the same"
        );

        // Assert that finalization and auto-finalization performed the same calls
        // to SNS Governance, NNS Governance, and SNS Root.
        assert_eq!(
            clients.sns_governance.calls, try_auto_finalize_clients.sns_governance.calls,
            "the calls to SNS governance should be the same"
        );
        assert_eq!(
            clients.nns_governance.calls, try_auto_finalize_clients.nns_governance.calls,
            "the calls to NNS governance should be the same"
        );
        assert_eq!(
            clients.sns_root.observed_calls, try_auto_finalize_clients.sns_root.observed_calls,
            "the calls to SNS root should be the same"
        );

        finalize_result
    };

    // Step 4: Inspect the results.
    {
        assert_eq!(
            result,
            FinalizeSwapResponse {
                sweep_icp_result: Some(SweepResult {
                    success: 3,
                    failure: 0,
                    skipped: 0,
                    invalid: 0,
                    global_failures: 0,
                }),
                sweep_sns_result: Some(SweepResult {
                    success: 12,
                    failure: 0,
                    skipped: 0,
                    invalid: 0,
                    global_failures: 0,
                }),
                claim_neuron_result: Some(SweepResult {
                    success: 12,
                    failure: 0,
                    skipped: 0,
                    invalid: 0,
                    global_failures: 0,
                }),
                create_sns_neuron_recipes_result: Some(SweepResult {
                    success: 12,
                    failure: 0,
                    skipped: 0,
                    invalid: 0,
                    global_failures: 0,
                }),
                set_mode_call_result: Some(successful_set_mode_call_result()),
                set_dapp_controllers_call_result: Some(
                    successful_set_dapp_controllers_call_result()
                ),
                settle_neurons_fund_participation_result: Some(
                    SettleNeuronsFundParticipationResult {
                        possibility: Some(
                            settle_neurons_fund_participation_result::Possibility::Ok(
                                settle_neurons_fund_participation_result::Ok {
                                    neurons_fund_participation_icp_e8s: Some(100 * E8),
                                    neurons_fund_neurons_count: Some(1),
                                }
                            )
                        ),
                    }
                ),
                error_message: None,
                // Deprecated field.
                settle_community_fund_participation_result: None,
            },
        );

        // Check that root was told to take sole control of the dapp controllers.
        assert_eq!(
            clients.sns_root.observed_calls,
            vec![SnsRootClientCall::set_dapp_controllers(
                None,
                vec![SNS_ROOT_CANISTER_ID.get()],
            )]
        );
    }

    // Assert that do_finalize_swap created neurons.
    assert_eq!(
        clients.sns_governance.calls.len(),
        2,
        "{:#?}",
        clients.sns_governance.calls
    );

    let neuron_controllers = clients
        .sns_governance
        .calls
        .iter()
        .filter_map(|sns_governance_client_call| {
            use common::doubles::SnsGovernanceClientCall as Call;
            match sns_governance_client_call {
                Call::ManageNeuron(_) => None,
                Call::SetMode(_) => None,
                Call::ClaimSwapNeurons(claim_swap_neurons_request) => {
                    Some(claim_swap_neurons_request)
                }
            }
        })
        .flat_map(|b| b.neuron_recipes.clone().unwrap().neuron_recipes)
        .map(|neuron_distribution| neuron_distribution.controller.as_ref().unwrap().to_string())
        .collect::<HashSet<_>>();
    assert_eq!(
        neuron_controllers,
        swap.buyers
            .keys()
            .cloned()
            .chain(vec![NNS_GOVERNANCE_CANISTER_ID.get().to_string()])
            .collect::<HashSet<String>>()
    );
    // Assert that SNS governance was set to normal mode.
    {
        let calls = &clients.sns_governance.calls;
        let last_call = &calls[calls.len() - 1];
        assert_eq!(
            last_call,
            &SnsGovernanceClientCall::SetMode(SetMode {
                mode: governance::Mode::Normal as i32,
            }),
        );
    }

    // Assert that ICP and SNS tokens were sent.
    let sns_transaction_fee_e8s = *swap
        .init_or_panic()
        .transaction_fee_e8s
        .as_ref()
        .expect("Transaction fee not known.");
    let icp_ledger_calls = clients.icp_ledger.get_calls_snapshot();
    assert_eq!(icp_ledger_calls.len(), 3, "{:#?}", icp_ledger_calls);
    for call in icp_ledger_calls.iter() {
        let (&fee_e8s, &memo) = match call {
            LedgerCall::TransferFundsICRC1 { fee_e8s, memo, .. } => (fee_e8s, memo),
            call => panic!("Unexpected call on the queue: {:?}", call),
        };

        assert_eq!(fee_e8s, DEFAULT_TRANSFER_FEE.get_e8s(), "{:#?}", call);
        assert_eq!(memo, 0, "{:#?}", call);
    }

    let sns_ledger_calls = clients.sns_ledger.get_calls_snapshot();
    assert_eq!(sns_ledger_calls.len(), 12, "{:#?}", sns_ledger_calls);
    for call in sns_ledger_calls.iter() {
        let (&fee_e8s, &memo) = match call {
            LedgerCall::TransferFundsICRC1 { fee_e8s, memo, .. } => (fee_e8s, memo),
            call => panic!("Unexpected call on the queue: {:?}", call),
        };

        assert_eq!(fee_e8s, sns_transaction_fee_e8s, "{:#?}", call);
        assert_eq!(memo, 0, "{:#?}", call);
    }

    // ICP should be sent to SNS governance (from various swap subaccounts.)
    let expected_to = Account {
        owner: SNS_GOVERNANCE_CANISTER_ID.into(),
        subaccount: None,
    };
    let expected_icp_ledger_calls = buyers
        .iter()
        .map(|(buyer, buyer_state)| {
            let icp_amount_e8s = buyer_state.icp.as_ref().unwrap().amount_e8s;
            let from_subaccount = Some(principal_to_subaccount(
                &PrincipalId::from_str(buyer).unwrap(),
            ));
            let amount_e8s = icp_amount_e8s - DEFAULT_TRANSFER_FEE.get_e8s();
            LedgerCall::TransferFundsICRC1 {
                amount_e8s,
                fee_e8s: DEFAULT_TRANSFER_FEE.get_e8s(),
                from_subaccount,
                to: expected_to,
                memo: 0,
            }
        })
        .collect::<Vec<_>>();
    let actual_icp_ledger_calls = icp_ledger_calls;
    assert_eq!(actual_icp_ledger_calls, expected_icp_ledger_calls);
    let neuron_basket_transfer_fund_calls =
        |amount_sns_tokens_e8s: u64, count: u64, buyer: PrincipalId| -> Vec<LedgerCall> {
            let split_amount =
                apportion_approximately_equally(amount_sns_tokens_e8s, count).unwrap();
            split_amount
                .iter()
                .enumerate()
                .map(|(ledger_account_memo, amount)| {
                    let to = Account {
                        owner: SNS_GOVERNANCE_CANISTER_ID.into(),
                        subaccount: Some(compute_neuron_staking_subaccount_bytes(
                            buyer,
                            ledger_account_memo as u64 + NEURON_BASKET_MEMO_RANGE_START,
                        )),
                    };
                    LedgerCall::TransferFundsICRC1 {
                        amount_e8s: amount - sns_transaction_fee_e8s,
                        fee_e8s: sns_transaction_fee_e8s,
                        from_subaccount: None,
                        to,
                        memo: 0,
                    }
                })
                .collect()
        };

    let count = swap
        .params
        .as_ref()
        .unwrap()
        .neuron_basket_construction_parameters
        .as_ref()
        .unwrap()
        .count;

    let mut expected_sns_ledger_calls: Vec<LedgerCall> = vec![];

    expected_sns_ledger_calls.append(&mut neuron_basket_transfer_fund_calls(
        E8,
        count,
        PrincipalId::new_user_test_id(1003),
    ));
    expected_sns_ledger_calls.append(&mut neuron_basket_transfer_fund_calls(
        250_000_000,
        count,
        PrincipalId::new_user_test_id(1001),
    ));
    expected_sns_ledger_calls.append(&mut neuron_basket_transfer_fund_calls(
        150_000_000,
        count,
        PrincipalId::new_user_test_id(1002),
    ));

    expected_sns_ledger_calls.append(&mut neuron_basket_transfer_fund_calls(
        5 * E8,
        count,
        NNS_GOVERNANCE_CANISTER_ID.get(),
    ));
    let actual_sns_ledger_calls = sns_ledger_calls;
    assert_eq!(actual_sns_ledger_calls, expected_sns_ledger_calls);

    // Assert that NNS governance was notified of positive outcome (i.e. ended in Committed).
    {
        use settle_neurons_fund_participation_request::{Committed, Result};
        assert_eq!(
            clients.nns_governance.calls,
            vec![NnsGovernanceClientCall::SettleNeuronsFundParticipation(
                SettleNeuronsFundParticipationRequest {
                    nns_proposal_id: Some(OPEN_SNS_TOKEN_SWAP_PROPOSAL_ID),
                    result: Some(Result::Committed(Committed {
                        sns_governance_canister_id: Some(SNS_GOVERNANCE_CANISTER_ID.into()),
                        total_direct_participation_icp_e8s: Some(100 * E8),
                        // TODO
                        total_neurons_fund_participation_icp_e8s: Some(0),
                    })),
                }
            )]
        );
    }

    assert_eq!(buyers.len(), 3);
    buyers
        .iter()
        .for_each(|(principal_string, buyer_state_initial)| {
            // Assert that buyer states are correctly updated
            let req = GetBuyerStateRequest {
                principal_id: Some(PrincipalId::from_str(principal_string).unwrap()),
            };
            let response = swap.get_buyer_state(&req);

            let initial_transferable_amount = buyer_state_initial.icp.as_ref().unwrap();
            let expected_amount_e8s = initial_transferable_amount.amount_e8s;
            let fee_e8s = DEFAULT_TRANSFER_FEE.get_e8s();
            let expected_amount_committed_e8s = expected_amount_e8s - fee_e8s;
            assert_eq!(
                response.buyer_state.unwrap(),
                BuyerState {
                    icp: Some(TransferableAmount {
                        amount_e8s: expected_amount_e8s,
                        transfer_start_timestamp_seconds: END_TIMESTAMP_SECONDS + 5,
                        transfer_success_timestamp_seconds: END_TIMESTAMP_SECONDS + 10,
                        amount_transferred_e8s: Some(expected_amount_committed_e8s),
                        transfer_fee_paid_e8s: Some(fee_e8s)
                    }),
                    has_created_neuron_recipes: Some(true),
                }
            );
        });
}

#[tokio::test]
async fn test_finalize_swap_abort_matched_funding() {
    // Step 1: Prepare the world.

    let buyers = btreemap! {
        i2principal_id_string(8502) => BuyerState::new(77 * E8),
    };
    let mut swap = SwapBuilder::new()
        .with_sns_governance_canister_id(SNS_GOVERNANCE_CANISTER_ID)
        .with_nns_proposal_id(OPEN_SNS_TOKEN_SWAP_PROPOSAL_ID)
        .with_lifecycle(Open)
        .with_swap_start_due(Some(START_TIMESTAMP_SECONDS), Some(END_TIMESTAMP_SECONDS))
        .with_min_participants(1)
        .with_min_max_participant_icp(1, 100)
        .with_min_max_direct_participation(36_000, 45_000)
        .with_sns_tokens(10 * E8)
        .with_neuron_basket_count(3)
        .with_neuron_basket_dissolve_delay_interval(7890000) // 3 months
        .with_neurons_fund_participation()
        .with_buyers(buyers.clone())
        .build();

    let buyer_principal_id = PrincipalId::new_user_test_id(8502);

    // Step 1.5: Attempt to auto-finalize the swap. It should not work, since
    // the swap is open. Not only should it not work, it should do nothing.
    assert_eq!(swap.lifecycle(), Open);
    assert_eq!(swap.already_tried_to_auto_finalize, Some(false));
    assert_eq!(swap.auto_finalize_swap_response, None);
    let auto_finalization_error = swap
        .try_auto_finalize(now_fn, &mut spy_clients_exploding_root())
        .await
        .unwrap_err();
    let allowed_to_finalize_error = swap.can_finalize().unwrap_err();
    assert_eq!(auto_finalization_error, allowed_to_finalize_error);

    // already_tried_to_auto_finalize should still be set to false, since it
    // couldn't try to auto-finalize due to the swap not being committed.
    assert_eq!(swap.already_tried_to_auto_finalize, Some(false));
    assert_eq!(swap.auto_finalize_swap_response, None);

    // Step 2: Abort the swap
    assert!(swap.try_abort(/* now_seconds: */ END_TIMESTAMP_SECONDS + 1));
    assert_eq!(swap.lifecycle(), Aborted);
    assert_eq!(
        swap.decentralization_swap_termination_timestamp_seconds,
        Some(END_TIMESTAMP_SECONDS + 1)
    );
    // Cannot open when aborted.
    assert!(!swap.can_open(END_TIMESTAMP_SECONDS + 1));
    assert!(!swap.try_open(END_TIMESTAMP_SECONDS + 1));

    // We need to create a function to generate the clients, so we can get them
    // twice: once for when we call `finalize` and once for when we call
    // `try_auto_finalize`
    fn get_clients() -> CanisterClients<
        SpySnsRootClient,
        SpySnsGovernanceClient,
        SpyLedger,
        SpyLedger,
        SpyNnsGovernanceClient,
    > {
        CanisterClients {
            icp_ledger: SpyLedger::new(
                // ICP Ledger should be called once and should return success
                vec![LedgerReply::TransferFunds(Ok(1000))],
            ),
            sns_root: SpySnsRootClient::new(vec![
                // SNS Root will respond with zero errors
                SnsRootClientReply::SetDappControllers(SetDappControllersResponse {
                    failed_updates: vec![],
                }),
            ]),
            // Mock 1 successful call to NNS governance settle_nf
            nns_governance: SpyNnsGovernanceClient::new(vec![
                NnsGovernanceClientReply::SettleNeuronsFundParticipation(
                    SettleNeuronsFundParticipationResponse {
                        result: Some(settle_neurons_fund_participation_response::Result::Ok(
                            settle_neurons_fund_participation_response::Ok {
                                neurons_fund_neuron_portions: vec![],
                            },
                        )),
                    },
                ),
            ]),
            ..spy_clients()
        }
    }
    let mut clients = get_clients();

    // Step 3: Run the code under test.
    // We'll test finalize and try_auto_finalize and make sure they have the
    // same result.
    let result = {
        // Clone swap & clients so we can run `finalize` and `try_auto_finalize` separately
        let mut try_auto_finalize_swap = swap.clone();
        let mut try_auto_finalize_clients = get_clients();

        // Call finalize on swap
        let finalize_result = swap.finalize(now_fn, &mut clients).await;

        // Call try_auto_finalize on the cloned version of swap.
        assert_eq!(
            try_auto_finalize_swap.already_tried_to_auto_finalize,
            Some(false)
        );
        let try_auto_finalize_result = try_auto_finalize_swap
            .try_auto_finalize(now_fn, &mut try_auto_finalize_clients)
            .await
            .unwrap();
        assert_eq!(
            try_auto_finalize_swap.already_tried_to_auto_finalize,
            Some(true)
        );
        assert_eq!(
            try_auto_finalize_swap.auto_finalize_swap_response,
            Some(finalize_result.clone())
        );

        // Try auto-finalizing again. It won't work since an attempt has already
        // been made to auto-finalize the swap
        let auto_finalization_error = try_auto_finalize_swap
            .try_auto_finalize(now_fn, &mut try_auto_finalize_clients)
            .await
            .unwrap_err();
        assert!(
            auto_finalization_error.contains("an attempt has already been made to auto-finalize")
        );

        // Assert that finalization and auto-finalization had the same result
        assert_eq!(
            finalize_result, try_auto_finalize_result,
            "the result from finalization and auto-finalization should be the same"
        );

        finalize_result
    };

    // Step 4: Inspect the results.
    {
        assert_eq!(
            result,
            FinalizeSwapResponse {
                sweep_icp_result: Some(SweepResult {
                    success: 1,
                    failure: 0,
                    skipped: 0,
                    invalid: 0,
                    global_failures: 0,
                }),
                sweep_sns_result: None,
                claim_neuron_result: None,
                create_sns_neuron_recipes_result: None,
                set_mode_call_result: None,
                set_dapp_controllers_call_result: Some(
                    successful_set_dapp_controllers_call_result()
                ),
                settle_neurons_fund_participation_result: Some(
                    SettleNeuronsFundParticipationResult {
                        possibility: Some(
                            settle_neurons_fund_participation_result::Possibility::Ok(
                                settle_neurons_fund_participation_result::Ok {
                                    neurons_fund_participation_icp_e8s: Some(0),
                                    neurons_fund_neurons_count: Some(0),
                                }
                            )
                        ),
                    }
                ),
                error_message: None,
                // Deprecated field.
                settle_community_fund_participation_result: None,
            },
        );
    }

    // Step 3.1: Assert that no neurons were created, and SNS governance was not set to normal mode.
    assert_eq!(
        clients.sns_governance.calls,
        vec![],
        "{:#?}",
        clients.sns_governance.calls
    );

    // Step 3.2: Verify ledger calls.
    let icp_ledger_calls = clients.icp_ledger.get_calls_snapshot();
    assert_eq!(
        icp_ledger_calls,
        vec![
            // Refund ICP to buyer.
            LedgerCall::TransferFundsICRC1 {
                amount_e8s: 77 * E8 - DEFAULT_TRANSFER_FEE.get_e8s(),

                fee_e8s: DEFAULT_TRANSFER_FEE.get_e8s(),
                from_subaccount: Some(principal_to_subaccount(&buyer_principal_id)),
                to: Account::from(buyer_principal_id.0),
                memo: 0,
            }
        ],
        "{icp_ledger_calls:#?}"
    );
    assert_eq!(clients.sns_ledger.get_calls_snapshot(), vec![]);

    // Step 3.3: SNS root was told to set dapp canister controllers.
    let controller_principal_ids = swap
        .init
        .as_ref()
        .unwrap()
        .fallback_controller_principal_ids
        .iter()
        .map(|s| PrincipalId::from_str(s).unwrap())
        .collect();
    assert_eq!(
        clients.sns_root.observed_calls,
        vec![SnsRootClientCall::SetDappControllers(
            SetDappControllersRequest {
                // Change controller of all dapps controlled by the root canister.
                canister_ids: None,
                controller_principal_ids
            }
        )],
    );

    // Assert that NNS governance was notified of negative outcome (i.e. ended in Aborted).
    {
        use settle_neurons_fund_participation_request::{Aborted, Result};
        assert_eq!(
            clients.nns_governance.calls,
            vec![NnsGovernanceClientCall::SettleNeuronsFundParticipation(
                SettleNeuronsFundParticipationRequest {
                    nns_proposal_id: Some(OPEN_SNS_TOKEN_SWAP_PROPOSAL_ID),
                    result: Some(Result::Aborted(Aborted {})),
                }
            )]
        );
    }
}

/// Test the error refund method for single user
#[test]
fn test_error_refund_single_user() {
    let user1 = *TEST_USER1_PRINCIPAL;
    let mut swap = SwapBuilder::new()
        .with_sns_governance_canister_id(SNS_GOVERNANCE_CANISTER_ID)
        .with_lifecycle(Open)
        .with_swap_start_due(Some(START_TIMESTAMP_SECONDS), Some(END_TIMESTAMP_SECONDS))
        .with_min_participants(1)
        .with_min_max_participant_icp(E8, 6 * E8)
        .with_min_max_direct_participation(5 * E8, 10 * E8)
        .with_sns_tokens(100_000 * E8)
        .build();

    // Swap should be open
    assert_eq!(swap.lifecycle(), Open);

    // Buy tokens
    let amount = 6 * E8;
    buy_token(
        &mut swap,
        &user1,
        &amount,
        &mock_stub(get_transfer_and_account_balance_mock_ledger(
            &amount, &user1, &user1, false,
        )),
    )
    .now_or_never()
    .unwrap();

    // Verify that SNS Swap canister registered the tokens
    assert_eq!(amount, get_sns_balance(&user1, &mut swap));

    // User has not committed yet --> Cannot get a refund
    let refund_err = try_error_refund_err(
        &mut swap,
        &user1,
        &mock_stub(get_account_balance_mock_ledger(&amount, &user1)),
    )
    .now_or_never()
    .unwrap();
    assert!(refund_err
        .description
        .unwrap()
        .contains("ABORTED or COMMITTED"));
    assert_eq!(refund_err.error_type.unwrap(), Precondition as i32);

    // The minimum number of participants is 1, so when calling commit with the appropriate end
    // time a commit should be possible, but an abort should not be possible
    assert!(!swap.can_abort(swap.params.clone().unwrap().swap_due_timestamp_seconds));
    assert!(!swap.try_abort(swap.params.clone().unwrap().swap_due_timestamp_seconds));
    assert!(swap.can_commit(swap.params.clone().unwrap().swap_due_timestamp_seconds));
    assert!(swap.try_commit(swap.params.clone().unwrap().swap_due_timestamp_seconds));

    // The life cycle should have changed to COMMITTED
    assert_eq!(swap.lifecycle(), Committed);

    // The lifecycle is committed, however the funds have not been swept i.e. sent to the
    // governance canister if committed or back to buyer if aborted. The lifecycle is currently
    // committed so funds should go to the governance canister after sweep. Until then the
    // buyer cannot refund.
    let refund_err = try_error_refund_err(
        &mut swap,
        &user1,
        &mock_stub(get_transfer_and_account_balance_mock_ledger(
            &amount, &user1, &user1, false,
        )),
    )
    .now_or_never()
    .unwrap();
    assert!(refund_err.description.unwrap().contains("escrow"));
    assert_eq!(refund_err.error_type.unwrap(), Precondition as i32);

    // If user1 sends another amount by accident without actually buying any tokens (and thus
    // not refreshing the balance of bought tokens) he should not be able to get a refund for
    // that amount until the sns has been swept.
    let refund_err = try_error_refund_err(
        &mut swap,
        &user1,
        &mock_stub(get_transfer_and_account_balance_mock_ledger(
            &(7 * E8),
            &user1,
            &user1,
            false,
        )),
    )
    .now_or_never()
    .unwrap();
    assert!(refund_err.description.unwrap().contains("escrow"));
    assert_eq!(refund_err.error_type.unwrap(), Precondition as i32);

    // Now try to sweep
    let SweepResult {
        success,
        failure,
        skipped,
        invalid,
        global_failures,
    } = sweep(
        &mut swap,
        &mock_stub(get_transfer_mock_ledger(
            &amount,
            &user1,
            &SNS_GOVERNANCE_CANISTER_ID.into(),
            false,
        )),
    )
    .now_or_never()
    .unwrap();
    assert_eq!(skipped, 0);
    assert_eq!(success, 1);
    assert_eq!(failure, 0);
    assert_eq!(invalid, 0);
    assert_eq!(global_failures, 0);

    // Now the user should be able to get their funds back which they send by accident earlier
    let refund_ok = try_error_refund_ok(
        &mut swap,
        &user1,
        &mock_stub(get_transfer_and_account_balance_mock_ledger(
            &(7 * E8),
            &user1,
            &user1,
            false,
        )),
    )
    .now_or_never()
    .unwrap();
    assert_eq!(refund_ok.block_height.unwrap(), 100);

    // User can't get a refund after sweep. Balance of the subaccount of the buyer is now 0
    // since it was transferred to the sns governance canister. Transfer Response is set to be
    // an Error since the account of the user1 in the sns swap canister is 0 and cannot pay for
    // fees.
    let refund_err = try_error_refund_err(
        &mut swap,
        &user1,
        &mock_stub(get_transfer_and_account_balance_mock_ledger(
            &DEFAULT_TRANSFER_FEE.get_e8s(),
            &user1,
            &user1,
            true,
        )),
    )
    .now_or_never()
    .unwrap();
    assert!(refund_err.description.unwrap().contains("Transfer"));
    assert_eq!(
        refund_err.error_type.unwrap(),
        error_refund_icp_response::err::Type::External as i32
    );
}

/// Test the error refund method for multiple users.
#[test]
fn test_error_refund_multiple_users() {
    let user1 = *TEST_USER1_PRINCIPAL;
    let user2 = *TEST_USER2_PRINCIPAL;

    let mut swap = SwapBuilder::new()
        .with_sns_governance_canister_id(SNS_GOVERNANCE_CANISTER_ID)
        .with_lifecycle(Open)
        .with_min_participants(2)
        .with_min_max_participant_icp(E8, 6 * E8)
        .with_min_max_direct_participation(5 * E8, 10 * E8)
        .with_sns_tokens(100_000 * E8)
        .build();

    //Buy a tokens
    let amount = 6 * E8;
    buy_token(
        &mut swap,
        &user1,
        &amount,
        &mock_stub(get_transfer_and_account_balance_mock_ledger(
            &amount, &user1, &user1, false,
        )),
    )
    .now_or_never()
    .unwrap();

    // The minimum number of participants is 1, so when calling abort with the appropriate end time an abort should be possible
    // (but a commit should not be possible)
    assert!(!swap.try_commit(swap.params.clone().unwrap().swap_due_timestamp_seconds));
    assert!(swap.try_abort(swap.params.clone().unwrap().swap_due_timestamp_seconds));

    //The life cycle should have changed to ABORTED
    assert_eq!(swap.lifecycle(), Aborted);

    //Make sure neither user1 nor any other user can refund tokens from user1 until they are swept
    let mut expects = get_account_balance_mock_ledger(&amount, &user1);
    expects.extend(
        get_transfer_mock_ledger(&amount, &user1, &user2, false)
            .iter()
            .copied(),
    );
    let refund_err = try_error_refund_err(
        &mut swap,
        &user1,
        &mock_stub(get_transfer_and_account_balance_mock_ledger(
            &amount, &user1, &user1, false,
        )),
    )
    .now_or_never()
    .unwrap();
    assert!(refund_err.description.unwrap().contains("escrow"));
    assert_eq!(refund_err.error_type.unwrap(), Precondition as i32);

    // If user2 has sent ICP to the SNS swap in error but did not go through normal payment flow they should be able to get a refund
    let refund_ok = try_error_refund_ok(
        &mut swap,
        &user2,
        &mock_stub(get_transfer_and_account_balance_mock_ledger(
            &(amount),
            &user2,
            &user2,
            false,
        )),
    )
    .now_or_never()
    .unwrap();
    assert_eq!(refund_ok.block_height.unwrap(), 100);

    //When status is aborted and sweep is called user1 should get their funds back
    let SweepResult {
        success,
        failure,
        skipped,
        invalid,
        global_failures,
    } = sweep(
        &mut swap,
        &mock_stub(get_transfer_mock_ledger(&amount, &user1, &user1, false)),
    )
    .now_or_never()
    .unwrap();
    assert_eq!(skipped, 0);
    assert_eq!(success, 1);
    assert_eq!(failure, 0);
    assert_eq!(invalid, 0);
    assert_eq!(global_failures, 0);

    //After user1 has gotten back their ICP they should not be able to call the refund_error function again and get back any ICP>0
    //Transfer Response is set to be an Error since the account of the user1 in the sns swap canister is 0 and cannot pay for fees or the amount requested
    let refund_err = try_error_refund_err(
        &mut swap,
        &user1,
        &mock_stub(get_transfer_and_account_balance_mock_ledger(
            &DEFAULT_TRANSFER_FEE.get_e8s(),
            &user1,
            &user1,
            true,
        )),
    )
    .now_or_never()
    .unwrap();
    assert!(refund_err.description.unwrap().contains("Transfer"));
    assert_eq!(
        refund_err.error_type.unwrap(),
        error_refund_icp_response::err::Type::External as i32
    );
}

/// Test the error refund method after swap has closed
#[test]
fn test_error_refund_after_close() {
    let user1 = *TEST_USER1_PRINCIPAL;
    let user2 = *TEST_USER2_PRINCIPAL;

    let mut swap = SwapBuilder::new()
        .with_sns_governance_canister_id(SNS_GOVERNANCE_CANISTER_ID)
        .with_lifecycle(Open)
        .with_swap_start_due(Some(START_TIMESTAMP_SECONDS), Some(END_TIMESTAMP_SECONDS))
        .with_min_participants(1)
        .with_min_max_participant_icp(E8, 6 * E8)
        .with_min_max_direct_participation(5 * E8, 10 * E8)
        .with_sns_tokens(100_000 * E8)
        .build();

    //Buy a tokens
    let amount = 6 * E8;
    buy_token(
        &mut swap,
        &user1,
        &amount,
        &mock_stub(get_transfer_and_account_balance_mock_ledger(
            &amount, &user1, &user1, false,
        )),
    )
    .now_or_never()
    .unwrap();

    //Verify that SNS Swap canister registered the tokens
    assert_eq!(amount, get_sns_balance(&user1, &mut swap));

    //The minimum number of participants is 1, so when calling commit with the appropriate end time a commit should be possible
    assert!(swap.can_commit(swap.params.clone().unwrap().swap_due_timestamp_seconds));
    assert!(swap.try_commit(swap.params.clone().unwrap().swap_due_timestamp_seconds));

    //The life cycle should have changed to COMMITTED
    assert_eq!(swap.lifecycle(), Committed);

    //Now that the lifecycle has changed to committed, the neurons for the buyers should have been generated
    verify_direct_participant_icp_balances(&swap, &user1, amount);

    //Now try to sweep
    let SweepResult {
        success,
        failure,
        skipped,
        invalid,
        global_failures,
    } = sweep(
        &mut swap,
        &mock_stub(get_transfer_mock_ledger(
            &amount,
            &user1,
            &SNS_GOVERNANCE_CANISTER_ID.into(),
            false,
        )),
    )
    .now_or_never()
    .unwrap();
    assert_eq!(skipped, 0);
    assert_eq!(success, 1);
    assert_eq!(failure, 0);
    assert_eq!(invalid, 0);
    assert_eq!(global_failures, 0);

    // If user2 has sent ICP in Error but never committed their tokens , i.e. never called refresh_buyer_tokens they should be able to get their funds back even after the swap is committed
    let refund_ok = try_error_refund_ok(
        &mut swap,
        &user2,
        &mock_stub(get_transfer_and_account_balance_mock_ledger(
            &E8, &user2, &user2, false,
        )),
    )
    .now_or_never()
    .unwrap();
    assert_eq!(refund_ok.block_height.unwrap(), 100);
}

/// Test that a single buyer states can be retrieved
#[test]
fn test_get_buyer_state() {
    let mut swap = SwapBuilder::new()
        .with_lifecycle(Open)
        .with_min_participants(1)
        .with_min_max_participant_icp(E8, 6 * E8)
        .with_min_max_direct_participation(5 * E8, 10 * E8)
        .with_sns_tokens(100_000 * E8)
        .build();

    assert_eq!(swap.lifecycle(), Open);
    // Deposit 6 ICP from one buyer.
    assert!(swap
        .refresh_buyer_token_e8s(
            *TEST_USER1_PRINCIPAL,
            None,
            SWAP_CANISTER_ID,
            &mock_stub(vec![LedgerExpect::AccountBalance(
                Account {
                    owner: SWAP_CANISTER_ID.get().into(),
                    subaccount: Some(principal_to_subaccount(&TEST_USER1_PRINCIPAL.clone()))
                },
                Ok(Tokens::from_e8s(6 * E8))
            )])
        )
        .now_or_never()
        .unwrap()
        .is_ok());
    // Assert the balance is correct
    assert_eq!(
        swap.buyers
            .get(&TEST_USER1_PRINCIPAL.to_string())
            .unwrap()
            .amount_icp_e8s(),
        6 * E8
    );

    // Assert the same balance using `get_buyer_state`
    assert_eq!(
        swap.get_buyer_state(&GetBuyerStateRequest {
            principal_id: Some(*TEST_USER1_PRINCIPAL)
        })
        .buyer_state
        .unwrap()
        .amount_icp_e8s(),
        6 * E8
    );

    // Deposit 6 ICP from another buyer.
    assert!(swap
        .refresh_buyer_token_e8s(
            *TEST_USER2_PRINCIPAL,
            None,
            SWAP_CANISTER_ID,
            &mock_stub(vec![LedgerExpect::AccountBalance(
                Account {
                    owner: SWAP_CANISTER_ID.get().into(),
                    subaccount: Some(principal_to_subaccount(&TEST_USER2_PRINCIPAL.clone()))
                },
                Ok(Tokens::from_e8s(6 * E8))
            )])
        )
        .now_or_never()
        .unwrap()
        .is_ok());
    // But only 4 ICP is "accepted" as the swap's init.max_direct_participation_icp_e8s is 10 Tokens and has
    // been reached by this point.
    assert_eq!(
        swap.buyers
            .get(&TEST_USER2_PRINCIPAL.to_string())
            .unwrap()
            .amount_icp_e8s(),
        4 * E8
    );

    // Assert the same balance using `get_buyer_state`
    assert_eq!(
        swap.get_buyer_state(&GetBuyerStateRequest {
            principal_id: Some(*TEST_USER2_PRINCIPAL)
        })
        .buyer_state
        .unwrap()
        .amount_icp_e8s(),
        4 * E8
    );

    // Using `get_buyer_state` without a known principal returns None
    assert!(swap
        .get_buyer_state(&GetBuyerStateRequest {
            principal_id: Some(*TEST_USER3_PRINCIPAL)
        })
        .buyer_state
        .is_none());
}

/// Test that the locking mechanism of finalize_swap works. Use the InterleavingTestLedger
/// to have one thread block on Ledger calls. Meanwhile, call the finalize_swap API once
/// the lock has been acquired, and assert that the request is rejected.
#[test]
fn test_finalize_swap_rejects_concurrent_calls() {
    // Step 1: Prepare the world.

    // The setup of the swap is irrelevant to the test, so use some generic swap state.
    // Make sure finalize_swap is unlocked.
    let swap = create_generic_committed_swap();
    assert!(!swap.is_finalize_swap_locked());

    // The swap canister relies on a static variable that's reused by multiple
    // canister calls. To avoid using static variables in the test, and yet
    // allow two mutable references to the same value, we'll take both a mutable
    // reference and a raw pointer to it that we'll (unsafely) dereference later.
    // To make sure that the pointer keeps pointing to the same reference, we'll pin
    // the mutable reference.
    let mut boxed_swap = Box::pin(swap);
    let raw_ptr_swap = unsafe { Pin::get_unchecked_mut(boxed_swap.as_mut()) as *mut Swap };

    // We control the interleaving of finalize calls by using channels. The ledger provided
    // to the finalize method will block on ledger calls, and continue only when messages are
    // drained from the channel. We can use this technique to guarantee ordering of API calls
    // across message blocks.
    #[allow(clippy::disallowed_methods)]
    let (sender_channel, mut receiver_channel) = mpsc::unbounded::<LedgerControlMessage>();

    let mut clients = CanisterClients {
        icp_ledger: {
            let underlying_icp_ledger: SpyLedger =
                SpyLedger::new(vec![LedgerReply::TransferFunds(Ok(1000))]);
            InterleavingTestLedger::new(Box::new(underlying_icp_ledger), sender_channel)
        },
        sns_governance: SpySnsGovernanceClient::new(vec![
            SnsGovernanceClientReply::ClaimSwapNeurons(ClaimSwapNeuronsResponse::new(
                create_successful_swap_neuron_basket_for_one_direct_participant(
                    PrincipalId::new_user_test_id(1001),
                    1,
                ),
            )),
            SnsGovernanceClientReply::SetMode(SetModeResponse {}),
        ]),
        sns_ledger: SpyLedger::new(vec![LedgerReply::TransferFunds(Ok(1000))]),
        sns_root: SpySnsRootClient::new(vec![
            // Add a mock reply of a successful call to SNS Root
            SnsRootClientReply::successful_set_dapp_controllers(),
        ]),
        nns_governance: SpyNnsGovernanceClient::new(vec![
            NnsGovernanceClientReply::SettleNeuronsFundParticipation(
                SettleNeuronsFundParticipationResponse {
                    result: Some(settle_neurons_fund_participation_response::Result::Ok(
                        settle_neurons_fund_participation_response::Ok {
                            neurons_fund_neuron_portions: vec![],
                        },
                    )),
                },
            ),
        ]),
    };

    // Step 2: Call finalize and have the thread block

    // Spawn a call to finalize in a new thread; meanwhile, on the main thread we'll await
    // for the signal that the ICP Ledger transfer has been initiated
    let thread_handle = thread::spawn(move || {
        let finalize_result = tokio_test::block_on(boxed_swap.finalize(now_fn, &mut clients));

        // Assert that this call to finalize returned a response. As we are only testing the
        // locking mechanism, assert that the values aren't set to None.
        assert!(
            finalize_result.error_message.is_none(),
            "{:?}",
            finalize_result.error_message
        );
        // Assert that the lock was released.
        assert!(!boxed_swap.is_finalize_swap_locked());
    });

    // Block the current main thread until an ICP Ledger transfer is triggered in the spawned thread
    // by the InterleavingTestLedger. A message will be sent to the receiver_channel to notify.
    let (_, ledger_control_message) =
        tokio_test::block_on(async { receiver_channel.next().await.unwrap() });

    // Step 3: Call finalize concurrently and inspect results

    // To add some safety measures given the unsafe block, add an Atomic Fence that will
    // guarantee (along with the fencing in the InterleavingTestLedger) that the unsafe block
    // sees the same memory as the other thread.
    atomic::fence(AtomicOrdering::SeqCst);
    unsafe {
        // Assert the lock exists in Swap's state
        assert!((*raw_ptr_swap).is_finalize_swap_locked());

        let mut clients = spy_clients_exploding_root();

        // Interleave a call to finalize using the raw pointer. This call should return a
        // default FinalizeSwapResponse with an error message after hitting the lock.
        let response = (*raw_ptr_swap)
            .finalize(now_fn, &mut clients)
            .now_or_never()
            .unwrap();

        // This would fail before introducing the locking mechanism
        match response.error_message {
            None => panic!("Expected finalize_swap to reject this concurrent request"),
            Some(error_message) => {
                assert!(error_message
                    .contains("The Swap canister has finalize_swap call already in progress"))
            }
        }

        // Assert not other subactions were started
        assert!(response.sweep_icp_result.is_none());
        assert!(response.settle_neurons_fund_participation_result.is_none());
        assert!(response.set_mode_call_result.is_none());
        assert!(response.sweep_sns_result.is_none());
        assert!(response.claim_neuron_result.is_none());
        assert!(response.set_mode_call_result.is_none());
    }

    // Step 4: Assert finalize finished and released the lock

    // Resume the spawned thread's execution of finalize.
    ledger_control_message
        .send(Ok(()))
        .expect("Error when continuing blocked finalize");

    // Drain the channel to finish the test.
    tokio_test::block_on(drain_receiver_channel(&mut receiver_channel));

    // Join the thread_handle to make sure the thread didn't exit unexpectedly
    thread_handle
        .join()
        .expect("Expected the spawned thread to succeed");

    atomic::fence(AtomicOrdering::SeqCst);
    // Assert that the lock was released after finalize succeeded.
    unsafe {
        assert!(!(*raw_ptr_swap).is_finalize_swap_locked());
    }
}

/// Test that the Swap canister must be in the terminal state (Aborted || Committed)
/// for finalize to be invoked correctly.
#[tokio::test]
async fn test_swap_must_be_terminal_to_invoke_finalize() {
    let invalid_finalize_lifecycles = vec![Open, Unspecified, Pending];

    for lifecycle in invalid_finalize_lifecycles {
        let mut swap = Swap {
            lifecycle: lifecycle as i32,
            init: Some(init()),
            params: Some(params()),
            ..Default::default()
        };

        let mut clients = spy_clients_exploding_root();

        let response = swap.finalize(now_fn, &mut clients).await;

        let error_message = response
            .error_message
            .expect("Expected the error_message to be set");

        // Assert the error message contains the correct message
        assert!(
            error_message
                .contains("The Swap can only be finalized in the COMMITTED or ABORTED states"),
            "{}",
            error_message,
        );

        // Assert that no other sub-actions were made.
        assert!(response.sweep_icp_result.is_none());
        assert!(response.settle_neurons_fund_participation_result.is_none());
        assert!(response.set_dapp_controllers_call_result.is_none());
        assert!(response.create_sns_neuron_recipes_result.is_none());
        assert!(response.sweep_sns_result.is_none());
        assert!(response.claim_neuron_result.is_none());
        assert!(response.set_mode_call_result.is_none());

        // Assert that the finalize_swap lock was released
        assert!(!swap.is_finalize_swap_locked());
    }
}

/// Test that sweep_icp will handle missing required state gracefully with an error.
#[tokio::test]
async fn test_sweep_icp_handles_missing_state() {
    // Step 1: Prepare the world

    // sweep_icp depends on init being set
    let mut swap = Swap {
        init: None,
        buyers: btreemap! {
          i2principal_id_string(1)=> BuyerState::default(),
          i2principal_id_string(2)=> BuyerState::default(),
        },
        ..Default::default()
    };

    // Step 2: Call sweep_icp
    let result = swap.sweep_icp(now_fn, &SpyLedger::default()).await;

    // Step 3: Inspect results

    // sweep_icp should gracefully handle missing state by incrementing global_failures
    assert_eq!(
        result,
        SweepResult {
            success: 0,
            failure: 0,
            skipped: 0,
            invalid: 0,
            global_failures: 1
        }
    );
}

/// Test that sweep_icp will handle invalid BuyerStates gracefully by incrementing the correct
/// SweepResult fields
#[tokio::test]
async fn test_sweep_icp_handles_invalid_buyer_states() {
    // Step 1: Prepare the world

    // Create some valid and invalid buyers in the state
    let mut swap = Swap {
        lifecycle: Committed as i32,
        init: Some(init()),
        params: Some(params()),
        buyers: btreemap! {
            i2principal_id_string(1001) => BuyerState::new(50 * E8), // Valid
            "GARBAGE_PRINCIPAL_ID".to_string() => BuyerState::new(50 * E8), // Invalid
            i2principal_id_string(1003) => BuyerState::default(), // Invalid
        },
        ..Default::default()
    };

    // Since only one buyer is valid, only one transfer call should be mocked
    let icp_ledger = SpyLedger::new(vec![LedgerReply::TransferFunds(Ok(1))]);

    // Step 2: Call sweep_icp
    let sweep_result = swap.sweep_icp(now_fn, &icp_ledger).await;

    assert_eq!(
        sweep_result,
        SweepResult {
            success: 1,         // Single valid buyer
            skipped: 0,         // No skips
            failure: 0,         // No failures
            invalid: 2,         // Two invalid buyer states
            global_failures: 0, // No global failures
        }
    );

    let observed_icp_ledger_calls = icp_ledger.get_calls_snapshot();
    assert_eq!(observed_icp_ledger_calls.len(), 1);
}

/// Tests that sweep_icp will handle all ledger transfers correctly. Mainly, that
/// the SweepResult fields are incremented when the correct state is reached
#[tokio::test]
async fn test_sweep_icp_handles_ledger_transfers() {
    // Step 1: Prepare the world

    // Setup the necessary buyers for the test
    let mut swap = Swap {
        lifecycle: Committed as i32,
        init: Some(init()),
        params: Some(params()),
        buyers: btreemap! {
            // This Buyer is `Invalid` because the amount committed is less than the
            // DEFAULT_TRANSFER_FEE of the ICP Ledger. This should never be possible
            // in production, but sweep_icp must handle this case.
            i2principal_id_string(1000) => BuyerState {
                icp: Some(TransferableAmount {
                    amount_e8s: DEFAULT_TRANSFER_FEE.get_e8s() - 1,
                    ..Default::default()
                }),
                has_created_neuron_recipes: Some(false),
            },
            // This Buyer has already had its transfer succeed, and should result in
            // as Skipped field increment
            i2principal_id_string(1001) => BuyerState {
                icp: Some(TransferableAmount {
                    amount_e8s: 10 * E8,
                    transfer_start_timestamp_seconds: END_TIMESTAMP_SECONDS,
                    transfer_success_timestamp_seconds: END_TIMESTAMP_SECONDS + 1,
                    ..Default::default()
                }),
                has_created_neuron_recipes: Some(false),
            },
            // This buyer's state is valid, and a mock call to the ledger will allow it
            // to succeed, which should result in a success field increment
            i2principal_id_string(1002) => BuyerState {
                icp: Some(TransferableAmount {
                    amount_e8s: 10 * E8,
                    ..Default::default()
                }),
                has_created_neuron_recipes: Some(false),
            },
            // This buyer's state is valid, but a mock call to the ledger will fail the transfer,
            // which should result in a failure field increment.
            i2principal_id_string(1003) => BuyerState {
                icp: Some(TransferableAmount {
                    amount_e8s: 10 * E8,
                    ..Default::default()
                }),
                has_created_neuron_recipes: Some(false),
            },
        },
        ..Default::default()
    };

    // Mock the replies from the ledger
    let icp_ledger = SpyLedger::new(vec![
        // This mocked reply should produce a successful transfer in SweepResult
        LedgerReply::TransferFunds(Ok(1000)),
        LedgerReply::TransferFunds(Err(NervousSystemError::new_with_message(
            "Error when transferring funds",
        ))),
    ]);

    // Step 2: Call sweep_icp
    let sweep_result = swap.sweep_icp(now_fn, &icp_ledger).await;

    assert_eq!(
        sweep_result,
        SweepResult {
            success: 1,         // Single successful transfer
            skipped: 1,         // Single skipped buyer
            failure: 1,         // Single failed transfer
            invalid: 1,         // Single invalid buyer
            global_failures: 0, // No global failures
        }
    );

    // Assert that only two calls were issued by finalize.
    let observed_icp_ledger_calls = icp_ledger.get_calls_snapshot();
    assert_eq!(observed_icp_ledger_calls.len(), 2);
}

/// Tests that if transferring does not complete fully, finalize will halt finalization
#[tokio::test]
async fn test_finalization_halts_when_sweep_icp_fails() {
    // Step 1: Prepare the world

    // Setup the necessary buyers for the test
    let mut swap = Swap {
        lifecycle: Committed as i32,
        init: Some(init()),
        params: Some(params()),
        buyers: btreemap! {
            // This Buyer is `Invalid` because the amount committed is less than the
            // DEFAULT_TRANSFER_FEE of the ICP Ledger. This should never be possible
            // in production, but sweep_icp must handle this case.
            i2principal_id_string(1000) => BuyerState {
                icp: Some(TransferableAmount {
                    amount_e8s: DEFAULT_TRANSFER_FEE.get_e8s() - 1,
                    ..Default::default()
                }),
                has_created_neuron_recipes: Some(false),
            },
            // This buyer's state is valid, but a mock call to the ledger will fail the transfer,
            // which should result in a failure field increment.
            i2principal_id_string(1003) => BuyerState {
                icp: Some(TransferableAmount {
                    amount_e8s: 10 * E8,
                    ..Default::default()
                }),
                has_created_neuron_recipes: Some(false),
            },
        },
        ..Default::default()
    };

    let mut clients = CanisterClients {
        icp_ledger: SpyLedger::new(vec![
            // This mocked reply should produce a successful transfer in SweepResult
            LedgerReply::TransferFunds(Err(NervousSystemError::new_with_message(
                "Error when transferring funds",
            ))),
        ]),
        ..spy_clients()
    };

    // Step 2: Call sweep_icp
    let result = swap.finalize(now_fn, &mut clients).await;

    assert_eq!(
        result.sweep_icp_result,
        Some(SweepResult {
            success: 0,
            skipped: 0,
            failure: 1, // Single failed transfer
            invalid: 1, // Single invalid buyer
            global_failures: 0,
        })
    );

    assert_eq!(
        result.error_message,
        Some(String::from("Transferring ICP did not complete fully, some transfers were invalid or failed. Halting swap finalization"))
    );

    // Assert that all other fields are set to None because finalization was halted.
    assert!(result.settle_neurons_fund_participation_result.is_none());
    assert!(result.set_dapp_controllers_call_result.is_none());
    assert!(result.create_sns_neuron_recipes_result.is_none());
    assert!(result.sweep_sns_result.is_none());
    assert!(result.set_mode_call_result.is_none());
    assert!(result.claim_neuron_result.is_none());
}

/// Test that sweep_sns will handle missing required state gracefully with an error.
#[tokio::test]
async fn test_sweep_sns_handles_missing_state() {
    // Step 1: Prepare the world

    // sweep_sns depends on init being set
    let mut swap = Swap {
        init: None,
        neuron_recipes: vec![SnsNeuronRecipe::default(), SnsNeuronRecipe::default()],
        ..Default::default()
    };

    // Step 2: Call sweep_sns
    let result = swap.sweep_sns(now_fn, &SpyLedger::default()).await;

    // Step 3: Inspect results

    // sweep_sns should gracefully handle missing state by incrementing global failures
    assert_eq!(
        result,
        SweepResult {
            success: 0,
            failure: 0,
            skipped: 0,
            invalid: 0,
            global_failures: 1,
        }
    );
}

fn dummy_valid_sns_neuron_recipe() -> SnsNeuronRecipe {
    SnsNeuronRecipe {
        neuron_attributes: Some(NeuronAttributes::default()),
        investor: Some(Investor::Direct(DirectInvestment {
            buyer_principal: (*TEST_USER1_PRINCIPAL).to_string(),
        })),
        sns: Some(TransferableAmount {
            amount_e8s: 10 * E8,
            ..Default::default()
        }),
        claimed_status: Some(ClaimedStatus::Pending as i32),
    }
}

/// Test that sweep_sns will handles invalid SnsNeuronRecipes gracefully by incrementing the correct
/// SweepResult fields
#[tokio::test]
async fn test_sweep_sns_handles_invalid_neuron_recipes() {
    // Step 1: Prepare the world

    let neuron_recipes_and_validation_errors = vec![
        (dummy_valid_sns_neuron_recipe(), None),
        (
            SnsNeuronRecipe {
                neuron_attributes: None,
                ..dummy_valid_sns_neuron_recipe()
            },
            Some("Missing neuron_attributes"),
        ),
        (
            SnsNeuronRecipe {
                investor: None,
                ..dummy_valid_sns_neuron_recipe()
            },
            Some("Missing investor"),
        ),
        (
            SnsNeuronRecipe {
                investor: Some(Investor::Direct(DirectInvestment {
                    buyer_principal: "GARBAGE_DATA".to_string(),
                })),
                ..dummy_valid_sns_neuron_recipe()
            },
            Some("Invalid principal"),
        ),
        (
            SnsNeuronRecipe {
                sns: None,
                ..dummy_valid_sns_neuron_recipe()
            },
            Some("Missing transferable_amount (field `sns`)"),
        ),
    ];

    // Assert that the individual recipes are invalid for the exact reasons we expect.
    let nns_governance = NNS_GOVERNANCE_CANISTER_ID;
    let sns_transaction_fee_e8s = 10_000;
    for (neuron_recipe, expected_err_substring) in &neuron_recipes_and_validation_errors {
        let observed = neuron_recipe.to_neuron_recipe(nns_governance, sns_transaction_fee_e8s);
        match (observed, expected_err_substring.as_ref()) {
            (Err((_, observed_err)), Some(expected_err_substring)) => {
                assert!(
                    observed_err.contains(expected_err_substring),
                    "Observed error `{}` does not contain the expected substring `{}`.",
                    observed_err,
                    expected_err_substring
                );
            }
            (Err((_, observed_err)), None) => {
                panic!("Expected valid neuron recipe, observed {:?}.", observed_err);
            }
            (Ok(_), Some(expected_err_substring)) => {
                panic!(
                    "Expected neuron recipe validation error matching `{}`, got ok.",
                    expected_err_substring
                );
            }
            (Ok(_), None) => (), // all good
        }
    }

    let neuron_recipes = neuron_recipes_and_validation_errors
        .into_iter()
        .map(|(neuron_recipe, _)| neuron_recipe)
        .collect();

    // Create some valid and invalid NeuronRecipes in the state
    let mut swap = Swap {
        neuron_recipes,
        lifecycle: Committed as i32,
        init: Some(init()),
        params: Some(params()),
        ..Default::default()
    };

    // Since only one NeuronRecipe is valid, only one transfer call should be mocked
    let sns_ledger = SpyLedger::new(vec![LedgerReply::TransferFunds(Ok(1))]);

    // Step 2: Call sweep_sns
    let sweep_result = swap.sweep_sns(now_fn, &sns_ledger).await;

    // Step 3: Inspect Results
    assert_eq!(
        sweep_result,
        SweepResult {
            success: 1,         // Single valid buyer
            skipped: 0,         // No skips
            failure: 0,         // No failures
            invalid: 4,         // Four invalid buyers
            global_failures: 0, // No global failures
        }
    );

    let observed_sns_ledger_calls = sns_ledger.get_calls_snapshot();
    assert_eq!(observed_sns_ledger_calls.len(), 1);
}

/// Tests that sweep_sns will handle all ledger transfers correctly. Mainly, that
/// the SweepResult fields are incremented when the correct state is reached
#[tokio::test]
async fn test_sweep_sns_handles_ledger_transfers() {
    // Step 1: Prepare the world

    let init = init();

    let direct_investor = Some(Investor::Direct(DirectInvestment {
        buyer_principal: (*TEST_USER1_PRINCIPAL).to_string(),
    }));

    // Setup the necessary neurons for the test
    let mut swap = Swap {
        lifecycle: Committed as i32,
        init: Some(init.clone()),
        params: Some(params()),
        neuron_recipes: vec![
            // This Neuron is `Invalid` because the amount committed is less than the
            // transaction_fee of the SNS Ledger. This should never be possible
            // in production, but sweep_sns must handle this case.
            SnsNeuronRecipe {
                neuron_attributes: Some(NeuronAttributes::default()),
                investor: direct_investor.clone(),
                sns: Some(TransferableAmount {
                    amount_e8s: init.transaction_fee_e8s() - 1,
                    ..Default::default()
                }),
                ..Default::default()
            },
            // This Neuron has already had its transfer succeed, and should result in
            // as Skipped field increment
            SnsNeuronRecipe {
                neuron_attributes: Some(NeuronAttributes::default()),
                investor: direct_investor.clone(),
                sns: Some(TransferableAmount {
                    amount_e8s: 10 * E8,
                    transfer_start_timestamp_seconds: END_TIMESTAMP_SECONDS,
                    transfer_success_timestamp_seconds: END_TIMESTAMP_SECONDS + 1,
                    ..Default::default()
                }),
                ..Default::default()
            },
            // This neuron's state is valid, and a mock call to the sns ledger will allow it
            // to succeed, which should result in a success field increment
            SnsNeuronRecipe {
                neuron_attributes: Some(NeuronAttributes::default()),
                investor: direct_investor.clone(),
                sns: Some(TransferableAmount {
                    amount_e8s: 10 * E8,
                    ..Default::default()
                }),
                ..Default::default()
            },
            // This neuron's state is valid, but a mock call to the sns ledger will fail the transfer,
            // which should result in a failure field increment.
            SnsNeuronRecipe {
                neuron_attributes: Some(NeuronAttributes::default()),
                investor: direct_investor.clone(),
                sns: Some(TransferableAmount {
                    amount_e8s: 10 * E8,
                    ..Default::default()
                }),
                ..Default::default()
            },
        ],
        ..Default::default()
    };

    // Mock the replies from the ledger
    let sns_ledger = SpyLedger::new(vec![
        // This mocked reply should produce a successful transfer in SweepResult
        LedgerReply::TransferFunds(Ok(1000)),
        LedgerReply::TransferFunds(Err(NervousSystemError::new_with_message(
            "Error when transferring funds",
        ))),
    ]);

    // Step 2: Call sweep_sns
    let sweep_result = swap.sweep_sns(now_fn, &sns_ledger).await;

    assert_eq!(
        sweep_result,
        SweepResult {
            success: 1,         // Single successful transfer
            skipped: 1,         // Single skipped buyer
            failure: 1,         // Single failed transfer
            invalid: 1,         // Single invalid buyer
            global_failures: 0, // No global failures
        }
    );

    // Assert that only two calls were issued by sweep_sns.
    let observed_icp_ledger_calls = sns_ledger.get_calls_snapshot();
    assert_eq!(observed_icp_ledger_calls.len(), 2);
}

/// Tests that if transferring does not complete fully, finalize will halt finalization
#[tokio::test]
async fn test_finalization_halts_when_sweep_sns_fails() {
    // Step 1: Prepare the world

    let init = init();
    // Setup the necessary neurons for the test
    let mut swap = Swap {
        lifecycle: Committed as i32,
        init: Some(init.clone()),
        params: Some(params()),
        buyers: buyers(),
        direct_participation_icp_e8s: Some(
            buyers()
                .values()
                .map(|buyer_state| buyer_state.icp.as_ref().unwrap().amount_e8s)
                .sum(),
        ),
        ..Default::default()
    };

    let mut clients = CanisterClients {
        nns_governance: SpyNnsGovernanceClient::new(vec![
            NnsGovernanceClientReply::SettleNeuronsFundParticipation(
                SettleNeuronsFundParticipationResponse {
                    result: Some(settle_neurons_fund_participation_response::Result::Ok(
                        settle_neurons_fund_participation_response::Ok {
                            neurons_fund_neuron_portions: vec![],
                        },
                    )),
                },
            ),
        ]),
        sns_ledger: SpyLedger::new(vec![
            LedgerReply::TransferFunds(Ok(1000)),
            LedgerReply::TransferFunds(Ok(1001)),
            LedgerReply::TransferFunds(Err(NervousSystemError::new_with_message(
                "Error when transferring funds",
            ))),
        ]),
        icp_ledger: SpyLedger::new(vec![LedgerReply::TransferFunds(Ok(1000))]),
        ..spy_clients()
    };

    // Step 2: Call sweep_icp
    let result = swap.finalize(now_fn, &mut clients).await;

    // Assert that sweep_icp was executed correctly, but ignore the specific values
    assert!(result.sweep_icp_result.is_some());
    assert!(result.settle_neurons_fund_participation_result.is_some());
    assert!(result.create_sns_neuron_recipes_result.is_some());

    assert_eq!(
        result.sweep_sns_result,
        Some(SweepResult {
            success: 2,
            skipped: 0,
            failure: 1,         // Single failed transfer
            invalid: 0,         // No invalid recipes
            global_failures: 0, // No global failures
        })
    );

    assert_eq!(
        result.error_message,
        Some(String::from("Transferring SNS tokens did not complete fully, some transfers were invalid or failed. Halting swap finalization"))
    );

    // Assert all other fields are set to None because finalization was halted
    assert!(result.set_dapp_controllers_call_result.is_none());
    assert!(result.set_mode_call_result.is_none());
    assert!(result.claim_neuron_result.is_none());
}

#[tokio::test]
async fn test_finalization_halts_when_settle_nf_fails() {
    // Step 1: Prepare the world

    let mut swap = SwapBuilder::new()
        .with_sns_governance_canister_id(SNS_GOVERNANCE_CANISTER_ID)
        .with_lifecycle(Committed)
        .with_swap_start_due(Some(START_TIMESTAMP_SECONDS), Some(END_TIMESTAMP_SECONDS))
        .with_min_participants(3)
        .with_min_max_participant_icp(100 * E8, 100_000 * E8)
        .with_min_max_direct_participation(36_000, 45_000)
        .with_sns_tokens(10 * E8)
        .with_neuron_basket_count(3)
        .with_neuron_basket_dissolve_delay_interval(7890000) // 3 months
        .with_neurons_fund_participation()
        .with_neurons_fund_participation_constraints(NeuronsFundParticipationConstraints {
            min_direct_participation_threshold_icp_e8s: Some(36_000 * E8),
            max_neurons_fund_participation_icp_e8s: Some(100_000),
            coefficient_intervals: vec![LinearScalingCoefficient {
                from_direct_participation_icp_e8s: Some(0),
                to_direct_participation_icp_e8s: Some(u64::MAX),
                slope_numerator: Some(1),
                slope_denominator: Some(1),
                intercept_icp_e8s: Some(0),
            }],
            ideal_matched_participation_function: None,
        })
        .build();

    let expected_canister_call_error = CanisterCallError {
        code: Some(0),
        description: "UNEXPECTED ERROR".to_string(),
    };

    let mut clients = CanisterClients {
        nns_governance: SpyNnsGovernanceClient::new(vec![
            NnsGovernanceClientReply::CanisterCallError(expected_canister_call_error.clone()),
        ]),
        ..spy_clients()
    };

    // Step 2: Call finalize
    let result = swap.finalize(now_fn, &mut clients).await;

    // Assert that sweep_icp was executed correctly, but ignore the specific values
    assert!(result.sweep_icp_result.is_some());

    // Assert that the settle_neurons_fund_participation_result is set as expected
    assert_eq!(
        result.settle_neurons_fund_participation_result,
        Some(SettleNeuronsFundParticipationResult {
            possibility: Some(settle_neurons_fund_participation_result::Possibility::Err(
                settle_neurons_fund_participation_result::Error {
                    message: Some("Replica returned an error when calling settle_neurons_fund_participation. Code: Some(0). Message: UNEXPECTED ERROR".to_string()),
                }
            )),
        })
    );

    assert_eq!(
        result.error_message,
        Some(String::from(
            "Settling the Neurons' Fund participation did not succeed. Halting swap finalization"
        ))
    );

    // Assert that all other fields are set to None because finalization was halted.
    assert_eq!(result.set_dapp_controllers_call_result, None);
    assert_eq!(result.create_sns_neuron_recipes_result, None);
    assert_eq!(result.sweep_sns_result, None);
    assert_eq!(result.set_mode_call_result, None);
    assert_eq!(result.claim_neuron_result, None);
}

/// Test that set_sns_governance_to_normal_mode correctly handles response from SNS Governance
#[tokio::test]
async fn test_set_sns_governance_to_normal_mode_handles_responses() {
    let mut sns_governance_client = SpySnsGovernanceClient::default();

    sns_governance_client.push_reply(SnsGovernanceClientReply::SetMode(SetModeResponse {}));

    let result = Swap::set_sns_governance_to_normal_mode(&mut sns_governance_client).await;
    assert!(result.is_successful_set_mode_call());

    sns_governance_client.push_reply(SnsGovernanceClientReply::CanisterCallError(
        CanisterCallError {
            code: Some(0),
            description: "BAD CALL".to_string(),
        },
    ));

    let result = Swap::set_sns_governance_to_normal_mode(&mut sns_governance_client).await;
    assert!(!result.is_successful_set_mode_call());
}

/// Tests that if set_sns_governance_to_normal_mode does not complete successfully, the finalization
/// halts
#[tokio::test]
async fn test_finalization_halts_when_set_mode_fails() {
    // Step 1: Prepare the world

    let mut swap = Swap {
        lifecycle: Committed as i32,
        init: Some(init()),
        params: Some(params()),
        buyers: buyers(),
        direct_participation_icp_e8s: Some(
            buyers()
                .values()
                .map(|buyer_state| buyer_state.icp.as_ref().unwrap().amount_e8s)
                .sum(),
        ),
        ..Default::default()
    };

    let expected_canister_call_error = CanisterCallError {
        code: Some(0),
        description: "BAD REPLY".to_string(),
    };

    let mut clients = CanisterClients {
        sns_governance: SpySnsGovernanceClient::new(vec![
            SnsGovernanceClientReply::ClaimSwapNeurons(ClaimSwapNeuronsResponse::new(
                create_successful_swap_neuron_basket_for_one_direct_participant(
                    PrincipalId::new_user_test_id(1001),
                    3,
                ),
            )),
            SnsGovernanceClientReply::CanisterCallError(expected_canister_call_error.clone()),
        ]),
        nns_governance: SpyNnsGovernanceClient::new(vec![
            NnsGovernanceClientReply::SettleNeuronsFundParticipation(
                SettleNeuronsFundParticipationResponse {
                    result: Some(settle_neurons_fund_participation_response::Result::Ok(
                        settle_neurons_fund_participation_response::Ok {
                            neurons_fund_neuron_portions: vec![],
                        },
                    )),
                },
            ),
        ]),
        icp_ledger: SpyLedger::new(vec![LedgerReply::TransferFunds(Ok(1000))]),
        sns_ledger: SpyLedger::new(vec![
            LedgerReply::TransferFunds(Ok(1000)),
            LedgerReply::TransferFunds(Ok(1001)),
            LedgerReply::TransferFunds(Ok(1002)),
        ]),
        ..spy_clients()
    };

    // Step 2: Call finalize
    let result = swap.finalize(now_fn, &mut clients).await;

    assert_eq!(
        result.set_mode_call_result,
        Some(SetModeCallResult {
            possibility: Some(set_mode_call_result::Possibility::Err(
                expected_canister_call_error
            )),
        })
    );

    assert_eq!(result.error_message, Some(String::from("Setting the SNS Governance mode to normal did not complete fully. Halting swap finalization")));

    // Assert that sweep_icp was executed correctly, but ignore the specific values
    assert!(result.sweep_icp_result.is_some());
    assert!(result.settle_neurons_fund_participation_result.is_some());
    assert!(result.create_sns_neuron_recipes_result.is_some());
    assert!(result.sweep_sns_result.is_some());
    assert!(result.claim_neuron_result.is_some());
    // set_dapp_controllers_result is None as this is not the aborted path
    assert!(result.set_dapp_controllers_call_result.is_none());
}

#[test]
fn test_derived_state() {
    let total_nf_maturity = 1_000_000 * E8;
    let nf_matching_fn =
        PolynomialMatchingFunction::new(total_nf_maturity, neurons_fund_participation_limits())
            .unwrap();
    println!("{}", nf_matching_fn.dbg_plot());
    let mut swap = Swap {
        init: Some(Init {
            neurons_fund_participation: Some(true),
            neurons_fund_participation_constraints: Some(NeuronsFundParticipationConstraints {
                min_direct_participation_threshold_icp_e8s: Some(25_000 * E8),
                max_neurons_fund_participation_icp_e8s: Some(total_nf_maturity / 10),
                coefficient_intervals: vec![LinearScalingCoefficient::trivial()],
                ideal_matched_participation_function: Some(IdealMatchedParticipationFunction {
                    serialized_representation: Some(nf_matching_fn.serialize()),
                }),
            }),
            ..Init::default()
        }),
        ..Swap::default()
    };
    // Validate initial Swap configuration
    let mut expected = DerivedState {
        buyer_total_icp_e8s: 0,
        sns_tokens_per_icp: 0f32,
        direct_participant_count: Some(0),
        direct_participation_icp_e8s: Some(0),
        neurons_fund_participation_icp_e8s: Some(0),
        cf_participant_count: Some(0), // initialized with zero and unchanged until the swap ends.
        cf_neuron_count: Some(0),      // initialized with zero and unchanged until the swap ends.
    };
    assert_eq!(swap.derived_state(), expected);

    // Set swap.params.sns_token_e8s; this should not directly affect the derived state.
    swap.params = Some(Params {
        sns_token_e8s: 100_000 * E8,
        ..Default::default()
    });
    swap.update_derived_fields();
    assert_eq!(swap.derived_state(), expected);

    // Set direct amount of direct buyers to a value below the minumum for the Neurons' Fund
    // to participate.
    swap.buyers = btreemap! {
        "".to_string() => BuyerState {
            icp: Some(TransferableAmount {
                amount_e8s: 25_000 * E8,
                transfer_start_timestamp_seconds: 10,
                transfer_success_timestamp_seconds: 12,
                ..Default::default()
            }),
            has_created_neuron_recipes: Some(false),
        },
    };
    swap.update_derived_fields();
    expected = DerivedState {
        buyer_total_icp_e8s: 25_000 * E8,
        sns_tokens_per_icp: 4f32,
        direct_participant_count: Some(1),
        direct_participation_icp_e8s: Some(25_000 * E8),
        ..expected
    };
    assert_eq!(swap.derived_state(), expected);

    // Set direct amount of direct buyers to a value sufficient for the Neurons' Fund to participate.
    let final_direct_participation_icp_e8s = 300_000 * E8;
    swap.buyers = btreemap! {
        "".to_string() => BuyerState {
            icp: Some(TransferableAmount {
                amount_e8s: final_direct_participation_icp_e8s,
                transfer_start_timestamp_seconds: 10,
                transfer_success_timestamp_seconds: 12,
                ..Default::default()
            }),
            has_created_neuron_recipes: Some(false),
        },
    };
    swap.update_derived_fields();
    let final_nf_participation_icp_e8s = nf_matching_fn
        .apply_and_rescale_to_icp_e8s(final_direct_participation_icp_e8s)
        .unwrap();
    expected = DerivedState {
        buyer_total_icp_e8s: final_direct_participation_icp_e8s + final_nf_participation_icp_e8s,
        sns_tokens_per_icp: 0.25f32,
        direct_participant_count: Some(1),
        direct_participation_icp_e8s: Some(final_direct_participation_icp_e8s),
        neurons_fund_participation_icp_e8s: Some(final_nf_participation_icp_e8s),
        ..expected
    };
    assert_eq!(swap.derived_state(), expected);
}

/// Test that claim_swap_neurons is called with the correct preconditions
#[tokio::test]
async fn test_claim_swap_neurons_rejects_wrong_life_cycle() {
    // Step 1: Prepare the world

    let mut swap = Swap {
        init: Some(init()),
        params: Some(params()),
        ..Default::default()
    };

    let invalid_lifecycles = vec![Unspecified, Aborted, Pending, Open];

    for lifecycle in invalid_lifecycles {
        swap.lifecycle = lifecycle as i32;

        let sweep_result = swap
            .claim_swap_neurons(&mut SpySnsGovernanceClient::default())
            .await;
        assert_eq!(
            sweep_result,
            SweepResult {
                success: 0,
                failure: 0,
                skipped: 0,
                invalid: 0,
                global_failures: 1,
            }
        );
    }

    let valid_lifecycles = vec![Committed];

    for lifecycle in valid_lifecycles {
        swap.lifecycle = lifecycle as i32;

        let sweep_result = swap
            .claim_swap_neurons(&mut SpySnsGovernanceClient::default())
            .await;
        assert_eq!(
            sweep_result,
            SweepResult {
                success: 0,
                failure: 0,
                skipped: 0,
                invalid: 0,
                global_failures: 0,
            }
        );
    }
}

/// Test that claim_swap_neurons will handle missing required state gracefully with an error.
#[tokio::test]
async fn test_claim_swap_neurons_handles_missing_state() {
    // Step 1: Prepare the world

    // claim_swap_neurons depends on init being set
    let mut swap = Swap {
        init: None,
        ..Default::default()
    };

    // Step 2: Call claim_swap_neurons
    let result = swap
        .claim_swap_neurons(&mut SpySnsGovernanceClient::default())
        .await;

    // Step 3: Inspect results

    // sweep_sns should gracefully handle missing state by incrementing global failures
    assert_eq!(
        result,
        SweepResult {
            success: 0,
            failure: 0,
            skipped: 0,
            invalid: 0,
            global_failures: 1,
        }
    );
}

/// Test that claim_swap_neurons will handles invalid SnsNeuronRecipes gracefully by incrementing the correct
/// SweepResult fields
#[tokio::test]
async fn test_claim_swap_neurons_handles_invalid_neuron_recipes() {
    // Step 1: Prepare the world

    // Create some valid and invalid NeuronRecipes in the state
    let mut swap = Swap {
        lifecycle: Committed as i32,
        init: Some(init()),
        params: Some(params()),
        neuron_recipes: vec![
            // Invalid: Missing NeuronAttributes field
            SnsNeuronRecipe {
                neuron_attributes: None, // Invalid
                ..Default::default()
            },
            // Invalid: Missing Investor field
            SnsNeuronRecipe {
                neuron_attributes: Some(NeuronAttributes::default()),
                investor: None, // Invalid
                ..Default::default()
            },
            // Invalid: buyer_principal is not a valid PrincipalId
            SnsNeuronRecipe {
                neuron_attributes: Some(NeuronAttributes::default()),
                investor: Some(Investor::Direct(DirectInvestment {
                    // Invalid
                    buyer_principal: "GARBAGE_DATA".to_string(),
                })),
                ..Default::default()
            },
            // Invalid: sns field set to None
            SnsNeuronRecipe {
                neuron_attributes: Some(NeuronAttributes::default()),
                investor: Some(Investor::Direct(DirectInvestment {
                    buyer_principal: (*TEST_USER1_PRINCIPAL).to_string(),
                })),
                sns: None, // Invalid
                ..Default::default()
            },
        ],
        ..Default::default()
    };

    // Step 2: Call claim_swap_neurons
    let sweep_result = swap
        .claim_swap_neurons(&mut SpySnsGovernanceClient::default())
        .await;

    // Step 3: Inspect Results
    assert_eq!(
        sweep_result,
        SweepResult {
            success: 0,         // No valid neurons
            skipped: 0,         // No skips
            failure: 0,         // No failures
            invalid: 4,         // Four invalid buyers
            global_failures: 0, // No global failures
        }
    );
}

/// Assert that the journaling system for SnsNeuronRecipes works correctly. The ClaimStatus
/// should be inspected and if it matches a condition, increment a field in the SweepResult
/// and don't add it to the batch to be claimed.
#[tokio::test]
async fn test_claim_swap_neuron_skips_correct_claim_statuses() {
    // Step 1: Prepare the world

    // Create some valid and invalid NeuronRecipes in the state
    let mut swap = Swap {
        lifecycle: Committed as i32,
        init: Some(init()),
        params: Some(params()),
        neuron_recipes: vec![
            SnsNeuronRecipe {
                // An success claim status should result in an skip without another
                // call to SNS Gov
                claimed_status: Some(ClaimedStatus::Success as i32),
                // Other attributes so the test can pass
                neuron_attributes: Some(NeuronAttributes::default()),
                investor: Some(Investor::Direct(DirectInvestment {
                    buyer_principal: (*TEST_USER1_PRINCIPAL).to_string(),
                })),
                sns: Some(TransferableAmount {
                    amount_e8s: 10 * E8,
                    ..Default::default()
                }),
            },
            SnsNeuronRecipe {
                // An invalid claim status should result in an invalid without another
                // call to SNS Gov
                claimed_status: Some(ClaimedStatus::Invalid as i32),
                // Other attributes so the test can pass
                neuron_attributes: Some(NeuronAttributes::default()),
                investor: Some(Investor::Direct(DirectInvestment {
                    buyer_principal: (*TEST_USER1_PRINCIPAL).to_string(),
                })),
                sns: Some(TransferableAmount {
                    amount_e8s: 10 * E8,
                    ..Default::default()
                }),
            },
        ],
        ..Default::default()
    };

    let mut sns_governance_client = SpySnsGovernanceClient::default();

    // Step 2: Call claim_swap_neurons
    let sweep_result = swap.claim_swap_neurons(&mut sns_governance_client).await;

    // Step 3: Inspect Results
    assert_eq!(
        sweep_result,
        SweepResult {
            success: 0,         // No valid neurons
            skipped: 1,         // One skip for the success
            failure: 0,         // No failures
            invalid: 1,         // One invalid for the invalid neuron recipe
            global_failures: 0, // No global failures
        }
    );

    // Assert no calls were made
    assert_eq!(sns_governance_client.get_calls_snapshot().len(), 0);
}

/// Assert that the NeuronRecipes are correctly created from SnsNeuronRecipes. This
/// is an ugly test that doesn't make use of a lot of variables, but given other tests
/// of claim_swap_neurons, this is more of a regression test. If something unexpected changes
/// in the NeuronParameter creation, this will fail loudly.
#[tokio::test]
async fn test_claim_swap_neuron_correctly_creates_neuron_recipes() {
    // Step 1: Prepare the world

    // Create some valid and invalid NeuronRecipes in the state
    #[allow(deprecated)] // TODO(NNS1-3198): Remove this once hotkey_principal is deprecated
    let mut swap = Swap {
        lifecycle: Committed as i32,
        init: Some(init()),
        params: Some(params()),
        neuron_recipes: vec![
            SnsNeuronRecipe {
                claimed_status: Some(ClaimedStatus::Pending as i32),
                neuron_attributes: Some(NeuronAttributes {
                    memo: 10,
                    dissolve_delay_seconds: ONE_MONTH_SECONDS,
                    followees: vec![NeuronId::new_test_neuron_id(10).into()],
                }),
                investor: Some(Investor::Direct(DirectInvestment {
                    buyer_principal: (*TEST_USER1_PRINCIPAL).to_string(),
                })),
                sns: Some(TransferableAmount {
                    amount_e8s: 10 * E8,
                    ..Default::default()
                }),
            },
            SnsNeuronRecipe {
                claimed_status: Some(ClaimedStatus::Pending as i32),
                neuron_attributes: Some(NeuronAttributes {
                    memo: 0,
                    dissolve_delay_seconds: 0,
                    followees: vec![NeuronId::new_test_neuron_id(20).into()],
                }),
                investor: Some(Investor::CommunityFund(CfInvestment {
                    controller: Some(*TEST_USER2_PRINCIPAL),
                    hotkeys: Some(Principals::from(vec![*TEST_USER3_PRINCIPAL])),
                    hotkey_principal: ic_nervous_system_common::obsolete_string_field(
                        "hotkey_principal",
                        Some("controller"),
                    ),
                    nns_neuron_id: 100,
                })),
                sns: Some(TransferableAmount {
                    amount_e8s: 20 * E8,
                    ..Default::default()
                }),
            },
        ],
        ..Default::default()
    };

    let mut sns_governance_client =
        SpySnsGovernanceClient::new(vec![SnsGovernanceClientReply::ClaimSwapNeurons(
            compute_single_successful_claim_swap_neurons_response(&swap.neuron_recipes),
        )]);

    // Step 2: Call claim_swap_neurons
    let sweep_result = swap.claim_swap_neurons(&mut sns_governance_client).await;

    // Step 3: Inspect Results
    assert_eq!(
        sweep_result,
        SweepResult {
            success: 2,         // No valid buyers
            skipped: 0,         // One skip for the success
            failure: 0,         // No failures
            invalid: 0,         // One invalid for the invalid neuron recipe
            global_failures: 0, // No global failures
        }
    );

    let expected = SnsGovernanceClientCall::ClaimSwapNeurons(ClaimSwapNeuronsRequest {
        neuron_recipes: Some(NeuronRecipes {
            neuron_recipes: vec![
                NeuronRecipe {
                    controller: Some(*TEST_USER1_PRINCIPAL),
                    neuron_id: Some(NeuronId::from(compute_neuron_staking_subaccount_bytes(
                        *TEST_USER1_PRINCIPAL,
                        10,
                    ))),
                    stake_e8s: Some((10 * E8) - init().transaction_fee_e8s()),
                    dissolve_delay_seconds: Some(ONE_MONTH_SECONDS),
                    followees: Some(NeuronIds {
                        neuron_ids: vec![NeuronId::new_test_neuron_id(10)],
                    }),
                    participant: Some(neuron_recipe::Participant::Direct(neuron_recipe::Direct {})),
                },
                NeuronRecipe {
                    controller: Some(NNS_GOVERNANCE_CANISTER_ID.get()),
                    neuron_id: Some(NeuronId::from(compute_neuron_staking_subaccount_bytes(
                        NNS_GOVERNANCE_CANISTER_ID.get(),
                        0,
                    ))),
                    stake_e8s: Some((20 * E8) - init().transaction_fee_e8s()),
                    dissolve_delay_seconds: Some(0),
                    followees: Some(NeuronIds {
                        neuron_ids: vec![NeuronId::new_test_neuron_id(20)],
                    }),
                    participant: Some(neuron_recipe::Participant::NeuronsFund(
                        neuron_recipe::NeuronsFund {
                            nns_neuron_id: Some(100),
                            nns_neuron_controller: Some(*TEST_USER2_PRINCIPAL),
                            nns_neuron_hotkeys: Some(Principals::from(vec![*TEST_USER3_PRINCIPAL])),
                        },
                    )),
                },
            ],
        }),
        ..Default::default()
    });
    assert_eq!(sns_governance_client.get_calls_snapshot(), vec![expected])
}

/// Test the batching mechanism for claim_swap_neurons, mostly that given a number of
/// SnsNeuronRecipes, the batches are well formed and handled as expected.
#[tokio::test]
async fn test_claim_swap_neurons_batches_claims() {
    // Step 1: Prepare the world

    // This test will create a set number of NeuronRecipes to trigger batching.
    let desired_batch_count = 10;
    let neuron_recipes_per_batch = CLAIM_SWAP_NEURONS_BATCH_SIZE;

    // We want the test to handle non-divisible batch counts. Therefore create N-1 full batches,
    // and final a half full batch
    let neuron_recipe_count =
        ((desired_batch_count - 1) * neuron_recipes_per_batch) + (neuron_recipes_per_batch / 2);

    // Create the Swap state with the correct number of neuron recipes that will
    // result in the correct number of NeuronRecipes to reach the desired batch count
    let mut swap = SwapBuilder::new()
        .with_sns_governance_canister_id(SNS_GOVERNANCE_CANISTER_ID)
        .with_lifecycle(Committed)
        .with_swap_start_due(Some(START_TIMESTAMP_SECONDS), Some(END_TIMESTAMP_SECONDS))
        .with_min_participants(1)
        .with_min_max_participant_icp(10 * E8, 20 * E8)
        .with_min_max_direct_participation(10 * E8, 100 * E8)
        .with_sns_tokens(1000)
        .with_neuron_basket_count(2)
        .with_neuron_basket_dissolve_delay_interval(700)
        .with_neuron_recipes(create_generic_sns_neuron_recipes(
            neuron_recipe_count as u64,
        ))
        .build();

    // This test is concerned with the batching mechanism. Use a helper method to create
    // successful responses that correspond with the batch.
    let batch_claim_swap_neurons_response =
        compute_multiple_successful_claim_swap_neurons_response(&swap.neuron_recipes)
            .into_iter()
            .map(SnsGovernanceClientReply::ClaimSwapNeurons)
            .collect();

    let mut sns_governance_client = SpySnsGovernanceClient::new(batch_claim_swap_neurons_response);

    // Step 2: Call claim_swap_neurons
    let sweep_result = swap.claim_swap_neurons(&mut sns_governance_client).await;

    // Step 3: Inspect Results
    assert_eq!(
        sweep_result,
        SweepResult {
            success: neuron_recipe_count as u32, // All recipes should have succeeded
            skipped: 0,
            failure: 0,
            invalid: 0,
            global_failures: 0,
        }
    );

    // Assert that the desired number of batches were created
    let replies_snapshot = sns_governance_client.get_calls_snapshot();
    assert_eq!(replies_snapshot.len(), desired_batch_count);
}

/// Test the batching mechanism for claim_swap_neurons handles errors from SNS Governance while
/// processing batches
#[tokio::test]
async fn test_claim_swap_neurons_handles_canister_call_error_during_batch() {
    // Step 1: Prepare the world

    // This test will create a set number of NeuronRecipes to trigger batching.
    let neuron_recipes_per_batch = CLAIM_SWAP_NEURONS_BATCH_SIZE;

    // The test requires 3 batches. The first call will succeed, the second one will fail, and the
    // 3rd one will not be attempted.
    let neuron_recipe_count = neuron_recipes_per_batch * 3;

    // Create the Swap state with the correct number of neuron recipes that will
    // result in the correct number of NeuronRecipes to reach the desired batch count
    let mut swap = Swap {
        lifecycle: Committed as i32,
        init: Some(init()),
        params: Some(params()),
        neuron_recipes: create_generic_sns_neuron_recipes(neuron_recipe_count as u64),
        ..Default::default()
    };

    // Generate the response for all three batches, but grab the first one to be used in the
    // SnsGovernanceClient
    let successful_claim_swap_neuron_response =
        compute_multiple_successful_claim_swap_neurons_response(&swap.neuron_recipes)
            .first()
            .unwrap()
            .clone();

    let mut sns_governance_client = SpySnsGovernanceClient::new(vec![
        SnsGovernanceClientReply::ClaimSwapNeurons(successful_claim_swap_neuron_response),
        SnsGovernanceClientReply::CanisterCallError(CanisterCallError::default()),
    ]);

    // Step 2: Call claim_swap_neurons
    let sweep_result = swap.claim_swap_neurons(&mut sns_governance_client).await;

    // Step 3: Inspect Results
    assert_eq!(
        sweep_result,
        SweepResult {
            success: neuron_recipes_per_batch as u32, // The first batch should have succeeded
            skipped: 0,
            failure: 0,
            invalid: 0,
            global_failures: 1, // The CanisterCallError should have interrupted the batching
        }
    );

    // Assert that the third batch call was skipped
    let replies_snapshot = sns_governance_client.get_calls_snapshot();
    assert_eq!(replies_snapshot.len(), 2);

    // Assert that the successful batch had their journal updated
    for recipe in &swap.neuron_recipes[0..neuron_recipes_per_batch] {
        assert_eq!(recipe.claimed_status, Some(ClaimedStatus::Success as i32));
    }

    // Assert that the two unsuccessful batch did not have their journal updated and can therefore
    // be retried
    for recipe in &swap.neuron_recipes[neuron_recipes_per_batch..swap.neuron_recipes.len()] {
        assert_eq!(recipe.claimed_status, Some(ClaimedStatus::Pending as i32));
    }
}

/// Test the batching mechanism for claim_swap_neurons handles inconsistent response from
/// SNS Governance, and still updates sns neuron recipe journals
#[tokio::test]
async fn test_claim_swap_neurons_handles_inconsistent_response() {
    // Step 1: Prepare the world

    // This test will create a set number of NeuronRecipes to trigger batching.
    let neuron_recipes_per_batch = CLAIM_SWAP_NEURONS_BATCH_SIZE;
    // The test requires 1 batch, and will pop one of the SwapNeurons from the response
    let neuron_recipe_count = neuron_recipes_per_batch;

    // Create the Swap state with the correct number of neuron recipes that will
    // result in the correct number of NeuronRecipes to reach the desired batch count
    let mut swap = Swap {
        lifecycle: Committed as i32,
        init: Some(init()),
        params: Some(params()),
        neuron_recipes: create_generic_sns_neuron_recipes(neuron_recipe_count as u64),
        ..Default::default()
    };

    // Generate the response for the batch
    let mut successful_claim_swap_neuron_response =
        compute_single_successful_claim_swap_neurons_response(&swap.neuron_recipes);

    // Pop one of the SwapNeurons from the end of the response
    match successful_claim_swap_neuron_response
        .claim_swap_neurons_result
        .as_mut()
    {
        Some(ClaimSwapNeuronsResult::Ok(result)) => result.swap_neurons.pop(),
        _ => panic!("ClaimedSwapNeurons is not populated..."),
    };

    let mut sns_governance_client = SpySnsGovernanceClient::new(vec![
        SnsGovernanceClientReply::ClaimSwapNeurons(successful_claim_swap_neuron_response),
        SnsGovernanceClientReply::CanisterCallError(CanisterCallError::default()),
    ]);

    // Step 2: Call claim_swap_neurons
    let sweep_result = swap.claim_swap_neurons(&mut sns_governance_client).await;

    // Step 3: Inspect Results
    assert_eq!(
        sweep_result,
        SweepResult {
            success: (neuron_recipes_per_batch - 1) as u32, // All but the last of the batch should result in success
            skipped: 0,
            failure: 0,
            invalid: 0,
            global_failures: 1, // The mismatch should result in a global_failure
        }
    );

    // Assert that the SwapNeurons returned in the batch are marked successful
    for recipe in &swap.neuron_recipes[0..swap.neuron_recipes.len() - 2] {
        assert_eq!(recipe.claimed_status, Some(ClaimedStatus::Success as i32));
    }

    // Assert that the last recipe (the one which had its neuron parameters removed from the response)
    // is not updated.
    assert_eq!(
        swap.neuron_recipes.last().unwrap().claimed_status,
        Some(ClaimedStatus::Pending as i32)
    );
}

/// Test that create_sns_neuron_recipes will handle missing required state gracefully with an error.
#[test]
fn test_create_sns_neuron_recipes_handles_missing_state() {
    // create_sns_neuron_recipes depends on params being set
    let mut swap = Swap {
        params: None,
        ..Default::default()
    };

    // Call create_sns_neuron_recipes
    let result = swap.create_sns_neuron_recipes();

    // Inspect results

    // create_sns_neuron_recipes should gracefully handle missing state by incrementing global_failures
    assert_eq!(
        result,
        SweepResult {
            success: 0,
            failure: 0,
            skipped: 0,
            invalid: 0,
            global_failures: 1
        }
    );

    // create_sns_neuron_recipes depends on params being set
    let mut swap = Swap {
        params: Some(Params {
            neuron_basket_construction_parameters: None,
            ..Default::default()
        }),
        ..Default::default()
    };

    // Call create_sns_neuron_recipes
    let result = swap.create_sns_neuron_recipes();

    // Inspect results

    // create_sns_neuron_recipes should gracefully handle missing state by incrementing global_failures
    assert_eq!(
        result,
        SweepResult {
            success: 0,
            failure: 0,
            skipped: 0,
            invalid: 0,
            global_failures: 1
        }
    );

    // create_sns_neuron_recipes depends on params being set
    let mut swap = Swap {
        params: Some(Params {
            neuron_basket_construction_parameters: Some(NeuronBasketConstructionParameters {
                count: 1,
                dissolve_delay_interval_seconds: ONE_MONTH_SECONDS,
            }),
            ..Default::default()
        }),
        init: None,
        ..Default::default()
    };

    // Call create_sns_neuron_recipes
    let result = swap.create_sns_neuron_recipes();

    // Inspect results

    // create_sns_neuron_recipes should gracefully handle missing state by incrementing global_failures
    assert_eq!(
        result,
        SweepResult {
            success: 0,
            failure: 0,
            skipped: 0,
            invalid: 0,
            global_failures: 1
        }
    );
}

/// Test that create_sns_neuron_recipes will handle invalid BuyerStates gracefully by incrementing the correct
/// SweepResult fields
#[test]
fn test_create_sns_neuron_recipes_handles_invalid_buyer_states() {
    // Step 1: Prepare the world

    // Create some valid and invalid buyers in the state
    let mut swap = Swap {
        lifecycle: Committed as i32,
        init: Some(init()),
        params: Some(params()),
        buyers: btreemap! {
            i2principal_id_string(1001) => BuyerState::new(50 * E8), // Valid
            "GARBAGE_PRINCIPAL_ID".to_string() => BuyerState::new(50 * E8), // Invalid
        },
        direct_participation_icp_e8s: Some(100 * E8),
        neurons_fund_participation_icp_e8s: Some(0),
        ..Default::default()
    };

    // Helper variable
    let neuron_basket_count = params()
        .neuron_basket_construction_parameters
        .unwrap()
        .count as u32;

    // Step 2: Call create_sns_neuron_recipes
    let sweep_result = swap.create_sns_neuron_recipes();

    // Step 3: Inspect results
    assert_eq!(
        sweep_result,
        SweepResult {
            success: neuron_basket_count, // Single valid buyer
            skipped: 0,                   // No skips
            failure: 0,                   // No failures
            invalid: neuron_basket_count, // Two invalid buyer states
            global_failures: 0,           // No global failures
        }
    );

    assert_eq!(swap.neuron_recipes.len(), neuron_basket_count as usize);
}

/// Test that create_sns_neuron_recipes will handle already created sns neuron recipes and
/// increment the correct field in SweepResult
#[test]
fn test_create_sns_neuron_recipes_skips_already_created_neuron_recipes_for_direct_buyers() {
    // Step 1: Prepare the world
    // Helper variable
    let neuron_basket_count = params()
        .neuron_basket_construction_parameters
        .unwrap()
        .count as u32;

    // Create some valid and invalid buyers in the state
    let mut swap = Swap {
        lifecycle: Committed as i32,
        init: Some(init()),
        params: Some(params()),
        buyers: btreemap! {
            i2principal_id_string(1001) => BuyerState {
                icp: Some(TransferableAmount {
                    amount_e8s: 50 * E8,
                    transfer_start_timestamp_seconds: 0,
                    transfer_success_timestamp_seconds: 0,
                    amount_transferred_e8s: Some(0),
                    transfer_fee_paid_e8s: Some(0),
                }),
                has_created_neuron_recipes: Some(true),
            }, // Already created
           i2principal_id_string(1002) => BuyerState {
                icp: Some(TransferableAmount {
                    amount_e8s: 50 * E8,
                    transfer_start_timestamp_seconds: 0,
                    transfer_success_timestamp_seconds: 0,
                    amount_transferred_e8s: Some(0),
                    transfer_fee_paid_e8s: Some(0),
                }),
                has_created_neuron_recipes: Some(false),
           },
        },
        direct_participation_icp_e8s: Some(100 * E8),
        neurons_fund_participation_icp_e8s: Some(0),
        // Create the correct number of recipes for the already processed buyer
        neuron_recipes: vec![SnsNeuronRecipe::default(); neuron_basket_count as usize],
        ..Default::default()
    };

    // Step 2: Call create_sns_neuron_recipes
    let sweep_result = swap.create_sns_neuron_recipes();

    // Step 3: Inspect results
    assert_eq!(
        sweep_result,
        SweepResult {
            success: neuron_basket_count, // Single valid buyer
            skipped: neuron_basket_count, // One skip
            failure: 0,                   // No failures
            invalid: 0,                   // No invalids
            global_failures: 0,           // No global failures
        }
    );

    assert_eq!(
        swap.neuron_recipes.len(),
        neuron_basket_count as usize * swap.buyers.len()
    );
}

/// Test that create_sns_neuron_recipes will handle already created sns neuron recipes and
/// increment the correct field in SweepResult
#[test]
fn test_create_sns_neuron_recipes_skips_already_created_neuron_recipes_for_nf_participants() {
    // Step 1: Prepare the world
    // Helper variable
    let neuron_basket_count = params()
        .neuron_basket_construction_parameters
        .unwrap()
        .count as u32;

    // Create some valid and invalid buyers in the state
    #[allow(deprecated)] // TODO(NNS1-3198): Remove once hotkey_principal is removed
    let mut swap = Swap {
        lifecycle: Committed as i32,
        init: Some(init()),
        params: Some(params()),
        buyers: btreemap! {},
        direct_participation_icp_e8s: Some(0),
        neurons_fund_participation_icp_e8s: Some(100 * E8),
        cf_participants: vec![
            CfParticipant {
                controller: Some(PrincipalId::new_user_test_id(1001)),
                hotkey_principal: ic_nervous_system_common::obsolete_string_field(
                    "hotkey_principal",
                    Some("controller"),
                ),
                cf_neurons: vec![CfNeuron {
                    nns_neuron_id: 1,
                    amount_icp_e8s: 50 * E8,
                    has_created_neuron_recipes: Some(true),
                    hotkeys: Some(Principals::from(Vec::new())),
                }],
            },
            CfParticipant {
                controller: Some(PrincipalId::new_user_test_id(1002)),
                hotkey_principal: ic_nervous_system_common::obsolete_string_field(
                    "hotkey_principal",
                    Some("controller"),
                ),
                cf_neurons: vec![CfNeuron {
                    nns_neuron_id: 2,
                    amount_icp_e8s: 50 * E8,
                    has_created_neuron_recipes: Some(false),
                    hotkeys: Some(Principals::from(Vec::new())),
                }],
            },
        ],
        // Create the correct number of recipes for the already processed buyer
        neuron_recipes: vec![SnsNeuronRecipe::default(); neuron_basket_count as usize],
        ..Default::default()
    };

    // Step 2: Call create_sns_neuron_recipes
    let sweep_result = swap.create_sns_neuron_recipes();

    // Step 3: Inspect results
    assert_eq!(
        sweep_result,
        SweepResult {
            success: neuron_basket_count, // Single valid CfParticipant
            skipped: neuron_basket_count, // One skip
            failure: 0,                   // No failures
            invalid: 0,                   // No invalids
            global_failures: 0,           // No global failures
        }
    );

    assert_eq!(
        swap.neuron_recipes.len(),
        neuron_basket_count as usize * swap.cf_participants.len()
    );
}

/// Test that create_sns_neuron_recipes generate SnsNeuronRecipe with hotkeys
#[test]
fn test_create_sns_neuron_recipes_includes_hotkeys() {
    // Step 1: Prepare the world
    // Helper variable
    let neuron_basket_count = params()
        .neuron_basket_construction_parameters
        .unwrap()
        .count as u32;

    // Create some valid and invalid buyers in the state
    #[allow(deprecated)] // TODO(NNS1-3198): Remove once hotkey_principal is removed
    let mut swap = Swap {
        lifecycle: Committed as i32,
        init: Some(init()),
        params: Some(params()),
        buyers: btreemap! {},
        direct_participation_icp_e8s: Some(0),
        neurons_fund_participation_icp_e8s: Some(100 * E8),
        cf_participants: vec![CfParticipant {
            controller: Some(PrincipalId::new_user_test_id(1001)),
            hotkey_principal: ic_nervous_system_common::obsolete_string_field(
                "hotkey_principal",
                Some("controller"),
            ),
            cf_neurons: vec![CfNeuron {
                nns_neuron_id: 1,
                amount_icp_e8s: 50 * E8,
                has_created_neuron_recipes: Some(false),
                hotkeys: Some(Principals::from(vec![PrincipalId::new_user_test_id(1002)])),
            }],
        }],
        // Create the correct number of recipes for the already processed buyer
        ..Default::default()
    };

    // Step 2: Call create_sns_neuron_recipes
    let sweep_result = swap.create_sns_neuron_recipes();

    // Step 3: Inspect results
    assert_eq!(
        sweep_result,
        SweepResult {
            success: neuron_basket_count,
            skipped: 0,
            failure: 0,
            invalid: 0,
            global_failures: 0,
        }
    );

    assert_eq!(
        swap.neuron_recipes.len(),
        neuron_basket_count as usize * swap.cf_participants.len()
    );

    // Check that the additional ones were processed
    let neurons_fund_investment = assert_matches!(
        swap.neuron_recipes[0].clone().investor.unwrap(),
        CommunityFund(neurons_fund_investment) => neurons_fund_investment
    );
    assert_eq!(
        neurons_fund_investment.hotkeys,
        Some(Principals {
            principals: vec![PrincipalId::new_user_test_id(1002)]
        }),
    )
}

/// Tests that if create sns neuron recipes fails finalize will halt finalization
#[tokio::test]
async fn test_finalization_halts_when_create_sns_neuron_recipes_fails() {
    // Step 1: Prepare the world

    // Setup the necessary buyers for the test.
    let mut swap = Swap {
        lifecycle: Committed as i32,
        init: Some(init()),
        params: Some(Params {
            // This should cause neuron recipe creation to fail.
            neuron_basket_construction_parameters: None,
            ..params()
        }),
        buyers: buyers(),
        ..Default::default()
    };

    let mut clients = CanisterClients {
        icp_ledger: SpyLedger::new(vec![LedgerReply::TransferFunds(Ok(1000))]),
        nns_governance: SpyNnsGovernanceClient::new(vec![
            NnsGovernanceClientReply::SettleNeuronsFundParticipation(
                SettleNeuronsFundParticipationResponse {
                    result: Some(settle_neurons_fund_participation_response::Result::Ok(
                        settle_neurons_fund_participation_response::Ok {
                            neurons_fund_neuron_portions: vec![],
                        },
                    )),
                },
            ),
        ]),
        ..spy_clients()
    };

    // Step 2: Call finalize
    let result = swap.finalize(now_fn, &mut clients).await;

    // Assert that previous subtasks execute correctly
    assert!(result.sweep_icp_result.is_some());
    assert!(result.settle_neurons_fund_participation_result.is_some());

    assert_eq!(
        result.create_sns_neuron_recipes_result,
        Some(SweepResult {
            success: 0,
            skipped: 0,
            failure: 0,
            invalid: 0,
            global_failures: 1,
        })
    );

    assert_eq!(
        result.error_message,
        Some(String::from("Creating SnsNeuronRecipes did not complete fully, some data was invalid or failed. Halting swap finalization"))
    );

    // Assert all other fields are set to None because finalization was halted
    assert!(result.set_dapp_controllers_call_result.is_none());
    assert!(result.sweep_sns_result.is_none());
    assert!(result.set_mode_call_result.is_none());
    assert!(result.claim_neuron_result.is_none());
}

#[tokio::test]
async fn test_settle_neurons_fund_participation_handles_missing_state() {
    // Step 1: Prepare the world

    // settle_neurons_fund_participation depends on init being set
    let mut swap = Swap {
        init: None,
        ..Default::default()
    };

    // Step 2: Call settle_neurons_fund_participation
    let result = swap
        .settle_neurons_fund_participation(&mut SpyNnsGovernanceClient::default())
        .await;

    // Step 3: Inspect results

    // settle_neurons_fund_participation should gracefully handle missing state by returning an error
    assert_eq!(
        result,
        SettleNeuronsFundParticipationResult {
            possibility: Some(settle_neurons_fund_participation_result::Possibility::Err(
                settle_neurons_fund_participation_result::Error {
                    message: Some("Missing Init in the Swap canister state".to_string()),
                }
            ))
        }
    );
}

#[tokio::test]
async fn test_settle_neurons_fund_participation_returns_successfully_on_subsequent_attempts() {
    // Step 1: Prepare the world

    let mut swap = Swap {
        init: Some(init_with_neurons_fund_funding()),
        lifecycle: Committed as i32,
        direct_participation_icp_e8s: Some(100 * E8),
        ..Default::default()
    };

    let mut spy_nns_governance_client = SpyNnsGovernanceClient::new(vec![
        NnsGovernanceClientReply::SettleNeuronsFundParticipation(
            SettleNeuronsFundParticipationResponse {
                result: Some(settle_neurons_fund_participation_response::Result::Ok(
                    settle_neurons_fund_participation_response::Ok {
                        neurons_fund_neuron_portions: vec![NeuronsFundNeuron {
                            nns_neuron_id: Some(43),
                            amount_icp_e8s: Some(100 * E8),
                            controller: Some(PrincipalId::new_user_test_id(1)),
                            hotkeys: Some(Principals::from(Vec::new())),
                            is_capped: Some(true),
                        }],
                    },
                )),
            },
        ),
    ]);
    // Step 2: Call settle_neurons_fund_participation
    let result = swap
        .settle_neurons_fund_participation(&mut spy_nns_governance_client)
        .await;

    // Step 3: Inspect results
    let expected_result = SettleNeuronsFundParticipationResult {
        possibility: Some(settle_neurons_fund_participation_result::Possibility::Ok(
            settle_neurons_fund_participation_result::Ok {
                neurons_fund_participation_icp_e8s: Some(100 * E8),
                neurons_fund_neurons_count: Some(1),
            },
        )),
    };

    assert_eq!(result, expected_result);

    // Assert the call to nns governance has been made
    assert_eq!(spy_nns_governance_client.calls.len(), 1);
    assert_eq!(swap.cf_participants.len(), 1);

    // Assert that calling settle_neurons_fund_participation again will have the same result
    // without a call to NNS governance
    let result = swap
        .settle_neurons_fund_participation(&mut spy_nns_governance_client)
        .await;

    assert_eq!(result, expected_result);
    assert_eq!(spy_nns_governance_client.calls.len(), 1);
    assert_eq!(swap.cf_participants.len(), 1);
}

#[tokio::test]
async fn test_settle_neurons_fund_participation_handles_governance_error() {
    // Step 1: Prepare the world

    let mut swap = Swap {
        init: Some(init_with_neurons_fund_funding()),
        lifecycle: Committed as i32,
        direct_participation_icp_e8s: Some(100 * E8),
        ..Default::default()
    };

    let mut spy_nns_governance_client = SpyNnsGovernanceClient::new(vec![
        NnsGovernanceClientReply::SettleNeuronsFundParticipation(
            SettleNeuronsFundParticipationResponse {
                result: Some(settle_neurons_fund_participation_response::Result::Err(
                    GovernanceError {
                        error_type: 0,
                        error_message: "ERROR".to_string(),
                    },
                )),
            },
        ),
    ]);
    // Step 2: Call settle_neurons_fund_participation
    let result = swap
        .settle_neurons_fund_participation(&mut spy_nns_governance_client)
        .await;

    // Step 3: Inspect results
    let expected_result = SettleNeuronsFundParticipationResult {
        possibility: Some(settle_neurons_fund_participation_result::Possibility::Err(
            settle_neurons_fund_participation_result::Error {
                message: Some("NNS governance returned an error when calling settle_neurons_fund_participation. Code: 0. Message: ERROR".to_string()),
            },
        )),
    };

    assert_eq!(result, expected_result);

    // Assert the call to nns governance has been made
    assert_eq!(spy_nns_governance_client.calls.len(), 1);
    assert_eq!(swap.cf_participants.len(), 0);
}

#[tokio::test]
async fn test_settle_neurons_fund_participation_handles_replica_error() {
    // Step 1: Prepare the world

    let mut swap = Swap {
        init: Some(init_with_neurons_fund_funding()),
        lifecycle: Committed as i32,
        direct_participation_icp_e8s: Some(100 * E8),
        ..Default::default()
    };

    let mut spy_nns_governance_client =
        SpyNnsGovernanceClient::new(vec![NnsGovernanceClientReply::CanisterCallError(
            CanisterCallError {
                code: Some(0),
                description: "ERROR".to_string(),
            },
        )]);
    // Step 2: Call settle_neurons_fund_participation
    let result = swap
        .settle_neurons_fund_participation(&mut spy_nns_governance_client)
        .await;

    // Step 3: Inspect results
    let expected_result = SettleNeuronsFundParticipationResult {
        possibility: Some(settle_neurons_fund_participation_result::Possibility::Err(
            settle_neurons_fund_participation_result::Error {
                message: Some("Replica returned an error when calling settle_neurons_fund_participation. Code: Some(0). Message: ERROR".to_string()),
            },
        )),
    };

    assert_eq!(result, expected_result);

    // Assert the call to nns governance has been made
    assert_eq!(spy_nns_governance_client.calls.len(), 1);
    assert_eq!(swap.cf_participants.len(), 0);
}

#[tokio::test]
async fn test_settle_neurons_fund_participation_handles_invalid_governance_response() {
    // Step 1: Prepare the world

    let mut swap = Swap {
        init: Some(init_with_neurons_fund_funding()),
        lifecycle: Committed as i32,
        direct_participation_icp_e8s: Some(100 * E8),
        ..Default::default()
    };

    let mut spy_nns_governance_client = SpyNnsGovernanceClient::new(vec![
        NnsGovernanceClientReply::SettleNeuronsFundParticipation(
            SettleNeuronsFundParticipationResponse {
                result: Some(settle_neurons_fund_participation_response::Result::Ok(
                    settle_neurons_fund_participation_response::Ok {
                        neurons_fund_neuron_portions: vec![NeuronsFundNeuron {
                            nns_neuron_id: Some(0),
                            amount_icp_e8s: Some(0),
                            controller: Some(PrincipalId::new_user_test_id(1)),
                            hotkeys: Some(Principals::from(Vec::new())),
                            is_capped: Some(false),
                        }],
                    },
                )),
            },
        ),
    ]);
    // Step 2: Call settle_neurons_fund_participation
    let result = swap
        .settle_neurons_fund_participation(&mut spy_nns_governance_client)
        .await;

    // Step 3: Inspect results
    let expected_result = SettleNeuronsFundParticipationResult {
        possibility: Some(settle_neurons_fund_participation_result::Possibility::Err(
            settle_neurons_fund_participation_result::Error {
                message: Some(
                    "NNS Governance returned invalid NeuronsFundNeurons. Could not settle_neurons_fund_participation. \
                    Defects: [\"NNS governance returned an invalid NeuronsFundNeuron. Struct: NeuronsFundNeuron { \
                    nns_neuron_id: Some(0), amount_icp_e8s: Some(0), controller: Some(6fyp7-3ibaa-aaaaa-aaaap-4ai), \
                    hotkeys: Some(Principals { principals: [] }), is_capped: \
                    Some(false) }, Reason: nns_neuron_id must be specified\"]".to_string()),
            },
        )),
    };

    assert_eq!(result, expected_result);

    // Assert the call to nns governance has been made
    assert_eq!(spy_nns_governance_client.calls.len(), 1);
    assert_eq!(swap.cf_participants.len(), 0);
}

#[tokio::test]
async fn test_settle_neurons_fund_participation_handles_corrupted_governance_response() {
    // Step 1: Prepare the world

    let mut swap = Swap {
        init: Some(init_with_neurons_fund_funding()),
        lifecycle: Committed as i32,
        direct_participation_icp_e8s: Some(100 * E8),
        ..Default::default()
    };

    let mut spy_nns_governance_client = SpyNnsGovernanceClient::new(vec![
        NnsGovernanceClientReply::SettleNeuronsFundParticipation(
            SettleNeuronsFundParticipationResponse { result: None },
        ),
    ]);
    // Step 2: Call settle_neurons_fund_participation
    let result = swap
        .settle_neurons_fund_participation(&mut spy_nns_governance_client)
        .await;

    // Step 3: Inspect results
    let expected_result = SettleNeuronsFundParticipationResult {
        possibility: Some(settle_neurons_fund_participation_result::Possibility::Err(
            settle_neurons_fund_participation_result::Error {
                message: Some("NNS governance returned a SettleNeuronsFundParticipationResponse with no result. Cannot determine if request succeeded or failed.".to_string()),
            },
        )),
    };

    assert_eq!(result, expected_result);

    // Assert the call to nns governance has been made
    assert_eq!(spy_nns_governance_client.calls.len(), 1);
    assert_eq!(swap.cf_participants.len(), 0);
}

/// Test that when paginating through the Participants, that different invocations
/// result in the same ordering.
#[test]
fn test_list_direct_participants_list_is_deterministic() {
    // Prepare the canister with multiple buyers
    let mut swap = Swap {
        lifecycle: Open as i32,
        params: Some(params()),
        init: Some(init()),
        ..Default::default()
    };

    // Set up the spy ledger to return token balances
    let spy_ledger = SpyLedger::new(vec![
        LedgerReply::AccountBalance(Ok(Tokens::from_e8s(100 * E8))),
        LedgerReply::AccountBalance(Ok(Tokens::from_e8s(100 * E8))),
        LedgerReply::AccountBalance(Ok(Tokens::from_e8s(100 * E8))),
        LedgerReply::AccountBalance(Ok(Tokens::from_e8s(100 * E8))),
    ]);

    // Participate in the swap by calling refresh_buyer_tokens. This will update the
    // buyers map and BUYERS_LIST_INDEX
    for i in 0..4 {
        swap.refresh_buyer_token_e8s(
            PrincipalId::new_user_test_id(i),
            None,
            SWAP_CANISTER_ID,
            &spy_ledger,
        )
        .now_or_never()
        .unwrap()
        .unwrap();
    }

    let first_pass = paginate_participants(&swap, /* limit */ 1);
    let second_pass = paginate_participants(&swap, /* limit */ 1);

    assert_eq!(first_pass, second_pass);
    assert!(!first_pass.is_empty())
}

/// Test that when paging through all participants, that all are returned.
#[test]
fn test_list_direct_participants_paginates_all_participants() {
    // Prepare the canister with multiple buyers
    let mut swap = Swap {
        lifecycle: Open as i32,
        params: Some(params()),
        init: Some(init()),
        ..Default::default()
    };

    // Set up the spy ledger to return token balances
    let spy_ledger = SpyLedger::new(vec![
        LedgerReply::AccountBalance(Ok(Tokens::from_e8s(100 * E8))),
        LedgerReply::AccountBalance(Ok(Tokens::from_e8s(100 * E8))),
        LedgerReply::AccountBalance(Ok(Tokens::from_e8s(100 * E8))),
        LedgerReply::AccountBalance(Ok(Tokens::from_e8s(100 * E8))),
    ]);

    // Participate in the swap by calling refresh_buyer_tokens. This will update the
    // buyers map and BUYERS_LIST_INDEX
    for i in 0..4 {
        swap.refresh_buyer_token_e8s(
            PrincipalId::new_user_test_id(i),
            None,
            SWAP_CANISTER_ID,
            &spy_ledger,
        )
        .now_or_never()
        .unwrap()
        .unwrap();
    }

    // Paginate through all of the participants
    let participants = paginate_participants(&swap, /* limit */ 3);
    assert!(!participants.is_empty());

    // Rebuild the buyer map based on the list response
    let mut rebuilt_buyers_map = btreemap! {};
    for participant in participants {
        rebuilt_buyers_map.insert(
            participant.participant_id.unwrap().to_string(),
            participant.participation.unwrap(),
        );
    }

    // Assert that they are equal, i.e. the test was able to get all participants
    assert_eq!(rebuilt_buyers_map, swap.buyers);
}

/// Test that `rebuild_index` hits the right condition and rebuilds if it was missing
#[test]
fn test_rebuild_indexes_correctly_rebuilds_buyers_list_index() {
    // Prepare the canister with multiple buyers
    let swap = Swap {
        lifecycle: Open as i32,
        params: Some(params()),
        init: Some(init()),
        buyers: btreemap! {
            i2principal_id_string(1) => BuyerState::new(50 * E8),
            i2principal_id_string(2) => BuyerState::new(50 * E8),
            i2principal_id_string(3) => BuyerState::new(50 * E8),
        },
        ..Default::default()
    };

    // Paginate through all of the participants
    let participants = paginate_participants(&swap, /* limit */ 1);
    // The list should be empty because there was no equivalent update to BUYERS_INDEX_LIST
    assert!(participants.is_empty());

    // The actual BUYERS_LIST_INDEX should be empty too
    let buyer_list_index_length = memory::BUYERS_LIST_INDEX.with(|list| list.borrow().len());
    assert_eq!(buyer_list_index_length, 0);

    // Execute the code under test
    swap.rebuild_indexes()
        .unwrap_or_else(|err| panic!("rebuild_indexes failed due to {}", err));

    // Inspect results

    // Paginate though all of the participants again
    let participants = paginate_participants(&swap, /* limit */ 1);
    assert_eq!(participants.len(), 3);

    // The actual BUYERS_LIST_INDEX should now be populated
    let buyer_list_index_length = memory::BUYERS_LIST_INDEX.with(|list| list.borrow().len());
    assert_eq!(buyer_list_index_length, 3);
}

/// Test that if the index exists, it is not rebuilt in a different order.
#[test]
fn test_rebuild_indexes_ignores_existing_index() {
    // Prepare the canister with multiple buyers
    let mut swap = Swap {
        lifecycle: Open as i32,
        params: Some(params()),
        init: Some(init()),
        ..Default::default()
    };

    // Set up the spy ledger to return token balances
    let spy_ledger = SpyLedger::new(vec![
        LedgerReply::AccountBalance(Ok(Tokens::from_e8s(100 * E8))),
        LedgerReply::AccountBalance(Ok(Tokens::from_e8s(100 * E8))),
    ]);

    // Participate in the swap by calling refresh_buyer_tokens. This will update the
    // buyers map and BUYERS_LIST_INDEX
    for i in 0..2 {
        swap.refresh_buyer_token_e8s(
            PrincipalId::new_user_test_id(i),
            None,
            SWAP_CANISTER_ID,
            &spy_ledger,
        )
        .now_or_never()
        .unwrap()
        .unwrap();
    }

    // Paginate through all of the participants
    let participants = paginate_participants(&swap, /* limit */ 1);
    assert_eq!(participants.len(), 2);

    // Grab a snapshot of the index to compare to later
    let buyer_list_index_length_before: Vec<Principal> =
        memory::BUYERS_LIST_INDEX.with(|list| list.borrow().iter().collect());
    assert_eq!(buyer_list_index_length_before.len(), 2);

    // Execute the code under test
    swap.rebuild_indexes()
        .unwrap_or_else(|err| panic!("rebuild_indexes failed due to {}", err));

    // Inspect results

    // Paginate though all of the participants again
    let participants = paginate_participants(&swap, /* limit */ 1);
    assert_eq!(participants.len(), 2);

    // The actual BUYERS_LIST_INDEX should not have been rebuilt
    let buyer_list_index_length_after: Vec<Principal> =
        memory::BUYERS_LIST_INDEX.with(|list| list.borrow().iter().collect());
    assert_eq!(buyer_list_index_length_after.len(), 2);

    assert_eq!(
        buyer_list_index_length_before,
        buyer_list_index_length_after
    )
}

fn buy_token_ok(
    swap: &mut Swap,
    user: &PrincipalId,
    balance_icp: &u64,
    balance_icp_accepted: &u64,
) {
    assert_eq!(
        swap.refresh_buyer_token_e8s(
            *user,
            None,
            SWAP_CANISTER_ID,
            &mock_stub(vec![LedgerExpect::AccountBalance(
                Account {
                    owner: SWAP_CANISTER_ID.get().into(),
                    subaccount: Some(principal_to_subaccount(user)),
                },
                Ok(Tokens::from_e8s(*balance_icp)),
            )]),
        )
        .now_or_never()
        .unwrap()
        .unwrap(),
        RefreshBuyerTokensResponse {
            icp_accepted_participation_e8s: *balance_icp_accepted,
            icp_ledger_account_balance_e8s: *balance_icp
        }
    );
}

#[track_caller]
fn buy_token_err(swap: &mut Swap, user: &PrincipalId, balance_icp: &u64, error_message: &str) {
    let observed = swap
        .refresh_buyer_token_e8s(
            *user,
            None,
            SWAP_CANISTER_ID,
            &mock_stub(vec![LedgerExpect::AccountBalance(
                Account {
                    owner: SWAP_CANISTER_ID.get().into(),
                    subaccount: Some(principal_to_subaccount(user)),
                },
                Ok(Tokens::from_e8s(*balance_icp)),
            )]),
        )
        .now_or_never()
        .unwrap()
        .unwrap_err();
    assert!(
        observed.contains(error_message),
        "Expected substring `{}` not found in observed error `{}`.",
        error_message,
        observed,
    );
}

fn check_final_conditions(
    swap: &mut Swap,
    user: &PrincipalId,
    amount_committed: &u64,
    participant_total_icp: &u64,
) {
    assert_eq!(
        swap.buyers
            .get(&user.to_string())
            .unwrap()
            .icp
            .as_ref()
            .unwrap()
            .amount_e8s,
        amount_committed.clone()
    );

    assert_eq!(
        swap.get_buyers_total().buyers_total,
        participant_total_icp.clone()
    );
}

#[test]
fn test_refresh_buyer_tokens_happy_scenario() {
    let user1 = PrincipalId::new_user_test_id(1);
    let user2 = PrincipalId::new_user_test_id(2);

    let mut swap = SwapBuilder::new()
        .with_sns_governance_canister_id(SNS_GOVERNANCE_CANISTER_ID)
        .with_lifecycle(Open)
        .with_swap_start_due(Some(START_TIMESTAMP_SECONDS), Some(END_TIMESTAMP_SECONDS))
        .with_min_participants(1)
        .with_min_max_participant_icp(2 * E8, 40 * E8)
        .with_min_max_direct_participation(5 * E8, 50 * E8)
        .with_sns_tokens(100_000 * E8)
        .with_neuron_basket_count(3)
        .with_neurons_fund_participation()
        .build();

    let amount_user1_0 = 5 * E8;
    let amount_user1_1 = 3 * E8;
    let amount_user2_0 = 35 * E8;

    // Make sure user1 has not committed any users yet
    assert!(!swap.buyers.contains_key(&user1.to_string()));

    buy_token_ok(&mut swap, &user1, &amount_user1_0, &amount_user1_0);

    // Make sure user1's commitment is reflected in the buyers state
    // Total committed balance should be that of user1
    check_final_conditions(&mut swap, &user1, &(amount_user1_0), &(amount_user1_0));

    // Commit another 35 ICP
    buy_token_ok(&mut swap, &user2, &amount_user2_0, &amount_user2_0);

    // Make sure user2's commitment is reflected in the buyers state
    // Total committed balance should be that of user1 + user2
    check_final_conditions(
        &mut swap,
        &user2,
        &(amount_user2_0),
        &(amount_user1_0 + amount_user2_0),
    );

    buy_token_ok(
        &mut swap,
        &user1,
        &(amount_user1_0 + amount_user1_1),
        &(amount_user1_0 + amount_user1_1),
    );

    // Make sure user1's commitment is reflected in the buyers state
    // Total committed balance should be that of user1 + user2
    check_final_conditions(
        &mut swap,
        &user1,
        &(amount_user1_0 + amount_user1_1),
        &(amount_user1_0 + amount_user1_1 + amount_user2_0),
    );
}

#[test]
fn test_refresh_buyer_tokens_token_limit() {
    let user1 = PrincipalId::new_user_test_id(1);
    let user2 = PrincipalId::new_user_test_id(2);
    let user3 = PrincipalId::new_user_test_id(3);

    let mut swap = SwapBuilder::new()
        .with_sns_governance_canister_id(SNS_GOVERNANCE_CANISTER_ID)
        .with_lifecycle(Open)
        .with_swap_start_due(Some(START_TIMESTAMP_SECONDS), Some(END_TIMESTAMP_SECONDS))
        .with_min_participants(1)
        .with_min_max_participant_icp(2 * E8, 40 * E8)
        .with_min_max_direct_participation(5 * E8, 50 * E8)
        .with_sns_tokens(100_000 * E8)
        .with_neuron_basket_count(3)
        .with_neurons_fund_participation()
        .build();

    let params = swap.params.clone().unwrap();

    // Buy limit of tokens available per user
    buy_token_ok(
        &mut swap,
        &user1,
        &(params.max_participant_icp_e8s),
        &(params.max_participant_icp_e8s),
    );

    // Buy limit of tokens available
    buy_token_ok(
        &mut swap,
        &user2,
        &(params.max_participant_icp_e8s),
        &(params.max_direct_participation_icp_e8s.unwrap() - params.max_participant_icp_e8s),
    );

    assert_eq!(
        swap.get_buyers_total().buyers_total,
        params.max_direct_participation_icp_e8s.unwrap()
    );

    // No user should be able to commit to tokens now no matter how small the amount
    buy_token_err(
        &mut swap,
        &user3,
        &(params.min_participant_icp_e8s),
        "ICP target",
    );
}

#[test]
fn test_refresh_buyer_tokens_quota() {
    let user1 = PrincipalId::new_user_test_id(1);
    let user2 = PrincipalId::new_user_test_id(2);
    let user3 = PrincipalId::new_user_test_id(3);
    let user4 = PrincipalId::new_user_test_id(4);

    let mut swap = SwapBuilder::new()
        .with_sns_governance_canister_id(SNS_GOVERNANCE_CANISTER_ID)
        .with_lifecycle(Open)
        .with_swap_start_due(Some(START_TIMESTAMP_SECONDS), Some(END_TIMESTAMP_SECONDS))
        .with_min_participants(1)
        .with_min_max_participant_icp(2 * E8, 40 * E8)
        .with_min_max_direct_participation(5 * E8, 200 * E8)
        .with_sns_tokens(100_000 * E8)
        .with_neuron_basket_count(3)
        .with_neurons_fund_participation()
        .build();

    let params = swap.params.clone().unwrap();

    let amount_user1_0 = 5 * E8;
    //The limit per user is 40 E8s and we want to test the maximum participation limit per user
    let amount_user2_0 = 40 * E8;
    let amount_user3_0 = 40 * E8;
    let amount_user4_0 = 100 * E8 - (amount_user1_0 + amount_user2_0 + amount_user3_0);
    let amount_user1_1 = 41 * E8;

    //Buy limit for each user which is 40 E8s. User1 contributes 5 at first
    buy_token_ok(&mut swap, &user1, &amount_user1_0, &amount_user1_0);
    buy_token_ok(&mut swap, &user2, &amount_user2_0, &amount_user2_0);
    buy_token_ok(&mut swap, &user3, &amount_user3_0, &amount_user3_0);
    buy_token_ok(&mut swap, &user4, &amount_user4_0, &amount_user4_0);

    // Make sure the total amount deposited by buyers is at 100
    assert_eq!(
        swap.get_buyers_total().buyers_total,
        amount_user1_0 + amount_user2_0 + amount_user3_0 + amount_user4_0
    );
    assert_eq!(
        amount_user1_0 + amount_user2_0 + amount_user3_0 + amount_user4_0,
        100 * E8
    );

    //Try and buy 41 more tokens. Since user1 has already participated in the swap they can purchase the missing amount until the user limit
    buy_token_ok(
        &mut swap,
        &user1,
        &(amount_user1_1 + amount_user1_0),
        &params.max_participant_icp_e8s,
    );

    //User 1 should have 40 tokens committed at the end and 135 tokens should be bought in total
    check_final_conditions(
        &mut swap,
        &user1,
        &(params.max_participant_icp_e8s),
        &(amount_user1_0
            + amount_user2_0
            + amount_user3_0
            + amount_user4_0
            + (params.max_participant_icp_e8s - amount_user1_0)),
    );
}

#[test]
fn test_refresh_buyer_tokens_not_enough_tokens_left() {
    let user1 = PrincipalId::new_user_test_id(1);
    let user2 = PrincipalId::new_user_test_id(2);
    let user3 = PrincipalId::new_user_test_id(3);
    let user4 = PrincipalId::new_user_test_id(4);

    let mut swap = SwapBuilder::new()
        .with_sns_governance_canister_id(SNS_GOVERNANCE_CANISTER_ID)
        .with_lifecycle(Open)
        .with_swap_start_due(Some(START_TIMESTAMP_SECONDS), Some(END_TIMESTAMP_SECONDS))
        .with_min_participants(1)
        .with_min_max_participant_icp(2 * E8, 40 * E8)
        .with_min_max_direct_participation(5 * E8, 100 * E8)
        .with_sns_tokens(100_000 * E8)
        .with_neuron_basket_count(3)
        .with_neurons_fund_participation()
        .build();

    let params = swap.params.clone().unwrap();

    let amount_user1_0 = 5 * E8;
    let amount_user2_0 = 40 * E8;
    let amount_user3_0 = 40 * E8;
    let amount_user4_0 = 99 * E8 - (amount_user2_0 + amount_user3_0);

    // All tokens but one should be already bought up by users 2 to 4 --> 99 Tokens were bought
    buy_token_ok(&mut swap, &user2, &amount_user2_0, &amount_user2_0);
    buy_token_ok(&mut swap, &user3, &amount_user3_0, &amount_user3_0);
    buy_token_ok(&mut swap, &user4, &amount_user4_0, &amount_user4_0);

    // Make sure the 99 tokens were registered
    assert_eq!(
        swap.get_buyers_total().buyers_total,
        amount_user2_0 + amount_user3_0 + amount_user4_0
    );

    // Make sure that only an amount smaller than the minimum amount to be bought per user is available
    assert!(
        params.max_direct_participation_icp_e8s.unwrap() - swap.get_buyers_total().buyers_total
            < params.min_participant_icp_e8s
    );

    // No user that has not participated in the swap yet can buy this one token left
    buy_token_err(
        &mut swap,
        &user1,
        &amount_user1_0,
        "minimum required to participate",
    );

    // The one token should still be left fur purchase
    check_final_conditions(
        &mut swap,
        &user2,
        &amount_user2_0,
        &(params.max_direct_participation_icp_e8s.unwrap() - E8),
    );
}

// Similar to test_refresh_buyer_tokens_not_enough_tokens_left, but we check that, once the number
// of SNS neurons that all participants (user2, user3, user4) would need to get (if the swap
// succeeds) exceeds the threshold `MAX_NEURONS_FOR_DIRECT_PARTICIPANTS`, then the swap would reject
// a new user (user1) that did not yet participate, while existing participants (e.g., user2) are
// still able to increase their participation amount.
#[test]
fn test_refresh_buyer_tokens_no_sns_neuron_baskets_available() {
    let user1 = PrincipalId::new_user_test_id(1);
    let user2 = PrincipalId::new_user_test_id(2);
    let user3 = PrincipalId::new_user_test_id(3);
    let user4 = PrincipalId::new_user_test_id(4);

    let mut swap = SwapBuilder::new()
        .with_sns_governance_canister_id(SNS_GOVERNANCE_CANISTER_ID)
        .with_lifecycle(Open)
        .with_swap_start_due(Some(START_TIMESTAMP_SECONDS), Some(END_TIMESTAMP_SECONDS))
        .with_min_participants(1)
        .with_min_max_participant_icp(2 * E8, 40 * E8)
        .with_min_max_direct_participation(5 * E8, 100 * E8)
        .with_sns_tokens(100_000 * E8)
        // An extremely large basket size, so we can reach MAX_NEURONS_FOR_DIRECT_PARTICIPANTS with
        // a relatively small number of participants.
        .with_neuron_basket_count(33_000)
        .with_neurons_fund_participation()
        .build();

    let params = swap.params.clone().unwrap();

    let amount_user1_0 = 5 * E8;
    let amount_user2_0 = 40 * E8;
    let amount_user3_0 = 40 * E8;
    let amount_user4_0 = 99 * E8 - (amount_user2_0 + amount_user3_0);

    // All tokens but one should be already bought up by users 2 to 4 --> 99 Tokens were bought
    buy_token_ok(&mut swap, &user2, &amount_user2_0, &amount_user2_0);
    buy_token_ok(&mut swap, &user3, &amount_user3_0, &amount_user3_0);
    buy_token_ok(&mut swap, &user4, &amount_user4_0, &amount_user4_0);

    // Make sure the 99 tokens were registered
    assert_eq!(
        swap.get_buyers_total().buyers_total,
        amount_user2_0 + amount_user3_0 + amount_user4_0
    );

    // Make sure that only an amount smaller than the minimum amount to be bought per user is available
    assert!(
        params.max_direct_participation_icp_e8s.unwrap() - swap.get_buyers_total().buyers_total
            < params.min_participant_icp_e8s
    );

    // No user that has not participated in the swap yet can buy this one token left
    buy_token_err(
        &mut swap,
        &user1,
        &amount_user1_0,
        "The swap has reached the maximum number of direct participants",
    );

    // The one token should still be left fur purchase
    check_final_conditions(
        &mut swap,
        &user2,
        &amount_user2_0,
        &(params.max_direct_participation_icp_e8s.unwrap() - E8),
    );
}

#[test]
fn test_refresh_buyer_tokens_minimum_tokens_requirement() {
    let user1 = PrincipalId::new_user_test_id(1);
    let user2 = PrincipalId::new_user_test_id(2);
    let user3 = PrincipalId::new_user_test_id(3);

    let mut swap = SwapBuilder::new()
        .with_sns_governance_canister_id(SNS_GOVERNANCE_CANISTER_ID)
        .with_lifecycle(Open)
        .with_swap_start_due(Some(START_TIMESTAMP_SECONDS), Some(END_TIMESTAMP_SECONDS))
        .with_min_participants(1)
        .with_min_max_participant_icp(2 * E8, 40 * E8)
        .with_min_max_direct_participation(5 * E8, 100 * E8)
        .with_sns_tokens(100_000 * E8)
        .with_neuron_basket_count(3)
        .with_neurons_fund_participation()
        .build();

    let amount_user1_0 = E8;
    let amount_user2_0 = 40 * E8;
    let amount_user3_0 = 10 * E8;

    buy_token_ok(&mut swap, &user2, &amount_user2_0, &amount_user2_0);

    buy_token_ok(&mut swap, &user3, &amount_user3_0, &amount_user3_0);

    // One cannot buy fewer tokens than the minimum participation limit
    buy_token_err(
        &mut swap,
        &user1,
        &amount_user1_0,
        "minimum required to participate",
    );
}

#[test]
fn test_refresh_buyer_tokens_committed_tokens_below_minimum() {
    let user1 = PrincipalId::new_user_test_id(1);
    let user2 = PrincipalId::new_user_test_id(2);
    let user3 = PrincipalId::new_user_test_id(3);
    let user4 = PrincipalId::new_user_test_id(4);

    let mut swap = SwapBuilder::new()
        .with_sns_governance_canister_id(SNS_GOVERNANCE_CANISTER_ID)
        .with_lifecycle(Open)
        .with_swap_start_due(Some(START_TIMESTAMP_SECONDS), Some(END_TIMESTAMP_SECONDS))
        .with_min_participants(1)
        .with_min_max_participant_icp(2 * E8, 40 * E8)
        .with_min_max_direct_participation(5 * E8, 100 * E8)
        .with_sns_tokens(100_000 * E8)
        .with_neuron_basket_count(3)
        .with_neurons_fund_participation()
        .build();

    let params = swap.params.clone().unwrap();

    let amount_user1_0 = 3 * E8;
    let amount_user1_1 = 150_000_000;
    let amount_user2_0 = 40 * E8;
    let amount_user3_0 = 40 * E8;
    let amount_user4_0 = 99 * E8 - (amount_user2_0 + amount_user3_0 + amount_user1_0);

    buy_token_ok(&mut swap, &user1, &amount_user1_0, &amount_user1_0);

    buy_token_ok(&mut swap, &user2, &amount_user2_0, &amount_user2_0);

    buy_token_ok(&mut swap, &user3, &amount_user3_0, &amount_user3_0);

    buy_token_ok(&mut swap, &user4, &amount_user4_0, &amount_user4_0);

    assert_eq!(
        swap.get_buyers_total().buyers_total,
        amount_user2_0 + amount_user3_0 + amount_user4_0 + amount_user1_0
    );

    assert!(
        params.max_direct_participation_icp_e8s.unwrap() - swap.get_buyers_total().buyers_total
            < params.min_participant_icp_e8s
    );

    assert!(
        (params.max_direct_participation_icp_e8s.unwrap() - swap.get_buyers_total().buyers_total)
            < amount_user1_1
    );

    assert!(
        swap.buyers
            .get(&user1.to_string())
            .unwrap()
            .icp
            .as_ref()
            .unwrap()
            .amount_e8s
            > 0
    );

    assert!(amount_user1_1 < params.min_participant_icp_e8s);

    buy_token_ok(
        &mut swap,
        &user1,
        &(amount_user1_0 + amount_user1_1),
        &(amount_user1_0 + E8),
    );

    check_final_conditions(
        &mut swap,
        &user1,
        &(amount_user1_0 + E8),
        &(params.max_direct_participation_icp_e8s.unwrap()),
    );
}

#[test]
fn test_refresh_buyer_tokens_not_sending_additional_funds() {
    let user1 = PrincipalId::new_user_test_id(1);
    let user2 = PrincipalId::new_user_test_id(2);

    let mut swap = SwapBuilder::new()
        .with_sns_governance_canister_id(SNS_GOVERNANCE_CANISTER_ID)
        .with_lifecycle(Open)
        .with_swap_start_due(Some(START_TIMESTAMP_SECONDS), Some(END_TIMESTAMP_SECONDS))
        .with_min_participants(1)
        .with_min_max_participant_icp(2 * E8, 40 * E8)
        .with_min_max_direct_participation(5 * E8, 50 * E8)
        .with_sns_tokens(100_000 * E8)
        .with_neuron_basket_count(3)
        .with_neurons_fund_participation()
        .build();

    let amount_user1_0 = 3 * E8;
    let amount_user2_0 = 37 * E8;

    buy_token_ok(&mut swap, &user1, &amount_user1_0, &amount_user1_0);

    buy_token_ok(&mut swap, &user2, &amount_user2_0, &amount_user2_0);

    buy_token_ok(&mut swap, &user1, &amount_user1_0, &amount_user1_0);

    check_final_conditions(
        &mut swap,
        &user1,
        &(amount_user1_0),
        &(amount_user1_0 + amount_user2_0),
    );
}

#[test]
fn test_refresh_buyer_tokens_committing_with_no_funds_sent() {
    let user1 = PrincipalId::new_user_test_id(1);
    let user2 = PrincipalId::new_user_test_id(2);
    let user3 = PrincipalId::new_user_test_id(3);
    let user4 = PrincipalId::new_user_test_id(4);

    let mut swap = SwapBuilder::new()
        .with_sns_governance_canister_id(SNS_GOVERNANCE_CANISTER_ID)
        .with_lifecycle(Open)
        .with_swap_start_due(Some(START_TIMESTAMP_SECONDS), Some(END_TIMESTAMP_SECONDS))
        .with_min_participants(1)
        .with_min_max_participant_icp(2 * E8, 40 * E8)
        .with_min_max_direct_participation(5 * E8, 100 * E8)
        .with_sns_tokens(100_000 * E8)
        .with_neuron_basket_count(3)
        .with_neurons_fund_participation()
        .build();

    let params = swap.params.clone().unwrap();

    let amount_user1_0 = 3 * E8;
    let amount_user2_0 = 40 * E8;
    let amount_user3_0 = 40 * E8;
    let amount_user4_0 = 18 * E8;

    buy_token_ok(&mut swap, &user2, &amount_user2_0, &amount_user2_0);

    buy_token_ok(&mut swap, &user3, &amount_user3_0, &amount_user3_0);

    buy_token_ok(&mut swap, &user4, &amount_user4_0, &amount_user4_0);

    assert_eq!(
        params.max_direct_participation_icp_e8s.unwrap() - swap.get_buyers_total().buyers_total,
        2 * E8
    );

    buy_token_ok(&mut swap, &user1, &amount_user1_0, &(2 * E8));

    check_final_conditions(
        &mut swap,
        &user1,
        &(2 * E8),
        &(params.max_direct_participation_icp_e8s.unwrap()),
    );
}

#[test]
fn test_refresh_buyer_tokens_with_neurons_fund_matched_funding() {
    let user1 = PrincipalId::new_user_test_id(1);
    let user2 = PrincipalId::new_user_test_id(2);
    let user3 = PrincipalId::new_user_test_id(3);
    let buy_token_ok = |swap: &mut Swap,
                        user: &PrincipalId,
                        icp_ledger_account_balance_e8s: u64,
                        icp_accepted_participation_e8s: u64| {
        assert_eq!(
            swap.refresh_buyer_token_e8s(
                *user,
                None,
                SWAP_CANISTER_ID,
                &mock_stub(vec![LedgerExpect::AccountBalance(
                    Account {
                        owner: SWAP_CANISTER_ID.get().into(),
                        subaccount: Some(principal_to_subaccount(user)),
                    },
                    Ok(Tokens::from_e8s(icp_ledger_account_balance_e8s)),
                )]),
            )
            .now_or_never()
            .unwrap()
            .unwrap(),
            RefreshBuyerTokensResponse {
                icp_accepted_participation_e8s,
                icp_ledger_account_balance_e8s,
            }
        );
    };

    let user_1_participation_amount_icp_e8s = 250_000 * E8;
    let user_2_participation_amount_icp_e8s = 150_000 * E8;
    let user_3_participation_amount_icp_e8s = 100_000 * E8;

    let nf_user_1_participation_amount_icp_e8s = 222_000 * E8;
    let nf_user_2_participation_amount_icp_e8s = 333_000 * E8;
    let nf_user_3_participation_amount_icp_e8s = 444_000 * E8;

    let max_direct_participation_icp_e8s = 500_000 * E8;

    let total_nf_maturity_equivalent_icp_e8s = 4_000_000 * E8;
    let max_neurons_fund_participation_icp_e8s = total_nf_maturity_equivalent_icp_e8s / 10;

    let mut swap = SwapBuilder::new()
        .with_sns_governance_canister_id(SNS_GOVERNANCE_CANISTER_ID)
        .with_lifecycle(Open)
        .with_min_participants(2)
        .with_min_max_participant_icp(2 * E8, 350_000 * E8)
        .with_min_max_direct_participation(250_000 * E8, 500_000 * E8)
        .with_sns_tokens(1_000_000 * E8)
        .with_neuron_basket_count(3)
        .with_neurons_fund_participation()
        .with_neurons_fund_participation_constraints(NeuronsFundParticipationConstraints {
            min_direct_participation_threshold_icp_e8s: Some(250_000 * E8),
            max_neurons_fund_participation_icp_e8s: Some(max_neurons_fund_participation_icp_e8s),
            // Set `slope_numerator` to zero, so the outcome does not depend on the kind of matching
            // function that is used. Only `intercept_icp_e8s` will have an impact on the amount
            // that the Neurons' Fund participates on each of the three intervals.
            coefficient_intervals: vec![
                LinearScalingCoefficient {
                    from_direct_participation_icp_e8s: Some(0),
                    to_direct_participation_icp_e8s: Some(250_000 * E8),
                    slope_numerator: Some(0),
                    slope_denominator: Some(1),
                    intercept_icp_e8s: Some(0),
                },
                LinearScalingCoefficient {
                    from_direct_participation_icp_e8s: Some(250_000 * E8),
                    to_direct_participation_icp_e8s: Some(400_000 * E8),
                    slope_numerator: Some(0),
                    slope_denominator: Some(1),
                    intercept_icp_e8s: Some(nf_user_1_participation_amount_icp_e8s),
                },
                LinearScalingCoefficient {
                    from_direct_participation_icp_e8s: Some(400_000 * E8),
                    to_direct_participation_icp_e8s: Some(500_000 * E8),
                    slope_numerator: Some(0),
                    slope_denominator: Some(1),
                    intercept_icp_e8s: Some(nf_user_2_participation_amount_icp_e8s),
                },
                LinearScalingCoefficient {
                    from_direct_participation_icp_e8s: Some(500_000 * E8),
                    to_direct_participation_icp_e8s: Some(u64::MAX),
                    slope_numerator: Some(0),
                    slope_denominator: Some(1),
                    intercept_icp_e8s: Some(nf_user_3_participation_amount_icp_e8s),
                },
            ],
            ideal_matched_participation_function: Some(IdealMatchedParticipationFunction {
                serialized_representation: Some(
                    (PolynomialMatchingFunction::new(
                        total_nf_maturity_equivalent_icp_e8s,
                        neurons_fund_participation_limits(),
                    )
                    .unwrap())
                    .serialize(),
                ),
            }),
        })
        .build();

    // Starting conditions
    assert_eq!(
        swap.max_direct_participation_e8s(),
        max_direct_participation_icp_e8s
    );
    assert_eq!(swap.current_neurons_fund_participation_e8s(), 0);
    assert_eq!(swap.current_direct_participation_e8s(), 0);
    assert_eq!(swap.current_total_participation_e8s(), 0);
    assert_eq!(
        swap.available_direct_participation_e8s(),
        max_direct_participation_icp_e8s
    );

    buy_token_ok(
        &mut swap,
        &user1,
        user_1_participation_amount_icp_e8s,
        user_1_participation_amount_icp_e8s,
    );

    assert_eq!(
        swap.max_direct_participation_e8s(),
        max_direct_participation_icp_e8s
    );
    assert_eq!(
        swap.current_direct_participation_e8s(),
        user_1_participation_amount_icp_e8s
    );
    assert_eq!(
        swap.current_neurons_fund_participation_e8s(),
        nf_user_1_participation_amount_icp_e8s
    );
    assert_eq!(
        swap.current_total_participation_e8s(),
        user_1_participation_amount_icp_e8s + nf_user_1_participation_amount_icp_e8s
    );
    assert_eq!(
        swap.available_direct_participation_e8s(),
        max_direct_participation_icp_e8s - user_1_participation_amount_icp_e8s
    );

    buy_token_ok(
        &mut swap,
        &user2,
        user_2_participation_amount_icp_e8s,
        user_2_participation_amount_icp_e8s,
    );

    assert_eq!(
        swap.max_direct_participation_e8s(),
        max_direct_participation_icp_e8s
    );
    assert_eq!(
        swap.current_neurons_fund_participation_e8s(),
        nf_user_2_participation_amount_icp_e8s
    );
    assert_eq!(
        swap.current_direct_participation_e8s(),
        user_1_participation_amount_icp_e8s + user_2_participation_amount_icp_e8s
    );
    assert_eq!(
        swap.current_total_participation_e8s(),
        user_1_participation_amount_icp_e8s
            + user_2_participation_amount_icp_e8s
            + nf_user_2_participation_amount_icp_e8s
    );
    assert_eq!(
        swap.available_direct_participation_e8s(),
        max_direct_participation_icp_e8s
            - user_1_participation_amount_icp_e8s
            - user_2_participation_amount_icp_e8s
    );

    buy_token_ok(
        &mut swap,
        &user3,
        user_3_participation_amount_icp_e8s,
        user_3_participation_amount_icp_e8s,
    );

    assert_eq!(
        swap.max_direct_participation_e8s(),
        max_direct_participation_icp_e8s
    );
    assert_eq!(
        swap.current_neurons_fund_participation_e8s(),
        max_neurons_fund_participation_icp_e8s
    );
    assert_eq!(
        swap.current_direct_participation_e8s(),
        user_1_participation_amount_icp_e8s
            + user_2_participation_amount_icp_e8s
            + user_3_participation_amount_icp_e8s
    );
    assert_eq!(
        swap.current_total_participation_e8s(),
        user_1_participation_amount_icp_e8s
            + user_2_participation_amount_icp_e8s
            + user_3_participation_amount_icp_e8s
            + max_neurons_fund_participation_icp_e8s
    );
    assert_eq!(swap.available_direct_participation_e8s(), 0);
}

/// Similar to `test_refresh_buyer_tokens_with_neurons_fund_matched_funding`, but we switch off
/// Neurons' Fund participation and expect there not to be any Neurons' Fund participation.
#[test]
fn test_refresh_buyer_tokens_without_neurons_fund_matched_funding() {
    let user1 = PrincipalId::new_user_test_id(1);
    let user2 = PrincipalId::new_user_test_id(2);
    let user3 = PrincipalId::new_user_test_id(3);
    let buy_token_ok = |swap: &mut Swap,
                        user: &PrincipalId,
                        icp_ledger_account_balance_e8s: u64,
                        icp_accepted_participation_e8s: u64| {
        assert_eq!(
            swap.refresh_buyer_token_e8s(
                *user,
                None,
                SWAP_CANISTER_ID,
                &mock_stub(vec![LedgerExpect::AccountBalance(
                    Account {
                        owner: SWAP_CANISTER_ID.get().into(),
                        subaccount: Some(principal_to_subaccount(user)),
                    },
                    Ok(Tokens::from_e8s(icp_ledger_account_balance_e8s)),
                )]),
            )
            .now_or_never()
            .unwrap()
            .unwrap(),
            RefreshBuyerTokensResponse {
                icp_accepted_participation_e8s,
                icp_ledger_account_balance_e8s,
            }
        );
    };

    let params = Some(Params {
        min_direct_participation_icp_e8s: Some(250_000 * E8),
        max_direct_participation_icp_e8s: Some(500_000 * E8),
        min_participant_icp_e8s: 2 * E8,
        max_participant_icp_e8s: 350_000 * E8,
        sns_token_e8s: 1_000_000 * E8,
        min_participants: 2,
        ..params()
    });
    let user_1_participation_amount_icp_e8s = 250_000 * E8;
    let user_2_participation_amount_icp_e8s = 150_000 * E8;
    let user_3_participation_amount_icp_e8s = 100_000 * E8;

    let max_direct_participation_icp_e8s = 500_000 * E8;

    let total_nf_maturity_equivalent_icp_e8s = 2_000_000 * E8;

    let mut swap = {
        let mut init = init_with_neurons_fund_funding();
        let neurons_fund_participation_constraints = Some(NeuronsFundParticipationConstraints {
            min_direct_participation_threshold_icp_e8s: Some(250_000 * E8),
            max_neurons_fund_participation_icp_e8s: Some(total_nf_maturity_equivalent_icp_e8s / 10),
            // Set `slope_numerator` to zero, so the outcome does not depend on the kind of matching
            // function that is used. Only `intercept_icp_e8s` will have an impact on the amount
            // that the Neurons' Fund participates on each of the three intervals.
            coefficient_intervals: vec![LinearScalingCoefficient {
                from_direct_participation_icp_e8s: Some(0),
                to_direct_participation_icp_e8s: Some(u64::MAX),
                // Does not matter what we set hese fields to (as long as the payload validates),
                // as the function should never be applied with the below `Init`:
                // neurons_fund_participation: Some(false).
                slope_numerator: Some(123_456_678 * E8),
                slope_denominator: Some(123_456_678 * E8),
                intercept_icp_e8s: Some(123_456_678 * E8),
            }],
            ideal_matched_participation_function: Some(IdealMatchedParticipationFunction {
                serialized_representation: Some(
                    (PolynomialMatchingFunction::new(
                        total_nf_maturity_equivalent_icp_e8s,
                        neurons_fund_participation_limits(),
                    )
                    .unwrap())
                    .serialize(),
                ),
            }),
        });
        println!("{:#?}", neurons_fund_participation_constraints);
        init = Init {
            neurons_fund_participation_constraints,
            neurons_fund_participation: Some(false),
            ..init
        };
        init.validate().unwrap();
        let swap = Swap::new(init);
        Swap {
            params,
            lifecycle: Open as i32,
            ..swap
        }
    };

    // Starting conditions
    assert_eq!(
        swap.max_direct_participation_e8s(),
        max_direct_participation_icp_e8s
    );
    assert_eq!(swap.current_neurons_fund_participation_e8s(), 0);
    assert_eq!(swap.current_direct_participation_e8s(), 0);
    assert_eq!(swap.current_total_participation_e8s(), 0);
    assert_eq!(
        swap.available_direct_participation_e8s(),
        max_direct_participation_icp_e8s
    );

    buy_token_ok(
        &mut swap,
        &user1,
        user_1_participation_amount_icp_e8s,
        user_1_participation_amount_icp_e8s,
    );

    assert_eq!(
        swap.max_direct_participation_e8s(),
        max_direct_participation_icp_e8s
    );
    assert_eq!(
        swap.current_direct_participation_e8s(),
        user_1_participation_amount_icp_e8s
    );
    assert_eq!(swap.current_neurons_fund_participation_e8s(), 0);
    assert_eq!(
        swap.current_total_participation_e8s(),
        user_1_participation_amount_icp_e8s
    );
    assert_eq!(
        swap.available_direct_participation_e8s(),
        max_direct_participation_icp_e8s - user_1_participation_amount_icp_e8s
    );

    buy_token_ok(
        &mut swap,
        &user2,
        user_2_participation_amount_icp_e8s,
        user_2_participation_amount_icp_e8s,
    );

    assert_eq!(
        swap.max_direct_participation_e8s(),
        max_direct_participation_icp_e8s
    );
    assert_eq!(swap.current_neurons_fund_participation_e8s(), 0);
    assert_eq!(
        swap.current_direct_participation_e8s(),
        user_1_participation_amount_icp_e8s + user_2_participation_amount_icp_e8s
    );
    assert_eq!(
        swap.current_total_participation_e8s(),
        user_1_participation_amount_icp_e8s + user_2_participation_amount_icp_e8s
    );
    assert_eq!(
        swap.available_direct_participation_e8s(),
        max_direct_participation_icp_e8s
            - user_1_participation_amount_icp_e8s
            - user_2_participation_amount_icp_e8s
    );

    buy_token_ok(
        &mut swap,
        &user3,
        user_3_participation_amount_icp_e8s,
        user_3_participation_amount_icp_e8s,
    );

    assert_eq!(
        swap.max_direct_participation_e8s(),
        max_direct_participation_icp_e8s
    );
    assert_eq!(swap.current_neurons_fund_participation_e8s(), 0);
    assert_eq!(
        swap.current_direct_participation_e8s(),
        user_1_participation_amount_icp_e8s
            + user_2_participation_amount_icp_e8s
            + user_3_participation_amount_icp_e8s
    );
    assert_eq!(
        swap.current_total_participation_e8s(),
        user_1_participation_amount_icp_e8s
            + user_2_participation_amount_icp_e8s
            + user_3_participation_amount_icp_e8s
    );
    assert_eq!(swap.available_direct_participation_e8s(), 0);
}

/// Test that the `refresh_buyer_token_e8s` function handles confirmations correctly.
#[test]
fn test_swap_participation_confirmation() {
    let confirmation_text = "Please confirm that 2+2=4".to_string();
    let another_text = "Please confirm that 2+2=5".to_string();
    let user = PrincipalId::new_user_test_id(1);
    let amount = 101 * E8;

    let buy_token = |swap: &mut Swap, confirmation_text: Option<String>| {
        swap.refresh_buyer_token_e8s(
            user,
            confirmation_text,
            SWAP_CANISTER_ID,
            &mock_stub(vec![LedgerExpect::AccountBalance(
                Account {
                    owner: SWAP_CANISTER_ID.get().into(),
                    subaccount: Some(principal_to_subaccount(&user)),
                },
                Ok(Tokens::from_e8s(amount)),
            )]),
        )
        .now_or_never()
        .unwrap()
    };

    // A. SNS specifies confirmation text & client sends confirmation text
    {
        let mut swap = SwapBuilder::new()
            .with_lifecycle(Open)
            .with_confirmation_text(confirmation_text.clone())
            .build();
        // A.1. The texts match
        assert_is_ok!(buy_token(&mut swap, Some(confirmation_text.clone())));
        // A.2. The texts do not match
        assert_is_err!(buy_token(&mut swap, Some(another_text)));
    }

    // B. SNS specifies confirmation text & client does not send a confirmation text
    {
        let mut swap = SwapBuilder::new()
            .with_lifecycle(Open)
            .with_confirmation_text(confirmation_text.clone())
            .build();
        assert_is_err!(buy_token(&mut swap, None));
    }

    // C. SNS does not specify confirmation text & client sends a confirmation text
    {
        let mut swap = SwapBuilder::new()
            .with_lifecycle(Open)
            .without_confirmation_text()
            .build();
        assert_is_err!(buy_token(&mut swap, Some(confirmation_text)));
    }

    // D. SNS does not specify confirmation text & client does not send a confirmation text
    {
        let mut swap = SwapBuilder::new()
            .with_lifecycle(Open)
            .without_confirmation_text()
            .build();
        assert_is_ok!(buy_token(&mut swap, None));
    }
}

/// Test that the `refresh_buyer_token_e8s` call fails in the special case when the remaining direct
/// participation amount is less than the minimal participation amount. In this scenario, the swap
/// cannot be finalized early by a new participant, only by an existing participant increasing their
/// participation.
#[test]
fn test_swap_cannot_finalize_via_new_participation_if_remaining_lt_minimal_participation_amount() {
    let user1 = PrincipalId::new_user_test_id(1);
    let user2 = PrincipalId::new_user_test_id(2);
    let call_refresh_buyer_token_e8s = |swap: &mut Swap,
                                        user: &PrincipalId,
                                        icp_ledger_account_balance_e8s: u64|
     -> Result<RefreshBuyerTokensResponse, String> {
        swap.refresh_buyer_token_e8s(
            *user,
            None,
            SWAP_CANISTER_ID,
            &mock_stub(vec![LedgerExpect::AccountBalance(
                Account {
                    owner: SWAP_CANISTER_ID.get().into(),
                    subaccount: Some(principal_to_subaccount(user)),
                },
                Ok(Tokens::from_e8s(icp_ledger_account_balance_e8s)),
            )]),
        )
        .now_or_never()
        .unwrap()
    };

    // The amount that will be participated by user 1 at the beginning.
    let user_1_first_participation_amount_icp_e8s = 400_000 * E8;

    // The amount that user 2 will attempt to participate with. Even though this is greater than
    // the per-participant minimum, it won't work, because there is "not enough room" left in
    // the swap to accept this user's participation while also honoring the per-participant minimum.
    let user_2_participation_amount_icp_e8s = 150_000 * E8;

    // The amount that will be participated by user 1 at the end.
    let user_1_second_participation_amount_icp_e8s = 100_000 * E8;

    let max_direct_participation_icp_e8s = 500_000 * E8;
    let total_nf_maturity_equivalent_icp_e8s = 2_000_000 * E8;
    let max_neurons_fund_participation_icp_e8s = total_nf_maturity_equivalent_icp_e8s / 10;

    // Slightly more than `user_2_participation_amount_icp_e8s`, but less than `user_1_first_participation_amount_icp_e8s`.
    let min_participant_icp_e8s = 150_000 * E8;

    let params = Some(Params {
        min_direct_participation_icp_e8s: Some(250_000 * E8),
        max_direct_participation_icp_e8s: Some(500_000 * E8),
        min_participant_icp_e8s,
        max_participant_icp_e8s: 500_000 * E8,
        sns_token_e8s: 1_000_000 * E8,
        min_participants: 1,
        ..params()
    });

    let mut swap = {
        // The Neuron's Fund should not affect the possibility of swap finalization.
        let mut init = init_with_neurons_fund_funding();

        let neurons_fund_participation_constraints = Some(NeuronsFundParticipationConstraints {
            min_direct_participation_threshold_icp_e8s: Some(250_000 * E8),
            max_neurons_fund_participation_icp_e8s: Some(max_neurons_fund_participation_icp_e8s),
            // Set `slope_numerator` to zero, so the outcome does not depend on the kind of matching
            // function that is used. Only `intercept_icp_e8s` will have an impact on the amount
            // that the Neurons' Fund participates on each of the three intervals.
            coefficient_intervals: vec![LinearScalingCoefficient {
                from_direct_participation_icp_e8s: Some(0),
                to_direct_participation_icp_e8s: Some(u64::MAX),
                // Does not matter what we set hese fields to (as long as the payload validates),
                // as the function should never be applied with the below `Init`:
                // neurons_fund_participation: Some(false).
                slope_numerator: Some(123_456_678 * E8),
                slope_denominator: Some(123_456_678 * E8),
                intercept_icp_e8s: Some(123_456_678 * E8),
            }],
            ideal_matched_participation_function: Some(IdealMatchedParticipationFunction {
                serialized_representation: Some(
                    PolynomialMatchingFunction::new(
                        total_nf_maturity_equivalent_icp_e8s,
                        neurons_fund_participation_limits(),
                    )
                    .unwrap()
                    .serialize(),
                ),
            }),
        });
        init = Init {
            neurons_fund_participation_constraints,
            neurons_fund_participation: Some(true),
            ..init
        };
        init.validate().unwrap();
        let swap = Swap::new(init);
        Swap {
            params,
            lifecycle: Open as i32,
            ..swap
        }
    };

    // Preconditions
    assert_eq!(swap.lifecycle(), Open);
    assert_eq!(
        swap.max_direct_participation_e8s(),
        max_direct_participation_icp_e8s
    );
    assert_eq!(swap.current_neurons_fund_participation_e8s(), 0);
    assert_eq!(swap.current_direct_participation_e8s(), 0);
    assert_eq!(swap.current_total_participation_e8s(), 0);
    assert_eq!(
        swap.available_direct_participation_e8s(),
        max_direct_participation_icp_e8s
    );

    // Operation A: User 1 participates with amount `user_1_first_participation_amount_icp_e8s`.
    assert_eq!(
        call_refresh_buyer_token_e8s(&mut swap, &user1, user_1_first_participation_amount_icp_e8s),
        Ok(RefreshBuyerTokensResponse {
            icp_accepted_participation_e8s: user_1_first_participation_amount_icp_e8s,
            icp_ledger_account_balance_e8s: user_1_first_participation_amount_icp_e8s,
        })
    );

    assert_eq!(swap.lifecycle(), Open);
    assert_eq!(
        swap.current_direct_participation_e8s(),
        user_1_first_participation_amount_icp_e8s
    );
    assert_eq!(
        swap.current_neurons_fund_participation_e8s(),
        max_neurons_fund_participation_icp_e8s
    );
    assert_eq!(
        swap.current_total_participation_e8s(),
        user_1_first_participation_amount_icp_e8s + max_neurons_fund_participation_icp_e8s
    );
    assert_eq!(
        swap.available_direct_participation_e8s(),
        max_direct_participation_icp_e8s - user_1_first_participation_amount_icp_e8s
    );

    // Operation B: User 2 attempts to participate with amount `user_2_participation_amount_icp_e8s`.
    assert_eq!(
        call_refresh_buyer_token_e8s(&mut swap, &user2, user_2_participation_amount_icp_e8s),
        Err(format!(
            "Rejecting participation of effective amount {}; minimum required to participate: {}",
            swap.available_direct_participation_e8s(),
            min_participant_icp_e8s
        ))
    );

    // Postcondition B: The state should not have changed, so we're still in the precondition state.
    assert_eq!(swap.lifecycle(), Open);
    assert_eq!(
        swap.current_direct_participation_e8s(),
        user_1_first_participation_amount_icp_e8s
    );
    assert_eq!(
        swap.current_neurons_fund_participation_e8s(),
        max_neurons_fund_participation_icp_e8s
    );
    assert_eq!(
        swap.current_total_participation_e8s(),
        user_1_first_participation_amount_icp_e8s + max_neurons_fund_participation_icp_e8s
    );
    assert_eq!(
        swap.available_direct_participation_e8s(),
        max_direct_participation_icp_e8s - user_1_first_participation_amount_icp_e8s
    );

    // Operation C: User 1 increases their participation by `user_1_second_participation_amount_icp_e8s`.
    assert_eq!(
        call_refresh_buyer_token_e8s(
            &mut swap,
            &user1,
            user_1_first_participation_amount_icp_e8s + user_1_second_participation_amount_icp_e8s
        ),
        Ok(RefreshBuyerTokensResponse {
            icp_accepted_participation_e8s: user_1_first_participation_amount_icp_e8s
                + user_1_second_participation_amount_icp_e8s,
            icp_ledger_account_balance_e8s: user_1_first_participation_amount_icp_e8s
                + user_1_second_participation_amount_icp_e8s,
        })
    );

    // Postcondition C
    assert_eq!(
        swap.current_direct_participation_e8s(),
        max_direct_participation_icp_e8s
    );
    assert_eq!(
        swap.current_neurons_fund_participation_e8s(),
        max_neurons_fund_participation_icp_e8s
    );
    assert_eq!(
        swap.current_total_participation_e8s(),
        max_direct_participation_icp_e8s + max_neurons_fund_participation_icp_e8s
    );
    assert_eq!(swap.available_direct_participation_e8s(), 0);

    // Operation D
    assert!(
        swap.try_commit(now_fn(true)),
        "cannot transition from Open to Committed"
    );
    assert_eq!(swap.lifecycle(), Committed);
}

/// Test that the get_state API bounds the dynamic data sources returned in the
/// GetStateResponse.
#[test]
fn test_get_state_bounds_data_sources() {
    // Prepare the canister with multiple buyers
    let mut swap = Swap {
        lifecycle: Committed as i32,
        params: Some(params()),
        init: Some(init()),
        buyers: btreemap! {
            i2principal_id_string(1) => BuyerState::new(E8),
        },
        neuron_recipes: create_generic_sns_neuron_recipes(1),
        cf_participants: create_generic_cf_participants(1),
        ..Default::default()
    };
    swap.update_derived_fields();

    let get_state_response = swap.get_state();
    let derived_state = get_state_response.derived.unwrap();
    // 1 CF participant and 1 direct participant at 1 E8 each
    assert_eq!(derived_state.buyer_total_icp_e8s, 2 * E8);
    // Exact exchange rate is not important to this test, just that it is set
    assert!(derived_state.sns_tokens_per_icp >= 0.0f32);

    let swap_state = get_state_response.swap.unwrap();
    // Assert that unbounded data sources are set to empty structs in the response
    assert!(swap_state.cf_participants.is_empty());
    assert!(swap_state.neuron_recipes.is_empty());
    assert!(swap_state.buyers.is_empty());

    // Assert that the origin data sources are still populated
    assert!(!swap.cf_participants.is_empty());
    assert!(!swap.neuron_recipes.is_empty());
    assert!(!swap.buyers.is_empty());
}

/// Assert that an aborted swap that successfully refunds buyers also clears these buyers' buyer
/// state (i.e. sets their committed amounts to 0).
#[tokio::test]
async fn test_finalize_swap_abort_sets_amount_transferred_and_fees_correctly() {
    let buyer = PrincipalId::new_user_test_id(1);
    let e8s = 50 * E8;
    // Create a swap in state aborted
    let mut swap = Swap {
        lifecycle: Aborted as i32,
        init: Some(init()),
        params: Some(params()),
        buyers: btreemap! {
            Principal::from(buyer).to_text() => BuyerState::new(e8s), // Valid
        },
        ..Default::default()
    };

    // Verify that the buyer state was updated as expected
    let req = GetBuyerStateRequest {
        principal_id: Some(buyer),
    };
    let response = swap.get_buyer_state(&req);
    assert_eq!(e8s, response.buyer_state.unwrap().amount_icp_e8s());

    let mut clients = CanisterClients {
        sns_root: SpySnsRootClient::new(vec![
            // Add a mock reply of a successful call to SNS Root
            SnsRootClientReply::successful_set_dapp_controllers(),
        ]),
        icp_ledger: SpyLedger::new(
            // ICP Ledger should be called once and should return success
            vec![LedgerReply::TransferFunds(Ok(1000))],
        ),
        nns_governance: SpyNnsGovernanceClient::new(vec![
            NnsGovernanceClientReply::SettleNeuronsFundParticipation(
                SettleNeuronsFundParticipationResponse {
                    result: Some(settle_neurons_fund_participation_response::Result::Ok(
                        settle_neurons_fund_participation_response::Ok {
                            neurons_fund_neuron_portions: vec![],
                        },
                    )),
                },
            ),
        ]),
        ..spy_clients()
    };

    let response = swap.finalize(now_fn, &mut clients).await;

    // Successful sweep_icp
    assert_eq!(
        response.sweep_icp_result,
        Some(SweepResult {
            success: 1, // Single valid buyer
            skipped: 0,
            failure: 0,
            invalid: 0,
            global_failures: 0,
        })
    );

    // After a user is refunded, their buyer state should be cleared
    let response = swap.get_buyer_state(&req);
    assert_eq!(
        response.buyer_state.unwrap(),
        BuyerState {
            icp: Some(TransferableAmount {
                amount_e8s: 50 * E8,
                transfer_start_timestamp_seconds: END_TIMESTAMP_SECONDS + 5,
                transfer_success_timestamp_seconds: END_TIMESTAMP_SECONDS + 10,
                amount_transferred_e8s: Some(50 * E8 - DEFAULT_TRANSFER_FEE.get_e8s()),
                transfer_fee_paid_e8s: Some(DEFAULT_TRANSFER_FEE.get_e8s())
            }),
            has_created_neuron_recipes: Some(false),
        },
    );
}
