use crate::common::{
    buy_token, compute_multiple_successful_claim_swap_neurons_response,
    compute_single_successful_claim_swap_neurons_response, create_generic_cf_participants,
    create_generic_sns_neuron_recipes, create_single_neuron_recipe,
    doubles::{
        ExplodingSnsRootClient, LedgerExpect, NnsGovernanceClientCall, NnsGovernanceClientReply,
        SnsGovernanceClientCall, SnsGovernanceClientReply, SnsRootClientCall, SnsRootClientReply,
        SpyNnsGovernanceClient, SpySnsGovernanceClient, SpySnsRootClient,
    },
    extract_canister_call_error, extract_set_dapp_controller_response,
    get_account_balance_mock_ledger, get_snapshot_of_buyers_index_list, get_sns_balance,
    get_transfer_and_account_balance_mock_ledger, get_transfer_mock_ledger, i2principal_id_string,
    mock_stub, open_swap, paginate_participants, successful_set_dapp_controllers_call_result,
    successful_set_mode_call_result, successful_settle_community_fund_participation_result, sweep,
    try_error_refund_err, try_error_refund_ok, verify_participant_balances, TestInvestor,
};
use candid::Principal;
use error_refund_icp_response::err::Type::Precondition;
use futures::{channel::mpsc, future::FutureExt, StreamExt};
use ic_base_types::{CanisterId, PrincipalId};
use ic_ledger_core::Tokens;
use ic_nervous_system_common::{
    assert_is_err, assert_is_ok, ledger::compute_neuron_staking_subaccount_bytes,
    NervousSystemError, E8, SECONDS_PER_DAY, START_OF_2022_TIMESTAMP_SECONDS,
};
use ic_nervous_system_common_test_keys::{
    TEST_USER1_PRINCIPAL, TEST_USER2_PRINCIPAL, TEST_USER3_PRINCIPAL,
};
use ic_nervous_system_common_test_utils::{
    drain_receiver_channel, InterleavingTestLedger, LedgerCall, LedgerControlMessage, LedgerReply,
    SpyLedger,
};
use ic_nervous_system_proto::pb::v1::Countries;
use ic_sns_governance::{
    pb::v1::{
        claim_swap_neurons_request::NeuronParameters,
        claim_swap_neurons_response::ClaimSwapNeuronsResult, governance, ClaimSwapNeuronsRequest,
        NeuronId, SetMode, SetModeResponse,
    },
    types::ONE_MONTH_SECONDS,
};
use ic_sns_swap::{
    memory,
    pb::v1::{
        params::NeuronBasketConstructionParameters,
        sns_neuron_recipe::{ClaimedStatus, Investor, NeuronAttributes},
        Lifecycle::{Aborted, Adopted, Committed, Open, Pending, Unspecified},
        SetDappControllersRequest, SetDappControllersResponse, *,
    },
    swap::{
        apportion_approximately_equally, principal_to_subaccount, CLAIM_SWAP_NEURONS_BATCH_SIZE,
        FIRST_PRINCIPAL_BYTES, SALE_NEURON_MEMO_RANGE_START,
    },
};
use icp_ledger::DEFAULT_TRANSFER_FEE;
use icrc_ledger_types::icrc1::account::Account;
use maplit::btreemap;
use std::{
    collections::HashSet,
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

const START_TIMESTAMP_SECONDS: u64 = START_OF_2022_TIMESTAMP_SECONDS + 42 * SECONDS_PER_DAY;
const END_TIMESTAMP_SECONDS: u64 = START_TIMESTAMP_SECONDS + 7 * SECONDS_PER_DAY;

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
    };
    assert_is_ok!(result.validate());
    result
}

fn init() -> Init {
    init_with_confirmation_text(None)
}

pub fn params() -> Params {
    let result = Params {
        min_participants: 3,
        min_icp_e8s: 1,
        max_icp_e8s: 1_000_000 * E8,
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
    assert!(result.is_valid_if_initiated_at(START_TIMESTAMP_SECONDS));
    assert!(result.validate(&init()).is_ok());
    result
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
        buyers: btreemap! {
            i2principal_id_string(1001) => BuyerState::new(50 * E8),
        },
        cf_participants: vec![],
        neuron_recipes: vec![create_single_neuron_recipe(
            params.sns_token_e8s,
            i2principal_id_string(1001),
        )],
        open_sns_token_swap_proposal_id: Some(OPEN_SNS_TOKEN_SWAP_PROPOSAL_ID),
        finalize_swap_in_progress: None,
        decentralization_sale_open_timestamp_seconds: None,
        next_ticket_id: Some(0),
        purge_old_tickets_last_completion_timestamp_nanoseconds: Some(0),
        purge_old_tickets_next_principal: Some(FIRST_PRINCIPAL_BYTES.to_vec()),
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
    let swap = Swap::new(init());
    assert!(swap.validate().is_ok());
}

#[test]
fn test_open() {
    let mut swap = Swap::new(init());
    let account = Account {
        owner: SWAP_CANISTER_ID.get().into(),
        subaccount: None,
    };
    let params = params();
    let open_request = OpenRequest {
        params: Some(params.clone()),
        cf_participants: vec![],
        open_sns_token_swap_proposal_id: Some(OPEN_SNS_TOKEN_SWAP_PROPOSAL_ID),
    };
    // Cannot open as the swap has not received its initial funding yet (zero).
    {
        let r = swap
            .open(
                SWAP_CANISTER_ID,
                &mock_stub(vec![LedgerExpect::AccountBalance(
                    account,
                    Ok(Tokens::ZERO),
                )]),
                START_TIMESTAMP_SECONDS,
                open_request.clone(),
            )
            .now_or_never()
            .unwrap();
        assert!(r.is_err());
    }
    // Cannot open as the swap has not received its initial funding yet (error).
    {
        let r = swap
            .open(
                SWAP_CANISTER_ID,
                &mock_stub(vec![LedgerExpect::AccountBalance(account, Err(13))]),
                START_TIMESTAMP_SECONDS,
                open_request.clone(),
            )
            .now_or_never()
            .unwrap();
        assert!(r.is_err());
    }
    // Cannot open as the swap has not received all of its initial funding yet.
    {
        let r = swap
            .open(
                SWAP_CANISTER_ID,
                &mock_stub(vec![LedgerExpect::AccountBalance(
                    account,
                    Ok(Tokens::from_e8s(params.sns_token_e8s - 1)),
                )]),
                START_TIMESTAMP_SECONDS,
                open_request.clone(),
            )
            .now_or_never()
            .unwrap();
        assert!(r.is_err());
    }
    // assert that before swap is open, no tokens are available for swap.
    assert_eq!(
        swap.sns_token_e8s().unwrap_err(),
        "Swap not open, no tokens available.".to_string()
    );
    // Funding is available - now we can open.
    {
        let r = swap
            .open(
                SWAP_CANISTER_ID,
                &mock_stub(vec![LedgerExpect::AccountBalance(
                    account,
                    Ok(Tokens::from_e8s(params.sns_token_e8s)),
                )]),
                START_TIMESTAMP_SECONDS,
                open_request,
            )
            .now_or_never()
            .unwrap();
        assert!(r.is_ok());
    }
    // Check that state is updated.
    assert_eq!(swap.sns_token_e8s().unwrap(), params.sns_token_e8s);
    assert_eq!(swap.lifecycle(), Open);
}

#[test]
fn test_open_with_delay() {
    let delay_seconds = 42;
    let init = init();
    let mut swap = Swap::new(init);
    let account = Account {
        owner: SWAP_CANISTER_ID.get().into(),
        subaccount: None,
    };
    let params = Params {
        sale_delay_seconds: Some(delay_seconds),
        ..params()
    };
    let open_request = OpenRequest {
        params: Some(params.clone()),
        cf_participants: vec![],
        open_sns_token_swap_proposal_id: Some(OPEN_SNS_TOKEN_SWAP_PROPOSAL_ID),
    };

    let r = swap
        .open(
            SWAP_CANISTER_ID,
            &mock_stub(vec![LedgerExpect::AccountBalance(
                account,
                Ok(Tokens::from_e8s(params.sns_token_e8s)),
            )]),
            START_TIMESTAMP_SECONDS,
            open_request,
        )
        .now_or_never()
        .unwrap();
    assert!(r.is_ok());

    // Check that state is updated.
    assert_eq!(swap.sns_token_e8s().unwrap(), params.sns_token_e8s);
    assert_eq!(swap.lifecycle(), Adopted);

    // Try opening before delay elapses, it should NOT succeed.
    let timestamp_before_delay = START_TIMESTAMP_SECONDS + delay_seconds - 1;
    assert!(!swap.can_open(START_TIMESTAMP_SECONDS));
    assert!(!swap.can_open(timestamp_before_delay));
    assert!(!swap.try_open_after_delay(timestamp_before_delay));
    assert_eq!(swap.lifecycle(), Adopted);

    // Try opening after delay elapses, it should succeed.
    let timestamp_after_delay = START_TIMESTAMP_SECONDS + delay_seconds + 1;
    assert!(swap.can_open(timestamp_after_delay));
    assert!(swap.try_open_after_delay(timestamp_after_delay));
    assert_eq!(swap.lifecycle(), Open);

    // Repeated opening fails.
    assert!(!swap.can_open(timestamp_after_delay));
    assert!(!swap.try_open_after_delay(timestamp_after_delay));
    assert_eq!(swap.lifecycle(), Open);
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
    let params = Params {
        max_icp_e8s: 10 * E8,
        min_icp_e8s: 5 * E8,
        min_participants: 2,
        min_participant_icp_e8s: E8,
        max_participant_icp_e8s: 5 * E8,
        ..params()
    };
    let account = Account {
        owner: SWAP_CANISTER_ID.get().into(),
        subaccount: None,
    };
    let mut swap = Swap::new(init());
    // Open swap.
    {
        let r = swap
            .open(
                SWAP_CANISTER_ID,
                &mock_stub(vec![LedgerExpect::AccountBalance(
                    account,
                    Ok(Tokens::from_e8s(params.sns_token_e8s)),
                )]),
                START_TIMESTAMP_SECONDS,
                OpenRequest {
                    params: Some(params),
                    cf_participants: vec![],
                    open_sns_token_swap_proposal_id: Some(OPEN_SNS_TOKEN_SWAP_PROPOSAL_ID),
                },
            )
            .now_or_never()
            .unwrap();
        assert!(r.is_ok());
    }
    assert_eq!(swap.lifecycle(), Open);
    // Cannot commit or abort, as the swap is not due yet.
    assert!(!swap.try_commit_or_abort(END_TIMESTAMP_SECONDS - 1));
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
    // This should now abort as the minimum hasn't been reached.
    assert!(swap.try_commit_or_abort(END_TIMESTAMP_SECONDS));
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
    let params = Params {
        max_icp_e8s: 10 * E8,
        min_icp_e8s: 5 * E8,
        min_participants: 2,
        min_participant_icp_e8s: E8,
        max_participant_icp_e8s: 5 * E8,
        ..params()
    };
    let account = Account {
        owner: SWAP_CANISTER_ID.get().into(),
        subaccount: None,
    };
    let mut swap = Swap::new(init());
    // Open swap.
    {
        let r = swap
            .open(
                SWAP_CANISTER_ID,
                &mock_stub(vec![LedgerExpect::AccountBalance(
                    account,
                    Ok(Tokens::from_e8s(params.sns_token_e8s)),
                )]),
                START_TIMESTAMP_SECONDS,
                OpenRequest {
                    params: Some(params),
                    cf_participants: vec![],
                    open_sns_token_swap_proposal_id: Some(OPEN_SNS_TOKEN_SWAP_PROPOSAL_ID),
                },
            )
            .now_or_never()
            .unwrap();
        assert!(r.is_ok());
    }
    assert_eq!(swap.lifecycle(), Open);
    // Cannot commit or abort, as the swap is not due yet.
    assert!(!swap.try_commit_or_abort(END_TIMESTAMP_SECONDS - 1));
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
        assert!(swap.buyers.get(&TEST_USER1_PRINCIPAL.to_string()).is_none());
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
    let params = Params {
        max_icp_e8s: 10 * E8,
        min_icp_e8s: 5 * E8,
        min_participants: 2,
        min_participant_icp_e8s: /* 1 */ E8,
        max_participant_icp_e8s: 6 * E8,
        ..params()
    };
    let account = Account {
        owner: SWAP_CANISTER_ID.get().into(),
        subaccount: None,
    };
    let mut swap = Swap::new(init());
    // Open swap.
    {
        let r = swap
            .open(
                SWAP_CANISTER_ID,
                &mock_stub(vec![LedgerExpect::AccountBalance(
                    account,
                    Ok(Tokens::from_e8s(params.sns_token_e8s)),
                )]),
                START_TIMESTAMP_SECONDS,
                OpenRequest {
                    params: Some(params),
                    cf_participants: vec![],
                    open_sns_token_swap_proposal_id: Some(OPEN_SNS_TOKEN_SWAP_PROPOSAL_ID),
                },
            )
            .now_or_never()
            .unwrap();
        assert!(r.is_ok());
    }
    assert_eq!(swap.lifecycle(), Open);
    // Cannot commit or abort, as the swap is not due yet.
    assert!(!swap.try_commit_or_abort(END_TIMESTAMP_SECONDS - 1));
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
    // This should commit...
    assert!(swap.try_commit_or_abort(END_TIMESTAMP_SECONDS - 1));
    assert_eq!(swap.lifecycle(), Committed);
    // Check that buyer balances are correct. Total SNS balance is 1M
    // and total ICP is 10, so 100k SNS tokens per ICP.
    verify_participant_balances(&swap, &TEST_USER1_PRINCIPAL, 6 * E8, 600000 * E8);
    verify_participant_balances(&swap, &TEST_USER2_PRINCIPAL, 4 * E8, 400000 * E8);
}

/// Test the happy path of a token swap. First 200k SNS tokens are
/// sent. Then three buyers commit 900 ICP, 600 ICP, and 400 ICP
/// respectively. The community fund commits 100 ICP from two
/// participants (one with two neurons and one with one neuron). Then
/// the swap is committed and the tokens distributed.
#[test]
fn test_scenario_happy() {
    let params = Params {
        sns_token_e8s: 200_000 * E8,
        min_participants: 5, // Two from the community fund, and three direct.
        ..params()
    };
    let account = Account {
        owner: SWAP_CANISTER_ID.get().into(),
        subaccount: None,
    };
    let mut swap = Swap::new(init());
    // Open swap.
    {
        let r = swap
            .open(
                SWAP_CANISTER_ID,
                &mock_stub(vec![LedgerExpect::AccountBalance(
                    account,
                    Ok(Tokens::from_e8s(params.sns_token_e8s)),
                )]),
                START_TIMESTAMP_SECONDS,
                OpenRequest {
                    params: Some(params.clone()),
                    cf_participants: vec![
                        CfParticipant {
                            hotkey_principal: TEST_USER1_PRINCIPAL.to_string(),
                            cf_neurons: vec![
                                CfNeuron {
                                    nns_neuron_id: 0x91,
                                    amount_icp_e8s: 50 * E8,
                                },
                                CfNeuron {
                                    nns_neuron_id: 0x92,
                                    amount_icp_e8s: 30 * E8,
                                },
                            ],
                        },
                        CfParticipant {
                            hotkey_principal: TEST_USER2_PRINCIPAL.to_string(),
                            cf_neurons: vec![CfNeuron {
                                nns_neuron_id: 0x93,
                                amount_icp_e8s: 20 * E8,
                            }],
                        },
                    ],
                    open_sns_token_swap_proposal_id: Some(OPEN_SNS_TOKEN_SWAP_PROPOSAL_ID),
                },
            )
            .now_or_never()
            .unwrap();
        assert!(r.is_ok());
    }
    assert_eq!(swap.lifecycle(), Open);
    assert_eq!(swap.sns_token_e8s().unwrap(), 200_000 * E8);
    // Cannot (re)-open, as already opened.
    assert!(!swap.can_open(END_TIMESTAMP_SECONDS));
    assert!(!swap.try_open_after_delay(END_TIMESTAMP_SECONDS));
    // Cannot commit or abort, as the swap is not due yet.
    assert!(!swap.try_commit_or_abort(END_TIMESTAMP_SECONDS - 1));
    // Deposit 900 ICP from one buyer.
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
    assert!(!swap.try_commit_or_abort(END_TIMESTAMP_SECONDS - 1));
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
    // could be aborted...
    {
        let mut abort_swap = swap.clone();
        assert!(abort_swap.try_commit_or_abort(END_TIMESTAMP_SECONDS));
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
    // This should commit...
    assert!(swap.try_commit_or_abort(END_TIMESTAMP_SECONDS));
    assert_eq!(swap.lifecycle(), Committed);
    // Should not be able to re-open after commit.
    assert!(!swap.can_open(END_TIMESTAMP_SECONDS));
    assert!(!swap.try_open_after_delay(END_TIMESTAMP_SECONDS));
    // Check that buyer balances are correct. Total SNS balance is
    // 200k and total ICP is 2k.
    verify_participant_balances(&swap, &TEST_USER1_PRINCIPAL, 900 * E8, 90000 * E8);
    verify_participant_balances(&swap, &TEST_USER2_PRINCIPAL, 600 * E8, 60000 * E8);
    verify_participant_balances(&swap, &TEST_USER3_PRINCIPAL, 400 * E8, 40000 * E8);

    for recipe in &swap.neuron_recipes {
        assert_eq!(
            recipe.claimed_status,
            Some(ClaimedStatus::Pending as i32),
            "Recipe for {:?} des not have the correct claim status ({:?})",
            recipe.investor,
            recipe.claimed_status,
        );
    }

    {
        // "Sweep" all ICP, going to the governance canister. Mock one failure.
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
                        600 * E8 - DEFAULT_TRANSFER_FEE.get_e8s(),
                        DEFAULT_TRANSFER_FEE.get_e8s(),
                        Some(principal_to_subaccount(&TEST_USER2_PRINCIPAL)),
                        Account {
                            owner: SNS_GOVERNANCE_CANISTER_ID.get().into(),
                            subaccount: None,
                        },
                        0,
                        Err(77),
                    ),
                    LedgerExpect::TransferFunds(
                        400 * E8 - DEFAULT_TRANSFER_FEE.get_e8s(),
                        DEFAULT_TRANSFER_FEE.get_e8s(),
                        Some(principal_to_subaccount(&TEST_USER3_PRINCIPAL)),
                        Account {
                            owner: SNS_GOVERNANCE_CANISTER_ID.get().into(),
                            subaccount: None,
                        },
                        0,
                        Ok(1066),
                    ),
                    LedgerExpect::TransferFunds(
                        900 * E8 - DEFAULT_TRANSFER_FEE.get_e8s(),
                        DEFAULT_TRANSFER_FEE.get_e8s(),
                        Some(principal_to_subaccount(&TEST_USER1_PRINCIPAL)),
                        Account {
                            owner: SNS_GOVERNANCE_CANISTER_ID.get().into(),
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
        assert_eq!(failure, 1);
        assert_eq!(invalid, 0);
        assert_eq!(global_failures, 0);
        let SweepResult {
            success,
            failure,
            skipped,
            invalid,
            global_failures,
        } = swap
            .sweep_icp(
                now_fn,
                &mock_stub(vec![LedgerExpect::TransferFunds(
                    600 * E8 - DEFAULT_TRANSFER_FEE.get_e8s(),
                    DEFAULT_TRANSFER_FEE.get_e8s(),
                    Some(principal_to_subaccount(&TEST_USER2_PRINCIPAL)),
                    Account {
                        owner: SNS_GOVERNANCE_CANISTER_ID.get().into(),
                        subaccount: None,
                    },
                    0,
                    Ok(1068),
                )]),
            )
            .now_or_never()
            .unwrap();
        assert_eq!(skipped, 2);
        assert_eq!(success, 1);
        assert_eq!(failure, 0);
        assert_eq!(invalid, 0);
        assert_eq!(global_failures, 0);
        // "Sweep" all SNS tokens, going to the buyers.
        fn dst(controller: PrincipalId, memo: u64) -> Account {
            Account {
                owner: SNS_GOVERNANCE_CANISTER_ID.get().into(),
                subaccount: Some(compute_neuron_staking_subaccount_bytes(controller, memo)),
            }
        }
        fn cf(memo: u64) -> Account {
            Account {
                owner: SNS_GOVERNANCE_CANISTER_ID.get().into(),
                subaccount: Some(compute_neuron_staking_subaccount_bytes(
                    NNS_GOVERNANCE_CANISTER_ID.get(),
                    memo,
                )),
            }
        }

        let sns_transaction_fee_e8s = *swap
            .init_or_panic()
            .transaction_fee_e8s
            .as_ref()
            .expect("Transaction fee not known.");
        let neuron_basket_transfer_fund_calls =
            |amount_sns_tokens_e8s: u64, count: u64, investor: TestInvestor| -> Vec<LedgerExpect> {
                let split_amount = apportion_approximately_equally(amount_sns_tokens_e8s, count);

                let starting_memo = match investor {
                    TestInvestor::CommunityFund(starting_memo) => starting_memo,
                    TestInvestor::Direct(_) => SALE_NEURON_MEMO_RANGE_START,
                };

                split_amount
                    .iter()
                    .enumerate()
                    .map(|(ledger_account_memo, amount)| {
                        let memo = starting_memo + ledger_account_memo as u64;
                        let to = match investor {
                            TestInvestor::CommunityFund(_) => cf(memo),
                            TestInvestor::Direct(principal_id) => dst(principal_id, memo),
                        };

                        LedgerExpect::TransferFunds(
                            amount - sns_transaction_fee_e8s,
                            /* fees */ sns_transaction_fee_e8s,
                            /* Subaccount */ None,
                            to,
                            /* memo */ 0,
                            /* Block height */ Ok(1066),
                        )
                    })
                    .collect()
            };

        let neurons_per_investor = params
            .neuron_basket_construction_parameters
            .as_ref()
            .unwrap()
            .count;

        let mut mock_ledger_calls: Vec<LedgerExpect> = vec![];
        mock_ledger_calls.append(&mut neuron_basket_transfer_fund_calls(
            60_000 * E8,
            neurons_per_investor,
            TestInvestor::Direct(*TEST_USER2_PRINCIPAL),
        ));
        mock_ledger_calls.append(&mut neuron_basket_transfer_fund_calls(
            40_000 * E8,
            neurons_per_investor,
            TestInvestor::Direct(*TEST_USER3_PRINCIPAL),
        ));
        mock_ledger_calls.append(&mut neuron_basket_transfer_fund_calls(
            90_000 * E8,
            neurons_per_investor,
            TestInvestor::Direct(*TEST_USER1_PRINCIPAL),
        ));
        mock_ledger_calls.append(&mut neuron_basket_transfer_fund_calls(
            5_000 * E8,
            neurons_per_investor,
            TestInvestor::CommunityFund(/* memo */ SALE_NEURON_MEMO_RANGE_START),
        ));
        mock_ledger_calls.append(&mut neuron_basket_transfer_fund_calls(
            3_000 * E8,
            neurons_per_investor,
            TestInvestor::CommunityFund(/* memo */ SALE_NEURON_MEMO_RANGE_START + 3),
        ));
        mock_ledger_calls.append(&mut neuron_basket_transfer_fund_calls(
            2_000 * E8,
            neurons_per_investor,
            TestInvestor::CommunityFund(/* memo */ SALE_NEURON_MEMO_RANGE_START + 6),
        ));

        let SweepResult {
            success,
            failure,
            skipped,
            invalid,
            global_failures,
        } = swap
            .sweep_sns(now_fn, &mock_stub(mock_ledger_calls))
            .now_or_never()
            .unwrap();
        assert_eq!(skipped, 0);
        assert_eq!(failure, 0);
        assert_eq!(invalid, 0);
        assert_eq!(success, 18);
        assert_eq!(global_failures, 0);

        for recipe in &swap.neuron_recipes {
            let sns = recipe.sns.as_ref().unwrap();
            assert_eq!(
                sns.amount_transferred_e8s.unwrap(),
                sns.amount_e8s - sns_transaction_fee_e8s
            );
            assert_eq!(sns.transfer_fee_paid_e8s.unwrap(), sns_transaction_fee_e8s);
        }
    }
}

#[tokio::test]
async fn test_finalize_swap_ok() {
    // Step 1: Prepare the world.

    let init = Init {
        fallback_controller_principal_ids: vec![i2principal_id_string(4242)],
        ..init()
    };
    let params = Params {
        max_icp_e8s: 100,
        min_icp_e8s: 0,
        min_participant_icp_e8s: 1,
        max_participant_icp_e8s: 100,
        min_participants: 1,
        sns_token_e8s: 10 * E8,
        swap_due_timestamp_seconds: END_TIMESTAMP_SECONDS,
        neuron_basket_construction_parameters: Some(NeuronBasketConstructionParameters {
            count: 3,
            dissolve_delay_interval_seconds: 7890000, // 3 months
        }),
        sale_delay_seconds: None,
    };
    let buyers = btreemap! {
        i2principal_id_string(1001) => BuyerState::new(50 * E8),
        i2principal_id_string(1002) => BuyerState::new(30 * E8),
        i2principal_id_string(1003) => BuyerState::new(20 * E8),
    };
    let mut swap = Swap {
        lifecycle: Open as i32,
        init: Some(init.clone()),
        params: Some(params.clone()),
        buyers: buyers.clone(),
        cf_participants: vec![],
        neuron_recipes: vec![],
        open_sns_token_swap_proposal_id: Some(OPEN_SNS_TOKEN_SWAP_PROPOSAL_ID),
        finalize_swap_in_progress: None,
        decentralization_sale_open_timestamp_seconds: None,
        next_ticket_id: Some(0),
        purge_old_tickets_last_completion_timestamp_nanoseconds: Some(0),
        purge_old_tickets_next_principal: Some(vec![0; 32]),
    };
    assert!(swap.try_commit_or_abort(END_TIMESTAMP_SECONDS));
    assert_eq!(swap.lifecycle(), Committed);

    let mut sns_root_client = ExplodingSnsRootClient::default();
    let mut nns_governance_client = SpyNnsGovernanceClient::with_successful_replies();

    let mut sns_governance_client = SpySnsGovernanceClient::new(vec![
        SnsGovernanceClientReply::ClaimSwapNeurons(
            compute_single_successful_claim_swap_neurons_response(&swap.neuron_recipes),
        ),
        SnsGovernanceClientReply::SetMode(SetModeResponse {}),
    ]);

    // Mock 3 successful ICP Ledger::transfer_funds calls
    let icp_ledger: SpyLedger = SpyLedger::new(vec![
        LedgerReply::TransferFunds(Ok(1000)),
        LedgerReply::TransferFunds(Ok(1001)),
        LedgerReply::TransferFunds(Ok(1002)),
    ]);

    // Mock 9 successful SNS Ledger::transfer_funds calls
    let sns_ledger_reply_calls = (0..9).map(|i| LedgerReply::TransferFunds(Ok(i))).collect();
    let sns_ledger: SpyLedger = SpyLedger::new(sns_ledger_reply_calls);

    // Step 2: Run the code under test. To wit, finalize_swap.
    let result = swap
        .finalize(
            now_fn,
            &mut sns_root_client,
            &mut sns_governance_client,
            &icp_ledger,
            &sns_ledger,
            &mut nns_governance_client,
        )
        .await;

    // Step 3: Inspect the results.
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
                    success: 9,
                    failure: 0,
                    skipped: 0,
                    invalid: 0,
                    global_failures: 0,
                }),
                claim_neuron_result: Some(SweepResult {
                    success: 9,
                    failure: 0,
                    skipped: 0,
                    invalid: 0,
                    global_failures: 0,
                }),
                set_mode_call_result: Some(successful_set_mode_call_result()),
                set_dapp_controllers_call_result: None,
                settle_community_fund_participation_result: Some(
                    successful_settle_community_fund_participation_result()
                ),
                error_message: None,
            },
        );
    }

    // Assert that do_finalize_swap created neurons.
    assert_eq!(
        sns_governance_client.calls.len(),
        2,
        "{:#?}",
        sns_governance_client.calls
    );
    let neuron_controllers = sns_governance_client
        .calls
        .iter()
        .filter_map(|c| {
            use common::doubles::SnsGovernanceClientCall as Call;
            match c {
                Call::ManageNeuron(_) => None,
                Call::SetMode(_) => None,
                Call::ClaimSwapNeurons(b) => Some(b),
            }
        })
        .flat_map(|b| &b.neuron_parameters)
        .map(|neuron_distribution| neuron_distribution.controller.as_ref().unwrap().to_string())
        .collect::<HashSet<_>>();
    assert_eq!(
        neuron_controllers,
        buyers.keys().cloned().collect::<HashSet<String>>()
    );
    // Assert that SNS governance was set to normal mode.
    {
        let calls = &sns_governance_client.calls;
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
    let icp_ledger_calls = icp_ledger.get_calls_snapshot();
    assert_eq!(icp_ledger_calls.len(), 3, "{:#?}", icp_ledger_calls);
    for call in icp_ledger_calls.iter() {
        let (fee_e8s, memo) = match call {
            LedgerCall::TransferFundsICRC1 { fee_e8s, memo, .. } => (fee_e8s, memo),
            call => panic!("Unexpected call on the queue: {call:?}"),
        };

        assert_eq!(*fee_e8s, DEFAULT_TRANSFER_FEE.get_e8s(), "{:#?}", call);
        assert_eq!(*memo, 0, "{:#?}", call);
    }

    let sns_ledger_calls = sns_ledger.get_calls_snapshot();
    assert_eq!(sns_ledger_calls.len(), 9, "{:#?}", sns_ledger_calls);
    for call in sns_ledger_calls.iter() {
        let (fee_e8s, memo) = match call {
            LedgerCall::TransferFundsICRC1 { fee_e8s, memo, .. } => (fee_e8s, memo),
            call => panic!("Unexpected call on the queue: {call:?}"),
        };

        assert_eq!(*fee_e8s, sns_transaction_fee_e8s, "{:#?}", call);
        assert_eq!(*memo, 0, "{:#?}", call);
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
        |amount_sns_tokens_e8s: u64, count: u64, buyer: u64| -> Vec<LedgerCall> {
            let buyer_principal_id = PrincipalId::from_str(&i2principal_id_string(buyer)).unwrap();
            let split_amount = apportion_approximately_equally(amount_sns_tokens_e8s, count);
            split_amount
                .iter()
                .enumerate()
                .map(|(ledger_account_memo, amount)| {
                    let to = Account {
                        owner: SNS_GOVERNANCE_CANISTER_ID.into(),
                        subaccount: Some(compute_neuron_staking_subaccount_bytes(
                            buyer_principal_id,
                            ledger_account_memo as u64 + SALE_NEURON_MEMO_RANGE_START,
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

    let count = params
        .neuron_basket_construction_parameters
        .as_ref()
        .unwrap()
        .count;

    let mut expected_sns_ledger_calls: Vec<LedgerCall> = vec![];
    expected_sns_ledger_calls.append(&mut neuron_basket_transfer_fund_calls(2 * E8, count, 1003));
    expected_sns_ledger_calls.append(&mut neuron_basket_transfer_fund_calls(5 * E8, count, 1001));
    expected_sns_ledger_calls.append(&mut neuron_basket_transfer_fund_calls(3 * E8, count, 1002));
    let actual_sns_ledger_calls = sns_ledger_calls;
    assert_eq!(actual_sns_ledger_calls, expected_sns_ledger_calls);

    // Assert that NNS governance was notified of positive outcome (i.e. ended in Committed).
    {
        use settle_community_fund_participation::{Committed, Result};
        assert_eq!(
            nns_governance_client.calls,
            vec![NnsGovernanceClientCall::SettleCommunityFundParticipation(
                SettleCommunityFundParticipation {
                    open_sns_token_swap_proposal_id: Some(OPEN_SNS_TOKEN_SWAP_PROPOSAL_ID),
                    result: Some(Result::Committed(Committed {
                        sns_governance_canister_id: Some(SNS_GOVERNANCE_CANISTER_ID.into()),
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
                    })
                }
            );
        });
}

#[tokio::test]
async fn test_finalize_swap_abort() {
    // Step 1: Prepare the world.

    let init = Init {
        fallback_controller_principal_ids: vec![i2principal_id_string(4242)],
        ..init()
    };
    let params = Params {
        // This absurdly large number ensures that the swap reaches the Aborted state.
        max_icp_e8s: E8 * E8,
        min_icp_e8s: E8 * E8,
        min_participant_icp_e8s: 1,
        max_participant_icp_e8s: E8 * E8,
        // There will only be one participant; therefore, this also ensures that
        // the swap reaches the Aborted state.
        min_participants: 2,
        sns_token_e8s: 10 * E8,
        swap_due_timestamp_seconds: END_TIMESTAMP_SECONDS,
        neuron_basket_construction_parameters: Some(NeuronBasketConstructionParameters {
            count: 12,
            dissolve_delay_interval_seconds: 7890000, // 3 months
        }),
        sale_delay_seconds: None,
    };
    let buyer_principal_id = PrincipalId::new_user_test_id(8502);
    let mut swap = Swap {
        lifecycle: Open as i32,
        init: Some(init.clone()),
        params: Some(params),
        cf_participants: vec![],
        buyers: btreemap! {
                i2principal_id_string(8502) => BuyerState::new(77 * E8),
        },
        neuron_recipes: vec![],
        open_sns_token_swap_proposal_id: Some(OPEN_SNS_TOKEN_SWAP_PROPOSAL_ID),
        finalize_swap_in_progress: None,
        decentralization_sale_open_timestamp_seconds: None,
        next_ticket_id: Some(0),
        purge_old_tickets_last_completion_timestamp_nanoseconds: Some(0),
        purge_old_tickets_next_principal: Some(vec![0; 32]),
    };

    assert!(swap.try_commit_or_abort(/* now_seconds: */ END_TIMESTAMP_SECONDS + 1));
    assert_eq!(swap.lifecycle(), Aborted);
    // Cannot open when aborted.
    assert!(!swap.can_open(END_TIMESTAMP_SECONDS + 1));
    assert!(!swap.try_open_after_delay(END_TIMESTAMP_SECONDS + 1));

    // These clients should have no calls observed and therefore no calls mocked
    let mut sns_governance_client = SpySnsGovernanceClient::default();
    let mut nns_governance_client = SpyNnsGovernanceClient::with_successful_replies();
    let sns_ledger: SpyLedger = SpyLedger::default();

    let mut sns_root_client = SpySnsRootClient::new(vec![
        // SNS Root will respond with zero errors
        SnsRootClientReply::SetDappControllers(SetDappControllersResponse {
            failed_updates: vec![],
        }),
    ]);

    let icp_ledger: SpyLedger = SpyLedger::new(
        // ICP Ledger should be called once and should return success
        vec![LedgerReply::TransferFunds(Ok(1000))],
    );

    // Step 2: Run the code under test. To wit, finalize_swap.
    let result = swap
        .finalize(
            now_fn,
            &mut sns_root_client,
            &mut sns_governance_client,
            &icp_ledger,
            &sns_ledger,
            &mut nns_governance_client,
        )
        .await;

    // Step 3: Inspect the results.
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
                set_mode_call_result: None,
                // This is the main assertion:
                set_dapp_controllers_call_result: Some(
                    successful_set_dapp_controllers_call_result()
                ),
                settle_community_fund_participation_result: Some(
                    successful_settle_community_fund_participation_result()
                ),
                error_message: None,
            },
        );
    }

    // Step 3.1: Assert that no neurons were created, and SNS governance was not set to normal mode.
    assert_eq!(
        sns_governance_client.calls,
        vec![],
        "{:#?}",
        sns_governance_client.calls
    );

    // Step 3.2: Verify ledger calls.
    let icp_ledger_calls = icp_ledger.get_calls_snapshot();
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
    assert_eq!(
        sns_ledger.get_calls_snapshot(),
        vec![/* Test started in Open state */]
    );

    // Step 3.3: SNS root was told to set dapp canister controllers.
    let controller_principal_ids = init
        .fallback_controller_principal_ids
        .iter()
        .map(|s| PrincipalId::from_str(s).unwrap())
        .collect();
    assert_eq!(
        sns_root_client.observed_calls,
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
        use settle_community_fund_participation::{Aborted, Result};
        assert_eq!(
            nns_governance_client.calls,
            vec![NnsGovernanceClientCall::SettleCommunityFundParticipation(
                SettleCommunityFundParticipation {
                    open_sns_token_swap_proposal_id: Some(OPEN_SNS_TOKEN_SWAP_PROPOSAL_ID),
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
    // Test with single account
    {
        let params = Params {
            max_icp_e8s: 10 * E8,
            min_icp_e8s: 5 * E8,
            min_participants: 1,
            min_participant_icp_e8s: E8,
            max_participant_icp_e8s: 6 * E8,
            sns_token_e8s: 100_000 * E8,
            ..params()
        };
        let mut swap = Swap::new(init());
        // Swap is not open and therefore cannot be commited
        assert_eq!(swap.lifecycle(), Pending);
        assert!(!swap.can_commit(params.swap_due_timestamp_seconds));

        // Open swap
        open_swap(&mut swap, &params).now_or_never().unwrap();

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

        // User has not commited yet --> No neuron has been created
        assert!(std::panic::catch_unwind(|| verify_participant_balances(
            &swap,
            &user1,
            amount,
            swap.params.clone().unwrap().sns_token_e8s,
        ))
        .is_err());

        // User has not commited yet --> Cannot get a refund
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
        // time a commit should be possible
        assert!(swap.can_commit(swap.params.clone().unwrap().swap_due_timestamp_seconds));
        assert!(swap.try_commit_or_abort(swap.params.clone().unwrap().swap_due_timestamp_seconds));

        // The life cycle should have changed to COMMITTED
        assert_eq!(swap.lifecycle(), Committed);

        // Now that the lifecycle has changed to commited, the neurons for the buyers should have been generated
        verify_participant_balances(
            &swap,
            &user1,
            amount,
            swap.params.clone().unwrap().sns_token_e8s,
        );

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
}

/// Test the error refund method for multiple users.
#[test]
fn test_error_refund_multiple_users() {
    let user1 = *TEST_USER1_PRINCIPAL;
    let user2 = *TEST_USER2_PRINCIPAL;

    {
        let params = Params {
            max_icp_e8s: 10 * E8,
            min_icp_e8s: 5 * E8,
            min_participants: 2,
            min_participant_icp_e8s: E8,
            max_participant_icp_e8s: 6 * E8,
            sns_token_e8s: 100_000 * E8,
            ..params()
        };
        let mut swap = Swap::new(init());
        // Open swap
        open_swap(&mut swap, &params).now_or_never().unwrap();
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

        //The minimum number of participants is 1, so when calling commit with the appropriate end time a commit should be possible
        assert!(swap.try_commit_or_abort(swap.params.clone().unwrap().swap_due_timestamp_seconds));

        //The life cycle should have changed to ABORTED
        assert_eq!(swap.lifecycle(), Aborted);

        //Make sure neither user1 nor any other user can refund tokens from user1 until they are sweeped
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
}

/// Test the error refund method after swap has closed
#[test]
fn test_error_refund_after_close() {
    let user1 = *TEST_USER1_PRINCIPAL;
    let user2 = *TEST_USER2_PRINCIPAL;

    //Test with single account
    {
        let params = Params {
            max_icp_e8s: 10 * E8,
            min_icp_e8s: 5 * E8,
            min_participants: 1,
            min_participant_icp_e8s: E8,
            max_participant_icp_e8s: 6 * E8,
            sns_token_e8s: 100_000 * E8,
            ..params()
        };
        let mut swap = Swap::new(init());

        // Open swap
        open_swap(&mut swap, &params).now_or_never().unwrap();

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
        assert!(swap.try_commit_or_abort(swap.params.clone().unwrap().swap_due_timestamp_seconds));

        //The life cycle should have changed to COMMITTED
        assert_eq!(swap.lifecycle(), Committed);

        //Now that the lifecycle has changed to commited, the neurons for the buyers should have been generated
        verify_participant_balances(
            &swap,
            &user1,
            amount,
            swap.params.clone().unwrap().sns_token_e8s,
        );

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
}

/// Test that a single buyer states can be retrieved
#[test]
fn test_get_buyer_state() {
    let params = Params {
        max_icp_e8s: 10 * E8,
        min_icp_e8s: 5 * E8,
        min_participants: 1,
        min_participant_icp_e8s: E8,
        max_participant_icp_e8s: 6 * E8,
        sns_token_e8s: 100_000 * E8,
        ..params()
    };
    let account = Account {
        owner: SWAP_CANISTER_ID.get().into(),
        subaccount: None,
    };
    let mut swap = Swap::new(init());
    // Open swap.
    {
        let r = swap
            .open(
                SWAP_CANISTER_ID,
                &mock_stub(vec![LedgerExpect::AccountBalance(
                    account,
                    Ok(Tokens::from_e8s(params.sns_token_e8s)),
                )]),
                START_TIMESTAMP_SECONDS,
                OpenRequest {
                    params: Some(params),
                    cf_participants: vec![],
                    open_sns_token_swap_proposal_id: Some(OPEN_SNS_TOKEN_SWAP_PROPOSAL_ID),
                },
            )
            .now_or_never()
            .unwrap();
        assert!(r.is_ok());
    }
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
    // But only 4 ICP is "accepted" as the swap's init.max_icp_e8s is 10 Tokens and has
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
    let (sender_channel, mut receiver_channel) = mpsc::unbounded::<LedgerControlMessage>();

    let underlying_icp_ledger: SpyLedger =
        SpyLedger::new(vec![LedgerReply::TransferFunds(Ok(1000))]);
    let interleaving_ledger =
        InterleavingTestLedger::new(Box::new(underlying_icp_ledger), sender_channel);

    // TODO there must be an easier way to specify these calls
    let mut sns_governance_client = SpySnsGovernanceClient::new(vec![
        SnsGovernanceClientReply::ClaimSwapNeurons(
            compute_single_successful_claim_swap_neurons_response(&boxed_swap.neuron_recipes),
        ),
        SnsGovernanceClientReply::SetMode(SetModeResponse {}),
    ]);

    // Step 2: Call finalize and have the thread block

    // Spawn a call to finalize in a new thread; meanwhile, on the main thread we'll await
    // for the signal that the ICP Ledger transfer has been initiated
    let thread_handle = thread::spawn(move || {
        let sns_ledger = SpyLedger::new(vec![LedgerReply::TransferFunds(Ok(1000))]);

        let finalize_result = tokio_test::block_on(boxed_swap.finalize(
            now_fn,
            &mut ExplodingSnsRootClient::default(),
            &mut sns_governance_client,
            &interleaving_ledger,
            &sns_ledger,
            &mut SpyNnsGovernanceClient::with_successful_replies(),
        ));

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

        // Interleave a call to finalize using the raw pointer. This call should return a
        // default FinalizeSwapResponse with an error message after hitting the lock.
        let response = (*raw_ptr_swap)
            .finalize(
                now_fn,
                &mut ExplodingSnsRootClient::default(),
                &mut SpySnsGovernanceClient::default(),
                &SpyLedger::default(),
                &SpyLedger::default(),
                &mut SpyNnsGovernanceClient::with_successful_replies(),
            )
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
        assert!(response
            .settle_community_fund_participation_result
            .is_none());
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

        let response = swap
            .finalize(
                now_fn,
                &mut ExplodingSnsRootClient::default(),
                &mut SpySnsGovernanceClient::default(),
                &SpyLedger::default(), // ICP Ledger
                &SpyLedger::default(), // SNS Ledger
                &mut SpyNnsGovernanceClient::default(),
            )
            .await;

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

        // Assert not other subactions were started
        assert!(response.sweep_icp_result.is_none());
        assert!(response
            .settle_community_fund_participation_result
            .is_none());
        assert!(response.set_dapp_controllers_call_result.is_none());
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
                })
            },
            // This Buyer has already had its transfer succeed, and should result in
            // as Skipped field increment
            i2principal_id_string(1001) => BuyerState {
                icp: Some(TransferableAmount {
                    amount_e8s: 10 * E8,
                    transfer_start_timestamp_seconds: END_TIMESTAMP_SECONDS,
                    transfer_success_timestamp_seconds: END_TIMESTAMP_SECONDS + 1,
                    ..Default::default()
                })
            },
            // This buyer's state is valid, and a mock call to the ledger will allow it
            // to succeed, which should result in a success field increment
            i2principal_id_string(1002) => BuyerState {
                icp: Some(TransferableAmount {
                    amount_e8s: 10 * E8,
                    ..Default::default()
                })
            },
            // This buyer's state is valid, but a mock call to the ledger will fail the transfer,
            // which should result in a failure field increment.
            i2principal_id_string(1003) => BuyerState {
                icp: Some(TransferableAmount {
                    amount_e8s: 10 * E8,
                    ..Default::default()
                })
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
                })
            },
            // This buyer's state is valid, but a mock call to the ledger will fail the transfer,
            // which should result in a failure field increment.
            i2principal_id_string(1003) => BuyerState {
                icp: Some(TransferableAmount {
                    amount_e8s: 10 * E8,
                    ..Default::default()
                })
            },
        },
        ..Default::default()
    };

    // Mock the replies from the ledger
    let icp_ledger = SpyLedger::new(vec![
        // This mocked reply should produce a successful transfer in SweepResult
        LedgerReply::TransferFunds(Err(NervousSystemError::new_with_message(
            "Error when transferring funds",
        ))),
    ]);

    // Step 2: Call sweep_icp
    let result = swap
        .finalize(
            now_fn,
            &mut SpySnsRootClient::default(),
            &mut SpySnsGovernanceClient::default(),
            &icp_ledger,
            &SpyLedger::default(), // SNS Ledger
            &mut SpyNnsGovernanceClient::default(),
        )
        .await;

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

    // Assert all other fields are set to None because finalization was halted
    assert!(result.settle_community_fund_participation_result.is_none());
    assert!(result.set_dapp_controllers_call_result.is_none());
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

/// Test that sweep_sns will handles invalid SnsNeuronRecipes gracefully by incrementing the correct
/// SweepResult fields
#[tokio::test]
async fn test_sweep_sns_handles_invalid_neuron_recipes() {
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
            // Valid
            SnsNeuronRecipe {
                neuron_attributes: Some(NeuronAttributes::default()),
                investor: Some(Investor::Direct(DirectInvestment {
                    buyer_principal: (*TEST_USER1_PRINCIPAL).to_string(),
                })),
                sns: Some(TransferableAmount {
                    amount_e8s: 10 * E8,
                    ..Default::default()
                }),
                ..Default::default()
            },
        ],
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

    let direct_investor = Some(Investor::Direct(DirectInvestment {
        buyer_principal: (*TEST_USER1_PRINCIPAL).to_string(),
    }));

    // Setup the necessary neurons for the test
    let mut swap = Swap {
        lifecycle: Committed as i32,
        init: Some(init.clone()),
        params: Some(params()),
        neuron_recipes: vec![
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
        ],
        ..Default::default()
    };

    let mut nns_governance_client = SpyNnsGovernanceClient::new(vec![
        NnsGovernanceClientReply::SettleCommunityFundParticipation(Ok(())),
    ]);

    // Mock the replies from the ledger
    let sns_ledger = SpyLedger::new(vec![
        // This mocked reply should produce a successful transfer in SweepResult
        LedgerReply::TransferFunds(Err(NervousSystemError::new_with_message(
            "Error when transferring funds",
        ))),
    ]);

    // Step 2: Call sweep_icp
    let result = swap
        .finalize(
            now_fn,
            &mut SpySnsRootClient::default(),
            &mut SpySnsGovernanceClient::default(),
            &SpyLedger::default(), // ICP Ledger
            &sns_ledger,
            &mut nns_governance_client,
        )
        .await;

    // Assert that sweep_icp was executed correctly, but ignore the specific values
    assert!(result.sweep_icp_result.is_some());
    assert!(result.settle_community_fund_participation_result.is_some());

    assert_eq!(
        result.sweep_sns_result,
        Some(SweepResult {
            success: 0,
            skipped: 0,
            failure: 1,         // Single failed transfer
            invalid: 1,         // Single invalid buyer
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

/// Test that settle_community_fund_participation will handle missing required state
/// gracefully with an error.
#[tokio::test]
async fn test_settle_community_fund_participation_handles_missing_state() {
    // Step 1: Prepare the world

    // settle_community_fund_participation depends on init being set
    let swap = Swap {
        init: None,
        ..Default::default()
    };

    // Step 2: Call settle_community_fund_participation
    let result = swap
        .settle_community_fund_participation(&mut SpyNnsGovernanceClient::default())
        .await;

    // Step 3: Inspect results

    // settle_community_fund_participation should gracefully handle missing state by returning an error
    assert_eq!(
        result,
        SettleCommunityFundParticipationResult { possibility: None }
    );
}

/// Test that settle_community_fund_participation will halt finalization execution
/// if NNS Governance fails to settle
#[tokio::test]
async fn test_finalization_halts_when_settle_cf_fails() {
    // Step 1: Prepare the world

    // Setup the necessary buyers for the test
    let mut swap = Swap {
        lifecycle: Committed as i32,
        init: Some(init()),
        params: Some(params()),
        ..Default::default()
    };

    let expected_canister_call_error = CanisterCallError {
        code: Some(0),
        description: "UNEXPECTED ERROR".to_string(),
    };

    let mut nns_governance_client =
        SpyNnsGovernanceClient::new(vec![NnsGovernanceClientReply::CanisterCallError(
            expected_canister_call_error.clone(),
        )]);

    // Step 2: Call finalize
    let result = swap
        .finalize(
            now_fn,
            &mut SpySnsRootClient::default(),
            &mut SpySnsGovernanceClient::default(),
            &SpyLedger::default(), // ICP Ledger
            &SpyLedger::default(), // SNS Ledger
            &mut nns_governance_client,
        )
        .await;

    // Assert that sweep_icp was executed correctly, but ignore the specific values
    assert!(result.sweep_icp_result.is_some());

    // Assert that the settle_community_fund_result is set as expected
    assert_eq!(
        result.settle_community_fund_participation_result,
        Some(SettleCommunityFundParticipationResult {
            possibility: Some(
                settle_community_fund_participation_result::Possibility::Err(
                    expected_canister_call_error
                )
            ),
        })
    );

    assert_eq!(
        result.error_message,
        Some(String::from(
            "Settling the CommunityFund participation did not succeed. Halting swap finalization"
        ))
    );

    // Assert all other fields are set to None because finalization was halted
    assert!(result.set_dapp_controllers_call_result.is_none());
    assert!(result.sweep_sns_result.is_none());
    assert!(result.set_mode_call_result.is_none());
    assert!(result.claim_neuron_result.is_none());
}

/// Tests that when finalize is called with Lifecycle::Aborted, only a subset of subactions are
/// performed.
#[tokio::test]
async fn test_finalize_swap_abort_executes_correct_subactions() {
    // Step 1: Prepare the world

    // Create a swap in state aborted
    let mut swap = Swap {
        lifecycle: Aborted as i32,
        init: Some(init()),
        params: Some(params()),
        buyers: btreemap! {
            i2principal_id_string(1001) => BuyerState::new(50 * E8), // Valid
        },
        ..Default::default()
    };

    let mut sns_root_client = SpySnsRootClient::new(vec![
        // Add a mock reply of a successful call to SNS Root
        SnsRootClientReply::successful_set_dapp_controllers(),
    ]);

    let icp_ledger: SpyLedger = SpyLedger::new(
        // ICP Ledger should be called once and should return success
        vec![LedgerReply::TransferFunds(Ok(1000))],
    );

    let response = swap
        .finalize(
            now_fn,
            &mut sns_root_client,
            &mut SpySnsGovernanceClient::default(),
            &icp_ledger,
            &SpyLedger::default(), // SNS Ledger
            &mut SpyNnsGovernanceClient::with_successful_replies(),
        )
        .await;

    // Assert not other subactions were started

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

    // Successful settle_community_fund_participation
    assert_eq!(
        response.settle_community_fund_participation_result,
        Some(successful_settle_community_fund_participation_result()),
    );

    // Successful set_dapp_controllers
    assert_eq!(
        response.set_dapp_controllers_call_result,
        Some(successful_set_dapp_controllers_call_result()),
    );

    // No other subactions should have been performed
    assert!(response.sweep_sns_result.is_none());
    assert!(response.claim_neuron_result.is_none());
    assert!(response.set_mode_call_result.is_none());

    // Assert that the finalize_swap lock was released
    assert!(!swap.is_finalize_swap_locked());
}

/// Test the restore_dapp_controllers API happy case
#[tokio::test]
async fn test_restore_dapp_controllers_happy() {
    // Create the set of controllers that we will later use to assert with
    let mut fallback_controllers = vec![(*TEST_USER1_PRINCIPAL), CanisterId::from_u64(1).get()];

    let init = Init {
        // Provide the fallback controllers in their expected form
        fallback_controller_principal_ids: fallback_controllers
            .iter()
            .map(|pid| pid.to_string())
            .collect(),
        ..init()
    };

    let mut swap = Swap {
        lifecycle: Pending as i32,
        init: Some(init),
        params: Some(params()),
        ..Default::default()
    };

    // Set up the series of mocked replies from the SNS Root canister
    let mut sns_root_client = SpySnsRootClient::default();

    // Step 2: Call restore_dapp_controllers

    // The call to SNS Root will succeed
    sns_root_client.push_reply(SnsRootClientReply::SetDappControllers(
        SetDappControllersResponse {
            failed_updates: vec![],
        },
    ));

    let restore_dapp_controllers_response = swap
        .restore_dapp_controllers(&mut sns_root_client, NNS_GOVERNANCE_CANISTER_ID.get())
        .await;

    // Step 3: Inspect results

    let set_dapp_controller_response =
        extract_set_dapp_controller_response(&restore_dapp_controllers_response);

    // Assert that the response contains no failures
    assert_eq!(set_dapp_controller_response.failed_updates, vec![],);

    // Assert that with a successful call the Lifecycle of the Swap has been set to aborted
    assert_eq!(swap.lifecycle(), Aborted);

    // Inspect the request to SNS Root and that it has all the fallback controllers
    match sns_root_client.pop_observed_call() {
        SnsRootClientCall::SetDappControllers(mut request) => {
            // Sort the vec so they can be compared
            request.controller_principal_ids.sort();
            fallback_controllers.sort();
            assert_eq!(request.controller_principal_ids, fallback_controllers);
        }
    }
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
        ..Default::default()
    };

    let expected_canister_call_error = CanisterCallError {
        code: Some(0),
        description: "BAD REPLY".to_string(),
    };

    let mut sns_governance_client =
        SpySnsGovernanceClient::new(vec![SnsGovernanceClientReply::CanisterCallError(
            expected_canister_call_error.clone(),
        )]);

    let mut nns_governance_client = SpyNnsGovernanceClient::new(vec![
        NnsGovernanceClientReply::SettleCommunityFundParticipation(Ok(())),
    ]);

    // Step 2: Call finalize
    let result = swap
        .finalize(
            now_fn,
            &mut SpySnsRootClient::default(),
            &mut sns_governance_client,
            &SpyLedger::default(), // ICP Ledger
            &SpyLedger::default(), // SNS Ledger
            &mut nns_governance_client,
        )
        .await;

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
    assert!(result.settle_community_fund_participation_result.is_some());
    assert!(result.claim_neuron_result.is_some());
    // set_dapp_controllers_result is None as this is not the aborted path
    assert!(result.set_dapp_controllers_call_result.is_none());
}

/// Test that the restore_dapp_controllers API will reject callers that
/// are not NNS Governance.
#[tokio::test]
#[should_panic(expected = "This method can only be called by NNS Governance")]
async fn test_restore_dapp_controllers_rejects_unauthorized() {
    // Step 1: Prepare the world.

    // Explicitly set the nns_governance_canister_id.
    let init = Init {
        nns_governance_canister_id: NNS_GOVERNANCE_CANISTER_ID.to_string(),
        ..init()
    };
    let mut swap = Swap {
        lifecycle: Pending as i32,
        init: Some(init),
        params: Some(params()),
        ..Default::default()
    };

    // Step 2: Call restore_dapp_controllers with an unauthorized caller
    swap.restore_dapp_controllers(
        &mut ExplodingSnsRootClient::default(),
        PrincipalId::new_anonymous(),
    )
    .await;
}

/// Test that the restore_dapp_controllers API will gracefully handle invalid
/// fallback_controller_ids
#[tokio::test]
async fn test_restore_dapp_controllers_cannot_parse_fallback_controllers() {
    // Step 1: Prepare the world.

    let init = Init {
        fallback_controller_principal_ids: vec![
            PrincipalId::new_anonymous().to_string(), // Valid
            CanisterId::from_u64(1).to_string(),      // Valid
            "GARBAGE_DATA_IN".to_string(),            // Invalid
        ],
        ..init()
    };
    let mut swap = Swap {
        lifecycle: Pending as i32,
        init: Some(init),
        params: Some(params()),
        ..Default::default()
    };

    // Step 2: Call restore_dapp_controllers
    let restore_dapp_controllers_response = swap
        .restore_dapp_controllers(
            &mut ExplodingSnsRootClient::default(), // Should fail before using RootClient
            NNS_GOVERNANCE_CANISTER_ID.get(),
        )
        .await;

    // Step 3: Inspect Results

    // Match the error case, panic with message for all other cases
    let canister_call_error = extract_canister_call_error(&restore_dapp_controllers_response);

    // Assert that the error message contains what is expected
    assert!(
        canister_call_error.description.contains(
            "Could not set_dapp_controllers, \
            one or more fallback_controller_principal_ids \
            could not be parsed as a PrincipalId"
        ),
        "{}",
        canister_call_error.description
    );

    // Assert that even with a failure, the Lifecycle of the Swap has been set to aborted
    assert_eq!(swap.lifecycle(), Aborted);
}

/// Test that the restore_dapp_controllers API will gracefully handle external failures
/// from SNS Root.
#[tokio::test]
async fn test_restore_dapp_controllers_handles_external_root_failures() {
    // Step 1: Prepare the world.

    let mut swap = Swap {
        lifecycle: Pending as i32,
        init: Some(init()),
        params: Some(params()),
        ..Default::default()
    };

    // Set up the series of mocked replies from the SNS Root canister
    let mut sns_root_client = SpySnsRootClient::default();

    // Step 2: Call restore_dapp_controllers

    // The call to SNS Root will fail due to external reasons to SNS Root
    sns_root_client.push_reply(SnsRootClientReply::CanisterCallError(CanisterCallError {
        code: Some(0),
        description: "EXTERNAL FAILURE".to_string(),
    }));

    let restore_dapp_controllers_response = swap
        .restore_dapp_controllers(&mut sns_root_client, NNS_GOVERNANCE_CANISTER_ID.get())
        .await;

    // Step 3: Inspect results

    let canister_call_error = extract_canister_call_error(&restore_dapp_controllers_response);

    // Assert that the error message contains what is expected
    assert!(
        canister_call_error.description.contains("EXTERNAL FAILURE"),
        "{}",
        canister_call_error.description
    );

    // Assert that the error code is expected
    assert_eq!(canister_call_error.code, Some(0));

    // Assert that even with a failure, the Lifecycle of the Swap has been set to aborted
    assert_eq!(swap.lifecycle(), Aborted);
}

/// Test that the restore_dapp_controllers API will gracefully handle internal failures
/// from SNS Root.
#[tokio::test]
async fn test_restore_dapp_controllers_handles_internal_root_failures() {
    // Step 1: Prepare the world.

    let mut swap = Swap {
        lifecycle: Pending as i32,
        init: Some(init()),
        params: Some(params()),
        ..Default::default()
    };

    // Set up the series of mocked replies from the SNS Root canister
    let mut sns_root_client = SpySnsRootClient::default();

    // Step 2: Call restore_dapp_controllers

    // The call to SNS Root will fail due to internal reasons to SNS Root
    sns_root_client.push_reply(SnsRootClientReply::SetDappControllers(
        SetDappControllersResponse {
            failed_updates: vec![set_dapp_controllers_response::FailedUpdate::default()],
        },
    ));

    let restore_dapp_controllers_response = swap
        .restore_dapp_controllers(&mut sns_root_client, NNS_GOVERNANCE_CANISTER_ID.get())
        .await;

    // Step 3: Inspect results

    let set_dapp_controller_response =
        extract_set_dapp_controller_response(&restore_dapp_controllers_response);

    // Assert that the response contains the expected failures
    assert_eq!(
        set_dapp_controller_response.failed_updates,
        vec![set_dapp_controllers_response::FailedUpdate::default()],
    );

    // Assert that even with a failure, the Lifecycle of the Swap has been set to aborted
    assert_eq!(swap.lifecycle(), Aborted);
}

#[test]
fn test_derived_state() {
    let mut swap = Swap::default();

    let expected_derived_state1 = DerivedState {
        buyer_total_icp_e8s: 0,
        sns_tokens_per_icp: 0f32,
        direct_participant_count: Some(0),
        cf_participant_count: Some(0),
        cf_neuron_count: Some(0),
    };
    let actual_derived_state1 = swap.derived_state();
    assert_eq!(expected_derived_state1, actual_derived_state1);

    let params = Params {
        sns_token_e8s: 1_000_000_000,
        ..Default::default()
    };
    swap.params = Some(params);

    let expected_derived_state2 = DerivedState {
        buyer_total_icp_e8s: 0,
        sns_tokens_per_icp: 0f32,
        direct_participant_count: Some(0),
        cf_participant_count: Some(0),
        cf_neuron_count: Some(0),
    };
    let actual_derived_state2 = swap.derived_state();
    assert_eq!(expected_derived_state2, actual_derived_state2);

    let buyer_state: BuyerState = BuyerState {
        icp: Some(TransferableAmount {
            amount_e8s: 100_000_000,
            transfer_start_timestamp_seconds: 10,
            transfer_success_timestamp_seconds: 12,
            ..Default::default()
        }),
    };
    let buyers = btreemap! {
        "".to_string() => buyer_state,
    };

    swap.buyers = buyers;

    let expected_derived_state3 = DerivedState {
        buyer_total_icp_e8s: 100_000_000,
        sns_tokens_per_icp: 10f32,
        direct_participant_count: Some(1),
        cf_participant_count: Some(0),
        cf_neuron_count: Some(0),
    };
    let actual_derived_state3 = swap.derived_state();
    assert_eq!(expected_derived_state3, actual_derived_state3);

    swap.cf_participants = vec![CfParticipant {
        hotkey_principal: "".to_string(),
        cf_neurons: vec![
            CfNeuron {
                nns_neuron_id: 0,
                amount_icp_e8s: 300_000_000,
            },
            CfNeuron {
                nns_neuron_id: 1,
                amount_icp_e8s: 400_000_000,
            },
        ],
    }];

    let expected_derived_state4 = DerivedState {
        buyer_total_icp_e8s: 800_000_000,
        sns_tokens_per_icp: 1.25f32,
        direct_participant_count: Some(1),
        cf_participant_count: Some(1),
        cf_neuron_count: Some(2),
    };
    let actual_derived_state4 = swap.derived_state();
    assert_eq!(expected_derived_state4, actual_derived_state4);
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

/// Assert that the NeuronParameters are correctly created from SnsNeuronRecipes. This
/// is an ugly test that doesn't make use of a lot of variables, but given other tests
/// of claim_swap_neurons, this is more of a regression test. If something unexpected changes
/// in the NeuronParameter creation, this will fail loudly.
#[tokio::test]
async fn test_claim_swap_neuron_correctly_creates_neuron_parameters() {
    // Step 1: Prepare the world

    // Create some valid and invalid NeuronRecipes in the state
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
                    followees: vec![NeuronId::new_test_neuron_id(10).try_into().unwrap()],
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
                    followees: vec![NeuronId::new_test_neuron_id(20).try_into().unwrap()],
                }),
                investor: Some(Investor::CommunityFund(CfInvestment {
                    hotkey_principal: (*TEST_USER2_PRINCIPAL).to_string(),
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

    assert_eq!(
        sns_governance_client.get_calls_snapshot(),
        vec![SnsGovernanceClientCall::ClaimSwapNeurons(
            ClaimSwapNeuronsRequest {
                neuron_parameters: vec![
                    NeuronParameters {
                        controller: Some(*TEST_USER1_PRINCIPAL),
                        hotkey: None,
                        stake_e8s: Some((10 * E8) - init().transaction_fee_e8s()),
                        dissolve_delay_seconds: Some(ONE_MONTH_SECONDS),
                        source_nns_neuron_id: None,
                        neuron_id: Some(NeuronId::from(compute_neuron_staking_subaccount_bytes(
                            *TEST_USER1_PRINCIPAL,
                            10
                        ))),
                        followees: vec![NeuronId::new_test_neuron_id(10)],
                    },
                    NeuronParameters {
                        controller: Some(NNS_GOVERNANCE_CANISTER_ID.get()),
                        hotkey: Some(*TEST_USER2_PRINCIPAL),
                        stake_e8s: Some((20 * E8) - init().transaction_fee_e8s()),
                        dissolve_delay_seconds: Some(0),
                        source_nns_neuron_id: Some(100),
                        neuron_id: Some(NeuronId::from(compute_neuron_staking_subaccount_bytes(
                            NNS_GOVERNANCE_CANISTER_ID.get(),
                            0
                        ))),
                        followees: vec![NeuronId::new_test_neuron_id(20)],
                    }
                ],
            }
        )]
    )
}

/// Test the batching mechanism for claim_swap_neurons, mostly that given a set number of
/// SnsNeuronRecipes, are the batches well formed and handled as expected
#[tokio::test]
async fn test_claim_swap_neurons_batches_claims() {
    // Step 1: Prepare the world

    // This test will create a set number of NeuronRecipes to trigger batching.
    let desired_batch_count = 10;
    let neuron_parameters_per_batch = CLAIM_SWAP_NEURONS_BATCH_SIZE;

    // We want the test to handle non-divisible batch counts. Therefore create N-1 full batches,
    // and final a half full batch
    let neuron_recipe_count = ((desired_batch_count - 1) * neuron_parameters_per_batch)
        + (neuron_parameters_per_batch / 2);

    // Create the Swap state with the correct number of neuron recipes that will
    // result in the correct number of NeuronParameters to reach the desired batch count
    let mut swap = Swap {
        lifecycle: Committed as i32,
        init: Some(init()),
        params: Some(params()),
        neuron_recipes: create_generic_sns_neuron_recipes(neuron_recipe_count as u64),
        ..Default::default()
    };

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
    let neuron_parameters_per_batch = CLAIM_SWAP_NEURONS_BATCH_SIZE;

    // The test requires 3 batches. The first call will succeed, the second one will fail, and the
    // 3rd one will not be attempted.
    let neuron_recipe_count = neuron_parameters_per_batch * 3;

    // Create the Swap state with the correct number of neuron recipes that will
    // result in the correct number of NeuronParameters to reach the desired batch count
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
            success: neuron_parameters_per_batch as u32, // The first batch should have succeeded
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
    for recipe in &swap.neuron_recipes[0..neuron_parameters_per_batch] {
        assert_eq!(recipe.claimed_status, Some(ClaimedStatus::Success as i32));
    }

    // Assert that the two unsuccessful batch did not have their journal updated and can therefore
    // be retried
    for recipe in &swap.neuron_recipes[neuron_parameters_per_batch..swap.neuron_recipes.len()] {
        assert_eq!(recipe.claimed_status, Some(ClaimedStatus::Pending as i32));
    }
}

/// Test the batching mechanism for claim_swap_neurons handles inconsistent response from
/// SNS Governance, and still updates sns neuron recipe journals
#[tokio::test]
async fn test_claim_swap_neurons_handles_inconsistent_response() {
    // Step 1: Prepare the world

    // This test will create a set number of NeuronRecipes to trigger batching.
    let neuron_parameters_per_batch = CLAIM_SWAP_NEURONS_BATCH_SIZE;
    // The test requires 1 batch, and will pop one of the SwapNeurons from the response
    let neuron_recipe_count = neuron_parameters_per_batch;

    // Create the Swap state with the correct number of neuron recipes that will
    // result in the correct number of NeuronParameters to reach the desired batch count
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
            success: (neuron_parameters_per_batch - 1) as u32, // All but the last of the batch should result in success
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
    let buyer_list_index_length_before: Vec<PrincipalId> =
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
    let buyer_list_index_length_after: Vec<PrincipalId> =
        memory::BUYERS_LIST_INDEX.with(|list| list.borrow().iter().collect());
    assert_eq!(buyer_list_index_length_after.len(), 2);

    assert_eq!(
        buyer_list_index_length_before,
        buyer_list_index_length_after
    )
}

//Test refresh buyer tokens endpoint
#[test]
fn test_refresh_buyer_tokens() {
    let user1 = PrincipalId::new_user_test_id(1);
    let user2 = PrincipalId::new_user_test_id(2);
    let user3 = PrincipalId::new_user_test_id(3);
    let user4 = PrincipalId::new_user_test_id(4);
    let account = Account {
        owner: SWAP_CANISTER_ID.get().into(),
        subaccount: None,
    };

    let buy_token_ok =
        |swap: &mut Swap, user: &PrincipalId, balance_icp: &u64, balance_icp_accepted: &u64| {
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
        };

    let buy_token_err =
        |swap: &mut Swap, user: &PrincipalId, balance_icp: &u64, error_message: &str| {
            assert!(swap
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
                .unwrap_err()
                .contains(error_message));
        };

    let open_swap = |swap: &mut Swap, params: &Params| {
        assert!(swap
            .open(
                SWAP_CANISTER_ID,
                &mock_stub(vec![LedgerExpect::AccountBalance(
                    account,
                    Ok(Tokens::from_e8s(params.sns_token_e8s)),
                )]),
                START_TIMESTAMP_SECONDS,
                OpenRequest {
                    params: Some(params.clone()),
                    cf_participants: vec![],
                    open_sns_token_swap_proposal_id: Some(OPEN_SNS_TOKEN_SWAP_PROPOSAL_ID),
                }
            )
            .now_or_never()
            .unwrap()
            .is_ok());
    };

    let check_final_conditions = |swap: &mut Swap,
                                  user: &PrincipalId,
                                  amount_committed: &u64,
                                  participant_total_icp: &u64| {
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
    };

    //Test happy scenario
    {
        let params = Params {
            max_icp_e8s: 50 * E8,
            min_icp_e8s: 5 * E8,
            min_participants: 1,
            min_participant_icp_e8s: 2 * E8,
            max_participant_icp_e8s: 40 * E8,
            sns_token_e8s: 100_000 * E8,
            ..params()
        };
        let amount_user1_0 = 5 * E8;
        let amount_user1_1 = 3 * E8;
        let amount_user2_0 = 35 * E8;
        let mut swap = Swap::new(init());

        // Make sure tokens can only be commited once the swap is open
        assert!(swap
            .refresh_buyer_token_e8s(user1, None, SWAP_CANISTER_ID, &mock_stub(vec![]))
            .now_or_never()
            .unwrap()
            .unwrap_err()
            .contains("OPEN state"));
        //Open the swap
        open_swap(&mut swap, &params);

        // Makse sure user1 has not committed any users yet
        assert!(!swap.buyers.contains_key(&user1.to_string()));

        buy_token_ok(&mut swap, &user1, &amount_user1_0, &amount_user1_0);

        // Make sure user1's committment is reflected in the buyers state
        // Total commited balance should be that of user1
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

        // Makse sure user1's committmend is reflected in the buyers state
        // Total commited balance should be that of user1 + user2
        check_final_conditions(
            &mut swap,
            &user1,
            &(amount_user1_0 + amount_user1_1),
            &(amount_user1_0 + amount_user1_1 + amount_user2_0),
        );
    }

    // Test token limit
    {
        let params = Params {
            max_icp_e8s: 50 * E8,
            min_icp_e8s: 5 * E8,
            min_participants: 1,
            min_participant_icp_e8s: 2 * E8,
            max_participant_icp_e8s: 40 * E8,
            sns_token_e8s: 100_000 * E8,
            ..params()
        };

        let mut swap = Swap::new(init());

        open_swap(&mut swap, &params);

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
            &(params.max_icp_e8s - params.max_participant_icp_e8s),
        );

        assert_eq!(swap.get_buyers_total().buyers_total, params.max_icp_e8s);

        // No user should be able to commit to tokens now no matter how small the amount
        buy_token_err(
            &mut swap,
            &user3,
            &(params.min_participant_icp_e8s),
            "ICP target",
        );
    }

    // Test quota
    {
        let params = Params {
            max_icp_e8s: 200 * E8,
            min_icp_e8s: 5 * E8,
            min_participants: 1,
            min_participant_icp_e8s: 2 * E8,
            max_participant_icp_e8s: 40 * E8,
            sns_token_e8s: 100_000 * E8,
            ..params()
        };
        let mut swap = Swap::new(init());
        let amount_user1_0 = 5 * E8;
        //The limit per user is 40 E8s and we want to test the maximum participation limit per user
        let amount_user2_0 = 40 * E8;
        let amount_user3_0 = 40 * E8;
        let amount_user4_0 = 100 * E8 - (amount_user1_0 + amount_user2_0 + amount_user3_0);
        let amount_user1_1 = 41 * E8;

        open_swap(&mut swap, &params);

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

    // Test not enough tokens left
    {
        let params = Params {
            max_icp_e8s: 100 * E8,
            min_icp_e8s: 5 * E8,
            min_participants: 1,
            min_participant_icp_e8s: 2 * E8,
            max_participant_icp_e8s: 40 * E8,
            sns_token_e8s: 100_000 * E8,
            ..params()
        };
        let mut swap = Swap::new(init());
        let amount_user1_0 = 5 * E8;
        let amount_user2_0 = 40 * E8;
        let amount_user3_0 = 40 * E8;
        let amount_user4_0 = 99 * E8 - (amount_user2_0 + amount_user3_0);

        open_swap(&mut swap, &params);

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
            params.max_icp_e8s - swap.get_buyers_total().buyers_total
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
            &(params.max_icp_e8s - E8),
        );
    }

    // Test minimum tokens requirement
    {
        let params = Params {
            max_icp_e8s: 100 * E8,
            min_icp_e8s: 5 * E8,
            min_participants: 1,
            min_participant_icp_e8s: 2 * E8,
            max_participant_icp_e8s: 40 * E8,
            sns_token_e8s: 100_000 * E8,
            ..params()
        };
        let mut swap = Swap::new(init());
        let amount_user1_0 = E8;
        let amount_user2_0 = 40 * E8;
        let amount_user3_0 = 10 * E8;

        open_swap(&mut swap, &params);

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

    // Test commited tokens below minimum
    {
        let params = Params {
            max_icp_e8s: 100 * E8,
            min_icp_e8s: 5 * E8,
            min_participants: 1,
            min_participant_icp_e8s: 2 * E8,
            max_participant_icp_e8s: 40 * E8,
            sns_token_e8s: 100_000 * E8,
            ..params()
        };
        let mut swap = Swap::new(init());
        let amount_user1_0 = 3 * E8;
        let amount_user1_1 = 150_000_000;
        let amount_user2_0 = 40 * E8;
        let amount_user3_0 = 40 * E8;
        let amount_user4_0 = 99 * E8 - (amount_user2_0 + amount_user3_0 + amount_user1_0);

        open_swap(&mut swap, &params);

        buy_token_ok(&mut swap, &user1, &amount_user1_0, &amount_user1_0);

        buy_token_ok(&mut swap, &user2, &amount_user2_0, &amount_user2_0);

        buy_token_ok(&mut swap, &user3, &amount_user3_0, &amount_user3_0);

        buy_token_ok(&mut swap, &user4, &amount_user4_0, &amount_user4_0);

        assert_eq!(
            swap.get_buyers_total().buyers_total,
            amount_user2_0 + amount_user3_0 + amount_user4_0 + amount_user1_0
        );

        assert!(
            params.max_icp_e8s - swap.get_buyers_total().buyers_total
                < params.min_participant_icp_e8s
        );

        assert!((params.max_icp_e8s - swap.get_buyers_total().buyers_total) < amount_user1_1);

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
            &(params.max_icp_e8s),
        );
    }

    // Test not sending additional funds
    {
        let params = Params {
            max_icp_e8s: 50 * E8,
            min_icp_e8s: 5 * E8,
            min_participants: 1,
            min_participant_icp_e8s: 2 * E8,
            max_participant_icp_e8s: 40 * E8,
            sns_token_e8s: 100_000 * E8,
            ..params()
        };
        let mut swap = Swap::new(init());
        let amount_user1_0 = 3 * E8;
        let amount_user2_0 = 37 * E8;

        open_swap(&mut swap, &params);

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

    // Test committing with no funds sent
    {
        let params = Params {
            max_icp_e8s: 100 * E8,
            min_icp_e8s: 5 * E8,
            min_participants: 1,
            min_participant_icp_e8s: 2 * E8,
            max_participant_icp_e8s: 40 * E8,
            sns_token_e8s: 100_000 * E8,
            ..params()
        };
        let mut swap = Swap::new(init());
        let amount_user1_0 = 3 * E8;
        let amount_user2_0 = 40 * E8;
        let amount_user3_0 = 40 * E8;
        let amount_user4_0 = 18 * E8;

        open_swap(&mut swap, &params);

        buy_token_ok(&mut swap, &user2, &amount_user2_0, &amount_user2_0);

        buy_token_ok(&mut swap, &user3, &amount_user3_0, &amount_user3_0);

        buy_token_ok(&mut swap, &user4, &amount_user4_0, &amount_user4_0);

        assert_eq!(
            params.max_icp_e8s - swap.get_buyers_total().buyers_total,
            2 * E8
        );

        buy_token_ok(&mut swap, &user1, &amount_user1_0, &(2 * E8));

        check_final_conditions(&mut swap, &user1, &(2 * E8), &(params.max_icp_e8s));
    }
}

/// Test that the `refresh_buyer_token_e8s` function handles confirmations correctly.
#[test]
fn test_swap_participation_confirmation() {
    let confirmation_text = "Please confirm that 2+2=4".to_string();
    let another_text = "Please confirm that 2+2=5".to_string();
    let user = PrincipalId::new_user_test_id(1);
    let account = Account {
        owner: SWAP_CANISTER_ID.get().into(),
        subaccount: None,
    };
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

    let open_swap = |swap: &mut Swap, params: &Params| {
        assert!(swap
            .open(
                SWAP_CANISTER_ID,
                &mock_stub(vec![LedgerExpect::AccountBalance(
                    account,
                    Ok(Tokens::from_e8s(params.sns_token_e8s)),
                )]),
                START_TIMESTAMP_SECONDS,
                OpenRequest {
                    params: Some(params.clone()),
                    cf_participants: vec![],
                    open_sns_token_swap_proposal_id: Some(OPEN_SNS_TOKEN_SWAP_PROPOSAL_ID),
                }
            )
            .now_or_never()
            .unwrap()
            .is_ok());
    };

    // A. SNS specifies confirmation text & client sends confirmation text
    {
        let mut swap = Swap::new(init_with_confirmation_text(Some(confirmation_text.clone())));
        open_swap(&mut swap, &params());
        // A.1. The texts match
        assert_is_ok!(buy_token(&mut swap, Some(confirmation_text.clone())));
        // A.2. The texts do not match
        assert_is_err!(buy_token(&mut swap, Some(another_text)));
    }

    // B. SNS specifies confirmation text & client does not send a confirmation text
    {
        let mut swap = Swap::new(init_with_confirmation_text(Some(confirmation_text.clone())));
        open_swap(&mut swap, &params());
        assert_is_err!(buy_token(&mut swap, None));
    }

    // C. SNS does not specify confirmation text & client sends a confirmation text
    {
        let mut swap = Swap::new(init_with_confirmation_text(None));
        open_swap(&mut swap, &params());
        assert_is_err!(buy_token(&mut swap, Some(confirmation_text)));
    }

    // D. SNS does not specify confirmation text & client does not send a confirmation text
    {
        let mut swap = Swap::new(init_with_confirmation_text(None));
        open_swap(&mut swap, &params());
        assert_is_ok!(buy_token(&mut swap, None));
    }
}

/// Test that the get_state API bounds the dynamic data sources returned in the
/// GetStateResponse.
#[test]
fn test_get_state_bounds_data_sources() {
    // Prepare the canister with multiple buyers
    let swap = Swap {
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

    let mut sns_root_client = SpySnsRootClient::new(vec![
        // Add a mock reply of a successful call to SNS Root
        SnsRootClientReply::successful_set_dapp_controllers(),
    ]);

    let icp_ledger: SpyLedger = SpyLedger::new(
        // ICP Ledger should be called once and should return success
        vec![LedgerReply::TransferFunds(Ok(1000))],
    );

    let response = swap
        .finalize(
            now_fn,
            &mut sns_root_client,
            &mut SpySnsGovernanceClient::default(),
            &icp_ledger,
            &SpyLedger::default(), // SNS Ledger
            &mut SpyNnsGovernanceClient::with_successful_replies(),
        )
        .await;

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
            })
        }
    );
}
