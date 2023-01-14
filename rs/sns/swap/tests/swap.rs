use crate::common::doubles::{
    ExplodingSnsRootClient, LedgerCall, LedgerExpect, NnsGovernanceClientCall,
    SnsGovernanceClientCall, SnsGovernanceClientReply, SnsRootClientCall, SnsRootClientReply,
    SpyLedger, SpyNnsGovernanceClient, SpySnsGovernanceClient, SpySnsRootClient,
};
use crate::common::{
    create_single_neuron_recipe, extract_canister_call_error, extract_set_dapp_controller_response,
    i2principal_id_string, mock_stub, successful_set_dapp_controllers_call_result,
    successful_settle_community_fund_participation_result, verify_participant_balances,
    TestInvestor,
};
use futures::{channel::mpsc, future::FutureExt, StreamExt};
use ic_base_types::{CanisterId, PrincipalId};
use ic_icrc1::Account;
use ic_ledger_core::Tokens;
use ic_nervous_system_common::{
    assert_is_err, assert_is_ok, ledger::compute_neuron_staking_subaccount_bytes, E8,
    SECONDS_PER_DAY, START_OF_2022_TIMESTAMP_SECONDS,
};
use ic_nervous_system_common_test_keys::{
    TEST_USER1_PRINCIPAL, TEST_USER2_PRINCIPAL, TEST_USER3_PRINCIPAL,
};
use ic_nervous_system_common_test_utils::{
    drain_receiver_channel, InterleavingTestLedger, LedgerControlMessage,
};
use ic_sns_governance::{
    pb::v1::{governance, ClaimSwapNeuronsResponse, SetMode},
    types::ONE_MONTH_SECONDS,
};
use ic_sns_swap::pb::v1::sns_neuron_recipe::{Investor, NeuronAttributes};
use ic_sns_swap::{
    pb::v1::{
        params::NeuronBasketConstructionParameters,
        Lifecycle::{Aborted, Committed, Open, Pending, Unspecified},
        SetDappControllersRequest, SetDappControllersResponse, *,
    },
    swap::principal_to_subaccount,
};
use icp_ledger::DEFAULT_TRANSFER_FEE;
use maplit::{btreemap, hashset};
use std::{
    collections::HashSet,
    pin::Pin,
    str::FromStr,
    sync::{atomic, atomic::Ordering as AtomicOrdering, Arc, Mutex},
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
fn init() -> Init {
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
    };
    assert_is_ok!(result.validate());
    result
}

fn params() -> Params {
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
    };
    assert!(result.is_valid_at(START_TIMESTAMP_SECONDS));
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
        owner: SWAP_CANISTER_ID.get(),
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
                    account.clone(),
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
                &mock_stub(vec![LedgerExpect::AccountBalance(account.clone(), Err(13))]),
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
                    account.clone(),
                    Ok(Tokens::from_e8s(params.sns_token_e8s - 1)),
                )]),
                START_TIMESTAMP_SECONDS,
                open_request.clone(),
            )
            .now_or_never()
            .unwrap();
        assert!(r.is_err());
    }
    // assert that before sale is open, no tokens are available for sale.
    assert_eq!(
        swap.sns_token_e8s().unwrap_err(),
        "Sale not open, no tokens available.".to_string()
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
        owner: SWAP_CANISTER_ID.get(),
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
            SWAP_CANISTER_ID,
            &mock_stub(vec![LedgerExpect::AccountBalance(
                Account {
                    owner: SWAP_CANISTER_ID.get(),
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
            SWAP_CANISTER_ID,
            &mock_stub(vec![LedgerExpect::AccountBalance(
                Account {
                    owner: SWAP_CANISTER_ID.get(),
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
        } = swap
            .sweep_icp(
                now_fn,
                &mock_stub(vec![
                    LedgerExpect::TransferFunds(
                        2 * E8 - DEFAULT_TRANSFER_FEE.get_e8s(),
                        DEFAULT_TRANSFER_FEE.get_e8s(),
                        Some(principal_to_subaccount(&TEST_USER2_PRINCIPAL)),
                        Account {
                            owner: *TEST_USER2_PRINCIPAL,
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
                            owner: *TEST_USER1_PRINCIPAL,
                            subaccount: None,
                        },
                        0,
                        Ok(1067),
                    ),
                ]),
            )
            .now_or_never()
            .unwrap()
            .expect("Expected sweep_icp to succeed");
        assert_eq!(skipped, 0);
        assert_eq!(success, 2);
        assert_eq!(failure, 0);
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
        owner: SWAP_CANISTER_ID.get(),
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
                SWAP_CANISTER_ID,
                &mock_stub(vec![LedgerExpect::AccountBalance(
                    Account {
                        owner: SWAP_CANISTER_ID.get(),
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
                SWAP_CANISTER_ID,
                &mock_stub(vec![LedgerExpect::AccountBalance(
                    Account {
                        owner: SWAP_CANISTER_ID.get(),
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
                SWAP_CANISTER_ID,
                &mock_stub(vec![LedgerExpect::AccountBalance(
                    Account {
                        owner: SWAP_CANISTER_ID.get(),
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
        owner: SWAP_CANISTER_ID.get(),
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
            SWAP_CANISTER_ID,
            &mock_stub(vec![LedgerExpect::AccountBalance(
                Account {
                    owner: SWAP_CANISTER_ID.get(),
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
            SWAP_CANISTER_ID,
            &mock_stub(vec![LedgerExpect::AccountBalance(
                Account {
                    owner: SWAP_CANISTER_ID.get(),
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
        owner: SWAP_CANISTER_ID.get(),
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
    // Cannot commit or abort, as the swap is not due yet.
    assert!(!swap.try_commit_or_abort(END_TIMESTAMP_SECONDS - 1));
    // Deposit 900 ICP from one buyer.
    assert!(swap
        .refresh_buyer_token_e8s(
            *TEST_USER1_PRINCIPAL,
            SWAP_CANISTER_ID,
            &mock_stub(vec![LedgerExpect::AccountBalance(
                Account {
                    owner: SWAP_CANISTER_ID.get(),
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
            SWAP_CANISTER_ID,
            &mock_stub(vec![LedgerExpect::AccountBalance(
                Account {
                    owner: SWAP_CANISTER_ID.get(),
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
            SWAP_CANISTER_ID,
            &mock_stub(vec![LedgerExpect::AccountBalance(
                Account {
                    owner: SWAP_CANISTER_ID.get(),
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
    // Can commit if the swap is due.
    assert!(swap.can_commit(END_TIMESTAMP_SECONDS));
    // This should commit...
    assert!(swap.try_commit_or_abort(END_TIMESTAMP_SECONDS));
    assert_eq!(swap.lifecycle(), Committed);
    // Check that buyer balances are correct. Total SNS balance is
    // 200k and total ICP is 2k.
    verify_participant_balances(&swap, &TEST_USER1_PRINCIPAL, 900 * E8, 90000 * E8);
    verify_participant_balances(&swap, &TEST_USER2_PRINCIPAL, 600 * E8, 60000 * E8);
    verify_participant_balances(&swap, &TEST_USER3_PRINCIPAL, 400 * E8, 40000 * E8);
    {
        // "Sweep" all ICP, going to the governance canister. Mock one failure.
        let SweepResult {
            success,
            failure,
            skipped,
        } = swap
            .sweep_icp(
                now_fn,
                &mock_stub(vec![
                    LedgerExpect::TransferFunds(
                        600 * E8 - DEFAULT_TRANSFER_FEE.get_e8s(),
                        DEFAULT_TRANSFER_FEE.get_e8s(),
                        Some(principal_to_subaccount(&TEST_USER2_PRINCIPAL)),
                        Account {
                            owner: SNS_GOVERNANCE_CANISTER_ID.get(),
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
                            owner: SNS_GOVERNANCE_CANISTER_ID.get(),
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
                            owner: SNS_GOVERNANCE_CANISTER_ID.get(),
                            subaccount: None,
                        },
                        0,
                        Ok(1067),
                    ),
                ]),
            )
            .now_or_never()
            .unwrap()
            .expect("Expected sweep_icp to succeed");
        assert_eq!(skipped, 0);
        assert_eq!(success, 2);
        assert_eq!(failure, 1);
        let SweepResult {
            success,
            failure,
            skipped,
        } = swap
            .sweep_icp(
                now_fn,
                &mock_stub(vec![LedgerExpect::TransferFunds(
                    600 * E8 - DEFAULT_TRANSFER_FEE.get_e8s(),
                    DEFAULT_TRANSFER_FEE.get_e8s(),
                    Some(principal_to_subaccount(&TEST_USER2_PRINCIPAL)),
                    Account {
                        owner: SNS_GOVERNANCE_CANISTER_ID.get(),
                        subaccount: None,
                    },
                    0,
                    Ok(1068),
                )]),
            )
            .now_or_never()
            .unwrap()
            .expect("Expected sweep_icp to succeed");
        assert_eq!(skipped, 2);
        assert_eq!(success, 1);
        assert_eq!(failure, 0);
        // "Sweep" all SNS tokens, going to the buyers.
        fn dst(controller: PrincipalId, memo: u64) -> Account {
            Account {
                owner: SNS_GOVERNANCE_CANISTER_ID.get(),
                subaccount: Some(compute_neuron_staking_subaccount_bytes(controller, memo)),
            }
        }
        fn cf(memo: u64) -> Account {
            Account {
                owner: SNS_GOVERNANCE_CANISTER_ID.get(),
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
                let split_amount = Swap::split(amount_sns_tokens_e8s, count);

                let starting_memo = match investor {
                    TestInvestor::CommunityFund(starting_memo) => starting_memo,
                    TestInvestor::Direct(_) => 0,
                };

                split_amount
                    .iter()
                    .enumerate()
                    .map(|(ledger_account_memo, amount)| {
                        let to = match investor {
                            TestInvestor::CommunityFund(_) => {
                                cf(starting_memo + ledger_account_memo as u64)
                            }
                            TestInvestor::Direct(principal_id) => {
                                dst(principal_id, ledger_account_memo as u64)
                            }
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
            TestInvestor::CommunityFund(/* memo */ 0),
        ));
        mock_ledger_calls.append(&mut neuron_basket_transfer_fund_calls(
            3_000 * E8,
            neurons_per_investor,
            TestInvestor::CommunityFund(/* memo */ 3),
        ));
        mock_ledger_calls.append(&mut neuron_basket_transfer_fund_calls(
            2_000 * E8,
            neurons_per_investor,
            TestInvestor::CommunityFund(/* memo */ 6),
        ));

        let SweepResult {
            success,
            failure,
            skipped,
        } = swap
            .sweep_sns(now_fn, &mock_stub(mock_ledger_calls))
            .now_or_never()
            .unwrap()
            .expect("Expected sweep_sns to succeed");
        assert_eq!(skipped, 0);
        assert_eq!(failure, 0);
        assert_eq!(success, 18);
    }
}

#[tokio::test]
async fn test_finalize_swap_ok() {
    // Step 1: Prepare the world.
    let icp_ledger_calls = Arc::new(Mutex::new(Vec::<LedgerCall>::new()));
    let icp_ledger: SpyLedger = SpyLedger::new(Arc::clone(&icp_ledger_calls));
    let sns_ledger_calls = Arc::new(Mutex::new(Vec::<LedgerCall>::new()));
    let sns_ledger: SpyLedger = SpyLedger::new(Arc::clone(&sns_ledger_calls));

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
    };
    let mut swap = Swap {
        lifecycle: Open as i32,
        init: Some(init.clone()),
        params: Some(params.clone()),
        buyers: btreemap! {
            i2principal_id_string(1001) => BuyerState::new(50 * E8),
            i2principal_id_string(1002) => BuyerState::new(30 * E8),
            i2principal_id_string(1003) => BuyerState::new(20 * E8),
        },
        cf_participants: vec![],
        neuron_recipes: vec![],
        open_sns_token_swap_proposal_id: Some(OPEN_SNS_TOKEN_SWAP_PROPOSAL_ID),
        finalize_swap_in_progress: None,
    };
    assert!(swap.try_commit_or_abort(END_TIMESTAMP_SECONDS));
    assert_eq!(swap.lifecycle(), Committed);

    let mut sns_root_client = ExplodingSnsRootClient::default();
    let mut sns_governance_client =
        SpySnsGovernanceClient::new(vec![SnsGovernanceClientReply::ClaimSwapNeurons(
            ClaimSwapNeuronsResponse {
                successful_claims: 9,
                skipped_claims: 0,
                failed_claims: 0,
            },
        )]);
    let mut nns_governance_client = SpyNnsGovernanceClient::default();

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
        use settle_community_fund_participation_result::{Possibility, Response};
        assert_eq!(
            result,
            FinalizeSwapResponse {
                sweep_icp: Some(SweepResult {
                    success: 3,
                    failure: 0,
                    skipped: 0,
                }),
                sweep_sns: Some(SweepResult {
                    success: 9,
                    failure: 0,
                    skipped: 0,
                }),
                create_neuron: Some(SweepResult {
                    success: 9,
                    failure: 0,
                    skipped: 0,
                }),
                sns_governance_normal_mode_enabled: Some(SetModeCallResult { possibility: None }),
                set_dapp_controllers_result: None,
                settle_community_fund_participation_result: Some(
                    SettleCommunityFundParticipationResult {
                        possibility: Some(Possibility::Ok(Response {
                            governance_error: None
                        })),
                    }
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
        hashset![
            i2principal_id_string(1001),
            i2principal_id_string(1002),
            i2principal_id_string(1003),
        ],
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
    let icp_ledger_calls = icp_ledger_calls
        .lock()
        .unwrap()
        .iter()
        .cloned()
        .collect::<Vec<LedgerCall>>();
    assert_eq!(icp_ledger_calls.len(), 3, "{:#?}", icp_ledger_calls);
    for call in icp_ledger_calls.iter() {
        let (fee_e8s, memo) = match call {
            LedgerCall::TransferFunds { fee_e8s, memo, .. } => (fee_e8s, memo),
            _ => panic!("Expected transfer call, but was {:#?}.", call),
        };

        assert_eq!(*fee_e8s, DEFAULT_TRANSFER_FEE.get_e8s(), "{:#?}", call);
        assert_eq!(*memo, 0, "{:#?}", call);
    }

    let sns_ledger_calls = sns_ledger_calls
        .lock()
        .unwrap()
        .iter()
        .cloned()
        .collect::<Vec<LedgerCall>>();
    assert_eq!(sns_ledger_calls.len(), 9, "{:#?}", sns_ledger_calls);
    for call in sns_ledger_calls.iter() {
        let (fee_e8s, memo) = match call {
            LedgerCall::TransferFunds { fee_e8s, memo, .. } => (fee_e8s, memo),
            _ => panic!("Expected transfer call, but was {:#?}.", call),
        };

        assert_eq!(*fee_e8s, sns_transaction_fee_e8s, "{:#?}", call);
        assert_eq!(*memo, 0, "{:#?}", call);
    }

    // ICP should be sent to SNS governance (from various swap subaccounts.)
    let expected_to = Account {
        owner: SNS_GOVERNANCE_CANISTER_ID.into(),
        subaccount: None,
    };
    let mut expected_icp_ledger_calls = hashset! {
        (1001, 50),
        (1002, 30),
        (1003, 20),
    }
    .into_iter()
    .map(|(buyer, icp_amount)| {
        let from_subaccount = Some(principal_to_subaccount(
            &PrincipalId::from_str(&i2principal_id_string(buyer)).unwrap(),
        ));
        let amount_e8s = icp_amount * E8 - DEFAULT_TRANSFER_FEE.get_e8s();
        LedgerCall::TransferFunds {
            amount_e8s,
            fee_e8s: DEFAULT_TRANSFER_FEE.get_e8s(),
            from_subaccount,
            to: expected_to.clone(),
            memo: 0,
        }
    })
    .collect::<Vec<_>>();
    expected_icp_ledger_calls.sort();
    let mut actual_icp_ledger_calls = icp_ledger_calls;
    actual_icp_ledger_calls.sort();
    assert_eq!(actual_icp_ledger_calls, expected_icp_ledger_calls);
    let neuron_basket_transfer_fund_calls =
        |amount_sns_tokens_e8s: u64, count: u64, buyer: u64| -> Vec<LedgerCall> {
            let buyer_principal_id = PrincipalId::from_str(&i2principal_id_string(buyer)).unwrap();
            let split_amount = Swap::split(amount_sns_tokens_e8s, count);
            split_amount
                .iter()
                .enumerate()
                .map(|(ledger_account_memo, amount)| {
                    let to = Account {
                        owner: SNS_GOVERNANCE_CANISTER_ID.into(),
                        subaccount: Some(compute_neuron_staking_subaccount_bytes(
                            buyer_principal_id,
                            ledger_account_memo as u64,
                        )),
                    };
                    LedgerCall::TransferFunds {
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
    expected_sns_ledger_calls.append(&mut neuron_basket_transfer_fund_calls(5 * E8, count, 1001));
    expected_sns_ledger_calls.append(&mut neuron_basket_transfer_fund_calls(3 * E8, count, 1002));
    expected_sns_ledger_calls.append(&mut neuron_basket_transfer_fund_calls(2 * E8, count, 1003));
    expected_sns_ledger_calls.sort();
    let mut actual_sns_ledger_calls = sns_ledger_calls;
    actual_sns_ledger_calls.sort();
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
}

#[tokio::test]
async fn test_finalize_swap_abort() {
    // Step 1: Prepare the world.
    let icp_ledger_calls = Arc::new(Mutex::new(Vec::<LedgerCall>::new()));
    let icp_ledger: SpyLedger = SpyLedger::new(Arc::clone(&icp_ledger_calls));
    let sns_ledger_calls = Arc::new(Mutex::new(Vec::<LedgerCall>::new()));
    let sns_ledger: SpyLedger = SpyLedger::new(Arc::clone(&sns_ledger_calls));

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
    };

    assert!(swap.try_commit_or_abort(/* now_seconds: */ END_TIMESTAMP_SECONDS + 1));
    assert_eq!(swap.lifecycle(), Aborted);

    let mut sns_root_client = SpySnsRootClient::new(vec![
        // SNS Root will respond with zero errors
        SnsRootClientReply::SetDappControllers(SetDappControllersResponse {
            failed_updates: vec![],
        }),
    ]);
    let mut sns_governance_client = SpySnsGovernanceClient::default();
    let mut nns_governance_client = SpyNnsGovernanceClient::default();

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
        use settle_community_fund_participation_result::{Possibility, Response};
        assert_eq!(
            result,
            FinalizeSwapResponse {
                sweep_icp: Some(SweepResult {
                    success: 1,
                    failure: 0,
                    skipped: 0,
                }),
                sweep_sns: None,
                create_neuron: None,
                sns_governance_normal_mode_enabled: None,
                // This is the main assertion:
                set_dapp_controllers_result: Some(SetDappControllersCallResult {
                    possibility: Some(set_dapp_controllers_call_result::Possibility::Ok(
                        SetDappControllersResponse {
                            failed_updates: vec![]
                        }
                    )),
                }),
                settle_community_fund_participation_result: Some(
                    SettleCommunityFundParticipationResult {
                        possibility: Some(Possibility::Ok(Response {
                            governance_error: None
                        })),
                    }
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
    assert_eq!(
        *icp_ledger_calls.lock().unwrap(),
        vec![
            // Refund ICP to buyer.
            LedgerCall::TransferFunds {
                amount_e8s: 77 * E8 - DEFAULT_TRANSFER_FEE.get_e8s(),

                fee_e8s: DEFAULT_TRANSFER_FEE.get_e8s(),
                from_subaccount: Some(principal_to_subaccount(&buyer_principal_id)),
                to: Account::from(buyer_principal_id),
                memo: 0,
            }
        ],
        "{icp_ledger_calls:#?}"
    );
    assert_eq!(
        *sns_ledger_calls.lock().unwrap(),
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

/// Test the error refund method.
#[test]
fn test_error_refund() {
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
        owner: SWAP_CANISTER_ID.get(),
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
            SWAP_CANISTER_ID,
            &mock_stub(vec![LedgerExpect::AccountBalance(
                Account {
                    owner: SWAP_CANISTER_ID.get(),
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
    // Refund must fail as the swap is not committed or aborted.
    {
        use error_refund_icp_response::err::Type::Precondition;
        match swap
            .error_refund_icp(
                SWAP_CANISTER_ID,
                &ErrorRefundIcpRequest {
                    source_principal_id: Some(*TEST_USER2_PRINCIPAL),
                },
                &mock_stub(vec![]),
            )
            .now_or_never()
            .unwrap()
        {
            ErrorRefundIcpResponse {
                result:
                    Some(error_refund_icp_response::Result::Err(error_refund_icp_response::Err {
                        error_type: Some(error_type),
                        description: Some(description),
                    })),
            } => {
                assert_eq!(error_type, Precondition as i32);
                assert!(
                    description.contains("ABORTED or COMMITTED"),
                    "{}",
                    description,
                );
            }
            _ => panic!("Expected error refund to fail!"),
        }
    }
    // Will not auto-commit before the swap is due.
    assert!(!swap.can_commit(END_TIMESTAMP_SECONDS - 1));
    assert!(!swap.try_commit_or_abort(END_TIMESTAMP_SECONDS - 1));
    // Commit when due.
    assert!(swap.try_commit_or_abort(END_TIMESTAMP_SECONDS));
    assert_eq!(swap.lifecycle(), Committed);
    // Check that buyer balance is correct. Total SNS balance is 100k and total ICP is 6.
    verify_participant_balances(&swap, &TEST_USER1_PRINCIPAL, 6 * E8, 100_000 * E8);

    // Now, we try to do some refunds.

    // Perhaps USER2 (who never participated in the swap) sent 10 ICP in error?
    match swap
        .error_refund_icp(
            SWAP_CANISTER_ID,
            &ErrorRefundIcpRequest {
                source_principal_id: Some(*TEST_USER2_PRINCIPAL),
            },
            &mock_stub(vec![
                LedgerExpect::AccountBalance(
                    Account {
                        owner: SWAP_CANISTER_ID.into(),
                        subaccount: Some(principal_to_subaccount(&TEST_USER2_PRINCIPAL)),
                    },
                    Ok(Tokens::from_e8s(10 * E8)),
                ),
                LedgerExpect::TransferFunds(
                    10 * E8 - DEFAULT_TRANSFER_FEE.get_e8s(),
                    DEFAULT_TRANSFER_FEE.get_e8s(),
                    Some(principal_to_subaccount(&TEST_USER2_PRINCIPAL.clone())),
                    Account {
                        owner: *TEST_USER2_PRINCIPAL,
                        subaccount: None,
                    },
                    0,
                    Ok(1066),
                ),
            ]),
        )
        .now_or_never()
        .unwrap()
    {
        // Refund should succeed.
        ErrorRefundIcpResponse {
            result:
                Some(error_refund_icp_response::Result::Ok(error_refund_icp_response::Ok {
                    block_height: Some(block_height),
                })),
        } => assert_eq!(block_height, 1066),
        _ => panic!("Expected error refund to succeed"),
    }
    // Perhaps USER3 didn't actually send 10 ICP in error, but tries to get a refund anyway?
    match swap
        .error_refund_icp(
            SWAP_CANISTER_ID,
            &ErrorRefundIcpRequest {
                source_principal_id: Some(*TEST_USER3_PRINCIPAL),
            },
            &mock_stub(vec![
                LedgerExpect::AccountBalance(
                    Account {
                        owner: SWAP_CANISTER_ID.get(),
                        subaccount: Some(principal_to_subaccount(&TEST_USER3_PRINCIPAL.clone())),
                    },
                    Ok(Tokens::from_e8s(10 * E8)),
                ),
                LedgerExpect::TransferFunds(
                    10 * E8 - DEFAULT_TRANSFER_FEE.get_e8s(),
                    DEFAULT_TRANSFER_FEE.get_e8s(),
                    Some(principal_to_subaccount(&TEST_USER3_PRINCIPAL.clone())),
                    Account {
                        owner: *TEST_USER3_PRINCIPAL,
                        subaccount: None,
                    },
                    0, // memo
                    Err(100),
                ),
            ]),
        )
        .now_or_never()
        .unwrap()
    {
        ErrorRefundIcpResponse {
            result:
                Some(error_refund_icp_response::Result::Err(error_refund_icp_response::Err {
                    error_type: Some(error_type),
                    description: Some(description),
                })),
        } => {
            assert_eq!(
                error_type,
                error_refund_icp_response::err::Type::External as i32,
            );
            assert!(description.contains("ransfer"), "{}", description);
        }
        _ => panic!("Expected error refund to fail"),
    }
    // Perhaps USER1 (who has a buyer record) sent 10 extra ICP in
    // error? We expect this to fail as USER1's ICP still hasn't been
    // "collected" (sweep).
    match swap
        .error_refund_icp(
            SWAP_CANISTER_ID,
            &ErrorRefundIcpRequest {
                source_principal_id: Some(*TEST_USER1_PRINCIPAL),
            },
            &mock_stub(vec![]),
        )
        .now_or_never()
        .unwrap()
    {
        ErrorRefundIcpResponse {
            result:
                Some(error_refund_icp_response::Result::Err(error_refund_icp_response::Err {
                    error_type: Some(error_type),
                    description: Some(description),
                })),
        } => {
            assert_eq!(
                error_type,
                error_refund_icp_response::err::Type::Precondition as i32,
            );
            assert!(description.contains("escrow"), "{}", description);
        }
        _ => panic!("Expected error refund to fail"),
    }
    // "Sweep" all ICP, going to the governance canister.
    let SweepResult {
        success,
        failure,
        skipped,
    } = swap
        .sweep_icp(
            now_fn,
            &mock_stub(vec![LedgerExpect::TransferFunds(
                6 * E8 - DEFAULT_TRANSFER_FEE.get_e8s(),
                DEFAULT_TRANSFER_FEE.get_e8s(),
                Some(principal_to_subaccount(&TEST_USER1_PRINCIPAL)),
                Account {
                    owner: SNS_GOVERNANCE_CANISTER_ID.get(),
                    subaccount: None,
                },
                0,
                Ok(1067),
            )]),
        )
        .now_or_never()
        .unwrap()
        .expect("Expected sweep_icp to succeed");
    assert_eq!(skipped, 0);
    assert_eq!(success, 1);
    assert_eq!(failure, 0);
    // Check that buyer balance still is correct.

    verify_participant_balances(&swap, &TEST_USER1_PRINCIPAL, 6 * E8, 100_000 * E8);

    // Perhaps USER1 (who has a buyer record) sent 10 extra ICP in
    // error? We expect this to succeed now that the ICP that
    // participated in the swap have been disbursed.
    match swap
        .error_refund_icp(
            SWAP_CANISTER_ID,
            &ErrorRefundIcpRequest {
                source_principal_id: Some(*TEST_USER1_PRINCIPAL),
            },
            &mock_stub(vec![
                LedgerExpect::AccountBalance(
                    Account {
                        owner: SWAP_CANISTER_ID.get(),
                        subaccount: Some(principal_to_subaccount(&TEST_USER1_PRINCIPAL.clone())),
                    },
                    Ok(Tokens::from_e8s(10 * E8)),
                ),
                LedgerExpect::TransferFunds(
                    10 * E8 - DEFAULT_TRANSFER_FEE.get_e8s(),
                    DEFAULT_TRANSFER_FEE.get_e8s(),
                    Some(principal_to_subaccount(&TEST_USER1_PRINCIPAL.clone())),
                    Account {
                        owner: *TEST_USER1_PRINCIPAL,
                        subaccount: None,
                    },
                    0, // memo
                    Ok(1066),
                ),
            ]),
        )
        .now_or_never()
        .unwrap()
    {
        ErrorRefundIcpResponse {
            result:
                Some(error_refund_icp_response::Result::Ok(error_refund_icp_response::Ok {
                    block_height: Some(block_height),
                })),
        } => assert_eq!(block_height, 1066),
        _ => panic!("Expected error refund to succeed"),
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
        owner: SWAP_CANISTER_ID.get(),
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
            SWAP_CANISTER_ID,
            &mock_stub(vec![LedgerExpect::AccountBalance(
                Account {
                    owner: SWAP_CANISTER_ID.get(),
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
            SWAP_CANISTER_ID,
            &mock_stub(vec![LedgerExpect::AccountBalance(
                Account {
                    owner: SWAP_CANISTER_ID.get(),
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

    let underlying_icp_ledger: SpyLedger = SpyLedger::default();
    let interleaving_ledger =
        InterleavingTestLedger::new(Box::new(underlying_icp_ledger), sender_channel);

    // Step 2: Call finalize and have the thread block

    // Spawn a call to finalize in a new thread; meanwhile, on the main thread we'll await
    // for the signal that the ICP Ledger transfer has been initiated
    let thread_handle = thread::spawn(move || {
        let finalize_result = tokio_test::block_on(boxed_swap.finalize(
            now_fn,
            &mut ExplodingSnsRootClient::default(),
            &mut SpySnsGovernanceClient::with_dummy_replies(),
            &interleaving_ledger,
            &SpyLedger::default(), // SNS Token Ledger
            &mut SpyNnsGovernanceClient::default(),
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
                &mut SpyNnsGovernanceClient::default(),
            )
            .now_or_never()
            .unwrap();

        // This would fail before introducing the locking mechanism
        match response.error_message {
            None => panic!("Expected finalize_swap to reject this concurrent request"),
            Some(error_message) => {
                assert!(error_message
                    .contains("The Sale canister has finalize_swap call already in progress"))
            }
        }

        // Assert not other subactions were started
        assert!(response.sweep_icp.is_none());
        assert!(response
            .settle_community_fund_participation_result
            .is_none());
        assert!(response.set_dapp_controllers_result.is_none());
        assert!(response.sweep_sns.is_none());
        assert!(response.create_neuron.is_none());
        assert!(response.sns_governance_normal_mode_enabled.is_none());
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

/// Test that the Sale canister must be in the terminal state (Aborted || Committed)
/// for finalize to be invoked correctly.
#[tokio::test]
async fn test_sale_must_be_terminal_to_invoke_finalize() {
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
                .contains("The Sale can only be finalized in the COMMITTED or ABORTED states"),
            "{}",
            error_message,
        );

        // Assert not other subactions were started
        assert!(response.sweep_icp.is_none());
        assert!(response
            .settle_community_fund_participation_result
            .is_none());
        assert!(response.set_dapp_controllers_result.is_none());
        assert!(response.sweep_sns.is_none());
        assert!(response.create_neuron.is_none());
        assert!(response.sns_governance_normal_mode_enabled.is_none());

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
        ..Default::default()
    };

    // Step 2: Call sweep_icp
    let result = swap.sweep_icp(now_fn, &SpyLedger::default()).await;

    // Step 3: Inspect results

    // sweep_icp should gracefully handle missing state by returning an error
    assert!(result.is_err());
}

/// Test that sweep_icp will handles invalid BuyerStates gracefully by incrementing the correct
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

    // Step 2: Call sweep_icp
    let result = swap.sweep_icp(now_fn, &SpyLedger::default()).await;

    let sweep_result = match result {
        Ok(res) => res,
        Err(msg) => panic!(
            "Expected sweep_icp to return a SweepResult, got Err: {:?}",
            msg
        ),
    };

    assert_eq!(
        sweep_result,
        SweepResult {
            success: 1, // Single valid buyer
            skipped: 0, // No skips
            failure: 2, // Two invalid buyers
        }
    )
}

/// Test that sweep_sns will handle missing required state gracefully with an error.
#[tokio::test]
async fn test_sweep_sns_handles_missing_state() {
    // Step 1: Prepare the world

    // sweep_sns depends on init being set
    let mut swap = Swap {
        init: None,
        ..Default::default()
    };

    // Step 2: Call sweep_sns
    let result = swap.sweep_sns(now_fn, &SpyLedger::default()).await;

    // Step 3: Inspect results

    // sweep_sns should gracefully handle missing state by returning an error
    assert!(result.is_err());
}

/// Test that sweep_sns will handles invalid SnsNeuronRecipes gracefully by incrementing the correct
/// SweepResult fields
#[tokio::test]
async fn test_sweep_sns_handles_invalid_buyer_states() {
    // Step 1: Prepare the world

    // Create some valid and invalid buyers in the state
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
            },
        ],
        ..Default::default()
    };

    // Step 2: Call sweep_sns
    let result = swap.sweep_sns(now_fn, &SpyLedger::default()).await;

    // Step 2: Inspect Results
    let sweep_result = match result {
        Ok(res) => res,
        Err(msg) => panic!(
            "Expected sweep_sns to return a SweepResult, got Err: {:?}",
            msg
        ),
    };

    assert_eq!(
        sweep_result,
        SweepResult {
            success: 1, // Single valid buyer
            skipped: 0, // No skips
            failure: 4, // Four invalid buyers
        }
    )
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
    assert!(result.is_err());
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

    let response = swap
        .finalize(
            now_fn,
            &mut sns_root_client,
            &mut SpySnsGovernanceClient::default(),
            &SpyLedger::default(), // ICP Ledger
            &SpyLedger::default(), // SNS Ledger
            &mut SpyNnsGovernanceClient::default(),
        )
        .await;

    // Assert not other subactions were started

    // Successful sweep_icp
    assert_eq!(
        response.sweep_icp,
        Some(SweepResult {
            success: 1, // Single valid buyer
            skipped: 0,
            failure: 0,
        })
    );

    // Successful settle_community_fund_participation
    assert_eq!(
        response.settle_community_fund_participation_result,
        Some(successful_settle_community_fund_participation_result()),
    );

    // Successful set_dapp_controllers
    assert_eq!(
        response.set_dapp_controllers_result,
        Some(successful_set_dapp_controllers_call_result()),
    );

    // No other subactions should have been performed
    assert!(response.sweep_sns.is_none());
    assert!(response.create_neuron.is_none());
    assert!(response.sns_governance_normal_mode_enabled.is_none());

    // Assert that the finalize_swap lock was released
    assert!(!swap.is_finalize_swap_locked());
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

    // Assert that even with a failure, the Lifecycle of the Sale has been set to aborted
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

    // Assert that even with a failure, the Lifecycle of the Sale has been set to aborted
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

    // Assert that even with a failure, the Lifecycle of the Sale has been set to aborted
    assert_eq!(swap.lifecycle(), Aborted);
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

    // Assert that with a successful call the Lifecycle of the Sale has been set to aborted
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
