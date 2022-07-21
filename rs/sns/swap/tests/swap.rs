use async_trait::async_trait;
use dfn_core::CanisterId;
use futures::future::FutureExt;
use ic_base_types::{ic_types::principal::Principal, PrincipalId};
use ic_icrc1::{Account, Subaccount};
use ic_ledger_core::Tokens;
use ic_nervous_system_common::{
    ledger::compute_neuron_staking_subaccount_bytes, NervousSystemError,
};
use ic_nervous_system_common_test_keys::{
    TEST_USER1_PRINCIPAL, TEST_USER2_PRINCIPAL, TEST_USER3_PRINCIPAL,
};
use ic_sns_governance::{
    ledger::Ledger,
    pb::v1::{
        governance, manage_neuron, ManageNeuron, ManageNeuronResponse, SetMode, SetModeResponse,
    },
};
use ic_sns_swap::{
    pb::v1::{
        Lifecycle::{Committed, Pending},
        *,
    },
    swap::{
        principal_to_subaccount, SnsGovernanceClient, TransferResult, SECONDS_PER_DAY,
        START_OF_2022_TIMESTAMP_SECONDS,
    },
};

use lazy_static::lazy_static;
use maplit::{btreemap, hashset};

use std::{
    collections::{HashMap, HashSet},
    str::FromStr,
    sync::{Arc, Mutex},
};

// 10 ^ 8.
const E8: u64 = 100_000_000;

// For tests only. This does not imply that the canisters must have these IDs.
pub const SWAP_CANISTER_ID: CanisterId = CanisterId::from_u64(1152);
pub const NNS_GOVERNANCE_CANISTER_ID: CanisterId = CanisterId::from_u64(1185);
pub const SNS_GOVERNANCE_CANISTER_ID: CanisterId = CanisterId::from_u64(1380);
pub const SNS_LEDGER_CANISTER_ID: CanisterId = CanisterId::from_u64(1571);
pub const ICP_LEDGER_CANISTER_ID: CanisterId = CanisterId::from_u64(1630);

/// Returns a valid Init.
fn init() -> Init {
    let result = Init {
        // TODO: should fail until canister ids have been changed to something real.
        nns_governance_canister_id: NNS_GOVERNANCE_CANISTER_ID.to_string(),
        sns_governance_canister_id: SNS_GOVERNANCE_CANISTER_ID.to_string(),
        sns_ledger_canister_id: SNS_LEDGER_CANISTER_ID.to_string(),
        icp_ledger_canister_id: ICP_LEDGER_CANISTER_ID.to_string(),
        max_icp_e8s: 1000000 * E8,
        min_icp_e8s: 0,
        min_participants: 3,
        min_participant_icp_e8s: 100 * E8,
        max_participant_icp_e8s: 1000000 * E8,
        fallback_controller_principal_ids: vec![i2principal_id_string(1230578)],
    };

    assert!(result.is_valid(), "{result:#?}");

    result
}

#[test]
fn fallback_controller_principal_ids_must_not_be_empty() {
    let mut init = init();
    init.fallback_controller_principal_ids.clear();
    assert!(!init.is_valid(), "{init:#?}");
}

/// Expectation of one call on the mock Ledger.
#[derive(Debug, Clone)]
enum LedgerExpect {
    AccountBalance(Account, Result<Tokens, i32>),
    TransferFunds(u64, u64, Option<Subaccount>, Account, u64, Result<u64, i32>),
}

struct MockLedger {
    expect: Arc<Mutex<Vec<LedgerExpect>>>,
}

impl MockLedger {
    fn pop(&self) -> Option<LedgerExpect> {
        (*self.expect).lock().unwrap().pop()
    }
}

#[async_trait]
impl Ledger for MockLedger {
    async fn transfer_funds(
        &self,
        amount_e8s: u64,
        fee_e8s: u64,
        from_subaccount: Option<Subaccount>,
        to: Account,
        memo: u64,
    ) -> Result<u64, NervousSystemError> {
        match self.pop() {
            Some(LedgerExpect::TransferFunds(
                amount_e8s_,
                fee_e8s_,
                from_subaccount_,
                to_,
                memo_,
                result,
            )) => {
                assert_eq!(amount_e8s_, amount_e8s);
                assert_eq!(fee_e8s_, fee_e8s);
                assert_eq!(from_subaccount_, from_subaccount);
                assert_eq!(to_, to);
                assert_eq!(memo_, memo);
                return result.map_err(|x| NervousSystemError::new_with_message(format!("{}", x)));
            }
            x => panic!(
                "Received transfer_funds({}, {}, {:?}, {}, {}), expected {:?}",
                amount_e8s, fee_e8s, from_subaccount, to, memo, x
            ),
        }
    }

    async fn total_supply(&self) -> Result<Tokens, NervousSystemError> {
        unimplemented!()
    }

    async fn account_balance(&self, account: Account) -> Result<Tokens, NervousSystemError> {
        match self.pop() {
            Some(LedgerExpect::AccountBalance(account_, result)) => {
                assert_eq!(account_, account);
                return result.map_err(|x| NervousSystemError::new_with_message(format!("{}", x)));
            }
            x => panic!("Received account_balance({}), expected {:?}", account, x),
        }
    }
}

fn mock_stub(mut expect: Vec<LedgerExpect>) -> impl Fn(CanisterId) -> Box<dyn Ledger> {
    expect.reverse();
    let e = Arc::new(Mutex::new(expect));
    move |_| Box::new(MockLedger { expect: e.clone() })
}

const START_TIMESTAMP_SECONDS: u64 = START_OF_2022_TIMESTAMP_SECONDS + 42 * SECONDS_PER_DAY;
const END_TIMESTAMP_SECONDS: u64 = START_TIMESTAMP_SECONDS + 7 * SECONDS_PER_DAY;
const OPEN_TIME_WINDOW: TimeWindow = TimeWindow {
    start_timestamp_seconds: START_TIMESTAMP_SECONDS,
    end_timestamp_seconds: END_TIMESTAMP_SECONDS,
};

fn new_swap(init: Init) -> Swap {
    let nns_governance = PrincipalId::from(init.nns_governance());
    let mut result = Swap::new(init);
    result.set_open_time_window(
        nns_governance,
        START_TIMESTAMP_SECONDS,
        &SetOpenTimeWindowRequest {
            open_time_window: Some(OPEN_TIME_WINDOW),
        },
    );
    result
}

fn open_at_start(swap: &mut Swap) -> Result<(), String> {
    let (start, _end) = swap
        .state()
        .open_time_window
        .unwrap()
        .to_boundaries_timestamp_seconds();
    swap.open(start)
}

#[should_panic]
#[test]
fn set_open_time_window_requires_authorization() {
    let wrong_canister = PrincipalId::from(init().icp_ledger());
    let mut swap = Swap::new(init());
    swap.set_open_time_window(
        wrong_canister,
        START_TIMESTAMP_SECONDS,
        &SetOpenTimeWindowRequest {
            open_time_window: Some(OPEN_TIME_WINDOW),
        },
    );
}

#[test]
fn test_init() {
    let swap = Swap::new(init());
    assert!(swap.is_valid());
}

#[test]
fn test_open() {
    let mut swap = new_swap(init());
    // Cannot open as the swap has not received its initial funding yet.
    assert!(open_at_start(&mut swap).is_err());
    let account = Account {
        of: SWAP_CANISTER_ID.get(),
        subaccount: None,
    };
    // Refresh yielding zero tokens...
    assert!(swap
        .refresh_sns_token_e8s(
            SWAP_CANISTER_ID,
            &mock_stub(vec![LedgerExpect::AccountBalance(
                account.clone(),
                Ok(Tokens::ZERO)
            )])
        )
        .now_or_never()
        .unwrap()
        .is_ok());
    // Can still not open...
    assert!(open_at_start(&mut swap).is_err());
    // Refresh giving error...
    assert!(swap
        .refresh_sns_token_e8s(
            SWAP_CANISTER_ID,
            &mock_stub(vec![LedgerExpect::AccountBalance(account.clone(), Err(13))])
        )
        .now_or_never()
        .unwrap()
        .is_err());
    // Can still not open...
    assert!(open_at_start(&mut swap).is_err());
    // Refresh giving 100k tokens
    assert!(swap
        .refresh_sns_token_e8s(
            SWAP_CANISTER_ID,
            &mock_stub(vec![LedgerExpect::AccountBalance(
                account,
                Ok(Tokens::from_e8s(100000 * E8))
            )])
        )
        .now_or_never()
        .unwrap()
        .is_ok());
    // Check that state is updated.
    assert_eq!(swap.state().sns_token_e8s, 100000 * E8);
    // Now the swap can be opened.
    assert!(open_at_start(&mut swap).is_ok());
}

/// Check that the behaviour is correct when the swap is due and the
/// minimum ICP hasn't been reached, i.e., the swap is aborted in this
/// case.
#[test]
fn test_min_icp() {
    let init = Init {
        max_icp_e8s: 10 * E8,
        min_icp_e8s: 5 * E8,
        min_participants: 2,
        min_participant_icp_e8s: E8,
        max_participant_icp_e8s: 5 * E8,
        ..init()
    };
    let mut swap = new_swap(init);
    // Open swap.
    // Refresh giving 100k SNS tokens
    assert!(swap
        .refresh_sns_token_e8s(
            SWAP_CANISTER_ID,
            &mock_stub(vec![LedgerExpect::AccountBalance(
                Account {
                    of: SWAP_CANISTER_ID.get(),
                    subaccount: None
                },
                Ok(Tokens::from_e8s(100000 * E8))
            )])
        )
        .now_or_never()
        .unwrap()
        .is_ok());
    assert_eq!(swap.state().sns_token_e8s, 100000 * E8);
    assert!(open_at_start(&mut swap).is_ok());
    assert_eq!(swap.state().lifecycle(), Lifecycle::Open);
    // Cannot commit or abort, as the swap is not due yet.
    assert!(!swap.try_commit_or_abort(END_TIMESTAMP_SECONDS - 1));
    // Deposit 2 ICP from one buyer.
    assert!(swap
        .refresh_buyer_token_e8s(
            *TEST_USER1_PRINCIPAL,
            SWAP_CANISTER_ID,
            &mock_stub(vec![LedgerExpect::AccountBalance(
                Account {
                    of: SWAP_CANISTER_ID.get(),
                    subaccount: Some(principal_to_subaccount(&TEST_USER1_PRINCIPAL.clone()))
                },
                Ok(Tokens::from_e8s(2 * E8))
            )])
        )
        .now_or_never()
        .unwrap()
        .is_ok());
    assert_eq!(
        swap.state()
            .buyers
            .get(&TEST_USER1_PRINCIPAL.to_string())
            .unwrap()
            .amount_icp_e8s,
        2 * E8
    );
    // Deposit 2 ICP from another buyer.
    assert!(swap
        .refresh_buyer_token_e8s(
            *TEST_USER2_PRINCIPAL,
            SWAP_CANISTER_ID,
            &mock_stub(vec![LedgerExpect::AccountBalance(
                Account {
                    of: SWAP_CANISTER_ID.get(),
                    subaccount: Some(principal_to_subaccount(&TEST_USER2_PRINCIPAL.clone()))
                },
                Ok(Tokens::from_e8s(2 * E8))
            )])
        )
        .now_or_never()
        .unwrap()
        .is_ok());
    assert_eq!(
        swap.state()
            .buyers
            .get(&TEST_USER2_PRINCIPAL.to_string())
            .unwrap()
            .amount_icp_e8s,
        2 * E8
    );
    // There are now two participants with a total of 4 ICP.
    //
    // Cannot commit
    assert!(!swap.can_commit(END_TIMESTAMP_SECONDS));
    // This should now abort as the minimum hasn't been reached.
    assert!(swap.try_commit_or_abort(END_TIMESTAMP_SECONDS));
    assert_eq!(swap.state().lifecycle(), Lifecycle::Aborted);
    {
        let fee = 1152;
        // "Sweep" all ICP, which should go back to the buyers.
        let SweepResult {
            success,
            failure,
            skipped,
        } = swap
            .sweep_icp(
                Tokens::from_e8s(fee),
                &mock_stub(vec![
                    LedgerExpect::TransferFunds(
                        2 * E8 - fee,
                        fee,
                        Some(principal_to_subaccount(&*TEST_USER2_PRINCIPAL)),
                        Account {
                            of: *TEST_USER2_PRINCIPAL,
                            subaccount: None,
                        },
                        0,
                        Ok(1066),
                    ),
                    LedgerExpect::TransferFunds(
                        2 * E8 - fee,
                        fee,
                        Some(principal_to_subaccount(&*TEST_USER1_PRINCIPAL)),
                        Account {
                            of: *TEST_USER1_PRINCIPAL,
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
    }
}

/// Test going below the minimum and above the maximum ICP for a single participant.
#[test]
fn test_min_max_icp_per_buyer() {
    let init = Init {
        max_icp_e8s: 10 * E8,
        min_icp_e8s: 5 * E8,
        min_participants: 2,
        min_participant_icp_e8s: E8,
        max_participant_icp_e8s: 5 * E8,
        ..init()
    };
    let mut swap = new_swap(init);
    // Open swap.
    // Refresh giving 100k SNS tokens
    assert!(swap
        .refresh_sns_token_e8s(
            SWAP_CANISTER_ID,
            &mock_stub(vec![LedgerExpect::AccountBalance(
                Account {
                    of: SWAP_CANISTER_ID.get(),
                    subaccount: None
                },
                Ok(Tokens::from_e8s(100000 * E8))
            )])
        )
        .now_or_never()
        .unwrap()
        .is_ok());
    assert_eq!(swap.state().sns_token_e8s, 100000 * E8);
    assert!(open_at_start(&mut swap).is_ok());
    assert_eq!(swap.state().lifecycle(), Lifecycle::Open);
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
                        of: SWAP_CANISTER_ID.get(),
                        subaccount: Some(principal_to_subaccount(&TEST_USER1_PRINCIPAL.clone())),
                    },
                    Ok(Tokens::from_e8s(99999999)),
                )]),
            )
            .now_or_never()
            .unwrap();
        assert!(e.is_err());
        assert!(swap
            .state()
            .buyers
            .get(&TEST_USER1_PRINCIPAL.to_string())
            .is_none());
    }
    // Try to deposit 6 ICP.
    {
        let e = swap
            .refresh_buyer_token_e8s(
                *TEST_USER1_PRINCIPAL,
                SWAP_CANISTER_ID,
                &mock_stub(vec![LedgerExpect::AccountBalance(
                    Account {
                        of: SWAP_CANISTER_ID.get(),
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
            swap.state()
                .buyers
                .get(&TEST_USER1_PRINCIPAL.to_string())
                .unwrap()
                .amount_icp_e8s,
            5 * E8
        );
        // Make sure that a second refresh of the same principal doesn't change the balance.
        let e = swap
            .refresh_buyer_token_e8s(
                *TEST_USER1_PRINCIPAL,
                SWAP_CANISTER_ID,
                &mock_stub(vec![LedgerExpect::AccountBalance(
                    Account {
                        of: SWAP_CANISTER_ID.get(),
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
            swap.state()
                .buyers
                .get(&TEST_USER1_PRINCIPAL.to_string())
                .unwrap()
                .amount_icp_e8s,
            5 * E8
        );
    }
}

/// Test going over the total max ICP for the swap.
#[test]
fn test_max_icp() {
    let init = Init {
        max_icp_e8s: 10 * E8,
        min_icp_e8s: 5 * E8,
        min_participants: 2,
        min_participant_icp_e8s: E8,
        max_participant_icp_e8s: 6 * E8,
        ..init()
    };
    let mut swap = new_swap(init);
    // Open swap.
    // Refresh giving 100k SNS tokens
    assert!(swap
        .refresh_sns_token_e8s(
            SWAP_CANISTER_ID,
            &mock_stub(vec![LedgerExpect::AccountBalance(
                Account {
                    of: SWAP_CANISTER_ID.get(),
                    subaccount: None
                },
                Ok(Tokens::from_e8s(100000 * E8))
            )])
        )
        .now_or_never()
        .unwrap()
        .is_ok());
    assert_eq!(swap.state().sns_token_e8s, 100000 * E8);
    assert!(open_at_start(&mut swap).is_ok());
    assert_eq!(swap.state().lifecycle(), Lifecycle::Open);
    // Cannot commit or abort, as the swap is not due yet.
    assert!(!swap.try_commit_or_abort(END_TIMESTAMP_SECONDS - 1));
    // Deposit 6 ICP from one buyer.
    assert!(swap
        .refresh_buyer_token_e8s(
            *TEST_USER1_PRINCIPAL,
            SWAP_CANISTER_ID,
            &mock_stub(vec![LedgerExpect::AccountBalance(
                Account {
                    of: SWAP_CANISTER_ID.get(),
                    subaccount: Some(principal_to_subaccount(&TEST_USER1_PRINCIPAL.clone()))
                },
                Ok(Tokens::from_e8s(6 * E8))
            )])
        )
        .now_or_never()
        .unwrap()
        .is_ok());
    assert_eq!(
        swap.state()
            .buyers
            .get(&TEST_USER1_PRINCIPAL.to_string())
            .unwrap()
            .amount_icp_e8s,
        6 * E8
    );
    // Deposit 6 ICP from another buyer.
    assert!(swap
        .refresh_buyer_token_e8s(
            *TEST_USER2_PRINCIPAL,
            SWAP_CANISTER_ID,
            &mock_stub(vec![LedgerExpect::AccountBalance(
                Account {
                    of: SWAP_CANISTER_ID.get(),
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
        swap.state()
            .buyers
            .get(&TEST_USER2_PRINCIPAL.to_string())
            .unwrap()
            .amount_icp_e8s,
        4 * E8
    );
    // Can commit even if time isn't up as the max has been reached.
    assert!(swap.can_commit(END_TIMESTAMP_SECONDS - 1));
    // This should commit...
    assert!(swap.try_commit_or_abort(END_TIMESTAMP_SECONDS - 1));
    assert_eq!(swap.state().lifecycle(), Lifecycle::Committed);
    // Check that buyer balances are correct. Total SNS balance is 100k and total ICP is 10.
    {
        let b1 = swap
            .state()
            .buyers
            .get(&TEST_USER1_PRINCIPAL.to_string())
            .unwrap();
        assert_eq!(b1.amount_icp_e8s, 6 * E8);
        assert_eq!(b1.amount_sns_e8s, 60000 * E8);
    }
    {
        let b2 = swap
            .state()
            .buyers
            .get(&TEST_USER2_PRINCIPAL.to_string())
            .unwrap();
        assert_eq!(b2.amount_icp_e8s, 4 * E8);
        assert_eq!(b2.amount_sns_e8s, 40000 * E8);
    }
}

/// Test the happy path of a token swap. First 200k SNS tokens are
/// sent. Then three buyers commit 1000 ICP, 600 ICP, and 400 ICP
/// respectively. Then the swap is committed and the tokens
/// distributed.
#[test]
fn test_scenario_happy() {
    let init = init();
    let mut swap = new_swap(init);
    // Refresh giving 200k tokens
    assert!(swap
        .refresh_sns_token_e8s(
            SWAP_CANISTER_ID,
            &mock_stub(vec![LedgerExpect::AccountBalance(
                Account {
                    of: SWAP_CANISTER_ID.get(),
                    subaccount: None
                },
                Ok(Tokens::from_e8s(200000 * E8))
            )])
        )
        .now_or_never()
        .unwrap()
        .is_ok());
    assert_eq!(swap.state().sns_token_e8s, 200000 * E8);
    assert!(open_at_start(&mut swap).is_ok());
    assert_eq!(swap.state().lifecycle(), Lifecycle::Open);
    // Cannot commit or abort, as the swap is not due yet.
    assert!(!swap.try_commit_or_abort(END_TIMESTAMP_SECONDS - 1));
    assert_eq!(swap.state().lifecycle(), Lifecycle::Open);
    // Deposit 1000 ICP from one buyer.
    assert!(swap
        .refresh_buyer_token_e8s(
            *TEST_USER1_PRINCIPAL,
            SWAP_CANISTER_ID,
            &mock_stub(vec![LedgerExpect::AccountBalance(
                Account {
                    of: SWAP_CANISTER_ID.get(),
                    subaccount: Some(principal_to_subaccount(&TEST_USER1_PRINCIPAL.clone()))
                },
                Ok(Tokens::from_e8s(1000 * E8))
            )])
        )
        .now_or_never()
        .unwrap()
        .is_ok());
    assert_eq!(
        swap.state()
            .buyers
            .get(&TEST_USER1_PRINCIPAL.to_string())
            .unwrap()
            .amount_icp_e8s,
        1000 * E8
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
                    of: SWAP_CANISTER_ID.get(),
                    subaccount: Some(principal_to_subaccount(&TEST_USER2_PRINCIPAL.clone()))
                },
                Ok(Tokens::from_e8s(600 * E8))
            )])
        )
        .now_or_never()
        .unwrap()
        .is_ok());
    assert_eq!(
        swap.state()
            .buyers
            .get(&TEST_USER2_PRINCIPAL.to_string())
            .unwrap()
            .amount_icp_e8s,
        600 * E8
    );
    // Now there are two participants. If the time was up, the swap could be aborted...
    {
        let mut abort_swap = swap.clone();
        assert!(abort_swap.try_commit_or_abort(END_TIMESTAMP_SECONDS));
        assert_eq!(abort_swap.state().lifecycle(), Lifecycle::Aborted);
    }
    // Deposit 400 ICP from a third buyer.
    assert!(swap
        .refresh_buyer_token_e8s(
            *TEST_USER3_PRINCIPAL,
            SWAP_CANISTER_ID,
            &mock_stub(vec![LedgerExpect::AccountBalance(
                Account {
                    of: SWAP_CANISTER_ID.get(),
                    subaccount: Some(principal_to_subaccount(&TEST_USER3_PRINCIPAL.clone()))
                },
                Ok(Tokens::from_e8s(400 * E8))
            )])
        )
        .now_or_never()
        .unwrap()
        .is_ok());
    assert_eq!(
        swap.state()
            .buyers
            .get(&TEST_USER3_PRINCIPAL.to_string())
            .unwrap()
            .amount_icp_e8s,
        400 * E8
    );
    // Cannot commit if the swap is not due.
    assert!(!swap.can_commit(END_TIMESTAMP_SECONDS - 1));
    // Can commit if the swap is due.
    assert!(swap.can_commit(END_TIMESTAMP_SECONDS));
    // This should commit...
    assert!(swap.try_commit_or_abort(END_TIMESTAMP_SECONDS));
    assert_eq!(swap.state().lifecycle(), Lifecycle::Committed);
    // Check that buyer balances are correct. Total SNS balance is 200k and total ICP is 2k.
    {
        let b1 = swap
            .state()
            .buyers
            .get(&TEST_USER1_PRINCIPAL.to_string())
            .unwrap();
        assert_eq!(b1.amount_icp_e8s, 1000 * E8);
        assert_eq!(b1.amount_sns_e8s, 100000 * E8);
    }
    {
        let b2 = swap
            .state()
            .buyers
            .get(&TEST_USER2_PRINCIPAL.to_string())
            .unwrap();
        assert_eq!(b2.amount_icp_e8s, 600 * E8);
        assert_eq!(b2.amount_sns_e8s, 60000 * E8);
    }
    {
        let b3 = swap
            .state()
            .buyers
            .get(&TEST_USER3_PRINCIPAL.to_string())
            .unwrap();
        assert_eq!(b3.amount_icp_e8s, 400 * E8);
        assert_eq!(b3.amount_sns_e8s, 40000 * E8);
    }
    {
        // "Sweep" all ICP, going to the governance canister. Mock one failure.
        let SweepResult {
            success,
            failure,
            skipped,
        } = swap
            .sweep_icp(
                Tokens::from_e8s(1),
                &mock_stub(vec![
                    LedgerExpect::TransferFunds(
                        600 * E8 - 1,
                        1,
                        Some(principal_to_subaccount(&*TEST_USER2_PRINCIPAL)),
                        Account {
                            of: SNS_GOVERNANCE_CANISTER_ID.get(),
                            subaccount: None,
                        },
                        0,
                        Err(77),
                    ),
                    LedgerExpect::TransferFunds(
                        1000 * E8 - 1,
                        1,
                        Some(principal_to_subaccount(&*TEST_USER1_PRINCIPAL)),
                        Account {
                            of: SNS_GOVERNANCE_CANISTER_ID.get(),
                            subaccount: None,
                        },
                        0,
                        Ok(1067),
                    ),
                    LedgerExpect::TransferFunds(
                        400 * E8 - 1,
                        1,
                        Some(principal_to_subaccount(&*TEST_USER3_PRINCIPAL)),
                        Account {
                            of: SNS_GOVERNANCE_CANISTER_ID.get(),
                            subaccount: None,
                        },
                        0,
                        Ok(1066),
                    ),
                ]),
            )
            .now_or_never()
            .unwrap();
        assert_eq!(skipped, 0);
        assert_eq!(success, 2);
        assert_eq!(failure, 1);
        let SweepResult {
            success,
            failure,
            skipped,
        } = swap
            .sweep_icp(
                Tokens::from_e8s(2),
                &mock_stub(vec![LedgerExpect::TransferFunds(
                    600 * E8 - 2,
                    2,
                    Some(principal_to_subaccount(&*TEST_USER2_PRINCIPAL)),
                    Account {
                        of: SNS_GOVERNANCE_CANISTER_ID.get(),
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
        // "Sweep" all SNS tokens, going to the buyers.
        fn dst(x: PrincipalId) -> Account {
            Account {
                of: SNS_GOVERNANCE_CANISTER_ID.get(),
                subaccount: Some(compute_neuron_staking_subaccount_bytes(x, 0)),
            }
        }
        let SweepResult {
            success,
            failure,
            skipped,
        } = swap
            .sweep_sns(
                Tokens::from_e8s(1),
                &mock_stub(vec![
                    LedgerExpect::TransferFunds(
                        60000 * E8 - 1,
                        1,
                        None,
                        dst(*TEST_USER2_PRINCIPAL),
                        0,
                        Ok(1068),
                    ),
                    LedgerExpect::TransferFunds(
                        100000 * E8 - 1,
                        1,
                        None,
                        dst(*TEST_USER1_PRINCIPAL),
                        0,
                        Ok(1067),
                    ),
                    LedgerExpect::TransferFunds(
                        40000 * E8 - 1,
                        1,
                        None,
                        dst(*TEST_USER3_PRINCIPAL),
                        0,
                        Ok(1066),
                    ),
                ]),
            )
            .now_or_never()
            .unwrap();
        assert_eq!(skipped, 0);
        assert_eq!(failure, 0);
        assert_eq!(success, 3);
        assert!(swap.state().all_zeroed());
    }
}

fn i2principal_id_string(i: u64) -> String {
    Principal::from(PrincipalId::new_user_test_id(i)).to_text()
}

#[tokio::test]
async fn test_finalize_swap() {
    // Step 0: Define helper types.
    #[rustfmt::skip]
    lazy_static! {
        static ref NNS_GOVERNANCE_CANISTER_ID : String = i2principal_id_string(1);
        static ref ICP_LEDGER_CANISTER_ID     : String = i2principal_id_string(2);

        static ref SNS_GOVERNANCE_CANISTER_ID : String = i2principal_id_string(3);
        static ref SNS_LEDGER_CANISTER_ID     : String = i2principal_id_string(4);

        static ref SWAP_CANISTER_ID: CanisterId = CanisterId::from(100);
    }

    #[allow(clippy::large_enum_variant)]
    #[derive(Debug, PartialEq)]
    enum SnsGovernanceClientCall {
        ManageNeuron(ManageNeuron),
        SetMode(SetMode),
    }
    #[derive(Default, Debug)]
    struct SpySnsGovernanceClient {
        calls: Vec<SnsGovernanceClientCall>,
    }
    #[async_trait]
    impl SnsGovernanceClient for SpySnsGovernanceClient {
        async fn manage_neuron(
            &mut self,
            request: ManageNeuron,
        ) -> Result<ManageNeuronResponse, CanisterCallError> {
            self.calls
                .push(SnsGovernanceClientCall::ManageNeuron(request));
            Ok(ManageNeuronResponse::default())
        }
        async fn set_mode(
            &mut self,
            request: SetMode,
        ) -> Result<SetModeResponse, CanisterCallError> {
            self.calls.push(SnsGovernanceClientCall::SetMode(request));
            Ok(SetModeResponse {})
        }
    }

    #[derive(Clone, Debug, PartialEq, Eq, Hash)]
    struct LedgerTransferCall {
        canister_id: CanisterId,

        amount_e8s: u64,
        fee_e8s: u64,
        from_subaccount: Option<Subaccount>,
        to: Account,
        memo: u64,
    }

    struct SpyLedger {
        calls: Arc<Mutex<Vec<LedgerTransferCall>>>,
        canister_id: CanisterId,
    }
    impl SpyLedger {
        fn new(calls: Arc<Mutex<Vec<LedgerTransferCall>>>, canister_id: CanisterId) -> Self {
            Self { calls, canister_id }
        }
    }
    #[async_trait]
    impl Ledger for SpyLedger {
        async fn transfer_funds(
            &self,
            amount_e8s: u64,
            fee_e8s: u64,
            from_subaccount: Option<Subaccount>,
            to: Account,
            memo: u64,
        ) -> Result</* block_height: */ u64, NervousSystemError> {
            self.calls.lock().unwrap().push(LedgerTransferCall {
                canister_id: self.canister_id,
                amount_e8s,
                fee_e8s,
                from_subaccount,
                to,
                memo,
            });

            Ok(42)
        }

        async fn total_supply(&self) -> Result<Tokens, NervousSystemError> {
            unimplemented!();
        }

        async fn account_balance(&self, account_id: Account) -> Result<Tokens, NervousSystemError> {
            assert_eq!(
                account_id,
                Account {
                    of: (*SWAP_CANISTER_ID).into(),
                    subaccount: None,
                }
            );

            Ok(Tokens::from_e8s(10 * E8))
        }
    }

    // Step 1: Prepare the world.
    let ledger_calls = Arc::new(Mutex::new(Vec::<LedgerTransferCall>::new()));
    let ledger_factory = |canister_id: CanisterId| -> Box<dyn Ledger> {
        Box::new(SpyLedger::new(Arc::clone(&ledger_calls), canister_id))
    };

    #[rustfmt::skip]
    let init = Some(Init {
        nns_governance_canister_id : NNS_GOVERNANCE_CANISTER_ID .clone(),
        icp_ledger_canister_id     :     ICP_LEDGER_CANISTER_ID .clone(),

        sns_governance_canister_id : SNS_GOVERNANCE_CANISTER_ID .clone(),
        sns_ledger_canister_id     :     SNS_LEDGER_CANISTER_ID .clone(),

        max_icp_e8s: 100,
        min_icp_e8s: 0,
        min_participant_icp_e8s: 1,
        max_participant_icp_e8s: 100,
        min_participants: 1,
        fallback_controller_principal_ids: vec![i2principal_id_string(4242)],
    });
    let nns_governance = PrincipalId::from(init.as_ref().unwrap().nns_governance());
    let mut swap = Swap {
        init,
        state: Some(State {
            buyers: btreemap! {
                i2principal_id_string(1001) => BuyerState {
                    amount_icp_e8s: 50 * E8,
                    amount_sns_e8s: 0,
                    icp_disbursing: false,
                    sns_disbursing: false,
                },

                i2principal_id_string(1002) => BuyerState {
                    amount_icp_e8s: 30 * E8,
                    amount_sns_e8s: 0,
                    icp_disbursing: false,
                    sns_disbursing: false,
                },

                i2principal_id_string(1003) => BuyerState {
                    amount_icp_e8s: 20 * E8,
                    amount_sns_e8s: 0,
                    icp_disbursing: false,
                    sns_disbursing: false,
                },
            },
            lifecycle: Pending as i32,
            sns_token_e8s: 0,
            open_time_window: None,
        }),
    };
    swap.set_open_time_window(
        nns_governance,
        START_TIMESTAMP_SECONDS,
        &SetOpenTimeWindowRequest {
            open_time_window: Some(OPEN_TIME_WINDOW),
        },
    );

    // Quickly run through the lifecycle.
    {
        let r = swap
            .refresh_sns_token_e8s(*SWAP_CANISTER_ID, &ledger_factory)
            .await;
        assert!(r.is_ok(), "{r:#?}");
    }
    {
        let r = open_at_start(&mut swap);
        assert!(r.is_ok(), "{r:#?}");
    }
    assert!(swap.try_commit_or_abort(/* now_seconds: */ 1));
    assert_eq!(swap.state().lifecycle(), Committed);

    let mut sns_governance_client = SpySnsGovernanceClient::default();

    // Step 2: Run the code under test. To wit, finalize_swap.
    let result = swap
        .finalize(&mut sns_governance_client, ledger_factory, ledger_factory)
        .await;

    // Step 3: Inspect the results.
    assert_eq!(
        result,
        FinalizeSwapResponse {
            sweep_icp: Some(SweepResult {
                success: 3,
                failure: 0,
                skipped: 0,
            }),
            sweep_sns: Some(SweepResult {
                success: 3,
                failure: 0,
                skipped: 0,
            }),
            create_neuron: Some(SweepResult {
                success: 3,
                failure: 0,
                skipped: 0,
            }),
            sns_governance_normal_mode_enabled: Some(SetModeCallResult { possibility: None }),
        },
    );

    // Assert that do_finalize_swap created neurons.
    assert_eq!(
        sns_governance_client.calls.len(),
        4,
        "{:#?}",
        sns_governance_client.calls
    );
    let neuron_controllers = sns_governance_client
        .calls
        .iter()
        .filter_map(|c| {
            use SnsGovernanceClientCall as Call;
            let m = match c {
                Call::ManageNeuron(m) => m,
                Call::SetMode(_) => return None,
            };

            let command = match m.command.as_ref().unwrap() {
                manage_neuron::Command::ClaimOrRefresh(command) => command,
                command => panic!("{command:#?}"),
            };

            let memo_and_controller = match command.by.as_ref().unwrap() {
                manage_neuron::claim_or_refresh::By::MemoAndController(ok) => ok,
                v => panic!("{v:#?}"),
            };

            Some(memo_and_controller.controller.unwrap().to_string())
        })
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
    let ledger_calls = ledger_calls
        .lock()
        .unwrap()
        .iter()
        .cloned()
        .collect::<Vec<LedgerTransferCall>>();
    assert_eq!(ledger_calls.len(), 6, "{ledger_calls:#?}");
    for t in &ledger_calls {
        let LedgerTransferCall { fee_e8s, memo, .. } = t;
        assert_eq!(*fee_e8s, FEE_E8S, "{t:#?}");
        assert_eq!(*memo, 0, "{t:#?}");
    }

    const FEE_E8S: u64 = 10_000;

    // ICP should be sent to SNS governance (from various swap subaccounts.)
    let observed_nns_ledger_calls = ledger_calls
        .iter()
        .filter(|t| t.canister_id.to_string() == ICP_LEDGER_CANISTER_ID.to_string())
        .map(Clone::clone)
        .collect::<HashSet<_>>();
    let expected_to = Account {
        of: PrincipalId::from_str(&SNS_GOVERNANCE_CANISTER_ID).unwrap(),
        subaccount: None,
    };
    for t in &observed_nns_ledger_calls {
        assert_eq!(t.to, expected_to, "{t:#?}");
    }
    let expected_nns_ledger_calls = hashset! {
        (1001, 50),
        (1002, 30),
        (1003, 20),
    }
    .into_iter()
    .map(|(buyer, icp_amount)| {
        let from_subaccount = Some(principal_to_subaccount(
            &PrincipalId::from_str(&i2principal_id_string(buyer)).unwrap(),
        ));
        let amount_e8s = icp_amount * E8 - FEE_E8S;
        (from_subaccount, amount_e8s)
    })
    .collect::<HashMap<_, _>>();
    assert_eq!(
        observed_nns_ledger_calls
            .iter()
            .map(|t| (t.from_subaccount, t.amount_e8s))
            .collect::<HashMap<_, _>>(),
        expected_nns_ledger_calls,
        "{observed_nns_ledger_calls:#?}",
    );

    // SNS tokens should be sent to neuron (sub)accounts (i.e. SNS governance subaccounts).
    let observed_sns_ledger_calls: HashSet<_> = ledger_calls
        .iter()
        .filter(|t| t.canister_id.to_string() == *SNS_LEDGER_CANISTER_ID)
        .map(Clone::clone)
        .collect();
    for t in &observed_sns_ledger_calls {
        assert_eq!(t.from_subaccount, None, "{t:#?}");
    }
    let expected_sns_ledger_calls = hashset! {
        (1001, 5),
        (1002, 3),
        (1003, 2),
    }
    .into_iter()
    .map(|(buyer, sns_amount)| {
        let buyer = PrincipalId::from_str(&i2principal_id_string(buyer)).unwrap();

        let to = Account {
            of: PrincipalId::from_str(&*SNS_GOVERNANCE_CANISTER_ID).unwrap(),
            subaccount: Some(
                ic_nervous_system_common::ledger::compute_neuron_staking_subaccount_bytes(buyer, 0),
            ),
        };
        let amount_e8s = sns_amount * E8 - FEE_E8S;

        (to, amount_e8s)
    })
    .collect::<HashMap<_, _>>();
    assert_eq!(
        observed_sns_ledger_calls
            .iter()
            .map(|t| (t.to.clone(), t.amount_e8s))
            .collect::<HashMap<_, _>>(),
        expected_sns_ledger_calls,
        "{observed_sns_ledger_calls:#?}",
    );
}

/// Test the error refund method.
#[test]
fn test_error_refund() {
    let init = Init {
        max_icp_e8s: 10 * E8,
        min_icp_e8s: 5 * E8,
        min_participants: 1,
        min_participant_icp_e8s: E8,
        max_participant_icp_e8s: 6 * E8,
        ..init()
    };
    let mut swap = new_swap(init);
    // Refresh giving 100k SNS tokens
    assert!(swap
        .refresh_sns_token_e8s(
            SWAP_CANISTER_ID,
            &mock_stub(vec![LedgerExpect::AccountBalance(
                Account {
                    of: SWAP_CANISTER_ID.get(),
                    subaccount: None
                },
                Ok(Tokens::from_e8s(100000 * E8))
            )])
        )
        .now_or_never()
        .unwrap()
        .is_ok());
    assert_eq!(swap.state().sns_token_e8s, 100000 * E8);
    assert!(open_at_start(&mut swap).is_ok());
    assert_eq!(swap.state().lifecycle(), Lifecycle::Open);
    // Cannot commit or abort, as the swap is not due yet.
    assert!(!swap.try_commit_or_abort(END_TIMESTAMP_SECONDS - 1));
    // Deposit 6 ICP from one buyer.
    assert!(swap
        .refresh_buyer_token_e8s(
            *TEST_USER1_PRINCIPAL,
            SWAP_CANISTER_ID,
            &mock_stub(vec![LedgerExpect::AccountBalance(
                Account {
                    of: SWAP_CANISTER_ID.get(),
                    subaccount: Some(principal_to_subaccount(&TEST_USER1_PRINCIPAL.clone()))
                },
                Ok(Tokens::from_e8s(6 * E8))
            )])
        )
        .now_or_never()
        .unwrap()
        .is_ok());
    assert_eq!(
        swap.state()
            .buyers
            .get(&TEST_USER1_PRINCIPAL.to_string())
            .unwrap()
            .amount_icp_e8s,
        6 * E8
    );
    let fee = 1234;
    // Refund must fail as the swap is not committed or aborted.
    {
        match swap
            .error_refund_icp(
                *TEST_USER2_PRINCIPAL,
                Tokens::from_e8s(10 * E8),
                Tokens::from_e8s(fee),
                &mock_stub(vec![]),
            )
            .now_or_never()
            .unwrap()
        {
            TransferResult::Failure(_) => (),
            _ => panic!("Expected error refund to fail!"),
        }
    }
    // Will not auto-commit before the swap is due.
    assert!(!swap.can_commit(END_TIMESTAMP_SECONDS - 1));
    assert!(!swap.try_commit_or_abort(END_TIMESTAMP_SECONDS - 1));
    // Commit when due.
    assert!(swap.try_commit_or_abort(END_TIMESTAMP_SECONDS));
    assert_eq!(swap.state().lifecycle(), Lifecycle::Committed);
    // Check that buyer balance is correct. Total SNS balance is 100k and total ICP is 6.
    {
        let b1 = swap
            .state()
            .buyers
            .get(&TEST_USER1_PRINCIPAL.to_string())
            .unwrap();
        assert_eq!(b1.amount_icp_e8s, 6 * E8);
        assert_eq!(b1.amount_sns_e8s, 100000 * E8);
    }
    // Now, we try to do some refunds.

    // Perhaps USER2 (who never participated in the swap) sent 10 ICP in error?
    match swap
        .error_refund_icp(
            *TEST_USER2_PRINCIPAL,
            Tokens::from_e8s(10 * E8),
            Tokens::from_e8s(fee),
            &mock_stub(vec![LedgerExpect::TransferFunds(
                10 * E8 - fee,
                fee,
                Some(principal_to_subaccount(&TEST_USER2_PRINCIPAL.clone())),
                Account {
                    of: *TEST_USER2_PRINCIPAL,
                    subaccount: None,
                },
                0,
                Ok(1066),
            )]),
        )
        .now_or_never()
        .unwrap()
    {
        // Refund should succeed.
        TransferResult::Success(x) => assert_eq!(x, 1066),
        _ => panic!("Expected error refund to succeed"),
    }
    // Perhaps USER3 didn't actually send 10 ICP in error, but tries to get a refund anyway?
    match swap
        .error_refund_icp(
            *TEST_USER3_PRINCIPAL,
            Tokens::from_e8s(10 * E8),
            Tokens::from_e8s(fee),
            &mock_stub(vec![LedgerExpect::TransferFunds(
                10 * E8 - fee,
                fee,
                Some(principal_to_subaccount(&TEST_USER3_PRINCIPAL.clone())),
                Account {
                    of: *TEST_USER3_PRINCIPAL,
                    subaccount: None,
                },
                0,
                Err(100),
            )]),
        )
        .now_or_never()
        .unwrap()
    {
        TransferResult::Failure(_) => (),
        _ => panic!("Expected error refund to fail"),
    }
    // Perhaps USER1 (who has a buyer record) sent 10 extra ICP in
    // error? We expect this to fail as USER1's ICP still hasn't been
    // "collected" (sweep).
    match swap
        .error_refund_icp(
            *TEST_USER1_PRINCIPAL,
            Tokens::from_e8s(10 * E8),
            Tokens::from_e8s(fee),
            &mock_stub(vec![]),
        )
        .now_or_never()
        .unwrap()
    {
        TransferResult::Failure(_) => (),
        _ => panic!("Expected error refund to fail"),
    }
    // "Sweep" all ICP, going to the governance canister.
    let SweepResult {
        success,
        failure,
        skipped,
    } = swap
        .sweep_icp(
            Tokens::from_e8s(fee),
            &mock_stub(vec![LedgerExpect::TransferFunds(
                6 * E8 - fee,
                fee,
                Some(principal_to_subaccount(&*TEST_USER1_PRINCIPAL)),
                Account {
                    of: SNS_GOVERNANCE_CANISTER_ID.get(),
                    subaccount: None,
                },
                0,
                Ok(1067),
            )]),
        )
        .now_or_never()
        .unwrap();
    assert_eq!(skipped, 0);
    assert_eq!(success, 1);
    assert_eq!(failure, 0);
    // Check that buyer balance is correct. Total SNS balance is 100k, but ICP is zero.
    {
        let b1 = swap
            .state()
            .buyers
            .get(&TEST_USER1_PRINCIPAL.to_string())
            .unwrap();
        assert_eq!(b1.amount_icp_e8s, 0);
        assert_eq!(b1.amount_sns_e8s, 100000 * E8);
    }
    // Perhaps USER1 (who has a buyer record) sent 10 extra ICP in
    // error? We expect this to succeed now that the ICP that
    // participated in the swap have been disbursed.
    match swap
        .error_refund_icp(
            *TEST_USER1_PRINCIPAL,
            Tokens::from_e8s(10 * E8),
            Tokens::from_e8s(fee),
            &mock_stub(vec![LedgerExpect::TransferFunds(
                10 * E8 - fee,
                fee,
                Some(principal_to_subaccount(&TEST_USER1_PRINCIPAL.clone())),
                Account {
                    of: *TEST_USER1_PRINCIPAL,
                    subaccount: None,
                },
                0,
                Ok(1066),
            )]),
        )
        .now_or_never()
        .unwrap()
    {
        TransferResult::Success(_) => (),
        _ => panic!("Expected error refund to succeed"),
    }
}

/// Test that a single buyer states can be retrieved
#[test]
fn test_get_buyer_state() {
    let init = Init {
        max_icp_e8s: 10 * E8,
        min_icp_e8s: 5 * E8,
        min_participants: 1,
        min_participant_icp_e8s: E8,
        max_participant_icp_e8s: 6 * E8,
        ..init()
    };
    let mut swap = new_swap(init);

    // Refresh giving 100k SNS tokens
    assert!(swap
        .refresh_sns_token_e8s(
            SWAP_CANISTER_ID,
            &mock_stub(vec![LedgerExpect::AccountBalance(
                Account {
                    of: SWAP_CANISTER_ID.get(),
                    subaccount: None
                },
                Ok(Tokens::from_e8s(100000 * E8))
            )])
        )
        .now_or_never()
        .unwrap()
        .is_ok());
    assert_eq!(swap.state().sns_token_e8s, 100000 * E8);
    assert!(open_at_start(&mut swap).is_ok());
    assert_eq!(swap.state().lifecycle(), Lifecycle::Open);
    // Deposit 6 ICP from one buyer.
    assert!(swap
        .refresh_buyer_token_e8s(
            *TEST_USER1_PRINCIPAL,
            SWAP_CANISTER_ID,
            &mock_stub(vec![LedgerExpect::AccountBalance(
                Account {
                    of: SWAP_CANISTER_ID.get(),
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
        swap.state()
            .buyers
            .get(&TEST_USER1_PRINCIPAL.to_string())
            .unwrap()
            .amount_icp_e8s,
        6 * E8
    );

    // Assert the same balance using `get_buyer_state`
    assert_eq!(
        swap.get_buyer_state(&GetBuyerStateRequest {
            principal_id: Some(*TEST_USER1_PRINCIPAL)
        })
        .buyer_state
        .unwrap()
        .amount_icp_e8s,
        6 * E8
    );

    // Deposit 6 ICP from another buyer.
    assert!(swap
        .refresh_buyer_token_e8s(
            *TEST_USER2_PRINCIPAL,
            SWAP_CANISTER_ID,
            &mock_stub(vec![LedgerExpect::AccountBalance(
                Account {
                    of: SWAP_CANISTER_ID.get(),
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
        swap.state()
            .buyers
            .get(&TEST_USER2_PRINCIPAL.to_string())
            .unwrap()
            .amount_icp_e8s,
        4 * E8
    );

    // Assert the same balance using `get_buyer_state`
    assert_eq!(
        swap.get_buyer_state(&GetBuyerStateRequest {
            principal_id: Some(*TEST_USER2_PRINCIPAL)
        })
        .buyer_state
        .unwrap()
        .amount_icp_e8s,
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
