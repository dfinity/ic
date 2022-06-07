use async_trait::async_trait;
use dfn_core::CanisterId;
use futures::future::FutureExt;
use ic_base_types::PrincipalId;
use ic_nervous_system_common::ledger::{self, Ledger};
use ic_nervous_system_common::NervousSystemError;
use ic_nervous_system_common_test_keys::{
    TEST_USER1_PRINCIPAL, TEST_USER2_PRINCIPAL, TEST_USER3_PRINCIPAL,
};
use ic_sns_sale::pb::v1::*;

use ledger_canister::Tokens;
use ledger_canister::{AccountIdentifier, Subaccount};

use std::sync::{Arc, Mutex};

// For tests only. This does not imply that the canisters must have these IDs.
pub const SALE_CANISTER_ID: CanisterId = CanisterId::from_u64(1152);
pub const NNS_GOVERNANCE_CANISTER_ID: CanisterId = CanisterId::from_u64(1185);
pub const SNS_GOVERNANCE_CANISTER_ID: CanisterId = CanisterId::from_u64(1380);
pub const SNS_LEDGER_CANISTER_ID: CanisterId = CanisterId::from_u64(1571);
pub const ICP_LEDGER_CANISTER_ID: CanisterId = CanisterId::from_u64(1630);

fn init() -> Init {
    Init {
        // TODO: should fail until canister ids have been changed to something real.
        nns_governance_canister_id: NNS_GOVERNANCE_CANISTER_ID.to_string(),
        sns_governance_canister_id: SNS_GOVERNANCE_CANISTER_ID.to_string(),
        sns_ledger_canister_id: SNS_LEDGER_CANISTER_ID.to_string(),
        icp_ledger_canister_id: ICP_LEDGER_CANISTER_ID.to_string(),
        target_icp_e8s: 1000000_00000000,
        // 1640995200 = 2022-01-01T00:00:00
        token_sale_timestamp_seconds: 1640995200 + 10,
        min_participants: 3,
        min_participant_icp_e8s: 100_00000000,
    }
}

/// Expectation of one call on the mock Ledger.
#[derive(Debug, Clone)]
enum LedgerExpect {
    AccountBalance(AccountIdentifier, Result<Tokens, i32>),
    TransferFunds(
        u64,
        u64,
        Option<Subaccount>,
        AccountIdentifier,
        u64,
        Result<u64, i32>,
    ),
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
        to: AccountIdentifier,
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

    async fn account_balance(
        &self,
        account: AccountIdentifier,
    ) -> Result<Tokens, NervousSystemError> {
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

#[test]
fn test_init() {
    let sale = Sale::new(init());
    assert!(sale.is_valid());
}

#[test]
fn test_open() {
    let mut sale = Sale::new(init());
    // Cannot open as nothing for sale yet.
    assert!(sale.open().is_err());
    let account = AccountIdentifier::new(SALE_CANISTER_ID.get(), None);
    // Refresh yielding zero tokens...
    assert!(sale
        .refresh_sns_token_e8s(
            SALE_CANISTER_ID,
            &mock_stub(vec![LedgerExpect::AccountBalance(
                account,
                Ok(Tokens::ZERO)
            )])
        )
        .now_or_never()
        .unwrap()
        .is_ok());
    // Can still not open...
    assert!(sale.open().is_err());
    // Refresh giving error...
    assert!(sale
        .refresh_sns_token_e8s(
            SALE_CANISTER_ID,
            &mock_stub(vec![LedgerExpect::AccountBalance(account, Err(13))])
        )
        .now_or_never()
        .unwrap()
        .is_err());
    // Can still not open...
    assert!(sale.open().is_err());
    // Refresh giving 100k tokens
    assert!(sale
        .refresh_sns_token_e8s(
            SALE_CANISTER_ID,
            &mock_stub(vec![LedgerExpect::AccountBalance(
                account,
                Ok(Tokens::from_e8s(100000_00000000))
            )])
        )
        .now_or_never()
        .unwrap()
        .is_ok());
    // Check that state is updated.
    assert_eq!(sale.state().sns_token_e8s, 100000_00000000);
    // Now the sale can be opened.
    assert!(sale.open().is_ok());
}

/// Test the happy path of a token sale. First 200k SNS tokens are
/// sent. Then three buyers commit 1000 ICP, 600 ICP, and 400 ICP
/// respectively. Then the sale is committed and the tokens
/// distributed.
#[test]
fn test_scenario_happy() {
    let init = init();
    let mut sale = Sale::new(init.clone());
    // Refresh giving 200k tokens
    assert!(sale
        .refresh_sns_token_e8s(
            SALE_CANISTER_ID,
            &mock_stub(vec![LedgerExpect::AccountBalance(
                AccountIdentifier::new(SALE_CANISTER_ID.get(), None),
                Ok(Tokens::from_e8s(200000_00000000))
            )])
        )
        .now_or_never()
        .unwrap()
        .is_ok());
    assert_eq!(sale.state().sns_token_e8s, 200000_00000000);
    assert!(sale.open().is_ok());
    assert_eq!(sale.state().lifecycle(), Lifecycle::Open);
    // Cannot commit or abort, as the sale is not due yet.
    assert!(!sale.try_commit_or_abort(init.token_sale_timestamp_seconds - 1));
    assert_eq!(sale.state().lifecycle(), Lifecycle::Open);
    // Deposit 1000 ICP from one buyer.
    assert!(sale
        .refresh_buyer_token_e8s(
            *TEST_USER1_PRINCIPAL,
            SALE_CANISTER_ID,
            &mock_stub(vec![LedgerExpect::AccountBalance(
                AccountIdentifier::new(
                    SALE_CANISTER_ID.get(),
                    Some(Subaccount::from(&TEST_USER1_PRINCIPAL.clone()))
                ),
                Ok(Tokens::from_e8s(1000_00000000))
            )])
        )
        .now_or_never()
        .unwrap()
        .is_ok());
    assert_eq!(
        sale.state()
            .buyers
            .get(&TEST_USER1_PRINCIPAL.to_string())
            .unwrap()
            .amount_icp_e8s,
        1000_00000000
    );
    // Cannot commit or abort, as the sale is not due yet.
    assert!(!sale.try_commit_or_abort(init.token_sale_timestamp_seconds - 1));
    // Deposit 600 ICP from another buyer.
    assert!(sale
        .refresh_buyer_token_e8s(
            *TEST_USER2_PRINCIPAL,
            SALE_CANISTER_ID,
            &mock_stub(vec![LedgerExpect::AccountBalance(
                AccountIdentifier::new(
                    SALE_CANISTER_ID.get(),
                    Some(Subaccount::from(&TEST_USER2_PRINCIPAL.clone()))
                ),
                Ok(Tokens::from_e8s(600_00000000))
            )])
        )
        .now_or_never()
        .unwrap()
        .is_ok());
    assert_eq!(
        sale.state()
            .buyers
            .get(&TEST_USER2_PRINCIPAL.to_string())
            .unwrap()
            .amount_icp_e8s,
        600_00000000
    );
    // Now there are two participants. If the time was up, the sale could be aborted...
    {
        let mut abort_sale = sale.clone();
        assert!(abort_sale.try_commit_or_abort(init.token_sale_timestamp_seconds));
        assert_eq!(abort_sale.state().lifecycle(), Lifecycle::Aborted);
    }
    // Deposit 400 ICP from a third buyer.
    assert!(sale
        .refresh_buyer_token_e8s(
            *TEST_USER3_PRINCIPAL,
            SALE_CANISTER_ID,
            &mock_stub(vec![LedgerExpect::AccountBalance(
                AccountIdentifier::new(
                    SALE_CANISTER_ID.get(),
                    Some(Subaccount::from(&TEST_USER3_PRINCIPAL.clone()))
                ),
                Ok(Tokens::from_e8s(400_00000000))
            )])
        )
        .now_or_never()
        .unwrap()
        .is_ok());
    assert_eq!(
        sale.state()
            .buyers
            .get(&TEST_USER3_PRINCIPAL.to_string())
            .unwrap()
            .amount_icp_e8s,
        400_00000000
    );
    // Cannot commit if the sale is not due.
    assert!(!sale.can_commit(init.token_sale_timestamp_seconds - 1));
    // Can commit if the sale is due.
    assert!(sale.can_commit(init.token_sale_timestamp_seconds));
    // This should commit...
    assert!(sale.try_commit_or_abort(init.token_sale_timestamp_seconds));
    assert_eq!(sale.state().lifecycle(), Lifecycle::Committed);
    // Check that buyer balances are correct. Total SNS balance is 200k and total ICP is 2k.
    {
        let b1 = sale
            .state()
            .buyers
            .get(&TEST_USER1_PRINCIPAL.to_string())
            .unwrap();
        assert_eq!(b1.amount_icp_e8s, 1000_00000000);
        assert_eq!(b1.amount_sns_e8s, 100000_00000000);
    }
    {
        let b2 = sale
            .state()
            .buyers
            .get(&TEST_USER2_PRINCIPAL.to_string())
            .unwrap();
        assert_eq!(b2.amount_icp_e8s, 600_00000000);
        assert_eq!(b2.amount_sns_e8s, 60000_00000000);
    }
    {
        let b3 = sale
            .state()
            .buyers
            .get(&TEST_USER3_PRINCIPAL.to_string())
            .unwrap();
        assert_eq!(b3.amount_icp_e8s, 400_00000000);
        assert_eq!(b3.amount_sns_e8s, 40000_00000000);
    }
    {
        // "Sweep" all ICP, going to the governance canister. Mock one failure.
        let SweepResult {
            success,
            failure,
            skipped,
        } = sale
            .sweep_icp(
                Tokens::from_e8s(1),
                &mock_stub(vec![
                    LedgerExpect::TransferFunds(
                        600_00000000 - 1,
                        1,
                        Some(Subaccount::from(&*TEST_USER2_PRINCIPAL)),
                        AccountIdentifier::new(SNS_GOVERNANCE_CANISTER_ID.get(), None),
                        0,
                        Err(77),
                    ),
                    LedgerExpect::TransferFunds(
                        1000_00000000 - 1,
                        1,
                        Some(Subaccount::from(&*TEST_USER1_PRINCIPAL)),
                        AccountIdentifier::new(SNS_GOVERNANCE_CANISTER_ID.get(), None),
                        0,
                        Ok(1067),
                    ),
                    LedgerExpect::TransferFunds(
                        400_00000000 - 1,
                        1,
                        Some(Subaccount::from(&*TEST_USER3_PRINCIPAL)),
                        AccountIdentifier::new(SNS_GOVERNANCE_CANISTER_ID.get(), None),
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
        } = sale
            .sweep_icp(
                Tokens::from_e8s(2),
                &mock_stub(vec![LedgerExpect::TransferFunds(
                    600_00000000 - 2,
                    2,
                    Some(Subaccount::from(&*TEST_USER2_PRINCIPAL)),
                    AccountIdentifier::new(SNS_GOVERNANCE_CANISTER_ID.get(), None),
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
        fn dst(x: PrincipalId) -> AccountIdentifier {
            AccountIdentifier::new(
                SNS_GOVERNANCE_CANISTER_ID.get(),
                Some(ledger::compute_neuron_staking_subaccount(x, 0)),
            )
        }
        let SweepResult {
            success,
            failure,
            skipped,
        } = sale
            .sweep_sns(
                Tokens::from_e8s(1),
                &mock_stub(vec![
                    LedgerExpect::TransferFunds(
                        60000_00000000 - 1,
                        1,
                        None,
                        dst(*TEST_USER2_PRINCIPAL),
                        0,
                        Ok(1068),
                    ),
                    LedgerExpect::TransferFunds(
                        100000_00000000 - 1,
                        1,
                        None,
                        dst(*TEST_USER1_PRINCIPAL),
                        0,
                        Ok(1067),
                    ),
                    LedgerExpect::TransferFunds(
                        40000_00000000 - 1,
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
        assert!(sale.state().all_zeroed());
    }
}

// TO-TEST:
// - Reaching the target ICP, going over the bound.
// - Refunds in aborted state.
// - Refunds of tokens that the sale cansiter does not know about.
