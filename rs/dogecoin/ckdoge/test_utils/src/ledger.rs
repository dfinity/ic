use crate::NNS_ROOT_PRINCIPAL;
use candid::{Decode, Encode, Nat, Principal};
use ic_management_canister_types::CanisterId;
use icrc_ledger_types::icrc1::account::Account;
use icrc_ledger_types::icrc2::approve::ApproveError;
use icrc_ledger_types::icrc3::transactions::{Burn, Mint, Transaction as LedgerTransaction};
use pocket_ic::PocketIc;
use std::ops::RangeInclusive;
use std::sync::Arc;

#[derive(Clone)]
pub struct LedgerCanister {
    pub(crate) env: Arc<PocketIc>,
    pub(crate) id: CanisterId,
}

impl LedgerCanister {
    pub fn assert_that_transaction(&self, ledger_index: u64) -> LedgerTransactionAssert<Self> {
        self.assert_that_transactions(ledger_index..=ledger_index)
    }

    pub fn assert_that_transactions(
        &self,
        indexes: RangeInclusive<u64>,
    ) -> LedgerTransactionAssert<Self> {
        LedgerTransactionAssert {
            setup: self.clone(),
            ledger_transactions: self.get_transactions(indexes),
        }
    }

    pub fn get_transactions(&self, indexes: RangeInclusive<u64>) -> Vec<LedgerTransaction> {
        use icrc_ledger_types::icrc3::transactions::{
            GetTransactionsRequest, GetTransactionsResponse,
        };

        assert!(!indexes.is_empty());
        let length = indexes.end() - indexes.start() + 1;

        let request = GetTransactionsRequest {
            start: (*indexes.start()).into(),
            length: length.into(),
        };
        let result = self
            .env
            .query_call(
                self.id,
                Principal::anonymous(),
                "get_transactions",
                Encode!(&request).unwrap(),
            )
            .expect("Failed to call get_transactions");
        let response = Decode!(&result, GetTransactionsResponse).unwrap();

        assert_eq!(response.transactions.len() as u64, length);

        response.transactions
    }

    pub fn icrc2_approve(
        &self,
        from: impl Into<Account>,
        amount: u64,
        spender: impl Into<Account>,
    ) -> Result<u64, ApproveError> {
        use icrc_ledger_types::icrc2::approve::ApproveArgs;

        let from_account = from.into();
        let spender = spender.into();
        let request = ApproveArgs {
            from_subaccount: from_account.subaccount,
            spender,
            amount: Nat::from(amount),
            expected_allowance: None,
            expires_at: None,
            fee: None,
            memo: None,
            created_at_time: None,
        };
        let call_result = self
            .env
            .update_call(
                self.id,
                from_account.owner,
                "icrc2_approve",
                Encode!(&request).unwrap(),
            )
            .expect("BUG: failed to call icrc2_approve");
        Decode!(&call_result, Result<Nat, ApproveError>)
            .unwrap()
            .map(|index| index.0.try_into().unwrap())
    }

    pub fn icrc1_balance_of(&self, user: impl Into<Account>) -> u64 {
        let user = user.into();
        let call_result = self
            .env
            .query_call(
                self.id,
                Principal::anonymous(),
                "icrc1_balance_of",
                Encode!(&user).unwrap(),
            )
            .expect("BUG: failed to call icrc1_balance_of");
        Decode!(&call_result, Nat).unwrap().0.try_into().unwrap()
    }

    pub fn stop(&self) {
        self.env
            .stop_canister(self.id, Some(NNS_ROOT_PRINCIPAL))
            .unwrap()
    }

    pub fn id(&self) -> CanisterId {
        self.id
    }
}

pub struct LedgerTransactionAssert<T> {
    pub(crate) setup: T,
    pub(crate) ledger_transactions: Vec<LedgerTransaction>,
}

impl<T> LedgerTransactionAssert<T> {
    pub fn equals_mint_ignoring_timestamp(self, expected: &[Mint]) -> T {
        assert_eq!(self.ledger_transactions.len(), expected.len());
        for (tx, mint) in self.ledger_transactions.into_iter().zip(expected) {
            assert_eq!(tx.kind, "mint");
            assert_eq!(tx.mint, Some(mint.clone()));
            assert_eq!(tx.burn, None);
            assert_eq!(tx.transfer, None);
            assert_eq!(tx.approve, None);
            // we ignore timestamp
        }
        self.setup
    }

    pub fn equals_burn_ignoring_timestamp(self, expected: &[Burn]) -> T {
        assert_eq!(self.ledger_transactions.len(), expected.len());
        for (tx, burn) in self.ledger_transactions.into_iter().zip(expected) {
            assert_eq!(tx.kind, "burn");
            assert_eq!(tx.mint, None);
            assert_eq!(tx.burn, Some(burn.clone()));
            assert_eq!(tx.transfer, None);
            assert_eq!(tx.approve, None);
            // we ignore timestamp
        }
        self.setup
    }
}
