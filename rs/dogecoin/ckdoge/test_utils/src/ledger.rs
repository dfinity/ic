use candid::{Decode, Encode, Nat, Principal};
use ic_management_canister_types::CanisterId;
use icrc_ledger_types::icrc1::account::Account;
use icrc_ledger_types::icrc2::approve::ApproveError;
use icrc_ledger_types::icrc3::transactions::{Burn, Mint, Transaction as LedgerTransaction};
use pocket_ic::PocketIc;
use std::sync::Arc;

#[derive(Clone)]
pub struct LedgerCanister {
    pub(crate) env: Arc<PocketIc>,
    pub(crate) id: CanisterId,
}

impl LedgerCanister {
    pub fn assert_that_transaction<T: Into<Nat>>(
        &self,
        ledger_index: T,
    ) -> LedgerTransactionAssert<Self> {
        LedgerTransactionAssert {
            setup: self.clone(),
            ledger_transaction: self.get_transaction(ledger_index),
        }
    }

    pub fn get_transaction<T: Into<Nat>>(&self, ledger_index: T) -> LedgerTransaction {
        use icrc_ledger_types::icrc3::transactions::{
            GetTransactionsRequest, GetTransactionsResponse,
        };

        let request = GetTransactionsRequest {
            start: ledger_index.into(),
            length: 1_u8.into(),
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
        let mut response = Decode!(&result, GetTransactionsResponse).unwrap();
        assert_eq!(
            response.transactions.len(),
            1,
            "Expected exactly one transaction but got {:?}",
            response.transactions
        );
        response.transactions.pop().unwrap()
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
}

pub struct LedgerTransactionAssert<T> {
    pub(crate) setup: T,
    pub(crate) ledger_transaction: LedgerTransaction,
}

impl<T> LedgerTransactionAssert<T> {
    pub fn equals_mint_ignoring_timestamp(self, expected: Mint) -> T {
        assert_eq!(self.ledger_transaction.kind, "mint");
        assert_eq!(self.ledger_transaction.mint, Some(expected));
        assert_eq!(self.ledger_transaction.burn, None);
        assert_eq!(self.ledger_transaction.transfer, None);
        assert_eq!(self.ledger_transaction.approve, None);
        // we ignore timestamp
        self.setup
    }

    pub fn equals_burn_ignoring_timestamp(self, expected: Burn) -> T {
        assert_eq!(self.ledger_transaction.kind, "burn");
        assert_eq!(self.ledger_transaction.mint, None);
        assert_eq!(self.ledger_transaction.burn, Some(expected));
        assert_eq!(self.ledger_transaction.transfer, None);
        assert_eq!(self.ledger_transaction.approve, None);
        // we ignore timestamp
        self.setup
    }
}
