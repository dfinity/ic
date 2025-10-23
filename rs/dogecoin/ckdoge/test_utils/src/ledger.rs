use candid::{Decode, Encode, Nat, Principal};
use ic_management_canister_types::CanisterId;
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
