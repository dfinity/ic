use super::{SignableTransaction, Signed, TransactionPrice};
use crate::{
    eth_rpc::Hash,
    eth_rpc_client::responses::{TransactionReceipt, TransactionStatus},
    numeric::{BlockNumber, Wei},
};
use ic_ethereum_types::Address;
use minicbor::{Decode, Encode};

/// Immutable finalized transaction.
/// Use [`Signed::try_finalize`] to create a finalized transaction.
#[derive(Clone, Eq, PartialEq, Debug, Decode, Encode)]
pub struct Finalized<T: SignableTransaction> {
    #[n(0)]
    transaction: Signed<T>,
    #[n(1)]
    receipt: TransactionReceipt,
}

impl<T: SignableTransaction> Finalized<T> {
    pub fn block_number(&self) -> &BlockNumber {
        &self.receipt.block_number
    }

    pub fn transaction_hash(&self) -> &Hash {
        &self.receipt.transaction_hash
    }

    pub fn effective_transaction_fee(&self) -> Wei {
        self.receipt.effective_transaction_fee()
    }

    pub fn transaction_status(&self) -> &TransactionStatus {
        &self.receipt.status
    }

    pub fn destination(&self) -> &Address {
        self.transaction.transaction().destination()
    }

    pub fn transaction_amount(&self) -> &Wei {
        self.transaction.transaction().amount()
    }

    pub fn transaction_data(&self) -> &[u8] {
        self.transaction.transaction().data()
    }

    pub fn transaction(&self) -> &T {
        self.transaction.transaction()
    }

    pub fn transaction_price(&self) -> TransactionPrice {
        self.transaction.transaction().transaction_price()
    }
}

impl<T: SignableTransaction> AsRef<T> for Finalized<T> {
    fn as_ref(&self) -> &T {
        self.transaction.as_ref()
    }
}

impl<T: SignableTransaction> Signed<T> {
    pub fn try_finalize(self, receipt: TransactionReceipt) -> Result<Finalized<T>, String> {
        if self.hash() != receipt.transaction_hash {
            return Err(format!(
                "transaction hash mismatch: expected {}, got {}",
                self.hash(),
                receipt.transaction_hash
            ));
        }
        if self.transaction().max_fee_per_gas() < receipt.effective_gas_price {
            return Err(format!(
                "transaction max_fee_per_gas {} is smaller than effective_gas_price {}",
                self.transaction().max_fee_per_gas(),
                receipt.effective_gas_price
            ));
        }
        if self.transaction().gas_limit() < receipt.gas_used {
            return Err(format!(
                "transaction gas limit {} is smaller than gas used {}",
                self.transaction().gas_limit(),
                receipt.gas_used
            ));
        }
        Ok(Finalized {
            transaction: self,
            receipt,
        })
    }
}
