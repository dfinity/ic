#[cfg(test)]
mod tests;

use crate::numeric::{LedgerBurnIndex, TransactionNonce};
use crate::tx::{Eip1559TransactionRequest, SignedEip1559TransactionRequest};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Pending Ethereum transaction issued by minter. A request can be in one of the following states:
/// - NotSigned: the request is not signed yet
/// - Signed: the request is signed and ready to be sent to Ethereum
/// - Sent: the request was sent to Ethereum
#[derive(Clone, Serialize, Deserialize, Debug, Eq, Hash, PartialEq)]
pub enum PendingEthTransaction {
    NotSigned(Eip1559TransactionRequest),
    Signed(SignedEip1559TransactionRequest),
    Sent(SignedEip1559TransactionRequest),
}

impl PendingEthTransaction {
    pub fn nonce(&self) -> TransactionNonce {
        match self {
            PendingEthTransaction::NotSigned(tx) => tx.nonce,
            PendingEthTransaction::Signed(tx) => tx.nonce(),
            PendingEthTransaction::Sent(tx) => tx.nonce(),
        }
    }
}

/// Pending Ethereum transactions indexed by their burn index and by their nonce.
#[derive(Clone, Serialize, Deserialize, Debug, Eq, Hash, PartialEq)]
pub struct PendingEthTransactions {
    by_nonce: BTreeMap<TransactionNonce, PendingEthTransaction>,
    by_burn_index: BTreeMap<LedgerBurnIndex, TransactionNonce>,
    /// Next transaction nonce.
    /// It's expected that the next inserted transaction will have nonce equal to this value.
    next_nonce: TransactionNonce,
}

impl PendingEthTransactions {
    pub fn new(next_nonce: TransactionNonce) -> Self {
        Self {
            by_nonce: BTreeMap::new(),
            by_burn_index: BTreeMap::new(),
            next_nonce,
        }
    }

    pub fn insert(
        &mut self,
        index: LedgerBurnIndex,
        transaction: Eip1559TransactionRequest,
    ) -> Result<(), String> {
        if self.by_burn_index.contains_key(&index) {
            return Err(format!(
                "Transaction with burn index {:?} already exists",
                index
            ));
        }
        let tx_nonce = transaction.nonce;
        if self.by_nonce.contains_key(&tx_nonce) {
            return Err(format!(
                "Transaction with nonce {:?} already exists",
                transaction.nonce
            ));
        }
        if self.next_nonce != tx_nonce {
            return Err(format!(
                "Expected transaction with nonce value {:?}, got {:?}",
                self.next_nonce, tx_nonce
            ));
        }
        self.next_nonce = self
            .next_nonce
            .checked_increment()
            .expect("Transaction nonce overflow");
        self.by_nonce
            .insert(tx_nonce, PendingEthTransaction::NotSigned(transaction));
        self.by_burn_index.insert(index, tx_nonce);
        Ok(())
    }

    /// Returns transactions to sign ordered by their nonce.
    pub fn transactions_to_sign(&self) -> Vec<Eip1559TransactionRequest> {
        self.by_nonce
            .values()
            .flat_map(|pending_tx| match pending_tx {
                PendingEthTransaction::NotSigned(tx) => Some(tx.clone()),
                PendingEthTransaction::Signed(_) | PendingEthTransaction::Sent(_) => None,
            })
            .collect()
    }

    pub fn transactions_to_send(&self) -> Vec<SignedEip1559TransactionRequest> {
        self.by_nonce
            .values()
            .flat_map(|tx| match tx {
                PendingEthTransaction::NotSigned(_) | PendingEthTransaction::Sent(_) => None,
                PendingEthTransaction::Signed(tx) => Some(tx.clone()),
            })
            .collect()
    }

    pub fn transactions_sent(&self) -> Vec<SignedEip1559TransactionRequest> {
        self.by_nonce
            .values()
            .flat_map(|tx| match tx {
                PendingEthTransaction::Sent(tx) => Some(tx.clone()),
                PendingEthTransaction::NotSigned(_) | PendingEthTransaction::Signed(_) => None,
            })
            .collect()
    }

    pub fn replace_with_signed_transaction(
        &mut self,
        signed_tx: SignedEip1559TransactionRequest,
    ) -> Result<(), String> {
        let tx = self
            .by_nonce
            .get_mut(&signed_tx.nonce())
            .ok_or_else(|| format!("Transaction with nonce {:?} not found", signed_tx.nonce()))?;
        *tx = PendingEthTransaction::Signed(signed_tx);
        Ok(())
    }

    pub fn replace_with_sent_transaction(
        &mut self,
        signed_tx: SignedEip1559TransactionRequest,
    ) -> Result<(), String> {
        let tx = self
            .by_nonce
            .get_mut(&signed_tx.nonce())
            .ok_or_else(|| format!("Transaction with nonce {:?} not found", signed_tx.nonce()))?;
        *tx = PendingEthTransaction::Sent(signed_tx);
        Ok(())
    }

    pub fn find_by_burn_index(&self, burn_index: LedgerBurnIndex) -> Option<PendingEthTransaction> {
        self.by_burn_index
            .get(&burn_index)
            .and_then(|nonce| self.by_nonce.get(nonce))
            .cloned()
    }
}
