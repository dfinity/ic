#[cfg(test)]
mod tests;

use crate::address::Address;
use crate::endpoints::{EthTransaction, RetrieveEthStatus};
use crate::map::MultiKeyMap;
use crate::numeric::{LedgerBurnIndex, TransactionNonce, Wei};
use crate::tx::{
    ConfirmedEip1559Transaction, Eip1559TransactionRequest, SignedEip1559TransactionRequest,
};
use minicbor::{Decode, Encode};
use serde::{Deserialize, Serialize};
use std::collections::vec_deque::Iter;
use std::collections::VecDeque;

/// Ethereum withdrawal request issued by the user.
#[derive(Clone, Serialize, Deserialize, Debug, Eq, PartialEq, Encode, Decode)]
pub struct EthWithdrawalRequest {
    #[n(0)]
    pub withdrawal_amount: Wei,
    #[n(1)]
    pub destination: Address,
    #[cbor(n(2), with = "crate::cbor::id")]
    pub ledger_burn_index: LedgerBurnIndex,
}

/// Pending Ethereum transaction issued by minter. A request can be in one of the following states:
/// - TxCreated: the request was created but is not signed yet
/// - TxSigned: the request is signed and ready to be sent to Ethereum
/// - TxSent: the request was sent to Ethereum
#[derive(Clone, Serialize, Deserialize, Debug, Eq, PartialEq)]
struct PendingEthTx<T> {
    request: EthWithdrawalRequest,
    transaction: T,
    status: RetrieveEthStatus,
}

#[derive(Clone, Serialize, Deserialize, Debug, Eq, PartialEq)]
struct TxCreated(Eip1559TransactionRequest);

#[derive(Clone, Serialize, Deserialize, Debug, Eq, PartialEq)]
struct TxSigned(SignedEip1559TransactionRequest);

#[derive(Clone, Serialize, Deserialize, Debug, Eq, PartialEq)]
struct TxSent(SignedEip1559TransactionRequest);

/// State machine holding Ethereum transactions issued by the minter.
/// The state machine always upholds the following invariants:
/// * There is at most one pending transaction at any given time.
/// * A pending transaction can be in 1 of 3 states:
///     * TxCreated: the request was created (which includes estimating the transaction fees) but is not signed yet
///     * TxSigned: the request is signed and ready to be sent to Ethereum
///     * TxSent: the request was sent to Ethereum
/// * Withdrawal requests (if any) are processed in FIFO order
/// * A transaction is no longer pending once it's confirmed. Overall the transaction lifecycle is:
///   Withdrawal request -> TxCreated -> TxSigned -> TxSent -> TxConfirmed
/// * All transactions have unique ledger burn indexes and nonces
#[derive(Clone, Serialize, Deserialize, Debug, Eq, PartialEq)]
pub struct EthTransactions {
    withdrawal_requests: VecDeque<EthWithdrawalRequest>,
    pending_created_tx: Option<PendingEthTx<TxCreated>>,
    pending_signed_tx: Option<PendingEthTx<TxSigned>>,
    pending_sent_tx: Option<PendingEthTx<TxSent>>,
    confirmed_transactions:
        MultiKeyMap<TransactionNonce, LedgerBurnIndex, ConfirmedEip1559Transaction>,
    next_nonce: TransactionNonce,
}

impl EthTransactions {
    pub fn new(next_nonce: TransactionNonce) -> Self {
        Self {
            withdrawal_requests: VecDeque::new(),
            pending_created_tx: None,
            pending_signed_tx: None,
            pending_sent_tx: None,
            confirmed_transactions: MultiKeyMap::default(),
            next_nonce,
        }
    }

    pub fn update_next_transaction_nonce(&mut self, new_nonce: TransactionNonce) {
        self.next_nonce = new_nonce;
    }

    pub fn maybe_process_new_transaction(&self) -> Option<EthWithdrawalRequest> {
        if self.has_pending_tx() {
            return None;
        }
        self.withdrawal_requests.front().cloned()
    }

    pub fn next_to_sign(&self) -> Option<Eip1559TransactionRequest> {
        self.pending_created_tx
            .as_ref()
            .map(|tx| tx.transaction.0.clone())
    }

    pub fn next_to_send(&self) -> Option<SignedEip1559TransactionRequest> {
        self.pending_signed_tx
            .as_ref()
            .map(|tx| tx.transaction.0.clone())
    }

    pub fn next_to_confirm(&self) -> Option<SignedEip1559TransactionRequest> {
        self.pending_sent_tx
            .as_ref()
            .map(|tx| tx.transaction.0.clone())
    }

    pub fn record_withdrawal_request(&mut self, request: EthWithdrawalRequest) {
        if self
            .withdrawal_requests
            .iter()
            .any(|r| r.ledger_burn_index == request.ledger_burn_index)
        {
            panic!(
                "BUG: Withdrawal request with burn index {:?} already exists",
                request.ledger_burn_index
            )
        }
        if self
            .confirmed_transactions
            .contains_alt(&request.ledger_burn_index)
        {
            panic!(
                "BUG: A confirmed transaction with burn index {:?} already exists",
                request.ledger_burn_index
            )
        }
        self.withdrawal_requests.push_back(request);
    }

    /// Move an existing withdrawal request to the back of the queue.
    pub fn reschedule_withdrawal_request(&mut self, request: EthWithdrawalRequest) {
        assert_eq!(
            self.withdrawal_requests
                .iter()
                .filter(|r| r.ledger_burn_index == request.ledger_burn_index)
                .count(),
            1,
            "BUG: expected exactly one withdrawal request with ledger burn index {}",
            request.ledger_burn_index
        );
        self.remove_withdrawal_request(&request);
        self.record_withdrawal_request(request);
    }

    fn remove_withdrawal_request(&mut self, request: &EthWithdrawalRequest) {
        self.withdrawal_requests.retain(|r| r != request);
    }

    pub fn record_created_transaction(
        &mut self,
        withdrawal_request: EthWithdrawalRequest,
        transaction: Eip1559TransactionRequest,
    ) {
        assert!(
            !self.has_pending_tx(),
            "BUG: a pending transaction already exists"
        );
        assert_eq!(
            withdrawal_request.destination, transaction.destination,
            "BUG: withdrawal request and transaction destination mismatch"
        );
        assert!(
            withdrawal_request.withdrawal_amount > transaction.amount,
            "BUG: transaction amount should be the withdrawal amount deducted from transaction fees"
        );
        assert!(
            self.withdrawal_requests.contains(&withdrawal_request),
            "BUG: withdrawal request not found"
        );
        let tx_nonce = transaction.nonce;
        assert!(
            !self.confirmed_transactions.contains(&tx_nonce),
            "BUG: a confirmed transaction with nonce {:?} already exists",
            tx_nonce
        );
        assert_eq!(
            self.next_nonce, tx_nonce,
            "BUG: expected transaction with nonce {:?}, got {:?}",
            self.next_nonce, tx_nonce
        );

        self.next_nonce = self
            .next_nonce
            .checked_increment()
            .expect("Transaction nonce overflow");
        self.remove_withdrawal_request(&withdrawal_request);
        self.pending_created_tx = Some(PendingEthTx {
            request: withdrawal_request,
            transaction: TxCreated(transaction),
            status: RetrieveEthStatus::TxCreated,
        });
    }

    fn has_pending_tx(&self) -> bool {
        self.pending_created_tx.is_some()
            || self.pending_signed_tx.is_some()
            || self.pending_sent_tx.is_some()
    }

    pub fn pending_tx_info(
        &self,
    ) -> Option<(
        &EthWithdrawalRequest,
        &Eip1559TransactionRequest,
        &RetrieveEthStatus,
    )> {
        self.pending_created_tx
            .as_ref()
            .map(|tx| (&tx.request, &tx.transaction.0, &tx.status))
            .or_else(|| {
                self.pending_signed_tx
                    .as_ref()
                    .map(|tx| (&tx.request, tx.transaction.0.transaction(), &tx.status))
            })
            .or_else(|| {
                self.pending_sent_tx
                    .as_ref()
                    .map(|tx| (&tx.request, tx.transaction.0.transaction(), &tx.status))
            })
    }

    pub fn record_signed_transaction(
        &mut self,
        signed_transaction: SignedEip1559TransactionRequest,
    ) {
        let pending_tx = self
            .pending_created_tx
            .take()
            .expect("BUG: no pending created transaction");

        assert_eq!(
            &pending_tx.transaction.0,
            signed_transaction.transaction(),
            "BUG: pending transaction does not match the signed transaction",
        );

        self.pending_signed_tx = Some(PendingEthTx {
            request: pending_tx.request,
            status: RetrieveEthStatus::TxSigned(EthTransaction {
                transaction_hash: signed_transaction.hash().to_string(),
            }),
            transaction: TxSigned(signed_transaction),
        });
    }

    pub fn record_sent_transaction(&mut self, sent_transaction: SignedEip1559TransactionRequest) {
        let signed_tx = self
            .pending_signed_tx
            .take()
            .expect("BUG: no pending signed transaction");

        assert_eq!(
            &signed_tx.transaction.0, &sent_transaction,
            "BUG: pending transaction does not match the sent transaction",
        );

        self.pending_sent_tx = Some(PendingEthTx {
            request: signed_tx.request,
            status: RetrieveEthStatus::TxSent(EthTransaction {
                transaction_hash: sent_transaction.hash().to_string(),
            }),
            transaction: TxSent(sent_transaction),
        });
    }

    pub fn record_confirmed_transaction(
        &mut self,
        confirmed_transaction: ConfirmedEip1559Transaction,
    ) {
        let sent_tx = self
            .pending_sent_tx
            .take()
            .expect("BUG: no pending sent transaction");

        assert_eq!(
            &sent_tx.transaction.0,
            confirmed_transaction.signed_transaction(),
            "BUG: pending transaction does not match the confirmed transaction",
        );

        let tx_nonce = confirmed_transaction.signed_transaction().nonce();
        let index = sent_tx.request.ledger_burn_index;
        assert_eq!(
            self.confirmed_transactions
                .try_insert(tx_nonce, index, confirmed_transaction),
            Ok(()),
            "BUG: a confirmed transaction with nonce {:?} or index ledger burn index {:?} already exists",
            tx_nonce, index
        );
    }

    pub fn transaction_status(&self, burn_index: &LedgerBurnIndex) -> RetrieveEthStatus {
        if self
            .withdrawal_requests
            .iter()
            .any(|r| &r.ledger_burn_index == burn_index)
        {
            return RetrieveEthStatus::Pending;
        }

        if let Some((req, _tx, status)) = self.pending_tx_info() {
            if &req.ledger_burn_index == burn_index {
                return status.clone();
            }
        }

        if let Some(confirmed_tx) = self.confirmed_transactions.get_alt(burn_index) {
            return RetrieveEthStatus::TxConfirmed(EthTransaction {
                transaction_hash: confirmed_tx.signed_transaction().hash().to_string(),
            });
        }
        RetrieveEthStatus::NotFound
    }

    pub fn withdrawal_requests_iter(&self) -> Iter<'_, EthWithdrawalRequest> {
        self.withdrawal_requests.iter()
    }

    pub fn confirmed_transactions_iter(
        &self,
    ) -> impl Iterator<
        Item = (
            &TransactionNonce,
            &LedgerBurnIndex,
            &ConfirmedEip1559Transaction,
        ),
    > {
        self.confirmed_transactions.iter()
    }
}
