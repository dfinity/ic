#[cfg(test)]
mod tests;

use crate::address::Address;
use crate::endpoints::{EthTransaction, RetrieveEthStatus};
use crate::lifecycle::EthereumNetwork;
use crate::map::MultiKeyMap;
use crate::numeric::{LedgerBurnIndex, TransactionNonce, Wei};
use crate::tx::{
    ConfirmedEip1559Transaction, Eip1559TransactionRequest, SignedEip1559TransactionRequest,
    TransactionPrice,
};
use minicbor::{Decode, Encode};
use serde::{Deserialize, Serialize};
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

/// State machine holding Ethereum transactions issued by the minter.
/// Overall the transaction lifecycle is as follows:
/// 1. The user's withdrawal request is enqueued and processed in a FIFO order.
/// 2. A transaction is created by either consuming a withdrawal request
///    (the first time a transaction is created for that nonce and burn index)
///    or re-submitting an already sent transaction for that nonce and burn index.
/// 3. The transaction is signed and sent to Ethereum. There may have been multiple
///    sent transactions for that nonce and burn index in case of resubmissions.
/// 4. For a given nonce (and burn index), at most one sent transaction is finalized.
///    The others sent transactions for that nonce were never mined and can be discarded.
#[derive(Clone, Serialize, Deserialize, Debug, Eq, PartialEq)]
pub struct EthTransactions {
    withdrawal_requests: VecDeque<EthWithdrawalRequest>,
    created_tx: MultiKeyMap<TransactionNonce, LedgerBurnIndex, Eip1559TransactionRequest>,
    sent_tx: MultiKeyMap<TransactionNonce, LedgerBurnIndex, Vec<SignedEip1559TransactionRequest>>,
    finalized_tx: MultiKeyMap<TransactionNonce, LedgerBurnIndex, ConfirmedEip1559Transaction>,
    next_nonce: TransactionNonce,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CreateTransactionError {
    InsufficientAmount {
        ledger_burn_index: LedgerBurnIndex,
        withdrawal_amount: Wei,
        max_transaction_fee: Wei,
    },
}

impl EthTransactions {
    pub fn new(next_nonce: TransactionNonce) -> Self {
        Self {
            withdrawal_requests: VecDeque::new(),
            created_tx: MultiKeyMap::default(),
            sent_tx: MultiKeyMap::default(),
            finalized_tx: MultiKeyMap::default(),
            next_nonce,
        }
    }

    pub fn next_transaction_nonce(&self) -> TransactionNonce {
        self.next_nonce
    }

    pub fn update_next_transaction_nonce(&mut self, new_nonce: TransactionNonce) {
        self.next_nonce = new_nonce;
    }

    pub fn record_withdrawal_request(&mut self, request: EthWithdrawalRequest) {
        let burn_index = request.ledger_burn_index;
        if self
            .withdrawal_requests
            .iter()
            .any(|r| r.ledger_burn_index == burn_index)
            || self.created_tx.contains_alt(&burn_index)
            || self.sent_tx.contains_alt(&burn_index)
            || self.finalized_tx.contains_alt(&burn_index)
        {
            panic!("BUG: duplicate ledger burn index {burn_index}");
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

    pub fn withdrawal_requests_batch(&self, batch_size: usize) -> Vec<EthWithdrawalRequest> {
        // TODO FI-933: maybe look ahead at the size of created_tx and adapt the batch size accordingly
        // to ensure that at each state we do not process more that batch size
        self.withdrawal_requests_iter()
            .take(batch_size)
            .cloned()
            .collect()
    }

    pub fn record_created_transaction(
        &mut self,
        withdrawal_request: EthWithdrawalRequest,
        transaction: Eip1559TransactionRequest,
    ) {
        assert!(
            self.withdrawal_requests.contains(&withdrawal_request),
            "BUG: withdrawal request not found"
        );
        assert_eq!(
            withdrawal_request.destination, transaction.destination,
            "BUG: withdrawal request and transaction destination mismatch"
        );
        assert!(
            withdrawal_request.withdrawal_amount > transaction.amount,
            "BUG: transaction amount should be the withdrawal amount deducted from transaction fees"
        );
        let nonce = self.next_nonce;
        assert_eq!(transaction.nonce, nonce, "BUG: transaction nonce mismatch");
        self.next_nonce = self
            .next_nonce
            .checked_increment()
            .expect("Transaction nonce overflow");
        self.remove_withdrawal_request(&withdrawal_request);
        assert_eq!(
            self.created_tx
                .try_insert(nonce, withdrawal_request.ledger_burn_index, transaction),
            Ok(())
        );
    }

    pub fn withdrawal_requests_iter(&self) -> impl Iterator<Item = &EthWithdrawalRequest> {
        self.withdrawal_requests.iter()
    }

    pub fn record_sent_transaction(&mut self, sent_transaction: SignedEip1559TransactionRequest) {
        if let Some(already_sent_transactions) = self.sent_tx.get_mut(&sent_transaction.nonce()) {
            let tx = sent_transaction.transaction();
            let last_sent_tx = already_sent_transactions
                .last()
                .expect("BUG: empty sent transactions list")
                .transaction();
            assert!(equal_ignoring_fee_and_amount(tx, last_sent_tx), "BUG: mismatch between last sent transaction {last_sent_tx:?} and the new sent transaction {tx:?}");
            already_sent_transactions.push(sent_transaction);
        } else {
            let created_tx = self
                .created_tx
                .get(&sent_transaction.nonce())
                .expect("BUG: missing created transaction");
            assert_eq!(
                created_tx,
                sent_transaction.transaction(),
                "BUG: mismatch between sent transaction and created transaction"
            );
            let (nonce, ledger_burn_index, _created_tx) = self
                .created_tx
                .remove_entry(&sent_transaction.nonce())
                .expect("BUG: missing created transaction");
            assert_eq!(
                self.sent_tx
                    .try_insert(nonce, ledger_burn_index, vec![sent_transaction]),
                Ok(())
            );
        }
    }

    pub fn record_finalized_transaction(
        &mut self,
        confirmed_transaction: ConfirmedEip1559Transaction,
    ) {
        let nonce = confirmed_transaction.transaction().nonce;
        let sent_txs = self
            .sent_tx
            .get(&nonce)
            .expect("BUG: missing sent transaction");
        assert!(!sent_txs.is_empty(), "BUG: empty sent transactions");

        assert!(sent_txs
            .iter()
            .any(|tx| tx == confirmed_transaction.signed_transaction()),
                "BUG: mismatch between sent transactions and the confirmed transaction. Sent: {sent_txs:?}, confirmed: {confirmed_transaction:?}");

        let (_nonce, index, _sent_txs) = self
            .sent_tx
            .remove_entry(&nonce)
            .expect("BUG: missing sent transaction");
        assert_eq!(
            self.finalized_tx
                .try_insert(nonce, index, confirmed_transaction),
            Ok(())
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

        if self.created_tx.contains_alt(burn_index) {
            return RetrieveEthStatus::TxCreated;
        }

        // TODO FI-933: maybe display all sent transactions for that burn index instead of just the last one
        if let Some(tx) = self.sent_tx.get_alt(burn_index).and_then(|txs| txs.last()) {
            return RetrieveEthStatus::TxSent(EthTransaction::from(tx));
        }

        if let Some(tx) = self.finalized_tx.get_alt(burn_index) {
            return RetrieveEthStatus::TxConfirmed(EthTransaction::from(tx.signed_transaction()));
        }

        RetrieveEthStatus::NotFound
    }

    pub fn created_transactions_iter(
        &self,
    ) -> impl Iterator<
        Item = (
            &TransactionNonce,
            &LedgerBurnIndex,
            &Eip1559TransactionRequest,
        ),
    > {
        self.created_tx.iter()
    }

    pub fn sent_transactions_iter(
        &self,
    ) -> impl Iterator<
        Item = (
            &TransactionNonce,
            &LedgerBurnIndex,
            &Vec<SignedEip1559TransactionRequest>,
        ),
    > {
        self.sent_tx.iter()
    }

    pub fn finalized_transactions_iter(
        &self,
    ) -> impl Iterator<
        Item = (
            &TransactionNonce,
            &LedgerBurnIndex,
            &ConfirmedEip1559Transaction,
        ),
    > {
        self.finalized_tx.iter()
    }

    fn remove_withdrawal_request(&mut self, request: &EthWithdrawalRequest) {
        self.withdrawal_requests.retain(|r| r != request);
    }
}

/// Creates an EIP-1559 transaction for the given withdrawal request.
/// The transaction fees are paid by the beneficiary,
/// meaning that the fees will be deducted from the withdrawal amount.
///
/// # Errors
/// * `CreateTransactionError::InsufficientAmount` if the withdrawal amount does not cover the transaction fee.
pub fn create_transaction(
    withdrawal_request: &EthWithdrawalRequest,
    nonce: TransactionNonce,
    transaction_price: TransactionPrice,
    ethereum_network: EthereumNetwork,
) -> Result<Eip1559TransactionRequest, CreateTransactionError> {
    let max_transaction_fee = transaction_price.max_transaction_fee();
    let tx_amount = match withdrawal_request
        .withdrawal_amount
        .checked_sub(max_transaction_fee)
    {
        Some(tx_amount) => tx_amount,
        None => {
            return Err(CreateTransactionError::InsufficientAmount {
                ledger_burn_index: withdrawal_request.ledger_burn_index,
                withdrawal_amount: withdrawal_request.withdrawal_amount,
                max_transaction_fee,
            });
        }
    };
    Ok(Eip1559TransactionRequest {
        chain_id: ethereum_network.chain_id(),
        nonce,
        max_priority_fee_per_gas: transaction_price.max_priority_fee_per_gas,
        max_fee_per_gas: transaction_price.max_fee_per_gas,
        gas_limit: transaction_price.gas_limit,
        destination: withdrawal_request.destination,
        amount: tx_amount,
        data: Vec::new(),
        access_list: Default::default(),
    })
}

/// Returns true if the two transactions are equal ignoring the transaction fee and amount.
/// The following fields are ignored:
/// * `max_fee_per_gas`
/// * `max_priority_fee_per_gas`
/// * `amount` (because the cost of the transaction is paid by the beneficiary and so influencing the fee does influence the transaction amount)
fn equal_ignoring_fee_and_amount(
    lhs: &Eip1559TransactionRequest,
    rhs: &Eip1559TransactionRequest,
) -> bool {
    let mut rhs_with_lhs_fee_and_amount = rhs.clone();
    rhs_with_lhs_fee_and_amount.max_fee_per_gas = lhs.max_fee_per_gas;
    rhs_with_lhs_fee_and_amount.max_priority_fee_per_gas = lhs.max_priority_fee_per_gas;
    rhs_with_lhs_fee_and_amount.amount = lhs.amount;

    lhs == &rhs_with_lhs_fee_and_amount
}
