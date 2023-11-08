#[cfg(test)]
mod tests;

use crate::address::Address;
use crate::endpoints::{EthTransaction, RetrieveEthStatus};
use crate::eth_rpc::Hash;
use crate::eth_rpc_client::responses::TransactionReceipt;
use crate::lifecycle::EvmNetwork;
use crate::map::MultiKeyMap;
use crate::numeric::{LedgerBurnIndex, TransactionCount, TransactionNonce, Wei};
use crate::tx::{
    Eip1559TransactionRequest, FinalizedEip1559Transaction, SignedEip1559TransactionRequest,
    TransactionPrice,
};
use minicbor::{Decode, Encode};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, VecDeque};

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
/// 3. The transaction is signed via threshold ECDSA and recorded by either consuming the
///    previously created transaction or re-submitting an already sent transaction as is.
/// 4. The transaction is sent to Ethereum. There may have been multiple
///    sent transactions for that nonce and burn index in case of resubmissions.
/// 5. For a given nonce (and burn index), at most one sent transaction is finalized.
///    The others sent transactions for that nonce were never mined and can be discarded.
#[derive(Clone, Serialize, Deserialize, Debug, Eq, PartialEq)]
// TODO FI-948: limit number of withdrawal_requests and pending transactions nonces
pub struct EthTransactions {
    withdrawal_requests: VecDeque<EthWithdrawalRequest>,
    created_tx: MultiKeyMap<TransactionNonce, LedgerBurnIndex, Eip1559TransactionRequest>,
    signed_tx: MultiKeyMap<TransactionNonce, LedgerBurnIndex, SignedEip1559TransactionRequest>,
    sent_tx: MultiKeyMap<TransactionNonce, LedgerBurnIndex, Vec<SignedEip1559TransactionRequest>>,
    finalized_tx: MultiKeyMap<TransactionNonce, LedgerBurnIndex, FinalizedEip1559Transaction>,
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

/// A transaction to re-submit to Ethereum.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ResubmitTransaction {
    /// The transaction was changed (in comparison to the last sent transaction with that nonce);
    /// e.g., the transaction fee was increased, and needs to be re-signed.
    ToSign(Eip1559TransactionRequest),
    /// The transaction was not changed (in comparison to the last sent transaction with that nonce);
    /// and should be sent again as is
    ToSend(SignedEip1559TransactionRequest),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ResubmitTransactionError {
    InsufficientTransactionAmount {
        ledger_burn_index: LedgerBurnIndex,
        transaction_nonce: TransactionNonce,
        transaction_amount: Wei,
        max_transaction_fee: Wei,
    },
}

impl EthTransactions {
    pub fn new(next_nonce: TransactionNonce) -> Self {
        Self {
            withdrawal_requests: VecDeque::new(),
            created_tx: MultiKeyMap::default(),
            signed_tx: MultiKeyMap::default(),
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
            || self.signed_tx.contains_alt(&burn_index)
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

    pub fn record_signed_transaction(
        &mut self,
        signed_transaction: SignedEip1559TransactionRequest,
    ) {
        let created_tx = self
            .created_tx
            .get(&signed_transaction.nonce())
            .expect("BUG: missing created transaction");
        assert_eq!(
            created_tx,
            signed_transaction.transaction(),
            "BUG: mismatch between sent transaction and created transaction"
        );
        let (nonce, ledger_burn_index, _created_tx) = self
            .created_tx
            .remove_entry(&signed_transaction.nonce())
            .expect("BUG: missing created transaction");
        assert_eq!(
            self.signed_tx
                .try_insert(nonce, ledger_burn_index, signed_transaction),
            Ok(())
        );
    }

    pub fn record_sent_transaction(&mut self, sent_transaction: SignedEip1559TransactionRequest) {
        let signed_tx = self
            .signed_tx
            .get(&sent_transaction.nonce())
            .expect("BUG: missing signed transaction");
        assert_eq!(
            signed_tx, &sent_transaction,
            "BUG: mismatch between sent transaction and signed transaction"
        );
        let (nonce, ledger_burn_index, _signed_tx) = self
            .signed_tx
            .remove_entry(&sent_transaction.nonce())
            .expect("BUG: missing created transaction");

        if let Some(already_sent_transactions) = self.sent_tx.get_mut(&sent_transaction.nonce()) {
            already_sent_transactions.push(sent_transaction);
        } else {
            assert_eq!(
                self.sent_tx
                    .try_insert(nonce, ledger_burn_index, vec![sent_transaction]),
                Ok(())
            );
        }
    }

    /// Create transactions to resubmit corresponding to already sent transactions
    /// with nonces greater than the latest mined transaction nonce:
    /// * the resubmitted transaction will need to be re-signed if its transaction fee was increased
    /// * the resubmitted transaction can be resent as is if its transaction fee was not increased
    /// We stop on the first error since if a transaction with nonce n could not be resubmitted
    /// (e.g., the transaction amount does not cover the new fees),
    /// then the next transactions with nonces n+1, n+2, ... are blocked anyway
    /// and trying to resubmit them would only artificially increase their transaction fees.
    pub fn create_resubmit_transactions(
        &self,
        latest_transaction_count: TransactionCount,
        current_transaction_price: TransactionPrice,
    ) -> Vec<Result<ResubmitTransaction, ResubmitTransactionError>> {
        // If transaction count at block height H is c > 0, then transactions with nonces
        // 0, 1, ..., c - 1 were mined. If transaction count is 0, then no transactions were mined.
        // The nonce of the first pending transaction is then exactly c.
        let first_pending_tx_nonce =
            TransactionNonce::from_be_bytes(latest_transaction_count.to_be_bytes());
        let mut transactions_to_resubmit = Vec::new();
        for (nonce, burn_index, signed_tx) in self
            .sent_tx
            .iter()
            .filter(|(nonce, _burn_index, _signed_tx)| *nonce >= &first_pending_tx_nonce)
        {
            let last_signed_tx = signed_tx.last().expect("BUG: empty sent transactions list");
            let last_tx = last_signed_tx.transaction().clone();
            let last_tx_price = last_tx.transaction_price();
            let last_tx_max_fee = last_tx_price.max_transaction_fee();
            if last_tx_price.is_fee_increased(&current_transaction_price) {
                let new_tx_price = last_tx_price
                    .increase_by_10_percent()
                    .max(current_transaction_price.clone());
                let new_amount = match last_tx.amount.checked_sub(
                    new_tx_price
                        .max_transaction_fee()
                        .checked_sub(last_tx_max_fee)
                        .expect("BUG: new price was increased by at least 10%"),
                ) {
                    Some(amount) => amount,
                    None => {
                        transactions_to_resubmit.push(Err(
                            ResubmitTransactionError::InsufficientTransactionAmount {
                                ledger_burn_index: *burn_index,
                                transaction_nonce: *nonce,
                                transaction_amount: last_tx.amount,
                                max_transaction_fee: new_tx_price.max_transaction_fee(),
                            },
                        ));
                        return transactions_to_resubmit;
                    }
                };
                let new_tx = Eip1559TransactionRequest {
                    max_priority_fee_per_gas: new_tx_price.max_priority_fee_per_gas,
                    max_fee_per_gas: new_tx_price.max_fee_per_gas,
                    gas_limit: new_tx_price.gas_limit,
                    amount: new_amount,
                    ..last_tx
                };
                transactions_to_resubmit.push(Ok(ResubmitTransaction::ToSign(new_tx)));
            } else {
                // the transaction fee is still up-to-date but because the transaction did not get mined,
                // we re-send it as is to be sure that it remains known to the mempool and hopefully be mined at some point.
                transactions_to_resubmit
                    .push(Ok(ResubmitTransaction::ToSend(last_signed_tx.clone())));
            }
        }
        transactions_to_resubmit
    }

    pub fn record_resubmit_transaction(&mut self, transaction: ResubmitTransaction) {
        match transaction {
            ResubmitTransaction::ToSign(new_tx) => {
                self.record_resubmit_to_sign_tx(new_tx);
            }
            ResubmitTransaction::ToSend(signed_tx) => {
                self.record_resubmit_to_send_tx(signed_tx);
            }
        }
    }

    fn record_resubmit_to_sign_tx(&mut self, new_tx: Eip1559TransactionRequest) {
        let (ledger_burn_index, last_sent_tx) =
            Self::expect_last_sent_tx_entry(&self.sent_tx, &new_tx.nonce);
        assert!(equal_ignoring_fee_and_amount(last_sent_tx.transaction(), &new_tx),
                "BUG: mismatch between last sent transaction {last_sent_tx:?} and the transaction to resubmit {new_tx:?}");
        Self::cleanup_failed_resubmitted_transactions(
            &mut self.created_tx,
            &mut self.signed_tx,
            &new_tx.nonce,
        );
        assert_eq!(
            self.created_tx
                .try_insert(new_tx.nonce, *ledger_burn_index, new_tx.clone()),
            Ok(())
        );
    }

    fn record_resubmit_to_send_tx(&mut self, signed_tx: SignedEip1559TransactionRequest) {
        let (ledger_burn_index, last_sent_tx) =
            Self::expect_last_sent_tx_entry(&self.sent_tx, &signed_tx.nonce());
        assert_eq!(last_sent_tx, &signed_tx, "BUG: mismatch between last sent transaction {last_sent_tx:?} and the transaction to resubmit {signed_tx:?}");
        Self::cleanup_failed_resubmitted_transactions(
            &mut self.created_tx,
            &mut self.signed_tx,
            &signed_tx.nonce(),
        );
        assert_eq!(
            self.signed_tx
                .try_insert(signed_tx.nonce(), *ledger_burn_index, signed_tx),
            Ok(())
        );
    }

    pub fn sent_transactions_to_finalize(
        &self,
        finalized_transaction_count: &TransactionCount,
    ) -> BTreeMap<Hash, LedgerBurnIndex> {
        let first_non_finalized_tx_nonce =
            TransactionNonce::from_be_bytes(finalized_transaction_count.to_be_bytes());
        let mut transactions = BTreeMap::new();
        for (_nonce, index, sent_txs) in self
            .sent_tx
            .iter()
            .filter(|(nonce, _burn_index, _signed_txs)| *nonce < &first_non_finalized_tx_nonce)
        {
            for sent_tx in sent_txs {
                if let Some(prev_index) = transactions.insert(sent_tx.hash(), *index) {
                    assert_eq!(prev_index, *index,
                               "BUG: duplicate transaction hash {} for burn indices {prev_index} and {index}", sent_tx.hash());
                }
            }
        }
        transactions
    }

    pub fn record_finalized_transaction(
        &mut self,
        ledger_burn_index: LedgerBurnIndex,
        receipt: TransactionReceipt,
    ) {
        let sent_tx = self
            .sent_tx
            .get_alt(&ledger_burn_index)
            .expect("BUG: missing sent transactions")
            .iter()
            .find(|sent_tx| sent_tx.hash() == receipt.transaction_hash)
            .expect("ERROR: no transaction matching receipt");
        let finalized_tx = sent_tx
            .clone()
            .try_finalize(receipt)
            .expect("ERROR: invalid transaction receipt");

        let nonce = sent_tx.nonce();
        self.sent_tx.remove_entry(&nonce);
        Self::cleanup_failed_resubmitted_transactions(
            &mut self.created_tx,
            &mut self.signed_tx,
            &nonce,
        );
        assert_eq!(
            self.finalized_tx
                .try_insert(nonce, ledger_burn_index, finalized_tx),
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

        if let Some(tx) = self.signed_tx.get_alt(burn_index) {
            return RetrieveEthStatus::TxSigned(EthTransaction::from(tx));
        }

        if let Some(tx) = self.sent_tx.get_alt(burn_index).and_then(|txs| txs.last()) {
            return RetrieveEthStatus::TxSent(EthTransaction::from(tx));
        }

        if let Some(tx) = self.finalized_tx.get_alt(burn_index) {
            return RetrieveEthStatus::TxConfirmed(EthTransaction {
                transaction_hash: tx.transaction_hash().to_string(),
            });
        }

        RetrieveEthStatus::NotFound
    }

    pub fn withdrawal_requests_batch(&self, batch_size: usize) -> Vec<EthWithdrawalRequest> {
        // TODO FI-948: maybe look ahead at the size of created_tx and adapt the batch size accordingly
        // to ensure that at each state we do not process more that batch size
        self.withdrawal_requests_iter()
            .take(batch_size)
            .cloned()
            .collect()
    }

    pub fn withdrawal_requests_iter(&self) -> impl Iterator<Item = &EthWithdrawalRequest> {
        self.withdrawal_requests.iter()
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

    pub fn signed_transactions_iter(
        &self,
    ) -> impl Iterator<
        Item = (
            &TransactionNonce,
            &LedgerBurnIndex,
            &SignedEip1559TransactionRequest,
        ),
    > {
        self.signed_tx.iter()
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
            &FinalizedEip1559Transaction,
        ),
    > {
        self.finalized_tx.iter()
    }

    pub fn is_sent_tx_empty(&self) -> bool {
        self.sent_tx.is_empty()
    }

    pub fn nothing_to_process(&self) -> bool {
        self.withdrawal_requests.is_empty()
            && self.created_tx.is_empty()
            && self.signed_tx.is_empty()
            && self.sent_tx.is_empty()
    }

    fn remove_withdrawal_request(&mut self, request: &EthWithdrawalRequest) {
        self.withdrawal_requests.retain(|r| r != request);
    }

    fn expect_last_sent_tx_entry<'a>(
        sent_tx: &'a MultiKeyMap<
            TransactionNonce,
            LedgerBurnIndex,
            Vec<SignedEip1559TransactionRequest>,
        >,
        nonce: &TransactionNonce,
    ) -> (&'a LedgerBurnIndex, &'a SignedEip1559TransactionRequest) {
        let (ledger_burn_index, sent_txs) = sent_tx
            .get_entry(nonce)
            .expect("BUG: sent transaction not found");
        let last_sent_tx = sent_txs.last().expect("BUG: empty sent transactions list");
        (ledger_burn_index, last_sent_tx)
    }

    fn cleanup_failed_resubmitted_transactions(
        created_tx: &mut MultiKeyMap<TransactionNonce, LedgerBurnIndex, Eip1559TransactionRequest>,
        signed_tx: &mut MultiKeyMap<
            TransactionNonce,
            LedgerBurnIndex,
            SignedEip1559TransactionRequest,
        >,
        nonce: &TransactionNonce,
    ) {
        use crate::logs::INFO;
        use ic_canister_log::log;

        if let Some((_nonce, _index, prev_resubmitted_tx)) = created_tx.remove_entry(nonce) {
            log!(INFO, "[cleanup_failed_resubmitted_transactions]: removing previously resubmitted transaction {prev_resubmitted_tx:?} that failed to progress");
        }
        if let Some((_nonce, _index, prev_resubmitted_tx)) = signed_tx.remove_entry(nonce) {
            log!(INFO, "[cleanup_failed_resubmitted_transactions]: removing previously resubmitted transaction {prev_resubmitted_tx:?} that failed to progress");
        }
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
    ethereum_network: EvmNetwork,
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
