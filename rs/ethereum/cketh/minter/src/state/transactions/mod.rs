#[cfg(test)]
mod tests;

use crate::endpoints::{EthTransaction, RetrieveEthStatus, TxFinalizedStatus};
use crate::erc20::CkTokenSymbol;
use crate::eth_rpc::Hash;
use crate::eth_rpc_client::responses::TransactionReceipt;
use crate::eth_rpc_client::responses::TransactionStatus;
use crate::lifecycle::EthereumNetwork;
use crate::map::MultiKeyMap;
use crate::numeric::{
    Erc20Value, LedgerBurnIndex, LedgerMintIndex, TransactionCount, TransactionNonce, Wei,
};
use crate::tx::{
    Eip1559TransactionRequest, FinalizedEip1559Transaction, SignedEip1559TransactionRequest,
    TransactionPrice,
};
use candid::Principal;
use ic_ethereum_types::Address;
use minicbor::{Decode, Encode};
use std::cmp::min;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt;

/// Ethereum withdrawal request issued by the user.
#[derive(Clone, Eq, PartialEq, Encode, Decode)]
pub struct EthWithdrawalRequest {
    /// The ETH amount that the receiver will get, not accounting for the Ethereum transaction fees.
    #[n(0)]
    pub withdrawal_amount: Wei,
    /// The address to which the minter will send ETH.
    #[n(1)]
    pub destination: Address,
    /// The transaction ID of the ckETH burn operation.
    #[cbor(n(2), with = "crate::cbor::id")]
    pub ledger_burn_index: LedgerBurnIndex,
    /// The owner of the account from which the minter burned ckETH.
    #[cbor(n(3), with = "crate::cbor::principal")]
    pub from: Principal,
    /// The subaccount from which the minter burned ckETH.
    #[n(4)]
    pub from_subaccount: Option<Subaccount>,
    /// The IC time at which the withdrawal request arrived.
    #[n(5)]
    pub created_at: Option<u64>,
}

/// ERC-20 withdrawal request issued by the user.
#[derive(Clone, Eq, PartialEq, Encode, Decode)]
pub struct Erc20WithdrawalRequest {
    /// Amount of burn ckETH that can be used to pay for the Ethereum transaction fees.
    #[n(0)]
    pub max_transaction_fee: Wei,
    /// The ERC-20 amount that the receiver will get, not accounting for the Ethereum transaction fees.
    #[n(1)]
    pub withdrawal_amount: Erc20Value,
    /// The address to which the minter will send the ERC20 token.
    #[n(2)]
    pub destination: Address,
    /// The transaction ID of the ckETH burn operation.
    #[cbor(n(3), with = "crate::cbor::id")]
    pub cketh_ledger_burn_index: LedgerBurnIndex,
    /// The symbol of the withdrawn ckERC20 token. e.g., "ckUSDT".
    #[n(4)]
    pub ckerc20_token_symbol: CkTokenSymbol,
    /// The transaction ID of the ckERC20 burn operation.
    #[cbor(n(5), with = "crate::cbor::id")]
    pub ckerc20_ledger_burn_index: LedgerBurnIndex,
    /// The owner of the account from which the minter burned ckETH.
    #[cbor(n(6), with = "crate::cbor::principal")]
    pub from: Principal,
    /// The subaccount from which the minter burned ckETH.
    #[n(7)]
    pub from_subaccount: Option<Subaccount>,
    /// The IC time at which the withdrawal request arrived.
    #[n(8)]
    pub created_at: u64,
}

#[derive(Debug, Clone, Eq, PartialEq, Encode, Decode)]
pub struct ReimbursementRequest {
    #[cbor(n(0), with = "crate::cbor::id")]
    pub withdrawal_id: LedgerBurnIndex,
    #[n(1)]
    pub reimbursed_amount: Wei,
    #[cbor(n(2), with = "crate::cbor::principal")]
    pub to: Principal,
    #[n(3)]
    pub to_subaccount: Option<Subaccount>,
    #[n(4)]
    /// Transaction hash of the failed ETH transaction.
    /// We use this hash to link the mint reimbursement transaction
    /// on the ledger with the failed ETH transaction.
    pub transaction_hash: Option<Hash>,
}

#[derive(Debug, Clone, Eq, PartialEq, Encode, Decode)]
pub struct Reimbursed {
    #[cbor(n(0), with = "crate::cbor::id")]
    pub reimbursed_in_block: LedgerMintIndex,
    #[cbor(n(1), with = "crate::cbor::id")]
    pub withdrawal_id: LedgerBurnIndex,
    #[n(2)]
    pub reimbursed_amount: Wei,
    #[n(3)]
    pub transaction_hash: Option<Hash>,
}

#[derive(Clone, Eq, PartialEq, Encode, Decode)]
#[cbor(transparent)]
pub struct Subaccount(#[cbor(n(0), with = "minicbor::bytes")] pub [u8; 32]);

impl fmt::Debug for Subaccount {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(f, "{}", hex::encode(self.0))
    }
}

struct DebugPrincipal<'a>(&'a Principal);

impl fmt::Debug for DebugPrincipal<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(f, "{}", self.0)
    }
}

impl fmt::Debug for EthWithdrawalRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        f.debug_struct("EthWithdrawalRequest")
            .field("withdrawal_amount", &self.withdrawal_amount)
            .field("destination", &self.destination)
            .field("ledger_burn_index", &self.ledger_burn_index)
            .field("from", &DebugPrincipal(&self.from))
            .field("from_subaccount", &self.from_subaccount)
            .finish()
    }
}

impl fmt::Debug for Erc20WithdrawalRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        f.debug_struct("Erc20WithdrawalRequest")
            .field("max_transaction_fee", &self.max_transaction_fee)
            .field("withdrawal_amount", &self.withdrawal_amount)
            .field(
                "ckerc20_token_symbol",
                &format_args!("{}", &self.ckerc20_token_symbol),
            )
            .field("destination", &self.destination)
            .field("cketh_ledger_burn_index", &self.cketh_ledger_burn_index)
            .field("ckerc20_ledger_burn_index", &self.ckerc20_ledger_burn_index)
            .field("from", &DebugPrincipal(&self.from))
            .field("from_subaccount", &self.from_subaccount)
            .finish()
    }
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
/// 6. If a given transaction fails the minter will reimburse the user who requested the
///    withdrawal with the corresponding amount minus fees.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EthTransactions {
    pub(in crate::state) withdrawal_requests: VecDeque<EthWithdrawalRequest>,
    pub(in crate::state) created_tx:
        MultiKeyMap<TransactionNonce, LedgerBurnIndex, Eip1559TransactionRequest>,
    pub(in crate::state) sent_tx:
        MultiKeyMap<TransactionNonce, LedgerBurnIndex, Vec<SignedEip1559TransactionRequest>>,
    pub(in crate::state) finalized_tx:
        MultiKeyMap<TransactionNonce, LedgerBurnIndex, FinalizedEip1559Transaction>,
    pub(in crate::state) next_nonce: TransactionNonce,

    pub(in crate::state) maybe_reimburse: BTreeMap<LedgerBurnIndex, EthWithdrawalRequest>,
    pub(in crate::state) reimbursement_requests: BTreeMap<LedgerBurnIndex, ReimbursementRequest>,
    pub(in crate::state) reimbursed: BTreeMap<LedgerBurnIndex, Reimbursed>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CreateTransactionError {
    InsufficientAmount {
        ledger_burn_index: LedgerBurnIndex,
        withdrawal_amount: Wei,
        max_transaction_fee: Wei,
    },
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
            sent_tx: MultiKeyMap::default(),
            finalized_tx: MultiKeyMap::default(),
            next_nonce,
            maybe_reimburse: Default::default(),
            reimbursement_requests: Default::default(),
            reimbursed: Default::default(),
        }
    }

    pub fn next_transaction_nonce(&self) -> TransactionNonce {
        self.next_nonce
    }

    pub fn update_next_transaction_nonce(&mut self, new_nonce: TransactionNonce) {
        self.next_nonce = new_nonce;
    }

    pub fn get_reimbursement_requests(&self) -> Vec<ReimbursementRequest> {
        self.reimbursement_requests.values().cloned().collect()
    }

    pub fn get_reimbursed_transactions(&self) -> Vec<Reimbursed> {
        self.reimbursed.values().cloned().collect()
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

    pub fn record_erc20_withdrawal_request(&mut self, _request: Erc20WithdrawalRequest) {
        unimplemented!("TODO XC-59")
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
        withdrawal_id: LedgerBurnIndex,
        transaction: Eip1559TransactionRequest,
    ) {
        let withdrawal_request = self
            .withdrawal_requests
            .iter()
            .find(|req| req.ledger_burn_index == withdrawal_id)
            .cloned()
            .unwrap_or_else(|| panic!("BUG: withdrawal request {withdrawal_id} not found"));
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
        self.maybe_reimburse
            .insert(withdrawal_id, withdrawal_request);
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
        if let Some(sent_tx) = self.sent_tx.get_mut(&nonce) {
            sent_tx.push(signed_transaction);
        } else {
            assert_eq!(
                self.sent_tx
                    .try_insert(nonce, ledger_burn_index, vec![signed_transaction]),
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
    ) -> Vec<Result<(LedgerBurnIndex, Eip1559TransactionRequest), ResubmitTransactionError>> {
        // If transaction count at block height H is c > 0, then transactions with nonces
        // 0, 1, ..., c - 1 were mined. If transaction count is 0, then no transactions were mined.
        // The nonce of the first pending transaction is then exactly c.
        let first_pending_tx_nonce: TransactionNonce = latest_transaction_count.change_units();
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
                transactions_to_resubmit.push(Ok((*burn_index, new_tx)));
            } else {
                // the transaction fee is still up-to-date but because the transaction did not get mined,
                // we re-send it as is to be sure that it remains known to the mempool and hopefully be mined at some point.
                // Since we always re-send the last non-mined transactions in sent_tx, there is nothing to do.
            }
        }
        transactions_to_resubmit
    }

    pub fn record_resubmit_transaction(&mut self, new_tx: Eip1559TransactionRequest) {
        let (ledger_burn_index, last_sent_tx) =
            Self::expect_last_sent_tx_entry(&self.sent_tx, &new_tx.nonce);
        assert!(equal_ignoring_fee_and_amount(last_sent_tx.transaction(), &new_tx),
                "BUG: mismatch between last sent transaction {last_sent_tx:?} and the transaction to resubmit {new_tx:?}");
        Self::cleanup_failed_resubmitted_transactions(&mut self.created_tx, &new_tx.nonce);
        assert_eq!(
            self.created_tx
                .try_insert(new_tx.nonce, *ledger_burn_index, new_tx.clone()),
            Ok(())
        );
    }

    pub fn sent_transactions_to_finalize(
        &self,
        finalized_transaction_count: &TransactionCount,
    ) -> BTreeMap<Hash, LedgerBurnIndex> {
        let first_non_finalized_tx_nonce: TransactionNonce =
            finalized_transaction_count.change_units();
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
            .expect("ERROR: no transaction matching receipt")
            .clone();
        let finalized_tx = sent_tx
            .clone()
            .try_finalize(receipt.clone())
            .expect("ERROR: invalid transaction receipt");

        let nonce = sent_tx.nonce();
        {
            self.sent_tx.remove_entry(&nonce);
            Self::cleanup_failed_resubmitted_transactions(&mut self.created_tx, &nonce);
        }
        assert_eq!(
            self.finalized_tx
                .try_insert(nonce, ledger_burn_index, finalized_tx.clone()),
            Ok(())
        );

        let maybe_reimburse = self.maybe_reimburse.remove(&ledger_burn_index).expect(
            "failed to remove entry from maybe_reimburse map with block index: {ledger_burn_index}",
        );
        if receipt.status == TransactionStatus::Failure {
            self.reimbursement_requests.insert(
                ledger_burn_index,
                ReimbursementRequest {
                    withdrawal_id: ledger_burn_index,
                    to: maybe_reimburse.from,
                    to_subaccount: maybe_reimburse.from_subaccount,
                    reimbursed_amount: *finalized_tx.transaction_amount(),
                    transaction_hash: Some(receipt.transaction_hash),
                },
            );
        }
    }

    pub fn record_finalized_reimbursement(
        &mut self,
        withdrawal_id: LedgerBurnIndex,
        reimbursed_in_block: LedgerMintIndex,
    ) {
        let reimbursement_request = self
            .reimbursement_requests
            .remove(&withdrawal_id)
            .expect("failed to remove reimbursement request");
        assert_eq!(
            self.reimbursed.insert(
                withdrawal_id,
                Reimbursed {
                    withdrawal_id,
                    reimbursed_in_block,
                    reimbursed_amount: reimbursement_request.reimbursed_amount,
                    transaction_hash: reimbursement_request.transaction_hash,
                },
            ),
            None
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

        if let Some(tx) = self.sent_tx.get_alt(burn_index).and_then(|txs| txs.last()) {
            return RetrieveEthStatus::TxSent(EthTransaction::from(tx));
        }

        if let Some(tx) = self.finalized_tx.get_alt(burn_index) {
            if let Some(reimbursed) = self.reimbursed.get(burn_index) {
                return RetrieveEthStatus::TxFinalized(TxFinalizedStatus::Reimbursed {
                    reimbursed_in_block: reimbursed.reimbursed_in_block.get().into(),
                    transaction_hash: tx.transaction_hash().to_string(),
                    reimbursed_amount: reimbursed.reimbursed_amount.into(),
                });
            }
            if tx.transaction_status() == &TransactionStatus::Failure {
                return RetrieveEthStatus::TxFinalized(TxFinalizedStatus::PendingReimbursement(
                    EthTransaction {
                        transaction_hash: tx.transaction_hash().to_string(),
                    },
                ));
            }

            return RetrieveEthStatus::TxFinalized(TxFinalizedStatus::Success(EthTransaction {
                transaction_hash: tx.transaction_hash().to_string(),
            }));
        }

        RetrieveEthStatus::NotFound
    }

    pub fn withdrawal_requests_batch(
        &self,
        requested_batch_size: usize,
    ) -> Vec<EthWithdrawalRequest> {
        // The number of pending transaction nonces is counted and not the number of pending transactions
        // because a nonce may be associated with several distinct transactions (due to re-submission and dynamic fees).
        // However, once a nonce is chosen for a withdrawal request, it's in our interest that the corresponding transaction be finalized asap.
        // Limiting the number of transactions would be counter-productive.
        const MAX_NUM_PENDING_TRANSACTION_NONCES: usize = 1000;
        let unique_pending_transaction_nonces: BTreeSet<_> =
            self.created_tx.keys().chain(self.sent_tx.keys()).collect();
        let actual_batch_size = min(
            MAX_NUM_PENDING_TRANSACTION_NONCES
                .saturating_sub(unique_pending_transaction_nonces.len()),
            requested_batch_size,
        );
        self.withdrawal_requests_iter()
            .take(actual_batch_size)
            .cloned()
            .collect()
    }

    pub fn withdrawal_requests_iter(&self) -> impl Iterator<Item = &EthWithdrawalRequest> {
        self.withdrawal_requests.iter()
    }

    pub fn withdrawal_requests_len(&self) -> usize {
        self.withdrawal_requests.len()
    }

    pub fn transactions_to_sign_iter(
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

    pub fn transactions_to_sign_batch(
        &self,
        batch_size: usize,
    ) -> Vec<(LedgerBurnIndex, Eip1559TransactionRequest)> {
        self.transactions_to_sign_iter()
            .take(batch_size)
            .map(|(_nonce, withdrawal_id, tx)| (*withdrawal_id, tx.clone()))
            .collect()
    }

    pub fn transactions_to_send_batch(
        &self,
        latest_transaction_count: TransactionCount,
        batch_size: usize,
    ) -> Vec<SignedEip1559TransactionRequest> {
        let first_pending_tx_nonce: TransactionNonce = latest_transaction_count.change_units();
        self.sent_tx
            .iter()
            .filter_map(move |(nonce, ledger_burn_index, txs)| {
                txs.last()
                    .map(|tx| (nonce, ledger_burn_index, tx))
                    .filter(|(nonce, _ledger_burn_index, _tx)| *nonce >= &first_pending_tx_nonce)
            })
            .take(batch_size)
            .map(|(_nonce, _index, tx)| tx)
            .cloned()
            .collect()
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

    pub fn has_pending_requests(&self) -> bool {
        !self.withdrawal_requests.is_empty()
            || !self.created_tx.is_empty()
            || !self.sent_tx.is_empty()
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
        nonce: &TransactionNonce,
    ) {
        use crate::logs::INFO;
        use ic_canister_log::log;

        if let Some((_nonce, _index, prev_resubmitted_tx)) = created_tx.remove_entry(nonce) {
            log!(INFO, "[cleanup_failed_resubmitted_transactions]: removing previously resubmitted transaction {prev_resubmitted_tx:?} that failed to progress");
        }
    }

    /// Checks whether two transaction state machines are equivalent.
    pub fn is_equivalent_to(&self, other: &Self) -> Result<(), String> {
        use ic_utils_ensure::ensure_eq;

        fn sorted_requests(requests: &VecDeque<EthWithdrawalRequest>) -> Vec<EthWithdrawalRequest> {
            let mut buf: Vec<_> = requests.iter().cloned().collect();
            buf.sort_unstable_by_key(|req| req.ledger_burn_index);
            buf
        }

        // We can reorder request in `reschedule_withdrawal_request`. The audit log won't
        // reflect this change, so we must sort the queues before comparing them.
        ensure_eq!(
            sorted_requests(&self.withdrawal_requests),
            sorted_requests(&other.withdrawal_requests)
        );
        ensure_eq!(self.created_tx, other.created_tx);
        ensure_eq!(self.sent_tx, other.sent_tx);
        ensure_eq!(self.finalized_tx, other.finalized_tx);
        ensure_eq!(self.next_nonce, other.next_nonce);

        ensure_eq!(self.maybe_reimburse, other.maybe_reimburse);
        ensure_eq!(self.reimbursement_requests, other.reimbursement_requests);
        ensure_eq!(self.reimbursed, other.reimbursed);

        Ok(())
    }

    pub fn oldest_incomplete_withdrawal_timestamp(&self) -> Option<u64> {
        self.withdrawal_requests
            .iter()
            .chain(self.maybe_reimburse.values())
            .flat_map(|req| req.created_at.into_iter())
            .min()
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
