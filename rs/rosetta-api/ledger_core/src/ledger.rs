use crate::{
    archive::ArchiveCanisterWasm,
    balances::{BalanceError, Balances, BalancesStore},
    block::{BlockHeight, BlockType, EncodedBlock, HashOf},
    blockchain::Blockchain,
    runtime::Runtime,
    timestamp::TimeStamp,
    tokens::Tokens,
};
use ic_base_types::CanisterId;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::time::Duration;

#[derive(Serialize, Deserialize, Debug)]
pub struct TransactionInfo<TransactionType> {
    pub block_timestamp: TimeStamp,
    pub transaction_hash: HashOf<TransactionType>,
}

pub trait LedgerTransaction: Sized {
    type AccountId: std::hash::Hash + Eq;

    /// Constructs a new "burn" transaction that removes the specified `amount` of tokens from the
    /// `from` account.
    fn burn(from: Self::AccountId, amount: Tokens, at: TimeStamp) -> Self;

    /// Returns the time at which the transaction was constructed.
    fn created_at_time(&self) -> TimeStamp;

    /// Returns the hash of this transaction.
    fn hash(&self) -> HashOf<Self>;

    /// Applies this transaction to the balance book.
    fn apply<S>(&self, balances: &mut Balances<Self::AccountId, S>) -> Result<(), BalanceError>
    where
        S: Default + BalancesStore<Self::AccountId>;
}

pub trait LedgerData {
    type AccountId: std::hash::Hash + Ord + Eq + Clone;
    type ArchiveWasm: ArchiveCanisterWasm;
    type Runtime: Runtime;
    type Block: BlockType<Transaction = Self::Transaction>;
    type Transaction: LedgerTransaction<AccountId = Self::AccountId> + Ord + Clone;

    // Purge configuration

    /// How long the ledger needs to remembered transactions to detect duplicates.
    fn transaction_window(&self) -> Duration;

    /// Maximum number of transactions that this ledger will accept
    /// within the [transaction_window].
    fn max_transactions_in_window(&self) -> usize;

    /// The maximum number of transactions that we attempt to purge in one go.
    fn max_transactions_to_purge(&self) -> usize;

    /// The maximum size of the balances map.
    fn max_number_of_accounts(&self) -> usize;

    /// How many accounts with lowest balances to purge when the number of accounts exceeds
    /// [LedgerData::max_number_of_accounts].
    fn accounts_overflow_trim_quantity(&self) -> usize;

    // Token configuration

    /// Token name (e.g., Bitcoin).
    fn token_name(&self) -> &str;

    /// Token symbol (e.g., BTC).
    fn token_symbol(&self) -> &str;

    // Ledger data structures

    fn balances(&self) -> &Balances<Self::AccountId, HashMap<Self::AccountId, Tokens>>;
    fn balances_mut(&mut self) -> &mut Balances<Self::AccountId, HashMap<Self::AccountId, Tokens>>;

    fn blockchain(&self) -> &Blockchain<Self::Runtime, Self::ArchiveWasm>;
    fn blockchain_mut(&mut self) -> &mut Blockchain<Self::Runtime, Self::ArchiveWasm>;

    fn transactions_by_hash(&self) -> &BTreeMap<HashOf<Self::Transaction>, BlockHeight>;
    fn transactions_by_hash_mut(&mut self)
        -> &mut BTreeMap<HashOf<Self::Transaction>, BlockHeight>;

    fn transactions_by_height(&self) -> &VecDeque<TransactionInfo<Self::Transaction>>;
    fn transactions_by_height_mut(&mut self) -> &mut VecDeque<TransactionInfo<Self::Transaction>>;

    /// The callback that the ledger framework calls when it purges a transaction.
    fn on_purged_transaction(&mut self, height: BlockHeight);
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub enum TransferError {
    BadFee { expected_fee: Tokens },
    InsufficientFunds { balance: Tokens },
    TxTooOld { allowed_window_nanos: u64 },
    TxCreatedInFuture,
    TxThrottled,
    TxDuplicate { duplicate_of: BlockHeight },
}

/// Adds a new block with the specified transaction to the ledger.
pub fn apply_transaction<L: LedgerData>(
    ledger: &mut L,
    transaction: L::Transaction,
    now: TimeStamp,
) -> Result<(BlockHeight, HashOf<EncodedBlock>), TransferError> {
    let num_pruned = purge_old_transactions(ledger, now);

    let created_at_time = transaction.created_at_time();

    if created_at_time + ledger.transaction_window() < now {
        return Err(TransferError::TxTooOld {
            allowed_window_nanos: ledger.transaction_window().as_nanos() as u64,
        });
    }

    if created_at_time > now + ic_constants::PERMITTED_DRIFT {
        return Err(TransferError::TxCreatedInFuture);
    }

    // If we pruned some transactions, let this one through
    // otherwise throttle if there are too many
    if num_pruned == 0 && throttle(ledger, now) {
        return Err(TransferError::TxThrottled);
    }

    let transaction_hash = transaction.hash();

    if let Some(block_height) = ledger.transactions_by_hash().get(&transaction_hash) {
        return Err(TransferError::TxDuplicate {
            duplicate_of: *block_height,
        });
    }

    transaction
        .apply(ledger.balances_mut())
        .map_err(|e| match e {
            BalanceError::InsufficientFunds { balance } => {
                TransferError::InsufficientFunds { balance }
            }
        })?;

    let block = L::Block::from_transaction(ledger.blockchain().last_hash, transaction, now);
    let block_timestamp = block.timestamp();

    let height = ledger
        .blockchain_mut()
        .add_block(block)
        .expect("failed to add block");

    ledger
        .transactions_by_hash_mut()
        .insert(transaction_hash, height);

    ledger
        .transactions_by_height_mut()
        .push_back(TransactionInfo {
            block_timestamp,
            transaction_hash,
        });

    let to_trim = if ledger.balances().store.len()
        >= ledger.max_number_of_accounts() + ledger.accounts_overflow_trim_quantity()
    {
        select_accounts_to_trim(ledger)
    } else {
        vec![]
    };

    for (balance, account) in to_trim {
        let burn_tx = L::Transaction::burn(account, balance, now);

        burn_tx
            .apply(ledger.balances_mut())
            .expect("failed to burn funds that must have existed");

        let parent_hash = ledger.blockchain().last_hash;

        ledger
            .blockchain_mut()
            .add_block(L::Block::from_transaction(parent_hash, burn_tx, now))
            .unwrap();
    }

    Ok((height, ledger.blockchain().last_hash.unwrap()))
}

/// Finds the archive canister that contains the block with the specified height.
pub fn find_block_in_archive<L: LedgerData>(ledger: &L, block_height: u64) -> Option<CanisterId> {
    let index = ledger
        .blockchain()
        .archive
        .try_read()
        .expect("Failed to get lock on archive")
        .as_ref()
        .expect("archiving not enabled")
        .index();

    let result = index.binary_search_by(|((from, to), _)| {
        // If within the range we've found the right node
        if *from <= block_height && block_height <= *to {
            std::cmp::Ordering::Equal
        } else if *from < block_height {
            std::cmp::Ordering::Less
        } else {
            std::cmp::Ordering::Greater
        }
    });

    match result {
        Ok(i) => Some(index[i].1),
        Err(_) => None,
    }
}

/// Returns true if the next transaction should be throttled due to high
/// load on the ledger.
fn throttle<L: LedgerData>(ledger: &L, now: TimeStamp) -> bool {
    let num_in_window = ledger.transactions_by_height().len();
    // We admit the first half of max_transactions_in_window freely.
    // After that we start throttling on per-second basis.
    // This way we guarantee that at most max_transactions_in_window will
    // get through within the transaction window.
    if num_in_window >= ledger.max_transactions_in_window() / 2 {
        // max num of transactions allowed per second
        let max_rate = (0.5 * ledger.max_transactions_in_window() as f64
            / ledger.transaction_window().as_secs_f64())
        .ceil() as usize;

        if ledger
            .transactions_by_height()
            .get(num_in_window.saturating_sub(max_rate))
            .map(|tx| tx.block_timestamp)
            .unwrap_or_else(|| TimeStamp::from_nanos_since_unix_epoch(0))
            + Duration::from_secs(1)
            > now
        {
            return true;
        }
    }
    false
}

/// Removes at most [LedgerData::max_transactions_to_purge] transactions older
/// than `now - Ledger::transaction_window` and returns the number of purged
/// transactions.
pub fn purge_old_transactions<L: LedgerData>(ledger: &mut L, now: TimeStamp) -> usize {
    let max_tx_to_purge = ledger.max_transactions_to_purge();
    let mut num_tx_purged = 0usize;

    while let Some(tx_info) = ledger.transactions_by_height().front() {
        if tx_info.block_timestamp + ledger.transaction_window() + ic_constants::PERMITTED_DRIFT
            >= now
        {
            // Stop at a sufficiently recent block.
            break;
        }

        let transaction_hash = tx_info.transaction_hash;

        match ledger.transactions_by_hash_mut().remove(&transaction_hash) {
            None => unreachable!(
                concat!(
                    "invariant violation: transaction with hash {} ",
                    "is in transaction_by_height but not in transactions_by_hash"
                ),
                transaction_hash
            ),
            Some(block_height) => ledger.on_purged_transaction(block_height),
        }

        ledger.transactions_by_height_mut().pop_front();

        num_tx_purged += 1;
        if num_tx_purged >= max_tx_to_purge {
            break;
        }
    }
    num_tx_purged
}

// Find the specified number of accounts with lowest balances so that their
// balances can be reclaimed.
fn select_accounts_to_trim<L: LedgerData>(ledger: &L) -> Vec<(Tokens, L::AccountId)> {
    let mut to_trim: std::collections::BinaryHeap<(Tokens, L::AccountId)> =
        std::collections::BinaryHeap::new();

    let num_accounts = ledger.accounts_overflow_trim_quantity();
    let mut iter = ledger.balances().store.iter();

    // Accumulate up to `trim_quantity` accounts
    for (account, balance) in iter.by_ref().take(num_accounts) {
        to_trim.push((*balance, account.clone()));
    }

    for (account, balance) in iter {
        // If any account's balance is lower than the maximum in our set,
        // include that account, and remove the current maximum
        if let Some((greatest_balance, _)) = to_trim.peek() {
            if balance < greatest_balance {
                to_trim.push((*balance, account.clone()));
                to_trim.pop();
            }
        }
    }

    to_trim.into_vec()
}
