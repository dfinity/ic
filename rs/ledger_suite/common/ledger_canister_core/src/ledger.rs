use crate::{
    archive::ArchiveCanisterWasm,
    blockchain::{BlockDataContainer, Blockchain},
    range_utils,
    runtime::Runtime,
};
use ic_base_types::CanisterId;
use ic_canister_log::{Sink, log};
use ic_ledger_core::approvals::{
    AllowanceTable, AllowancesData, ApproveError, InsufficientAllowance,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, VecDeque};
use std::ops::Range;
use std::time::Duration;

use crate::archive::{ArchivingGuardError, FailedToArchiveBlocks, LedgerArchivingGuard};
use ic_ledger_core::balances::{BalanceError, Balances, BalancesStore};
use ic_ledger_core::block::{BlockIndex, BlockType, EncodedBlock, FeeCollector};
use ic_ledger_core::timestamp::TimeStamp;
use ic_ledger_core::tokens::{TokensType, Zero};
use ic_ledger_hash_of::HashOf;

#[derive(Debug, Deserialize, Serialize)]
pub struct TransactionInfo<TransactionType> {
    pub block_timestamp: TimeStamp,
    pub transaction_hash: HashOf<TransactionType>,
}

#[derive(Eq, PartialEq, Debug)]
pub enum TxApplyError<Tokens> {
    InsufficientFunds { balance: Tokens },
    InsufficientAllowance { allowance: Tokens },
    ExpiredApproval { now: TimeStamp },
    AllowanceChanged { current_allowance: Tokens },
    SelfApproval,
    BurnOrMintFee,
}

impl<Tokens> From<BalanceError<Tokens>> for TxApplyError<Tokens> {
    fn from(e: BalanceError<Tokens>) -> Self {
        match e {
            BalanceError::InsufficientFunds { balance } => Self::InsufficientFunds { balance },
        }
    }
}

impl<Tokens> From<InsufficientAllowance<Tokens>> for TxApplyError<Tokens> {
    fn from(e: InsufficientAllowance<Tokens>) -> Self {
        Self::InsufficientAllowance { allowance: e.0 }
    }
}

impl<Tokens> From<ApproveError<Tokens>> for TxApplyError<Tokens> {
    fn from(ae: ApproveError<Tokens>) -> Self {
        match ae {
            ApproveError::ExpiredApproval { now } => Self::ExpiredApproval { now },
            ApproveError::AllowanceChanged { current_allowance } => {
                Self::AllowanceChanged { current_allowance }
            }
            ApproveError::SelfApproval => Self::SelfApproval,
        }
    }
}

pub trait LedgerContext {
    type AccountId: std::hash::Hash + Ord + Eq + Clone;
    type BalancesStore: BalancesStore<AccountId = Self::AccountId, Tokens = Self::Tokens> + Default;
    type AllowancesData: AllowancesData<AccountId = Self::AccountId, Tokens = Self::Tokens>
        + Default;
    type Tokens: TokensType;

    fn balances(&self) -> &Balances<Self::BalancesStore>;
    fn balances_mut(&mut self) -> &mut Balances<Self::BalancesStore>;

    fn approvals(&self) -> &AllowanceTable<Self::AllowancesData>;
    fn approvals_mut(&mut self) -> &mut AllowanceTable<Self::AllowancesData>;

    fn fee_collector(&self) -> Option<&FeeCollector<Self::AccountId>>;
}

pub trait LedgerTransaction: Sized {
    type AccountId: Clone;
    type Tokens: TokensType;

    /// Constructs a new "burn" transaction that removes the specified `amount` of tokens from the
    /// `from` account.
    fn burn(
        from: Self::AccountId,
        spender: Option<Self::AccountId>,
        amount: Self::Tokens,
        at: Option<TimeStamp>,
        memo: Option<u64>,
    ) -> Self;

    fn approve(
        from: Self::AccountId,
        spender: Self::AccountId,
        amount: Self::Tokens,
        at: Option<TimeStamp>,
        memo: Option<u64>,
    ) -> Self;

    /// Returns the time at which the transaction was constructed.
    fn created_at_time(&self) -> Option<TimeStamp>;

    /// Returns the hash of this transaction.
    fn hash(&self) -> HashOf<Self>;

    /// Applies this transaction to the balance book.
    fn apply<C>(
        &self,
        context: &mut C,
        now: TimeStamp,
        effective_fee: Self::Tokens,
    ) -> Result<(), TxApplyError<Self::Tokens>>
    where
        C: LedgerContext<AccountId = Self::AccountId, Tokens = Self::Tokens>;
}

pub trait LedgerAccess {
    type Ledger: LedgerData;

    /// Executes a function on a ledger reference.
    ///
    /// # Panics
    ///
    /// Panics if `f` tries to call `with_ledger` or `with_ledger_mut` recursively.
    fn with_ledger<R>(f: impl FnOnce(&Self::Ledger) -> R) -> R;

    /// Executes a function on a mutable ledger reference.
    ///
    /// # Panics
    ///
    /// Panics if `f` tries to call `with_ledger` or `with_ledger_mut` recursively.
    fn with_ledger_mut<R>(f: impl FnOnce(&mut Self::Ledger) -> R) -> R;
}

pub trait LedgerData: LedgerContext {
    type ArchiveWasm: ArchiveCanisterWasm;
    type Runtime: Runtime;
    type Block: BlockType<
            Transaction = Self::Transaction,
            AccountId = Self::AccountId,
            Tokens = Self::Tokens,
        >;
    type Transaction: LedgerTransaction<AccountId = Self::AccountId, Tokens = Self::Tokens>
        + Ord
        + Clone;
    type BlockDataContainer: BlockDataContainer + Default;

    // Purge configuration

    /// How long the ledger needs to remembered transactions to detect duplicates.
    fn transaction_window(&self) -> Duration;

    /// Maximum number of transactions that this ledger will accept
    /// within the [transaction_window].
    fn max_transactions_in_window(&self) -> usize;

    /// The maximum number of transactions that we attempt to purge in one go.
    fn max_transactions_to_purge(&self) -> usize;

    // Token configuration

    /// Token name (e.g., Bitcoin).
    fn token_name(&self) -> &str;

    /// Token symbol (e.g., BTC).
    fn token_symbol(&self) -> &str;

    // Ledger data structures

    fn blockchain(&self)
    -> &Blockchain<Self::Runtime, Self::ArchiveWasm, Self::BlockDataContainer>;
    fn blockchain_mut(
        &mut self,
    ) -> &mut Blockchain<Self::Runtime, Self::ArchiveWasm, Self::BlockDataContainer>;

    fn transactions_by_hash(&self) -> &BTreeMap<HashOf<Self::Transaction>, BlockIndex>;
    fn transactions_by_hash_mut(&mut self) -> &mut BTreeMap<HashOf<Self::Transaction>, BlockIndex>;

    fn transactions_by_height(&self) -> &VecDeque<TransactionInfo<Self::Transaction>>;
    fn transactions_by_height_mut(&mut self) -> &mut VecDeque<TransactionInfo<Self::Transaction>>;

    /// The callback that the ledger framework calls when it purges a transaction.
    fn on_purged_transaction(&mut self, height: BlockIndex);

    fn fee_collector_mut(&mut self) -> Option<&mut FeeCollector<Self::AccountId>>;

    fn increment_archiving_failure_metric(&mut self);

    fn get_archiving_failure_metric(&self) -> u64;
}

#[derive(Clone, Eq, PartialEq, Debug, Deserialize, Serialize)]
pub enum TransferError<Tokens> {
    BadFee { expected_fee: Tokens },
    BadBurn { min_burn_amount: Tokens },
    InsufficientFunds { balance: Tokens },
    InsufficientAllowance { allowance: Tokens },
    ExpiredApproval { ledger_time: TimeStamp },
    TxTooOld { allowed_window_nanos: u64 },
    TxCreatedInFuture { ledger_time: TimeStamp },
    TxThrottled,
    TxDuplicate { duplicate_of: BlockIndex },
    AllowanceChanged { current_allowance: Tokens },
    SelfApproval,
}

const APPROVE_PRUNE_LIMIT: usize = 100;

/// Adds a new block with the specified transaction to the ledger.
pub fn apply_transaction<L>(
    ledger: &mut L,
    transaction: L::Transaction,
    now: TimeStamp,
    effective_fee: L::Tokens,
) -> Result<(BlockIndex, HashOf<EncodedBlock>), TransferError<L::Tokens>>
where
    L: LedgerData,
{
    let num_pruned = purge_old_transactions(ledger, now);

    // If we pruned some transactions, let this one through
    // otherwise throttle if there are too many
    if num_pruned == 0 && throttle(ledger, now) {
        return Err(TransferError::TxThrottled);
    }

    ledger.approvals_mut().prune(now, APPROVE_PRUNE_LIMIT);

    let maybe_time_and_hash = transaction
        .created_at_time()
        .map(|created_at_time| (created_at_time, transaction.hash()));

    if let Some((created_at_time, tx_hash)) = maybe_time_and_hash {
        // The caller requested deduplication.
        if created_at_time + ledger.transaction_window() < now {
            return Err(TransferError::TxTooOld {
                allowed_window_nanos: ledger.transaction_window().as_nanos() as u64,
            });
        }

        if created_at_time > now + ic_limits::PERMITTED_DRIFT {
            return Err(TransferError::TxCreatedInFuture { ledger_time: now });
        }

        if let Some(block_height) = ledger.transactions_by_hash().get(&tx_hash) {
            return Err(TransferError::TxDuplicate {
                duplicate_of: *block_height,
            });
        }
    }

    transaction
        .apply(ledger, now, effective_fee.clone())
        .map_err(|e| match e {
            TxApplyError::InsufficientFunds { balance } => {
                TransferError::InsufficientFunds { balance }
            }
            TxApplyError::InsufficientAllowance { allowance } => {
                TransferError::InsufficientAllowance { allowance }
            }
            TxApplyError::ExpiredApproval { now } => {
                TransferError::ExpiredApproval { ledger_time: now }
            }
            TxApplyError::AllowanceChanged { current_allowance } => {
                TransferError::AllowanceChanged { current_allowance }
            }
            TxApplyError::SelfApproval => TransferError::SelfApproval,
            TxApplyError::BurnOrMintFee => TransferError::BadFee {
                expected_fee: L::Tokens::zero(),
            },
        })?;

    let fee_collector = ledger.fee_collector().cloned();
    let block = L::Block::from_transaction(
        ledger.blockchain().last_hash,
        transaction,
        now,
        effective_fee,
        fee_collector,
    );
    let block_timestamp = block.timestamp();

    let height = ledger
        .blockchain_mut()
        .add_block(block)
        .expect("failed to add block");
    if let Some(fee_collector) = ledger.fee_collector_mut().as_mut()
        && fee_collector.block_index.is_none()
    {
        fee_collector.block_index = Some(height);
    }

    if let Some((_, tx_hash)) = maybe_time_and_hash {
        // The caller requested deduplication, so we have to remember this
        // transaction within the dedup window.
        ledger.transactions_by_hash_mut().insert(tx_hash, height);

        ledger
            .transactions_by_height_mut()
            .push_back(TransactionInfo {
                block_timestamp,
                transaction_hash: tx_hash,
            });
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
        if tx_info.block_timestamp + ledger.transaction_window() + ic_limits::PERMITTED_DRIFT >= now
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

/// Asynchronously archives a suffix of the locally available blockchain.
///
/// NOTE: only one archiving task can run at each point in time.
/// If archiving is already in process, this function returns immediately.
pub async fn archive_blocks<LA: LedgerAccess>(sink: impl Sink + Clone, max_message_size: u64) {
    use crate::archive::{ArchivingGuardError, send_blocks_to_archive};

    let archive_arc = LA::with_ledger(|ledger| ledger.blockchain().archive.clone());

    // NOTE: this guard will prevent another logical thread to start the archiving process.
    let (archiving_guard, blocks_to_archive) = match blocks_to_archive::<LA>(&sink) {
        Ok((guard, blocks)) => (guard, blocks),
        Err(ArchivingGuardError::NoArchive) => {
            return; // Archiving not enabled
        }
        Err(ArchivingGuardError::AlreadyArchiving) => {
            return; // Ledger is currently archiving, skipping archive_blocks.
        }
    };

    if blocks_to_archive.is_empty() {
        return;
    }

    let num_blocks = blocks_to_archive.len();

    let result = send_blocks_to_archive(
        sink.clone(),
        archive_arc,
        blocks_to_archive,
        max_message_size,
    )
    .await;

    if result.is_err() {
        LA::with_ledger_mut(|ledger| ledger.increment_archiving_failure_metric());
    }

    remove_archived_blocks::<LA>(archiving_guard, num_blocks, &sink, result)
}

// The maximum blocks to archive at once. Note that chunking may still split up the blocks that are
// being archived into multiple messages to the archive canister.
pub const MAX_BLOCKS_TO_ARCHIVE: usize = 18_000;

pub fn blocks_to_archive<LA: LedgerAccess>(
    sink: &impl Sink,
) -> Result<(LedgerArchivingGuard<LA>, VecDeque<EncodedBlock>), ArchivingGuardError> {
    // NOTE: this guard will prevent another logical thread to start the archiving process.
    let archiving_guard = LedgerArchivingGuard::new()?;

    let blocks_to_archive = LA::with_ledger(|ledger| {
        let archive_guard = ledger.blockchain().archive.read().unwrap();
        let archive = archive_guard.as_ref().unwrap();
        ledger.blockchain().get_blocks_for_archiving(
            archive.trigger_threshold,
            archive.num_blocks_to_archive.min(MAX_BLOCKS_TO_ARCHIVE),
        )
    });
    if !blocks_to_archive.is_empty() {
        log!(
            sink,
            "[ledger] archiving {} blocks",
            blocks_to_archive.len()
        );
    }
    Ok((archiving_guard, blocks_to_archive))
}

pub fn remove_archived_blocks<LA: LedgerAccess>(
    _archiving_guard: LedgerArchivingGuard<LA>,
    expected_num_blocks: usize,
    sink: &impl Sink,
    result: Result<usize, (usize, FailedToArchiveBlocks)>,
) {
    LA::with_ledger_mut(|ledger| match result {
        Ok(num_sent_blocks) => ledger
            .blockchain_mut()
            .remove_archived_blocks(num_sent_blocks),
        Err((num_sent_blocks, FailedToArchiveBlocks(err))) => {
            ledger
                .blockchain_mut()
                .remove_archived_blocks(num_sent_blocks);
            log!(
                sink,
                "[ledger] archived only {} out of {} blocks; error: {}",
                num_sent_blocks,
                expected_num_blocks,
                err
            );
        }
    });
}

/// The distribution of a block range across canisters.
pub struct BlockLocations {
    /// Blocks currently owned by the main ledger canister.
    pub local_blocks: Range<u64>,
    /// Blocks stored in the archive canisters.
    pub archived_blocks: Vec<(CanisterId, Range<u64>)>,
}

/// Returns the locations of the specified block range.
pub fn block_locations<L: LedgerData>(ledger: &L, start: u64, length: usize) -> BlockLocations {
    let requested_range = range_utils::make_range(start, length);
    let local_range = ledger.blockchain().local_block_range();
    let local_blocks = range_utils::intersect(&requested_range, &local_range)
        .unwrap_or_else(|_| range_utils::make_range(local_range.start, 0));

    let archive = ledger.blockchain().archive.read().unwrap();

    // Collect the ranges of blocks stored in the archive canisters. The archives are sorted, so
    // that the oldest archive (with the lowest block IDs) is first, and the newest archive (with
    // the highest block IDs) is last. Iterate over the archives in reverse order since we are
    // removing overlapping suffixes from the ranges, starting from the latest blocks stored in the
    // ledger.
    let mut later_range = None;
    let archived_blocks: Vec<_> = archive
        .iter()
        .flat_map(|archive| archive.index().into_iter())
        .rev()
        .filter_map(|((from, to), canister_id)| {
            let mut slice = range_utils::intersect(&(from..to + 1), &requested_range).ok()?;
            if !slice.is_empty() {
                match &later_range {
                    None => {
                        // Remove the intersection of the local block range from the current range.
                        range_utils::remove_suffix(&mut slice, &local_blocks);
                    }
                    Some(later_range) => {
                        // Remove the intersection of the previous archive range from the current range.
                        range_utils::remove_suffix(&mut slice, later_range);
                    }
                }
                later_range = Some(slice.clone());
            }
            (!slice.is_empty()).then_some((canister_id, slice))
        })
        .collect();
    // Reverse the order of the archived blocks to return the oldest archive first.
    let archived_blocks: Vec<_> = archived_blocks.into_iter().rev().collect();

    debug_assert!(
        !range_utils::contains_intersections(
            [
                [&local_blocks].as_slice(),
                archived_blocks
                    .iter()
                    .map(|(_canister_id, archived_blocks_range)| archived_blocks_range)
                    .collect::<Vec<_>>()
                    .as_slice()
            ]
            .concat()
            .as_slice()
        ),
        "overlapping block ranges - local_blocks: {local_blocks:?}, archived_blocks: {archived_blocks:?}"
    );

    BlockLocations {
        local_blocks,
        archived_blocks,
    }
}
