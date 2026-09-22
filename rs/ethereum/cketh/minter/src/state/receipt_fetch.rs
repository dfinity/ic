//! How many pipeline ids one finalization round fetches transaction receipts for, and where in the
//! pending set the next round resumes. Soft state, reset on upgrade.

#[cfg(test)]
mod tests;

use crate::eth_rpc::Hash;
use std::collections::BTreeMap;
use std::ops::Bound;

pub const INITIAL_RECEIPT_FETCH_WINDOW: usize = 10;
pub const MIN_RECEIPT_FETCH_WINDOW: usize = 1;
pub const MAX_RECEIPT_FETCH_WINDOW: usize = 20;
pub const ROUNDS_SINCE_CHAIN_READ_BEFORE_SKIPPING: u32 = 3;
/// One round out of this many is still attempted while rounds are being skipped.
pub const ROUNDS_PER_ATTEMPT_WHILE_SKIPPING: u32 = 4;

/// What one round's receipt lookups returned. Only provider-level failures shrink the window:
/// "not mined" is the ordinary answer for a superseded resubmission.
#[derive(Clone, Copy, Debug, Default)]
pub struct RoundOutcome {
    receipts: u32,
    not_mined: u32,
    failures: u32,
    stalled_ids: u32,
    abandoned: bool,
}

impl RoundOutcome {
    pub fn record_receipt(&mut self) {
        self.receipts = self.receipts.saturating_add(1);
    }

    pub fn record_not_mined(&mut self) {
        self.not_mined = self.not_mined.saturating_add(1);
    }

    pub fn record_failure(&mut self) {
        self.failures = self.failures.saturating_add(1);
    }

    pub fn record_stalled_id(&mut self) {
        self.stalled_ids = self.stalled_ids.saturating_add(1);
    }

    /// A flag rather than a count, so a round with several conflicting ids counts once.
    pub fn abandon(&mut self) {
        self.abandoned = true;
    }

    pub fn receipts(&self) -> u32 {
        self.receipts
    }

    pub fn not_mined(&self) -> u32 {
        self.not_mined
    }

    pub fn failures(&self) -> u32 {
        self.failures
    }

    pub fn stalled_ids(&self) -> u32 {
        self.stalled_ids
    }

    pub fn is_abandoned(&self) -> bool {
        self.abandoned
    }

    pub fn lookups(&self) -> u32 {
        self.receipts
            .saturating_add(self.not_mined)
            .saturating_add(self.failures)
    }

    fn next_window(&self, window: usize) -> usize {
        if self.abandoned || (self.lookups() > 0 && self.failures == self.lookups()) {
            return MIN_RECEIPT_FETCH_WINDOW;
        }
        if self.failures > 0 {
            return (window / 2).max(MIN_RECEIPT_FETCH_WINDOW);
        }
        window
            .saturating_mul(2)
            .clamp(MIN_RECEIPT_FETCH_WINDOW, MAX_RECEIPT_FETCH_WINDOW)
    }
}

/// One window per pipeline, so a sweeper problem cannot throttle user withdrawals.
#[derive(Clone, Copy, Eq, PartialEq, Debug)]
pub struct ReceiptFetchWindow<Id> {
    window: usize,
    cursor: Option<Id>,
    rounds_since_chain_read: u32,
    receipts_total: u64,
    not_mined_total: u64,
    failures_total: u64,
    stalled_ids_total: u64,
    abandoned_rounds_total: u64,
}

impl<Id> Default for ReceiptFetchWindow<Id> {
    fn default() -> Self {
        Self {
            window: INITIAL_RECEIPT_FETCH_WINDOW,
            cursor: None,
            rounds_since_chain_read: 0,
            receipts_total: 0,
            not_mined_total: 0,
            failures_total: 0,
            stalled_ids_total: 0,
            abandoned_rounds_total: 0,
        }
    }
}

impl<Id: Copy + Ord> ReceiptFetchWindow<Id> {
    /// Takes whole ids, resuming past the cursor and wrapping around. A resubmitted id spans
    /// several hashes of which only one has a receipt, so slicing the hash-keyed map would split it.
    pub fn select_next_round(&mut self, pending: &BTreeMap<Hash, Id>) -> BTreeMap<Hash, Id> {
        let by_id = group_by_id(pending);
        let ids = self.next_ids(&by_id);
        if let Some(last) = ids.last() {
            self.cursor = Some(*last);
        }
        ids.iter()
            .flat_map(|id| by_id[id].iter().map(move |hash| (*hash, *id)))
            .collect()
    }

    fn next_ids(&self, by_id: &BTreeMap<Id, Vec<Hash>>) -> Vec<Id> {
        let after_cursor = match self.cursor {
            Some(cursor) => Bound::Excluded(cursor),
            None => Bound::Unbounded,
        };
        by_id
            .range((after_cursor, Bound::Unbounded))
            .map(|(id, _hashes)| *id)
            .chain(by_id.keys().copied())
            .take(self.window.min(by_id.len()))
            .collect()
    }

    /// Deliberately not a general backoff: only a pipeline with no failure to shrink its window
    /// with skips rounds.
    pub fn should_skip_round(&self) -> bool {
        self.rounds_since_chain_read >= ROUNDS_SINCE_CHAIN_READ_BEFORE_SKIPPING
            && !(self.rounds_since_chain_read - ROUNDS_SINCE_CHAIN_READ_BEFORE_SKIPPING)
                .is_multiple_of(ROUNDS_PER_ATTEMPT_WHILE_SKIPPING)
    }

    pub fn record_round_without_chain_read(&mut self) {
        self.rounds_since_chain_read = self.rounds_since_chain_read.saturating_add(1);
    }

    /// An empty outcome still proves the providers answered, so rounds stop being skipped.
    pub fn record_round(&mut self, outcome: RoundOutcome) {
        self.rounds_since_chain_read = 0;
        if outcome.lookups() == 0 {
            return;
        }
        self.receipts_total = self
            .receipts_total
            .saturating_add(outcome.receipts() as u64);
        self.not_mined_total = self
            .not_mined_total
            .saturating_add(outcome.not_mined() as u64);
        self.failures_total = self
            .failures_total
            .saturating_add(outcome.failures() as u64);
        self.stalled_ids_total = self
            .stalled_ids_total
            .saturating_add(outcome.stalled_ids() as u64);
        if outcome.is_abandoned() {
            self.abandoned_rounds_total = self.abandoned_rounds_total.saturating_add(1);
        }
        self.window = outcome.next_window(self.window);
    }

    pub fn window(&self) -> usize {
        self.window
    }

    pub fn cursor(&self) -> Option<Id> {
        self.cursor
    }

    pub fn rounds_since_chain_read(&self) -> u32 {
        self.rounds_since_chain_read
    }

    pub fn counters(&self) -> ReceiptFetchCounters {
        ReceiptFetchCounters {
            receipts: self.receipts_total,
            not_mined: self.not_mined_total,
            failures: self.failures_total,
            stalled_ids: self.stalled_ids_total,
            abandoned_rounds: self.abandoned_rounds_total,
        }
    }
}

/// Reset on upgrade, so alerts on these must be written against rates.
#[derive(Clone, Copy, Eq, PartialEq, Debug, Default)]
pub struct ReceiptFetchCounters {
    pub receipts: u64,
    pub not_mined: u64,
    pub failures: u64,
    /// Counted once per round, so an id that cannot be finalized keeps adding to it.
    pub stalled_ids: u64,
    pub abandoned_rounds: u64,
}

fn group_by_id<Id: Copy + Ord>(pending: &BTreeMap<Hash, Id>) -> BTreeMap<Id, Vec<Hash>> {
    let mut by_id: BTreeMap<Id, Vec<Hash>> = BTreeMap::new();
    for (hash, id) in pending {
        by_id.entry(*id).or_default().push(*hash);
    }
    by_id
}
