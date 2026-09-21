//! How many pipeline ids one finalization round fetches transaction receipts for, and where in the
//! pending set the next round resumes.
//!
//! One receipt lookup is one HTTPS outcall per provider per replica, so a round fetching the whole
//! pending set at once fans out hardest exactly when that set is large — which is when receipts are
//! failing in the first place. The window bounds that fan-out and follows what the providers do
//! with it: it doubles while no lookup fails, halves when some do, and drops straight to its floor
//! when they all do, since a total failure is binary and shrinking gradually only spends more
//! doomed lookups on the way down.
//!
//! The window counts **ids**, not lookups: an id resubmitted at a higher gas price spans several
//! transaction hashes, and a round looks up every one of them, so a round of N ids makes N times
//! the variants per id lookups.
//!
//! The pending set is keyed by transaction hash, so its iteration order is arbitrary but stable.
//! Fetching its first ids every round would retry the same arbitrary subset forever, and anything
//! behind an id that cannot be finalized would never be attempted at all. The window therefore
//! carries a cursor over the ids and resumes past it, wrapping around, so the rounds together walk
//! the whole pending set.
//!
//! The window is soft state kept beside the event-sourced state: an upgrade resets it to
//! [`INITIAL_RECEIPT_FETCH_WINDOW`], which only means the round after the upgrade starts over from
//! the initial size and the first id.

#[cfg(test)]
mod tests;

use crate::eth_rpc::Hash;
use std::collections::BTreeMap;
use std::ops::Bound;

/// Ids a round fetches receipts for before any round has reported how the providers fared.
pub const INITIAL_RECEIPT_FETCH_WINDOW: usize = 10;

/// Smallest window: a round always attempts at least one id, so a pipeline whose providers are
/// broken keeps probing them, and recovers on its own once they answer again.
pub const MIN_RECEIPT_FETCH_WINDOW: usize = 1;

/// Largest window, capping the fan-out of a single round.
pub const MAX_RECEIPT_FETCH_WINDOW: usize = 20;

/// Consecutive rounds that could not make a single receipt lookup before rounds start being
/// skipped. A round reaches its lookups only once the sender's finalized transaction count came
/// back, and that read goes to the same providers: while it fails, no lookup is made, so no lookup
/// fails, so nothing shrinks the window and the round repeats at full cadence forever.
pub const ROUNDS_WITHOUT_READS_BEFORE_SKIPPING: u32 = 3;

/// Once rounds are being skipped, one round out of this many is still attempted, so a pipeline
/// whose providers recover picks up again without anything having to reset it.
pub const ROUNDS_PER_ATTEMPT_WHILE_SKIPPING: u32 = 4;

/// What one round's receipt lookups returned, as counted while their results are walked.
///
/// The distinction that matters to the window is between a lookup that failed at the provider level
/// and one that answered "not mined": the latter is the normal answer for a resubmission variant
/// that was superseded, and letting it shrink the window would collapse it to the floor on a
/// perfectly healthy minter.
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

    /// Counts an id none of whose transactions came back with a receipt, which stays pending for a
    /// later round.
    pub fn record_stalled_id(&mut self) {
        self.stalled_ids = self.stalled_ids.saturating_add(1);
    }

    /// Marks a round whose receipts cannot be used at all, because two different receipts named the
    /// same id. The window then shrinks to its floor: the round is a total loss, and repeating it at
    /// the same size would cost the same fan-out again.
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

    /// Lookups the round made, whatever they returned.
    pub fn lookups(&self) -> u32 {
        self.receipts
            .saturating_add(self.not_mined)
            .saturating_add(self.failures)
    }

    /// The window a round with this outcome leaves behind, given the window it ran with.
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

/// The ids one finalization round of a pipeline fetches receipts for, and how that round fared.
///
/// One window per pipeline, so a sweeper problem cannot throttle user withdrawals and vice versa.
#[derive(Clone, Copy, Eq, PartialEq, Debug)]
pub struct ReceiptFetchWindow<Id> {
    window: usize,
    cursor: Option<Id>,
    rounds_without_reads: u32,
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
            rounds_without_reads: 0,
            receipts_total: 0,
            not_mined_total: 0,
            failures_total: 0,
            stalled_ids_total: 0,
            abandoned_rounds_total: 0,
        }
    }
}

impl<Id: Copy + Ord> ReceiptFetchWindow<Id> {
    /// The transactions of the next [`Self::window`] ids of `pending`, resuming past the cursor and
    /// wrapping around, with the cursor left on the last id taken.
    ///
    /// Chunking by id rather than by the hashes `pending` is keyed by matters: a resubmitted
    /// withdrawal spans several hashes of which only one has a receipt, so slicing the hashes would
    /// split one id's variants across rounds and could fetch a round of nothing but superseded
    /// variants.
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

    /// Whether this round should skip its receipt fetch altogether. A skipped round reads nothing,
    /// so the caller records it as such, which is what makes the next attempt come round.
    ///
    /// Deliberately not a general backoff: it only keeps a pipeline that cannot even reach its
    /// receipt lookups — so has no failures to shrink its window with — from re-running at full
    /// cadence forever.
    pub fn should_skip_round(&self) -> bool {
        self.rounds_without_reads >= ROUNDS_WITHOUT_READS_BEFORE_SKIPPING
            && !(self.rounds_without_reads - ROUNDS_WITHOUT_READS_BEFORE_SKIPPING)
                .is_multiple_of(ROUNDS_PER_ATTEMPT_WHILE_SKIPPING)
    }

    /// Records a round that could not make a single receipt lookup, because the chain read the
    /// lookups depend on failed or because the round was skipped over. The window is left as it
    /// is: such a round observed nothing about how receipt lookups fare.
    pub fn record_round_without_reads(&mut self) {
        self.rounds_without_reads = self.rounds_without_reads.saturating_add(1);
    }

    /// Records how a round that reached its receipt lookups fared, adapting the window to it.
    ///
    /// A round that read the chain and found nothing to fetch — the ordinary state of a pipeline
    /// whose transactions are all still awaiting finality — reports an empty outcome: it leaves the
    /// window alone, but it is proof that the providers answered, so rounds stop being skipped.
    pub fn record_round(&mut self, outcome: RoundOutcome) {
        self.rounds_without_reads = 0;
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

    pub fn rounds_without_reads(&self) -> u32 {
        self.rounds_without_reads
    }

    /// What this pipeline's rounds have returned since the last upgrade, in a shape that does not
    /// name the pipeline's id type, so both pipelines report the same metrics.
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

/// What a pipeline's receipt lookups returned since the last upgrade. Reset on upgrade, so alerts
/// on them must be written against rates rather than absolute values.
#[derive(Clone, Copy, Eq, PartialEq, Debug, Default)]
pub struct ReceiptFetchCounters {
    /// Lookups that returned a receipt.
    pub receipts: u64,
    /// Lookups that answered that the transaction was not mined.
    pub not_mined: u64,
    /// Lookups that failed at the provider level.
    pub failures: u64,
    /// Ids that a round left pending because none of their transactions came back with a receipt.
    /// Counted once per round, so an id that cannot be finalized keeps adding to it.
    pub stalled_ids: u64,
    /// Rounds abandoned because two different receipts named the same id. No chain can produce
    /// that, so anything above zero is an invariant breach rather than an unhealthy provider.
    pub abandoned_rounds: u64,
}

/// The transactions of `pending` grouped by the id that sent them, so a round takes whole ids.
fn group_by_id<Id: Copy + Ord>(pending: &BTreeMap<Hash, Id>) -> BTreeMap<Id, Vec<Hash>> {
    let mut by_id: BTreeMap<Id, Vec<Hash>> = BTreeMap::new();
    for (hash, id) in pending {
        by_id.entry(*id).or_default().push(*hash);
    }
    by_id
}
