//! What the balance scan's chain reads looked like, as opposed to what the minter decided from
//! them. A failed `eth_call` or a batch that would not decode leaves no trace in the event log —
//! nothing was decided — yet each is exactly what an operator needs to see before the queue stops
//! draining.
//!
//! These counters are therefore kept beside the event-sourced state and start afresh after an
//! upgrade, so alerts on them must be written against rates rather than absolute values.

use crate::balance_scan::ScanErrors;
use crate::timed_sized_map::Timestamp;
use std::time::Duration;

#[derive(Clone, Copy, Eq, PartialEq, Debug, Default)]
pub struct SweepObservations {
    balance_scan_call_errors: u64,
    balance_scan_decode_errors: u64,
    balance_scan_fresh_since: Option<Timestamp>,
}

impl SweepObservations {
    /// The observations of a minter starting at `now`: nothing seen yet, and the balance scan
    /// counted as fresh from the start, so that its age grows from there until a pass completes.
    pub fn started_at(now: Timestamp) -> Self {
        Self {
            balance_scan_fresh_since: Some(now),
            ..Self::default()
        }
    }

    /// Records the chunks of one balance-scan pass that did not come back, whether or not any
    /// other chunk of that pass did.
    pub fn record_balance_scan_errors(&mut self, ScanErrors { call, decode }: ScanErrors) {
        self.balance_scan_call_errors = self.balance_scan_call_errors.saturating_add(call);
        self.balance_scan_decode_errors = self.balance_scan_decode_errors.saturating_add(decode);
    }

    /// Stamps a balance-scan pass that read balances off the chain, at the time the scan tick
    /// started. Only such a pass moves the stamp: a pass with nothing due, or one whose every chunk
    /// failed, says nothing about how long ago the scan last worked.
    pub fn record_completed_balance_scan(&mut self, started_at: Timestamp) {
        self.balance_scan_fresh_since = Some(started_at);
    }

    pub fn balance_scan_call_errors(&self) -> u64 {
        self.balance_scan_call_errors
    }

    pub fn balance_scan_decode_errors(&self) -> u64 {
        self.balance_scan_decode_errors
    }

    /// How long ago the last balance scan completed, counted from the minter's start while none
    /// has completed since, or `None` for a minter that never started. A stamp in the future (the
    /// clock moved back) reads as zero rather than wrapping.
    pub fn last_balance_scan_age(&self, now: Timestamp) -> Option<Duration> {
        self.balance_scan_fresh_since.map(|fresh_since| {
            Duration::from_nanos(now.as_nanos().saturating_sub(fresh_since.as_nanos()))
        })
    }
}
