//! What the sweep pipeline's chain reads looked like, as opposed to what the minter decided from
//! them. A failed `eth_call`, a batch that would not decode, or a deposit address someone else
//! delegated leaves no trace in the event log — nothing was decided — yet each is exactly what an
//! operator needs to see before the queue stops draining.
//!
//! These counters are therefore kept beside the event-sourced state and start afresh after an
//! upgrade, so alerts on them must be written against rates rather than absolute values.

#[cfg(test)]
mod tests;

use crate::balance_scan::ScanErrors;
use crate::timed_sized_map::Timestamp;
use std::time::Duration;

#[derive(Clone, Copy, Eq, PartialEq, Debug, Default)]
pub struct SweepObservations {
    balance_scan_call_errors: u64,
    balance_scan_decode_errors: u64,
    last_completed_balance_scan: Option<Timestamp>,
    untracked_delegations: u64,
}

impl SweepObservations {
    /// Records one completed pass of the balance scan: when it finished, and how many of its chunks
    /// did not come back. A pass that read nothing still counts as completed — the scan ran, so the
    /// staleness this stamps clears.
    pub fn record_balance_scan_pass(&mut self, now: Timestamp, errors: &ScanErrors) {
        self.balance_scan_call_errors = self.balance_scan_call_errors.saturating_add(errors.call);
        self.balance_scan_decode_errors = self
            .balance_scan_decode_errors
            .saturating_add(errors.decode);
        self.last_completed_balance_scan = Some(now);
    }

    pub fn record_untracked_delegations(&mut self, count: u64) {
        self.untracked_delegations = self.untracked_delegations.saturating_add(count);
    }

    pub fn balance_scan_call_errors(&self) -> u64 {
        self.balance_scan_call_errors
    }

    pub fn balance_scan_decode_errors(&self) -> u64 {
        self.balance_scan_decode_errors
    }

    pub fn untracked_delegations(&self) -> u64 {
        self.untracked_delegations
    }

    /// How long ago the last balance scan completed, or `None` when none has completed since the
    /// minter last started. A scan stamped in the future (the clock moved back) reads as zero
    /// rather than wrapping.
    pub fn last_balance_scan_age(&self, now: Timestamp) -> Option<Duration> {
        self.last_completed_balance_scan.map(|scanned_at| {
            Duration::from_nanos(now.as_nanos().saturating_sub(scanned_at.as_nanos()))
        })
    }
}
