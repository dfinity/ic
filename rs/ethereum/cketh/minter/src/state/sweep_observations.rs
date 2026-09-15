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
use crate::balance_scan::batcher::Delegation;
use crate::deposit_address::DepositAddress;
use crate::timed_sized_map::Timestamp;
use ic_ethereum_types::Address;
use std::collections::BTreeMap;
use std::time::Duration;

#[derive(Clone, Copy, Eq, PartialEq, Debug, Default)]
pub struct SweepObservations {
    balance_scan_call_errors: u64,
    balance_scan_decode_errors: u64,
    last_completed_balance_scan: Option<Timestamp>,
    untracked_delegations: u64,
}

impl SweepObservations {
    /// Records the chunks of one balance-scan pass that did not come back, whether or not any
    /// other chunk of that pass did.
    pub fn record_balance_scan_errors(&mut self, errors: &ScanErrors) {
        self.balance_scan_call_errors = self.balance_scan_call_errors.saturating_add(errors.call);
        self.balance_scan_decode_errors = self
            .balance_scan_decode_errors
            .saturating_add(errors.decode);
    }

    /// Stamps a balance-scan pass that read balances off the chain, at the time it finished. Only
    /// such a pass moves the stamp: a pass with nothing due, or one whose every chunk failed, says
    /// nothing about how long ago the scan last worked.
    pub fn record_completed_balance_scan(&mut self, completed_at: Timestamp) {
        self.last_completed_balance_scan = Some(completed_at);
    }

    /// Records the addresses one delegation read found delegated to a contract other than
    /// `delegate`. Counted off the read's own map, whose keys are the distinct addresses the read
    /// asked about, so an address with several assets queued counts once per read rather than once
    /// per asset swept.
    pub fn record_delegation_read(
        &mut self,
        delegations: &BTreeMap<DepositAddress, Delegation>,
        delegate: Address,
    ) {
        let untracked = delegations
            .values()
            .filter(|delegation| match delegation {
                Delegation::Delegated(installed) => *installed != delegate,
                Delegation::NotDelegated | Delegation::Other => false,
            })
            .count() as u64;
        self.untracked_delegations = self.untracked_delegations.saturating_add(untracked);
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
