#[cfg(test)]
mod tests;

use crate::endpoints::DepositErc20Error;
use crate::numeric::{BlockNumber, Erc20Value};
use crate::state::event::{DepositAddressRegistration, DepositAddressRegistry, SweepQueueEntry};
use crate::timed_sized_map::{Entry, InsertError, TimedSizedMap, Timestamp};
use ic_ethereum_types::Address;
use icrc_ledger_types::icrc1::account::Account;
use std::collections::BTreeMap;
use std::num::NonZeroUsize;
use std::time::Duration;

/// Time window during which a registered ckERC20 deposit address is kept armed.
pub const DEPOSIT_ADDRESS_SCAN_WINDOW: Duration = Duration::from_secs(24 * 60 * 60);

/// Gaps in seconds between consecutive balance scans of a deposit address,
/// indexed by the number of scans already performed. The cadence bursts right
/// after registration, ramps up to five-minute gaps, then settles to hourly
/// scans until the 24h window closes. Once the schedule is exhausted the address
/// is no longer scanned (it expires at 24h anyway).
const SCAN_GAP_SECS: [u64; 33] = [
    // Burst then ramp: cumulative 1_800s (30min) over the first ten scans.
    30, 30, 60, 120, 120, 240, 300, 300, 300, 300,
    // Hourly tail up to the 24h window: 23 more scans of 3_600s (82_800s), for a
    // cumulative 84_600s (23.5h) including the burst/ramp above.
    3600, 3600, 3600, 3600, 3600, 3600, 3600, 3600, 3600, 3600, 3600, 3600, 3600, 3600, 3600, 3600,
    3600, 3600, 3600, 3600, 3600, 3600, 3600,
];

/// Approximate post-merge Ethereum block time, used to convert elapsed blocks
/// into elapsed seconds against [`SCAN_GAP_SECS`].
const SECS_PER_BLOCK: u64 = 12;

// Ethereum blocktime is 12s (on average), so that there are 7_200 blocks per day.
// Use 1 transaction per block to a minter-controlled address as a crude upper-bound.
const MAX_ACTIVE_DEPOSIT_ADDRESSES: NonZeroUsize = NonZeroUsize::new(7_000).unwrap();

/// Registry of minter-controlled ckERC20 deposit addresses, each derived
/// individually for a user's account. This in particular enables deposits from
/// central exchanges (CEX), which send from an address the user does not
/// control.
///
/// A `deposit_erc20` request arms the user-derived address by adding it to a
/// bounded, time-expiring watchlist. Scanning those addresses and minting the
/// corresponding ckERC20 is future work (DEFI-2927).
#[derive(Clone, PartialEq, Debug)]
pub struct AutomaticDeposits {
    watchlist: TimedSizedMap<Account, DepositRequest>,
    /// Funded deposit addresses moved out of the watchlist, awaiting sweeping,
    /// keyed per `(account, ERC-20 token contract)`.
    sweep: BTreeMap<(Account, Address), SweepEntry>,
}

impl AutomaticDeposits {
    /// Add the deposit `address` derived for `account` to the watchlist.
    ///
    /// Returns the watched address together with the timestamp until which a
    /// deposit to it is guaranteed to be noticed. Re-registering an account that
    /// is still armed returns the already-stored address and its original
    /// validity window without re-arming it, and fails with
    /// [`DepositErc20Error::TooManyActiveAddresses`] when the watchlist is full
    /// of live entries.
    pub fn watch_address_for_account(
        &mut self,
        now: Timestamp,
        account: Account,
        address: Address,
    ) -> Result<Entry<DepositRequest>, DepositErc20Error> {
        match self
            .watchlist
            .insert(now, account, DepositRequest::from(address))
        {
            Ok(_) | Err(InsertError::AlreadyPresent { .. }) => {
                let entry = self
                    .watchlist
                    .get_entry(now, &account)
                    .expect("BUG: the entry is live right after insert or AlreadyPresent");
                Ok(entry.clone())
            }
            Err(InsertError::AtCapacity { .. }) => Err(DepositErc20Error::TooManyActiveAddresses),
        }
    }

    /// Rebuild this state exactly from a registry previously produced by
    /// [`Self::snapshot`], replacing any existing content (both the watchlist and
    /// the sweep queue).
    ///
    /// The watchlist is restored verbatim under the limits recorded in the
    /// registry (`scan_window_nanos`, `capacity`), not the current code
    /// constants: entries keep their stored expiry (no clamping), expired
    /// entries are preserved (no eviction), and the entry count may exceed
    /// `capacity` (no admission check). This makes the restored state equal to
    /// the one that produced the registry, which the event-log equivalence
    /// check relies on. Changing the limits across versions is future work.
    pub fn rebuild(&mut self, registry: &DepositAddressRegistry) {
        let ttl = Duration::from_nanos(registry.scan_window_nanos);
        let capacity = NonZeroUsize::new(usize::try_from(registry.capacity).unwrap_or(usize::MAX))
            .expect("BUG: deposit address registry capacity must be non-zero");
        let entries = registry.registrations.iter().map(|deposit| {
            (
                Account {
                    owner: deposit.owner,
                    subaccount: deposit.subaccount,
                },
                Entry {
                    value: DepositRequest {
                        address: deposit.address,
                        last_scanned_block: deposit.last_scanned_block,
                        scan_count: deposit.scan_count,
                    },
                    expires_at: deposit.expires_at_nanos,
                },
            )
        });
        self.watchlist = TimedSizedMap::from_ordered_entries(ttl, capacity, entries);
        self.sweep = registry
            .sweep_queue
            .iter()
            .map(|entry| {
                (
                    (
                        Account {
                            owner: entry.owner,
                            subaccount: entry.subaccount,
                        },
                        entry.token,
                    ),
                    SweepEntry {
                        address: entry.address,
                        last_scanned_block: entry.last_scanned_block,
                        scan_count: entry.scan_count,
                        scanned_balance: entry.scanned_balance,
                    },
                )
            })
            .collect();
    }

    /// Iterate the live deposit addresses that are due for a balance scan as of the
    /// given latest block height, using elapsed blocks as a proxy for elapsed time
    /// against the backoff schedule. `now` filters expired entries.
    pub fn addresses_to_scan_iter(
        &self,
        now: Timestamp,
        latest_block: BlockNumber,
    ) -> impl Iterator<Item = (Account, Address)> + '_ {
        self.watchlist.iter().filter_map(move |(account, entry)| {
            if entry.expires_at < now {
                return None;
            }
            let request = &entry.value;
            let due = match request.last_scanned_block {
                None => true,
                Some(last_scanned_block) => {
                    let index = request.scan_count as usize;
                    index < SCAN_GAP_SECS.len() && {
                        let elapsed_blocks = latest_block
                            .checked_sub(last_scanned_block)
                            .unwrap_or(BlockNumber::ZERO);
                        let elapsed_secs = u64::try_from(elapsed_blocks.into_inner())
                            .unwrap_or(u64::MAX)
                            .saturating_mul(SECS_PER_BLOCK);
                        elapsed_secs >= SCAN_GAP_SECS[index]
                    }
                }
            };
            due.then_some((*account, request.address))
        })
    }

    /// The live watchlist entry for `account`, or `None` if the account is not
    /// currently armed (absent or expired as of `now`).
    pub fn get_entry(&self, now: Timestamp, account: &Account) -> Option<&Entry<DepositRequest>> {
        self.watchlist.get_entry(now, account)
    }

    /// Record that `account`'s deposit address was scanned at `block`, advancing it along the
    /// backoff schedule (`last_scanned_block = block`, `scan_count += 1`). No-op if the account is
    /// no longer live as of `now` (expired or evicted).
    pub fn record_scan(&mut self, now: Timestamp, account: &Account, block: BlockNumber) {
        if let Some(request) = self.watchlist.get_value_mut(now, account) {
            request.last_scanned_block = Some(block);
            request.scan_count = request.scan_count.saturating_add(1);
        }
    }

    /// Move `account`'s deposit address out of the watchlist into the sweep queue, recording one
    /// entry per `(token, balance)` candidate found at `block`. No-op if `account` is not live as
    /// of `now` or if `candidates` is empty.
    pub fn move_to_sweep(
        &mut self,
        now: Timestamp,
        account: &Account,
        block: BlockNumber,
        candidates: &[(Address, Erc20Value)],
    ) {
        if candidates.is_empty() || self.watchlist.get_entry(now, account).is_none() {
            return;
        }
        let removed = self
            .watchlist
            .remove(account)
            .expect("BUG: entry is live right after a successful get_entry")
            .value;
        let scan_count = removed.scan_count.saturating_add(1);
        for (token, balance) in candidates {
            self.sweep.insert(
                (*account, *token),
                SweepEntry {
                    address: removed.address,
                    last_scanned_block: block,
                    scan_count,
                    scanned_balance: *balance,
                },
            );
        }
    }

    /// Full snapshot of this state, faithful enough to reconstruct it exactly via
    /// [`Self::rebuild`]: it records the current limits, lists every watchlist
    /// entry (live and expired-but-unevicted) in time-index order, and lists the
    /// sweep queue in `(account, token)` order.
    pub fn snapshot(&self) -> DepositAddressRegistry {
        let registrations = self
            .watchlist
            .iter_by_expiry()
            .map(|(account, deposit)| DepositAddressRegistration {
                owner: account.owner,
                subaccount: account.subaccount,
                address: deposit.value.address,
                expires_at_nanos: deposit.expires_at,
                last_scanned_block: deposit.value.last_scanned_block,
                scan_count: deposit.value.scan_count,
            })
            .collect();
        let sweep_queue = self
            .sweep
            .iter()
            .map(|((account, token), entry)| SweepQueueEntry {
                owner: account.owner,
                subaccount: account.subaccount,
                token: *token,
                address: entry.address,
                last_scanned_block: entry.last_scanned_block,
                scan_count: entry.scan_count,
                scanned_balance: entry.scanned_balance,
            })
            .collect();
        DepositAddressRegistry {
            scan_window_nanos: u64::try_from(self.watchlist.ttl().as_nanos()).unwrap_or(u64::MAX),
            capacity: self.watchlist.capacity().get() as u64,
            registrations,
            sweep_queue,
        }
    }

    pub fn watchlist_len(&self) -> usize {
        self.watchlist.len()
    }

    pub fn sweep_len(&self) -> usize {
        self.sweep.len()
    }
}

impl Default for AutomaticDeposits {
    fn default() -> Self {
        Self {
            watchlist: TimedSizedMap::new(
                DEPOSIT_ADDRESS_SCAN_WINDOW,
                MAX_ACTIVE_DEPOSIT_ADDRESSES,
            ),
            sweep: BTreeMap::new(),
        }
    }
}

/// A funded deposit address moved out of the watchlist and awaiting sweeping, for
/// one supported ERC-20 token.
#[derive(Clone, Eq, PartialEq, Debug)]
pub struct SweepEntry {
    /// The deposit address (holder) the funds sit at.
    pub address: Address,
    /// The block whose scan found the funds.
    pub last_scanned_block: BlockNumber,
    /// How many times this address was scanned, including the finding scan.
    pub scan_count: u32,
    /// The balance read for this token at `last_scanned_block`.
    pub scanned_balance: Erc20Value,
}

#[derive(Clone, PartialEq, Debug)]
pub struct DepositRequest {
    pub address: Address,
    /// Latest block number at which this address's balance was scanned; None if never scanned.
    pub last_scanned_block: Option<BlockNumber>,
    /// How many times this address has been scanned (indexes the backoff schedule).
    pub scan_count: u32,
}

impl From<Address> for DepositRequest {
    fn from(address: Address) -> Self {
        Self {
            address,
            last_scanned_block: None,
            scan_count: 0,
        }
    }
}
