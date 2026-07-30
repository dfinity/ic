#[cfg(test)]
mod tests;

use crate::endpoints::DepositErc20Error;
use crate::numeric::{BlockNumber, Erc20Value};
use crate::state::event::{DepositAddressRegistration, DepositAddressRegistry, SweepMove};
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
    /// keyed per account and ERC-20 token contract.
    sweep: BTreeMap<SweepKey, SweepEntry>,
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

    /// Rebuild the watchlist exactly from a registry previously produced by
    /// [`Self::snapshot`], replacing any existing watchlist content.
    ///
    /// The watchlist is restored verbatim under the limits recorded in the
    /// registry (`scan_window_nanos`, `capacity`), not the current code
    /// constants: entries keep their stored expiry (no clamping), expired
    /// entries are preserved (no eviction), and the entry count may exceed
    /// `capacity` (no admission check). This makes the restored state equal to
    /// the one that produced the registry, which the event-log equivalence
    /// check relies on. Changing the limits across versions is future work.
    ///
    /// The sweep queue is deliberately left untouched: it is reconstructed from
    /// the mid-stream `MovedToSweepQueue` events that precede the final snapshot
    /// event in the log, so clearing it here would wipe them.
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
                    let index = (request.scan_count as usize).saturating_sub(1);
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

    /// Apply a [`SweepMove`]: drop the account's deposit address from the watchlist (if still
    /// present) and record the funded `(account, token)` in the sweep queue. Unconditional and
    /// idempotent per key, so replaying the event log reconstructs the queue. Removing the
    /// watchlist entry is a no-op on replay (the watchlist is only rebuilt by the final snapshot
    /// event), which is intended.
    pub fn apply_sweep_move(&mut self, mv: &SweepMove) {
        let account = Account {
            owner: mv.owner,
            subaccount: mv.subaccount,
        };
        self.watchlist.remove(&account);
        self.sweep.insert(
            SweepKey {
                account,
                token: mv.token,
            },
            SweepEntry {
                address: mv.address,
                last_scanned_block: mv.last_scanned_block,
                scan_count: mv.scan_count,
                scanned_balance: mv.scanned_balance,
            },
        );
    }

    /// Snapshot of the watchlist, faithful enough to reconstruct it exactly via
    /// [`Self::rebuild`]: it records the current limits and lists every watchlist
    /// entry (live and expired-but-unevicted) in time-index order. The sweep queue
    /// is not part of the snapshot; it is event-sourced via `MovedToSweepQueue`
    /// events.
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
        DepositAddressRegistry {
            scan_window_nanos: u64::try_from(self.watchlist.ttl().as_nanos()).unwrap_or(u64::MAX),
            capacity: self.watchlist.capacity().get() as u64,
            registrations,
        }
    }

    pub fn watchlist_len(&self) -> usize {
        self.watchlist.len()
    }

    pub fn sweep_len(&self) -> usize {
        self.sweep.len()
    }

    /// The sweep-queue entries for `account` (one per funded token), if any. Backs
    /// both the `deposit_erc20` response and the re-registration guard. Returns a
    /// public projection so [`SweepEntry`]/`SweepKey` stay private to this module.
    pub fn sweep_entries_for_account(&self, account: &Account) -> Vec<DetectedSweep> {
        self.sweep
            .iter()
            .filter(|(key, _)| key.account == *account)
            .map(|(key, entry)| DetectedSweep {
                token: key.token,
                address: entry.address,
                scanned_balance: entry.scanned_balance,
                last_scanned_block: entry.last_scanned_block,
            })
            .collect()
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

/// Key into the sweep queue: the user account together with the ERC-20 token
/// contract whose balance was found. Names the token address so it is not
/// conflated with the user-derived deposit address in [`SweepEntry`].
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Debug)]
struct SweepKey {
    account: Account,
    token: Address,
}

/// A funded token awaiting sweeping for a deposit address, as surfaced by
/// [`AutomaticDeposits::sweep_entries_for_account`]. Flattens the private
/// `SweepKey`/[`SweepEntry`] into the values callers need.
#[derive(Clone, Copy, Eq, PartialEq, Debug)]
pub struct DetectedSweep {
    /// The ERC-20 token contract whose balance was found.
    pub token: Address,
    /// The deposit address (holder) the funds sit at.
    pub address: Address,
    /// The balance read for `token` at `last_scanned_block`.
    pub scanned_balance: Erc20Value,
    /// The block whose scan found the funds.
    pub last_scanned_block: BlockNumber,
}

/// A funded deposit address moved out of the watchlist and awaiting sweeping, for
/// one supported ERC-20 token.
#[derive(Clone, PartialEq, Debug)]
struct SweepEntry {
    /// The deposit address (holder) the funds sit at.
    address: Address,
    /// The block whose scan found the funds.
    last_scanned_block: BlockNumber,
    /// How many times this address was scanned, including the finding scan.
    scan_count: u32,
    /// The balance read for this token at `last_scanned_block`.
    scanned_balance: Erc20Value,
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
