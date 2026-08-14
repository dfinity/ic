#[cfg(test)]
mod tests;

use crate::endpoints::{DepositErc20Error, DepositErc20Response, DepositStatus, DetectedDeposit};
use crate::numeric::{BlockNumber, Erc20Value};
use crate::state::event::{AutomaticDeposit, DepositAddressRegistration, DepositAddressRegistry};
use crate::timed_sized_map::{Entry, InsertError, TimedSizedMap, Timestamp};
use ic_ethereum_types::Address;
use icrc_ledger_types::icrc1::account::Account;
use std::collections::BTreeMap;
use std::num::NonZeroUsize;
use std::time::Duration;

/// Time window during which a registered ckERC20 deposit is kept armed.
pub const DEPOSIT_ADDRESS_SCAN_WINDOW: Duration = Duration::from_secs(24 * 60 * 60);

/// Gaps in seconds between consecutive balance scans of a deposit, indexed by the
/// number of scans already performed. The cadence bursts right after registration,
/// ramps up to five-minute gaps, then settles to hourly scans until the 24h window
/// closes. Once the schedule is exhausted the deposit is no longer scanned (it
/// expires at 24h anyway).
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
const MAX_ACTIVE_DEPOSITS: NonZeroUsize = NonZeroUsize::new(7_000).unwrap();

/// Maximum number of ERC-20 tokens a single account may have armed at once. Bounds an
/// account's share of every scan tick, so a caller cannot arm the whole supported set.
const MAX_TOKENS_PER_ACCOUNT: usize = 5;

/// Registry of minter-controlled ckERC20 deposits, each a user account paired with an
/// ERC-20 token it wants to deposit. Every account's tokens share one deposit address,
/// derived individually for the account; this in particular enables deposits from
/// central exchanges (CEX), which send from an address the user does not control.
///
/// A `deposit_erc20` request arms an `(account, token)` pair by adding it to a bounded,
/// time-expiring watchlist. Scanning those pairs and minting the corresponding ckERC20
/// is future work (DEFI-2927).
#[derive(Clone, PartialEq, Debug)]
pub struct AutomaticDeposits {
    watchlist: TimedSizedMap<DepositKey, DepositRequest>,
    /// Funded `(account, token)` pairs moved out of the watchlist, awaiting sweeping,
    /// keyed by the funded [`DepositKey`]; each holds one [`SweepEntry`].
    sweep: BTreeMap<DepositKey, SweepEntry>,
}

impl AutomaticDeposits {
    /// Arm the `(account, token)` pair, whose deposit `address` is derived for `account`.
    ///
    /// Returns the watched pair together with the timestamp until which a deposit to it is
    /// guaranteed to be noticed. Re-registering a pair that is still armed returns the
    /// already-stored request and its original validity window without re-arming it, fails with
    /// [`DepositErc20Error::TooManyTokensForAccount`] when the account already has
    /// [`MAX_TOKENS_PER_ACCOUNT`] tokens armed, and with
    /// [`DepositErc20Error::TooManyActiveAddresses`] when the watchlist is full of live entries.
    pub fn watch_deposit(
        &mut self,
        now: Timestamp,
        account: Account,
        token: Address,
        address: Address,
    ) -> Result<Entry<DepositRequest>, DepositErc20Error> {
        let key = DepositKey::new(account, token);
        if self.watchlist.get_entry(now, &key).is_none()
            && self.armed_token_count(now, &account) >= MAX_TOKENS_PER_ACCOUNT
        {
            return Err(DepositErc20Error::TooManyTokensForAccount);
        }
        match self
            .watchlist
            .insert(now, key, DepositRequest::from(address))
        {
            Ok(_) | Err(InsertError::AlreadyPresent { .. }) => {
                let entry = self
                    .watchlist
                    .get_entry(now, &key)
                    .expect("BUG: the entry is live right after insert or AlreadyPresent");
                Ok(entry.clone())
            }
            Err(InsertError::AtCapacity { .. }) => Err(DepositErc20Error::TooManyActiveAddresses),
        }
    }

    /// The number of tokens `account` currently has armed (live as of `now`).
    fn armed_token_count(&self, now: Timestamp, account: &Account) -> usize {
        self.watchlist
            .iter()
            .filter(|(key, entry)| &key.account == account && entry.expires_at >= now)
            .count()
    }

    /// Rebuild the watchlist exactly from a registry previously produced by
    /// [`Self::watchlist_snapshot`], replacing any existing watchlist content.
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
    /// the mid-stream `AutomaticDepositReceived` events that precede the final snapshot
    /// event in the log, so clearing it here would wipe them.
    pub fn rebuild_watchlist(&mut self, registry: &DepositAddressRegistry) {
        let ttl = Duration::from_nanos(registry.scan_window_nanos);
        let capacity = NonZeroUsize::new(usize::try_from(registry.capacity).unwrap_or(usize::MAX))
            .expect("BUG: deposit address registry capacity must be non-zero");
        let entries = registry.registrations.iter().map(|deposit| {
            (
                DepositKey::new(
                    Account {
                        owner: deposit.owner,
                        subaccount: deposit.subaccount,
                    },
                    deposit.token,
                ),
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

    /// Iterate the live [`ScanTarget`]s that are due for a balance scan as of the given
    /// latest block height, using elapsed blocks as a proxy for elapsed time against the
    /// backoff schedule. `now` filters expired entries.
    ///
    /// Each target carries everything a scan of it needs (address, scan count), so the scanner
    /// never looks the entry up again: a scan spans several await points, and a concurrent
    /// [`Self::watch_deposit`] can evict an entry whose window closed at any of them — re-reading
    /// it could come back empty and drop funds already observed on-chain.
    pub fn scan_targets_iter(
        &self,
        now: Timestamp,
        latest_block: BlockNumber,
    ) -> impl Iterator<Item = ScanTarget> + '_ {
        self.watchlist.iter().filter_map(move |(key, entry)| {
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
            due.then_some(ScanTarget {
                key: *key,
                address: request.address,
                scan_count: request.scan_count,
            })
        })
    }

    /// The live watchlist entry for the `(account, token)` pair, or `None` if the pair is not
    /// currently armed (absent or expired as of `now`).
    pub fn get_entry(&self, now: Timestamp, key: &DepositKey) -> Option<&Entry<DepositRequest>> {
        self.watchlist.get_entry(now, key)
    }

    /// Record that the pair's deposit address was scanned at `block`, advancing it along the
    /// backoff schedule (`last_scanned_block = block`, `scan_count += 1`). No-op if the pair is
    /// no longer live as of `now` (expired or evicted).
    pub fn record_scan(&mut self, now: Timestamp, key: &DepositKey, block: BlockNumber) {
        if let Some(request) = self.watchlist.get_value_mut(now, key) {
            request.last_scanned_block = Some(block);
            request.scan_count = request.scan_count.saturating_add(1);
        }
    }

    /// Record an [`AutomaticDeposit`]: drop the funded `(account, token)` pair from the watchlist
    /// (if still present) and queue it in the sweep queue. Removing the watchlist entry is a no-op
    /// on replay (the watchlist is only rebuilt by the final snapshot event), which is intended.
    ///
    /// # Panics
    ///
    /// If `(account, token)` is already queued. A funded pair leaves the watchlist and is never
    /// re-scanned, so each pair reaches the queue at most once; a second entry means the log records
    /// the same funds twice, leaving `scanned_balance` — what the sweeper acts on — ambiguous.
    ///
    /// Note the blast radius: [`apply_state_transition`] runs on replay as well as live, so this
    /// panic traps `post_upgrade` and no upgrade succeeds until a repairing version ships. That is
    /// deliberate — a corrupt event log should be loud rather than silently resolved by picking one
    /// of the two records — and matches how the sibling handlers there treat a log that violates a
    /// state invariant (see [`replay_events`]).
    ///
    /// [`apply_state_transition`]: crate::state::audit::apply_state_transition
    /// [`replay_events`]: crate::state::audit::replay_events
    pub fn record_automatic_deposit_received(&mut self, deposit: &AutomaticDeposit) {
        let account = Account {
            owner: deposit.owner,
            subaccount: deposit.subaccount,
        };
        let key = DepositKey::new(account, deposit.token);
        self.watchlist.remove(&key);
        let previous = self.sweep.insert(
            key,
            SweepEntry {
                address: deposit.address,
                last_scanned_block: deposit.last_scanned_block,
                scan_count: deposit.scan_count,
                scanned_balance: deposit.scanned_balance,
            },
        );
        assert!(
            previous.is_none(),
            "BUG: sweep queue already has an entry for account {account:?} token {}",
            deposit.token
        );
    }

    /// Snapshot of the watchlist, faithful enough to reconstruct it exactly via
    /// [`Self::rebuild_watchlist`]: it records the current limits and lists every
    /// watchlist entry (live and expired-but-unevicted) in time-index order. The sweep
    /// queue is not part of the snapshot; it is event-sourced via `AutomaticDepositReceived`
    /// events.
    pub fn watchlist_snapshot(&self) -> DepositAddressRegistry {
        let registrations = self
            .watchlist
            .iter_by_expiry()
            .map(|(key, deposit)| DepositAddressRegistration {
                owner: key.account.owner,
                subaccount: key.account.subaccount,
                token: key.token,
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

    /// Where the `(account, token)` pair's deposit currently stands, or `None` if the pair is
    /// neither armed nor has funds queued for sweeping (so it must be registered). Reports
    /// [`DepositStatus::AwaitingSweep`] once funds have been detected and queued, otherwise
    /// [`DepositStatus::Scanning`] while the address is armed and being scanned as of `now`.
    pub fn deposit_status(
        &self,
        now: Timestamp,
        account: &Account,
        token: Address,
    ) -> Option<DepositErc20Response> {
        let key = DepositKey::new(*account, token);
        if let Some(entry) = self.sweep.get(&key) {
            return Some(DepositErc20Response {
                address: entry.address.to_string(),
                status: DepositStatus::AwaitingSweep(DetectedDeposit {
                    erc20_contract_address: token.to_string(),
                    scanned_balance: entry.scanned_balance.into(),
                    detected_at_block: entry.last_scanned_block.into(),
                }),
            });
        }
        self.get_entry(now, &key).map(|entry| DepositErc20Response {
            address: entry.value.address.to_string(),
            status: DepositStatus::Scanning {
                valid_until: entry.expires_at.as_nanos(),
                last_scanned_block: entry.value.last_scanned_block.map(Into::into),
                scan_count: entry.value.scan_count as u64,
            },
        })
    }
}

impl Default for AutomaticDeposits {
    fn default() -> Self {
        Self {
            watchlist: TimedSizedMap::new(DEPOSIT_ADDRESS_SCAN_WINDOW, MAX_ACTIVE_DEPOSITS),
            sweep: BTreeMap::new(),
        }
    }
}

/// The unit of registration, scanning, and sweeping: a user `account` paired with the ERC-20
/// `token` contract it wants to deposit. All of an account's tokens share one derived deposit
/// address, but each pair is armed, scanned, and swept independently.
#[derive(Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Debug)]
pub struct DepositKey {
    account: Account,
    token: Address,
}

impl DepositKey {
    pub fn new(account: Account, token: Address) -> Self {
        Self { account, token }
    }

    pub fn account(&self) -> Account {
        self.account
    }

    pub fn token(&self) -> Address {
        self.token
    }
}

/// A [`DepositKey`] due for a balance scan, carrying everything a scan of it needs read off the
/// watchlist up front: the deposit `address` derived for its account and the `scan_count` before
/// this scan. Self-contained so the scanner never re-reads the watchlist (which a concurrent
/// arming could have evicted from) after its outcalls.
#[derive(Clone, Copy, Debug)]
pub struct ScanTarget {
    key: DepositKey,
    address: Address,
    scan_count: u32,
}

impl ScanTarget {
    pub fn key(&self) -> DepositKey {
        self.key
    }

    pub fn account(&self) -> Account {
        self.key.account
    }

    pub fn token(&self) -> Address {
        self.key.token
    }

    pub fn address(&self) -> Address {
        self.address
    }

    pub fn scan_count(&self) -> u32 {
        self.scan_count
    }
}

/// A funded token awaiting sweeping at a [`DepositKey`]'s deposit address.
#[derive(Clone, PartialEq, Debug)]
struct SweepEntry {
    /// The deposit address the funds sit at.
    address: Address,
    /// The block whose scan found the funds.
    last_scanned_block: BlockNumber,
    /// How many times the pair was scanned, including the finding scan.
    scan_count: u32,
    /// The balance read for the token at `last_scanned_block`.
    scanned_balance: Erc20Value,
}

#[derive(Clone, PartialEq, Debug)]
pub struct DepositRequest {
    pub address: Address,
    /// Latest block number at which this pair's balance was scanned; None if never scanned.
    pub last_scanned_block: Option<BlockNumber>,
    /// How many times this pair has been scanned (indexes the backoff schedule).
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
