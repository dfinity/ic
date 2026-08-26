#[cfg(test)]
mod tests;

use crate::attestation::AttestationRequest;
use crate::deposit_address::DepositAddress;
use crate::endpoints::{DepositErc20Error, DepositErc20Response, DepositStatus, DetectedDeposit};
use crate::logs::INFO;
use crate::numeric::{BlockNumber, Erc20Value};
use crate::state::event::{AutomaticDeposit, DepositAddressRegistration, DepositAddressRegistry};
use crate::state::transactions::{SweepId, SweptDeposit};
use crate::timed_sized_map::{Entry, InsertError, TimedSizedMap, Timestamp};
use crate::tx::TransactionSignature;
use ic_canister_log::log;
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
    watchlist: TimedSizedMap<DepositRequest, ScanProgress>,
    /// Funded `(account, token)` pairs moved out of the watchlist, awaiting sweeping,
    /// keyed by the funded [`DepositRequest`]; each holds one [`SweepEntry`].
    sweep: BTreeMap<DepositRequest, SweepEntry>,
    /// Attestations the minter has signed, keyed by exactly what each one signed. An attestation
    /// binds an account to one chain and one helper deployment and never expires, so a later sweep
    /// of the same address reuses it instead of paying for another threshold-ECDSA signature; a new
    /// helper deployment yields a different key and simply misses.
    ///
    /// Nothing prunes this map: it grows with the number of accounts that have ever been swept, and
    /// entries naming a retired helper stay behind forever. [`Self::attestations_len`] is exported
    /// as a metric so that growth is visible before it needs bounding.
    attestations: BTreeMap<AttestationRequest, TransactionSignature>,
}

impl AutomaticDeposits {
    /// The signature already stored for `request`, if any: signing another would cost a
    /// threshold-ECDSA signature for the same digest.
    pub fn attestation(&self, request: &AttestationRequest) -> Option<&TransactionSignature> {
        self.attestations.get(request)
    }

    pub fn record_attestation(
        &mut self,
        request: AttestationRequest,
        signature: TransactionSignature,
    ) {
        self.attestations.insert(request, signature);
    }

    /// Arm the `(account, token)` pair, whose deposit `address` is derived for `account`.
    ///
    /// Returns the watched pair together with the timestamp until which a deposit to it is
    /// guaranteed to be noticed. Re-registering a pair that is still armed returns the
    /// already-stored request and its original validity window without re-arming it, fails with
    /// [`DepositErc20Error::TooManyTokensForAccount`] when the account already has
    /// [`MAX_TOKENS_PER_ACCOUNT`] tokens armed, and with
    /// [`DepositErc20Error::TooManyActiveDeposits`] when the watchlist is full of live entries.
    ///
    /// # Panics
    ///
    /// If the pair already has funds queued for sweeping.
    pub fn watch_deposit(
        &mut self,
        now: Timestamp,
        account: Account,
        token: Address,
        address: DepositAddress,
    ) -> Result<Entry<ScanProgress>, DepositErc20Error> {
        let request = DepositRequest::new(account, token);
        // Unreachable from `deposit_erc20`, which returns a pair's status whenever it has one and a
        // queued pair always does, so a caller sees `AwaitingSweep` instead of arriving here. Its
        // last such check is followed by no await, so no scan can queue the pair in between.
        assert!(
            !self.sweep.contains_key(&request),
            "BUG: cannot arm {request:?}, it already has funds queued for sweeping"
        );
        if self.watchlist.get_entry(now, &request).is_none()
            && self.armed_token_count(now, &account) >= MAX_TOKENS_PER_ACCOUNT
        {
            return Err(DepositErc20Error::TooManyTokensForAccount);
        }
        match self
            .watchlist
            .insert(now, request, ScanProgress::from(address))
        {
            Ok(_) | Err(InsertError::AlreadyPresent { .. }) => {
                let entry = self
                    .watchlist
                    .get_entry(now, &request)
                    .expect("BUG: the entry is live right after insert or AlreadyPresent");
                Ok(entry.clone())
            }
            Err(InsertError::AtCapacity { .. }) => Err(DepositErc20Error::TooManyActiveDeposits),
        }
    }

    /// The number of tokens `account` currently has armed (live as of `now`).
    fn armed_token_count(&self, now: Timestamp, account: &Account) -> usize {
        self.watchlist
            .iter()
            .filter(|(request, entry)| &request.account == account && entry.expires_at >= now)
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
                DepositRequest::new(
                    Account {
                        owner: deposit.owner,
                        subaccount: deposit.subaccount,
                    },
                    deposit.erc20_contract_address,
                ),
                Entry {
                    value: ScanProgress {
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
        self.watchlist.iter().filter_map(move |(request, entry)| {
            if entry.expires_at < now {
                return None;
            }
            let progress = &entry.value;
            let due = match progress.last_scanned_block {
                None => true,
                Some(last_scanned_block) => {
                    let index = (progress.scan_count as usize).saturating_sub(1);
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
                request: *request,
                address: progress.address,
                scan_count: progress.scan_count,
            })
        })
    }

    /// The live watchlist entry for the `(account, token)` pair, or `None` if the pair is not
    /// currently armed (absent or expired as of `now`).
    pub fn get_entry(
        &self,
        now: Timestamp,
        request: &DepositRequest,
    ) -> Option<&Entry<ScanProgress>> {
        self.watchlist.get_entry(now, request)
    }

    /// Record that the pair's deposit address was scanned at `block`, advancing it along the
    /// backoff schedule (`last_scanned_block = block`, `scan_count += 1`). No-op if the pair is
    /// no longer live as of `now` (expired or evicted).
    pub fn record_scan(&mut self, now: Timestamp, request: &DepositRequest, block: BlockNumber) {
        if let Some(progress) = self.watchlist.get_value_mut(now, request) {
            progress.last_scanned_block = Some(block);
            progress.scan_count = progress.scan_count.saturating_add(1);
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
        let request = DepositRequest::new(account, deposit.erc20_contract_address);
        self.watchlist.remove(&request);
        let previous = self.sweep.insert(
            request,
            SweepEntry {
                address: deposit.address,
                last_scanned_block: deposit.last_scanned_block,
                scan_count: deposit.scan_count,
                scanned_balance: deposit.scanned_balance,
                swept_by: None,
            },
        );
        assert!(
            previous.is_none(),
            "BUG: sweep queue already has an entry for account {account:?} token {}",
            deposit.erc20_contract_address
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
            .map(|(request, deposit)| DepositAddressRegistration {
                owner: request.account.owner,
                subaccount: request.account.subaccount,
                erc20_contract_address: request.token,
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

    /// The queued deposits waiting for a sweep to take them.
    ///
    /// Yielded in `(account, token)` key order: by principal, then by subaccount, then by token
    /// address, which says nothing about when each was queued — nothing here records that. A sweep
    /// takes a bounded prefix of this iterator, so the same order decides which deposits get into
    /// the next batch.
    pub fn sweep_targets_iter(&self) -> impl Iterator<Item = SweepTarget> + '_ {
        self.sweep
            .iter()
            .filter(|(_request, entry)| entry.swept_by.is_none())
            .map(|(request, entry)| SweepTarget {
                request: *request,
                address: entry.address,
                scanned_balance: entry.scanned_balance,
            })
    }

    /// Record that `sweep_id` took these deposits: each leaves the pool of sweepable entries until
    /// the sweep is done with it.
    ///
    /// # Panics
    ///
    /// If a deposit is not queued, or another sweep already took it. Sweeping the same funds twice
    /// would move a balance the minter has already accounted for.
    pub fn record_sweep_scheduled(&mut self, sweep_id: SweepId, deposits: &[SweptDeposit]) {
        for deposit in deposits {
            let request = DepositRequest::new(deposit.account, deposit.erc20_contract_address);
            let entry = self
                .sweep
                .get_mut(&request)
                .unwrap_or_else(|| panic!("BUG: {request:?} is not queued for sweeping"));
            assert_eq!(
                entry.swept_by, None,
                "BUG: {request:?} was already taken by another sweep"
            );
            entry.swept_by = Some(sweep_id);
        }
    }

    /// Drop the deposits `sweep_id` took, its transaction having failed, logging each one.
    ///
    /// The minter does not retry them. The funds are not lost — a reverted sweep moved nothing, so
    /// the balance the scan found is still at the deposit address — but nothing here remembers them
    /// any more, and getting them moving again means arming the pair afresh.
    ///
    /// Dropping rather than retrying is deliberate, and interim: a sweep's call data is rebuilt from
    /// the queue in the same key order, so a batch that reverted for a reason of its own reverts
    /// again on the next tick, and every attempt burns the sweeper address' gas. What to retry, how
    /// often, and how to isolate the deposit actually at fault is DEFI-2981.
    ///
    /// # Panics
    ///
    /// If a deposit is not queued, or is held by another sweep. Either means the queue no longer
    /// describes which sweep owns which funds.
    pub fn record_sweep_failed(&mut self, sweep_id: SweepId, deposits: &[SweptDeposit]) {
        for deposit in deposits {
            let request = DepositRequest::new(deposit.account, deposit.erc20_contract_address);
            let entry = self
                .sweep
                .remove(&request)
                .unwrap_or_else(|| panic!("BUG: {request:?} is not queued for sweeping"));
            assert_eq!(
                entry.swept_by,
                Some(sweep_id),
                "BUG: {request:?} is not held by sweep {sweep_id:?}"
            );
            log!(
                INFO,
                "[record_sweep_failed]: DROPPING {request:?} from the sweep queue: {sweep_id:?} \
                 failed and the minter does not retry. Its {:?} stays at {}, and reaching it again \
                 needs the pair armed afresh.",
                entry.scanned_balance,
                entry.address
            );
        }
    }

    /// Drop the deposits `sweep_id` moved: the balance the scan found is no longer at the deposit
    /// address, so there is nothing left to sweep and nothing to keep an entry for. The pair leaves
    /// the queue exactly as it entered it, which is what lets it be armed again for the next
    /// deposit to the same address.
    ///
    /// # Panics
    ///
    /// If a deposit is not queued, or is held by another sweep. Either means the queue no longer
    /// describes which sweep owns which funds.
    pub fn record_sweep_succeeded(&mut self, sweep_id: SweepId, deposits: &[SweptDeposit]) {
        for deposit in deposits {
            let request = DepositRequest::new(deposit.account, deposit.erc20_contract_address);
            let entry = self
                .sweep
                .remove(&request)
                .unwrap_or_else(|| panic!("BUG: {request:?} is not queued for sweeping"));
            assert_eq!(
                entry.swept_by,
                Some(sweep_id),
                "BUG: {request:?} is not held by sweep {sweep_id:?}"
            );
        }
    }

    /// Where the sweep queue's entries stand, counted in one pass: the metrics endpoint asks for
    /// both numbers together, and only the two together say whether sweeping is making progress.
    ///
    /// One pass over the queue per call. The queue holds only deposits a sweep has yet to finish
    /// with, so it is bounded by what is in flight rather than by every deposit ever swept.
    pub fn sweep_queue_depth(&self) -> SweepQueueDepth {
        let mut depth = SweepQueueDepth::default();
        for entry in self.sweep.values() {
            match entry.swept_by {
                Some(_) => depth.in_flight += 1,
                None => depth.sweepable += 1,
            }
        }
        depth
    }

    pub fn watchlist_len(&self) -> usize {
        self.watchlist.len()
    }

    pub fn sweep_len(&self) -> usize {
        self.sweep.len()
    }

    pub fn attestations_len(&self) -> usize {
        self.attestations.len()
    }

    /// Where `request`'s deposit currently stands, or `None` if the pair is neither armed nor has
    /// funds queued for sweeping (so it must be registered). Reports
    /// [`DepositStatus::AwaitingSweep`] once funds have been detected and queued, and otherwise
    /// [`DepositStatus::Scanning`] while the address is armed and being scanned as of `now`.
    /// `minimum_deposit_amount` is the balance the address must hold for the scan to detect it,
    /// reported back to the caller alongside the status.
    pub fn deposit_status(
        &self,
        now: Timestamp,
        request: &DepositRequest,
        minimum_deposit_amount: Erc20Value,
    ) -> Option<DepositErc20Response> {
        if let Some(entry) = self.sweep.get(request) {
            let detected = DetectedDeposit {
                erc20_contract_address: request.token().to_string(),
                scanned_balance: entry.scanned_balance.into(),
                detected_at_block: entry.last_scanned_block.into(),
            };
            return Some(DepositErc20Response {
                address: entry.address.to_string(),
                minimum_deposit_amount: minimum_deposit_amount.into(),
                status: DepositStatus::AwaitingSweep(detected),
            });
        }
        self.get_entry(now, request)
            .map(|entry| DepositErc20Response {
                address: entry.value.address.to_string(),
                minimum_deposit_amount: minimum_deposit_amount.into(),
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
            attestations: BTreeMap::new(),
        }
    }
}

/// What `deposit_erc20` asks for, and the unit of registration, scanning, and sweeping: a user
/// `account` paired with the ERC-20 `token` contract it intends to deposit. Nothing has been
/// deposited yet — the request only arms the pair so a later deposit to it is noticed.
///
/// All of an account's tokens share one derived deposit address, but each pair is armed, scanned,
/// and swept independently.
#[derive(Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Debug)]
pub struct DepositRequest {
    account: Account,
    token: Address,
}

impl DepositRequest {
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

/// A [`DepositRequest`] due for a balance scan, carrying everything a scan of it needs read off the
/// watchlist up front: the deposit `address` derived for its account and the `scan_count` before
/// this scan. Self-contained so the scanner never re-reads the watchlist (which a concurrent
/// arming could have evicted from) after its outcalls.
#[derive(Clone, Copy, Debug)]
pub struct ScanTarget {
    request: DepositRequest,
    address: DepositAddress,
    scan_count: u32,
}

impl ScanTarget {
    pub fn request(&self) -> DepositRequest {
        self.request
    }

    pub fn account(&self) -> Account {
        self.request.account
    }

    pub fn token(&self) -> Address {
        self.request.token
    }

    pub fn address(&self) -> DepositAddress {
        self.address
    }

    pub fn scan_count(&self) -> u32 {
        self.scan_count
    }
}

/// How many queued deposits are in each of the two states the sweep queue holds them in.
#[derive(Clone, Copy, Default, Eq, PartialEq, Debug)]
pub struct SweepQueueDepth {
    /// Held by a sweep that has not been finalized yet.
    pub in_flight: usize,
    /// Waiting for a sweep to take them.
    pub sweepable: usize,
}

/// A funded token awaiting sweeping at a [`DepositRequest`]'s deposit address.
#[derive(Clone, PartialEq, Debug)]
struct SweepEntry {
    /// The deposit address the funds sit at.
    address: DepositAddress,
    /// The block whose scan found the funds.
    last_scanned_block: BlockNumber,
    /// How many times the pair was scanned, including the finding scan.
    scan_count: u32,
    /// The balance read for the token at `last_scanned_block`.
    scanned_balance: Erc20Value,
    /// The sweep that took this entry, once one has been enqueued for it. Set so a later scan tick
    /// does not enqueue the same funds twice; the entry stays until the sweep is finalized.
    swept_by: Option<SweepId>,
}

/// A queued deposit a sweep can move: the `(account, token)` pair, the address its funds sit at,
/// and the balance the scan found there.
#[derive(Clone, Copy, Debug)]
pub struct SweepTarget {
    request: DepositRequest,
    address: DepositAddress,
    scanned_balance: Erc20Value,
}

impl SweepTarget {
    pub fn account(&self) -> Account {
        self.request.account
    }

    pub fn token(&self) -> Address {
        self.request.token
    }

    pub fn address(&self) -> DepositAddress {
        self.address
    }

    pub fn scanned_balance(&self) -> Erc20Value {
        self.scanned_balance
    }
}

/// The watchlist value held against one [`DepositRequest`]: the deposit address derived for its
/// account, and how far the balance scan has got with the pair.
#[derive(Clone, PartialEq, Debug)]
pub struct ScanProgress {
    pub address: DepositAddress,
    /// Latest block number at which this pair's balance was scanned; None if never scanned.
    pub last_scanned_block: Option<BlockNumber>,
    /// How many times this pair has been scanned (indexes the backoff schedule).
    pub scan_count: u32,
}

impl From<DepositAddress> for ScanProgress {
    fn from(address: DepositAddress) -> Self {
        Self {
            address,
            last_scanned_block: None,
            scan_count: 0,
        }
    }
}
