#[cfg(test)]
mod tests;

use crate::attestation::AttestationRequest;
use crate::deposit_address::DepositAddress;
use crate::endpoints::{DepositErc20Error, DepositErc20Response, DepositStatus, DetectedDeposit};
use crate::eth_rpc::Hash;
use crate::eth_rpc_client::responses::{TransactionReceipt, TransactionStatus};
use crate::logs::INFO;
use crate::numeric::{BlockNumber, Erc20Value, TransactionCount, TransactionNonce};
use crate::state::event::{AutomaticDeposit, DepositAddressRegistration, DepositAddressRegistry};
use crate::state::transactions::{
    ResubmitTransactionError, SweepId, SweepRequest, SweeperTransactionPipeline,
};
use crate::timed_sized_map::{Entry, InsertError, TimedSizedMap, Timestamp};
use crate::tx::{
    AuthorizationRequest, Finalized, GasFeeEstimate, Signed, SweepTransaction, TransactionSignature,
};
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
pub(crate) const SCAN_GAP_SECS: [u64; 33] = [
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
    /// Delegation authorizations the minter has signed, keyed by exactly what each one signed. A
    /// signature only delegates the chain, the sweeper contract and the nonce its request names, so
    /// re-pointing the minter at another sweeper contract misses this map rather than reusing a
    /// tuple that delegates the old one.
    ///
    /// Nothing prunes this map: it grows with the number of accounts that have ever been swept, and
    /// entries naming a retired helper stay behind forever. [`Self::authorizations_len`] is exported
    /// as a metric so that growth is visible before it needs bounding.
    authorizations: BTreeMap<AuthorizationRequest, TransactionSignature>,
    /// The dedicated sweeper address' transaction pipeline: sweeps sent from the sweeper address on
    /// its own nonce sequence, independent of the main-address withdrawal pipeline.
    sweeper_transactions: SweeperTransactionPipeline,
}

impl AutomaticDeposits {
    pub fn new(initial_sweeper_nonce: TransactionNonce) -> Self {
        Self {
            sweeper_transactions: SweeperTransactionPipeline::new(initial_sweeper_nonce),
            ..Default::default()
        }
    }

    pub fn has_pending_sweeps(&self) -> bool {
        self.sweeper_transactions.has_pending_requests()
    }

    pub fn is_sent_sweep_tx_empty(&self) -> bool {
        self.sweeper_transactions.is_sent_tx_empty()
    }

    pub fn next_sweeper_transaction_nonce(&self) -> TransactionNonce {
        self.sweeper_transactions.next_transaction_nonce()
    }

    pub fn update_next_sweeper_transaction_nonce(&mut self, new_nonce: TransactionNonce) {
        self.sweeper_transactions
            .update_next_transaction_nonce(new_nonce)
    }

    pub fn sweep_requests_batch(&self, requested_batch_size: usize) -> Vec<SweepRequest> {
        self.sweeper_transactions
            .requests_batch(requested_batch_size)
    }

    pub fn create_resubmit_sweep_transactions(
        &self,
        latest_transaction_count: TransactionCount,
        current_gas_fee: GasFeeEstimate,
    ) -> Vec<Result<(SweepId, SweepTransaction), ResubmitTransactionError<SweepId>>> {
        self.sweeper_transactions
            .create_resubmit_transactions(latest_transaction_count, current_gas_fee)
    }

    pub fn sweep_transactions_to_sign_batch(
        &self,
        batch_size: usize,
    ) -> Vec<(SweepId, SweepTransaction)> {
        self.sweeper_transactions
            .transactions_to_sign_batch(batch_size)
    }

    pub fn sweep_transactions_to_send_batch(
        &self,
        latest_transaction_count: TransactionCount,
        batch_size: usize,
    ) -> Vec<Signed<SweepTransaction>> {
        self.sweeper_transactions
            .transactions_to_send_batch(latest_transaction_count, batch_size)
    }

    pub fn sent_sweep_transactions_to_finalize(
        &self,
        finalized_transaction_count: &TransactionCount,
    ) -> BTreeMap<Hash, SweepId> {
        self.sweeper_transactions
            .sent_transactions_to_finalize(finalized_transaction_count)
    }

    pub fn record_sweep_request(&mut self, request: SweepRequest) {
        self.sweeper_transactions.record_request(request)
    }

    /// The request of a sweep the pipeline has taken up, still available once the sweep finalizes.
    pub fn processed_sweep_request(&self, id: &SweepId) -> Option<&SweepRequest> {
        self.sweeper_transactions.get_processed_request(id)
    }

    pub fn reschedule_sweep_request(&mut self, id: SweepId) {
        self.sweeper_transactions.reschedule_request(id)
    }

    pub fn record_created_sweep_transaction(&mut self, id: SweepId, transaction: SweepTransaction) {
        self.sweeper_transactions
            .record_created_transaction(id, transaction)
    }

    pub fn record_signed_sweep_transaction(
        &mut self,
        signed_transaction: Signed<SweepTransaction>,
    ) {
        self.sweeper_transactions
            .record_signed_transaction(signed_transaction)
    }

    pub fn record_resubmit_sweep_transaction(&mut self, new_tx: SweepTransaction) {
        self.sweeper_transactions
            .record_resubmit_transaction(new_tx)
    }

    /// Finalize `id`'s transaction and release the deposits it held, whichever way it went: they
    /// leave the queue on success because the funds moved, and on failure because the minter does
    /// not retry them.
    ///
    /// # Panics
    ///
    /// If the sweep has no processed request, or a deposit it named is not queued or is held by
    /// another sweep. Each means the queue has stopped describing which sweep owns which funds.
    pub fn record_finalized_sweep_transaction(
        &mut self,
        id: SweepId,
        receipt: &TransactionReceipt,
    ) -> Finalized<SweepTransaction> {
        let finalized = self
            .sweeper_transactions
            .record_finalized_transaction(id, receipt);
        let request = self
            .sweeper_transactions
            .get_processed_request(&id)
            .expect("BUG: missing sweep request");
        let token = request.token;
        let accounts: Vec<_> = request.items.iter().map(|item| item.item.account).collect();

        for account in accounts {
            let request = DepositRequest::new(account, token);
            let entry = self
                .sweep
                .remove(&request)
                .unwrap_or_else(|| panic!("BUG: {request:?} is not queued for sweeping"));
            assert_eq!(
                entry.swept_by,
                Some(id),
                "BUG: {request:?} is not held by sweep {id:?}"
            );
            if receipt.status == TransactionStatus::Failure {
                log!(
                    INFO,
                    "[record_finalized_sweep_transaction]: DROPPING {request:?} from the sweep queue: {id:?} failed and the minter does not retry. Its {:?} stays at {}, and reaching it again needs the pair armed afresh.",
                    entry.scanned_balance,
                    entry.address
                );
            }
        }
        finalized
    }

    /// Equality as replay defines it: the sweeper pipeline reorders its queue without recording an
    /// event, so it compares itself rather than being compared field by field.
    pub fn is_equivalent_to(&self, other: &Self) -> Result<(), String> {
        use ic_utils_ensure::ensure_eq;

        let Self {
            watchlist,
            sweep,
            attestations,
            authorizations,
            sweeper_transactions,
        } = self;

        ensure_eq!(watchlist, &other.watchlist);
        ensure_eq!(sweep, &other.sweep);
        ensure_eq!(attestations, &other.attestations);
        ensure_eq!(authorizations, &other.authorizations);
        sweeper_transactions.is_equivalent_to(&other.sweeper_transactions)
    }

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

    /// The authorization already stored for `account`, if any: signing another would cost a
    /// threshold-ECDSA signature for the same tuple.
    pub fn authorization(&self, request: &AuthorizationRequest) -> Option<&TransactionSignature> {
        self.authorizations.get(request)
    }

    pub fn record_authorization(
        &mut self,
        request: AuthorizationRequest,
        signature: TransactionSignature,
    ) {
        self.authorizations.insert(request, signature);
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

    pub fn watchlist_len(&self) -> usize {
        self.watchlist.len()
    }

    pub fn sweep_len(&self) -> usize {
        self.sweep.len()
    }

    pub fn attestations_len(&self) -> usize {
        self.attestations.len()
    }

    pub fn authorizations_len(&self) -> usize {
        self.authorizations.len()
    }

    /// Where `request`'s deposit currently stands, or `None` if the pair is neither armed nor has
    /// funds queued for sweeping (so it must be registered). Reports
    /// [`DepositStatus::AwaitingSweep`] once funds have been detected and queued, otherwise
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
            return Some(DepositErc20Response {
                address: entry.address.to_string(),
                minimum_deposit_amount: minimum_deposit_amount.into(),
                status: DepositStatus::AwaitingSweep(DetectedDeposit {
                    erc20_contract_address: request.token().to_string(),
                    scanned_balance: entry.scanned_balance.into(),
                    detected_at_block: entry.last_scanned_block.into(),
                }),
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

    /// The queued deposits a sweep could take next, batched by token, skipping those a sweep
    /// already holds: taking them twice would move a balance the minter has already accounted for.
    pub fn requests_batch(
        &self,
        requested_batch_size: usize,
    ) -> BTreeMap<Address, Vec<SweepTarget>> {
        let mut batches = BTreeMap::new();
        for (deposit_request, sweep_entry) in
            self.sweep.iter().filter(|(_, entry)| entry.is_sweepable())
        {
            let batch: &mut Vec<_> = batches.entry(deposit_request.token).or_default();
            if batch.len() < requested_batch_size {
                batch.push(SweepTarget {
                    account: deposit_request.account,
                    address: sweep_entry.address,
                });
            }
        }
        batches
    }

    /// Record that `sweep_id` took these accounts' deposits of `token`: each leaves the pool of
    /// sweepable entries until the sweep is done with it.
    ///
    /// # Panics
    ///
    /// If a deposit is not queued, or another sweep already took it. Either means the queue no
    /// longer describes which sweep owns which funds.
    pub fn record_sweep_scheduled(
        &mut self,
        sweep_id: SweepId,
        token: Address,
        accounts: impl IntoIterator<Item = Account>,
    ) {
        for account in accounts {
            let request = DepositRequest::new(account, token);
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
}

impl Default for AutomaticDeposits {
    fn default() -> Self {
        Self {
            watchlist: TimedSizedMap::new(DEPOSIT_ADDRESS_SCAN_WINDOW, MAX_ACTIVE_DEPOSITS),
            sweep: BTreeMap::new(),
            attestations: BTreeMap::new(),
            authorizations: BTreeMap::new(),
            sweeper_transactions: SweeperTransactionPipeline::new(TransactionNonce::ZERO),
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
    /// The sweep holding these funds, if one does. The entry stays queued while a sweep has it,
    /// rather than leaving on being taken: until that sweep settles, this is the only record of
    /// which balance sits at which address, and a failed sweep has to be able to say so.
    swept_by: Option<SweepId>,
}

impl SweepEntry {
    /// Whether a sweep could take these funds, i.e. no sweep already holds them.
    fn is_sweepable(&self) -> bool {
        self.swept_by.is_none()
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

/// A queued deposit a sweep can move: the account it credits and the address its funds sit at.
/// The token is the key its batch is grouped under, so it is not repeated here.
#[derive(Clone, Copy, Debug)]
pub struct SweepTarget {
    account: Account,
    address: DepositAddress,
}

impl SweepTarget {
    pub fn account(&self) -> Account {
        self.account
    }

    pub fn address(&self) -> DepositAddress {
        self.address
    }
}

impl AsRef<Account> for SweepTarget {
    fn as_ref(&self) -> &Account {
        &self.account
    }
}
