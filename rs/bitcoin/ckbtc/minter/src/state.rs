///! State management module.
///!
///! The state is stored in the global thread-level variable `__STATE`.
///! This module provides utility functions to manage the state. Most
///! code should use those functions instead of touching `__STATE` directly.
use std::{
    cell::RefCell,
    collections::{BTreeMap, BTreeSet, VecDeque},
};

pub mod audit;
pub mod eventlog;

use crate::lifecycle::init::InitArgs;
use crate::lifecycle::upgrade::UpgradeArgs;
use crate::{address::BitcoinAddress, ECDSAPublicKey};
use candid::{Deserialize, Principal};
use ic_base_types::{CanisterId, PrincipalId};
use ic_btc_types::{Network, OutPoint, Utxo};
use ic_icrc1::Account;
use serde::Serialize;

// Like assert_eq, but returns an error instead of panicking.
macro_rules! ensure_eq {
    ($lhs:expr, $rhs:expr, $msg:expr $(, $args:expr)* $(,)*) => {
        if $lhs != $rhs {
            return Err(format!("{} ({:?}) != {} ({:?}): {}",
                               std::stringify!($lhs), $lhs,
                               std::stringify!($rhs), $rhs,
                               format!($msg $(,$args)*)));
        }
    }
}
macro_rules! ensure {
    ($cond:expr, $msg:expr $(, $args:expr)* $(,)*) => {
        if !$cond {
            return Err(format!("Condition {} is false: {}",
                               std::stringify!($cond),
                               format!($msg $(,$args)*)));
        }
    }
}

/// The maximum number of finalized BTC retrieval requests that we keep in the
/// history.
const MAX_FINALIZED_REQUESTS: usize = 100;

thread_local! {
    static __STATE: RefCell<Option<CkBtcMinterState>> = RefCell::default();
}

// A pending retrieve btc request
#[derive(candid::CandidType, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RetrieveBtcRequest {
    pub amount: u64,
    pub address: BitcoinAddress,
    pub block_index: u64,
    pub received_at: u64,
}

/// A transaction output storing the minter's change.
#[derive(candid::CandidType, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChangeOutput {
    /// The index of the output in the transaction.
    pub vout: u32,
    /// The value of the output.
    pub value: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubmittedBtcTransaction {
    /// The original retrieve_btc requests that initiated the transaction.
    pub requests: Vec<RetrieveBtcRequest>,
    /// The identifier of the unconfirmed transaction.
    pub txid: [u8; 32],
    /// The list of UTXOs we used in the transaction.
    pub used_utxos: Vec<Utxo>,
    /// The IC time at which we submitted the Bitcoin transaction.
    pub submitted_at: u64,
    /// The tx output from the submitted transaction that the minter owns.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub change_output: Option<ChangeOutput>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FinalizedBtcRetrieval {
    /// The original retrieve_btc request that initiated the transaction.
    pub request: RetrieveBtcRequest,
    /// The state of the finalized request.
    pub state: FinalizedStatus,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum FinalizedStatus {
    /// The request amount was to low to cover the fees.
    AmountTooLow,
    /// The transaction that retrieves BTC got enough confirmations.
    Confirmed {
        /// The witness transaction identifier of the transaction.
        txid: [u8; 32],
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum InFlightStatus {
    Signing,
    Sending { txid: [u8; 32] },
}

#[derive(candid::CandidType, Clone, Debug, PartialEq, Eq, Deserialize)]
pub enum RetrieveBtcStatus {
    Unknown,
    Pending,
    Signing,
    Sending { txid: [u8; 32] },
    Submitted { txid: [u8; 32] },
    AmountTooLow,
    Confirmed { txid: [u8; 32] },
}

#[derive(candid::CandidType, Clone, Debug, PartialEq, Eq, serde::Deserialize, Serialize)]
pub enum Mode {
    ReadOnly,
    RestrictedTo(Vec<Principal>),
    DepositsRestrictedTo(Vec<Principal>),
    GeneralAvailability,
}

impl Mode {
    /// Returns Ok if the specified principal can convert BTC to ckBTC.
    pub fn is_deposit_available_for(&self, p: &Principal) -> Result<(), String> {
        match self {
            Self::GeneralAvailability => Ok(()),
            Self::ReadOnly => Err("the minter is in read-only mode".to_string()),
            Self::RestrictedTo(allow_list) => {
                if !allow_list.contains(p) {
                    return Err("access to the minter is temporarily restricted".to_string());
                }
                Ok(())
            }
            Self::DepositsRestrictedTo(allow_list) => {
                if !allow_list.contains(p) {
                    return Err("BTC deposits are temporarily restricted".to_string());
                }
                Ok(())
            }
        }
    }

    /// Returns Ok if the specified principal can convert ckBTC to BTC.
    pub fn is_withdrawal_available_for(&self, p: &Principal) -> Result<(), String> {
        match self {
            Self::GeneralAvailability | Self::DepositsRestrictedTo(_) => Ok(()),
            Self::ReadOnly => Err("the minter is in read-only mode".to_string()),
            Self::RestrictedTo(allow_list) => {
                if !allow_list.contains(p) {
                    return Err("BTC withdrawals are temporarily restricted".to_string());
                }
                Ok(())
            }
        }
    }
}

impl Default for Mode {
    fn default() -> Self {
        Self::GeneralAvailability
    }
}

/// The state of the ckBTC Minter.
///
/// Every piece of state of the Minter should be stored as field of this struct.
#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, Serialize)]
pub struct CkBtcMinterState {
    /// The bitcoin network that the minter will connect to
    pub btc_network: Network,

    /// The name of the [EcdsaKeyId]. Use "dfx_test_key" for local replica and "test_key_1" for
    /// a testing key for testnet and mainnet
    pub ecdsa_key_name: String,

    /// The Minter ECDSA public key
    pub ecdsa_public_key: Option<ECDSAPublicKey>,

    /// The minimum number of confirmations on the Bitcoin chain.
    pub min_confirmations: u32,

    /// Maximum time of nanoseconds that a transaction should spend in the queue
    /// before being sent.
    pub max_time_in_queue_nanos: u64,

    /// Per-principal lock for update_balance
    pub update_balance_principals: BTreeSet<Principal>,

    /// Per-principal lock for retrieve_btc
    pub retrieve_btc_principals: BTreeSet<Principal>,

    /// Minimum amount of bitcoin that can be retrieved
    pub retrieve_btc_min_amount: u64,

    /// Retrieve_btc requests that are waiting to be served, sorted by
    /// received_at.
    pub pending_retrieve_btc_requests: Vec<RetrieveBtcRequest>,

    /// The identifiers of retrieve_btc requests which we're currently signing a
    /// transaction or sending to the Bitcoin network.
    pub requests_in_flight: BTreeMap<u64, InFlightStatus>,

    /// BTC transactions waiting for finalization.
    pub submitted_transactions: Vec<SubmittedBtcTransaction>,

    /// Finalized retrieve_btc requests for which we received enough confirmations.
    pub finalized_requests: VecDeque<FinalizedBtcRetrieval>,

    /// The total number of finalized requests.
    pub finalized_requests_count: u64,

    /// The total amount of ckBTC minted.
    pub tokens_minted: u64,

    /// The total amount of ckBTC burned.
    pub tokens_burned: u64,

    /// The CanisterId of the ckBTC Ledger
    pub ledger_id: CanisterId,

    /// The set of UTXOs unused in pending transactions.
    pub available_utxos: BTreeSet<Utxo>,

    /// The mapping from output points to the ledger accounts to which they
    /// belong.
    pub outpoint_account: BTreeMap<OutPoint, Account>,

    /// The map of known addresses to their utxos.
    pub utxos_state_addresses: BTreeMap<Account, BTreeSet<Utxo>>,

    /// This map contains the UTXOs we removed due to a transaction finalization
    /// while there was a concurrent update_balance call for the principal whose
    /// UTXOs participated in the transaction. The UTXOs can belong to any
    /// subaccount of the principal.
    ///
    /// We insert a new entry into this map if we discover a concurrent
    /// update_balance calls during a transaction finalization and remove the
    /// entry once the update_balance call completes.
    pub finalized_utxos: BTreeMap<PrincipalId, BTreeSet<Utxo>>,

    /// Process one timer event at a time.
    #[serde(skip)]
    pub is_timer_running: bool,

    /// The mode in which the minter runs.
    pub mode: Mode,
}

impl CkBtcMinterState {
    pub fn reinit(
        &mut self,
        InitArgs {
            btc_network,
            ecdsa_key_name,
            retrieve_btc_min_amount,
            ledger_id,
            max_time_in_queue_nanos,
            min_confirmations,
            mode,
        }: InitArgs,
    ) {
        self.btc_network = btc_network;
        self.ecdsa_key_name = ecdsa_key_name;
        self.retrieve_btc_min_amount = retrieve_btc_min_amount;
        self.ledger_id = ledger_id;
        self.max_time_in_queue_nanos = max_time_in_queue_nanos;
        self.mode = mode;
        if let Some(min_confirmations) = min_confirmations {
            self.min_confirmations = min_confirmations;
        }
    }

    pub fn upgrade(
        &mut self,
        UpgradeArgs {
            retrieve_btc_min_amount,
            max_time_in_queue_nanos,
            min_confirmations,
            mode,
        }: UpgradeArgs,
    ) {
        if let Some(retrieve_btc_min_amount) = retrieve_btc_min_amount {
            self.retrieve_btc_min_amount = retrieve_btc_min_amount;
        }
        if let Some(max_time_in_queue_nanos) = max_time_in_queue_nanos {
            self.max_time_in_queue_nanos = max_time_in_queue_nanos;
        }
        if let Some(min_conf) = min_confirmations {
            self.min_confirmations = min_conf;
        }
        if let Some(mode) = mode {
            self.mode = mode;
        }
    }

    pub fn check_invariants(&self) -> Result<(), String> {
        for utxo in self.available_utxos.iter() {
            ensure!(
                self.outpoint_account.contains_key(&utxo.outpoint),
                "the output_account map is missing an entry for {:?}",
                utxo.outpoint
            );

            ensure!(
                self.utxos_state_addresses
                    .iter()
                    .any(|(_, utxos)| utxos.contains(utxo)),
                "available utxo {:?} does not belong to any account",
                utxo
            );
        }

        for (addr, utxos) in self.utxos_state_addresses.iter() {
            for utxo in utxos.iter() {
                ensure_eq!(
                    self.outpoint_account.get(&utxo.outpoint),
                    Some(addr),
                    "missing outpoint account for {:?}",
                    utxo.outpoint
                );
            }
        }

        for (l, r) in self
            .pending_retrieve_btc_requests
            .iter()
            .zip(self.pending_retrieve_btc_requests.iter().skip(1))
        {
            ensure!(
                l.received_at <= r.received_at,
                "pending retrieve_btc requests are not sorted by receive time"
            );
        }

        Ok(())
    }

    // public for only for tests
    pub(crate) fn add_utxos(&mut self, account: Account, utxos: Vec<Utxo>) {
        if utxos.is_empty() {
            return;
        }

        self.tokens_minted += utxos.iter().map(|u| u.value).sum::<u64>();

        let account_bucket = self
            .utxos_state_addresses
            .entry(account.clone())
            .or_default();

        for utxo in utxos {
            self.outpoint_account
                .insert(utxo.outpoint.clone(), account.clone());
            self.available_utxos.insert(utxo.clone());
            account_bucket.insert(utxo);
        }

        #[cfg(debug_assertions)]
        self.check_invariants()
            .expect("state invariants are violated");
    }

    /// Returns the status of the retrieve_btc request with the specified
    /// identifier.
    pub fn retrieve_btc_status(&self, block_index: u64) -> RetrieveBtcStatus {
        if self
            .pending_retrieve_btc_requests
            .iter()
            .any(|req| req.block_index == block_index)
        {
            return RetrieveBtcStatus::Pending;
        }

        if let Some(status) = self.requests_in_flight.get(&block_index).cloned() {
            return match status {
                InFlightStatus::Signing => RetrieveBtcStatus::Signing,
                InFlightStatus::Sending { txid } => RetrieveBtcStatus::Sending { txid },
            };
        }

        if let Some(txid) = self.submitted_transactions.iter().find_map(|tx| {
            (tx.requests.iter().any(|r| r.block_index == block_index)).then_some(tx.txid)
        }) {
            return RetrieveBtcStatus::Submitted { txid };
        }

        match self
            .finalized_requests
            .iter()
            .find(|finalized_request| finalized_request.request.block_index == block_index)
            .map(|final_req| final_req.state.clone())
        {
            Some(FinalizedStatus::AmountTooLow) => return RetrieveBtcStatus::AmountTooLow,
            Some(FinalizedStatus::Confirmed { txid }) => {
                return RetrieveBtcStatus::Confirmed { txid }
            }
            None => (),
        }

        RetrieveBtcStatus::Unknown
    }

    /// Returns true if the pending requests queue has enough requests to form a
    /// batch or there are old enough requests to form a batch.
    pub fn can_form_a_batch(&self, min_pending: usize, now: u64) -> bool {
        if self.pending_retrieve_btc_requests.len() >= min_pending {
            return true;
        }

        match self.pending_retrieve_btc_requests.first() {
            Some(req) => self.max_time_in_queue_nanos < now.saturating_sub(req.received_at),
            None => false,
        }
    }

    /// Forms a batch of retrieve_btc requests that the minter can fulfill.
    pub fn build_batch(&mut self, max_size: usize) -> Vec<RetrieveBtcRequest> {
        let available_utxos_value = self.available_utxos.iter().map(|u| u.value).sum::<u64>();
        let mut batch = vec![];
        let mut tx_amount = 0;
        for req in std::mem::take(&mut self.pending_retrieve_btc_requests) {
            if available_utxos_value < req.amount + tx_amount || batch.len() >= max_size {
                // Put this request back to the queue until we have enough liquid UTXOs.
                self.pending_retrieve_btc_requests.push(req);
            } else {
                tx_amount += req.amount;
                batch.push(req);
            }
        }

        batch
    }

    /// Returns the total number of all retrieve_btc requests that we haven't
    /// finalized yet.
    pub fn count_incomplete_retrieve_btc_requests(&self) -> usize {
        self.pending_retrieve_btc_requests.len()
            + self.requests_in_flight.len()
            + self
                .submitted_transactions
                .iter()
                .map(|tx| tx.requests.len())
                .sum::<usize>()
    }

    /// Returns true if there is a pending retrieve_btc request with the given
    /// identifier.
    fn has_pending_request(&self, block_index: u64) -> bool {
        self.pending_retrieve_btc_requests
            .iter()
            .any(|req| req.block_index == block_index)
    }

    fn forget_utxo(&mut self, utxo: &Utxo) {
        if let Some(account) = self.outpoint_account.remove(&utxo.outpoint) {
            if self
                .update_balance_principals
                .contains(&account.owner.into())
            {
                self.finalized_utxos
                    .entry(account.owner)
                    .or_insert_with(BTreeSet::new)
                    .insert(utxo.clone());
            }

            let last_utxo = match self.utxos_state_addresses.get_mut(&account) {
                Some(utxo_set) => {
                    utxo_set.remove(utxo);
                    utxo_set.is_empty()
                }
                None => false,
            };
            if last_utxo {
                self.utxos_state_addresses.remove(&account);
            }
        }
    }

    fn finalize_transaction(&mut self, txid: &[u8; 32]) {
        if let Some(pos) = self
            .submitted_transactions
            .iter()
            .position(|req| &req.txid == txid)
        {
            let submitted_tx = self.submitted_transactions.swap_remove(pos);
            for utxo in submitted_tx.used_utxos.iter() {
                self.forget_utxo(utxo);
            }
            self.finalized_requests_count += submitted_tx.requests.len() as u64;
            for request in submitted_tx.requests {
                self.push_finalized_request(FinalizedBtcRetrieval {
                    request,
                    state: FinalizedStatus::Confirmed { txid: *txid },
                });
            }
        } else {
            ic_cdk::trap(&format!(
                "Attempted to finalized a non-existent transaction {}",
                crate::tx::DisplayTxid(txid)
            ));
        }
    }

    /// Removes a pending retrive_btc request with the specified block index.
    fn remove_pending_request(&mut self, block_index: u64) -> Option<RetrieveBtcRequest> {
        match self
            .pending_retrieve_btc_requests
            .iter()
            .position(|req| req.block_index == block_index)
        {
            Some(pos) => Some(self.pending_retrieve_btc_requests.remove(pos)),
            None => None,
        }
    }

    /// Marks the specified retrieve_btc request as in-flight.
    ///
    /// # Panics
    ///
    /// This function panics if there is a pending retrieve_btc request with the
    /// same identifier.
    pub fn push_in_flight_request(&mut self, block_index: u64, status: InFlightStatus) {
        assert!(!self.has_pending_request(block_index));

        self.requests_in_flight.insert(block_index, status);
    }

    /// Returns a retrieve_btc requests back to the pending queue.
    ///
    /// # Panics
    ///
    /// This function panics if there is a pending retrieve_btc request with the
    /// same identifier.
    pub fn push_from_in_flight_to_pending_requests(
        &mut self,
        mut requests: Vec<RetrieveBtcRequest>,
    ) {
        for req in requests.iter() {
            assert!(!self.has_pending_request(req.block_index));
            self.requests_in_flight.remove(&req.block_index);
        }
        self.pending_retrieve_btc_requests.append(&mut requests);
        self.pending_retrieve_btc_requests
            .sort_by_key(|r| r.received_at);
    }

    /// Push back a retrieve_btc request to the ordered queue.
    ///
    /// # Panics
    ///
    /// This function panics if the new request breaks the request ordering in
    /// the queue.
    pub fn push_back_pending_request(&mut self, request: RetrieveBtcRequest) {
        if let Some(last_req) = self.pending_retrieve_btc_requests.last() {
            assert!(last_req.received_at <= request.received_at);
        }
        self.tokens_burned += request.amount;
        self.pending_retrieve_btc_requests.push(request);
    }

    /// Records a BTC transaction as submitted and updates statuses of all
    /// requests involved.
    ///
    /// # Panics
    ///
    /// This function panics if there is a pending retrieve_btc request with the
    /// same identifier as one of the request used for the transaction.
    pub fn push_submitted_transaction(&mut self, tx: SubmittedBtcTransaction) {
        for req in tx.requests.iter() {
            assert!(!self.has_pending_request(req.block_index));
            self.requests_in_flight.remove(&req.block_index);
        }
        self.submitted_transactions.push(tx);
    }

    /// Marks the specified retrieve_btc request as finalized.
    ///
    /// # Panics
    ///
    /// This function panics if there is a pending retrieve_btc request with the
    /// same identifier.
    fn push_finalized_request(&mut self, req: FinalizedBtcRetrieval) {
        assert!(!self.has_pending_request(req.request.block_index));

        if self.finalized_requests.len() >= MAX_FINALIZED_REQUESTS {
            self.finalized_requests.pop_front();
        }
        self.finalized_requests.push_back(req)
    }

    /// Checks whether the internal state of the minter matches the other state
    /// semantically (the state holds the same data, but maybe in a slightly
    /// different form).
    pub fn check_semantically_eq(&self, other: &Self) -> Result<(), String> {
        ensure_eq!(
            self.btc_network,
            other.btc_network,
            "btc_network does not match"
        );
        ensure_eq!(
            self.ecdsa_key_name,
            other.ecdsa_key_name,
            "ecdsa_key_name does not match"
        );
        ensure_eq!(
            self.min_confirmations,
            other.min_confirmations,
            "min_confirmations does not match"
        );
        ensure_eq!(self.ledger_id, other.ledger_id, "ledger_id does not match");
        ensure_eq!(
            self.finalized_requests,
            other.finalized_requests,
            "finalized_requests do not match"
        );
        ensure_eq!(
            self.requests_in_flight,
            other.requests_in_flight,
            "requests_in_flight do not match"
        );
        ensure_eq!(
            self.available_utxos,
            other.available_utxos,
            "available_utxos do not match"
        );
        ensure_eq!(
            self.utxos_state_addresses,
            other.utxos_state_addresses,
            "utxos_state_addresses do not match"
        );

        let my_txs = as_sorted_vec(self.submitted_transactions.iter().cloned(), |tx| tx.txid);
        let other_txs = as_sorted_vec(other.submitted_transactions.iter().cloned(), |tx| tx.txid);
        ensure_eq!(my_txs, other_txs, "submitted_transactions do not match");

        let my_requests = as_sorted_vec(self.pending_retrieve_btc_requests.iter().cloned(), |r| {
            r.block_index
        });
        let other_requests =
            as_sorted_vec(other.pending_retrieve_btc_requests.iter().cloned(), |r| {
                r.block_index
            });
        ensure_eq!(
            my_requests,
            other_requests,
            "pending_retrieve_btc_requests do not match"
        );

        Ok(())
    }
}

fn as_sorted_vec<T, K: Ord>(values: impl Iterator<Item = T>, key: impl Fn(&T) -> K) -> Vec<T> {
    let mut v: Vec<_> = values.collect();
    v.sort_by_key(key);
    v
}

impl From<InitArgs> for CkBtcMinterState {
    fn from(args: InitArgs) -> Self {
        Self {
            btc_network: args.btc_network,
            ecdsa_key_name: args.ecdsa_key_name,
            ecdsa_public_key: None,
            min_confirmations: args
                .min_confirmations
                .unwrap_or(crate::lifecycle::init::DEFAULT_MIN_CONFIRMATIONS),
            max_time_in_queue_nanos: args.max_time_in_queue_nanos,
            update_balance_principals: Default::default(),
            retrieve_btc_principals: Default::default(),
            retrieve_btc_min_amount: args.retrieve_btc_min_amount,
            pending_retrieve_btc_requests: Default::default(),
            requests_in_flight: Default::default(),
            submitted_transactions: Default::default(),
            finalized_requests: VecDeque::with_capacity(MAX_FINALIZED_REQUESTS),
            finalized_requests_count: 0,
            tokens_minted: 0,
            tokens_burned: 0,
            ledger_id: args.ledger_id,
            available_utxos: Default::default(),
            outpoint_account: Default::default(),
            utxos_state_addresses: Default::default(),
            finalized_utxos: Default::default(),
            is_timer_running: false,
            mode: args.mode,
        }
    }
}

/// Take the current state.
///
/// After calling this function the state won't be initialized anymore.
/// Panics if there is no state.
pub fn take_state<F, R>(f: F) -> R
where
    F: FnOnce(CkBtcMinterState) -> R,
{
    __STATE.with(|s| f(s.take().expect("State not initialized!")))
}

/// Mutates (part of) the current state using `f`.
///
/// Panics if there is no state.
pub fn mutate_state<F, R>(f: F) -> R
where
    F: FnOnce(&mut CkBtcMinterState) -> R,
{
    __STATE.with(|s| f(s.borrow_mut().as_mut().expect("State not initialized!")))
}

/// Read (part of) the current state using `f`.
///
/// Panics if there is no state.
pub fn read_state<F, R>(f: F) -> R
where
    F: FnOnce(&CkBtcMinterState) -> R,
{
    __STATE.with(|s| f(s.borrow().as_ref().expect("State not initialized!")))
}

/// Replaces the current state.
pub fn replace_state(state: CkBtcMinterState) {
    __STATE.with(|s| {
        *s.borrow_mut() = Some(state);
    });
}
