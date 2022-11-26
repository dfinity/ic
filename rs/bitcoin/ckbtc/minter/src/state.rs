///! State management module.
///!
///! The state is stored in the global thread-level variable `__STATE`.
///! This module provides utility functions to manage the state. Most
///! code should use those functions instead of touching `__STATE` directly.
use std::{
    cell::RefCell,
    collections::{BTreeMap, BTreeSet, VecDeque},
};

use crate::lifecycle::init::InitArgs;
use crate::{address::BitcoinAddress, ECDSAPublicKey};
use candid::{Deserialize, Principal};
use ic_base_types::CanisterId;
use ic_btc_types::{Network, OutPoint, Utxo};
use ic_icrc1::Account;
use serde::Serialize;

/// The maximum number of finalized BTC retrieval requests that we keep in the
/// history.
const MAX_FINALIZED_REQUESTS: usize = 100;

thread_local! {
    static __STATE: RefCell<Option<CkBtcMinterState>> = RefCell::default();
}

// A pending retrieve btc request
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RetrieveBtcRequest {
    pub amount: u64,
    pub address: BitcoinAddress,
    pub block_index: u64,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SubmittedBtcRetrieval {
    /// The original retrieve_btc request that initiated the transaction.
    pub request: RetrieveBtcRequest,
    /// The identifier of the unconfirmed transaction.
    pub txid: [u8; 32],
    /// The list of UTXOs we used in the transaction.
    pub used_utxos: Vec<Utxo>,
    /// The IC time at which we submitted the Bitcoin transaction.
    pub submitted_at: u64,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct FinalizedBtcRetrieval {
    /// The original retrieve_btc request that initiated the transaction.
    pub request: RetrieveBtcRequest,
    /// The state of the finalized request.
    pub state: FinalizedStatus,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum FinalizedStatus {
    /// The request amount was to low to cover the fees.
    AmountTooLow,
    /// The transaction that retrieves BTC got enough confirmations.
    Confirmed {
        /// The witness transaction identifier of the transaction.
        txid: [u8; 32],
    },
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum InFlightStatus {
    Signing,
    Sending { txid: [u8; 32] },
}

#[derive(candid::CandidType, Clone, Debug, PartialEq, Deserialize)]
pub enum RetrieveBtcStatus {
    Unknown,
    Pending,
    Signing,
    Sending { txid: [u8; 32] },
    Submitted { txid: [u8; 32] },
    AmountTooLow,
    Confirmed { txid: [u8; 32] },
}

/// The state of the ckBTC Minter.
///
/// Every piece of state of the Minter should be stored as field of this struct.
#[derive(Clone, Debug, serde::Deserialize, Serialize)]
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

    /// Per-principal lock for update_balance
    pub update_balance_principals: BTreeSet<Principal>,

    /// Per-principal lock for retrieve_btc
    pub retrieve_btc_principals: BTreeSet<Principal>,

    /// Minimum amount of bitcoin that can be retrieved
    pub retrieve_btc_min_amount: u64,

    /// Retrieve_btc requests that are waiting to be served
    pub pending_retrieve_btc_requests: VecDeque<RetrieveBtcRequest>,

    /// The identifiers of retrieve_btc requests which we're currently signing a
    /// transaction or sending to the Bitcoin network.
    pub requests_in_flight: BTreeMap<u64, InFlightStatus>,

    /// Processed retrieve_btc requests waiting for finalization.
    pub submitted_requests: Vec<SubmittedBtcRetrieval>,

    /// Finalized retrieve_btc requests for which we received enough confirmations.
    pub finalized_requests: VecDeque<FinalizedBtcRetrieval>,

    /// The CanisterId of the ckBTC Ledger
    pub ledger_id: CanisterId,

    /// The set of UTXOs unused in pending transactions.
    pub available_utxos: BTreeSet<Utxo>,

    /// The mapping from output points to the ledger accounts to which they
    /// belong.
    pub outpoint_account: BTreeMap<OutPoint, Account>,

    /// The map of known addresses to their utxos.
    pub utxos_state_addresses: BTreeMap<Account, BTreeSet<Utxo>>,

    /// Process one heartbeat at a time
    #[serde(skip)]
    pub is_heartbeat_running: bool,
}

impl CkBtcMinterState {
    pub fn check_invariants(&self) {
        for utxo in self.available_utxos.iter() {
            assert!(
                self.outpoint_account.contains_key(&utxo.outpoint),
                "the output_account map is missing an entry for {:?}",
                utxo.outpoint
            );

            assert!(
                self.utxos_state_addresses
                    .iter()
                    .any(|(_, utxos)| utxos.contains(utxo)),
                "available utxo {:?} does not belong to any account",
                utxo
            );
        }

        for (addr, utxos) in self.utxos_state_addresses.iter() {
            for utxo in utxos.iter() {
                assert_eq!(self.outpoint_account.get(&utxo.outpoint), Some(addr));
            }
        }
    }

    pub fn add_utxos(&mut self, account: Account, utxos: Vec<Utxo>) {
        if utxos.is_empty() {
            return;
        }

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
        self.check_invariants();
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

        if let Some(txid) = self
            .submitted_requests
            .iter()
            .find_map(|req| (req.request.block_index == block_index).then(|| req.txid))
        {
            return RetrieveBtcStatus::Submitted { txid };
        }

        match self
            .finalized_requests
            .iter()
            .find_map(|req| (req.request.block_index == block_index).then(|| req.state.clone()))
        {
            Some(FinalizedStatus::AmountTooLow) => return RetrieveBtcStatus::AmountTooLow,
            Some(FinalizedStatus::Confirmed { txid }) => {
                return RetrieveBtcStatus::Confirmed { txid }
            }
            None => (),
        }

        RetrieveBtcStatus::Unknown
    }

    /// Returns the total number of all retrieve_btc requests that we haven't
    /// finalized yet.
    pub fn count_incomplete_retrieve_btc_requests(&self) -> usize {
        self.pending_retrieve_btc_requests.len()
            + self.requests_in_flight.len()
            + self.submitted_requests.len()
    }

    /// Count the total of BTC managed by the minter at the moment
    pub fn count_total_btc(&self) -> u64 {
        self.available_utxos.iter().map(|u| u.value).sum::<u64>()
            + self
                .submitted_requests
                .iter()
                .map(|s| s.request.amount)
                .sum::<u64>()
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

    pub fn finalize_request(&mut self, block_index: u64) {
        if let Some(pos) = self
            .submitted_requests
            .iter()
            .position(|req| req.request.block_index == block_index)
        {
            let submitted_req = self.submitted_requests.swap_remove(pos);
            for utxo in submitted_req.used_utxos.iter() {
                self.forget_utxo(utxo);
            }
            self.push_finalized_request(FinalizedBtcRetrieval {
                request: submitted_req.request,
                state: FinalizedStatus::Confirmed {
                    txid: submitted_req.txid,
                },
            });
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

    /// Adds a new retrieve_btc request to the back of the queue.
    ///
    /// # Panics
    ///
    /// This function panics if there is a pending retrieve_btc request with the
    /// same identifier.
    pub fn push_pending_request(&mut self, req: RetrieveBtcRequest) {
        assert!(!self.has_pending_request(req.block_index));

        self.requests_in_flight.remove(&req.block_index);
        self.pending_retrieve_btc_requests.push_back(req);
    }

    /// Marks the specified retrieve_btc request as submitted.
    ///
    /// # Panics
    ///
    /// This function panics if there is a pending retrieve_btc request with the
    /// same identifier.
    pub fn push_submitted_request(&mut self, req: SubmittedBtcRetrieval) {
        assert!(!self.has_pending_request(req.request.block_index));

        self.requests_in_flight.remove(&req.request.block_index);
        self.submitted_requests.push(req);
    }

    /// Marks the specified retrieve_btc request as finalized.
    ///
    /// # Panics
    ///
    /// This function panics if there is a pending retrieve_btc request with the
    /// same identifier.
    pub fn push_finalized_request(&mut self, req: FinalizedBtcRetrieval) {
        assert!(!self.has_pending_request(req.request.block_index));

        if self.finalized_requests.len() >= MAX_FINALIZED_REQUESTS {
            self.finalized_requests.pop_front();
        }
        self.finalized_requests.push_back(req)
    }
}

impl From<InitArgs> for CkBtcMinterState {
    fn from(args: InitArgs) -> Self {
        Self {
            btc_network: args.btc_network,
            ecdsa_key_name: args.ecdsa_key_name,
            ecdsa_public_key: None,
            min_confirmations: crate::lifecycle::init::DEFAULT_MIN_CONFIRMATIONS,
            update_balance_principals: Default::default(),
            retrieve_btc_principals: Default::default(),
            retrieve_btc_min_amount: args.retrieve_btc_min_amount,
            pending_retrieve_btc_requests: Default::default(),
            requests_in_flight: Default::default(),
            submitted_requests: Default::default(),
            finalized_requests: VecDeque::with_capacity(MAX_FINALIZED_REQUESTS),
            ledger_id: args.ledger_id,
            available_utxos: Default::default(),
            outpoint_account: Default::default(),
            utxos_state_addresses: Default::default(),
            is_heartbeat_running: false,
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
