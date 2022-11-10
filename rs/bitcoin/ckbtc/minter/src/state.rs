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

thread_local! {
    static __STATE: RefCell<Option<CkBtcMinterState>> = RefCell::default();
}

// A pending retrieve btc request
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RetrieveBtcRequest {
    pub amount: u64,
    pub address: BitcoinAddress,
    pub fee: u64,
    pub block_index: u64,
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

    /// Minimum fee for retrieve_btc bitcoin transactions
    pub retrieve_btc_min_fee: u64,

    /// Minimum amount of bitcoin that can be retrieved
    pub retrieve_btc_min_amount: u64,

    /// Retrieve_btc requests that are waiting to be served
    pub pending_retrieve_btc_requests: VecDeque<RetrieveBtcRequest>,

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
            retrieve_btc_min_fee: args.retrieve_btc_min_fee,
            retrieve_btc_min_amount: args.retrieve_btc_min_amount,
            pending_retrieve_btc_requests: Default::default(),
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
