//! Types used to support the candid API.

use ic_cdk::export::{
    candid::{CandidType, Deserialize},
    Principal,
};
use serde::Serialize;
use std::collections::{HashMap, HashSet};

pub type Satoshi = u64;

/// Initialization payload of the `ic-btc-library`.
#[derive(CandidType, Debug, Deserialize, PartialEq)]
pub struct InitPayload {
    pub bitcoin_canister_id: Principal,
}

/// A reference to a transaction output.
#[derive(CandidType, Clone, Debug, Deserialize, PartialEq, Eq, Hash)]
pub struct OutPoint {
    pub tx_id: Vec<u8>,
    pub vout: u32,
}

/// An unspent transaction output.
#[derive(CandidType, Debug, Deserialize, PartialEq, Clone, Hash, Eq)]
pub struct Utxo {
    pub outpoint: OutPoint,
    pub value: Satoshi,
    pub height: u32,
    pub confirmations: u32,
}

/// A request for getting the UTXOs for a given address.
#[derive(CandidType, Debug, Deserialize, PartialEq)]
pub struct GetUtxosRequest {
    pub address: String,
    pub min_confirmations: Option<u32>,
}

#[derive(CandidType, Debug, Deserialize, PartialEq)]
pub struct GetUtxosResponse {
    pub utxos: Vec<Utxo>,
    pub total_count: u32,
}

/// Errors when requesting a `get_utxos` to the Bitcoin canister.
#[derive(CandidType, Debug, Deserialize, PartialEq)]
pub enum BitcoinCanisterGetUtxosError {
    MalformedAddress,
}

/// Errors when processing a `get_utxos` request.
#[derive(CandidType, Debug, Deserialize, PartialEq)]
pub enum GetUtxosError {
    MalformedAddress,
    MinConfirmationsTooHigh,
}

impl From<BitcoinCanisterGetUtxosError> for GetUtxosError {
    fn from(bitcoin_canister_get_utxos_error: BitcoinCanisterGetUtxosError) -> Self {
        match bitcoin_canister_get_utxos_error {
            BitcoinCanisterGetUtxosError::MalformedAddress => GetUtxosError::MalformedAddress,
        }
    }
}

#[derive(CandidType, Debug, Deserialize, PartialEq)]
pub struct SendTransactionRequest {
    pub transaction: Vec<u8>,
}

/// Errors when requesting a `send_transaction` to the Bitcoin canister.
#[derive(CandidType, Debug, Deserialize, PartialEq)]
pub enum SendTransactionError {
    MalformedTransaction,
}

/// ECDSA public key and chain code.
#[derive(CandidType, Debug, Deserialize, PartialEq, Clone)]
pub struct EcdsaPubKey {
    pub public_key: Vec<u8>,
    pub chain_code: Vec<u8>,
    pub derivation_path: Vec<Vec<u8>>,
}

/// Address types supported by the `ic-btc-library`.
#[derive(CandidType, Debug, Deserialize, PartialEq, Clone, Copy)]
pub enum AddressType {
    P2pkh,
    P2sh,
    P2wpkh,
}

/// Error when processing an `add_address` request.
#[derive(CandidType, Debug, Deserialize, PartialEq)]
pub struct DerivationPathTooLong;

/// Contains the information which UTXOs were added and removed since a given moment.
#[derive(CandidType, Debug, Deserialize, PartialEq, Clone)]
pub struct UtxosUpdate {
    pub added_utxos: Vec<Utxo>,
    pub removed_utxos: Vec<Utxo>,
}

impl UtxosUpdate {
    pub fn new() -> Self {
        Self {
            added_utxos: vec![],
            removed_utxos: vec![],
        }
    }
}

impl Default for UtxosUpdate {
    fn default() -> Self {
        Self::new()
    }
}

/// Returns a `HashSet<Utxo>` from the given UTXOs vector reference.
fn to_hashset(state: &[Utxo]) -> HashSet<Utxo> {
    HashSet::from_iter(state.iter().cloned())
}

/// Returns `state_0`'s UTXOs that aren't in `state_1`.
fn state_difference(state_0: &HashSet<Utxo>, state_1: &HashSet<Utxo>) -> Vec<Utxo> {
    state_0
        .difference(state_1)
        .collect::<Vec<&Utxo>>()
        .into_iter()
        .cloned()
        .collect()
}

impl UtxosUpdate {
    /// Returns an `UtxosUpdate` defined by the changes in the UTXOs set between `seen_state` and `unseen_state`.
    pub fn from_state(seen_state: &[Utxo], unseen_state: &[Utxo]) -> Self {
        let seen_state_hashset = &to_hashset(seen_state);
        let unseen_state_hashset = &to_hashset(unseen_state);
        UtxosUpdate {
            added_utxos: state_difference(unseen_state_hashset, seen_state_hashset),
            removed_utxos: state_difference(seen_state_hashset, unseen_state_hashset),
        }
    }
}

/// Represents the last seen state and the unseen state UTXOs for a given `min_confirmations`.
#[derive(CandidType, Debug, Deserialize, PartialEq, Clone)]
pub struct UtxosState {
    pub seen_state: Vec<Utxo>,
    pub unseen_state: Vec<Utxo>,
    pub min_confirmations: u32,
}

impl UtxosState {
    pub fn new(min_confirmations: u32) -> Self {
        Self {
            seen_state: vec![],
            unseen_state: vec![],
            min_confirmations,
        }
    }
}

#[derive(CandidType, Debug, Deserialize, PartialEq, Clone)]
pub struct AddressNotTracked;

/// Represents the last seen state and the unseen state balances for a given `min_confirmations`.
#[derive(CandidType, Debug, Deserialize, PartialEq, Clone)]
pub struct BalanceUpdate {
    pub added_balance: Satoshi,
    pub removed_balance: Satoshi,
}

impl BalanceUpdate {
    pub fn new() -> Self {
        Self {
            added_balance: 0,
            removed_balance: 0,
        }
    }
}

impl Default for BalanceUpdate {
    fn default() -> Self {
        Self::new()
    }
}

/// Returns the total value of a UTXOs set.
pub(crate) fn get_balance_from_utxos(utxos: &[Utxo]) -> Satoshi {
    utxos.iter().map(|utxo| utxo.value).sum()
}

impl From<UtxosUpdate> for BalanceUpdate {
    fn from(utxos_update: UtxosUpdate) -> Self {
        Self {
            added_balance: get_balance_from_utxos(&utxos_update.added_utxos),
            removed_balance: get_balance_from_utxos(&utxos_update.removed_utxos),
        }
    }
}

/// Represents a Bitcoin network which is compatible with Candid.
#[derive(CandidType, Debug, Deserialize, Serialize, Copy, PartialEq, Clone, Eq, Hash)]
pub enum Network {
    Bitcoin,
    Testnet,
    Regtest,
}

impl From<Network> for bitcoin::Network {
    fn from(network: Network) -> Self {
        match network {
            Network::Bitcoin => bitcoin::Network::Bitcoin,
            Network::Testnet => bitcoin::Network::Testnet,
            Network::Regtest => bitcoin::Network::Regtest,
        }
    }
}

impl From<bitcoin::Network> for Network {
    fn from(network: bitcoin::Network) -> Self {
        match network {
            bitcoin::Network::Bitcoin => Network::Bitcoin,
            bitcoin::Network::Testnet => Network::Testnet,
            bitcoin::Network::Regtest => Network::Regtest,
            // Other cases can't happen see BitcoinCanister::new
            _ => panic!(),
        }
    }
}

/// Needs to use `(String, Network)` to describe an address otherwise there is an ambiguity between testnet and regtest because of the same address prefix.
pub type AddressUsingPrimitives = (String, Network);

/// Represents the Bitcoin agent state used for canister upgrades.
#[derive(CandidType, Debug, Deserialize, PartialEq, Clone)]
pub struct BitcoinAgentState {
    pub network: Network,
    pub main_address_type: AddressType,
    pub ecdsa_pub_key_addresses: HashMap<AddressUsingPrimitives, EcdsaPubKey>,
    pub utxos_state_addresses: HashMap<AddressUsingPrimitives, UtxosState>,
}

/// The upper bound on the minimum number of confirmations supported by the Bitcoin integration.
pub const STABILITY_THRESHOLD: u32 = 6;

#[derive(CandidType, Debug, Deserialize, PartialEq)]
pub struct MinConfirmationsTooHigh;

/// Error when processing an `add_address_with_parameters` request.
#[derive(CandidType, Debug, Deserialize, PartialEq)]
pub enum AddAddressWithParametersError {
    DerivationPathTooLong,
    MinConfirmationsTooHigh,
}
