//! Types used to support the candid API.

use crate::{Satoshi, Utxo};
use ic_cdk::export::candid::{CandidType, Deserialize};
use std::collections::{HashMap, HashSet};

#[derive(CandidType, Debug, Deserialize, PartialEq, Clone, Eq, Hash)]
pub enum Network {
    Mainnet,
    Testnet,
    #[cfg(locally)]
    Regtest,
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

#[derive(CandidType, Debug, Deserialize, PartialEq)]
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

pub(crate) fn from_types_network_to_bitcoin_network(network: Network) -> bitcoin::Network {
    match network {
        Network::Mainnet => bitcoin::Network::Bitcoin,
        Network::Testnet => bitcoin::Network::Testnet,
        #[cfg(locally)]
        Network::Regtest => bitcoin::Network::Regtest,
    }
}

pub(crate) fn from_bitcoin_network_to_ic_btc_types_network(
    network: bitcoin::Network,
) -> ic_btc_types::Network {
    match network {
        bitcoin::Network::Bitcoin => ic_btc_types::Network::Mainnet,
        bitcoin::Network::Testnet => ic_btc_types::Network::Testnet,
        bitcoin::Network::Regtest => ic_btc_types::Network::Regtest,
        // Other cases can't happen see BitcoinCanister::new
        _ => panic!(),
    }
}

pub(crate) fn from_bitcoin_network_to_types_network(network: bitcoin::Network) -> Network {
    match network {
        bitcoin::Network::Bitcoin => Network::Mainnet,
        bitcoin::Network::Testnet => Network::Testnet,
        #[cfg(locally)]
        bitcoin::Network::Regtest => Network::Regtest,
        // Other cases can't happen see BitcoinCanister::new
        _ => panic!(),
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
