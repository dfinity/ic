pub use ic_btc_interface::{Address, Network, OutPoint, Utxo};
use serde::{Deserialize, Serialize};

#[derive(Clone, Eq, PartialEq, Debug, Deserialize, Serialize, candid::CandidType)]
pub struct PushUtxosToAddress {
    pub address: Address,
    pub utxos: Vec<Utxo>,
}
