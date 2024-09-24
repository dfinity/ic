pub use ic_btc_interface::{Address, OutPoint, Utxo};
use serde::{Deserialize, Serialize};

#[derive(Clone, Eq, PartialEq, Debug, candid::CandidType, Deserialize, Serialize)]
pub struct PushUtxoToAddress {
    pub address: Address,
    pub utxo: Utxo,
}
