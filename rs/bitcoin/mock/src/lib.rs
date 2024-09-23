pub use ic_btc_interface::{Address, OutPoint, Utxo};
use serde::{Deserialize, Serialize};

#[derive(Clone, Eq, PartialEq, Debug, Deserialize, Serialize, candid::CandidType)]
pub struct PushUtxoToAddress {
    pub address: Address,
    pub utxo: Utxo,
}
