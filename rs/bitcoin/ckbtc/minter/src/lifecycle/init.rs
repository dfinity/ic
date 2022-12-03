use crate::state::{replace_state, CkBtcMinterState};
use candid::{CandidType, Deserialize};
use ic_base_types::CanisterId;
use ic_btc_types::Network;
use serde::Serialize;

pub const DEFAULT_MIN_CONFIRMATIONS: u32 = 6;

#[derive(CandidType, Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct InitArgs {
    /// The bitcoin network that the minter will connect to
    pub btc_network: Network,

    /// The name of the [EcdsaKeyId]. Use "dfx_test_key" for local replica and "test_key_1" for
    /// a testing key for testnet and mainnet
    pub ecdsa_key_name: String,

    /// Minimum amount of bitcoin that can be retrieved
    pub retrieve_btc_min_amount: u64,

    /// The CanisterId of the ckBTC Ledger
    pub ledger_id: CanisterId,
}

pub fn init(args: InitArgs) {
    replace_state(CkBtcMinterState::from(args));
}
