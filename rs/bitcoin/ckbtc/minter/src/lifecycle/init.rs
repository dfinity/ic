use crate::state::{replace_state, CkBtcMinterState};
use candid::{CandidType, Deserialize};
use ic_btc_types::Network;
use serde::Serialize;

#[derive(CandidType, Clone, Debug, Deserialize, Serialize, PartialEq)]
pub struct InitArgs {
    /// The bitcoin network that the minter will connect to
    pub btc_network: Network,

    /// The name of the [EcdsaKeyId]. Use "dfx_test_key" for local replica and "test_key_1" for
    /// a testing key for testnet and mainnet
    pub ecdsa_key_name: String,
}

pub fn init(args: InitArgs) {
    replace_state(CkBtcMinterState {
        btc_network: args.btc_network,
        ecdsa_key_name: args.ecdsa_key_name,
        ecdsa_public_key: None,
        update_balance_principals: Default::default(),
    });
}
