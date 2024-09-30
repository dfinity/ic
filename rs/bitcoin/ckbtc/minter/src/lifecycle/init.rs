use crate::lifecycle::upgrade::UpgradeArgs;
pub use crate::state::Mode;
use crate::state::{replace_state, CkBtcMinterState};
use candid::{CandidType, Deserialize};
use ic_base_types::CanisterId;
use ic_btc_interface::Network;
use serde::Serialize;

pub const DEFAULT_MIN_CONFIRMATIONS: u32 = 6;
pub const DEFAULT_KYT_FEE: u64 = 1000;

#[derive(CandidType, serde::Deserialize)]
pub enum MinterArg {
    Init(InitArgs),
    Upgrade(Option<UpgradeArgs>),
}

// TODO: Use `ic_btc_interface::Network` directly.
// The Bitcoin canister's network enum no longer has snake-case versions
// (refer to [PR171](https://github.com/dfinity/bitcoin-canister/pull/171)),
// instead it uses lower-case candid variants.
// A temporary fix for ckbtc minter is to create a new enum with capital letter variants.
#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug, CandidType, Deserialize, Serialize)]
pub enum BtcNetwork {
    Mainnet,
    Testnet,
    Regtest,
}

impl From<BtcNetwork> for Network {
    fn from(network: BtcNetwork) -> Self {
        match network {
            BtcNetwork::Mainnet => Network::Mainnet,
            BtcNetwork::Testnet => Network::Testnet,
            BtcNetwork::Regtest => Network::Regtest,
        }
    }
}

impl From<Network> for BtcNetwork {
    fn from(network: Network) -> Self {
        match network {
            Network::Mainnet => BtcNetwork::Mainnet,
            Network::Testnet => BtcNetwork::Testnet,
            Network::Regtest => BtcNetwork::Regtest,
        }
    }
}

#[derive(Clone, Eq, PartialEq, Debug, CandidType, Deserialize, Serialize)]
pub struct InitArgs {
    /// The bitcoin network that the minter will connect to
    pub btc_network: BtcNetwork,

    /// The name of the [EcdsaKeyId]. Use "dfx_test_key" for local replica and "test_key_1" for
    /// a testing key for testnet and mainnet
    pub ecdsa_key_name: String,

    /// Minimum amount of bitcoin that can be retrieved
    pub retrieve_btc_min_amount: u64,

    /// The CanisterId of the ckBTC Ledger
    pub ledger_id: CanisterId,

    /// Maximum time in nanoseconds that a transaction should spend in the queue
    /// before being sent.
    pub max_time_in_queue_nanos: u64,

    /// Specifies the minimum number of confirmations on the Bitcoin network
    /// required for the minter to accept a transaction.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_confirmations: Option<u32>,

    /// The mode controlling access to the minter.
    #[serde(default)]
    pub mode: Mode,

    /// The fee that the minter will pay for each KYT check.
    /// NOTE: this field is optional for backward compatibility.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kyt_fee: Option<u64>,

    /// The principal of the KYT canister.
    /// NOTE: this field is optional for backward compatibility.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kyt_principal: Option<CanisterId>,
}

pub fn init(args: InitArgs) {
    let state: CkBtcMinterState = CkBtcMinterState::from(args);
    state.validate_config();
    replace_state(state);
}
