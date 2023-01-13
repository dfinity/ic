pub use crate::state::Mode;
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

    /// Maximum time in nanoseconds that a transaction should spend in the queue
    /// before being sent.
    pub max_time_in_queue_nanos: u64,

    /// Specifies the minimum number of confirmations on the Bitcoin network
    /// required for the minter to accept a transaction.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_confirmations: Option<u32>,

    /// Flag that indicates if the minter is in read-only mode.
    #[serde(default)]
    pub mode: Mode,
}

pub fn init(args: InitArgs) {
    replace_state(CkBtcMinterState::from(args));
}
