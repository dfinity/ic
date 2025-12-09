use crate::lifecycle::upgrade::UpgradeArgs;
pub use crate::state::Mode;
use crate::state::{CkBtcMinterState, replace_state};
use crate::{CanisterRuntime, Network};
use candid::{CandidType, Deserialize};
use ic_base_types::CanisterId;
use serde::Serialize;

pub const DEFAULT_MIN_CONFIRMATIONS: u32 = 6;
pub const DEFAULT_CHECK_FEE: u64 = 1000;

#[derive(CandidType, serde::Deserialize)]
pub enum MinterArg {
    Init(InitArgs),
    Upgrade(Option<UpgradeArgs>),
}

#[derive(Clone, Eq, PartialEq, Debug, CandidType, Deserialize, Serialize)]
pub struct InitArgs {
    /// The Bitcoin network that the minter will connect to
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

    /// The mode controlling access to the minter.
    #[serde(default)]
    pub mode: Mode,

    /// The fee that the minter will pay for each Bitcoin check.
    /// NOTE: this field is optional for backward compatibility.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub check_fee: Option<u64>,

    /// The fee that the minter will pay for each KYT check.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[deprecated(note = "use check_fee instead")]
    pub kyt_fee: Option<u64>,

    /// The principal of the Bitcoin checker canister.
    /// NOTE: this field is optional for backward compatibility.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub btc_checker_principal: Option<CanisterId>,

    /// The principal of the kyt canister.
    /// NOTE: this field is optional for backward compatibility.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[deprecated(note = "use btc_checker_principal instead")]
    pub kyt_principal: Option<CanisterId>,

    /// The expiration duration in seconds) for cached entries in
    /// the get_utxos cache.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub get_utxos_cache_expiration_seconds: Option<u64>,

    /// The minimum number of available UTXOs required to trigger a consolidation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub utxo_consolidation_threshold: Option<u64>,
}

pub fn init<R: CanisterRuntime>(args: InitArgs, runtime: &R) {
    use crate::logs::Priority;
    use canlog::log;

    log!(
        Priority::Info,
        "[init]: Initializing canister with args {args:?}"
    );
    let state: CkBtcMinterState = CkBtcMinterState::from(args);
    runtime.validate_config(&state);
    replace_state(state);
}
