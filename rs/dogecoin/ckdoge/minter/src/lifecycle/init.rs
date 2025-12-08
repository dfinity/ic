use candid::{CandidType, Deserialize, Principal};
use ic_ckbtc_minter::lifecycle::{
    init::InitArgs as CkbtcMinterInitArgs, upgrade::UpgradeArgs as CkbtcMinterUpgradeArgs,
};
use serde::Serialize;

pub use ic_ckbtc_minter::state::Mode;

#[derive(CandidType, serde::Deserialize)]
pub enum MinterArg {
    Init(InitArgs),
    Upgrade(Option<UpgradeArgs>),
}

#[derive(Clone, Eq, PartialEq, Debug, CandidType, Deserialize, Serialize)]
pub struct InitArgs {
    /// The Dogecoin network that the minter will connect to
    pub doge_network: Network,

    /// The name of the [EcdsaKeyId]. Use "dfx_test_key" for local replica and "test_key_1" for
    /// a testing key for testnet and mainnet
    pub ecdsa_key_name: String,

    /// Minimum amount of dogecoin that can be retrieved
    pub retrieve_doge_min_amount: u64,

    /// The CanisterId of the ckDOGE Ledger
    pub ledger_id: Principal,

    /// Maximum time in nanoseconds that a transaction should spend in the queue
    /// before being sent.
    pub max_time_in_queue_nanos: u64,

    /// Specifies the minimum number of confirmations on the Dogecoin network
    /// required for the minter to accept a transaction.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_confirmations: Option<u32>,

    /// The mode controlling access to the minter.
    #[serde(default)]
    pub mode: Mode,

    /// The expiration duration in seconds) for cached entries in
    /// the get_utxos cache.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub get_utxos_cache_expiration_seconds: Option<u64>,
}

#[derive(Clone, Eq, PartialEq, Debug, Default, CandidType, Deserialize, Serialize)]
pub struct UpgradeArgs {
    /// Minimum amount of doge that can be retrieved.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retrieve_doge_min_amount: Option<u64>,

    /// Specifies the minimum number of confirmations on the Dogecoin network
    /// required for the minter to accept a transaction.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_confirmations: Option<u32>,

    /// Maximum time in nanoseconds that a transaction should spend in the queue
    /// before being sent.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_time_in_queue_nanos: Option<u64>,

    /// The mode in which the minter is running.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mode: Option<Mode>,

    /// The expiration duration (in seconds) for cached entries in
    /// the get_utxos cache.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub get_utxos_cache_expiration_seconds: Option<u64>,
}

#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug, CandidType, Deserialize, Serialize)]
pub enum Network {
    Mainnet,
    Testnet,
    Regtest,
}

impl From<ic_ckbtc_minter::Network> for Network {
    fn from(network: ic_ckbtc_minter::Network) -> Self {
        match network {
            ic_ckbtc_minter::Network::Mainnet => Self::Mainnet,
            ic_ckbtc_minter::Network::Testnet => Self::Testnet,
            ic_ckbtc_minter::Network::Regtest => Self::Regtest,
        }
    }
}

impl From<Network> for ic_ckbtc_minter::Network {
    fn from(network: Network) -> Self {
        match network {
            Network::Mainnet => ic_ckbtc_minter::Network::Mainnet,
            Network::Testnet => ic_ckbtc_minter::Network::Testnet,
            Network::Regtest => ic_ckbtc_minter::Network::Regtest,
        }
    }
}

impl std::fmt::Display for Network {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Self::Mainnet => write!(f, "mainnet"),
            Self::Testnet => write!(f, "testnet"),
            Self::Regtest => write!(f, "regtest"),
        }
    }
}

impl From<InitArgs> for CkbtcMinterInitArgs {
    fn from(args: InitArgs) -> Self {
        CkbtcMinterInitArgs {
            btc_network: ic_ckbtc_minter::Network::from(args.doge_network),
            ecdsa_key_name: args.ecdsa_key_name,
            retrieve_btc_min_amount: args.retrieve_doge_min_amount,
            ledger_id: args
                .ledger_id
                .as_slice()
                .try_into()
                .expect("ERROR: invalid canister ID"),
            max_time_in_queue_nanos: args.max_time_in_queue_nanos,
            min_confirmations: args.min_confirmations,
            mode: args.mode,
            check_fee: Some(0),
            #[allow(deprecated)]
            kyt_fee: None,
            btc_checker_principal: None,
            #[allow(deprecated)]
            kyt_principal: None,
            get_utxos_cache_expiration_seconds: args.get_utxos_cache_expiration_seconds,
        }
    }
}

impl From<UpgradeArgs> for CkbtcMinterUpgradeArgs {
    fn from(
        UpgradeArgs {
            retrieve_doge_min_amount,
            min_confirmations,
            max_time_in_queue_nanos,
            mode,
            get_utxos_cache_expiration_seconds,
        }: UpgradeArgs,
    ) -> Self {
        CkbtcMinterUpgradeArgs {
            retrieve_btc_min_amount: retrieve_doge_min_amount,
            min_confirmations,
            max_time_in_queue_nanos,
            mode,
            get_utxos_cache_expiration_seconds,
            ..CkbtcMinterUpgradeArgs::default()
        }
    }
}
