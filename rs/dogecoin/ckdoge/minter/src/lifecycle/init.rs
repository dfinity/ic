use candid::{CandidType, Deserialize, Principal};
use ic_ckbtc_minter::lifecycle::init::InitArgs as CkbtcMinterInitArgs;
use serde::Serialize;

pub use ic_ckbtc_minter::state::Mode;

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

    /// The minimum number of available UTXOs required to trigger a consolidation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub utxo_consolidation_threshold: Option<u64>,

    /// The maximum number of input UTXOs allowed in a transaction.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_num_inputs_in_transaction: Option<u64>,
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
    fn from(
        InitArgs {
            doge_network,
            ecdsa_key_name,
            retrieve_doge_min_amount,
            ledger_id,
            max_time_in_queue_nanos,
            min_confirmations,
            mode,
            get_utxos_cache_expiration_seconds,
            utxo_consolidation_threshold,
            max_num_inputs_in_transaction,
        }: InitArgs,
    ) -> Self {
        CkbtcMinterInitArgs {
            btc_network: ic_ckbtc_minter::Network::from(doge_network),
            ecdsa_key_name,
            retrieve_btc_min_amount: retrieve_doge_min_amount,
            ledger_id: ledger_id
                .as_slice()
                .try_into()
                .expect("ERROR: invalid canister ID"),
            max_time_in_queue_nanos,
            min_confirmations,
            mode,
            check_fee: Some(0),
            #[allow(deprecated)]
            kyt_fee: None,
            btc_checker_principal: None,
            #[allow(deprecated)]
            kyt_principal: None,
            get_utxos_cache_expiration_seconds,
            utxo_consolidation_threshold,
            max_num_inputs_in_transaction,
        }
    }
}

#[allow(deprecated)]
impl From<CkbtcMinterInitArgs> for InitArgs {
    fn from(
        CkbtcMinterInitArgs {
            btc_network,
            ecdsa_key_name,
            retrieve_btc_min_amount,
            ledger_id,
            max_time_in_queue_nanos,
            min_confirmations,
            mode,
            check_fee: _,
            kyt_fee: _,
            btc_checker_principal: _,
            kyt_principal: _,
            get_utxos_cache_expiration_seconds,
            utxo_consolidation_threshold,
            max_num_inputs_in_transaction,
        }: CkbtcMinterInitArgs,
    ) -> Self {
        InitArgs {
            doge_network: Network::from(btc_network),
            ecdsa_key_name,
            retrieve_doge_min_amount: retrieve_btc_min_amount,
            ledger_id: ledger_id.into(),
            max_time_in_queue_nanos,
            min_confirmations,
            mode,
            get_utxos_cache_expiration_seconds,
            utxo_consolidation_threshold,
            max_num_inputs_in_transaction,
        }
    }
}
