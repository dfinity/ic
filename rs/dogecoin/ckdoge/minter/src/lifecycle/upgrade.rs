use candid::{CandidType, Deserialize};
use ic_ckbtc_minter::lifecycle::upgrade::UpgradeArgs as CkbtcMinterUpgradeArgs;
use ic_ckbtc_minter::state::Mode;
use serde::Serialize;

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

    /// The minimum number of available UTXOs required to trigger a consolidation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub utxo_consolidation_threshold: Option<u64>,

    /// The maximum number of input UTXOs allowed in a transaction.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_num_inputs_in_transaction: Option<u64>,
}

impl From<UpgradeArgs> for CkbtcMinterUpgradeArgs {
    fn from(
        UpgradeArgs {
            retrieve_doge_min_amount,
            min_confirmations,
            max_time_in_queue_nanos,
            mode,
            get_utxos_cache_expiration_seconds,
            utxo_consolidation_threshold,
            max_num_inputs_in_transaction,
        }: UpgradeArgs,
    ) -> Self {
        CkbtcMinterUpgradeArgs {
            retrieve_btc_min_amount: retrieve_doge_min_amount,
            min_confirmations,
            max_time_in_queue_nanos,
            mode,
            get_utxos_cache_expiration_seconds,
            utxo_consolidation_threshold,
            max_num_inputs_in_transaction,
            ..CkbtcMinterUpgradeArgs::default()
        }
    }
}

impl From<CkbtcMinterUpgradeArgs> for UpgradeArgs {
    fn from(
        CkbtcMinterUpgradeArgs {
            retrieve_btc_min_amount,
            min_confirmations,
            max_time_in_queue_nanos,
            mode,
            check_fee: _,
            #[allow(deprecated)]
                kyt_fee: _,
            btc_checker_principal: _,
            #[allow(deprecated)]
                kyt_principal: _,
            get_utxos_cache_expiration_seconds,
            utxo_consolidation_threshold,
            max_num_inputs_in_transaction,
        }: CkbtcMinterUpgradeArgs,
    ) -> Self {
        UpgradeArgs {
            retrieve_doge_min_amount: retrieve_btc_min_amount,
            min_confirmations,
            max_time_in_queue_nanos,
            mode,
            get_utxos_cache_expiration_seconds,
            utxo_consolidation_threshold,
            max_num_inputs_in_transaction,
        }
    }
}
