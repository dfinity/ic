use ic_base_types::CanisterId;
use serde::{Deserialize, Serialize};

/// Engine management canister on mainnet. Other environments have to configure
/// their own via the `cloud_engine` section of `ic.json5`.
pub const MAINNET_ENGINE_MANAGEMENT_CANISTER_ID: &str = "q6cfj-fyaaa-aaaar-qb77q-cai";

/// Configuration that only cloud engine nodes use.
#[derive(Clone, Eq, PartialEq, Hash, Debug, Default, Deserialize, Serialize)]
pub struct Config {
    /// Principal of the engine management canister, which an all-in-one node
    /// needs to discover the operator canister of its own engine. When unset,
    /// the node cannot find its operator and therefore does not run `ic-gateway`.
    #[serde(default)]
    pub engine_management_canister_id: Option<CanisterId>,
}
