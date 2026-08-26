use serde::{Deserialize, Serialize};

/// Configuration that only cloud engine nodes use.
#[derive(Clone, Eq, PartialEq, Hash, Debug, Default, Deserialize, Serialize)]
pub struct Config {
    /// Principal of the engine management canister, which an all-in-one node
    /// needs to discover the operator canister of its own engine. When unset,
    /// the node cannot find its operator and therefore does not run `ic-gateway`.
    pub engine_management_canister_id: Option<String>,
}
