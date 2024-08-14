use serde::{Deserialize, Serialize};
use std::default::Default;

/// The transport format specified in the ic.json
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(default)]
pub struct IPv4Config {
    pub public_address: String,
    pub public_gateway: String,
}
