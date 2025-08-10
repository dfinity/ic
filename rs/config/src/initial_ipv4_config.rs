use serde::{Deserialize, Serialize};
use std::default::Default;

/// The transport format specified in the ic.json
#[derive(Clone, Eq, PartialEq, Hash, Debug, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct IPv4Config {
    pub public_address: String,
    pub public_gateway: String,
}
