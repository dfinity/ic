use serde::{Deserialize, Serialize};

/// Configuration of the NNS Registry Replicator.
///
/// This should eventually replace the registry client configuration. The path
/// to the local store is taken from the registry client configuration, iff the
/// LocalStore is configured as the DataProvider.
///
/// Eventually, the local store will replace all other data providers.
#[derive(Clone, Eq, PartialEq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct Config {
    /// The duration to
    pub poll_delay_duration_ms: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            poll_delay_duration_ms: 5000,
        }
    }
}
