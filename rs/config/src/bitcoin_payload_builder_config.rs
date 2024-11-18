use serde::{Deserialize, Serialize};
use std::time::Duration;

#[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
#[serde(default)]
pub struct Config {
    /// The duration bitcoin adapters have to respond before timing out.
    #[serde(default = "adapter_timeout_default")]
    pub adapter_timeout: Duration,
}

fn adapter_timeout_default() -> Duration {
    Duration::from_millis(50)
}

impl Default for Config {
    fn default() -> Self {
        Self {
            adapter_timeout: adapter_timeout_default(),
        }
    }
}
