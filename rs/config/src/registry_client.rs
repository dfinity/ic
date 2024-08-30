use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// The replica only reads registry data from the local store.
/// The orchestrator both reads from and writes to the registry local store.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    pub local_store: PathBuf,
}
