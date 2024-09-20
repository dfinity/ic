use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// The replica only reads registry data from the local store.
/// The orchestrator both reads from and writes to the registry local store.
#[derive(Clone, Eq, PartialEq, Debug, Default, Deserialize, Serialize)]
pub struct Config {
    pub local_store: PathBuf,
}
