use crate::error::fs::ReadFileError;
use std::path::PathBuf;
use thiserror::Error;

/// The subset of dfx-core's `LoadDfxConfigError` (`error/load_dfx_config.rs`)
/// this crate needs, to read and parse a project's `dfx.json`. Omits variants
/// for machinery this crate doesn't replicate (extension canister types,
/// canonicalizing a config path via `Config::resolve_config_path`).
#[derive(Error, Debug)]
pub enum LoadDfxConfigError {
    #[error("Failed to load dfx configuration")]
    ReadFile(#[from] ReadFileError),

    #[error("Failed to deserialize json from {0}")]
    DeserializeValueFailed(Box<PathBuf>, #[source] serde_json::Error),
}
