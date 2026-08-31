use crate::error::config::ConfigError;
use crate::error::structured_file::StructuredFileError;
use thiserror::Error;

/// Copied (name + shape) from dfx-core's `LoadNetworksConfigError`
/// (`error/load_networks_config.rs`).
#[derive(Error, Debug)]
pub enum LoadNetworksConfigError {
    #[error("Failed to get path for network configuration")]
    GetConfigPathFailed(#[source] ConfigError),

    #[error("Failed to load network configuration")]
    LoadConfigFromFileFailed(#[source] StructuredFileError),
}
