use crate::error::fs::EnsureDirExistsError;
use crate::error::get_user_home::GetUserHomeError;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ConfigError {
    #[error("failed to ensure config directory exists")]
    EnsureConfigDirectoryExistsFailed(#[source] EnsureDirExistsError),

    #[error("Failed to determine config directory path")]
    DetermineConfigDirectoryFailed(#[source] GetUserHomeError),
}
