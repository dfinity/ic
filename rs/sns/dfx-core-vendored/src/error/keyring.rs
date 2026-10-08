use crate::error::structured_file::StructuredFileError;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum KeyringError {
    #[error("Failed to decode pem from keyring")]
    DecodePemFailed(#[source] hex::FromHexError),

    #[error("Failed to get password for keyring")]
    GetPasswordFailed(#[source] keyring::Error),

    #[error("Failed to create entry for keyring")]
    NewEntryFailed(#[source] keyring::Error),

    #[error("Failed to load mock keyring")]
    LoadMockKeyringFailed(#[source] StructuredFileError),

    #[error("Mock Keyring: key {0} not found")]
    MockKeyNotFound(String),

    #[error("Mock keyring unavailable - access rejected.")]
    MockUnavailable(),

    #[error(transparent)]
    MaintenanceRequired(#[from] KeyringMaintenanceError),
}

#[derive(Error, Debug)]
#[error("\
A macOS issue prevents arm64 versions of dfx from accessing your identities while an x64 version of dfx also has access.

You will need to go into Keychain Access and remove dfx from the 'Access Control' tab of all 'internet_computer_identities' keys.

For more information, see the dfx 0.28.0 migration guide: https://github.com/dfinity/sdk/blob/0.28.0/docs/migration/dfx-0.28.0-migration-guide.md
")]
pub struct KeyringMaintenanceError;
