use crate::error::{
    config::ConfigError, encryption::EncryptionError, fs::ReadFileError,
    get_user_home::GetUserHomeError, keyring::KeyringError, structured_file::StructuredFileError,
};
use ic_agent::identity::PemError;
use ic_identity_hsm::HardwareIdentityError;
use std::path::PathBuf;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum GetIdentityConfigOrDefaultError {
    #[error("Failed to load configuration for identity '{0}'")]
    LoadIdentityConfigurationFailed(String, #[source] StructuredFileError),
}

#[derive(Error, Debug)]
pub enum GetLegacyCredentialsPemPathError {
    #[error("Failed to get legacy pem path")]
    GetLegacyPemPathFailed(#[source] GetUserHomeError),
}

#[derive(Error, Debug)]
pub enum InstantiateIdentityFromNameError {
    #[error("Failed to get principal of identity: {0}")]
    GetIdentityPrincipalFailed(String),

    #[error("Failed to load identity")]
    LoadIdentityFailed(#[source] LoadIdentityError),

    #[error("Identity must exist")]
    RequireIdentityExistsFailed(#[source] RequireIdentityExistsError),
}

#[derive(Error, Debug)]
pub enum LoadIdentityError {
    #[error("Failed to get identity config")]
    GetIdentityConfigOrDefaultFailed(#[source] GetIdentityConfigOrDefaultError),

    #[error("Failed to instantiate identity")]
    NewIdentityFailed(#[source] NewIdentityError),
}

#[derive(Error, Debug)]
pub enum LoadPemError {
    #[error("Failed to load PEM file from file")]
    LoadFromFileFailed(#[source] LoadPemFromFileError),

    #[error("Failed to load PEM file from keyring for identity '{0}'")]
    LoadFromKeyringFailed(Box<String>, #[source] KeyringError),
}

#[derive(Error, Debug)]
pub enum LoadPemFromFileError {
    #[error("Failed to decrypt PEM file at {0}")]
    DecryptPemFileFailed(PathBuf, #[source] EncryptionError),

    #[error("failed to read pem file")]
    ReadPemFileFailed(#[from] ReadFileError),
}

#[derive(Error, Debug)]
pub enum LoadPemIdentityError {
    #[error("Cannot read identity file '{0}'")]
    ReadIdentityFileFailed(String, #[source] Box<PemError>),
}

#[derive(Error, Debug)]
pub enum NewHardwareIdentityError {
    #[error("Failed to instantiate hardware identity for identity '{0}'")]
    InstantiateHardwareIdentityFailed(String, #[source] Box<HardwareIdentityError>),
}

#[derive(Error, Debug)]
pub enum NewIdentityError {
    #[error("Failed to load PEM")]
    LoadPemFailed(#[source] LoadPemError),

    #[error("Failed to load PEM identity")]
    LoadPemIdentityFailed(#[source] LoadPemIdentityError),

    #[error("Failed to instantiate hardware identity")]
    NewHardwareIdentityFailed(#[source] NewHardwareIdentityError),
}

#[derive(Error, Debug)]
pub enum NewIdentityManagerError {
    #[error("Failed to get config directory for identity manager")]
    GetConfigDirectoryFailed(#[source] ConfigError),

    #[error("Failed to load identity manager configuration")]
    LoadIdentityManagerConfigurationFailed(#[source] StructuredFileError),

    #[error("The specified identity must exist")]
    OverrideIdentityMustExist(#[source] RequireIdentityExistsError),

    #[error(r#"No identity configuration found.  Please run "dfx identity get-principal" or "dfx identity new <identity name>" to create a new identity."#)]
    NoIdentityConfigurationFound,
}

#[derive(Error, Debug)]
pub enum RequireIdentityExistsError {
    #[error("Identity {0} does not exist at '{1}'.")]
    IdentityDoesNotExist(String, PathBuf),

    #[error("An Identity named {0} cannot be created as it is reserved for internal use.")]
    ReservedIdentityName(String),
}
