use thiserror::Error;

#[derive(Error, Debug)]
pub enum EncryptionError {
    #[error("Failed to decrypt content")]
    DecryptContentFailed(#[source] aes_gcm::Error),

    #[error("Failed to hash password")]
    HashPasswordFailed(#[source] argon2::password_hash::Error),

    #[error("Failed to read user input")]
    ReadUserPasswordFailed(#[source] dialoguer::Error),
}
