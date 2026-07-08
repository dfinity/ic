use super::identity_manager::EncryptionConfiguration;
use super::{IdentityConfiguration, IdentityType};
use crate::error::{
    encryption::{
        EncryptionError,
        EncryptionError::{DecryptContentFailed, HashPasswordFailed},
    },
    identity::{
        LoadPemError, LoadPemError::LoadFromKeyringFailed, LoadPemFromFileError,
        LoadPemFromFileError::DecryptPemFileFailed,
    },
};
use crate::identity::identity_file_locations::IdentityFileLocations;
use crate::identity::keyring_mock;
use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use argon2::{Argon2, password_hash::PasswordHasher};
use slog::{Logger, debug};
use std::path::Path;

/// Loads an identity's PEM file content.
pub(crate) fn load_pem(
    log: &Logger,
    locations: &IdentityFileLocations,
    identity_name: &str,
    identity_config: &IdentityConfiguration,
) -> Result<(Vec<u8>, IdentityType), LoadPemError> {
    if identity_config.hsm.is_some() {
        unreachable!("Cannot load pem content for an HSM identity.")
    } else if identity_config.keyring_identity_suffix.is_some() {
        debug!(
            log,
            "Found keyring identity suffix - PEM file is stored in keyring."
        );
        let pem = keyring_mock::load_pem_from_keyring(identity_name)
            .map_err(|err| LoadFromKeyringFailed(Box::new(identity_name.to_string()), err))?;
        Ok((pem, IdentityType::Keyring))
    } else {
        let pem_path = locations.get_identity_pem_path(identity_name, identity_config);
        load_pem_from_file(&pem_path, Some(identity_config))
            .map_err(LoadPemError::LoadFromFileFailed)
    }
}

/// Loads a pem file, no matter if it is a plaintext pem file or if it is encrypted with a password.
/// Transparently handles all complexities regarding pem file encryption, including prompting the user for the password.
/// Returns the pem and whether the original was encrypted.
///
/// Try to only load the pem file once, as the user may be prompted for the password every single time you call this function.
pub fn load_pem_from_file(
    path: &Path,
    config: Option<&IdentityConfiguration>,
) -> Result<(Vec<u8>, IdentityType), LoadPemFromFileError> {
    let content = crate::fs::read(path)?;

    let (content, was_encrypted) = maybe_decrypt_pem(content.as_slice(), config)
        .map_err(|err| DecryptPemFileFailed(path.to_path_buf(), err))?;
    Ok((
        content,
        if was_encrypted {
            IdentityType::EncryptedLocal
        } else {
            IdentityType::Plaintext
        },
    ))
}

/// If the IndentityConfiguration suggests that the content of the pem file is encrypted,
/// then the user is prompted for the password to the pem file.
/// The decrypted pem file content is then returned.
///
/// If the pem file should not be encrypted, then the content is returned as is.
///
/// Additionally returns whether or not it was necessary to decrypt the file.
fn maybe_decrypt_pem(
    pem_content: &[u8],
    config: Option<&IdentityConfiguration>,
) -> Result<(Vec<u8>, bool), EncryptionError> {
    if let Some(decryption_config) = config.and_then(|c| c.encryption.as_ref()) {
        let password = password_prompt()?;
        let pem = decrypt(pem_content, decryption_config, &password)?;
        // print to stderr so that output redirection works for the identity export command
        eprintln!("Decryption complete.");
        Ok((pem, true))
    } else {
        Ok((Vec::from(pem_content), false))
    }
}

/// Unlike the original, this does not take a `PromptMode`. It behaves like the
/// original when `PromptMode::DecryptingToUse` is passed (the only mode reached
/// on the load path; encryption/creation is not vendored).
fn password_prompt() -> Result<String, EncryptionError> {
    dialoguer::Password::new()
        .with_prompt("Please enter the passphrase for your identity")
        .interact()
        .map_err(EncryptionError::ReadUserPasswordFailed)
}

fn get_argon_params() -> argon2::Params {
    argon2::Params::new(64000 /* in kb */, 3, 1, Some(32 /* in bytes */)).unwrap()
}

fn decrypt(
    encrypted_content: &[u8],
    config: &EncryptionConfiguration,
    password: &str,
) -> Result<Vec<u8>, EncryptionError> {
    let argon2 = Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        get_argon_params(),
    );
    let hash = argon2
        .hash_password(password.as_bytes(), &config.pw_salt)
        .map_err(HashPasswordFailed)?;
    let key = Key::<Aes256Gcm>::clone_from_slice(hash.hash.unwrap().as_ref());
    let cipher = Aes256Gcm::new(&key);
    let nonce = Nonce::from_slice(config.file_nonce.as_slice());

    cipher
        .decrypt(nonce, encrypted_content.as_ref())
        .map_err(DecryptContentFailed)
}
