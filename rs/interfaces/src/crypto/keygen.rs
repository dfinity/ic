mod errors;

pub use errors::*;
use ic_base_types::NodeId;

use ic_protobuf::registry::crypto::v1::PublicKey as PublicKeyProto;
use ic_types::RegistryVersion;
use ic_types::crypto::{CryptoError, CurrentNodePublicKeys, KeyPurpose};
use ic_types::registry::RegistryClientError;

/// Methods for checking and retrieving key material.
pub trait KeyManager {
    /// Checks whether this crypto component is properly set up and in sync with the registry. As
    /// part of the check, the number of public keys in the registry, as well as the corresponding
    /// local public and secret keys, are counted, and metrics observations are made.
    ///
    /// This is done by ensuring that:
    /// 1. the registry contains all necessary public keys
    /// 2. the public keys coming from the registry match the ones stored in the local public key store
    /// 3. the secret key store contains all corresponding secret keys.
    ///
    /// # Errors
    /// * [`CheckKeysWithRegistryError::PublicKeyNotFound`] in case a public key of the node was
    ///   not found in the registry
    /// * [`CheckKeysWithRegistryError::TlsCertNotFound`] in case the TLS certificate of the node
    ///   was not found in the registry
    /// * [`CheckKeysWithRegistryError::InternalError`] in case there were inconsistencies with the
    ///   node keys, or if there was an error performing the checks
    /// * [`CheckKeysWithRegistryError::TransientInternalError`] in case there was an RPC error
    ///   communicating the the CSP vault
    fn check_keys_with_registry(
        &self,
        registry_version: RegistryVersion,
    ) -> Result<(), CheckKeysWithRegistryError>;

    /// Returns the node's public keys currently stored in the public key store.
    ///
    /// Calling this method multiple times may lead to different results
    /// depending on the state of the public key store.
    ///
    /// # Errors
    /// * [`CurrentNodePublicKeysError::TransientInternalError`] in case of a transient internal error.
    fn current_node_public_keys(&self)
    -> Result<CurrentNodePublicKeys, CurrentNodePublicKeysError>;

    /// Rotates the I-DKG dealing encryption keys. This function checks to see if the local node
    /// may rotate its key, and if so, performs the rotation. If a previously rotated key has not
    /// yet been registered, it is returned. Returns
    /// [`IDkgKeyRotationResult::IDkgDealingEncPubkeyNeedsRegistration`] with a `PublicKeyProto`
    /// containing the new I-DKG dealing encryption key to be registered,
    /// [`IDkgKeyRotationResult::LatestRotationTooRecent`] is the local node may not yet rotate its
    /// key, or an error if the key rotation failed.
    ///
    /// # Errors
    /// * [`IDkgDealingEncryptionKeyRotationError::KeyGenerationError`] if there was an error
    ///   generating a new key
    /// * [`IDkgDealingEncryptionKeyRotationError::RegistryClientError`] if there was an error communicating
    ///   with the registry
    /// * [`IDkgDealingEncryptionKeyRotationError::KeyRotationNotEnabled`] if key rotation was not
    ///   enabled on the subnet the node is assigned to.
    /// * [`IDkgDealingEncryptionKeyRotationError::TransientInternalError`] if there was an RPC error
    ///   communicating with the CSP vault.
    fn rotate_idkg_dealing_encryption_keys(
        &self,
        registry_version: RegistryVersion,
    ) -> Result<IDkgKeyRotationResult, IDkgDealingEncryptionKeyRotationError>;
}

#[derive(Clone, Eq, PartialEq, Debug)]
pub enum CheckKeysWithRegistryError {
    /// Public key for given (entity, purpose) pair not found at given registry
    /// version.
    PublicKeyNotFound {
        node_id: NodeId,
        key_purpose: KeyPurpose,
        registry_version: RegistryVersion,
    },
    /// TLS cert for given node_id not found at given registry version.
    TlsCertNotFound {
        node_id: NodeId,
        registry_version: RegistryVersion,
    },
    /// Internal error.
    InternalError { internal_error: String },
    /// Transient internal error; retrying may cause the operation to succeed.
    TransientInternalError { internal_error: String },
}

impl From<CryptoError> for CheckKeysWithRegistryError {
    fn from(crypto_error: CryptoError) -> Self {
        match crypto_error {
            CryptoError::TransientInternalError { internal_error } => {
                CheckKeysWithRegistryError::TransientInternalError { internal_error }
            }
            CryptoError::PublicKeyNotFound {
                node_id,
                key_purpose,
                registry_version,
            } => CheckKeysWithRegistryError::PublicKeyNotFound {
                node_id,
                key_purpose,
                registry_version,
            },
            CryptoError::TlsCertNotFound {
                node_id,
                registry_version,
            } => CheckKeysWithRegistryError::TlsCertNotFound {
                node_id,
                registry_version,
            },
            _ => CheckKeysWithRegistryError::InternalError {
                internal_error: format!("{crypto_error}"),
            },
        }
    }
}

#[derive(Clone, Eq, PartialEq, Debug)]
pub enum KeyRotationOutcome {
    KeyRotated { new_key: PublicKeyProto },
    KeyNotRotated { existing_key: PublicKeyProto },
    KeyNotRotatedButTooOld { existing_key: PublicKeyProto },
}

impl From<KeyRotationOutcome> for PublicKeyProto {
    fn from(value: KeyRotationOutcome) -> Self {
        match value {
            KeyRotationOutcome::KeyRotated { new_key } => new_key,
            KeyRotationOutcome::KeyNotRotated { existing_key } => existing_key,
            KeyRotationOutcome::KeyNotRotatedButTooOld { existing_key } => existing_key,
        }
    }
}

#[derive(Clone, Eq, PartialEq, Debug)]
pub enum IDkgKeyRotationResult {
    /// If no key rotation is necessary because the latest rotation was too recent
    LatestRotationTooRecent,
    /// If the key was rotated, or if an already-rotated key still needs to be registered
    IDkgDealingEncPubkeyNeedsRegistration(KeyRotationOutcome),
}

#[derive(Clone, Debug)]
pub enum IDkgDealingEncryptionKeyRotationError {
    KeyGenerationError(String),
    RegistryClientError(RegistryClientError),
    RegistryKeyBadOrMissing,
    KeyRotationNotEnabled,
    TransientInternalError(String),
    PublicKeyNotFound,
}

impl From<RegistryClientError> for IDkgDealingEncryptionKeyRotationError {
    fn from(registry_client_error: RegistryClientError) -> Self {
        IDkgDealingEncryptionKeyRotationError::RegistryClientError(registry_client_error)
    }
}
