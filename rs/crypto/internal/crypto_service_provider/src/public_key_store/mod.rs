//! Interfaces for saving and retrieving public keys
use crate::PUBLIC_KEY_STORE_DATA_FILENAME;
use ic_protobuf::crypto::v1::NodePublicKeys;
use ic_protobuf::registry::crypto::v1::{PublicKey as PublicKeyProto, X509PublicKeyCert};
use ic_types::Time;
use prost::Message;
use std::fs;
use std::path::Path;

pub mod proto_pubkey_store;

#[cfg(test)]
pub mod temp_pubkey_store;

#[cfg(test)]
pub mod mock_pubkey_store;

/// Error while reading or writing public keys
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum PublicKeyStoreError {
    ParsingError(String),
    SerialisationError(String),
    IOError(String),
}

/// Write the node public keys to local storage
pub fn store_node_public_keys(
    crypto_root: &Path,
    node_pks: &NodePublicKeys,
) -> Result<(), PublicKeyStoreError> {
    let pk_file = crypto_root.join(PUBLIC_KEY_STORE_DATA_FILENAME);

    ic_utils::fs::write_protobuf_using_tmp_file(pk_file, node_pks)
        .map_err(|err| PublicKeyStoreError::IOError(err.to_string()))
}

/// Read the node public keys from local storage
pub fn read_node_public_keys(crypto_root: &Path) -> Result<NodePublicKeys, PublicKeyStoreError> {
    let pk_file = crypto_root.join(PUBLIC_KEY_STORE_DATA_FILENAME);
    match fs::read(pk_file) {
        Ok(data) => NodePublicKeys::decode(&*data)
            .map_err(|err| PublicKeyStoreError::ParsingError(err.to_string())),
        Err(err) => Err(PublicKeyStoreError::IOError(err.to_string())),
    }
}

#[derive(Debug)]
pub enum PublicKeySetOnceError {
    AlreadySet,
    Io(std::io::Error),
}

#[derive(Debug)]
pub enum PublicKeyAddError {
    Io(std::io::Error),
}

#[derive(Debug)]
pub enum PublicKeyRetainError {
    Io(std::io::Error),
    OldestPublicKeyNotFound,
}

/// A store for public key material persisted on disk.
///
/// If errors occur regarding reading from or writing to disk,
/// the methods generally return an error rather than panic.
pub trait PublicKeyStore: Send + Sync {
    /// Sets the node signing public key.
    ///
    /// Returns an error if a key is already set, or if writing to disk fails.
    fn set_once_node_signing_pubkey(
        &mut self,
        key: PublicKeyProto,
    ) -> Result<(), PublicKeySetOnceError>;

    /// Gets the node signing public key.
    ///
    /// Note: any timestamp in [`PublicKeyProto`] will be stripped off.
    fn node_signing_pubkey(&self) -> Option<PublicKeyProto>;

    /// Sets the committee signing public key.
    ///
    /// Returns an error if a key is already set, or if writing to disk fails.
    fn set_once_committee_signing_pubkey(
        &mut self,
        key: PublicKeyProto,
    ) -> Result<(), PublicKeySetOnceError>;

    /// Gets the committee signing public key.
    ///
    /// Note: any timestamp in [`PublicKeyProto`] will be stripped off.
    fn committee_signing_pubkey(&self) -> Option<PublicKeyProto>;

    /// Sets the NI-DKG dealing encryption public key.
    ///
    /// Returns an error if a key is already set, or if writing to disk fails.
    fn set_once_ni_dkg_dealing_encryption_pubkey(
        &mut self,
        key: PublicKeyProto,
    ) -> Result<(), PublicKeySetOnceError>;

    /// Gets the NI-DKG dealing encryption public key.
    ///
    /// Note: any timestamp in [`PublicKeyProto`] will be stripped off.
    fn ni_dkg_dealing_encryption_pubkey(&self) -> Option<PublicKeyProto>;

    /// Sets the TLS certificate.
    ///
    /// Returns an error if a certificate is already set, or if writing to disk fails.
    fn set_once_tls_certificate(
        &mut self,
        cert: X509PublicKeyCert,
    ) -> Result<(), PublicKeySetOnceError>;

    /// Gets the TLS certificate.
    fn tls_certificate(&self) -> Option<&X509PublicKeyCert>;

    /// Adds a new iDKG dealing encryption public key.
    fn add_idkg_dealing_encryption_pubkey(
        &mut self,
        key: PublicKeyProto,
    ) -> Result<(), PublicKeyAddError>;

    /// Retain only the most recent iDKG dealing encryption public keys.
    /// Returns `Ok(true)` iff this operation modified the public key store.
    ///
    /// The order of public keys is based on their order of insertion ([`Self::add_idkg_dealing_encryption_pubkey`])
    /// and in particular not on their [`timestamp`](PublicKeyProto::timestamp) field.
    /// The largest suffix of public keys starting with (and including) the given `oldest_public_key_to_keep` is kept,
    /// while other keys are deleted. Keys are compared using [`PublicKeyProto::equal_ignoring_timestamp`].
    ///
    /// # Errors
    /// * [`PublicKeyRetainError::OldestPublicKeyNotFound`] if the given `oldest_public_key_to_keep` was not found.
    /// No keys are deleted in that case.
    /// * [`PublicKeyRetainError::Io`] if an I/O error occurred while writing the retained keys back to disk.
    fn retain_most_recent_idkg_public_keys_up_to_inclusive(
        &mut self,
        oldest_public_key_to_keep: &PublicKeyProto,
    ) -> Result<bool, PublicKeyRetainError>;

    /// Gets the iDKG dealing encryption public keys.
    ///
    /// The ordering of the keys is guaranteed to be same as when the keys were added
    /// with [`Self::add_idkg_dealing_encryption_pubkey`].
    /// Note: any timestamp in [`PublicKeyProto`] will be stripped off.
    fn idkg_dealing_encryption_pubkeys(&self) -> Vec<PublicKeyProto>;

    /// Gets the timestamps of when public keys were generated.
    fn generation_timestamps(&self) -> PublicKeyGenerationTimestamps;

    /// Gets the number of iDKG dealing encryption public keys stored locally.
    fn idkg_dealing_encryption_pubkeys_count(&self) -> usize;
}

/// Timestamps of when public keys were generated.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct PublicKeyGenerationTimestamps {
    /// Timestamp of when the node signing public key was generated.
    pub node_signing_public_key: Option<Time>,

    /// Timestamp of when the committee signing public key was generated.
    pub committee_signing_public_key: Option<Time>,

    /// Timestamp of when the NIDKG dealing encryption public key was generated.
    pub dkg_dealing_encryption_public_key: Option<Time>,

    /// Timestamp of when the last IDKG dealing encryption public key was generated.
    pub last_idkg_dealing_encryption_public_key: Option<Time>,
}
