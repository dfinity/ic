//! Interfaces for saving and retrieving public keys
use ic_protobuf::registry::crypto::v1::{PublicKey as PublicKeyProto, X509PublicKeyCert};
use ic_types::Time;

pub mod proto_pubkey_store;

#[cfg(test)]
pub mod temp_pubkey_store;

#[cfg(test)]
pub mod mock_pubkey_store;

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

#[derive(Debug)]
pub enum PublicKeyRetainCheckError {
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
    fn tls_certificate(&self) -> Option<X509PublicKeyCert>;

    /// Adds a new iDKG dealing encryption public key.
    fn add_idkg_dealing_encryption_pubkey(
        &mut self,
        key: PublicKeyProto,
    ) -> Result<(), PublicKeyAddError>;

    /// Retain only the most recent iDKG dealing encryption public keys including the
    /// `oldest_public_key_to_keep`.
    /// Returns `Ok(true)` iff this operation modified the public key store.
    ///
    /// The order of public keys is based on their order of insertion ([`Self::add_idkg_dealing_encryption_pubkey`])
    /// and in particular not on their [`timestamp`](PublicKeyProto::timestamp) field.
    /// The largest suffix of public keys starting with (and including) the given `oldest_public_key_to_keep` is kept,
    /// while other keys are deleted. Keys are compared using [`PublicKeyProto::equal_ignoring_timestamp`].
    ///
    /// # Errors
    /// * [`PublicKeyRetainError::OldestPublicKeyNotFound`] if the given `oldest_public_key_to_keep` was not found.
    ///   No keys are deleted in that case.
    /// * [`PublicKeyRetainError::Io`] if an I/O error occurred while writing the retained keys back to disk.
    fn retain_idkg_public_keys_since(
        &mut self,
        oldest_public_key_to_keep: &PublicKeyProto,
    ) -> Result<bool, PublicKeyRetainError>;

    /// Checks to see if a call to `retain_idkg_public_keys_since` would modify the keystore.
    ///
    /// Returns `true` if the keystore would be modified, `false` otherwise.
    ///
    /// # Errors
    /// * [`PublicKeyRetainError::OldestPublicKeyNotFound`] if the given `oldest_public_key_to_keep` was not found.
    fn would_retain_idkg_public_keys_modify_pubkey_store(
        &self,
        oldest_public_key_to_keep: &PublicKeyProto,
    ) -> Result<bool, PublicKeyRetainCheckError>;

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
