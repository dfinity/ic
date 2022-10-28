//! Interfaces for saving and retrieving public keys
use ic_protobuf::crypto::v1::NodePublicKeys;
use ic_protobuf::registry::crypto::v1::{PublicKey as PublicKeyProto, X509PublicKeyCert};
use prost::Message;
use std::fs;
use std::path::Path;

const PK_DATA_FILENAME: &str = "public_keys.pb";

/// Error while reading or writing public keys
#[derive(Clone, Debug)]
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
    let pk_file = crypto_root.join(PK_DATA_FILENAME);

    ic_utils::fs::write_protobuf_using_tmp_file(pk_file, node_pks)
        .map_err(|err| PublicKeyStoreError::IOError(err.to_string()))
}

/// Read the node public keys from local storage
pub fn read_node_public_keys(crypto_root: &Path) -> Result<NodePublicKeys, PublicKeyStoreError> {
    let pk_file = crypto_root.join(PK_DATA_FILENAME);
    match fs::read(pk_file) {
        Ok(data) => NodePublicKeys::decode(&*data)
            .map_err(|err| PublicKeyStoreError::ParsingError(err.to_string())),
        Err(err) => Err(PublicKeyStoreError::IOError(err.to_string())),
    }
}

pub enum PublicKeySetOnceError {
    AlreadySet,
    Io(std::io::Error),
}

/// A store for public key material persisted on disk.
///
/// If errors occur regarding reading from or writing to disk,
/// the methods generally return an error rather than panic.
pub trait PublicKeyStore {
    /// Sets the node signing public key.
    ///
    /// Returns an error if a key is already set, or if writing to disk fails.
    fn set_once_node_signing_pubkey(
        &mut self,
        key: PublicKeyProto,
    ) -> Result<(), PublicKeySetOnceError>;

    /// Gets the node signing public key.
    fn node_signing_pubkey(&self) -> Option<&PublicKeyProto>;

    /// Sets the committee signing public key.
    ///
    /// Returns an error if a key is already set, or if writing to disk fails.
    fn set_once_committee_signing_pubkey(
        &mut self,
        key: PublicKeyProto,
    ) -> Result<(), PublicKeySetOnceError>;

    /// Gets the committee signing public key.
    fn committee_signing_pubkey(&self) -> Option<&PublicKeyProto>;

    /// Sets the NI-DKG dealing encryption public key.
    ///
    /// Returns an error if a key is already set, or if writing to disk fails.
    fn set_once_ni_dkg_dealing_encryption_pubkey(
        &mut self,
        key: PublicKeyProto,
    ) -> Result<(), PublicKeySetOnceError>;

    /// Gets the NI-DKG dealing encryption public key.
    fn ni_dkg_dealing_encryption_pubkey(&self) -> Option<&PublicKeyProto>;

    /// Sets the TLS certificate.
    ///
    /// Returns an error if a certificate is already set, or if writing to disk fails.
    fn set_once_tls_certificate(
        &mut self,
        cert: X509PublicKeyCert,
    ) -> Result<(), PublicKeySetOnceError>;

    /// Gets the TLS certificate.
    fn tls_certificate(&self) -> Option<&X509PublicKeyCert>;

    /// Sets the iDKG dealing encryption public keys.
    fn set_idkg_dealing_encryption_pubkeys(
        &mut self,
        keys: Vec<PublicKeyProto>,
    ) -> Result<(), std::io::Error>;

    /// Gets the iDKG dealing encryption public keys.
    ///
    /// The ordering of the keys is guaranteed to be same as when the keys were set.
    fn idkg_dealing_encryption_pubkeys(&self) -> &Vec<PublicKeyProto>;
}
