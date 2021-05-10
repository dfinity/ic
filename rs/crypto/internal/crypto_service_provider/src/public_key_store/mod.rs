//! Interfaces for saving and retrieving public keys
use prost::Message;
use std::fs;
use std::path::Path;

use ic_protobuf::crypto::v1::NodePublicKeys;
use std::io::Write;

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
    let mut buf = Vec::new();
    match node_pks.encode(&mut buf) {
        Ok(_) => ic_utils::fs::write_atomically(&pk_file, |f| f.write_all(&buf))
            .map_err(|err| PublicKeyStoreError::IOError(err.to_string())),
        Err(err) => Err(PublicKeyStoreError::SerialisationError(err.to_string())),
    }
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
