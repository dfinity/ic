//! Interfaces for saving and retrieving public keys
use prost::Message;
use std::fs;
use std::path::Path;

use ic_protobuf::crypto::v1::NodePublicKeys;

const PK_DATA_FILENAME: &str = "public_keys.pb";
const PUBLIC_FOLDER: &str = "public";

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
    let legacy_pk_file = crypto_root.join(PK_DATA_FILENAME);
    let pk_folder = crypto_root.join(PUBLIC_FOLDER);
    let pk_file = pk_folder.join(PK_DATA_FILENAME);

    let src_file = if pk_file.exists() {
        pk_file
    } else {
        legacy_pk_file
    };
    match fs::read(src_file) {
        Ok(data) => NodePublicKeys::decode(&*data)
            .map_err(|err| PublicKeyStoreError::ParsingError(err.to_string())),
        Err(err) => Err(PublicKeyStoreError::IOError(err.to_string())),
    }
}
